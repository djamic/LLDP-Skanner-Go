package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"lldp_scanner/modules"
	_ "lldp_scanner/modules/esxi"
	_ "lldp_scanner/modules/unificontroller"
	_ "lldp_scanner/modules/vcenter"
)

// ─── Device modules ───────────────────────────────────────────────────────────
//
// The device modules (modules/<kind>, loaded by the blank imports above)
// log in to one kind of device and detect or change it. The scanner gives
// a module the devices of its type (deviceTypesOf) and the logins of the
// Credentials window for them (credentialsFor), tried in order until the
// device takes one; the UI shows a device's modules and their actions in
// its info panel (static/modules.js).

const (
	moduleRunTimeout    = 3 * time.Minute
	moduleProbeTimeout  = 4 * time.Second
	moduleProbeLifetime = 30 * time.Minute // how long a probe's answer is kept
)

// moduleProbes holds the answers of the modules' probes by "module|ip",
// and moduleProbeMu guards it.
var (
	moduleProbeMu sync.Mutex
	moduleProbes  = make(map[string]moduleProbeAnswer)
)

type moduleProbeAnswer struct {
	is bool
	at time.Time
}

// esxiConfirmedIP reports whether the device at ip is an HTTP-confirmed
// ESXi host: the confirmation's IP, or the current IP of a MAC confirmed
// without one.
func esxiConfirmedIP(ip string) bool {
	found := false
	ConfirmedESXiMACs.Range(func(mac, v any) bool {
		switch v := v.(type) {
		case string:
			found = v == ip
		case bool:
			globalMACtoIPMutex.RLock()
			found = globalMACtoIP[fmt.Sprint(mac)] == ip
			globalMACtoIPMutex.RUnlock()
		}
		return !found
	})
	return found
}

// deviceTypesOf returns the device types (Credentials types) of the device
// at ip, most specific first: those the Credentials window declares for it
// (a login for its IP or range with a device type), "esxi" for a confirmed
// ESXi host, then the type of each module that recognizes the device
// itself (modules.Prober; answers are kept moduleProbeLifetime). A type
// declared or known is not probed for.
func deviceTypesOf(ctx context.Context, ip string) []string {
	types := credentialsDeclaredTypes(ip)
	if esxiConfirmedIP(ip) && !slices.Contains(types, "esxi") {
		types = append(types, "esxi")
	}
	for _, m := range modules.All() {
		p, ok := m.(modules.Prober)
		if !ok || slices.Contains(types, m.Type()) {
			continue
		}
		key := m.ID() + "|" + ip
		moduleProbeMu.Lock()
		a, known := moduleProbes[key]
		moduleProbeMu.Unlock()
		if !known || time.Since(a.at) > moduleProbeLifetime {
			pctx, cancel := context.WithTimeout(ctx, moduleProbeTimeout)
			a = moduleProbeAnswer{is: p.Probe(pctx, ip), at: time.Now()}
			cancel()
			moduleProbeMu.Lock()
			moduleProbes[key] = a
			moduleProbeMu.Unlock()
		}
		if a.is {
			types = append(types, m.Type())
		}
	}
	return types
}

// moduleLastRun is the last action of a module on a device.
type moduleLastRun struct {
	Action  string    `json:"action"`
	Time    time.Time `json:"time"`
	OK      bool      `json:"ok"`
	Summary string    `json:"summary"`
}

// moduleLast holds the last action by "module|ip" and moduleBusy the
// devices an action runs on; moduleRunMu guards both.
var (
	moduleRunMu sync.Mutex
	moduleLast  = make(map[string]moduleLastRun)
	moduleBusy  = make(map[string]bool)
)

// moduleView is a module as GET /api/modules shows it for one device.
type moduleView struct {
	ID       string           `json:"id"`
	Label    string           `json:"label"`
	Type     string           `json:"type"`
	Protocol string           `json:"protocol"`
	Actions  []modules.Action `json:"actions"`
	Logins   int              `json:"logins"` // the logins the Credentials window has for the device
	Last     *moduleLastRun   `json:"last,omitempty"`
}

// modulesHandler (GET ?ip=) lists the modules of the device at ip.
func modulesHandler(w http.ResponseWriter, r *http.Request) {
	ip := net.ParseIP(r.URL.Query().Get("ip"))
	if r.Method != http.MethodGet || ip == nil || ip.To4() == nil {
		credentialsError(w, http.StatusBadRequest, "GET ?ip=<IPv4 address>")
		return
	}
	addr := ip.String()
	types := deviceTypesOf(r.Context(), addr)
	views := []moduleView{}
	for _, m := range modules.All() {
		if !slices.Contains(types, m.Type()) {
			continue
		}
		logins, _ := credentialsFor(addr, m.Protocol(), types)
		v := moduleView{ID: m.ID(), Label: m.Label(), Type: m.Type(), Protocol: m.Protocol(), Actions: m.Actions(), Logins: len(logins)}
		moduleRunMu.Lock()
		if last, ok := moduleLast[m.ID()+"|"+addr]; ok {
			v.Last = &last
		}
		moduleRunMu.Unlock()
		views = append(views, v)
	}
	credentialsReply(w, http.StatusOK, map[string]any{"ip": addr, "types": types, "modules": views})
}

// moduleRunRequest is the body of POST /api/modules/run. Confirmed says
// the user agreed to an action that changes the device.
type moduleRunRequest struct {
	Module    string `json:"module"`
	Action    string `json:"action"`
	IP        string `json:"ip"`
	Confirmed bool   `json:"confirmed"`
}

// moduleRunHandler (POST) runs a module's action on a device of its type:
// the device's logins are tried in order until it takes one, which is
// tried first next time (credentialsWorked). An action that changes the
// device needs "confirmed"; one that sets SNMP is checked by polling the
// device with the scanner's community. The answer has the result also
// when the action failed (what it changed before).
func moduleRunHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		credentialsError(w, http.StatusMethodNotAllowed, "POST")
		return
	}
	var req moduleRunRequest
	if json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req) != nil {
		credentialsError(w, http.StatusBadRequest, "invalid request")
		return
	}
	ip := net.ParseIP(req.IP)
	if ip == nil || ip.To4() == nil {
		credentialsError(w, http.StatusBadRequest, "not an IPv4 address: "+req.IP)
		return
	}
	addr := ip.String()
	m := modules.Find(req.Module)
	if m == nil {
		credentialsError(w, http.StatusNotFound, "no module "+req.Module)
		return
	}
	action, ok := modules.ActionOf(m, req.Action)
	if !ok {
		credentialsError(w, http.StatusBadRequest, fmt.Sprintf("module %s has no action %s", m.ID(), req.Action))
		return
	}
	types := deviceTypesOf(r.Context(), addr)
	if !slices.Contains(types, m.Type()) {
		credentialsError(w, http.StatusForbidden, fmt.Sprintf("%s is no %s device (its types: %s)", addr, m.Label(), strings.Join(types, ", ")))
		return
	}
	if action.Changes && !req.Confirmed {
		credentialsError(w, http.StatusBadRequest, "this action changes the device: confirm it")
		return
	}
	logins, err := credentialsFor(addr, m.Protocol(), types)
	if err != nil {
		credentialsError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if len(logins) == 0 {
		credentialsError(w, http.StatusPreconditionFailed, fmt.Sprintf(
			"no %s login for %s in Credentials: add one for its IP, an IP range holding it, or the device type %s", m.Protocol(), addr, m.Type()))
		return
	}
	moduleRunMu.Lock()
	if moduleBusy[addr] {
		moduleRunMu.Unlock()
		credentialsError(w, http.StatusConflict, "another action runs on "+addr)
		return
	}
	moduleBusy[addr] = true
	moduleRunMu.Unlock()
	defer func() {
		moduleRunMu.Lock()
		delete(moduleBusy, addr)
		moduleRunMu.Unlock()
	}()

	// The action runs to its end when the page goes away meanwhile
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), moduleRunTimeout)
	defer cancel()
	community := GetCurrentSettings().Community
	if community == "" {
		community = "public"
	}
	user := "?"
	if s, ok := authSessionOf(r); ok {
		user = s.User
	}
	var res modules.Result
	var used *credentialLogin
	tried := 0
	for i := range logins {
		tried++
		login, others := moduleLogins(logins, i)
		res, err = m.Run(ctx, modules.Request{IP: addr, Action: action.ID, Login: login, Others: others, Community: community})
		if errors.Is(err, modules.ErrLoginRejected) {
			continue
		}
		used = &logins[i]
		break
	}

	answer := map[string]any{"module": m.ID(), "action": action.ID, "ip": addr, "tried": tried, "result": res}
	if used != nil {
		answer["login"] = map[string]string{"id": used.ID, "username": used.Username}
	}
	if used != nil && err == nil {
		credentialsWorked(addr, m.Protocol(), used.ID)
		if action.VerifySNMP {
			answer["snmp"] = moduleCheckSNMP(addr, community)
		}
	}
	switch {
	case used == nil:
		err = fmt.Errorf("%s refused all %d logins of Credentials (%v)", addr, tried, err)
	case err != nil:
		err = fmt.Errorf("with login %s (%s): %w", used.ID, used.Username, err)
	}
	last := moduleLastRun{Action: action.ID, Time: time.Now(), OK: err == nil, Summary: res.Summary}
	if err != nil {
		last.Summary = err.Error()
		answer["error"] = err.Error()
	}
	answer["ok"] = err == nil
	moduleRunMu.Lock()
	moduleLast[m.ID()+"|"+addr] = last
	moduleRunMu.Unlock()
	fmt.Printf("🧩 [Module %s] %s on %s by %s: %s (%d login(s) tried)\n", m.ID(), action.ID, addr, user, last.Summary, tried)
	credentialsReply(w, http.StatusOK, answer)
}

// moduleSNMPRetry is the wait between the SNMP checks of an action (a
// variable for tests).
var moduleSNMPRetry = 3 * time.Second

// moduleCheckSNMP polls the device's sysName with the community, a few
// times (an agent just started may take seconds), and says what it got.
func moduleCheckSNMP(ip, community string) string {
	obj := NewSNMPObject(nil, nil)
	obj.Community = community
	for try := 0; try < 3; try++ {
		if try > 0 {
			time.Sleep(moduleSNMPRetry)
		}
		if name := obj.collectSysText(ip, oidSysName); name != "" {
			return fmt.Sprintf("the device answers SNMP with community %s: sysName %q", community, name)
		}
	}
	return "the device does not answer SNMP with community " + community + " yet"
}

// moduleLogins gives a module login i of logins, and the others in their
// order.
func moduleLogins(logins []credentialLogin, i int) (modules.Login, []modules.Login) {
	var others []modules.Login
	for j, l := range logins {
		if j != i {
			others = append(others, modules.Login{Username: l.Username, Password: l.Password})
		}
	}
	return modules.Login{Username: logins[i].Username, Password: logins[i].Password}, others
}

// registerModuleRoutes adds the modules' API.
func registerModuleRoutes() {
	http.HandleFunc("/api/modules", modulesHandler)
	http.HandleFunc("/api/modules/run", moduleRunHandler)
	var ids []string
	for _, m := range modules.All() {
		ids = append(ids, m.ID())
	}
	fmt.Printf("🧩 Device modules: %s\n", strings.Join(ids, ", "))
}
