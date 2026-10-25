package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"lldp_scanner/modules"
)

// Tests of the device modules' API (device_modules.go): which modules a
// device has, and how an action tries the device's logins.

// fakeModule serves "fake-dev" devices: it recognizes 10.9.70.1 by its
// probe and takes the password "good"; "boom" fails the action.
type fakeModule struct {
	mu     sync.Mutex
	probes int
	runs   []string // the passwords tried
}

func (*fakeModule) ID() string       { return "fake" }
func (*fakeModule) Label() string    { return "Fake device" }
func (*fakeModule) Type() string     { return "fake-dev" }
func (*fakeModule) Protocol() string { return "ssh" }
func (*fakeModule) Actions() []modules.Action {
	return []modules.Action{{ID: "detect", Label: "Detect"},
		{ID: "change", Label: "Change", Changes: true, Confirm: "Sure?", VerifySNMP: true}}
}

func (f *fakeModule) Probe(_ context.Context, ip string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.probes++
	return ip == "10.9.70.1"
}

func (f *fakeModule) Run(_ context.Context, req modules.Request) (modules.Result, error) {
	f.mu.Lock()
	f.runs = append(f.runs, req.Login.Password)
	f.mu.Unlock()
	switch req.Login.Password {
	case "good":
		return modules.Result{Summary: req.Action + " done for " + req.Login.Username, Changes: []string{"community " + req.Community}}, nil
	case "boom":
		return modules.Result{Changes: []string{"half done"}}, errors.New("the device broke")
	}
	return modules.Result{}, fmt.Errorf("%w: wrong password", modules.ErrLoginRejected)
}

var testFakeModule = &fakeModule{}

func init() { modules.Register(testFakeModule) }

// moduleTestSetup gives the fake module's device logins (in this order)
// and forgets earlier runs and probes.
func moduleTestSetup(t *testing.T, passwords ...string) {
	t.Helper()
	authTestSetup(t)
	var entries []credentialEntry
	for i, p := range passwords {
		id := fmt.Sprintf("login%d", i+1)
		secret, _ := credentialsSeal(id, p)
		entries = append(entries, credentialEntry{ID: id, Target: credentialTarget{"type", "fake-dev"}, Protocol: "ssh", Username: "u" + id, Secret: secret})
	}
	if err := credentialsSave(entries); err != nil {
		t.Fatal(err)
	}
	moduleRunMu.Lock()
	moduleLast, moduleBusy = map[string]moduleLastRun{}, map[string]bool{}
	moduleRunMu.Unlock()
	moduleProbeMu.Lock()
	moduleProbes = map[string]moduleProbeAnswer{}
	moduleProbeMu.Unlock()
	testFakeModule.mu.Lock()
	testFakeModule.runs, testFakeModule.probes = nil, 0
	testFakeModule.mu.Unlock()
}

func moduleTestRun(t *testing.T, req moduleRunRequest) (int, map[string]any) {
	t.Helper()
	data, _ := json.Marshal(req)
	r := httptest.NewRequest("POST", "/api/modules/run", strings.NewReader(string(data)))
	r = r.WithContext(context.WithValue(r.Context(), authCtxKey{}, authSession{User: "admin", ID: "s"}))
	w := httptest.NewRecorder()
	captureStdoutQuiet(func() { moduleRunHandler(w, r) })
	var v map[string]any
	json.Unmarshal(w.Body.Bytes(), &v)
	return w.Code, v
}

func moduleTestList(t *testing.T, ip string) map[string]any {
	t.Helper()
	w := httptest.NewRecorder()
	modulesHandler(w, httptest.NewRequest("GET", "/api/modules?ip="+ip, nil))
	var v map[string]any
	json.Unmarshal(w.Body.Bytes(), &v)
	return v
}

func TestModulesList(t *testing.T) {
	moduleTestSetup(t, "bad", "good")
	v := moduleTestList(t, "10.9.70.1")
	list := v["modules"].([]any)
	if len(list) != 1 || list[0].(map[string]any)["id"] != "fake" || list[0].(map[string]any)["logins"] != 2.0 {
		t.Fatalf("modules of the fake device: %v", v)
	}
	if acts := list[0].(map[string]any)["actions"].([]any); len(acts) != 2 || acts[1].(map[string]any)["changes"] != true {
		t.Errorf("actions %v", acts)
	}
	if v := moduleTestList(t, "10.9.70.2"); len(v["modules"].([]any)) != 0 {
		t.Errorf("modules of another device: %v", v)
	}
	// The probe's answer is kept
	moduleTestList(t, "10.9.70.1")
	if testFakeModule.probes != 2 {
		t.Errorf("%d probes for two devices listed three times, want 2", testFakeModule.probes)
	}
	// The ESXi module is loaded and serves confirmed ESXi hosts
	if modules.Find("esxi") == nil {
		t.Fatal("the ESXi module is not registered")
	}
	ConfirmedESXiMACs.Store("48:df:37:00:00:01", "10.9.70.40")
	defer ConfirmedESXiMACs.Delete("48:df:37:00:00:01")
	if types := deviceTypesOf(context.Background(), "10.9.70.40"); !slices.Contains(types, "esxi") {
		t.Errorf("types of a confirmed ESXi host %v", types)
	}
	if v := moduleTestList(t, "10.9.70.40"); len(v["modules"].([]any)) != 1 || v["modules"].([]any)[0].(map[string]any)["id"] != "esxi" {
		t.Errorf("modules of a confirmed ESXi host: %v", v)
	}
}

func TestModuleRunTriesLogins(t *testing.T) {
	moduleTestSetup(t, "bad", "good", "never")
	code, v := moduleTestRun(t, moduleRunRequest{Module: "fake", Action: "detect", IP: "10.9.70.1"})
	if code != 200 || v["ok"] != true || v["tried"] != 2.0 || v["login"].(map[string]any)["id"] != "login2" {
		t.Fatalf("run: %d %v", code, v)
	}
	if res := v["result"].(map[string]any); res["summary"] != "detect done for ulogin2" {
		t.Errorf("result %v", res)
	}
	if strings.Contains(fmt.Sprint(v), "good") {
		t.Errorf("the answer holds a password: %v", v)
	}
	// The login that worked goes first next time
	testFakeModule.runs = nil
	if _, v := moduleTestRun(t, moduleRunRequest{Module: "fake", Action: "detect", IP: "10.9.70.1"}); v["tried"] != 1.0 || !slices.Equal(testFakeModule.runs, []string{"good"}) {
		t.Errorf("second run tried %v (%v), want the login that worked first", testFakeModule.runs, v["tried"])
	}
	// The device's last action is listed
	last := moduleTestList(t, "10.9.70.1")["modules"].([]any)[0].(map[string]any)["last"].(map[string]any)
	if last["ok"] != true || last["action"] != "detect" {
		t.Errorf("last run %v", last)
	}
}

func TestModuleRunFailures(t *testing.T) {
	moduleTestSetup(t, "bad", "bad2")
	if code, v := moduleTestRun(t, moduleRunRequest{Module: "fake", Action: "detect", IP: "10.9.70.1"}); code != 200 || v["ok"] != false ||
		v["tried"] != 2.0 || !strings.Contains(v["error"].(string), "refused all 2 logins") {
		t.Errorf("all logins refused: %d %v", code, v)
	}

	moduleTestSetup(t, "boom", "good")
	code, v := moduleTestRun(t, moduleRunRequest{Module: "fake", Action: "detect", IP: "10.9.70.1"})
	if code != 200 || v["ok"] != false || v["tried"] != 1.0 || !strings.Contains(v["error"].(string), "the device broke") ||
		fmt.Sprint(v["result"].(map[string]any)["changes"]) != "[half done]" {
		t.Errorf("a failing action stops at its login and keeps what it changed: %d %v", code, v)
	}

	moduleTestSetup(t)
	if code, _ := moduleTestRun(t, moduleRunRequest{Module: "fake", Action: "detect", IP: "10.9.70.1"}); code != 412 {
		t.Errorf("no login: %d, want 412", code)
	}
	moduleTestSetup(t, "good")
	for name, c := range map[string]struct {
		req  moduleRunRequest
		code int
	}{
		"not its device":    {moduleRunRequest{Module: "fake", Action: "detect", IP: "10.9.70.2"}, 403},
		"unknown module":    {moduleRunRequest{Module: "nope", Action: "detect", IP: "10.9.70.1"}, 404},
		"unknown action":    {moduleRunRequest{Module: "fake", Action: "nope", IP: "10.9.70.1"}, 400},
		"not an address":    {moduleRunRequest{Module: "fake", Action: "detect", IP: "10.9.70"}, 400},
		"change, no yes":    {moduleRunRequest{Module: "fake", Action: "change", IP: "10.9.70.1"}, 400},
		"busy with another": {moduleRunRequest{Module: "fake", Action: "detect", IP: "10.9.70.1"}, 409},
	} {
		if name == "busy with another" {
			moduleBusy["10.9.70.1"] = true
		}
		if code, v := moduleTestRun(t, c.req); code != c.code {
			t.Errorf("%s: %d %v, want %d", name, code, v, c.code)
		}
		delete(moduleBusy, "10.9.70.1")
	}
	if len(testFakeModule.runs) != 0 {
		t.Errorf("refused requests ran the module: %v", testFakeModule.runs)
	}
}

func TestModuleRunVerifiesSNMP(t *testing.T) {
	resetState(t)
	moduleTestSetup(t, "good")
	moduleSNMPRetry = time.Millisecond
	defer func() { moduleSNMPRetry = 3 * time.Second }()
	fakeSNMP.set("10.9.70.1", nonSwitchAgent("fake-dev-1", "Fake OS"))
	_, v := moduleTestRun(t, moduleRunRequest{Module: "fake", Action: "change", IP: "10.9.70.1", Confirmed: true})
	if v["ok"] != true || v["snmp"] != `the device answers SNMP with community public: sysName "fake-dev-1"` {
		t.Errorf("a confirmed change: %v", v)
	}
	if res := v["result"].(map[string]any); fmt.Sprint(res["changes"]) != "[community public]" {
		t.Errorf("the module got community %v, want the scanner's", res["changes"])
	}
	fakeSNMP.set("10.9.70.1", nil)
	if _, v := moduleTestRun(t, moduleRunRequest{Module: "fake", Action: "change", IP: "10.9.70.1", Confirmed: true}); !strings.Contains(fmt.Sprint(v["snmp"]), "does not answer") {
		t.Errorf("a device that does not answer: %v", v["snmp"])
	}
}

// TestModuleDeclaredType: a device the Credentials window declares of a
// module's type has the module with no probe.
func TestModuleDeclaredType(t *testing.T) {
	moduleTestSetup(t)
	secret, _ := credentialsSeal("decl", "good")
	if err := credentialsSave([]credentialEntry{{ID: "decl", Target: credentialTarget{"ip", "10.9.70.9"}, Protocol: "ssh",
		Username: "u", Secret: secret, DeviceType: "fake-dev"}}); err != nil {
		t.Fatal(err)
	}
	v := moduleTestList(t, "10.9.70.9")
	if list := v["modules"].([]any); len(list) != 1 || list[0].(map[string]any)["logins"] != 1.0 {
		t.Fatalf("modules of a declared device: %v", v)
	}
	if testFakeModule.probes != 0 {
		t.Errorf("a declared device was probed %d times", testFakeModule.probes)
	}
	if _, v := moduleTestRun(t, moduleRunRequest{Module: "fake", Action: "detect", IP: "10.9.70.9"}); v["ok"] != true {
		t.Errorf("run on a declared device: %v", v)
	}
}
