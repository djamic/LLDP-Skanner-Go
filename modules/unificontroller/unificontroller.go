// Package unificontroller is the device module of the UniFi Network
// application (the controller of the network's UniFi access points), on a
// UniFi OS console or self-hosted. Over the application's Network
// Integration API (v1), with an API key (a login of protocol "https" with
// the key as its password and no user name), it detects the application:
// its version, its sites, every device it manages (name, model, MAC, IP,
// state, firmware, uplink device) and how many clients are on each device.
// It recognizes the application with no key (Probe) by its status page, by
// the way its API refuses a request with no key, or by its UniFi OS
// console.
package unificontroller

import (
	"cmp"
	"context"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"lldp_scanner/modules"
)

func init() { modules.Register(Module{}) }

// Module is the UniFi Network controller device module.
type Module struct{}

func (Module) ID() string       { return "unificontroller" }
func (Module) Label() string    { return "UniFi Network controller" }
func (Module) Type() string     { return "unifi-controller" }
func (Module) Protocol() string { return "https" }

func (Module) Actions() []modules.Action {
	return []modules.Action{{ID: "detect", Label: "🔎 Detect"}}
}

// Run finds the application's API with the key (Login.Password) and runs
// the action.
func (Module) Run(ctx context.Context, req modules.Request) (modules.Result, error) {
	if req.Action != "detect" {
		return modules.Result{}, fmt.Errorf("unknown action %q", req.Action)
	}
	key := strings.TrimSpace(req.Login.Password)
	if key == "" {
		return modules.Result{}, fmt.Errorf("%w: no API key (the key is the login's password)", modules.ErrLoginRejected)
	}
	c, info, err := connect(ctx, req.IP, key)
	if err != nil {
		return modules.Result{}, err
	}
	defer c.http.CloseIdleConnections()
	return detect(ctx, c, info)
}

// Probe tells, with no key, whether a UniFi Network application answers at
// ip: its status page, its API refusing a request with no key in its own
// error JSON, or a UniFi OS console's page and gateway refusal
// (unifiOSConsole). The checks run at once, for probeTimeout at most.
func (Module) Probe(ctx context.Context, ip string) bool {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()
	hc := newHTTPClient(probeTimeout)
	defer hc.CloseIdleConnections()
	var checks []func() bool
	for _, u := range statusURLs(ip) {
		checks = append(checks, func() bool { return isStatusPage(ctx, hc, u) })
	}
	for _, base := range apiBases(ip) {
		checks = append(checks, func() bool { return refusesWithoutKey(ctx, hc, base) },
			func() bool { return unifiOSConsole(ctx, hc, base) })
	}
	found := make(chan bool, len(checks))
	for _, check := range checks {
		go func() { found <- check() }()
	}
	for range checks {
		if <-found {
			return true
		}
	}
	return false
}

// ─── The values the API sends ─────────────────────────────────────────────────

// site is one site of the application.
type site struct {
	ID                string `json:"id"`
	InternalReference string `json:"internalReference"` // "default"
	Name              string `json:"name"`              // "Default"
}

func (s site) label() string { return firstOf(s.Name, s.InternalReference, s.ID) }

// device is one device the application manages (an access point, a
// switch, a gateway). Firmware and uplink are not in every version's list.
type device struct {
	ID              string `json:"id"`
	Name            string `json:"name"`       // "AP-Floor2-East"
	Model           string `json:"model"`      // "U6 Pro"
	MacAddress      string `json:"macAddress"` // "28:70:4e:01:02:03"
	IPAddress       string `json:"ipAddress"`
	State           string `json:"state"` // "ONLINE", "OFFLINE", "PENDING_ADOPTION", ...
	FirmwareVersion string `json:"firmwareVersion"`
	// Uplink is the device it is connected through (a switch, or the
	// access point of a mesh link): {"deviceId":"..."}
	Uplink *struct {
		DeviceID string `json:"deviceId"`
	} `json:"uplink"`
	// UplinkDeviceID is the same, as the clients carry it
	UplinkDeviceID string `json:"uplinkDeviceId"`
}

func (d device) label() string { return firstOf(d.Name, d.MacAddress, d.ID) }

func (d device) uplinkID() string {
	if d.Uplink != nil && d.Uplink.DeviceID != "" {
		return d.Uplink.DeviceID
	}
	return d.UplinkDeviceID
}

// clientInfo is one connected client: only its kind and the device it is
// on are read.
type clientInfo struct {
	Type           string `json:"type"`           // "WIRED", "WIRELESS", "VPN", "TELEPORT"
	UplinkDeviceID string `json:"uplinkDeviceId"` // the access point or switch it is on
}

func firstOf(values ...string) string {
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}

// ─── Detect ───────────────────────────────────────────────────────────────────

// clientCount is how many clients are on one device, by kind.
type clientCount struct {
	site, device            string
	wired, wireless, others int
}

func detect(ctx context.Context, c *apiClient, info appInfo) (modules.Result, error) {
	var r modules.Result
	sites, _, err := getAll[site](ctx, c, "/sites")
	if err != nil {
		return r, fmt.Errorf("sites: %w", err)
	}
	slices.SortFunc(sites, func(a, b site) int { return cmp.Compare(strings.ToLower(a.label()), strings.ToLower(b.label())) })

	devices := modules.Table{Title: "Devices", Columns: []string{"Site", "Name", "Model", "MAC", "IP", "State", "Firmware", "Uplink"}}
	counts := map[[2]string]*clientCount{} // site ID, device ID → its clients
	var notRead []string
	states := map[string]int{}
	deviceCount, online := 0, 0
	clientTotal, clientsRead, wired, wireless := 0, 0, 0, 0
	for _, s := range sites {
		devs, devTotal, err := getAll[device](ctx, c, "/sites/"+url.PathEscape(s.ID)+"/devices")
		if err != nil {
			notRead = append(notRead, fmt.Sprintf("devices of site %s: %v", s.label(), err))
			continue
		}
		if devTotal > len(devs) {
			notRead = append(notRead, fmt.Sprintf("site %s: only the first %d of %d devices", s.label(), len(devs), devTotal))
		}
		nameOf := map[string]string{}
		for _, d := range devs {
			nameOf[d.ID] = d.label()
		}
		for _, d := range devs {
			deviceCount++
			if strings.EqualFold(d.State, "ONLINE") {
				online++
			}
			states[firstOf(d.State, "unknown")]++
			uplink := d.uplinkID()
			if uplink != "" {
				uplink = cmp.Or(nameOf[uplink], uplink)
			}
			devices.Rows = append(devices.Rows, []string{s.label(), d.Name, d.Model, d.MacAddress, d.IPAddress, d.State, d.FirmwareVersion, uplink})
		}

		clients, total, err := getAll[clientInfo](ctx, c, "/sites/"+url.PathEscape(s.ID)+"/clients")
		if err != nil {
			notRead = append(notRead, fmt.Sprintf("clients of site %s: %v", s.label(), err))
			continue
		}
		clientTotal += total
		clientsRead += len(clients)
		for _, cl := range clients {
			key := [2]string{s.ID, cl.UplinkDeviceID}
			n := counts[key]
			if n == nil {
				name := "(none)"
				if cl.UplinkDeviceID != "" {
					name = cmp.Or(nameOf[cl.UplinkDeviceID], cl.UplinkDeviceID)
				}
				n = &clientCount{site: s.label(), device: name}
				counts[key] = n
			}
			switch strings.ToUpper(cl.Type) {
			case "WIRED":
				n.wired++
				wired++
			case "WIRELESS":
				n.wireless++
				wireless++
			default:
				n.others++
			}
		}
	}
	slices.SortFunc(devices.Rows, func(a, b []string) int {
		return cmp.Or(cmp.Compare(strings.ToLower(a[0]), strings.ToLower(b[0])),
			cmp.Compare(strings.ToLower(a[1]), strings.ToLower(b[1])), cmp.Compare(a[3], b[3]))
	})

	byDevice := modules.Table{Title: "Clients by device", Columns: []string{"Site", "Device", "Wired", "Wireless", "Other"}}
	for _, n := range counts {
		byDevice.Rows = append(byDevice.Rows, []string{n.site, n.device, strconv.Itoa(n.wired), strconv.Itoa(n.wireless), strconv.Itoa(n.others)})
	}
	slices.SortFunc(byDevice.Rows, func(a, b []string) int {
		return cmp.Or(cmp.Compare(strings.ToLower(a[0]), strings.ToLower(b[0])), cmp.Compare(strings.ToLower(a[1]), strings.ToLower(b[1])))
	})
	if clientsRead < clientTotal {
		byDevice.Title += fmt.Sprintf(" (the first %d of %d clients)", clientsRead, clientTotal)
	}

	var siteNames []string
	for _, s := range sites {
		siteNames = append(siteNames, s.label())
	}
	r.AddFact("Application version", info.ApplicationVersion)
	r.AddFact("API", c.base)
	r.AddFact("Sites", strings.Join(siteNames, ", "))
	r.AddFact("Device states", stateCounts(states))
	if clientTotal > 0 {
		r.AddFact("Clients", fmt.Sprintf("%d (%d wired, %d wireless)", clientTotal, wired, wireless))
	}
	r.AddFact("Not read", strings.Join(notRead, "; "))
	r.Tables = append(r.Tables, devices, byDevice)

	r.Summary = fmt.Sprintf("%s: %s, %s (%d online), %s", strings.TrimSpace("UniFi Network "+info.ApplicationVersion),
		plural(len(sites), "site"), plural(deviceCount, "device"), online, plural(clientTotal, "client"))
	return r, nil
}

// stateCounts is how many devices are in each state, most first:
// "ONLINE 98, OFFLINE 5, PENDING_ADOPTION 1".
func stateCounts(states map[string]int) string {
	names := make([]string, 0, len(states))
	for s := range states {
		names = append(names, s)
	}
	slices.SortFunc(names, func(a, b string) int { return cmp.Or(cmp.Compare(states[b], states[a]), cmp.Compare(a, b)) })
	parts := make([]string, len(names))
	for i, s := range names {
		parts[i] = fmt.Sprintf("%s %d", s, states[s])
	}
	return strings.Join(parts, ", ")
}

// plural is "1 site", "2 sites".
func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return strconv.Itoa(n) + " " + noun + "s"
}
