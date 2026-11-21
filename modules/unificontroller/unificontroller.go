// Package unificontroller is the device module of the UniFi Network
// application (the controller of the network's UniFi access points), on a
// UniFi OS console or self-hosted. Over the application's Network
// Integration API (v1), with an API key (a login of protocol "https" with
// the key as its password and no user name), it detects the application:
// its version, its sites, every device it manages (name, model, MAC, IP,
// state, firmware, uplink device) and how many clients are on each device.
// The application's older API (classic.go), with the key or a local
// user's login (a login with a user name), adds the clients' Wi-Fi
// details and the devices' uplinks.
// It recognizes the application with no key (Probe) by its status page, by
// the way its API refuses a request with no key, or by its UniFi OS
// console.
package unificontroller

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"

	"lldp_scanner/modules"
	"lldp_scanner/modules/kit"
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
	return detect(ctx, c, info, loginsOf(req))
}

// loginsOf is the request's login, then its others.
func loginsOf(req modules.Request) []modules.Login {
	return append([]modules.Login{req.Login}, req.Others...)
}

// Probe tells, with no key, whether a UniFi Network application answers at
// ip: its status page, its API refusing a request with no key in its own
// error JSON, or a UniFi OS console's page and gateway refusal
// (unifiOSConsole; the API's /info is asked once per address). The checks
// run at once, for probeTimeout at most.
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
		checks = append(checks, func() bool {
			info := probeInfo(ctx, hc, base) // once for both checks
			return info.refusesWithoutKey() || unifiOSConsole(ctx, hc, base, info)
		})
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

func (s site) label() string { return kit.FirstOf(s.Name, s.InternalReference, s.ID) }

// ref is the site's name in the older API.
func (s site) ref() string { return kit.FirstOf(s.InternalReference, "default") }

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
	// Features are what it does: ["accessPoint","switching"] in the list,
	// {"accessPoint":{...},"switching":{...}} in its details
	Features json.RawMessage `json:"features"`
}

func (d device) label() string { return kit.FirstOf(d.Name, d.MacAddress, d.ID) }

func (d device) mac() string { return strings.ToLower(strings.TrimSpace(d.MacAddress)) }

// gatewayModels start the model names of UniFi's gateways (the Dream
// Machines and Routers, the Next-Gen and Security Gateways, the Cloud
// Gateways, the Express, the Fortress: "UDM Pro", "UDMPRO", "UCG Ultra",
// "UX"; no access point's or switch's starts so). A gateway's features are
// a switch's or an access point's ("switching", "accessPoint"), so without
// the older API's device type its kind used to flip to switch or access
// point.
var gatewayModels = []string{"UDM", "UDR", "UDW", "UXG", "USG", "UCG", "UX", "EFG"}

// kind is "gateway" for a gateway's model, "access_point" for a device with
// the access point feature, "switch" for one that only switches, else "":
// the same with the older API or without it (classicKinds agrees).
func (d device) kind() string {
	model := strings.ToUpper(strings.TrimSpace(d.Model))
	if slices.ContainsFunc(gatewayModels, func(p string) bool { return strings.HasPrefix(model, p) }) {
		return modules.KindGateway
	}
	var names []string
	if json.Unmarshal(d.Features, &names) != nil {
		var features map[string]json.RawMessage
		json.Unmarshal(d.Features, &features)
		for name := range features {
			names = append(names, name)
		}
	}
	switch {
	case slices.Contains(names, "accessPoint"):
		return modules.KindAccessPoint
	case slices.Contains(names, "switching"):
		return modules.KindSwitch
	}
	return ""
}

// managedState is a device's state as the scanner reads it
// (modules.State*): OFFLINE also when the application lost it
// (CONNECTION_INTERRUPTED, DISCONNECTED) or it has no uplink (ISOLATED);
// the others as the application says them ("PENDING_ADOPTION", "ADOPTING",
// "UPDATING"), upper case.
func managedState(state string) string {
	switch s := strings.ToUpper(strings.TrimSpace(state)); s {
	case "CONNECTION_INTERRUPTED", "DISCONNECTED", "ISOLATED":
		return modules.StateOffline
	default:
		return s
	}
}

func (d device) uplinkID() string {
	if d.Uplink != nil && d.Uplink.DeviceID != "" {
		return d.Uplink.DeviceID
	}
	return d.UplinkDeviceID
}

// clientInfo is one connected client.
type clientInfo struct {
	Type           string `json:"type"`           // "WIRED", "WIRELESS", "VPN", "TELEPORT"
	UplinkDeviceID string `json:"uplinkDeviceId"` // the access point or switch it is on
	Name           string `json:"name"`
	MacAddress     string `json:"macAddress"`
	IPAddress      string `json:"ipAddress"`
}

// ─── Inventory ────────────────────────────────────────────────────────────────

// Inventory reads the devices the application manages, with the clients
// on each (modules.Inventorier): the scanner names its access points by
// them, draws those it has no node for, and lists their clients in the
// tree. The older API adds the clients' Wi-Fi details and the devices'
// kinds and uplinks; without it the Integration API's device details give
// the kinds and the uplinks to UniFi devices. A site that cannot be read
// fails the whole read, so the scanner keeps the inventory it had; details
// that cannot be read are a note.
func (Module) Inventory(ctx context.Context, req modules.Request) (modules.Inventory, error) {
	var inv modules.Inventory
	key := strings.TrimSpace(req.Login.Password)
	if key == "" {
		return inv, fmt.Errorf("%w: no API key (the key is the login's password)", modules.ErrLoginRejected)
	}
	c, _, err := connect(ctx, req.IP, key)
	if err != nil {
		return inv, err
	}
	defer c.http.CloseIdleConnections()
	sites, _, err := getAll[site](ctx, c, "/sites")
	if err != nil {
		return inv, fmt.Errorf("sites: %w", err)
	}
	var cc *classicClient
	if len(sites) > 0 {
		if cc, err = classicOpen(ctx, c, sites[0].ref(), loginsOf(req)); err != nil {
			inv.Notes = append(inv.Notes, "client details: "+err.Error())
		} else {
			defer cc.close()
		}
	}
	for _, s := range sites {
		devs, _, err := getAll[device](ctx, c, "/sites/"+url.PathEscape(s.ID)+"/devices")
		if err != nil {
			return inv, fmt.Errorf("devices of site %s: %w", s.label(), err)
		}
		clients, _, err := getAll[clientInfo](ctx, c, "/sites/"+url.PathEscape(s.ID)+"/clients")
		if err != nil {
			return inv, fmt.Errorf("clients of site %s: %w", s.label(), err)
		}
		var stations map[string]station
		var details map[string]classicDevice
		if cc != nil {
			stations, details = classicSite(ctx, cc, s, &inv.Notes)
		} else {
			deviceDetails(ctx, c, s, devs, &inv.Notes)
		}
		inv.Devices = append(inv.Devices, siteDevices(devs, clients, stations, details)...)
	}
	return inv, nil
}

// classicSite reads the stations and the devices of a site from the older
// API, by MAC; what cannot be read is a note.
func classicSite(ctx context.Context, cc *classicClient, s site, notes *[]string) (map[string]station, map[string]classicDevice) {
	stations := map[string]station{}
	list, err := cc.stations(ctx, s.ref())
	if err != nil {
		*notes = append(*notes, fmt.Sprintf("client details of site %s: %v", s.label(), err))
	}
	for _, st := range list {
		stations[strings.ToLower(strings.TrimSpace(st.MAC))] = st
	}
	details := map[string]classicDevice{}
	devs, err := cc.devices(ctx, s.ref())
	if err != nil {
		*notes = append(*notes, fmt.Sprintf("device uplinks of site %s: %v", s.label(), err))
	}
	for _, d := range devs {
		details[strings.ToLower(strings.TrimSpace(d.MAC))] = d
	}
	return stations, details
}

// detailWorkers is how many device details are read at once.
const detailWorkers = 4

// deviceDetails reads the Integration API's details of the devices whose
// list entry tells no uplink or kind, and takes those from them.
func deviceDetails(ctx context.Context, c *apiClient, s site, devs []device, notes *[]string) {
	var wg sync.WaitGroup
	var mu sync.Mutex
	failed, firstErr := 0, error(nil)
	slots := make(chan struct{}, detailWorkers)
	for i := range devs {
		if devs[i].uplinkID() != "" && devs[i].kind() != "" {
			continue
		}
		wg.Add(1)
		go func(d *device) {
			defer wg.Done()
			slots <- struct{}{}
			defer func() { <-slots }()
			var detail device
			err := c.get(ctx, "/sites/"+url.PathEscape(s.ID)+"/devices/"+url.PathEscape(d.ID), nil, &detail)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failed++
				firstErr = cmp.Or(firstErr, err)
				return
			}
			if detail.uplinkID() != "" {
				d.Uplink, d.UplinkDeviceID = detail.Uplink, detail.UplinkDeviceID
			}
			if detail.kind() != "" {
				d.Features = detail.Features
			}
		}(&devs[i])
	}
	wg.Wait()
	if failed > 0 {
		*notes = append(*notes, fmt.Sprintf("device details of site %s: %d not read: %v", s.label(), failed, firstErr))
	}
}

// siteDevices makes the managed devices of a site: each with its kind, its
// uplink and its clients, sorted by name. A client gets the details of its
// station (the older API), and its name there when the Integration API
// names it by its MAC only; a Wi-Fi station the Integration API did not
// list (it connected between the two reads) is added to its access point.
func siteDevices(devs []device, clients []clientInfo, stations map[string]station, details map[string]classicDevice) []modules.ManagedDevice {
	macOf := map[string]string{} // device ID → MAC
	kindOf := map[string]string{}
	for _, d := range devs {
		mac := d.mac()
		macOf[d.ID] = mac
		kindOf[mac] = d.kind()
		if cd, ok := details[mac]; ok {
			kindOf[mac] = cmp.Or(classicKinds[strings.ToLower(cd.Type)], kindOf[mac])
		}
	}
	onDevice := map[string][]modules.ManagedClient{}
	listed := map[string]bool{}
	for _, cl := range clients {
		dev := macOf[cl.UplinkDeviceID]
		if cl.UplinkDeviceID == "" || dev == "" {
			continue // VPN and Teleport clients are on no device
		}
		mc := modules.ManagedClient{MAC: strings.ToLower(strings.TrimSpace(cl.MacAddress)), Name: strings.TrimSpace(cl.Name),
			IP: strings.TrimSpace(cl.IPAddress), Kind: strings.ToLower(cl.Type)}
		if st, ok := stations[mc.MAC]; ok {
			st.apply(&mc)
			if mc.Name == "" || strings.EqualFold(mc.Name, mc.MAC) {
				mc.Name = kit.FirstOf(st.Name, st.Hostname, mc.Name)
			}
		}
		listed[mc.MAC] = true
		onDevice[dev] = append(onDevice[dev], mc)
	}
	for mac, st := range stations {
		ap := strings.ToLower(strings.TrimSpace(st.APMAC))
		if _, known := kindOf[ap]; listed[mac] || st.IsWired || ap == "" || !known {
			continue
		}
		mc := modules.ManagedClient{MAC: mac, Name: kit.FirstOf(st.Name, st.Hostname), Kind: "wireless"}
		st.apply(&mc)
		onDevice[ap] = append(onDevice[ap], mc)
	}
	var out []modules.ManagedDevice
	for _, d := range devs {
		mac := d.mac()
		cls := onDevice[mac]
		slices.SortFunc(cls, func(a, b modules.ManagedClient) int {
			return cmp.Or(cmp.Compare(strings.ToLower(kit.FirstOf(a.Name, a.MAC)), strings.ToLower(kit.FirstOf(b.Name, b.MAC))), cmp.Compare(a.MAC, b.MAC))
		})
		md := modules.ManagedDevice{MAC: mac, Name: d.label(), Model: d.Model, IP: d.IPAddress, State: managedState(d.State),
			Firmware: d.FirmwareVersion, Kind: kindOf[mac], Clients: cls}
		if cd, ok := details[mac]; ok {
			md.Uplink = cd.uplink()
		}
		if up := macOf[d.uplinkID()]; md.Uplink == nil && up != "" {
			md.Uplink = &modules.ManagedUplink{MAC: up, Wireless: md.Kind == modules.KindAccessPoint && kindOf[up] == modules.KindAccessPoint}
		}
		if md.Kind == "" && slices.ContainsFunc(cls, func(c modules.ManagedClient) bool { return c.Kind == "wireless" }) {
			md.Kind = modules.KindAccessPoint
		}
		out = append(out, md)
	}
	return out
}

// ─── Detect ───────────────────────────────────────────────────────────────────

// clientCount is how many clients are on one device, by kind.
type clientCount struct {
	site, device            string
	wired, wireless, others int
}

// ssidCount is how many Wi-Fi clients one SSID has, by band.
type ssidCount struct {
	site, ssid             string
	all, ghz24, ghz5, ghz6 int
}

func detect(ctx context.Context, c *apiClient, info appInfo, logins []modules.Login) (modules.Result, error) {
	var r modules.Result
	sites, _, err := getAll[site](ctx, c, "/sites")
	if err != nil {
		return r, fmt.Errorf("sites: %w", err)
	}
	slices.SortFunc(sites, func(a, b site) int { return cmp.Compare(strings.ToLower(a.label()), strings.ToLower(b.label())) })

	// The older API: the clients' Wi-Fi details, and the devices' uplinks
	// by site ID and MAC
	details := ""
	networks := modules.Table{Title: "Wi-Fi networks", Columns: []string{"Site", "SSID", "Clients", "2.4 GHz", "5 GHz", "6 GHz"}}
	uplinks := map[string]map[string]*modules.ManagedUplink{}
	if len(sites) > 0 {
		cc, err := classicOpen(ctx, c, sites[0].ref(), logins)
		if err != nil {
			details = "not read: " + err.Error()
		} else {
			details = "read with " + cc.who
			ssids := map[[2]string]*ssidCount{}
			for _, s := range sites {
				if cdevs, err := cc.devices(ctx, s.ref()); err == nil {
					uplinks[s.ID] = map[string]*modules.ManagedUplink{}
					for _, d := range cdevs {
						uplinks[s.ID][strings.ToLower(strings.TrimSpace(d.MAC))] = d.uplink()
					}
				}
				stations, err := cc.stations(ctx, s.ref())
				if err != nil {
					details += fmt.Sprintf("; site %s not read: %v", s.label(), err)
					continue
				}
				for _, st := range stations {
					if st.IsWired {
						continue
					}
					var mc modules.ManagedClient
					st.apply(&mc)
					n := ssids[[2]string{s.ID, mc.SSID}]
					if n == nil {
						n = &ssidCount{site: s.label(), ssid: kit.FirstOf(mc.SSID, "(none)")}
						ssids[[2]string{s.ID, mc.SSID}] = n
					}
					n.all++
					switch mc.Band {
					case bands["ng"]:
						n.ghz24++
					case bands["na"]:
						n.ghz5++
					case bands["6e"]:
						n.ghz6++
					}
				}
			}
			cc.close()
			for _, n := range ssids {
				networks.Rows = append(networks.Rows, []string{n.site, n.ssid, strconv.Itoa(n.all), strconv.Itoa(n.ghz24), strconv.Itoa(n.ghz5), strconv.Itoa(n.ghz6)})
			}
			slices.SortFunc(networks.Rows, func(a, b []string) int {
				return cmp.Or(cmp.Compare(strings.ToLower(a[0]), strings.ToLower(b[0])), cmp.Compare(strings.ToLower(a[1]), strings.ToLower(b[1])))
			})
		}
	}

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
		nameByMAC := map[string]string{}
		for _, d := range devs {
			nameOf[d.ID] = d.label()
			nameByMAC[d.mac()] = d.label()
		}
		for _, d := range devs {
			deviceCount++
			if strings.EqualFold(d.State, modules.StateOnline) {
				online++
			}
			states[kit.FirstOf(d.State, "unknown")]++
			uplink := d.uplinkID()
			if uplink != "" {
				uplink = cmp.Or(nameOf[uplink], uplink)
			}
			if up := uplinks[s.ID][d.mac()]; uplink == "" && up != nil {
				// the older API's: "Core USW 5", "4c:ae:a3:a2:01:ac GigabitEthernet1/0/12", "mesh AP-A"
				uplink = strings.TrimSpace(cmp.Or(nameByMAC[up.MAC], up.MAC) + " " + up.Port)
				if up.Wireless {
					uplink = "mesh " + cmp.Or(nameByMAC[up.MAC], up.MAC)
				}
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
	r.AddFact("Client details", details)
	r.AddFact("Not read", strings.Join(notRead, "; "))
	r.Tables = append(r.Tables, devices, byDevice)
	if len(networks.Rows) > 0 {
		r.Tables = append(r.Tables, networks)
	}

	r.Summary = fmt.Sprintf("%s: %s, %s (%d online), %s", strings.TrimSpace("UniFi Network "+info.ApplicationVersion),
		kit.Plural(len(sites), "site"), kit.Plural(deviceCount, "device"), online, kit.Plural(clientTotal, "client"))
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
