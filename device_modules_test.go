package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
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

// Inventory makes the fake module a controller: with the password "good"
// it manages one access point with two clients; "down" fails the read.
func (f *fakeModule) Inventory(_ context.Context, req modules.Request) (modules.Inventory, error) {
	switch req.Login.Password {
	case "good":
		return modules.Inventory{Devices: []modules.ManagedDevice{{MAC: "AA:00:00:00:00:01", Name: "AP 1 qavat", Model: "U6 LR", State: "ONLINE",
			Clients: []modules.ManagedClient{{MAC: "de:ad:00:00:00:01", Name: "Laptop", IP: "10.9.71.5", Kind: "wireless"}, {MAC: "de:ad:00:00:00:02", Kind: "wireless"}}}}}, nil
	case "down":
		return modules.Inventory{}, errors.New("the controller is down")
	}
	return modules.Inventory{}, fmt.Errorf("%w: wrong key", modules.ErrLoginRejected)
}

// TestModuleInventory checks the inventory of a controller the Credentials
// window declares: read with its login, kept in the file (0600) and read
// back, given to the graph node of its MAC, and kept when a later read
// fails.
func TestModuleInventory(t *testing.T) {
	moduleTestSetup(t)
	inventoryFile = filepath.Join(t.TempDir(), "modules_inventory.json")
	defer func() { inventoryFile = "modules_inventory.json" }()
	inventoryMu.Lock()
	inventories, managedByMAC, inventoryNotices = map[string]inventoryRecord{}, map[string]ManagedView{}, map[string]string{}
	inventoryMu.Unlock()
	save := func(passwords ...string) {
		var entries []credentialEntry
		for i, p := range passwords {
			id := fmt.Sprintf("inv%d", i)
			secret, _ := credentialsSeal(id, p)
			entries = append(entries, credentialEntry{ID: id, Target: credentialTarget{"ip", "10.9.70.9"}, Protocol: "ssh", Secret: secret, DeviceType: "fake-dev"})
		}
		credentialsSave(entries)
	}
	save("bad", "good")
	if got := inventoryTargets(testFakeModule); !slices.Equal(got, []string{"10.9.70.9"}) {
		t.Fatalf("targets %v", got)
	}
	captureStdoutQuiet(inventoryRound)
	v := managedViewOf("aa:00:00:00:00:01")
	if v == nil || v.Name != "AP 1 qavat" || v.Controller != "10.9.70.9" || v.Source != "Fake device" || len(v.Clients) != 2 || v.Clients[0].Name != "Laptop" {
		t.Fatalf("managed view %+v", v)
	}
	data := GraphData{Nodes: []GraphNode{{ID: "aa:00:00:00:00:01"}, {ID: "aa:00:00:00:00:02"}, {ID: "10.9.70.9"}}}
	addManaged(&data)
	if data.Nodes[0].Managed == nil || data.Nodes[1].Managed != nil || data.Nodes[2].Managed != nil {
		t.Errorf("managed of the nodes %+v", data.Nodes)
	}
	if info, err := os.Stat(inventoryFile); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("inventory file %v (%v), want mode 0600", info, err)
	}

	// The kept inventory comes back after a restart, and a failed read
	// keeps it
	inventoryMu.Lock()
	inventories, managedByMAC = map[string]inventoryRecord{}, map[string]ManagedView{}
	inventoryMu.Unlock()
	inventoryLoad()
	if v := managedViewOf("aa:00:00:00:00:01"); v == nil || v.Model != "U6 LR" {
		t.Fatalf("after a restart %+v", v)
	}
	save("down")
	out := captureStdout(t, inventoryRound)
	if v := managedViewOf("aa:00:00:00:00:01"); v == nil || !strings.Contains(out, "the controller is down") {
		t.Errorf("after a failed read: %+v, log %q", v, out)
	}
	if again := captureStdout(t, inventoryRound); strings.Contains(again, "down") {
		t.Errorf("the same failure is logged twice: %q", again)
	}
}

// TestManagedClientsInGraph checks the Wi-Fi clients of a managed access
// point in the graph data: a node (wifi_client, its name and IP) for a
// client that is no node yet, named by its DNS name when the controller
// has no name for it (but not by a name that only spells its IP), a "WLAN"
// link of kind wlan from the access point to every wireless client, none
// twice, and nothing for a wired client.
func TestManagedClientsInGraph(t *testing.T) {
	resetState(t)
	dnsCacheMutex.Lock()
	dnsCache["10.9.71.10"] = dnsEntry{name: "Elliot"}
	dnsCache["10.9.71.11"] = dnsEntry{name: "10-9-71-11"}
	dnsCacheMutex.Unlock()
	ap := "70:a7:41:00:00:01"
	data := GraphData{
		Nodes: []GraphNode{{ID: "4c:ae:a3:00:00:01", Group: "switch"}, {ID: ap, Group: "access_point", Managed: &ManagedView{Name: "A 1", Clients: []modules.ManagedClient{
			{MAC: "DE:AD:00:00:00:01", Name: "Laptop", IP: "10.9.71.5", Kind: "wireless", SSID: "TUIT", Signal: -61},
			{MAC: "de:ad:00:00:00:02", Name: "de:ad:00:00:00:02", Kind: "wireless"},
			{MAC: "de:ad:00:00:00:03", Name: "phone", Kind: "wireless", SSID: "TUIT-Guest"},
			{MAC: "de:ad:00:00:00:04", Name: "printer", Kind: "wired"},
			{MAC: ap, Kind: "wireless"},
			{MAC: "de:ad:00:00:00:05", Name: "de:ad:00:00:00:05", IP: "10.9.71.10", Kind: "wireless"},
			{MAC: "de:ad:00:00:00:06", IP: "10.9.71.11", Kind: "wireless"},
			{MAC: "de:ad:00:00:00:07", IP: "10.9.71.10", Kind: "wireless", Hostname: "phone-y"},
		}}}, {ID: "de:ad:00:00:00:03", Group: "wifi_random"}},
		Links: []GraphLink{{Source: "4c:ae:a3:00:00:01", Target: ap}, {Source: "de:ad:00:00:00:03", Target: ap, Label: "x"}},
	}
	addManagedClients(&data)
	nodes := map[string]GraphNode{}
	for _, n := range data.Nodes {
		nodes[n.ID] = n
	}
	if n := nodes["de:ad:00:00:00:01"]; n.Group != "wifi_client" || n.SysName != "Laptop\n10.9.71.5" || n.IP != "10.9.71.5" || n.Label != "Laptop\n10.9.71.5\nde:ad:00:00:00:01" ||
		n.Client == nil || n.Client.Device != "A 1" || n.Client.SSID != "TUIT" || n.Client.Signal != -61 {
		t.Errorf("a new client %+v", n)
	}
	if n := nodes["de:ad:00:00:00:03"]; n.Client == nil || n.Client.SSID != "TUIT-Guest" {
		t.Errorf("a client that was a node already gets no details: %+v", n)
	}
	if n := nodes["de:ad:00:00:00:07"]; n.SysName != "phone-y\n10.9.71.10" || n.Hostname != "" {
		t.Errorf("a client named by its DHCP host name %+v", n)
	}
	if n := nodes["de:ad:00:00:00:02"]; n.Group != "wifi_client" || n.SysName != "" || n.Label != "de:ad:00:00:00:02" {
		t.Errorf("a client named by its MAC %+v", n)
	}
	if n := nodes["de:ad:00:00:00:05"]; n.SysName != "Elliot\n10.9.71.10" || n.Hostname != "Elliot" || n.Label != "Elliot\n10.9.71.10\nde:ad:00:00:00:05" {
		t.Errorf("a client named by its DNS name %+v", n)
	}
	if n := nodes["de:ad:00:00:00:06"]; n.SysName != "10.9.71.11" || n.Hostname != "" {
		t.Errorf("a client whose DNS name spells its IP %+v", n)
	}
	if n := nodes["de:ad:00:00:00:03"]; n.Group != "wifi_random" {
		t.Errorf("a client that was a node already is changed: %+v", n)
	}
	if _, ok := nodes["de:ad:00:00:00:04"]; ok {
		t.Error("a wired client is drawn")
	}
	var links []string
	for _, l := range data.Links[2:] {
		links = append(links, l.Source+">"+l.Target+" "+l.Label+" "+l.SourceLabel+" "+l.Kind)
	}
	want := []string{ap + ">de:ad:00:00:00:01 WLAN|wlan WLAN wlan", ap + ">de:ad:00:00:00:02 WLAN|wlan WLAN wlan",
		ap + ">de:ad:00:00:00:05 WLAN|wlan WLAN wlan", ap + ">de:ad:00:00:00:06 WLAN|wlan WLAN wlan", ap + ">de:ad:00:00:00:07 WLAN|wlan WLAN wlan"}
	if !slices.Equal(links, want) {
		t.Errorf("new links %v, want %v (the linked client gets none)", links, want)
	}
	if len(data.Nodes) != 8 {
		t.Errorf("%d nodes, want the 3 and 5 new clients", len(data.Nodes))
	}
}

// TestGatewayWLAN checks the gateways joined with the Wi-Fi clients of the
// access points: a client's gateway is one whose ARP table has its MAC, the
// one whose own IP is in the client's subnet first (debian216 has an IP in
// the pfSense's Wi-Fi /16 too), else the first in gateway_ip order; a
// client with no IP gets the ARP table's; the router node counts its
// clients. No node or link is added, and a host only the ARP tables show
// is not drawn; the inventory itself is not changed.
func TestGatewayWLAN(t *testing.T) {
	resetState(t)
	const pf, pfMAC, deb, debMAC = "10.9.0.1", "18:a9:05:00:00:01", "10.20.0.1", "00:0c:29:00:00:02"
	setGatewayIPs([]string{fixedGatewayIP, deb, pf})
	ap := "70:a7:41:00:00:01"
	inventoryMu.Lock()
	managedByMAC = map[string]ManagedView{ap: {Name: "A 1", Kind: "access_point", Clients: []modules.ManagedClient{
		{MAC: "de:ad:00:00:00:01", Name: "Laptop", IP: "10.9.71.5", Kind: "wireless"},
		{MAC: "de:ad:00:00:00:02", Name: "phone", Kind: "wireless"},                   // no IP from the controller
		{MAC: "de:ad:00:00:00:03", Name: "tablet", IP: "10.50.0.7", Kind: "wireless"}, // a subnet neither gateway's IP is in
		{MAC: "de:ad:00:00:00:04", Name: "printer", IP: "10.9.72.4", Kind: "wired"},
		{MAC: "de:ad:00:00:00:05", Name: "far", IP: "10.9.71.50", Kind: "wireless"}, // in no ARP table
	}}}
	inventoryMu.Unlock()
	t.Cleanup(func() {
		inventoryMu.Lock()
		managedByMAC = map[string]ManagedView{}
		inventoryMu.Unlock()
	})
	arp := []ARPEntry{
		{IPAddress: "10.9.71.5", MACAddress: "de:ad:00:00:00:01"}, {IPAddress: "10.9.71.8", MACAddress: "de:ad:00:00:00:02"},
		{IPAddress: "10.50.0.7", MACAddress: "de:ad:00:00:00:03"}, {IPAddress: "10.9.72.4", MACAddress: "de:ad:00:00:00:04"},
		{IPAddress: "10.9.80.9", MACAddress: "de:ad:00:00:00:09"}, // a host no controller lists
	}
	subnets := []netip.Prefix{netip.MustParsePrefix("10.9.0.0/16"), netip.MustParsePrefix("10.50.0.0/24")}
	gatewayPollsMu.Lock()
	gatewayPolls[pf] = gatewayPoll{Answered: true, ARP: arp, Subnets: subnets}
	gatewayPolls[deb] = gatewayPoll{Answered: true, ARP: arp, Subnets: subnets}
	gatewayPollsMu.Unlock()
	data := GraphData{Nodes: []GraphNode{
		{ID: pfMAC, Group: "router", SysName: "pfSense\n" + pf},
		{ID: debMAC, Group: "router", SysName: "debian216\n" + deb},
		{ID: ap, Group: "access_point"},
	}}
	addManaged(&data)
	addGatewayWLAN(&data)
	var got []string
	for _, c := range data.Nodes[2].Managed.Clients {
		got = append(got, strings.Join([]string{c.Name, c.IP, c.Gateway}, " | "))
	}
	want := []string{"Laptop | 10.9.71.5 | pfSense 10.9.0.1", "phone | 10.9.71.8 | pfSense 10.9.0.1", "tablet | 10.50.0.7 | debian216 10.20.0.1",
		"printer | 10.9.72.4 | ", "far | 10.9.71.50 | "}
	if !slices.Equal(got, want) {
		t.Errorf("clients\n got %q\nwant %q", got, want)
	}
	if w := data.Nodes[0].WLAN; w == nil || w.Clients != 2 {
		t.Errorf("pfSense %+v, want 2 Wi-Fi clients", w)
	}
	if w := data.Nodes[1].WLAN; w == nil || w.Clients != 1 {
		t.Errorf("debian216 %+v, want 1 Wi-Fi client", w)
	}
	if data.Nodes[0].Managed != nil || data.Nodes[1].Managed != nil || len(data.Nodes) != 3 || len(data.Links) != 0 {
		t.Errorf("the gateways got clients, or nodes or links were added: %+v", data)
	}
	if v := managedViewOf(ap); v.Clients[1].IP != "" || v.Clients[0].Gateway != "" {
		t.Errorf("the inventory changed: %+v", v.Clients)
	}

	// The Wi-Fi client's node gets the ARP table's IP and its gateway
	addManagedClients(&data)
	for _, n := range data.Nodes {
		if n.ID == "de:ad:00:00:00:02" && (n.IP != "10.9.71.8" || n.Client == nil || n.Client.Gateway != "pfSense 10.9.0.1") {
			t.Errorf("the client's node %+v", n)
		}
		if n.ID == "de:ad:00:00:00:09" {
			t.Error("a host only the ARP table shows is drawn")
		}
	}
}

// TestManagedAPNodes checks the access points the controllers manage that
// the graph has no node for: a node each (group access_point, its name and
// IP, unreachable when offline), linked by its uplink when that device is a
// node (a switch by its chassis MAC, the parent of a mesh link; a port the
// controller does not name, or names by a MAC, from the switch's FDB),
// else by the switch port its MAC is learned on ([MAC-REF]), else not at
// all; an
// access point the graph has by MAC or IP, and a device of another kind,
// get no node.
func TestManagedAPNodes(t *testing.T) {
	resetState(t)
	const sw = "4c:ae:a3:50:00:01"
	const apUp, apMesh, apFDB, apNone, apInGraph, apByIP, usw = "70:a7:41:50:00:01", "70:a7:41:50:00:02", "70:a7:41:50:00:03",
		"70:a7:41:50:00:04", "70:a7:41:50:00:05", "70:a7:41:50:00:06", "70:a7:41:50:00:09"
	const apNoPort, apMACPort = "70:a7:41:50:00:07", "70:a7:41:50:00:08"
	snapshot := map[string]*DeviceData{"10.9.50.1": {IP: "10.9.50.1", ChassisID: sw, Interfaces: gigabitPorts(10, nil),
		MACTable: slices.Concat(macEntries(5, apFDB, "de:ad:00:50:00:01", "de:ad:00:50:00:02"), macEntries(6, apUp),
			macEntries(8, apNoPort, "de:ad:00:50:00:03", "de:ad:00:50:00:04"), macEntries(9, apNoPort, "de:ad:00:50:00:05"))}}
	switchMACs := buildSwitchOwnMACs(snapshot)
	graph := NewDJGraph()
	for _, id := range []string{sw, apInGraph, "10.9.50.77"} {
		graph.AddNode(id)
	}
	graph.graphSwitches = map[string]bool{sw: true}
	inventoryMu.Lock()
	inventoryNotices = map[string]string{}
	managedByMAC = map[string]ManagedView{
		apUp:      {Name: "A up", IP: "10.9.50.11", Kind: "access_point", Source: "UniFi", Controller: "10.9.60.5", Uplink: &modules.ManagedUplink{MAC: "4C:AE:A3:50:00:01", Port: "GigabitEthernet1/0/12", LocalPort: "eth0"}},
		apMesh:    {Name: "A mesh", Kind: "access_point", Uplink: &modules.ManagedUplink{MAC: apUp, Wireless: true}},
		apFDB:     {Name: "A fdb", IP: "10.9.50.13", Kind: "access_point"},
		apNone:    {Name: "A none", Kind: "access_point", State: "OFFLINE", Uplink: &modules.ManagedUplink{MAC: "00:11:22:33:44:55", Port: "3"}},
		apInGraph: {Name: "A in graph", Kind: "access_point"},
		apByIP:    {Name: "A by IP", IP: "10.9.50.77", Kind: "access_point"},
		usw:       {Name: "USW", Kind: "switch"},
		apNoPort:  {Name: "A no port", Kind: "access_point", Uplink: &modules.ManagedUplink{MAC: sw, LocalPort: "eth0"}},
		apMACPort: {Name: "A MAC port", Kind: "access_point", Uplink: &modules.ManagedUplink{MAC: sw, Port: "AA:BB:CC:DD:EE:FF"}},
	}
	inventoryMu.Unlock()
	t.Cleanup(func() {
		inventoryMu.Lock()
		managedByMAC, inventoryNotices = map[string]ManagedView{}, map[string]string{}
		inventoryMu.Unlock()
	})
	out := captureStdout(t, func() { addManagedAPNodes(graph, snapshot, switchMACs) })
	data := graph.GetGraphData()
	groups := map[string]string{}
	for _, n := range data.Nodes {
		groups[n.ID] = n.Group + " " + strings.ReplaceAll(n.SysName, "\n", "/")
		if n.Unreachable {
			groups[n.ID] += " unreachable"
		}
	}
	for mac, want := range map[string]string{apUp: "access_point A up/10.9.50.11", apMesh: "access_point A mesh", apFDB: "access_point A fdb/10.9.50.13",
		apNone: "access_point A none unreachable"} {
		if groups[mac] != want {
			t.Errorf("node %s: %q, want %q", mac, groups[mac], want)
		}
	}
	for _, mac := range []string{apByIP, usw} {
		if _, ok := groups[mac]; ok {
			t.Errorf("a node for %s", mac)
		}
	}
	if graph.graphManaged[apInGraph] {
		t.Error("the access point the graph has is changed")
	}
	var links []string
	for _, l := range data.Links {
		links = append(links, l.Source+">"+l.Target+" "+l.Label)
	}
	slices.Sort(links)
	want := []string{sw + ">" + apUp + " GigabitEthernet1/0/12|eth0", sw + ">" + apFDB + " GE1/0/5 [MAC-REF]|",
		sw + ">" + apNoPort + " GE1/0/9|eth0", sw + ">" + apMACPort + " |", apUp + ">" + apMesh + " mesh|mesh"}
	if !slices.Equal(links, want) {
		t.Errorf("links\n got %q\nwant %q", links, want)
	}
	if !strings.Contains(out, "6 access points no switch shows drawn from their controllers: 4 linked by their uplink, 1 by the FDB, 1 not linked") ||
		!strings.Contains(out, "A up "+apUp+" (10.9.50.11) drawn from UniFi 10.9.60.5, linked by its uplink "+sw+" GigabitEthernet1/0/12\n") ||
		!strings.Contains(out, "A fdb "+apFDB+" (10.9.50.13) drawn from  , linked by the FDB of 10.9.50.1 GE1/0/5 (3 MACs on the port)") {
		t.Errorf("log %q", out)
	}
}

// TestManagedVMNames checks the virtual machines a vCenter lists: the node
// of each gets what vCenter tells of it (its name, guest OS, power, its
// host's name), whether or not its host is a node, and no VM gets a node
// or a link of its own (the graph places VMs by the FDBs).
func TestManagedVMNames(t *testing.T) {
	resetState(t)
	const esxA, esxB = "48:df:37:00:0a:01", "48:df:37:00:0b:01"
	inventoryMu.Lock()
	managedByMAC = map[string]ManagedView{
		esxA: {Name: "esx-a.lab.local", Kind: "hypervisor", Clients: []modules.ManagedClient{
			{MAC: "00:50:56:AA:00:01", Name: "Web & App", IP: "10.9.1.10", Kind: "vm", OS: "Ubuntu Linux (64-bit)", Power: "On"},
			{MAC: "00:50:56:aa:00:05", Name: "not a node", Kind: "vm"},
		}},
		esxB: {Name: "esx-b.lab.local", Kind: "hypervisor", Clients: []modules.ManagedClient{{MAC: "00:0c:29:aa:00:03", Name: "db", Kind: "vm", Power: "Off"}}},
	}
	inventoryMu.Unlock()
	t.Cleanup(func() {
		inventoryMu.Lock()
		managedByMAC = map[string]ManagedView{}
		inventoryMu.Unlock()
	})
	data := GraphData{
		Nodes: []GraphNode{{ID: esxA, Group: "hypervisor"}, {ID: "00:50:56:aa:00:01", Group: "vm"}, {ID: "00:0c:29:aa:00:03", Group: "vm"}},
		Links: []GraphLink{{Source: esxA, Target: "00:50:56:aa:00:01", Label: "vNIC"}},
	}
	addManaged(&data)
	addManagedClients(&data)
	addManagedVMNames(&data)
	if len(data.Nodes) != 3 || len(data.Links) != 1 {
		t.Errorf("nodes %+v links %+v: want none added", data.Nodes, data.Links)
	}
	if c := data.Nodes[1].Client; c == nil || c.Name != "Web & App" || c.Device != "esx-a.lab.local" || c.OS != "Ubuntu Linux (64-bit)" {
		t.Errorf("the VM of esx-a %+v", c)
	}
	if c := data.Nodes[2].Client; c == nil || c.Name != "db" || c.Device != "esx-b.lab.local" || c.Power != "Off" {
		t.Errorf("the VM of esx-b, no node: %+v", c)
	}
	if m := data.Nodes[0].Managed; m == nil || m.Name != "esx-a.lab.local" || len(m.Clients) != 2 {
		t.Errorf("the host %+v", m)
	}
}

// TestManagedPhones checks the phones a PBX (Kerio Operator) lists: one by
// its MAC goes to the node of that MAC, one with no MAC to the node of its
// IP (the node's IP or a label line), but never a switch's or router's;
// an endpoint a PBX names a phone is one, a camera stays one.
func TestManagedPhones(t *testing.T) {
	resetState(t)
	inventoryMu.Lock()
	inventories = map[string]inventoryRecord{"keriooperator|10.9.16.97": {Module: "keriooperator", IP: "10.9.16.97", Time: time.Now(),
		Inventory: modules.Inventory{Devices: []modules.ManagedDevice{
			{MAC: "00:0B:82:AA:BB:01", Name: "101, 102 · Ali Valiyev", Model: "Grandstream GXP1610", State: "ONLINE", Kind: "phone"},
			{IP: "10.9.16.40", Name: "305 · Lola", State: "ONLINE", Kind: "phone"},
			{IP: "10.9.16.41", Name: "306", State: "OFFLINE", Kind: "phone"},
			{IP: "10.9.16.42", Name: "307", Kind: "phone"},
			{Name: "no address", Kind: "phone"},
		}}}}
	inventoryIndex()
	inventoryMu.Unlock()
	t.Cleanup(func() {
		inventoryMu.Lock()
		inventories, managedByMAC, managedByIP = map[string]inventoryRecord{}, map[string]ManagedView{}, map[string]ManagedView{}
		inventoryMu.Unlock()
	})
	data := GraphData{Nodes: []GraphNode{
		{ID: "00:0b:82:aa:bb:01", Group: "phone"},
		{ID: "aa:00:00:00:00:40", Group: "endpoint", IP: "10.9.16.40"},
		{ID: "aa:00:00:00:00:41", Group: "camera", SysName: "[ENDPOINT] Hikvision\n10.9.16.41"},
		{ID: "4c:ae:a3:00:00:42", Group: "switch", IP: "10.9.16.42"},
		{ID: "aa:00:00:00:00:99", Group: "endpoint", IP: "10.9.16.99"},
	}}
	addManaged(&data)
	want := []struct{ name, group string }{
		{"101, 102 · Ali Valiyev", "phone"}, {"305 · Lola", "phone"}, {"306", "camera"}, {"", "switch"}, {"", "endpoint"},
	}
	for i, w := range want {
		n := data.Nodes[i]
		name := ""
		if n.Managed != nil {
			name = n.Managed.Name
			if n.Managed.Source != "Kerio Operator" || n.Managed.Controller != "10.9.16.97" {
				t.Errorf("%s: managed by %q %q", n.ID, n.Managed.Source, n.Managed.Controller)
			}
		}
		if name != w.name || n.Group != w.group {
			t.Errorf("%s: managed %q group %q, want %q %q", n.ID, name, n.Group, w.name, w.group)
		}
	}
}
