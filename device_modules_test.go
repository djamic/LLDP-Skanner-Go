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
			{MAC: "DE:AD:00:00:00:01", Name: "Laptop", IP: "10.9.71.5", Kind: "wireless"},
			{MAC: "de:ad:00:00:00:02", Name: "de:ad:00:00:00:02", Kind: "wireless"},
			{MAC: "de:ad:00:00:00:03", Name: "phone", Kind: "wireless"},
			{MAC: "de:ad:00:00:00:04", Name: "printer", Kind: "wired"},
			{MAC: ap, Kind: "wireless"},
			{MAC: "de:ad:00:00:00:05", Name: "de:ad:00:00:00:05", IP: "10.9.71.10", Kind: "wireless"},
			{MAC: "de:ad:00:00:00:06", IP: "10.9.71.11", Kind: "wireless"},
		}}}, {ID: "de:ad:00:00:00:03", Group: "wifi_random"}},
		Links: []GraphLink{{Source: "4c:ae:a3:00:00:01", Target: ap}, {Source: "de:ad:00:00:00:03", Target: ap, Label: "x"}},
	}
	addManagedClients(&data)
	nodes := map[string]GraphNode{}
	for _, n := range data.Nodes {
		nodes[n.ID] = n
	}
	if n := nodes["de:ad:00:00:00:01"]; n.Group != "wifi_client" || n.SysName != "Laptop\n10.9.71.5" || n.IP != "10.9.71.5" || n.Label != "Laptop\n10.9.71.5\nde:ad:00:00:00:01" {
		t.Errorf("a new client %+v", n)
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
		ap + ">de:ad:00:00:00:05 WLAN|wlan WLAN wlan", ap + ">de:ad:00:00:00:06 WLAN|wlan WLAN wlan"}
	if !slices.Equal(links, want) {
		t.Errorf("new links %v, want %v (the linked client gets none)", links, want)
	}
	if len(data.Nodes) != 7 {
		t.Errorf("%d nodes, want the 3 and 4 new clients", len(data.Nodes))
	}
}

// TestGatewayWLANHosts checks the WLAN hosts of a gateway: the hosts of
// its ARP table in its subnets that hold a client of a managed device go to
// its router node as clients (source "Gateway ARP", in IP order), named by
// the controller when it lists them on a device the graph has not, and
// addManagedClients draws them with "ARP" links. Left out are the hosts in
// its other subnets, the clients shown under a device of the graph, the
// graph's nodes, the managed devices, the gateway and a repeated or
// unusable MAC.
func TestGatewayWLANHosts(t *testing.T) {
	resetState(t)
	const gw, gwMAC = "10.9.0.1", "00:0c:29:00:00:01"
	setGatewayIPs([]string{fixedGatewayIP, gw})
	ap, apAway := "70:a7:41:00:00:01", "70:a7:41:00:00:02"
	inventoryMu.Lock()
	inventories, managedByMAC = map[string]inventoryRecord{}, map[string]ManagedView{
		ap:     {Name: "A 1", Clients: []modules.ManagedClient{{MAC: "de:ad:00:00:00:01", Name: "Laptop", IP: "10.9.71.5", Kind: "wireless"}}},
		apAway: {Name: "B 2", Clients: []modules.ManagedClient{{MAC: "de:ad:00:00:00:02", Name: "Phone-X", IP: "10.9.71.9", Kind: "wireless"}}},
	}
	inventoryMu.Unlock()
	t.Cleanup(func() {
		inventoryMu.Lock()
		inventories, managedByMAC = map[string]inventoryRecord{}, map[string]ManagedView{}
		inventoryMu.Unlock()
	})
	arp := []ARPEntry{
		{IPAddress: "10.9.80.3", MACAddress: "de:ad:00:00:00:03"},
		{IPAddress: "10.9.71.5", MACAddress: "de:ad:00:00:00:01"}, // shown under the access point
		{IPAddress: "10.9.71.9", MACAddress: "DE:AD:00:00:00:02"}, // its access point is no node
		{IPAddress: "10.9.70.2", MACAddress: "de:ad:00:00:00:04"}, // a node of the graph
		{IPAddress: "10.9.1.2", MACAddress: ap},
		{IPAddress: "10.9.1.3", MACAddress: apAway},
		{IPAddress: "10.9.0.1", MACAddress: gwMAC},
		{IPAddress: "10.20.0.5", MACAddress: "de:ad:00:00:00:05"}, // not in the WLAN
		{IPAddress: "10.9.80.3", MACAddress: "de:ad:00:00:00:03"},
		{IPAddress: "10.9.80.4", MACAddress: "00:00:00:00:00:00"},
		{IPAddress: "10.9.12.1", MACAddress: "de:ad:00:00:00:06"},
	}
	gatewayPollsMu.Lock()
	gatewayPolls[gw] = gatewayPoll{Answered: true, ARP: arp, Subnets: []netip.Prefix{
		netip.MustParsePrefix("10.9.0.0/16"), netip.MustParsePrefix("10.20.0.0/24"), netip.MustParsePrefix("10.9.71.9/32")}}
	gatewayPollsMu.Unlock()
	data := GraphData{Nodes: []GraphNode{
		{ID: gwMAC, Group: "router", SysName: "pfSense\n" + gw},
		{ID: ap, Group: "access_point"},
		{ID: "de:ad:00:00:00:04", Group: "endpoint"},
	}}
	addManaged(&data)
	addGatewayWLANHosts(&data)
	m := data.Nodes[0].Managed
	if m == nil || m.Source != "Gateway ARP" || m.Controller != gw {
		t.Fatalf("the router's view %+v", m)
	}
	var hosts []string
	for _, c := range m.Clients {
		hosts = append(hosts, strings.Join([]string{c.MAC, c.IP, c.Name, c.Kind}, " "))
	}
	if want := []string{"de:ad:00:00:00:06 10.9.12.1  arp", "de:ad:00:00:00:02 10.9.71.9 Phone-X wireless", "de:ad:00:00:00:03 10.9.80.3  arp"}; !slices.Equal(hosts, want) {
		t.Errorf("WLAN hosts %q, want %q", hosts, want)
	}
	addManagedClients(&data)
	var links []string
	for _, l := range data.Links {
		links = append(links, l.Source+">"+l.Target+" "+l.Label)
	}
	if want := []string{gwMAC + ">de:ad:00:00:00:06 ARP|wlan", gwMAC + ">de:ad:00:00:00:02 ARP|wlan", gwMAC + ">de:ad:00:00:00:03 ARP|wlan", ap + ">de:ad:00:00:00:01 WLAN|wlan"}; !slices.Equal(links, want) {
		t.Errorf("links %q, want %q", links, want)
	}

	// No managed client in a subnet of the gateway: no WLAN, no hosts
	inventoryMu.Lock()
	managedByMAC = map[string]ManagedView{ap: {Name: "A 1", Clients: []modules.ManagedClient{{MAC: "de:ad:00:00:00:01", IP: "192.168.5.5"}}}}
	inventoryMu.Unlock()
	data = GraphData{Nodes: []GraphNode{{ID: gwMAC, Group: "router", SysName: "pfSense\n" + gw}}}
	addGatewayWLANHosts(&data)
	if data.Nodes[0].Managed != nil {
		t.Errorf("hosts without a WLAN subnet: %+v", data.Nodes[0].Managed)
	}
}
