package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"lldp_scanner/modules"
)

// TestClassifyNode pins classifyNode's order of evidence, a case per rule,
// with the quirks of today's rules (a polled device is grouped by its name
// words only).
func TestClassifyNode(t *testing.T) {
	for _, c := range []struct {
		ev   nodeEvidence
		want string
	}{
		{nodeEvidence{ID: "10.0.0.1", Router: true, AP: true, Polled: true}, "router"},
		{nodeEvidence{ID: "f0:9f:c2:00:00:01", AP: true, Polled: true, Info: "[LLDP-EP] U6"}, "access_point"},
		{nodeEvidence{ID: "10.0.0.2", Polled: true}, "switch"},
		{nodeEvidence{ID: "10.0.0.3", Polled: true, Info: "Server-room switch"}, "server"},
		{nodeEvidence{ID: "10.0.0.4", Polled: true, Info: "Cisco ISR router"}, "switch"},
		{nodeEvidence{ID: "10.0.0.5", Polled: true, Info: "[ENDPOINT] x", ESXi: true}, "switch"},
		{nodeEvidence{ID: "00:50:56:00:00:01", ESXi: true, Info: "[WiFi]\n[BMC]", VoIP: true}, "hypervisor"},
		{nodeEvidence{ID: "da:00:00:00:00:01", Info: "[WiFi]", VoIP: true}, "wifi_random"},
		{nodeEvidence{ID: "c0:74:ad:00:00:01", Info: "[LLDP-EP] GXP1610", VoIP: true, Category: "camera"}, "phone"},
		{nodeEvidence{ID: "c0:51:7e:00:00:01", Info: "[LLDP-EP] cam", Category: "camera"}, "camera"},
		{nodeEvidence{ID: "00:1b:21:00:00:01", Info: "[ENDPOINT]", Category: "network"}, "endpoint"},
		{nodeEvidence{ID: "00:1b:21:00:00:02", Info: "[ENDPOINT]", Category: "endpoint"}, "endpoint"},
		{nodeEvidence{ID: "00:1b:21:00:00:03", Info: "[ENDPOINT]\n[HUB]"}, "endpoint"},
		{nodeEvidence{ID: "hub-10.0.0.2-p8", Info: "[MINIHUB] 30 MACs\n[HUB]"}, "minihub"},
		{nodeEvidence{ID: "hub-10.0.0.2-p9", Info: "[HUB] Unmanaged\n2 devices"}, "hub"},
		{nodeEvidence{ID: "hub-reception"}, "unknown"}, // an id is no tag
		{nodeEvidence{ID: "x", Info: "[HUB] Unmanaged"}, "hub"},
		{nodeEvidence{ID: "x", Info: "[BMC] iLO\n[HYPERVISOR]"}, "bmc"},
		{nodeEvidence{ID: "bmc-1"}, "unknown"},                        // no id prefix
		{nodeEvidence{ID: "vm-backup", Info: "Backup box"}, "switch"}, // an LLDP name
		{nodeEvidence{ID: "x", Info: "[HYPERVISOR] VMware ESXi\n[VM]"}, "hypervisor"},
		{nodeEvidence{ID: "hyp-10.0.0.2-ge1_0_2", Info: "[HYPERVISOR] VMware ESXi\n2 VMs on ge1/0/2"}, "hypervisor"},
		{nodeEvidence{ID: "x", Info: "[VM] win-22"}, "vm"},
		{nodeEvidence{ID: "vm-1"}, "unknown"},
		{nodeEvidence{ID: "linux-box"}, "server"},
		{nodeEvidence{ID: "x", Info: "HPE 5130"}, "switch"},
		{nodeEvidence{ID: "edge-router"}, "router"},
		{nodeEvidence{ID: "x", Info: "something"}, "switch"},
		{nodeEvidence{ID: "x"}, "unknown"},
	} {
		if got := classifyNode(labelEvidence(c.ev), ClassifySettings{}); got != c.want {
			t.Errorf("classifyNode(%+v) = %q, want %q", c.ev, got, c.want)
		}
	}

	// LLDP capabilities (rules.LLDPCaps): the vendor's kind first, then an
	// access point, then a bridge or router that is no phone
	lldp := ClassifySettings{LLDPCaps: true}
	for _, c := range []struct {
		ev        nodeEvidence
		want, off string
	}{
		{nodeEvidence{ID: "4c:ae:a3:27:83:4a", Info: "[LLDP-EP] HPE\nATS234", Category: "network", LLDPCaps: 0x28}, "lldp_switch", "endpoint"},
		{nodeEvidence{ID: "58:94:80:00:be:61", Info: "[LLDP-EP]\npublic", LLDPCaps: 0x28}, "lldp_switch", "endpoint"},
		{nodeEvidence{ID: "e0:d9:e3:ee:19:c0", Info: "[LLDP-EP]", LLDPCaps: 0x20}, "lldp_switch", "endpoint"},
		{nodeEvidence{ID: "68:cc:ae:96:e5:e8", Info: "[LLDP-EP] Fortinet", Category: "network", LLDPCaps: 0x08}, "lldp_switch", "endpoint"},
		{nodeEvidence{ID: "72:a7:41:9a:65:6e", Info: "[LLDP-EP]\nA1qavat124", LLDPCaps: 0x38}, "access_point", "endpoint"},
		{nodeEvidence{ID: "70:a7:41:a8:8c:9b", Info: "[LLDP-EP] Ubiquiti\nU6-LR", Category: "access_point", LLDPCaps: 0x28}, "access_point", "access_point"},
		{nodeEvidence{ID: "00:1b:21:00:00:04", Info: "[LLDP-EP]", LLDPCaps: 0x24}, "endpoint", "endpoint"},
		{nodeEvidence{ID: "00:1b:21:00:00:05", Info: "[LLDP-EP]"}, "endpoint", "endpoint"},
		{nodeEvidence{ID: "c0:74:ad:00:00:02", Info: "[LLDP-EP]", VoIP: true, LLDPCaps: 0x24}, "phone", "phone"},
		{nodeEvidence{ID: "10.0.0.6", Polled: true, LLDPCaps: 0x38}, "switch", "switch"},
	} {
		if got := classifyNode(labelEvidence(c.ev), lldp); got != c.want {
			t.Errorf("classifyNode(%+v, lldpCaps) = %q, want %q", c.ev, got, c.want)
		}
		if got := classifyNode(labelEvidence(c.ev), ClassifySettings{}); got != c.off {
			t.Errorf("classifyNode(%+v) = %q, want %q", c.ev, got, c.off)
		}
	}

	// A smartphone maker's OUI (rules.MobileGroup): mobile, else a phone as
	// before; an IP phone is a phone either way
	mobile := ClassifySettings{MobileGroup: true}
	for _, c := range []struct {
		ev        nodeEvidence
		want, off string
	}{
		{nodeEvidence{ID: "3c:22:fb:9b:9d:cd", Info: "[ENDPOINT] Apple", Category: "mobile"}, "mobile", "phone"},
		{nodeEvidence{ID: "28:6c:07:00:00:01", Info: "[LLDP-EP] Xiaomi", Category: "mobile"}, "mobile", "phone"},
		{nodeEvidence{ID: "c0:74:ad:00:00:03", Info: "[ENDPOINT] Grandstream", Category: "phone"}, "phone", "phone"},
		{nodeEvidence{ID: "3c:22:fb:00:00:02", Info: "[LLDP-EP]", VoIP: true, Category: "mobile"}, "phone", "phone"},
		{nodeEvidence{ID: "3c:22:fb:00:00:03", Info: "[WiFi]", Category: "mobile"}, "wifi_random", "wifi_random"},
	} {
		if got := classifyNode(labelEvidence(c.ev), mobile); got != c.want {
			t.Errorf("classifyNode(%+v, mobileGroup) = %q, want %q", c.ev, got, c.want)
		}
		if got := classifyNode(labelEvidence(c.ev), ClassifySettings{}); got != c.off {
			t.Errorf("classifyNode(%+v) = %q, want %q", c.ev, got, c.off)
		}
	}

	for _, c := range []struct{ group, kind, want string }{
		{"endpoint", "phone", "phone"}, {"unknown", "phone", "phone"}, {"camera", "phone", "camera"},
		{"switch", "phone", "switch"}, {"endpoint", "access_point", "endpoint"}, {"endpoint", "", "endpoint"},
	} {
		if got := managedGroup(c.group, c.kind); got != c.want {
			t.Errorf("managedGroup(%q, %q) = %q, want %q", c.group, c.kind, got, c.want)
		}
	}
}

// TestLLDPCapsGroups builds a graph with unpolled LLDP neighbors of each
// kind (the network's: a PiXiETECH and an Eltex switch, a UniFi access
// point with a locally administered MAC, a U6-LR advertising no access point
// bit, a phone, a neighbor of unknown capabilities) and checks their groups
// with the LLDP capabilities rule on and off.
func TestLLDPCapsGroups(t *testing.T) {
	resetState(t)
	sw := &DeviceData{
		IP: "10.9.96.1", SysName: "sw-core", ChassisID: "18:56:44:00:01:01",
		BridgePortIfIndex: map[int]int{},
	}
	neighbors := []struct {
		chassis, name, desc string
		caps                uint8
	}{
		{"58 94 80 00 BE 61", "public", "PiXiETECH(tm) PXT-S2790G-24FX Software", 0x28},
		{"E0 D9 E3 EE 19 C0", "", "", 0x20},
		{"72 A7 41 9A 65 6E", "A1qavat124", "U6-LR, 6.7.57.15670", 0x38},
		{"70 A7 41 A8 8C 9B", "U6-LR", "U6-LR, 5.60.8.12971", 0x28},
		{"00 1B 21 00 02 01", "desk", "", 0x24},
		{"00 1B 21 00 02 02", "pc", "", 0},
	}
	for i, n := range neighbors {
		port := 10 + i
		sw.Interfaces = append(sw.Interfaces, InterfaceData{IfIndex: port, IfDescr: fmt.Sprintf("\"GigabitEthernet0/0/%d\"", i+1), IfOperStatus: 1})
		sw.BridgePortIfIndex[i+1] = port
		sw.Neighbors = append(sw.Neighbors, LLDPNeighbor{LocalPortNum: port, RemIndex: 1,
			RemChassisIdSubtype: 4, RemChassisId: n.chassis, RemPortIdSubtype: 5, RemPortId: `"eth0"`,
			RemSysName: n.name, RemSysDesc: n.desc, RemSysCapEnabled: n.caps})
	}
	g := buildGraphFromSnapshot(map[string]*DeviceData{sw.IP: sw})

	want := map[string][2]string{ // on, off
		"58:94:80:00:be:61": {"lldp_switch", "endpoint"},
		"e0:d9:e3:ee:19:c0": {"lldp_switch", "endpoint"},
		"72:a7:41:9a:65:6e": {"access_point", "endpoint"},
		"70:a7:41:a8:8c:9b": {"access_point", "access_point"},
		"00:1b:21:00:02:01": {"phone", "phone"}, // the voip engine: telephone bit
		"00:1b:21:00:02:02": {"endpoint", "endpoint"},
	}
	for i, rules := range []ClassifySettings{{LLDPCaps: true}, {}} {
		currentSettingsMutex.Lock()
		currentSettings.Classify = rules
		currentSettingsMutex.Unlock()
		groups := map[string]string{}
		for _, n := range g.GetGraphData().Nodes {
			groups[n.ID] = n.Group
		}
		for id, w := range want {
			if groups[id] != w[i] {
				t.Errorf("%+v: %s is %q, want %q", rules, id, groups[id], w[i])
			}
		}
	}
}

// TestLLDPHubs builds a switch whose ports have several LLDP neighbors and
// checks what each gets with the Classification choices lldpHubs,
// apHubAlert and wifiClientsCountOnly: Windows PCs (their own LLDP driver:
// hostname chassis, MAC port) and a device without LLDP behind a Shadow-IT
// hub, UniFi access points behind an AP hub with their clients counted, a
// PC behind a phone, an unpolled switch's port left as it was, and a
// UAP-AC-Mesh-Pro behind another one's pass-through port (its controller
// tells) left as it was; on ports with access points and other devices,
// the AP hub of a majority of access points (a Wi-Fi laptop's LLDP passed
// on) and a hub whose randomised MACs are counted, not drawn.
func TestLLDPHubs(t *testing.T) {
	resetState(t)
	const (
		pc1, pc2, pc3, other = "00:1b:21:0a:00:01", "00:1b:21:0a:00:02", "00:1b:21:0a:00:03", "00:1b:21:0a:00:04"
		ap1, ap2, ap3        = "9c:05:d6:31:89:c1", "9c:05:d6:31:89:c2", "9c:05:d6:31:89:c3"
		client1, client2     = "da:00:00:0a:00:01", "00:1b:21:0a:00:05"
		phone, deskPC        = "c0:74:ad:90:01:8e", "00:1b:21:0a:00:06"
		hpe, behindHPE       = "4c:ae:a3:27:83:4a", "00:1b:21:0a:00:07"
		mesh1, mesh2         = "78:45:58:73:0f:69", "ac:8b:a9:70:a9:66"
		ap6a, ap6b, laptop   = "9c:05:d6:31:89:d1", "9c:05:d6:31:89:d2", "00:1b:21:0a:00:08"
		ap7, pc7a, pc7b, rnd = "9c:05:d6:31:89:e1", "00:1b:21:0a:00:09", "00:1b:21:0a:00:0a", "da:00:00:0a:00:02"
	)
	sw := &DeviceData{IP: "10.9.97.1", SysName: "sw-access", ChassisID: "18:56:44:00:02:01"}
	for port := 1; port <= 7; port++ {
		sw.Interfaces = append(sw.Interfaces, InterfaceData{IfIndex: port, IfDescr: fmt.Sprintf("\"GigabitEthernet0/0/%d\"", port), IfOperStatus: 1})
	}
	pc := func(port int, host, mac string) LLDPNeighbor {
		return LLDPNeighbor{LocalPortNum: port, RemIndex: 1, RemChassisIdSubtype: 7, RemChassisId: `"` + host + `"`,
			RemPortIdSubtype: 3, RemPortId: mac}
	}
	byChassis := func(port int, mac, name, desc string, caps uint8) LLDPNeighbor {
		return LLDPNeighbor{LocalPortNum: port, RemIndex: 1, RemChassisIdSubtype: 4, RemChassisId: mac,
			RemPortIdSubtype: 5, RemPortId: `"eth0"`, RemSysName: name, RemSysDesc: desc, RemSysCapEnabled: caps}
	}
	sw.Neighbors = []LLDPNeighbor{
		pc(1, "desktop-a", pc1), pc(1, "desktop-b", pc2), pc(1, "desktop-c", pc3),
		byChassis(2, ap1, "A1", "U6-Pro, 6.8.2.15592", 0x38), byChassis(2, ap2, "A2", "U6-Pro, 6.8.2.15592", 0x38),
		byChassis(2, ap3, "A3", "U6-LR, 5.60.8.12971", 0x28),
		byChassis(3, phone, "GXP1610_"+phone, "GXP1610 1.0.7.13", 0x24), pc(3, "desk", deskPC),
		byChassis(4, hpe, "ATS234", "HPE Comware Platform Software", 0x28), pc(4, "behind", behindHPE),
		byChassis(5, mesh1, "Sportzal", "UAP-AC-Mesh-Pro, 6.8.2.15592", 0x38), byChassis(5, mesh2, "Sportzal", "UAP-AC-Mesh-Pro, 6.8.2.15592", 0x38),
		byChassis(6, ap6a, "C1", "U6-Pro", 0x38), byChassis(6, ap6b, "C2", "U6-Pro", 0x38), pc(6, "laptop", laptop),
		byChassis(7, ap7, "D1", "U6-Pro", 0x38), pc(7, "desk-a", pc7a), pc(7, "desk-b", pc7b),
	}
	for _, e := range []struct {
		port int
		mac  string
	}{{1, pc1}, {1, pc2}, {1, other}, {2, ap1}, {2, client1}, {2, client2}, {3, phone}, {3, deskPC}, {4, behindHPE},
		{6, client1}, {7, rnd}, {7, client2}} {
		sw.MACTable = append(sw.MACTable, MACEntry{PortNumber: e.port, MACAddress: e.mac})
	}
	src := graphDeviceNodeID(sw)
	hub := func(port int) string { return fmt.Sprintf("hub-%s-p%d", src, port) }
	inventoryMu.Lock()
	inventories = map[string]inventoryRecord{"unificontroller|10.9.97.5": {Module: "unificontroller", IP: "10.9.97.5", Time: time.Now(),
		Inventory: modules.Inventory{Devices: []modules.ManagedDevice{
			{MAC: mesh1, Name: "Sportzal", Kind: "access_point", Uplink: &modules.ManagedUplink{MAC: "18:56:44:00:02:01"}},
			{MAC: mesh2, Name: "Sportzal", Kind: "access_point", Uplink: &modules.ManagedUplink{MAC: "78:45:58:73:0F:69", LocalPort: "1"}},
			{MAC: ap1, Name: "A1", Kind: "access_point", Uplink: &modules.ManagedUplink{MAC: "18:56:44:00:02:01"}},
		}}}}
	inventoryIndex()
	inventoryMu.Unlock()
	t.Cleanup(func() {
		inventoryMu.Lock()
		inventories, managedByMAC, managedByIP = map[string]inventoryRecord{}, map[string]ManagedView{}, map[string]ManagedView{}
		inventoryMu.Unlock()
	})

	type view struct {
		groups map[string]string
		links  map[[2]string]bool
		labels map[string]string
		kinds  map[int]fdbPortKind
	}
	build := func(rules ClassifySettings) view {
		currentSettingsMutex.Lock()
		currentSettings.Classify = rules
		currentSettingsMutex.Unlock()
		v := view{map[string]string{}, map[[2]string]bool{}, map[string]string{}, map[int]fdbPortKind{}}
		data := buildGraphFromSnapshot(map[string]*DeviceData{sw.IP: sw}).GetGraphData()
		for _, n := range data.Nodes {
			v.groups[n.ID], v.labels[n.ID] = n.Group, n.SysName
		}
		for _, l := range data.Links {
			v.links[[2]string{l.Source, l.Target}] = true
		}
		for _, p := range fdbPorts(sw, buildSwitchOwnMACs(map[string]*DeviceData{sw.IP: sw})) {
			v.kinds[p.Port] = p.Kind
		}
		return v
	}
	linked := func(v view, a, b string) bool { return v.links[[2]string{a, b}] }

	v := build(DefaultClassifySettings())
	if v.groups[hub(1)] != "hub" || v.kinds[1] != fdbHub || v.labels[hub(1)] != "[HUB] Unmanaged\n4 devices" {
		t.Errorf("PC port: %q %v %q", v.groups[hub(1)], v.kinds[1], v.labels[hub(1)])
	}
	for _, m := range []string{pc1, pc2, pc3, other} {
		if !linked(v, hub(1), m) || linked(v, src, m) {
			t.Errorf("PC port: %s is not behind the hub only", m)
		}
	}
	if v.groups[hub(2)] != "ap_hub" || v.kinds[2] != fdbAPHub || v.labels[hub(2)] != "[APHUB] AP hub\n3 access points, 2 clients" {
		t.Errorf("AP port: %q %v %q", v.groups[hub(2)], v.kinds[2], v.labels[hub(2)])
	}
	for _, m := range []string{ap1, ap2, ap3} {
		if !linked(v, hub(2), m) || linked(v, src, m) {
			t.Errorf("AP port: %s is not behind the AP hub only", m)
		}
	}
	if _, ok := v.groups[client1]; ok {
		t.Errorf("AP port: client %s is drawn", client1)
	}
	if !linked(v, src, phone) || !linked(v, phone, deskPC) || linked(v, src, deskPC) || v.groups[hub(3)] != "" {
		t.Errorf("phone port: the PC is not behind the phone")
	}
	if !linked(v, src, hpe) || !linked(v, src, behindHPE) || v.groups[hub(4)] != "" {
		t.Errorf("unpolled switch port: changed")
	}
	if !linked(v, src, mesh1) || !linked(v, src, mesh2) || v.groups[hub(5)] != "" {
		t.Errorf("pass-through AP port: changed")
	}
	if v.groups[hub(6)] != "ap_hub" || v.labels[hub(6)] != "[APHUB] AP hub\n2 access points, 1 other device, 1 client" || !linked(v, hub(6), laptop) {
		t.Errorf("AP majority port: %q %q", v.groups[hub(6)], v.labels[hub(6)])
	}
	if v.groups[hub(7)] != "hub" || v.labels[hub(7)] != "[HUB] Unmanaged\n5 devices" || linked(v, hub(7), rnd) || !linked(v, hub(7), client2) {
		t.Errorf("hub with an access point: %q %q, randomised MAC drawn %v", v.groups[hub(7)], v.labels[hub(7)], linked(v, hub(7), rnd))
	}

	rules := DefaultClassifySettings()
	rules.APHubAlert = true
	if v := build(rules); v.groups[hub(2)] != "hub" || v.kinds[2] != fdbHub {
		t.Errorf("apHubAlert: AP port %q %v", v.groups[hub(2)], v.kinds[2])
	}
	rules = DefaultClassifySettings()
	rules.WiFiClientsCountOnly = false
	if v := build(rules); !linked(v, hub(2), client1) || !linked(v, hub(2), client2) {
		t.Errorf("wifiClientsCountOnly off: the clients are not drawn under the AP hub")
	}
	rules = DefaultClassifySettings()
	rules.LLDPHubs = false
	v = build(rules)
	for _, m := range []string{pc1, pc2, pc3, ap1, ap2, ap3, phone, deskPC} {
		if !linked(v, src, m) {
			t.Errorf("lldpHubs off: %s is not linked to the switch", m)
		}
	}
	if len(v.kinds) != 0 || v.groups[hub(1)] != "" || v.groups[hub(2)] != "" {
		t.Errorf("lldpHubs off: hubs %v", v.kinds)
	}
}

// TestControllerKinds: with rules.ControllerKindWins, what a Credentials
// login for the node's IP declares, else the kind a controller manages its
// MAC as, comes after the gateways, the controller's access points and the
// polled devices, above the tags and the OUI; a controller's device known
// by the node's IP only makes an endpoint a phone. Off, none counts.
func TestControllerKinds(t *testing.T) {
	on := ClassifySettings{ControllerKindWins: true, MobileGroup: true}
	off := ClassifySettings{MobileGroup: true}
	for _, c := range []struct {
		ev        nodeEvidence
		want, off string
	}{
		{nodeEvidence{ID: "10.0.0.1", Router: true, Declared: []string{"linux"}, Managed: "phone"}, "router", "router"},
		{nodeEvidence{ID: "10.0.0.7", Polled: true, Declared: []string{"esxi"}, Managed: "access_point"}, "switch", "switch"},
		// a vCenter host's VMkernel NIC: a VMware OUI
		{nodeEvidence{ID: "00:50:56:6a:00:01", Info: "[VM] 🐧 Linux", Category: "vm", Managed: "hypervisor"}, "hypervisor", "vm"},
		// a UniFi access point's locally administered MAC
		{nodeEvidence{ID: "72:a7:41:00:00:01", Info: "[WiFi]", Managed: "access_point"}, "access_point", "wifi_random"},
		{nodeEvidence{ID: "f0:9f:c2:00:00:02", Info: "[LLDP-EP] Ubiquiti", Category: "access_point", Managed: "switch"}, "lldp_switch", "access_point"},
		{nodeEvidence{ID: "f0:9f:c2:00:00:03", Info: "[ENDPOINT] Ubiquiti", Category: "access_point", Managed: "gateway"}, "router", "access_point"},
		{nodeEvidence{ID: "c0:51:7e:00:00:02", Info: "[ENDPOINT] Hikvision", Category: "camera", Managed: "phone"}, "phone", "camera"},
		{nodeEvidence{ID: "00:1b:21:00:00:08", Info: "[BMC] iLO", Managed: "kind-of-no-group"}, "bmc", "bmc"},
		// by the IP only: an endpoint or unknown node only
		{nodeEvidence{ID: "94:c6:91:3f:f8:ee", Info: "[LLDP-EP] EliteGroup\n10.9.16.40", ManagedIP: "phone"}, "phone", "endpoint"},
		{nodeEvidence{ID: "c0:51:7e:00:00:03", Info: "[ENDPOINT] Hikvision\n10.9.16.41", Category: "camera", ManagedIP: "phone"}, "camera", "camera"},
		{nodeEvidence{ID: "3c:22:fb:00:00:04", Info: "[ENDPOINT] Apple\n10.9.16.42", Category: "mobile", ManagedIP: "phone"}, "mobile", "mobile"},
		// the owner's declaration: the first type that names a kind, above a controller's
		{nodeEvidence{ID: "00:1b:21:00:00:07", Info: "[ENDPOINT] Intel\n10.9.0.5", Declared: []string{"vcenter", "esxi"}, Managed: "phone"}, "hypervisor", "endpoint"},
		{nodeEvidence{ID: "00:1b:21:00:00:09", Info: "[ENDPOINT] HPE\n10.9.0.9", Declared: []string{"linux", "ilo"}}, "bmc", "endpoint"},
		{nodeEvidence{ID: "00:50:56:00:00:0b", Info: "[VM] 🐧 Linux\n10.9.0.12", Category: "vm", Declared: []string{"linux", "router"}}, "vm", "vm"},
		{nodeEvidence{ID: "00:1b:21:00:00:0a", Info: "[ENDPOINT]\n10.9.0.10", Declared: []string{"any", "kerio-operator"}}, "endpoint", "endpoint"},
		{nodeEvidence{ID: "e0:d9:e3:00:00:01", Info: "[LLDP-EP] Eltex\n10.9.0.11", Declared: []string{"switch-eltex"}}, "lldp_switch", "endpoint"},
	} {
		if got := classifyNode(labelEvidence(c.ev), on); got != c.want {
			t.Errorf("classifyNode(%+v, controllerKindWins) = %q, want %q", c.ev, got, c.want)
		}
		if got := classifyNode(labelEvidence(c.ev), off); got != c.off {
			t.Errorf("classifyNode(%+v) = %q, want %q", c.ev, got, c.off)
		}
	}

	// Every Credentials device type names a group or, by its list, none;
	// every kind of a managed device names a group
	groups := map[string]bool{}
	for _, d := range deviceGroups {
		groups[d.Key] = true
	}
	for _, o := range credentialTypes {
		g, ok := declaredTypeGroups[o.ID]
		if ok == slices.Contains(declaredTypeNoGroup, o.ID) || ok && !groups[g] {
			t.Errorf("Credentials device type %q: group %q (in declaredTypeGroups %v, in declaredTypeNoGroup %v)",
				o.ID, g, ok, slices.Contains(declaredTypeNoGroup, o.ID))
		}
	}
	for kind, g := range managedKindGroups {
		if !groups[g] {
			t.Errorf("managed kind %q: group %q is no group", kind, g)
		}
	}
}

// TestControllerKindsGraph: GetGraphData, the graph data of the reports,
// the analyzer and Telegram, reads the controllers' inventories and the
// Credentials logins for an IP (not those for a range) when the rule is
// on, and neither when it is off.
func TestControllerKindsGraph(t *testing.T) {
	resetState(t)
	dir := t.TempDir()
	before := secretsDir
	secretsDir = dir
	t.Cleanup(func() { secretsDir = before })
	creds := `{"entries": [
		{"id": "a", "target": {"kind": "ip", "value": "10.9.0.5"}, "protocol": "https", "username": "root", "deviceType": "esxi"},
		{"id": "b", "target": {"kind": "cidr", "value": "10.9.1.0/24"}, "protocol": "https", "username": "admin", "deviceType": "voip-yealink"},
		{"id": "c", "target": {"kind": "ip", "value": "10.9.0.6"}, "protocol": "ssh", "username": "x", "deviceType": "any"}]}`
	if err := os.WriteFile(filepath.Join(dir, "credentials.json"), []byte(creds), 0o600); err != nil {
		t.Fatal(err)
	}
	inventoryMu.Lock()
	inventories = map[string]inventoryRecord{
		"vcenter|10.9.0.2": {Module: "vcenter", IP: "10.9.0.2", Time: time.Now(), Inventory: modules.Inventory{Devices: []modules.ManagedDevice{
			{MAC: "00:50:56:6a:00:01", Name: "esx-1", Kind: "hypervisor"}}}},
		"keriooperator|10.9.16.97": {Module: "keriooperator", IP: "10.9.16.97", Time: time.Now(), Inventory: modules.Inventory{Devices: []modules.ManagedDevice{
			{IP: "10.9.16.40", Name: "305", Kind: "phone"}, {IP: "10.9.16.41", Name: "306", Kind: "phone"},
			{MAC: "C0:51:7E:00:00:09", Name: "307", Kind: "phone"}}}},
		"unificontroller|10.9.97.5": {Module: "unificontroller", IP: "10.9.97.5", Time: time.Now(), Inventory: modules.Inventory{Devices: []modules.ManagedDevice{
			{MAC: "f0:9f:c2:00:00:05", Name: "USW", Kind: "switch"}}}},
	}
	inventoryIndex()
	inventoryMu.Unlock()
	t.Cleanup(func() {
		inventoryMu.Lock()
		inventories, managedByMAC, managedByIP = map[string]inventoryRecord{}, map[string]ManagedView{}, map[string]ManagedView{}
		inventoryMu.Unlock()
	})

	g := NewDJGraph()
	nodes := []struct{ id, info, on, off string }{
		{"00:50:56:6a:00:01", "[VM] 🐧 Linux", "hypervisor", "vm"},
		{"00:1b:21:00:00:40", "[ENDPOINT] Intel\n10.9.16.40", "phone", "endpoint"},
		{"c0:51:7e:00:00:41", "[ENDPOINT] Hikvision\n10.9.16.41", "camera", "camera"},
		{"c0:51:7e:00:00:09", "[ENDPOINT] Hikvision", "phone", "camera"},
		{"f0:9f:c2:00:00:05", "[LLDP-EP] Ubiquiti", "lldp_switch", "access_point"},
		{"00:1b:21:00:00:05", "[ENDPOINT] Intel\n10.9.0.5", "hypervisor", "endpoint"},
		{"00:1b:21:00:01:07", "[ENDPOINT] Intel\n10.9.1.7", "endpoint", "endpoint"},
		{"00:1b:21:00:00:06", "[ENDPOINT] Intel\n10.9.0.6", "endpoint", "endpoint"},
	}
	for _, n := range nodes {
		g.AddNode(n.id)
		setLabel(g, n.id, n.info)
	}
	for _, kindWins := range []bool{true, false} {
		currentSettingsMutex.Lock()
		currentSettings.Classify.ControllerKindWins = kindWins
		currentSettingsMutex.Unlock()
		got := map[string]GraphNode{}
		for _, n := range g.GetGraphData().Nodes {
			got[n.ID] = n
		}
		for _, n := range nodes {
			want := n.off
			if kindWins {
				want = n.on
			}
			if got[n.id].Group != want || got[n.id].NodeType != want || g.determineDeviceGroup(n.id, n.info) != want {
				t.Errorf("controllerKindWins %v: %s group %q type %q, want %q", kindWins, n.id, got[n.id].Group, got[n.id].NodeType, want)
			}
		}
	}
}
