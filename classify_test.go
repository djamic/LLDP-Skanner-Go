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

// TestLLDPHubLink: an unmanaged switch on the link between two polled
// switches that passes LLDP on (172.20.230.254 Eth1/0/24 and 172.20.230.40
// GigaEthernet0/25 with the four Sportzal U6 Pro access points, 2026-11-24).
// Both switches see each other and the same access points on the port; the
// controller has them ADOPTING with each other as uplinks (stale). The graph
// draws one hub between the two switches (the same node from both sides),
// the access points under it, and no direct link between the switches, the
// switches and the access points; the port's FDB (everything behind the
// other switch) is not drawn under the hub. A Windows PC on such a link
// makes a Shadow-IT hub whose alerts (one per switch port) point at that
// one node. ONLINE access points with uplinks to each other stay off the
// hub, as before, and so does every neighbor of a port with two polled
// switches.
func TestLLDPHubLink(t *testing.T) {
	resetState(t)
	const (
		coreMAC, accMAC, thirdMAC = "f8:f0:82:00:98:01", "58:94:80:00:98:40", "4c:ae:a3:00:98:50"
		ap1, ap2, ap3, ap4        = "9c:05:d6:31:98:01", "f4:e2:c6:f7:98:02", "9c:05:d6:31:98:03", "f4:e2:c6:f7:98:04"
		pcBehindAcc, pcOnAcc      = "00:1b:21:98:00:01", "00:1b:21:98:00:02"
		winPC, apX                = "00:1b:21:98:00:03", "9c:05:d6:31:98:05"
	)
	ports := func(d *DeviceData, n int) {
		for port := 1; port <= n; port++ {
			d.Interfaces = append(d.Interfaces, InterfaceData{IfIndex: port, IfDescr: fmt.Sprintf("\"Ethernet1/0/%d\"", port), IfOperStatus: 1})
		}
	}
	nb := func(port int, mac, name, desc, farPort string, caps uint8) LLDPNeighbor {
		return LLDPNeighbor{LocalPortNum: port, RemIndex: 1, RemChassisIdSubtype: 4, RemChassisId: mac,
			RemPortIdSubtype: 5, RemPortId: `"` + farPort + `"`, RemSysName: name, RemSysDesc: desc, RemSysCapEnabled: caps}
	}
	win := func(port int) LLDPNeighbor {
		return LLDPNeighbor{LocalPortNum: port, RemIndex: 9, RemChassisIdSubtype: 7, RemChassisId: `"desktop-link"`,
			RemPortIdSubtype: 3, RemPortId: winPC}
	}
	aps := func(port int) []LLDPNeighbor {
		var out []LLDPNeighbor
		for i, mac := range []string{ap1, ap2, ap3, ap4} {
			out = append(out, nb(port, mac, fmt.Sprintf("Sportzal%d", i+1), "U6-Pro, 6.8.2.15592", "eth0", 0x38))
		}
		return out
	}
	fdb := func(d *DeviceData, port int, macs ...string) {
		for _, m := range macs {
			d.MACTable = append(d.MACTable, MACEntry{PortNumber: port, MACAddress: m})
		}
	}
	// core: port 24 to acc (through the AP switch), port 10 to third
	// (through a switch with a Windows PC)
	core := &DeviceData{IP: "10.9.98.254", SysName: "core", ChassisID: coreMAC}
	ports(core, 24)
	core.Neighbors = append(aps(24), nb(24, accMAC, "Switch", "PiXiETECH", "Gig0/25", 0x04),
		nb(10, thirdMAC, "third", "HPE Comware Platform Software", "GigabitEthernet1/0/1", 0x28), win(10))
	fdb(core, 24, accMAC, ap1, ap2, ap3, ap4, pcBehindAcc, pcOnAcc)
	fdb(core, 10, thirdMAC, winPC)
	acc := &DeviceData{IP: "10.9.98.40", SysName: "Switch", ChassisID: accMAC}
	ports(acc, 25)
	acc.Neighbors = append(aps(25), nb(25, coreMAC, "", "", "Ethernet1/0/24", 0x04))
	fdb(acc, 25, coreMAC, ap1, ap2, ap3, ap4)
	fdb(acc, 3, pcOnAcc)
	third := &DeviceData{IP: "10.9.98.50", SysName: "third", ChassisID: thirdMAC}
	ports(third, 24)
	third.Neighbors = []LLDPNeighbor{nb(1, coreMAC, "", "", "Ethernet1/0/10", 0x04), win(1)}
	fdb(third, 1, coreMAC, winPC)
	snapshot := map[string]*DeviceData{core.IP: core, acc.IP: acc, third.IP: third}
	coreID, accID, thirdID := graphDeviceNodeID(core), graphDeviceNodeID(acc), graphDeviceNodeID(third)

	setInventory := func(state string) {
		var devs []modules.ManagedDevice
		uplinks := map[string]string{ap1: ap4, ap2: ap1, ap3: ap1, ap4: ap1} // ap1 and ap4 each other's
		for _, mac := range []string{ap1, ap2, ap3, ap4} {
			devs = append(devs, modules.ManagedDevice{MAC: mac, Name: "Sportzal", Kind: "access_point", State: state,
				Uplink: &modules.ManagedUplink{MAC: uplinks[mac], LocalPort: "1"}})
		}
		inventoryMu.Lock()
		inventories = map[string]inventoryRecord{"unificontroller|10.9.98.2": {Module: "unificontroller", IP: "10.9.98.2", Time: time.Now(),
			Inventory: modules.Inventory{Devices: devs}}}
		inventoryIndex()
		inventoryMu.Unlock()
	}
	t.Cleanup(func() {
		inventoryMu.Lock()
		inventories, managedByMAC, managedByIP = map[string]inventoryRecord{}, map[string]ManagedView{}, map[string]ManagedView{}
		inventoryMu.Unlock()
	})

	type view struct {
		groups, labels map[string]string
		links          map[[2]string]bool
	}
	build := func() (view, *DJGraph) {
		g := buildGraphFromSnapshot(snapshot)
		data := g.GetGraphData()
		v := view{map[string]string{}, map[string]string{}, map[[2]string]bool{}}
		for _, n := range data.Nodes {
			v.groups[n.ID], v.labels[n.ID] = n.Group, n.SysName
		}
		for _, l := range data.Links {
			v.links[[2]string{l.Source, l.Target}] = true
		}
		return v, g
	}
	linked := func(v view, a, b string) bool { return v.links[[2]string{a, b}] || v.links[[2]string{b, a}] }
	switchMACs := buildSwitchOwnMACs(snapshot)
	portOf := func(d *DeviceData, port int) (fdbPort, bool) {
		for _, p := range fdbPorts(d, switchMACs) {
			if p.Port == port {
				return p, true
			}
		}
		return fdbPort{}, false
	}

	setInventory("ADOPTING")
	v, g := build()
	apHub, pcHub := hubLinkNodeID(coreID, accID), hubLinkNodeID(thirdID, coreID)
	if apHub != hubLinkNodeID(accID, coreID) {
		t.Fatalf("hubLinkNodeID depends on the order: %q %q", apHub, hubLinkNodeID(accID, coreID))
	}
	if v.groups[apHub] != "ap_hub" || v.labels[apHub] != "[APHUB] AP hub\n4 access points, 0 clients" {
		t.Errorf("AP link hub: %q %q", v.groups[apHub], v.labels[apHub])
	}
	if !linked(v, coreID, apHub) || !linked(v, accID, apHub) || linked(v, coreID, accID) {
		t.Errorf("AP link hub: core-hub %v, acc-hub %v, core-acc straight %v", linked(v, coreID, apHub), linked(v, accID, apHub), linked(v, coreID, accID))
	}
	for _, ap := range []string{ap1, ap2, ap3, ap4} {
		if !linked(v, apHub, ap) || linked(v, coreID, ap) || linked(v, accID, ap) {
			t.Errorf("AP link hub: %s is not under the hub only", ap)
		}
	}
	if linked(v, apHub, pcBehindAcc) || linked(v, apHub, pcOnAcc) || linked(v, coreID, pcBehindAcc) || !linked(v, accID, pcOnAcc) {
		t.Errorf("AP link hub: the FDB behind the peer is drawn under the hub or from the core")
	}
	for _, c := range []struct {
		d    *DeviceData
		port int
		peer string
	}{{core, 24, accID}, {acc, 25, coreID}, {core, 10, thirdID}, {third, 1, coreID}} {
		p, ok := portOf(c.d, c.port)
		want := fdbAPHub
		if c.port != 24 && c.port != 25 {
			want = fdbHub
		}
		if !ok || p.Kind != want || p.Peer != c.peer || len(p.MACs) != 0 {
			t.Errorf("%s port %d: fdbPort %+v, want kind %v peer %s and no MACs", c.d.IP, c.port, p, want, c.peer)
		}
	}
	if v.groups[pcHub] != "hub" || !linked(v, coreID, pcHub) || !linked(v, thirdID, pcHub) || !linked(v, pcHub, winPC) ||
		linked(v, coreID, thirdID) || linked(v, coreID, winPC) || linked(v, thirdID, winPC) {
		t.Errorf("PC link hub: group %q, the PC or the switches linked around it", v.groups[pcHub])
	}
	var alerts []string
	for _, s := range NewAnalyzer(captureData("link", []*DeviceData{core, acc, third}, g)).analyzeShadowIT() {
		alerts = append(alerts, s.IssueID+" "+s.nodeID)
	}
	slices.Sort(alerts)
	want := []string{shadowITIssueID(core.IP, 10) + " " + pcHub, shadowITIssueID(third.IP, 1) + " " + pcHub}
	if slices.Sort(want); !slices.Equal(alerts, want) {
		t.Errorf("alerts = %v, want %v", alerts, want)
	}

	setInventory(modules.StateOnline)
	if v, _ = build(); v.groups[apHub] != "" || !linked(v, coreID, ap1) || !linked(v, accID, ap1) || !linked(v, coreID, accID) {
		t.Errorf("ONLINE access points with uplinks to each other: hub %q, links changed", v.groups[apHub])
	}

	// a port where two polled switches are neighbors gets no plan: its
	// access point stays linked straight
	setInventory("ADOPTING")
	core.Neighbors = append(core.Neighbors, nb(20, accMAC, "Switch", "PiXiETECH", "Gig0/20", 0x04),
		nb(20, thirdMAC, "third", "HPE Comware Platform Software", "GigabitEthernet1/0/20", 0x28), nb(20, apX, "X", "U6-Pro, 6.8.2.15592", "eth0", 0x38))
	if v, _ = build(); !linked(v, coreID, apX) || linked(v, apHub, apX) || v.groups[apHub] != "ap_hub" {
		t.Errorf("two polled switches on a port: the access point is not linked straight, or the AP link hub is gone")
	}
	if _, ok := lldpPortPlans(core, switchMACs)[20]; ok {
		t.Errorf("two polled switches on a port: got a plan")
	}
}

// TestPhonePCs: with the Classification choice phonePCs, the one device a
// switch learns on a port whose only LLDP neighbor is an IP phone is behind
// the phone (its PC port): linked from the phone, not the switch, also when
// the phone is known by its port MAC (a chassis id that is an address).
// Two devices behind a phone, and a port whose LLDP neighbor is no phone,
// keep the old rule (no FDB node on an LLDP port); off, the PC is not drawn.
func TestPhonePCs(t *testing.T) {
	resetState(t)
	const (
		phone1, pc1        = "c0:74:ad:90:02:01", "00:1b:21:0b:00:01"
		phone2, pc2        = "ec:74:d7:64:cb:9f", "00:1b:21:0b:00:02"
		phone3, pc3a, pc3b = "c0:74:ad:90:02:03", "00:1b:21:0b:00:03", "00:1b:21:0b:00:04"
		host4, other4      = "00:1b:21:0b:00:05", "00:1b:21:0b:00:06"
	)
	sw := &DeviceData{IP: "10.9.98.1", SysName: "sw-phones", ChassisID: "18:56:44:00:03:01", Interfaces: gigabitPorts(4, nil)}
	sw.Neighbors = []LLDPNeighbor{
		{LocalPortNum: 1, RemIndex: 1, RemChassisIdSubtype: 4, RemChassisId: phone1, RemPortIdSubtype: 5, RemPortId: `"eth0"`,
			RemSysName: "GXP1610_" + phone1, RemSysDesc: "GXP1610 1.0.7.64", RemSysCapEnabled: 0x24},
		{LocalPortNum: 2, RemIndex: 1, RemChassisIdSubtype: 5, RemChassisId: "01 AC 10 00 8A", RemPortIdSubtype: 3, RemPortId: "EC 74 D7 64 CB 9F",
			RemSysName: "GXP1610_" + phone2, RemSysDesc: "GXP1610 1.0.7.64", RemSysCapEnabled: 0x24},
		{LocalPortNum: 3, RemIndex: 1, RemChassisIdSubtype: 4, RemChassisId: phone3, RemPortIdSubtype: 5, RemPortId: `"eth0"`,
			RemSysName: "GXP1610_" + phone3, RemSysDesc: "GXP1610 1.0.7.64", RemSysCapEnabled: 0x24},
		{LocalPortNum: 4, RemIndex: 1, RemChassisIdSubtype: 7, RemChassisId: `"desk"`, RemPortIdSubtype: 3, RemPortId: host4},
	}
	sw.MACTable = append(sw.MACTable, macEntries(1, phone1, pc1)...)
	sw.MACTable = append(sw.MACTable, macEntries(2, phone2, pc2)...)
	sw.MACTable = append(sw.MACTable, macEntries(3, phone3, pc3a, pc3b)...)
	sw.MACTable = append(sw.MACTable, macEntries(4, host4, other4)...)
	src := graphDeviceNodeID(sw)
	snapshot := map[string]*DeviceData{sw.IP: sw}

	build := func(on bool) (map[[2]string]bool, map[string]bool, map[int]string) {
		currentSettingsMutex.Lock()
		currentSettings.Classify = DefaultClassifySettings()
		currentSettings.Classify.PhonePCs = on
		currentSettingsMutex.Unlock()
		g := buildGraphFromSnapshot(snapshot)
		links := map[[2]string]bool{}
		for from, tos := range g.Edges {
			for to := range tos {
				links[[2]string{from, to}] = true
			}
		}
		phones := map[int]string{}
		for _, p := range fdbPorts(sw, buildSwitchOwnMACs(snapshot)) {
			phones[p.Port] = p.Phone
		}
		return links, g.Nodes, phones
	}

	links, nodes, phones := build(true)
	for _, c := range []struct{ phone, pc string }{{phone1, pc1}, {phone2, pc2}} {
		if !links[[2]string{src, c.phone}] || !links[[2]string{c.phone, c.pc}] || links[[2]string{src, c.pc}] {
			t.Errorf("phonePCs: %s is not behind the phone %s only", c.pc, c.phone)
		}
	}
	if phones[1] != phone1 || phones[2] != phone2 {
		t.Errorf("phonePCs: fdbPorts phones %v", phones)
	}
	for _, m := range []string{pc3a, pc3b, other4} {
		if nodes[m] {
			t.Errorf("phonePCs: %s is drawn (two devices behind a phone, or no phone)", m)
		}
	}

	_, nodes, phones = build(false)
	if nodes[pc1] || nodes[pc2] || len(phones) != 0 {
		t.Errorf("phonePCs off: PCs drawn %v %v, ports %v", nodes[pc1], nodes[pc2], phones)
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
