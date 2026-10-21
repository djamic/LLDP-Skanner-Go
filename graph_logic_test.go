package main

// Focused tests for the graph-logic fixes (switch identity, LLDP targets,
// FDB endpoint classification, hypervisor detection, groups and labels).

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
)

// TestGraphCanonicalMAC pins the MAC spellings the graph reads as MACs (node
// ids, LLDP ids, FDB entries): canonicalMAC of mac_identity.go, which
// replaced the graph's own parser with the same answers (H3).
func TestGraphCanonicalMAC(t *testing.T) {
	cases := []struct{ in, want string }{
		{"4c:ae:a3:8e:42:11", "4c:ae:a3:8e:42:11"},
		{"4C:AE:A3:8E:42:11", "4c:ae:a3:8e:42:11"},
		{"4c-ae-a3-8e-42-11", "4c:ae:a3:8e:42:11"},
		{"4C AE A3 8E 42 11", "4c:ae:a3:8e:42:11"},
		{"4C AE A3 8E 42 11 ", "4c:ae:a3:8e:42:11"},
		{"Hex-STRING: 4C AE A3 8E 42 11", "4c:ae:a3:8e:42:11"},
		{"STRING: \"4c:ae:a3:8e:42:11\"", "4c:ae:a3:8e:42:11"},
		{"\"f8-f0-82-7a-d9-69\"", "f8:f0:82:7a:d9:69"},
		{"5894.8000.f7a3", "58:94:80:00:f7:a3"},
		{"\"5894.8000.F7A3\"", "58:94:80:00:f7:a3"},
		{"4caea32784cb", "4c:ae:a3:27:84:cb"},
		{"0:c:29:aa:bb:cd", "00:0c:29:aa:bb:cd"},
		{"00:00:00:00:00:00", "00:00:00:00:00:00"},
		{"No Such Object available on this agent at this OID", ""},
		{"no:such:object:available:on:this:agent:at:this:oid", ""},
		{"no:such:instance:currently:exists:at:this:oid", ""},
		{"DESKTOP-V380CHD", ""},
		{"FERUZA", ""},
		{"lanxyz", ""},
		{"01 AC 10 01 0F", ""},
		{"fe80::1", ""},
		{"172.20.1.1", ""},
		{"", ""},
		{"a-b-c-d-e-f", ""},
		{"aa:bb:cc:dd:ee", ""},
		{"aa:bb:cc:dd:ee:ff:00", ""},
		{"4C AE A3 8E 42 1", ""},
		{"4c-ae-a3-8e-42-1", ""},
		{"4c:ae:a3:8e:42:1g", ""},
		{"5894.8000.f7a", ""},
	}
	for _, c := range cases {
		if got := canonicalMAC(c.in); got != c.want {
			t.Errorf("canonicalMAC(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestGraphIsSNMPException(t *testing.T) {
	for in, want := range map[string]bool{
		"No Such Object available on this agent at this OID":                           true,
		"No Such Instance currently exists at this OID":                                true,
		"No more variables left in this MIB View (It is past the end of the MIB tree)": true,
		"no:such:object:available:on:this:agent:at:this:oid":                           true,
		"no:such:instance:currently:exists:at:this:oid":                                true,
		"\"No Such Object available on this agent at this OID\"":                       true,
		"4c:ae:a3:8e:42:11": false,
		"No-Name switch":    false,
		"":                  false,
		"nosuchobject":      false,
	} {
		if got := graphIsSNMPException(in); got != want {
			t.Errorf("graphIsSNMPException(%q) = %v, want %v", in, got, want)
		}
	}
}

// TestGraphDeviceNodeID covers Q12: exception text and the null MAC fall
// back to the IP, every MAC spelling (Cisco-dotted included) is canonical.
func TestGraphDeviceNodeID(t *testing.T) {
	cases := []struct{ chassis, wantID, wantKey string }{
		{"4c:ae:a3:8e:42:11", "4c:ae:a3:8e:42:11", "4c:ae:a3:8e:42:11"},
		{"4C AE A3 8E 42 11", "4c:ae:a3:8e:42:11", "4c:ae:a3:8e:42:11"},
		{"5894.8000.f7a3", "58:94:80:00:f7:a3", "58:94:80:00:f7:a3"},
		{"No Such Object available on this agent at this OID", "10.9.9.9", ""},
		{"no:such:object:available:on:this:agent:at:this:oid", "10.9.9.9", ""},
		{"no:such:instance:currently:exists:at:this:oid", "10.9.9.9", ""},
		{"", "10.9.9.9", ""},
		{"00:00:00:00:00:00", "10.9.9.9", ""},
		{"SW-CORE1", "SW-CORE1", ""},
	}
	for _, c := range cases {
		d := &DeviceData{IP: "10.9.9.9", ChassisID: c.chassis}
		if got := graphDeviceNodeID(d); got != c.wantID {
			t.Errorf("graphDeviceNodeID(chassis %q) = %q, want %q", c.chassis, got, c.wantID)
		}
		if got := graphChassisKey(c.chassis); got != c.wantKey {
			t.Errorf("graphChassisKey(%q) = %q, want %q", c.chassis, got, c.wantKey)
		}
	}
}

// TestGraphLocalChassisCollect covers F7, F8 and F9 at collection time.
func TestGraphLocalChassisCollect(t *testing.T) {
	resetState(t)
	cases := []struct {
		line    string
		want    string
		wantErr bool
	}{
		{oidChassis + " = Hex-STRING: F8 F0 82 D8 7E 81 ", "f8:f0:82:d8:7e:81", false},
		{oidChassis + " = No Such Object available on this agent at this OID", "", true},
		{oidChassis + " = No Such Instance currently exists at this OID", "", true},
		{oidChassis + " = STRING: \"5894.8000.f7a3\"", "58:94:80:00:f7:a3", false},
		{oidChassis + " = STRING: \"LANxyz\"", "4c:41:4e:78:79:7a", false},
		{oidChassis + " = STRING: \"pM{?WA\"", "70:4d:7b:3f:57:41", false},
		{oidChassis + " = STRING: \"f8-f0-82-7a-d9-69\"", "f8:f0:82:7a:d9:69", false},
		{oidChassis + " = STRING: \"SW-CORE1\"", "SW-CORE1", false},
	}
	obj := NewSNMPObject(nil, nil)
	for i, c := range cases {
		ip := "10.9.8." + string(rune('1'+i))
		fakeSNMP.set(ip, map[string][]string{oidChassis: {c.line}})
		got, err := obj.collectLocalChassisID(ip)
		if got != c.want || (err != nil) != c.wantErr {
			t.Errorf("collectLocalChassisID(%q) = %q, %v; want %q (error %v)", c.line, got, err, c.want, c.wantErr)
		}
	}
	// The neighbor view of "LANxyz" (chassis subtype 4) is the same node id.
	if got := normalizeID("\"LANxyz\"", 4); got != "4c:41:4e:78:79:7a" {
		t.Errorf("normalizeID(LANxyz, 4) = %q", got)
	}
}

// TestGraphSwitchIdentityBuild builds a small network: two switches whose
// chassis id is SNMP exception text get a node each (F7), and a switch with
// a Cisco-dotted chassis id is one node, reached by its neighbor's LLDP edge
// and by a third switch's MAC cross-reference (F8).
func TestGraphSwitchIdentityBuild(t *testing.T) {
	resetState(t)
	devices := map[string]*DeviceData{
		"10.9.7.1": {IP: "10.9.7.1", SysName: "sw-x1", ChassisID: "no:such:object:available:on:this:agent:at:this:oid",
			Interfaces: gigabitPorts(4, nil), MACTable: macEntries(1, "00:1b:21:07:01:01")},
		"10.9.7.2": {IP: "10.9.7.2", SysName: "sw-x2", ChassisID: "No Such Object available on this agent at this OID",
			Interfaces: gigabitPorts(4, nil), MACTable: macEntries(1, "00:1b:21:07:02:01"), Unreachable: true},
		"10.9.7.3": {IP: "10.9.7.3", SysName: "pixie", ChassisID: "5894.8000.f7a3", Interfaces: gigabitPorts(4, nil)},
		"10.9.7.4": {IP: "10.9.7.4", SysName: "core", ChassisID: "4c:ae:a3:07:04:00", Interfaces: gigabitPorts(8, nil),
			Neighbors: []LLDPNeighbor{{LocalPortNum: 2, RemIndex: 1, RemChassisIdSubtype: 4, RemChassisId: "58 94 80 00 F7 A3",
				RemPortIdSubtype: 5, RemPortId: "\"Gi0/1\""}}},
		"10.9.7.5": {IP: "10.9.7.5", SysName: "edge", ChassisID: "4c:ae:a3:07:05:00", Interfaces: gigabitPorts(8, nil),
			MACTable: macEntries(3, "58:94:80:00:f7:a3")},
	}
	g := buildGraphFromSnapshot(devices)
	for _, id := range []string{"10.9.7.1", "10.9.7.2", "58:94:80:00:f7:a3"} {
		if !g.Nodes[id] {
			t.Errorf("node %s missing", id)
		}
	}
	for id := range g.Nodes {
		if strings.HasPrefix(id, "no:such") || id == "5894.8000.f7a3" {
			t.Errorf("unexpected switch node %q", id)
		}
	}
	if got := g.SwitchInfo["58:94:80:00:f7:a3"]; got != "pixie\n10.9.7.3" {
		t.Errorf("dotted switch label = %q", got)
	}
	if got := g.SwitchInfo["10.9.7.1"]; got != "sw-x1" {
		t.Errorf("exception-text switch label = %q", got)
	}
	if g.NodeStatus["10.9.7.1"] != "" || g.NodeStatus["10.9.7.2"] != "unreachable" {
		t.Errorf("node status = %v", g.NodeStatus)
	}
	if got := g.GetEdgeLabel("4c:ae:a3:07:04:00", "58:94:80:00:f7:a3"); !strings.HasPrefix(got, "GE1/0/2") {
		t.Errorf("LLDP edge to the dotted switch = %q", got)
	}
	if got := g.GetEdgeLabel("4c:ae:a3:07:05:00", "58:94:80:00:f7:a3"); got != "GE1/0/3 [MAC-REF]|" {
		t.Errorf("MAC-REF edge to the dotted switch = %q", got)
	}
	if !g.GetEdge("10.9.7.1", "00:1b:21:07:01:01") || !g.GetEdge("10.9.7.2", "00:1b:21:07:02:01") {
		t.Errorf("FDB endpoints are not attached to their own switch: %v", g.Edges)
	}
	switchMACs := buildSwitchChassisMACs(devices)
	if len(switchMACs) != 3 || switchMACs["58:94:80:00:f7:a3"] != "58:94:80:00:f7:a3" {
		t.Errorf("buildSwitchChassisMACs = %v", switchMACs)
	}
}

// TestGraphLLDPIDNormalization covers the chassis subtype table (F40, F41)
// and the separate port subtype table (F42).
func TestGraphLLDPIDNormalization(t *testing.T) {
	chassis := []struct {
		id      string
		subtype int
		want    string
	}{
		{"01 AC 10 01 0F", 5, "172.16.1.15"},
		{"01 AC 10", 5, ""},
		{"01 AC 10 01", 5, ""},
		{"02 20 01 0D B8 00 00 00 00 00 00 00 00 00 00 00 01", 5, "2001:db8::1"},
		{"FA EF EF EF AA 4F", 7, "fa:ef:ef:ef:aa:4f"},
		{"00 00 00 00 00 00", 7, "00:00:00:00:00:00"},
		{"\"f4-b5-20-19-12-5e\"", 7, "f4:b5:20:19:12:5e"},
		{"\"DESKTOP-V380CHD\"", 7, "DESKTOP-V380CHD"},
		{"\"WORKSTATION-ROOM-301\"", 7, "WORKSTATION-ROOM-301"},
		{"\"5894.8000.f7a3\"", 4, "58:94:80:00:f7:a3"},
		{"4C AE A3 8E 42 11", 4, "4c:ae:a3:8e:42:11"},
		{"\"pM{?WA\"", 4, "70:4d:7b:3f:57:41"},
	}
	for _, c := range chassis {
		if got := normalizeID(c.id, c.subtype); got != c.want {
			t.Errorf("normalizeID(%q, %d) = %q, want %q", c.id, c.subtype, got, c.want)
		}
	}
	ports := []struct {
		id      string
		subtype int
		want    string
	}{
		{"\"eth0\"", 5, "eth0"},
		{"\"GigabitEthernet1/0/47\"", 5, "GigabitEthernet1/0/47"},
		{"\"uplink\"", 1, "uplink"},
		{"\"LAN\"", 1, "LAN"},
		{"10 7C 61 C0 9E AA", 3, "10:7c:61:c0:9e:aa"},
		{"\"c8-41-8a-20-51-72\"", 3, "c8:41:8a:20:51:72"},
		{"\"pM{?WA\"", 3, "70:4d:7b:3f:57:41"},
		{"01 AC 10 01 0F", 4, "172.16.1.15"},
		{"\"28\"", 7, "28"},
		{"\"f4-b5-20-19-12-5e\"", 7, "f4:b5:20:19:12:5e"},
		{"98 EE CB E0 89 74", 0, "98:ee:cb:e0:89:74"},
	}
	for _, c := range ports {
		if got := graphNormalizePortID(c.id, c.subtype); got != c.want {
			t.Errorf("graphNormalizePortID(%q, %d) = %q, want %q", c.id, c.subtype, got, c.want)
		}
	}
}

// TestGraphResolveLLDPTarget covers Q13 target selection: a null or locally
// assigned chassis MAC is neither the node id (when the port id is a real
// MAC) nor the display name (F43), a network-address chassis is an IP (F40),
// port names never become fake MACs (F42) and hostname targets are kept.
func TestGraphResolveLLDPTarget(t *testing.T) {
	cases := []struct {
		name          string
		n             LLDPNeighbor
		target, shown string
		usable        bool
	}{
		{"null chassis, port MAC", LLDPNeighbor{RemChassisIdSubtype: 7, RemChassisId: "00 00 00 00 00 00", RemPortIdSubtype: 3, RemPortId: "\"c8-41-8a-20-51-72\""},
			"c8:41:8a:20:51:72", "", true},
		{"null chassis, port MAC, sysName", LLDPNeighbor{RemChassisIdSubtype: 7, RemChassisId: "00 00 00 00 00 00", RemPortIdSubtype: 3, RemPortId: "\"c8-41-8a-20-51-72\"", RemSysName: "cam-7"},
			"c8:41:8a:20:51:72", "cam-7", true},
		{"local MAC-like chassis, port MAC", LLDPNeighbor{RemChassisIdSubtype: 7, RemChassisId: "FA EF EF EF AA 4F", RemPortIdSubtype: 3, RemPortId: "\"40-c2-ba-4d-fc-3d\""},
			"40:c2:ba:4d:fc:3d", "", true},
		{"local MAC-like chassis, port name", LLDPNeighbor{RemChassisIdSubtype: 7, RemChassisId: "FA EF EF EF AA 4F", RemPortIdSubtype: 5, RemPortId: "\"eth0\""},
			"fa:ef:ef:ef:aa:4f", "", true},
		{"network address chassis, port name", LLDPNeighbor{RemChassisIdSubtype: 5, RemChassisId: "01 AC 10 01 0F", RemPortIdSubtype: 5, RemPortId: "\"eth0\"", RemSysName: "GXP1610"},
			"172.16.1.15", "GXP1610", true},
		{"network address chassis, port MAC", LLDPNeighbor{RemChassisIdSubtype: 5, RemChassisId: "01 AC 10 01 0F", RemPortIdSubtype: 3, RemPortId: "EC 74 D7 64 CB AC"},
			"ec:74:d7:64:cb:ac", "172.16.1.15", true},
		{"truncated network address", LLDPNeighbor{RemChassisIdSubtype: 5, RemChassisId: "01 AC 10", RemPortIdSubtype: 3, RemPortId: "EC 74 D7 64 CB B1"},
			"ec:74:d7:64:cb:b1", "", true},
		{"hostname chassis, local port", LLDPNeighbor{RemChassisIdSubtype: 7, RemChassisId: "B-318/1", RemPortIdSubtype: 7, RemPortId: "\"28\"", RemSysName: "B-318/1"},
			"B-318/1", "B-318/1", true},
		{"hostname chassis, 6-char alias port", LLDPNeighbor{RemChassisIdSubtype: 7, RemChassisId: "\"host-x\"", RemPortIdSubtype: 1, RemPortId: "\"uplink\""},
			"host-x", "", true},
		{"MAC chassis, interface name port", LLDPNeighbor{RemChassisIdSubtype: 4, RemChassisId: "4C AE A3 09 00 03", RemPortIdSubtype: 5, RemPortId: "\"GigabitEthernet1/0/48\"", RemSysName: "sw-b"},
			"4c:ae:a3:09:00:03", "sw-b", true},
		{"hostname chassis, port MAC", LLDPNeighbor{RemChassisIdSubtype: 7, RemChassisId: "\"DESKTOP-V380CHD\"", RemPortIdSubtype: 3, RemPortId: "10 7C 61 C0 9E AA"},
			"10:7c:61:c0:9e:aa", "DESKTOP-V380CHD", true},
		{"null chassis, local port", LLDPNeighbor{RemChassisIdSubtype: 7, RemChassisId: "00 00 00 00 00 00", RemPortIdSubtype: 7, RemPortId: "\"1\""},
			"", "", false},
		{"empty", LLDPNeighbor{}, "", "", false},
	}
	for _, c := range cases {
		target, shown := resolveLLDPTarget(c.n)
		if target != c.target || shown != c.shown {
			t.Errorf("%s: resolveLLDPTarget = (%q, %q), want (%q, %q)", c.name, target, shown, c.target, c.shown)
		}
		if got := graphUsableTargetID(target); got != c.usable {
			t.Errorf("%s: graphUsableTargetID(%q) = %v, want %v", c.name, target, got, c.usable)
		}
	}
	for id, want := range map[string]bool{
		"E109-9": true, "173.16.1.15": true, "172.16.1.15": true, "F-3(2)": true, "4caea32784cb": true,
		"0.0.0.0": false, "0:0:0:0": false, "::": false, "": false, "SW1": false,
		"00:00:00:00:00:00": false, "01:00:5e:00:00:fb": false, "ff:ff:ff:ff:ff:ff": false,
	} {
		if got := graphUsableTargetID(id); got != want {
			t.Errorf("graphUsableTargetID(%q) = %v, want %v", id, got, want)
		}
	}
}

// TestGraphLLDPBuild covers the LLDP part of buildGraphEdges: no orphan node
// for a neighbor on a NULL or "Port 0" port (F44), a port whose only
// neighbor was rejected keeps its FDB endpoints (F48), an LLDP-known MAC is
// matched by its resolved target (F46), FDB node ids are canonical (F47),
// and hostname and network-address targets get nodes (Q13).
func TestGraphLLDPBuild(t *testing.T) {
	resetState(t)
	sw := &DeviceData{
		IP: "10.9.6.1", SysName: "sw", ChassisID: "4c:ae:a3:06:01:00",
		Interfaces: gigabitPorts(12, map[int]string{9: "NULL0"}),
		Neighbors: []LLDPNeighbor{
			{LocalPortNum: 0, RemIndex: 1, RemChassisIdSubtype: 4, RemChassisId: "AA BB CC 06 00 01", RemPortIdSubtype: 3, RemPortId: "AA BB CC 06 00 01"},
			{LocalPortNum: 9, RemIndex: 2, RemChassisIdSubtype: 4, RemChassisId: "AA BB CC 06 00 02", RemPortIdSubtype: 3, RemPortId: "AA BB CC 06 00 02"},
			{LocalPortNum: 7, RemIndex: 3, RemChassisIdSubtype: 7, RemChassisId: "00 00 00 00 00 00", RemPortIdSubtype: 7, RemPortId: "\"1\""},
			{LocalPortNum: 2, RemIndex: 4, RemChassisIdSubtype: 7, RemChassisId: "\"PC-2\"", RemPortIdSubtype: 3, RemPortId: "00 1B 21 06 02 01"},
			{LocalPortNum: 3, RemIndex: 5, RemChassisIdSubtype: 7, RemChassisId: "B-318/1", RemPortIdSubtype: 7, RemPortId: "\"28\"", RemSysName: "B-318/1"},
			{LocalPortNum: 4, RemIndex: 6, RemChassisIdSubtype: 5, RemChassisId: "01 AC 10 01 0F", RemPortIdSubtype: 5, RemPortId: "\"eth0\"", RemSysName: "phone-4"},
		},
		MACTable: append(append(append(
			macEntries(7, "00:1b:21:06:07:01"),
			macEntries(5, "00:1b:21:06:02:01", "00:1b:21:06:05:02")...),
			macEntries(6, "00-50-56-AA-BB-CC")...),
			macEntries(8, "00:1b:21:06:08:01")...),
	}
	g := buildGraphFromSnapshot(map[string]*DeviceData{sw.IP: sw})
	for _, id := range []string{"aa:bb:cc:06:00:01", "aa:bb:cc:06:00:02", "00-50-56-AA-BB-CC", "00:00:00:00:00:00"} {
		if g.Nodes[id] {
			t.Errorf("unexpected node %q (%q)", id, g.SwitchInfo[id])
		}
	}
	src := "4c:ae:a3:06:01:00"
	checks := []struct{ id, label string }{
		{"00:1b:21:06:07:01", "GE1/0/7|"},                // F48: the rejected neighbor does not hide it
		{"00:1b:21:06:02:01", "GE1/0/2 1G|001B21060201"}, // LLDP edge; not a hub member on port 5 (F46)
		{"00:1b:21:06:05:02", "GE1/0/5|"},                // port 5 is left with one MAC: direct endpoint
		{"00:50:56:aa:bb:cc", "GE1/0/6|"},                // F47: canonical node id
		{"B-318/1", "GE1/0/3 1G|28"},
		{"172.16.1.15", "GE1/0/4 1G|eth0"},
	}
	for _, c := range checks {
		if !g.Nodes[c.id] {
			t.Errorf("node %q missing", c.id)
			continue
		}
		if got := g.GetEdgeLabel(src, c.id); got != c.label {
			t.Errorf("edge %s -> %s = %q, want %q", src, c.id, got, c.label)
		}
	}
	for id := range g.Nodes {
		if strings.HasPrefix(id, "hub-") {
			t.Errorf("unexpected hub %s", id)
		}
	}
	if got := g.SwitchInfo["172.16.1.15"]; got != "[LLDP-EP]\nphone-4" {
		t.Errorf("network-address neighbor label = %q", got)
	}
}

// graphVMPortGraph is a switch with one VM port: every MAC gets a [VM] node
// and an edge with the given label.
func graphVMPortGraph(label string, macs ...string) *DJGraph {
	g := NewDJGraph()
	addInfoNode(g, "4c:ae:a3:00:05:00", "sw\n10.0.5.1")
	for _, mac := range macs {
		addInfoNode(g, mac, "[VM] 💻 VM")
		g.AddEdge("4c:ae:a3:00:05:00", mac, label)
	}
	return g
}

// TestGraphHypervisorTypes covers F21/Q8/Q9 (every VMware OUI is 'VMware
// ESXi', bc:24:11 is 'Proxmox VE') and F22 (majority, fixed tie-break).
func TestGraphHypervisorTypes(t *testing.T) {
	const sw = "4c:ae:a3:00:05:00"
	cases := []struct {
		macs []string
		want string
	}{
		{[]string{"00:50:56:00:00:01", "00:0c:29:00:00:02", "00:50:56:00:00:03"}, "VMware ESXi"},
		{[]string{"00:05:69:00:00:01", "00:05:69:00:00:02"}, "VMware ESXi"},
		{[]string{"00:1c:14:00:00:01", "00:1c:14:00:00:02"}, "VMware ESXi"},
		{[]string{"bc:24:11:00:00:01", "bc:24:11:00:00:02"}, "Proxmox VE"},
		{[]string{"52:54:00:00:00:01", "00:15:5d:00:00:02", "52:54:00:00:00:03"}, "QEMU/KVM"},
		{[]string{"52:54:00:00:00:01", "00:15:5d:00:00:02"}, "Hyper-V"},
		{[]string{"00:16:3e:00:00:01", "08:00:27:00:00:02", "00:50:56:00:00:03"}, "VMware ESXi"},
	}
	for _, c := range cases {
		for i := 0; i < 20; i++ { // map order must not matter
			g := graphVMPortGraph("GE1/0/5 [T]|", c.macs...)
			detectHypervisors(g)
			hyp := "hyp-" + sw + "-ge1_0_5"
			want := fmt.Sprintf("[HYPERVISOR] %s\n%d VMs on ge1/0/5", c.want, len(c.macs))
			if got := g.SwitchInfo[hyp]; got != want {
				t.Fatalf("%v: hyp label = %q, want %q", c.macs, got, want)
			}
			for _, mac := range c.macs {
				if g.GetEdgeLabel(hyp, mac) != "vNIC" || g.GetEdge(sw, mac) {
					t.Fatalf("%v: %s is not moved under %s: %v", c.macs, mac, hyp, g.Edges)
				}
				if g.SwitchInfo[mac] != "[VM] 💻 VM" {
					t.Fatalf("VM label changed: %q", g.SwitchInfo[mac])
				}
			}
		}
	}
}

// TestGraphHypervisorTypesFromRegistry (H2): detectHypervisors takes the
// platform of a VM NIC from the MAC registry (hypervisorTypeOf), so every
// virtual-NIC OUI there, and one added to it, names its hyp- node.
func TestGraphHypervisorTypesFromRegistry(t *testing.T) {
	const sw = "4c:ae:a3:00:05:00"
	const added = "02:00:42" // a test-only virtual-NIC OUI
	ouiRegistry[added] = ouiRole{VirtNIC: "TestHV", HypType: "Test Hypervisor"}
	t.Cleanup(func() { delete(ouiRegistry, added) })
	checked := 0
	for _, prefix := range slices.Sorted(maps.Keys(ouiRegistry)) {
		hypType := ouiRegistry[prefix].HypType
		if hypType == "" {
			continue
		}
		g := graphVMPortGraph("GE1/0/5|", prefix+":00:00:01", prefix+":00:00:02")
		detectHypervisors(g)
		want := fmt.Sprintf("[HYPERVISOR] %s\n2 VMs on ge1/0/5", hypType)
		if got := g.SwitchInfo["hyp-"+sw+"-ge1_0_5"]; got != want {
			t.Errorf("%s: hyp label = %q, want %q", prefix, got, want)
		}
		checked++
	}
	if checked < 10 {
		t.Errorf("only %d virtual-NIC OUIs checked", checked)
	}
}

// TestGraphHypervisorPortKey covers F23 (speed and traffic text never enter
// the port key) and F24 (VMs behind a hub are keyed by the hub's port).
func TestGraphHypervisorPortKey(t *testing.T) {
	const sw = "4c:ae:a3:00:05:00"
	for _, label := range []string{"GigabitEthernet1/0/9 1G ↓5M ↑3M|eth0", "GE1/0/9 1G|vmnic0", "GE1/0/9 [V100]|", "GE1/0/9|"} {
		g := graphVMPortGraph(label, "00:50:56:00:09:01", "00:50:56:00:09:02")
		detectHypervisors(g)
		hyp := "hyp-" + sw + "-ge1_0_9"
		if got := g.SwitchInfo[hyp]; got != "[HYPERVISOR] VMware ESXi\n2 VMs on ge1/0/9" {
			t.Errorf("label %q: hyp %s = %q (nodes %v)", label, hyp, got, g.Nodes)
		}
		if got := g.GetEdgeLabel(sw, hyp); got != "ge1/0/9" {
			t.Errorf("label %q: switch→hyp edge = %q", label, got)
		}
	}

	g := NewDJGraph()
	hub := "hub-" + sw + "-p7"
	addInfoNode(g, sw, "sw\n10.0.5.1")
	addInfoNode(g, hub, "[HUB] Unmanaged\n3 devices")
	g.AddEdge(sw, hub, "GE1/0/7|Hub")
	for _, mac := range []string{"00:0c:29:00:07:01", "00:0c:29:00:07:02", "00:1b:21:00:07:03"} {
		addInfoNode(g, mac, "[ENDPOINT]")
		g.AddEdge(hub, mac, "")
	}
	detectHypervisors(g)
	hyp := "hyp-" + hub + "-ge1_0_7"
	if got := g.SwitchInfo[hyp]; got != "[HYPERVISOR] VMware ESXi\n2 VMs on ge1/0/7" {
		t.Fatalf("hub hypervisor %s = %q (nodes %v)", hyp, got, g.Nodes)
	}
	if label, ok := g.Edges[hub][hyp]; !ok || label != "" {
		t.Errorf("hub→hyp edge = %q, %v", label, ok)
	}
	if g.GetEdgeLabel(hyp, "00:0c:29:00:07:01") != "vNIC" || g.Edges[hub]["00:0c:29:00:07:01"] == "" && len(g.Edges[hub]) != 2 {
		t.Errorf("hub VMs not moved: %v", g.Edges)
	}
	if _, still := g.Edges[hub]["00:0c:29:00:07:02"]; still {
		t.Errorf("hub still links the VM directly: %v", g.Edges[hub])
	}
	if _, ok := g.Edges[hub]["00:1b:21:00:07:03"]; !ok {
		t.Errorf("non-VM hub member lost its edge: %v", g.Edges[hub])
	}
}

func graphMACRange(prefix string, from, n int) []string {
	var out []string
	for i := from; i < from+n; i++ {
		out = append(out, fmt.Sprintf("%s:%02x", prefix, i))
	}
	return out
}

// TestGraphFDBEndpoints covers the FDB branches of buildGraphEdges: VM ports
// on trunks and with more than 20 MACs (F26) unless another switch's MAC is
// learned there, only virtual NICs get [VM] (F27), no '[T]' on access ports
// (F28), every hub member gets a node with the BMC/random/DNS checks (F29),
// a lone virtual NIC is a VM (F30, Q4), DNS names reach the BMC check on the
// direct, hub and LLDP paths (F31, Q5), and a port with an HTTP-confirmed
// ESXi MAC is no hub (Q14).
func TestGraphFDBEndpoints(t *testing.T) {
	resetState(t)
	const src = "4c:ae:a3:05:01:00"
	devices := graphFDBTestDevices()
	globalMACtoIPMutex.Lock()
	globalMACtoIP = map[string]string{"00:1b:21:05:09:08": "10.0.9.13", "00:1b:21:05:0b:01": "172.20.0.48", "00:1b:21:05:0c:01": "172.16.25.231"}
	globalMACtoIPMutex.Unlock()
	ConfirmedESXiMACs.Store("00:1b:21:05:0a:01", true)

	// The per-port rule on its own (what Shadow-IT counting can share, Q14)
	var rule []string
	for _, p := range fdbPorts(devices["10.9.5.1"], buildSwitchChassisMACs(devices)) {
		rule = append(rule, fmt.Sprintf("%d:%d:%v", p.Port, len(p.MACs), p.Kind == fdbHub))
	}
	if got, want := strings.Join(rule, " "), "5:3:false 6:1:false 7:1:false 8:1:false 9:8:true 10:3:false 11:1:false 18:5:false 19:22:false"; got != want {
		t.Errorf("fdbPorts = %s, want %s", got, want)
	}

	g := buildGraphFromSnapshot(devices)
	for port, n := range map[string]int{"ge1_0_18": 4, "ge1_0_19": 21, "ge1_0_5": 2} {
		hyp := "hyp-" + src + "-" + port
		if !strings.Contains(g.SwitchInfo[hyp], fmt.Sprintf("\n%d VMs on ", n)) || len(g.Edges[hyp]) != n {
			t.Errorf("%s = %q with %d vNICs, want %d VMs", hyp, g.SwitchInfo[hyp], len(g.Edges[hyp]), n)
		}
	}
	graphCheckFDBEndpoints(t, g)
}

// graphFDBTestDevices is a switch with every kind of FDB port, and a second
// polled switch whose MAC is learned on port 20.
func graphFDBTestDevices() map[string]*DeviceData {
	const src = "4c:ae:a3:05:01:00"
	var fdb []MACEntry
	fdb = append(fdb, macEntries(18, append(graphMACRange("00:0c:29:05:12", 1, 4), "00:1b:21:05:12:05")...)...)
	fdb = append(fdb, macEntries(19, append(graphMACRange("00:50:56:05:13", 1, 21), "00:1b:21:05:13:99")...)...)
	fdb = append(fdb, macEntries(20, append(graphMACRange("00:0c:29:05:14", 1, 5), "4c:ae:a3:05:02:00")...)...)
	fdb = append(fdb, macEntries(5, "00:0c:29:05:05:01", "00:0c:29:05:05:02", "00:1b:21:05:05:03")...)
	fdb = append(fdb, macEntries(6, "00:0c:29:05:06:01")...)
	fdb = append(fdb, macEntries(7, "52:54:00:05:07:01")...)
	fdb = append(fdb, macEntries(8, "bc:24:11:05:08:01")...)
	fdb = append(fdb, macEntries(9, append(graphMACRange("00:1b:21:05:09", 1, 6), "da:a1:19:05:09:07", "00:1b:21:05:09:08")...)...)
	fdb = append(fdb, macEntries(10, graphMACRange("00:1b:21:05:0a", 1, 3)...)...)
	fdb = append(fdb, macEntries(11, "00:1b:21:05:0b:01")...)
	devices := map[string]*DeviceData{
		"10.9.5.1": {
			IP: "10.9.5.1", SysName: "sw", ChassisID: src, Interfaces: gigabitPorts(24, nil),
			PortVLANs: []PortVLAN{{PortIndex: 18, PVID: 1, IsTrunk: true}, {PortIndex: 19, PVID: 1, IsTrunk: true},
				{PortIndex: 20, PVID: 1, IsTrunk: true}, {PortIndex: 5, PVID: 10}},
			Neighbors: []LLDPNeighbor{{LocalPortNum: 12, RemIndex: 1, RemChassisIdSubtype: 4, RemChassisId: "00 1B 21 05 0C 01",
				RemPortIdSubtype: 3, RemPortId: "00 1B 21 05 0C 01"}},
			MACTable: fdb,
		},
		"10.9.5.2": {IP: "10.9.5.2", SysName: "sw2", ChassisID: "4c:ae:a3:05:02:00", Interfaces: gigabitPorts(4, nil)},
	}
	return devices
}

func graphCheckFDBEndpoints(t *testing.T, g *DJGraph) {
	t.Helper()
	const src = "4c:ae:a3:05:01:00"
	for id := range g.Nodes {
		if strings.HasPrefix(id, "00:0c:29:05:14:") || strings.HasPrefix(id, "hyp-"+src+"-ge1_0_20") {
			t.Errorf("switch link port 20 produced node %s", id)
		}
	}
	labels := []struct{ id, prefix, edge string }{
		{"00:1b:21:05:12:05", "[ENDPOINT]", "GE1/0/18 [T]|"},
		{"00:1b:21:05:13:99", "[ENDPOINT]", "GE1/0/19 [T]|"},
		{"00:1b:21:05:05:03", "[ENDPOINT]", "GE1/0/5 [V10]|"},
		{"00:0c:29:05:06:01", "[VM] 💻 VMware VM VMware", "GE1/0/6|"},
		{"52:54:00:05:07:01", "[VM] 💻 KVM/Proxmox VM", "GE1/0/7|"},
		{"bc:24:11:05:08:01", "[VM] 💻 KVM/Proxmox VM", "GE1/0/8|"},
		{"00:1b:21:05:0a:01", "[HYPERVISOR] VMware ESXi\n[ENDPOINT]", "GE1/0/10|"},
		{"00:1b:21:05:0a:03", "[ENDPOINT]", "GE1/0/10|"},
		{"00:1b:21:05:0b:01", "[BMC] Dell iDRAC", "GE1/0/11|"},
	}
	for _, c := range labels {
		if got := g.SwitchInfo[c.id]; !strings.HasPrefix(got, c.prefix) {
			t.Errorf("%s label = %q, want prefix %q", c.id, got, c.prefix)
		}
		if got := g.GetEdgeLabel(src, c.id); got != c.edge {
			t.Errorf("edge to %s = %q, want %q", c.id, got, c.edge)
		}
	}
	if got := g.SwitchInfo["00:0c:29:05:12:01"]; !strings.HasPrefix(got, "[VM]") {
		t.Errorf("VM on the trunk port: %q", got)
	}
	hub := "hub-" + src + "-p9"
	if g.SwitchInfo[hub] != "[HUB] Unmanaged\n8 devices" || len(g.Edges[hub]) != 8 {
		t.Errorf("hub %q has %d members: %v", g.SwitchInfo[hub], len(g.Edges[hub]), g.Edges[hub])
	}
	if got := g.SwitchInfo["da:a1:19:05:09:07"]; !strings.HasPrefix(got, "[WiFi]") {
		t.Errorf("random hub member = %q", got)
	}
	// 00:1b:21 is an Intel OUI, named by the IEEE database (mac-layer Q1)
	if got := g.SwitchInfo["00:1b:21:05:09:08"]; got != "[BMC] Dell iDRAC Intel Corporate\n10.0.9.13\n[DNS] srv01-idrac" {
		t.Errorf("hub member with a BMC DNS name = %q", got)
	}
	if g.Nodes["hub-"+src+"-p10"] {
		t.Errorf("port with a confirmed ESXi host became a hub")
	}
	if got := g.SwitchInfo["00:1b:21:05:0c:01"]; got != "[BMC] Fujitsu iRMC\n172.16.25.231" {
		t.Errorf("LLDP endpoint with a BMC DNS name = %q", got)
	}
}

// graphServerRelabel is the label detectHypervisors gives a server-NIC node
// that is not protected as a switch (it follows the server-NIC table).
func graphServerRelabel(mac, label string) string {
	if ok, vendor := isServerNIC(mac); ok {
		return fmt.Sprintf("[HYPERVISOR] %s Server\n%s", vendor, label)
	}
	return label
}

// TestGraphSwitchProtection covers Q2's precondition and F36: switch
// protection (server-NIC relabel, ESXi rewrite, groups) and the Zabbix SNR
// templates come from the polled-switch set and sysName/sysDescr, not from
// vendor words in labels; HTTP-confirmed ESXi hosts are hypervisors whatever
// their tag (Q10, F10).
func TestGraphSwitchProtection(t *testing.T) {
	resetState(t)
	devices := map[string]*DeviceData{
		// A polled switch whose chassis OUI is also a server-NIC OUI.
		"10.9.4.1": {IP: "10.9.4.1", SysName: "SW-50", ChassisID: "3c:a8:2a:04:01:00", Interfaces: gigabitPorts(8, nil),
			Neighbors: []LLDPNeighbor{
				{LocalPortNum: 1, RemIndex: 1, RemChassisIdSubtype: 4, RemChassisId: "1C 98 EC 04 00 01", RemPortIdSubtype: 5, RemPortId: "\"Gi1/0/1\"",
					RemSysName: "agg-1", RemSysDesc: "HPE Comware Platform Software, Software Version 7.1.070"},
				{LocalPortNum: 2, RemIndex: 2, RemChassisIdSubtype: 4, RemChassisId: "94 57 A5 04 00 02", RemPortIdSubtype: 3, RemPortId: "94 57 A5 04 00 02",
					RemSysName: "web01"},
				{LocalPortNum: 3, RemIndex: 3, RemChassisIdSubtype: 4, RemChassisId: "F8 F0 82 04 00 03", RemPortIdSubtype: 7, RemPortId: "\"28\"",
					RemSysDesc: "SNR-S2995G-24FX Device, Compiled 2020"},
			},
			MACTable: append(macEntries(5, "5c:ed:8c:04:05:01"), macEntries(6, "00:1b:21:04:06:01")...)},
		"10.9.4.2": {IP: "10.9.4.2", SysName: "SNR-S2985G-24TC", ChassisID: "f8:f0:82:04:02:00", Interfaces: gigabitPorts(4, nil)},
		"10.9.4.3": {IP: "10.9.4.3", SysName: "E109", ChassisID: "f8:f0:82:04:03:00", Interfaces: gigabitPorts(4, nil)},
	}
	ConfirmedESXiMACs.Store("3c:a8:2a:04:01:00", true) // a stale binding to a switch
	ConfirmedESXiMACs.Store("1c:98:ec:04:00:01", true)
	ConfirmedESXiMACs.Store("00:1b:21:04:06:01", true)
	g := buildGraphFromSnapshot(devices)

	tag := func(tag, id string) string { // tag line as the build writes it
		if vendor := getMACVendor(id); vendor != "" {
			return tag + " " + vendor
		}
		return tag
	}
	want := map[string]string{
		"3c:a8:2a:04:01:00": "SW-50\n10.9.4.1",
		"1c:98:ec:04:00:01": tag("[LLDP-EP]", "1c:98:ec:04:00:01") + "\nagg-1\nHPE Comware Platform Software, Software Version 7.1.070",
		"94:57:a5:04:00:02": graphServerRelabel("94:57:a5:04:00:02", tag("[LLDP-EP]", "94:57:a5:04:00:02")+"\nweb01"),
		"f8:f0:82:04:00:03": tag("[LLDP-EP]", "f8:f0:82:04:00:03") + "\nSNR-S2995G-24FX Device, Compiled 2020",
		"5c:ed:8c:04:05:01": graphServerRelabel("5c:ed:8c:04:05:01", tag("[ENDPOINT]", "5c:ed:8c:04:05:01")),
		"00:1b:21:04:06:01": "[HYPERVISOR] VMware ESXi\n" + tag("[ENDPOINT]", "00:1b:21:04:06:01"),
	}
	for id, label := range want {
		if got := g.SwitchInfo[id]; got != label {
			t.Errorf("%s label = %q, want %q", id, got, label)
		}
	}
	groups := map[string]string{
		"3c:a8:2a:04:01:00": "switch",     // polled: never hypervisor
		"00:1b:21:04:06:01": "hypervisor", // confirmed ESXi with an [ENDPOINT] tag
	}
	for id, wantGroup := range groups {
		if got := g.determineDeviceGroup(id, g.SwitchInfo[id]); got != wantGroup {
			t.Errorf("%s group = %q, want %q", id, got, wantGroup)
		}
	}
	if got := g.determineDeviceGroup("1c:98:ec:04:00:01", g.SwitchInfo["1c:98:ec:04:00:01"]); got == "hypervisor" {
		t.Errorf("LLDP switch with a confirmed MAC is grouped hypervisor")
	}

	zabbix := map[string]bool{"f8:f0:82:04:02:00": true, "f8:f0:82:04:03:00": false, "f8:f0:82:04:00:03": true, "1c:98:ec:04:00:01": false}
	for id, snr := range zabbix {
		templates := g.GenerateZabbixTemplate(id)
		if got := strings.Contains(fmt.Sprint(templates), "SNR"); got != snr {
			t.Errorf("Zabbix templates of %s = %v, want SNR %v", id, templates, snr)
		}
	}

	// Q10 on its own: tags do not matter for a confirmed ESXi host, and an
	// unconfirmed [HYPERVISOR] prefix keeps today's precedence.
	clearConfirmedESXi()
	tg := NewDJGraph()
	for _, info := range []string{"[ENDPOINT] Dell", "[LLDP-EP]\nesx01", "[WiFi]", "[BMC] Dell iDRAC", "[HYPERVISOR] VMware ESXi\n[ENDPOINT]"} {
		const mac = "00:1b:21:04:07:01"
		if got := tg.determineDeviceGroup(mac, info); got == "hypervisor" {
			t.Errorf("unconfirmed %q grouped hypervisor", info)
		}
		ConfirmedESXiMACs.Store(mac, true)
		if got := tg.determineDeviceGroup(mac, info); got != "hypervisor" {
			t.Errorf("confirmed %q grouped %q", info, got)
		}
		clearConfirmedESXi()
	}
	if got := tg.determineDeviceGroup("5c:ed:8c:04:07:02", "[HYPERVISOR] HPE ProLiant Server\n[ENDPOINT] Intel"); got != "endpoint" {
		t.Errorf("unconfirmed server NIC grouped %q", got)
	}
}

// TestGraphIPEnrichment covers F68 (an IP is added unless it is a whole
// label line) and F69 (the hyp "VMs:" line lists the IP each VM label shows).
func TestGraphIPEnrichment(t *testing.T) {
	resetState(t)
	g := NewDJGraph()
	addInfoNode(g, "00:1b:21:03:00:01", "[ENDPOINT]\n10.10.10.68")
	addInfoNode(g, "00:1b:21:03:00:02", "[ENDPOINT]\n10.10.10.6")
	addInfoNode(g, "hyp-x-ge1_0_1", "[HYPERVISOR] VMware ESXi\n2 VMs on ge1/0/1")
	addInfoNode(g, "00:50:56:03:00:01", "[VM] 🐧 Linux VMware\n10.0.0.5")
	addInfoNode(g, "00:50:56:03:00:02", "[VM] 🐧 Linux VMware")
	g.AddEdge("hyp-x-ge1_0_1", "00:50:56:03:00:01", "vNIC")
	g.AddEdge("hyp-x-ge1_0_1", "00:50:56:03:00:02", "vNIC")
	globalMACtoIPMutex.Lock()
	globalMACtoIP = map[string]string{
		"00:1b:21:03:00:01": "10.10.10.6", "00:1b:21:03:00:02": "10.10.10.6",
		"00:50:56:03:00:01": "10.0.0.9", "00:50:56:03:00:02": "10.0.0.7",
	}
	globalMACtoIPMutex.Unlock()
	enrichGraphWithIPs(g)
	for id, want := range map[string]string{
		"00:1b:21:03:00:01": "[ENDPOINT]\n10.10.10.68\n10.10.10.6",
		"00:1b:21:03:00:02": "[ENDPOINT]\n10.10.10.6",
		"00:50:56:03:00:01": "[VM] 🐧 Linux VMware\n10.0.0.5\n10.0.0.9",
		"hyp-x-ge1_0_1":     "[HYPERVISOR] VMware ESXi\n2 VMs on ge1/0/1\nVMs: 10.0.0.5, 10.0.0.7",
	} {
		if got := g.SwitchInfo[id]; got != want {
			t.Errorf("%s = %q, want %q", id, got, want)
		}
	}
}

// TestGraphBuildDeterminism covers F45/Q16: repeated builds of the same
// devices give the same graph (map order never decides a label, an edge or
// a group), and a MAC seen by two switches is labelled by the first switch
// in IP order.
func TestGraphBuildDeterminism(t *testing.T) {
	resetState(t)
	devices := scenarioNetwork()
	// The same MAC on two switches with different local ARP answers: a direct
	// port on 10.0.9.2 (sw-a, port 22) and a hub port on 10.0.9.4 (sw-c).
	devices["10.0.9.2"].ARPTable = append(devices["10.0.9.2"].ARPTable, ARPEntry{IPAddress: "10.0.9.122", MACAddress: "00:1b:21:09:16:01"})
	devices["10.0.9.4"].MACTable = append(devices["10.0.9.4"].MACTable, macEntries(7, "00:1b:21:09:16:01", "00:1b:21:09:47:02")...)
	devices["10.0.9.4"].ARPTable = []ARPEntry{{IPAddress: "10.0.9.144", MACAddress: "00:1b:21:09:16:01"}}
	collectedDataMutex.Lock()
	collectedData = devices
	collectedDataMutex.Unlock()
	ConfirmedESXiMACs.Store("00:1b:21:09:03:01", true)

	var first graphView
	for i := 0; i < 30; i++ {
		g := buildGraphFromSnapshot(snapshotCollectedData())
		view := viewGraph(g)
		if i == 0 {
			first = view
			if got := g.SwitchInfo["00:1b:21:09:16:01"]; !strings.Contains(got, "\n10.0.9.122") || strings.Contains(got, "10.0.9.144") {
				t.Fatalf("MAC seen by two switches labelled %q, want the first switch's view", got)
			}
			continue
		}
		if fmt.Sprint(view) != fmt.Sprint(first) {
			t.Fatalf("build %d differs from the first build", i)
		}
	}
}
