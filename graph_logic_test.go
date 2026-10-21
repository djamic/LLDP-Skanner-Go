package main

// Focused tests for the graph-logic fixes (switch identity, LLDP targets,
// FDB endpoint classification, hypervisor detection, groups and labels).

import (
	"fmt"
	"strings"
	"testing"
)

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
		if got := graphCanonicalMAC(c.in); got != c.want {
			t.Errorf("graphCanonicalMAC(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestGraphIsSNMPException(t *testing.T) {
	for in, want := range map[string]bool{
		"No Such Object available on this agent at this OID":                         true,
		"No Such Instance currently exists at this OID":                              true,
		"No more variables left in this MIB View (It is past the end of the MIB tree)": true,
		"no:such:object:available:on:this:agent:at:this:oid":                         true,
		"no:such:instance:currently:exists:at:this:oid":                              true,
		"\"No Such Object available on this agent at this OID\"":                     true,
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
		{"00:1b:21:06:07:01", "GE1/0/7|"},    // F48: the rejected neighbor does not hide it
		{"00:1b:21:06:02:01", "GE1/0/2 1G|001B21060201"}, // LLDP edge; not a hub member on port 5 (F46)
		{"00:1b:21:06:05:02", "GE1/0/5|"},    // port 5 is left with one MAC: direct endpoint
		{"00:50:56:aa:bb:cc", "GE1/0/6|"},    // F47: canonical node id
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
	globalMACtoIPMutex.Lock()
	globalMACtoIP = map[string]string{"00:1b:21:05:09:08": "10.0.9.13", "00:1b:21:05:0b:01": "172.20.0.48", "00:1b:21:05:0c:01": "172.16.25.231"}
	globalMACtoIPMutex.Unlock()
	ConfirmedESXiMACs.Store("00:1b:21:05:0a:01", true)

	g := buildGraphFromSnapshot(devices)
	for port, n := range map[string]int{"ge1_0_18": 4, "ge1_0_19": 21, "ge1_0_5": 2} {
		hyp := "hyp-" + src + "-" + port
		if !strings.Contains(g.SwitchInfo[hyp], fmt.Sprintf("\n%d VMs on ", n)) || len(g.Edges[hyp]) != n {
			t.Errorf("%s = %q with %d vNICs, want %d VMs", hyp, g.SwitchInfo[hyp], len(g.Edges[hyp]), n)
		}
	}
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
	if got := g.SwitchInfo["00:1b:21:05:09:08"]; got != "[BMC] Dell iDRAC\n10.0.9.13\n[DNS] srv01-idrac" {
		t.Errorf("hub member with a BMC DNS name = %q", got)
	}
	if g.Nodes["hub-"+src+"-p10"] {
		t.Errorf("port with a confirmed ESXi host became a hub")
	}
	if got := g.SwitchInfo["00:1b:21:05:0c:01"]; got != "[BMC] Fujitsu iRMC\n172.16.25.231" {
		t.Errorf("LLDP endpoint with a BMC DNS name = %q", got)
	}
}
