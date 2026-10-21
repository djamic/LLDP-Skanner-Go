package main

// Focused tests for the graph-logic fixes (switch identity, LLDP targets,
// FDB endpoint classification, hypervisor detection, groups and labels).

import (
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
