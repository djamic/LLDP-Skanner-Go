package main

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
)

// identityDevices are two polled switches whose stored chassis ids are not
// canonical: a Cisco-dotted MAC (as saved data from before the graph fix
// holds it) and net-snmp exception text. The dotted switch has a looped
// cable (it is its own LLDP neighbor on port 2 and learns its own MAC on
// port 3), is the STP root of both, has an LLDP neighbor on port 1 and a
// hub on port 4. The other switch has a neighbor without a chassis id.
func identityDevices() map[string]*DeviceData {
	dotted := &DeviceData{
		IP: "10.0.9.90", SysName: "cisco-90", ChassisID: "5894.8000.f7a3",
		Interfaces: gigabitPorts(6, nil),
		Neighbors: []LLDPNeighbor{
			{LocalPortNum: 1, RemIndex: 1, RemChassisIdSubtype: 4, RemChassisId: "4C AE A3 90 00 01", RemSysName: "sw-far"},
			{LocalPortNum: 2, RemIndex: 2, RemChassisIdSubtype: 4, RemChassisId: "58 94 80 00 F7 A3", RemSysName: "cisco-90"},
		},
		MACTable: append(macEntries(3, "58:94:80:00:f7:a3"), macEntries(4, "00:1b:21:90:04:01", "00:1b:21:90:04:02")...),
		STPInfo:  STPData{Enabled: true, RootBridgeID: "58:94:80:00:f7:a3"},
	}
	exception := &DeviceData{
		IP: "10.0.9.91", SysName: "sw-91", ChassisID: "no:such:object:available:on:this:agent:at:this:oid",
		Interfaces: gigabitPorts(2, nil),
		Neighbors:  []LLDPNeighbor{{LocalPortNum: 1, RemIndex: 1, RemChassisIdSubtype: 4, RemChassisId: ""}},
		STPInfo:    STPData{Enabled: true, RootBridgeID: "58:94:80:00:f7:a3"},
	}
	return map[string]*DeviceData{dotted.IP: dotted, exception.IP: exception}
}

// TestSwitchIdentitySites (H4, Q12): every place that names a polled switch
// uses the graph's identity (graphDeviceNodeID, graphChassisKey): the report
// and BFS root lookup (reportDeviceNode), the traffic label refresh, the
// analyzer's loopback check (with the F17 guard), its STP root check and the
// graph nodes its anomalies are shown on.
func TestSwitchIdentitySites(t *testing.T) {
	resetState(t)
	devices := identityDevices()
	collectedDataMutex.Lock()
	collectedData = devices
	collectedDataMutex.Unlock()
	const dottedNode, exceptionNode = "58:94:80:00:f7:a3", "10.0.9.91"
	g := buildGraphFromSnapshot(snapshotCollectedData())
	if !g.Nodes[dottedNode] || !g.Nodes[exceptionNode] {
		t.Fatalf("graph switch nodes missing: %v", slices.Sorted(maps.Keys(g.Nodes)))
	}

	for ip, want := range map[string]string{"10.0.9.90": dottedNode, "10.0.9.91": exceptionNode} {
		if got := reportDeviceNode(g, devices[ip]); got != want {
			t.Errorf("reportDeviceNode(%s) = %q, want %q", ip, got, want)
		}
	}

	// Traffic labels of the dotted switch's links are refreshed
	SetGlobalGraph(g)
	interfaceTrafficMapMutex.Lock()
	interfaceTrafficMap["10.0.9.90"] = map[int]*InterfaceTraffic{1: {InSpeed: 5_000_000, OutSpeed: 3_000_000}}
	interfaceTrafficMapMutex.Unlock()
	refreshGraphEdgeLabels()
	if label := GetGlobalGraph().GetEdgeLabel(dottedNode, "4c:ae:a3:90:00:01"); !strings.Contains(label, "↓5M ↑3M") {
		t.Errorf("refreshed label of the dotted switch's port 1 = %q, want traffic", label)
	}

	na := NewAnalyzer(captureData("identity", sortedDevices(devices), g))
	report := na.BuildReport()
	var loops, stp []string
	for _, s := range report.Suggestions {
		switch s.Type {
		case "loopback":
			loops = append(loops, s.IssueID)
		case "stp":
			stp = append(stp, s.Device)
		}
	}
	slices.Sort(loops)
	if want := []string{"loop_lldp_10_0_9_90_2", "loop_mac_10_0_9_90_3"}; !slices.Equal(loops, want) {
		t.Errorf("loopback issues = %v, want %v (none for the switch without a chassis id, F17)", loops, want)
	}
	if len(stp) != 0 {
		t.Errorf("the polled dotted switch is the STP root, but stp suggestions name %v", stp)
	}
	anomalies := na.anomalyMap(report.Suggestions)
	if !slices.Contains(anomalies[dottedNode], "loopback") || !slices.Contains(anomalies["hub-"+dottedNode+"-p4"], "shadow_it") {
		t.Errorf("anomalies are not on the dotted switch's graph nodes: %v", anomalies)
	}
}

// bridgePortDevices is a switch numbered like Huawei 172.20.254.249:
// ifIndex 1 InLoopBack0, 2 NULL0, 6.. GigabitEthernet0/0/1.., and bridge
// port N is ifIndex N+5 (dot1dBasePortIfIndex). Bridge ports 1 and 2 hold
// one endpoint each, bridge port 19 two MACs (a hub), bridge port 3 the
// chassis MAC of a second polled switch; the VLAN table is indexed by bridge
// port, and bridge port 4 is a trunk with two MACs.
func bridgePortDevices() map[string]*DeviceData {
	var ifaces []InterfaceData
	ifaces = append(ifaces, InterfaceData{IfIndex: 1, IfDescr: "\"InLoopBack0\""}, InterfaceData{IfIndex: 2, IfDescr: "\"NULL0\""})
	for i := 1; i <= 24; i++ {
		ifaces = append(ifaces, InterfaceData{IfIndex: i + 5, IfDescr: fmt.Sprintf("\"GigabitEthernet0/0/%d\"", i), IfSpeed: 1000000000, IfOperStatus: 1})
	}
	bridge := map[int]int{}
	for p := 1; p <= 24; p++ {
		bridge[p] = p + 5
	}
	var fdb []MACEntry
	fdb = append(fdb, macEntries(1, "00:1b:21:95:01:01")...)
	fdb = append(fdb, macEntries(2, "00:1b:21:95:02:01")...)
	fdb = append(fdb, macEntries(3, "4c:ae:a3:95:00:02")...)
	fdb = append(fdb, macEntries(4, "00:1b:21:95:04:01", "00:1b:21:95:04:02")...)
	fdb = append(fdb, macEntries(19, "00:1b:21:95:13:01", "00:1b:21:95:13:02")...)
	huawei := &DeviceData{
		IP: "10.0.9.95", SysName: "huawei-95", ChassisID: "4c:ae:a3:95:00:01",
		Interfaces: ifaces, BridgePortIfIndex: bridge, MACTable: fdb,
		PortVLANs: []PortVLAN{{PortIndex: 4, PVID: 1, IsTrunk: true}, {PortIndex: 19, PVID: 30}},
	}
	other := &DeviceData{IP: "10.0.9.96", SysName: "sw-96", ChassisID: "4c:ae:a3:95:00:02", Interfaces: gigabitPorts(2, nil)}
	return map[string]*DeviceData{huawei.IP: huawei, other.IP: other}
}

// TestFDBPortNames (H5, F60): FDB ports are bridge ports, so the graph names
// them through dot1dBasePortIfIndex (getFDBPortName): bridge ports 1 and 2
// are GE0/0/1 and GE0/0/2, not the InLoopBack0/NULL0 interfaces with those
// ifIndexes, and the hub on bridge port 19 is GE0/0/19. Hub ids, Shadow-IT
// issue ids and the bridge-port indexed VLAN and trunk lookups keep the
// bridge port.
func TestFDBPortNames(t *testing.T) {
	resetState(t)
	devices := bridgePortDevices()
	collectedDataMutex.Lock()
	collectedData = devices
	collectedDataMutex.Unlock()
	const src = "4c:ae:a3:95:00:01"
	g := buildGraphFromSnapshot(snapshotCollectedData())

	for mac, want := range map[string]string{"00:1b:21:95:01:01": "GE0/0/1|", "00:1b:21:95:02:01": "GE0/0/2|"} {
		if got, ok := g.Edges[src][mac]; !ok || got != want {
			t.Errorf("edge to %s = %q (present %v), want %q", mac, got, ok, want)
		}
	}
	hub := "hub-" + src + "-p19"
	if got := g.GetEdgeLabel(src, hub); got != "GE0/0/19|Hub" {
		t.Errorf("hub edge %s = %q, want GE0/0/19|Hub", hub, got)
	}
	if got := g.GetEdgeLabel(src, "4c:ae:a3:95:00:02"); got != "GE0/0/3 [MAC-REF]|" {
		t.Errorf("MAC-REF edge = %q, want GE0/0/3 [MAC-REF]|", got)
	}
	if g.Nodes["hub-"+src+"-p4"] {
		t.Error("the trunk on bridge port 4 became a hub")
	}

	report := NewAnalyzer(captureData("ports", sortedDevices(devices), g)).BuildReport()
	var shadow []string
	for _, s := range report.Suggestions {
		if s.Type == "shadow_it" {
			shadow = append(shadow, s.IssueID)
		}
	}
	if want := []string{"shadow_10_0_9_95_19"}; !slices.Equal(shadow, want) {
		t.Errorf("Shadow-IT issues = %v, want %v", shadow, want)
	}
}

// TestChassisIDKeptOnFlakyPoll (H9): a switch whose agent sometimes answers
// lldpLocChassisId with exception text or not at all (172.20.230.40
// alternates) keeps its last valid chassis id, so its node id does not flip
// to the IP and back between polls. A new valid chassis id replaces the old
// one, and a switch that never had a valid one stays an IP node.
func TestChassisIDKeptOnFlakyPoll(t *testing.T) {
	resetState(t)
	const ip = "10.9.8.40"
	agent := func(chassis string) map[string][]string {
		walks := map[string][]string{oidIfDescr: {oidIfDescr + ".1 = STRING: \"Gi0/1\""}}
		if chassis != "" {
			walks[oidChassis] = []string{oidChassis + " = " + chassis}
		}
		return walks
	}
	obj := newRescanSNMPObject()
	nodeID := func() string {
		collectedDataMutex.RLock()
		defer collectedDataMutex.RUnlock()
		return graphDeviceNodeID(collectedData[ip])
	}
	for _, step := range []struct{ name, chassis, want string }{
		{"dotted chassis", `STRING: "5894.8000.f7a3"`, "58:94:80:00:f7:a3"},
		{"exception text", "No Such Object available on this agent at this OID", "58:94:80:00:f7:a3"},
		{"chassis walk fails", "", "58:94:80:00:f7:a3"},
		{"null chassis", "Hex-STRING: 00 00 00 00 00 00 ", "58:94:80:00:f7:a3"},
		{"new valid chassis", "Hex-STRING: 4C AE A3 09 08 40 ", "4c:ae:a3:09:08:40"},
	} {
		fakeSNMP.set(ip, agent(step.chassis))
		obj.CollectData(ip, "flaky")
		if got := nodeID(); got != step.want {
			t.Errorf("%s: node id = %q, want %q", step.name, got, step.want)
		}
	}

	const never = "10.9.8.41"
	fakeSNMP.set(never, agent("No Such Instance currently exists at this OID"))
	obj.CollectData(never, "never")
	collectedDataMutex.RLock()
	d := collectedData[never]
	collectedDataMutex.RUnlock()
	if d == nil || d.ChassisID != "" || graphDeviceNodeID(d) != never {
		t.Errorf("switch without a valid chassis id: %+v", d)
	}
}
