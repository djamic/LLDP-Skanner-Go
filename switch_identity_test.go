package main

import (
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
