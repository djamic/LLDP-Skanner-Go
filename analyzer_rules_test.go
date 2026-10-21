package main

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// Tests for the analyzer fixes: one per-port Shadow-IT rule shared with the
// graph (Q14, F15, F16, F49) and the loopback chassis guard (F17).

func analyzerIssueIDs(suggestions []OptimizationSuggestion, typ string) []string {
	var out []string
	for _, s := range suggestions {
		if s.Type == typ {
			out = append(out, s.IssueID)
		}
	}
	return out
}

// analyzerGraphHubs lists the hub nodes of g as "<hub id> <n>", where n is
// the MAC count of the hub label ("[HUB] Unmanaged\n<n> devices").
func analyzerGraphHubs(g *DJGraph) []string {
	var out []string
	for id := range g.Nodes {
		if !strings.HasPrefix(id, "hub-") {
			continue
		}
		n := -1
		fmt.Sscanf(strings.TrimPrefix(g.SwitchInfo[id], "[HUB] Unmanaged\n"), "%d devices", &n)
		out = append(out, fmt.Sprintf("%s %d", id, n))
	}
	slices.Sort(out)
	return out
}

// analyzerShadowPorts lists the shadow_it suggestions the same way: the hub
// id the graph gives that switch port, and the MAC count of the alert.
func analyzerShadowPorts(t *testing.T, devices []*DeviceData, suggestions []OptimizationSuggestion) []string {
	t.Helper()
	srcID := map[string]string{}
	for _, d := range devices {
		id := normalizeID(d.ChassisID, 0)
		if id == "" {
			id = d.IP
		}
		srcID[d.IP] = id
	}
	var out []string
	for _, s := range suggestions {
		if s.Type != "shadow_it" {
			continue
		}
		port, ok := strings.CutPrefix(s.IssueID, "shadow_"+strings.ReplaceAll(s.Device, ".", "_")+"_")
		if !ok {
			t.Errorf("issue id %q does not name device %q", s.IssueID, s.Device)
			continue
		}
		n := -1
		fmt.Sscanf(s.Value, "%d MACs on single port", &n)
		if want := fmt.Sprintf("Port %s has %d MAC addresses.", port, n); !strings.HasPrefix(s.Description, want) {
			t.Errorf("%s: description %q does not start with %q", s.IssueID, s.Description, want)
		}
		out = append(out, fmt.Sprintf("hub-%s-p%s %d", srcID[s.Device], port, n))
	}
	slices.Sort(out)
	return out
}

// TestAnalyzerShadowITMatchesGraphHubs: on the fixture the Shadow-IT alerts
// are exactly the graph's hub nodes, port for port, with the hub's MAC count.
func TestAnalyzerShadowITMatchesGraphHubs(t *testing.T) {
	graph := buildFixtureGraph(t)
	collectedDataMutex.RLock()
	devices := sortedDevices(collectedData)
	collectedDataMutex.RUnlock()

	want := analyzerGraphHubs(graph)
	if len(want) == 0 {
		t.Fatal("the fixture graph has no hub nodes")
	}
	got := analyzerShadowPorts(t, devices, NewAnalyzer(captureData("hubs", devices, graph)).analyzeShadowIT())
	if !slices.Equal(got, want) {
		t.Errorf("Shadow-IT alerts and graph hubs differ:\nalerts (%d): %v\nhubs (%d): %v", len(got), got, len(want), want)
	}
}

// analyzerRuleNetwork is a switch with one port per filter of the per-port
// rule, plus a second polled switch whose chassis MAC it has learned.
func analyzerRuleNetwork() []*DeviceData {
	var macs []MACEntry
	add := func(port int, list ...string) { macs = append(macs, macEntries(port, list...)...) }
	var uplink, edge []string
	for i := 1; i <= 21; i++ {
		uplink = append(uplink, fmt.Sprintf("00:1b:21:60:03:%02x", i))
	}
	for i := 1; i <= 20; i++ {
		edge = append(edge, fmt.Sprintf("00:1b:21:60:04:%02x", i))
	}
	add(1, "00:1b:21:60:01:01", "00:1b:21:60:01:02", "00:1b:21:60:01:03")                                            // LLDP neighbor on the port
	add(2, "00:1b:21:60:02:01", "00:1b:21:60:02:02")                                                                 // hub
	add(3, uplink...)                                                                                                // more than 20 MACs: implicit uplink
	add(4, edge...)                                                                                                  // 20 MACs: still a hub
	add(5, "00:1b:21:60:05:01", "00:1b:21:60:05:02")                                                                 // trunk
	add(6, "00:1b:21:60:06:01", "4c:ae:a3:60:00:60")                                                                 // own chassis MAC
	add(7, "00:1b:21:60:07:01", "4c:ae:a3:60:00:61")                                                                 // other polled switch
	add(8, "00:1b:21:60:08:01", "00:1b:21:60:09:99")                                                                 // chassis MAC of an LLDP neighbor
	add(10, "00:1b:21:60:0a:01", "ff:ff:ff:ff:ff:ff")                                                                // invalid MAC
	add(11, "00:50:56:60:0b:01", "00:50:56:60:0b:02", "00:1b:21:60:0b:03")                                           // VM majority
	add(12, "00:50:56:60:0c:01", "00:1b:21:60:0c:02")                                                                // exactly half VM: hub
	add(13, "00:50:56:60:0d:01", "00:50:56:60:0d:02", "da:a1:19:60:0d:03", "de:a1:19:60:0d:04", "00:1b:21:60:0d:05") // F16
	add(14, "00:1b:21:60:0e:01", "da:a1:19:60:0e:02", "de:a1:19:60:0e:03")                                           // random MACs count
	add(15, "52:54:00:60:0f:01", "52:54:00:60:0f:02")                                                                // KVM pair: VM port
	add(16, "00:1b:21:60:10:01", "00:1b:21:60:10:02")                                                                // HTTP-confirmed ESXi host
	add(17, "00:1b:21:60:11:01", "00:1b:21:60:11:02")                                                                // ignored issue
	add(29, "00:1b:21:60:1d:01", "00:1b:21:60:1d:02")                                                                // NULL0
	add(30, "00:1b:21:60:1e:01", "00:1b:21:60:1e:02")                                                                // InLoopBack0
	sw := &DeviceData{
		IP: "10.0.9.60", SysName: "sw-60", ChassisID: "4c:ae:a3:60:00:60",
		Interfaces: gigabitPorts(30, map[int]string{29: "NULL0", 30: "InLoopBack0"}),
		PortVLANs:  []PortVLAN{{PortIndex: 5, PVID: 1, IsTrunk: true}},
		Neighbors: []LLDPNeighbor{
			{LocalPortNum: 1, RemIndex: 1, RemChassisIdSubtype: 4, RemChassisId: "4C AE A3 60 00 62", RemSysName: "sw-62"},
			{LocalPortNum: 9, RemIndex: 2, RemChassisIdSubtype: 4, RemChassisId: "00 1B 21 60 09 99", RemSysName: "phone-9"},
		},
		MACTable: macs,
	}
	other := &DeviceData{IP: "10.0.9.61", SysName: "sw-61", ChassisID: "4c:ae:a3:60:00:61", Interfaces: gigabitPorts(4, nil)}
	return []*DeviceData{sw, other}
}

func analyzerDeviceMap(devices []*DeviceData) map[string]*DeviceData {
	m := map[string]*DeviceData{}
	for _, d := range devices {
		cp := *d
		m[d.IP] = &cp
	}
	return m
}

// TestAnalyzerShadowITPortRule pins every filter of the per-port rule and
// checks that, without ESXi hosts or ignored issues, the alerts are the hubs
// of the graph built from the same devices.
func TestAnalyzerShadowITPortRule(t *testing.T) {
	resetState(t)
	devices := analyzerRuleNetwork()
	graph := buildGraphFromSnapshot(analyzerDeviceMap(devices))
	data := FullCaptureData{DevicesData: deviceValues(devices), Topology: graph.GetGraphData()}

	plain := NewAnalyzer(data).analyzeShadowIT()
	wantAll := []string{"shadow_10_0_9_60_2", "shadow_10_0_9_60_4", "shadow_10_0_9_60_12", "shadow_10_0_9_60_13", "shadow_10_0_9_60_14", "shadow_10_0_9_60_16", "shadow_10_0_9_60_17"}
	if got := analyzerIssueIDs(plain, "shadow_it"); !slices.Equal(got, wantAll) {
		t.Errorf("Shadow-IT ports:\n got %v\nwant %v", got, wantAll)
	}
	if got, want := analyzerShadowPorts(t, devices, plain), analyzerGraphHubs(graph); !slices.Equal(got, want) {
		t.Errorf("alerts and graph hubs differ:\nalerts %v\nhubs   %v", got, want)
	}
	values := map[string]string{}
	for _, s := range plain {
		values[s.IssueID] = s.Value
	}
	for id, want := range map[string]string{
		"shadow_10_0_9_60_4":  "20 MACs on single port",
		"shadow_10_0_9_60_13": "5 MACs on single port", // the same list decides, is checked for VMs and is counted (F16)
		"shadow_10_0_9_60_14": "3 MACs on single port", // random MACs are not dropped (graph rule)
	} {
		if values[id] != want {
			t.Errorf("%s: value %q, want %q", id, values[id], want)
		}
	}

	ConfirmedESXiMACs.Store("00:1b:21:60:10:01", true)
	ignoredIssuesMutex.Lock()
	ignoredIssuesData["shadow_10_0_9_60_17"] = true
	ignoredIssuesMutex.Unlock()
	exempt := NewAnalyzer(data).analyzeShadowIT()
	wantExempt := []string{"shadow_10_0_9_60_2", "shadow_10_0_9_60_4", "shadow_10_0_9_60_12", "shadow_10_0_9_60_13", "shadow_10_0_9_60_14"}
	if got := analyzerIssueIDs(exempt, "shadow_it"); !slices.Equal(got, wantExempt) {
		t.Errorf("with an ESXi host on port 16 and port 17 ignored:\n got %v\nwant %v", got, wantExempt)
	}
}

// TestAnalyzerExperimentMetricsFollowGraph: the experiment's Shadow-IT and VM
// port counts use the same per-port rule as the graph and the alerts (F49).
func TestAnalyzerExperimentMetricsFollowGraph(t *testing.T) {
	graph := buildFixtureGraph(t)
	metrics := experimentMetrics(t, graph)
	if got, want := fmt.Sprint(metrics["shadow_it_filtered"]), fmt.Sprint(len(analyzerGraphHubs(graph))); got != want {
		t.Errorf("fixture shadow_it_filtered = %s, the graph has %s hubs", got, want)
	}

	resetState(t)
	devices := analyzerRuleNetwork()
	collectedDataMutex.Lock()
	collectedData = analyzerDeviceMap(devices)
	collectedDataMutex.Unlock()
	ruleGraph := buildGraphFromSnapshot(snapshotCollectedData())
	check := func(name string, want map[string]int) {
		t.Helper()
		got := experimentMetrics(t, ruleGraph)
		for k, v := range want {
			if fmt.Sprint(got[k]) != fmt.Sprint(v) {
				t.Errorf("%s: %s = %v, want %d", name, k, got[k], v)
			}
		}
	}
	// Candidates: ports 2, 4, 11-17; VM ports: 11 (VMware) and 15 (KVM).
	check("rule network", map[string]int{"shadow_it_raw": 9, "shadow_it_filtered": 7, "vm_ports_filtered": 2, "unique_macs": 79, "vm_macs": 7})
	ConfirmedESXiMACs.Store("00:1b:21:60:10:01", true)
	check("rule network with an ESXi host on port 16", map[string]int{"shadow_it_raw": 9, "shadow_it_filtered": 6, "vm_ports_filtered": 3})
}

// TestAnalyzerLoopbackChassisGuard: a switch whose chassis id is empty (or
// null) cannot recognise itself, so it never reports a loopback (F17).
func TestAnalyzerLoopbackChassisGuard(t *testing.T) {
	resetState(t)
	cases := []struct {
		name, local, remote string
		macs                []MACEntry
		want                []string
	}{
		{name: "both chassis ids empty", local: "", remote: ""},
		{name: "local chassis id empty", local: "", remote: "4C AE A3 09 00 70"},
		{name: "remote chassis id empty", local: "4c:ae:a3:09:00:70", remote: ""},
		{name: "both chassis ids null", local: "00:00:00:00:00:00", remote: "00 00 00 00 00 00"},
		{name: "empty chassis id and an empty FDB MAC", local: "", remote: "", macs: macEntries(4, "")},
		{name: "own chassis as LLDP neighbor", local: "4c:ae:a3:09:00:70", remote: "4C AE A3 09 00 70", want: []string{"loop_lldp_10_0_9_70_3"}},
		{name: "own chassis MAC in the FDB", local: "4c:ae:a3:09:00:70", remote: "4C AE A3 09 00 71", macs: macEntries(4, "4c:ae:a3:09:00:70"), want: []string{"loop_mac_10_0_9_70_4"}},
	}
	for _, c := range cases {
		d := &DeviceData{
			IP: "10.0.9.70", ChassisID: c.local,
			Interfaces: gigabitPorts(4, nil),
			Neighbors:  []LLDPNeighbor{{LocalPortNum: 3, RemIndex: 1, RemChassisId: c.remote}},
			MACTable:   c.macs,
		}
		got := analyzerIssueIDs(NewAnalyzer(FullCaptureData{DevicesData: devicesData(d)}).analyzeLoopback(), "loopback")
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
