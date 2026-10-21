package main

import (
	"encoding/json"
	"fmt"
	"maps"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Tests for the analyzer fixes: one per-port Shadow-IT rule shared with the
// graph (Q14, F15, F16, F49), the loopback chassis guard (F17), the STP
// root check (F18), path depths (F19), anomalies on graph nodes (F11) and
// unique total_macs (F13, Q15).

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

// TestAnalyzerSTPRootBridges: a root bridge that is a polled switch (by its
// chassis MAC or an interface MAC) is fine; the others are reported, and the
// suggestion names the same root on every run (F18).
func TestAnalyzerSTPRootBridges(t *testing.T) {
	resetState(t)
	stp := func(root string) STPData { return STPData{Enabled: true, Protocol: "stp", RootBridgeID: root} }
	devices := []*DeviceData{
		{IP: "10.0.9.81", SysName: "sw-81", ChassisID: "4c:ae:a3:09:00:81", STPInfo: stp("4c:ae:a3:09:00:81")},
		{IP: "10.0.9.82", SysName: "sw-82", ChassisID: "4c:ae:a3:09:00:82", STPInfo: stp("4c:ae:a3:09:00:81")},
		{IP: "10.0.9.83", SysName: "sw-83", ChassisID: "4c:ae:a3:09:00:83", STPInfo: stp("00:16:e0:5a:5c:e0")},
		{IP: "10.0.9.84", SysName: "sw-84", ChassisID: "4c:ae:a3:09:00:84", STPInfo: stp("00:16:e0:5a:5c:e0")},
		{IP: "10.0.9.85", SysName: "sw-85", ChassisID: "4c:ae:a3:09:00:85", STPInfo: stp("00:16:e0:00:00:01")},
		{IP: "10.0.9.86", SysName: "sw-86", ChassisID: "4c:ae:a3:09:00:86", STPInfo: stp("4c:ae:a3:09:86:ff"),
			Interfaces: []InterfaceData{{IfIndex: 1, IfDescr: "Vlan1", IfPhysAddress: "4C:AE:A3:09:86:FF"}}},
	}
	topology := buildGraphFromSnapshot(analyzerDeviceMap(devices)).GetGraphData()
	rng := rand.New(rand.NewSource(1))
	for run := 0; run < 20; run++ {
		values := deviceValues(devices)
		rng.Shuffle(len(values), func(i, j int) { values[i], values[j] = values[j], values[i] })
		got := NewAnalyzer(FullCaptureData{DevicesData: values, Topology: topology}).analyzeSTP()
		if len(got) != 1 || got[0].Device != "00:16:e0:5a:5c:e0" || got[0].Value != "2 non-core roots" {
			t.Fatalf("run %d: got %+v, want one suggestion for root 00:16:e0:5a:5c:e0 with 2 non-core roots", run, got)
		}
	}
}

// TestAnalyzerReportsListAnomalies: /api/report/summary and the audit reports
// list the anomalies of the last analysis (F12).
func TestAnalyzerReportsListAnomalies(t *testing.T) {
	_, report := reportFixture(t)
	want := map[string]int{}
	for _, s := range report.Suggestions {
		want[s.Type]++
	}
	if len(want) == 0 {
		t.Fatal("the fixture analysis found no anomalies")
	}
	rr := httptest.NewRecorder()
	reportSummaryHandler(rr, httptest.NewRequest(http.MethodGet, "/api/report/summary", nil))
	var summary ReportSummary
	if err := json.Unmarshal(rr.Body.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}
	if !maps.Equal(summary.Anomalies, want) {
		t.Errorf("/api/report/summary anomalies %v, want %v", summary.Anomalies, want)
	}

	md := generateAuditMD([]string{"switch", "hub"})
	start, end := strings.Index(md, "## 6. Anomaliyalar"), strings.Index(md, "## 7.")
	if start < 0 || end < start {
		t.Fatalf("audit report has no section 6 before section 7")
	}
	rows := 0
	for _, line := range strings.Split(md[start:end], "\n") {
		if strings.HasPrefix(line, "| ") && !strings.HasPrefix(line, "| Turi |") {
			rows++
		}
	}
	if rows != len(report.Suggestions) {
		t.Errorf("audit section 6 has %d anomaly rows, want %d", rows, len(report.Suggestions))
	}
	if strings.Contains(md, "Anomaliyalar topilmadi") {
		t.Errorf("audit report says no anomalies were found")
	}

	rr = httptest.NewRecorder()
	reportFullHandler(rr, httptest.NewRequest(http.MethodGet, "/api/report/full", nil))
	if got := strings.Count(rr.Body.String(), "<tr><td>shadow_it</td><td>"); got != want["shadow_it"]+1 {
		t.Errorf("full report has %d shadow_it rows, want %d anomaly rows and the count row", got, want["shadow_it"])
	}
}

// TestAnalyzerTotalMACsCountsUniqueAddresses: total_macs is the number of
// distinct MAC addresses, not the number of FDB rows (F13, Q15).
func TestAnalyzerTotalMACsCountsUniqueAddresses(t *testing.T) {
	resetState(t)
	a := &DeviceData{IP: "10.0.9.71", ChassisID: "4c:ae:a3:09:00:71",
		MACTable: append(macEntries(1, "00:1b:21:09:71:01", "00:1b:21:09:71:02"), macEntries(24, "00:1b:21:09:72:01")...)}
	b := &DeviceData{IP: "10.0.9.72", ChassisID: "4c:ae:a3:09:00:72",
		MACTable: append(macEntries(1, "00:1b:21:09:72:01"), macEntries(24, "00:1B:21:09:71:01", "00:1b:21:09:71:02")...)}
	NewAnalyzer(FullCaptureData{DevicesData: devicesData(a, b)}).Analyze()
	lastReportMutex.RLock()
	got := lastTotalMACs
	lastReportMutex.RUnlock()
	if got != 3 {
		t.Errorf("total_macs = %d for 6 FDB rows of 3 addresses, want 3", got)
	}

	graph := buildFixtureGraph(t)
	analyzeFixture(t, graph)
	lastReportMutex.RLock()
	got = lastTotalMACs
	lastReportMutex.RUnlock()
	if got != 4569 {
		t.Errorf("fixture total_macs = %d, want the 4569 unique MACs", got)
	}
}

// analyzerPathChain is a chain of six switches from ids[0] (the core) with
// a hub and an endpoint below the last one. Every link points toward the
// core, as when the access switches were polled first.
func analyzerPathChain(ids []string, core GraphNode) GraphData {
	gd := GraphData{Nodes: []GraphNode{core}}
	for i, id := range ids[1:] {
		gd.Nodes = append(gd.Nodes, GraphNode{ID: id, Group: "switch", NodeType: "switch", SysName: fmt.Sprintf("sw-%d\n10.0.9.%d", 91+i, 91+i)})
	}
	gd.Nodes = append(gd.Nodes,
		GraphNode{ID: "hub-4c:ae:a3:09:00:95-p3", Group: "hub", NodeType: "hub", SysName: "[HUB] Unmanaged\n2 devices"},
		GraphNode{ID: "00:1b:21:09:95:01", Group: "endpoint", NodeType: "endpoint", SysName: "[ENDPOINT]"})
	for i := len(ids) - 1; i > 0; i-- {
		gd.Links = append(gd.Links, GraphLink{Source: ids[i], Target: ids[i-1], Label: "GE1/0/1|GE1/0/2"})
	}
	gd.Links = append(gd.Links,
		GraphLink{Source: ids[5], Target: "hub-4c:ae:a3:09:00:95-p3", Label: "GE1/0/3|Hub"},
		GraphLink{Source: "hub-4c:ae:a3:09:00:95-p3", Target: "00:1b:21:09:95:01"})
	return gd
}

// TestAnalyzerPathDepthsFromCore: the core is found from the gateway IP even
// when its node is MAC-keyed or only an LLDP endpoint, links count in both
// directions, and only switches and routers are reported (F19).
func TestAnalyzerPathDepthsFromCore(t *testing.T) {
	resetState(t)
	ids := []string{"4c:ae:a3:09:00:90", "4c:ae:a3:09:00:91", "4c:ae:a3:09:00:92", "4c:ae:a3:09:00:93", "4c:ae:a3:09:00:94", "4c:ae:a3:09:00:95"}
	far := []string{"4c:ae:a3:09:00:94", "4c:ae:a3:09:00:95"}
	cases := []struct {
		name string
		data FullCaptureData
		want []string
	}{
		{"polled core switch", FullCaptureData{
			DevicesData: devicesData(&DeviceData{IP: fixedGatewayIP, SysName: "core", ChassisID: "4c:ae:a3:09:00:90"}),
			Topology:    analyzerPathChain(ids, GraphNode{ID: ids[0], Group: "switch", NodeType: "switch", SysName: "core\n" + fixedGatewayIP}),
		}, far},
		{"core as LLDP endpoint", FullCaptureData{
			Topology: analyzerPathChain(ids, GraphNode{ID: ids[0], Group: "endpoint", NodeType: "endpoint", SysName: "[LLDP-EP] Cisco\ncore-gw\n" + fixedGatewayIP}),
		}, far},
		{"no core in topology", FullCaptureData{
			Topology: analyzerPathChain(ids, GraphNode{ID: ids[0], Group: "switch", NodeType: "switch", SysName: "core\n10.0.9.90"}),
		}, nil},
	}
	for _, c := range cases {
		var got []string
		for _, s := range NewAnalyzer(c.data).analyzePaths() {
			got = append(got, strings.TrimSuffix(s.Device[strings.LastIndex(s.Device, "(")+1:], ")"))
			if want := "Device is too far from Core (" + ids[0] + ")."; !strings.HasPrefix(s.Description, want) {
				t.Errorf("%s: description %q, want it to name the core %s", c.name, s.Description, ids[0])
			}
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: path suggestions for %v, want %v", c.name, got, c.want)
		}

		// The anomalies are keyed by the far nodes' ids (F11).
		NewAnalyzer(c.data).Analyze()
		lastReportMutex.RLock()
		keys := slices.Sorted(maps.Keys(lastAnomalyMap))
		lastReportMutex.RUnlock()
		if !slices.Equal(keys, c.want) {
			t.Errorf("%s: anomaly map keys %v, want the node ids %v", c.name, keys, c.want)
		}
	}
}

// TestAnalyzerAnomaliesOnGraphNodes: every anomaly is keyed by the graph node
// /api/graph draws: Shadow-IT on the hub node, the others on the switch node
// (F11).
func TestAnalyzerAnomaliesOnGraphNodes(t *testing.T) {
	graph := buildFixtureGraph(t)
	SetGlobalGraph(graph)
	report, _ := analyzeFixture(t, graph)
	graphDebugFile = filepath.Join(t.TempDir(), "graphs_data.txt")
	rr := httptest.NewRecorder()
	graphHandler(rr, httptest.NewRequest(http.MethodGet, "/api/graph", nil))
	var api GraphData
	if err := json.Unmarshal(rr.Body.Bytes(), &api); err != nil {
		t.Fatal(err)
	}
	shown := 0
	for _, n := range api.Nodes {
		for _, a := range n.Anomalies {
			if a == "stp" { // the fixture's STP root is not a graph node
				continue
			}
			shown++
			if a == "shadow_it" && !strings.HasPrefix(n.ID, "hub-") {
				t.Errorf("shadow_it anomaly on %s, want it on the hub node", n.ID)
			}
		}
	}
	want := 0
	for _, s := range report.Suggestions {
		if s.Type != "stp" {
			want++
		}
	}
	if want == 0 || shown != want {
		t.Errorf("/api/graph shows %d anomalies on nodes, the analysis has %d (stp not counted)", shown, want)
	}

	// A loopback and congestion on a switch whose node is its chassis MAC.
	resetState(t)
	sw := &DeviceData{
		IP: "10.0.9.22", SysName: "sw-22", ChassisID: "4c:ae:a3:09:00:22",
		Interfaces: gigabitPorts(9, nil),
		Neighbors:  []LLDPNeighbor{{LocalPortNum: 9, RemIndex: 1, RemChassisIdSubtype: 4, RemChassisId: "4C AE A3 09 00 22"}},
	}
	data := FullCaptureData{
		DevicesData: devicesData(sw),
		Topology:    buildGraphFromSnapshot(analyzerDeviceMap([]*DeviceData{sw})).GetGraphData(),
		Metrics:     []TrafficMetrics{{DeviceIP: "10.0.9.22", Interface: "GE1/0/2", InDiscards: 3}},
	}
	NewAnalyzer(data).Analyze()
	lastReportMutex.RLock()
	got := maps.Clone(lastAnomalyMap)
	lastReportMutex.RUnlock()
	if types := got["4c:ae:a3:09:00:22"]; len(got) != 1 || !slices.Contains(types, "loopback") || !slices.Contains(types, "congestion") {
		t.Errorf("anomaly map %v, want loopback and congestion on node 4c:ae:a3:09:00:22", got)
	}
}
