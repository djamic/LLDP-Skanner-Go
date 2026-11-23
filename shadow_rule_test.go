package main

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"lldp_scanner/modules"
)

// shadowRuleViews lists one network's Shadow-IT ports as each consumer sees
// them, as "hub-<switch node>-p<port> <MACs>" (the report and the UI list
// hub ids only): the graph's hub nodes, the analyzer's alerts, the audit
// report's Shadow-IT section, the experiment metrics' hub count, and the UI's
// Shadow-IT modal on the /api/graph data (uiOK is false without Node.js).
// devices must be in collectedData (the report checks the live FDB tables).
func shadowRuleViews(t *testing.T, devices []*DeviceData) (g *DJGraph, graphHubs, alerts, reportHubs []string, metricHubs int, uiHubs []string, uiOK bool) {
	t.Helper()
	byIP := make(map[string]*DeviceData, len(devices))
	for _, d := range devices {
		byIP[d.IP] = d
	}
	g = buildGraphFromSnapshot(byIP)
	graphHubs = analyzerGraphHubs(g)
	alerts = analyzerShadowPorts(t, devices, NewAnalyzer(captureData("rule", devices, g)).analyzeShadowIT())
	reportHubs = reportShadowHubs(g, GenerateShadowDiagrams(g))
	metricHubs = analyzerShadowCounts(devices).Hubs
	uiHubs, uiOK = uiShadowModalHubs(t, g.GetGraphData())
	return g, graphHubs, alerts, reportHubs, metricHubs, uiHubs, uiOK
}

// shadowHubIDs drops the MAC counts of shadowRuleViews' lists.
func shadowHubIDs(views []string) []string {
	var ids []string
	for _, v := range views {
		id, _, _ := strings.Cut(v, " ")
		ids = append(ids, id)
	}
	return ids
}

// checkShadowRuleViews fails unless the graph, the alerts, the report, the
// metrics and the UI modal list the same Shadow-IT ports. It returns the
// graph and its hubs.
func checkShadowRuleViews(t *testing.T, name string, devices []*DeviceData) (*DJGraph, []string) {
	t.Helper()
	g, graphHubs, alerts, reportHubs, metricHubs, uiHubs, uiOK := shadowRuleViews(t, devices)
	hubIDs := shadowHubIDs(graphHubs)
	if !slices.Equal(alerts, graphHubs) {
		t.Errorf("%s: alerts and graph hubs differ:\nalerts (%d): %v\nhubs (%d): %v", name, len(alerts), alerts, len(graphHubs), graphHubs)
	}
	if !slices.Equal(reportHubs, hubIDs) {
		t.Errorf("%s: report section and graph hubs differ:\nreport (%d): %v\nhubs (%d): %v", name, len(reportHubs), reportHubs, len(hubIDs), hubIDs)
	}
	if metricHubs != len(graphHubs) {
		t.Errorf("%s: experiment shadow_it_filtered = %d, graph has %d hubs", name, metricHubs, len(graphHubs))
	}
	if uiOK && !slices.Equal(uiHubs, hubIDs) {
		t.Errorf("%s: UI Shadow-IT modal and graph hubs differ:\nmodal (%d): %v\nhubs (%d): %v", name, len(uiHubs), uiHubs, len(hubIDs), hubIDs)
	}
	return g, graphHubs
}

// shadowRuleNetwork is a switch whose LLDP neighbors the graph resolves
// differently from the raw chassis ids: a neighbor with a null chassis id is
// dropped (so its port is no LLDP port), and a phone named by its chassis id
// is known by its port MAC (so that MAC, learned on another port, is no hub
// member). Port 6 carries an HTTP-confirmed ESXi host, port 7 is a plain hub.
func shadowRuleNetwork() []*DeviceData {
	var fdb []MACEntry
	fdb = append(fdb, macEntries(3, "00:1b:21:80:03:01", "00:1b:21:80:03:02")...)
	fdb = append(fdb, macEntries(5, "00:1b:21:80:04:99", "00:1b:21:80:05:01", "00:1b:21:80:05:02")...)
	fdb = append(fdb, macEntries(6, "00:1b:21:80:06:01", "00:1b:21:80:06:02")...)
	fdb = append(fdb, macEntries(7, "00:1b:21:80:07:01", "00:1b:21:80:07:02")...)
	return []*DeviceData{{
		IP: "10.0.9.80", SysName: "sw-80", ChassisID: "4c:ae:a3:80:00:80",
		Interfaces: gigabitPorts(12, nil),
		Neighbors: []LLDPNeighbor{
			{LocalPortNum: 3, RemIndex: 1, RemChassisIdSubtype: 4, RemChassisId: "00 00 00 00 00 00", RemPortIdSubtype: 5, RemPortId: "eth0"},
			{LocalPortNum: 4, RemIndex: 2, RemChassisIdSubtype: 7, RemChassisId: "phone-4", RemPortIdSubtype: 3, RemPortId: "00 1B 21 80 04 99", RemSysName: "phone-4"},
		},
		MACTable: fdb,
	}}
}

// TestShadowITOneRule (H1, Q14): the graph's hubs, the Shadow-IT alerts, the
// experiment metrics, the audit's Shadow-IT section and the UI's Shadow-IT
// modal come from one per-port rule (fdbPorts), so they list the same
// ports: on a switch whose LLDP neighbors the graph resolves differently
// from the raw chassis ids, on the fixture, and on the fixture with
// HTTP-confirmed ESXi hosts, also when a host is confirmed after the graph
// was built.
func TestShadowITOneRule(t *testing.T) {
	resetState(t)
	devices := shadowRuleNetwork()
	collectedDataMutex.Lock()
	collectedData = map[string]*DeviceData{devices[0].IP: devices[0]}
	collectedDataMutex.Unlock()
	ConfirmedESXiMACs.Store("00:1b:21:80:06:02", true)
	_, got := checkShadowRuleViews(t, "synthetic", devices)
	want := []string{"hub-4c:ae:a3:80:00:80-p3 2", "hub-4c:ae:a3:80:00:80-p5 2", "hub-4c:ae:a3:80:00:80-p7 2"}
	if !slices.Equal(got, want) {
		t.Errorf("synthetic hubs = %v, want %v", got, want)
	}
	stats := analyzerShadowCounts(devices)
	if stats.Candidates != 4 || stats.Hubs != 3 || stats.VMPorts != 1 {
		t.Errorf("synthetic metrics = %+v, want 4 candidates, 3 hubs, 1 ESXi port", stats)
	}

	useFixture(t)
	collectedDataMutex.RLock()
	fixture := sortedDevices(collectedData)
	collectedDataMutex.RUnlock()
	_, plain := checkShadowRuleViews(t, "fixture", fixture)
	for _, mac := range esxiConfirmedMACs {
		ConfirmedESXiMACs.Store(mac, true)
	}
	_, esxi := checkShadowRuleViews(t, "fixture with ESXi hosts", fixture)
	if len(esxi) >= len(plain) {
		t.Errorf("the confirmed ESXi hosts exempt no hub: %d hubs, %d without them", len(esxi), len(plain))
	}

	// A host confirmed after the build: the report, the alerts and the UI
	// modal (the member's group is read when the graph is served) follow the
	// live rule at once, and the next build drops the hub.
	clearConfirmedESXi()
	byIP := make(map[string]*DeviceData, len(fixture))
	for _, d := range fixture {
		byIP[d.IP] = d
	}
	g := buildGraphFromSnapshot(byIP)
	ConfirmedESXiMACs.Store("5c:62:8b:b8:b3:11", true) // hub member on 172.20.230.11 port 11
	section := reportShadowHubs(g, GenerateShadowDiagrams(g))
	alerts := analyzerShadowPorts(t, fixture, NewAnalyzer(captureData("late", fixture, g)).analyzeShadowIT())
	if len(section) != len(plain)-1 || len(alerts) != len(plain)-1 {
		t.Errorf("host confirmed after the build: report lists %d hubs, alerts %d, want %d", len(section), len(alerts), len(plain)-1)
	}
	if ui, ok := uiShadowModalHubs(t, g.GetGraphData()); ok && !slices.Equal(ui, shadowHubIDs(alerts)) {
		t.Errorf("host confirmed after the build: UI modal lists %v, alerts %v", ui, shadowHubIDs(alerts))
	}
}

// TestShadowITIgnored: a Shadow-IT hub whose alert the owner ignores
// (Telegram's Ignore, IsIssueIgnored) is still drawn, and its node says so
// (GraphNode.Ignored, by its syntheticNode.Issue); the alerts, the audit
// report's Shadow-IT section and the UI's Shadow-IT modal all leave it out.
func TestShadowITIgnored(t *testing.T) {
	resetState(t)
	devices := shadowRuleNetwork()
	collectedDataMutex.Lock()
	collectedData = map[string]*DeviceData{devices[0].IP: devices[0]}
	collectedDataMutex.Unlock()
	ConfirmedESXiMACs.Store("00:1b:21:80:06:02", true)
	const ignored = "hub-4c:ae:a3:80:00:80-p5"
	ignoredIssuesMutex.Lock()
	ignoredIssuesData[shadowITIssueID("10.0.9.80", 5)] = true
	ignoredIssuesMutex.Unlock()

	g, graphHubs, alerts, reportHubs, _, uiHubs, uiOK := shadowRuleViews(t, devices)
	if want := []string{"hub-4c:ae:a3:80:00:80-p3", ignored, "hub-4c:ae:a3:80:00:80-p7"}; !slices.Equal(shadowHubIDs(graphHubs), want) {
		t.Errorf("graph hubs = %v, want %v (an ignored hub is still drawn)", graphHubs, want)
	}
	want := []string{"hub-4c:ae:a3:80:00:80-p3", "hub-4c:ae:a3:80:00:80-p7"}
	if !slices.Equal(shadowHubIDs(alerts), want) {
		t.Errorf("alerts = %v, want %v", alerts, want)
	}
	if !slices.Equal(reportHubs, want) {
		t.Errorf("report section = %v, want %v", reportHubs, want)
	}
	if uiOK && !slices.Equal(uiHubs, want) {
		t.Errorf("UI modal = %v, want %v", uiHubs, want)
	}
	for _, n := range g.GetGraphData().Nodes {
		if n.Group == "hub" && n.Ignored != (n.ID == ignored) {
			t.Errorf("%s: ignored = %v", n.ID, n.Ignored)
		}
	}
}

// shadowVMHubNetwork is a switch with three hubs. Port 5 holds two VMware VM
// NICs and three PCs: the VMs are no majority, so the port is a hub, and
// detectHypervisors puts a hyp- node (group hypervisor, label "[HYPERVISOR]
// VMware ESXi") between the hub and the two VMs. Port 7 is a plain hub and
// port 9 a hub with one VM NIC (no hyp- node).
func shadowVMHubNetwork() []*DeviceData {
	var fdb []MACEntry
	fdb = append(fdb, macEntries(5, "00:50:56:81:05:01", "00:50:56:81:05:02", "00:1b:21:81:05:03", "00:1b:21:81:05:04", "00:1b:21:81:05:05")...)
	fdb = append(fdb, macEntries(7, "00:1b:21:81:07:01", "00:1b:21:81:07:02")...)
	fdb = append(fdb, macEntries(9, "00:0c:29:81:09:01", "00:1b:21:81:09:02", "00:1b:21:81:09:03", "00:1b:21:81:09:04")...)
	return []*DeviceData{{IP: "10.0.9.81", SysName: "sw-81", ChassisID: "4c:ae:a3:81:00:81", Interfaces: gigabitPorts(12, nil), MACTable: fdb}}
}

// TestShadowITModalHubWithVMs (G1, AC-1, R1; Q14): a hub whose VM NICs are no
// majority is a Shadow-IT port for the graph, the alerts, the report, the
// metrics and the UI modal alike. The modal used to take the synthetic hyp-
// node below such a hub (group hypervisor, "[HYPERVISOR] VMware ESXi"
// label) for an HTTP-confirmed ESXi host and dropped the hub, while
// Telegram alerted on it. A VM NIC behind the hyp- node that is confirmed
// after the build does exempt the hub, as it does for the alerts. The same
// holds on the rule network's port 13 (two VMware NICs, three others).
func TestShadowITModalHubWithVMs(t *testing.T) {
	if nodePath() == "" {
		t.Skip("Node.js 16 or newer is not installed, so static/app.js is not checked")
	}
	resetState(t)
	devices := shadowVMHubNetwork()
	collectedDataMutex.Lock()
	collectedData = analyzerDeviceMap(devices)
	collectedDataMutex.Unlock()
	g, hubs := checkShadowRuleViews(t, "hubs with VM NICs", devices)
	hyp := "hyp-hub-4c:ae:a3:81:00:81-p5-ge1_0_5"
	if !g.Nodes[hyp] || g.Edges["hub-4c:ae:a3:81:00:81-p5"][hyp] != "" {
		t.Fatalf("precondition: no hyp- node %s below the port 5 hub (nodes %v)", hyp, slices.Sorted(maps.Keys(g.Nodes)))
	}
	want := []string{"hub-4c:ae:a3:81:00:81-p5 5", "hub-4c:ae:a3:81:00:81-p7 2", "hub-4c:ae:a3:81:00:81-p9 4"}
	if !slices.Equal(hubs, want) {
		t.Errorf("hubs = %v, want %v", hubs, want)
	}
	// The audit's diagram of that hub draws the VMs below the hyp- node and
	// counts the hub's 5 devices, as the alert does ("5 MACs on single
	// port"), not 3 PCs plus the hyp- node.
	md := GenerateShadowDiagrams(g)
	hubSafe, hypSafe := sanitizeMermaidID("hub-4c:ae:a3:81:00:81-p5"), sanitizeMermaidID(hyp)
	start := strings.Index(md, "  "+hubSafe+"((")
	if start < 0 {
		t.Fatalf("no Shadow-IT diagram for the port 5 hub:\n%s", md)
	}
	section := md[start:]
	if end := strings.Index(section, "**Ulanganlar:**"); end >= 0 {
		section = section[:min(len(section), end+len("**Ulanganlar:** 5 ta qurilma"))]
	}
	for _, line := range []string{
		"  " + hubSafe + "-->" + hypSafe,
		"  " + hypSafe + "-->" + sanitizeMermaidID("00:50:56:81:05:01"),
		"  " + hypSafe + "-->" + sanitizeMermaidID("00:50:56:81:05:02"),
		"  style " + hypSafe + " fill:#26C6DA,stroke:#0097A7,color:#fff",
		"  style " + sanitizeMermaidID("00:50:56:81:05:01") + " fill:#9C27B0,stroke:#7B1FA2,color:#fff",
		"**Ulanganlar:** 5 ta qurilma",
	} {
		if !strings.Contains(section, line+"\n") && !strings.HasSuffix(section, line) {
			t.Errorf("Shadow-IT diagram of the port 5 hub lacks %q:\n%s", line, section)
		}
	}

	// A VM behind the hyp- node turns out to be an ESXi host (nested ESXi)
	// after the build: the live rule exempts the port, so do the alerts and
	// the modal.
	ConfirmedESXiMACs.Store("00:50:56:81:05:02", true)
	alerts := analyzerShadowPorts(t, devices, NewAnalyzer(captureData("late", devices, g)).analyzeShadowIT())
	ui, _ := uiShadowModalHubs(t, g.GetGraphData())
	if wantLate := []string{"hub-4c:ae:a3:81:00:81-p7", "hub-4c:ae:a3:81:00:81-p9"}; !slices.Equal(shadowHubIDs(alerts), wantLate) || !slices.Equal(ui, wantLate) {
		t.Errorf("VM confirmed as ESXi after the build: alerts %v, UI modal %v, want %v", shadowHubIDs(alerts), ui, wantLate)
	}

	clearConfirmedESXi()
	rule := analyzerRuleNetwork()
	collectedDataMutex.Lock()
	collectedData = analyzerDeviceMap(rule)
	collectedDataMutex.Unlock()
	g, hubs = checkShadowRuleViews(t, "rule network", rule)
	if !g.Nodes["hyp-hub-4c:ae:a3:60:00:60-p13-ge1_0_13"] || !slices.Contains(hubs, "hub-4c:ae:a3:60:00:60-p13 5") {
		t.Errorf("precondition: the rule network's port 13 is no hub with a hyp- node (hubs %v)", hubs)
	}
}

// TestShadowITVCenterHost (D1): a port whose member a vCenter lists as an
// ESXi host's NIC is exempt from Shadow IT for every consumer, as a port
// with an HTTP-confirmed host is: the UI modal took that hypervisor member
// for the exemption, while the alerts, the report and the graph exempted a
// confirmed host only. Off (controllerKindWins), the vCenter tells nothing,
// and every consumer lists the hub.
func TestShadowITVCenterHost(t *testing.T) {
	resetState(t)
	const host = "48:df:37:82:03:01"
	var fdb []MACEntry
	fdb = append(fdb, macEntries(3, host, "00:1b:21:82:03:02")...)
	fdb = append(fdb, macEntries(5, "00:1b:21:82:05:01", "00:1b:21:82:05:02")...)
	devices := []*DeviceData{{IP: "10.0.9.82", SysName: "sw-82", ChassisID: "4c:ae:a3:82:00:82", Interfaces: gigabitPorts(8, nil), MACTable: fdb}}
	collectedDataMutex.Lock()
	collectedData = map[string]*DeviceData{devices[0].IP: devices[0]}
	collectedDataMutex.Unlock()
	inventoryMu.Lock()
	inventories = map[string]inventoryRecord{"vcenter|10.9.0.2": {Module: "vcenter", IP: "10.9.0.2", Time: time.Now(),
		Inventory: modules.Inventory{Devices: []modules.ManagedDevice{{MAC: host, Name: "esx-82", Kind: "hypervisor"}}}}}
	inventoryIndex()
	inventoryMu.Unlock()
	t.Cleanup(func() {
		inventoryMu.Lock()
		inventories, managedByMAC, managedByIP = map[string]inventoryRecord{}, map[string]ManagedView{}, map[string]ManagedView{}
		inventoryMu.Unlock()
	})
	for _, c := range []struct {
		kindWins bool
		want     []string
	}{
		{true, []string{"hub-4c:ae:a3:82:00:82-p5 2"}},
		{false, []string{"hub-4c:ae:a3:82:00:82-p3 2", "hub-4c:ae:a3:82:00:82-p5 2"}},
	} {
		currentSettingsMutex.Lock()
		currentSettings.Classify.ControllerKindWins = c.kindWins
		currentSettingsMutex.Unlock()
		if _, hubs := checkShadowRuleViews(t, fmt.Sprintf("vCenter host member, controllerKindWins %v", c.kindWins), devices); !slices.Equal(hubs, c.want) {
			t.Errorf("controllerKindWins %v: hubs %v, want %v", c.kindWins, hubs, c.want)
		}
	}
}
