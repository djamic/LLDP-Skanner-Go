package main

import (
	"fmt"
	"slices"
	"testing"
)

// shadowRuleViews lists one network's Shadow-IT ports as each consumer sees
// them, as "hub-<switch node>-p<port> <MACs>" (the report lists hub ids
// only): the graph's hub nodes, the analyzer's alerts, the audit report's
// Shadow-IT section, and the experiment metrics' hub count. devices must be
// in collectedData (the report checks the live FDB tables).
func shadowRuleViews(t *testing.T, devices []*DeviceData) (graphHubs, alerts, reportHubs []string, metricHubs int) {
	t.Helper()
	byIP := make(map[string]*DeviceData, len(devices))
	for _, d := range devices {
		byIP[d.IP] = d
	}
	g := buildGraphFromSnapshot(byIP)
	graphHubs = analyzerGraphHubs(g)
	alerts = analyzerShadowPorts(t, devices, NewAnalyzer(captureData("rule", devices, g)).analyzeShadowIT())
	reportHubs = reportShadowHubs(g, GenerateShadowDiagrams(g))
	metricHubs = analyzerShadowCounts(devices).Hubs
	return graphHubs, alerts, reportHubs, metricHubs
}

// checkShadowRuleViews fails unless the graph, the alerts, the report and
// the metrics list the same Shadow-IT ports.
func checkShadowRuleViews(t *testing.T, name string, devices []*DeviceData) []string {
	t.Helper()
	graphHubs, alerts, reportHubs, metricHubs := shadowRuleViews(t, devices)
	var hubIDs []string
	for _, h := range graphHubs {
		var id string
		var n int
		fmt.Sscanf(h, "%s %d", &id, &n)
		hubIDs = append(hubIDs, id)
	}
	if !slices.Equal(alerts, graphHubs) {
		t.Errorf("%s: alerts and graph hubs differ:\nalerts (%d): %v\nhubs (%d): %v", name, len(alerts), alerts, len(graphHubs), graphHubs)
	}
	if !slices.Equal(reportHubs, hubIDs) {
		t.Errorf("%s: report section and graph hubs differ:\nreport (%d): %v\nhubs (%d): %v", name, len(reportHubs), reportHubs, len(hubIDs), hubIDs)
	}
	if metricHubs != len(graphHubs) {
		t.Errorf("%s: experiment shadow_it_filtered = %d, graph has %d hubs", name, metricHubs, len(graphHubs))
	}
	return graphHubs
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
// experiment metrics and the audit's Shadow-IT section come from one
// per-port rule (fdbPorts), so they list the same ports: on a switch whose
// LLDP neighbors the graph resolves differently from the raw chassis ids, on
// the fixture, and on the fixture with HTTP-confirmed ESXi hosts, also when
// a host is confirmed after the graph was built.
func TestShadowITOneRule(t *testing.T) {
	resetState(t)
	devices := shadowRuleNetwork()
	collectedDataMutex.Lock()
	collectedData = map[string]*DeviceData{devices[0].IP: devices[0]}
	collectedDataMutex.Unlock()
	ConfirmedESXiMACs.Store("00:1b:21:80:06:02", true)
	got := checkShadowRuleViews(t, "synthetic", devices)
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
	plain := checkShadowRuleViews(t, "fixture", fixture)
	for _, mac := range esxiConfirmedMACs {
		ConfirmedESXiMACs.Store(mac, true)
	}
	esxi := checkShadowRuleViews(t, "fixture with ESXi hosts", fixture)
	if len(esxi) >= len(plain) {
		t.Errorf("the confirmed ESXi hosts exempt no hub: %d hubs, %d without them", len(esxi), len(plain))
	}

	// A host confirmed after the build: the report and the alerts follow the
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
}
