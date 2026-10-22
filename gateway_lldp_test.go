package main

import (
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// Tests of the router node links from a gateway's own LLDP neighbors
// (collectGatewayLLDP, gatewayLLDPLinks), with the FortiGate agent of
// lldp_layouts_test.go: its live lldpRemTable, no lldpLocalSystemData.

// TestGatewayLLDPRead checks the gateway's own LLDP read on the FortiGate
// agent (an lldpRemTable, no lldpLocalSystemData): three neighbors on its
// ports mgmt, x7 and x8 (ifName; its ifDescr is empty) with their
// management addresses; the Debian router has none ("No Such Object"). The
// gateway walks record the view for the router node; a later read that
// fails keeps it, one without neighbors clears it.
func TestGatewayLLDPRead(t *testing.T) {
	resetState(t)
	collectResetCache(t)
	macIPCacheFile = filepath.Join(t.TempDir(), "mac_ip_cache.json")
	fakeSNMP.set(fortiGW, fortiGateLLDPAgent(t))
	fakeSNMP.set(debianGW, debianGateway())
	obj := &SNMPObject{Community: "public", Port: 161}

	lldp, err := obj.collectGatewayLLDP(fortiGW)
	if err != nil || lldp == nil {
		t.Fatalf("FortiGate LLDP: %v, %v", lldp, err)
	}
	var got []string
	for _, n := range lldp.Neighbors {
		got = append(got, fmt.Sprintf("%s %d.%d %s %s %s %s", lldp.Ports[n.LocalPortNum], n.LocalPortNum, n.RemIndex,
			normalizeID(n.RemChassisId, n.RemChassisIdSubtype), n.RemPortId, n.RemSysName, n.RemMgmtIP))
	}
	want := []string{
		`mgmt 2.1 ` + hpe238MAC + ` "GigabitEthernet1/0/47" HPE 172.20.230.238`,
		`x7 33.2 ` + sw203MAC + ` "Ten-GigabitEthernet1/0/52" HPE 172.20.254.203`,
		`x8 34.3 ` + aruba253 + ` "1/1/27" 6300 172.20.230.253`,
	}
	if !slices.Equal(got, want) {
		t.Errorf("FortiGate neighbors\n%q\nwant\n%q", got, want)
	}
	if len(lldp.Ports) != 52 || lldp.Ports[1] != "ha" {
		t.Errorf("FortiGate port names: %d, port 1 %q; want the 52 ifNames", len(lldp.Ports), lldp.Ports[1])
	}
	if d, err := obj.collectGatewayLLDP(debianGW); d != nil || err != nil {
		t.Errorf("Debian LLDP = %v, %v; want none", d, err)
	}

	setGatewayIPs([]string{debianGW, fortiGW})
	captureStdout(t, collectGatewayARP)
	views := func() map[string]*gatewayLLDP {
		out := map[string]*gatewayLLDP{}
		for _, gw := range answeredGateways() {
			out[gw.IP] = gw.LLDP
		}
		return out
	}
	if v := views(); v[debianGW] != nil || v[fortiGW] == nil || len(v[fortiGW].Neighbors) != 3 {
		t.Fatalf("after the startup gateway walk: %+v, want the FortiGate's 3 neighbors only", v)
	}
	agent := fortiGateLLDPAgent(t)
	delete(agent, oidLLDPRem) // the LLDP walk times out, the ARP walk answers
	fakeSNMP.set(fortiGW, agent)
	captureStdout(t, collectARPFromAllSwitches)
	if v := views(); v[fortiGW] == nil || len(v[fortiGW].Neighbors) != 3 {
		t.Errorf("after a sweep whose LLDP walk failed: %+v, want the view kept", v[fortiGW])
	}
	agent[oidLLDPRem] = noSuchObject(oidLLDPRem)
	captureStdout(t, collectARPFromAllSwitches)
	if v := views(); v[fortiGW] != nil {
		t.Errorf("after a sweep without neighbors: %+v, want none", v[fortiGW])
	}
}

// fortiGateInGatewayNetwork is the FortiGate agent with its live LLDP rows
// moved onto gatewayNetwork: x7 is sw-core's Ten-GigabitEthernet1/0/52
// (where sw-core sees the FortiGate itself), x8 is sw-acc (which sends no
// LLDP to it), mgmt stays the HPE 5130 that no switch of the network
// polls.
func fortiGateInGatewayNetwork(t *testing.T) map[string][]string {
	t.Helper()
	agent := fortiGateLLDPAgent(t)
	var rows []string
	for _, line := range agent[oidLLDPRem] {
		line = strings.ReplaceAll(line, "4C AE A3 A2 09 8C", "4C AE A3 48 00 02")
		line = strings.ReplaceAll(line, "88 22 5B 88 E2 40", "4C AE A3 48 00 03")
		rows = append(rows, line)
	}
	agent[oidLLDPRem] = rows
	return agent
}

// TestGatewayLLDPLinks checks the router node's links from the gateway's
// own LLDP neighbors in gatewayNetwork: the neighbor that sees the gateway
// itself (sw-core, whose LLDP node of the FortiGate the router node
// replaced) keeps its link and gets no second one; sw-acc, which does not
// see the gateway, gets a link from the router node; the HPE that no
// switch polls gets an LLDP endpoint node and a link; links carry the
// gateway's port name (ifName) and the neighbor's port. Two builds give
// the same graph, and the log line names the links.
func TestGatewayLLDPLinks(t *testing.T) {
	gatewayNetworkUp(t)
	fakeSNMP.set(fortiGW, fortiGateInGatewayNetwork(t))
	captureStdout(t, collectGatewayARP)
	var g *DJGraph
	out := captureStdout(t, func() { g = buildGraphFromSnapshot(snapshotCollectedData()) })

	links := map[string]string{}
	for src, targets := range g.Edges {
		for dst, label := range targets {
			if src == fortiMAC || dst == fortiMAC {
				links[src+" -> "+dst] = label
			}
		}
	}
	want := map[string]string{
		"4c:ae:a3:48:00:02 -> " + fortiMAC: "TGE1/0/52 [T] 10G|LAN", // sw-core's own LLDP link
		fortiMAC + " -> 4c:ae:a3:48:00:03": "x8|1/1/27",
		fortiMAC + " -> " + hpe238MAC:      "mgmt|GE1/0/47",
	}
	if !maps.Equal(links, want) {
		t.Errorf("FortiGate links %v, want %v", links, want)
	}
	if got := g.SwitchInfo[hpe238MAC]; got != "[LLDP-EP] HPE\nHPE\n172.20.230.238" {
		t.Errorf("the HPE's node label %q", got)
	}
	if !graphIsSwitchNode(g, hpe238MAC) {
		t.Error("the HPE's sysDescr (Comware) does not make its node a switch")
	}
	if g.Nodes[fortiLLDP] || g.Nodes[fortiGW] {
		t.Error("a second node of the FortiGate is drawn")
	}
	line := "LLDP of 172.20.0.1: linked to " + hpe238MAC + " (mgmt), 4c:ae:a3:48:00:03 (x8); already linked: 4c:ae:a3:48:00:02 (x7)"
	if n := strings.Count(out, line); n != 1 {
		t.Errorf("log line %q printed %d times:\n%s", line, n, out)
	}
	if a, b := viewGraph(g), viewGraph(buildGraphFromSnapshot(snapshotCollectedData())); !maps.Equal(a.Nodes, b.Nodes) || !slices.Equal(a.Edges, b.Edges) {
		t.Error("two builds of the same snapshot differ")
	}
}

// TestGatewayLLDPBeforeMACRef checks that a gateway's LLDP link to the
// switch whose port learned its MAC needs no MAC-REF link: the Debian
// router, linked from sw-core GE1/0/10 by the MAC cross-reference rule,
// gets its LLDP link to sw-core instead when its own LLDP sees sw-core;
// neighbors that are the router node itself or on a NULL port are left
// out.
func TestGatewayLLDPBeforeMACRef(t *testing.T) {
	gatewayNetworkUp(t)
	rem := oidLLDPRem
	debian := debianGateway()
	debian[rem] = []string{
		rem + ".4.0.2.1 = INTEGER: 4",
		rem + ".5.0.2.1 = Hex-STRING: 4C AE A3 48 00 02 ",
		rem + ".6.0.2.1 = INTEGER: 5",
		rem + ".7.0.2.1 = STRING: \"GigabitEthernet1/0/10\"",
		rem + ".4.0.2.2 = INTEGER: 4", // its own MAC (a loop through the ESXi host)
		rem + ".5.0.2.2 = Hex-STRING: 00 0C 29 98 7B C2 ",
		rem + ".4.0.9.1 = INTEGER: 4", // on its loopback
		rem + ".5.0.9.1 = Hex-STRING: 4C AE A3 48 00 03 ",
	}
	debian[oidLLDPMan] = noSuchObject(oidLLDPMan)
	debian[collectIfNameOID] = []string{collectIfNameOID + ".2 = STRING: \"ens192\"", collectIfNameOID + ".9 = STRING: \"Null0\""}
	fakeSNMP.set(debianGW, debian)
	captureStdout(t, collectGatewayARP)
	var g *DJGraph
	out := captureStdout(t, func() { g = buildGraphFromSnapshot(snapshotCollectedData()) })
	links := map[string]string{}
	for src, targets := range g.Edges {
		for dst, label := range targets {
			if src == debianMAC || dst == debianMAC {
				links[src+" -> "+dst] = label
			}
		}
	}
	if want := map[string]string{debianMAC + " -> 4c:ae:a3:48:00:02": "ens192|GE1/0/10"}; !maps.Equal(links, want) {
		t.Errorf("Debian links %v, want %v (no MAC-REF link next to the LLDP one)", links, want)
	}
	if !strings.Contains(out, "linked from 10.9.48.2 GE1/0/10 (4 MACs on the port), by its existing link") ||
		!strings.Contains(out, "LLDP of 172.20.1.254: linked to 4c:ae:a3:48:00:02 (ens192); 2 neighbors left out") {
		t.Errorf("log:\n%s", out)
	}
}

// TestGoldenGatewayLLDP pins the FortiGate's own LLDP view (the live
// lldpRemTable of 172.20.0.1, no lldpLocalSystemData) on the fixture with
// both gateways answering (fixtureWithGateways): 172.20.254.203
// Ten-GigabitEthernet1/0/52 sees the FortiGate itself, so the router node
// keeps that link and gets no second one for x7; its neighbor on mgmt, the
// HPE 5130 4c:ae:a3:8e:05:89 (an LLDP node the SNR 172.20.230.254 sees),
// and on x8, the Aruba 6300 172.20.230.253 (whose saved LLDP table of
// 2026-10-20 does not list the FortiGate), get links from the router node.
// It pins the router links, the graph changes against the build without
// the view, the log line and the analysis around the core.
func TestGoldenGatewayLLDP(t *testing.T) {
	_, before, _ := fixtureWithGateways(t)
	beforeReport, _ := analyzeFixture(t, before)
	fakeSNMP.set(fortiGW, fortiGateLLDPAgent(t))
	lldp, err := (&SNMPObject{Community: "public", Port: 161}).collectGatewayLLDP(fortiGW)
	if err != nil || lldp == nil {
		t.Fatalf("FortiGate LLDP: %v, %v", lldp, err)
	}
	recordGatewayLLDP(fortiGW, lldp, nil)
	var after *DJGraph
	out := captureStdout(t, func() { after = buildGraphFromSnapshot(snapshotCollectedData()) })
	var log []string
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "[Gateway]") {
			log = append(log, line)
		}
	}
	report, _ := analyzeFixture(t, after)
	routerLinks := func(g *DJGraph) []goldenLink {
		var links []goldenLink
		for _, l := range graphRecord(g).Links {
			if g.graphRouters[l.Source] || g.graphRouters[l.Target] {
				links = append(links, l)
			}
		}
		return links
	}
	pathCount := func(r Report) int {
		n := 0
		for _, s := range r.Suggestions {
			if s.Type == "path" {
				n++
			}
		}
		return n
	}
	beforeNodes, nodes := slices.Collect(maps.Keys(before.Nodes)), slices.Collect(maps.Keys(after.Nodes))
	beforeEdges, edges := graphEdgeLines(before), graphEdgeLines(after)
	na := NewAnalyzer(captureData("golden", sortedDevices(snapshotCollectedData()), after))
	neighborPorts := map[int]string{}
	for _, n := range lldp.Neighbors {
		neighborPorts[n.LocalPortNum] = lldp.Ports[n.LocalPortNum]
	}
	rec := map[string]any{
		"fortigate_lldp": map[string]any{
			"neighbors":      lldp.Neighbors,
			"neighbor_ports": neighborPorts,
			"ports_named":    len(lldp.Ports),
		},
		"router_links": map[string]any{
			"without_lldp": routerLinks(before),
			"with_lldp":    routerLinks(after),
		},
		"graph_changes": map[string]any{
			"nodes_removed": sortedMinus(beforeNodes, nodes),
			"nodes_added":   sortedMinus(nodes, beforeNodes),
			"edges_removed": sortedMinus(beforeEdges, edges),
			"edges_added":   sortedMinus(edges, beforeEdges),
		},
		"log": log,
		"analysis": map[string]any{
			"core":                     na.coreNode(),
			"health_without_lldp":      beforeReport.HealthScore,
			"health_with_lldp":         report.HealthScore,
			"path_issues_without_lldp": pathCount(beforeReport),
			"path_issues_with_lldp":    pathCount(report),
		},
	}
	checkGolden(t, "gateway_lldp.json", goldenJSON(t, rec, 3))
}
