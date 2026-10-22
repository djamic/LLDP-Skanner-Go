package main

import (
	"bytes"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
)

// graphEdgeLines lists the edges of g as "src -> dst : label", sorted.
func graphEdgeLines(g *DJGraph) []string {
	var lines []string
	for src, targets := range g.Edges {
		for dst, label := range targets {
			lines = append(lines, fmt.Sprintf("%s -> %s : %q", src, dst, label))
		}
	}
	slices.Sort(lines)
	return lines
}

// sortedMinus returns the elements of a that are not in b, sorted.
func sortedMinus(a, b []string) []string {
	var out []string
	for _, s := range a {
		if !slices.Contains(b, s) {
			out = append(out, s)
		}
	}
	slices.Sort(out)
	return out
}

// fixtureWithGateways loads the fixture and notes the two gateways of
// 2026-10-22 as answering SNMP with their sysNames, as the startup gateway
// ARP does when their agents answer (the fixture's ARP data stays as it
// is). It returns the graph built without and with the gateways, and the
// gateway lines the build with them logged.
func fixtureWithGateways(t *testing.T) (base, graph *DJGraph, log []string) {
	t.Helper()
	base = buildFixtureGraph(t)
	setGatewayIPs([]string{debianGW, fortiGW})
	t.Cleanup(func() { setGatewayIPs([]string{fixedGatewayIP}) })
	recordGatewayPoll(debianGW, true, "debian216")
	recordGatewayPoll(fortiGW, true, "FortiGate-600F")
	out := captureStdout(t, func() { graph = buildGraphFromSnapshot(snapshotCollectedData()) })
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "[Gateway]") {
			log = append(log, line)
		}
	}
	return base, graph, log
}

// TestGoldenGateways pins what the two gateways of gateway_ip do to the
// fixture once both answer SNMP: the router nodes (the Debian VM linked
// from 172.20.254.202 Ten-GigabitEthernet1/0/52, the FortiGate taking the
// place of its LLDP node on 172.20.254.203 Ten-GigabitEthernet1/0/52), the
// graph changes, the log, and the analysis with a real core: the core node,
// the path suggestions (the same nodes bfs_depths.json lists deeper than 3
// hops), the health score (the path penalty is capped at 10), the
// analyserbot messages (no path message) and bfs_depths.json. It also pins
// the synthetic gateway network of TestGatewayRouterNodes.
func TestGoldenGateways(t *testing.T) {
	base, graph, log := fixtureWithGateways(t)
	again := buildGraphFromSnapshot(snapshotCollectedData())
	if a, b := goldenJSON(t, graphRecord(graph), 2), goldenJSON(t, graphRecord(again), 2); !bytes.Equal(a, b) {
		t.Fatalf("two builds with the gateways differ:\n%s", lineDiff(a, b, 20))
	}

	data := graph.GetGraphData()
	var routers []goldenNode
	for _, n := range graphRecord(graph).Nodes {
		if n.Group == "router" {
			routers = append(routers, n)
		}
	}
	var routerLinks []goldenLink
	for _, l := range graphRecord(graph).Links {
		if graph.graphRouters[l.Source] || graph.graphRouters[l.Target] {
			routerLinks = append(routerLinks, l)
		}
	}
	baseNodes, nodes := slices.Collect(maps.Keys(base.Nodes)), slices.Collect(maps.Keys(graph.Nodes))
	baseEdges, edges := graphEdgeLines(base), graphEdgeLines(graph)

	collectedDataMutex.RLock()
	devices := sortedDevices(collectedData)
	collectedDataMutex.RUnlock()
	baseReport, baseMsgs := analyzeFixture(t, base)
	report, msgs := analyzeFixture(t, graph)
	na := NewAnalyzer(captureData("golden", devices, graph))
	// The same analysis again within the hour: nothing is sent twice
	NewAnalyzer(captureData("golden", devices, graph)).Analyze()
	repeated := bot.taken()

	var paths []map[string]string
	var pathNodes []string
	for _, s := range report.Suggestions {
		if s.Type == "path" {
			paths = append(paths, map[string]string{"node": s.nodeID, "device": s.Device, "value": s.Value})
			pathNodes = append(pathNodes, s.nodeID)
			if s.IssueID != "" {
				t.Errorf("path suggestion %s has issue id %q: it could become a per-issue alert", s.nodeID, s.IssueID)
			}
		}
	}
	slices.SortFunc(paths, func(a, b map[string]string) int { return strings.Compare(a["node"], b["node"]) })
	slices.Sort(pathNodes)

	// Telegram: the gateways change the summary's numbers only
	msgTypes := func(msgs []botMessage) map[string]int {
		types := map[string]int{}
		for _, m := range msgs {
			kind := "summary"
			if m.IssueID != "" {
				kind, _, _ = strings.Cut(m.IssueID, "_")
			}
			types[kind]++
		}
		return types
	}
	issueIDs := func(msgs []botMessage) []string {
		var ids []string
		for _, m := range msgs {
			ids = append(ids, m.IssueID)
		}
		return ids
	}
	if !slices.Equal(issueIDs(msgs), issueIDs(baseMsgs)) || len(repeated) != 0 {
		t.Errorf("analyserbot messages with the gateways %v (then %d more), want the issues of the analysis without them %v and nothing more",
			issueIDs(msgs), len(repeated), issueIDs(baseMsgs))
	}

	// The path penalty is capped: the path suggestions cost at most 10
	withoutPaths := Report{Suggestions: slices.DeleteFunc(slices.Clone(report.Suggestions), func(s OptimizationSuggestion) bool { return s.Type == "path" })}
	if pathless := na.CalculateHealthScore(&withoutPaths); report.HealthScore != pathless-min(10, 2*len(paths)) {
		t.Errorf("health %d with %d path suggestions and %d without them, want the path penalty capped at 10", report.HealthScore, len(paths), pathless)
	}

	bfs := reportBFSExport(t, graph)
	var deepSwitches []string
	types := map[string]string{}
	for _, n := range data.Nodes {
		types[n.ID] = n.NodeType
	}
	for _, d := range bfs.DeepDevices {
		if types[d.NodeID] == "switch" || types[d.NodeID] == "router" {
			deepSwitches = append(deepSwitches, d.NodeID)
		}
	}
	slices.Sort(deepSwitches)
	if core := na.coreNode(); core != debianMAC || bfs.CoreSwitchIP != core || !slices.Equal(pathNodes, deepSwitches) {
		t.Errorf("core %q (bfs_depths %q), want the Debian router %s; path nodes %v, bfs_depths' deep switches and routers %v",
			core, bfs.CoreSwitchIP, debianMAC, pathNodes, deepSwitches)
	}

	gatewayNetworkUp(t)
	network := viewGraph(buildGraphFromSnapshot(snapshotCollectedData()))

	rec := map[string]any{
		"fixture": map[string]any{
			"gateway_ip":   []string{debianGW, fortiGW},
			"router_nodes": routers,
			"router_links": routerLinks,
			"graph_changes": map[string]any{
				"nodes_before":  len(baseNodes),
				"nodes_after":   len(nodes),
				"nodes_removed": sortedMinus(baseNodes, nodes),
				"nodes_added":   sortedMinus(nodes, baseNodes),
				"edges_removed": sortedMinus(baseEdges, edges),
				"edges_added":   sortedMinus(edges, baseEdges),
			},
			"log":  log,
			"core": na.coreNode(),
			"health": map[string]any{
				"without_gateways": baseReport.HealthScore,
				"with_gateways":    report.HealthScore,
				"label":            GetHealthLabel(report.HealthScore),
			},
			"summary_without_gateways": baseReport.Summary,
			"summary_with_gateways":    report.Summary,
			"path_suggestions":         paths,
			"bot_messages": map[string]any{
				"without_gateways":     msgTypes(baseMsgs),
				"with_gateways":        msgTypes(msgs),
				"summary":              msgs[0].Text,
				"repeated_within_hour": len(repeated),
			},
			"bfs_depths": map[string]any{
				"core_switch_ip":     bfs.CoreSwitchIP,
				"core_found":         bfs.CoreFound,
				"total_nodes":        bfs.TotalNodes,
				"max_depth":          bfs.MaxDepth,
				"depth_distribution": bfs.DepthDistribution,
				"deep_devices":       len(bfs.DeepDevices),
				"deep_switches":      deepSwitches,
			},
		},
		"gateway_network": network,
	}
	checkGolden(t, "gateways.json", goldenJSON(t, rec, 3))
}
