package main

import (
	"slices"
	"strings"
	"testing"
)

// labelTagLines are the lines of a label that start with a tag ("[VM] ..."),
// in order: what the label shows of the node's tags.
func labelTagLines(info string) []string {
	var out []string
	for _, l := range strings.Split(info, "\n") {
		for _, tag := range labelTags {
			if l == "["+tag+"]" || strings.HasPrefix(l, "["+tag+"] ") {
				out = append(out, l)
				break
			}
		}
	}
	return out
}

// checkGraphTags fails t unless every node's recorded tags are its label's
// tag lines, in order, and no tags are left of a node the graph dropped.
func checkGraphTags(t *testing.T, name string, g *DJGraph) {
	t.Helper()
	bad := 0
	for _, id := range slices.Sorted(func(yield func(string) bool) {
		for id := range g.Nodes {
			if !yield(id) {
				return
			}
		}
	}) {
		var recorded []string
		for _, tag := range g.graphTags[id] {
			recorded = append(recorded, tag.line())
		}
		if shown := labelTagLines(g.SwitchInfo[id]); !slices.Equal(recorded, shown) {
			if bad++; bad <= 10 {
				t.Errorf("%s: %s: tags %q, its label shows %q", name, id, recorded, shown)
			}
		}
	}
	for id := range g.graphTags {
		if !g.Nodes[id] {
			t.Errorf("%s: tags of %s, which is no node", name, id)
		}
	}
	if bad > 10 {
		t.Errorf("%s: %d nodes in all", name, bad)
	}
}

// TestGraphTagsMatchLabels: the build records every tag its labels show
// (tags.go), on the fixture, with confirmed ESXi hosts, with the gateways,
// on every kind of FDB port and with LLDP hubs.
func TestGraphTagsMatchLabels(t *testing.T) {
	checkGraphTags(t, "fixture", buildFixtureGraph(t))

	useFixture(t)
	for _, mac := range esxiConfirmedMACs {
		ConfirmedESXiMACs.Store(mac, true)
	}
	checkGraphTags(t, "fixture with ESXi hosts", buildGraphFromSnapshot(snapshotCollectedData()))
	clearConfirmedESXi()

	_, gw, _ := fixtureWithGateways(t)
	checkGraphTags(t, "fixture with the gateways", gw)

	resetState(t)
	devices := graphFDBTestDevices()
	globalMACtoIPMutex.Lock()
	globalMACtoIP = map[string]string{"00:1b:21:05:09:08": "10.0.9.13", "00:1b:21:05:0b:01": "172.20.0.48", "00:1b:21:05:0c:01": "172.16.25.231"}
	globalMACtoIPMutex.Unlock()
	ConfirmedESXiMACs.Store("00:1b:21:05:0a:01", true)
	checkGraphTags(t, "FDB ports", buildGraphFromSnapshot(devices))
}

// TestNodeTagLine: a tag's label line.
func TestNodeTagLine(t *testing.T) {
	for _, c := range []struct {
		tag  nodeTag
		want string
	}{
		{nodeTag{Tag: tagLLDPEndpoint}, "[LLDP-EP]"},
		{nodeTag{Tag: tagLLDPEndpoint, Vendor: "Ubiquiti"}, "[LLDP-EP] Ubiquiti"},
		{nodeTag{Tag: tagVM, Detail: "🐧 Linux", Vendor: "VMware, Inc."}, "[VM] 🐧 Linux VMware, Inc."},
		{nodeTag{Tag: tagBMC, Detail: "Fujitsu iRMC"}, "[BMC] Fujitsu iRMC"},
		{esxiTag, "[HYPERVISOR] VMware ESXi"},
	} {
		if got := c.tag.line(); got != c.want {
			t.Errorf("%+v: %q, want %q", c.tag, got, c.want)
		}
	}
	g := NewDJGraph()
	g.AddNode("x")
	graphSetTags(g, "x", nodeTag{Tag: tagEndpoint, Vendor: "Intel"}, esxiTag)
	graphPrependTag(g, "x", esxiTag)
	if got := g.graphTags["x"]; len(got) != 2 || got[0] != esxiTag || !graphHasTag(g, "x", tagEndpoint) || graphHasTag(g, "x", tagVM) {
		t.Errorf("tags after the prepend %+v", got)
	}
	graphSetTags(g, "x")
	if _, ok := g.graphTags["x"]; ok {
		t.Error("no tags left a record")
	}
}

// labelEvidence is ev with the tags its Info's tag lines show, when it has
// none: the classification tables write a node's label, as the build did
// before it recorded tags.
func labelEvidence(ev nodeEvidence) nodeEvidence {
	if len(ev.Tags) > 0 {
		return ev
	}
	for _, l := range labelTagLines(ev.Info) {
		tag, detail, _ := strings.Cut(strings.TrimPrefix(l, "["), "]")
		ev.Tags = append(ev.Tags, nodeTag{Tag: tag, Detail: strings.TrimSpace(detail)})
	}
	return ev
}

// determineDeviceGroup is the group of a node with label info, with the
// current classification choices: classifyNode of its evidence, with the
// tags info's tag lines show when the build recorded none (the scenario
// tables give labels). GetGraphData classifies the build's nodes.
func (g *DJGraph) determineDeviceGroup(node, info string) string {
	rules := currentClassify()
	return classifyNode(labelEvidence(g.nodeEvidence(node, info, currentClassifyFacts(rules))), rules)
}

// setLabel gives a node of a test's graph its label and the tags the label's
// tag lines show, as the build's writers do.
func setLabel(g *DJGraph, id, info string) {
	g.SwitchInfo[id] = info
	graphSetTags(g, id, labelEvidence(nodeEvidence{Info: info}).Tags...)
}
