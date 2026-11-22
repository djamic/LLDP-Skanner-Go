package main

import (
	"regexp"
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

// labelVMOS is a [VM] line's OS: an emoji and a word, or "<word> VM"
// ("🐧 Linux", "💻 VMware VM"), then the vendor (app.js's former rule).
var labelVMOS = regexp.MustCompile(`^([^\x00-\x7F]\S*\s+(?:\S+\s+VM(?:\s|$)|\S+))\s*(.*)$`)

// labelTag is the tag a label's tag line shows, as the build records it:
// an [ENDPOINT], [LLDP-EP] or [WiFi] line's text is the vendor; a [VM]
// line's the OS and the vendor; a [BMC] line's the type ("BMC", "IPMI" or
// two words) and the vendor; the others' the detail.
func labelTag(l string) nodeTag {
	tag, text, _ := strings.Cut(strings.TrimPrefix(l, "["), "]")
	text = strings.TrimSpace(text)
	switch tag {
	case tagEndpoint, tagLLDPEndpoint, tagWiFi:
		return nodeTag{Tag: tag, Vendor: text}
	case tagVM:
		if m := labelVMOS.FindStringSubmatch(text); m != nil {
			return nodeTag{Tag: tag, Detail: strings.TrimSpace(m[1]), Vendor: m[2]}
		}
		return nodeTag{Tag: tag, Vendor: text}
	case tagBMC:
		words := strings.Fields(text)
		n := min(2, len(words))
		if n > 0 && (words[0] == "BMC" || words[0] == "IPMI") {
			n = 1
		}
		return nodeTag{Tag: tag, Detail: strings.Join(words[:n], " "), Vendor: strings.Join(words[n:], " ")}
	}
	return nodeTag{Tag: tag, Detail: text}
}

// labelEvidence is ev with the tags its Info's tag lines show, when it has
// none: the classification tables write a node's label, as the build did
// before it recorded tags.
func labelEvidence(ev nodeEvidence) nodeEvidence {
	if len(ev.Tags) > 0 {
		return ev
	}
	for _, l := range labelTagLines(ev.Info) {
		ev.Tags = append(ev.Tags, labelTag(l))
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
