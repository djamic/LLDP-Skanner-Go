package main

import (
	"slices"
	"strings"
)

// nodeTag is one tag of a node: the kind of device the graph build tells it
// is, with what it knows of it. The build records a node's tags
// (DJGraph.graphTags) where it writes them, and its label shows each one
// as a line (line: "[LLDP-EP] Ubiquiti", "[VM] 🐧 Linux VMware, Inc.",
// "[HYPERVISOR] VMware ESXi"). Readers take the tags, not the label: the
// label's text is for display only (labelTokens).
type nodeTag struct {
	Tag    string `json:"tag"`              // one of the tag* constants
	Detail string `json:"detail,omitempty"` // a VM's OS, a BMC's type, a hypervisor's or a hub's text
	Vendor string `json:"vendor,omitempty"` // the MAC's vendor
}

// The tags (nodeTag.Tag).
const (
	tagLLDPEndpoint = "LLDP-EP"    // an LLDP neighbor that is no polled device
	tagEndpoint     = "ENDPOINT"   // a MAC an FDB learns
	tagWiFi         = "WiFi"       // a randomised MAC an FDB learns
	tagVM           = "VM"         // a virtual NIC
	tagBMC          = "BMC"        // a server's management (iDRAC, iLO, XCC, iRMC)
	tagHypervisor   = "HYPERVISOR" // a hypervisor: an ESXi host, a server NIC, a hyp- node
	tagHub          = "HUB"        // an unmanaged hub (Shadow IT)
	tagMiniHub      = "MINIHUB"    // a trunk or big port no polled switch is behind
	tagAPHub        = "APHUB"      // access points behind an unmanaged switch
)

// labelTags are the tags a label line can start with, as "[<tag>]".
var labelTags = []string{tagLLDPEndpoint, tagEndpoint, tagWiFi, tagVM, tagBMC, tagHypervisor, tagHub, tagMiniHub, tagAPHub}

// esxiTag is the tag of an ESXi host (graphESXiTag is its line).
var esxiTag = nodeTag{Tag: tagHypervisor, Detail: "VMware ESXi"}

// line is the tag's label line: "[<tag>]", then the detail and the vendor.
func (t nodeTag) line() string {
	s := "[" + t.Tag + "]"
	if t.Detail != "" {
		s += " " + t.Detail
	}
	if t.Vendor != "" {
		s += " " + t.Vendor
	}
	return s
}

// graphSetTags makes tags a node's tags, in its label's order (none clears
// them: a label without a tag line).
func graphSetTags(graph *DJGraph, id string, tags ...nodeTag) {
	if len(tags) == 0 {
		delete(graph.graphTags, id)
		return
	}
	if graph.graphTags == nil {
		graph.graphTags = make(map[string][]nodeTag)
	}
	graph.graphTags[id] = slices.Clone(tags)
}

// graphPrependTag puts t first among a node's tags, as its label's first
// line (an ESXi host's, a server NIC's tag), once: an equal tag further down
// moves up.
func graphPrependTag(graph *DJGraph, id string, t nodeTag) {
	rest := slices.DeleteFunc(slices.Clone(graph.graphTags[id]), func(o nodeTag) bool { return o == t })
	graphSetTags(graph, id, append([]nodeTag{t}, rest...)...)
}

// graphHasTag reports whether a node has a tag of kind tag.
func graphHasTag(graph *DJGraph, id, tag string) bool {
	return slices.ContainsFunc(graph.graphTags[id], func(t nodeTag) bool { return t.Tag == tag })
}

// nodeHasTag reports whether a graph data node has a tag of kind tag: one of
// its Tags. A node with none from a capture written before the nodes had
// tags (FullCaptureData) tells its tags by its label's tag lines only, and
// this is the one place that reads them.
func nodeHasTag(n GraphNode, tag string) bool {
	if len(n.Tags) > 0 {
		return slices.ContainsFunc(n.Tags, func(t nodeTag) bool { return t.Tag == tag })
	}
	return slices.ContainsFunc(strings.Split(n.SysName, "\n"), func(l string) bool {
		return l == "["+tag+"]" || strings.HasPrefix(l, "["+tag+"] ")
	})
}
