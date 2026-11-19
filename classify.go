package main

import (
	"strings"

	"lldp_scanner/modules"
)

// nodeEvidence is what a node's group is decided from: what the graph
// build knows of it. classifyNode decides; DJGraph.nodeEvidence gathers.
type nodeEvidence struct {
	ID   string // the node id: a MAC, an IP, a hub-/hyp- id or a name
	Info string // its label (SysName): tags ([LLDP-EP], [HUB], ...), names, IPs

	Router bool // a configured gateway's router node (graphRouters)
	AP     bool // an access point a controller manages (graphManaged)
	Polled bool // a polled device (graphSwitches)
	ESXi   bool // an HTTP-confirmed ESXi host, and no switch
	VoIP   bool // a phone the voip engine identified (graphVoIP)

	// Category is the OUI category (categorizeVendor) of the id's vendor
	// when the id is a MAC of a known vendor, else "".
	Category string
}

// nodeEvidence gathers the evidence of a node with label info.
func (g *DJGraph) nodeEvidence(node, info string) nodeEvidence {
	ev := nodeEvidence{
		ID:     node,
		Info:   info,
		Router: g.graphRouters[node],
		AP:     g.graphManaged[node],
		Polled: g.graphSwitches[node],
	}
	ev.ESXi = graphIsConfirmedESXi(node) && !graphIsSwitchNode(g, node)
	_, ev.VoIP = g.graphVoIP[node]
	if len(node) >= 8 && (strings.Contains(node, ":") || strings.Contains(node, "-")) {
		if vendor := lookupVendor(node); vendor != "Unknown" {
			ev.Category = categorizeVendor(vendor)
		}
	}
	return ev
}

// classifyNode is a node's group (groups.go deviceGroups), the first that
// its evidence gives:
//
//  1. a configured gateway's node: router
//  2. a controller's access point: access_point
//  3. a polled device: by its own name only (graphNameGroup), server, router
//     or switch, even with an empty label
//  4. an HTTP-confirmed ESXi host, whatever tag its label has ([ENDPOINT],
//     [LLDP-EP], [WiFi], [BMC]): hypervisor
//  5. [WiFi], a randomised MAC: wifi_random
//  6. a phone of the voip engine (Yealink, Grandstream, ...): phone
//  7. [LLDP-EP] or [ENDPOINT]: its MAC's OUI category, endpoint when that is
//     endpoint, network or none
//  8. [MINIHUB] (fdbPorts: a trunk or big port no polled switch is behind;
//     its node is a hub- node too): minihub
//  9. [HUB] or a hub- node: hub
//  10. [BMC] or a bmc- node: bmc
//  11. [HYPERVISOR] or a hyp- node: hypervisor
//  12. [VM] or a vm- node: vm
//  13. else by its name and label (graphNameGroup)
func classifyNode(ev nodeEvidence) string {
	node, info := ev.ID, ev.Info
	switch {
	case ev.Router:
		return "router"
	case ev.AP:
		return "access_point"
	case ev.Polled:
		return graphNameGroup(node, info, true)
	case ev.ESXi:
		return "hypervisor"
	case strings.Contains(info, "[WiFi]"):
		return "wifi_random"
	case ev.VoIP:
		return "phone"
	case strings.Contains(info, "[LLDP-EP]") || strings.Contains(info, "[ENDPOINT]"):
		if ev.Category != "" && ev.Category != "endpoint" && ev.Category != "network" {
			return ev.Category
		}
		return "endpoint"
	case strings.Contains(info, "[MINIHUB]"):
		return "minihub"
	case strings.Contains(info, "[HUB]") || strings.HasPrefix(node, "hub-"):
		return "hub"
	case strings.Contains(info, "[BMC]") || strings.HasPrefix(node, "bmc-"):
		return "bmc"
	case strings.Contains(info, "[HYPERVISOR]") || strings.HasPrefix(node, "hyp-"):
		return "hypervisor"
	case strings.Contains(info, "[VM]") || strings.HasPrefix(node, "vm-"):
		return "vm"
	}
	return graphNameGroup(node, info, false)
}

// graphNameGroup is the group of an untagged node from its name and label:
// server, switch or router, else switch when it has a label or is a polled
// device, else unknown.
func graphNameGroup(node, info string, polled bool) string {
	infoLower := strings.ToLower(info)
	nodeLower := strings.ToLower(node)

	// Check for server indicators
	if strings.Contains(infoLower, "linux") || strings.Contains(infoLower, "windows") || strings.Contains(infoLower, "server") ||
		strings.Contains(nodeLower, "linux") || strings.Contains(nodeLower, "windows") || strings.Contains(nodeLower, "server") {
		return "server"
	}

	// Check for switch indicators
	if strings.Contains(infoLower, "hpe") ||
		strings.Contains(infoLower, "snr") ||
		strings.Contains(infoLower, "switch") ||
		strings.Contains(infoLower, "cisco") ||
		strings.Contains(nodeLower, "switch") {
		return "switch"
	}

	// Check for router indicators
	if strings.Contains(infoLower, "router") ||
		strings.Contains(nodeLower, "router") {
		return "router"
	}

	// Default to "switch" for any discovered device with info
	if info != "" || polled {
		return "switch"
	}

	// Default to unknown
	return "unknown"
}

// managedGroup is the group of a node of group a controller's inventory
// tells the kind of (addManaged, at /api/graph time): a PBX's phone is a
// phone when nothing else told what it is.
func managedGroup(group, kind string) string {
	if kind == modules.KindPhone && (group == "endpoint" || group == "unknown") {
		return "phone"
	}
	return group
}
