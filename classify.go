package main

import (
	"slices"
	"strings"

	"lldp_scanner/modules"
)

// nodeEvidence is what a node's group is decided from: what the graph
// build knows of it. classifyNode decides, with the owner's choices
// (ClassifySettings); DJGraph.nodeEvidence gathers.
type nodeEvidence struct {
	ID   string    // the node id: a MAC, an IP, a hub-/hyp- id or a name
	Info string    // its label (SysName): names, IPs (for graphNameGroup)
	Tags []nodeTag // its tags (graphTags): what the build tells it is

	Router bool        // a configured gateway's router node (graphRouters)
	AP     bool        // an access point a controller manages (graphManaged)
	Polled bool        // a polled device (graphSwitches)
	Own    polledFacts // what a polled device's agent shows (graphPolled)
	ESXi   bool        // an HTTP-confirmed ESXi host, and no switch
	VoIP   bool        // a phone the voip engine identified (graphVoIP)
	// NotPhone: the voip engine excludes it (a VoIP maker's non-phone
	// product, graphNotPhone), so its OUI's "phone" tells nothing
	NotPhone bool

	// Category is the OUI category (categorizeVendor) of the id's vendor
	// when the id is a MAC of a known vendor, else "".
	Category string
	// LLDPCaps are the LLDP capabilities its LLDP rows enable (graphLLDPCaps)
	LLDPCaps uint8

	// What the controllers and the Credentials window tell of it
	// (classifyFacts; with ClassifySettings.ControllerKindWins only):
	// Managed is the kind (modules.Kind*) a controller manages its MAC as
	// (UniFi, vCenter, Kerio); ManagedIP the kind of the device a
	// controller knows by its IP only (a PBX's phone, by the address its
	// extension registered from); Declared the device types (credentialTypes
	// ids) the logins for its IP itself declare.
	Managed, ManagedIP string
	Declared           []string
}

// classifyFacts is what the controllers' inventories and the Credentials
// window tell of the nodes, read once for a GetGraphData.
type classifyFacts struct {
	byMAC    map[string]string   // canonical MAC → the kind a controller manages it as
	byIP     map[string]string   // IP → the kind of a device a controller knows by IP only
	declared map[string][]string // IP → the device types its own logins declare
}

// currentClassifyFacts reads the facts the rules use: none unless
// rules.ControllerKindWins.
func currentClassifyFacts(rules ClassifySettings) classifyFacts {
	if !rules.ControllerKindWins {
		return classifyFacts{}
	}
	f := classifyFacts{byMAC: map[string]string{}, byIP: map[string]string{}, declared: credentialsDeclaredByIP()}
	inventoryMu.Lock()
	for mac, v := range managedByMAC {
		if v.Kind != "" {
			f.byMAC[mac] = v.Kind
		}
	}
	for ip, v := range managedByIP {
		if v.Kind != "" {
			f.byIP[ip] = v.Kind
		}
	}
	inventoryMu.Unlock()
	return f
}

// nodeEvidence gathers the evidence of a node with label info, facts
// what the controllers and Credentials tell.
func (g *DJGraph) nodeEvidence(node, info string, facts classifyFacts) nodeEvidence {
	ev := nodeEvidence{
		ID:     node,
		Info:   info,
		Router: g.graphRouters[node],
		AP:     g.graphManaged[node],
		Polled: g.graphSwitches[node],
		Own:    g.graphPolled[node],
		Tags:   g.graphTags[node],
	}
	ev.ESXi = graphIsConfirmedESXi(node) && !graphIsSwitchNode(g, node)
	_, ev.VoIP = g.graphVoIP[node]
	ev.NotPhone = g.graphNotPhone[node]
	ev.LLDPCaps = g.graphLLDPCaps[node]
	if len(node) >= 8 && (strings.Contains(node, ":") || strings.Contains(node, "-")) {
		if vendor := lookupVendor(node); vendor != "Unknown" {
			ev.Category = categorizeVendor(vendor)
		}
	}
	if mac := canonicalMAC(node); mac != "" {
		ev.Managed = facts.byMAC[mac]
	}
	ip := parseIPv4(node)
	if ip == "" {
		ip = graphLabelIP(info)
	}
	if ip != "" {
		ev.ManagedIP, ev.Declared = facts.byIP[ip], facts.declared[ip]
	}
	return ev
}

// managedKindGroups are the groups of the kinds a controller manages a
// device as (ManagedView.Kind, modules.Kind*). A switch a controller
// manages is no polled one (those are polled devices first): an unpolled
// switch, as an LLDP bridge is.
var managedKindGroups = map[string]string{
	modules.KindAccessPoint: "access_point",
	modules.KindSwitch:      "lldp_switch",
	modules.KindGateway:     "router",
	modules.KindHypervisor:  "hypervisor",
	modules.KindPhone:       "phone",
}

// declaredTypeGroups are the groups of the device types a login for an IP
// declares (credentialTypes ids) that name a kind of device. The others
// tell none (declaredTypeNoGroup): vcenter, unifi-controller,
// kerio-operator and linux name the software, not the device (a Linux VM
// stays a VM); router and fortigate a role the gateways' configuration
// gives (graphRouters), and a gateway's address is on more nodes than its
// own (a VRRP or HA MAC); any.
var declaredTypeGroups = map[string]string{
	"esxi":   "hypervisor",
	"switch": "lldp_switch", "switch-hpe": "lldp_switch", "switch-aruba": "lldp_switch", "switch-eltex": "lldp_switch",
	"switch-snr": "lldp_switch", "switch-huawei": "lldp_switch", "switch-pixietech": "lldp_switch",
	"bmc": "bmc", "ilo": "bmc", "idrac": "bmc",
	"voip-grandstream": "phone", "voip-yealink": "phone",
}

var declaredTypeNoGroup = []string{"vcenter", "unifi-controller", "kerio-operator", "linux", "router", "fortigate", "any"}

// toldGroup is the group the owner or a controller tells for a node: the
// first declared type that names a kind of device, else the kind a
// controller manages its MAC as; "" when they tell none.
func toldGroup(ev nodeEvidence) string {
	for _, t := range ev.Declared {
		if g := declaredTypeGroups[t]; g != "" {
			return g
		}
	}
	return managedKindGroups[ev.Managed]
}

// classifyNode is a node's group (groups.go deviceGroups), the first that
// its evidence gives (a tag "[X]" below is a tag of the node, ev.Tags, not
// its label's text):
//
//  1. a configured gateway's node: router
//  2. a controller's access point: access_point
//  3. a polled device: with rules.PolledByMIB by what its agent shows
//     (polledGroup: a switch, a server or an ESXi host), else by its own
//     name only (graphNameGroup), server, router or switch, even with an
//     empty label
//  4. with rules.ControllerKindWins, what the owner or a controller tells
//     (toldGroup): the device type the Credentials logins for its IP
//     declare, else the kind a controller manages its MAC as (a UniFi
//     access point or switch, a vCenter host, a Kerio phone), above its
//     tags and its OUI
//  5. an HTTP-confirmed ESXi host, whatever tag its label has ([ENDPOINT],
//     [LLDP-EP], [WiFi], [BMC]): hypervisor
//  6. [WiFi], a randomised MAC: wifi_random
//  7. a phone of the voip engine (Yealink, Grandstream, ...): phone
//  8. [LLDP-EP] or [ENDPOINT]: its MAC's OUI category when that tells a
//     kind (a smartphone maker's, mobile: with rules.MobileGroup mobile,
//     else phone, as before; a VoIP maker's, phone, unless the voip engine
//     excludes the device); else, with rules.LLDPCaps, its LLDP
//     capabilities: a wireless access point is an access_point, a bridge
//     or router (no phone, the rule of lldpDiscoverable) an unpolled
//     switch, lldp_switch; else endpoint
//  9. [MINIHUB] (fdbPorts: a trunk or big port no polled switch is behind;
//     its node is a hub- node too): minihub
//  10. [APHUB] (lldpPortPlans: access points behind an unmanaged switch;
//     a hub- node too): ap_hub
//  11. [HUB]: hub (an id is no tag: an LLDP name may start "hub-")
//  12. [BMC]: bmc (no id prefix: the graph makes no bmc- node, and an LLDP
//     name may start so)
//  13. [HYPERVISOR]: hypervisor
//  14. [VM]: vm (no id prefix either: "vm-backup" may be an LLDP name)
//  15. else by its name and label (graphNameGroup)
//
// With rules.ControllerKindWins, last, a device a controller knows by the
// node's IP only is a weaker fact (an address is no identity): a PBX's
// phone there makes an endpoint or unknown node a phone (managedGroup), as
// /api/graph did alone before.
func classifyNode(ev nodeEvidence, rules ClassifySettings) string {
	group := classifyOwn(ev, rules)
	if rules.ControllerKindWins {
		group = managedGroup(group, ev.ManagedIP)
	}
	return group
}

// classifyOwn is classifyNode but the weaker fact of the node's IP.
func classifyOwn(ev nodeEvidence, rules ClassifySettings) string {
	node, info := ev.ID, ev.Info
	has := func(tag string) bool {
		return slices.ContainsFunc(ev.Tags, func(t nodeTag) bool { return t.Tag == tag })
	}
	told := ""
	if rules.ControllerKindWins {
		told = toldGroup(ev)
	}
	switch {
	case ev.Router:
		return "router"
	case ev.AP:
		return "access_point"
	case ev.Polled && rules.PolledByMIB:
		return polledGroup(ev.Own)
	case ev.Polled:
		return graphNameGroup(node, info, true)
	case told != "":
		return told
	case ev.ESXi:
		return "hypervisor"
	case has(tagWiFi):
		return "wifi_random"
	case ev.VoIP:
		return "phone"
	case has(tagLLDPEndpoint) || has(tagEndpoint):
		switch ev.Category {
		case "", "endpoint", "network":
		case "phone":
			if !ev.NotPhone {
				return "phone"
			}
		case "mobile":
			if !rules.MobileGroup {
				return "phone"
			}
			return "mobile"
		default:
			return ev.Category
		}
		if rules.LLDPCaps {
			switch {
			case ev.LLDPCaps&lldpCapWLANAP != 0:
				return "access_point"
			case lldpDiscoverable(ev.LLDPCaps):
				return "lldp_switch"
			}
		}
		return "endpoint"
	case has(tagMiniHub):
		return "minihub"
	case has(tagAPHub):
		return "ap_hub"
	case has(tagHub):
		return "hub"
	case has(tagBMC):
		return "bmc"
	case has(tagHypervisor):
		return "hypervisor"
	case has(tagVM):
		return "vm"
	}
	return graphNameGroup(node, info, false)
}

// polledGroup is the group of a polled device by what its agent shows, not
// by its name ("Server-room switch" is a switch): it passed the switch
// qualification (a BRIDGE-MIB port or an LLDP-MIB chassis id), so it is a
// switch, unless it bridges nothing (no BRIDGE-MIB port, no FDB) and its
// sysDescr names a host's OS: an LLDP agent on a server (lldpd, Windows'
// own) is a server, and on an ESXi host a hypervisor.
func polledGroup(own polledFacts) string {
	if own.Bridge {
		return "switch"
	}
	switch d := own.SysDescr; {
	case strings.HasPrefix(d, "VMware ESXi"):
		return "hypervisor"
	case strings.Contains(d, "Software: Windows"), slices.ContainsFunc(serverOSPrefixes, func(p string) bool { return strings.HasPrefix(d, p) }):
		return "server"
	}
	return "switch"
}

// serverOSPrefixes start the sysDescr of a host's SNMP agent: net-snmp's
// "<kernel> <hostname> <release> ..." (Windows' says "Hardware: ...
// Software: Windows ...").
var serverOSPrefixes = []string{"Linux ", "FreeBSD ", "OpenBSD ", "NetBSD ", "SunOS "}

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
// tells the kind of (addManaged, at /api/graph time; classifyNode, for the
// kind of a device known by the node's IP only): a PBX's phone is a phone
// when nothing else told what it is.
func managedGroup(group, kind string) string {
	if kind == modules.KindPhone && (group == "endpoint" || group == "unknown") {
		return "phone"
	}
	return group
}
