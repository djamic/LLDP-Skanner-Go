package main

import (
	"cmp"
	"strings"

	"lldp_scanner/modules/voip"
)

// graphRecordVoIPNeighbor runs the standalone VoIP detector (modules/voip) on
// an accepted LLDP neighbor and records its structured VoIP profile on the
// graph when matched. Polled switches and routers are never recorded as phones.
func graphRecordVoIPNeighbor(graph *DJGraph, targetID string, neighbor LLDPNeighbor, arpIP string) {
	if graph == nil || targetID == "" || graph.graphSwitches[targetID] || graph.graphRouters[targetID] {
		return
	}
	if prof, ok := voip.Detect(voipEvidence(targetID, neighbor, arpIP)); ok {
		if graph.graphVoIP == nil {
			graph.graphVoIP = make(map[string]voip.Profile)
		}
		// Keep richer profile fields if multiple neighbors reported the same phone
		if prev, exists := graph.graphVoIP[targetID]; exists {
			prof.Model = cmp.Or(prof.Model, prev.Model)
			prof.Firmware = cmp.Or(prof.Firmware, prev.Firmware)
			prof.IP = cmp.Or(prof.IP, prev.IP)
			prof.Port = cmp.Or(prof.Port, prev.Port)
			prof.PCBridge = prof.PCBridge || prev.PCBridge
		}
		graph.graphVoIP[targetID] = prof
	}
}

// voipEvidence is what the VoIP detector reads of an LLDP neighbor with node
// id targetID and ARP address arpIP.
func voipEvidence(targetID string, neighbor LLDPNeighbor, arpIP string) voip.Evidence {
	return voip.Evidence{
		MAC:            targetID,
		Vendor:         getMACVendor(targetID),
		SysName:        neighbor.RemSysName,
		SysDesc:        neighbor.RemSysDesc,
		PortDesc:       cleanSNMPValue(neighbor.RemPortDesc),
		Capabilities:   neighbor.RemSysCapEnabled,
		ChassisSubtype: neighbor.RemChassisIdSubtype,
		ChassisID:      neighbor.RemChassisId,
		MgmtIP:         cmp.Or(neighbor.RemMgmtIP, arpIP),
	}
}

// addVoIPProfiles attaches VoIP metadata (Brand, Model, Firmware, PCBridge) to
// phone nodes in /api/graph responses (mirrors addHARoles / addManaged).
func addVoIPProfiles(data *GraphData, graph *DJGraph) {
	if data == nil || graph == nil {
		return
	}
	for i := range data.Nodes {
		n := &data.Nodes[i]
		if prof, ok := graph.graphVoIP[n.ID]; ok && n.Group == "phone" {
			p := prof
			if p.IP == "" {
				p.IP = cmp.Or(n.IP, graphLabelIP(n.SysName))
			}
			n.VoIP = &p
			continue
		}
		if n.Group == "phone" {
			if brand, ok := voip.BrandForDedicatedVendor(lookupVendor(n.ID)); ok {
				n.VoIP = &voip.Profile{
					Brand:  brand,
					IP:     cmp.Or(n.IP, graphLabelIP(n.SysName)),
					Source: "oui:" + strings.ToLower(brand),
				}
			}
		}
	}
}

// voipKnownTypesForIP returns the Credentials device type ("voip-grandstream",
// "voip-yealink") when the current topology graph knows ip belongs to a
// Grandstream or Yealink IP phone, avoiding slow network probes.
func voipKnownTypesForIP(ip string) []string {
	if ip == "" {
		return nil
	}
	globalGraphMutex.RLock()
	graph := globalGraph
	var out []string
	if graph != nil {
		for nodeID, prof := range graph.graphVoIP {
			nodeIP := cmp.Or(prof.IP, graphLabelIP(graph.SwitchInfo[nodeID]))
			if nodeIP != ip {
				continue
			}
			switch prof.Brand {
			case "Grandstream":
				out = append(out, "voip-grandstream")
			case "Yealink":
				out = append(out, "voip-yealink")
			}
		}
	}
	globalGraphMutex.RUnlock()
	return out
}
