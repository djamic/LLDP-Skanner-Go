package main

// Helpers only the tests call: thin wrappers over the code the program
// runs, moved out of it (its callers had all gone).

// resolveHostname performs DNS reverse lookup with 2s timeout and caching
// "PC-JAMIL.tuit.local." → "PC-JAMIL"; an IP being looked up already is
// not looked up twice.
func resolveHostname(ip string) string {
	if name, ok := cachedHostname(ip); ok {
		return name
	}
	<-dnsStartLookup(ip)
	name, _ := cachedHostname(ip)
	return name
}

// isSpecialMAC checks if MAC is broadcast, null, multicast or zero-OUI (should be
// filtered everywhere, Q11). It reads the bits of the parsed address, so text that
// is no MAC (a hostname, an IP) is never special (F38).
func isSpecialMAC(mac string) bool {
	m, ok := parseMAC(mac)
	return ok && m.IsSpecial()
}

// collectARPFromSwitch collects ARP table from a single switch IP and
// merges results into globalMACtoIP. Returns number of new or changed entries.
func collectARPFromSwitch(snmpObj *SNMPObject, ip string) int {
	updated, _, _ := collectARPMerge(snmpObj, ip)
	return updated
}

// GetEdgeLabel returns the label of the edge
func (g *DJGraph) GetEdgeLabel(a, b string) string {
	if g.Edges[a] != nil && g.Edges[a][b] != "" {
		return g.Edges[a][b]
	} else if g.Edges[b] != nil && g.Edges[b][a] != "" {
		return g.Edges[b][a]
	}
	return ""
}

// collectARPMerge merges the ARP table of ip into globalMACtoIP and returns
// the number of new or changed mappings and of ARP rows read, and the walk
// error.
func collectARPMerge(snmpObj *SNMPObject, ip string) (updated, rows int, err error) {
	entries, err := snmpObj.collectARPTable(ip)
	if err != nil {
		return 0, 0, err
	}
	added, changed := collectMergeMACIP(entries, macIPClock())
	return added + changed, len(entries), nil
}
