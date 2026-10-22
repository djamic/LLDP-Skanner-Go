package main

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
)

// Switch own MACs: the chassis MAC and the ARP aliases (buildSwitchOwnMACs,
// switchARPAliases). The HPE 5130 172.20.230.76 never sends from its chassis
// MAC 4c:ae:a3:8d:ec:c1 (LLDP off, no FDB of the saved data learns it); it
// answers ARP from its Vlan-interface1 MAC 4c:ae:a3:8d:ec:cb, the SNR
// 172.20.230.77 (chassis f8:f0:82:d8:62:67) from f8:f0:82:d8:62:66.

// TestSwitchARPAliases checks the one alias decision: a MAC the ARP data
// (the polled switches' ARP tables, globalMACtoIP) maps to one IP, a polled
// device's, that is no polled device's chassis MAC, is that switch's own
// MAC; a MAC with two IPs, another device's chassis MAC, a MAC of an IP that
// is not polled, a special MAC and the MAC of a gateway stored without
// switch data are not.
func TestSwitchARPAliases(t *testing.T) {
	resetState(t)
	const (
		core, hpe, snr, ipNode, gw, gwSwitch = "10.9.81.1", "10.9.81.2", "10.9.81.3", "10.9.81.4", "10.9.81.254", "10.9.81.253"
		coreMAC, hpeMAC, snrMAC, gwSwMAC     = "4c:ae:a3:81:00:01", "4c:ae:a3:81:00:02", "f8:f0:82:81:00:03", "4c:ae:a3:81:00:fd"
	)
	arp := func(ip, mac string) ARPEntry { return ARPEntry{IPAddress: ip, MACAddress: mac, Interface: 636} }
	devices := map[string]*DeviceData{
		core: {IP: core, ChassisID: coreMAC, ARPTable: []ARPEntry{
			arp(hpe, "4C:AE:A3:81:00:0C"), // the HPE's VLAN MAC (chassis + 10), any spelling
			arp(snr, "f8:f0:82:81:00:02"), // the SNR's (chassis - 1)
			arp(ipNode, "00:1b:21:81:00:04"),
			arp("10.9.81.50", "00:1b:21:81:00:50"), // a host: not polled
			arp(hpe, "00:1b:21:81:00:99"),          // also mapped to 10.9.81.99 by the cache
			arp(snr, hpeMAC),                       // the HPE's chassis MAC, for the SNR's IP
			arp(gw, "00:1b:21:81:00:fe"),
			arp(hpe, "01:00:5e:00:00:16"), // multicast
		}},
		hpe: {IP: hpe, ChassisID: hpeMAC, ARPTable: []ARPEntry{arp(snr, "f8:f0:82:81:00:02")}},
		snr: {IP: snr, ChassisID: snrMAC},
		// exception-text chassis id: the node id is the IP (172.20.230.17)
		ipNode: {IP: ipNode, ChassisID: "No Such Object available on this agent at this OID", Interfaces: gigabitPorts(4, nil)},
		// a gateway stored without switch data (the FortiGate the rescue scan
		// stored), and a gateway that is a switch
		gw:       {IP: gw},
		gwSwitch: {IP: gwSwitch, ChassisID: gwSwMAC},
	}
	setGatewayIPs([]string{gw, gwSwitch})
	t.Cleanup(func() { setGatewayIPs([]string{fixedGatewayIP}) })
	globalMACtoIPMutex.Lock()
	globalMACtoIP = map[string]string{
		"4c:ae:a3:81:00:0b": core,         // only the cache knows the core's VLAN MAC
		"00:1b:21:81:00:99": "10.9.81.99", // a second IP for that MAC
		"f8:f0:82:81:00:02": snr,          // the cache agrees with the ARP tables
		"4c:ae:a3:81:00:fc": gwSwitch,     // the switch gateway's VLAN MAC
	}
	globalMACtoIPMutex.Unlock()

	got := buildSwitchOwnMACs(devices)
	want := map[string]string{
		coreMAC: coreMAC, hpeMAC: hpeMAC, snrMAC: snrMAC, gwSwMAC: gwSwMAC, // chassis MACs
		"4c:ae:a3:81:00:0b": coreMAC, // cache only
		"4c:ae:a3:81:00:0c": hpeMAC,  // a switch ARP table
		"f8:f0:82:81:00:02": snrMAC,  // two ARP tables and the cache, one IP
		"00:1b:21:81:00:04": ipNode,  // a switch whose node id is its IP
		"4c:ae:a3:81:00:fc": gwSwMAC, // a gateway that is a polled switch
	}
	if !maps.Equal(got, want) {
		t.Errorf("buildSwitchOwnMACs:\n got %v\nwant %v", got, want)
	}
	for mac, why := range map[string]string{
		"00:1b:21:81:00:50": "the IP is no polled device's",
		"00:1b:21:81:00:99": "the ARP data maps it to two IPs",
		"00:1b:21:81:00:fe": "a gateway without switch data: its MAC is its router node",
		"01:00:5e:00:00:16": "multicast",
	} {
		if id, ok := got[mac]; ok {
			t.Errorf("%s is an alias of %s, want none (%s)", mac, id, why)
		}
	}
	if got[hpeMAC] != hpeMAC {
		t.Errorf("the HPE's chassis MAC, mapped to the SNR's IP, belongs to %q, want the HPE", got[hpeMAC])
	}
}

// aliasAgent is a fake switch agent for the alias tests: the chassis id,
// ports GigabitEthernet1/0/1-52, an LLDP table without neighbors (LLDP off,
// like 172.20.230.76: the agent answers "No Such Instance"), the FDB rows by
// port and the ARP rows by IP.
func aliasAgent(chassis string, fdb map[int][]string, arp map[string]string) map[string][]string {
	octets := func(mac string) string {
		m, _ := parseMAC(mac)
		parts := make([]string, len(m))
		for i, b := range m {
			parts[i] = fmt.Sprint(b)
		}
		return strings.Join(parts, ".")
	}
	hex := func(mac string) string {
		return strings.ToUpper(strings.ReplaceAll(canonicalMAC(mac), ":", " "))
	}
	walks := map[string][]string{
		oidChassis: {oidChassis + " = Hex-STRING: " + hex(chassis) + " "},
		oidLLDPRem: {oidLLDPRem + " = No Such Instance currently exists at this OID"},
		oidFDBPort: {},
		oidARP:     {},
	}
	for i := 1; i <= 52; i++ {
		walks[oidIfDescr] = append(walks[oidIfDescr], fmt.Sprintf("%s.%d = STRING: \"GigabitEthernet1/0/%d\"", oidIfDescr, i, i))
	}
	for _, port := range slices.Sorted(maps.Keys(fdb)) {
		for _, mac := range fdb[port] {
			walks[oidFDBPort] = append(walks[oidFDBPort], fmt.Sprintf("%s.%s = INTEGER: %d", oidFDBPort, octets(mac), port))
		}
	}
	for _, ip := range slices.Sorted(maps.Keys(arp)) {
		walks[oidARP] = append(walks[oidARP], fmt.Sprintf("%s.636.%s = Hex-STRING: %s ", oidARP, ip, hex(arp[ip])))
	}
	return walks
}

// stations returns n station MACs 00:1b:21:<a>:<b>:01.. for FDB rows.
func stations(a, b, n int) []string {
	var out []string
	for i := 1; i <= n; i++ {
		out = append(out, fmt.Sprintf("00:1b:21:%02x:%02x:%02x", a, b, i))
	}
	return out
}

// aliasNetwork is the synthetic network of TestMACRefARPAliasAgents: the
// core A, the HPE B (LLDP off, chassis MAC never learned, VLAN MAC
// 4c:ae:a3:82:00:0c) on A's port 5, the SNR D (VLAN MAC f8:f0:82:82:00:03)
// on A's port 7 and the leaf E on A's port 9, whose uplink with 30 MACs has
// B's VLAN MAC as its only switch MAC.
const (
	aliasA, aliasB, aliasD, aliasE     = "10.9.82.1", "10.9.82.2", "10.9.82.4", "10.9.82.5"
	aliasAMAC, aliasBMAC, aliasDMAC    = "4c:ae:a3:82:00:01", "4c:ae:a3:82:00:02", "f8:f0:82:82:00:04"
	aliasEMAC                          = "4c:ae:a3:82:00:05"
	aliasAVLAN, aliasBVLAN, aliasDVLAN = "4c:ae:a3:82:00:0b", "4c:ae:a3:82:00:0c", "f8:f0:82:82:00:03"
	aliasEVLAN                         = "4c:ae:a3:82:00:0f"
	aliasBSecondIP, aliasHub           = "10.9.82.247", "hub-4c:ae:a3:82:00:01-p5"
)

func aliasNetwork() map[string]map[string][]string {
	return map[string]map[string][]string{
		aliasA: aliasAgent(aliasAMAC, map[int][]string{
			5:  append([]string{aliasBVLAN}, stations(5, 1, 1)...),
			7:  append([]string{aliasDVLAN}, stations(7, 1, 1)...),
			9:  append([]string{aliasEVLAN}, stations(9, 1, 1)...),
			11: stations(11, 1, 1), // a direct endpoint
		}, map[string]string{aliasB: aliasBVLAN, aliasD: aliasDVLAN, aliasE: aliasEVLAN}),
		// B: its own VLAN MAC in its own FDB (port 52) is no endpoint, and
		// the core is learned there by its chassis MAC and its VLAN MAC
		aliasB: aliasAgent(aliasBMAC, map[int][]string{
			3:  stations(3, 2, 1),
			52: append([]string{aliasAMAC, aliasAVLAN, aliasBVLAN}, stations(52, 2, 21)...),
		}, nil),
		aliasD: aliasAgent(aliasDMAC, map[int][]string{
			24: append([]string{aliasAVLAN, aliasBVLAN}, stations(24, 4, 23)...), // two switches: transit
		}, nil),
		aliasE: aliasAgent(aliasEMAC, map[int][]string{
			1: append([]string{aliasBVLAN}, stations(1, 5, 29)...), // B alone on an uplink of 30 MACs
		}, nil),
	}
}

// pollAliasNetwork polls the agents with the rescan's SNMP object and the
// cache, and returns the graph built from what was stored.
func pollAliasNetwork(t *testing.T, cache map[string]string) *DJGraph {
	t.Helper()
	resetState(t)
	agents := aliasNetwork()
	for _, ip := range slices.Sorted(maps.Keys(agents)) {
		fakeSNMP.set(ip, agents[ip])
	}
	globalMACtoIPMutex.Lock()
	globalMACtoIP = cache
	globalMACtoIPMutex.Unlock()
	obj := newRescanSNMPObject()
	for _, ip := range slices.Sorted(maps.Keys(agents)) {
		obj.CollectData(ip, "")
		if !collectedReachable(ip) {
			t.Fatalf("%s was not stored", ip)
		}
	}
	return buildGraphFromSnapshot(snapshotCollectedData())
}

// TestMACRefARPAliasAgents polls synthetic agents of switches whose chassis
// MAC is never learned in an FDB, while the MAC their management IP answers
// ARP from is: the switches are linked where their VLAN MAC is the only
// switch MAC on a port (MAC-REF), the VLAN MACs get no endpoint node, and a
// switch learned alone on an uplink with many MACs is linked from the port
// with the fewest MACs only. When the cache maps B's VLAN MAC to a second IP
// (as the fixture's cache maps 172.20.230.76's to 172.20.230.247) it is no
// alias: the MAC is an ordinary station, so A's port 5 becomes a two-MAC
// hub (a false Shadow-IT port) and B is linked only from its own uplink,
// where A is the only switch.
func TestMACRefARPAliasAgents(t *testing.T) {
	g := pollAliasNetwork(t, map[string]string{aliasAVLAN: aliasA})
	links := graphEdgeLines(g)
	var macRef []string
	for _, l := range links {
		if strings.Contains(l, "[MAC-REF]") {
			macRef = append(macRef, l)
		}
	}
	if want := []string{
		aliasAMAC + " -> " + aliasBMAC + ` : "GE1/0/5 [MAC-REF]|"`,
		aliasAMAC + " -> " + aliasEMAC + ` : "GE1/0/9 [MAC-REF]|"`,
		aliasAMAC + " -> " + aliasDMAC + ` : "GE1/0/7 [MAC-REF]|"`,
	}; !slices.Equal(macRef, want) {
		t.Errorf("MAC-REF links:\n%s\nwant\n%s\n(B from A's port 5 with 2 MACs, not from E's 30-MAC uplink; D's uplink has two switches)",
			strings.Join(macRef, "\n"), strings.Join(want, "\n"))
	}
	for _, mac := range []string{aliasAVLAN, aliasBVLAN, aliasDVLAN, aliasEVLAN} {
		if g.Nodes[mac] {
			t.Errorf("the VLAN MAC %s of a switch has an endpoint node", mac)
		}
	}
	if !g.GetEdge(aliasAMAC, "00:1b:21:0b:01:01") || !g.GetEdge(aliasBMAC, "00:1b:21:03:02:01") {
		t.Errorf("direct endpoints missing: %v", links)
	}
	if g.Nodes[aliasHub] || !g.GetEdge(aliasAMAC, "00:1b:21:05:01:01") {
		t.Errorf("A's port 5 (B's VLAN MAC and one station): hub %v, want the station as a direct endpoint", g.Nodes[aliasHub])
	}

	// A second IP for B's VLAN MAC: no alias
	g = pollAliasNetwork(t, map[string]string{aliasAVLAN: aliasA, aliasBVLAN: aliasBSecondIP})
	if got := g.GetEdgeLabel(aliasBMAC, aliasAMAC); got != "GE1/0/52 [MAC-REF]|" || g.Edges[aliasAMAC][aliasBMAC] != "" || g.GetEdge(aliasEMAC, aliasBMAC) {
		t.Errorf("B's links %q (A -> B %q), want only B's uplink GE1/0/52 to A: %v", got, g.Edges[aliasAMAC][aliasBMAC], graphEdgeLines(g))
	}
	if _, member := g.Edges[aliasHub][aliasBVLAN]; !g.Nodes[aliasHub] || !member {
		t.Errorf("B's VLAN MAC with two IPs is not a station of A's port 5 (the port's hub)")
	}
	if !g.GetEdge(aliasAMAC, aliasDMAC) || !g.GetEdge(aliasAMAC, aliasEMAC) {
		t.Errorf("D and E lost their links: %v", graphEdgeLines(g))
	}
}

// TestMACRefPortChoice checks the MAC cross-reference rule with own MACs: a
// switch learned by its chassis MAC and its alias on one port is one switch
// there, the switch's own alias does not count on its own port, two switches
// make a transit port, a port whose LLDP neighbor is a polled switch is
// skipped also when the switch MAC learned there is an alias, and of the
// ports where a switch is learned alone the one with the fewest MACs wins,
// then the first switch in IP order, then the lower port.
func TestMACRefPortChoice(t *testing.T) {
	resetState(t)
	const swA, swB, swC, swD = "10.9.83.1", "10.9.83.2", "10.9.83.3", "10.9.83.4"
	const macA, macB, macC, macD = "4c:ae:a3:83:00:01", "4c:ae:a3:83:00:02", "4c:ae:a3:83:00:03", "4c:ae:a3:83:00:04"
	const vlanA, vlanB, vlanC = "4c:ae:a3:83:00:0b", "4c:ae:a3:83:00:0c", "4c:ae:a3:83:00:0d"
	dev := func(ip, chassis string, table ...[]MACEntry) *DeviceData {
		return &DeviceData{IP: ip, ChassisID: chassis, Interfaces: gigabitPorts(10, nil), MACTable: slices.Concat(table...)}
	}
	build := func(devices map[string]*DeviceData) []string {
		g := NewDJGraph()
		for _, ip := range sortedDeviceIPs(devices) {
			graphAddSwitchNode(g, devices[ip])
		}
		addMACCrossRefEdges(g, devices, buildSwitchOwnMACs(devices))
		return graphEdgeLines(g)
	}
	globalMACtoIPMutex.Lock()
	globalMACtoIP = map[string]string{vlanA: swA, vlanB: swB, vlanC: swC}
	globalMACtoIPMutex.Unlock()

	for _, c := range []struct {
		name    string
		devices map[string]*DeviceData
		want    []string
	}{
		{"chassis and alias of one switch, the own alias", map[string]*DeviceData{
			swA: dev(swA, macA, macEntries(2, macB, vlanB, vlanA, "00:1b:21:83:02:01")),
			swB: dev(swB, macB),
		}, []string{macA + " -> " + macB + ` : "GE1/0/2 [MAC-REF]|"`}},
		{"two switches: transit", map[string]*DeviceData{
			swA: dev(swA, macA, macEntries(2, vlanB, vlanC)),
			swB: dev(swB, macB), swC: dev(swC, macC),
		}, nil},
		{"fewest MACs", map[string]*DeviceData{
			swA: dev(swA, macA, macEntries(2, vlanB, "00:1b:21:83:02:01", "00:1b:21:83:02:02")),
			swC: dev(swC, macC, macEntries(4, vlanB, "00:1b:21:83:04:01")),
			swB: dev(swB, macB),
		}, []string{macC + " -> " + macB + ` : "GE1/0/4 [MAC-REF]|"`}},
		{"a tie: the first switch in IP order, then the lower port", map[string]*DeviceData{
			swC: dev(swC, macC, macEntries(4, vlanB), macEntries(3, vlanB)),
			swA: dev(swA, macA, macEntries(6, vlanB), macEntries(5, vlanB)),
			swB: dev(swB, macB),
		}, []string{macA + " -> " + macB + ` : "GE1/0/5 [MAC-REF]|"`}},
		{"an LLDP neighbor that is a polled switch", map[string]*DeviceData{
			swA: {IP: swA, ChassisID: macA, Interfaces: gigabitPorts(10, nil),
				Neighbors: []LLDPNeighbor{{LocalPortNum: 2, RemIndex: 1, RemChassisIdSubtype: 4, RemChassisId: "4C AE A3 83 00 04", RemPortIdSubtype: 5, RemPortId: "\"GigabitEthernet1/0/1\""}},
				MACTable:  macEntries(2, vlanB)},
			swB: dev(swB, macB), swD: dev(swD, macD),
		}, nil},
		{"each side picks the other: the first in IP order draws the link", map[string]*DeviceData{
			swB: dev(swB, macB, macEntries(9, vlanA)),
			swA: dev(swA, macA, macEntries(2, vlanB)),
		}, []string{macA + " -> " + macB + ` : "GE1/0/2 [MAC-REF]|"`}},
	} {
		if got := build(c.devices); !slices.Equal(got, c.want) {
			t.Errorf("%s: links %q, want %q", c.name, got, c.want)
		}
	}
}

// TestFixtureSwitchAliases pins the aliases of the saved data of 2026-10-20:
// the SNR 172.20.230.77's VLAN MAC is the only switch MAC on 172.20.230.76
// GigabitEthernet1/0/48 (24 MACs) and links .77 to .76; the Huawei
// 172.20.230.17 (no SNMP answer, node id its IP) is linked from the SNR
// 172.20.230.254 Ethernet1/0/23 (17 MACs) by c4:08:80:02:7b:ff; the
// Huawei 172.20.254.249's GE0/0/14 link to TTJ-3&4 172.20.230.23 is gone:
// that port is 254.249's uplink, 1194 MACs and 53 switches by their VLAN
// MACs. The fixture cache maps .76's VLAN MAC 4c:ae:a3:8d:ec:cb to
// 172.20.230.247, so it is no alias; with the entry the live cache had on
// 2026-10-22 (4c:ae:a3:8d:ec:cb -> 172.20.230.76) it is, and .76 still gets
// no link from another switch: each port where it is learned has an LLDP
// neighbor that is a polled switch (172.20.254.202 TGE1/0/51 the Aruba
// 6300, 172.20.230.47 Eth1/0/25 172.20.230.46, 172.20.230.83 Eth1/0/2
// 172.20.230.2) or other switches too. Its upstream is the Aruba's port
// 1/1/1, and the saved data has no FDB of the Aruba.
func TestFixtureSwitchAliases(t *testing.T) {
	const dot76, dot77, dot76VLAN = "4c:ae:a3:8d:ec:c1", "f8:f0:82:d8:62:67", "4c:ae:a3:8d:ec:cb"
	g := buildFixtureGraph(t)
	own := buildSwitchOwnMACs(snapshotCollectedData())
	for mac, id := range map[string]string{
		"f8:f0:82:d8:62:66": dot77, "c4:08:80:02:7b:ff": "172.20.230.17",
		dot76: dot76, dot77: dot77,
	} {
		if own[mac] != id {
			t.Errorf("own MAC %s: %q, want %q", mac, own[mac], id)
		}
	}
	if id, ok := own[dot76VLAN]; ok {
		t.Errorf("%s is an alias of %s, but the fixture cache maps it to 172.20.230.247", dot76VLAN, id)
	}
	for _, c := range []struct{ a, b, label string }{
		{dot76, dot77, "GE1/0/48 [MAC-REF]|"},
		{"f8:f0:82:d1:67:5e", "172.20.230.17", "Eth1/0/23 [MAC-REF]|"},
		{"172.20.254.249", "4c:ae:a3:a2:01:ac", ""},
	} {
		if got := g.GetEdgeLabel(c.a, c.b); got != c.label {
			t.Errorf("link %s - %s = %q, want %q", c.a, c.b, got, c.label)
		}
	}

	globalMACtoIPMutex.Lock()
	globalMACtoIP[dot76VLAN] = "172.20.230.76"
	globalMACtoIPMutex.Unlock()
	snapshot := snapshotCollectedData()
	if id := buildSwitchOwnMACs(snapshot)[dot76VLAN]; id != dot76 {
		t.Errorf("with the live cache %s is an alias of %q, want %s", dot76VLAN, id, dot76)
	}
	live := buildGraphFromSnapshot(snapshot)
	var switches []string
	for _, id := range slices.Sorted(maps.Keys(live.Nodes)) {
		if live.graphSwitches[id] && id != dot76 && live.GetEdge(dot76, id) {
			switches = append(switches, id)
		}
	}
	if !slices.Equal(switches, []string{dot77}) {
		t.Errorf("with the live cache .76 is linked to the switches %v, want only .77", switches)
	}
	if baseLinks, liveLinks := graphEdgeLines(g), graphEdgeLines(live); !slices.Equal(baseLinks, liveLinks) {
		t.Errorf("the alias of .76 changes links: -%v +%v", sortedMinus(baseLinks, liveLinks), sortedMinus(liveLinks, baseLinks))
	}
}

// TestFDBPortsOwnAlias checks the FDB rule with own MACs: on a VLAN trunk
// whose MACs are mostly virtual NICs (an ESXi host) the switch's own ARP
// alias is no MAC of the port and no switch learned there, so the port is a
// VM port; another switch's alias makes a trunk a switch link, no VM port
// (its two other MACs are direct endpoints, as on any trunk with at most 3).
func TestFDBPortsOwnAlias(t *testing.T) {
	resetState(t)
	const sw, other = "10.9.84.1", "10.9.84.2"
	const swMAC, swVLAN, otherMAC, otherVLAN = "4c:ae:a3:84:00:01", "4c:ae:a3:84:00:0b", "4c:ae:a3:84:00:02", "4c:ae:a3:84:00:0c"
	vms := []string{"00:0c:29:84:00:01", "00:0c:29:84:00:02"}
	devices := map[string]*DeviceData{
		sw: {IP: sw, ChassisID: swMAC, Interfaces: gigabitPorts(12, nil),
			PortVLANs: []PortVLAN{{PortIndex: 10, PVID: 1, IsTrunk: true}, {PortIndex: 11, PVID: 1, IsTrunk: true}},
			ARPTable:  []ARPEntry{{IPAddress: sw, MACAddress: swVLAN}, {IPAddress: other, MACAddress: otherVLAN}},
			MACTable:  slices.Concat(macEntries(10, append([]string{swVLAN}, vms...)...), macEntries(11, append([]string{otherVLAN}, vms...)...))},
		other: {IP: other, ChassisID: otherMAC},
	}
	var got []string
	for _, p := range fdbPorts(devices[sw], buildSwitchOwnMACs(devices)) {
		got = append(got, fmt.Sprintf("%d %d %v", p.Port, p.Kind, p.MACs))
	}
	if want := []string{fmt.Sprintf("10 %d %v", fdbVMPort, vms), fmt.Sprintf("11 %d %v", fdbDirect, vms)}; !slices.Equal(got, want) {
		t.Errorf("fdbPorts = %q, want %q (port 11 is a link to %s)", got, want, other)
	}
}
