package main

import (
	"cmp"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"unicode"
)

// Gateways. gateway_ip names the routers of the network: one IP, or several
// (one per line, or separated by spaces or commas; '#' starts a comment).
// gatewayIP is the first one, the core of the analyzer's path check and of
// bfs_depths.json; gatewayIPs is the whole list. The ARP table of every
// gateway feeds the MAC-IP lookup (the startup gateway ARP and the MAC-IP
// service), the ipAddrTable of every gateway feeds the subnet discovery, and
// each gateway that answers SNMP is drawn as one router node
// (addGatewayNodes).
//
// On 2026-10-22 the two gateways were 172.20.1.254, a Debian router VM
// (sysName debian216, MAC 00:0c:29:98:7b:c2, 1388 ARP rows), and 172.20.0.1,
// the FortiGate-600F firewall (MAC 68:cc:ae:96:e6:08 on 172.20.0.1, 2488 ARP
// rows). Neither has BRIDGE-MIB or a local LLDP chassis id, so neither
// passes checkSwitch and neither is polled as a switch: the owner
// configured them, so they are drawn from their gateway walks instead,
// never as a device of collectedData. The FortiGate has an lldpRemTable,
// though (without lldpLocalSystemData): it sees the HPE 5130 4c:ae:a3:8e:05:89
// (172.20.230.238) on its mgmt port, 172.20.254.203 on x7 and the Aruba
// 6300 172.20.230.253 on x8, so the gateway walks read it too
// (collectGatewayLLDP) and its router node is linked to its neighbors.

// gatewayIPs is every gateway of gateway_ip in file order; gatewayIP is its
// first entry. Both are set together (setGatewayIPs).
var gatewayIPs []string

// setGatewayIPs sets the gateway list and gatewayIP, its first entry ("" for
// an empty list).
func setGatewayIPs(ips []string) {
	gatewayIPs = slices.Clone(ips)
	gatewayIP = ""
	if len(gatewayIPs) > 0 {
		gatewayIP = gatewayIPs[0]
	}
}

// isGatewayIP reports whether ip is one of the configured gateways.
func isGatewayIP(ip string) bool {
	return ip != "" && slices.Contains(gatewayIPs, ip)
}

// gatewayListText names the gateways for log lines ("172.20.1.254,
// 172.20.0.1").
func gatewayListText() string {
	return strings.Join(gatewayIPs, ", ")
}

// parseGatewayIPs reads the text of gateway_ip: IPv4 addresses one per line
// or separated by spaces, tabs, commas or semicolons, '#' starting a comment
// that runs to the end of the line. It returns the addresses in file order
// without repeats, and the words that are no IPv4 address (a prefix length,
// a host name or an IPv6 address: ARP and ipAddrTable are IPv4 tables).
func parseGatewayIPs(text string) (ips, invalid []string) {
	text = strings.TrimPrefix(text, string(rune(0xFEFF))) // a byte order mark
	seen := make(map[string]bool)
	for _, line := range strings.Split(text, "\n") {
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		words := strings.FieldsFunc(line, func(r rune) bool { return r == ',' || r == ';' || unicode.IsSpace(r) })
		for _, word := range words {
			addr, err := netip.ParseAddr(word)
			if err != nil || !addr.Is4() {
				invalid = append(invalid, word)
				continue
			}
			if ip := addr.String(); !seen[ip] {
				seen[ip] = true
				ips = append(ips, ip)
			}
		}
	}
	return ips, invalid
}

// loadGatewayIPs reads the gateway list from the file at path (gateway_ip)
// and sets it (setGatewayIPs). A missing file, or one without an IPv4
// address, leaves the list as it is, with a warning; words that are no IPv4
// address are named and skipped.
func loadGatewayIPs(path string) {
	data, err := os.ReadFile(path)
	if err != nil {
		fmt.Println("⚠️  gateway_ip fayl topilmadi! Yarating: echo '172.20.1.254' > gateway_ip")
		return
	}
	ips, invalid := parseGatewayIPs(string(data))
	if len(invalid) > 0 {
		fmt.Printf("⚠️  gateway_ip: IPv4 manzil emas, o'tkazib yuborildi: %s\n", strings.Join(invalid, ", "))
	}
	if len(ips) == 0 {
		fmt.Println("⚠️  gateway_ip fayl bo'sh!")
		return
	}
	setGatewayIPs(ips)
	if len(ips) == 1 {
		fmt.Printf("🌐 Gateway IP yuklandi: %s\n", gatewayIP)
		return
	}
	fmt.Printf("🌐 Gateway IP yuklandi: %s (core: %s)\n", gatewayListText(), gatewayIP)
}

// ─── Gateway walks ────────────────────────────────────────────────────────────

// gatewayPoll is what the gateway walks of this run showed of one gateway.
type gatewayPoll struct {
	SysName  string // sysName.0 of the last walk that read one
	Answered bool   // the agent answered SNMP at least once in this run
	Down     bool   // the last walk got no answer
	// LLDP is the gateway's own LLDP view from the last LLDP read that
	// answered; nil when it showed no neighbor (or none was read yet)
	LLDP *gatewayLLDP
}

// gatewayLLDP is a gateway's own LLDP view (collectGatewayLLDP): the
// neighbors of its lldpRemTable, read like a switch's, and the names of
// its ports. It is never changed once made.
type gatewayLLDP struct {
	Neighbors []LLDPNeighbor // in local port, then remote index order
	// Ports names the gateway's ports by lldpRemLocalPortNum: the ifName
	// of that ifIndex, or its ifDescr when the agent has no ifName (the
	// FortiGate's ifDescr is empty; its LLDP port numbers are ifIndexes:
	// 2 mgmt, 33 x7, 34 x8)
	Ports map[int]string
}

// device is the gateway as a device for the LLDP rules of the switches
// (graphLLDPNeighborTarget, getLocalPortName): its IP, sysName and ports.
func (l *gatewayLLDP) device(ip, sysName string) *DeviceData {
	d := &DeviceData{IP: ip, SysName: sysName}
	for _, port := range slices.Sorted(maps.Keys(l.Ports)) {
		d.Interfaces = append(d.Interfaces, InterfaceData{IfIndex: port, IfDescr: l.Ports[port]})
	}
	return d
}

// gatewayPolls holds the walks of this run by gateway IP (guarded by
// gatewayPollsMu). The graph build draws the gateways that answered.
var (
	gatewayPollsMu sync.Mutex
	gatewayPolls   = make(map[string]gatewayPoll)
)

// recordGatewayPoll notes one walk of gateway ip: whether its agent answered
// and the sysName it gave ("" keeps the one read before).
func recordGatewayPoll(ip string, answered bool, sysName string) {
	gatewayPollsMu.Lock()
	defer gatewayPollsMu.Unlock()
	p := gatewayPolls[ip]
	p.Down = !answered
	if answered {
		p.Answered = true
		if sysName != "" {
			p.SysName = sysName
		}
	}
	gatewayPolls[ip] = p
}

// recordGatewayLLDP notes the LLDP read of gateway ip (collectGatewayLLDP):
// its view, nil when it showed no neighbor. A read that failed (err) keeps
// the view read before.
func recordGatewayLLDP(ip string, lldp *gatewayLLDP, err error) {
	if err != nil {
		return
	}
	gatewayPollsMu.Lock()
	defer gatewayPollsMu.Unlock()
	p := gatewayPolls[ip]
	p.LLDP = lldp
	gatewayPolls[ip] = p
}

// gatewayNode is a configured gateway that answered SNMP in this run, as
// the graph build draws it.
type gatewayNode struct {
	IP      string
	SysName string
	Down    bool         // its last walk got no answer: the router node is unreachable
	LLDP    *gatewayLLDP // its own LLDP view; nil when it showed no neighbor
}

// answeredGateways lists the configured gateways that answered SNMP in this
// run, in gateway_ip order.
func answeredGateways() []gatewayNode {
	gatewayPollsMu.Lock()
	defer gatewayPollsMu.Unlock()
	var out []gatewayNode
	for _, ip := range gatewayIPs {
		if p := gatewayPolls[ip]; p.Answered {
			out = append(out, gatewayNode{IP: ip, SysName: p.SysName, Down: p.Down, LLDP: p.LLDP})
		}
	}
	return out
}

// OIDs of the gateway port names (IF-MIB ifName and ifDescr).
const (
	collectIfNameOID  = ".1.3.6.1.2.1.31.1.1.1.1"
	collectIfDescrOID = ".1.3.6.1.2.1.2.2.1.2"
)

// collectGatewayLLDP reads the gateway's own LLDP view for its router node:
// the neighbors of its lldpRemTable with their management addresses, read
// like a switch's (collectLLDPNeighbors), and, when it has neighbors, the
// names of its ports (collectPortNames). A gateway needs no
// lldpLocalSystemData for it: the FortiGate answers "No Such Object" there
// and lists its neighbors all the same. It returns nil when the gateway
// shows no neighbor ("No Such Object", the Debian router); err is the walk
// error of an agent that did not answer.
func (s *SNMPObject) collectGatewayLLDP(ip string) (*gatewayLLDP, error) {
	neighbors, err := s.collectLLDPNeighbors(ip)
	if err != nil {
		return nil, err
	}
	if len(neighbors) == 0 {
		return nil, nil
	}
	slices.SortFunc(neighbors, func(a, b LLDPNeighbor) int {
		return cmp.Or(cmp.Compare(a.LocalPortNum, b.LocalPortNum), cmp.Compare(a.RemIndex, b.RemIndex))
	})
	return &gatewayLLDP{Neighbors: neighbors, Ports: s.collectPortNames(ip)}, nil
}

// collectPortNames reads the names of the agent's interfaces by ifIndex:
// ifName, or ifDescr when no ifName is set. Empty names are left out (the
// port is then "Port N", getLocalPortName); nil when neither walk names
// any.
func (s *SNMPObject) collectPortNames(ip string) map[int]string {
	for _, oid := range []string{collectIfNameOID, collectIfDescrOID} {
		lines, err := s.runSNMPWalk(ip, oid)
		if err != nil {
			continue
		}
		var names map[int]string
		for _, line := range lines {
			rowOID, _, val, ok := collectSNMPValue(line)
			idx, inTable := collectOIDIndex(rowOID, oid)
			name := strings.TrimSpace(strings.Trim(val, "\""))
			if !ok || !inTable || len(idx) != 1 || name == "" || graphIsSNMPException(name) {
				continue
			}
			if names == nil {
				names = make(map[int]string)
			}
			names[idx[0]] = name
		}
		if names != nil {
			return names
		}
	}
	return nil
}

// gatewayARP is the result of one gateway's ARP walk in a run.
type gatewayARP struct {
	IP      string
	Rows    int        // ARP rows read
	Updated int        // new or changed MAC-IP mappings
	Err     error      // the walk failed: the gateway did not answer
	entries []ARPEntry // the rows read
}

// walkGatewaysARP walks the ARP table of every configured gateway at the
// same time (gateways that do not answer cost one timeout together, not
// one each) and reads the sysName and the own LLDP view
// (collectGatewayLLDP) of each one that answered. Each walk is recorded:
// recordGatewayPoll and recordGatewayLLDP for the router node,
// recordGatewayARP for the gateway's expiry clock and the one warning per
// start of a gateway that does not answer. Nothing is merged. Returns the
// walks in gateway_ip order.
func walkGatewaysARP(snmpObj *SNMPObject) []gatewayARP {
	type walk struct {
		entries []ARPEntry
		err     error
		sysName string
		lldp    *gatewayLLDP
		lldpErr error
	}
	gateways := slices.Clone(gatewayIPs)
	walks := make([]walk, len(gateways))
	var wg sync.WaitGroup
	for i, ip := range gateways {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := walk{}
			w.entries, w.err = snmpObj.collectARPTable(ip)
			if w.err == nil {
				// The agent answered: its name labels the router node, its
				// LLDP neighbors are linked to it
				w.sysName = snmpObj.collectSysText(ip, oidSysName)
				w.lldp, w.lldpErr = snmpObj.collectGatewayLLDP(ip)
			}
			walks[i] = w
		}()
	}
	wg.Wait()

	results := make([]gatewayARP, len(gateways))
	for i, ip := range gateways {
		w := walks[i]
		results[i] = gatewayARP{IP: ip, Rows: len(w.entries), Err: w.err, entries: w.entries}
		recordGatewayPoll(ip, w.err == nil, w.sysName)
		if w.err == nil {
			recordGatewayLLDP(ip, w.lldp, w.lldpErr)
		}
		recordGatewayARP(ip, len(w.entries), w.err, macIPClock()) // warns once per gateway when it fails
	}
	return results
}

// collectGatewaysARP walks the ARP table of every gateway
// (walkGatewaysARP) and merges the tables into globalMACtoIP in gateway_ip
// order with the policy of every ARP collector (collectMergeARPTables: a
// later gateway's row for a MAC replaces an earlier one's, each MAC merged
// once). Returns the walks in gateway_ip order.
func collectGatewaysARP(snmpObj *SNMPObject) []gatewayARP {
	results := walkGatewaysARP(snmpObj)
	tables := make([][]ARPEntry, len(results))
	for i, res := range results {
		tables[i] = res.entries
	}
	for i, n := range collectMergeARPTables(tables, macIPClock()) {
		results[i].Updated = n
	}
	return results
}

// ─── Gateway notices ──────────────────────────────────────────────────────────

// gatewayNotices holds the gateway lines printed in this run (guarded by
// gatewayNoticesMu): every graph build places the gateways again, and each
// line is printed once per start.
var (
	gatewayNoticesMu sync.Mutex
	gatewayNotices   = make(map[string]bool)
)

// gatewayNotice prints a gateway line unless this run printed it before.
func gatewayNotice(format string, args ...any) {
	line := fmt.Sprintf(format, args...)
	gatewayNoticesMu.Lock()
	printed := gatewayNotices[line]
	gatewayNotices[line] = true
	gatewayNoticesMu.Unlock()
	if !printed {
		fmt.Println(line)
	}
}

// ─── Router nodes ─────────────────────────────────────────────────────────────

// graphKnownSwitch reports whether a polled device shows switch data: a
// usable chassis MAC, FDB rows or LLDP neighbors. A device stored without
// any (the FortiGate the rescue scan stored on 2026-10-22, before
// checkSwitch) is no switch.
func graphKnownSwitch(d *DeviceData) bool {
	return graphChassisKey(d.ChassisID) != "" || len(d.MACTable) > 0 || len(d.Neighbors) > 0
}

// gatewayMAC finds the MAC of gateway ip in the ARP data, in canonical form,
// and names its source. The ARP tables of the polled switches come first:
// they are keyed by IP, and the MAC most of them give the IP wins (then the
// lowest). Otherwise the globalMACtoIP entries that map a MAC to the IP: the
// cache keeps one IP per MAC, so an old MAC can still map to the IP (the
// fixture cache maps the Dell 08:92:04:99:a9:42 to 172.20.0.1 next to the
// FortiGate's 68:cc:ae:96:e6:08), and a MAC learned in a switch FDB wins,
// then the one seen last, then the lowest. "" when neither knows the IP.
func gatewayMAC(ip string, snapshot map[string]*DeviceData) (mac, source string) {
	votes := make(map[string]int)
	for _, devIP := range sortedDeviceIPs(snapshot) {
		listed := make(map[string]bool)
		for _, e := range snapshot[devIP].ARPTable {
			if m := usableMAC(e.MACAddress); m != "" && e.IPAddress == ip && !listed[m] {
				listed[m] = true
				votes[m]++
			}
		}
	}
	if len(votes) > 0 {
		best := ""
		for _, m := range slices.Sorted(maps.Keys(votes)) {
			if votes[m] > votes[best] {
				best = m
			}
		}
		return best, "switch ARP tables"
	}

	globalMACtoIPMutex.RLock()
	var candidates []string
	seen := make(map[string]int64)
	for m, mappedIP := range globalMACtoIP {
		if mappedIP == ip && usableMAC(m) != "" {
			candidates = append(candidates, m)
			if t, ok := collectMACIPSeen[m]; ok {
				seen[m] = t.Unix()
			}
		}
	}
	globalMACtoIPMutex.RUnlock()
	if len(candidates) == 0 {
		return "", ""
	}
	inFDB := make(map[string]bool)
	if len(candidates) > 1 {
		wanted := make(map[string]bool, len(candidates))
		for _, m := range candidates {
			wanted[m] = true
		}
		for _, d := range snapshot {
			for _, e := range d.MACTable {
				if m := canonicalMAC(e.MACAddress); wanted[m] {
					inFDB[m] = true
				}
			}
		}
	}
	slices.SortFunc(candidates, func(a, b string) int {
		switch {
		case inFDB[a] != inFDB[b]:
			if inFDB[a] {
				return -1
			}
			return 1
		case seen[a] != seen[b]:
			if seen[a] > seen[b] {
				return -1
			}
			return 1
		}
		return strings.Compare(a, b)
	})
	return candidates[0], "MAC-IP cache"
}

// gatewayLink is the switch port a router node is linked from.
type gatewayLink struct {
	dev  *DeviceData
	port int // FDB bridge port
	macs int // station MACs learned on the port
}

// gatewayPort picks the port the router node with this MAC is linked from,
// with the rule addMACCrossRefEdges applies to a switch seen in another
// switch's FDB: a port of a polled switch where the MAC's device is the only
// infrastructure device learned (infra maps the own MACs of the switches,
// buildSwitchOwnMACs, to their node ids and each gateway MAC to itself; a
// device other than the switch itself counts once whatever number of its
// MACs is learned there, and two or more make a transit port), NULL0 ports
// left out. Of those the port with the fewest MACs wins, then the first
// switch in IP order, then the lower port: the FortiGate's MAC is the only
// MAC on 172.20.254.203 Ten-GigabitEthernet1/0/52.
func gatewayPort(snapshot map[string]*DeviceData, mac string, infra map[string]string) (gatewayLink, bool) {
	var best gatewayLink
	found := false
	for _, ip := range sortedDeviceIPs(snapshot) {
		d := snapshot[ip]
		ports := make(map[int]map[string]bool)
		for _, e := range d.MACTable {
			if usableMAC(e.MACAddress) == mac {
				ports[e.PortNumber] = make(map[string]bool)
			}
		}
		if len(ports) == 0 {
			continue
		}
		for _, e := range d.MACTable {
			if macs, ok := ports[e.PortNumber]; ok {
				if m := usableMAC(e.MACAddress); m != "" {
					macs[m] = true
				}
			}
		}
		own := graphDeviceNodeID(d)
		for _, port := range slices.Sorted(maps.Keys(ports)) {
			if isNullInterface(getFDBPortName(d, port)) {
				continue
			}
			macs := ports[port]
			devices := make(map[string]bool) // the infrastructure devices learned there
			for m := range macs {
				if id, ok := infra[m]; ok && id != own {
					devices[id] = true
				}
			}
			if len(devices) != 1 {
				continue // another switch or gateway is learned there too
			}
			if !found || len(macs) < best.macs {
				best, found = gatewayLink{dev: d, port: port, macs: len(macs)}, true
			}
		}
	}
	return best, found
}

// gatewaySameDevice lists the nodes other than the router node mac that are
// the gateway itself, so the router node takes their place (no second node
// for one gateway, and no node with the gateway's IP as id): a device
// stored with the gateway's IP that shows no switch data (graphKnownSwitch)
// and so has the IP as node id, and the LLDP neighbors of the polled
// switches whose node id is the gateway's IP, that advertise the gateway's
// IP as their management address, or that carry the gateway's sysName on a
// port where its MAC is learned. 172.20.254.203 sees the FortiGate on
// Ten-GigabitEthernet1/0/52 with its chassis MAC 68:cc:ae:96:e5:e8 and its
// management address 172.20.0.1, while its ARP MAC is 68:cc:ae:96:e6:08 (the
// fixture predates the management address: there the sysName and the port
// tell). The node of a polled switch, or another gateway's router node, is
// never the gateway.
func gatewaySameDevice(graph *DJGraph, snapshot map[string]*DeviceData, gws []gatewayNode, mac string) []string {
	same := make(map[string]bool)
	for _, gw := range gws {
		if d, polled := snapshot[gw.IP]; polled && !graphKnownSwitch(d) && graphDeviceNodeID(d) == d.IP {
			same[d.IP] = true
		}
	}
	for _, ip := range sortedDeviceIPs(snapshot) {
		d := snapshot[ip]
		macPorts := make(map[int]bool) // ifIndex of the ports where mac is learned
		for _, e := range d.MACTable {
			if usableMAC(e.MACAddress) == mac {
				macPorts[collectFDBIfIndex(d, e.PortNumber)] = true
			}
		}
		for _, n := range d.Neighbors {
			target, _, ok := graphLLDPNeighborTarget(d, n)
			if !ok || target == mac || graph.graphSwitches[target] || graph.graphRouters[target] {
				continue
			}
			sysName := strings.TrimSpace(strings.Trim(n.RemSysName, "\""))
			for _, gw := range gws {
				if target == gw.IP || n.RemMgmtIP == gw.IP ||
					(gw.SysName != "" && strings.EqualFold(sysName, gw.SysName) && macPorts[n.LocalPortNum]) {
					same[target] = true
				}
			}
		}
	}
	var out []string
	for _, id := range slices.Sorted(maps.Keys(same)) {
		if id != mac && graph.Nodes[id] {
			out = append(out, id)
		}
	}
	return out
}

// graphMergeNode moves the links of node from to node into, with their
// labels (a link into already has keeps its own), and removes from with its
// label, status, sysName text and switch mark. into must exist.
func graphMergeNode(graph *DJGraph, from, into string) {
	if from == into || !graph.Nodes[from] || !graph.Nodes[into] {
		return
	}
	for _, tgt := range slices.Sorted(maps.Keys(graph.Edges[from])) {
		if tgt != into {
			graph.AddEdge(into, tgt, graph.Edges[from][tgt])
		}
	}
	delete(graph.Edges, from)
	for _, src := range slices.Sorted(maps.Keys(graph.Edges)) {
		label, ok := graph.Edges[src][from]
		if !ok {
			continue
		}
		delete(graph.Edges[src], from)
		if src != into {
			graph.AddEdge(src, into, label)
		}
	}
	if text := graph.graphSysText[from]; text != "" {
		graphAddSysText(graph, into, strings.Split(text, "\n")...)
	}
	delete(graph.Nodes, from)
	delete(graph.SwitchInfo, from)
	delete(graph.NodeStatus, from)
	delete(graph.NodeCoords, from)
	delete(graph.IDs, from)
	delete(graph.graphSwitches, from)
	delete(graph.graphSysText, from)
}

// addGatewayNodes draws every configured gateway that answered SNMP
// (answeredGateways) as one router node: its id is the gateway's MAC from
// the ARP data (gatewayMAC), its label the sysName and the gateway IP, its
// group "router" (graphRouters). Gateway IPs with one MAC are one device and
// share the node, with every IP as a label line. The router node takes the
// place of the nodes that are the same device (an endpoint node of its MAC,
// gatewaySameDevice), keeps their links, and is linked from the port that
// gatewayPort picks unless that switch is linked to it already, with the
// label of a MAC cross-reference link ("TGE1/0/52 [MAC-REF]|"). A gateway
// is configured by the owner, so it needs no switch MIB (checkSwitch) and
// is never a device of collectedData; a gateway that is a polled switch is
// drawn by the switch rules instead. A gateway whose MAC is not known is not
// drawn; that, and where each router node is linked, is logged once per
// start. Runs after the LLDP, FDB and MAC cross-reference links and before
// detectHypervisors and enrichGraphWithIPs, which leave router nodes alone.
func addGatewayNodes(graph *DJGraph, snapshot map[string]*DeviceData, switchMACs map[string]string, gateways []gatewayNode) {
	// The MAC of each gateway, and the gateways of each MAC in gateway_ip order
	var macOrder []string
	byMAC := make(map[string][]gatewayNode)
	for _, gw := range gateways {
		if d, polled := snapshot[gw.IP]; polled && graphKnownSwitch(d) {
			gatewayNotice("🌐 [Gateway] %s is the polled switch %s: drawn as that switch, no router node", gw.IP, graphDeviceNodeID(d))
			continue
		}
		mac, source := gatewayMAC(gw.IP, snapshot)
		if mac == "" {
			gatewayNotice("⚠️ [Gateway] %s (%s) answered SNMP but its MAC is unknown: no switch ARP table and no MAC-IP cache entry has %s, so no router node is drawn", gw.IP, gatewayName(gw), gw.IP)
			continue
		}
		if switchID, isSwitch := switchMACs[mac]; isSwitch {
			gatewayNotice("🌐 [Gateway] %s has the chassis MAC %s of the polled switch %s: drawn as that switch, no router node", gw.IP, mac, switchID)
			continue
		}
		if byMAC[mac] == nil {
			macOrder = append(macOrder, mac)
		}
		byMAC[mac] = append(byMAC[mac], gw)
		gatewayNotice("🌐 [Gateway] %s (%s): MAC %s from the %s", gw.IP, gatewayName(gw), mac, source)
	}

	// The own MACs of the switches and the gateway MACs, by device: a port
	// where two of these devices are learned is a transit port
	infra := make(map[string]string, len(switchMACs)+len(macOrder))
	for m, id := range switchMACs {
		infra[m] = id
	}
	for _, m := range macOrder {
		infra[m] = m
	}

	for _, mac := range macOrder {
		gws := byMAC[mac]
		lines := []string{}
		sysName := ""
		down := true
		for _, gw := range gws {
			if sysName == "" {
				sysName = gw.SysName
			}
			down = down && gw.Down
		}
		if sysName != "" {
			lines = append(lines, sysName)
		}
		for _, gw := range gws {
			lines = append(lines, gw.IP)
		}

		graph.AddNode(mac)
		graph.SwitchInfo[mac] = strings.Join(lines, "\n")
		if graph.graphRouters == nil {
			graph.graphRouters = make(map[string]bool)
		}
		graph.graphRouters[mac] = true
		graphAddSysText(graph, mac, sysName)
		if down {
			graph.NodeStatus[mac] = "unreachable"
		} else {
			delete(graph.NodeStatus, mac)
		}

		merged := gatewaySameDevice(graph, snapshot, gws, mac)
		for _, id := range merged {
			graphMergeNode(graph, id, mac)
		}

		// The gateway's own LLDP neighbors come before the FDB port: a link
		// LLDP shows needs no MAC-REF link
		lldpWhere := gatewayLLDPLinks(graph, mac, gws, merged)

		where := "not linked: its MAC is learned on no switch port without another switch or gateway MAC"
		if link, ok := gatewayPort(snapshot, mac, infra); ok {
			switchID := graphDeviceNodeID(link.dev)
			portName := normalizePortName(getFDBPortName(link.dev, link.port))
			where = fmt.Sprintf("linked from %s %s (%s on the port)", link.dev.IP, portName, switchSkipCount(link.macs, "MAC"))
			if graph.GetEdge(switchID, mac) {
				where += ", by its existing link"
			} else {
				graph.AddEdge(switchID, mac, fmt.Sprintf("%s [MAC-REF]|", portName))
			}
		}
		if len(merged) > 0 {
			where += fmt.Sprintf("; in place of node(s) %s", strings.Join(merged, ", "))
		}
		if lldpWhere != "" {
			where += "; " + lldpWhere
		}
		gatewayNotice("🌐 [Gateway] %s drawn as router %s, %s", strings.Join(lines, " "), mac, where)
	}
}

// gatewayLLDPLinks links router node mac to the LLDP neighbors of its
// gateways (gatewayNode.LLDP). Each neighbor is matched to its node as a
// switch's neighbor is (graphLLDPNeighborTarget: a polled switch's chassis
// MAC is the switch's node; a neighbor that is no node yet gets an LLDP
// endpoint node, graphAddLLDPEndpoint) and is linked from the router node
// with the label "<gateway port>|<neighbor port>" ("mgmt|GE1/0/47"), unless
// the two are linked already: a switch that sees the gateway reports the
// link from its side (172.20.254.203 Ten-GigabitEthernet1/0/52, whose LLDP
// node of the FortiGate the router node replaced, gatewaySameDevice), and
// that link stays as it is. Neighbors that are the router node itself or a
// node it replaced (merged) are left out. It returns the text for the log
// line ("" when no gateway of the node has LLDP neighbors).
func gatewayLLDPLinks(graph *DJGraph, mac string, gws []gatewayNode, merged []string) string {
	var notes []string
	for _, gw := range gws {
		if gw.LLDP == nil {
			continue
		}
		dev := gw.LLDP.device(gw.IP, gw.SysName)
		var linked, existing []string
		skipped := 0
		for _, n := range gw.LLDP.Neighbors {
			target, displayName, ok := graphLLDPNeighborTarget(dev, n)
			if !ok || target == mac || slices.Contains(merged, target) {
				skipped++
				continue
			}
			port := normalizePortName(getLocalPortName(dev, n.LocalPortNum))
			graphAddSysText(graph, target, n.RemSysName, n.RemSysDesc)
			if !graph.Nodes[target] {
				graphAddLLDPEndpoint(graph, target, displayName, n, getGlobalIP(target))
			}
			link := fmt.Sprintf("%s (%s)", target, port)
			if graph.GetEdge(mac, target) {
				existing = append(existing, link)
				continue
			}
			graph.AddEdge(mac, target, fmt.Sprintf("%s|%s", port, normalizePortName(lldpRemotePortName(n))))
			linked = append(linked, link)
		}
		var parts []string
		if len(linked) > 0 {
			parts = append(parts, "linked to "+strings.Join(linked, ", "))
		}
		if len(existing) > 0 {
			parts = append(parts, "already linked: "+strings.Join(existing, ", "))
		}
		if skipped > 0 {
			parts = append(parts, fmt.Sprintf("%s left out", switchSkipCount(skipped, "neighbor")))
		}
		notes = append(notes, fmt.Sprintf("LLDP of %s: %s", gw.IP, strings.Join(parts, "; ")))
	}
	return strings.Join(notes, "; ")
}

// gatewayName is the sysName of a gateway for log lines.
func gatewayName(gw gatewayNode) string {
	if gw.SysName == "" {
		return "no sysName"
	}
	return gw.SysName
}
