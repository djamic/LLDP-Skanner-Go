package main

import (
	"cmp"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"lldp_scanner/modules"
)

// Tests of the LLDP and FDB shapes of 2026-10-22 (snmpbulkwalk of the live
// agents, read only; testdata/agents holds the answers): the PiXiETECH
// PXT-S2780G switches 172.20.230.40 and .44, whose lldpRemTable has a
// 2-part index (lldpRemIndex.lldpRemLocalPortNum), whose lldpLocChassisId
// is a Cisco-dotted STRING that the saved data of 2026-10-20 holds as "No
// Such Instance" and whose FDB comes in hash order, and the FortiGate-600F
// gateway 172.20.0.1, which has an lldpRemTable without any
// lldpLocalSystemData.

const (
	pixieA    = "172.20.230.40"
	pixieB    = "172.20.230.44"
	pixieAMAC = "58:94:80:00:f7:a3" // lldpLocChassisId "5894.8000.f7a3"
	pixieBMAC = "58:94:80:01:01:27" // lldpLocChassisId "5894.8001.0127"
	snrMAC    = "f8:f0:82:d1:67:5e" // 172.20.230.254 SNR-S2995G-24FX, .44's upstream
	hpe238MAC = "4c:ae:a3:8e:05:89" // HPE 5130 172.20.230.238, the FortiGate's mgmt port
	sw203MAC  = "4c:ae:a3:a2:09:8c" // 172.20.254.203, the FortiGate's x7
	aruba253  = "88:22:5b:88:e2:40" // Aruba 6300 172.20.230.253, the FortiGate's x8
)

// pixieAgents answers like the two PiXiETECH switches, with net-snmp's OID
// order check on (their FDB is in hash order).
func pixieAgents(t *testing.T) {
	t.Helper()
	for ip, file := range map[string]string{pixieA: "pixietech_40.walks", pixieB: "pixietech_44.walks"} {
		fakeSNMP.set(ip, agentWalks(t, file))
		fakeSNMP.checkOrder(ip)
	}
}

// fortiGateLLDPAgent answers like the FortiGate 172.20.0.1: the gateway
// agent of the gateway tests (ARP, ipAddrTable) with the live LLDP-MIB and
// interface names.
func fortiGateLLDPAgent(t *testing.T) map[string][]string {
	t.Helper()
	walks := fortiGateGateway()
	maps.Copy(walks, agentWalks(t, "fortigate_0_1.walks"))
	return walks
}

// pixieRecord is what one PiXiETECH poll delivered, for the golden file.
type pixieRecord struct {
	collectResult
	FailedWalks []string    `json:"failed_walks,omitempty"`
	BridgePorts map[int]int `json:"bridge_port_ifindex,omitempty"`
	PolledMIBs  string      `json:"polled_mibs"`
	FDBPorts    map[int]int `json:"fdb_rows_by_port,omitempty"`
}

// collectPixie runs CollectData on the fake agent at ip and returns what it
// delivered, in a canonical order.
func collectPixie(ip string) pixieRecord {
	var rec pixieRecord
	obj := NewSNMPObject(func(d *DeviceData) {
		rec.Callback = "success"
		rec.ChassisID = d.ChassisID
		rec.SysName = d.SysName
		rec.Neighbors = slices.Clone(d.Neighbors)
		rec.MACTableNil = d.MACTable == nil
		rec.ARPTable = d.ARPTable
		rec.PortVLANs = slices.Clone(d.PortVLANs)
		rec.STPInfo = d.STPInfo
		rec.FailedWalks = slices.Sorted(slices.Values(d.failedWalks))
		rec.BridgePorts = d.BridgePortIfIndex
		rec.PolledMIBs = d.polledMIBs.String()
		for _, e := range d.MACTable {
			if rec.FDBPorts == nil {
				rec.FDBPorts = map[int]int{}
			}
			rec.FDBPorts[e.PortNumber]++
		}
		rec.MACTable = slices.Clone(d.MACTable)
	}, func(_ string, err error) {
		rec.Callback = "failure: " + err.Error()
	})
	obj.CollectData(ip, "")
	slices.SortFunc(rec.Neighbors, func(a, b LLDPNeighbor) int {
		return cmp.Or(cmp.Compare(a.LocalPortNum, b.LocalPortNum), cmp.Compare(a.RemIndex, b.RemIndex))
	})
	slices.SortFunc(rec.MACTable, func(a, b MACEntry) int { return strings.Compare(a.MACAddress, b.MACAddress) })
	slices.SortFunc(rec.PortVLANs, func(a, b PortVLAN) int { return cmp.Compare(a.PortIndex, b.PortIndex) })
	return rec
}

// TestPixieFDBNeedsUnorderedWalk shows why the FDB of both switches stayed
// empty: walked as before (snmpbulkwalk checks OID order), the agent's
// hash-ordered dot1dTpFdbPort ends in "OID not increasing" at the second
// request, the walk fails and the poll keeps the stored, empty table. The
// other walks of the poll keep OID order and pass the check. CollectData
// walks the FDB unordered (-Cc) with the poll timing.
func TestPixieFDBNeedsUnorderedWalk(t *testing.T) {
	resetState(t)
	pixieAgents(t)
	for ip, rows := range map[string]int{pixieA: 94, pixieB: 106} {
		_, err := snmpWalk("public", ip, collectFDBPortOID, pollTiming)
		if err == nil || !strings.Contains(err.Error(), "OID not increasing") {
			t.Errorf("%s: the ordered FDB walk gave %v, want net-snmp's OID order error", ip, err)
		}
		unordered := pollTiming
		unordered.Unordered = true
		lines, err := snmpWalk("public", ip, collectFDBPortOID, unordered)
		if err != nil || len(lines) != rows {
			t.Errorf("%s: the unordered FDB walk gave %d lines (%v), want %d", ip, len(lines), err, rows)
		}
		for oid := range agentWalks(t, map[string]string{pixieA: "pixietech_40.walks", pixieB: "pixietech_44.walks"}[ip]) {
			if oid == collectFDBPortOID {
				continue
			}
			if _, err := snmpWalk("public", ip, oid, pollTiming); err != nil {
				t.Errorf("%s: walk of %s: %v (only the FDB comes out of OID order)", ip, oid, err)
			}
		}
	}
	fakeSNMP.walkTimings()
	rec := collectPixie(pixieA)
	if len(rec.FailedWalks) != 0 || rec.FDBPorts[25] != 94 {
		t.Errorf("CollectData: failed walks %v, FDB rows by port %v; want none failed and 94 rows on port 25", rec.FailedWalks, rec.FDBPorts)
	}
	if n := fakeSNMP.walkTimings()[pixieA+" "+collectFDBPortOID+" 5s/1"]; n != 1 {
		t.Errorf("%d FDB walks with the poll timing 5s/1, want 1", n)
	}
	// Without -Cc a poll keeps the FDB of the poll before (F57): empty
	prev := &DeviceData{IP: pixieA}
	data := &DeviceData{IP: pixieA, failedWalks: []string{collectWalkFDB}}
	collectKeepPrevious(data, prev)
	if data.MACTable != nil {
		t.Errorf("a failed FDB walk kept %v", data.MACTable)
	}
}

// TestGoldenPixieCollect pins CollectData on the two PiXiETECH agents: the
// chassis id from the dotted STRING, the LLDP neighbors from the 2-part
// index on the local ports the agent names (lldpRemLocalPortNum: 25 and 1
// on .40; 28, 2, 3, 4, 6 and 27 on .44) with the management addresses of
// their lldpRemManAddrTable form, the whole FDB (94 and 106 rows), the
// bridge ports, VLANs and STP data.
func TestGoldenPixieCollect(t *testing.T) {
	resetState(t)
	pixieAgents(t)
	rec := map[string]pixieRecord{
		pixieA: collectPixie(pixieA),
		pixieB: collectPixie(pixieB),
	}
	checkGolden(t, "scenario_pixietech.json", goldenJSON(t, rec, 3))
}

// pixieGraphRecord is the part of a graph around the PiXiETECH switches:
// the nodes of the two switches and of their neighbors, and every link of
// the two.
func pixieGraphRecord(g *DJGraph) map[string]any {
	rec := graphRecord(g)
	ids := map[string]bool{pixieAMAC: true, pixieBMAC: true, pixieA: true, pixieB: true}
	var links []goldenLink
	for _, l := range rec.Links {
		if ids[l.Source] || ids[l.Target] {
			links = append(links, l)
		}
	}
	near := maps.Clone(ids)
	for _, l := range links {
		near[l.Source], near[l.Target] = true, true
	}
	var nodes []goldenNode
	for _, n := range rec.Nodes {
		if near[n.ID] {
			nodes = append(nodes, n)
		}
	}
	return map[string]any{"nodes": nodes, "links": links}
}

// pollPixies polls the two PiXiETECH agents as the periodic rescan does
// (the stored sysName, the rescan's callbacks).
func pollPixies(t *testing.T) {
	t.Helper()
	pixieAgents(t)
	obj := newRescanSNMPObject()
	for _, ip := range []string{pixieA, pixieB} {
		collectedDataMutex.RLock()
		sysName := ""
		if d := collectedData[ip]; d != nil {
			sysName = d.SysName
		}
		collectedDataMutex.RUnlock()
		obj.CollectData(ip, sysName)
	}
}

// TestGoldenPixieGraph polls the two PiXiETECH agents over the fixture (the
// saved data of 2026-10-20, where both have "No Such Instance" text as
// chassis id, no LLDP neighbor and no FDB row, and are isolated switch
// nodes with their IP as id) the way the periodic rescan does, and pins
// the graph around them and what the polls change in the whole graph and
// in the analysis: the IP nodes become the chassis MAC nodes 58:94:80:00:f7:a3
// and 58:94:80:01:01:27, linked to each other (.40 port 25 to .44 port 27),
// .44 to the SNR switch 172.20.230.254 (port 28) and both to their access
// points (their uplink ports hold every FDB MAC and have an LLDP neighbor,
// so the FDB adds no node). .40 port 1 shows two UAP-AC-Mesh-Pro
// "Sportzal"; the UniFi controller has one on .40 and the other on the
// first one's pass-through port, so they get no AP hub (lldpPortPlans).
func TestGoldenPixieGraph(t *testing.T) {
	base := buildFixtureGraph(t)
	baseReport, _ := analyzeFixture(t, base)
	before := pixieGraphRecord(base)
	inventoryMu.Lock()
	inventories = map[string]inventoryRecord{"unificontroller|10.9.60.5": {Module: "unificontroller", IP: "10.9.60.5", Time: time.Now(),
		Inventory: modules.Inventory{Devices: []modules.ManagedDevice{
			{MAC: "78:45:58:73:0f:69", Name: "Sportzal", Kind: "access_point", Uplink: &modules.ManagedUplink{MAC: pixieAMAC}},
			{MAC: "ac:8b:a9:70:a9:66", Name: "Sportzal", Kind: "access_point", Uplink: &modules.ManagedUplink{MAC: "ac:8b:a9:70:a3:6b", LocalPort: "1"}},
		}}}}
	inventoryIndex()
	inventoryMu.Unlock()
	t.Cleanup(func() {
		inventoryMu.Lock()
		inventories, managedByMAC, managedByIP = map[string]inventoryRecord{}, map[string]ManagedView{}, map[string]ManagedView{}
		inventoryMu.Unlock()
	})
	pollPixies(t)
	graph := buildGraphFromSnapshot(snapshotCollectedData())
	report, _ := analyzeFixture(t, graph)

	for _, c := range []struct{ a, b, label string }{
		{pixieAMAC, pixieBMAC, "GigaEth0/25 [T] 1G|GigaEth0/27"}, // .40 port 25 - .44 Gig0/27
		{pixieBMAC, snrMAC, "GigaEth0/28 [T] 1G|Eth1/0/24"},      // .44 port 28 - SNR Ethernet1/0/24 (its port description is "": the port id names it)
		{pixieAMAC, "ac:8b:a9:70:a9:66", "GigaEth0/1 [V1500] 1G|eth0"},
		{pixieBMAC, "f4:e2:c6:f7:23:81", "GigaEth0/2 [V1500] 1G|eth0"},
	} {
		if got := graph.GetEdgeLabel(c.a, c.b); got != c.label {
			t.Errorf("link %s - %s = %q, want %q", c.a, c.b, got, c.label)
		}
	}
	if graph.GetEdge(pixieAMAC, aruba253) {
		t.Errorf("MAC-REF link from .40 port 25 (LLDP neighbor .44) to the Aruba %s", aruba253)
	}
	if graph.Nodes[pixieA] || graph.Nodes[pixieB] {
		t.Error("a PiXiETECH switch is still drawn with its IP as id")
	}

	baseNodes, nodes := slices.Collect(maps.Keys(base.Nodes)), slices.Collect(maps.Keys(graph.Nodes))
	baseEdges, edges := graphEdgeLines(base), graphEdgeLines(graph)
	baseSuggestions, _ := suggestionRecords(baseReport)
	suggestions, _ := suggestionRecords(report)
	key := func(s goldenSuggestion) string { return s.Type + " " + s.Device + " " + s.IssueID + " " + s.Value }
	keys := func(list []goldenSuggestion) []string {
		var out []string
		for _, s := range list {
			out = append(out, key(s))
		}
		return out
	}
	rec := map[string]any{
		"before_polls": before,
		"after_polls":  pixieGraphRecord(graph),
		"graph_changes": map[string]any{
			"nodes_before":  len(baseNodes),
			"nodes_after":   len(nodes),
			"nodes_removed": sortedMinus(baseNodes, nodes),
			"nodes_added":   sortedMinus(nodes, baseNodes),
			"edges_removed": sortedMinus(baseEdges, edges),
			"edges_added":   sortedMinus(edges, baseEdges),
		},
		"analysis_changes": map[string]any{
			"health_before":       baseReport.HealthScore,
			"health_after":        report.HealthScore,
			"suggestions_removed": sortedMinus(keys(baseSuggestions), keys(suggestions)),
			"suggestions_added":   sortedMinus(keys(suggestions), keys(baseSuggestions)),
		},
	}
	checkGolden(t, "pixietech_graph.json", goldenJSON(t, rec, 3))
}

// TestPixieChassisRead checks the lldpLocChassisId read on the PiXiETECH
// agent. The saved data of 2026-10-20 holds "No Such Instance" as the
// chassis id of both switches, so their agent answers the instance with
// it now and then; the switch stored that way gets its MAC node id from
// the first poll that reads the dotted STRING. A walk answered "No Such
// Instance" (or with nothing) is read once more as the column; when that
// has no chassis id either, the stored one stays (H9), so the node id
// never flips to the IP. "No Such Object" (no LLDP-MIB: the FortiGate)
// costs no second walk.
func TestPixieChassisRead(t *testing.T) {
	resetState(t)
	walks := agentWalks(t, "pixietech_40.walks")
	const noInstance = " = No Such Instance currently exists at this OID"
	collectedDataMutex.Lock()
	collectedData[pixieA] = &DeviceData{IP: pixieA, ChassisID: "no:such:instance:currently:exists:at:this:oid",
		Interfaces: []InterfaceData{{IfIndex: 25, IfDescr: "\"GigaEthernet0/25\""}}}
	collectedDataMutex.Unlock()
	nodeID := func() string {
		collectedDataMutex.RLock()
		defer collectedDataMutex.RUnlock()
		return graphDeviceNodeID(collectedData[pixieA])
	}
	if got := nodeID(); got != pixieA {
		t.Fatalf("saved data: node id %q, want the IP", got)
	}
	obj := newRescanSNMPObject()
	for _, step := range []struct {
		name           string
		scalar, column []string // nil: the walk times out
		columnWalks    int
	}{
		{"the agent answers the instance", walks[oidLLDPLocChassisID], walks[oidLLDPLocChassisIDColumn], 0},
		{"the instance is missing, the column has it", []string{oidLLDPLocChassisID + noInstance}, walks[oidLLDPLocChassisIDColumn], 1},
		{"no output, the column has it", []string{}, walks[oidLLDPLocChassisIDColumn], 1},
		{"both are missing", []string{oidLLDPLocChassisID + noInstance},
			[]string{oidLLDPLocChassisIDColumn + " = No Such Object available on this agent at this OID"}, 1},
		{"the column walk times out", []string{oidLLDPLocChassisID + noInstance}, nil, 1},
	} {
		agent := maps.Clone(walks)
		delete(agent, oidLLDPLocChassisIDColumn)
		agent[oidLLDPLocChassisID] = step.scalar
		if step.column != nil {
			agent[oidLLDPLocChassisIDColumn] = step.column
		}
		fakeSNMP.set(pixieA, agent)
		fakeSNMP.walkCounts()
		obj.CollectData(pixieA, "")
		counts := fakeSNMP.walkCounts()
		if got := nodeID(); got != pixieAMAC {
			t.Errorf("%s: node id %q, want %s", step.name, got, pixieAMAC)
		}
		if n := counts[pixieA+" "+oidLLDPLocChassisIDColumn]; n != step.columnWalks {
			t.Errorf("%s: %d column walks, want %d", step.name, n, step.columnWalks)
		}
		id, err := obj.collectLocalChassisID(pixieA)
		if wantID := step.column != nil && len(step.column) == 1 && strings.Contains(step.column[0], "5894"); (id == pixieAMAC) != wantID ||
			(!wantID && !errors.Is(err, errNoLocalChassis)) {
			t.Errorf("%s: collectLocalChassisID = %q, %v", step.name, id, err)
		}
	}

	// The FortiGate has no LLDP-MIB: one walk, "No Such Object", an
	// answering agent that is no switch
	fakeSNMP.set(fortiGW, fortiGateLLDPAgent(t))
	fakeSNMP.walkCounts()
	check := (&SNMPObject{Community: "public", Port: 161}).checkSwitch(fortiGW)
	if counts := fakeSNMP.walkCounts(); counts[fortiGW+" "+oidLLDPLocChassisIDColumn] != 0 || counts[fortiGW+" "+oidLLDPLocChassisID] != 1 {
		t.Errorf("FortiGate chassis walks %v, want the instance once and no column walk", counts)
	}
	if !check.Answered || check.isSwitch() || check.SysName != "FortiGate-600F" {
		t.Errorf("FortiGate check = %+v, want an answering agent that is no switch", check)
	}
}

// TestMACRefLLDPSwitchPort checks the MAC cross-reference rule on a port
// whose LLDP neighbor is a polled switch: the switch MAC learned there is
// behind that switch, so the port gets no MAC-REF link, as 172.20.230.40
// port 25 (neighbor .44) learns the Aruba 6300's chassis MAC. A port with
// one switch MAC and no LLDP neighbor, or with an LLDP neighbor that is no
// polled switch (an access point), keeps its MAC-REF link.
func TestMACRefLLDPSwitchPort(t *testing.T) {
	resetState(t)
	const swA, swB, swC = "10.9.60.1", "10.9.60.2", "10.9.60.3"
	const macA, macB, macC = "4c:ae:a3:60:00:01", "4c:ae:a3:60:00:02", "4c:ae:a3:60:00:03"
	devices := map[string]*DeviceData{
		swA: {IP: swA, ChassisID: macA, Interfaces: gigabitPorts(8, nil),
			Neighbors: []LLDPNeighbor{
				{LocalPortNum: 1, RemIndex: 1, RemChassisIdSubtype: 4, RemChassisId: "4C AE A3 60 00 02", RemPortIdSubtype: 5, RemPortId: "\"GigabitEthernet1/0/8\""},
				{LocalPortNum: 3, RemIndex: 2, RemChassisIdSubtype: 4, RemChassisId: "F4 E2 C6 60 00 03", RemPortIdSubtype: 3, RemPortId: "F4 E2 C6 60 00 03", RemSysName: "ap-3"},
			},
			MACTable: slices.Concat(macEntries(1, macC, "00:1b:21:60:01:01"), macEntries(2, macC), macEntries(3, macC)),
		},
		swB: {IP: swB, ChassisID: macB, Interfaces: gigabitPorts(8, nil)},
		swC: {IP: swC, ChassisID: macC, Interfaces: gigabitPorts(8, nil)},
	}
	g := NewDJGraph()
	for _, ip := range sortedDeviceIPs(devices) {
		graphAddSwitchNode(g, devices[ip])
	}
	addMACCrossRefEdges(g, devices, buildSwitchOwnMACs(devices))
	if got := graphEdgeLines(g); !slices.Equal(got, []string{
		macA + " -> " + macC + ` : "GE1/0/2 [MAC-REF]|"`,
	}) {
		t.Errorf("MAC-REF links %q, want only port 2's (port 1 has the polled switch %s as LLDP neighbor; port 3's AP is no switch, but port 2 came first)", got, macB)
	}
	devices[swA].MACTable = slices.Concat(macEntries(1, macC), macEntries(3, macC))
	g2 := NewDJGraph()
	for _, ip := range sortedDeviceIPs(devices) {
		graphAddSwitchNode(g2, devices[ip])
	}
	addMACCrossRefEdges(g2, devices, buildSwitchOwnMACs(devices))
	if got := graphEdgeLines(g2); !slices.Equal(got, []string{macA + " -> " + macC + ` : "GE1/0/3 [MAC-REF]|"`}) {
		t.Errorf("MAC-REF links %q, want the AP port's (an LLDP neighbor that is no polled switch)", got)
	}
}

// TestLLDPRemIndexLayouts unit-tests the lldpRemTable index decoder: the
// LLDP-MIB's three parts as before, the PiXiETECH two parts (remote index
// first), and nothing else.
func TestLLDPRemIndexLayouts(t *testing.T) {
	for _, c := range []struct {
		oid            string
		col, port, rem int
		key            string
		twoPart, ok    bool
	}{
		{oidLLDPRem + ".9.84555519.33.2", 9, 33, 2, "33.2", false, true}, // the FortiGate
		{oidLLDPRem + ".5.0.48.1", 5, 48, 1, "48.1", false, true},
		{"1.0.8802.1.1.2.1.4.1.1.7.3900.28.1", 7, 28, 1, "28.1", false, true}, // no leading dot
		{oidLLDPRem + ".9.1.25", 9, 25, 1, "25.1", true, true},                // PiXiETECH: remote index 1 on port 25
		{oidLLDPRem + ".2.6.27", 2, 27, 6, "27.6", true, true},
		{oidLLDPRem + ".5.9", 0, 0, 0, "", false, false},       // one part
		{oidLLDPRem + ".5.1.2.3.4", 0, 0, 0, "", false, false}, // four parts (was read from the last three)
		{oidLLDPRem + ".5.x.2.3", 0, 0, 0, "", false, false},   // not a number
		{oidLLDPRem, 0, 0, 0, "", false, false},                // the table itself ("No Such Object")
		{oidLLDPMan + ".3.0.48.1", 0, 0, 0, "", false, false},  // another table
		{".1.0.8802.1.1.2.1.4.1.10.5.0.48.1", 0, 0, 0, "", false, false},
	} {
		col, key, port, rem, twoPart, ok := collectLLDPRemIndex(c.oid)
		if col != c.col || key != c.key || port != c.port || rem != c.rem || twoPart != c.twoPart || ok != c.ok {
			t.Errorf("collectLLDPRemIndex(%q) = %d %q %d %d %v %v, want %d %q %d %d %v %v",
				c.oid, col, key, port, rem, twoPart, ok, c.col, c.key, c.port, c.rem, c.twoPart, c.ok)
		}
	}
	for _, c := range []struct {
		oid, typ, val, key, ip string
		ok                     bool
	}{
		{oidLLDPMan + ".2.1.25", "STRING", `"172.20.230.44"`, "25.1", "172.20.230.44", true},
		{oidLLDPMan + ".2.6.27", "STRING", `"172.20.230.40"`, "27.6", "172.20.230.40", true},
		{oidLLDPMan + ".2.2.1", "STRING", `"FE80::AE8B:A9FF:FE70:A966"`, "", "", false}, // the access points: IPv6
		{oidLLDPMan + ".2.1.28", "", `""`, "", "", false},                               // .44's upstream SNR: none
		{oidLLDPMan + ".2.3.4", "Hex-STRING", "AC 14 E6 2C ", "4.3", "172.20.230.44", true},
		{oidLLDPMan + ".2.3.4", "IpAddress", "10.0.0.1", "4.3", "10.0.0.1", true},
		{oidLLDPMan + ".2.3.4", "STRING", `"0.0.0.0"`, "", "", false},
		{oidLLDPMan + ".1.1.25", "INTEGER", "1", "", "", false}, // the address subtype column
		{oidLLDPMan + ".4.1.25", "INTEGER", "1", "", "", false},
		{oidLLDPMan + ".3.0.48.1.1.4.172.20.1.5", "INTEGER", "2", "", "", false}, // the standard form: collectLLDPManAddr's
		{oidLLDPRem + ".2.1.25", "STRING", `"172.20.230.44"`, "", "", false},
	} {
		key, ip, ok := collectLLDPManAddrValue(c.oid, c.typ, c.val)
		if key != c.key || ip != c.ip || ok != c.ok {
			t.Errorf("collectLLDPManAddrValue(%q, %q, %q) = %q %q %v, want %q %q %v", c.oid, c.typ, c.val, key, ip, ok, c.key, c.ip, c.ok)
		}
	}
}

// TestLLDPIndexColumns checks where the local port of a neighbor comes
// from. A standard agent's index is the answer, whatever its index columns
// say (an agent that reports them, as the FortiGate does, must not move a
// neighbor to another port: never misread a standard agent). A 2-part
// agent's own lldpRemLocalPortNum and lldpRemIndex are taken when it
// reports them; without them its index is read in the PiXiETECH order
// (remote index, then local port).
func TestLLDPIndexColumns(t *testing.T) {
	resetState(t)
	rem := oidLLDPRem
	fakeSNMP.set("10.9.61.1", map[string][]string{oidLLDPRem: {
		rem + ".2.100.7.1 = INTEGER: 9", // contradicts the index: ignored
		rem + ".3.100.7.1 = INTEGER: 5",
		rem + ".5.100.7.1 = Hex-STRING: 4C AE A3 61 00 01 ",
		rem + ".9.100.7.1 = STRING: \"std\"",
	}})
	fakeSNMP.set("10.9.61.2", map[string][]string{oidLLDPRem: {
		rem + ".2.4.12 = INTEGER: 13", // the agent's own local port wins over the index order
		rem + ".3.4.12 = INTEGER: 4",
		rem + ".5.4.12 = STRING: \"4CAE.A361.0002\"",
		rem + ".5.2.30 = STRING: \"4CAE.A361.0003\"", // no index columns: remote index 2 on port 30
		rem + ".9.2.30 = STRING: \"no-columns\"",
		rem + ".2.2.31 = INTEGER: 0", // an index column of 0 is no port
		rem + ".5.2.31 = STRING: \"4CAE.A361.0004\"",
	}})
	obj := &SNMPObject{Community: "public"}
	got := map[string][]string{}
	for _, ip := range []string{"10.9.61.1", "10.9.61.2"} {
		neighbors, err := obj.collectLLDPNeighbors(ip)
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range neighbors {
			got[ip] = append(got[ip], fmt.Sprintf("%d.%d %s %s", n.LocalPortNum, n.RemIndex, n.RemChassisId, n.RemSysName))
		}
		slices.Sort(got[ip])
	}
	want := map[string][]string{
		"10.9.61.1": {"7.1 4C AE A3 61 00 01 std"},
		"10.9.61.2": {"13.4 \"4CAE.A361.0002\" ", "30.2 \"4CAE.A361.0003\" no-columns", "31.2 \"4CAE.A361.0004\" "},
	}
	if !maps.EqualFunc(got, want, slices.Equal) {
		t.Errorf("neighbors %q, want %q", got, want)
	}
}

// TestSNMPWalkOutput unit-tests the walk reader: an ordered walk keeps
// every line (net-snmp checks its order itself); an unordered walk whose
// agent repeats an OID calls stop and fails, after the output is drained;
// continuation lines of multi-line values are no OIDs.
func TestSNMPWalkOutput(t *testing.T) {
	const out = ".1.3.6.1.2.1.17.4.3.1.2.1 = INTEGER: 25\n" +
		".1.3.6.1.2.1.1.1.0 = STRING: \"two\n" +
		"lines\"\n" +
		".1.3.6.1.2.1.17.4.3.1.2.1 = INTEGER: 25\n" +
		".1.3.6.1.2.1.17.4.3.1.2.2 = INTEGER: 26\n"
	stops := 0
	stop := func() { stops++ }
	r := strings.NewReader(out)
	lines, err := snmpWalkOutput(r, false, stop)
	if err != nil || len(lines) != 5 || stops != 0 {
		t.Errorf("ordered: %d lines, %v, %d stops; want 5 lines", len(lines), err, stops)
	}
	r = strings.NewReader(out)
	lines, err = snmpWalkOutput(r, true, stop)
	if !errors.Is(err, errWalkRepeats) || lines != nil || stops != 1 || r.Len() != 0 {
		t.Errorf("unordered with a repeated OID: %d lines, %v, %d stops, %d bytes unread; want errWalkRepeats, one stop, drained", len(lines), err, stops, r.Len())
	}
	lines, err = snmpWalkOutput(strings.NewReader("lines\"\nlines\"\n"), true, stop)
	if err != nil || len(lines) != 2 {
		t.Errorf("unordered continuation lines: %q, %v", lines, err)
	}
}

// fakeBulkWalkScript is a stand-in for snmpbulkwalk that answers by the
// agent IP (the next to last argument): 192.0.2.1 prints two rows and exits
// 0, 192.0.2.2 prints rows out of order and exits 1 like net-snmp's "OID
// not increasing", 192.0.2.3 repeats a row and then hangs, 192.0.2.4
// prints two rows (the first over two lines, as the port lists of the
// egress table come) and times out, 192.0.2.5 times out with no row,
// 192.0.2.6 prints the rows of .4 and then hangs, 192.0.2.7 hangs with no
// row. It logs its arguments to args in its directory.
const fakeBulkWalkScript = `
dir=$(dirname "$0")
echo "$*" >> "$dir/args"
for oid; do :; done
eval ip=\${$(($# - 1))}
rows() { printf '%s\n' "$oid.0.1 = Hex-STRING: 00 00 38 00 00 00 F0 00 " "00 00 00 00 01 FF FE " "$oid.0.21 = Hex-STRING: 00 00 00 10 "; }
case "$ip" in
192.0.2.1) printf '%s\n' "$oid.1 = INTEGER: 1" "$oid.2 = STRING: \"a\"" ;;
192.0.2.2) printf '%s\n' "$oid.2 = INTEGER: 2" "$oid.1 = INTEGER: 1"; echo "Error: OID not increasing" >&2; exit 1 ;;
192.0.2.3) printf '%s\n' "$oid.1 = INTEGER: 1" "$oid.2 = INTEGER: 2" "$oid.1 = INTEGER: 1"; exec sleep 30 ;;
192.0.2.4) rows; echo "Timeout: No Response from $ip" >&2; exit 1 ;;
192.0.2.5) echo "Timeout: No Response from $ip" >&2; exit 1 ;;
192.0.2.6) rows; exec sleep 30 ;;
192.0.2.7) exec sleep 30 ;;
esac
`

// TestSNMPBulkWalkExec runs snmpBulkWalk, the production walk, against
// fakeBulkWalkScript on PATH (no SNMP request is sent): its arguments (-Cc
// for an unordered walk only), the lines of a walk that exits 0, no lines
// for one that exits 1, and an unordered walk whose agent repeats an OID is
// killed at once, not after the 30 s limit. A walk that fails after rows,
// at a timeout or killed at the walk limit (snmpBulkWalkWithin, with a
// short limit), gives a walkCutError with its rows (walkAnswered) and the
// message as before; one with no row gives a plain error.
func TestSNMPBulkWalkExec(t *testing.T) {
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "snmpbulkwalk"), []byte("#!"+sh+"\n"+fakeBulkWalkScript), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	const oid = ".1.3.6.1.2.1.17.4.3.1.2"
	unordered := pollTiming
	unordered.Unordered = true

	lines, err := snmpBulkWalk("public", "192.0.2.1", oid, pollTiming)
	if err != nil || !slices.Equal(lines, []string{oid + ".1 = INTEGER: 1", oid + `.2 = STRING: "a"`}) {
		t.Errorf("walk that exits 0: %q, %v", lines, err)
	}
	if lines, err := snmpBulkWalk("public", "192.0.2.1", oid, unordered); err != nil || len(lines) != 2 {
		t.Errorf("unordered walk that exits 0: %q, %v", lines, err)
	}
	if lines, err := snmpBulkWalk("public", "192.0.2.2", oid, pollTiming); err == nil || lines != nil || !walkAnswered(err) {
		t.Errorf("walk that exits 1 (OID not increasing): %q, %v; want no lines and an error after rows", lines, err)
	}
	start := time.Now()
	lines, err = snmpBulkWalk("public", "192.0.2.3", oid, unordered)
	if !errors.Is(err, errWalkRepeats) || lines != nil {
		t.Errorf("unordered walk that repeats an OID: %q, %v; want errWalkRepeats", lines, err)
	}
	if took := time.Since(start); took > 10*time.Second {
		t.Errorf("the repeating walk took %v: it was not killed", took)
	}

	// The walk limit, short here: a walk is killed after it whether its
	// rows still come (.6, the egress walk of 172.20.254.226) or none came
	// (.7); the error counts the rows read before the kill or the timeout.
	const limit = time.Second
	for _, c := range []struct {
		ip, exit string
		rows     int
	}{
		{"192.0.2.4", "exit status 1", 2},
		{"192.0.2.5", "exit status 1", 0},
		{"192.0.2.6", "signal: killed", 2},
		{"192.0.2.7", "signal: killed", 0},
	} {
		start := time.Now()
		lines, err := snmpBulkWalkWithin("public", c.ip, oid, pollTiming, limit)
		took := time.Since(start)
		var cut *walkCutError
		rows := 0
		if errors.As(err, &cut) {
			rows = cut.rows
		}
		if wantMsg := "snmpwalk timeout/error for " + c.ip + " OID " + oid + ": " + c.exit; err == nil || err.Error() != wantMsg || lines != nil {
			t.Errorf("%s: %q, %v; want no lines and %q", c.ip, lines, err, wantMsg)
		}
		if rows != c.rows || walkAnswered(err) != (c.rows > 0) {
			t.Errorf("%s: %d rows before the error (walkAnswered %v), want %d", c.ip, rows, walkAnswered(err), c.rows)
		}
		if took > limit+5*time.Second {
			t.Errorf("%s took %v: it was not killed at the walk limit %v", c.ip, took, limit)
		}
	}

	args, err := os.ReadFile(filepath.Join(dir, "args"))
	if err != nil {
		t.Fatal(err)
	}
	want := "-v2c -c public -On -Cr25 -t 5 -r 1 192.0.2.1 " + oid + "\n" +
		"-v2c -c public -On -Cr25 -Cc -t 5 -r 1 192.0.2.1 " + oid + "\n" +
		"-v2c -c public -On -Cr25 -t 5 -r 1 192.0.2.2 " + oid + "\n" +
		"-v2c -c public -On -Cr25 -Cc -t 5 -r 1 192.0.2.3 " + oid + "\n" +
		"-v2c -c public -On -Cr25 -t 5 -r 1 192.0.2.4 " + oid + "\n" +
		"-v2c -c public -On -Cr25 -t 5 -r 1 192.0.2.5 " + oid + "\n" +
		"-v2c -c public -On -Cr25 -t 5 -r 1 192.0.2.6 " + oid + "\n" +
		"-v2c -c public -On -Cr25 -t 5 -r 1 192.0.2.7 " + oid + "\n"
	if string(args) != want {
		t.Errorf("snmpbulkwalk arguments:\n%s\nwant\n%s", args, want)
	}
}
