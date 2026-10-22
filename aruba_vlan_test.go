package main

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"
)

// The Aruba 6300 172.20.230.253: its FDB and IF-MIB were missing from the
// polls because its agent stalls on dot1qVlanCurrentEgressPorts (10.8 s,
// collectVLANLastIPs) while the FDB walk is in flight. The fake agent
// answers what the live agent answered (testdata/agents/aruba_253.walks)
// and stalls the same way (fakeAgents.stall): every walk is in flight for
// 2 ms per request (10 rows per response), and the egress walk keeps the
// agent busy and fails.

const arubaIP = "172.20.230.253"

// arubaAgent installs the fake Aruba agent.
func arubaAgent(t *testing.T) {
	t.Helper()
	fakeSNMP.set(arubaIP, agentWalks(t, "aruba_253.walks"))
	fakeSNMP.stall(arubaIP, collectVLANEgressOID, 2*time.Millisecond, 30*time.Millisecond)
}

// arubaPoll is what one poll of the fake Aruba delivered.
type arubaPoll struct {
	VLANLastBefore bool        `json:"vlan_walk_last_before"`
	VLANLastAfter  bool        `json:"vlan_walk_last_after"`
	FDBFailed      bool        `json:"fdb_walk_failed"`
	FDBRows        map[int]int `json:"fdb_rows_by_port,omitempty"`
	Interfaces     int         `json:"interfaces,omitempty"`
	Neighbors      int         `json:"lldp_neighbors,omitempty"`
	PortVLANs      int         `json:"port_vlans,omitempty"`
	STPRootPort    int         `json:"stp_root_port,omitempty"`
	SysName        string      `json:"sys_name,omitempty"`
	FailedWalks    []string    `json:"failed_walks,omitempty"`
	Victims        []string    `json:"walks_the_stall_failed,omitempty"`
}

// pollAruba polls the fake Aruba once with obj, as the periodic rescan does
// (the stored sysName), and returns what the poll delivered: the data of
// deliver, filled in by obj's callback.
func pollAruba(obj *SNMPObject, deliver func() *DeviceData) arubaPoll {
	collectedDataMutex.RLock()
	sysName := ""
	if d := collectedData[arubaIP]; d != nil {
		sysName = d.SysName
	}
	collectedDataMutex.RUnlock()
	rec := arubaPoll{VLANLastBefore: collectVLANLast(arubaIP)}
	obj.CollectData(arubaIP, sysName)
	rec.VLANLastAfter = collectVLANLast(arubaIP)
	rec.Victims = fakeSNMP.stallVictims(arubaIP)
	d := deliver()
	if d == nil {
		return rec
	}
	rec.FDBFailed = d.collectWalkFailed(collectWalkFDB)
	for _, e := range d.MACTable {
		if rec.FDBRows == nil {
			rec.FDBRows = map[int]int{}
		}
		rec.FDBRows[e.PortNumber]++
	}
	rec.Interfaces, rec.Neighbors, rec.PortVLANs = len(d.Interfaces), len(d.Neighbors), len(d.PortVLANs)
	rec.STPRootPort, rec.SysName = d.STPInfo.RootPort, d.SysName
	rec.FailedWalks = slices.Sorted(slices.Values(d.failedWalks))
	return rec
}

// TestArubaVLANLast polls the fake Aruba three times. The first poll walks
// as before: the egress walk starts while the FDB walk (163 requests) is in
// flight, the stall fails the FDB walk, and the egress walk, failed with no
// row, marks the agent. The next polls walk the VLAN table after the other
// walks: the FDB (1,619 rows: 1,588 on the uplink 1/1/28, 30 on 1/1/1
// toward 172.20.230.76, 1 on 1/1/27, the FortiGate), the 30 interfaces and
// the sysName "6300" (the poll had no name) come in and nothing but the
// egress walk fails; the mark stays while it fails. An agent whose egress
// walk answers is never marked (the PiXiETECH 172.20.230.40), and a mark
// goes with the first egress walk that answers.
func TestArubaVLANLast(t *testing.T) {
	resetState(t)
	arubaAgent(t)
	var got *DeviceData
	obj := NewSNMPObject(func(d *DeviceData) { got = d }, func(_ string, err error) { t.Errorf("Aruba poll failed: %v", err) })
	deliver := func() *DeviceData { d := got; got = nil; return d }

	first := pollAruba(obj, deliver)
	if first.VLANLastBefore || !first.VLANLastAfter || !first.FDBFailed || first.FDBRows != nil || !slices.Contains(first.Victims, collectFDBPortOID) {
		t.Errorf("first poll (the walks as before): %+v; want the FDB walk failed by the stall and the agent marked", first)
	}
	wantRows := map[int]int{1: 30, 27: 1, 28: 1588}
	for i := 2; i <= 3; i++ {
		p := pollAruba(obj, deliver)
		if !p.VLANLastBefore || !p.VLANLastAfter || p.FDBFailed || !maps.Equal(p.FDBRows, wantRows) || p.Interfaces != 30 ||
			p.Neighbors != 3 || p.PortVLANs != 26 || p.STPRootPort != 28 || p.SysName != "6300" || len(p.FailedWalks) != 0 || len(p.Victims) != 0 {
			t.Errorf("poll %d (VLAN walk last): %+v; want the FDB %v, 30 interfaces, 3 neighbors, 26 port VLANs, sysName 6300 and no failed walk", i, p, wantRows)
		}
	}

	pixieAgents(t)
	NewSNMPObject(func(*DeviceData) {}, nil).CollectData(pixieA, "")
	if collectVLANLast(pixieA) {
		t.Errorf("%s is marked, but its egress walk answers", pixieA)
	}
	collectNoteEgressWalk(pixieA, errors.New("one lost answer"))
	NewSNMPObject(func(*DeviceData) {}, nil).CollectData(pixieA, "")
	if collectVLANLast(pixieA) {
		t.Errorf("%s stays marked after an egress walk that answered", pixieA)
	}
}

const jamicIP = "172.20.254.226"

// jamicEgressRow is a row of the egress table of 172.20.254.226 as
// snmpbulkwalk -On printed it (2026-10-22 22:33): the 127-byte port list
// of the Eltex agent, 16 bytes per line, so one row takes 8 lines.
func jamicEgressRow(vlan int, first string) []string {
	row := []string{fmt.Sprintf("%s.0.%d = Hex-STRING: %s", collectVLANEgressOID, vlan, first)}
	for i := 0; i < 6; i++ {
		row = append(row, strings.Repeat("00 ", 16))
	}
	return append(row, strings.Repeat("00 ", 15))
}

// TestVLANLastSlowAgent polls a fake 172.20.254.226 (Jamic) three times as
// the periodic rescan does. Its agent answers, slowly: its ifDescr, FDB and
// egress walks run into the walk limit while their rows still come
// (fakeAgents.killAfter; 30 s live, jamicLimit here), its dot1qPvid and
// the other walks answer. An egress walk that got rows is no stall of the
// Aruba's kind: the agent is never marked, its VLAN walks stay with the
// others, and every poll takes one walk limit. Marked, as any failed egress
// walk marked an agent before, its polls after the first took two walk
// limits (the VLAN walks ran after the killed walks): about 61 s instead of
// 33 s live, the last poll the rescan waits for before it rebuilds the
// graph.
func TestVLANLastSlowAgent(t *testing.T) {
	resetState(t)
	const jamicLimit = 300 * time.Millisecond
	agent := collectTestAgent()
	agent[collectVLANEgressOID] = slices.Concat(jamicEgressRow(1, "00 00 38 00 00 00 F0 00 00 00 00 00 00 00 00 00 "),
		jamicEgressRow(21, "00 00 00 00 00 00 10 00 00 00 00 00 00 00 00 00 "))
	fakeSNMP.set(jamicIP, agent)
	fakeSNMP.killAfter(jamicIP, jamicLimit, oidIfDescr, oidFDBPort, collectVLANEgressOID)
	obj := newRescanSNMPObject()
	for i := 1; i <= 3; i++ {
		fakeSNMP.walkCounts()
		start := time.Now()
		obj.CollectData(jamicIP, "Jamic")
		took := time.Since(start)
		walks := fakeSNMP.walkCounts()
		d := collectStored(jamicIP)
		if collectVLANLast(jamicIP) {
			t.Errorf("poll %d marked %s: its egress walk got rows before the walk limit killed it", i, jamicIP)
		}
		if took >= jamicLimit*3/2 {
			t.Errorf("poll %d took %v, want about one walk limit (%v): the VLAN walks ran after the killed walks", i, took, jamicLimit)
		}
		if walks[jamicIP+" "+collectVLANEgressOID] != 1 || d == nil || len(d.PortVLANs) != 2 ||
			!d.collectWalkFailed(collectWalkFDB) || !d.collectWalkFailed(collectWalkInterfaces) {
			t.Errorf("poll %d: %d egress walks, stored %+v; want one egress walk, the 2 PVIDs and the FDB and ifDescr walks failed", i, walks[jamicIP+" "+collectVLANEgressOID], d)
		}
	}
}

// TestCollectNoteEgressWalk pins what marks an agent for collectVLANLast:
// an egress walk that failed with no row (the Aruba's timeout after its two
// 5 s attempts, or a kill before any row came), not one that failed after
// rows (walkCutError, wrapped or not: the walk limit killed Jamic's while
// its rows came), which clears a mark as a walk that answers to its end
// does.
func TestCollectNoteEgressWalk(t *testing.T) {
	resetState(t)
	const ip = "10.9.93.2"
	timeout := errors.New("snmpwalk timeout/error for 172.20.230.253 OID .1.3.6.1.2.1.17.7.1.4.2.1.4: exit status 1")
	killed := &walkCutError{err: errors.New("snmpwalk timeout/error for 172.20.254.226 OID .1.3.6.1.2.1.17.7.1.4.2.1.4: signal: killed"), rows: 1826}
	for _, c := range []struct {
		name         string
		marked       bool
		err          error
		wantMarked   bool
		wantAnswered bool
	}{
		{"no answer", false, timeout, true, false},
		{"no answer again", true, timeout, true, false},
		{"killed before a row", false, &walkCutError{err: errors.New("signal: killed")}, true, false},
		{"killed while rows came", false, killed, false, true},
		{"killed while rows came, marked", true, killed, false, true},
		{"killed while rows came, wrapped", true, fmt.Errorf("vlan: %w", killed), false, true},
		{"answered", true, nil, false, false},
	} {
		collectNoteEgressWalk(ip, nil)
		if c.marked {
			collectNoteEgressWalk(ip, timeout)
		}
		collectNoteEgressWalk(ip, c.err)
		if got := collectVLANLast(ip); got != c.wantMarked {
			t.Errorf("%s: marked %v, want %v", c.name, got, c.wantMarked)
		}
		if got := walkAnswered(c.err); got != c.wantAnswered {
			t.Errorf("%s: walkAnswered %v, want %v", c.name, got, c.wantAnswered)
		}
	}
	if killed.Error() != killed.err.Error() || !errors.Is(fmt.Errorf("vlan: %w", killed), killed.err) {
		t.Errorf("walkCutError %q does not keep the walk's error %q", killed, killed.err)
	}
}

// TestCollectInterfaceSpeedOrder walks the Aruba's 10G ports (ifSpeed
// 4294967295, ifHighSpeed 10000) with ifSpeed finishing last and with
// ifHighSpeed finishing last (the other walk has 100 more rows, of ifIndex
// values the agent does not have, so it is in flight 10 requests longer):
// the speed is 10G either way, and the 1G-less ports stay at 0.
func TestCollectInterfaceSpeedOrder(t *testing.T) {
	walks := agentWalks(t, "aruba_253.walks")
	pad := func(oid, val string) []string {
		lines := slices.Clone(walks[oid])
		for i := 1000; i < 1100; i++ {
			lines = append(lines, fmt.Sprintf("%s.%d = %s", oid, i, val))
		}
		return lines
	}
	const ifSpeed, ifHighSpeed = ".1.3.6.1.2.1.2.2.1.5", ".1.3.6.1.2.1.31.1.1.1.15"
	for _, last := range []string{ifSpeed, ifHighSpeed} {
		resetState(t)
		agent := maps.Clone(walks)
		agent[last] = pad(last, "Gauge32: 0")
		fakeSNMP.set(arubaIP, agent)
		fakeSNMP.stall(arubaIP, collectVLANEgressOID, 5*time.Millisecond, time.Millisecond)
		ifaces, err := NewSNMPObject(nil, nil).collectInterfaces(arubaIP)
		if err != nil {
			t.Fatalf("collectInterfaces: %v", err)
		}
		speeds := map[int]string{}
		for _, i := range ifaces {
			if i.IfIndex <= 28 && i.IfSpeed > 0 {
				speeds[i.IfIndex] = formatSpeed(i.IfSpeed)
			}
		}
		if want := map[int]string{1: "10G", 27: "10G", 28: "10G"}; !maps.Equal(speeds, want) {
			t.Errorf("%s last: speeds %v, want %v", last, speeds, want)
		}
	}
}

// TestGoldenArubaPolls polls the fake Aruba three times over the fixture
// (the saved data of 2026-10-20, where the Aruba has no interface, no FDB
// row, no name and one LLDP neighbor) as the periodic rescan does, and pins
// what each poll stored and the graph around the Aruba before and after:
// its node gets the name 6300, its uplink to 172.20.254.202 TGE1/0/51 its
// own port 1/1/28 (the saved data, without interfaces, has "Port28"), and
// its LLDP rows add the links to 172.20.230.76 (1/1/1, TGE1/0/52) and to
// the FortiGate (1/1/27, x8). Its FDB adds no node: every port where it
// learns MACs has an LLDP neighbor. The first poll fails the FDB walk as
// the live polls did; the polls after it store the FDB.
func TestGoldenArubaPolls(t *testing.T) {
	base := buildFixtureGraph(t)
	arubaAgent(t)
	obj := newRescanSNMPObject()
	stored := func() *DeviceData {
		collectedDataMutex.RLock()
		defer collectedDataMutex.RUnlock()
		return collectedData[arubaIP]
	}
	var polls []arubaPoll
	for i := 0; i < 3; i++ {
		p := pollAruba(obj, stored)
		if i == 0 {
			// which walks besides the FDB the stall hits depends on timing
			p = arubaPoll{VLANLastBefore: p.VLANLastBefore, VLANLastAfter: p.VLANLastAfter, FDBFailed: p.FDBFailed, FDBRows: p.FDBRows}
		}
		polls = append(polls, p)
	}
	graph := buildGraphFromSnapshot(snapshotCollectedData())

	around := func(g *DJGraph) map[string]any {
		rec := graphRecord(g)
		var links []goldenLink
		for _, l := range rec.Links {
			if l.Source == aruba253 || l.Target == aruba253 {
				links = append(links, l)
			}
		}
		var node goldenNode
		for _, n := range rec.Nodes {
			if n.ID == aruba253 {
				node = n
			}
		}
		return map[string]any{"node": node, "links": links}
	}
	baseNodes, nodes := slices.Collect(maps.Keys(base.Nodes)), slices.Collect(maps.Keys(graph.Nodes))
	baseEdges, edges := graphEdgeLines(base), graphEdgeLines(graph)
	rec := map[string]any{
		"polls":        polls,
		"before_polls": around(base),
		"after_polls":  around(graph),
		"graph_changes": map[string]any{
			"nodes_removed": sortedMinus(baseNodes, nodes),
			"nodes_added":   sortedMinus(nodes, baseNodes),
			"edges_removed": sortedMinus(baseEdges, edges),
			"edges_added":   sortedMinus(edges, baseEdges),
		},
	}
	checkGolden(t, "scenario_aruba.json", goldenJSON(t, rec, 3))
}
