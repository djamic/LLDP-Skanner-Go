package main

import (
	"fmt"
	"slices"
	"strings"
	"testing"
)

// miniHubNetwork is a switch with one port per branch of the per-port rule
// the mini hub changed, and a second polled switch whose chassis MAC it
// learns on ports 3, 4 and 5.
func miniHubNetwork() map[string]*DeviceData {
	const other = "4c:ae:a3:90:00:91"
	var fdb []MACEntry
	add := func(port int, macs ...string) { fdb = append(fdb, macEntries(port, macs...)...) }
	add(1, graphMACRange("00:1b:21:90:01", 1, 5)...)                // trunk, 5 MACs, no switch: mini hub
	add(2, graphMACRange("00:1b:21:90:02", 1, 25)...)               // 25 MACs, no switch: mini hub
	add(3, append(graphMACRange("00:1b:21:90:03", 1, 6), other)...) // 6 MACs and a polled switch: uplink (was a hub)
	add(4, append(graphMACRange("00:1b:21:90:04", 1, 6), other)...) // trunk, 6 MACs and a polled switch: uplink
	add(5, append(graphMACRange("00:1b:21:90:05", 1, 2), other)...) // 2 MACs and a polled switch: direct
	add(7, graphMACRange("00:1b:21:90:07", 1, 4)...)                // trunk with an HTTP-confirmed ESXi host
	add(8, graphMACRange("00:1b:21:90:08", 1, 5)...)                // 5 MACs: a hub, Shadow IT
	var big []string
	for i := 0; i < fdbMiniHubMax+1; i++ {
		big = append(big, fmt.Sprintf("00:1b:21:96:%02x:%02x", i/256, i%256))
	}
	add(6, big...) // 501 MACs, no switch: an uplink toward unpolled switches
	return map[string]*DeviceData{
		"10.9.90.1": {
			IP: "10.9.90.1", SysName: "sw-90", ChassisID: "4c:ae:a3:90:00:90", Interfaces: gigabitPorts(12, nil),
			PortVLANs: []PortVLAN{{PortIndex: 1, PVID: 1, IsTrunk: true}, {PortIndex: 4, PVID: 1, IsTrunk: true}, {PortIndex: 7, PVID: 1, IsTrunk: true}},
			MACTable:  fdb,
		},
		"10.9.90.2": {IP: "10.9.90.2", SysName: "sw-91", ChassisID: other, Interfaces: gigabitPorts(4, nil)},
	}
}

// TestFDBPortsMiniHub pins the mini hub rule: a trunk or a port with more
// than 20 MACs that no polled switch is behind is a mini hub (its devices
// are drawn, under a hub- node of group minihub), not dropped; with more
// than 500 MACs it stays an uplink. A port where a polled switch's MAC is
// learned is no hub (it was a false Shadow-IT hub) and no mini hub, but its
// stations are direct when there are at most 3. A trunk with an
// HTTP-confirmed ESXi host is an ESXi port. A mini hub raises no Shadow-IT
// alert, is no Shadow-IT candidate and has no Shadow-IT diagram, but the
// audit lists it in its own section.
func TestFDBPortsMiniHub(t *testing.T) {
	resetState(t)
	devices := miniHubNetwork()
	ConfirmedESXiMACs.Store("00:1b:21:90:07:01", true)

	kinds := map[fdbPortKind]string{fdbDirect: "direct", fdbHub: "hub", fdbVMPort: "vm", fdbESXiPort: "esxi", fdbMiniHub: "minihub"}
	var rule []string
	for _, p := range fdbPorts(devices["10.9.90.1"], buildSwitchOwnMACs(devices)) {
		rule = append(rule, fmt.Sprintf("%d:%d:%s:%v", p.Port, len(p.MACs), kinds[p.Kind], p.Candidate))
	}
	if got, want := strings.Join(rule, " "), "1:5:minihub:false 2:25:minihub:false 5:2:direct:false 7:4:esxi:false 8:5:hub:true"; got != want {
		t.Errorf("fdbPorts = %s\nwant       %s", got, want)
	}

	g := buildGraphFromSnapshot(devices)
	const sw = "4c:ae:a3:90:00:90"
	groups := map[string]string{}
	for _, n := range g.GetGraphData().Nodes {
		groups[n.ID] = n.Group
	}
	for port, n := range map[int]int{1: 5, 2: 25} {
		hub := fmt.Sprintf("hub-%s-p%d", sw, port)
		if got := g.SwitchInfo[hub]; got != fmt.Sprintf("[MINIHUB] Mini hub\n%d devices", n) || groups[hub] != "minihub" || len(g.Edges[hub]) != n {
			t.Errorf("%s = %q, group %q, %d members, want a mini hub of %d", hub, got, groups[hub], len(g.Edges[hub]), n)
		}
		if got := g.GetEdgeLabel(sw, hub); got != fmt.Sprintf("GE1/0/%d|Hub", port) {
			t.Errorf("%s link = %q", hub, got)
		}
	}
	if hub := "hub-" + sw + "-p8"; groups[hub] != "hub" {
		t.Errorf("port 8 = group %q, want a hub", groups[hub])
	}
	for _, port := range []int{3, 4, 6} {
		if g.Nodes[fmt.Sprintf("hub-%s-p%d", sw, port)] || g.Nodes[fmt.Sprintf("00:1b:21:90:%02x:01", port)] || (port == 6 && g.Nodes["00:1b:21:96:00:00"]) {
			t.Errorf("uplink port %d got nodes", port)
		}
	}
	if !g.GetEdge(sw, "00:1b:21:90:05:01") || !g.GetEdge(sw, "00:1b:21:90:07:02") {
		t.Errorf("the direct stations of port 5 or the ESXi port 7 are not linked to the switch")
	}

	// Shadow IT: the hub only
	list := make([]*DeviceData, 0, len(devices))
	for _, ip := range sortedDeviceIPs(devices) {
		list = append(list, devices[ip])
	}
	alerts := analyzerIssueIDs(NewAnalyzer(captureData("minihub", list, g)).analyzeShadowIT(), "shadow_it")
	if !slices.Equal(alerts, []string{"shadow_10_9_90_1_8"}) {
		t.Errorf("Shadow-IT alerts = %v, want the hub on port 8 only", alerts)
	}
	if stats := analyzerShadowCounts(list); stats.Candidates != 1 || stats.Hubs != 1 {
		t.Errorf("Shadow-IT counts = %+v, want 1 candidate, 1 hub", stats)
	}
	if hubs := reportShadowHubs(g, GenerateShadowDiagrams(g)); !slices.Equal(hubs, []string{"hub-" + sw + "-p8"}) {
		t.Errorf("Shadow-IT diagrams for %v, want the hub on port 8 only", hubs)
	}

	// The audit's own section lists the mini hubs
	collectedDataMutex.Lock()
	collectedData = devices
	collectedDataMutex.Unlock()
	SetGlobalGraph(g)
	section := reportMDSection(generateAuditMD([]string{"switch", "hub", "minihub"}), "### 4.15", "## 5.")
	if !strings.Contains(section, "(2 ta)") || !strings.Contains(section, "hub-"+sw+"-p1") || !strings.Contains(section, "hub-"+sw+"-p2") {
		t.Errorf("audit section 4.15:\n%s", section)
	}
}

// TestFDBPortsHuaweiBridgePortMapping checks Huawei VRP switches where
// MACEntry.PortNumber and PortVLAN.PortIndex are dot1dBasePort numbers while
// LLDPNeighbor.LocalPortNum is an ifIndex (mapped via BridgePortIfIndex):
//   - a switch-to-switch trunk port (Core1 bp=5 -> ifIdx=9) whose LLDP
//     neighbor is a polled switch (L4Acc4_7) produces no fake [MINIHUB], so
//     L4Acc4_7's own LLDP AP and IP phone stay [LLDP-EP] instead of [ENDPOINT];
//   - LLDP edge VLAN labels look up the mapped bridge port (bp=42 [T], not
//     bp=48 [V20]);
//   - a cascaded DownLink hub port (bp=33 -> ifIdx=39) with an LLDP phone and
//     5 non-LLDP PCs keeps its [HUB] and endpoints;
//   - an FDB port (bp=32 -> ifIdx=38) is not dropped just because another port
//     has ifIndex=32 with an LLDP neighbor.
func TestFDBPortsHuaweiBridgePortMapping(t *testing.T) {
	resetState(t)
	const (
		coreMAC  = "18:56:44:00:00:01"
		accMAC   = "18:56:44:00:00:02"
		apMAC    = "18:56:44:00:00:a1"
		phoneMAC = "c0:74:ad:00:00:b1"
		pc32MAC  = "00:1b:21:32:00:01"
	)

	downstreamPCs := graphMACRange("00:1b:21:47:01", 1, 16)
	coreFDB := macEntries(5, append([]string{accMAC, apMAC, phoneMAC}, downstreamPCs...)...)

	core := &DeviceData{
		IP:        "10.9.91.1",
		SysName:   "sw-core-1",
		ChassisID: coreMAC,
		Interfaces: []InterfaceData{
			{IfIndex: 9, IfDescr: "\"XGigabitEthernet0/0/3\"", IfSpeed: 10_000_000_000, IfOperStatus: 1},
		},
		BridgePortIfIndex: map[int]int{5: 9},
		PortVLANs:         []PortVLAN{{PortIndex: 5, PVID: 1, IsTrunk: true}},
		Neighbors: []LLDPNeighbor{{
			LocalPortNum: 9, RemIndex: 1,
			RemChassisIdSubtype: 4, RemChassisId: accMAC,
			RemPortIdSubtype: 5, RemPortId: "XGigabitEthernet0/0/1",
			RemSysName: "sw-acc-7", RemMgmtIP: "10.9.91.30",
		}},
		MACTable: coreFDB,
	}

	cascadedPCs := graphMACRange("00:1b:21:33:01", 1, 5)
	var accFDB []MACEntry
	for i, m := range downstreamPCs {
		accFDB = append(accFDB, MACEntry{PortNumber: i + 1, MACAddress: m})
	}
	accFDB = append(accFDB, macEntries(26, phoneMAC)...)
	accFDB = append(accFDB, macEntries(32, pc32MAC)...)
	accFDB = append(accFDB, macEntries(33, cascadedPCs...)...)
	accFDB = append(accFDB, macEntries(42, apMAC, "9e:00:00:00:00:21")...)

	accIfaces := make([]InterfaceData, 0, 50)
	accBridge := make(map[int]int, 50)
	for bp := 1; bp <= 48; bp++ {
		ifIdx := bp + 6
		accBridge[bp] = ifIdx
		accIfaces = append(accIfaces, InterfaceData{
			IfIndex: ifIdx, IfDescr: fmt.Sprintf("\"GigabitEthernet0/0/%d\"", bp), IfSpeed: 1_000_000_000, IfOperStatus: 1,
		})
	}
	accBridge[49] = 55
	accIfaces = append(accIfaces, InterfaceData{IfIndex: 55, IfDescr: "\"XGigabitEthernet0/0/1\"", IfSpeed: 10_000_000_000, IfOperStatus: 1})

	acc := &DeviceData{
		IP:                "10.9.91.30",
		SysName:           "sw-acc-7",
		ChassisID:         accMAC,
		Interfaces:        accIfaces,
		BridgePortIfIndex: accBridge,
		PortVLANs: []PortVLAN{
			{PortIndex: 42, PVID: 1, IsTrunk: true},
			{PortIndex: 48, PVID: 20, IsTrunk: false},
			{PortIndex: 49, PVID: 1, IsTrunk: true},
		},
		Neighbors: []LLDPNeighbor{
			{
				LocalPortNum: 32, RemIndex: 1, // bp=26 -> ifIdx=32 (must NOT silence bp=32 -> ifIdx=38!)
				RemChassisIdSubtype: 4, RemChassisId: phoneMAC,
				RemPortIdSubtype: 3, RemPortId: phoneMAC,
				RemSysName: "GXP1625", RemMgmtIP: "192.0.2.81",
			},
			{
				LocalPortNum: 39, RemIndex: 1, // bp=33 -> ifIdx=39 cascaded hub with 1 LLDP phone + 5 non-LLDP PCs
				RemChassisIdSubtype: 4, RemChassisId: "c0:74:ad:00:99:99",
				RemPortIdSubtype: 3, RemPortId: "c0:74:ad:00:99:99",
				RemSysName: "GRP2613", RemMgmtIP: "192.0.2.99",
			},
			{
				LocalPortNum: 48, RemIndex: 1, // bp=42 -> ifIdx=48 Huawei AP on trunk port
				RemChassisIdSubtype: 4, RemChassisId: apMAC,
				RemPortIdSubtype: 5, RemPortId: "MultiGE0/0/0",
				RemSysName: "ap-42", RemSysDesc: "Huawei AP AP7060DN", RemMgmtIP: "192.0.2.17",
			},
			{
				LocalPortNum: 55, RemIndex: 1,
				RemChassisIdSubtype: 4, RemChassisId: coreMAC,
				RemPortIdSubtype: 5, RemPortId: "XGigabitEthernet0/0/3",
				RemSysName: "sw-core-1", RemMgmtIP: "10.9.91.1",
			},
		},
		MACTable: accFDB,
	}

	devices := map[string]*DeviceData{core.IP: core, acc.IP: acc}
	g := buildGraphFromSnapshot(devices)

	if fakeHub := "hub-" + coreMAC + "-p5"; g.Nodes[fakeHub] {
		t.Errorf("Core1 switch link created fake mini hub %s: %q", fakeHub, g.SwitchInfo[fakeHub])
	}
	if got := g.SwitchInfo[apMAC]; !strings.HasPrefix(got, "[LLDP-EP]") {
		t.Errorf("AP node %s = %q, want [LLDP-EP] prefix", apMAC, got)
	}
	if got := g.SwitchInfo[phoneMAC]; !strings.HasPrefix(got, "[LLDP-EP]") {
		t.Errorf("IP phone node %s = %q, want [LLDP-EP] prefix", phoneMAC, got)
	}
	if got := g.GetEdgeLabel(accMAC, apMAC); !strings.Contains(got, "GE0/0/42 [T]") {
		t.Errorf("AP edge label = %q, want GE0/0/42 [T] (mapped from ifIdx=48 -> bp=42)", got)
	}
	realHub := "hub-" + accMAC + "-p33"
	if !g.Nodes[realHub] || len(g.Edges[realHub]) != 5 {
		t.Errorf("cascaded hub %s: exists=%v members=%d, want true and 5", realHub, g.Nodes[realHub], len(g.Edges[realHub]))
	}
	if !g.GetEdge(accMAC, pc32MAC) {
		t.Errorf("endpoint %s on bp=32 (ifIdx=38) was falsely dropped by ifIdx=32 LLDP collision", pc32MAC)
	}
}
