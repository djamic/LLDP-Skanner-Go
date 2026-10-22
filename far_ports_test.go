package main

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
)

// Far ports: the port at the other end of a link, after the "|" of its
// label (the Tree tab's "<parent port> ⇄ <child port>"). LLDP names it from
// the neighbor's description or port id (lldpRemotePortName), from the far
// switch's own LLDP view when the near one names none (lldpReverseFarPort),
// and a MAC cross-reference link from the far switch's FDB (macRefFarPort).

// TestLLDPRemotePortName covers the neighbor classes of the saved data of
// 2026-10-20 and of the live /api/hosts of 2026-10-22, by port id subtype
// (1 interfaceAlias, 3 macAddress, 4 networkAddress, 5 interfaceName, 7
// local, 0 none) and description: a description with text names the port,
// an empty one (`""`, the SNR switches; blanks) gives the port id when it
// names a port, and a MAC port id never becomes a port name.
func TestLLDPRemotePortName(t *testing.T) {
	cases := []struct {
		name            string
		subtype         int
		portID, desc    string
		sysName         string
		want, wantLabel string // lldpRemotePortName, and normalizePortName of it
	}{
		{"SNR interfaceName, empty description (172.20.230.51 -> .254)", 5, `"Ethernet1/0/10"`, `""`, "", "Ethernet1/0/10", "Eth1/0/10"},
		{"interfaceName, blank description", 5, `"Ethernet1/0/10"`, `"  "`, "", "Ethernet1/0/10", "Eth1/0/10"},
		{"interfaceName, no description column", 5, `"Ten-GigabitEthernet1/0/49"`, "", "", "Ten-GigabitEthernet1/0/49", "TGE1/0/49"},
		{"HPE interfaceName, default description", 5, `"GigabitEthernet1/0/48"`, `"GigabitEthernet1/0/48 Interface"`, "HPE", "GigabitEthernet1/0/48 Interface", "GE1/0/48"},
		{"HPE interfaceName, the admin's description", 5, `"GigabitEthernet1/0/47"`, `"B-318/3"`, "B-318/1", "B-318/3", "B-318/3"},
		{"Eltex interfaceName, empty description", 5, `"gi1/0/4"`, `""`, "", "gi1/0/4", "gi1/0/4"},
		{"Aruba interfaceName = description", 5, `"1/1/28"`, `"1/1/28"`, "6300", "1/1/28", "1/1/28"},
		{"FortiGate interfaceAlias, empty description", 1, `"LAN"`, `""`, "FortiGate-600F", "LAN", "LAN"},
		{"SNR S2985G-24TC local port number", 7, `"28"`, `""`, "", "28", "28"},
		{"PiXiETECH local id with a description", 7, `"Gig0/27"`, `"GigaEthernet0/27"`, "Switch", "GigaEthernet0/27", "GigaEth0/27"},
		{"local id that spells a MAC", 7, `"f4-b5-20-19-12-5e"`, `""`, "", "", ""},
		{"PC: MAC port id as Hex-STRING, empty description", 3, "48 F3 17 07 58 7F", `""`, "", "", ""},
		{"PC: MAC port id, no description column (was 98EECBE08974)", 3, "98 EE CB E0 89 74", "", "", "", ""},
		{"SNR's PC: dashed MAC port id", 3, `"00-e0-1a-ae-03-75"`, `""`, "", "", ""},
		{"MAC port id as 6 raw bytes (172.20.230.254 port 3)", 3, "\"|WXI`:\"", `""`, "", "", ""},
		{"access point: dotted MAC port id, eth0", 3, `"AC8B.A970.A966"`, `"eth0"`, "Sportzal", "eth0", "eth0"},
		{"UniFi: MAC port id, eth0", 3, "70 A7 41 AA 23 4D", `"eth0"`, "U6-LR", "eth0", "eth0"},
		{"phone: network address chassis, MAC port id, eth0", 3, "EC 74 D7 64 CB AC", `"eth0"`, "GXP1610_ec:74:d7:64:cb:ac", "eth0", "eth0"},
		{"networkAddress port id", 4, "01 AC 10 01 0F", `""`, "", "", ""},
		{"no subtype, no port id", 0, "", "", "", "", ""},
		{"no subtype, quoted empty description", 0, "", `""`, "", "", ""},
		{"description is the sysName: the port id", 5, `"Gi0/1"`, `"sw-x"`, "sw-x", "Gi0/1", "Gi0/1"},
		{"description is the sysName, MAC port id (was the MAC)", 3, "10 7C 61 C0 9E AA", `"DESKTOP-V380CHD"`, "DESKTOP-V380CHD", "", ""},
		{"port id is the sysName, empty description (was Uplink)", 7, `"sw-x"`, `""`, "sw-x", "", ""},
	}
	for _, c := range cases {
		n := LLDPNeighbor{RemPortIdSubtype: c.subtype, RemPortId: c.portID, RemPortDesc: c.desc, RemSysName: c.sysName}
		got := lldpRemotePortName(n)
		if got != c.want || normalizePortName(got) != c.wantLabel {
			t.Errorf("%s: lldpRemotePortName = %q (label %q), want %q (label %q)", c.name, got, normalizePortName(got), c.want, c.wantLabel)
		}
	}
}

// TestFixtureFarPorts runs the far-port rule on every accepted LLDP
// neighbor of the saved data: no far port spells a MAC, an empty or blank
// description of a naming port id gives the normalized port id, and a MAC
// port id gives the description or nothing. 172.20.230.51 names the port
// of 172.20.230.254 now (lldpRemPortDesc `""`, lldpRemPortId
// "Ethernet1/0/10"), and no switch-to-switch LLDP link of the fixture is
// left without its far port.
func TestFixtureFarPorts(t *testing.T) {
	devices := fixtureDevices(t)
	classes := map[string]int{}
	for _, ip := range sortedDeviceIPs(devices) {
		d := devices[ip]
		for _, n := range d.Neighbors {
			if _, _, ok := graphLLDPNeighborTarget(d, n); !ok {
				continue
			}
			far := normalizePortName(lldpRemotePortName(n))
			if far != "" && canonicalMAC(far) != "" {
				t.Errorf("%s port %d: far port %q spells a MAC (port id %q, subtype %d)", ip, n.LocalPortNum, far, n.RemPortId, n.RemPortIdSubtype)
			}
			desc := cleanSNMPValue(n.RemPortDesc)
			switch {
			case n.RemPortIdSubtype == 3 && far != normalizePortName(desc):
				t.Errorf("%s port %d: MAC port id %q gives %q, want the description %q", ip, n.LocalPortNum, n.RemPortId, far, desc)
			case n.RemPortIdSubtype == 5 && desc == "" && far != normalizePortName(n.RemPortId):
				t.Errorf("%s port %d: empty description %q gives %q, want the port id %q", ip, n.LocalPortNum, n.RemPortDesc, far, n.RemPortId)
			}
			key := fmt.Sprintf("subtype %d, description %v: named %v", n.RemPortIdSubtype, desc != "", far != "")
			classes[key]++
		}
	}
	t.Logf("accepted LLDP neighbors of the fixture by class: %v", classes)

	g := buildFixtureGraph(t)
	const dot51, dot254 = "f8:f0:82:d8:7e:81", "f8:f0:82:d1:67:5e"
	if got := g.GetEdgeLabel(dot51, dot254); got != "Eth1/0/28 1G|Eth1/0/10" {
		t.Errorf("172.20.230.51 -> 172.20.230.254 = %q, want %q", got, "Eth1/0/28 1G|Eth1/0/10")
	}
	switches := map[string]bool{}
	for _, d := range devices {
		switches[graphDeviceNodeID(d)] = true
	}
	for _, line := range graphEdgeLines(g) {
		src, rest, _ := strings.Cut(line, " -> ")
		dst, label, _ := strings.Cut(rest, " : ")
		if switches[src] && switches[dst] && strings.HasSuffix(label, `|"`) && !strings.Contains(label, "[MAC-REF]") {
			t.Errorf("switch-to-switch LLDP link without a far port: %s", line)
		}
	}
}

// farPortSwitch is a polled switch of the far-port tests with ports
// GigabitEthernet1/0/1-52 ("Ethernet1/0/n" when snr) and the given LLDP
// rows and FDB.
func farPortSwitch(ip, chassis string, snr bool, rows []LLDPNeighbor, fdb ...[]MACEntry) *DeviceData {
	ports := gigabitPorts(52, nil)
	if snr {
		for i := range ports {
			ports[i].IfDescr = fmt.Sprintf("Ethernet1/0/%d", ports[i].IfIndex)
		}
	}
	return &DeviceData{IP: ip, ChassisID: chassis, Interfaces: ports, Neighbors: rows, MACTable: slices.Concat(fdb...)}
}

// farPortRow is an LLDP row toward the switch with chassis MAC chassis.
func farPortRow(local int, chassis string, subtype int, portID, desc string) LLDPNeighbor {
	return LLDPNeighbor{LocalPortNum: local, RemIndex: local, RemChassisIdSubtype: 4,
		RemChassisId: strings.ToUpper(strings.ReplaceAll(chassis, ":", " ")), RemPortIdSubtype: subtype, RemPortId: portID, RemPortDesc: desc}
}

// TestLLDPReverseFarPort: switch A (first in IP order) sees B with a port id
// that names no port (a MAC, as some agents send), so A's link has no far
// port; B's own row toward A names its port. One row each: B's port fills
// A's link. A port A's view named is kept. B's row must fit the link: a row
// that names another port of A fills nothing, a port number fits ("49" is
// GE1/0/49), and with two links each of B's rows fills only the link whose
// port of A it names, in any row order. A local port that B's interface
// table does not name fills nothing.
func TestLLDPReverseFarPort(t *testing.T) {
	resetState(t)
	const ipA, ipB = "10.9.90.1", "10.9.90.2"
	const macA, macB = "4c:ae:a3:90:00:01", "f8:f0:82:90:00:02"
	noName := func(local int) LLDPNeighbor { return farPortRow(local, macB, 3, "F8 F0 82 90 00 32", `""`) }
	toA := func(local int, portID string) LLDPNeighbor { return farPortRow(local, macA, 5, portID, `""`) }
	for _, c := range []struct {
		name   string
		rowsA  []LLDPNeighbor
		rowsB  []LLDPNeighbor
		labels map[int]string // A's port -> the label of the link (only one link is drawn per pair)
	}{
		{"one row each: B names its port", []LLDPNeighbor{noName(49)}, []LLDPNeighbor{toA(28, `"GigabitEthernet1/0/49"`)},
			map[int]string{49: "GE1/0/49 1G|Eth1/0/28"}},
		{"B's row names no port of A: one row each", []LLDPNeighbor{noName(49)}, []LLDPNeighbor{farPortRow(28, macA, 3, "4C AE A3 90 00 31", `""`)},
			map[int]string{49: "GE1/0/49 1G|Eth1/0/28"}},
		{"A's view names B's port: kept", []LLDPNeighbor{farPortRow(49, macB, 3, "F8 F0 82 90 00 32", `"Ethernet1/0/27"`)}, []LLDPNeighbor{toA(28, `"GigabitEthernet1/0/49"`)},
			map[int]string{49: "GE1/0/49 1G|Eth1/0/27"}},
		{"B's row names another port of A", []LLDPNeighbor{noName(49)}, []LLDPNeighbor{toA(28, `"GigabitEthernet1/0/47"`)},
			map[int]string{49: "GE1/0/49 1G|"}},
		{"B's row names A's port by its number", []LLDPNeighbor{noName(49)}, []LLDPNeighbor{toA(28, `"49"`)},
			map[int]string{49: "GE1/0/49 1G|Eth1/0/28"}},
		{"two links: B's row of the drawn link fills it", []LLDPNeighbor{noName(49), noName(50)},
			[]LLDPNeighbor{toA(27, `"GigabitEthernet1/0/50"`), toA(28, `"GigabitEthernet1/0/49"`)},
			map[int]string{49: "GE1/0/49 1G|Eth1/0/28"}},
		{"two links, B's rows name no port of A", []LLDPNeighbor{noName(49), noName(50)},
			[]LLDPNeighbor{farPortRow(27, macA, 3, "4C AE A3 90 00 32", `""`), farPortRow(28, macA, 3, "4C AE A3 90 00 31", `""`)},
			map[int]string{49: "GE1/0/49 1G|"}},
		{"B's local port is not in its interface table", []LLDPNeighbor{noName(49)}, []LLDPNeighbor{toA(60, `"GigabitEthernet1/0/49"`)},
			map[int]string{49: "GE1/0/49 1G|"}},
	} {
		for _, reversed := range []bool{false, true} {
			rowsB := slices.Clone(c.rowsB)
			if reversed {
				slices.Reverse(rowsB)
			}
			devices := map[string]*DeviceData{
				ipA: farPortSwitch(ipA, macA, false, c.rowsA),
				ipB: farPortSwitch(ipB, macB, true, rowsB),
			}
			g := buildGraphFromSnapshot(devices)
			got := map[int]string{}
			if label := g.Edges[macA][macB]; label != "" {
				got[c.rowsA[0].LocalPortNum] = label
			}
			if !maps.Equal(got, c.labels) || g.Edges[macB][macA] != "" {
				t.Errorf("%s (B's rows reversed: %v): A -> B %q, B -> A %q; want %q", c.name, reversed, g.Edges[macA][macB], g.Edges[macB][macA], c.labels)
			}
		}
	}
}

// TestFillTargetPort: the far port of a link label is set only when empty.
func TestFillTargetPort(t *testing.T) {
	g := NewDJGraph()
	for _, id := range []string{"a", "b", "c", "d"} {
		g.AddNode(id)
	}
	g.AddEdge("a", "b", "GE1/0/1 1G|")
	g.AddEdge("a", "c", "GE1/0/2|Eth1/0/9")
	g.AddEdge("a", "d", "ge1/0/7")
	for _, c := range []struct {
		src, dst, port string
		filled         bool
		label          string
	}{
		{"a", "b", "Eth1/0/28", true, "GE1/0/1 1G|Eth1/0/28"},
		{"a", "b", "Eth1/0/27", false, "GE1/0/1 1G|Eth1/0/28"},
		{"a", "c", "Eth1/0/1", false, "GE1/0/2|Eth1/0/9"},
		{"a", "d", "Eth1/0/1", false, "ge1/0/7"},
		{"b", "a", "Eth1/0/1", false, ""},
		{"a", "b", " ", false, "GE1/0/1 1G|Eth1/0/28"},
	} {
		if filled := g.FillTargetPort(c.src, c.dst, c.port); filled != c.filled || g.Edges[c.src][c.dst] != c.label {
			t.Errorf("FillTargetPort(%s, %s, %q) = %v, label %q; want %v, %q", c.src, c.dst, c.port, filled, g.Edges[c.src][c.dst], c.filled, c.label)
		}
	}
}

// TestMACRefFarPort: the MAC cross-reference link A(port 5) -> B (A's FDB
// learns B alone on port 5) gets B's port toward A from B's FDB: the port
// where B learns A's own MACs, by chassis MAC or ARP alias, through the
// bridge port's ifIndex. Of two such ports the one where no other switch
// is learned is it; two equal ones, no FDB, a NULL0 port or a port the
// interface table does not name leave it unknown.
func TestMACRefFarPort(t *testing.T) {
	resetState(t)
	const ipA, ipB, ipC = "10.9.91.1", "10.9.91.2", "10.9.91.3"
	const macA, macB, macC, aliasA = "4c:ae:a3:91:00:01", "4c:ae:a3:91:00:02", "4c:ae:a3:91:00:03", "4c:ae:a3:91:00:0b"
	globalMACtoIPMutex.Lock()
	globalMACtoIP = map[string]string{aliasA: ipA}
	globalMACtoIPMutex.Unlock()
	hosts := []string{"00:1b:21:91:00:01", "00:1b:21:91:00:02", "00:1b:21:91:00:03"}
	a := farPortSwitch(ipA, macA, false, nil, macEntries(5, append([]string{macB}, hosts...)...))
	for _, c := range []struct {
		name string
		b    *DeviceData
		want string
	}{
		{"B learns A's chassis MAC on its uplink", farPortSwitch(ipB, macB, false, nil, macEntries(48, macA, macC, "00:1b:21:91:01:01")), "GE1/0/48"},
		{"B learns A by its ARP alias", farPortSwitch(ipB, macB, false, nil, macEntries(47, aliasA)), "GE1/0/47"},
		{"two ports, one learns another switch too", farPortSwitch(ipB, macB, false, nil, macEntries(48, macA, macC), macEntries(7, aliasA)), "GE1/0/7"},
		{"two ports, neither learns another switch", farPortSwitch(ipB, macB, false, nil, macEntries(48, macA), macEntries(7, aliasA)), ""},
		{"no FDB", farPortSwitch(ipB, macB, false, nil), ""},
		{"B does not learn A", farPortSwitch(ipB, macB, false, nil, macEntries(48, "00:1b:21:91:01:01")), ""},
		{"a NULL0 port is no connection", func() *DeviceData {
			b := farPortSwitch(ipB, macB, false, nil, macEntries(30, macA), macEntries(48, aliasA))
			b.Interfaces[29].IfDescr = "NULL0"
			return b
		}(), "GE1/0/48"},
		{"the port's interface is unknown", farPortSwitch(ipB, macB, false, nil, macEntries(60, macA)), ""},
		{"bridge port 3 is ifIndex 51", func() *DeviceData {
			b := farPortSwitch(ipB, macB, false, nil, macEntries(3, macA))
			b.BridgePortIfIndex = map[int]int{3: 51}
			return b
		}(), "GE1/0/51"},
	} {
		devices := map[string]*DeviceData{ipA: a, ipB: c.b, ipC: farPortSwitch(ipC, macC, false, nil)}
		g := NewDJGraph()
		for _, ip := range sortedDeviceIPs(devices) {
			graphAddSwitchNode(g, devices[ip])
		}
		addMACCrossRefEdges(g, devices, buildSwitchOwnMACs(devices))
		want := []string{macA + " -> " + macB + fmt.Sprintf(" : %q", "GE1/0/5 [MAC-REF]|"+c.want)}
		if got := graphEdgeLines(g); !slices.Equal(got, want) {
			t.Errorf("%s: links %q, want %q", c.name, got, want)
		}
	}
}

// TestFarPortsDeterministic builds the far-port networks with their rows,
// FDB entries and devices in every order: the labels never change.
func TestFarPortsDeterministic(t *testing.T) {
	resetState(t)
	const ipA, ipB, ipC = "10.9.92.1", "10.9.92.2", "10.9.92.3"
	const macA, macB, macC = "4c:ae:a3:92:00:01", "f8:f0:82:92:00:02", "4c:ae:a3:92:00:03"
	build := func(flip bool) []string {
		rowsA := []LLDPNeighbor{farPortRow(49, macB, 3, "F8 F0 82 92 00 31", `""`), farPortRow(50, macB, 3, "F8 F0 82 92 00 32", `""`)}
		rowsB := []LLDPNeighbor{farPortRow(27, macA, 5, `"GigabitEthernet1/0/50"`, `""`), farPortRow(28, macA, 5, `"GigabitEthernet1/0/49"`, `""`)}
		fdbC := slices.Concat(macEntries(5, macA, "00:1b:21:92:00:01"), macEntries(9, "00:1b:21:92:00:02"))
		fdbA := macEntries(3, macC, "00:1b:21:92:00:03")
		if flip {
			slices.Reverse(rowsB)
			slices.Reverse(fdbC)
		}
		devices := map[string]*DeviceData{
			ipA: farPortSwitch(ipA, macA, false, rowsA, fdbA),
			ipB: farPortSwitch(ipB, macB, true, rowsB),
			ipC: farPortSwitch(ipC, macC, false, nil, fdbC),
		}
		return graphEdgeLines(buildGraphFromSnapshot(devices))
	}
	first := build(false)
	if again := build(true); !slices.Equal(first, again) {
		t.Errorf("the labels depend on the order of the rows and FDB entries:\n%q\n%q", first, again)
	}
	want := []string{
		macA + " -> " + macB + ` : "GE1/0/49 1G|Eth1/0/28"`,
		macA + " -> " + macC + ` : "GE1/0/3 [MAC-REF]|GE1/0/5"`,
	}
	slices.Sort(want)
	var got []string
	for _, line := range first {
		if strings.HasPrefix(line, macA+" -> "+macB) || strings.HasPrefix(line, macA+" -> "+macC) {
			got = append(got, line)
		}
	}
	if !slices.Equal(got, want) {
		t.Errorf("far ports %q, want %q", got, want)
	}
}
