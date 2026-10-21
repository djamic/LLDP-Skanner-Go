package main

import (
	"slices"
	"strconv"
	"testing"
)

// Tests for the SNMP collection fixes. Every walk is answered by the fake
// agents of the harness (synthetic snmpbulkwalk -On lines).

// collectTestLLDPNeighbors walks the fake LLDP tables of ip and returns the
// management IP of each neighbor, keyed "localPort.remIndex".
func collectTestLLDPNeighbors(t *testing.T, ip string) map[string]string {
	t.Helper()
	obj := &SNMPObject{Community: "public"}
	neighbors, err := obj.collectLLDPNeighbors(ip)
	if err != nil {
		t.Fatalf("collectLLDPNeighbors: %v", err)
	}
	got := map[string]string{}
	for _, n := range neighbors {
		got[collectNeighborKey(n.LocalPortNum, n.RemIndex)] = n.RemMgmtIP
	}
	return got
}

func collectNeighborKey(localPort, remIndex int) string {
	return strconv.Itoa(localPort) + "." + strconv.Itoa(remIndex)
}

// TestCollectLLDPManagementIP checks the lldpRemManAddrTable parsing (F62)
// against the LLDP-MIB index layout:
// lldpRemManAddrEntry.<column>.<lldpRemTimeMark>.<lldpRemLocalPortNum>.
// <lldpRemIndex>.<lldpRemManAddrSubtype>.<lldpRemManAddr>, where the address
// is an OCTET STRING index (length first, then the octets).
func TestCollectLLDPManagementIP(t *testing.T) {
	resetState(t)
	rem := func(col, timeMark, port, idx int, val string) string {
		return oidLLDPRem + "." + strconv.Itoa(col) + "." + strconv.Itoa(timeMark) + "." + strconv.Itoa(port) + "." + strconv.Itoa(idx) + " = " + val
	}
	var remLines []string
	for _, n := range [][3]int{{3900, 28, 1}, {0, 48, 1}, {0, 25, 2}, {0, 26, 3}, {0, 27, 4}, {0, 29, 5}, {0, 30, 6}, {0, 31, 7}} {
		remLines = append(remLines,
			rem(4, n[0], n[1], n[2], "INTEGER: 4"),
			rem(5, n[0], n[1], n[2], "Hex-STRING: F8 F0 82 D1 67 5E "),
			rem(9, n[0], n[1], n[2], "STRING: \"sw-"+strconv.Itoa(n[1])+"\""))
	}
	man := oidLLDPMan
	fakeSNMP.set("10.9.1.1", map[string][]string{
		oidLLDPRem: remLines,
		oidLLDPMan: {
			// 28.1: time mark 3900, every accessible column (3, 4, 5) of one IPv4 address.
			man + ".3.3900.28.1.1.4.172.20.0.3 = INTEGER: 2",
			man + ".4.3900.28.1.1.4.172.20.0.3 = INTEGER: 26",
			man + ".5.3900.28.1.1.4.172.20.0.3 = OID: .0.0",
			// 48.1: the example of the finding (time mark 0).
			man + ".3.0.48.1.1.4.172.20.1.5 = INTEGER: 2",
			// 25.2: IPv6 only (address family 2, 16 octets): no IPv4 address.
			man + ".3.0.25.2.2.16.254.128.0.0.0.0.0.0.2.80.86.255.254.1.2.3 = INTEGER: 2",
			// 26.3: an agent that leaves out the length octet.
			man + ".3.0.26.3.1.10.0.0.26 = INTEGER: 2",
			// 27.4: two IPv4 addresses: the first one in walk order is kept.
			man + ".3.0.27.4.1.4.10.0.0.27 = INTEGER: 2",
			man + ".3.0.27.4.1.4.10.0.1.27 = INTEGER: 2",
			// 29.5: an octet above 255 is not an address.
			man + ".3.0.29.5.1.4.10.0.300.29 = INTEGER: 2",
			// 30.6: 0.0.0.0 is not a management address.
			man + ".3.0.30.6.1.4.0.0.0.0 = INTEGER: 2",
			// 31.7: a wrong length octet.
			man + ".3.0.31.7.1.5.10.0.0.31 = INTEGER: 2",
			// A neighbor that is not in lldpRemTable, short OIDs and garbage.
			man + ".3.0.99.9.1.4.10.0.0.99 = INTEGER: 2",
			man + ".3.0.48 = INTEGER: 2",
			man + ".3.0.48.1.1.4.172.x.1.5 = INTEGER: 2",
			"garbage line without separator",
		},
	})
	got := collectTestLLDPNeighbors(t, "10.9.1.1")
	want := map[string]string{
		"28.1": "172.20.0.3",
		"48.1": "172.20.1.5",
		"25.2": "",
		"26.3": "10.0.0.26",
		"27.4": "10.0.0.27",
		"29.5": "",
		"30.6": "",
		"31.7": "",
	}
	for key, ip := range want {
		if got[key] != ip {
			t.Errorf("neighbor %s: RemMgmtIP = %q, want %q", key, got[key], ip)
		}
	}
	if len(got) != len(want) {
		t.Errorf("got %d neighbors, want %d: %v", len(got), len(want), got)
	}

	// The management address walk fails: the neighbors are kept, without IPs
	// (the behavior before the fix).
	fakeSNMP.set("10.9.1.2", map[string][]string{oidLLDPRem: remLines})
	for key, ip := range collectTestLLDPNeighbors(t, "10.9.1.2") {
		if ip != "" {
			t.Errorf("no management table: neighbor %s got RemMgmtIP %q", key, ip)
		}
	}
}

// TestCollectLLDPManAddrIndex unit-tests the OID decoder on its own.
func TestCollectLLDPManAddrIndex(t *testing.T) {
	for _, c := range []struct {
		oid, key, ip string
		ok           bool
	}{
		{".1.0.8802.1.1.2.1.4.2.1.3.0.48.1.1.4.172.20.1.5", "48.1", "172.20.1.5", true},
		{"1.0.8802.1.1.2.1.4.2.1.3.0.48.1.1.4.172.20.1.5", "48.1", "172.20.1.5", true}, // no leading dot
		{".1.0.8802.1.1.2.1.4.2.1.4.123456.7.2.1.4.10.1.2.3", "7.2", "10.1.2.3", true},
		{".1.0.8802.1.1.2.1.4.2.1.3.0.7.2.1.10.1.2.3", "7.2", "10.1.2.3", true}, // no length octet
		{".1.0.8802.1.1.2.1.4.2.1.3.0.7.2.2.4.10.1.2.3", "", "", false},         // not IPv4
		{".1.0.8802.1.1.2.1.4.2.1.3.0.7.2.1.4.10.1.2", "", "", false},           // too short
		{".1.0.8802.1.1.2.1.4.2.1.3.0.7.2.1.4.10.1.2.3.4", "", "", false},       // too long
		{".1.0.8802.1.1.2.1.4.1.1.3.0.7.2.1.4.10.1.2.3", "", "", false},         // lldpRemTable, not the address table
		{".1.0.8802.1.1.2.1.4.2.1.3.0.7.2.1.4.10.1.2.256", "", "", false},
		{".1.0.8802.1.1.2.1.4.2.1.3.0.7.2.1.4.0.0.0.0", "", "", false},
		{".1.0.8802.1.1.2.1.4.2.1", "", "", false},
		{"", "", "", false},
	} {
		key, ip, ok := collectLLDPManAddr(c.oid)
		if key != c.key || ip != c.ip || ok != c.ok {
			t.Errorf("collectLLDPManAddr(%q) = (%q, %q, %v), want (%q, %q, %v)", c.oid, key, ip, ok, c.key, c.ip, c.ok)
		}
	}
}

// TestCollectFDBIndex checks the dot1dTpFdbPort index guard (F63): exactly
// six octets of at most 255 after the column OID.
func TestCollectFDBIndex(t *testing.T) {
	resetState(t)
	fdb := oidFDBPort
	fakeSNMP.set("10.9.1.3", map[string][]string{oidFDBPort: {
		fdb + ".0.80.86.1.2.3 = INTEGER: 5",
		fdb + ".248.240.130.209.103.94 = INTEGER: 28",
		fdb + ".1.0.94.0.0.251 = INTEGER: 2",                 // multicast: kept (the graph and snapshot filter it)
		fdb + ".1.2.3.4.5 = INTEGER: 3",                      // five octets (was 02:01:02:03:04:05)
		fdb + ".0.27.33.9.999.1 = INTEGER: 7",                // octet above 255 (was 00:1b:21:09:3e7:01)
		fdb + ".0.27.33.9.0.1.7 = INTEGER: 7",                // seven octets
		fdb + ".0.27.33.9.x.1 = INTEGER: 7",                  // not a number
		fdb + ".0.27.33.9.0.2 = INTEGER: 0",                  // port 0
		".1.3.6.1.2.1.17.4.3.1.1.0.27.33.9.0.3 = INTEGER: 4", // another column
		"garbage line without separator",
	}})
	obj := &SNMPObject{Community: "public"}
	got, err := obj.collectMACTable("10.9.1.3")
	if err != nil {
		t.Fatal(err)
	}
	want := []MACEntry{
		{MACAddress: "00:50:56:01:02:03", PortNumber: 5, Status: "learned"},
		{MACAddress: "f8:f0:82:d1:67:5e", PortNumber: 28, Status: "learned"},
		{MACAddress: "01:00:5e:00:00:fb", PortNumber: 2, Status: "learned"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("collectMACTable =\n%v\nwant\n%v", got, want)
	}
}

// TestCollectARPTable checks the ipNetToMediaPhysAddress parsing: the index
// guard (F63), MACs that net-snmp prints as STRING because all six bytes are
// printable or because MIBs are loaded (F58), and the Q11 filter that drops
// null, broadcast, multicast and zero-OUI MACs (F59).
func TestCollectARPTable(t *testing.T) {
	resetState(t)
	arp := oidARP
	fakeSNMP.set("10.9.1.4", map[string][]string{oidARP: {
		arp + ".5.172.20.1.105 = Hex-STRING: 00 0C 29 6F E0 BC ",
		arp + ".5.172.20.1.106 = STRING: \"P(J3:L\"",            // printable bytes 50 28 4a 33 3a 4c
		arp + ".5.172.20.1.114 = STRING: \"\\\"\\\\ABCD\"",      // escaped quote and backslash: 22 5c 41 42 43 44
		arp + ".5.172.20.1.115 = STRING: \"PB: CD\"",            // ": " inside the bytes
		arp + ".5.172.20.1.124 = STRING: \"AB: CD\"",            // 0x41 first: multicast bit set
		arp + ".5.172.20.1.116 = STRING: 0:c:29:aa:bb:cd",       // DISPLAY-HINT 1x: (MIBs loaded), unpadded
		arp + ".5.172.20.1.113 = STRING: \"f8-f0-82-7a-d9-69\"", // text with dashes (accepted before too)
		arp + ".7.10.20.30.40 = Hex-STRING: B4 7A F1 4A C1 98",
		arp + ".5.172.20.1.107 = Hex-STRING: 01 00 5E 00 00 FB ",    // multicast
		arp + ".5.172.20.1.108 = Hex-STRING: 00 00 00 12 34 56 ",    // zero OUI
		arp + ".5.172.20.1.109 = Hex-STRING: FF FF FF FF FF FF ",    // broadcast
		arp + ".5.172.20.1.117 = Hex-STRING: 00 00 00 00 00 00 ",    // null
		arp + ".5.172.20.1.118 = Hex-STRING: 33 33 00 00 00 01 ",    // IPv6 multicast
		arp + ".5.0.0.0.5 = Hex-STRING: 00 50 56 01 02 04 ",         // IP 0.0.0.5
		arp + ".5.172.20.1.110 = Hex-STRING: 00 50 56 01 02 ",       // five bytes
		arp + ".5.172.20.1.119 = Hex-STRING: 00 50 56 01 02 03 04 ", // seven bytes
		arp + ".172.20.1.112 = Hex-STRING: 00 50 56 01 02 05 ",      // no ifIndex (was Interface 2)
		arp + ".5.172.20.300.112 = Hex-STRING: 00 50 56 01 02 06 ",  // octet above 255
		arp + ".5.172.20.1.120 = STRING: \"ABCDEFG\"",               // seven printable bytes
		arp + ".5.172.20.1.121 = STRING: \"\"",                      // incomplete entry
		arp + ".5.172.20.1.122 = No Such Instance currently exists at this OID",
		arp + ".5.172.20.1.123 = INTEGER: 3",
		"garbage line without separator",
	}})
	obj := &SNMPObject{Community: "public"}
	got, err := obj.collectARPTable("10.9.1.4")
	if err != nil {
		t.Fatal(err)
	}
	want := []ARPEntry{
		{IPAddress: "172.20.1.105", MACAddress: "00:0c:29:6f:e0:bc", Interface: 5},
		{IPAddress: "172.20.1.106", MACAddress: "50:28:4a:33:3a:4c", Interface: 5},
		{IPAddress: "172.20.1.114", MACAddress: "22:5c:41:42:43:44", Interface: 5},
		{IPAddress: "172.20.1.115", MACAddress: "50:42:3a:20:43:44", Interface: 5},
		{IPAddress: "172.20.1.116", MACAddress: "00:0c:29:aa:bb:cd", Interface: 5},
		{IPAddress: "172.20.1.113", MACAddress: "f8:f0:82:7a:d9:69", Interface: 5},
		{IPAddress: "10.20.30.40", MACAddress: "b4:7a:f1:4a:c1:98", Interface: 7},
	}
	if !slices.Equal(got, want) {
		t.Errorf("collectARPTable =\n%v\nwant\n%v", got, want)
	}
}

// TestCollectUsableMAC pins the Q11 MAC filter.
func TestCollectUsableMAC(t *testing.T) {
	for mac, want := range map[string]bool{
		"00:0c:29:6f:e0:bc":  true,
		"da:a1:19:09:23:03":  true, // locally administered: kept (not special)
		"52:54:00:12:34:56":  true,
		"AA:BB:CC:00:00:01":  true, // normalized first
		"00:00:00:00:00:00":  false,
		"ff:ff:ff:ff:ff:ff":  false,
		"01:00:5e:00:00:16":  false,
		"33:33:00:00:00:01":  false,
		"03:00:00:00:00:01":  false,
		"00:00:00:2d:2a:56":  false,
		"00:1b:21:09:3e7:01": false,
		"00:1b:21:09:00":     false,
		"desktop-v380chd":    false,
		"":                   false,
	} {
		if got := collectUsableMAC(mac); got != want {
			t.Errorf("collectUsableMAC(%q) = %v, want %v", mac, got, want)
		}
	}
}

// collectHuaweiAgent is a switch numbered like Huawei 172.20.254.249:
// ifIndex 1 InLoopBack0, 2 NULL0, 6..29 GigabitEthernet0/0/1..24, while the
// FDB reports bridge ports 1, 2 and 19 (dot1dBasePortIfIndex: port N is
// ifIndex N+5).
func collectHuaweiAgent(withBasePorts bool) map[string][]string {
	walks := map[string][]string{
		oidIfDescr: {
			oidIfDescr + ".1 = STRING: \"InLoopBack0\"",
			oidIfDescr + ".2 = STRING: \"NULL0\"",
			oidIfDescr + ".6 = STRING: \"GigabitEthernet0/0/1\"",
			oidIfDescr + ".7 = STRING: \"GigabitEthernet0/0/2\"",
			oidIfDescr + ".19 = STRING: \"GigabitEthernet0/0/14\"",
			oidIfDescr + ".24 = STRING: \"GigabitEthernet0/0/19\"",
		},
		oidFDBPort: {
			oidFDBPort + ".0.80.86.1.2.1 = INTEGER: 1",
			oidFDBPort + ".0.80.86.1.2.2 = INTEGER: 2",
			oidFDBPort + ".76.174.163.162.1.172 = INTEGER: 19",
		},
	}
	if withBasePorts {
		walks[collectBasePortIfIndexOID] = []string{
			collectBasePortIfIndexOID + ".1 = INTEGER: 6",
			collectBasePortIfIndexOID + ".2 = INTEGER: 7",
			collectBasePortIfIndexOID + ".19 = INTEGER: 24",
			collectBasePortIfIndexOID + ".20 = INTEGER: 0", // bridge port without an interface
			collectBasePortIfIndexOID + ".x = INTEGER: 25",
			"garbage line without separator",
		}
	}
	return walks
}

// TestCollectBridgePortIfIndex checks F60: the FDB reports dot1dBasePort
// numbers, and dot1dBasePortIfIndex maps them to the ifIndex that names the
// port. PortNumber stays the bridge port (ids and the bridge-port indexed
// VLAN table use it); without the mapping the bridge port is used as the
// ifIndex, as before.
func TestCollectBridgePortIfIndex(t *testing.T) {
	resetState(t)
	fakeSNMP.set("10.9.1.5", collectHuaweiAgent(true))
	fakeSNMP.set("10.9.1.6", collectHuaweiAgent(false))
	var got []*DeviceData
	obj := NewSNMPObject(func(d *DeviceData) { got = append(got, d) }, nil)
	obj.CollectData("10.9.1.5", "huawei")
	obj.CollectData("10.9.1.6", "huawei-no-base-ports")
	if len(got) != 2 {
		t.Fatalf("got %d devices, want 2", len(got))
	}
	mapped, unmapped := got[0], got[1]

	wantMap := map[int]int{1: 6, 2: 7, 19: 24}
	if len(mapped.BridgePortIfIndex) != len(wantMap) {
		t.Errorf("BridgePortIfIndex = %v, want %v", mapped.BridgePortIfIndex, wantMap)
	}
	for port, ifIndex := range wantMap {
		if mapped.BridgePortIfIndex[port] != ifIndex {
			t.Errorf("BridgePortIfIndex[%d] = %d, want %d", port, mapped.BridgePortIfIndex[port], ifIndex)
		}
	}
	if unmapped.BridgePortIfIndex != nil {
		t.Errorf("no dot1dBasePortIfIndex: BridgePortIfIndex = %v, want nil", unmapped.BridgePortIfIndex)
	}
	for _, e := range mapped.MACTable {
		if e.PortNumber != 1 && e.PortNumber != 2 && e.PortNumber != 19 {
			t.Errorf("PortNumber %d is not the bridge port", e.PortNumber)
		}
	}

	for _, c := range []struct {
		data       *DeviceData
		bridgePort int
		ifIndex    int
		name       string
	}{
		{mapped, 19, 24, "\"GigabitEthernet0/0/19\""},
		{mapped, 1, 6, "\"GigabitEthernet0/0/1\""},
		{mapped, 2, 7, "\"GigabitEthernet0/0/2\""},
		{mapped, 5, 5, "Port 5"}, // not in the mapping: bridge port used as ifIndex
		{unmapped, 19, 19, "\"GigabitEthernet0/0/14\""},
		{unmapped, 1, 1, "\"InLoopBack0\""},
		{&DeviceData{}, 3, 3, "Port 3"},
	} {
		ifIndex := collectFDBIfIndex(c.data, c.bridgePort)
		if ifIndex != c.ifIndex {
			t.Errorf("%s: collectFDBIfIndex(%d) = %d, want %d", c.data.SysName, c.bridgePort, ifIndex, c.ifIndex)
		}
		if name := getLocalPortName(c.data, ifIndex); name != c.name {
			t.Errorf("%s: port name of bridge port %d = %q, want %q", c.data.SysName, c.bridgePort, name, c.name)
		}
	}
}

// TestCollectNullInterface checks F61: IfDescr is stored quoted, and a
// quoted "NULL0" is still the discard interface.
func TestCollectNullInterface(t *testing.T) {
	for name, want := range map[string]bool{
		"NULL0":                    true,
		"\"NULL0\"":                true,
		"\"Null0\"":                true,
		" \"NULL0\" ":              true,
		"\"InLoopBack0\"":          true,
		"\"\"":                     true,
		"Port 0":                   true,
		"\"GigabitEthernet0/0/1\"": false,
		"\"Vlanif1\"":              false,
		"GigabitEthernet1/0/1":     false,
		"Port 7":                   false,
	} {
		if got := isNullInterface(name); got != want {
			t.Errorf("isNullInterface(%q) = %v, want %v", name, got, want)
		}
	}
}
