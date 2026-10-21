package main

import (
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
