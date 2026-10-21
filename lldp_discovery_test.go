package main

import (
	"fmt"
	"maps"
	"slices"
	"testing"
)

// lldpCapsAgent is a switch with one LLDP neighbor per lldpRemSysCapEnabled
// form (column 12 of lldpRemTable), each advertising a management IP
// 10.9.7.<local port>:
//
//	port 1  Hex-STRING 28 00         bridge + router
//	port 2  BITS with the LLDP-MIB   bridge
//	port 3  STRING "0" (0x30)        bridge + wlanAccessPoint
//	port 4  Hex-STRING 24 00         bridge + telephone
//	port 5  Hex-STRING 08            router only
//	port 6  STRING "\x04"-like 04    telephone
//	port 7  no capability column     unknown
//	port 8  Hex-STRING 20 00         bridge (does not answer SNMP)
//	port 9  Hex-STRING 00 00         none
func lldpCapsAgent() map[string][]string {
	caps := map[int]string{
		1: "Hex-STRING: 28 00 ",
		2: "BITS: 20 00 bridge(2) ",
		3: "STRING: \"0\"",
		4: "Hex-STRING: 24 00 ",
		5: "Hex-STRING: 08 ",
		6: "Hex-STRING: 04 00 ",
		8: "Hex-STRING: 20 00 ",
		9: "Hex-STRING: 00 00 ",
	}
	var rem, man []string
	for port := 1; port <= 9; port++ {
		idx := fmt.Sprintf("0.%d.1", port)
		rem = append(rem,
			fmt.Sprintf("%s.4.%s = INTEGER: 4", oidLLDPRem, idx),
			fmt.Sprintf("%s.5.%s = Hex-STRING: 4C AE A3 97 00 %02X ", oidLLDPRem, idx, port),
			fmt.Sprintf("%s.9.%s = STRING: \"nb-%d\"", oidLLDPRem, idx, port))
		if c, ok := caps[port]; ok {
			rem = append(rem, fmt.Sprintf("%s.12.%s = %s", oidLLDPRem, idx, c))
		}
		man = append(man, fmt.Sprintf("%s.3.%s.1.4.10.9.7.%d = INTEGER: 2", oidLLDPMan, idx, port))
	}
	return map[string][]string{
		oidChassis: {oidChassis + " = Hex-STRING: 4C AE A3 97 00 00 "},
		oidIfDescr: {oidIfDescr + ".1 = STRING: \"GigabitEthernet1/0/1\""},
		oidLLDPRem: rem,
		oidLLDPMan: man,
	}
}

// TestLLDPCapabilities checks that lldpRemSysCapEnabled is read in each
// form net-snmp prints it (Hex-STRING, BITS with the LLDP-MIB, a printable
// STRING), and that a missing column leaves the capabilities unknown (0).
func TestLLDPCapabilities(t *testing.T) {
	resetState(t)
	fakeSNMP.set("10.9.7.100", lldpCapsAgent())
	obj := &SNMPObject{Community: "public", Port: 161}
	neighbors, err := obj.collectLLDPNeighbors("10.9.7.100")
	if err != nil {
		t.Fatal(err)
	}
	got := map[int]uint8{}
	mgmt := map[int]string{}
	for _, n := range neighbors {
		got[n.LocalPortNum] = n.RemSysCapEnabled
		mgmt[n.LocalPortNum] = n.RemMgmtIP
	}
	want := map[int]uint8{1: 0x28, 2: 0x20, 3: 0x30, 4: 0x24, 5: 0x08, 6: 0x04, 7: 0, 8: 0x20, 9: 0}
	if !maps.Equal(got, want) {
		t.Errorf("RemSysCapEnabled by port = %v, want %v", got, want)
	}
	if mgmt[1] != "10.9.7.1" || mgmt[9] != "10.9.7.9" {
		t.Errorf("management IPs = %v", mgmt)
	}
	for caps, want := range map[uint8]bool{0x28: true, 0x20: true, 0x08: true, 0x18: true, 0x30: false, 0x24: false, 0x04: false, 0x10: false, 0x80: false, 0x01: false, 0: false} {
		if got := lldpDiscoverable(caps); got != want {
			t.Errorf("lldpDiscoverable(%#02x) = %v, want %v", caps, got, want)
		}
	}
}

// TestLLDPDiscoveryCapabilities (H7): LLDP discovery polls only neighbors
// that enable router, or bridge without wlanAccessPoint and telephone, and
// adds a polled one to swich_ips only after it answered. Access points,
// phones and neighbors with unknown capabilities, which advertise
// management IPs too since F62, are neither polled nor added.
func TestLLDPDiscoveryCapabilities(t *testing.T) {
	resetState(t)
	fakeSNMP.set("10.9.7.100", lldpCapsAgent())
	obj := newRescanSNMPObject()
	obj.CollectData("10.9.7.100", "sw-caps")
	for _, port := range []int{1, 2, 3, 4, 5, 6, 7, 9} { // 8 does not answer
		ip := fmt.Sprintf("10.9.7.%d", port)
		fakeSNMP.set(ip, map[string][]string{oidChassis: {fmt.Sprintf("%s = Hex-STRING: 4C AE A3 97 00 %02X ", oidChassis, port)}})
	}
	switchIPAdds.taken()

	discoverFromLLDP(obj)

	collectedDataMutex.RLock()
	polled := slices.Sorted(maps.Keys(collectedData))
	collectedDataMutex.RUnlock()
	if want := []string{"10.9.7.1", "10.9.7.100", "10.9.7.2", "10.9.7.5"}; !slices.Equal(polled, want) {
		t.Errorf("polled devices = %v, want %v", polled, want)
	}
	if got, want := switchIPAdds.taken(), []string{"10.9.7.1", "10.9.7.2", "10.9.7.5"}; !slices.Equal(got, want) {
		t.Errorf("added to swich_ips = %v, want %v", got, want)
	}
}
