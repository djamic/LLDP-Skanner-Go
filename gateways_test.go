package main

import (
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// Tests of the gateways (gateways.go): the gateway_ip list, the ARP tables
// and subnets of every gateway, and the one router node each gateway that
// answers SNMP gets. The fake agents answer like the two gateways of
// 2026-10-22 (snmpget of the live agents): the FortiGate-600F 172.20.0.1
// (sysName "FortiGate-600F", sysDescr "" without a type, no BRIDGE-MIB and
// no LLDP-MIB, 172.20.0.1 on ifIndex 33 with MAC 68:cc:ae:96:e6:08, its ARP
// entry for 172.20.1.254 is 00 0C 29 98 7B C2) and the Debian router VM
// 172.20.1.254 (sysName debian216, a Linux sysDescr, no BRIDGE-MIB and no
// LLDP-MIB, 172.20.1.254 on ifIndex 2 with MAC 00:0c:29:98:7b:c2, its ARP
// entry for 172.20.0.1 is 68 CC AE 96 E6 08). 172.20.254.203 sees the
// FortiGate as an LLDP neighbor on Ten-GigabitEthernet1/0/52 (chassis
// 68:cc:ae:96:e5:e8, port "LAN", management address 172.20.0.1).

const (
	debianGW  = "172.20.1.254"
	debianMAC = "00:0c:29:98:7b:c2"
	fortiGW   = "172.20.0.1"
	fortiMAC  = "68:cc:ae:96:e6:08"
	fortiLLDP = "68:cc:ae:96:e5:e8" // the FortiGate's LLDP chassis id

	oidIPAdEntIfIndex = ".1.3.6.1.2.1.4.20.1.2"
	oidIPAdEntNetMask = ".1.3.6.1.2.1.4.20.1.3"
)

// arpRow is one ipNetToMediaPhysAddress line of an agent.
func arpRow(ifIndex int, ip, mac string) string {
	return fmt.Sprintf("%s.%d.%s = Hex-STRING: %s ", oidARP, ifIndex, ip, strings.ToUpper(strings.ReplaceAll(mac, ":", " ")))
}

// gwAddr is one ipAddrTable row of a gateway agent.
type gwAddr struct {
	ip, mask string
	ifIndex  int
}

// gatewayAgent is a router's agent (nonSwitchAgent: sysName, sysDescr,
// IF-MIB, "No Such Object" for BRIDGE-MIB and LLDP-MIB) with the given ARP
// rows and ipAddrTable.
func gatewayAgent(sysName, sysDescr string, arp []string, addrs ...gwAddr) map[string][]string {
	walks := nonSwitchAgent(sysName, sysDescr)
	walks[oidARP] = arp
	var ifIndex, masks []string
	for _, a := range addrs {
		ifIndex = append(ifIndex, fmt.Sprintf("%s.%s = INTEGER: %d", oidIPAdEntIfIndex, a.ip, a.ifIndex))
		masks = append(masks, fmt.Sprintf("%s.%s = IpAddress: %s", oidIPAdEntNetMask, a.ip, a.mask))
	}
	walks[oidIPAdEntIfIndex] = ifIndex
	walks[oidIPAdEntNetMask] = masks
	return walks
}

// fortiGateGateway answers like 172.20.0.1: its ARP table lists the Debian
// gateway, then the extra rows; 172.20.0.1/16 and 172.17.1.1/22.
func fortiGateGateway(arp ...string) map[string][]string {
	rows := append([]string{arpRow(33, debianGW, debianMAC)}, arp...)
	return gatewayAgent("FortiGate-600F", "", rows,
		gwAddr{fortiGW, "255.255.0.0", 33}, gwAddr{"172.17.1.1", "255.255.252.0", 52})
}

// debianGateway answers like 172.20.1.254: its ARP table lists the
// FortiGate, then the extra rows; 172.20.1.254/16, 10.20.5.1/16 and the
// loopback.
func debianGateway(arp ...string) map[string][]string {
	rows := append([]string{arpRow(2, fortiGW, fortiMAC)}, arp...)
	return gatewayAgent("debian216", "Linux debian216 6.12.101+deb13-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.12.101-1 (2026-08-05) x86_64", rows,
		gwAddr{debianGW, "255.255.0.0", 2}, gwAddr{"10.20.5.1", "255.255.0.0", 65}, gwAddr{"127.0.0.1", "255.0.0.0", 1})
}

// TestParseGatewayIPs checks the gateway_ip format: one IP as before, or
// several, one per line or separated by spaces or commas, with '#'
// comments; repeats once, words that are no IPv4 address reported.
func TestParseGatewayIPs(t *testing.T) {
	bom := string(rune(0xFEFF))
	both := []string{debianGW, fortiGW}
	for _, c := range []struct {
		name, text   string
		ips, invalid []string
	}{
		{"one IP (the file of today)", "172.20.1.254\n", []string{debianGW}, nil},
		{"one IP without a newline", "172.20.1.254", []string{debianGW}, nil},
		{"one per line", "172.20.1.254\n172.20.0.1\n", both, nil},
		{"spaces", "172.20.1.254 172.20.0.1", both, nil},
		{"commas", "172.20.1.254,172.20.0.1", both, nil},
		{"mixed separators", " 172.20.1.254 ,\t172.20.0.1; 10.20.5.1 \n", []string{debianGW, fortiGW, "10.20.5.1"}, nil},
		{"comments", "# core first\n172.20.1.254   # debian216\n\n172.20.0.1#FortiGate-600F\n# 172.20.9.9\n", both, nil},
		{"repeats", "172.20.1.254\n172.20.0.1, 172.20.1.254\n", both, nil},
		{"CRLF and byte order mark", bom + "172.20.1.254\r\n172.20.0.1\r\n", both, nil},
		{"order is kept", "172.20.0.1\n172.20.1.254\n", []string{fortiGW, debianGW}, nil},
		{"not IPv4", "172.20.1.254/16 gw.tuit.local 172.20.0.1 fe80::1 256.1.1.1 172.020.1.1",
			[]string{fortiGW}, []string{"172.20.1.254/16", "gw.tuit.local", "fe80::1", "256.1.1.1", "172.020.1.1"}},
		{"empty", "", nil, nil},
		{"comments only", "# no gateway yet\n\n", nil, nil},
	} {
		ips, invalid := parseGatewayIPs(c.text)
		if !slices.Equal(ips, c.ips) || !slices.Equal(invalid, c.invalid) {
			t.Errorf("%s: parseGatewayIPs(%q) = %q, invalid %q; want %q, invalid %q", c.name, c.text, ips, invalid, c.ips, c.invalid)
		}
	}
}

// TestLoadGatewayIPs checks the file reader: gatewayIP is the first entry
// (the analyzer's core) and gatewayIPs all of them; a missing file or one
// without an IPv4 address keeps what was loaded, with a warning.
func TestLoadGatewayIPs(t *testing.T) {
	resetState(t)
	t.Cleanup(func() { setGatewayIPs([]string{fixedGatewayIP}) })
	dir := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return path
	}
	check := func(step string, wantIPs []string) {
		t.Helper()
		if gatewayIP != wantIPs[0] || !slices.Equal(gatewayIPs, wantIPs) {
			t.Errorf("%s: gatewayIP %q, gatewayIPs %q; want %q, %q", step, gatewayIP, gatewayIPs, wantIPs[0], wantIPs)
		}
	}

	out := captureStdout(t, func() { loadGatewayIPs(write("one", "172.20.1.254\n")) })
	check("one IP", []string{debianGW})
	if !strings.Contains(out, "Gateway IP yuklandi: 172.20.1.254\n") {
		t.Errorf("one IP: printed %q", out)
	}

	out = captureStdout(t, func() { loadGatewayIPs(write("two", "172.20.1.254 # debian216\n172.20.0.1 # FortiGate\n")) })
	check("two IPs", []string{debianGW, fortiGW})
	if !strings.Contains(out, "172.20.1.254, 172.20.0.1 (core: 172.20.1.254)") {
		t.Errorf("two IPs: printed %q", out)
	}

	out = captureStdout(t, func() { loadGatewayIPs(write("bad", "gw.tuit.local, 172.20.0.0/16\n")) })
	check("no IPv4 address", []string{debianGW, fortiGW})
	if !strings.Contains(out, "gw.tuit.local, 172.20.0.0/16") || !strings.Contains(out, "bo'sh") {
		t.Errorf("no IPv4 address: printed %q", out)
	}

	out = captureStdout(t, func() { loadGatewayIPs(filepath.Join(dir, "missing")) })
	check("missing file", []string{debianGW, fortiGW})
	if !strings.Contains(out, "topilmadi") {
		t.Errorf("missing file: printed %q", out)
	}
}

// TestGatewayARPEveryGateway checks the ARP collection of every gateway, at
// startup (collectGatewayARP) and in the MAC-IP sweep: both tables merge
// with the one policy (last write wins, in gateway_ip order), each
// gateway's sysName is noted for its router node, a gateway that does not
// answer is warned about once per start however many sweeps run, the SVI
// IPs of every gateway that answered are walked, and cache entries expire
// only once every gateway answered (TestGatewayExpiryPerGateway).
func TestGatewayARPEveryGateway(t *testing.T) {
	resetState(t)
	collectResetCache(t)
	macIPCacheFile = filepath.Join(t.TempDir(), "mac_ip_cache.json")
	const shared, silent = "00:1b:21:40:00:01", "172.20.40.254"
	fakeSNMP.set(debianGW, debianGateway(arpRow(2, "172.20.40.1", shared), arpRow(2, "172.20.40.2", "00:1b:21:40:00:02")))
	fakeSNMP.set(fortiGW, fortiGateGateway(arpRow(33, "172.20.40.11", shared), arpRow(33, "172.20.40.3", "00:1b:21:40:00:03")))
	fakeSNMP.set("172.17.1.1", map[string][]string{oidARP: {arpRow(52, "172.17.1.9", "00:1b:21:40:00:09")}}) // a FortiGate SVI
	setGatewayIPs([]string{debianGW, fortiGW, silent})

	out := captureStdout(t, collectGatewayARP)
	want := map[string]string{
		fortiMAC: fortiGW, debianMAC: debianGW, // each gateway's MAC from the other one's table
		shared:              "172.20.40.11", // the FortiGate comes after the Debian in gateway_ip
		"00:1b:21:40:00:02": "172.20.40.2",
		"00:1b:21:40:00:03": "172.20.40.3",
	}
	if got := collectCacheMap(); !maps.Equal(got, want) {
		t.Errorf("after the startup gateway ARP: cache %v, want %v", got, want)
	}
	if got, want := answeredGateways(), []gatewayNode{{IP: debianGW, SysName: "debian216"}, {IP: fortiGW, SysName: "FortiGate-600F"}}; !slices.Equal(got, want) {
		t.Errorf("answered gateways %+v, want %+v", got, want)
	}
	for _, ip := range []string{debianGW, fortiGW} {
		if !strings.Contains(out, "Collected 3 ARP entries from gateway "+ip) {
			t.Errorf("startup log lacks the ARP count of %s:\n%s", ip, out)
		}
	}

	// Two sweeps: no second warning; the FortiGate's SVI 172.17.1.1 is
	// walked; an entry not seen for 10 days stays while the third gateway
	// has not answered (it may be one of its hosts, F1 of the review), and
	// expires once all three answered
	globalMACtoIPMutex.Lock()
	globalMACtoIP["00:1b:21:40:00:99"] = "172.20.40.99"
	collectMACIPSeen["00:1b:21:40:00:99"] = testClock.Now().Add(-10 * 24 * time.Hour)
	globalMACtoIPMutex.Unlock()
	out += captureStdout(t, func() {
		collectARPFromAllSwitches()
		testClock.advance(5 * time.Minute)
		collectARPFromAllSwitches()
	})
	if n := strings.Count(out, "did not answer the SNMP ARP walk"); n != 1 || !strings.Contains(out, "Gateway "+silent+" did not answer") {
		t.Errorf("want one warning, naming %s, got %d in:\n%s", silent, n, out)
	}
	want["00:1b:21:40:00:09"] = "172.17.1.9"
	want["00:1b:21:40:00:99"] = "172.20.40.99"
	if got := collectCacheMap(); !maps.Equal(got, want) {
		t.Errorf("after the sweeps: cache %v, want %v (the SVI's entry added, the 10-day-old entry kept)", got, want)
	}
	fakeSNMP.set(silent, map[string][]string{oidARP: {arpRow(7, "172.20.40.250", "00:1b:21:40:00:fa")}})
	captureStdout(t, collectARPFromAllSwitches)
	delete(want, "00:1b:21:40:00:99")
	want["00:1b:21:40:00:fa"] = "172.20.40.250"
	if got := collectCacheMap(); !maps.Equal(got, want) {
		t.Errorf("once every gateway answered: cache %v, want %v (the 10-day-old entry expired)", got, want)
	}

	// The order of gateway_ip decides which row of a MAC both list wins
	setGatewayIPs([]string{fortiGW, debianGW})
	collectGatewayARP()
	if got := collectCacheMap()[shared]; got != "172.20.40.1" {
		t.Errorf("FortiGate first, then the Debian: %s maps to %s, want the Debian's 172.20.40.1", shared, got)
	}
}

// TestGatewaySVISilentRetry checks the SVI walks of the sweep. The
// FortiGate answers SNMP on 172.20.0.1 only (172.17.1.1, 172.16.0.1,
// 10.255.1.1 and 192.168.0.254 timed out on 2026-10-22), so an SVI IP that
// does not answer is left out of the sweeps for an hour instead of costing
// a timeout in each, with one line per start; one that answers is walked
// in every sweep, and the SVI list is logged once per start.
func TestGatewaySVISilentRetry(t *testing.T) {
	resetState(t)
	collectResetCache(t)
	macIPCacheFile = filepath.Join(t.TempDir(), "mac_ip_cache.json")
	forti := fortiGateGateway()
	forti[oidIPAdEntIfIndex] = append(forti[oidIPAdEntIfIndex], oidIPAdEntIfIndex+".172.16.0.1 = INTEGER: 41")
	fakeSNMP.set(fortiGW, forti)
	fakeSNMP.set("172.17.1.1", map[string][]string{oidARP: {arpRow(52, "172.17.1.9", "00:1b:21:40:00:09")}})
	setGatewayIPs([]string{fortiGW}) // 172.16.0.1 has no agent: it does not answer

	var counts []map[string]int
	out := captureStdout(t, func() {
		for _, after := range []time.Duration{0, 5 * time.Minute, 56 * time.Minute} {
			testClock.advance(after)
			fakeSNMP.walkCounts()
			collectARPFromAllSwitches()
			counts = append(counts, fakeSNMP.walkCounts())
		}
	})
	silent, answering := "172.16.0.1 "+oidARP, "172.17.1.1 "+oidARP
	for i, want := range [][2]int{{1, 1}, {0, 1}, {1, 1}} { // at 0, 5 and 61 minutes
		if got := [2]int{counts[i][silent], counts[i][answering]}; got != want {
			t.Errorf("sweep %d: ARP walks of the silent and the answering SVI %v, want %v", i+1, got, want)
		}
	}
	if n := strings.Count(out, "Gateway SVI 172.16.0.1 does not answer SNMP"); n != 1 {
		t.Errorf("%d lines about the silent SVI, want 1:\n%s", n, out)
	}
	if n := strings.Count(out, "Found gateway SVI IP: 172.17.1.1"); n != 1 {
		t.Errorf("the SVI was logged %d times in three sweeps, want once:\n%s", n, out)
	}
	if got := collectCacheMap()["00:1b:21:40:00:09"]; got != "172.17.1.9" {
		t.Errorf("the answering SVI's entry maps to %q", got)
	}
}

// TestGatewayARPNoGatewayAnswers checks the expiry rule with several
// gateways: while none of them answers, no entry expires however old, and
// each one is warned about once per start.
func TestGatewayARPNoGatewayAnswers(t *testing.T) {
	resetState(t)
	collectResetCache(t)
	macIPCacheFile = filepath.Join(t.TempDir(), "mac_ip_cache.json")
	setGatewayIPs([]string{"172.20.41.1", "172.20.41.2"})
	globalMACtoIPMutex.Lock()
	globalMACtoIP["00:1b:21:41:00:01"] = "172.20.41.11"
	collectMACIPSeen["00:1b:21:41:00:01"] = testClock.Now().Add(-30 * 24 * time.Hour)
	globalMACtoIPMutex.Unlock()
	out := captureStdout(t, func() {
		collectGatewayARP()
		collectARPFromAllSwitches()
		collectARPFromAllSwitches()
	})
	if got := collectCacheMap(); len(got) != 1 {
		t.Errorf("cache %v: an entry expired although no gateway answered", got)
	}
	for _, ip := range []string{"172.20.41.1", "172.20.41.2"} {
		if n := strings.Count(out, "Gateway "+ip+" did not answer the SNMP ARP walk"); n != 1 {
			t.Errorf("%d warnings about %s, want 1:\n%s", n, ip, out)
		}
	}
	if got := answeredGateways(); len(got) != 0 {
		t.Errorf("answered gateways %+v, want none", got)
	}
}

// TestGatewayExpiryPerGateway (F1 of the gateway review) checks the cache
// expiry with one silent and one answering gateway. The two route
// different subnets, so the FortiGate's answers say nothing about a host
// only the Debian knows: while the Debian has not answered in this run no
// entry expires; once both answered, an entry neither shows expires; when
// the Debian falls silent again, its host does not expire however long
// the FortiGate keeps answering, and it does once the Debian answers
// without it.
func TestGatewayExpiryPerGateway(t *testing.T) {
	resetState(t)
	collectResetCache(t)
	macIPCacheFile = filepath.Join(t.TempDir(), "mac_ip_cache.json")
	const debianOnly, gone, fortiOnly = "00:1b:21:42:00:01", "00:1b:21:42:00:02", "00:1b:21:42:00:03"
	setGatewayIPs([]string{debianGW, fortiGW})
	fakeSNMP.set(fortiGW, fortiGateGateway(arpRow(41, "172.16.4.20", fortiOnly)))
	globalMACtoIPMutex.Lock()
	globalMACtoIP[debianOnly] = "10.20.4.1" // a host of the Debian's 10.20.0.0/16
	globalMACtoIP[gone] = "10.20.4.2"
	collectMACIPSeen[debianOnly] = testClock.Now().Add(-8 * 24 * time.Hour)
	collectMACIPSeen[gone] = testClock.Now().Add(-8 * 24 * time.Hour)
	globalMACtoIPMutex.Unlock()
	cached := func(mac string) bool { _, ok := collectCacheMap()[mac]; return ok }
	sweep := func(after time.Duration) {
		testClock.advance(after)
		captureStdout(t, collectARPFromAllSwitches)
	}

	sweep(0) // the Debian does not answer
	if !cached(debianOnly) || !cached(gone) {
		t.Errorf("an entry expired while the Debian had not answered: %v", collectCacheMap())
	}
	fakeSNMP.set(debianGW, debianGateway(arpRow(65, "10.20.4.1", debianOnly)))
	sweep(5 * time.Minute)
	if !cached(debianOnly) || cached(gone) || !cached(fortiOnly) {
		t.Errorf("both gateways answered: cache %v, want the 8-day-old entry neither shows expired", collectCacheMap())
	}
	fakeSNMP.set(debianGW, nil) // the Debian falls silent, the FortiGate answers for 8 days
	sweep(4 * 24 * time.Hour)
	sweep(4 * 24 * time.Hour)
	if !cached(debianOnly) {
		t.Errorf("the Debian's host expired while the Debian was silent: %v", collectCacheMap())
	}
	fakeSNMP.set(debianGW, debianGateway()) // it answers again, without the host
	sweep(5 * time.Minute)
	if cached(debianOnly) || !cached(fortiOnly) {
		t.Errorf("the Debian answered without its host 8 days after it last showed it: cache %v, want it expired", collectCacheMap())
	}
}

// TestGatewaySVIMergeOrder (F3 of the gateway review) checks the merge
// order of the sweeps with the live Debian, which answers SNMP on its other
// addresses too. The Debian and the FortiGate map one MAC to different
// IPs: after the startup walk and after every sweep it maps to the
// FortiGate's IP (the later gateway), because each gateway's SVIs merge
// right after it and each MAC is merged once per sweep. A sweep logs only
// real changes (it used to flip the MAC twice per sweep and log both), an
// SVI that answers with its gateway's own table is left out for an hour,
// and an SVI with rows of its own is walked in every sweep.
func TestGatewaySVIMergeOrder(t *testing.T) {
	resetState(t)
	collectResetCache(t)
	macIPCacheFile = filepath.Join(t.TempDir(), "mac_ip_cache.json")
	const shared, own = "00:1b:21:43:00:01", "00:1b:21:43:00:02"
	debian := gatewayAgent("debian216", "Linux debian216", []string{arpRow(2, fortiGW, fortiMAC), arpRow(2, "172.20.43.1", shared)},
		gwAddr{debianGW, "255.255.0.0", 2}, gwAddr{"10.20.5.1", "255.255.0.0", 65}, gwAddr{"192.168.0.213", "255.255.255.0", 2})
	fakeSNMP.set(debianGW, debian)
	fakeSNMP.set("10.20.5.1", debian) // the same agent on another address
	// An SVI with a table of its own
	fakeSNMP.set("192.168.0.213", map[string][]string{oidARP: {arpRow(2, "172.20.43.1", shared), arpRow(2, "192.168.0.50", own)}})
	fakeSNMP.set(fortiGW, fortiGateGateway(arpRow(33, "172.20.43.11", shared)))
	fakeSNMP.set("172.17.1.1", map[string][]string{oidARP: {arpRow(52, "172.17.1.9", "00:1b:21:43:00:09")}})
	setGatewayIPs([]string{debianGW, fortiGW})

	captureStdout(t, collectGatewayARP)
	if got := collectCacheMap()[shared]; got != "172.20.43.11" {
		t.Fatalf("after the startup walk %s maps to %s, want the FortiGate's 172.20.43.11", shared, got)
	}
	var outs []string
	var walks [][3]int
	for _, after := range []time.Duration{0, 5 * time.Minute, 5 * time.Minute, 51 * time.Minute} {
		testClock.advance(after)
		fakeSNMP.walkCounts()
		outs = append(outs, captureStdout(t, collectARPFromAllSwitches))
		c := fakeSNMP.walkCounts()
		walks = append(walks, [3]int{c["10.20.5.1 "+oidARP], c["192.168.0.213 "+oidARP], c["172.17.1.1 "+oidARP]})
		if got := collectCacheMap()[shared]; got != "172.20.43.11" {
			t.Errorf("after sweep %d %s maps to %s, want the FortiGate's 172.20.43.11", len(outs), shared, got)
		}
	}
	if want := [][3]int{{1, 1, 1}, {0, 1, 1}, {0, 1, 1}, {1, 1, 1}}; !slices.Equal(walks, want) {
		t.Errorf("ARP walks of the SVIs 10.20.5.1, 192.168.0.213 and 172.17.1.1 at 0, 5, 10 and 61 minutes: %v, want %v", walks, want)
	}
	for i, out := range outs {
		var changes []string
		for _, line := range strings.Split(out, "\n") {
			if strings.Contains(line, " new/changed MAC-IP entries") {
				changes = append(changes, line)
			}
		}
		var want []string
		if i == 0 {
			want = []string{"🌐 [MacIPService] Gateway SVI 192.168.0.213: +1 new/changed MAC-IP entries",
				"🌐 [MacIPService] Gateway SVI 172.17.1.1: +1 new/changed MAC-IP entries"}
		}
		if !slices.Equal(changes, want) {
			t.Errorf("sweep %d logged changes %q, want %q", i+1, changes, want)
		}
	}
	if n := strings.Count(strings.Join(outs, ""), "Gateway SVI 10.20.5.1 answers with the ARP table of gateway 172.20.1.254"); n != 1 {
		t.Errorf("%d lines about the SVI that repeats the Debian's table, want 1", n)
	}
}

// TestSweepWalksEachIPOnce checks how the gateways meet the ARP sources of
// the swich_ips ranges (addARPSource): a configured gateway is an ARP
// source by definition, so the rescue scan that rejects it (the FortiGate
// is in the ranges) does not add it to the registry, while another router
// of the ranges and an SVI address of the Debian that answers SNMP are
// added; and one sweep walks every IP once, whatever lists it twice: a
// gateway that is also stored, an SVI that is also a registry entry.
func TestSweepWalksEachIPOnce(t *testing.T) {
	resetState(t)
	collectResetCache(t)
	macIPCacheFile = filepath.Join(t.TempDir(), "mac_ip_cache.json")
	const router, sw, svi = "10.9.51.1", "10.9.51.2", "10.20.5.1"
	fakeSNMP.set(debianGW, debianGateway(arpRow(2, "10.9.51.40", "00:1b:21:51:00:40")))
	fakeSNMP.set(svi, debianGateway(arpRow(2, "10.9.51.40", "00:1b:21:51:00:40"))) // the Debian answers on its SVI too
	fakeSNMP.set(fortiGW, fortiGateGateway())                                      // its SVI 172.17.1.1 does not answer
	fakeSNMP.set(router, linuxRouterAgent())
	fakeSNMP.set(sw, bridgeSwitchAgent(24))
	setGatewayIPs([]string{debianGW, fortiGW})
	alive := func(ip string) bool { return slices.Contains([]string{fortiGW, router, sw, svi}, ip) }

	captureStdout(t, func() { rescueScan(newRescanSNMPObject(), []string{fortiGW, router, sw, svi}, alive) })
	if got, want := arpSourceIPs(), []string{router, svi}; !slices.Equal(got, want) {
		t.Errorf("ARP sources %v, want %v (the gateway is none)", got, want)
	}
	if got := collectedIPs(); !slices.Equal(got, []string{sw}) {
		t.Fatalf("collectedData %v, want the switch only", got)
	}
	// The FortiGate stored by an older build (2026-10-22): a device and a gateway
	collectedDataMutex.Lock()
	collectedData[fortiGW] = &DeviceData{IP: fortiGW, SysName: "FortiGate-600F"}
	collectedDataMutex.Unlock()

	fakeSNMP.walkCounts()
	captureStdout(t, collectARPFromAllSwitches)
	arpWalks := map[string]int{}
	for key, n := range fakeSNMP.walkCounts() {
		if ip, oid, _ := strings.Cut(key, " "); oid == oidARP {
			arpWalks[ip] = n
		}
	}
	want := map[string]int{debianGW: 1, fortiGW: 1, svi: 1, "172.17.1.1": 1, sw: 1, router: 1}
	if !maps.Equal(arpWalks, want) {
		t.Errorf("ARP walks of one sweep %v, want each IP once: %v", arpWalks, want)
	}
}

// TestSubnetDiscoveryEveryGateway checks that subnet discovery reads the
// ipAddrTable of every gateway: a subnet both gateways have is searched
// once and each of its IPs probed once, the subnet only the second gateway
// has is searched too and its WAN subnet is not, only switches are
// appended (checkSwitch), and the gateways and their addresses are never
// probed, although the FortiGate's MACs are a network maker's.
func TestSubnetDiscoveryEveryGateway(t *testing.T) {
	resetState(t)
	const debianLike, fortiLike = "10.9.45.1", "10.9.45.2"
	fakeSNMP.set(debianLike, gatewayAgent("debian216", "Linux debian216", nil,
		gwAddr{debianLike, "255.255.255.240", 2}, gwAddr{"127.0.0.1", "255.0.0.0", 1}))
	fakeSNMP.set(fortiLike, gatewayAgent("FortiGate-600F", "", nil,
		gwAddr{fortiLike, "255.255.255.240", 33}, gwAddr{"10.9.46.1", "255.255.255.240", 52}, gwAddr{"195.158.2.221", "255.255.255.224", 40}))
	fakeSNMP.set("10.9.45.5", bridgeSwitchAgent(24))
	fakeSNMP.set("10.9.45.6", accessPointAgent("C46"))
	fakeSNMP.set("10.9.46.5", lldpSwitchAgent(0x46))
	fakeSNMP.set("10.9.46.6", esxiAgent())
	fakeSNMP.set("195.158.2.193", lldpSwitchAgent(0xc1)) // the ISP's router: the WAN is not searched
	setGatewayIPs([]string{debianLike, fortiLike})
	setARPCache(map[string]string{
		debianMAC:           debianLike,      // a VMware VM
		"84:39:8f:2d:00:02": fortiLike,       // Fortinet: a maker's MAC, but a gateway
		"84:39:8f:2e:00:01": "10.9.46.1",     // the FortiGate's other address
		"00:e0:fc:2d:00:05": "10.9.45.5",     // Huawei
		"18:e8:29:2d:00:06": "10.9.45.6",     // Ubiquiti
		"4c:ae:a3:2e:00:05": "10.9.46.5",     // HPE
		"5c:ed:8c:2e:00:06": "10.9.46.6",     // HPE: the ESXi host's NIC
		"00:1a:a1:c3:02:c1": "195.158.2.193", // Cisco
	})
	switchIPAdds.taken()

	var added []string
	out := captureStdout(t, func() {
		added = subnetDiscovery(&SNMPObject{Community: "public", Port: 161}, nil, subnetDiscoveryDefaults, appendSwitchIP)
	})
	if want := []string{"10.9.45.5", "10.9.46.5"}; !slices.Equal(added, want) {
		t.Errorf("added %v, want %v", added, want)
	}
	if got := switchIPAdds.taken(); !slices.Equal(got, []string{"10.9.45.5", "10.9.46.5"}) {
		t.Errorf("appended to swich_ips: %v", got)
	}
	if got, want := sortedStrings(snmpProbes.taken()), []string{"10.9.45.5", "10.9.45.6", "10.9.46.5", "10.9.46.6"}; !slices.Equal(got, want) {
		t.Errorf("probed %v, want each candidate once and no gateway or WAN address: %v", got, want)
	}
	want := "🔍 [SubnetDisc] 2 subnets of 10.9.45.1, 10.9.45.2 (1 left out: 195.158.2.192/27 not private), 7 ARP-known IPs in them, " +
		"6 with a network-equipment maker's MAC (2 of them stored, a gateway's address or in swich_ips), 4 probed, " +
		"2 switches added: 10.9.45.5, 10.9.46.5; not added: 2 devices without BRIDGE-MIB ports or lldpLocChassisId (no switch): " +
		"10.9.45.6 (C46, U6-Pro 6.8.2.15592), 10.9.46.6 (localhost, VMware ESXi 6.5.0 build-4887370 VMware, Inc. x86_64)\n"
	if out != want {
		t.Errorf("output =\n%s\nwant\n%s", out, want)
	}
}

// tenGigPorts are interfaces first..last named like the HPE uplinks.
func tenGigPorts(first, last int) []InterfaceData {
	var out []InterfaceData
	for i := first; i <= last; i++ {
		out = append(out, InterfaceData{IfIndex: i, IfDescr: fmt.Sprintf("\"Ten-GigabitEthernet1/0/%d\"", i), IfSpeed: 10000000000, IfOperStatus: 1})
	}
	return out
}

const (
	gwNetCore  = "10.9.48.2" // sw-core
	gwNetAcc   = "10.9.48.3" // sw-acc
	gwNetVM    = "10.9.48.253"
	gwNetVMMAC = "00:0c:29:48:07:fd" // a router VM on an ESXi host of sw-acc
)

// gatewayNetwork is a small network laid out like the live one: the
// FortiGate is the only MAC on sw-core Ten-GigabitEthernet1/0/52 and sends
// LLDP there with its chassis MAC; the Debian router VM sits on the ESXi
// host of sw-core GigabitEthernet1/0/10, whose NIC sends LLDP (so the VMs
// of that port get no FDB nodes); a third gateway, a router VM, sits with
// two other VMs on the ESXi host of sw-acc GigabitEthernet1/0/7 (a VM port:
// the VMs are FDB endpoints). The uplink of sw-acc learns sw-core and both
// gateways, and fewer MACs than the Debian's ESXi port: a transit port, so
// no router node is linked from it. The switches' ARP tables know the
// gateways.
func gatewayNetwork() map[string]*DeviceData {
	const coreMAC, accMAC = "4c:ae:a3:48:00:02", "4c:ae:a3:48:00:03"
	ports := func() []InterfaceData { return append(gigabitPorts(48, nil), tenGigPorts(49, 52)...) }
	core := &DeviceData{
		IP: gwNetCore, SysName: "sw-core", ChassisID: coreMAC, Interfaces: ports(),
		PortVLANs: []PortVLAN{{PortIndex: 10, PVID: 1, IsTrunk: true}, {PortIndex: 49, PVID: 1, IsTrunk: true}, {PortIndex: 52, PVID: 1, IsTrunk: true}},
		Neighbors: []LLDPNeighbor{
			{LocalPortNum: 52, RemIndex: 1, RemChassisIdSubtype: 4, RemChassisId: "68 CC AE 96 E5 E8", RemPortIdSubtype: 1, RemPortId: "\"LAN\"",
				RemSysName: "FortiGate-600F", RemSysDesc: "FortiGate-600F v7.4.12,build2902,260505 (GA.M)"},
			{LocalPortNum: 10, RemIndex: 2, RemChassisIdSubtype: 4, RemChassisId: "6C B3 11 48 00 10", RemPortIdSubtype: 3, RemPortId: "6C B3 11 48 00 10"},
			{LocalPortNum: 49, RemIndex: 3, RemChassisIdSubtype: 4, RemChassisId: "4C AE A3 48 00 03", RemPortIdSubtype: 5, RemPortId: "\"Ten-GigabitEthernet1/0/49\"", RemSysName: "sw-acc"},
		},
		MACTable: slices.Concat(
			macEntries(52, fortiMAC),
			macEntries(10, debianMAC, "00:0c:29:48:00:0a", "00:0c:29:48:00:0b", "00:50:56:48:00:0c"),
			macEntries(49, accMAC, "00:1b:21:48:05:01", "00:0c:29:48:07:01", "00:0c:29:48:07:02", gwNetVMMAC),
		),
		ARPTable: []ARPEntry{{IPAddress: debianGW, MACAddress: debianMAC, Interface: 636}, {IPAddress: fortiGW, MACAddress: fortiMAC, Interface: 636}},
	}
	acc := &DeviceData{
		IP: gwNetAcc, SysName: "sw-acc", ChassisID: accMAC, Interfaces: ports(),
		PortVLANs: []PortVLAN{{PortIndex: 49, PVID: 1, IsTrunk: true}},
		Neighbors: []LLDPNeighbor{
			{LocalPortNum: 49, RemIndex: 1, RemChassisIdSubtype: 4, RemChassisId: "4C AE A3 48 00 02", RemPortIdSubtype: 5, RemPortId: "\"Ten-GigabitEthernet1/0/49\"", RemSysName: "sw-core"},
		},
		MACTable: slices.Concat(
			macEntries(49, coreMAC, fortiMAC, debianMAC),
			macEntries(5, "00:1b:21:48:05:01"),
			macEntries(7, "00:0c:29:48:07:01", "00:0c:29:48:07:02", gwNetVMMAC),
		),
		ARPTable: []ARPEntry{{IPAddress: debianGW, MACAddress: debianMAC, Interface: 636}, {IPAddress: gwNetVM, MACAddress: gwNetVMMAC, Interface: 636}},
	}
	return map[string]*DeviceData{core.IP: core, acc.IP: acc}
}

// gatewayNetworkUp loads gatewayNetwork into collectedData, and fake agents
// for the Debian, the FortiGate, the router VM and a gateway whose IP no
// ARP table knows; gateway_ip lists all four, and the startup gateway ARP
// reads them.
func gatewayNetworkUp(t *testing.T) {
	t.Helper()
	resetState(t)
	collectResetCache(t)
	collectedDataMutex.Lock()
	collectedData = gatewayNetwork()
	collectedDataMutex.Unlock()
	fakeSNMP.set(debianGW, debianGateway())
	fakeSNMP.set(fortiGW, fortiGateGateway())
	fakeSNMP.set(gwNetVM, gatewayAgent("vyos", "VyOS 1.4", nil))
	fakeSNMP.set("10.9.48.250", gatewayAgent("gw-unknown", "", nil))
	setGatewayIPs([]string{debianGW, fortiGW, gwNetVM, "10.9.48.250"})
	captureStdout(t, collectGatewayARP)
}

// gatewayNodeLines returns the nodes whose label has ip as a line.
func gatewayNodeLines(g *DJGraph, ip string) []string {
	var ids []string
	for _, id := range slices.Sorted(maps.Keys(g.Nodes)) {
		if slices.Contains(strings.Split(g.SwitchInfo[id], "\n"), ip) {
			ids = append(ids, id)
		}
	}
	return ids
}

// TestGatewayRouterNodes checks the router node of every gateway that
// answers SNMP: its id is the MAC from the ARP data, its label the sysName
// and the IP, its group router; it is linked from the port where its MAC is
// learned with the fewest MACs and no other switch or gateway MAC (the
// MAC-REF rule), takes the place of the FortiGate's LLDP node on that port
// and of an FDB node of its MAC, and no node has a gateway IP as id. The
// first gateway's router node is the core. A gateway whose MAC is unknown
// gets no node and one log line.
func TestGatewayRouterNodes(t *testing.T) {
	gatewayNetworkUp(t)
	// Neither gateway is a switch, and their walks stored no device: they
	// are drawn because gateway_ip names them
	obj := &SNMPObject{Community: "public", Port: 161}
	for _, ip := range []string{debianGW, fortiGW} {
		if check := obj.checkSwitch(ip); check.isSwitch() || !check.Answered {
			t.Errorf("checkSwitch(%s) = %+v, want an answering agent that is no switch", ip, check)
		}
	}
	if got := collectedIPs(); !slices.Equal(got, []string{gwNetCore, gwNetAcc}) {
		t.Errorf("collectedData after the gateway walks = %v, want the two switches only", got)
	}
	// An older IP of the router VM's MAC in the cache: the label keeps the
	// gateway's IP only (enrichGraphWithIPs leaves router nodes alone)
	globalMACtoIPMutex.Lock()
	globalMACtoIP[gwNetVMMAC] = "10.9.48.99"
	globalMACtoIPMutex.Unlock()
	var g *DJGraph
	out := captureStdout(t, func() {
		g = buildGraphFromSnapshot(snapshotCollectedData())
		buildGraphFromSnapshot(snapshotCollectedData()) // a second build logs nothing new
	})

	data := g.GetGraphData()
	nodes := map[string]GraphNode{}
	for _, n := range data.Nodes {
		nodes[n.ID] = n
	}
	for _, c := range []struct{ ip, mac, label string }{
		{debianGW, debianMAC, "debian216\n" + debianGW},
		{fortiGW, fortiMAC, "FortiGate-600F\n" + fortiGW},
		{gwNetVM, gwNetVMMAC, "vyos\n" + gwNetVM},
	} {
		n, ok := nodes[c.mac]
		if !ok || n.Group != "router" || n.NodeType != "router" || n.SysName != c.label || g.determineDeviceGroup(c.mac, g.SwitchInfo[c.mac]) != "router" {
			t.Errorf("gateway %s: node %+v (present %v), want a router node %s labelled %q", c.ip, n, ok, c.mac, c.label)
		}
		if ids := gatewayNodeLines(g, c.ip); !slices.Equal(ids, []string{c.mac}) {
			t.Errorf("gateway %s: nodes with its IP as a label line %v, want only %s", c.ip, ids, c.mac)
		}
		if g.Nodes[c.ip] {
			t.Errorf("gateway %s has a node with its IP as id", c.ip)
		}
	}

	// The links: the FortiGate keeps the LLDP link of the node it replaced,
	// the Debian gets a MAC-REF link from the ESXi port (its VMs get no FDB
	// nodes there, the port has an LLDP neighbor), the router VM keeps the
	// FDB link of its VM port and is no VM of the hypervisor node there.
	links := map[string]string{}
	for _, l := range data.Links {
		if g.graphRouters[l.Source] || g.graphRouters[l.Target] {
			links[l.Source+" -> "+l.Target] = l.Label
		}
	}
	wantLinks := map[string]string{
		"4c:ae:a3:48:00:02 -> " + fortiMAC:   "TGE1/0/52 [T] 10G|LAN",
		"4c:ae:a3:48:00:02 -> " + debianMAC:  "GE1/0/10 [MAC-REF]|",
		"4c:ae:a3:48:00:03 -> " + gwNetVMMAC: "GE1/0/7|",
	}
	if !maps.Equal(links, wantLinks) {
		t.Errorf("router links %v, want %v", links, wantLinks)
	}
	if g.Nodes[fortiLLDP] {
		t.Errorf("the FortiGate's LLDP node %s is still drawn next to its router node", fortiLLDP)
	}
	hyp := "hyp-4c:ae:a3:48:00:03-ge1_0_7"
	if !g.Nodes[hyp] || !strings.Contains(g.SwitchInfo[hyp], "2 VMs") || g.Edges[hyp][gwNetVMMAC] != "" {
		t.Errorf("hypervisor node %s: present %v, label %q, edges %v; want the 2 other VMs only", hyp, g.Nodes[hyp], g.SwitchInfo[hyp], g.Edges[hyp])
	}

	// The core is the first gateway's router node
	collectedDataMutex.RLock()
	core := topologyCore(nodes, collectedData)
	collectedDataMutex.RUnlock()
	if core != debianMAC {
		t.Errorf("core node %q, want the Debian router %s", core, debianMAC)
	}

	// The gateway whose MAC no ARP data knows: no node, one line
	if ids := gatewayNodeLines(g, "10.9.48.250"); len(ids) != 0 {
		t.Errorf("gateway with an unknown MAC drawn as %v", ids)
	}
	if n := strings.Count(out, "10.9.48.250 (gw-unknown) answered SNMP but its MAC is unknown"); n != 1 {
		t.Errorf("%d lines about the unknown MAC, want 1:\n%s", n, out)
	}
	if n := strings.Count(out, "drawn as router "+fortiMAC); n != 1 || !strings.Contains(out, "in place of node(s) "+fortiLLDP) {
		t.Errorf("want one placement line for the FortiGate naming the LLDP node it replaced:\n%s", out)
	}

	// Two builds give the same graph
	if a, b := viewGraph(g), viewGraph(buildGraphFromSnapshot(snapshotCollectedData())); !maps.Equal(a.Nodes, b.Nodes) || !slices.Equal(a.Edges, b.Edges) {
		t.Error("two builds of the same snapshot differ")
	}
}

// TestGatewayRouterNodeCases checks the other shapes of a gateway: one
// stored as a device before checkSwitch (its IP-id node gives way to the
// router node), one that stops answering (unreachable), two gateway IPs of
// one router (one node, both IPs), one that is a polled switch (drawn as
// that switch, which is the core), and the FortiGate advertising its IP as
// the LLDP management address on a port where its MAC is not learned.
func TestGatewayRouterNodeCases(t *testing.T) {
	t.Run("stored before checkSwitch", func(t *testing.T) {
		gatewayNetworkUp(t)
		// The rescue scan stored the FortiGate on 2026-10-22: no chassis id,
		// no FDB, no LLDP, its IF-MIB and ARP table
		collectedDataMutex.Lock()
		collectedData[fortiGW] = &DeviceData{IP: fortiGW, SysName: "FortiGate-600F", Interfaces: gigabitPorts(2, nil),
			ARPTable: []ARPEntry{{IPAddress: debianGW, MACAddress: debianMAC, Interface: 33}}}
		collectedDataMutex.Unlock()
		g := buildGraphFromSnapshot(snapshotCollectedData())
		if g.Nodes[fortiGW] || !g.graphRouters[fortiMAC] {
			t.Errorf("node %s drawn %v, router %s %v; want only the router node", fortiGW, g.Nodes[fortiGW], fortiMAC, g.graphRouters[fortiMAC])
		}
		if ids := gatewayNodeLines(g, fortiGW); !slices.Equal(ids, []string{fortiMAC}) {
			t.Errorf("nodes with %s as a label line: %v", fortiGW, ids)
		}
	})

	t.Run("stops answering", func(t *testing.T) {
		gatewayNetworkUp(t)
		fakeSNMP.set(fortiGW, nil)
		captureStdout(t, collectGatewayARP)
		g := buildGraphFromSnapshot(snapshotCollectedData())
		if !g.graphRouters[fortiMAC] || g.NodeStatus[fortiMAC] != "unreachable" || g.SwitchInfo[fortiMAC] != "FortiGate-600F\n"+fortiGW {
			t.Errorf("FortiGate after a failed walk: router %v, status %q, label %q; want an unreachable router node with its last sysName",
				g.graphRouters[fortiMAC], g.NodeStatus[fortiMAC], g.SwitchInfo[fortiMAC])
		}
		if g.NodeStatus[debianMAC] != "" {
			t.Errorf("the Debian router is %q, want reachable", g.NodeStatus[debianMAC])
		}
	})

	t.Run("two IPs of one router", func(t *testing.T) {
		gatewayNetworkUp(t)
		collectedDataMutex.Lock()
		core := collectedData[gwNetCore]
		core.ARPTable = append(slices.Clone(core.ARPTable), ARPEntry{IPAddress: "172.20.0.254", MACAddress: fortiMAC, Interface: 636})
		collectedDataMutex.Unlock()
		fakeSNMP.set("172.20.0.254", fortiGateGateway())
		setGatewayIPs([]string{debianGW, fortiGW, "172.20.0.254"})
		captureStdout(t, collectGatewayARP)
		g := buildGraphFromSnapshot(snapshotCollectedData())
		if got := g.SwitchInfo[fortiMAC]; got != "FortiGate-600F\n172.20.0.1\n172.20.0.254" {
			t.Errorf("label of the shared router node %q", got)
		}
		if ids := gatewayNodeLines(g, "172.20.0.254"); !slices.Equal(ids, []string{fortiMAC}) {
			t.Errorf("nodes with 172.20.0.254 as a label line: %v", ids)
		}
	})

	t.Run("a polled switch", func(t *testing.T) {
		gatewayNetworkUp(t)
		// sw-acc's ARP table has the MAC of sw-core's VLAN interface, not
		// its chassis MAC
		collectedDataMutex.Lock()
		acc := collectedData[gwNetAcc]
		acc.ARPTable = append(slices.Clone(acc.ARPTable), ARPEntry{IPAddress: gwNetCore, MACAddress: "4c:ae:a3:48:00:12", Interface: 1})
		collectedDataMutex.Unlock()
		fakeSNMP.set(gwNetCore, gatewayAgent("sw-core", "HPE Comware Platform Software", nil))
		setGatewayIPs([]string{gwNetCore, fortiGW})
		captureStdout(t, collectGatewayARP)
		g := buildGraphFromSnapshot(snapshotCollectedData())
		const coreMAC = "4c:ae:a3:48:00:02"
		if g.graphRouters[coreMAC] || !g.graphSwitches[coreMAC] || g.determineDeviceGroup(coreMAC, g.SwitchInfo[coreMAC]) != "switch" {
			t.Errorf("the gateway that is a polled switch: router %v, switch %v", g.graphRouters[coreMAC], g.graphSwitches[coreMAC])
		}
		if len(g.graphRouters) != 1 || !g.graphRouters[fortiMAC] {
			t.Errorf("router nodes %v, want only the FortiGate", g.graphRouters)
		}
		na := NewAnalyzer(captureData("gw", sortedDevices(snapshotCollectedData()), g))
		if core := na.coreNode(); core != coreMAC {
			t.Errorf("core %q, want the polled switch %s", core, coreMAC)
		}
	})

	t.Run("LLDP management address", func(t *testing.T) {
		gatewayNetworkUp(t)
		collectedDataMutex.Lock()
		acc := collectedData[gwNetAcc]
		// The FortiGate's second LAN port on sw-acc port 20: its MAC is not
		// learned there, but it advertises 172.20.0.1
		acc.Neighbors = append(slices.Clone(acc.Neighbors), LLDPNeighbor{LocalPortNum: 20, RemIndex: 2, RemChassisIdSubtype: 4,
			RemChassisId: "68 CC AE 96 E5 E9", RemPortIdSubtype: 1, RemPortId: "\"LAN2\"", RemSysName: "FortiGate-600F", RemMgmtIP: fortiGW})
		collectedDataMutex.Unlock()
		g := buildGraphFromSnapshot(snapshotCollectedData())
		if g.Nodes["68:cc:ae:96:e5:e9"] || g.Edges["4c:ae:a3:48:00:03"][fortiMAC] != "GE1/0/20 1G|LAN2" {
			t.Errorf("the second LLDP node: present %v; sw-acc edges %v", g.Nodes["68:cc:ae:96:e5:e9"], g.Edges["4c:ae:a3:48:00:03"])
		}
	})
}

// TestGatewayPortRule checks the port a router node is linked from (the
// MAC-REF rule): the gateway must be the only switch or gateway learned on
// the port (a switch by any of its own MACs, the switch itself not
// counted), and of those ports the one with the fewest MACs wins, then the
// first switch in IP order, then the lower port; NULL0 is never a port.
func TestGatewayPortRule(t *testing.T) {
	resetState(t)
	const gw, otherGW, sw2MAC = "00:1b:21:49:00:01", "00:1b:21:49:00:02", "4c:ae:a3:49:00:02"
	const sw1MAC, sw1Alias, sw2Alias = "4c:ae:a3:49:00:01", "4c:ae:a3:49:00:1b", "4c:ae:a3:49:00:1c"
	infra := map[string]string{gw: gw, otherGW: otherGW, sw2MAC: sw2MAC, sw2Alias: sw2MAC, sw1MAC: sw1MAC, sw1Alias: sw1MAC}
	dev := func(ip, chassis string, table ...[]MACEntry) *DeviceData {
		return &DeviceData{IP: ip, ChassisID: chassis, Interfaces: gigabitPorts(30, map[int]string{30: "NULL0"}), MACTable: slices.Concat(table...)}
	}
	cases := []struct {
		name     string
		snapshot map[string]*DeviceData
		ip       string
		port     int
		ok       bool
	}{
		{"fewest MACs", map[string]*DeviceData{
			"10.9.49.1": dev("10.9.49.1", "4c:ae:a3:49:00:01", macEntries(3, gw, "00:1b:21:49:03:01", "00:1b:21:49:03:02"), macEntries(4, gw, "00:1b:21:49:04:01")),
		}, "10.9.49.1", 4, true},
		{"another switch's MAC makes a transit port", map[string]*DeviceData{
			"10.9.49.1": dev("10.9.49.1", "4c:ae:a3:49:00:01", macEntries(3, gw, sw2MAC), macEntries(4, gw, "00:1b:21:49:04:01", "00:1b:21:49:04:02")),
		}, "10.9.49.1", 4, true},
		{"another gateway's MAC makes a transit port", map[string]*DeviceData{
			"10.9.49.1": dev("10.9.49.1", "4c:ae:a3:49:00:01", macEntries(3, gw, otherGW)),
		}, "", 0, false},
		{"the switch's own MAC does not count", map[string]*DeviceData{
			"10.9.49.1": dev("10.9.49.1", "4c:ae:a3:49:00:01", macEntries(3, gw, "4c:ae:a3:49:00:01")),
		}, "10.9.49.1", 3, true},
		{"nor does the switch's own ARP alias", map[string]*DeviceData{
			"10.9.49.1": dev("10.9.49.1", sw1MAC, macEntries(3, gw, sw1Alias)),
		}, "10.9.49.1", 3, true},
		{"another switch's ARP alias makes a transit port", map[string]*DeviceData{
			"10.9.49.1": dev("10.9.49.1", sw1MAC, macEntries(3, gw, sw2Alias), macEntries(4, gw, "00:1b:21:49:04:01", "00:1b:21:49:04:02")),
		}, "10.9.49.1", 4, true},
		{"a tie goes to the first switch in IP order, then the lower port", map[string]*DeviceData{
			"10.9.49.12": dev("10.9.49.12", "4c:ae:a3:49:00:0c", macEntries(2, gw)),
			"10.9.49.2":  dev("10.9.49.2", sw2MAC, macEntries(9, gw), macEntries(5, gw)),
		}, "10.9.49.2", 5, true},
		{"NULL0", map[string]*DeviceData{
			"10.9.49.1": dev("10.9.49.1", "4c:ae:a3:49:00:01", macEntries(30, gw)),
		}, "", 0, false},
		{"not learned", map[string]*DeviceData{
			"10.9.49.1": dev("10.9.49.1", "4c:ae:a3:49:00:01", macEntries(3, "00:1b:21:49:03:01")),
		}, "", 0, false},
	}
	for _, c := range cases {
		link, ok := gatewayPort(c.snapshot, gw, infra)
		got := ""
		if ok {
			got = link.dev.IP
		}
		if ok != c.ok || got != c.ip || link.port != c.port {
			t.Errorf("%s: gatewayPort = %s port %d (found %v), want %s port %d (found %v)", c.name, got, link.port, ok, c.ip, c.port, c.ok)
		}
	}
}

// TestGatewayMACSources checks where a gateway's MAC comes from: the ARP
// tables of the polled switches first (the MAC most of them list), else
// the MAC-IP cache, where a MAC learned in a switch FDB beats one that is
// not, then the one seen last, then the lowest. The fixture's cache maps
// both the FortiGate's MAC and an old Dell MAC to 172.20.0.1.
func TestGatewayMACSources(t *testing.T) {
	resetState(t)
	const dell = "08:92:04:99:a9:42"
	sw := func(ip string, arp ...ARPEntry) *DeviceData {
		return &DeviceData{IP: ip, ARPTable: arp, MACTable: macEntries(5, fortiMAC, dell)}
	}
	arp := func(mac string) ARPEntry { return ARPEntry{IPAddress: fortiGW, MACAddress: mac, Interface: 636} }
	setCache := func(seen map[string]time.Duration) {
		globalMACtoIPMutex.Lock()
		defer globalMACtoIPMutex.Unlock()
		globalMACtoIP = map[string]string{fortiMAC: fortiGW, dell: fortiGW, "00:1b:21:4a:00:01": "172.20.0.9"}
		collectMACIPSeen = map[string]time.Time{}
		for mac, ago := range seen {
			collectMACIPSeen[mac] = testClock.Now().Add(-ago)
		}
	}

	setCache(nil)
	snapshot := map[string]*DeviceData{
		"10.9.50.1": sw("10.9.50.1", arp(dell)),
		"10.9.50.2": sw("10.9.50.2", arp(fortiMAC)),
		"10.9.50.3": sw("10.9.50.3", arp("68-CC-AE-96-E6-08")),
	}
	if mac, src := gatewayMAC(fortiGW, snapshot); mac != fortiMAC || src != "switch ARP tables" {
		t.Errorf("two of three switch ARP tables: %s from %q, want %s from the switch ARP tables", mac, src, fortiMAC)
	}

	noARP := map[string]*DeviceData{"10.9.50.1": sw("10.9.50.1")}
	setCache(map[string]time.Duration{dell: 9 * 24 * time.Hour, fortiMAC: 5 * time.Minute})
	if mac, src := gatewayMAC(fortiGW, noARP); mac != fortiMAC || src != "MAC-IP cache" {
		t.Errorf("cache, the FortiGate seen last: %s from %q, want %s", mac, src, fortiMAC)
	}
	setCache(nil) // no last-seen times: both learned in the FDB, the lowest MAC wins
	if mac, _ := gatewayMAC(fortiGW, noARP); mac != dell {
		t.Errorf("cache without times: %s, want the lowest MAC %s", mac, dell)
	}
	onlyForti := map[string]*DeviceData{"10.9.50.1": {IP: "10.9.50.1", MACTable: macEntries(5, fortiMAC)}}
	if mac, _ := gatewayMAC(fortiGW, onlyForti); mac != fortiMAC {
		t.Errorf("cache, only the FortiGate's MAC in an FDB: %s, want %s", mac, fortiMAC)
	}
	if mac, src := gatewayMAC("172.20.0.77", noARP); mac != "" || src != "" {
		t.Errorf("unknown IP: %q from %q, want none", mac, src)
	}
}

// TestGatewaySysNameAloneNotMerged checks that the sysName alone does not
// merge an LLDP node: a node that carries the FortiGate's sysName on a port
// where the FortiGate's MAC is not learned, without its IP, stays (a second
// FortiGate-600F would have that name too).
func TestGatewaySysNameAloneNotMerged(t *testing.T) {
	gatewayNetworkUp(t)
	collectedDataMutex.Lock()
	acc := collectedData[gwNetAcc]
	acc.Neighbors = append(slices.Clone(acc.Neighbors), LLDPNeighbor{LocalPortNum: 21, RemIndex: 3, RemChassisIdSubtype: 4,
		RemChassisId: "68 CC AE 99 00 01", RemPortIdSubtype: 1, RemPortId: "\"LAN\"", RemSysName: "FortiGate-600F"})
	collectedDataMutex.Unlock()
	g := buildGraphFromSnapshot(snapshotCollectedData())
	if !g.Nodes["68:cc:ae:99:00:01"] {
		t.Error("another FortiGate-600F (same sysName, other port, no IP) was merged into the gateway's router node")
	}
}

// pathAnomalies counts the new path anomalies of a snapshot diff.
func pathAnomalies(diff *SnapshotDiff) int {
	n := 0
	for _, a := range diff.NewAnomalies {
		if a.AnomalyType == "path" {
			n++
		}
	}
	return n
}

// TestMonitorFirstCycleWaitsForGraph (F2 of the gateway review): in
// monitor24h, restarted every day at 05:00, the first cycle ran before the
// startup graph was published and analysed the empty graph main() puts up
// first, which has no core; the second cycle, on the graph with the
// gateways' router nodes, reported every path anomaly as new. A cycle now
// takes no snapshot before a graph with nodes is published (and
// runMonitor24h waits for the startup graph), so the first diff of a run
// reports no path anomaly.
func TestMonitorFirstCycleWaitsForGraph(t *testing.T) {
	_, graph, _ := fixtureWithGateways(t)
	collectedDataMutex.RLock()
	devices := sortedDevices(collectedData)
	collectedDataMutex.RUnlock()

	SetGlobalGraph(NewDJGraph()) // what main() publishes at start
	var first *NetworkSnapshot
	out := captureStdout(t, func() { first = monitorCycle(nil) })
	if first != nil || !strings.Contains(out, "No graph yet") {
		t.Fatalf("a cycle on the empty graph took a snapshot (%v), output %q", first != nil, out)
	}

	SetGlobalGraph(graph) // the startup graph is published
	var second *NetworkSnapshot
	captureStdout(t, func() {
		first = monitorCycle(nil)
		second = monitorCycle(first)
	})
	if first == nil || second == nil {
		t.Fatal("no snapshot once the startup graph was published")
	}
	if n := pathAnomalies(CompareSnapshots(first, second)); n != 0 {
		t.Errorf("the first diff of the run reports %d new path anomalies, want none", n)
	}

	// The diff the old first cycle gave: the empty graph's snapshot against
	// the real one
	var report Report
	captureStdout(t, func() { report = NewAnalyzer(captureData("monitor24h", devices, NewDJGraph())).Analyze() })
	empty := CreateSnapshot(devices, NewDJGraph(), &report)
	if n := pathAnomalies(CompareSnapshots(empty, second)); n == 0 {
		t.Error("against a snapshot of the empty graph no path anomaly is new: the test does not reproduce the burst")
	}
}
