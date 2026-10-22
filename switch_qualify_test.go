package main

import (
	"fmt"
	"maps"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// Tests of the switch qualification (checkSwitch) and of the paths that add
// devices on their own. The fake agents answer like the devices of
// 2026-10-22 (production log and snmpget of the live agents): UniFi access
// points, the FortiGate-600F firewall (empty sysDescr), an ESXi 6.5 host
// and the Debian gateway VM answer sysName, sysDescr, IF-MIB and ARP, and
// "No Such Object" for dot1dBaseNumPorts, lldpLocChassisId and the other
// switch tables, so their poll is a partial success with only the chassis
// id missing; switches answer dot1dBaseNumPorts and/or lldpLocChassisId.

// noSuchObject is net-snmp's answer for an object the agent does not have.
func noSuchObject(oid string) []string {
	return []string{oid + " = No Such Object available on this agent at this OID"}
}

// nonSwitchAgent is an agent without BRIDGE-MIB and LLDP-MIB. sysDescr ""
// is answered as the FortiGate does: `""` without a type.
func nonSwitchAgent(sysName, sysDescr string) map[string][]string {
	walks := map[string][]string{
		oidSysName:                {fmt.Sprintf("%s = STRING: %q", oidSysName, sysName)},
		oidSysDescr:               {fmt.Sprintf("%s = STRING: %q", oidSysDescr, sysDescr)},
		oidDot1dBaseNumPorts:      noSuchObject(oidDot1dBaseNumPorts),
		oidChassis:                noSuchObject(oidChassis),
		oidIfDescr:                {oidIfDescr + ".1 = STRING: \"lo\"", oidIfDescr + ".2 = STRING: \"eth0\""},
		".1.3.6.1.2.1.2.2.1.8":    {".1.3.6.1.2.1.2.2.1.8.1 = INTEGER: 1", ".1.3.6.1.2.1.2.2.1.8.2 = INTEGER: 1"},
		oidLLDPRem:                noSuchObject(oidLLDPRem),
		oidLLDPMan:                noSuchObject(oidLLDPMan),
		oidFDBPort:                noSuchObject(oidFDBPort),
		collectBasePortIfIndexOID: noSuchObject(collectBasePortIfIndexOID),
		oidARP:                    {oidARP + ".2.10.9.19.9 = Hex-STRING: 00 1B 21 13 00 09 "},
		oidPVID:                   noSuchObject(oidPVID),
		oidSTPProto:               noSuchObject(oidSTPProto),
	}
	if sysDescr == "" {
		walks[oidSysDescr] = []string{oidSysDescr + ` = ""`}
	}
	return walks
}

func accessPointAgent(name string) map[string][]string {
	return nonSwitchAgent(name, "U6-Pro 6.8.2.15592")
}

func fortiGateAgent() map[string][]string { return nonSwitchAgent("FortiGate-600F", "") }

func esxiAgent() map[string][]string {
	return nonSwitchAgent("localhost", "VMware ESXi 6.5.0 build-4887370 VMware, Inc. x86_64")
}

func linuxRouterAgent() map[string][]string {
	return nonSwitchAgent("gw", "Linux gw 6.1.0-25-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.106-3 (2024-08-26) x86_64")
}

// bridgeSwitchAgent is a switch with BRIDGE-MIB and without LLDP-MIB (the
// Huawei switches here): ports bridge ports, an FDB, no chassis id.
func bridgeSwitchAgent(ports int) map[string][]string {
	walks := nonSwitchAgent("HUAWEI", "Huawei Versatile Routing Platform Software")
	walks[oidDot1dBaseNumPorts] = []string{fmt.Sprintf("%s = INTEGER: %d", oidDot1dBaseNumPorts, ports)}
	walks[oidIfDescr] = []string{oidIfDescr + ".6 = STRING: \"GigabitEthernet0/0/1\"", oidIfDescr + ".7 = STRING: \"GigabitEthernet0/0/2\""}
	walks[oidFDBPort] = []string{oidFDBPort + ".0.27.33.19.0.1 = INTEGER: 1", oidFDBPort + ".0.27.33.19.0.2 = INTEGER: 2"}
	walks[collectBasePortIfIndexOID] = []string{collectBasePortIfIndexOID + ".1 = INTEGER: 6", collectBasePortIfIndexOID + ".2 = INTEGER: 7"}
	return walks
}

// lldpSwitchAgent is a switch with LLDP-MIB and without BRIDGE-MIB.
func lldpSwitchAgent(last byte) map[string][]string {
	walks := nonSwitchAgent("sw-lldp", "HPE Comware Platform Software")
	walks[oidChassis] = []string{fmt.Sprintf("%s = Hex-STRING: 4C AE A3 13 00 %02X ", oidChassis, last)}
	walks[oidIfDescr] = []string{oidIfDescr + ".1 = STRING: \"GigabitEthernet1/0/1\""}
	return walks
}

// TestSwitchQualification checks the rule of checkSwitch: BRIDGE-MIB with
// at least one port or LLDP-MIB's local chassis id makes a switch; access
// points, the FortiGate, an ESXi host, a Linux router and a bridge without
// ports are rejected with their sysName and sysDescr, and an agent that
// does not answer is no switch either.
func TestSwitchQualification(t *testing.T) {
	resetState(t)
	both := healthyAgent()
	both[oidDot1dBaseNumPorts] = []string{oidDot1dBaseNumPorts + " = INTEGER: 52"}
	noPorts := linuxRouterAgent()
	noPorts[oidDot1dBaseNumPorts] = []string{oidDot1dBaseNumPorts + " = INTEGER: 0"}
	cases := []struct {
		name  string
		agent map[string][]string // nil: no agent answers
		want  switchCheck
	}{
		{"UniFi access point", accessPointAgent("C41"), switchCheck{SysName: "C41", SysDescr: "U6-Pro 6.8.2.15592", Answered: true}},
		{"FortiGate", fortiGateAgent(), switchCheck{SysName: "FortiGate-600F", Answered: true}},
		{"ESXi host", esxiAgent(), switchCheck{SysName: "localhost", SysDescr: "VMware ESXi 6.5.0 build-4887370 VMware, Inc. x86_64", Answered: true}},
		{"Linux router", linuxRouterAgent(), switchCheck{SysName: "gw", SysDescr: "Linux gw 6.1.0-25-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.106-3 (2024-08-26) x86_64", Answered: true}},
		{"bridge without ports", noPorts, switchCheck{SysName: "gw", SysDescr: "Linux gw 6.1.0-25-amd64 #1 SMP PREEMPT_DYNAMIC Debian 6.1.106-3 (2024-08-26) x86_64", Answered: true}},
		{"no SNMP answer", nil, switchCheck{}},
		{"BRIDGE-MIB switch without LLDP", bridgeSwitchAgent(28), switchCheck{Answered: true, switchMIBs: switchMIBs{BridgePorts: 28}}},
		{"LLDP switch without BRIDGE-MIB", lldpSwitchAgent(1), switchCheck{Answered: true, switchMIBs: switchMIBs{LLDPChassis: true}}},
		{"BRIDGE-MIB and LLDP-MIB", both, switchCheck{Answered: true, switchMIBs: switchMIBs{BridgePorts: 52, LLDPChassis: true}}},
	}
	obj := &SNMPObject{Community: "public", Port: 161}
	for i, c := range cases {
		ip := fmt.Sprintf("10.9.19.%d", i+1)
		if c.agent != nil {
			fakeSNMP.set(ip, c.agent)
		}
		c.want.IP = ip
		if got := obj.checkSwitch(ip); got != c.want || got.isSwitch() != c.want.isSwitch() {
			t.Errorf("%s: checkSwitch = %+v (switch %v), want %+v (switch %v)", c.name, got, got.isSwitch(), c.want, c.want.isSwitch())
		}
	}
	for i, c := range cases[:6] {
		if c.want.isSwitch() {
			t.Errorf("case %d (%s) should be no switch", i, c.name)
		}
	}
	for i, c := range cases[6:] {
		if !c.want.isSwitch() {
			t.Errorf("case %d (%s) should be a switch", i+6, c.name)
		}
	}
}

// TestSwitchSkipSummary checks the one line per run about the devices that
// were not added: the count, three examples (different device types first,
// in IP order) with sysName and sysDescr, and the hosts that did not answer
// SNMP, as for the 46 access points (polled by LLDP discovery, now listed
// in swich_ips), the FortiGate and the ESXi host of 2026-10-22.
func TestSwitchSkipSummary(t *testing.T) {
	skips := &switchSkips{}
	if got := skips.summary("Rescue"); got != "" {
		t.Errorf("summary without skips = %q, want none", got)
	}
	for i := 10; i < 56; i++ {
		skips.add(switchCheck{IP: fmt.Sprintf("10.9.20.%d", i), SysName: fmt.Sprintf("C%d", i), SysDescr: "U6-Pro 6.8.2.15592", Answered: true})
	}
	skips.add(switchCheck{IP: "10.9.21.1", SysName: "FortiGate-600F", Answered: true})
	skips.add(switchCheck{IP: "10.9.21.67", SysName: "localhost", SysDescr: "VMware ESXi 6.5.0 build-4887370 VMware, Inc. x86_64 and a long tail", Answered: true})
	for _, last := range []int{50, 40, 41, 2, 3} {
		skips.add(switchCheck{IP: fmt.Sprintf("10.9.21.%d", last)})
	}
	want := "🚫 [Rescue] Not added: 48 devices without BRIDGE-MIB ports or lldpLocChassisId (no switch): " +
		"10.9.20.10 (C10, U6-Pro 6.8.2.15592), 10.9.21.1 (FortiGate-600F), " +
		"10.9.21.67 (localhost, VMware ESXi 6.5.0 build-4887370 VMware, Inc. x86_64 and a lo…) and 45 more; " +
		"5 hosts did not answer SNMP: 10.9.21.2, 10.9.21.3, 10.9.21.40 and 2 more"
	if got := skips.summary("Rescue"); got != want {
		t.Errorf("summary =\n%s\nwant\n%s", got, want)
	}
	if skips.count() != 53 {
		t.Errorf("count = %d, want 53", skips.count())
	}
}

// collectedIPs lists the IPs in collectedData.
func collectedIPs() []string {
	collectedDataMutex.RLock()
	defer collectedDataMutex.RUnlock()
	return slices.SortedFunc(maps.Keys(collectedData), compareIPs)
}

// TestRescueScanRecoversOnlySwitches checks the rescue scan (B): of the
// alive IPs of swich_ips that are not collected, only those that pass
// checkSwitch are polled; the FortiGate, an access point, an ESXi host and
// a host without SNMP are not, and one summary line names them. Only a
// switch whose poll stored it counts as recovered (a qualified switch whose
// walks all time out does not), and the graph is rebuilt only when one was
// recovered.
func TestRescueScanRecoversOnlySwitches(t *testing.T) {
	resetState(t)
	const known = "10.9.22.2"
	fakeSNMP.set(known, lldpSwitchAgent(2))
	newRescanSNMPObject().CollectData(known, "sw-known")
	if got := collectedIPs(); !slices.Equal(got, []string{known}) {
		t.Fatalf("known switch not stored: %v", got)
	}

	fakeSNMP.set("10.9.22.1", fortiGateAgent())
	fakeSNMP.set("10.9.22.3", accessPointAgent("C41"))
	fakeSNMP.set("10.9.22.4", esxiAgent())
	fakeSNMP.set("10.9.22.5", bridgeSwitchAgent(24))
	fakeSNMP.set("10.9.22.6", lldpSwitchAgent(6))
	// a switch MIB, but every walk of the poll times out
	fakeSNMP.set("10.9.22.7", map[string][]string{
		oidDot1dBaseNumPorts: {oidDot1dBaseNumPorts + " = INTEGER: 24"},
		oidChassis:           noSuchObject(oidChassis),
	})
	// 10.9.22.8 answers ping, not SNMP; 10.9.22.9 and up do not answer ping
	// (.9 has a switch agent: a host that is not alive is not checked)
	fakeSNMP.set("10.9.22.9", bridgeSwitchAgent(24))
	alive := func(ip string) bool { return compareIPs(ip, "10.9.22.8") <= 0 }
	ranges := []string{"10.9.22.0/28", "10.9.22.5"}

	recovered, skips := rescueScan(newRescanSNMPObject(), ranges, alive)
	if want := []string{"10.9.22.5", "10.9.22.6"}; !slices.Equal(recovered, want) {
		t.Errorf("recovered = %v, want %v", recovered, want)
	}
	if got, want := collectedIPs(), []string{"10.9.22.2", "10.9.22.5", "10.9.22.6"}; !slices.Equal(got, want) {
		t.Errorf("collectedData = %v, want %v", got, want)
	}
	summary := skips.summary("Rescue")
	for _, part := range []string{"Not added: 3 devices without BRIDGE-MIB ports", "10.9.22.1 (FortiGate-600F)", "10.9.22.3 (C41, U6-Pro", "10.9.22.4 (localhost, VMware ESXi", "1 host did not answer SNMP: 10.9.22.8"} {
		if !strings.Contains(summary, part) {
			t.Errorf("summary %q lacks %q", summary, part)
		}
	}
	graph := GetGlobalGraph()
	if graph == nil {
		t.Fatal("no graph published after a recovery")
	}
	if !graph.Nodes["10.9.22.5"] || !graph.Nodes["4c:ae:a3:13:00:06"] {
		t.Errorf("recovered switches missing from the graph: %v", slices.Sorted(maps.Keys(graph.Nodes)))
	}
	for _, id := range []string{"10.9.22.1", "10.9.22.3", "10.9.22.4", "10.9.22.7", "10.9.22.8"} {
		if graph.Nodes[id] {
			t.Errorf("%s is a graph node", id)
		}
	}

	// Next run: nothing to recover, so no rebuild
	sentinel := NewDJGraph()
	SetGlobalGraph(sentinel)
	recovered, skips = rescueScan(newRescanSNMPObject(), ranges, alive)
	if len(recovered) != 0 || skips.count() != 4 {
		t.Errorf("second run: recovered %v, %d skipped; want none and 4", recovered, skips.count())
	}
	if GetGlobalGraph() != sentinel {
		t.Error("the graph was rebuilt although no switch was recovered")
	}
}

// TestNonSwitchNeverANode checks C on the FortiGate-like agent: whichever
// SNMP object polls it (the rescan object, the first scan's, the UI
// rescan's helper), it is never stored and never a graph node, although
// its poll is a partial success; LLDP discovery does not poll or list it
// even when a switch's LLDP table advertises it as a router.
func TestNonSwitchNeverANode(t *testing.T) {
	resetState(t)
	const forti = "10.9.23.1"
	fakeSNMP.set(forti, fortiGateAgent())

	delivered := false
	NewSNMPObject(func(*DeviceData) { delivered = true }, nil).CollectData(forti, "")
	if !delivered {
		t.Fatal("the FortiGate-like poll is no partial success: the test agent does not reproduce production")
	}
	newRescanSNMPObject().CollectData(forti, "")
	newReactiveSNMPObject().CollectData(forti, "FortiGate-600F")
	skips := &switchSkips{}
	collectScannedSwitch(newRescanSNMPObject(), forti, "FortiGate-600F", skips)
	if got := collectedIPs(); len(got) != 0 {
		t.Errorf("collectedData = %v, want empty", got)
	}
	if GetGlobalGraph() != nil || liveAnalyses.Load() != 0 {
		t.Error("the first scan published a graph or started an analysis for a device it did not store")
	}
	if !strings.Contains(skips.summary("Scan"), forti+" (FortiGate-600F)") {
		t.Errorf("first-scan summary = %q", skips.summary("Scan"))
	}

	// A switch whose LLDP table has the FortiGate as a router neighbor
	const sw = "10.9.23.100"
	agent := lldpSwitchAgent(100)
	agent[oidLLDPRem] = []string{
		oidLLDPRem + ".4.0.1.1 = INTEGER: 4",
		oidLLDPRem + ".5.0.1.1 = Hex-STRING: 68 CC AE 96 E6 08 ",
		oidLLDPRem + ".9.0.1.1 = STRING: \"FortiGate-600F\"",
		oidLLDPRem + ".12.0.1.1 = Hex-STRING: 08 00 ",
	}
	agent[oidLLDPMan] = []string{oidLLDPMan + ".3.0.1.1.1.4.10.9.23.1 = INTEGER: 2"}
	fakeSNMP.set(sw, agent)
	newRescanSNMPObject().CollectData(sw, "sw")
	switchIPAdds.taken()
	lldpSkips := discoverFromLLDP(newRescanSNMPObject())
	if got := collectedIPs(); !slices.Equal(got, []string{sw}) {
		t.Errorf("collectedData after LLDP discovery = %v, want only %s", got, sw)
	}
	if got := switchIPAdds.taken(); len(got) != 0 {
		t.Errorf("added to swich_ips: %v", got)
	}
	if !strings.Contains(lldpSkips.summary("LLDP-Discovery"), forti+" (FortiGate-600F)") {
		t.Errorf("LLDP discovery summary = %q", lldpSkips.summary("LLDP-Discovery"))
	}
	graph := buildGraphFromSnapshot(snapshotCollectedData())
	if graph.Nodes[forti] || graphIsSwitchNode(graph, forti) {
		t.Error("the FortiGate is a graph node")
	}
}

// TestLLDPDiscoveryQualifies checks that LLDP discovery keeps its
// capability filter and asks checkSwitch on top: a neighbor that enables
// bridge but whose agent is an access point's is not polled or listed, a
// neighbor that does not answer SNMP is not either, a real switch is.
func TestLLDPDiscoveryQualifies(t *testing.T) {
	resetState(t)
	const sw = "10.9.24.100"
	agent := lldpSwitchAgent(0x64)
	var rem, man []string
	for i, caps := range []string{"Hex-STRING: 20 00 ", "Hex-STRING: 20 00 ", "Hex-STRING: 28 00 ", "Hex-STRING: 30 00 "} {
		port := i + 1
		idx := fmt.Sprintf("0.%d.1", port)
		rem = append(rem,
			fmt.Sprintf("%s.4.%s = INTEGER: 4", oidLLDPRem, idx),
			fmt.Sprintf("%s.5.%s = Hex-STRING: 4C AE A3 24 00 %02X ", oidLLDPRem, idx, port),
			fmt.Sprintf("%s.12.%s = %s", oidLLDPRem, idx, caps))
		man = append(man, fmt.Sprintf("%s.3.%s.1.4.10.9.24.%d = INTEGER: 2", oidLLDPMan, idx, port))
	}
	agent[oidLLDPRem], agent[oidLLDPMan] = rem, man
	fakeSNMP.set(sw, agent)
	newRescanSNMPObject().CollectData(sw, "sw")
	fakeSNMP.set("10.9.24.1", accessPointAgent("C44")) // bridge: an access point that does not say so
	// 10.9.24.2 (bridge) does not answer SNMP
	fakeSNMP.set("10.9.24.3", lldpSwitchAgent(3)) // bridge + router: a switch
	fakeSNMP.set("10.9.24.4", lldpSwitchAgent(4)) // bridge + wlanAccessPoint: filtered by capabilities
	switchIPAdds.taken()

	skips := discoverFromLLDP(newRescanSNMPObject())
	if got, want := collectedIPs(), []string{"10.9.24.3", sw}; !slices.Equal(got, want) {
		t.Errorf("collectedData = %v, want %v", got, want)
	}
	if got, want := switchIPAdds.taken(), []string{"10.9.24.3"}; !slices.Equal(got, want) {
		t.Errorf("added to swich_ips = %v, want %v", got, want)
	}
	if got, want := skips.summary("LLDP-Discovery"), "🚫 [LLDP-Discovery] Not added: 1 device without BRIDGE-MIB ports or lldpLocChassisId (no switch): 10.9.24.1 (C44, U6-Pro 6.8.2.15592); 1 host did not answer SNMP: 10.9.24.2"; got != want {
		t.Errorf("summary =\n%s\nwant\n%s", got, want)
	}
}

// TestSubnetDiscoveryAddsOnlySwitches checks subnet discovery (A): of the
// devices in the gateway's subnets that answer sysDescr (all IPs of a small
// subnet, the ARP-known ones of a /16), only switches are appended to
// swich_ips; the access points, the FortiGate and the ESXi host are named
// in the summary, a host without SNMP is not probed further, a collected
// switch is not probed at all, and none of them becomes an ARP source.
func TestSubnetDiscoveryAddsOnlySwitches(t *testing.T) {
	resetState(t)
	fakeSNMP.set(fixedGatewayIP, map[string][]string{".1.3.6.1.2.1.4.20.1.3": {
		".1.3.6.1.2.1.4.20.1.3.10.9.25.1 = IpAddress: 255.255.255.240",
		".1.3.6.1.2.1.4.20.1.3.10.26.0.1 = IpAddress: 255.255.0.0",
		".1.3.6.1.2.1.4.20.1.3.127.0.0.1 = IpAddress: 255.0.0.0",
	}})
	fakeSNMP.set("10.9.25.2", accessPointAgent("Sportzal3"))
	fakeSNMP.set("10.9.25.3", fortiGateAgent())
	fakeSNMP.set("10.9.25.4", esxiAgent())
	fakeSNMP.set("10.9.25.5", bridgeSwitchAgent(24))
	fakeSNMP.set("10.9.25.6", lldpSwitchAgent(6))
	fakeSNMP.set("10.9.25.7", lldpSwitchAgent(7)) // collected already
	collectedDataMutex.Lock()
	collectedData["10.9.25.7"] = &DeviceData{IP: "10.9.25.7", SysName: "sw-7"}
	collectedDataMutex.Unlock()
	// The /16: probed through the ARP-known IPs only
	fakeSNMP.set("10.26.5.5", accessPointAgent("C45"))
	fakeSNMP.set("10.26.5.6", bridgeSwitchAgent(48))
	fakeSNMP.set("10.26.5.7", lldpSwitchAgent(0x57)) // not in the ARP cache
	globalMACtoIPMutex.Lock()
	globalMACtoIP = map[string]string{"00:1b:21:1a:05:05": "10.26.5.5", "00:1b:21:1a:05:06": "10.26.5.6"}
	globalMACtoIPMutex.Unlock()

	obj := &SNMPObject{Community: "public", Port: 161}
	var added []string
	out := captureStdout(t, func() { added = subnetDiscovery(obj, nil, subnetProbeWorkers, appendSwitchIP) })
	if want := []string{"10.9.25.5", "10.9.25.6", "10.26.5.6"}; !slices.Equal(added, want) {
		t.Errorf("subnetDiscovery added %v, want %v", added, want)
	}
	if got, want := switchIPAdds.taken(), []string{"10.26.5.6", "10.9.25.5", "10.9.25.6"}; !slices.Equal(got, want) {
		t.Errorf("appended to swich_ips = %v, want %v", got, want)
	}
	// Every host of the /28 but the gateway's own address and the stored
	// switch, and the ARP-known IPs of the /16
	wantProbes := append(subnetHostStrings(t, "10.9.25.0/28", "10.9.25.1", "10.9.25.7"), "10.26.5.5", "10.26.5.6")
	if got := snmpProbes.taken(); !slices.Equal(sortedStrings(got), sortedStrings(wantProbes)) {
		t.Errorf("probed %v, want %v", sortedStrings(got), sortedStrings(wantProbes))
	}
	want := "🚫 [SubnetDisc] Not added: 4 devices without BRIDGE-MIB ports or lldpLocChassisId (no switch): " +
		"10.9.25.2 (Sportzal3, U6-Pro 6.8.2.15592), 10.9.25.3 (FortiGate-600F), 10.9.25.4 (localhost, VMware ESXi 6.5.0 build-4887370 VMware, Inc. x86_64) and 1 more\n"
	if !strings.Contains(out, want) {
		t.Errorf("output lacks the summary\n%s\nin\n%s", want, out)
	}
	if got := collectedIPs(); !slices.Equal(got, []string{"10.9.25.7"}) {
		t.Errorf("subnet discovery changed collectedData: %v", got)
	}
	if got := arpSourceIPs(); len(got) != 0 {
		t.Errorf("subnet discovery made ARP sources: %v", got)
	}
}

// subnetHostStrings lists the host IPs of cidr (subnetHosts) without the
// IPs given.
func subnetHostStrings(t *testing.T, cidr string, without ...string) []string {
	t.Helper()
	var ips []string
	for _, a := range subnetHosts(netip.MustParsePrefix(cidr)) {
		if !slices.Contains(without, a.String()) {
			ips = append(ips, a.String())
		}
	}
	return ips
}

// sortedStrings returns a sorted copy of s.
func sortedStrings(s []string) []string { return slices.Sorted(slices.Values(s)) }

// TestSubnetHosts checks the small-subnet host lists: a /22 to /30 without
// its network and broadcast addresses, both addresses of a point-to-point
// /31, the one of a /32 (generateSubnetIPs made room for 2^32-1 strings
// there, a 64 GiB allocation), and none for a subnet larger than a /22.
func TestSubnetHosts(t *testing.T) {
	cases := []struct {
		cidr        string
		n           int
		first, last string
	}{
		{"10.9.32.0/22", 1022, "10.9.32.1", "10.9.35.254"},
		{"10.9.36.7/24", 254, "10.9.36.1", "10.9.36.254"},
		{"10.190.47.58/30", 2, "10.190.47.57", "10.190.47.58"},
		{"10.9.37.4/31", 2, "10.9.37.4", "10.9.37.5"},
		{"10.9.38.1/32", 1, "10.9.38.1", "10.9.38.1"},
		{"10.9.40.0/21", 0, "", ""},
	}
	for _, c := range cases {
		hosts := subnetHosts(netip.MustParsePrefix(c.cidr))
		if len(hosts) != c.n {
			t.Errorf("%s: %d hosts, want %d", c.cidr, len(hosts), c.n)
			continue
		}
		if c.n > 0 && (hosts[0].String() != c.first || hosts[c.n-1].String() != c.last) {
			t.Errorf("%s: hosts %s … %s, want %s … %s", c.cidr, hosts[0], hosts[c.n-1], c.first, c.last)
		}
	}
}

// TestSubnetDiscoveryBounded (F2) checks the bounds of a discovery run on a
// gateway shaped like 172.20.1.254 (a client /16 full of random MACs, a /16
// with the swich_ips ranges, small subnets, a /32, a /31, a /12): the
// subnet that overlaps swich_ips is probed first; a /16 is probed only at
// the ARP-known IPs that a MAC which is not random maps to, each once; the
// IPs swich_ips lists (alone or in a range), the stored devices and the
// gateway's own addresses are not probed; a /32 does not end the run. With
// one worker the probes run in plan order and a switch is appended as soon
// as it is found, before the next host is probed; with subnetProbeWorkers
// the same hosts are probed, each once.
func TestSubnetDiscoveryBounded(t *testing.T) {
	resetState(t)
	fakeSNMP.set(fixedGatewayIP, map[string][]string{".1.3.6.1.2.1.4.20.1.3": {
		".1.3.6.1.2.1.4.20.1.3.10.30.0.1 = IpAddress: 255.255.0.0",
		".1.3.6.1.2.1.4.20.1.3.10.31.0.1 = IpAddress: 255.255.0.0",
		".1.3.6.1.2.1.4.20.1.3.10.32.0.1 = IpAddress: 255.255.255.252",
		".1.3.6.1.2.1.4.20.1.3.10.33.0.1 = IpAddress: 255.255.255.255",
		".1.3.6.1.2.1.4.20.1.3.10.34.0.0 = IpAddress: 255.255.255.254",
		".1.3.6.1.2.1.4.20.1.3.10.35.0.1 = IpAddress: 255.240.0.0",
		".1.3.6.1.2.1.4.20.1.3.127.0.0.1 = IpAddress: 255.0.0.0",
		".1.3.6.1.2.1.4.20.1.3.172.20.1.254 = IpAddress: 255.255.0.0",
	}})
	cache := map[string]string{
		"00:0c:29:98:7b:c2": fixedGatewayIP, // the gateway itself
		"00:1b:21:1e:00:01": "10.30.0.1",    // the gateway's address in the client /16
		"da:a1:19:1e:00:02": "10.30.1.2",    // the same IP behind a random MAC
		"00:1b:21:1e:01:02": "10.30.1.2",    // and a maker's MAC: probed once
		"00:1b:21:1e:01:03": "10.30.1.3",
		"00:1b:21:1e:01:04": "10.30.1.4",
		"00:1b:21:1f:05:20": "10.31.5.20", // inside the listed range 10.31.5.0/24
		"00:1b:21:1f:09:09": "10.31.9.9",  // listed alone
		"00:1b:21:1f:07:07": "10.31.7.7",  // a switch
		"00:1b:21:1f:07:08": "10.31.7.8",  // stored already
	}
	for i := range 30 { // phones and laptops of the client /16
		cache[fmt.Sprintf("de:ad:00:1e:02:%02x", i)] = fmt.Sprintf("10.30.2.%d", i+1)
	}
	globalMACtoIPMutex.Lock()
	globalMACtoIP = cache
	globalMACtoIPMutex.Unlock()
	collectedDataMutex.Lock()
	collectedData["10.31.7.8"] = &DeviceData{IP: "10.31.7.8", SysName: "sw-8"}
	collectedDataMutex.Unlock()
	fakeSNMP.set("10.31.7.7", bridgeSwitchAgent(24))
	fakeSNMP.set("10.31.5.20", lldpSwitchAgent(0x20)) // the rescue scan's, not probed here
	fakeSNMP.set("10.30.1.3", accessPointAgent("C46"))
	fakeSNMP.set("10.34.0.1", lldpSwitchAgent(0x34)) // the peer of the /31
	ranges := []string{"10.31.5.0/24", "10.31.9.9"}

	obj := &SNMPObject{Community: "public", Port: 161}
	plan := planSubnetDiscovery(discoverGatewaySubnets(obj, fixedGatewayIP), ranges)
	type planned struct {
		subnet string
		listed bool
		ips    []string
		random int
	}
	var got []planned
	var order []string
	for _, p := range plan {
		got = append(got, planned{fmt.Sprintf("%s/%d", p.Net, p.Prefix), p.Listed, p.IPs, p.Random})
		order = append(order, p.IPs...)
	}
	want := []planned{
		{"10.31.0.0/16", true, []string{"10.31.7.7"}, 0},
		{"10.30.0.0/16", false, []string{"10.30.1.2", "10.30.1.3", "10.30.1.4"}, 30},
		{"10.32.0.0/30", false, []string{"10.32.0.2"}, 0},
		{"10.33.0.1/32", false, nil, 0},
		{"10.34.0.0/31", false, []string{"10.34.0.1"}, 0},
		{"172.20.0.0/16", false, nil, 0},
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("plan =\n%v\nwant\n%v", got, want)
	}

	// One worker: the probes follow the plan, and the switch of the first
	// subnet is appended right after its own probe
	var adds []string
	added := subnetDiscovery(obj, ranges, 1, func(ip string) bool {
		adds = append(adds, fmt.Sprintf("%s after %d probes", ip, snmpProbes.count()))
		return true
	})
	if probed := snmpProbes.taken(); !slices.Equal(probed, order) {
		t.Errorf("probed %v, want the plan order %v", probed, order)
	}
	if want := []string{"10.31.7.7 after 1 probes", "10.34.0.1 after 6 probes"}; !slices.Equal(adds, want) {
		t.Errorf("appended %v, want %v", adds, want)
	}
	if want := []string{"10.31.7.7", "10.34.0.1"}; !slices.Equal(added, want) {
		t.Errorf("subnetDiscovery returned %v, want %v", added, want)
	}

	// The production worker count probes the same hosts, each once
	added = subnetDiscovery(obj, ranges, subnetProbeWorkers, appendSwitchIP)
	if probed := snmpProbes.taken(); !slices.Equal(sortedStrings(probed), sortedStrings(order)) {
		t.Errorf("with %d workers probed %v, want %v", subnetProbeWorkers, sortedStrings(probed), sortedStrings(order))
	}
	if got, want := switchIPAdds.taken(), []string{"10.31.7.7", "10.34.0.1"}; !slices.Equal(got, want) || !slices.Equal(added, want) {
		t.Errorf("with %d workers appended %v (returned %v), want %v", subnetProbeWorkers, got, added, want)
	}
}

// TestRejectedRouterARPStillMerged (F3): the FortiGate in a swich_ips range
// fails checkSwitch, so the rescue scan neither polls nor stores it, but
// every MAC-IP sweep still merges its ARP table, as it did while the rescue
// scan stored it: on 2026-10-22 it held 1,066 MACs that neither the
// gateway's table nor the saved switch tables showed. Its entries stay
// fresh while the gateway's walks expire the others. A host that does not answer SNMP and a device that LLDP discovery
// rejects are no ARP sources, an ARP source is never a node, and a device
// stops being one once swich_ips no longer lists it.
func TestRejectedRouterARPStillMerged(t *testing.T) {
	resetState(t)
	macIPCacheFile = filepath.Join(t.TempDir(), "mac_ip_cache.json") // the sweep saves the cache
	const forti, esxi, quiet, sw = "10.9.27.1", "10.9.27.67", "10.9.27.5", "10.9.27.10"
	agent := fortiGateAgent()
	agent[oidARP] = []string{
		oidARP + ".5.10.9.28.10 = Hex-STRING: 00 1B 21 1C 00 0A ",
		oidARP + ".5.10.9.28.11 = Hex-STRING: 00 1B 21 1C 00 0B ",
	}
	fakeSNMP.set(forti, agent)
	esxiARP := esxiAgent()
	esxiARP[oidARP] = noSuchObject(oidARP) // no ARP table: no rows
	fakeSNMP.set(esxi, esxiARP)
	fakeSNMP.set(sw, bridgeSwitchAgent(24)) // its ARP row: 10.9.19.9
	fakeSNMP.set(fixedGatewayIP, map[string][]string{oidARP: {oidARP + ".5.10.9.28.20 = Hex-STRING: 00 1B 21 1C 00 14 "}})
	alive := func(ip string) bool { return slices.Contains([]string{forti, esxi, quiet, sw}, ip) }

	recovered, _ := rescueScan(newRescanSNMPObject(), []string{"10.9.27.0/24"}, alive)
	if !slices.Equal(recovered, []string{sw}) || !slices.Equal(collectedIPs(), []string{sw}) {
		t.Fatalf("recovered %v, stored %v; want the switch %s only", recovered, collectedIPs(), sw)
	}
	if got, want := arpSourceIPs(), []string{forti, esxi}; !slices.Equal(got, want) {
		t.Errorf("ARP sources = %v, want %v", got, want)
	}

	// An old entry that only the FortiGate shows, one that no table shows
	// any more, and a sweep 8 days later: the FortiGate's stays
	globalMACtoIPMutex.Lock()
	globalMACtoIP["00:1b:21:1c:00:0a"] = "10.9.28.10"
	globalMACtoIP["00:1b:21:1c:00:0c"] = "10.9.28.12"
	collectMACIPSeen["00:1b:21:1c:00:0a"] = testClock.Now()
	collectMACIPSeen["00:1b:21:1c:00:0c"] = testClock.Now()
	globalMACtoIPMutex.Unlock()
	testClock.advance(8 * 24 * time.Hour)
	out := captureStdout(t, collectARPFromAllSwitches)
	want := map[string]string{
		"00:1b:21:1c:00:0a": "10.9.28.10", // the FortiGate's, kept fresh
		"00:1b:21:1c:00:0b": "10.9.28.11", // the FortiGate's, new
		"00:1b:21:1c:00:14": "10.9.28.20", // the gateway's
		"00:1b:21:13:00:09": "10.9.19.9",  // the switch's
	}
	if got := collectCacheMap(); !maps.Equal(got, want) {
		t.Errorf("MAC-IP entries after the sweep = %v, want %v", got, want)
	}
	if !strings.Contains(out, "ARP source "+forti+" (no switch): +1 new/changed MAC-IP entries") {
		t.Errorf("sweep output does not name the FortiGate as an ARP source:\n%s", out)
	}
	if strings.Contains(out, "ARP source "+esxi) {
		t.Errorf("an ARP source without rows was reported:\n%s", out)
	}

	// Never a node, however the graph is built
	rebuildGraph()
	for _, graph := range []*DJGraph{GetGlobalGraph(), buildGraphFromSnapshot(snapshotCollectedData())} {
		if graph.Nodes[forti] || graph.Nodes[esxi] || graphIsSwitchNode(graph, forti) {
			t.Errorf("an ARP source is a graph node: %v", slices.Sorted(maps.Keys(graph.Nodes)))
		}
	}

	// A device LLDP discovery rejects is no ARP source
	const lldpSw = "10.9.27.100"
	lldpAgent := lldpSwitchAgent(100)
	lldpAgent[oidLLDPRem] = []string{
		oidLLDPRem + ".4.0.1.1 = INTEGER: 4",
		oidLLDPRem + ".5.0.1.1 = Hex-STRING: 4C AE A3 27 00 01 ",
		oidLLDPRem + ".12.0.1.1 = Hex-STRING: 20 00 ",
	}
	lldpAgent[oidLLDPMan] = []string{oidLLDPMan + ".3.0.1.1.1.4.10.9.29.1 = INTEGER: 2"}
	fakeSNMP.set(lldpSw, lldpAgent)
	fakeSNMP.set("10.9.29.1", accessPointAgent("C47"))
	newRescanSNMPObject().CollectData(lldpSw, "sw")
	if skips := discoverFromLLDP(newRescanSNMPObject()); skips.count() != 1 {
		t.Errorf("LLDP discovery skipped %d devices, want the access point", skips.count())
	}
	if got, want := arpSourceIPs(), []string{forti, esxi}; !slices.Equal(got, want) {
		t.Errorf("ARP sources after LLDP discovery = %v, want %v", got, want)
	}

	// The owner removes the range: the next rescue run drops its sources
	rescueScan(newRescanSNMPObject(), []string{sw, esxi}, alive)
	if got, want := arpSourceIPs(), []string{esxi}; !slices.Equal(got, want) {
		t.Errorf("ARP sources once the range is gone = %v, want %v", got, want)
	}
}

// TestKnownDeviceKeepsPolls checks the other half of C: a device that was
// collected before is still stored by every successful poll, also when the
// poll shows no switch MIB (a saved host, or a flaky agent: F57, H9), and
// turns unreachable when it stops answering, with its last data and an
// "unreachable" graph node.
func TestKnownDeviceKeepsPolls(t *testing.T) {
	resetState(t)
	const sw, saved = "10.9.26.1", "10.9.26.2"
	obj := newRescanSNMPObject()
	fakeSNMP.set(sw, bridgeSwitchAgent(24))
	obj.CollectData(sw, "sw")
	first := collectStored(sw)
	if first == nil || len(first.MACTable) != 2 {
		t.Fatalf("switch not stored: %+v", first)
	}

	fakeSNMP.set(sw, map[string][]string{}) // stops answering
	obj.CollectData(sw, "sw")
	down := collectStored(sw)
	if down == nil || !down.Unreachable || !slices.Equal(down.MACTable, first.MACTable) {
		t.Fatalf("known switch that stopped answering: %+v", down)
	}
	graph := buildGraphFromSnapshot(snapshotCollectedData())
	if id := graphDeviceNodeID(down); !graph.Nodes[id] || graph.NodeStatus[id] != "unreachable" {
		t.Errorf("node %s: present %v, status %q; want an unreachable node", id, graph.Nodes[id], graph.NodeStatus[id])
	}

	// A saved host polled while its agent shows no switch MIB
	collectedDataMutex.Lock()
	collectedData[saved] = &DeviceData{IP: saved, SysName: "saved"}
	collectedDataMutex.Unlock()
	fakeSNMP.set(saved, linuxRouterAgent())
	obj.CollectData(saved, "saved")
	if d := collectStored(saved); d == nil || d.Unreachable || len(d.Interfaces) != 2 {
		t.Errorf("poll of a known device without switch MIB not stored: %+v", d)
	}
}
