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

// setARPCache sets globalMACtoIP (MAC → IP) as the ARP sources left it.
func setARPCache(cache map[string]string) {
	globalMACtoIPMutex.Lock()
	globalMACtoIP = maps.Clone(cache)
	globalMACtoIPMutex.Unlock()
}

// subnetTestLimits are the production limits with workers at a time and no
// time budget.
func subnetTestLimits(workers int) subnetDiscoveryLimits {
	limits := subnetDiscoveryDefaults
	limits.Workers, limits.Budget = workers, 0
	return limits
}

// TestSubnetDiscoveryAddsOnlySwitches checks subnet discovery (A): of the
// ARP-known IPs in the gateway's subnets only those whose MAC is a
// network-equipment maker's are probed (no subnet is swept: a switch agent
// behind a PC's MAC, behind a random MAC or without an ARP entry is never
// asked), and of those only switches are appended to swich_ips. The access
// points, the FortiGate, the ESXi host and the candidate that does not
// answer are named in the run's one log line, the stored switch is not
// probed, collectedData is not changed and no ARP source is made. The
// probes run with the short probe timing, everything else with the poll
// timing.
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
	fakeSNMP.set("10.9.25.7", lldpSwitchAgent(7))    // collected already
	fakeSNMP.set("10.9.25.8", bridgeSwitchAgent(2))  // a Linux bridge behind a PC's NIC
	fakeSNMP.set("10.9.25.9", lldpSwitchAgent(9))    // no ARP entry
	fakeSNMP.set("10.9.25.10", bridgeSwitchAgent(8)) // behind a random MAC
	collectedDataMutex.Lock()
	collectedData["10.9.25.7"] = &DeviceData{IP: "10.9.25.7", SysName: "sw-7"}
	collectedDataMutex.Unlock()
	fakeSNMP.set("10.26.5.5", accessPointAgent("C45"))
	fakeSNMP.set("10.26.5.6", bridgeSwitchAgent(48))
	fakeSNMP.set("10.26.5.7", lldpSwitchAgent(0x57)) // no ARP entry
	setARPCache(map[string]string{
		"18:e8:29:19:25:02": "10.9.25.2",  // Ubiquiti: the access point
		"84:39:8f:19:25:03": "10.9.25.3",  // Fortinet
		"5c:ed:8c:19:25:04": "10.9.25.4",  // HPE: a ProLiant NIC of the ESXi host
		"00:e0:fc:19:25:05": "10.9.25.5",  // Huawei
		"4c:ae:a3:19:25:06": "10.9.25.6",  // HPE
		"4c:ae:a3:19:25:07": "10.9.25.7",  // HPE, stored
		"00:1b:21:19:25:08": "10.9.25.8",  // Intel: a PC
		"da:a1:19:19:25:0a": "10.9.25.10", // random
		"18:e8:29:1a:05:05": "10.26.5.5",  // Ubiquiti
		"00:0f:e2:1a:05:06": "10.26.5.6",  // H3C
		"00:1a:a1:1a:05:08": "10.26.5.8",  // Cisco, no SNMP agent
		"00:1b:21:1a:05:09": "10.26.5.9",  // Intel
		"00:1a:a1:1b:00:01": "10.27.0.1",  // Cisco, outside the gateway's subnets
	})

	obj := &SNMPObject{Community: "public", Port: 161}
	var added []string
	out := captureStdout(t, func() {
		added = subnetDiscovery(obj, nil, subnetTestLimits(subnetDiscoveryDefaults.Workers), appendSwitchIP)
	})
	if want := []string{"10.9.25.5", "10.9.25.6", "10.26.5.6"}; !slices.Equal(added, want) {
		t.Errorf("subnetDiscovery added %v, want %v", added, want)
	}
	if got, want := switchIPAdds.taken(), []string{"10.26.5.6", "10.9.25.5", "10.9.25.6"}; !slices.Equal(got, want) {
		t.Errorf("appended to swich_ips = %v, want %v", got, want)
	}
	candidates := []string{"10.9.25.2", "10.9.25.3", "10.9.25.4", "10.9.25.5", "10.9.25.6", "10.26.5.5", "10.26.5.6", "10.26.5.8"}
	if got := snmpProbes.taken(); !slices.Equal(sortedStrings(got), sortedStrings(candidates)) {
		t.Errorf("probed %v, want the network makers' IPs %v", sortedStrings(got), sortedStrings(candidates))
	}
	want := "🔍 [SubnetDisc] 2 subnets of 172.20.1.254, 12 ARP-known IPs in them, " +
		"9 with a network-equipment maker's MAC (1 of them stored, a gateway's address or in swich_ips), 8 probed, " +
		"3 switches added: 10.9.25.5, 10.9.25.6, 10.26.5.6; not added: 4 devices without BRIDGE-MIB ports or lldpLocChassisId (no switch): " +
		"10.9.25.2 (Sportzal3, U6-Pro 6.8.2.15592), 10.9.25.3 (FortiGate-600F), 10.9.25.4 (localhost, VMware ESXi 6.5.0 build-4887370 VMware, Inc. x86_64) and 1 more; " +
		"1 host did not answer SNMP: 10.26.5.8\n"
	if out != want {
		t.Errorf("output =\n%s\nwant the one summary line\n%s", out, want)
	}
	timings := fakeSNMP.walkTimings()
	for _, ip := range candidates {
		if key := ip + " " + oidSysDescr + " 2s/0"; timings[key] != 1 {
			t.Errorf("%d probes %q, want 1 with the probe timing 2s/0", timings[key], key)
		}
	}
	for key, n := range timings {
		if !strings.HasSuffix(key, " 2s/0") && !strings.HasSuffix(key, " 5s/1") || strings.HasSuffix(key, " 2s/0") && !strings.Contains(key, " "+oidSysDescr+" ") {
			t.Errorf("%d walks %q: want the probe timing 2s/0 for the sysDescr probes only, the poll timing 5s/1 for the rest", n, key)
		}
	}
	if got := collectedIPs(); !slices.Equal(got, []string{"10.9.25.7"}) {
		t.Errorf("subnet discovery changed collectedData: %v", got)
	}
	if got := arpSourceIPs(); len(got) != 0 {
		t.Errorf("subnet discovery made ARP sources: %v", got)
	}
}

// sortedStrings returns a sorted copy of s.
func sortedStrings(s []string) []string { return slices.Sorted(slices.Values(s)) }

// TestSubnetDiscoverySubnets checks which gateway subnets subnet discovery
// searches (it sweeps none: TestSubnetHosts checked the host lists of the
// sweeps it made until 2026-10-22). Each prefix once, also when two
// gateways have it; a subnet inside another stays (its IPs count once,
// TestSubnetDiscoveryEveryGateway); left out are the subnets that are not
// all private (the FortiGate's WAN, the Wi-Fi 172.15.0.0/16 the Debian
// routes, link-local, a /7 reaching past 10.0.0.0/8) and the /31 and /32
// links.
func TestSubnetDiscoverySubnets(t *testing.T) {
	row := func(ip string, bits int) SubnetInfo {
		p := netip.PrefixFrom(netip.MustParseAddr(ip), bits).Masked()
		return SubnetInfo{IP: ip, Prefix: bits, Net: p.Addr().String()}
	}
	search, skipped := subnetDiscoveryPrefixes([]SubnetInfo{
		row("172.20.1.254", 16), row("172.15.1.253", 16), row("195.158.2.221", 27),
		row("10.190.47.58", 30), row("10.190.47.61", 31), row("10.9.38.1", 32),
		row("172.17.1.254", 22), row("172.17.1.1", 21), row("172.20.0.1", 16),
		row("192.168.0.213", 24), row("169.254.1.1", 16), row("10.0.0.1", 7),
	})
	var got []string
	for _, p := range search {
		got = append(got, p.String())
	}
	if want := []string{"172.20.0.0/16", "10.190.47.56/30", "172.17.0.0/22", "172.17.0.0/21", "192.168.0.0/24"}; !slices.Equal(got, want) {
		t.Errorf("searched %v, want %v", got, want)
	}
	if want := []string{"172.15.0.0/16 not private", "195.158.2.192/27 not private", "10.190.47.60/31 a link",
		"10.9.38.1/32 a link", "169.254.0.0/16 not private", "10.0.0.0/7 not private"}; !slices.Equal(skipped, want) {
		t.Errorf("left out %v, want %v", skipped, want)
	}
}

// TestSubnetDiscoveryBounded (F2, and F4 of the gateway review) checks the
// bounds of a run on a gateway shaped like the live ones: a client /16
// full of random MACs and PCs, a /16 with the swich_ips ranges, /30, /31
// and /32 links, the Wi-Fi /16 that is not private, the WAN and the
// loopback. Only the ARP-known IPs with a network maker's MAC are
// candidates, each IP once although two MACs map to it; the gateway's own
// address, the IPs swich_ips lists alone or in a range, a stored switch
// and an interface MAC of it at another IP are not probed; the subnet that
// overlaps swich_ips comes first. With one worker the probes follow the
// plan and a switch is appended as soon as it is found; with the
// production worker count each candidate is probed once; once the time
// budget is spent no probe starts, and the run's one line says so.
func TestSubnetDiscoveryBounded(t *testing.T) {
	resetState(t)
	fakeSNMP.set(fixedGatewayIP, map[string][]string{".1.3.6.1.2.1.4.20.1.3": {
		".1.3.6.1.2.1.4.20.1.3.10.30.0.1 = IpAddress: 255.255.0.0",
		".1.3.6.1.2.1.4.20.1.3.10.31.0.1 = IpAddress: 255.255.0.0",
		".1.3.6.1.2.1.4.20.1.3.10.32.0.1 = IpAddress: 255.255.255.252",
		".1.3.6.1.2.1.4.20.1.3.10.33.0.1 = IpAddress: 255.255.255.255",
		".1.3.6.1.2.1.4.20.1.3.10.34.0.0 = IpAddress: 255.255.255.254",
		".1.3.6.1.2.1.4.20.1.3.127.0.0.1 = IpAddress: 255.0.0.0",
		".1.3.6.1.2.1.4.20.1.3.172.15.1.253 = IpAddress: 255.255.0.0",
		".1.3.6.1.2.1.4.20.1.3.172.20.1.254 = IpAddress: 255.255.0.0",
		".1.3.6.1.2.1.4.20.1.3.195.158.2.221 = IpAddress: 255.255.255.224",
	}})
	cache := map[string]string{
		"00:0c:29:98:7b:c2": fixedGatewayIP,  // the gateway itself, a VMware VM
		"00:1a:a1:1e:00:01": "10.30.0.1",     // the gateway's address in the client /16, a Cisco MAC
		"da:a1:19:1e:00:02": "10.30.1.2",     // the same IP behind a random MAC
		"00:1a:a1:1e:01:02": "10.30.1.2",     // and a Cisco MAC: probed once
		"18:e8:29:1e:01:03": "10.30.1.3",     // a Ubiquiti access point
		"00:1a:a1:1e:01:04": "10.30.1.4",     // Cisco, no SNMP agent
		"00:1b:21:1e:01:05": "10.30.1.5",     // Intel: a PC (its agent has a bridge)
		"4c:ae:a3:1f:05:20": "10.31.5.20",    // inside the listed range 10.31.5.0/24
		"4c:ae:a3:1f:09:09": "10.31.9.9",     // listed alone
		"00:0f:e2:1f:07:07": "10.31.7.7",     // an H3C switch
		"4c:ae:a3:1f:07:08": "10.31.7.8",     // stored already
		"4c:ae:a3:1f:07:89": "10.31.7.9",     // an interface MAC of the stored switch, at an SVI
		"00:10:db:20:00:02": "10.32.0.2",     // Juniper, the /30's peer
		"00:10:db:22:00:01": "10.34.0.1",     // Juniper, the /31's peer: links are not searched
		"18:e8:29:0f:01:50": "172.15.1.80",   // an access point in the Wi-Fi /16
		"00:1a:a1:c3:02:c1": "195.158.2.193", // the ISP's router on the WAN
		"4c:ae:a3:14:e6:32": "172.20.230.50", // an HPE switch nobody listed
	}
	for i := range 30 { // phones and laptops of the client /16
		cache[fmt.Sprintf("de:ad:00:1e:02:%02x", i)] = fmt.Sprintf("10.30.2.%d", i+1)
	}
	setARPCache(cache)
	collectedDataMutex.Lock()
	collectedData["10.31.7.8"] = &DeviceData{IP: "10.31.7.8", SysName: "sw-8", ChassisID: "4c:ae:a3:1f:07:08",
		Interfaces: []InterfaceData{{IfIndex: 1, IfPhysAddress: "4C AE A3 1F 07 89"}}}
	collectedDataMutex.Unlock()
	fakeSNMP.set("10.31.7.7", bridgeSwitchAgent(24))
	fakeSNMP.set("10.31.5.20", lldpSwitchAgent(0x20)) // the rescue scan's, not probed here
	fakeSNMP.set("10.31.7.9", lldpSwitchAgent(0x79))  // the stored switch at its SVI
	fakeSNMP.set("10.30.1.3", accessPointAgent("C46"))
	fakeSNMP.set("10.30.1.5", bridgeSwitchAgent(2))
	fakeSNMP.set("10.32.0.2", lldpSwitchAgent(0x32))
	fakeSNMP.set("10.34.0.1", lldpSwitchAgent(0x34))
	fakeSNMP.set("172.15.1.80", accessPointAgent("C80"))
	fakeSNMP.set("195.158.2.193", lldpSwitchAgent(0xc1))
	fakeSNMP.set("172.20.230.50", lldpSwitchAgent(0x50))
	ranges := []string{"10.31.5.0/24", "10.31.9.9"}

	obj := &SNMPObject{Community: "public", Port: 161}
	plan := planSubnetDiscovery(discoverGatewaySubnets(obj, fixedGatewayIP), ranges)
	var subnets, order []string
	var listed []bool
	for _, p := range plan.Subnets {
		subnets = append(subnets, p.String())
	}
	for _, c := range plan.Candidates {
		order = append(order, c.IP)
		listed = append(listed, c.Listed)
	}
	if want := []string{"10.30.0.0/16", "10.31.0.0/16", "10.32.0.0/30", "172.20.0.0/16"}; !slices.Equal(subnets, want) {
		t.Errorf("subnets %v, want %v", subnets, want)
	}
	if want := []string{"10.33.0.1/32 a link", "10.34.0.0/31 a link", "172.15.0.0/16 not private", "195.158.2.192/27 not private"}; !slices.Equal(plan.Skipped, want) {
		t.Errorf("left out %v, want %v", plan.Skipped, want)
	}
	if got, want := [3]int{plan.ARPIPs, plan.Makers, plan.Known}, [3]int{43, 11, 5}; got != want {
		t.Errorf("ARP-known IPs, makers' IPs, known ones %v, want %v", got, want)
	}
	if want := []string{"10.31.7.7", "10.30.1.2", "10.30.1.3", "10.30.1.4", "10.32.0.2", "172.20.230.50"}; !slices.Equal(order, want) ||
		!slices.Equal(listed, []bool{true, false, false, false, false, false}) {
		t.Errorf("candidates %v (in a listed subnet: %v), want %v with the first one listed", order, listed, want)
	}
	if c := plan.Candidates[1]; c.MAC != "00:1a:a1:1e:01:02" {
		t.Errorf("10.30.1.2 is probed for the MAC %s, want the Cisco one", c.MAC)
	}

	// One worker: the probes follow the plan, and each switch is appended
	// right after its own probe
	var adds []string
	added := subnetDiscovery(obj, ranges, subnetTestLimits(1), func(ip string) bool {
		adds = append(adds, fmt.Sprintf("%s after %d probes", ip, snmpProbes.count()))
		return true
	})
	if probed := snmpProbes.taken(); !slices.Equal(probed, order) {
		t.Errorf("probed %v, want the plan order %v", probed, order)
	}
	if want := []string{"10.31.7.7 after 1 probes", "10.32.0.2 after 5 probes", "172.20.230.50 after 6 probes"}; !slices.Equal(adds, want) {
		t.Errorf("appended %v, want %v", adds, want)
	}
	if want := []string{"10.31.7.7", "10.32.0.2", "172.20.230.50"}; !slices.Equal(added, want) {
		t.Errorf("subnetDiscovery returned %v, want %v", added, want)
	}

	// The production worker count probes the same hosts, each once
	added = subnetDiscovery(obj, ranges, subnetTestLimits(subnetDiscoveryDefaults.Workers), appendSwitchIP)
	if probed := snmpProbes.taken(); !slices.Equal(sortedStrings(probed), sortedStrings(order)) {
		t.Errorf("with %d workers probed %v, want %v", subnetDiscoveryDefaults.Workers, sortedStrings(probed), sortedStrings(order))
	}
	if got, want := switchIPAdds.taken(), []string{"10.31.7.7", "10.32.0.2", "172.20.230.50"}; !slices.Equal(got, want) || !slices.Equal(added, want) {
		t.Errorf("with %d workers appended %v (returned %v), want %v", subnetDiscoveryDefaults.Workers, got, added, want)
	}

	// A budget of one minute, each probe taking 30 s: the probes that start
	// at 0, 30 and 60 s run, the rest do not
	limits := subnetTestLimits(1)
	limits.Budget = time.Minute
	limits.Now = func() time.Time { return fixedTime.Add(time.Duration(snmpProbes.count()) * 30 * time.Second) }
	out := captureStdout(t, func() { added = subnetDiscovery(obj, ranges, limits, appendSwitchIP) })
	if probed := snmpProbes.taken(); !slices.Equal(probed, order[:3]) || !slices.Equal(added, order[:1]) {
		t.Errorf("with the budget probed %v and added %v, want %v and %v", probed, added, order[:3], order[:1])
	}
	want := "🔍 [SubnetDisc] 4 subnets of 172.20.1.254 (4 left out: 10.33.0.1/32 a link, 10.34.0.0/31 a link, 172.15.0.0/16 not private, 195.158.2.192/27 not private), " +
		"43 ARP-known IPs in them, 11 with a network-equipment maker's MAC (5 of them stored, a gateway's address or in swich_ips), " +
		"3 probed (time budget of 1m0s spent: 3 not probed), 1 switch added: 10.31.7.7; " +
		"not added: 1 device without BRIDGE-MIB ports or lldpLocChassisId (no switch): 10.30.1.3 (C46, U6-Pro 6.8.2.15592); 1 host did not answer SNMP: 10.30.1.2\n"
	if out != want {
		t.Errorf("output with the budget =\n%s\nwant\n%s", out, want)
	}
}

// TestSNMPWalkTiming checks that the timing of an SNMP object reaches
// snmpbulkwalk (it used to run every walk with -t 5 -r 1, whatever
// SNMPObject.Timeout said): -t in whole seconds, at least 1, and -r; an
// object without a timeout, and NewSNMPObject, use the poll timing.
func TestSNMPWalkTiming(t *testing.T) {
	resetState(t)
	for _, c := range []struct {
		timing walkTiming
		t, r   string
	}{
		{pollTiming, "5", "1"},
		{subnetDiscoveryDefaults.Probe, "2", "0"},
		{walkTiming{Timeout: 1500 * time.Millisecond}, "2", "0"},
		{walkTiming{Timeout: 200 * time.Millisecond, Retries: -1}, "1", "0"},
	} {
		want := []string{"-v2c", "-c", "public", "-On", "-Cr25", "-t", c.t, "-r", c.r, "10.9.27.1", oidSysDescr}
		if got := snmpBulkWalkArgs("public", "10.9.27.1", oidSysDescr, c.timing); !slices.Equal(got, want) {
			t.Errorf("snmpBulkWalkArgs(%+v) = %q, want %q", c.timing, got, want)
		}
	}
	for _, c := range []struct {
		obj  *SNMPObject
		want string
	}{
		{&SNMPObject{Community: "public"}, "5s/1"},
		{NewSNMPObject(nil, nil), "5s/1"},
		{&SNMPObject{Community: "public", Timeout: 3 * time.Second}, "3s/0"},
		{&SNMPObject{Community: "public", Timeout: 2 * time.Second, Retries: 2}, "2s/2"},
	} {
		fakeSNMP.walkTimings()
		c.obj.runSNMPWalk("10.9.27.1", oidSysName)
		if got := fakeSNMP.walkTimings(); !maps.Equal(got, map[string]int{"10.9.27.1 " + oidSysName + " " + c.want: 1}) {
			t.Errorf("walk of %+v: %v, want the timing %s", c.obj, got, c.want)
		}
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
