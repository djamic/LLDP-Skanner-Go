package main

import (
	"cmp"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// analyzerCase runs Analyze() on hand-made input and returns what it produced.
func analyzerCase(t *testing.T, data FullCaptureData, esxi []string, ignored []string) map[string]any {
	t.Helper()
	resetBot()
	clearConfirmedESXi()
	for _, mac := range esxi {
		ConfirmedESXiMACs.Store(mac, true)
	}
	ignoredIssuesMutex.Lock()
	ignoredIssuesData = map[string]bool{}
	for _, id := range ignored {
		ignoredIssuesData[id] = true
	}
	ignoredIssuesMutex.Unlock()
	defer func() {
		clearConfirmedESXi()
		ignoredIssuesMutex.Lock()
		ignoredIssuesData = map[string]bool{}
		ignoredIssuesMutex.Unlock()
	}()

	report := NewAnalyzer(data).Analyze()
	// These inputs have at most one STP root, so the stp device is fixed.
	suggestions, stpDevice := suggestionRecords(report)
	return map[string]any{
		"stp_device":   stpDevice,
		"health_score": report.HealthScore,
		"summary":      report.Summary,
		"suggestions":  suggestions,
		"bot_messages": bot.taken(),
		"last_report":  lastReportRecord(),
	}
}

func devicesData(devices ...*DeviceData) []DeviceData {
	return deviceValues(devices)
}

// TestGoldenScenarioAnalyzer pins analyzer rules on hand-made input: the
// LLDP loopback check with empty chassis ids, MAC self-reference, every
// Shadow-IT filter (random MACs, trunk, VM port, confirmed ESXi, ignored
// issue), STP with one root and with the root on a core switch, path
// analysis from the gateway and from a router, congestion/stability input,
// the health score caps, and a capture without device data.
func TestGoldenScenarioAnalyzer(t *testing.T) {
	resetState(t)
	rec := map[string]any{}

	rec["loopback_empty_chassis"] = analyzerCase(t, FullCaptureData{DevicesData: devicesData(&DeviceData{
		IP: "10.0.9.21", ChassisID: "",
		Neighbors:  []LLDPNeighbor{{LocalPortNum: 3, RemIndex: 1, RemChassisId: ""}},
		Interfaces: []InterfaceData{{IfIndex: 3, IfDescr: "GigabitEthernet1/0/3"}},
	})}, nil, nil)

	rec["loopback_self_mac"] = analyzerCase(t, FullCaptureData{DevicesData: devicesData(&DeviceData{
		IP: "10.0.9.22", ChassisID: "4C AE A3 09 00 22",
		Neighbors:  []LLDPNeighbor{{LocalPortNum: 9, RemIndex: 1, RemChassisIdSubtype: 4, RemChassisId: "4C AE A3 09 00 22"}},
		Interfaces: []InterfaceData{{IfIndex: 9, IfDescr: "\"GigabitEthernet1/0/9\""}},
		MACTable:   append(macEntries(7, "4c:ae:a3:09:00:22"), macEntries(8, "4c:ae:a3:09:00:22")...),
		PortVLANs:  []PortVLAN{{PortIndex: 8, PVID: 1, IsTrunk: true}},
	})}, nil, nil)

	var shadowMACs []MACEntry
	shadowMACs = append(shadowMACs, macEntries(1, "00:50:56:09:23:01", "00:50:56:09:23:02", "da:a1:19:09:23:03", "de:a1:19:09:23:04", "00:1b:21:09:23:05")...)
	shadowMACs = append(shadowMACs, macEntries(2, "00:1b:21:09:23:21", "00:1b:21:09:23:22")...)
	shadowMACs = append(shadowMACs, macEntries(3, "00:1b:21:09:23:31", "00:1b:21:09:23:32")...)
	shadowMACs = append(shadowMACs, macEntries(4, "00:1b:21:09:24:01", "00:1b:21:09:24:02")...)
	shadowMACs = append(shadowMACs, macEntries(5, "00:1b:21:09:23:51", "00:1b:21:09:23:52")...)
	shadowMACs = append(shadowMACs, macEntries(6, "00:0c:29:09:23:61", "00:0c:29:09:23:62", "00:0c:29:09:23:63")...)
	shadowMACs = append(shadowMACs, macEntries(7, "00:1b:21:09:23:71", "da:a1:19:09:23:72", "de:a1:19:09:23:73")...)
	shadowMACs = append(shadowMACs, macEntries(8, "52:54:00:09:23:81", "52:54:00:09:23:82")...)
	shadowMACs = append(shadowMACs, macEntries(9, "bc:24:11:09:23:91", "bc:24:11:09:23:92")...)
	rec["shadow_it_rules"] = analyzerCase(t, FullCaptureData{DevicesData: devicesData(&DeviceData{
		IP: "10.0.9.23", ChassisID: "4c:ae:a3:09:00:23", MACTable: shadowMACs,
		PortVLANs: []PortVLAN{{PortIndex: 3, PVID: 1, IsTrunk: true}},
	})}, []string{"00:1b:21:09:24:01"}, []string{"shadow_10_0_9_23_5"})

	stp := STPData{Enabled: true, Protocol: "stp", RootBridgeID: "00:16:e0:5a:5c:e0"}
	rec["stp_single_root"] = analyzerCase(t, FullCaptureData{DevicesData: devicesData(
		&DeviceData{IP: "10.0.9.24", ChassisID: "4c:ae:a3:09:00:24", STPInfo: stp},
		&DeviceData{IP: "10.0.9.25", ChassisID: "4c:ae:a3:09:00:25", STPInfo: stp},
		&DeviceData{IP: "10.0.9.26", ChassisID: "4c:ae:a3:09:00:26", STPInfo: STPData{Enabled: true}},
	)}, nil, nil)
	rec["stp_root_on_core"] = analyzerCase(t, FullCaptureData{
		DevicesData: devicesData(&DeviceData{
			IP: "10.0.9.27", ChassisID: "00:16:e0:5a:5c:e0", STPInfo: stp,
			Interfaces: []InterfaceData{{IfIndex: 1, IfDescr: "Vlan1", IfPhysAddress: "00:16:E0:5A:5C:E0"}},
		}),
		Topology: GraphData{Nodes: []GraphNode{{ID: "10.0.9.27", NodeType: "switch", Group: "switch"}}},
	}, nil, nil)

	chain := func(core string, coreType string) GraphData {
		ids := []string{core, "10.0.9.31", "10.0.9.32", "10.0.9.33", "10.0.9.34", "10.0.9.35"}
		var gd GraphData
		for i, id := range ids {
			n := GraphNode{ID: id, NodeType: "switch", Group: "switch", SysName: "sw-" + id}
			if i == 0 {
				n.NodeType, n.Group = coreType, coreType
			}
			gd.Nodes = append(gd.Nodes, n)
			if i > 0 {
				gd.Links = append(gd.Links, GraphLink{Source: ids[i-1], Target: id, Label: "GE1/0/1|GE1/0/2"})
			}
		}
		return gd
	}
	rec["path_from_gateway"] = analyzerCase(t, FullCaptureData{Topology: chain(fixedGatewayIP, "switch")}, nil, nil)
	rec["path_from_router"] = analyzerCase(t, FullCaptureData{Topology: chain("10.0.9.30", "router")}, nil, nil)

	var manyShadow []MACEntry
	for p := 1; p <= 6; p++ {
		manyShadow = append(manyShadow, macEntries(p, fmt.Sprintf("00:1b:21:09:3%d:01", p), fmt.Sprintf("00:1b:21:09:3%d:02", p))...)
	}
	rec["health_caps_and_traffic"] = analyzerCase(t, FullCaptureData{
		DevicesData: devicesData(&DeviceData{IP: "10.0.9.36", ChassisID: "4c:ae:a3:09:00:36", MACTable: manyShadow}),
		Metrics: []TrafficMetrics{
			{DeviceIP: "10.0.9.36", Interface: "GE1/0/1", InBps: 700_000_000, OutBps: 200_000_000},
			{DeviceIP: "10.0.9.36", Interface: "GE1/0/2", InDiscards: 5, OutDiscards: 2},
			{DeviceIP: "10.0.9.36", Interface: "GE1/0/3", InErrors: 9},
		},
		Events: []StatusEvent{
			{DeviceIP: "10.0.9.36", Interface: "GE1/0/4", OldStatus: 1, NewStatus: 2},
			{DeviceIP: "10.0.9.36", Interface: "GE1/0/4", OldStatus: 2, NewStatus: 1},
			{DeviceIP: "10.0.9.36", Interface: "GE1/0/4", OldStatus: 1, NewStatus: 2},
		},
	}, nil, nil)

	rec["capture_without_devices"] = analyzerCase(t, FullCaptureData{
		Session:  CaptureSession{ID: "capture", Name: "capture", StartTime: fixedTime},
		Topology: GraphData{Nodes: []GraphNode{{ID: "10.0.9.40", NodeType: "switch", Group: "switch"}}},
	}, nil, nil)

	checkGolden(t, "scenario_analyzer.json", goldenJSON(t, rec, 3))
}

// Fake SNMP agents in snmpbulkwalk -On output format.
const (
	oidChassis  = ".1.0.8802.1.1.2.1.3.2.0"
	oidIfDescr  = ".1.3.6.1.2.1.2.2.1.2"
	oidLLDPRem  = ".1.0.8802.1.1.2.1.4.1.1"
	oidLLDPMan  = ".1.0.8802.1.1.2.1.4.2.1"
	oidFDBPort  = ".1.3.6.1.2.1.17.4.3.1.2"
	oidARP      = ".1.3.6.1.2.1.4.22.1.2"
	oidPVID     = ".1.3.6.1.2.1.17.7.1.4.5.1.1"
	oidVLANEgr  = ".1.3.6.1.2.1.17.7.1.4.2.1.4"
	oidSTPProto = ".1.3.6.1.2.1.17.2.1"
	oidSTPRoot  = ".1.3.6.1.2.1.17.2.5"
	oidSTPCost  = ".1.3.6.1.2.1.17.2.6"
	oidSTPPort  = ".1.3.6.1.2.1.17.2.7"
	// dot1dBasePortIfIndex: bridge port number → ifIndex. CollectData does
	// not walk it today; the answer is there for the bridge-port mapping.
	oidBasePortIf = ".1.3.6.1.2.1.17.1.4.1.2"
)

// healthyAgent answers every walk CollectData makes, with the value shapes
// seen on real switches (quoted strings, Hex-STRING with trailing space,
// printable STRING MACs, exception text, short OIDs and garbage lines), and
// the bridge-port → ifIndex table, where bridge port 1 is not ifIndex 1.
func healthyAgent() map[string][]string {
	walks := map[string][]string{
		oidChassis: {oidChassis + " = Hex-STRING: F8 F0 82 D8 7E 81 "},
		oidIfDescr: {
			oidIfDescr + ".1 = STRING: \"GigabitEthernet1/0/1\"",
			oidIfDescr + ".2 = STRING: \"GigabitEthernet1/0/2\"",
			oidIfDescr + ".25 = STRING: \"GigabitEthernet1/0/25\"",
			oidIfDescr + ".28 = STRING: \"GigabitEthernet1/0/28\"",
			oidIfDescr + ".50 = STRING: \"NULL0\"",
			oidIfDescr + ".101 = STRING: \"Ten-GigabitEthernet1/0/49\"",
		},
		// ifSpeed and ifHighSpeed are walked concurrently and both write
		// IfSpeed, so no interface gets both (the result would depend on
		// goroutine timing).
		".1.3.6.1.2.1.2.2.1.5":     {".1.3.6.1.2.1.2.2.1.5.1 = Gauge32: 1000000000", ".1.3.6.1.2.1.2.2.1.5.2 = Gauge32: 4294967295"},
		".1.3.6.1.2.1.31.1.1.1.15": {".1.3.6.1.2.1.31.1.1.1.15.28 = Gauge32: 10000"},
		".1.3.6.1.2.1.2.2.1.7":     {".1.3.6.1.2.1.2.2.1.7.1 = INTEGER: 1", ".1.3.6.1.2.1.2.2.1.7.28 = INTEGER: 1"},
		".1.3.6.1.2.1.2.2.1.8":     {".1.3.6.1.2.1.2.2.1.8.1 = INTEGER: 1", ".1.3.6.1.2.1.2.2.1.8.2 = INTEGER: 2", ".1.3.6.1.2.1.2.2.1.8.28 = INTEGER: 1"},
		".1.3.6.1.2.1.31.1.1.1.18": {".1.3.6.1.2.1.31.1.1.1.18.1 = STRING: \"to-printer\""},
		".1.3.6.1.2.1.2.2.1.10":    {".1.3.6.1.2.1.2.2.1.10.1 = Counter32: 1234"},
		".1.3.6.1.2.1.2.2.1.14":    {".1.3.6.1.2.1.2.2.1.14.1 = Counter32: 3"},
		".1.3.6.1.2.1.31.1.1.1.6":  {".1.3.6.1.2.1.31.1.1.1.6.1 = Counter64: 99999999999"},
		oidLLDPRem: {
			oidLLDPRem + ".4.3900.28.1 = INTEGER: 4",
			oidLLDPRem + ".5.3900.28.1 = Hex-STRING: F8 F0 82 D1 67 5E ",
			oidLLDPRem + ".6.3900.28.1 = INTEGER: 5",
			oidLLDPRem + ".7.3900.28.1 = STRING: \"GigabitEthernet1/0/26\"",
			oidLLDPRem + ".8.3900.28.1 = STRING: \"uplink to core\"",
			oidLLDPRem + ".9.3900.28.1 = STRING: \"sw-core\"",
			oidLLDPRem + ".10.3900.28.1 = STRING: \"SNR S2985G-24T\"",
			oidLLDPRem + ".4.5600.25.2 = INTEGER: 7",
			oidLLDPRem + ".5.5600.25.2 = STRING: \"DESKTOP-V380CHD\"",
			oidLLDPRem + ".6.5600.25.2 = INTEGER: 3",
			oidLLDPRem + ".7.5600.25.2 = Hex-STRING: 10 7C 61 C0 9E AA ",
			oidLLDPRem + ".5.12500.2.7 = Hex-STRING: 00 00 00 00 00 00 ",
			oidLLDPRem + ".5.9 = INTEGER: 1",
			"garbage line without separator",
		},
		oidLLDPMan: {
			oidLLDPMan + ".3.3900.28.1.1.4.172.20.0.3 = INTEGER: 2",
			oidLLDPMan + ".4.3900.28.1.1.4.172.20.0.3 = INTEGER: 26",
		},
		// FDB ports are bridge port numbers. Bridge port 1 is ifIndex 101
		// (dot1dBasePortIfIndex below), the others equal their ifIndex.
		oidFDBPort: {
			oidFDBPort + ".0.27.33.9.1.1 = INTEGER: 1",
			oidFDBPort + ".0.80.86.1.2.3 = INTEGER: 5",
			oidFDBPort + ".248.240.130.209.103.94 = INTEGER: 28",
			oidFDBPort + ".16.124.97.192.158.170 = INTEGER: 25",
			oidFDBPort + ".0.27.33.9.0.1 = INTEGER: 0",
			oidFDBPort + ".1.2.3 = INTEGER: 3",
			oidFDBPort + ".0.27.33.9.999.1 = INTEGER: 7",
			oidFDBPort + ".1.0.94.0.0.251 = INTEGER: 2",
		},
		oidARP: {
			oidARP + ".5.172.20.1.105 = Hex-STRING: 00 0C 29 6F E0 BC ",
			oidARP + ".5.172.20.1.106 = STRING: \"P(J3:L\"",
			oidARP + ".5.172.20.1.107 = Hex-STRING: 01 00 5E 00 00 FB ",
			oidARP + ".5.172.20.1.108 = Hex-STRING: 00 00 00 12 34 56 ",
			oidARP + ".5.172.20.1.109 = Hex-STRING: FF FF FF FF FF FF ",
			oidARP + ".5.0.0.0.5 = Hex-STRING: 00 50 56 01 02 04 ",
			oidARP + ".5.172.20.1.110 = Hex-STRING: 00 50 56 01 02 ",
			oidARP + ".5.172.20.1.111 = Hex-STRING: 00 50 56 01 02 04 ",
			oidARP + ".172.20.1.112 = Hex-STRING: 00 50 56 01 02 05 ",
			oidARP + ".5.172.20.1.113 = STRING: \"f8-f0-82-7a-d9-69\"",
		},
		oidPVID: {
			oidPVID + ".1 = Gauge32: 100",
			oidPVID + ".2 = Gauge32: 1",
			oidPVID + ".25 = Gauge32: 1",
			oidPVID + ".28 = Gauge32: 1",
			oidPVID + ".0 = Gauge32: 1",
		},
		oidSTPProto: {oidSTPProto + ".0 = INTEGER: 3"},
		oidSTPRoot:  {oidSTPRoot + ".0 = Hex-STRING: 80 00 00 16 E0 5A 5C E0 "},
		oidSTPCost:  {oidSTPCost + ".0 = INTEGER: 4"},
		oidSTPPort:  {oidSTPPort + ".0 = INTEGER: 28"},
		oidBasePortIf: {
			oidBasePortIf + ".1 = INTEGER: 101",
			oidBasePortIf + ".2 = INTEGER: 2",
			oidBasePortIf + ".5 = INTEGER: 5",
			oidBasePortIf + ".25 = INTEGER: 25",
			oidBasePortIf + ".28 = INTEGER: 28",
		},
	}
	var egress []string
	for vlan := 1; vlan <= 7; vlan++ {
		egress = append(egress, fmt.Sprintf("%s.0.%d = Hex-STRING: 00 00 00 10 ", oidVLANEgr, vlan))
	}
	egress = append(egress, oidVLANEgr+".0.100 = Hex-STRING: 80 00 00 00 ")
	walks[oidVLANEgr] = egress
	return walks
}

type collectResult struct {
	Callback    string          `json:"callback"`
	ChassisID   string          `json:"chassis_id,omitempty"`
	SysName     string          `json:"sys_name,omitempty"`
	Interfaces  []InterfaceData `json:"interfaces,omitempty"`
	Neighbors   []LLDPNeighbor  `json:"neighbors,omitempty"`
	MACTableNil bool            `json:"mac_table_nil"`
	MACTable    []MACEntry      `json:"mac_table,omitempty"`
	ARPTable    []ARPEntry      `json:"arp_table,omitempty"`
	PortVLANs   []PortVLAN      `json:"port_vlans,omitempty"`
	STPInfo     STPData         `json:"stp"`
}

// collect runs CollectData against the fake agent at ip and returns the
// delivered data in a canonical order.
func collect(ip, sysName string) collectResult {
	var res collectResult
	obj := NewSNMPObject(func(d *DeviceData) {
		res.Callback = "success"
		res.ChassisID = d.ChassisID
		res.SysName = d.SysName
		res.Interfaces = slices.Clone(d.Interfaces)
		res.Neighbors = slices.Clone(d.Neighbors)
		res.MACTableNil = d.MACTable == nil
		res.MACTable = d.MACTable
		res.ARPTable = d.ARPTable
		res.PortVLANs = slices.Clone(d.PortVLANs)
		res.STPInfo = d.STPInfo
	}, func(_ string, err error) {
		res.Callback = "failure: " + err.Error()
	})
	obj.CollectData(ip, sysName)
	slices.SortFunc(res.Interfaces, func(a, b InterfaceData) int { return cmp.Compare(a.IfIndex, b.IfIndex) })
	slices.SortFunc(res.Neighbors, func(a, b LLDPNeighbor) int {
		return cmp.Or(cmp.Compare(a.LocalPortNum, b.LocalPortNum), cmp.Compare(a.RemIndex, b.RemIndex))
	})
	slices.SortFunc(res.PortVLANs, func(a, b PortVLAN) int { return cmp.Compare(a.PortIndex, b.PortIndex) })
	return res
}

// TestGoldenScenarioSNMPCollect pins CollectData on fake agents: a healthy
// switch, SNMP exception text and a printable 6-byte STRING as the local
// chassis id, a Cisco-dotted chassis id, a switch whose FDB walk fails while
// the rest succeeds, and a switch where every walk fails.
func TestGoldenScenarioSNMPCollect(t *testing.T) {
	resetState(t)
	fakeSNMP.set("10.9.0.1", healthyAgent())
	fakeSNMP.set("10.9.0.2", map[string][]string{
		oidChassis: {oidChassis + " = No Such Object available on this agent at this OID"},
		oidIfDescr: {oidIfDescr + ".1 = STRING: \"GigabitEthernet0/1\""},
	})
	fakeSNMP.set("10.9.0.3", map[string][]string{
		oidChassis: {oidChassis + " = STRING: \"pM{?WA\""},
	})
	fakeSNMP.set("10.9.0.6", map[string][]string{
		oidChassis: {oidChassis + " = STRING: \"5894.8000.f7a3\""},
		oidIfDescr: {oidIfDescr + ".1 = STRING: \"Gi0/1\""},
	})
	noFDB := healthyAgent()
	delete(noFDB, oidFDBPort)
	fakeSNMP.set("10.9.0.5", noFDB)

	rec := map[string]collectResult{
		"healthy_10.9.0.1":           collect("10.9.0.1", "sw-a"),
		"exception_chassis_10.9.0.2": collect("10.9.0.2", "sw-x"),
		"string_chassis_10.9.0.3":    collect("10.9.0.3", ""),
		"all_walks_fail_10.9.0.4":    collect("10.9.0.4", "sw-down"),
		"fdb_walk_fails_10.9.0.5":    collect("10.9.0.5", "sw-partial"),
		"dotted_chassis_10.9.0.6":    collect("10.9.0.6", "cisco"),
	}
	checkGolden(t, "scenario_snmp.json", goldenJSON(t, rec, 3))
}

// TestGoldenScenarioMACIPCache pins the MAC→IP cache and the ESXi queue:
// ARP collection from a switch and from the gateway (one policy: last write
// wins, Q11 filter, observed MACs asked for the ESXi check), loading the
// cache file (canonical keys, Q11 filter, nothing queued), saving it, the
// confirmed-ESXi skip, and the cache over 30 days on the test clock.
func TestGoldenScenarioMACIPCache(t *testing.T) {
	resetState(t)
	fakeSNMP.set("10.9.0.1", healthyAgent())
	rec := map[string]any{}
	snapshotMap := func() map[string]string {
		globalMACtoIPMutex.RLock()
		defer globalMACtoIPMutex.RUnlock()
		return maps.Clone(globalMACtoIP)
	}
	setMap := func(m map[string]string) {
		globalMACtoIPMutex.Lock()
		globalMACtoIP = m
		globalMACtoIPMutex.Unlock()
	}
	obj := &SNMPObject{Community: "public", Port: 161, Timeout: 10 * time.Second, Retries: 1}

	setMap(map[string]string{"00:50:56:01:02:04": "10.0.0.99"})
	added := collectARPFromSwitch(obj, "10.9.0.1")
	rec["arp_from_switch"] = map[string]any{"added": added, "mac_to_ip": snapshotMap(), "queued": esxiJobs.taken()}

	setMap(map[string]string{"00:50:56:01:02:04": "10.0.0.99"})
	gatewayIP = "10.9.0.1"
	collectGatewayARP()
	gatewayIP = fixedGatewayIP
	rec["gateway_arp"] = map[string]any{"mac_to_ip": snapshotMap(), "queued": esxiJobs.taken()}

	dir := t.TempDir()
	macIPCacheFile = filepath.Join(dir, "mac_ip_cache.json")
	cacheJSON := `{"AA:BB:CC:00:00:01": "10.0.0.1", "01:00:5e:00:00:fb": "10.0.0.2", "00:00:00:12:34:56": "10.0.0.3", "00:50:56:00:00:09": "10.0.0.4", "00:50:56:00:00:0a": ""}`
	if err := os.WriteFile(macIPCacheFile, []byte(cacheJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	setMap(map[string]string{"00:50:56:00:00:09": "10.0.0.40"})
	ConfirmedESXiMACs.Store("01:00:5e:00:00:fb", true)
	loadMacIPCache()
	clearConfirmedESXi()
	rec["load_cache"] = map[string]any{"file": cacheJSON, "mac_to_ip": snapshotMap(), "queued": esxiJobs.taken()}

	macIPCacheFile = filepath.Join(dir, "missing.json")
	setMap(map[string]string{"00:50:56:00:00:09": "10.0.0.40"})
	loadMacIPCache()
	rec["load_missing_cache"] = map[string]any{"mac_to_ip": snapshotMap(), "queued": esxiJobs.taken()}

	macIPCacheFile = filepath.Join(dir, "saved.json")
	setMap(map[string]string{"00:50:56:00:00:09": "10.0.0.40", "aa:bb:cc:00:00:01": "10.0.0.1"})
	saveMacIPCache()
	saved, err := os.ReadFile(macIPCacheFile)
	if err != nil {
		t.Fatal(err)
	}
	entries, _ := os.ReadDir(dir)
	var files []string
	for _, e := range entries {
		files = append(files, e.Name())
	}
	rec["save_cache"] = map[string]any{"content": string(saved), "files": files}

	ConfirmedESXiMACs.Store("00:50:56:00:00:01", true)
	queueESXiValidation("00:50:56:00:00:01", "10.0.0.1")
	queueESXiValidation("00:50:56:00:00:02", "10.0.0.2")
	queueESXiValidation("00:50:56:00:00:02", "10.0.0.2")
	clearConfirmedESXi()
	rec["queue_validation"] = map[string]any{"queued": esxiJobs.taken()}

	rec["cache_aging"] = cacheAging(t, filepath.Join(dir, "aging.json"))

	checkGolden(t, "scenario_cache.json", goldenJSON(t, rec, 3))
}

// cacheAging runs the cache through 30 days on the test clock: load three
// entries (the file has no sidecar, so they count as just seen), see one of
// them again with a new IP plus a new MAC an hour later, see the same ARP
// table 30 days later, run a sweep while the gateway does not answer (no
// entry expires), then a sweep where the gateway answers with one MAC
// (entries unseen for more than the TTL expire, H8), and save: the cache in
// the "mac": "ip" form, the last-seen times in the sidecar.
func cacheAging(t *testing.T, path string) []map[string]any {
	t.Helper()
	macIPCacheFile = path
	cacheJSON := `{"00:1b:21:0a:00:01": "10.0.1.1", "00:1b:21:0a:00:02": "10.0.1.2", "00:50:56:0a:00:03": "10.0.1.3"}`
	if err := os.WriteFile(path, []byte(cacheJSON), 0o644); err != nil {
		t.Fatal(err)
	}
	fakeSNMP.set("10.9.0.7", map[string][]string{oidARP: {
		oidARP + ".5.10.0.1.11 = Hex-STRING: 00 1B 21 0A 00 01 ",
		oidARP + ".5.10.0.1.4 = Hex-STRING: 00 1B 21 0A 00 04 ",
	}})
	globalMACtoIPMutex.Lock()
	globalMACtoIP = map[string]string{}
	collectMACIPSeen = map[string]time.Time{}
	macIPGatewayOK = time.Time{} // no gateway answer yet in this run
	globalMACtoIPMutex.Unlock()
	esxiJobs.reset()
	obj := &SNMPObject{Community: "public", Port: 161, Timeout: 10 * time.Second, Retries: 1}
	state := func(step string) map[string]any {
		globalMACtoIPMutex.RLock()
		defer globalMACtoIPMutex.RUnlock()
		return map[string]any{"step": step, "clock": testClock.Now().Format(time.RFC3339), "mac_to_ip": maps.Clone(globalMACtoIP), "queued": esxiJobs.taken()}
	}
	var steps []map[string]any
	loadMacIPCache()
	steps = append(steps, state("load "+cacheJSON))
	testClock.advance(time.Hour)
	collectARPFromSwitch(obj, "10.9.0.7")
	steps = append(steps, state("ARP: 00:1b:21:0a:00:01 now 10.0.1.11, new 00:1b:21:0a:00:04"))
	testClock.advance(30 * 24 * time.Hour)
	collectARPFromSwitch(obj, "10.9.0.7")
	steps = append(steps, state("same ARP table 30 days later"))
	collectARPFromAllSwitches()
	steps = append(steps, state("sweep, the gateway does not answer"))
	fakeSNMP.set(fixedGatewayIP, map[string][]string{oidARP: {oidARP + ".5.10.0.1.11 = Hex-STRING: 00 1B 21 0A 00 01 "}})
	collectARPFromAllSwitches()
	fakeSNMP.set(fixedGatewayIP, nil)
	saveMacIPCache()
	last := state("sweep, the gateway answers with 00:1b:21:0a:00:01, then save")
	for name, file := range map[string]string{"saved": path, "saved_sidecar": macIPSeenFile()} {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		last[name] = string(data)
	}
	return append(steps, last)
}

// TestNoSideEffectSeamsLeak checks the harness itself: the stubs answer
// without the network, and production defaults are still in place for
// everything the stubs do not cover.
func TestNoSideEffectSeamsLeak(t *testing.T) {
	resetState(t)
	if _, err := snmpWalk("public", "192.0.2.1", oidChassis); err == nil || !strings.Contains(err.Error(), "fake snmp") {
		t.Errorf("snmpWalk is not the fake agent: %v", err)
	}
	if _, err := snmpProbeWalk("public", "192.0.2.1", oidSysDescr); err == nil || !strings.Contains(err.Error(), "fake snmp") || !slices.Equal(snmpProbes.taken(), []string{"192.0.2.1"}) {
		t.Errorf("snmpProbeWalk is not the probe recorder over the fake agent: %v", err)
	}
	if out, err := runPing("192.0.2.1"); err != nil || !strings.Contains(out, "ttl=64") {
		t.Errorf("runPing is not the fake ping: %q %v", out, err)
	}
	if gatewayIP != fixedGatewayIP {
		t.Error("harness settings were changed by a test")
	}
	if influxReady() {
		t.Error("InfluxDB recording is on outside a recording window")
	}
	if !eventClock().Equal(fixedTime) || !macIPClock().Equal(fixedTime) {
		t.Error("eventClock or macIPClock is not the test clock")
	}
	if globalCaptureManager == nil || globalCaptureManager.paramDir != guardCapturesDir || ouiFile != "oui.txt" {
		t.Errorf("file seams were changed by a test: capture manager %+v, oui %q", globalCaptureManager, ouiFile)
	}
	if appendSwitchIP("192.0.2.9"); !slices.Equal(switchIPAdds.taken(), []string{"192.0.2.9"}) {
		t.Error("appendSwitchIP is not the recorder: swich_ips could be written")
	}
	startMacIPCollector()
	startLiveAnalysis(NewDJGraph())
	if macIPCollectorStarts.Load() != 1 || liveAnalyses.Load() != 1 {
		t.Error("startMacIPCollector or startLiveAnalysis is not the stub")
	}
}
