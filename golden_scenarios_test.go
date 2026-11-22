package main

import (
	"fmt"
	"maps"
	"slices"
	"testing"
)

// graphView is a compact, sorted view of a small graph: node id → "group |
// SwitchInfo" and one "src -> dst : label" line per edge.
type graphView struct {
	Nodes  map[string]string `json:"nodes"`
	Edges  []string          `json:"edges"`
	Status map[string]string `json:"status,omitempty"`
}

func viewGraph(g *DJGraph) graphView {
	v := graphView{Nodes: map[string]string{}}
	for id := range g.Nodes {
		v.Nodes[id] = g.determineDeviceGroup(id, g.SwitchInfo[id]) + " | " + g.SwitchInfo[id]
	}
	for src, targets := range g.Edges {
		for tgt, label := range targets {
			v.Edges = append(v.Edges, fmt.Sprintf("%s -> %s : %q", src, tgt, label))
		}
	}
	slices.Sort(v.Edges)
	if len(g.NodeStatus) > 0 {
		v.Status = maps.Clone(g.NodeStatus)
	}
	return v
}

func addInfoNode(g *DJGraph, id, info string) {
	g.AddNode(id)
	if info != "" {
		setLabel(g, id, info) // with its tags, as the build's writers
	}
}

// TestGoldenScenarioTables pins small rule tables: determineDeviceGroup for
// tag combinations and id shapes, NULL-port detection, port-name
// normalization, the reverse-DNS name trimming, and detectOSFromMAC /
// detectOSByTTL with the fake ping.
func TestGoldenScenarioTables(t *testing.T) {
	resetState(t)
	g := NewDJGraph()
	groupCases := [][2]string{
		{"aa:bb:cc:dd:ee:ff", "[HYPERVISOR] HPE Server\n[ENDPOINT]"},
		{"02:11:22:33:44:55", "[HYPERVISOR] VMware ESXi\n[WiFi]"},
		{"0c:c4:7a:11:22:33", "[HYPERVISOR] VMware ESXi\n[BMC] Supermicro IPMI"},
		{"00:50:56:11:22:33", "[HYPERVISOR] VMware ESXi\n[VM] 💻 VMware VM VMware"},
		{"5c:ed:8c:11:22:33", "[HYPERVISOR] HPE ProLiant Server\n[LLDP-EP] Intel"},
		{"4c:ae:a3:11:22:33", "[HYPERVISOR] VMware ESXi\nSNR-S2985G\n172.20.230.5"},
		{"00:26:ab:11:22:33", "[ENDPOINT] Epson"},
		{"e4:38:83:11:22:33", "[ENDPOINT] Ubiquiti"},
		{"54:c4:15:11:22:33", "[LLDP-EP] Hikvision"},
		{"28:6c:07:11:22:33", "[ENDPOINT] Xiaomi"},
		{"cc:50:e3:11:22:33", "[ENDPOINT] ESP (Espressif)"},
		{"00:0c:29:11:22:33", "[ENDPOINT] VMware"},
		{"52:54:00:11:22:33", "[WiFi] QEMU/KVM"},
		{"4c:ae:a3:27:84:cb", "[LLDP-EP] SNR\nB-318/1"},
		{"00:00:0c:07:ac:01", "[ENDPOINT] Cisco Systems, Inc"},
		{"5894.8000.f7a3", "[LLDP-EP]"},
		{"B-318/1", "[LLDP-EP]\nB-318/1"},
		{"DESKTOP-V380CHD", "[LLDP-EP]"},
		{"no:such:object:available:on:this:agent:at:this:oid", "sw-x\n172.20.230.9"},
		{"4c:ae:a3:8e:42:11", "SNR-S2985G-24T\n172.20.230.4"},
		{"4c:ae:a3:8e:42:12", "HPE\n172.20.230.5"},
		{"4c:ae:a3:8e:42:13", "Core Router\n172.20.230.6"},
		{"4c:ae:a3:8e:42:14", "MikroTik RB4011\n172.20.230.7"},
		{"4c:ae:a3:8e:42:15", "Linux box\n172.20.230.8"},
		{"10.0.0.2", "Server-room switch\n10.0.0.2"},
		{"10.0.0.9", ""},
		{"hub-4c:ae:a3:8e:42:11-p7", ""},
		{"hub-x", "[HUB] Unmanaged\n3 devices"},
		{"hyp-4c:ae:a3:8e:42:11-ge1_0_9", ""},
		{"bmc-1", ""},
		{"vm-1", ""},
		{"x", "[BMC] Dell iDRAC\nsrv1"},
		{"x", "[VM] 🐧 Linux"},
		{"router-1", ""},
		{"switch-1", ""},
		{"linux-node", ""},
	}
	var groups []map[string]string
	for _, c := range groupCases {
		groups = append(groups, map[string]string{"node": c[0], "info": c[1], "group": g.determineDeviceGroup(c[0], c[1])})
	}

	var nulls []map[string]any
	for _, name := range []string{"NULL0", "\"NULL0\"", "Null0", "null 0", "InLoopBack0", "\"InLoopBack0\"", "", "Port 0", "Port 7", "GigabitEthernet1/0/1", "Vlan-interface1"} {
		nulls = append(nulls, map[string]any{"name": name, "null": isNullInterface(name)})
	}

	var ports []map[string]string
	for _, name := range []string{
		"GigabitEthernet1/0/26", "GigabitF1/0/26", "Ten-GigabitEthernet1/0/49", "TenGigabitEthernet1/0/49",
		"\"GigabitEthernet1/0/47\"", "4c:ae:a3:a2:06:2c:GE1/0/43", "fastethernet 0/1", "FastEthernet0/1",
		"HundredGigE1/0/1", "Ethernet1/1", "GE1/0/26 [T]", "GE1/0/9 1G ↓5M ↑3M", "\"NULL0\"", "port", "Port 12",
	} {
		ports = append(ports, map[string]string{"in": name, "normalizePortName": normalizePortName(name), "hypervisorKey": normalizePortForHypervisor(name)})
	}

	var dns []map[string]string
	for _, ip := range []string{"195.158.2.202", "172.16.16.223", "172.16.1.153", "172.20.230.15", "172.20.230.16", "10.0.9.13", "8.8.8.8", "999.999.999.999", ""} {
		dns = append(dns, map[string]string{"ip": ip, "resolveHostname": resolveHostname(ip)})
	}

	neighbors := &DeviceData{Neighbors: []LLDPNeighbor{
		{RemChassisId: "00 50 56 00 00 21", RemSysName: "DESKTOP-ABC"},
		{RemChassisId: "00:50:56:00:00:25", RemSysName: "ubuntu-web01"},
		{RemChassisId: "52:54:00:00:00:26", RemSysName: "WIN-SRV2019"},
	}}
	macToIP := map[string]string{
		"00:50:56:00:00:22": "10.0.0.1", "00:50:56:00:00:23": "10.0.0.2", "00:50:56:00:00:24": "10.0.0.3",
		"00:50:56:00:00:27": "10.0.0.4", "00:15:5d:00:00:28": "10.0.0.5",
	}
	var osRows []map[string]string
	for _, mac := range []string{
		"00:50:56:00:00:21", "00:50:56:00:00:25", "52:54:00:00:00:26", "00:50:56:00:00:22", "00:50:56:00:00:23",
		"00:50:56:00:00:24", "00:50:56:00:00:27", "00:15:5d:00:00:28", "00-50-56-00-00-22", "00:05:69:00:00:29",
		"bc:24:11:00:00:30", "00:16:3e:00:00:31", "08:00:27:00:00:32", "aa:bb:cc:00:00:33",
	} {
		osRows = append(osRows, map[string]string{"mac": mac, "detectOSFromMAC": detectOSFromMAC(mac, macToIP, neighbors)})
	}
	var ttlRows []map[string]string
	for _, ip := range []string{"10.0.0.4", "10.0.0.5", "10.0.0.6", "10.0.0.7", "fe80::1", ""} {
		ttlRows = append(ttlRows, map[string]string{"ip": ip, "detectOSByTTL": detectOSByTTL(ip)})
	}

	var esxiBodies []map[string]any
	for _, body := range []string{
		"<html><body ng-app=\"esxUiApp\"></body></html>",
		"<title>VMware ESXi</title>",
		"<title>VMware vCenter Server</title>",
		"Blog post: how to install VMware ESXi at home",
		"",
	} {
		esxiBodies = append(esxiBodies, map[string]any{"body": body, "isESXiResponse": isESXiResponse(body)})
	}

	rec := map[string]any{
		"device_groups":    groups,
		"null_interfaces":  nulls,
		"port_names":       ports,
		"reverse_dns":      dns,
		"vm_os":            osRows,
		"ttl":              ttlRows,
		"esxi_fingerprint": esxiBodies,
	}
	checkGolden(t, "scenario_tables.json", goldenJSON(t, rec, 2))
}

// hypervisorCase builds a small graph, runs detectHypervisors on it and
// returns the result.
func hypervisorCase(build func(g *DJGraph)) graphView {
	g := NewDJGraph()
	build(g)
	detectHypervisors(g)
	return viewGraph(g)
}

// TestGoldenScenarioGraphs pins detectHypervisors on hand-made graphs (mixed
// VMware OUIs, mixed hypervisor families with the lowest MAC in the
// minority, in the majority and in a tie, Proxmox and the other VMware OUIs,
// KVM, hub children, a speed-only edge label, server-NIC relabelling and its
// switch protections), enrichGraphWithIPs with an IP that is a prefix of one
// in the label, and the whole build (buildGraphFromSnapshot) on a small
// synthetic network that exercises every branch of buildGraphEdges and
// addMACCrossRefEdges.
func TestGoldenScenarioGraphs(t *testing.T) {
	resetState(t)
	const sw = "4c:ae:a3:00:01:01"
	vmPort := func(g *DJGraph, port string, macs ...string) {
		for _, mac := range macs {
			addInfoNode(g, mac, "[VM] 💻 VMware VM "+getMACVendor(mac))
			g.AddEdge(sw, mac, port)
		}
	}
	rec := map[string]graphView{}
	rec["hyp_mixed_vmware_port"] = hypervisorCase(func(g *DJGraph) {
		addInfoNode(g, sw, "SNR-S2985G\n172.20.0.11")
		vmPort(g, "GE1/0/26 [T]", "00:50:56:00:01:01", "00:0c:29:00:01:02", "00:50:56:00:01:03")
	})
	rec["hyp_proxmox_bc_24_11"] = hypervisorCase(func(g *DJGraph) {
		addInfoNode(g, sw, "SNR-S2985G\n172.20.0.11")
		vmPort(g, "GE1/0/5 [T]", "bc:24:11:00:05:01", "bc:24:11:00:05:02")
	})
	rec["hyp_vmware_00_05_69"] = hypervisorCase(func(g *DJGraph) {
		addInfoNode(g, sw, "SNR-S2985G\n172.20.0.11")
		vmPort(g, "GE1/0/6 [T]", "00:05:69:00:06:01", "00:05:69:00:06:02")
	})
	rec["hyp_vmware_00_1c_14"] = hypervisorCase(func(g *DJGraph) {
		addInfoNode(g, sw, "SNR-S2985G\n172.20.0.11")
		vmPort(g, "GE1/0/14 [T]", "00:1c:14:00:0e:01", "00:1c:14:00:0e:02")
	})
	rec["hyp_kvm_52_54_00"] = hypervisorCase(func(g *DJGraph) {
		addInfoNode(g, sw, "SNR-S2985G\n172.20.0.11")
		vmPort(g, "GE1/0/8 [T]", "52:54:00:00:08:01", "52:54:00:00:08:02")
	})
	// Mixed hypervisor families: the lowest MAC is in the minority (one
	// Hyper-V MAC, two KVM MACs), in the majority (two Hyper-V, one KVM),
	// and a 1:1 tie.
	rec["hyp_mixed_family_minority_first"] = hypervisorCase(func(g *DJGraph) {
		addInfoNode(g, sw, "SNR-S2985G\n172.20.0.11")
		vmPort(g, "GE1/0/27 [T]", "00:15:5d:00:1b:01", "52:54:00:00:1b:02", "52:54:00:00:1b:03")
	})
	rec["hyp_mixed_family_majority_first"] = hypervisorCase(func(g *DJGraph) {
		addInfoNode(g, sw, "SNR-S2985G\n172.20.0.11")
		vmPort(g, "GE1/0/29 [T]", "00:15:5d:00:1d:01", "00:15:5d:00:1d:02", "52:54:00:00:1d:03")
	})
	rec["hyp_mixed_family_tie"] = hypervisorCase(func(g *DJGraph) {
		addInfoNode(g, sw, "SNR-S2985G\n172.20.0.11")
		vmPort(g, "GE1/0/28 [T]", "52:54:00:00:1c:01", "00:15:5d:00:1c:02")
	})
	rec["hyp_single_vm_mac"] = hypervisorCase(func(g *DJGraph) {
		addInfoNode(g, sw, "SNR-S2985G\n172.20.0.11")
		vmPort(g, "GE1/0/3 [T]", "00:50:56:00:03:01")
	})
	rec["hyp_hub_children"] = hypervisorCase(func(g *DJGraph) {
		hub := "hub-" + sw + "-p7"
		addInfoNode(g, sw, "SNR-S2985G\n172.20.0.11")
		addInfoNode(g, hub, "[HUB] Unmanaged\n3 devices")
		g.AddEdge(sw, hub, "GE1/0/7|Hub")
		for _, mac := range []string{"00:0c:29:00:07:01", "00:0c:29:00:07:02", "00:1b:21:00:07:03"} {
			addInfoNode(g, mac, "[ENDPOINT] "+getMACVendor(mac))
			g.AddEdge(hub, mac, "")
		}
	})
	rec["hyp_speed_only_label"] = hypervisorCase(func(g *DJGraph) {
		addInfoNode(g, sw, "SNR-S2985G\n172.20.0.11")
		vmPort(g, "GigabitEthernet1/0/9 1G ↓5M ↑3M|eth0", "00:50:56:00:09:01", "00:50:56:00:09:02")
	})
	rec["hyp_vm_on_two_switches"] = hypervisorCase(func(g *DJGraph) {
		const sw2 = "4c:ae:a3:00:01:02"
		addInfoNode(g, sw, "SNR-S2985G\n172.20.0.11")
		addInfoNode(g, sw2, "SNR-S2985G\n172.20.0.12")
		vmPort(g, "GE1/0/3 [T]", "00:50:56:00:0a:01", "00:50:56:00:0a:02")
		addInfoNode(g, "00:50:56:00:0a:03", "[VM] 💻 VMware VM VMware")
		g.AddEdge(sw2, "00:50:56:00:0a:01", "GE1/0/4 [T]")
		g.AddEdge(sw2, "00:50:56:00:0a:03", "GE1/0/4 [T]")
	})

	// Switch protection comes from the build: polled devices
	// (graphAddSwitchNode) and LLDP sysName/sysDescr text (graphAddSysText),
	// not from vendor words in labels.
	rec["hyp_server_nic_phase2"] = hypervisorCase(func(g *DJGraph) {
		addInfoNode(g, "f8:f0:82:00:00:01", "[ENDPOINT] SNR")
		addInfoNode(g, "f8:f0:82:00:00:02", "[ENDPOINT] NAGTECH LLC")
		addInfoNode(g, "00:25:b5:00:00:03", "[ENDPOINT]")
		addInfoNode(g, "0c:c4:7a:00:00:04", "[BMC] Supermicro IPMI Supermicro")
		addInfoNode(g, "5c:ed:8c:00:00:05", "[LLDP-EP] Intel\nILOCZJ33411C3")
		addInfoNode(g, "b4:7a:f1:00:00:06", "[HYPERVISOR] VMware ESXi\n[ENDPOINT] Supermicro")
		graphAddSwitchNode(g, &DeviceData{IP: "172.20.0.50", SysName: "SW-50", ChassisID: "3C A8 2A 00 00 50"})
		addInfoNode(g, "4c:ae:a3:00:00:07", "[LLDP-EP] SNR\nB-318/1")
		addInfoNode(g, "e8:39:35:00:00:08", "Cisco IOS\n172.20.0.8")
		graphAddSysText(g, "e8:39:35:00:00:08", "Cisco IOS")
		graphAddSwitchNode(g, &DeviceData{IP: "172.20.0.9", SysName: "HPE", ChassisID: "10:e7:c6:00:00:09"})
		addInfoNode(g, "94:57:a5:00:00:10", "[ENDPOINT] HP")
		addInfoNode(g, "1c:98:ec:00:00:11", "Comware switch")
		graphAddSysText(g, "1c:98:ec:00:00:11", "Comware switch")
		addInfoNode(g, "ec:b1:d7:00:00:12", "HUAWEI S5720\n172.20.0.12")
		graphAddSysText(g, "ec:b1:d7:00:00:12", "HUAWEI S5720")
		addInfoNode(g, "00:14:22:00:00:13", "")
		addInfoNode(g, "hub-x-p1", "[HUB] Unmanaged\n2 devices")
		addInfoNode(g, "hyp-x-ge1", "[HYPERVISOR] VMware ESXi\n2 VMs on ge1")
	})

	// enrichGraphWithIPs when the label already holds an IP of which the
	// node's own IP is a prefix (10.0.9.41 vs 10.0.9.4), and a control node.
	globalMACtoIPMutex.Lock()
	globalMACtoIP = map[string]string{"00:1b:21:09:29:01": "10.0.9.4", "00:1b:21:09:29:02": "10.0.9.5"}
	globalMACtoIPMutex.Unlock()
	enrich := NewDJGraph()
	addInfoNode(enrich, "00:1b:21:09:29:01", "[ENDPOINT] Intel\n10.0.9.41")
	addInfoNode(enrich, "00:1b:21:09:29:02", "[ENDPOINT] Intel\n10.0.9.41")
	enrichGraphWithIPs(enrich)
	rec["enrich_ip_prefix_of_label_ip"] = viewGraph(enrich)

	// Whole build on a synthetic network.
	devices := scenarioNetwork()
	collectedDataMutex.Lock()
	collectedData = devices
	collectedDataMutex.Unlock()
	globalMACtoIPMutex.Lock()
	globalMACtoIP = map[string]string{
		"00:50:56:09:09:01": "10.0.9.41", "00:50:56:09:09:02": "10.0.9.42", "00:50:56:09:09:03": "10.0.9.43",
		"5c:ed:8c:09:09:04": "10.0.9.44", "00:1b:21:09:0d:03": "10.0.9.13", "da:a1:19:09:0d:02": "10.0.9.15",
		"00:1b:21:09:03:01": "10.0.9.31", "4c:ae:a3:09:00:02": "10.0.9.2", "00:50:56:09:72:01": "10.0.9.71",
		"00:1b:21:09:16:01": "10.0.9.25", "0c:c4:7a:09:15:01": "10.0.9.21",
		"00:50:56:09:72:02": "10.0.9.72", "0c:c4:7a:09:00:16": "10.0.9.16", "00:1b:21:09:0b:01": "10.0.9.81",
	}
	globalMACtoIPMutex.Unlock()
	rec["build_synthetic_network"] = viewGraph(buildGraphFromSnapshot(snapshotCollectedData()))

	ConfirmedESXiMACs.Store("00:1b:21:09:03:01", true) // direct endpoint
	ConfirmedESXiMACs.Store("00:1b:21:09:18:01", true) // hub member
	ConfirmedESXiMACs.Store("4c:ae:a3:09:00:04", true) // switch chassis (sw-c)
	ConfirmedESXiMACs.Store("5c:ed:8c:09:00:17", true) // server NIC already tagged [HYPERVISOR]
	ConfirmedESXiMACs.Store("da:a1:19:09:0d:02", true) // [WiFi] endpoint
	rec["build_synthetic_network_esxi"] = viewGraph(buildGraphFromSnapshot(snapshotCollectedData()))
	clearConfirmedESXi()

	checkGolden(t, "scenario_graphs.json", goldenJSON(t, rec, 3))
}

func gigabitPorts(n int, extra map[int]string) []InterfaceData {
	var out []InterfaceData
	for i := 1; i <= n; i++ {
		descr := fmt.Sprintf("GigabitEthernet1/0/%d", i)
		if d, ok := extra[i]; ok {
			descr = d
		}
		out = append(out, InterfaceData{IfIndex: i, IfDescr: descr, IfSpeed: 1000000000, IfOperStatus: 1})
	}
	return out
}

func macEntries(port int, macs ...string) []MACEntry {
	var out []MACEntry
	for _, m := range macs {
		out = append(out, MACEntry{MACAddress: m, PortNumber: port, Status: "learned"})
	}
	return out
}

// scenarioNetwork is a small network that reaches every branch of the graph
// build: LLDP neighbors of each subtype shape (MAC, hostname + port MAC,
// network address, null chassis, rejected hostname, NULL0 port, ASCII MAC,
// BMC and server-NIC OUIs, port ids of subtype 1 and 5), FDB ports for the
// VM, hub (2+ MACs), trunk, uplink and direct (one MAC, or at most 3 on a
// trunk) branches, an LLDP neighbor's port MAC seen on another port, MAC
// cross-reference links, switches with exception-text chassis ids (merged
// node) and a switch without a chassis id.
func scenarioNetwork() map[string]*DeviceData {
	var swAMACs []MACEntry
	swAMACs = append(swAMACs, macEntries(6, "00:1b:21:09:06:01", "00:1b:21:09:06:02")...)
	swAMACs = append(swAMACs, macEntries(8, "52:54:00:09:08:01")...)
	swAMACs = append(swAMACs, macEntries(9, "00:50:56:09:09:01", "00:50:56:09:09:02", "00:50:56:09:09:03", "5c:ed:8c:09:09:04", "0c:c4:7a:09:09:05")...)
	swAMACs = append(swAMACs, macEntries(10, "00:0c:29:09:0a:01", "00:0c:29:09:0a:02", "00:0c:29:09:0a:03", "00:0c:29:09:0a:04")...)
	swAMACs = append(swAMACs, macEntries(11, "b0:83:fe:09:0b:07", "da:a1:19:09:0b:06", "00:1b:21:09:0b:01", "00:1b:21:09:0b:02", "00:1b:21:09:0b:03", "00:1b:21:09:0b:04", "00:1b:21:09:0b:05")...)
	var uplink []string
	for i := 1; i <= 21; i++ {
		uplink = append(uplink, fmt.Sprintf("00:1b:21:09:0c:%02x", i))
	}
	swAMACs = append(swAMACs, macEntries(12, uplink...)...)
	// Port 13 is a trunk: 2-3 MACs there take the direct-endpoint branch.
	swAMACs = append(swAMACs, macEntries(13, "0c:c4:7a:09:0d:01", "da:a1:19:09:0d:02", "00:1b:21:09:0d:03")...)
	// Single-MAC ports take the direct-endpoint branch too.
	swAMACs = append(swAMACs, macEntries(21, "0c:c4:7a:09:15:01")...)
	swAMACs = append(swAMACs, macEntries(22, "00:1b:21:09:16:01")...)
	swAMACs = append(swAMACs, macEntries(23, "de:a1:19:09:17:01")...)
	swAMACs = append(swAMACs, macEntries(14, "AA:BB:CC:09:0E:01")...)
	// Port 15: the port MAC of the port-2 LLDP neighbor plus one more MAC.
	swAMACs = append(swAMACs, macEntries(15, "10:7c:61:c0:9e:aa", "00:1b:21:09:0f:02")...)
	swAMACs = append(swAMACs, macEntries(3, "00:1b:21:09:03:01")...)
	swAMACs = append(swAMACs, macEntries(24, "00:1b:21:09:18:01", "00:1b:21:09:18:02")...)
	swAMACs = append(swAMACs, macEntries(29, "00:1b:21:09:1d:01")...)
	swAMACs = append(swAMACs, macEntries(30, "00:1b:21:09:1e:01")...)
	swAMACs = append(swAMACs, macEntries(18, "4c:ae:a3:09:00:04")...)
	swAMACs = append(swAMACs, macEntries(19, "4c:ae:a3:09:00:02")...)
	swAMACs = append(swAMACs, macEntries(20, "01:00:5e:00:00:fb", "ff:ff:ff:ff:ff:ff", "00:00:00:09:14:01")...)

	swA := &DeviceData{
		IP: "10.0.9.2", SysName: "sw-a", ChassisID: "4c:ae:a3:09:00:02",
		Interfaces: gigabitPorts(30, map[int]string{29: "NULL0", 30: "\"NULL0\""}),
		PortVLANs: []PortVLAN{
			{PortIndex: 3, PVID: 100}, {PortIndex: 10, PVID: 1, IsTrunk: true}, {PortIndex: 12, PVID: 1},
			{PortIndex: 13, PVID: 1, IsTrunk: true},
		},
		Neighbors: []LLDPNeighbor{
			{LocalPortNum: 1, RemIndex: 1, RemChassisIdSubtype: 4, RemChassisId: "4C AE A3 09 00 03", RemPortIdSubtype: 5, RemPortId: "\"GigabitEthernet1/0/48\"", RemSysName: "sw-b", RemMgmtIP: "10.0.9.3"},
			{LocalPortNum: 2, RemIndex: 2, RemChassisIdSubtype: 7, RemChassisId: "\"DESKTOP-V380CHD\"", RemPortIdSubtype: 3, RemPortId: "10 7C 61 C0 9E AA"},
			{LocalPortNum: 4, RemIndex: 3, RemChassisIdSubtype: 5, RemChassisId: "01 AC 10 01 0F", RemPortIdSubtype: 3, RemPortId: "EC 74 D7 64 CB B1", RemSysName: "GXP1610_ec:74:d7:64:cb:b1"},
			{LocalPortNum: 5, RemIndex: 4, RemChassisIdSubtype: 7, RemChassisId: "00 00 00 00 00 00", RemPortIdSubtype: 3, RemPortId: "74 56 3C BB D0 16"},
			{LocalPortNum: 6, RemIndex: 5, RemChassisIdSubtype: 7, RemChassisId: "B-318/1", RemPortIdSubtype: 7, RemPortId: "\"28\"", RemSysName: "B-318/1"},
			{LocalPortNum: 29, RemIndex: 6, RemChassisIdSubtype: 4, RemChassisId: "AA BB CC 09 00 29", RemPortIdSubtype: 3, RemPortId: "AA BB CC 09 00 29"},
			{LocalPortNum: 7, RemIndex: 7, RemChassisIdSubtype: 7, RemChassisId: "\"f4-b5-20-19-12-5e\"", RemPortIdSubtype: 7, RemPortId: "\"eth0\"", RemSysName: "printer-7", RemSysDesc: "HP LaserJet\nrev 2"},
			{LocalPortNum: 16, RemIndex: 8, RemChassisIdSubtype: 4, RemChassisId: "0C C4 7A 09 00 16", RemPortIdSubtype: 3, RemPortId: "0C C4 7A 09 00 16", RemSysName: "node16-ipmi"},
			{LocalPortNum: 17, RemIndex: 9, RemChassisIdSubtype: 4, RemChassisId: "5C ED 8C 09 00 17", RemPortIdSubtype: 3, RemPortId: "5C ED 8C 09 00 17", RemSysName: "ILOCZJ33411C3"},
			// Port ids whose subtype number means something else for a port
			// than for a chassis: 1 is ifAlias (chassis: entPhysicalAlias)
			// and 5 is ifName (chassis: network address).
			{LocalPortNum: 25, RemIndex: 10, RemChassisIdSubtype: 7, RemChassisId: "printer-x", RemPortIdSubtype: 1, RemPortId: "uplink"},
			{LocalPortNum: 26, RemIndex: 11, RemChassisIdSubtype: 7, RemChassisId: "nas-26", RemPortIdSubtype: 5, RemPortId: "\"eth0\"", RemSysName: "nas-26"},
		},
		ARPTable: []ARPEntry{{IPAddress: "10.0.9.99", MACAddress: "00:50:56:09:09:01", Interface: 1}},
		MACTable: swAMACs,
	}
	swB := &DeviceData{
		IP: "10.0.9.3", SysName: "sw-b", ChassisID: "4C AE A3 09 00 03",
		Interfaces: gigabitPorts(8, nil),
		MACTable: append(append(macEntries(1, "4c:ae:a3:09:00:02"), macEntries(2, "4c:ae:a3:09:00:04")...),
			macEntries(3, "4c:ae:a3:09:00:02", "4c:ae:a3:09:00:04")...),
	}
	swC := &DeviceData{
		IP: "10.0.9.4", SysName: "sw-c", ChassisID: "4c:ae:a3:09:00:04",
		Interfaces: gigabitPorts(8, nil),
		MACTable:   append(macEntries(5, "4c:ae:a3:09:00:03"), macEntries(6, "4c:ae:a3:09:00:02")...),
	}
	swD := &DeviceData{
		IP: "10.0.9.5", SysName: "sw-d", ChassisID: "No Such Object available on this agent at this OID",
		Interfaces: gigabitPorts(4, nil),
		MACTable:   macEntries(1, "00:1b:21:09:51:01"),
	}
	swE := &DeviceData{
		IP: "10.0.9.6", SysName: "sw-e", ChassisID: "No Such Object available on this agent at this OID",
		Interfaces: gigabitPorts(4, nil), Unreachable: true,
	}
	swF := &DeviceData{
		IP: "10.0.9.7", SysName: "sw-f", ChassisID: "",
		Interfaces: gigabitPorts(4, nil),
		MACTable:   macEntries(2, "00:50:56:09:72:01", "00:50:56:09:72:02"),
	}
	return map[string]*DeviceData{
		swA.IP: swA, swB.IP: swB, swC.IP: swC, swD.IP: swD, swE.IP: swE, swF.IP: swF,
	}
}
