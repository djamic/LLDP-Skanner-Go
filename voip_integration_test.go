package main

import (
	"slices"
	"strings"
	"testing"
)

func TestVoIPIntegrationGraphAndModules(t *testing.T) {
	resetState(t)
	const (
		swMAC   = "18:56:44:21:58:d0"
		ylMAC   = "c4:fc:22:21:0b:90"
		gsMAC   = "c0:74:ad:96:03:25"
		gsFDB   = "c0:74:ad:ae:9b:91"
		panaMAC = "4c:36:4e:7b:1b:45"
		pcMAC   = "00:1b:21:77:00:01"
	)

	sw := &DeviceData{
		IP:        "10.67.100.29",
		SysName:   "L4Acc4_8",
		ChassisID: swMAC,
		Interfaces: []InterfaceData{
			{IfIndex: 10, IfDescr: "\"GigabitEthernet0/0/4\"", IfSpeed: 1_000_000_000, IfOperStatus: 1},
			{IfIndex: 11, IfDescr: "\"GigabitEthernet0/0/5\"", IfSpeed: 1_000_000_000, IfOperStatus: 1},
			{IfIndex: 12, IfDescr: "\"GigabitEthernet0/0/6\"", IfSpeed: 1_000_000_000, IfOperStatus: 1},
			{IfIndex: 13, IfDescr: "\"GigabitEthernet0/0/7\"", IfSpeed: 1_000_000_000, IfOperStatus: 1},
		},
		BridgePortIfIndex: map[int]int{4: 10, 5: 11, 6: 12, 7: 13},
		Neighbors: []LLDPNeighbor{
			{
				LocalPortNum: 10, RemIndex: 1,
				RemChassisIdSubtype: 5, RemChassisId: "01 C0 A8 B1 1D", // 192.168.177.29
				RemPortIdSubtype: 3, RemPortId: ylMAC, RemPortDesc: "\"WAN PORT\"",
				RemSysName: "SIP-T48U", RemSysDesc: "108.86.0.90", RemSysCapEnabled: 0x24,
			},
			{
				LocalPortNum: 11, RemIndex: 1,
				RemChassisIdSubtype: 5, RemChassisId: "01 0A 43 0A 5C", // 10.67.10.92
				RemPortIdSubtype: 3, RemPortId: gsMAC, RemPortDesc: "\"eth0\"",
				RemSysName: "GRP2613_" + gsMAC, RemSysDesc: "GRP2613 1.0.7.33", RemSysCapEnabled: 0x24,
			},
			{
				LocalPortNum: 12, RemIndex: 1,
				RemChassisIdSubtype: 5, RemChassisId: "01 C0 A8 B2 50", // 192.168.178.80
				RemPortIdSubtype: 3, RemPortId: panaMAC, RemPortDesc: "\"LAN PORT\"",
				RemSysName: "KX-HDV230RU", RemSysDesc: "Panasonic", RemSysCapEnabled: 0x04,
			},
		},
		MACTable: []MACEntry{
			{PortNumber: 4, MACAddress: ylMAC},
			{PortNumber: 4, MACAddress: pcMAC}, // daisy-chained PC behind Yealink
			{PortNumber: 7, MACAddress: gsFDB}, // FDB-only Grandstream phone
		},
	}

	g := buildGraphFromSnapshot(map[string]*DeviceData{sw.IP: sw})
	SetGlobalGraph(g)

	data := g.GetGraphData()
	addVoIPProfiles(&data, g)

	byID := map[string]GraphNode{}
	for _, n := range data.Nodes {
		byID[n.ID] = n
	}

	for _, id := range []string{ylMAC, gsMAC, gsFDB, panaMAC} {
		if got := byID[id].Group; got != "phone" {
			t.Errorf("phone %s group = %q, want \"phone\"", id, got)
		}
		if byID[id].VoIP == nil {
			t.Errorf("phone %s missing VoIP profile", id)
		}
	}
	if byID[pcMAC].Group != "endpoint" {
		t.Errorf("daisy-chained PC %s group = %q, want endpoint", pcMAC, byID[pcMAC].Group)
	}

	// ChassisSubtype=5 IP enrichment when ARP table did not know the phones
	if !strings.Contains(byID[ylMAC].SysName, "192.168.177.29") {
		t.Errorf("Yealink SysName missing decoded Chassis IP: %q", byID[ylMAC].SysName)
	}
	if byID[ylMAC].VoIP.Brand != "Yealink" || byID[ylMAC].VoIP.Model != "SIP-T48U" || byID[ylMAC].VoIP.Firmware != "108.86.0.90" || !byID[ylMAC].VoIP.PCBridge {
		t.Errorf("Yealink VoIP profile = %+v", byID[ylMAC].VoIP)
	}
	if byID[gsMAC].VoIP.Brand != "Grandstream" || byID[gsMAC].VoIP.Model != "GRP2613" || byID[gsMAC].VoIP.Firmware != "1.0.7.33" {
		t.Errorf("Grandstream VoIP profile = %+v", byID[gsMAC].VoIP)
	}
	if byID[panaMAC].VoIP.Brand != "Panasonic" || byID[panaMAC].VoIP.Model != "KX-HDV230RU" {
		t.Errorf("Panasonic VoIP profile = %+v", byID[panaMAC].VoIP)
	}

	// Active module auto-association by known phone IP
	if types := voipKnownTypesForIP("10.67.10.92"); !slices.Contains(types, "voip-grandstream") {
		t.Errorf("voipKnownTypesForIP(10.67.10.92) = %v, want voip-grandstream", types)
	}
	if types := voipKnownTypesForIP("192.168.177.29"); !slices.Contains(types, "voip-yealink") {
		t.Errorf("voipKnownTypesForIP(192.168.177.29) = %v, want voip-yealink", types)
	}
}
