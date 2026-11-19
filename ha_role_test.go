package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"strings"
	"testing"
)

func TestCollectVRRPInfoAndKeepPrevious(t *testing.T) {
	resetState(t)
	const ip = "10.9.92.3"
	obj := newRescanSNMPObject()

	agent := collectTestAgent()
	agent[oidVRRPOperState] = []string{
		oidVRRPOperState + ".37.100 = INTEGER: 2",
		oidVRRPOperState + ".38.10 = INTEGER: 2",
	}
	agent[oidVRRPAssoIpAddr] = []string{
		oidVRRPAssoIpAddr + ".37.100.10.9.92.1 = INTEGER: 1",
		oidVRRPAssoIpAddr + ".38.10.10.9.10.1 = INTEGER: 1",
	}
	fakeSNMP.set(ip, agent)
	obj.CollectData(ip, "sw-core-2")

	first := collectStored(ip)
	if first == nil || first.VRRPInfo == nil || len(first.VRRPInfo.Instances) != 2 {
		t.Fatalf("expected 2 VRRP instances, got %+v", first)
	}
	if first.VRRPInfo.Instances[0].State != "backup" || !slices.Equal(first.VRRPInfo.Instances[0].VIPs, []string{"10.9.92.1"}) {
		t.Errorf("unexpected VRRP instance[0]: %+v", first.VRRPInfo.Instances[0])
	}

	// Simulate VRRP walk timeout on next poll while chassis succeeds: VRRPInfo is preserved.
	partial := collectTestAgent()
	delete(partial, oidVRRPOperState)
	fakeSNMP.set(ip, partial)
	obj.CollectData(ip, "sw-core-2")

	second := collectStored(ip)
	if second == nil || second.VRRPInfo == nil || len(second.VRRPInfo.Instances) != 2 {
		t.Fatalf("expected VRRPInfo kept across failed walk, got %+v", second)
	}

	// Non-VRRP switch ("No Such Instance") stores nil VRRPInfo.
	noVRRP := collectTestAgent()
	noVRRP[oidVRRPOperState] = []string{oidVRRPOperState + " = No Such Instance currently exists at this OID"}
	fakeSNMP.set("10.9.92.40", noVRRP)
	obj.CollectData("10.9.92.40", "sw-dc-1")
	if dc1 := collectStored("10.9.92.40"); dc1 == nil || dc1.VRRPInfo != nil {
		t.Errorf("expected nil VRRPInfo for non-VRRP switch, got %+v", dc1)
	}
}

func TestComputeHARolesSNMPAndFallback(t *testing.T) {
	// 1. Fallback mode (before VRRP-MIB poll, or HSRP): Core1 active, Core2 passive, DC2 L2 untouched.
	core1 := &DeviceData{
		IP:        "10.9.92.2",
		SysName:   "sw-core-1",
		ChassisID: "18:56:44:00:00:01",
		Interfaces: []InterfaceData{
			{IfIndex: 37, IfDescr: `"Vlanif100"`, IfOperStatus: 1},
			{IfIndex: 38, IfDescr: `"Vlanif10"`, IfOperStatus: 1},
			{IfIndex: 39, IfDescr: `"Vlanif20"`, IfOperStatus: 1},
		},
		ARPTable: []ARPEntry{
			{IPAddress: "10.9.92.2", MACAddress: "18:56:44:00:00:0b", Interface: 37},
		},
	}
	core2 := &DeviceData{
		IP:        "10.9.92.3",
		SysName:   "sw-core-2",
		ChassisID: "18:56:44:00:00:02",
		Interfaces: []InterfaceData{
			{IfIndex: 37, IfDescr: `"Vlanif100"`, IfOperStatus: 1},
			{IfIndex: 38, IfDescr: `"Vlanif10"`, IfOperStatus: 1},
			{IfIndex: 39, IfDescr: `"Vlanif20"`, IfOperStatus: 1},
		},
		MACTable: []MACEntry{
			{MACAddress: "00:00:5e:00:01:64", PortNumber: 1, Status: "learned"},
			{MACAddress: "00:00:5e:00:01:0a", PortNumber: 1, Status: "learned"},
			{MACAddress: "00:00:5e:00:01:14", PortNumber: 1, Status: "learned"},
		},
		ARPTable: []ARPEntry{
			{IPAddress: "10.9.92.1", MACAddress: "00:00:5e:00:01:64", Interface: 37},
			{IPAddress: "10.9.10.1", MACAddress: "00:00:5e:00:01:0a", Interface: 38},
			{IPAddress: "192.0.2.1", MACAddress: "00:00:5e:00:01:14", Interface: 39},
		},
	}
	// Downstream L2 switch with management SVI learning the gateway VRRP MAC: must NOT be marked passive.
	dc2 := &DeviceData{
		IP:        "10.9.92.41",
		SysName:   "sw-dc-2",
		ChassisID: "f4:e5:f2:00:00:41",
		Interfaces: []InterfaceData{
			{IfIndex: 37, IfDescr: `"Vlanif100"`, IfOperStatus: 1},
		},
		MACTable: []MACEntry{
			{MACAddress: "00:00:5e:00:01:64", PortNumber: 2, Status: "learned"},
		},
		ARPTable: []ARPEntry{
			{IPAddress: "10.9.92.1", MACAddress: "00:00:5e:00:01:64", Interface: 37},
		},
	}

	snap := map[string]*DeviceData{
		core1.IP: core1,
		core2.IP: core2,
		dc2.IP:   dc2,
	}
	roles := computeHARoles(snap)
	if got := roles[core1.ChassisID]; got.Role != "active" || len(got.VIPs) != 3 {
		t.Errorf("Core1 fallback role = %+v, want active with 3 VIPs", got)
	}
	if got := roles[core2.ChassisID]; got.Role != "passive" || len(got.VIPs) != 3 {
		t.Errorf("Core2 fallback role = %+v, want passive with 3 VIPs", got)
	}
	if got, exists := roles[dc2.ChassisID]; exists {
		t.Errorf("DC2 (L2 switch) got unexpected HA role: %+v", got)
	}

	// 2. Direct SNMP VRRP-MIB failover: Core1 becomes backup, Core2 becomes master.
	core1.VRRPInfo = &VRRPData{Instances: []VRRPInstance{{IfIndex: 37, VRID: 100, State: "backup", VIPs: []string{"10.9.92.1"}}}}
	core2.VRRPInfo = &VRRPData{Instances: []VRRPInstance{{IfIndex: 37, VRID: 100, State: "master", VIPs: []string{"10.9.92.1"}}}}

	g := NewDJGraph()
	g.AddNode(core1.ChassisID)
	g.SwitchInfo[core1.ChassisID] = "sw-core-1\n10.9.92.2"
	g.graphSwitches = map[string]bool{core1.ChassisID: true, core2.ChassisID: true}
	g.AddNode(core2.ChassisID)
	g.SwitchInfo[core2.ChassisID] = "sw-core-2\n10.9.92.3"
	g.AddEdge(core1.ChassisID, core2.ChassisID, "XGE0/0/23 10G|XGE0/0/24")

	resetState(t)
	setGatewayIPs([]string{core1.IP, core2.IP})
	collectedDataMutex.Lock()
	collectedData[core1.IP] = core1
	collectedData[core2.IP] = core2
	collectedDataMutex.Unlock()
	SetGlobalGraph(g)
	graphDebugFile = t.TempDir() + "/graphs_data.txt"

	req := httptest.NewRequest(http.MethodGet, "/api/graph", nil)
	rec := httptest.NewRecorder()
	graphHandler(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("/api/graph status = %d", rec.Code)
	}
	var gd GraphData
	if err := json.Unmarshal(rec.Body.Bytes(), &gd); err != nil {
		t.Fatalf("decode /api/graph: %v", err)
	}
	// Core1 is passive after failover, so data.Core promotes to active Core2.
	if gd.Core != core2.ChassisID {
		t.Errorf("gd.Core after failover = %q, want %q", gd.Core, core2.ChassisID)
	}
	byID := map[string]GraphNode{}
	for _, n := range gd.Nodes {
		byID[n.ID] = n
	}
	if byID[core1.ChassisID].HARole != "passive" || byID[core2.ChassisID].HARole != "active" {
		t.Errorf("unexpected node roles: core1=%q core2=%q", byID[core1.ChassisID].HARole, byID[core2.ChassisID].HARole)
	}
}

func TestUIPassiveFilterWiring(t *testing.T) {
	indexHTML, err := os.ReadFile("static/index.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(indexHTML), `id="filterPassive"`) || !strings.Contains(string(indexHTML), `id="fc-passive"`) {
		t.Errorf("index.html missing #filterPassive checkbox or #fc-passive counter")
	}
	appJS, err := os.ReadFile("static/app.js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(appJS), "n.haRole === 'passive' && !filterState.showPassive") {
		t.Errorf("app.js uiGroupShown missing passive HA filter check")
	}
	treeJS, err := os.ReadFile("static/tree.js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(treeJS), "tv-ha-") {
		t.Errorf("tree.js missing HA role badge rendering")
	}
}
