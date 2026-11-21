package main

import (
	"fmt"
	"testing"
)

// TestPolledGroup: with rules.PolledByMIB a polled device is grouped by
// what its agent shows, never by its name; off, by its name words.
func TestPolledGroup(t *testing.T) {
	const (
		linux   = "Linux web-01 5.15.0-91-generic #101-Ubuntu SMP x86_64"
		windows = "Hardware: Intel64 Family 6 Model 85 - Software: Windows Version 6.3 (Build 17763 Multiprocessor Free)"
		esxi    = "VMware ESXi 7.0.3 build-21930508 VMware, Inc. x86_64"
		comware = "HPE Comware Platform Software, Software Version 7.1.070"
	)
	on := ClassifySettings{PolledByMIB: true}
	for _, c := range []struct {
		ev        nodeEvidence
		want, off string
	}{
		{nodeEvidence{ID: "10.0.0.3", Polled: true, Info: "Server-room switch", Own: polledFacts{Bridge: true}}, "switch", "server"},
		{nodeEvidence{ID: "10.0.0.4", Polled: true, Info: "Cisco ISR router", Own: polledFacts{Bridge: true}}, "switch", "switch"},
		{nodeEvidence{ID: "10.0.0.5", Polled: true, Info: "edge-router"}, "switch", "router"},
		{nodeEvidence{ID: "10.0.0.6", Polled: true, Info: "web-01", Own: polledFacts{SysDescr: linux}}, "server", "switch"},
		{nodeEvidence{ID: "10.0.0.7", Polled: true, Info: "dc-01", Own: polledFacts{SysDescr: windows}}, "server", "switch"},
		{nodeEvidence{ID: "10.0.0.8", Polled: true, Info: "localhost", Own: polledFacts{SysDescr: esxi}}, "hypervisor", "switch"},
		// a Linux-based switch bridges
		{nodeEvidence{ID: "10.0.0.9", Polled: true, Info: "leaf-1", Own: polledFacts{Bridge: true, SysDescr: linux}}, "switch", "switch"},
		{nodeEvidence{ID: "10.0.0.10", Polled: true, Info: "HPE", Own: polledFacts{SysDescr: comware}}, "switch", "switch"},
		{nodeEvidence{ID: "10.0.0.11", Polled: true}, "switch", "switch"},
		// a configured gateway first
		{nodeEvidence{ID: "10.0.0.1", Router: true, Polled: true, Own: polledFacts{SysDescr: "FreeBSD pfSense.home.arpa 14.0-CURRENT"}}, "router", "router"},
	} {
		if got := classifyNode(c.ev, on); got != c.want {
			t.Errorf("classifyNode(%+v, polledByMIB) = %q, want %q", c.ev, got, c.want)
		}
		if got := classifyNode(c.ev, ClassifySettings{}); got != c.off {
			t.Errorf("classifyNode(%+v) = %q, want %q", c.ev, got, c.off)
		}
	}
}

// TestPolledByMIBGraph: the poll stores the sysDescr and the BRIDGE-MIB
// port count (a poll that reads none keeps the stored ones), and the graph
// groups the polled devices by them: an LLDP agent on a Linux host with no
// bridge is a server, a switch named "Server-room switch" a switch.
func TestPolledByMIBGraph(t *testing.T) {
	resetState(t)
	const host, sw = "10.9.6.1", "10.9.6.2"
	obj := newRescanSNMPObject()
	hostAgent := nonSwitchAgent("web-01", "Linux web-01 5.15.0-91-generic #101-Ubuntu SMP x86_64")
	hostAgent[oidChassis] = []string{oidChassis + " = Hex-STRING: 00 1B 21 09 06 01 "}
	swAgent := collectTestAgent()
	swAgent[oidSysDescr] = []string{oidSysDescr + ` = STRING: "HPE Comware Platform Software"`}
	swAgent[oidDot1dBaseNumPorts] = []string{oidDot1dBaseNumPorts + " = INTEGER: 28"}
	fakeSNMP.set(host, hostAgent)
	fakeSNMP.set(sw, swAgent)
	obj.CollectData(host, "")
	obj.CollectData(sw, "Server-room switch")
	h, s := collectStored(host), collectStored(sw)
	if h == nil || s == nil {
		t.Fatalf("not stored: host %v, switch %v", h != nil, s != nil)
	}
	if h.SysDescr == "" || h.BridgePorts != 0 || s.SysDescr != "HPE Comware Platform Software" || s.BridgePorts != 28 {
		t.Errorf("stored host %q %d, switch %q %d", h.SysDescr, h.BridgePorts, s.SysDescr, s.BridgePorts)
	}

	// a poll whose sysDescr and port count reads give nothing keeps them
	delete(swAgent, oidSysDescr)
	delete(swAgent, oidDot1dBaseNumPorts)
	fakeSNMP.set(sw, swAgent)
	obj.CollectData(sw, "Server-room switch")
	if s := collectStored(sw); s.SysDescr != "HPE Comware Platform Software" || s.BridgePorts != 28 {
		t.Errorf("after a poll without them: switch %q %d", s.SysDescr, s.BridgePorts)
	}

	for _, byMIB := range []bool{true, false} {
		currentSettingsMutex.Lock()
		currentSettings.Classify.PolledByMIB = byMIB
		currentSettingsMutex.Unlock()
		groups := map[string]string{}
		for _, n := range buildGraphFromSnapshot(snapshotCollectedData()).GetGraphData().Nodes {
			groups[n.ID] = n.Group
		}
		want := map[bool][2]string{true: {"server", "switch"}, false: {"switch", "server"}}[byMIB]
		got := [2]string{groups[graphDeviceNodeID(collectStored(host))], groups[graphDeviceNodeID(collectStored(sw))]}
		if got != want {
			t.Errorf("polledByMIB %v: host, switch groups %v, want %v", byMIB, got, want)
		}
	}
}

// TestSwitchSysMarkers: an LLDP neighbor whose sysDescr names Aruba,
// PiXiETECH or FortiSwitch is a switch node (no ESXi host, whatever the
// MAC cache binds to it).
func TestSwitchSysMarkers(t *testing.T) {
	g := NewDJGraph()
	for i, text := range []string{
		"Aruba JL659A 6300M 48SR5 CL6 PoE 4SFP56 Swch FL.10.10",
		"PiXiETECH(tm) PXT-S2790G-24FX Software, Version 2.2.0F",
		"FortiSwitch-148F-FPOE v7.2.5",
		"HPE Comware Platform Software",
	} {
		id := fmt.Sprintf("58:94:80:00:00:%02x", i)
		g.AddNode(id)
		graphAddSysText(g, id, text)
		if !graphIsSwitchNode(g, id) {
			t.Errorf("%q is no switch node", text)
		}
	}
	g.AddNode("00:50:56:00:00:01")
	graphAddSysText(g, "00:50:56:00:00:01", "VMware ESXi 7.0.3")
	if graphIsSwitchNode(g, "00:50:56:00:00:01") {
		t.Error("an ESXi host is a switch node")
	}
}
