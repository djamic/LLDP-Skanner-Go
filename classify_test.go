package main

import "testing"

// TestClassifyNode pins classifyNode's order of evidence, a case per rule,
// with the quirks of today's rules (a polled device is grouped by its name
// words only).
func TestClassifyNode(t *testing.T) {
	for _, c := range []struct {
		ev   nodeEvidence
		want string
	}{
		{nodeEvidence{ID: "10.0.0.1", Router: true, AP: true, Polled: true}, "router"},
		{nodeEvidence{ID: "f0:9f:c2:00:00:01", AP: true, Polled: true, Info: "[LLDP-EP] U6"}, "access_point"},
		{nodeEvidence{ID: "10.0.0.2", Polled: true}, "switch"},
		{nodeEvidence{ID: "10.0.0.3", Polled: true, Info: "Server-room switch"}, "server"},
		{nodeEvidence{ID: "10.0.0.4", Polled: true, Info: "Cisco ISR router"}, "switch"},
		{nodeEvidence{ID: "10.0.0.5", Polled: true, Info: "[ENDPOINT] x", ESXi: true}, "switch"},
		{nodeEvidence{ID: "00:50:56:00:00:01", ESXi: true, Info: "[WiFi]\n[BMC]", VoIP: true}, "hypervisor"},
		{nodeEvidence{ID: "da:00:00:00:00:01", Info: "[WiFi]", VoIP: true}, "wifi_random"},
		{nodeEvidence{ID: "c0:74:ad:00:00:01", Info: "[LLDP-EP] GXP1610", VoIP: true, Category: "camera"}, "phone"},
		{nodeEvidence{ID: "c0:51:7e:00:00:01", Info: "[LLDP-EP] cam", Category: "camera"}, "camera"},
		{nodeEvidence{ID: "00:1b:21:00:00:01", Info: "[ENDPOINT]", Category: "network"}, "endpoint"},
		{nodeEvidence{ID: "00:1b:21:00:00:02", Info: "[ENDPOINT]", Category: "endpoint"}, "endpoint"},
		{nodeEvidence{ID: "00:1b:21:00:00:03", Info: "[ENDPOINT]\n[HUB]"}, "endpoint"},
		{nodeEvidence{ID: "hub-10.0.0.2-p8", Info: "[MINIHUB] 30 MACs\n[HUB]"}, "minihub"},
		{nodeEvidence{ID: "hub-10.0.0.2-p9"}, "hub"},
		{nodeEvidence{ID: "x", Info: "[HUB] Unmanaged"}, "hub"},
		{nodeEvidence{ID: "x", Info: "[BMC] iLO\n[HYPERVISOR]"}, "bmc"},
		{nodeEvidence{ID: "bmc-1"}, "bmc"},
		{nodeEvidence{ID: "x", Info: "[HYPERVISOR] VMware ESXi\n[VM]"}, "hypervisor"},
		{nodeEvidence{ID: "hyp-10.0.0.2-ge1_0_2"}, "hypervisor"},
		{nodeEvidence{ID: "x", Info: "[VM] win-22"}, "vm"},
		{nodeEvidence{ID: "vm-1"}, "vm"},
		{nodeEvidence{ID: "linux-box"}, "server"},
		{nodeEvidence{ID: "x", Info: "HPE 5130"}, "switch"},
		{nodeEvidence{ID: "edge-router"}, "router"},
		{nodeEvidence{ID: "x", Info: "something"}, "switch"},
		{nodeEvidence{ID: "x"}, "unknown"},
	} {
		if got := classifyNode(c.ev); got != c.want {
			t.Errorf("classifyNode(%+v) = %q, want %q", c.ev, got, c.want)
		}
	}

	for _, c := range []struct{ group, kind, want string }{
		{"endpoint", "phone", "phone"}, {"unknown", "phone", "phone"}, {"camera", "phone", "camera"},
		{"switch", "phone", "switch"}, {"endpoint", "access_point", "endpoint"}, {"endpoint", "", "endpoint"},
	} {
		if got := managedGroup(c.group, c.kind); got != c.want {
			t.Errorf("managedGroup(%q, %q) = %q, want %q", c.group, c.kind, got, c.want)
		}
	}
}
