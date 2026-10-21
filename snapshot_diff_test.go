package main

import (
	"fmt"
	"testing"
	"time"
)

// TestCompareSnapshots_JoinLeave tests basic JOIN and LEAVE detection
func TestCompareSnapshots_JoinLeave(t *testing.T) {
	prev := &NetworkSnapshot{
		Timestamp:  time.Now().Add(-1 * time.Minute),
		ActiveMACs: map[string]MACInfo{
			"aa:bb:cc:dd:ee:01": {IP: "192.168.1.1", SwitchIP: "172.20.230.4", Port: 5, Vendor: "Intel"},
			"aa:bb:cc:dd:ee:02": {IP: "192.168.1.2", SwitchIP: "172.20.230.4", Port: 6, Vendor: "Samsung"},
			"aa:bb:cc:dd:ee:03": {IP: "192.168.1.3", SwitchIP: "172.20.230.31", Port: 10, Vendor: "Apple"},
		},
		ActiveHosts: map[string]HostInfo{
			"172.20.230.4":  {SysName: "Switch-A", Vendor: "SNR", Health: 100},
			"172.20.230.31": {SysName: "Switch-B", Vendor: "SNR", Health: 90},
		},
		Anomalies:   map[string][]string{
			"172.20.230.31": {"shadow_it"},
		},
		HealthScore: 90,
	}

	curr := &NetworkSnapshot{
		Timestamp:  time.Now(),
		ActiveMACs: map[string]MACInfo{
			"aa:bb:cc:dd:ee:01": {IP: "192.168.1.1", SwitchIP: "172.20.230.4", Port: 5, Vendor: "Intel"},
			// ee:02 LEFT
			"aa:bb:cc:dd:ee:03": {IP: "192.168.1.3", SwitchIP: "172.20.230.31", Port: 10, Vendor: "Apple"},
			"aa:bb:cc:dd:ee:04": {IP: "192.168.1.4", SwitchIP: "172.20.230.4", Port: 12, Vendor: "Xiaomi"}, // JOINED
		},
		ActiveHosts: map[string]HostInfo{
			"172.20.230.4":  {SysName: "Switch-A", Vendor: "SNR", Health: 100},
			"172.20.230.31": {SysName: "Switch-B", Vendor: "SNR", Health: 100},
			"172.20.230.50": {SysName: "Switch-C", Vendor: "HPE", Health: 85}, // NEW HOST
		},
		Anomalies:   map[string][]string{
			// shadow_it on 230.31 is FIXED
			"172.20.230.50": {"congestion"}, // NEW anomaly
		},
		HealthScore: 85,
	}

	diff := CompareSnapshots(prev, curr)

	// Test JOIN
	if len(diff.JoinedMACs) != 1 {
		t.Errorf("Expected 1 joined MAC, got %d", len(diff.JoinedMACs))
	} else if diff.JoinedMACs[0].MAC != "aa:bb:cc:dd:ee:04" {
		t.Errorf("Expected joined MAC aa:bb:cc:dd:ee:04, got %s", diff.JoinedMACs[0].MAC)
	}

	// Test LEAVE
	if len(diff.LeftMACs) != 1 {
		t.Errorf("Expected 1 left MAC, got %d", len(diff.LeftMACs))
	} else if diff.LeftMACs[0].MAC != "aa:bb:cc:dd:ee:02" {
		t.Errorf("Expected left MAC aa:bb:cc:dd:ee:02, got %s", diff.LeftMACs[0].MAC)
	}

	// Test new host
	if len(diff.NewHosts) != 1 {
		t.Errorf("Expected 1 new host, got %d", len(diff.NewHosts))
	} else if diff.NewHosts[0] != "172.20.230.50" {
		t.Errorf("Expected new host 172.20.230.50, got %s", diff.NewHosts[0])
	}

	// Test lost hosts (none expected)
	if len(diff.LostHosts) != 0 {
		t.Errorf("Expected 0 lost hosts, got %d", len(diff.LostHosts))
	}

	// Test health delta
	if diff.HealthDelta != -5 {
		t.Errorf("Expected health delta -5, got %d", diff.HealthDelta)
	}

	// Test MAC count delta (3 → 3 = 0)
	if diff.MACCountDelta != 0 {
		t.Errorf("Expected MAC count delta 0, got %d", diff.MACCountDelta)
	}

	// Test new anomalies
	if len(diff.NewAnomalies) != 1 {
		t.Errorf("Expected 1 new anomaly, got %d", len(diff.NewAnomalies))
	}

	// Test fixed anomalies
	if len(diff.FixedAnomalies) != 1 {
		t.Errorf("Expected 1 fixed anomaly, got %d", len(diff.FixedAnomalies))
	}

	// Print diff for visual verification
	fmt.Println("\n=== Visual Diff Output ===")
	diff.LogChanges()
}

// TestCompareSnapshots_NoChanges tests that identical snapshots produce empty diff
func TestCompareSnapshots_NoChanges(t *testing.T) {
	snapshot := &NetworkSnapshot{
		Timestamp:  time.Now(),
		ActiveMACs: map[string]MACInfo{
			"aa:bb:cc:dd:ee:01": {IP: "192.168.1.1", SwitchIP: "172.20.230.4", Port: 5, Vendor: "Intel"},
		},
		ActiveHosts: map[string]HostInfo{
			"172.20.230.4": {SysName: "Switch-A", Vendor: "SNR", Health: 100},
		},
		Anomalies:   map[string][]string{},
		HealthScore: 100,
	}

	diff := CompareSnapshots(snapshot, snapshot)

	if len(diff.JoinedMACs) != 0 {
		t.Errorf("Expected 0 joined MACs, got %d", len(diff.JoinedMACs))
	}
	if len(diff.LeftMACs) != 0 {
		t.Errorf("Expected 0 left MACs, got %d", len(diff.LeftMACs))
	}
	if len(diff.NewHosts) != 0 {
		t.Errorf("Expected 0 new hosts, got %d", len(diff.NewHosts))
	}
	if len(diff.LostHosts) != 0 {
		t.Errorf("Expected 0 lost hosts, got %d", len(diff.LostHosts))
	}
	if diff.HealthDelta != 0 {
		t.Errorf("Expected health delta 0, got %d", diff.HealthDelta)
	}
	if diff.MACCountDelta != 0 {
		t.Errorf("Expected MAC count delta 0, got %d", diff.MACCountDelta)
	}
}

// TestCompareSnapshots_MassJoin tests many devices joining at once
func TestCompareSnapshots_MassJoin(t *testing.T) {
	prev := &NetworkSnapshot{
		Timestamp:   time.Now().Add(-1 * time.Minute),
		ActiveMACs:  map[string]MACInfo{},
		ActiveHosts: map[string]HostInfo{},
		Anomalies:   map[string][]string{},
		HealthScore: 100,
	}

	curr := &NetworkSnapshot{
		Timestamp:  time.Now(),
		ActiveMACs: make(map[string]MACInfo),
		ActiveHosts: map[string]HostInfo{
			"172.20.230.4": {SysName: "Switch-A", Vendor: "SNR", Health: 80},
		},
		Anomalies:   map[string][]string{},
		HealthScore: 80,
	}

	// Simulate 100 MACs joining
	for i := 0; i < 100; i++ {
		mac := fmt.Sprintf("aa:bb:cc:dd:%02x:%02x", i/256, i%256)
		curr.ActiveMACs[mac] = MACInfo{
			IP:       fmt.Sprintf("192.168.1.%d", i+1),
			SwitchIP: "172.20.230.4",
			Port:     i%48 + 1,
			Vendor:   "Unknown",
		}
	}

	diff := CompareSnapshots(prev, curr)

	if len(diff.JoinedMACs) != 100 {
		t.Errorf("Expected 100 joined MACs, got %d", len(diff.JoinedMACs))
	}
	if len(diff.LeftMACs) != 0 {
		t.Errorf("Expected 0 left MACs, got %d", len(diff.LeftMACs))
	}
	if diff.MACCountDelta != 100 {
		t.Errorf("Expected MAC count delta 100, got %d", diff.MACCountDelta)
	}
	if diff.HealthDelta != -20 {
		t.Errorf("Expected health delta -20, got %d", diff.HealthDelta)
	}

	// Visual output (should show max 10 + "... va yana 90 ta")
	fmt.Println("\n=== Mass Join Visual Diff ===")
	diff.LogChanges()
}
