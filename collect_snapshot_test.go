package main

import (
	"fmt"
	"maps"
	"slices"
	"testing"
	"time"
)

// Tests for the snapshot fixes (snapshot_diff.go).

// collectPortMACs returns n MAC entries on one bridge port: the given MACs
// first, then fillers 00:1b:21:<tag>:xx:xx.
func collectPortMACs(port, n int, tag byte, macs ...string) []MACEntry {
	entries := macEntries(port, macs...)
	for i := len(macs); i < n; i++ {
		entries = append(entries, MACEntry{MACAddress: fmt.Sprintf("00:1b:21:%02x:%02x:%02x", tag, port, i), PortNumber: port, Status: "learned"})
	}
	return entries
}

// TestCollectSnapshotAttribution checks F54: a MAC learned on several
// switches is attributed to the port where it has the fewest neighbors (the
// access port, not the uplinks that carry it), preferring reachable
// switches, then the lower switch IP, whatever order the devices come in.
// It also checks the Q11 filter and the ifIndex port (F60).
func TestCollectSnapshotAttribution(t *testing.T) {
	resetState(t)
	const x, y, w = "00:50:56:09:03:01", "00:50:56:09:03:02", "00:50:56:09:03:03"
	core := &DeviceData{IP: "10.9.3.1", ChassisID: "4c:ae:a3:09:03:01",
		MACTable: append(collectPortMACs(48, 31, 0x31, x, y), macEntries(3, w)...)}
	access := &DeviceData{IP: "10.9.3.2", ChassisID: "4c:ae:a3:09:03:02",
		MACTable: append(append(macEntries(5, x), macEntries(4, w)...),
			macEntries(6, "01:00:5e:00:00:fb", "00:00:00:12:34:56", "ff:ff:ff:ff:ff:ff", "00:1b:21:09:3e7:01", "33:33:00:00:00:02")...),
		BridgePortIfIndex: map[int]int{5: 10}}
	stale := &DeviceData{IP: "10.9.3.3", ChassisID: "4c:ae:a3:09:03:03", Unreachable: true,
		MACTable: macEntries(2, y)}
	other := &DeviceData{IP: "10.9.3.4", ChassisID: "4c:ae:a3:09:03:04",
		MACTable: collectPortMACs(9, 3, 0x34, y)}
	globalMACtoIPMutex.Lock()
	globalMACtoIP = map[string]string{x: "10.0.3.1"}
	globalMACtoIPMutex.Unlock()

	want := map[string]MACInfo{
		x: {IP: "10.0.3.1", SwitchIP: "10.9.3.2", Port: 10, Vendor: getMACVendor(x)}, // access port, bridge port 5 is ifIndex 10
		y: {SwitchIP: "10.9.3.4", Port: 9, Vendor: getMACVendor(y)},                  // reachable 3-MAC port beats the 31-MAC uplink and the unreachable switch
		w: {SwitchIP: "10.9.3.1", Port: 3, Vendor: getMACVendor(w)},                  // tie (one MAC each): lower switch IP
	}
	orders := [][]*DeviceData{{core, access, stale, other}, {other, stale, access, core}, {stale, other, core, access}}
	for i, devices := range orders {
		snap := CreateSnapshot(devices, nil, nil)
		for mac, info := range want {
			if got := snap.ActiveMACs[mac]; got != info {
				t.Errorf("order %d: %s = %+v, want %+v", i, mac, got, info)
			}
		}
		for _, mac := range []string{"01:00:5e:00:00:fb", "00:00:00:12:34:56", "ff:ff:ff:ff:ff:ff", "00:1b:21:09:3e7:01", "33:33:00:00:00:02"} {
			if _, ok := snap.ActiveMACs[mac]; ok {
				t.Errorf("order %d: %s should be filtered (Q11)", i, mac)
			}
		}
		// 31 + 1 on the core (x, y and fillers, w), 2 fillers on the other switch
		if n := len(snap.ActiveMACs); n != 3+29+2 {
			t.Errorf("order %d: %d active MACs, want %d", i, n, 3+29+2)
		}
	}
}

// collectSnapshotDevices is a small network for the anomaly tests.
func collectSnapshotDevices() []*DeviceData {
	return []*DeviceData{
		{IP: "10.9.4.1", SysName: "core", ChassisID: "4c:ae:a3:09:04:01"},
		{IP: "10.9.4.2", SysName: "sw-b", ChassisID: "4C AE A3 09 04 02"},
		{IP: "10.9.4.3", SysName: "sw-c", ChassisID: ""},
	}
}

// TestCollectSnapshotAnomalies checks F55: suggestions whose Device is not a
// switch IP are matched too. path names a graph label "SysName (node id)";
// stp, one suggestion about the whole network, goes to the "network" host.
func TestCollectSnapshotAnomalies(t *testing.T) {
	resetState(t)
	report := &Report{HealthScore: 80, Suggestions: []OptimizationSuggestion{
		{Type: "shadow_it", Device: "10.9.4.3"},
		{Type: "stp", Device: "4c:ae:a3:09:04:02"},
		{Type: "path", Device: "sw-b\n10.9.4.2 (4c:ae:a3:09:04:02)"},
		{Type: "path", Device: "sw-c (10.9.4.3)"},
		{Type: "path", Device: "4C-AE-A3-09-04-01"},                              // chassis MAC of core
		{Type: "path", Device: "core"},                                           // a SysName alone is not enough
		{Type: "path", Device: "[ENDPOINT] Intel\n10.0.4.9 (00:1b:21:09:04:09)"}, // not a polled switch
		{Type: "congestion", Severity: "high", Device: "10.9.4.1"},
		{Type: "loopback", Device: "10.9.4.99"}, // not polled
	}}
	snap := CreateSnapshot(collectSnapshotDevices(), nil, report)
	got := map[string][]string{}
	for host, types := range snap.Anomalies {
		got[host] = slices.Sorted(slices.Values(types))
	}
	want := map[string][]string{
		"10.9.4.1": {"congestion", "path"},
		"10.9.4.2": {"path"},
		"10.9.4.3": {"path", "shadow_it"},
		"network":  {"stp"},
	}
	if !maps.EqualFunc(got, want, slices.Equal[[]string]) {
		t.Errorf("Anomalies = %v, want %v", got, want)
	}
	for ip, health := range map[string]int{"10.9.4.1": 93, "10.9.4.2": 98, "10.9.4.3": 88} {
		if h := snap.ActiveHosts[ip].Health; h != health {
			t.Errorf("Health[%s] = %d, want %d", ip, h, health)
		}
	}
}

// TestCollectSTPAnomalyNoFlap checks that the stp anomaly does not follow the
// root bridge the analyzer names (one of many, chosen by map order, F18):
// the snapshot is the same whichever root is named, so there are events only
// when stp appears or goes away.
func TestCollectSTPAnomalyNoFlap(t *testing.T) {
	resetState(t)
	snap := func(sugg ...OptimizationSuggestion) *NetworkSnapshot {
		return CreateSnapshot(collectSnapshotDevices(), nil, &Report{Suggestions: sugg})
	}
	shadow := OptimizationSuggestion{Type: "shadow_it", Device: "10.9.4.1"}
	rootA := snap(shadow, OptimizationSuggestion{Type: "stp", Device: "4c:ae:a3:09:04:01"})
	rootB := snap(shadow, OptimizationSuggestion{Type: "stp", Device: "4c:ae:a3:09:04:02"})
	rootX := snap(shadow, OptimizationSuggestion{Type: "stp", Device: "00:16:e0:5a:5c:e0"})
	none := snap(shadow)

	for _, pair := range [][2]*NetworkSnapshot{{rootA, rootB}, {rootB, rootX}} {
		if d := CompareSnapshots(pair[0], pair[1]); len(d.NewAnomalies) != 0 || len(d.FixedAnomalies) != 0 {
			t.Errorf("another root named: new %v, fixed %v; want no events", d.NewAnomalies, d.FixedAnomalies)
		}
	}
	stp := []AnomalyDiff{{DeviceIP: "network", AnomalyType: "stp"}}
	if d := CompareSnapshots(rootB, none); !slices.Equal(d.FixedAnomalies, stp) || len(d.NewAnomalies) != 0 {
		t.Errorf("stp gone: new %v, fixed %v", d.NewAnomalies, d.FixedAnomalies)
	}
	if d := CompareSnapshots(none, rootA); !slices.Equal(d.NewAnomalies, stp) || len(d.FixedAnomalies) != 0 {
		t.Errorf("stp appeared: new %v, fixed %v", d.NewAnomalies, d.FixedAnomalies)
	}
	// Per-device anomalies follow their device.
	moved := snap(OptimizationSuggestion{Type: "shadow_it", Device: "10.9.4.2"})
	d := CompareSnapshots(none, moved)
	if !slices.Equal(d.NewAnomalies, []AnomalyDiff{{DeviceIP: "10.9.4.2", AnomalyType: "shadow_it"}}) ||
		!slices.Equal(d.FixedAnomalies, []AnomalyDiff{{DeviceIP: "10.9.4.1", AnomalyType: "shadow_it"}}) {
		t.Errorf("shadow_it moved: new %v, fixed %v", d.NewAnomalies, d.FixedAnomalies)
	}
}

// TestCollectEventDurationKeys checks F56: a closing event is paired with
// the opening event of the same host (host events) or the same switch port
// (port events). All host events used to share the key ":0", so the
// host_up of one host closed the host_down of another.
func TestCollectEventDurationKeys(t *testing.T) {
	resetState(t)
	const a, b, sw = "10.9.5.1", "10.9.5.2", "10.9.5.3"
	cleanup := func() {
		openEventTimesMutex.Lock()
		for _, evt := range []NetworkEvent{{Type: "host_down", IP: a}, {Type: "host_down", IP: b}, {Type: "port_down", SwitchIP: sw, Port: 5}} {
			delete(openEventTimes, collectOpenEventKey(evt))
		}
		openEventTimesMutex.Unlock()
	}
	cleanup()
	t.Cleanup(cleanup)
	influxRec.start("network_events")

	persistEventToInflux(NetworkEvent{Type: "host_down", IP: a, Message: "a down"})
	persistEventToInflux(NetworkEvent{Type: "host_down", IP: b, Message: "b down"})
	persistEventToInflux(NetworkEvent{Type: "port_down", SwitchIP: sw, Port: 5, Message: "port down"})
	// Back-date the opening events: a 120 s, b 60 s, the port 30 s ago.
	openEventTimesMutex.Lock()
	for evt, ago := range map[NetworkEvent]time.Duration{
		{Type: "host_down", IP: a}:                 120 * time.Second,
		{Type: "host_down", IP: b}:                 60 * time.Second,
		{Type: "port_down", SwitchIP: sw, Port: 5}: 30 * time.Second,
	} {
		key := collectOpenEventKey(evt)
		if _, open := openEventTimes[key]; !open {
			t.Errorf("%+v did not open %q", evt, key)
		}
		openEventTimes[key] = eventClock().Add(-ago) // the durations' clock
	}
	openEventTimesMutex.Unlock()

	persistEventToInflux(NetworkEvent{Type: "host_up", IP: b, Message: "b up"})
	persistEventToInflux(NetworkEvent{Type: "port_up", SwitchIP: sw, Port: 5, Message: "port up"})
	persistEventToInflux(NetworkEvent{Type: "host_up", IP: a, Message: "a up"})

	durations := map[string]any{}
	for _, p := range influxRec.stop() {
		if msg, _ := p.Fields["message"].(string); msg != "" {
			durations[msg] = p.Fields["duration_s"]
		}
	}
	for msg, lo := range map[string]int{"a up": 120, "b up": 60, "port up": 30} {
		d, _ := durations[msg].(int64)
		if d < int64(lo) || d > int64(lo)+5 {
			t.Errorf("%s: duration_s = %v, want about %d", msg, durations[msg], lo)
		}
	}
}
