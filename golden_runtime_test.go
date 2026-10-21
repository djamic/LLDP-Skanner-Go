package main

import (
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// TestGoldenScenarioRuntime pins the main() wiring that lives in named
// functions: the SNMP objects of each mode with their store and unreachable
// callbacks (storeCollectedDevice, markUnreachable), the startup sequence
// (loadStartupData), the event durations written to InfluxDB, and the
// network_summary point of a snapshot diff.
func TestGoldenScenarioRuntime(t *testing.T) {
	rec := map[string]any{
		"snmp_objects":    runtimeSNMPObjects(t),
		"startup":         runtimeStartup(t),
		"event_durations": runtimeEventDurations(t),
		"network_summary": runtimeNetworkSummary(t),
	}
	checkGolden(t, "scenario_runtime.json", goldenJSON(t, rec, 3))
}

// collectedState describes what collectedData holds for ip.
func collectedState(ip string) map[string]any {
	collectedDataMutex.RLock()
	defer collectedDataMutex.RUnlock()
	d, ok := collectedData[ip]
	if !ok {
		return map[string]any{"present": false}
	}
	macTable := "nil"
	if d.MACTable != nil {
		macTable = fmt.Sprintf("%d entries", len(d.MACTable))
	}
	return map[string]any{
		"present":       true,
		"sys_name":      d.SysName,
		"interfaces":    len(d.Interfaces),
		"mac_table":     macTable,
		"unreachable":   d.Unreachable,
		"last_seen_set": !d.LastSeen.IsZero(),
	}
}

// trafficBaselines lists the switches that have traffic counters.
func trafficBaselines() []string {
	interfaceTrafficMapMutex.RLock()
	defer interfaceTrafficMapMutex.RUnlock()
	return slices.Sorted(maps.Keys(interfaceTrafficMap))
}

// runtimeSNMPObjects polls fake agents with the SNMP object of each mode and
// records what reaches collectedData: monitor24h with saved hosts (a full
// poll, a poll whose FDB walk fails, a poll where every walk fails), normal
// mode with saved hosts (a saved and a new switch), and the failure callback
// of the reactive first scan.
func runtimeSNMPObjects(t *testing.T) []map[string]any {
	resetState(t)
	var steps []map[string]any
	step := func(name, ip string) {
		steps = append(steps, map[string]any{"step": name, "ip": ip, "collected_data": collectedState(ip), "traffic_baselines": trafficBaselines()})
	}

	const monitorIP = "10.9.1.1"
	monitor := newMonitorSNMPObject()
	fakeSNMP.set(monitorIP, healthyAgent())
	monitor.CollectData(monitorIP, "sw-monitor")
	step("monitor24h: full poll", monitorIP)
	noFDB := healthyAgent()
	delete(noFDB, oidFDBPort)
	fakeSNMP.set(monitorIP, noFDB)
	monitor.CollectData(monitorIP, "sw-monitor")
	step("monitor24h: poll whose FDB walk fails", monitorIP)
	fakeSNMP.set(monitorIP, map[string][]string{})
	monitor.CollectData(monitorIP, "sw-monitor")
	step("monitor24h: poll where every walk fails", monitorIP)

	const savedIP, newIP = "10.9.1.2", "10.9.1.3"
	collectedDataMutex.Lock()
	collectedData[savedIP] = &DeviceData{IP: savedIP, SysName: "sw-saved", MACTable: macEntries(3, "00:1b:21:09:aa:01")}
	collectedDataMutex.Unlock()
	saved := newSavedHostsSNMPObject()
	fakeSNMP.set(savedIP, healthyAgent())
	fakeSNMP.set(newIP, healthyAgent())
	saved.CollectData(savedIP, "sw-saved-polled")
	step("saved hosts: full poll of a saved switch", savedIP)
	saved.CollectData(newIP, "sw-new")
	step("saved hosts: full poll of a switch not saved", newIP)

	const reactiveIP = "10.9.1.4"
	collectedDataMutex.Lock()
	collectedData[reactiveIP] = &DeviceData{IP: reactiveIP, SysName: "sw-reactive"}
	collectedDataMutex.Unlock()
	newReactiveSNMPObject().OnFailure(reactiveIP, errors.New("all 7 SNMP walks failed for "+reactiveIP))
	step("first scan: failure callback for a stored switch", reactiveIP)
	return steps
}

// runtimeStartup runs loadStartupData twice: with two saved switches, and
// with no saved data. The MAC-IP cache file has IPs for every MAC of the
// saved switches and the gateway's ARP table adds one more. The first graph
// is recorded together with the graph the next rebuild publishes.
func runtimeStartup(t *testing.T) map[string]any {
	out := map[string]any{}
	for _, withHosts := range []bool{true, false} {
		resetState(t)
		macIPCacheFile = filepath.Join(t.TempDir(), "mac_ip_cache.json")
		cache := `{"00:1b:21:08:01:01": "10.0.8.51", "00:50:56:08:01:01": "10.0.8.61", "00:50:56:08:01:02": "10.0.8.71",
			"00:1b:21:08:02:01": "10.0.8.52", "00:50:56:08:02:01": "10.0.8.62", "00:50:56:08:02:02": "10.0.8.72"}`
		if err := os.WriteFile(macIPCacheFile, []byte(cache), 0o644); err != nil {
			t.Fatal(err)
		}
		fakeSNMP.set(fixedGatewayIP, map[string][]string{oidARP: {
			oidARP + ".5.10.0.8.99 = Hex-STRING: 00 1B 21 08 09 09 ",
			oidARP + ".5.10.0.8.51 = Hex-STRING: 00 1B 21 08 01 01 ",
		}})
		var hosts map[string]*DeviceData
		name := "no_saved_data"
		if withHosts {
			name = "saved_hosts"
			hosts = map[string]*DeviceData{}
			for _, d := range reactiveDevices()[:2] {
				hosts[d.IP] = d
			}
		}
		loadStartupData(hosts)

		rec := map[string]any{
			"collected_data":    slices.Sorted(maps.Keys(snapshotCollectedData())),
			"traffic_baselines": trafficBaselines(),
			"collector_starts":  macIPCollectorStarts.Load(),
			"queued":            esxiJobs.taken(),
		}
		globalMACtoIPMutex.RLock()
		rec["mac_to_ip"] = maps.Clone(globalMACtoIP)
		globalMACtoIPMutex.RUnlock()
		if g := GetGlobalGraph(); g != nil {
			rec["first_graph"] = viewGraph(g)
			// What the next rebuild (the first periodic rescan) publishes.
			rec["next_rebuild_graph"] = viewGraph(rebuildGraph())
		} else {
			rec["first_graph"] = "none published"
		}
		out[name] = rec
	}
	return out
}

// runtimeEventDurations feeds host and port events to persistEventToInflux
// on the test clock and records the network_events point of each: a host
// goes down, a port goes down, another host comes up, the port comes back,
// and the first host comes back.
func runtimeEventDurations(t *testing.T) []map[string]any {
	resetState(t)
	events := []struct {
		after time.Duration
		evt   NetworkEvent
	}{
		{0, NetworkEvent{Type: "host_down", IP: "172.20.230.21", Message: "SNMP host down: 172.20.230.21"}},
		{10 * time.Second, NetworkEvent{Type: "port_down", SwitchIP: "172.20.230.22", Port: 5, Message: "Port 5 down on 172.20.230.22"}},
		{20 * time.Second, NetworkEvent{Type: "host_up", IP: "172.20.230.23", Message: "SNMP host up: 172.20.230.23"}},
		{10 * time.Second, NetworkEvent{Type: "port_up", SwitchIP: "172.20.230.22", Port: 5, Message: "Port 5 up on 172.20.230.22"}},
		{60 * time.Second, NetworkEvent{Type: "host_up", IP: "172.20.230.21", Message: "SNMP host up: 172.20.230.21"}},
	}
	var out []map[string]any
	elapsed := time.Duration(0)
	for _, e := range events {
		testClock.advance(e.after)
		elapsed += e.after
		influxRec.start("network_events")
		persistEventToInflux(e.evt)
		out = append(out, map[string]any{"at_s": elapsed.Seconds(), "event": e.evt.Type + " " + e.evt.IP + e.evt.SwitchIP, "points": influxRec.stop()})
	}
	return out
}

// runtimeNetworkSummary runs recordSnapshotDiff on two small snapshots whose
// MACs include a KVM MAC, a VMware MAC, random and locally administered MACs,
// and records the random_macs count it writes to InfluxDB.
func runtimeNetworkSummary(t *testing.T) map[string]any {
	resetState(t)
	macs := []string{
		"52:54:00:12:34:56", // QEMU/KVM
		"00:50:56:09:aa:02", // VMware
		"da:a1:19:09:aa:03", // random (locally administered)
		"02:42:ac:11:00:02", // Docker bridge (locally administered)
		"00:1b:21:09:aa:01", // Intel
	}
	snapshot := func(n int) *NetworkSnapshot {
		s := &NetworkSnapshot{
			Timestamp:   fixedTime,
			ActiveMACs:  map[string]MACInfo{},
			ActiveHosts: map[string]HostInfo{"10.0.9.2": {SysName: "sw-a", Health: 100}},
			Anomalies:   map[string][]string{},
			Ports:       map[string]map[int]int{},
			HealthScore: 90,
		}
		for i, mac := range macs[:n] {
			s.ActiveMACs[mac] = MACInfo{SwitchIP: "10.0.9.2", Port: i + 1}
		}
		return s
	}
	prev, curr := snapshot(len(macs)-1), snapshot(len(macs))
	random := map[string]bool{}
	for _, mac := range macs {
		random[mac] = isRandomMAC(mac)
	}
	report := Report{Summary: map[string]int{"shadow_it_issues": 2}}
	influxRec.start("network_summary")
	recordSnapshotDiff(prev, curr, &report)
	return map[string]any{
		"isRandomMAC":     random,
		"countRandomMACs": countRandomMACs(curr),
		"influx_points":   influxRec.stop(),
	}
}
