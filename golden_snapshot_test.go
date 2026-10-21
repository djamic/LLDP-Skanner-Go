package main

import (
	"cmp"
	"maps"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

type snapMAC struct {
	Switch string `json:"switch"`
	Port   int    `json:"port"`
	IP     string `json:"ip,omitempty"`
	Vendor string `json:"vendor,omitempty"`
}

type snapEntry struct {
	MAC    string `json:"mac"`
	Switch string `json:"switch"`
	Port   int    `json:"port"`
	IP     string `json:"ip,omitempty"`
	Vendor string `json:"vendor,omitempty"`
}

func diffEntries(list []MACDiffEntry) []snapEntry {
	var out []snapEntry
	for _, m := range list {
		out = append(out, snapEntry{MAC: m.MAC, Switch: m.SwitchIP, Port: m.Port, IP: m.IP, Vendor: m.Vendor})
	}
	slices.SortFunc(out, func(a, b snapEntry) int { return strings.Compare(a.MAC, b.MAC) })
	return out
}

// macsOnly returns the MACs that appear in exactly one device's MAC table,
// mapped to that device's IP.
func macsOnly(devices map[string]*DeviceData) map[string]string {
	owner := map[string]string{}
	count := map[string]int{}
	for ip, d := range devices {
		seen := map[string]bool{}
		for _, m := range d.MACTable {
			mac := normalizeMAC(m.MACAddress)
			if !seen[mac] {
				seen[mac] = true
				count[mac]++
				owner[mac] = ip
			}
		}
	}
	for mac, n := range count {
		if n != 1 {
			delete(owner, mac)
		}
	}
	return owner
}

// derivePrevious returns a copy of the fixture as it could have looked one
// cycle earlier: three MACs missing (they JOIN), three extra MACs (they
// LEAVE), one MAC on another switch (it only moves), one switch missing (it
// is new), one extra switch (it is lost), reachability flips and one port
// status flip. Slices are copied before they are changed.
func derivePrevious(t *testing.T, devices map[string]*DeviceData, cache map[string]string) (map[string]*DeviceData, map[string]any) {
	t.Helper()
	prev := map[string]*DeviceData{}
	for ip, d := range devices {
		cp := *d
		cp.MACTable = slices.Clone(d.MACTable)
		cp.Interfaces = slices.Clone(d.Interfaces)
		prev[ip] = &cp
	}
	ips := sortedDeviceIPs(prev)
	single := macsOnly(devices)
	singleMACs := slices.Sorted(maps.Keys(single))
	if len(singleMACs) < 4 {
		t.Fatal("fixture has too few single-switch MACs")
	}

	// JOIN: drop three MACs from every switch.
	joined := singleMACs[:3]
	for _, d := range prev {
		d.MACTable = slices.DeleteFunc(d.MACTable, func(m MACEntry) bool {
			return slices.Contains(joined, normalizeMAC(m.MACAddress))
		})
	}

	// MOVE: one MAC was on another switch's port 1.
	moved := singleMACs[3]
	from := single[moved]
	to := ips[0]
	if to == from {
		to = ips[1]
	}
	prev[from].MACTable = slices.DeleteFunc(prev[from].MACTable, func(m MACEntry) bool { return normalizeMAC(m.MACAddress) == moved })
	prev[to].MACTable = append(prev[to].MACTable, MACEntry{MACAddress: moved, PortNumber: 1, Status: "learned"})

	// LEAVE: a random MAC, a VMware MAC and a MAC with a cached IP.
	cachedOnly := ""
	for _, mac := range slices.Sorted(maps.Keys(cache)) {
		if _, inFDB := single[mac]; !inFDB && !isRandomMAC(mac) && !isSpecialMAC(mac) {
			cachedOnly = mac
			break
		}
	}
	left := []string{"02:00:5e:10:00:01", "00:50:56:00:00:99", cachedOnly}
	for i, mac := range left {
		prev[ips[2]].MACTable = append(prev[ips[2]].MACTable, MACEntry{MACAddress: mac, PortNumber: 40 + i, Status: "learned"})
	}

	// NEW HOST: the switch with the fewest MAC entries was not polled yet.
	newHost := ips[0]
	for _, ip := range ips {
		if len(devices[ip].MACTable) < len(devices[newHost].MACTable) {
			newHost = ip
		}
	}
	delete(prev, newHost)

	// LOST HOST: a switch that no longer answers.
	prev["172.20.230.250"] = &DeviceData{IP: "172.20.230.250", SysName: "lost-switch", ChassisID: "4c:ae:a3:00:02:50"}

	// UNREACHABLE / RESTORED.
	var unreachable []string
	for _, ip := range ips {
		if d, ok := prev[ip]; ok && d.Unreachable {
			d.Unreachable = false
			unreachable = append(unreachable, ip)
		}
	}
	restored := ""
	for _, ip := range ips {
		if d, ok := prev[ip]; ok && !d.Unreachable && !slices.Contains(unreachable, ip) && ip != newHost {
			d.Unreachable = true
			restored = ip
			break
		}
	}

	// PORT FLIP: the first interface with status 1 or 2 on the last switch.
	flipped := ""
	last := prev[ips[len(ips)-1]]
	for i, iface := range last.Interfaces {
		if iface.IfOperStatus == 1 || iface.IfOperStatus == 2 {
			last.Interfaces[i].IfOperStatus = 3 - iface.IfOperStatus
			flipped = last.IP + " port " + strconv.Itoa(iface.IfIndex)
			break
		}
	}

	return prev, map[string]any{
		"joined":                  joined,
		"left":                    left,
		"moved":                   map[string]string{"mac": moved, "previous_switch": to, "current_switch": from},
		"new_host":                newHost,
		"lost_host":               "172.20.230.250",
		"made_reachable_before":   unreachable,
		"made_unreachable_before": restored,
		"port_flipped":            flipped,
	}
}

// TestGoldenSnapshot pins CreateSnapshot on the fixture (devices in IP order)
// and recordSnapshotDiff between a derived previous cycle and the fixture:
// the JOIN/LEAVE and host/port/anomaly diff, the UI event log entries and the
// device_events and network_summary points written to InfluxDB.
func TestGoldenSnapshot(t *testing.T) {
	graph := buildFixtureGraph(t)
	report, _ := analyzeFixture(t, graph)
	collectedDataMutex.RLock()
	devices := make(map[string]*DeviceData, len(collectedData))
	for ip, d := range collectedData {
		devices[ip] = d
	}
	collectedDataMutex.RUnlock()

	curr := CreateSnapshot(sortedDevices(devices), graph, &report)
	curr.Timestamp = fixedTime

	_, stpDevice := suggestionRecords(report)
	hostAnomalies := map[string][]string{}
	for ip, types := range curr.Anomalies {
		hostAnomalies[ip] = slices.Sorted(slices.Values(types))
	}
	macs := map[string]snapMAC{}
	for mac, info := range curr.ActiveMACs {
		macs[mac] = snapMAC{Switch: info.SwitchIP, Port: info.Port, IP: info.IP, Vendor: info.Vendor}
	}

	// Previous cycle: derived devices and a report with one fixed and one
	// new anomaly.
	prevDevices, derivation := derivePrevious(t, devices, fixtureCache(t))
	prevReport := report
	prevReport.HealthScore = report.HealthScore + 5
	prevReport.Suggestions = nil
	// The shadow_it device with the lowest IP had no alert one cycle ago.
	newAnomalyDevice := ""
	for _, s := range report.Suggestions {
		if s.Type == "shadow_it" && (newAnomalyDevice == "" || compareIPs(s.Device, newAnomalyDevice) < 0) {
			newAnomalyDevice = s.Device
		}
	}
	for _, s := range report.Suggestions {
		if s.Device == newAnomalyDevice && s.Type == "shadow_it" {
			continue
		}
		prevReport.Suggestions = append(prevReport.Suggestions, s)
	}
	prevReport.Suggestions = append(prevReport.Suggestions, OptimizationSuggestion{Type: "loopback", Severity: "high", Device: "172.20.230.250"})
	derivation["new_anomaly"] = newAnomalyDevice + " shadow_it"
	derivation["fixed_anomaly"] = "172.20.230.250 loopback"

	prev := CreateSnapshot(sortedDevices(prevDevices), graph, &prevReport)
	prev.Timestamp = fixedTime.Add(-time.Minute)

	diff := CompareSnapshots(prev, curr)
	networkEventLogMutex.Lock()
	networkEventLog = nil
	networkEventLogMutex.Unlock()
	influxRec.start("device_events", "network_summary")
	recordSnapshotDiff(prev, curr, &report)
	points := influxRec.stop()
	events := GetNetworkEvents()
	slices.SortFunc(events, func(a, b NetworkEvent) int {
		return cmp.Or(strings.Compare(a.Type, b.Type), strings.Compare(a.Message, b.Message))
	})

	slices.Sort(diff.NewHosts)
	slices.Sort(diff.LostHosts)
	slices.Sort(diff.UnreachableHosts)
	slices.Sort(diff.RestoredHosts)
	slices.SortFunc(diff.PortStatusChanges, func(a, b PortStatusChange) int {
		return cmp.Or(strings.Compare(a.SwitchIP, b.SwitchIP), cmp.Compare(a.PortIndex, b.PortIndex))
	})
	anomalyKey := func(a, b AnomalyDiff) int {
		return cmp.Or(strings.Compare(a.DeviceIP, b.DeviceIP), strings.Compare(a.AnomalyType, b.AnomalyType))
	}
	slices.SortFunc(diff.NewAnomalies, anomalyKey)
	slices.SortFunc(diff.FixedAnomalies, anomalyKey)
	for _, a := range append(slices.Clone(diff.NewAnomalies), diff.FixedAnomalies...) {
		if stpDevice != "" && a.DeviceIP == stpDevice {
			t.Fatalf("stp anomaly leaked into the diff: %+v", a)
		}
	}

	rec := map[string]any{
		"snapshot_summary": map[string]any{
			"active_macs":  len(curr.ActiveMACs),
			"random_macs":  countRandomMACs(curr),
			"active_hosts": len(curr.ActiveHosts),
			"health_score": curr.HealthScore,
			"graph_nodes":  curr.GraphNodes,
			"graph_edges":  curr.GraphEdges,
		},
		"snapshot_hosts":     curr.ActiveHosts,
		"snapshot_anomalies": hostAnomalies,
		"snapshot_ports":     curr.Ports,
		"snapshot_macs":      macs,
		"previous_cycle":     derivation,
		"compare_summary": map[string]any{
			"health_delta":      diff.HealthDelta,
			"mac_count_delta":   diff.MACCountDelta,
			"new_hosts":         diff.NewHosts,
			"lost_hosts":        diff.LostHosts,
			"unreachable_hosts": diff.UnreachableHosts,
			"restored_hosts":    diff.RestoredHosts,
		},
		"compare_joined":          diffEntries(diff.JoinedMACs),
		"compare_left":            diffEntries(diff.LeftMACs),
		"compare_port_changes":    diff.PortStatusChanges,
		"compare_new_anomalies":   diff.NewAnomalies,
		"compare_fixed_anomalies": diff.FixedAnomalies,
		"events":                  events,
		"influx_points":           points,
	}
	checkGolden(t, "snapshot.json", goldenJSON(t, rec, 2))
}
