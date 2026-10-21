package main

import (
	"cmp"
	"fmt"
	"maps"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"
)

// ============================================================
// B.1 — Snapshot Diff Engine
// ============================================================

// MACInfo holds metadata about a single MAC address seen on the network
type MACInfo struct {
	IP       string
	SwitchIP string
	Port     int
	Vendor   string
}

// HostInfo holds metadata about an SNMP-reachable host
type HostInfo struct {
	SysName     string
	Vendor      string
	Health      int
	Unreachable bool // Phase 8: device was unreachable at snapshot time
}

// NetworkSnapshot represents the state of the network at a given point in time
type NetworkSnapshot struct {
	Timestamp   time.Time
	ActiveMACs  map[string]MACInfo  // MAC address → info
	ActiveHosts map[string]HostInfo // IP → host info
	Anomalies   map[string][]string // IP → anomaly types list
	Ports       map[string]map[int]int // Phase 8: SwitchIP → PortIndex → IfOperStatus
	HealthScore int
	GraphNodes  int
	GraphEdges  int
}

// MACDiffEntry holds details about a MAC that joined or left the network
type MACDiffEntry struct {
	MAC      string
	IP       string
	SwitchIP string
	Port     int
	Vendor   string
}

// AnomalyDiff holds details about an anomaly that appeared or disappeared
type AnomalyDiff struct {
	DeviceIP    string
	AnomalyType string
}

// PortStatusChange holds details about a port that went up or down
type PortStatusChange struct {
	SwitchIP     string
	PortIndex    int
	PortName     string
	OldStatus    int // 1=up, 2=down
	NewStatus    int
	AffectedMACs int
}

// SnapshotDiff represents the differences between two snapshots
type SnapshotDiff struct {
	Timestamp         time.Time
	JoinedMACs        []MACDiffEntry    // DEVICE_JOIN
	LeftMACs          []MACDiffEntry    // DEVICE_LEAVE
	NewHosts          []string          // New SNMP-reachable hosts
	LostHosts         []string          // Hosts that stopped responding
	UnreachableHosts  []string          // Phase 8: hosts that became unreachable
	RestoredHosts     []string          // Phase 8: hosts that restored from unreachable
	PortStatusChanges []PortStatusChange // Phase 8: port Up/Down changes
	NewAnomalies      []AnomalyDiff     // Newly appeared anomalies
	FixedAnomalies    []AnomalyDiff     // Anomalies that disappeared (fixed)
	HealthDelta       int               // Health score change (current - previous)
	MACCountDelta     int               // MAC count change
}

// Global previous snapshot for periodic comparison
var (
	previousSnapshot      *NetworkSnapshot
	previousSnapshotMutex sync.Mutex
)

// ============================================================
// Network Event Log (for UI Events Panel)
// ============================================================

// NetworkEvent represents a single network event (device join/leave/anomaly)
type NetworkEvent struct {
	Time     string `json:"time"`
	Type     string `json:"type"`     // "join", "leave", "host_up", "host_down", "anomaly", "fixed"
	MAC      string `json:"mac,omitempty"`
	IP       string `json:"ip,omitempty"`
	Vendor   string `json:"vendor,omitempty"`
	SwitchIP string `json:"switchIP,omitempty"`
	Port     int    `json:"port,omitempty"`
	Message  string `json:"message"`
}

const maxEventLogSize = 200

var (
	networkEventLog      []NetworkEvent
	networkEventLogMutex sync.RWMutex
)

// Phase 14: Duration tracking cache for open events (port_down, host_down, unreachable)
var (
	openEventTimes      = make(map[string]time.Time) // key: "switch_ip:port:type" → start time
	openEventTimesMutex sync.Mutex
)

// AddNetworkEvent appends an event to the global log (thread-safe, capped at maxEventLogSize)
// Phase 14: Also writes to InfluxDB with duration tracking
func AddNetworkEvent(evt NetworkEvent) {
	networkEventLogMutex.Lock()
	defer networkEventLogMutex.Unlock()

	networkEventLog = append(networkEventLog, evt)

	// Cap at max size — keep newest events
	if len(networkEventLog) > maxEventLogSize {
		networkEventLog = networkEventLog[len(networkEventLog)-maxEventLogSize:]
	}

	// Phase 14: Persist to InfluxDB + duration tracking
	go persistEventToInflux(evt)
}

// eventClock is the time source of the event durations. Tests replace it
// with a clock they control.
var eventClock = time.Now

// persistEventToInflux writes the event to InfluxDB with duration calculation
func persistEventToInflux(evt NetworkEvent) {
	durationS := 0

	openEventTimesMutex.Lock()
	key := collectOpenEventKey(evt)

	switch evt.Type {
	case "host_down", "port_down":
		// Open event — record start time
		openEventTimes[key] = eventClock()
	case "host_up", "port_up":
		// Close event — calculate duration
		if start, ok := openEventTimes[key]; ok {
			durationS = int(eventClock().Sub(start).Seconds())
			delete(openEventTimes, key)
		}
	}
	openEventTimesMutex.Unlock()

	WriteNetworkEventToInflux(evt, durationS)
}

// collectOpenEventKey pairs a closing event with the event that opened it:
// port events by switch and port, host events by host IP. Host events have
// no port, so every host used to share the key ":0" (F56) and the host_up of
// one host closed the host_down of another.
func collectOpenEventKey(evt NetworkEvent) string {
	switch evt.Type {
	case "port_down", "port_up":
		return fmt.Sprintf("port|%s|%d", evt.SwitchIP, evt.Port)
	}
	return "host|" + evt.IP
}

// GetNetworkEvents returns a copy of the event log (thread-safe)
func GetNetworkEvents() []NetworkEvent {
	networkEventLogMutex.RLock()
	defer networkEventLogMutex.RUnlock()

	result := make([]NetworkEvent, len(networkEventLog))
	copy(result, networkEventLog)
	return result
}

// CreateSnapshot builds a NetworkSnapshot from current collected data, graph, and analysis report
func CreateSnapshot(devices []*DeviceData, graph *DJGraph, report *Report) *NetworkSnapshot {
	snapshot := &NetworkSnapshot{
		Timestamp:   time.Now(),
		ActiveMACs:  make(map[string]MACInfo),
		ActiveHosts: make(map[string]HostInfo),
		Anomalies:   make(map[string][]string),
		Ports:       make(map[string]map[int]int),
	}

	// Devices in IP order, so the result does not depend on the caller's
	// (map) order.
	devices = slices.Clone(devices)
	slices.SortStableFunc(devices, func(a, b *DeviceData) int { return compareIPs(a.IP, b.IP) })

	// The host each suggestion is about ("" when it matches no switch)
	var suggestionHosts []string
	if report != nil {
		suggestionHosts = collectSuggestionHosts(devices, report.Suggestions)
	}

	// Where each MAC was learned; a MAC seen on several switches gets one
	// place (F54)
	sightings := make(map[string]collectMACSighting)

	// Populate ActiveHosts from devices
	for _, dev := range devices {
		vendor := getMACVendor(dev.ChassisID)

		// Calculate per-device health from report
		deviceHealth := 100
		if report != nil {
			for i, sugg := range report.Suggestions {
				if suggestionHosts[i] == dev.IP {
					switch sugg.Type {
					case "shadow_it":
						deviceHealth -= 10
					case "loopback":
						deviceHealth -= 20
					case "stp":
						deviceHealth -= 15
					case "congestion":
						if sugg.Severity == "high" {
							deviceHealth -= 5
						} else {
							deviceHealth -= 2
						}
					case "stability":
						deviceHealth -= 3
					case "physical":
						deviceHealth -= 2
					case "path":
						deviceHealth -= 2
					}
				}
			}
			if deviceHealth < 0 {
				deviceHealth = 0
			}
		}

		snapshot.ActiveHosts[dev.IP] = HostInfo{
			SysName:     dev.SysName,
			Vendor:      vendor,
			Health:      deviceHealth,
			Unreachable: dev.Unreachable, // Phase 8
		}

		// Phase 8: Capture port IfOperStatus for port change detection
		portMap := make(map[int]int)
		for _, iface := range dev.Interfaces {
			if iface.IfOperStatus > 0 {
				portMap[iface.IfIndex] = iface.IfOperStatus
			}
		}
		if len(portMap) > 0 {
			snapshot.Ports[dev.IP] = portMap
		}

		// Record where this device's FDB learned each MAC
		collectSightMACs(sightings, dev)
	}

	// Populate ActiveMACs: switch and port of the chosen sighting (the port
	// as ifIndex, like the port events, F60)
	for mac, seen := range sightings {
		snapshot.ActiveMACs[mac] = MACInfo{
			SwitchIP: seen.dev.IP,
			Port:     collectFDBIfIndex(seen.dev, seen.port),
			Vendor:   getMACVendor(mac),
		}
	}

	// Resolve IPs from the global ARP table (one read lock)
	globalMACtoIPMutex.RLock()
	for mac, info := range snapshot.ActiveMACs {
		if ip := globalMACtoIP[mac]; ip != "" {
			info.IP = ip
			snapshot.ActiveMACs[mac] = info
		}
	}
	globalMACtoIPMutex.RUnlock()

	// Populate Anomalies from report
	if report != nil {
		for i, sugg := range report.Suggestions {
			if host := suggestionHosts[i]; host != "" {
				snapshot.Anomalies[host] = append(snapshot.Anomalies[host], sugg.Type)
			}
		}
	}

	// Set graph stats
	if graph != nil {
		snapshot.GraphNodes = len(graph.Nodes)
		snapshot.GraphEdges = countEdges(graph)
	}

	// Set health score from report
	if report != nil {
		snapshot.HealthScore = report.HealthScore
	}

	return snapshot
}

// collectMACSighting is where a snapshot MAC was learned: a switch, its
// bridge port and how many usable MACs that port has.
type collectMACSighting struct {
	dev      *DeviceData
	port     int
	portMACs int
}

// collectSightMACs records the usable MACs of dev's FDB (Q11: no null,
// broadcast, multicast or zero-OUI MACs, no malformed ones) in sightings,
// keeping for each MAC the better of its sightings so far.
func collectSightMACs(sightings map[string]collectMACSighting, dev *DeviceData) {
	macs := make([]string, len(dev.MACTable))
	perPort := make(map[int]int)
	for i, entry := range dev.MACTable {
		if mac := collectCanonicalMAC(entry.MACAddress); mac != "" && collectUsableMAC(mac) {
			macs[i] = mac
			perPort[entry.PortNumber]++
		}
	}
	for i, entry := range dev.MACTable {
		if macs[i] == "" {
			continue
		}
		seen := collectMACSighting{dev: dev, port: entry.PortNumber, portMACs: perPort[entry.PortNumber]}
		if prev, ok := sightings[macs[i]]; !ok || collectBetterSighting(seen, prev) {
			sightings[macs[i]] = seen
		}
	}
}

// collectBetterSighting reports whether a beats b as the place of a MAC:
// a reachable switch first, then the port with fewer MACs (the access port
// rather than the uplinks that also learn the MAC). On a tie the earlier
// sighting (lower switch IP) stays.
func collectBetterSighting(a, b collectMACSighting) bool {
	if a.dev.Unreachable != b.dev.Unreachable {
		return !a.dev.Unreachable
	}
	return a.portMACs < b.portMACs
}

// collectNetworkAnomalies are the suggestion types about the whole network.
// The analyzer reports one stp suggestion ("N root bridges not on the core")
// and names one of the roots, picked by map order (F18), as its device, so
// stp is kept under collectNetworkHost: it is new or fixed as a whole and the
// snapshot does not change with the root the analyzer happened to name.
var collectNetworkAnomalies = map[string]bool{"stp": true}

// collectNetworkHost is the snapshot host of whole-network anomalies (the
// events read "Anomaly: stp on network").
const collectNetworkHost = "network"

// collectSuggestionHosts returns, for each suggestion, the snapshot host it
// is about, or "" when it matches no polled switch (F55: only Device ==
// switch IP matched, so stp and path never did). Most suggestions name the
// switch IP; path names a graph label "SysName (node id)", whose SysName part
// is the node label and holds the switch IP; a switch can also be named by
// its graph node id or chassis MAC. stp goes to collectNetworkHost.
func collectSuggestionHosts(devices []*DeviceData, suggestions []OptimizationSuggestion) []string {
	byKey := make(map[string]string) // switch IP, graph node id, chassis MAC → switch IP
	for _, d := range devices {
		byKey[d.IP] = d.IP
	}
	addKey := func(key, ip string) {
		if _, taken := byKey[key]; key != "" && !taken {
			byKey[key] = ip
		}
	}
	for _, d := range devices {
		nodeID := normalizeID(d.ChassisID, 0)
		if nodeID == "" {
			nodeID = d.IP
		}
		addKey(nodeID, d.IP)
		addKey(collectCanonicalMAC(d.ChassisID), d.IP)
	}

	lookup := func(word string) (string, bool) {
		if host, ok := byKey[word]; ok {
			return host, true
		}
		host, ok := byKey[collectCanonicalMAC(word)]
		return host, ok
	}
	hosts := make([]string, len(suggestions))
	for i, sugg := range suggestions {
		if collectNetworkAnomalies[sugg.Type] {
			hosts[i] = collectNetworkHost
			continue
		}
		if host, ok := lookup(sugg.Device); ok {
			hosts[i] = host
			continue
		}
		words := strings.FieldsFunc(sugg.Device, func(r rune) bool { return unicode.IsSpace(r) || strings.ContainsRune("(),", r) })
		for _, word := range words {
			if host, ok := lookup(word); ok {
				hosts[i] = host
				break
			}
		}
	}
	return hosts
}

// collectAnomalySet keys a snapshot's anomalies "host|type" for the diff.
func collectAnomalySet(anomalies map[string][]string) map[string]AnomalyDiff {
	set := make(map[string]AnomalyDiff)
	for host, types := range anomalies {
		for _, t := range types {
			set[host+"|"+t] = AnomalyDiff{DeviceIP: host, AnomalyType: t}
		}
	}
	return set
}

// CompareSnapshots compares two snapshots and returns their differences
func CompareSnapshots(prev, curr *NetworkSnapshot) *SnapshotDiff {
	diff := &SnapshotDiff{
		Timestamp:     curr.Timestamp,
		HealthDelta:   curr.HealthScore - prev.HealthScore,
		MACCountDelta: len(curr.ActiveMACs) - len(prev.ActiveMACs),
	}

	// --- MAC JOIN/LEAVE ---
	// JOINed: in current but NOT in previous
	for mac, info := range curr.ActiveMACs {
		if _, existed := prev.ActiveMACs[mac]; !existed {
			diff.JoinedMACs = append(diff.JoinedMACs, MACDiffEntry{
				MAC:      mac,
				IP:       info.IP,
				SwitchIP: info.SwitchIP,
				Port:     info.Port,
				Vendor:   info.Vendor,
			})
		}
	}

	// LEFT: in previous but NOT in current
	for mac, info := range prev.ActiveMACs {
		if _, exists := curr.ActiveMACs[mac]; !exists {
			diff.LeftMACs = append(diff.LeftMACs, MACDiffEntry{
				MAC:      mac,
				IP:       info.IP,
				SwitchIP: info.SwitchIP,
				Port:     info.Port,
				Vendor:   info.Vendor,
			})
		}
	}

	// --- Host JOIN/LEAVE ---
	// New hosts: in current but not in previous
	for ip := range curr.ActiveHosts {
		if _, existed := prev.ActiveHosts[ip]; !existed {
			diff.NewHosts = append(diff.NewHosts, ip)
		}
	}

	// Lost hosts: in previous but not in current
	for ip := range prev.ActiveHosts {
		if _, exists := curr.ActiveHosts[ip]; !exists {
			diff.LostHosts = append(diff.LostHosts, ip)
		}
	}

	// --- Anomaly changes ---
	// Sets of "ip|type" (whole-network types such as stp are on "network")
	prevAnomalySet := collectAnomalySet(prev.Anomalies)
	currAnomalySet := collectAnomalySet(curr.Anomalies)

	// New anomalies: in current but not in previous
	for _, key := range slices.Sorted(maps.Keys(currAnomalySet)) {
		if _, existed := prevAnomalySet[key]; !existed {
			diff.NewAnomalies = append(diff.NewAnomalies, currAnomalySet[key])
		}
	}

	// Fixed anomalies: in previous but not in current
	for _, key := range slices.Sorted(maps.Keys(prevAnomalySet)) {
		if _, exists := currAnomalySet[key]; !exists {
			diff.FixedAnomalies = append(diff.FixedAnomalies, prevAnomalySet[key])
		}
	}
	// --- Phase 8: Unreachable / Restored hosts ---
	for ip, currHost := range curr.ActiveHosts {
		if prevHost, existed := prev.ActiveHosts[ip]; existed {
			// Was reachable, now unreachable
			if !prevHost.Unreachable && currHost.Unreachable {
				diff.UnreachableHosts = append(diff.UnreachableHosts, ip)
			}
			// Was unreachable, now restored
			if prevHost.Unreachable && !currHost.Unreachable {
				diff.RestoredHosts = append(diff.RestoredHosts, ip)
			}
		}
	}

	// --- Phase 8: Port Status Changes (Up↔Down) ---
	for switchIP, currPorts := range curr.Ports {
		prevPorts, hasPrev := prev.Ports[switchIP]
		if !hasPrev {
			continue
		}
		for portIdx, currStatus := range currPorts {
			prevStatus, hadPort := prevPorts[portIdx]
			if !hadPort {
				continue
			}
			// Detect 1→2 (up→down) or 2→1 (down→up)
			if (prevStatus == 1 && currStatus == 2) || (prevStatus == 2 && currStatus == 1) {
				diff.PortStatusChanges = append(diff.PortStatusChanges, PortStatusChange{
					SwitchIP:  switchIP,
					PortIndex: portIdx,
					OldStatus: prevStatus,
					NewStatus: currStatus,
				})
			}
		}
	}

	// Map order must not decide the event order (Q16)
	byMAC := func(a, b MACDiffEntry) int { return strings.Compare(a.MAC, b.MAC) }
	slices.SortFunc(diff.JoinedMACs, byMAC)
	slices.SortFunc(diff.LeftMACs, byMAC)
	for _, hosts := range [][]string{diff.NewHosts, diff.LostHosts, diff.UnreachableHosts, diff.RestoredHosts} {
		slices.SortFunc(hosts, compareIPs)
	}
	slices.SortFunc(diff.PortStatusChanges, func(a, b PortStatusChange) int {
		return cmp.Or(compareIPs(a.SwitchIP, b.SwitchIP), cmp.Compare(a.PortIndex, b.PortIndex))
	})

	return diff
}

// LogChanges prints a human-readable summary of the snapshot diff to the console
// and records events to the global network event log for UI consumption
func (diff *SnapshotDiff) LogChanges() {
	if len(diff.JoinedMACs) == 0 && len(diff.LeftMACs) == 0 &&
		len(diff.NewHosts) == 0 && len(diff.LostHosts) == 0 &&
		len(diff.UnreachableHosts) == 0 && len(diff.RestoredHosts) == 0 &&
		len(diff.PortStatusChanges) == 0 &&
		len(diff.NewAnomalies) == 0 && len(diff.FixedAnomalies) == 0 {
		fmt.Printf("📸 Snapshot diff: no changes (MACs: %+d, Health: %+d)\n",
			diff.MACCountDelta, diff.HealthDelta)
		return
	}

	now := diff.Timestamp.Format("15:04:05")

	fmt.Println("\n" + strings.Repeat("─", 50))
	fmt.Printf("🔄 SNAPSHOT DIFF at %s\n", now)
	fmt.Println(strings.Repeat("─", 50))

	// MAC changes (limit output to first 10)
	if len(diff.JoinedMACs) > 0 {
		fmt.Printf("🟢 +%d MAC(s) joined:\n", len(diff.JoinedMACs))
		limit := len(diff.JoinedMACs)
		if limit > 10 {
			limit = 10
		}
		for _, m := range diff.JoinedMACs[:limit] {
			label := m.MAC
			if m.Vendor != "" {
				label = fmt.Sprintf("%s (%s)", m.MAC, m.Vendor)
			}
			if m.IP != "" {
				label = fmt.Sprintf("%s → %s", label, m.IP)
			}
			fmt.Printf("   %s on %s port %d\n", label, m.SwitchIP, m.Port)
		}
		if len(diff.JoinedMACs) > 10 {
			fmt.Printf("   ... va yana %d ta\n", len(diff.JoinedMACs)-10)
		}
		// Record events
		for _, m := range diff.JoinedMACs {
			msg := m.MAC
			if m.Vendor != "" {
				msg = fmt.Sprintf("%s (%s)", msg, m.Vendor)
			}
			if m.IP != "" {
				msg = fmt.Sprintf("%s → %s", msg, m.IP)
			}
			msg = fmt.Sprintf("%s on %s:%d", msg, m.SwitchIP, m.Port)
			AddNetworkEvent(NetworkEvent{
				Time: now, Type: "join", MAC: m.MAC, IP: m.IP,
				Vendor: m.Vendor, SwitchIP: m.SwitchIP, Port: m.Port,
				Message: msg,
			})
		}
	}

	if len(diff.LeftMACs) > 0 {
		fmt.Printf("🔴 -%d MAC(s) left:\n", len(diff.LeftMACs))
		limit := len(diff.LeftMACs)
		if limit > 10 {
			limit = 10
		}
		for _, m := range diff.LeftMACs[:limit] {
			label := m.MAC
			if m.Vendor != "" {
				label = fmt.Sprintf("%s (%s)", m.MAC, m.Vendor)
			}
			if m.IP != "" {
				label = fmt.Sprintf("%s → %s", label, m.IP)
			}
			fmt.Printf("   %s from %s port %d\n", label, m.SwitchIP, m.Port)
		}
		if len(diff.LeftMACs) > 10 {
			fmt.Printf("   ... va yana %d ta\n", len(diff.LeftMACs)-10)
		}
		// Record events
		for _, m := range diff.LeftMACs {
			msg := m.MAC
			if m.Vendor != "" {
				msg = fmt.Sprintf("%s (%s)", msg, m.Vendor)
			}
			if m.IP != "" {
				msg = fmt.Sprintf("%s → %s", msg, m.IP)
			}
			msg = fmt.Sprintf("%s from %s:%d", msg, m.SwitchIP, m.Port)
			AddNetworkEvent(NetworkEvent{
				Time: now, Type: "leave", MAC: m.MAC, IP: m.IP,
				Vendor: m.Vendor, SwitchIP: m.SwitchIP, Port: m.Port,
				Message: msg,
			})
		}
	}

	// Host changes
	if len(diff.NewHosts) > 0 {
		fmt.Printf("🆕 +%d new SNMP host(s): %s\n", len(diff.NewHosts), strings.Join(diff.NewHosts, ", "))
		for _, ip := range diff.NewHosts {
			AddNetworkEvent(NetworkEvent{
				Time: now, Type: "host_up", IP: ip,
				Message: fmt.Sprintf("SNMP host up: %s", ip),
			})
		}
	}
	if len(diff.LostHosts) > 0 {
		fmt.Printf("❌ -%d lost SNMP host(s): %s\n", len(diff.LostHosts), strings.Join(diff.LostHosts, ", "))
		for _, ip := range diff.LostHosts {
			AddNetworkEvent(NetworkEvent{
				Time: now, Type: "host_down", IP: ip,
				Message: fmt.Sprintf("SNMP host down: %s", ip),
			})
		}
	}

	// Anomaly changes
	if len(diff.NewAnomalies) > 0 {
		fmt.Printf("⚠️ +%d new anomaly(ies):\n", len(diff.NewAnomalies))
		for _, a := range diff.NewAnomalies {
			fmt.Printf("   %s — %s\n", a.DeviceIP, a.AnomalyType)
			AddNetworkEvent(NetworkEvent{
				Time: now, Type: "anomaly", IP: a.DeviceIP,
				Message: fmt.Sprintf("Anomaly: %s on %s", a.AnomalyType, a.DeviceIP),
			})
		}
	}
	if len(diff.FixedAnomalies) > 0 {
		fmt.Printf("✅ -%d fixed anomaly(ies):\n", len(diff.FixedAnomalies))
		for _, a := range diff.FixedAnomalies {
			fmt.Printf("   %s — %s\n", a.DeviceIP, a.AnomalyType)
			AddNetworkEvent(NetworkEvent{
				Time: now, Type: "fixed", IP: a.DeviceIP,
				Message: fmt.Sprintf("Fixed: %s on %s", a.AnomalyType, a.DeviceIP),
			})
		}
	}

	// Phase 8: Unreachable hosts
	if len(diff.UnreachableHosts) > 0 {
		fmt.Printf("❌ %d switch(es) became UNREACHABLE:\n", len(diff.UnreachableHosts))
		for _, ip := range diff.UnreachableHosts {
			fmt.Printf("   🔴 %s\n", ip)
			AddNetworkEvent(NetworkEvent{
				Time: now, Type: "host_down", IP: ip,
				Message: fmt.Sprintf("Switch UNREACHABLE: %s", ip),
			})
		}
	}

	// Phase 8: Restored hosts
	if len(diff.RestoredHosts) > 0 {
		fmt.Printf("🟢 %d switch(es) RESTORED:\n", len(diff.RestoredHosts))
		for _, ip := range diff.RestoredHosts {
			fmt.Printf("   ✅ %s\n", ip)
			AddNetworkEvent(NetworkEvent{
				Time: now, Type: "host_up", IP: ip,
				Message: fmt.Sprintf("Switch RESTORED: %s", ip),
			})
		}
	}

	// Phase 8: Port status changes
	if len(diff.PortStatusChanges) > 0 {
		fmt.Printf("🔌 %d port status change(s):\n", len(diff.PortStatusChanges))
		for _, p := range diff.PortStatusChanges {
		statusLabel := "DOWN"
			eventType := "port_down"
			icon := "🔴"
			if p.NewStatus == 1 {
				statusLabel = "UP"
				eventType = "port_up"
				icon = "🟢"
			}
			fmt.Printf("   %s %s port %d → %s\n", icon, p.SwitchIP, p.PortIndex, statusLabel)
			AddNetworkEvent(NetworkEvent{
				Time: now, Type: eventType, SwitchIP: p.SwitchIP,
				Port: p.PortIndex,
				Message: fmt.Sprintf("Port %s: %s port %d", statusLabel, p.SwitchIP, p.PortIndex),
			})
		}
	}

	// Summary
	fmt.Printf("📊 Health: %+d | MACs: %+d\n", diff.HealthDelta, diff.MACCountDelta)
	fmt.Println(strings.Repeat("─", 50))
}
