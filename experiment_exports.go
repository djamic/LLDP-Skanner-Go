package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// exportsDir is the directory the experiment JSON exports are written to.
// Tests point it at a temporary directory.
var exportsDir = "results"

// ============================================================
// A.3 — Individual HealthScore Export
// ============================================================

// DeviceHealthExport holds per-device health information
type DeviceHealthExport struct {
	IP        string   `json:"ip"`
	SysName   string   `json:"sys_name"`
	Vendor    string   `json:"vendor"`
	Health    int      `json:"health_score"`
	Anomalies []string `json:"anomalies"`
	PortCount int      `json:"port_count"`
	MACCount  int      `json:"mac_count"`
}

// HealthScoreExport holds the complete health export data
type HealthScoreExport struct {
	ExportTime      string               `json:"export_time"`
	Devices         []DeviceHealthExport  `json:"devices"`
	AverageHealth   float64              `json:"average_health"`
	MinHealth       int                  `json:"min_health"`
	MaxHealth       int                  `json:"max_health"`
	TotalAnomalies  int                  `json:"total_anomalies"`
	TotalDevices    int                  `json:"total_devices"`
}

// ExportHealthScores generates per-device health scores and saves to JSON
func ExportHealthScores(devices []*DeviceData, graph *DJGraph) {
	if len(devices) == 0 {
		return
	}

	// Build FullCaptureData for analyzer
	var devicesValue []DeviceData
	for _, d := range devices {
		devicesValue = append(devicesValue, *d)
	}

	var graphData GraphData
	if graph != nil {
		graphData = graph.GetGraphData()
	}

	fullData := FullCaptureData{
		Session:     CaptureSession{ID: "health-export", Name: "Health Export", StartTime: time.Now()},
		DevicesData: devicesValue,
		Topology:    graphData,
	}

	analyzer := NewAnalyzer(fullData)
	report := analyzer.Analyze()

	// Build anomaly map: device IP -> list of anomaly types
	anomalyMap := make(map[string][]string)
	for _, sugg := range report.Suggestions {
		anomalyMap[sugg.Device] = append(anomalyMap[sugg.Device], sugg.Type)
	}

	// Build per-device health export
	var deviceExports []DeviceHealthExport
	totalAnomalies := 0
	minHealth := 100
	maxHealth := 0
	totalHealth := 0

	for _, d := range devices {
		vendor := getMACVendor(d.ChassisID)
		if vendor == "" && d.SysName != "" {
			// Try to infer vendor from sysName
			nameLower := strings.ToLower(d.SysName)
			switch {
			case strings.Contains(nameLower, "snr"):
				vendor = "SNR"
			case strings.Contains(nameLower, "mikrotik"):
				vendor = "MikroTik"
			case strings.Contains(nameLower, "cisco"):
				vendor = "Cisco"
			case strings.Contains(nameLower, "hpe") || strings.Contains(nameLower, "hp"):
				vendor = "HPE"
			case strings.Contains(nameLower, "ubiquiti") || strings.Contains(nameLower, "ubnt"):
				vendor = "Ubiquiti"
			case strings.Contains(nameLower, "huawei"):
				vendor = "Huawei"
			}
		}

		anomalies := anomalyMap[d.IP]
		anomalyCount := len(anomalies)
		totalAnomalies += anomalyCount

		// Simple per-device health: 100 - (anomalies * 10)
		health := 100 - (anomalyCount * 10)
		if health < 0 {
			health = 0
		}
		totalHealth += health
		if health < minHealth {
			minHealth = health
		}
		if health > maxHealth {
			maxHealth = health
		}

		deviceExports = append(deviceExports, DeviceHealthExport{
			IP:        d.IP,
			SysName:   d.SysName,
			Vendor:    vendor,
			Health:    health,
			Anomalies: anomalies,
			PortCount: len(d.Interfaces),
			MACCount:  len(d.MACTable),
		})
	}

	avgHealth := float64(totalHealth) / float64(len(devices))
	if len(devices) == 0 {
		avgHealth = 0
		minHealth = 0
	}

	export := HealthScoreExport{
		ExportTime:     time.Now().Format("2006-01-02 15:04:05"),
		Devices:        deviceExports,
		AverageHealth:  avgHealth,
		MinHealth:      minHealth,
		MaxHealth:      maxHealth,
		TotalAnomalies: totalAnomalies,
		TotalDevices:   len(devices),
	}

	os.MkdirAll(exportsDir, 0755)
	jsonData, _ := json.MarshalIndent(export, "", "  ")
	os.WriteFile(filepath.Join(exportsDir, "health_scores.json"), jsonData, 0644)
	fmt.Println("✅ Health scores saqlandi: results/health_scores.json")
}

// ============================================================
// A.4 — BFS Depth Export
// ============================================================

// BFSDepthExport holds BFS analysis results
type BFSDepthExport struct {
	ExportTime       string            `json:"export_time"`
	CoreSwitchIP     string            `json:"core_switch_ip"`
	DepthDistribution map[int]int      `json:"depth_distribution"`
	MaxDepth         int               `json:"max_depth"`
	AverageDepth     float64           `json:"average_depth"`
	DeepDevices      []DeepDeviceInfo  `json:"deep_devices"`
	TotalNodes       int               `json:"total_nodes"`
}

// DeepDeviceInfo holds info about devices with depth > 3
type DeepDeviceInfo struct {
	NodeID string `json:"node_id"`
	Depth  int    `json:"depth"`
	Info   string `json:"info"`
}

// ExportBFSDepths runs BFS from core and exports depth data
func ExportBFSDepths(graph *DJGraph) {
	if graph == nil || len(graph.Nodes) == 0 {
		return
	}

	// Find core switch - try multiple strategies
	coreID := gatewayIP
	if !graph.Nodes[coreID] {
		// Strategy 1: Search SwitchInfo for node containing gateway IP
		for nodeID, info := range graph.SwitchInfo {
			if strings.Contains(info, gatewayIP) {
				coreID = nodeID
				break
			}
		}
	}
	if !graph.Nodes[coreID] {
		// Strategy 1.5: Resolve gateway IP → ChassisID via collectedData
		collectedDataMutex.RLock()
		if devData, ok := collectedData[gatewayIP]; ok && devData.ChassisID != "" {
			resolved := normalizeID(devData.ChassisID, 0)
			if graph.Nodes[resolved] {
				coreID = resolved
			}
		}
		collectedDataMutex.RUnlock()
	}
	if !graph.Nodes[coreID] {
		// Strategy 2: Find node with most edges (likely core switch)
		maxEdges := 0
		for nodeID := range graph.Nodes {
			// Count both outgoing and incoming edges
			edgeCount := len(graph.Edges[nodeID])
			for _, targets := range graph.Edges {
				if _, ok := targets[nodeID]; ok {
					edgeCount++
				}
			}
			if edgeCount > maxEdges {
				maxEdges = edgeCount
				coreID = nodeID
			}
		}
	}

	depths := graph.CalculateDepths(coreID)

	// Build depth distribution
	distribution := make(map[int]int)
	maxDepth := 0
	totalDepth := 0
	var deepDevices []DeepDeviceInfo

	for nodeID, depth := range depths {
		distribution[depth]++
		totalDepth += depth
		if depth > maxDepth {
			maxDepth = depth
		}
		if depth > 3 {
			info := ""
			if val, ok := graph.SwitchInfo[nodeID]; ok {
				info = val
			}
			deepDevices = append(deepDevices, DeepDeviceInfo{
				NodeID: nodeID,
				Depth:  depth,
				Info:   info,
			})
		}
	}

	avgDepth := 0.0
	if len(depths) > 0 {
		avgDepth = float64(totalDepth) / float64(len(depths))
	}

	export := BFSDepthExport{
		ExportTime:        time.Now().Format("2006-01-02 15:04:05"),
		CoreSwitchIP:      coreID,
		DepthDistribution: distribution,
		MaxDepth:          maxDepth,
		AverageDepth:      avgDepth,
		DeepDevices:       deepDevices,
		TotalNodes:        len(depths),
	}

	os.MkdirAll(exportsDir, 0755)
	jsonData, _ := json.MarshalIndent(export, "", "  ")
	os.WriteFile(filepath.Join(exportsDir, "bfs_depths.json"), jsonData, 0644)
	fmt.Println("✅ BFS depth ma'lumotlari saqlandi: results/bfs_depths.json")
}

// ============================================================
// A.6 — Vendor Statistics Export
// ============================================================

// VendorStat holds per-vendor statistics
type VendorStat struct {
	Vendor       string `json:"vendor"`
	DeviceCount  int    `json:"device_count"`
	SNMPSuccess  int    `json:"snmp_success"`
	SNMPFailure  int    `json:"snmp_failure"`
	LLDPSuccess  int    `json:"lldp_success"`
	LLDPFailure  int    `json:"lldp_failure"`
	FDBSuccess   int    `json:"fdb_success"`
	FDBFailure   int    `json:"fdb_failure"`
}

// VendorStatsExport holds the complete vendor statistics
type VendorStatsExport struct {
	ExportTime string       `json:"export_time"`
	Vendors    []VendorStat `json:"vendors"`
	TotalVendors int        `json:"total_vendors"`
}

// ExportVendorStats generates vendor-level statistics from devices
func ExportVendorStats(devices []*DeviceData) {
	if len(devices) == 0 {
		return
	}

	vendorMap := make(map[string]*VendorStat)

	for _, d := range devices {
		vendor := getMACVendor(d.ChassisID)
		if vendor == "" {
			// Try to infer from sysName
			nameLower := strings.ToLower(d.SysName)
			switch {
			case strings.Contains(nameLower, "snr"):
				vendor = "SNR"
			case strings.Contains(nameLower, "mikrotik"):
				vendor = "MikroTik"
			case strings.Contains(nameLower, "cisco"):
				vendor = "Cisco"
			case strings.Contains(nameLower, "hpe") || strings.Contains(nameLower, "hp"):
				vendor = "HPE"
			case strings.Contains(nameLower, "ubiquiti") || strings.Contains(nameLower, "ubnt"):
				vendor = "Ubiquiti"
			case strings.Contains(nameLower, "huawei"):
				vendor = "Huawei"
			case strings.Contains(nameLower, "fortinet") || strings.Contains(nameLower, "fortigate"):
				vendor = "Fortinet"
			default:
				vendor = "Unknown"
			}
		}

		if _, exists := vendorMap[vendor]; !exists {
			vendorMap[vendor] = &VendorStat{Vendor: vendor}
		}
		vs := vendorMap[vendor]
		vs.DeviceCount++

		// SNMP: if we have data, it was successful
		vs.SNMPSuccess++

		// LLDP: check if neighbors were collected
		if len(d.Neighbors) > 0 {
			vs.LLDPSuccess++
		} else {
			vs.LLDPFailure++
		}

		// FDB: check if MAC table was collected
		if len(d.MACTable) > 0 {
			vs.FDBSuccess++
		} else {
			vs.FDBFailure++
		}
	}

	// Convert map to slice
	var vendors []VendorStat
	for _, v := range vendorMap {
		vendors = append(vendors, *v)
	}

	export := VendorStatsExport{
		ExportTime:   time.Now().Format("2006-01-02 15:04:05"),
		Vendors:      vendors,
		TotalVendors: len(vendors),
	}

	os.MkdirAll(exportsDir, 0755)
	jsonData, _ := json.MarshalIndent(export, "", "  ")
	os.WriteFile(filepath.Join(exportsDir, "vendor_stats.json"), jsonData, 0644)
	fmt.Println("✅ Vendor statistikasi saqlandi: results/vendor_stats.json")
}

// ============================================================
// A.5 — Telegram Timing Export
// ============================================================

// TelegramTimingEntry holds timing for one notification
type TelegramTimingEntry struct {
	IssueID    string `json:"issue_id"`
	IssueType  string `json:"issue_type"`
	DetectTime string `json:"detect_time"`
	NotifyTime string `json:"notify_time"`
	LatencyMs  int64  `json:"latency_ms"`
}

// TelegramTimingExport holds all timing entries
type TelegramTimingExport struct {
	ExportTime     string                `json:"export_time"`
	Entries        []TelegramTimingEntry `json:"entries"`
	AverageLatency float64               `json:"average_latency_ms"`
	MaxLatency     int64                 `json:"max_latency_ms"`
	TotalMessages  int                   `json:"total_messages"`
}

var (
	telegramTimings      []TelegramTimingEntry
	telegramTimingsMutex sync.Mutex
)

// AddTelegramTiming records a telegram notification timing
func AddTelegramTiming(issueID, issueType string, detectTime, notifyTime time.Time) {
	telegramTimingsMutex.Lock()
	defer telegramTimingsMutex.Unlock()

	latency := notifyTime.Sub(detectTime).Milliseconds()
	telegramTimings = append(telegramTimings, TelegramTimingEntry{
		IssueID:    issueID,
		IssueType:  issueType,
		DetectTime: detectTime.Format("15:04:05.000"),
		NotifyTime: notifyTime.Format("15:04:05.000"),
		LatencyMs:  latency,
	})
}

// ExportTelegramTiming saves all telegram timing data to JSON
func ExportTelegramTiming() {
	telegramTimingsMutex.Lock()
	entries := make([]TelegramTimingEntry, len(telegramTimings))
	copy(entries, telegramTimings)
	telegramTimingsMutex.Unlock()

	if len(entries) == 0 {
		// Write empty file anyway
		export := TelegramTimingExport{
			ExportTime:     time.Now().Format("2006-01-02 15:04:05"),
			Entries:        []TelegramTimingEntry{},
			AverageLatency: 0,
			MaxLatency:     0,
			TotalMessages:  0,
		}
		os.MkdirAll(exportsDir, 0755)
		jsonData, _ := json.MarshalIndent(export, "", "  ")
		os.WriteFile(filepath.Join(exportsDir, "telegram_timing.json"), jsonData, 0644)
		fmt.Println("✅ Telegram timing saqlandi: results/telegram_timing.json (bo'sh)")
		return
	}

	var totalLatency int64
	var maxLatency int64
	for _, e := range entries {
		totalLatency += e.LatencyMs
		if e.LatencyMs > maxLatency {
			maxLatency = e.LatencyMs
		}
	}

	export := TelegramTimingExport{
		ExportTime:     time.Now().Format("2006-01-02 15:04:05"),
		Entries:        entries,
		AverageLatency: float64(totalLatency) / float64(len(entries)),
		MaxLatency:     maxLatency,
		TotalMessages:  len(entries),
	}

	os.MkdirAll(exportsDir, 0755)
	jsonData, _ := json.MarshalIndent(export, "", "  ")
	os.WriteFile(filepath.Join(exportsDir, "telegram_timing.json"), jsonData, 0644)
	fmt.Printf("✅ Telegram timing saqlandi: results/telegram_timing.json (%d ta xabar)\n", len(entries))
}

// ============================================================
// A.2 — Benchmark Mode
// ============================================================

// BenchmarkResult holds one benchmark run result
type BenchmarkResult struct {
	Workers      int     `json:"workers"`
	Duration     string  `json:"duration"`
	DurationSec  float64 `json:"duration_sec"`
	DevicesFound int     `json:"devices_found"`
	SNMPSuccess  int32   `json:"snmp_success"`
	SNMPFailure  int32   `json:"snmp_failure"`
}

// BenchmarkExport holds all benchmark results
type BenchmarkExport struct {
	ExportTime string            `json:"export_time"`
	Results    []BenchmarkResult `json:"results"`
}

// ExportBenchmarkResults saves benchmark results to JSON
func ExportBenchmarkResults(results []BenchmarkResult) {
	export := BenchmarkExport{
		ExportTime: time.Now().Format("2006-01-02 15:04:05"),
		Results:    results,
	}

	os.MkdirAll(exportsDir, 0755)
	jsonData, _ := json.MarshalIndent(export, "", "  ")
	os.WriteFile(filepath.Join(exportsDir, "benchmark_results.json"), jsonData, 0644)
	fmt.Println("✅ Benchmark natijalari saqlandi: results/benchmark_results.json")
}
