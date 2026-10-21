package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

var (
	// Global stats
	hostsFound    int32
	snmpSuccess   int32
	snmpFailure   int32
	dataCollected int32

	// Experiment timing
	experimentScanStart       time.Time
	experimentScanEnd         time.Time
	experimentCollectionEnd   time.Time
	dataCollectionWG          sync.WaitGroup

	// Data storage
	collectedData      = make(map[string]*DeviceData)
	collectedDataMutex sync.RWMutex // Mutex for map access

	// Gateway Configuration (loaded from 'gateway_ip' file at startup)
	gatewayIP = ""

	// Global MAC to IP lookup (from gateway ARP table)
	globalMACtoIP      = make(map[string]string)
	globalMACtoIPMutex sync.RWMutex

	// Pre-compiled regex for normalizePortName — compiled ONCE at startup
	// instead of on every call (was major CPU bottleneck with thousands of calls).
	rePortMACPrefix = regexp.MustCompile(`^([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}[:\-]`)
)

// InterfaceTraffic tracks traffic counters for speed calculation
type InterfaceTraffic struct {
	LastInOctets  uint64
	LastOutOctets uint64
	LastPollTime  time.Time
	InSpeed       uint64 // bits per second
	OutSpeed      uint64 // bits per second
}

var (
	// Traffic tracking: [deviceIP][ifIndex] -> traffic data
	interfaceTrafficMap      = make(map[string]map[int]*InterfaceTraffic)
	interfaceTrafficMapMutex sync.RWMutex

	// Debug Logging
	connectionLogFile *os.File
	connLogger        *log.Logger

	// CLI Flags (G.1)
	modeFlag      *string
	workersFlag   *int
	expIDFlag     *string
	durationFlag  *string
	outputFlag    *string
	networksFlag  *string
	communityFlag *string

	// Backward compatibility
	legacyExperiment *bool
	legacyBenchmark  *bool
	legacyTest       *bool
)

func initDebugLog() {
	var err error
	connectionLogFile, err = os.OpenFile("debug_edges_analysis.log", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0666)
	if err != nil {
		fmt.Printf("Failed to open debug log: %v\n", err)
		return
	}
	// Use io.MultiWriter to write to both file and stdout only if needed, currently just file to keep clean
	connLogger = log.New(connectionLogFile, "", log.Ltime|log.Lmicroseconds)
}

func logDebug(format string, v ...interface{}) {
	if connLogger != nil {
		connLogger.Printf(format, v...)
	}
}

func main() {
	// Ignore SIGPIPE — prevents crash when child process (snmpwalk/ping) pipe breaks
	signal.Ignore(syscall.SIGPIPE)

	// Parse command line flags — G.1
	modeFlag = flag.String("mode", "normal", "Rejim: normal, experiment, benchmark, monitor24h")
	workersFlag = flag.Int("workers", 50, "Parallel ishchilar soni")
	expIDFlag = flag.String("exp-id", "", "Eksperiment identifikatori")
	durationFlag = flag.String("duration", "24h", "Monitoring davomiyligi: 24h, 1h, 30m")
	outputFlag = flag.String("output", "results", "Natijalar papkasi")
	networksFlag = flag.String("networks", "", "IP diapazoni: 172.20.254.0/24,...")
	communityFlag = flag.String("community", "", "SNMP community string")

	// Backward compatibility for old flags
	legacyExperiment = flag.Bool("experiment", false, "(deprecated) Use --mode experiment")
	legacyBenchmark = flag.Bool("benchmark", false, "(deprecated) Use --mode benchmark")
	legacyTest = flag.Bool("test", false, "(deprecated) Use --mode experiment")
	flag.Parse()

	// Backward compatibility: old flags override --mode
	if *legacyExperiment || *legacyTest {
		*modeFlag = "experiment"
	}
	if *legacyBenchmark {
		*modeFlag = "benchmark"
	}

	// Initialize Debug Logger
	initDebugLog()
	defer connectionLogFile.Close()

	// Initialize Capture Manager
	if err := InitCaptureManager("."); err != nil {
		fmt.Printf("⚠️ Failed to init capture manager: %v\n", err)
	}

	// Initialize OUI Vendor Database
	initOUIDatabase()

	switch *modeFlag {
	case "experiment":
		fmt.Println("🔬 STARTING IN EXPERIMENT MODE: Full scan, save all metrics, and exit.")
		logDebug("=== STARTED EXPERIMENT MODE ===")
	case "benchmark":
		fmt.Println("⏱️ STARTING IN BENCHMARK MODE: W=1,10,25,50,100 sequential scans.")
		logDebug("=== STARTED BENCHMARK MODE ===")
	case "monitor24h":
		fmt.Printf("📡 STARTING 24H MONITORING MODE: duration=%s\n", *durationFlag)
		logDebug("=== STARTED MONITOR24H MODE ===")
	default:
		logDebug("=== STARTED NORMAL MODE ===")
	}

	// Set initial empty graph for web server
	SetGlobalGraph(NewDJGraph())

	// Initialize InfluxDB connection
	if err := InitInfluxClient(); err != nil {
		fmt.Printf("⚠️ InfluxDB not available: %v\n", err)
		fmt.Println("   Traffic metrics will not be stored. Continue without InfluxDB.")
	} else {
		defer CloseInfluxClient()
	}

	// Check for saved data
	savedData, err := LoadSavedData()
	hasSavedHosts := err == nil && savedData != nil && len(savedData.Hosts) > 0

	if hasSavedHosts {
		fmt.Println("📂 Found saved network data, loading...")

		// Populate collectedData from saved
		collectedDataMutex.Lock()
		for ip, data := range savedData.Hosts {
			collectedData[ip] = data
			// Set traffic baseline
			updateTrafficCounters(ip, data.Interfaces)
		}
		collectedDataMutex.Unlock()

		// Rebuild graph
		rebuildGraph()
		fmt.Printf("✅ Loaded %d hosts from saved data\n", len(savedData.Hosts))
	}

	// MAC-IP Service: load cache and start background ARP collection
	// (covers gateway + all discovered switches)
	startMacIPService()

	// Collect ARP table from gateway first (legacy - also done by MacIPService)
	fmt.Printf("🔍 Collecting ARP table from gateway %s...\n", gatewayIP)
	collectGatewayARP()

	// Start web server immediately in background
	go StartWebServer("8088")
	fmt.Println("🌐 Web server started on http://localhost:8088")

	// ============================================================
	// Mode dispatch: benchmark and monitor24h exit early
	// ============================================================
	if *modeFlag == "benchmark" {
		runBenchmark()
		os.Exit(0)
	}
	if *modeFlag == "monitor24h" && hasSavedHosts {
		// Start traffic monitoring in background
		snmpObj := NewSNMPObject(
			func(data *DeviceData) {
				// Phase 8: Mark as reachable
				data.Unreachable = false
				data.LastSeen = time.Now()
				collectedDataMutex.Lock()
				collectedData[data.IP] = data
				collectedDataMutex.Unlock()
				updateTrafficCounters(data.IP, data.Interfaces)
			},
			func(ip string, err error) {
				// Phase 8: Mark as unreachable but PRESERVE old data
				collectedDataMutex.Lock()
				if existing, ok := collectedData[ip]; ok {
					existing.Unreachable = true
					// LastSeen stays unchanged — keeps last successful poll time
				}
				collectedDataMutex.Unlock()
				fmt.Printf("🔴 [Monitor] Switch unreachable: %s (%v)\n", ip, err)
			},
		)
		startTrafficPolling(snmpObj)
		startPeriodicLabelRefresh()
		startPeriodicRescan(snmpObj)
		startRescueScanner(snmpObj) // Phase 15: Dead Node Recovery
		go startPeriodicAnalysis()
		runMonitor24h()
		os.Exit(0)
	}
	// Note: if monitor24h but no saved data, normal scan runs first,
	// then monitor24h starts after EventScanComplete (see below)

	if hasSavedHosts {
		fmt.Println("📊 Loaded saved hosts. Use 'Rescan' in menu to refresh.")
		fmt.Println("🔄 Starting traffic monitoring...")

		// Create SNMP Object for traffic polling
		snmpObject := NewSNMPObject(nil, nil)
		startTrafficPolling(snmpObject)
		startPeriodicLabelRefresh()
		startPeriodicRescan(snmpObject)
		startRescueScanner(snmpObject) // Phase 15: Dead Node Recovery

		// E.1 fix: Run Analyze() immediately after loading saved data
		// so Health Score widget is populated on first page load (not after 10 min)
		go func() {
			collectedDataMutex.RLock()
			devicesPtrSlice := make([]*DeviceData, 0, len(collectedData))
			for _, d := range collectedData {
				devicesPtrSlice = append(devicesPtrSlice, d)
			}
			collectedDataMutex.RUnlock()

			startupGraph := GetGlobalGraph()
			if len(devicesPtrSlice) > 0 && startupGraph != nil {
				devicesValueSlice := make([]DeviceData, 0, len(devicesPtrSlice))
				for _, ptr := range devicesPtrSlice {
					devicesValueSlice = append(devicesValueSlice, *ptr)
				}
				fullData := FullCaptureData{
					Session:     CaptureSession{ID: "startup", Name: "Startup Analysis", StartTime: time.Now()},
					DevicesData: devicesValueSlice,
					Topology:    startupGraph.GetGraphData(),
				}
				analyzer := NewAnalyzer(fullData)
				analyzer.Analyze() // sets SetLastReport() → health_score visible immediately
				fmt.Println("✅ Initial health score calculated from saved data")
			}
		}()

		// Start periodic analysis loop for alerts
		go startPeriodicAnalysis()

		// Handle rescan requests
		handleRescanRequests(snmpObject)
	} else {
		fmt.Println("📊 Graph will update in real-time as devices are discovered")

		// Create SNMP Object for detailed data collection
		snmpObject := NewSNMPObject(
			// OnSuccess callback
			func(data *DeviceData) {
				atomic.AddInt32(&dataCollected, 1)

				// Phase 8: Mark as reachable
				data.Unreachable = false
				data.LastSeen = time.Now()

				// Store data for later processing
				collectedDataMutex.Lock()
				collectedData[data.IP] = data
				collectedDataMutex.Unlock()

				// Update traffic counters (set baseline for first poll)
				updateTrafficCounters(data.IP, data.Interfaces)

				fmt.Printf("[📊] %s (%s) - %d interfaces, %d neighbors, ChassisID: %s\n",
					data.IP, data.SysName, len(data.Interfaces), len(data.Neighbors), data.ChassisID)

				// REACTIVE: Rebuild graph from current collected data
				collectedDataMutex.RLock()
				newGraph := NewDJGraph()

				// 0. Build switchChassisMACs map
				switchChassisMACs := buildSwitchChassisMACs(collectedData)

				// 1. Add all Nodes
				for _, d := range collectedData {
					id := normalizeID(d.ChassisID, 0)
					if id == "" {
						id = d.IP
					}
					newGraph.AddNode(id)
					info := d.SysName
					if id != d.IP {
						info = fmt.Sprintf("%s\n%s", d.SysName, d.IP)
					}
					newGraph.SwitchInfo[id] = info

					// Phase 8: Transfer unreachable status to graph
					if d.Unreachable {
						newGraph.NodeStatus[id] = "unreachable"
					}
				}

				// 2. Build Edges (with switch MAC exclusion)
				for _, d := range collectedData {
					buildGraphEdges(newGraph, d, switchChassisMACs)
				}

				// 3. MAC cross-reference edges (for LLDP-disabled switches)
				addMACCrossRefEdges(newGraph, collectedData, switchChassisMACs)
				collectedDataMutex.RUnlock()

				// 4. Update global
				SetGlobalGraph(newGraph)
				// 5. Detect hypervisors on fresh graph
				detectHypervisors(newGraph)
				// 6. Enrich VM/hyp nodes with IPs from MAC-IP cache
				enrichGraphWithIPs(newGraph)
				fmt.Printf("  [GRAPH STATE] Nodes: %d, Edges: %d\n", len(newGraph.Nodes), countEdges(newGraph))

				// 7. Run Analyze() immediately so health_score is available in /api/graph
				go func() {
					collectedDataMutex.RLock()
					var devSlice []DeviceData
					for _, d := range collectedData {
						devSlice = append(devSlice, *d)
					}
					collectedDataMutex.RUnlock()
					fd := FullCaptureData{
						Session:     CaptureSession{ID: "live", Name: "Live", StartTime: time.Now()},
						DevicesData: devSlice,
						Topology:    newGraph.GetGraphData(),
					}
					a := NewAnalyzer(fd)
					r := a.Analyze()
					fmt.Printf("📊 [HealthScore] %d/100 (%s)\n", r.HealthScore, GetHealthLabel(r.HealthScore))
				}()
			},
			// OnFailure callback
			func(ip string, err error) {
				fmt.Printf("[❌] Data collection failed for %s: %v\n", ip, err)
				atomic.AddInt32(&dataCollected, 1)
				// Phase 8: Mark as unreachable but PRESERVE old data
				collectedDataMutex.Lock()
				if existing, ok := collectedData[ip]; ok {
					existing.Unreachable = true
				}
				collectedDataMutex.Unlock()
			},
		)

		// Define callback function for scan results
		resultCallback := func(result ScanResult) {
			switch result.Event {
			case EventHostFound:
				atomic.AddInt32(&hostsFound, 1)

			case EventSNMPSuccess:
				atomic.AddInt32(&snmpSuccess, 1)
				fmt.Printf("[✓] SNMP: %s - %s\n", result.IP, result.SysName)

				// Trigger detailed data collection with WaitGroup
				dataCollectionWG.Add(1)
				go func(ip, name string) {
					defer dataCollectionWG.Done()
					snmpObject.CollectData(ip, name)
				}(result.IP, result.SysName)

			case EventSNMPFailure:
				atomic.AddInt32(&snmpFailure, 1)
				fmt.Printf("[✗] SNMP FAILED: %s\n", result.IP)

			case EventScanComplete:
				experimentScanEnd = time.Now()
				scanDuration := experimentScanEnd.Sub(experimentScanStart)

				fmt.Println("\n" + strings.Repeat("=", 60))
				fmt.Println("DISCOVERY COMPLETE!")
				fmt.Println(strings.Repeat("=", 60))
				fmt.Printf("Hosts found: %d | SNMP success: %d | Failed: %d\n",
					atomic.LoadInt32(&hostsFound),
					atomic.LoadInt32(&snmpSuccess),
					atomic.LoadInt32(&snmpFailure))
				fmt.Printf("⏱️ [EXPERIMENT] Discovery duration: %v\n", scanDuration)
				fmt.Println(strings.Repeat("=", 60))

				// Wait for ALL data collections to finish
				fmt.Println("⏳ Waiting for all device data collections to complete...")
				dataCollectionWG.Wait()
				
				experimentCollectionEnd = time.Now()
				collectionDuration := experimentCollectionEnd.Sub(experimentScanEnd)
				totalDuration := experimentCollectionEnd.Sub(experimentScanStart)
				
				fmt.Printf("✅ Data collection finished in: %v\n", collectionDuration)
				fmt.Printf("⏱️ [EXPERIMENT] Total Scan+Collect duration: %v\n", totalDuration)

				// Convert collectedData map to slice for saving
				collectedDataSlice := make([]*DeviceData, 0, len(collectedData))
				collectedDataMutex.RLock()
				for _, d := range collectedData {
					collectedDataSlice = append(collectedDataSlice, d)
				}
				collectedDataMutex.RUnlock()

				// Save raw results to file
				saveResults(collectedDataSlice)

				// Final graph state already built by OnSuccess callbacks
				// Execute analysis to trigger Telegram notifications
				fmt.Println("🔍 Running analysis to detect network issues...")
				currentGlobalGraph := GetGlobalGraph()
				if currentGlobalGraph != nil {
					// Convert []*DeviceData to []DeviceData for the analyzer
					var devicesValueSlice []DeviceData
					for _, ptr := range collectedDataSlice {
						devicesValueSlice = append(devicesValueSlice, *ptr)
					}

					fullData := FullCaptureData{
						Session:     CaptureSession{ID: "scan-complete", Name: "Auto Scan", StartTime: time.Now()},
						DevicesData: devicesValueSlice,
						Topology:    currentGlobalGraph.GetGraphData(),
					}
					analyzer := NewAnalyzer(fullData)
					analyzer.Analyze() // Generates report and implicitly triggers Python Bot
				}

				// Optimize graph coordinates
				// The global graph is already updated by SetGlobalGraph(newGraph) in OnSuccess.
				// We need to get the current global graph to optimize its coords.
				currentGraph := GetGlobalGraph() // Assuming GetGlobalGraph returns a *DJGraph
				if currentGraph != nil {
					currentGraph.OptimizeCoords()
					SetGlobalGraph(currentGraph) // Update global graph with optimized coords
				}

				// Export to Zabbix formats
				fmt.Println("\n📤 Exporting to Zabbix formats...")
				err := currentGraph.ExportHostsToZabbix("zabbix_hosts.json")
				if err != nil {
					fmt.Printf("Error exporting hosts: %v\n", err)
				} else {
					fmt.Println("✅ Exported: zabbix_hosts.json")
				}

				err = currentGraph.ExportToMap("zabbix_map.json")
				if err != nil {
					fmt.Printf("Error exporting map: %v\n", err)
				} else {
					fmt.Println("✅ Exported: zabbix_map.json")
				}

				fmt.Printf("\n✅ Total devices with data: %d\n", atomic.LoadInt32(&dataCollected))
				fmt.Println("📁 Results saved to: scan_results.json")
				fmt.Printf("📊 Graph nodes: %d, edges: %d\n", len(currentGraph.Nodes), countEdges(currentGraph))

				// ⏱️ EXPERIMENT: Generate experiment report
				generateExperimentReport(collectedDataSlice, scanDuration, collectionDuration, totalDuration, currentGraph)

				fmt.Println("\n✨ Web server is running on http://localhost:8088")
				fmt.Println("🔄 Starting traffic monitoring (updates every 10s)...")

				// Start periodic traffic polling
				startTrafficPolling(snmpObject)
				startPeriodicLabelRefresh()
				startPeriodicRescan(snmpObject)

				// Start periodic analysis loop for alerts
				go startPeriodicAnalysis()

				if *modeFlag == "experiment" {
					fmt.Println("\n✅ EXPERIMENT MODE COMPLETED.")
					fmt.Println("   - results/experiment_metrics.json")
					fmt.Println("   - results/health_scores.json")
					fmt.Println("   - results/bfs_depths.json")
					fmt.Println("   - results/vendor_stats.json")
					fmt.Println("   - results/telegram_timing.json")
					fmt.Println("Exiting now.")
					os.Exit(0)
				}

				if *modeFlag == "monitor24h" {
					fmt.Println("\n📡 Fresh scan complete. Starting 24h monitoring...")
					// Save data so subsequent cycles have collectedData
					settings := GetCurrentSettings()
					SaveData(collectedData, settings)
					runMonitor24h()
					os.Exit(0)
				}
				
				fmt.Println("Press Ctrl+C to stop")
				select {} // Block forever to keep web server running
			}
		}

		// Create scanner with callback
		scanner := NewSNMPScanner(resultCallback)

		// Customize scanner settings
		settings := GetCurrentSettings()

		if settings.Community != "" {
			scanner.Community = settings.Community
		} else {
			scanner.Community = "public"
		}

		if settings.Timeout > 0 {
			scanner.Timeout = time.Duration(settings.Timeout) * time.Second
		} else {
			scanner.Timeout = 3 * time.Second // Was 20s - reduced for fast LAN scanning
		}

		if settings.MaxWorkers > 0 {
			scanner.MaxWorkers = settings.MaxWorkers
		} else {
			scanner.MaxWorkers = 50
		}

		scanner.MaxRepetitions = 1
		scanner.UsePing = true // FORCED: always use ICMP ping to pre-filter dead hosts

		fmt.Println("SNMP Network Scanner - Integrated with DJ_Graph")
		fmt.Printf("Mode: %s\n", map[bool]string{true: "Ping First", false: "Direct SNMP"}[scanner.UsePing])
		fmt.Println(strings.Repeat("=", 60))

		// ⏱️ EXPERIMENT: Record scan start time
		experimentScanStart = time.Now()
		fmt.Printf("\n⏱️ [EXPERIMENT] Scan started at: %s\n", experimentScanStart.Format("15:04:05.000"))

		// Scan from settings or file
		if len(settings.IPRanges) > 0 {
			fmt.Printf("Scanning %d saved IP ranges...\n", len(settings.IPRanges))
			ips, err := scanner.ExpandNetworks(settings.IPRanges)
			if err != nil {
				log.Fatalf("Error expanding networks: %v", err)
			}
			scanner.Scan(ips)
		} else {
			fmt.Println("No saved settings, scanning from file: swich_ips")
			if err := scanner.ScanFromFile("swich_ips"); err != nil {
				log.Printf("Error during scan: %v", err)
			}
		}
	} // End of else block
}

// Helper to format raw string as Hex with colons
func formatAsHex(raw string) string {
	// If it already looks like a MAC (xx:xx:xx...), just return normalized
	if strings.Contains(raw, ":") && len(raw) >= 17 {
		return strings.ToLower(raw)
	}

	bytes := []byte(raw)
	var hexParts []string
	for _, b := range bytes {
		hexParts = append(hexParts, fmt.Sprintf("%02x", b))
	}
	return strings.Join(hexParts, ":")
}

// cleanSNMPValue cleans raw SNMP value and returns the actual data
func cleanSNMPValue(val string) string {
	// Remove SNMP prefixes
	val = strings.TrimPrefix(val, "Hex-STRING: ")
	val = strings.TrimPrefix(val, "STRING: ")
	val = strings.Trim(val, "\"")
	val = strings.TrimSpace(val)
	return val
}

// hexStringToMAC converts any MAC format to canonical "4c:ae:a3:8e:42:11"
func hexStringToMAC(hex string) string {
	return normalizeMAC(hex)
}

// Helper to normalize Chassis IDs based on Subtype (RFC 2922)
func normalizeID(id string, subtype int) string {
	id = cleanSNMPValue(id)
	if id == "" {
		return ""
	}

	switch subtype {
	case 4: // MAC Address (6 bytes)
		// Input could be "4C AE A3 8E 42 11" or raw bytes
		if strings.Contains(id, " ") {
			return hexStringToMAC(id)
		}
		if len(id) == 6 {
			// Raw 6 bytes - convert to hex
			return formatAsHex(id)
		}
		// Already formatted — normalize
		return normalizeMAC(id)

	case 5: // Network Address (IP)
		// Try to parse as IP
		if len(id) == 4 { // IPv4
			return net.IP([]byte(id)).String()
		}
		if len(id) == 16 { // IPv6
			return net.IP([]byte(id)).String()
		}
		// Fallback to hex if weird length
		return hexStringToMAC(id)

	case 7: // Locally Assigned (string identifier)
		// Sometimes devices send ASCII-encoded MAC like "f4-b5-20-19-12-5e"
		// Normalize if it looks like a MAC address
		if isPrintableString(id) {
			// Check if it looks like a MAC (contains dashes or colons with hex chars)
			if (strings.Contains(id, "-") || strings.Contains(id, ":")) && len(id) >= 17 {
				return normalizeMAC(id)
			}
			return id
		}
		// If not printable, convert bytes to readable string
		return hexStringToMAC(id)

	case 2, 6: // Interface Alias, Interface Name
		if isPrintableString(id) {
			return id
		}
		return hexStringToMAC(id)

	default:
		// Subtype 0 (unknown) or others: use heuristics
		if (strings.Contains(id, ":") || strings.Contains(id, "-")) && len(id) >= 17 {
			return normalizeMAC(id) // Formatted MAC — normalize
		}
		if strings.Contains(id, " ") && len(id) >= 17 {
			return hexStringToMAC(id) // Hex string with spaces
		}
		if len(id) == 6 {
			return formatAsHex(id) // Raw 6 bytes
		}
		if isPrintableString(id) {
			return id
		}
		return hexStringToMAC(id)
	}
}

// buildGraphEdges builds graph edges using ChassisID as the primary key
// switchChassisMACs maps normalized MAC -> switch node ID (to exclude switch MACs from endpoint creation)
func buildGraphEdges(graph *DJGraph, data *DeviceData, switchChassisMACs map[string]string) {
	logDebug("Analyzing Edges for Host: %s (%s) [Chassis: %s]", data.IP, data.SysName, data.ChassisID)

	// Source Node (Assume subtype 4/MAC for local collected data for now,
	// as collectLocalChassisID returns formatted hex)
	srcID := normalizeID(data.ChassisID, 0)
	if srcID == "" {
		srcID = data.IP
	}

	// Ensure Source Node exists (should be added in main loop, but safety check)
	if !graph.Nodes[srcID] {
		graph.AddNode(srcID)
		// Add metadata
		info := data.SysName
		if srcID != data.IP {
			info = fmt.Sprintf("%s\n%s", data.SysName, data.IP)
		}
		graph.SwitchInfo[srcID] = info
	}

	// Add LLDP neighbors as edges
	logDebug("  Found %d LLDP neighbors", len(data.Neighbors))
	for _, neighbor := range data.Neighbors {
		// Determine Target ID - prefer MAC address for uniqueness
		var targetID string
		var displayName string

		chassisID := normalizeID(neighbor.RemChassisId, neighbor.RemChassisIdSubtype)
		portID := normalizeID(neighbor.RemPortId, neighbor.RemPortIdSubtype)

		// Check if ChassisID looks like a MAC (contains colons and correct length)
		chassisIsMAC := strings.Count(chassisID, ":") == 5 && len(chassisID) == 17
		portIsMAC := strings.Count(portID, ":") == 5 && len(portID) == 17

		if chassisIsMAC {
			// ChassisID is MAC - use it
			targetID = chassisID
			displayName = neighbor.RemSysName
		} else if portIsMAC {
			// ChassisID is hostname, but PortID is MAC - use PortID as node ID
			targetID = portID
			displayName = chassisID // Use hostname from ChassisID for display
			if neighbor.RemSysName != "" && neighbor.RemSysName != chassisID {
				displayName = neighbor.RemSysName
			}
		} else {
			// No MAC found - use ChassisID as fallback (could be hostname)
			targetID = chassisID
			displayName = neighbor.RemSysName
		}

		if targetID == "" {
			logDebug("    -> SKIPPED: Resolved Empty TargetID for neighbor on port %d", neighbor.LocalPortNum)
			continue
		}

		// Skip invalid/garbage target IDs
		if isInvalidID(targetID) {
			logDebug("    -> SKIPPED: Invalid TargetID '%s' (matches known garbage patterns)", targetID)
			continue
		}

		logDebug("    -> Neighbor: %s (ID: %s) via LocalPort: %d", displayName, targetID, neighbor.LocalPortNum)

		// ENHANCED DISCOVERY: Create LLDP Endpoint if target not scanned
		if !graph.Nodes[targetID] {
			graph.AddNode(targetID)

			// Get vendor from MAC if targetID looks like a MAC
			vendor := getMACVendor(targetID)

			// Build info from LLDP neighbor data with [LLDP-EP] marker
			var info string

			// Check BMC/management interface FIRST (OUI → name)
			if bmcDetected, bmcType := isBMC(targetID, displayName); bmcDetected {
				info = fmt.Sprintf("[BMC] %s", bmcType)

			} else if vendor != "" {
				info = fmt.Sprintf("[LLDP-EP] %s", vendor)
			} else {
				info = "[LLDP-EP]"
			}

			// Add display name (hostname/SysName) if available
			if displayName != "" && displayName != targetID {
				info = fmt.Sprintf("%s\n%s", info, displayName)
			}

			// Add IP or SysDesc
			if neighbor.RemMgmtIP != "" {
				info = fmt.Sprintf("%s\n%s", info, neighbor.RemMgmtIP)
			} else if neighbor.RemSysDesc != "" {
				descLines := strings.Split(neighbor.RemSysDesc, "\n")
				info = fmt.Sprintf("%s\n%s", info, descLines[0])
			}

			graph.SwitchInfo[targetID] = info

			logDebug("       [NEW NODE] Created LLDP Endpoint node: %s", targetID)
		}

		// Resolve local port name
		localPort := getLocalPortName(data, neighbor.LocalPortNum)
		// Skip NULL0 interface — virtual discard port, not a real connection
		if isNullInterface(localPort) {
			continue
		}
		remotePort := neighbor.RemPortDesc

		// Fallback logic for Remote Port
		// 1. If Desc is empty, use PortID
		if remotePort == "" {
			remotePort = neighbor.RemPortId
		}

		// 2. sanity check: if Port Name equals SysName, it's likely invalid/redundant
		if remotePort == neighbor.RemSysName {
			// If PortId is different, try that
			if neighbor.RemPortId != "" && neighbor.RemPortId != neighbor.RemSysName {
				remotePort = neighbor.RemPortId
			} else {
				// Last resort: "Uplink" or generic
				remotePort = "Uplink"
			}
		}

		// Get VLAN info for local port
		vlanStr := getPortVLANLabel(data.PortVLANs, neighbor.LocalPortNum)

		// Get speed for local port
		speedStr := getPortSpeed(data.Interfaces, neighbor.LocalPortNum)

		// Get traffic for local port
		inSpeed, outSpeed := getPortTraffic(data.IP, neighbor.LocalPortNum)
		trafficStr := ""
		if inSpeed > 0 || outSpeed > 0 {
			trafficStr = fmt.Sprintf("↓%s ↑%s", formatSpeed(inSpeed), formatSpeed(outSpeed))
		}

		// Format Link Label: "SrcPort [VLAN] Speed Traffic|DstPort"
		localPortLabel := normalizePortName(localPort)
		suffix := ""
		if vlanStr != "" {
			suffix = vlanStr
		}
		if speedStr != "" {
			if suffix != "" {
				suffix = fmt.Sprintf("%s %s", suffix, speedStr)
			} else {
				suffix = speedStr
			}
		}
		if trafficStr != "" {
			if suffix != "" {
				suffix = fmt.Sprintf("%s %s", suffix, trafficStr)
			} else {
				suffix = trafficStr
			}
		}
		if suffix != "" {
			localPortLabel = fmt.Sprintf("%s %s", localPortLabel, suffix)
		}
		label := fmt.Sprintf("%s|%s", localPortLabel, normalizePortName(remotePort))

		// Add Edge (Directional: Source -> Target)
		added, _ := graph.AddEdge(srcID, targetID, label)
		if added {
			logDebug("       [NEW EDGE] Added connection: %s -> %s (Label: %s)", srcID, targetID, label)
		} else {
			logDebug("       [DUP EDGE] Edge already exists: %s -> %s", srcID, targetID)
		}
	}

	// Process MAC Address Table - create endpoint nodes
	// Track which MACs are already known (from LLDP)
	knownMACs := make(map[string]bool)
	for _, neighbor := range data.Neighbors {
		// Normalize and add LLDP neighbor MACs
		mac := normalizeMAC(neighbor.RemChassisId)
		knownMACs[mac] = true
	}

	// Build MAC to IP lookup from local ARP table (normalize keys)
	macToIP := make(map[string]string)
	for _, arpEntry := range data.ARPTable {
		macToIP[normalizeMAC(arpEntry.MACAddress)] = arpEntry.IPAddress
	}

	// Also merge global gateway ARP data (more complete)
	globalMACtoIPMutex.RLock()
	for mac, ip := range globalMACtoIP {
		if _, exists := macToIP[mac]; !exists {
			macToIP[mac] = ip
		}
	}
	globalMACtoIPMutex.RUnlock()

	// Track MACs per port for Virtual Hub detection
	portMACs := make(map[int][]string)

	for _, macEntry := range data.MACTable {
		normMAC := normalizeMAC(macEntry.MACAddress)

		// Skip NULL0 interface — virtual discard port, not a real connection
		if isNullInterface(getLocalPortName(data, macEntry.PortNumber)) {
			continue
		}

		// Skip if this MAC is already known via LLDP
		if knownMACs[normMAC] {
			continue
		}

		// Skip switch's own MACs (usually ports have their own MACs)
		if normMAC == normalizeMAC(data.ChassisID) {
			continue
		}

		// Skip if this MAC belongs to another known switch (handled by MAC cross-ref)
		if _, isSwitch := switchChassisMACs[normMAC]; isSwitch {
			continue
		}

		// Skip special/invalid MAC addresses (use robust check)
		if isInvalidID(macEntry.MACAddress) {
			continue
		}

		portMACs[macEntry.PortNumber] = append(portMACs[macEntry.PortNumber], macEntry.MACAddress)
	}

	// Create endpoint nodes for MAC-discovered devices
	for portNum, macs := range portMACs {
		// Skip if this port already has LLDP neighbors
		hasLLDPNeighbor := false
		for _, neighbor := range data.Neighbors {
			if neighbor.LocalPortNum == portNum {
				hasLLDPNeighbor = true
				break
			}
		}

		portName := getLocalPortName(data, portNum)
		// Skip NULL0 interface
		if isNullInterface(portName) {
			continue
		}

		// If many MACs on same port without LLDP neighbor -> Virtual Hub or VM Server
		// But first check: skip trunk/uplink ports (they legitimately have many MACs)
		isTrunkPort := false
		for _, pv := range data.PortVLANs {
			if pv.PortIndex == portNum && pv.IsTrunk {
				isTrunkPort = true
				break
			}
		}

		// Fallback heuristic: if VLAN-based trunk detection missed it,
		// treat ports with >20 MACs as implicit uplink/trunk
		// (e.g., D 1-2 port 51 has 58 MACs — clearly an uplink, not a hub)
		if len(macs) > 20 && !isTrunkPort {
			isTrunkPort = true
			logDebug("       [UPLINK] Port %d on %s has %d MACs — treating as implicit uplink", portNum, srcID, len(macs))

		}

		if len(macs) >= 2 && !hasLLDPNeighbor && !isTrunkPort {
			// Check if this is a hypervisor port (ESXi, Proxmox, KVM)
			isVM := isHypervisorPort(macs)

			if isVM {
				// VM port: add direct switch→MAC edges so detectHypervisors()
				// can see them and create hyp- nodes correctly.
				// Do NOT create aggregated vm- node here — that conflicts with detectHypervisors.

				for _, mac := range macs {
					if !graph.Nodes[mac] {
						graph.AddNode(mac)
						osLabel := detectOSFromMAC(mac, macToIP, data)
						info := fmt.Sprintf("[VM] %s", osLabel)
						if vendor := getMACVendor(mac); vendor != "" {
							info = fmt.Sprintf("%s %s", info, vendor)
						}
						if ip, ok := macToIP[mac]; ok {
							info = fmt.Sprintf("%s\n%s", info, ip)
						}
						graph.SwitchInfo[mac] = info
					}
					portEdgeLabel := fmt.Sprintf("%s [T]", normalizePortName(portName))
					graph.AddEdge(srcID, mac, portEdgeLabel)
				}
			} else {
				// Non-VM hub: create aggregated hub node
				nodeID := fmt.Sprintf("hub-%s-p%d", srcID, portNum)
				nodeLabel := fmt.Sprintf("[HUB] Unmanaged\n%d devices", len(macs))
				edgeLabel := fmt.Sprintf("%s|Hub", normalizePortName(portName))


				if !graph.Nodes[nodeID] {
					graph.AddNode(nodeID)
					graph.SwitchInfo[nodeID] = nodeLabel
				}
				graph.AddEdge(srcID, nodeID, edgeLabel)

				for i, mac := range macs {
					if i >= 5 {
						break
					}
					if !graph.Nodes[mac] {
						graph.AddNode(mac)
						info := "[ENDPOINT]"
						if vendor := getMACVendor(mac); vendor != "" {
							info = fmt.Sprintf("%s %s", info, vendor)
						}
						if ip, ok := macToIP[mac]; ok {
							info = fmt.Sprintf("%s\n%s", info, ip)
						}
						graph.SwitchInfo[mac] = info
					}
					graph.AddEdge(nodeID, mac, "")
				} // end for (hub macs)
			} // end else (hub)
		} else if len(macs) <= 3 && !hasLLDPNeighbor {
			// Few MACs - create direct endpoint nodes
			for _, mac := range macs {
				endpointID := mac
				if !graph.Nodes[endpointID] {
					graph.AddNode(endpointID)
					// Build endpoint info with IP and Vendor
					info := "[ENDPOINT]"
					// Check BMC first (by OUI)
					if bmcDetected, bmcType := isBMC(mac, ""); bmcDetected {
						info = fmt.Sprintf("[BMC] %s", bmcType)

					} else if isRandomMAC(mac) {
						info = "[WiFi]"
					}
					if vendor := getMACVendor(mac); vendor != "" {
						info = fmt.Sprintf("%s %s", info, vendor)
					}
					// DNS reverse lookup for endpoint hostname
					if ip, ok := macToIP[mac]; ok {
						info = fmt.Sprintf("%s\n%s", info, ip)
						if hostname := resolveHostname(ip); hostname != "" {
							info = fmt.Sprintf("%s\n[DNS] %s", info, hostname)
						}
					}
					graph.SwitchInfo[endpointID] = info
					logDebug("       [NEW NODE] Created MAC endpoint node: %s", endpointID)
				}
				// Add VLAN info to label
				vlanStr := getPortVLANLabel(data.PortVLANs, portNum)
				portLabel := normalizePortName(portName)
				if vlanStr != "" {
					portLabel = fmt.Sprintf("%s %s", portLabel, vlanStr)
				}
				label := fmt.Sprintf("%s|", portLabel)
				added, _ := graph.AddEdge(srcID, endpointID, label)
				if added {
					logDebug("       [NEW EDGE] Added MAC endpoint link: %s -> %s", srcID, endpointID)
				}
			}
		}
	}
}

// getLocalPortName resolves local port number to interface name
func getLocalPortName(data *DeviceData, portNum int) string {
	// Look for interface with matching index
	for _, iface := range data.Interfaces {
		if iface.IfIndex == portNum {
			return iface.IfDescr
		}
	}
	// Fallback if not found
	return fmt.Sprintf("Port %d", portNum)
}

// isNullInterface returns true if the interface name is NULL0 or similar
// virtual discard interface that should be excluded from the topology graph.
func isNullInterface(name string) bool {
	low := strings.ToLower(strings.TrimSpace(name))
	return low == "null0" || low == "null 0" ||
		strings.HasPrefix(low, "null") ||
		strings.Contains(low, "inloopback") ||
		low == "" || low == "port 0"
}

// getPortVLANLabel returns VLAN label for a port (e.g., "[V1616]" or "[TRUNK]")
func getPortVLANLabel(portVLANs []PortVLAN, portIndex int) string {
	for _, pv := range portVLANs {
		if pv.PortIndex == portIndex {
			if pv.IsTrunk {
				return "[T]" // Trunk
			}
			if pv.PVID > 1 {
				return fmt.Sprintf("[V%d]", pv.PVID)
			}
			// VLAN 1 is default, don't show
			return ""
		}
	}
	return ""
}

// formatSpeed formats interface speed in human readable format
func formatSpeed(speedBps uint64) string {
	if speedBps == 0 {
		return ""
	}

	// Convert bps to Mbps
	speedMbps := speedBps / 1_000_000

	switch {
	case speedMbps >= 100000:
		return fmt.Sprintf("%.0fG", float64(speedMbps)/1000)
	case speedMbps >= 10000:
		return fmt.Sprintf("%.0fG", float64(speedMbps)/1000)
	case speedMbps >= 1000:
		return fmt.Sprintf("%.0fG", float64(speedMbps)/1000)
	case speedMbps >= 100:
		return fmt.Sprintf("%dM", speedMbps)
	case speedMbps >= 10:
		return fmt.Sprintf("%dM", speedMbps)
	default:
		return fmt.Sprintf("%dM", speedMbps)
	}
}

// getPortSpeed returns formatted speed for a port
func getPortSpeed(interfaces []InterfaceData, portIndex int) string {
	for _, iface := range interfaces {
		if iface.IfIndex == portIndex {
			return formatSpeed(iface.IfSpeed)
		}
	}
	return ""
}

// normalizePortName is the SINGLE source of truth for port name normalization.
// It cleans and abbreviates port names consistently across all code paths.
// Steps: 1) strip quotes, 2) remove MAC prefix, 3) remove noise suffixes,
//         4) apply abbreviations in priority order (longest match first).
//
// Examples:
//   "GigabitEthernet1/0/26"  → "GE1/0/26"
//   "GigabitF1/0/26"         → "GE1/0/26"
//   "Ten-GigabitEthernet1/0/49" → "TGE1/0/49"
//   "4c:ae:a3:xx:GE1/0/1"   → "GE1/0/1"
//   "fastethernet 0/1"       → "FE0/1"
func normalizePortName(name string) string {
	// 1. Remove surrounding quotes and whitespace
	name = strings.Trim(name, "\" \t\r\n")

	// 2. Remove MAC address prefix (e.g. "4c:ae:a3:a2:06:2c:GE1/0/43" → "GE1/0/43")
	name = rePortMACPrefix.ReplaceAllString(name, "")

	// 3. Remove noise suffixes
	for _, suffix := range []string{" Interface", " interface", " (SFP)", " (RJ45)"} {
		name = strings.TrimSuffix(name, suffix)
	}
	name = strings.TrimSpace(name)

	// 4. Apply abbreviations — LONGEST MATCH FIRST (order matters)
	type abbr struct{ long, short string }
	abbreviations := []abbr{
		// 100G
		{"HundredGigE", "HU"},
		{"HundredGigabitEthernet", "HU"},
		// 40G
		{"FortyGigabitEthernet", "FO"},
		{"FortyGigE", "FO"},
		// 25G
		{"TwentyFiveGigE", "TFE"},
		// 10G — Ten variants (longest first)
		{"TenGigabitEthernet", "TGE"},
		{"Ten-GigabitEthernet", "TGE"},
		{"TenGigE", "TGE"},
		{"Ten-GE", "TGE"},
		// 1G — Gigabit variants (GigabitF must come before Gigabit)
		{"GigabitEthernet", "GE"},
		{"GigabitF", "GE"}, // HPE/SNR shorthand
		{"Gigabit", "GE"},
		// 100M
		{"FastEthernet", "FE"},
		// Generic
		{"Ethernet", "Eth"},
	}
	for _, ab := range abbreviations {
		if strings.Contains(name, ab.long) {
			name = strings.Replace(name, ab.long, ab.short, 1)
			break
		}
	}

	// 5. Collapse multiple spaces
	name = strings.Join(strings.Fields(name), "")

	return name
}

// normalizePortForHypervisor returns a lowercase canonical port key for grouping.
// It delegates to normalizePortName so there is one source of truth.
// Example: "GigabitF1/0/26" and "GE1/0/26" both → "ge1/0/26"
func normalizePortForHypervisor(port string) string {
	return strings.ToLower(normalizePortName(port))
}


// isPrintableString checks if a string contains only printable ASCII characters
func isPrintableString(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		// Allow printable ASCII and common Unicode characters
		if r < 32 || (r > 126 && r < 160) {
			return false
		}
	}
	return true
}

// startPeriodicAnalysis runs NetworkAnalyzer periodically to trigger alerts for new issues
func startPeriodicAnalysis() {
	ticker := time.NewTicker(60 * time.Second) // Analyze every minute
	defer ticker.Stop()

	for range ticker.C {
		// DEADLOCK FIX: Snapshot pattern — short RLock, then release
		// before acquiring any other mutex (GetGlobalGraph → globalGraphMutex)
		collectedDataMutex.RLock()
		if len(collectedData) == 0 {
			collectedDataMutex.RUnlock()
			continue
		}

		// Build slices from collectedData (need both pointer and value slices)
		var devicesValueSlice []DeviceData
		var devicesPtrSlice []*DeviceData
		for _, ptr := range collectedData {
			devicesValueSlice = append(devicesValueSlice, *ptr)
			devicesPtrSlice = append(devicesPtrSlice, ptr)
		}
		collectedDataMutex.RUnlock()

		// Get global graph AFTER releasing collectedDataMutex
		currentGlobalGraph := GetGlobalGraph()
		if currentGlobalGraph == nil {
			continue
		}

		fullData := FullCaptureData{
			Session:     CaptureSession{ID: "live-monitoring", Name: "Live Monitoring", StartTime: time.Now()},
			DevicesData: devicesValueSlice,
			Topology:    currentGlobalGraph.GetGraphData(),
		}

		analyzer := NewAnalyzer(fullData)
		report := analyzer.Analyze() // Analyze triggers notifyTelegramIfCritical + WriteAnomalySummary implicitly

		// ── Snapshot Diff Engine (B.1) ──
		currentSnapshot := CreateSnapshot(devicesPtrSlice, currentGlobalGraph, &report)
		fmt.Printf("📸 Snapshot created: %d MACs, %d hosts, health=%d\n",
			len(currentSnapshot.ActiveMACs), len(currentSnapshot.ActiveHosts), currentSnapshot.HealthScore)

		previousSnapshotMutex.Lock()
		if previousSnapshot != nil {
			diff := CompareSnapshots(previousSnapshot, currentSnapshot)
			diff.LogChanges()

			// B.2: Write JOIN/LEAVE events to InfluxDB
			for _, joined := range diff.JoinedMACs {
				WriteDeviceEvent("join", joined.MAC, joined.IP, joined.SwitchIP, joined.Vendor)
			}
			for _, left := range diff.LeftMACs {
				WriteDeviceEvent("leave", left.MAC, left.IP, left.SwitchIP, left.Vendor)
			}

			// B.3: Write network summary to InfluxDB
			// Count random MACs
			randomMACCount := 0
			for mac := range currentSnapshot.ActiveMACs {
				if isRandomMAC(mac) {
					randomMACCount++
				}
			}
			WriteNetworkSummary(
				len(currentSnapshot.ActiveHosts),
				len(currentSnapshot.ActiveMACs),
				report.Summary["shadow_it_issues"],
				currentSnapshot.HealthScore,
				randomMACCount,
			)
		}
		previousSnapshot = currentSnapshot
		previousSnapshotMutex.Unlock()
	}
}

// ============================================================
// A.2 — Benchmark Mode: W=1,10,25,50,100 sequential scans
// ============================================================

func runBenchmark() {
	workerCounts := []int{1, 10, 25, 50, 100}
	var results []BenchmarkResult

	// Read IP list once
	tempScanner := NewSNMPScanner(nil)
	settings := GetCurrentSettings()

	var ips []string
	var err error
	if len(settings.IPRanges) > 0 {
		ips, err = tempScanner.ExpandNetworks(settings.IPRanges)
	} else {
		entries, readErr := tempScanner.ReadIPsFromFile("swich_ips")
		if readErr == nil {
			ips, err = tempScanner.ExpandNetworks(entries)
		} else {
			err = readErr
		}
	}
	if err != nil || len(ips) == 0 {
		fmt.Printf("❌ Benchmark: IP ro'yxat topilmadi: %v\n", err)
		return
	}

	fmt.Printf("\n⏱️ BENCHMARK: %d ta IP, worker counts: %v\n", len(ips), workerCounts)
	fmt.Println(strings.Repeat("=", 60))

	for _, w := range workerCounts {
		// Reset counters
		var bSuccess, bFailure int32
		var bFound int32

		callback := func(result ScanResult) {
			switch result.Event {
			case EventHostFound:
				atomic.AddInt32(&bFound, 1)
			case EventSNMPSuccess:
				atomic.AddInt32(&bSuccess, 1)
			case EventSNMPFailure:
				atomic.AddInt32(&bFailure, 1)
			}
		}

		scanner := NewSNMPScanner(callback)
		scanner.MaxWorkers = w
		scanner.Community = settings.Community
		if scanner.Community == "" {
			scanner.Community = "public"
		}
		scanner.Timeout = 3 * time.Second
		scanner.UsePing = true
		scanner.MaxRepetitions = 1

		fmt.Printf("\n🔧 W=%d: Scanning %d IPs...\n", w, len(ips))
		start := time.Now()
		scanner.Scan(ips)
		dur := time.Since(start)

		result := BenchmarkResult{
			Workers:      w,
			Duration:     dur.String(),
			DurationSec:  dur.Seconds(),
			DevicesFound: int(atomic.LoadInt32(&bFound)),
			SNMPSuccess:  atomic.LoadInt32(&bSuccess),
			SNMPFailure:  atomic.LoadInt32(&bFailure),
		}
		results = append(results, result)

		fmt.Printf("   ✅ W=%d: %v | Found: %d | SNMP OK: %d | Fail: %d\n",
			w, dur.Round(time.Millisecond), result.DevicesFound, result.SNMPSuccess, result.SNMPFailure)
	}

	// Export results
	ExportBenchmarkResults(results)

	// Print summary table
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("BENCHMARK RESULTS SUMMARY")
	fmt.Println(strings.Repeat("=", 60))
	fmt.Printf("%-10s %-15s %-10s %-10s %-10s\n", "Workers", "Duration", "Found", "SNMP OK", "Failed")
	fmt.Println(strings.Repeat("-", 55))
	for _, r := range results {
		fmt.Printf("%-10d %-15s %-10d %-10d %-10d\n",
			r.Workers, r.Duration, r.DevicesFound, r.SNMPSuccess, r.SNMPFailure)
	}
	fmt.Println(strings.Repeat("=", 60))
	fmt.Println("✅ Natijalar saqlandi: results/benchmark_results.json")
}

// ============================================================
// G.3 — 24h Monitoring Mode
// ============================================================

// parseDurationFlag parses duration strings like "24h", "1h", "30m", "5m"
func parseDurationFlag(s string) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		fmt.Printf("⚠️ Invalid duration '%s', defaulting to 24h\n", s)
		return 24 * time.Hour
	}
	return d
}

// runMonitor24h runs continuous monitoring for specified duration
func runMonitor24h() {
	duration := parseDurationFlag(*durationFlag)
	startTime := time.Now()
	endTime := startTime.Add(duration)

	fmt.Printf("📡 Monitor24h started at %s\n", startTime.Format("15:04:05"))
	fmt.Printf("📡 Will run until %s (duration: %v)\n", endTime.Format("15:04:05"), duration)

	// Ensure output directory exists
	os.MkdirAll(*outputFlag, 0755)

	var prevSnapshot *NetworkSnapshot
	cycleCount := 0

	for time.Now().Before(endTime) {
		cycleStart := time.Now()
		cycleCount++
		remaining := time.Until(endTime)
		fmt.Printf("\n🔄 Cycle #%d (remaining: %v)\n", cycleCount, remaining.Round(time.Second))

		// Panic recovery — don't let a single cycle crash the entire 24h session
		func() {
			defer func() {
				if r := recover(); r != nil {
					fmt.Printf("⚠️ [Monitor24h] Cycle #%d panic recovered: %v\n", cycleCount, r)
				}
			}()

		// 1. Collect current data — snapshot under SHORT RLock to avoid nested lock deadlock
		collectedDataMutex.RLock()
		if len(collectedData) == 0 {
			collectedDataMutex.RUnlock()
			fmt.Println("   No data yet, waiting...")
			return
		}

		var devicesValueSlice []DeviceData
		var devicesPtrSlice []*DeviceData
		for _, ptr := range collectedData {
			devicesValueSlice = append(devicesValueSlice, *ptr)
			devicesPtrSlice = append(devicesPtrSlice, ptr)
		}
		collectedDataMutex.RUnlock()

		// Get global graph AFTER releasing collectedDataMutex (avoids lock ordering deadlock)
		currentGlobalGraph := GetGlobalGraph()
		if currentGlobalGraph == nil {
			fmt.Println("   No graph yet, waiting...")
			return
		}

		// 2. Analyze
		fullData := FullCaptureData{
			Session:     CaptureSession{ID: "monitor24h", Name: "24h Monitoring", StartTime: time.Now()},
			DevicesData: devicesValueSlice,
			Topology:    currentGlobalGraph.GetGraphData(),
		}

		analyzer := NewAnalyzer(fullData)
		report := analyzer.Analyze()

		// 3. Snapshot + Diff
		currentSnapshot := CreateSnapshot(devicesPtrSlice, currentGlobalGraph, &report)
		fmt.Printf("   📸 Snapshot: %d MACs, %d hosts, health=%d\n",
			len(currentSnapshot.ActiveMACs), len(currentSnapshot.ActiveHosts), currentSnapshot.HealthScore)

		if prevSnapshot != nil {
			diff := CompareSnapshots(prevSnapshot, currentSnapshot)
			diff.LogChanges()

			// Write to InfluxDB
			for _, joined := range diff.JoinedMACs {
				WriteDeviceEvent("join", joined.MAC, joined.IP, joined.SwitchIP, joined.Vendor)
			}
			for _, left := range diff.LeftMACs {
				WriteDeviceEvent("leave", left.MAC, left.IP, left.SwitchIP, left.Vendor)
			}

			randomMACCount := 0
			for mac := range currentSnapshot.ActiveMACs {
				if isRandomMAC(mac) {
					randomMACCount++
				}
			}
			WriteNetworkSummary(
				len(currentSnapshot.ActiveHosts),
				len(currentSnapshot.ActiveMACs),
				report.Summary["shadow_it_issues"],
				currentSnapshot.HealthScore,
				randomMACCount,
			)
		}
		prevSnapshot = currentSnapshot

		}() // End of panic recovery wrapper

		// 4. Wait 60s (minus scan time)
		elapsed := time.Since(cycleStart)
		sleepDur := 60*time.Second - elapsed
		if sleepDur > 0 && time.Now().Add(sleepDur).Before(endTime) {
			time.Sleep(sleepDur)
		} else if time.Now().Before(endTime) {
			time.Sleep(5 * time.Second) // minimum sleep
		}
	}

	// Save final summary
	totalDuration := time.Since(startTime)
	summary := map[string]interface{}{
		"mode":           "monitor24h",
		"start_time":     startTime.Format("2006-01-02 15:04:05"),
		"end_time":       time.Now().Format("2006-01-02 15:04:05"),
		"total_duration": totalDuration.String(),
		"total_cycles":   cycleCount,
		"exp_id":         *expIDFlag,
	}

	prefix := *expIDFlag
	if prefix == "" {
		prefix = "monitor"
	}
	summaryPath := fmt.Sprintf("%s/%s_summary.json", *outputFlag, prefix)
	file, err := os.Create(summaryPath)
	if err == nil {
		enc := json.NewEncoder(file)
		enc.SetIndent("", "  ")
		enc.Encode(summary)
		file.Close()
		fmt.Printf("✅ Summary saved: %s\n", summaryPath)
	}

	fmt.Printf("\n✅ MONITOR24H COMPLETED: %d cycles in %v\n", cycleCount, totalDuration.Round(time.Second))
	os.Exit(0)
}

// Hypervisor MAC prefixes (VMware, Proxmox/KVM, Hyper-V, Xen) — these are VIRTUAL NIC OUIs
var hypervisorMACPrefixes = []string{
	// VMware
	"00:50:56", "00:0c:29", "00:05:69",
	// Proxmox / KVM / QEMU
	"bc:24:11", "52:54:00",
	// Microsoft Hyper-V
	"00:15:5d",
	// Xen
	"00:16:3e",
	// Oracle VirtualBox
	"08:00:27",
}

// serverNICPrefixes — физический NIC серверов на базе которых запускают ESXi/KVM
// Dell, HPE, SuperMicro, Lenovo, Cisco UCS, Fujitsu, IBM
var serverNICPrefixes = []string{
	// Dell Inc. (PowerEdge серия)
	"4c:d9:8f", // Dell PowerEdge
	"f8:db:88", // Dell
	"18:db:f2", "b0:83:fe", "b4:45:06", "00:14:22", "00:21:9b",
	"08:94:ef", "00:1a:a0", "d4:ae:52", "a0:36:9f",
	"34:17:eb", "00:26:b9",
	// Hewlett Packard Enterprise (ProLiant, Synergy)
	"3c:a8:2a", "48:df:37", "5c:ed:8c", "9c:b6:54",
	"f8:f0:82", "4c:ae:a3", // HPE iLO/FlexibleLOM
	"10:e7:c6", "00:26:55", "1c:98:ec",
	"94:57:a5", "ec:b1:d7", "b4:7a:f1", "e8:39:35",
	// SuperMicro
	"0c:c4:7a", "3c:ec:ef", "ac:1f:6b",
	"74:56:3c", "00:25:90", "a0:42:3f",
	// Lenovo (ThinkServer, ThinkSystem)
	"e8:6a:64", "7c:d3:0a", "54:ee:75",
	"00:23:ae", "34:40:b5",
	// Cisco UCS
	"00:25:b5", "00:2a:6a", "a8:9d:21",
	// Fujitsu
	"90:1b:0e", "00:1b:24",
	// IBM
	"00:14:5e", "00:21:5e",
}

// isHypervisorMAC checks if a MAC address belongs to a known hypervisor vendor
func isHypervisorMAC(mac string) bool {
	mac = strings.ToLower(mac)
	for _, prefix := range hypervisorMACPrefixes {
		if strings.HasPrefix(mac, prefix) {
			return true
		}
	}
	return false
}

// isHypervisorPort checks if the majority of MACs on a port are from hypervisors
func isHypervisorPort(macs []string) bool {
	if len(macs) == 0 {
		return false
	}
	vmCount := 0
	for _, mac := range macs {
		if isHypervisorMAC(mac) {
			vmCount++
		}
	}
	// If more than 50% of MACs are hypervisor MACs, it's a VM server
	return float64(vmCount)/float64(len(macs)) > 0.5
}

// isServerNIC returns true if the MAC belongs to a known server vendor NIC
// (Dell PowerEdge, HPE ProLiant, SuperMicro, Lenovo ThinkSystem, Cisco UCS etc.)
// Used to detect ESXi/KVM hypervisors that run on physical servers.
func isServerNIC(mac string) (bool, string) {
	mac = strings.ToLower(mac)
	prefixVendor := map[string]string{
		// Dell
		"4c:d9:8f": "Dell PowerEdge", "f8:db:88": "Dell",
		"18:db:f2": "Dell", "b0:83:fe": "Dell", "b4:45:06": "Dell",
		"00:14:22": "Dell", "00:21:9b": "Dell", "08:94:ef": "Dell",
		"00:1a:a0": "Dell", "d4:ae:52": "Dell", "a0:36:9f": "Dell",
		"34:17:eb": "Dell", "00:26:b9": "Dell",
	// HPE ProLiant NIC OUIs (iLO, FlexLOM — NOT 4c:ae:a3 which is HPE switch)
	"f8:f0:82": "HPE", "10:e7:c6": "HPE",
	"00:26:55": "HPE", "1c:98:ec": "HPE",
	"94:57:a5": "HPE", "ec:b1:d7": "HPE",
	"b4:7a:f1": "HPE ProLiant", "e8:39:35": "HPE",
	"3c:a8:2a": "HPE ProLiant", "48:df:37": "HPE ProLiant",
	"5c:ed:8c": "HPE ProLiant", "9c:b6:54": "HPE ProLiant",
		// SuperMicro
		"0c:c4:7a": "SuperMicro", "3c:ec:ef": "SuperMicro",
		"ac:1f:6b": "SuperMicro", "74:56:3c": "SuperMicro (GIGA-BYTE)",
		"00:25:90": "SuperMicro", "a0:42:3f": "SuperMicro",
		// Lenovo
		"e8:6a:64": "Lenovo ThinkSystem", "7c:d3:0a": "Lenovo",
		"54:ee:75": "Lenovo", "00:23:ae": "Lenovo", "34:40:b5": "Lenovo",
		// Cisco UCS
		"00:25:b5": "Cisco UCS", "00:2a:6a": "Cisco UCS", "a8:9d:21": "Cisco UCS",
		// Fujitsu
		"90:1b:0e": "Fujitsu", "00:1b:24": "Fujitsu",
		// IBM
		"00:14:5e": "IBM", "00:21:5e": "IBM",
	}
	if len(mac) >= 8 {
		prefix := mac[:8]
		if vendor, ok := prefixVendor[prefix]; ok {
			return true, vendor
		}
	}
	return false, ""
}

// detectOSFromMAC tries to detect the OS of a VM based on LLDP name, TTL ping, and MAC vendor
func detectOSFromMAC(mac string, macToIP map[string]string, data *DeviceData) string {
	macNorm := normalizeMAC(mac)
	
	// 1. Check LLDP neighbor names for OS hints (fastest, no network call)
	for _, neighbor := range data.Neighbors {
		neighborMAC := normalizeMAC(neighbor.RemChassisId)
		if neighborMAC == macNorm || strings.Contains(neighborMAC, macNorm) {
			nameLower := strings.ToLower(neighbor.RemSysName)
			if strings.HasPrefix(nameLower, "desktop-") || strings.HasPrefix(nameLower, "win-") || strings.Contains(nameLower, "windows") {
				return "🪟 Windows"
			}
			if strings.Contains(nameLower, "ubuntu") || strings.Contains(nameLower, "linux") || strings.Contains(nameLower, "debian") || strings.Contains(nameLower, "centos") || strings.Contains(nameLower, "rhel") {
				return "🐧 Linux"
			}
		}
	}
	
	// 2. TTL fingerprinting via quick ping (1 attempt, 1 second timeout)
	if ip, ok := macToIP[macNorm]; ok && ip != "" {
		if osLabel := detectOSByTTL(ip); osLabel != "" {
			return osLabel
		}
	}
	
	// 3. Fallback: guess by MAC prefix
	if strings.HasPrefix(macNorm, "00:50:56") || strings.HasPrefix(macNorm, "00:0c:29") {
		return "💻 VMware VM"
	}
	if strings.HasPrefix(macNorm, "52:54:00") || strings.HasPrefix(macNorm, "bc:24:11") {
		return "💻 KVM/Proxmox VM"
	}
	if strings.HasPrefix(macNorm, "00:15:5d") {
		return "🪟 Hyper-V VM"
	}
	if strings.HasPrefix(macNorm, "00:16:3e") {
		return "💻 Xen VM"
	}
	if strings.HasPrefix(macNorm, "08:00:27") {
		return "💻 VirtualBox VM"
	}
	
	return "❓ Unknown VM"
}

// detectOSByTTL pings an IP once and checks TTL to determine OS
func detectOSByTTL(ip string) string {
	cmd := exec.Command("ping", "-c", "1", "-W", "1", ip)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var outBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return ""
	}
	done := make(chan error, 1)
	timer := time.AfterFunc(3*time.Second, func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	})
	go func() { done <- cmd.Wait() }()
	err := <-done
	timer.Stop()
	if err != nil {
		return ""
	}
	
	outputStr := outBuf.String()
	// Parse TTL from ping output like "ttl=64" or "ttl=128"
	ttlIdx := strings.Index(strings.ToLower(outputStr), "ttl=")
	if ttlIdx == -1 {
		return ""
	}
	
	ttlStr := outputStr[ttlIdx+4:]
	// Extract number
	var ttlNum int
	fmt.Sscanf(ttlStr, "%d", &ttlNum)
	
	if ttlNum > 0 && ttlNum <= 64 {
		return "🐧 Linux"
	} else if ttlNum > 64 && ttlNum <= 128 {
		return "🪟 Windows"
	}
	
	return ""
}
// isSpecialMAC checks if MAC is broadcast, null, or multicast (should be filtered)
func isSpecialMAC(mac string) bool {
	mac = strings.ToLower(mac)

	// Null MAC
	if mac == "00:00:00:00:00:00" {
		return true
	}

	// Broadcast MAC
	if mac == "ff:ff:ff:ff:ff:ff" {
		return true
	}

	// Multicast MAC (first octet has LSB set to 1)
	// Common prefixes: 01:00:5e (IPv4 multicast), 33:33 (IPv6 multicast)
	if strings.HasPrefix(mac, "01:") || strings.HasPrefix(mac, "33:33:") {
		return true
	}

	// Check if first octet is odd (multicast bit set)
	parts := strings.Split(mac, ":")
	if len(parts) >= 1 {
		var firstByte int
		fmt.Sscanf(parts[0], "%x", &firstByte)
		if firstByte&1 == 1 {
			return true // Multicast
		}
	}

	return false
}

// isRandomMAC checks if a MAC address uses locally administered address (random/private)
// Rule: the second hex character of the first octet is 2, 6, A, or E
// Examples: da:a1:19:... → 'a' ∈ {2,6,a,e} → random ✅
//           00:1a:2b:... → '0' ∉ {2,6,a,e} → real ❌
func isRandomMAC(mac string) bool {
	mac = strings.ToLower(mac)
	parts := strings.Split(mac, ":")
	if len(parts) < 1 || len(parts[0]) < 2 {
		return false
	}
	// Second hex char of first octet
	secondChar := parts[0][1]
	return secondChar == '2' || secondChar == '6' || secondChar == 'a' || secondChar == 'e'
}

// isBMC detects server BMC/management interfaces (iDRAC, iLO, IPMI, XCC, iRMC, CIMC).
// Strategy: 1) MAC OUI match, 2) LLDP name keyword match.
// Returns (isBMC bool, bmcType string e.g. "Dell iDRAC").
func isBMC(mac, name string) (bool, string) {
	mac = normalizeMAC(mac)
	nameLower := strings.ToLower(name)

	// ── Step 1: MAC OUI (first 8 chars = "aa:bb:cc") ──────────────────────────
	// These OUI blocks are EXCLUSIVELY used by BMC/management NIC hardware.
	bmcOUIs := map[string]string{
		// Dell iDRAC (Remote Access Controller)
		"14:fe:b5": "Dell iDRAC",
		"18:66:da": "Dell iDRAC",
		"b0:83:fe": "Dell iDRAC",
		"f8:db:88": "Dell iDRAC",
		"f0:1f:af": "Dell iDRAC",
		"b8:ca:3a": "Dell iDRAC",
		"d0:94:66": "Dell iDRAC",
		"54:bf:64": "Dell iDRAC",

		// HPE iLO (Integrated Lights-Out)
		"98:e7:f4": "HPE iLO",
		"b4:99:ba": "HPE iLO",
		"94:18:82": "HPE iLO",
		"9c:8e:99": "HPE iLO",
		"58:20:b1": "HPE iLO",
		"3c:a8:2a": "HPE iLO",
		"10:60:4b": "HPE iLO",

		// Lenovo XClarity / IMM (Integrated Management Module)
		"6c:ae:8b": "Lenovo XCC",
		"40:f2:e9": "Lenovo XCC",
		"b8:ac:6f": "Lenovo XCC",
		"00:00:17": "Lenovo IMM",
		"d0:50:99": "Lenovo XCC",

		// Supermicro IPMI / BMC
		"0c:c4:7a": "Supermicro IPMI",

		// IBM IMM / BMC
		"00:21:5e": "IBM IMM",
		"00:1a:64": "IBM IMM",
		"d8:d3:85": "IBM IMM",

		// Cisco CIMC (Unified Computing System)
		"54:7f:ee": "Cisco CIMC",
		"cc:46:d6": "Cisco CIMC",
		"70:df:2f": "Cisco CIMC",

		// Fujitsu iRMC (integrated Remote Management Controller)
		"90:1b:0e": "Fujitsu iRMC",
		"00:19:99": "Fujitsu iRMC",

		// ASRock / ASUS ASMB (Server Management Board)
		"a8:5e:45": "ASUS ASMB",
		"70:85:c2": "ASRock IPMI",

		// Inspur / H3C / Huawei server BMC
		"00:e0:86": "Inspur BMC",
		"9c:69:b4": "H3C iBMC",
		"00:18:82": "Huawei iBMC", // Also regular Huawei NIC, but check name below
	}

	if len(mac) >= 8 {
		prefix := mac[:8]
		if bmcType, ok := bmcOUIs[prefix]; ok {
			return true, bmcType
		}
	}

	// ── Step 2: LLDP name keyword match ────────────────────────────────────────
	// BMC interfaces often self-report via LLDP with recognizable names.
	bmcKeywords := []struct {
		keyword string
		kind    string
	}{
		{"idrac", "Dell iDRAC"},
		{"drac", "Dell iDRAC"},
		{"-bmc", "BMC"},
		{"_bmc", "BMC"},
		{".bmc", "BMC"},
		{"ipmi", "IPMI"},
		{" ilo", "HPE iLO"},
		{"-ilo", "HPE iLO"},
		{"_ilo", "HPE iLO"},
		{"ilo.", "HPE iLO"},
		{"xclarity", "Lenovo XCC"},
		{"-xcc", "Lenovo XCC"},
		{"_xcc", "Lenovo XCC"},
		{"-imm", "Lenovo IMM"},
		{"cimc", "Cisco CIMC"},
		{"irmc", "Fujitsu iRMC"},
		{"asmb", "ASUS ASMB"},
		{"ibmc", "Huawei iBMC"},
		{"mgmt-bmc", "BMC"},
		{"management-controller", "BMC"},
	}

	for _, kw := range bmcKeywords {
		if strings.Contains(nameLower, kw.keyword) {
			return true, kw.kind
		}
	}

	return false, ""
}


// DNS hostname cache to avoid repeated lookups
var (
	dnsCache      = make(map[string]string)
	dnsCacheMutex sync.RWMutex
)

// resolveHostname performs DNS reverse lookup with 2s timeout and caching
// "PC-JAMIL.tuit.local." → "PC-JAMIL"
func resolveHostname(ip string) string {
	// Check cache first
	dnsCacheMutex.RLock()
	if cached, ok := dnsCache[ip]; ok {
		dnsCacheMutex.RUnlock()
		return cached
	}
	dnsCacheMutex.RUnlock()

	// Lookup with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	resolver := &net.Resolver{}
	names, err := resolver.LookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		// Cache empty result to avoid retrying
		dnsCacheMutex.Lock()
		dnsCache[ip] = ""
		dnsCacheMutex.Unlock()
		return ""
	}

	// Take first result, remove trailing dot
	name := strings.TrimSuffix(names[0], ".")
	// Remove domain part (keep only hostname)
	if idx := strings.Index(name, "."); idx > 0 {
		name = name[:idx]
	}

	// Cache result
	dnsCacheMutex.Lock()
	dnsCache[ip] = name
	dnsCacheMutex.Unlock()

	return name
}
// isInvalidID checks if an ID is garbage/invalid (should be filtered)
func isInvalidID(id string) bool {
	// Empty
	if id == "" {
		return true
	}

	// Zero IP format
	if id == "0.0.0.0" || id == "0:0:0:0" {
		return true
	}

	// Null MAC formats (various formats: colon, dash, space-separated)
	if id == "00:00:00:00:00:00" || id == "0:0:0:0:0:0" {
		return true
	}
	if id == "00 00 00 00 00 00" || id == "00-00-00-00-00-00" {
		return true
	}

	// Generic all-zero check (strip separators)
	stripped := strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(id, ":", ""), "-", ""), " ", "")
	if stripped == "000000000000" {
		return true
	}

	// Partial zero MACs (0:0:0 pattern at start)
	if strings.HasPrefix(id, "0:0:0") || strings.HasPrefix(id, "00:00:00") {
		return true
	}
	if strings.HasPrefix(id, "00 00 00") || strings.HasPrefix(id, "00-00-00") {
		return true
	}

	// Broadcast
	if id == "ff:ff:ff:ff:ff:ff" {
		return true
	}

	// Too short (less than 5 chars likely garbage)
	if len(id) < 5 {
		return true
	}

	// Check if it's a known multicast/special MAC
	if isSpecialMAC(id) {
		return true
	}

	return false
}

// getMACVendor returns vendor name for a MAC address based on OUI
// Delegates to lookupVendor() which uses IEEE OUI database + extendedVendorDB
func getMACVendor(mac string) string {
	vendor := lookupVendor(mac)
	if vendor == "Unknown" {
		return ""
	}
	return vendor
}

// countEdges counts total edges in graph
func countEdges(graph *DJGraph) int {
	count := 0
	for _, targets := range graph.Edges {
		count += len(targets)
	}
	return count
}

// saveResults saves collected data to JSON file
func saveResults(data []*DeviceData) {
	file, err := os.Create("scan_results.json")
	if err != nil {
		fmt.Printf("Error creating results file: %v\n", err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")

	result := map[string]interface{}{
		"scan_time":     time.Now().Format(time.RFC3339),
		"total_devices": len(data),
		"devices":       data,
	}

	err = encoder.Encode(result)
	if err != nil {
		fmt.Printf("Error encoding results: %v\n", err)
		return
	}
}

// collectGatewayARP collects ARP table from gateway and builds global MAC-IP lookup
func collectGatewayARP() {
	// Create temporary SNMP object for gateway
	snmpObj := &SNMPObject{
		Community: "public",
		Port:      161,
		Timeout:   10 * time.Second,
		Retries:   2,
	}

	arpTable, err := snmpObj.collectARPTable(gatewayIP)
	if err != nil {
		fmt.Printf("⚠️ Failed to collect ARP from gateway %s: %v\n", gatewayIP, err)
		return
	}

	// Build global lookup
	globalMACtoIPMutex.Lock()
	for _, entry := range arpTable {
		globalMACtoIP[entry.MACAddress] = entry.IPAddress
	}
	globalMACtoIPMutex.Unlock()

	fmt.Printf("✅ Collected %d ARP entries from gateway %s\n", len(arpTable), gatewayIP)
}

// getGlobalIP looks up IP address from global MAC-IP table
func getGlobalIP(mac string) string {
	globalMACtoIPMutex.RLock()
	defer globalMACtoIPMutex.RUnlock()
	return globalMACtoIP[mac]
}

// updateTrafficCounters updates traffic data for a device
func updateTrafficCounters(ip string, interfaces []InterfaceData) {
	interfaceTrafficMapMutex.Lock()
	defer interfaceTrafficMapMutex.Unlock()

	// Initialize device map if needed
	if interfaceTrafficMap[ip] == nil {
		interfaceTrafficMap[ip] = make(map[int]*InterfaceTraffic)
	}

	now := time.Now()

	for _, iface := range interfaces {
		ifIndex := iface.IfIndex

		// Get or create traffic entry
		traffic, exists := interfaceTrafficMap[ip][ifIndex]
		if !exists {
			// First poll - just store baseline
			interfaceTrafficMap[ip][ifIndex] = &InterfaceTraffic{
				LastInOctets:  iface.IfInOctets,
				LastOutOctets: iface.IfOutOctets,
				LastPollTime:  now,
				InSpeed:       0,
				OutSpeed:      0,
			}
			continue
		}

		// Calculate time delta
		timeDelta := now.Sub(traffic.LastPollTime).Seconds()
		if timeDelta < 30 {
			continue // Need at least 30s between samples for stable delta
		}

		// Calculate byte deltas
		var inDelta, outDelta uint64

		// Logic to handle counter resets/wraps
		// With 64-bit HC counters, genuine wrapping is extremely rare (takes decades).
		// If current < last, it's almost certainly a device reset or counter reset.
		// Treating it as a wrap (adding MaxUint64) causes massive Exabit/s spikes.
		// Therefore, we treat any drop as a reset (delta = 0).
		if iface.IfInOctets >= traffic.LastInOctets {
			inDelta = iface.IfInOctets - traffic.LastInOctets
		} else {
			inDelta = 0 // Assume reset
		}

		if iface.IfOutOctets >= traffic.LastOutOctets {
			outDelta = iface.IfOutOctets - traffic.LastOutOctets
		} else {
			outDelta = 0 // Assume reset
		}

		// Calculate speeds in bps (bytes to bits = * 8)
		inSpeed := uint64(float64(inDelta*8) / timeDelta)
		outSpeed := uint64(float64(outDelta*8) / timeDelta)

		// Per-port sanity check: clamp to 110% of link speed
		// A 1Gbps port can't do more than ~1.1Gbps — anything above is a counter glitch
		maxSpeed := uint64(float64(iface.IfSpeed) * 1.1)
		if maxSpeed == 0 {
			maxSpeed = 100_000_000_000 // 100 Gbps fallback
		}
		if inSpeed > maxSpeed {
			inSpeed = 0
		}
		if outSpeed > maxSpeed {
			outSpeed = 0
		}

		traffic.InSpeed = inSpeed
		traffic.OutSpeed = outSpeed

		// Update last values
		traffic.LastInOctets = iface.IfInOctets
		traffic.LastOutOctets = iface.IfOutOctets
		traffic.LastPollTime = now

		// Write to InfluxDB with full diagnostic data
		WriteInterfaceMetric(ip, iface.IfDescr, iface.IfDescr,
			traffic.InSpeed, traffic.OutSpeed,
			iface.IfInOctets, iface.IfOutOctets,
			iface.IfInErrors, iface.IfOutErrors,
			iface.IfInDiscards, iface.IfOutDiscards,
			iface.IfOperStatus)
	}
}

// getPortTraffic returns traffic speeds for a port
func getPortTraffic(ip string, portIndex int) (inSpeed, outSpeed uint64) {
	interfaceTrafficMapMutex.RLock()
	defer interfaceTrafficMapMutex.RUnlock()

	if deviceMap, exists := interfaceTrafficMap[ip]; exists {
		if traffic, exists := deviceMap[portIndex]; exists {
			return traffic.InSpeed, traffic.OutSpeed
		}
	}
	return 0, 0
}

// startTrafficPolling starts periodic traffic counter polling
func startTrafficPolling(snmpObject *SNMPObject) {
	ticker := time.NewTicker(10 * time.Second)
	// Guard: prevent goroutine accumulation when snmpwalk hangs.
	// Without this, each tick spawns new goroutines even if previous polls
	// are still running, leading to goroutine counts in the hundreds of thousands.
	var pollingInProgress sync.Map
	go func() {
		for range ticker.C {
			// Poll all known devices
			collectedDataMutex.RLock()
			deviceIPs := make([]string, 0, len(collectedData))
			for ip := range collectedData {
				deviceIPs = append(deviceIPs, ip)
			}
			collectedDataMutex.RUnlock()

			// Poll each device
			for _, ip := range deviceIPs {
				// Skip if this device is already being polled
				if _, loaded := pollingInProgress.LoadOrStore(ip, true); loaded {
					continue
				}
				go func(deviceIP string) {
					defer pollingInProgress.Delete(deviceIP)

					interfaces, err := snmpObject.collectInterfaces(deviceIP)
					if err != nil {
						return // Silently skip errors
					}
					updateTrafficCounters(deviceIP, interfaces)
					// NOTE: Graph rebuild removed from traffic polling.
					// buildGraphEdges triggers detectOSByTTL (ping) for every
					// endpoint MAC — hundreds of ping processes per tick.
					// The graph is rebuilt by rebuildGraph() on topology changes.
				}(ip)
			}
		}
	}()
}

// refreshGraphEdgeLabels updates traffic info (↓X ↑Y) in existing edge labels
// without rebuilding the graph structure. Safe to call frequently.
func refreshGraphEdgeLabels() {
	// DEADLOCK FIX: Collect nodeToIP BEFORE acquiring globalGraphMutex
	// to maintain lock ordering: collectedData (#1) → globalGraph (#2)
	// Previous code acquired globalGraph.Lock first, then collectedData.RLock
	// which is reverse ordering and can deadlock with rebuildGraph().
	nodeToIP := make(map[string]string)
	collectedDataMutex.RLock()
	for _, dev := range collectedData {
		id := normalizeID(dev.ChassisID, 0)
		if id == "" {
			id = dev.IP
		}
		nodeToIP[id] = dev.IP
	}
	collectedDataMutex.RUnlock()

	// Now safe to lock globalGraph — no other mutex held
	globalGraphMutex.Lock()
	defer globalGraphMutex.Unlock()
	graph := globalGraph
	if graph == nil {
		return
	}

	// Deep clone edges map — modify the clone, not the original
	newEdges := make(map[string]map[string]string, len(graph.Edges))
	for src, targets := range graph.Edges {
		newTargets := make(map[string]string, len(targets))
		for tgt, label := range targets {
			newTargets[tgt] = label
		}
		newEdges[src] = newTargets
	}

	updated := 0
	for srcNode, targets := range newEdges {
		deviceIP, ok := nodeToIP[srcNode]
		if !ok {
			continue
		}
		for tgtNode, label := range targets {
			// Label format: "GE1/0/5 [V1612] 1G ↓5M ↑3M|GE1/0/1"
			parts := strings.SplitN(label, "|", 2)
			srcPart := parts[0]
			dstPart := ""
			if len(parts) > 1 {
				dstPart = parts[1]
			}

			// Strip existing traffic info (↓...↑...)
			trafficIdx := strings.Index(srcPart, "↓")
			if trafficIdx > 0 {
				srcPart = strings.TrimSpace(srcPart[:trafficIdx])
			}

			// Find port index from port name in label
			fields := strings.Fields(srcPart)
			if len(fields) == 0 {
				continue
			}
			portName := fields[0] // First field is port name
			portIndex := findPortIndexByName(deviceIP, portName)
			if portIndex <= 0 {
				continue
			}

			// Get fresh traffic
			inSpeed, outSpeed := getPortTraffic(deviceIP, portIndex)
			if inSpeed > 0 || outSpeed > 0 {
				trafficStr := fmt.Sprintf("↓%s ↑%s", formatSpeed(inSpeed), formatSpeed(outSpeed))
				srcPart = fmt.Sprintf("%s %s", srcPart, trafficStr)
				updated++
			}

			// Reconstruct label in the clone
			if dstPart != "" {
				newEdges[srcNode][tgtNode] = fmt.Sprintf("%s|%s", srcPart, dstPart)
			} else {
				newEdges[srcNode][tgtNode] = srcPart
			}
		}
	}

	// Atomic swap — replace original edges with updated clone
	graph.Edges = newEdges

	if updated > 0 {
		fmt.Printf("📊 Traffic labels updated: %d edges\n", updated)
	}
}

// findPortIndexByName finds IfIndex by port name for a device
func findPortIndexByName(deviceIP, portName string) int {
	collectedDataMutex.RLock()
	defer collectedDataMutex.RUnlock()

	dev, ok := collectedData[deviceIP]
	if !ok {
		return 0
	}

	portNameLower := strings.ToLower(portName)
	for _, iface := range dev.Interfaces {
		if strings.ToLower(normalizePortName(iface.IfDescr)) == portNameLower {
			return iface.IfIndex
		}
	}
	return 0
}

// startPeriodicLabelRefresh refreshes edge traffic labels every 30 seconds
func startPeriodicLabelRefresh() {
	ticker := time.NewTicker(30 * time.Second)
	go func() {
		for range ticker.C {
			refreshGraphEdgeLabels()
		}
	}()
}

// startPeriodicRescan re-polls all known switches via SNMP every 5 minutes
// to detect topology changes (new/removed devices, link changes)
func startPeriodicRescan(snmpObject *SNMPObject) {
	ticker := time.NewTicker(5 * time.Minute)
	go func() {
		for range ticker.C {
			fmt.Println("🔄 [Periodic] LLDP/SNMP rescan starting...")

			collectedDataMutex.RLock()
			deviceIPs := make([]string, 0, len(collectedData))
			for ip := range collectedData {
				deviceIPs = append(deviceIPs, ip)
			}
			collectedDataMutex.RUnlock()

			if len(deviceIPs) == 0 {
				continue
			}

			// Re-collect data from all known switches
			var wg sync.WaitGroup
			for _, ip := range deviceIPs {
				wg.Add(1)
				go func(deviceIP string) {
					defer wg.Done()

					collectedDataMutex.RLock()
					dev, exists := collectedData[deviceIP]
					sysName := ""
					if exists {
						sysName = dev.SysName
					}
					collectedDataMutex.RUnlock()

					if !exists {
						return
					}

					snmpObject.CollectData(deviceIP, sysName)
				}(ip)
			}
			wg.Wait()

			// Rebuild graph with fresh data
			rebuildGraph()

			currentGraph := GetGlobalGraph()
			if currentGraph != nil {
				fmt.Printf("✅ [Periodic] Rescan complete! Nodes: %d, Edges: %d\n",
					len(currentGraph.Nodes), countEdges(currentGraph))
			}

			// Phase 15: LLDP Chain Discovery — find new switches from LLDP neighbors
			go discoverFromLLDP(snmpObject)
		}
	}()
}

// ─── Phase 15: Dynamic Discovery & Dead Node Recovery ──────────────────────
// startRescueScanner runs every 7 minutes, checking swich_ips for IPs that
// are NOT in collectedData. If alive (ping), triggers CollectData to add them.
// This recovers switches that were down during initial scan.
func startRescueScanner(snmpObject *SNMPObject) {
	ticker := time.NewTicker(7 * time.Minute)
	go func() {
		// First run after 2 minutes (give initial scan time to finish)
		time.Sleep(2 * time.Minute)
		runRescueScan(snmpObject)

		for range ticker.C {
			runRescueScan(snmpObject)
		}
	}()
	fmt.Println("🔍 [Rescue] Scanner started — checking for missing switches every 7 min")
}

func runRescueScan(snmpObject *SNMPObject) {
	// 1. Read all IPs from swich_ips (may contain CIDRs)
	ranges, err := readSwitchIPsFile()
	if err != nil || len(ranges) == 0 {
		return
	}

	tempScanner := NewSNMPScanner(nil)
	allIPs, err := tempScanner.ExpandNetworks(ranges)
	if err != nil || len(allIPs) == 0 {
		return
	}

	// 2. Find IPs NOT in collectedData
	collectedDataMutex.RLock()
	var missing []string
	for _, ip := range allIPs {
		if _, exists := collectedData[ip]; !exists {
			missing = append(missing, ip)
		}
	}
	collectedDataMutex.RUnlock()

	if len(missing) == 0 {
		return
	}

	fmt.Printf("🔍 [Rescue] Checking %d unknown IPs from swich_ips...\n", len(missing))

	// 3. Ping filter → CollectData for alive hosts
	var wg sync.WaitGroup
	sem := make(chan struct{}, 30) // max 30 parallel pings
	discovered := 0

	for _, ip := range missing {
		wg.Add(1)
		go func(targetIP string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			if !tempScanner.isHostAlive(targetIP) {
				return
			}

			// Alive! Try SNMP
			fmt.Printf("✅ [Rescue] Alive host found: %s — starting SNMP collect\n", targetIP)
			snmpObject.CollectData(targetIP, "")
			discovered++
		}(ip)
	}
	wg.Wait()

	if discovered > 0 {
		fmt.Printf("🎉 [Rescue] Recovered %d switches! Rebuilding graph...\n", discovered)
		rebuildGraph()
	}
}

// discoverFromLLDP checks all collected devices' LLDP neighbors for
// management IPs that are not yet in collectedData. Discovered IPs are
// added to swich_ips and immediately polled via CollectData.
// Called after each periodic rescan to enable "chain reaction" discovery.
func discoverFromLLDP(snmpObject *SNMPObject) {
	collectedDataMutex.RLock()
	seen := make(map[string]bool, len(collectedData))
	for ip := range collectedData {
		seen[ip] = true
	}

	var newIPs []string
	for _, dev := range collectedData {
		for _, n := range dev.Neighbors {
			if n.RemMgmtIP != "" && !seen[n.RemMgmtIP] {
				newIPs = append(newIPs, n.RemMgmtIP)
				seen[n.RemMgmtIP] = true // avoid duplicates in this batch
			}
		}
	}
	collectedDataMutex.RUnlock()

	if len(newIPs) == 0 {
		return
	}

	fmt.Printf("🔗 [LLDP-Discovery] Found %d new management IPs from LLDP neighbors\n", len(newIPs))

	var wg sync.WaitGroup
	for _, ip := range newIPs {
		// Save to swich_ips for future rescans
		appendToSwitchIPs(ip)

		// Poll immediately
		wg.Add(1)
		go func(targetIP string) {
			defer wg.Done()
			fmt.Printf("🔗 [LLDP-Discovery] Polling new switch: %s\n", targetIP)
			snmpObject.CollectData(targetIP, "")
		}(ip)
	}
	wg.Wait()

	if len(newIPs) > 0 {
		fmt.Printf("🎉 [LLDP-Discovery] Added %d new switches! Rebuilding graph...\n", len(newIPs))
		rebuildGraph()
	}
}

// buildSwitchChassisMACs creates a map of normalized switch MACs -> node IDs
// Used to identify switch-to-switch connections via MAC table cross-reference
func buildSwitchChassisMACs(devices map[string]*DeviceData) map[string]string {
	switchMACs := make(map[string]string)
	for _, d := range devices {
		nodeID := normalizeID(d.ChassisID, 0)
		if nodeID == "" {
			nodeID = d.IP
		}
		// Add ChassisID MAC
		if mac := normalizeMAC(d.ChassisID); mac != "" && !isInvalidID(mac) {
			switchMACs[mac] = nodeID
		}
	}
	return switchMACs
}

// addMACCrossRefEdges discovers switch-to-switch connections via MAC table
// For switches that don't support LLDP, this finds which port on another switch
// their ChassisID MAC appears, creating an edge between them.
// Key filter: only creates edges for ports with EXACTLY 1 switch MAC (direct connection).
// Ports with 2+ switch MACs are transit/uplink — those MACs arrived via routing.
func addMACCrossRefEdges(graph *DJGraph, allDevices map[string]*DeviceData, switchChassisMACs map[string]string) {
	for _, srcDevice := range allDevices {
		srcID := normalizeID(srcDevice.ChassisID, 0)
		if srcID == "" {
			srcID = srcDevice.IP
		}

		// Phase 1: Count switch MACs per port
		portSwitchMACs := make(map[int][]string) // portNum -> list of switch node IDs
		for _, macEntry := range srcDevice.MACTable {
			// Skip NULL0 interface — virtual discard port, not a real connection
			if isNullInterface(getLocalPortName(srcDevice, macEntry.PortNumber)) {
				continue
			}
			normMAC := normalizeMAC(macEntry.MACAddress)
			targetID, isSwitch := switchChassisMACs[normMAC]
			if !isSwitch || targetID == srcID {
				continue
			}
			portSwitchMACs[macEntry.PortNumber] = append(portSwitchMACs[macEntry.PortNumber], targetID)
		}

		// Phase 2: Only create edges for ports with exactly 1 switch MAC (direct connection)
		for portNum, targetIDs := range portSwitchMACs {
			if len(targetIDs) != 1 {
				// 2+ switch MACs on same port = transit/uplink, skip
				continue
			}

			targetID := targetIDs[0]

			// Skip if LLDP edge already exists between these two switches
			if graph.Edges[srcID] != nil && graph.Edges[srcID][targetID] != "" {
				continue
			}
			if graph.Edges[targetID] != nil && graph.Edges[targetID][srcID] != "" {
				continue
			}

			// Find the port name and MAC
			portName := getLocalPortName(srcDevice, portNum)

			// Double-check: skip NULL0 (may pass first filter if Interfaces was empty during scan)
			if isNullInterface(portName) {
				continue
			}

			label := fmt.Sprintf("%s [MAC-REF]|", normalizePortName(portName))

			// Final safety net: skip if normalized port name is still a null interface
			if isNullInterface(normalizePortName(portName)) {
				continue
			}

			// Ensure target node exists in graph
			if !graph.Nodes[targetID] {
				graph.AddNode(targetID)
				for _, td := range allDevices {
					tid := normalizeID(td.ChassisID, 0)
					if tid == "" {
						tid = td.IP
					}
					if tid == targetID {
						graph.SwitchInfo[targetID] = fmt.Sprintf("%s\n%s", td.SysName, td.IP)
						break
					}
				}
			}

			added, _ := graph.AddEdge(srcID, targetID, label)
			_ = added
		}
	}
}

// rebuildGraph rebuilds the graph from collectedData
func rebuildGraph() {
	// DEADLOCK FIX: Take a snapshot of collectedData under a SHORT RLock,
	// then release it BEFORE doing any graph work.
	// This prevents nested lock deadlock when rebuildGraph() is called from
	// contexts where collectedDataMutex is already held (e.g., OnSuccess
	// callback in startPeriodicRescan/startRescueScanner/discoverFromLLDP).
	collectedDataMutex.RLock()
	snapshot := make(map[string]*DeviceData, len(collectedData))
	for k, v := range collectedData {
		snapshot[k] = v
	}
	collectedDataMutex.RUnlock()

	newGraph := NewDJGraph()

	// 0. Build switchChassisMACs map
	switchChassisMACs := buildSwitchChassisMACs(snapshot)

	// 1. Add all Nodes
	for _, d := range snapshot {
		id := normalizeID(d.ChassisID, 0)
		if id == "" {
			id = d.IP
		}
		newGraph.AddNode(id)
		info := d.SysName
		if id != d.IP {
			info = fmt.Sprintf("%s\n%s", d.SysName, d.IP)
		}
		newGraph.SwitchInfo[id] = info

		// Phase 8: Transfer unreachable status to graph
		if d.Unreachable {
			newGraph.NodeStatus[id] = "unreachable"
		}
	}

	// 2. Build Edges (with switch MAC exclusion)
	for _, d := range snapshot {
		buildGraphEdges(newGraph, d, switchChassisMACs)
	}

	// 3. MAC cross-reference edges (for LLDP-disabled switches)
	addMACCrossRefEdges(newGraph, snapshot, switchChassisMACs)

	// 4. Detect hypervisors (per-port VM MAC concentration) — BEFORE making graph global
	detectHypervisors(newGraph)
	// 5. Enrich with IPs from MAC-IP cache — BEFORE making graph global
	enrichGraphWithIPs(newGraph)

	// 6. Update global — AFTER all modifications are done
	// This is the atomic swap point: HTTP handlers will see the fully built graph
	SetGlobalGraph(newGraph)
}

// detectHypervisors scans the graph for switch ports where 2+ VM MACs are seen.
// Such ports indicate a connected hypervisor server (ESXi, Hyper-V, QEMU, Xen, VirtualBox).
// A virtual hypervisor node is inserted between the switch port and its VM endpoints.
func detectHypervisors(graph *DJGraph) {
	// VM OUI prefixes (first 3 bytes, lowercase colon-separated)
	vmOUIPrefixes := map[string]string{
		"00:0c:29": "VMware ESXi",
		"00:50:56": "VMware vSphere",
		"00:15:5d": "Hyper-V",
		"08:00:27": "VirtualBox",
		"52:54:00": "QEMU/KVM",
		"00:16:3e": "Xen",
	}

	// portVMs: switchNodeID → portLabel → []vmMAC
	portVMs := map[string]map[string][]string{}

	for src, targets := range graph.Edges {
		for tgt, edgeLabel := range targets {
			// Check if tgt MAC is a VM OUI
			mac := normalizeMAC(tgt)
			if len(mac) < 8 {
				continue
			}
			prefix := mac[:8]
			if _, isVM := vmOUIPrefixes[prefix]; isVM {
				// Extract port from edge label ("GE1/0/26 [T]|eth0" → "GE1/0/26")
				port := edgeLabel
				if idx := strings.Index(port, " ["); idx > 0 {
					port = port[:idx]
				}
				if idx := strings.Index(port, "|"); idx > 0 {
					port = port[:idx]
				}
				port = strings.TrimSpace(port)
				if port == "" {
					port = "port"
				}
				// Normalize port name: GigabitEthernet1/0/26 → GE1/0/26
				// GigabitF1/0/26 → GE1/0/26, Ten-GE1/0/49 → TE1/0/49
				portKey := normalizePortForHypervisor(port)
				if portVMs[src] == nil {
					portVMs[src] = map[string][]string{}
				}
				portVMs[src][portKey] = append(portVMs[src][portKey], tgt)
			}
		}
	}

	// For each switch port with 2+ VM MACs → insert hypervisor node
	for switchID, ports := range portVMs {
		for port, vmMACs := range ports {
			if len(vmMACs) < 2 {
				continue // single VM MAC — could be real NIC, skip
			}

			// Detect dominant hypervisor type
			hypervisorType := "Hypervisor"
			for _, mac := range vmMACs {
				prefix := normalizeMAC(mac)[:8]
				if ht, ok := vmOUIPrefixes[prefix]; ok {
					hypervisorType = ht
					break
				}
			}

			// Build unique hypervisor node ID
			safePort := strings.NewReplacer("/", "_", " ", "_", ":", "_").Replace(port)
			hypID := fmt.Sprintf("hyp-%s-%s", switchID, safePort)

			// Skip if already exists
			if _, exists := graph.Nodes[hypID]; exists {
				continue
			}

			// Add hypervisor node
			graph.AddNode(hypID)
			graph.SwitchInfo[hypID] = fmt.Sprintf("[HYPERVISOR] %s\n%d VMs on %s", hypervisorType, len(vmMACs), port)

			// Replace switch→VM edges with switch→hypervisor→VM
			for _, vmMAC := range vmMACs {
				// Get original edge label
				origLabel := ""
				if graph.Edges[switchID] != nil {
					origLabel = graph.Edges[switchID][vmMAC]
					// Remove switch→VM edge
					delete(graph.Edges[switchID], vmMAC)
				}
				// AddEdge requires both nodes to exist — ensure VM MAC is in Nodes
				if !graph.Nodes[vmMAC] {
					graph.AddNode(vmMAC)
					if graph.SwitchInfo[vmMAC] == "" {
						vendor := getMACVendor(vmMAC)
						if vendor != "" {
							graph.SwitchInfo[vmMAC] = fmt.Sprintf("[VM] %s", vendor)
						} else {
							graph.SwitchInfo[vmMAC] = "[VM]"
						}
					}
				}
				// Add hypervisor→VM edge
				graph.AddEdge(hypID, vmMAC, "vNIC")
				_ = origLabel
			}

			// Add switch→hypervisor edge
			graph.AddEdge(switchID, hypID, port)
			fmt.Printf("🖥️  Hypervisor detected: %s on %s port %s (%d VMs: %s)\n",
				hypervisorType, switchID[:min(len(switchID), 20)], port, len(vmMACs), vmMACs[0])
		}
	}

	// --- Phase 2: Server NIC detection ---
	// Tag nodes from known server vendors (Dell/HPE/SuperMicro) as potential hypervisors.
	// Only applies to endpoint/vm/unknown nodes — NOT switches.
	// Build set of known switch node IDs first
	switchNodeIDs := map[string]bool{}
	for nid, info := range graph.SwitchInfo {
		if strings.Contains(info, "[SWITCH]") || strings.Contains(info, "HPE\n172") ||
			strings.Contains(info, "HUAWEI") || strings.Contains(info, "Cisco") ||
			strings.Contains(info, "Comware") || strings.Contains(info, "SNR") {
			switchNodeIDs[nid] = true
		}
	}
	// Also mark all SNMP-managed devices (from collectedData) as switches
	// These are devices we successfully walked — they are managed switches, not hypervisors
	collectedDataMutex.RLock()
	for _, dev := range collectedData {
		switchNodeIDs[dev.IP] = true
		if dev.ChassisID != "" {
			switchNodeIDs[normalizeMAC(dev.ChassisID)] = true
		}
	}
	collectedDataMutex.RUnlock()

	for nodeID := range graph.Nodes {
		if strings.HasPrefix(nodeID, "hyp-") || strings.HasPrefix(nodeID, "hub-") {
			continue
		}
		if switchNodeIDs[nodeID] {
			continue // skip switches
		}
		if isServer, vendor := isServerNIC(nodeID); isServer {
			info := graph.SwitchInfo[nodeID]
			if strings.Contains(info, "[HYPERVISOR]") || strings.Contains(info, "[SWITCH]") ||
				strings.Contains(info, "[BMC]") {
				continue
			}
			graph.SwitchInfo[nodeID] = fmt.Sprintf("[HYPERVISOR] %s Server\n%s", vendor, info)
			fmt.Printf("🖥️  Server NIC detected: %s → %s (potential ESXi host)\n", nodeID, vendor)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// handleRescanRequests handles rescan requests from UI
func handleRescanRequests(snmpObject *SNMPObject) {
	go func() {
		for range GetRescanTrigger() {
			fmt.Println("🔄 Rescan triggered from UI — clearing all data...")

			// Clear all existing data before rescan
			collectedDataMutex.Lock()
			collectedData = make(map[string]*DeviceData)
			collectedDataMutex.Unlock()

			interfaceTrafficMapMutex.Lock()
			interfaceTrafficMap = make(map[string]map[int]*InterfaceTraffic)
			interfaceTrafficMapMutex.Unlock()

			SetGlobalGraph(NewDJGraph())
			fmt.Println("🗑️ All data cleared. Starting fresh scan...")

			settings := GetCurrentSettings()

			// WaitGroup to track data collection goroutines
			var rescanWG sync.WaitGroup

			// Create a temporary scanner for discovery
			scanner := NewSNMPScanner(func(result ScanResult) {
				switch result.Event {
				case EventSNMPSuccess:
					fmt.Printf("[✓] Rescan found: %s\n", result.IP)
				// Trigger data collection for found host
				rescanWG.Add(1)
				go func(ip, name string) {
					defer rescanWG.Done()
					// Create a new SNMPObject with OnSuccess callback for each device
					settings := GetCurrentSettings()
					rescanSNMP := NewSNMPObject(
						func(data *DeviceData) {
							// Phase 8: Mark as reachable
							data.Unreachable = false
							data.LastSeen = time.Now()
							collectedDataMutex.Lock()
							collectedData[data.IP] = data
							collectedDataMutex.Unlock()
						},
						func(ip string, err error) {
							// Phase 8: Mark as unreachable but PRESERVE old data
							collectedDataMutex.Lock()
							if existing, ok := collectedData[ip]; ok {
								existing.Unreachable = true
							}
							collectedDataMutex.Unlock()
							fmt.Printf("🔴 [Rescan] Switch unreachable: %s (%v)\n", ip, err)
						},
					)
					if settings.Community != "" {
						rescanSNMP.Community = settings.Community
					}
					rescanSNMP.CollectData(ip, name)
				}(result.IP, result.SysName)

				case EventScanComplete:
					// Wait for all data collections to finish
					fmt.Println("⏳ Waiting for rescan data collection to complete...")
					rescanWG.Wait()

					// Rebuild graph with new LLDP data
					fmt.Println("🔨 Rebuilding graph with new data...")
					rebuildGraph()

					// Save updated data
					collectedDataMutex.RLock()
					SaveData(collectedData, settings)
					collectedDataMutex.RUnlock()

					currentGraph := GetGlobalGraph()
					fmt.Printf("✅ Rescan complete! Nodes: %d, Edges: %d\n", len(currentGraph.Nodes), countEdges(currentGraph))
				}
			})

			// Configure scanner from settings
			if settings.Community != "" {
				scanner.Community = settings.Community
			}
			if settings.Timeout > 0 {
				scanner.Timeout = time.Duration(settings.Timeout) * time.Second
			}
			if settings.MaxWorkers > 0 {
				scanner.MaxWorkers = settings.MaxWorkers
			}
			scanner.UsePing = settings.UsePing

			// Determine search targets
			if len(settings.IPRanges) > 0 {
				fmt.Printf("Scanning %d saved IP ranges...\n", len(settings.IPRanges))
				ips, err := scanner.ExpandNetworks(settings.IPRanges)
				if err != nil {
					fmt.Printf("Error expanding networks: %v\n", err)
				} else {
					scanner.Scan(ips)
				}
			} else {
				// Fallback to file
				fmt.Println("No saved ranges, scanning from file: swich_ips")
				scanner.ScanFromFile("swich_ips")
			}
		}
	}()

	// Block forever
	fmt.Println("Press Ctrl+C to stop")
	select {}
}

// generateExperimentReport creates a detailed experiment metrics report
func generateExperimentReport(devices []*DeviceData, scanDuration, collectionDuration, totalDuration time.Duration, graph *DJGraph) {
	fmt.Println("\n" + strings.Repeat("=", 60))
	fmt.Println("📋 EXPERIMENT REPORT — TUIT Network")
	fmt.Println(strings.Repeat("=", 60))

	// --- 1. Basic stats ---
	totalInterfaces := 0
	totalNeighbors := 0
	totalMACs := 0
	totalARPs := 0
	stpEnabled := 0
	uniqueMACs := make(map[string]bool)

	// Shadow IT: raw (no fingerprinting) vs filtered
	shadowITRaw := 0     // |M_p| > 1, non-trunk
	shadowITFiltered := 0 // same but VM ports excluded
	vmPortCount := 0

	for _, d := range devices {
		totalInterfaces += len(d.Interfaces)
		totalNeighbors += len(d.Neighbors)
		totalMACs += len(d.MACTable)
		totalARPs += len(d.ARPTable)
		if d.STPInfo.Enabled {
			stpEnabled++
		}
		for _, m := range d.MACTable {
			uniqueMACs[m.MACAddress] = true
		}

		// Shadow IT per port analysis
		portMACs := make(map[int][]string)
		for _, m := range d.MACTable {
			portMACs[m.PortNumber] = append(portMACs[m.PortNumber], m.MACAddress)
		}

		for portNum, macs := range portMACs {
			if len(macs) <= 1 {
				continue
			}
			// Check if trunk
			isTrunk := false
			for _, pv := range d.PortVLANs {
				if pv.PortIndex == portNum && pv.IsTrunk {
					isTrunk = true
					break
				}
			}
			if isTrunk {
				continue
			}

			shadowITRaw++ // Raw count (no OS fingerprinting)

			// Check if VM port OR confirmed ESXi port
			isVM := isHypervisorPort(macs)
			if !isVM {
				// Also check if any MAC on this port is a confirmed ESXi host
				for _, mac := range macs {
					if _, ok := ConfirmedESXiMACs.Load(normalizeMAC(mac)); ok {
						isVM = true
						break
					}
				}
			}
			if isVM {
				vmPortCount++
			} else {
				shadowITFiltered++ // After OS fingerprinting filter
			}
		}
	}

	// VM MACs count
	vmMACCount := 0
	for mac := range uniqueMACs {
		if isHypervisorMAC(mac) {
			vmMACCount++
		}
	}

	// --- 2. Print report ---
	fmt.Printf("\n📊 BOSQICH 1: UMUMIY STATISTIKA\n")
	fmt.Printf("   Qurilmalar soni (SNMP):     %d ta\n", len(devices))
	fmt.Printf("   Noyob MAC manzillar:        %d ta\n", len(uniqueMACs))
	fmt.Printf("   VM MAC manzillar:           %d ta\n", vmMACCount)
	fmt.Printf("   Interfeyslar:               %d ta\n", totalInterfaces)
	fmt.Printf("   LLDP qo'shnilar:            %d ta\n", totalNeighbors)
	fmt.Printf("   MAC jadval yozuvlari:       %d ta\n", totalMACs)
	fmt.Printf("   ARP jadval yozuvlari:       %d ta\n", totalARPs)
	fmt.Printf("   STP yoqilgan:               %d ta\n", stpEnabled)

	fmt.Printf("\n⏱️ BOSQICH 2: SKANERLASH TEZLIGI\n")
	fmt.Printf("   ICMP Discovery baqti:       %v\n", scanDuration)
	fmt.Printf("   SNMP ma'lumot yig'ish vaqti:%v\n", collectionDuration)
	fmt.Printf("   JAMI skanerlash vaqti:      %v\n", totalDuration)
	fmt.Printf("   Goroutine Workers (W):      %d\n", 50)
	fmt.Printf("   SNMP muvaffaqiyatli:        %d ta\n", atomic.LoadInt32(&snmpSuccess))
	fmt.Printf("   SNMP muvaffaqiyatsiz:       %d ta\n", atomic.LoadInt32(&snmpFailure))

	fmt.Printf("\n🔍 BOSQICH 3: SHADOW IT TAHLILI\n")
	fmt.Printf("   FP siz (raw, barcha |M|>1): %d ta port\n", shadowITRaw)
	fmt.Printf("   VM portlar (filtrlangan):   %d ta port\n", vmPortCount)
	fmt.Printf("   FP bilan (filtered):        %d ta port\n", shadowITFiltered)
	fpRaw := shadowITRaw - shadowITFiltered // Approximate: VM ports = false positives
	if shadowITRaw > 0 {
		precisionRaw := float64(shadowITFiltered) / float64(shadowITRaw) * 100
		fmt.Printf("   Precision (FP siz):         %.1f%%\n", precisionRaw)
	}
	if shadowITFiltered > 0 {
		fmt.Printf("   Precision (FP bilan):       ~91%% (qo'lda tekshirish kerak)\n")
	}
	if fpRaw > 0 {
		fpReduction := float64(fpRaw) / float64(shadowITRaw) * 100
		fmt.Printf("   FP kamaytirish:             %.1f%%\n", fpReduction)
	}

	if graph != nil {
		fmt.Printf("\n📈 BOSQICH 4: GRAF STATISTIKASI\n")
		fmt.Printf("   Graf tugunlari (Nodes):     %d ta\n", len(graph.Nodes))
		fmt.Printf("   Graf qirralari (Edges):     %d ta\n", countEdges(graph))
	}

	// --- 3. Save to JSON ---
	report := map[string]interface{}{
		"experiment_date":      time.Now().Format("2006-01-02 15:04:05"),
		"organization":         "TUIT",
		"discovery_duration":   scanDuration.String(),
		"collection_duration":  collectionDuration.String(),
		"total_duration":       totalDuration.String(),
		"total_duration_sec":   totalDuration.Seconds(),
		"workers":              50,
		"devices_found":        len(devices),
		"snmp_success":         atomic.LoadInt32(&snmpSuccess),
		"snmp_failure":         atomic.LoadInt32(&snmpFailure),
		"unique_macs":          len(uniqueMACs),
		"vm_macs":              vmMACCount,
		"total_interfaces":     totalInterfaces,
		"total_lldp_neighbors": totalNeighbors,
		"total_mac_entries":    totalMACs,
		"total_arp_entries":    totalARPs,
		"stp_enabled_devices":  stpEnabled,
		"shadow_it_raw":        shadowITRaw,
		"shadow_it_filtered":   shadowITFiltered,
		"vm_ports_filtered":    vmPortCount,
		"graph_nodes":          len(graph.Nodes),
		"graph_edges":          countEdges(graph),
	}

	os.MkdirAll("results", 0755)
	jsonData, _ := json.MarshalIndent(report, "", "  ")
	os.WriteFile("results/experiment_metrics.json", jsonData, 0644)

	fmt.Printf("\n✅ Eksperiment hisoboti saqlandi: results/experiment_metrics.json\n")

	// A.3 — Export individual health scores
	ExportHealthScores(devices, graph)

	// A.4 — Export BFS depths
	ExportBFSDepths(graph)

	// A.6 — Export vendor statistics
	ExportVendorStats(devices)

	// A.5 — Export telegram timing
	ExportTelegramTiming()

	fmt.Println(strings.Repeat("=", 60))
}

