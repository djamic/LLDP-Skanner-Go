package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"maps"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"slices"
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

	// Saved hosts, then the MAC-IP cache and the gateway ARP table, all before
	// the first graph is built (F51)
	var savedHosts map[string]*DeviceData
	if hasSavedHosts {
		savedHosts = savedData.Hosts
	}
	loadStartupData(savedHosts)

	// Start web server immediately in background (it serves the empty graph
	// until the first build below is published)
	go StartWebServer("8088")
	fmt.Println("🌐 Web server started on http://localhost:8088")

	// First graph from the saved hosts, with the cache's IP and DNS lines
	buildStartupGraph(savedHosts)

	// ============================================================
	// Mode dispatch: benchmark and monitor24h exit early
	// ============================================================
	if *modeFlag == "benchmark" {
		runBenchmark()
		os.Exit(0)
	}
	if *modeFlag == "monitor24h" && hasSavedHosts {
		// Start traffic monitoring in background
		snmpObj := newRescanSNMPObject()
		startTrafficPolling(snmpObj)
		startPeriodicLabelRefresh()
		startPeriodicRescan(snmpObj)
		startRescueScanner(snmpObj) // Phase 15: Dead Node Recovery
		// No startPeriodicAnalysis here: runMonitor24h runs the same analysis
		// and snapshot diff every minute, and two loops wrote every event and
		// network summary twice (F52).
		runMonitor24h()
		os.Exit(0)
	}
	// Note: if monitor24h but no saved data, normal scan runs first,
	// then monitor24h starts after EventScanComplete (see below)

	if hasSavedHosts {
		fmt.Println("📊 Loaded saved hosts. Use 'Rescan' in menu to refresh.")
		fmt.Println("🔄 Starting traffic monitoring...")

		// Create SNMP Object for traffic polling and rescans (its callbacks
		// store every rescan, F53)
		snmpObject := newRescanSNMPObject()
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
		snmpObject := newReactiveSNMPObject()

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

				// Start periodic analysis loop for alerts (monitor24h runs its
				// own per-minute analysis below, F52)
				if *modeFlag != "monitor24h" {
					go startPeriodicAnalysis()
				}

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

// loadStartupData runs the startup steps before the web server starts: the
// saved hosts (nil when there are none) go into collectedData with their
// traffic baselines; then the MAC-IP service loads its cache and starts, and
// the gateway ARP table is read. The first graph is built after that
// (buildStartupGraph), so it already has the IP and DNS lines (F51: they
// used to appear only after the first rescan).
func loadStartupData(savedHosts map[string]*DeviceData) {
	if len(savedHosts) > 0 {
		fmt.Println("📂 Found saved network data, loading...")

		// Populate collectedData from saved
		collectedDataMutex.Lock()
		for ip, data := range savedHosts {
			collectedData[ip] = data
			// Set traffic baseline
			updateTrafficCounters(ip, data.Interfaces)
		}
		collectedDataMutex.Unlock()
	}

	// MAC-IP Service: load cache and start background ARP collection
	// (covers gateway + all discovered switches)
	startMacIPService()

	// Collect ARP table from gateway first (legacy - also done by MacIPService)
	fmt.Printf("🔍 Collecting ARP table from gateway %s...\n", gatewayIP)
	collectGatewayARP()
}

// buildStartupGraph builds and publishes the first graph from the saved
// hosts that loadStartupData stored. Without saved hosts the first scan
// builds the graph as switches are collected.
func buildStartupGraph(savedHosts map[string]*DeviceData) {
	if len(savedHosts) == 0 {
		return
	}
	rebuildGraph()
	fmt.Printf("✅ Loaded %d hosts from saved data\n", len(savedHosts))
}

// storeCollectedDevice stores the data of a successful SNMP poll in
// collectedData and marks the switch reachable (the OnSuccess callbacks).
// The tables of walks that failed in this poll are kept from the previous
// poll (F57), and the traffic counters are only updated from interfaces
// walked just now.
func storeCollectedDevice(data *DeviceData) {
	// Phase 8: Mark as reachable
	data.Unreachable = false
	data.LastSeen = time.Now()
	collectedDataMutex.Lock()
	collectKeepPrevious(data, collectedData[data.IP])
	collectedData[data.IP] = data
	collectedDataMutex.Unlock()
	if !data.collectWalkFailed(collectWalkInterfaces) {
		updateTrafficCounters(data.IP, data.Interfaces)
	}
}

// markUnreachable flags a known switch as unreachable after a failed poll
// and keeps its last data (the OnFailure callbacks). The struct is replaced,
// not changed: snapshots and the analyzer read the stored pointers without
// the lock.
func markUnreachable(ip string) {
	// Phase 8: Mark as unreachable but PRESERVE old data
	collectedDataMutex.Lock()
	defer collectedDataMutex.Unlock()
	if existing, ok := collectedData[ip]; ok {
		marked := *existing
		marked.Unreachable = true
		// LastSeen stays unchanged — keeps last successful poll time
		collectedData[ip] = &marked
	}
}

// newRescanSNMPObject returns the SNMP object for traffic polling and
// rescans when saved data was loaded (normal and monitor24h mode): every
// poll is stored (storeCollectedDevice) and a failed poll marks the switch
// unreachable. Normal mode used to pass nil callbacks and threw every
// periodic, rescue and LLDP-discovery rescan away (F53).
func newRescanSNMPObject() *SNMPObject {
	return NewSNMPObject(storeCollectedDevice, func(ip string, err error) {
		markUnreachable(ip)
		fmt.Printf("🔴 [Monitor] Switch unreachable: %s (%v)\n", ip, err)
	})
}

// newReactiveSNMPObject returns the SNMP object of the first scan in normal
// mode without saved hosts: every collected switch updates the graph at once
// (handleReactiveDevice) and the analysis runs on the new graph.
func newReactiveSNMPObject() *SNMPObject {
	return NewSNMPObject(
		// OnSuccess callback
		func(data *DeviceData) {
			newGraph := handleReactiveDevice(data)

			// 7. Run Analyze() immediately so health_score is available in /api/graph
			startLiveAnalysis(newGraph)
		},
		// OnFailure callback
		func(ip string, err error) {
			fmt.Printf("[❌] Data collection failed for %s: %v\n", ip, err)
			atomic.AddInt32(&dataCollected, 1)
			markUnreachable(ip)
		},
	)
}

// startLiveAnalysis runs analyzeLiveGraph in the background. Tests replace it
// so that no analysis outlives a test.
var startLiveAnalysis = func(graph *DJGraph) { go analyzeLiveGraph(graph) }

// analyzeLiveGraph runs Analyze() on collectedData and graph, which sets the
// health score and anomalies that /api/graph serves.
func analyzeLiveGraph(graph *DJGraph) {
	collectedDataMutex.RLock()
	var devSlice []DeviceData
	for _, d := range collectedData {
		devSlice = append(devSlice, *d)
	}
	collectedDataMutex.RUnlock()
	fd := FullCaptureData{
		Session:     CaptureSession{ID: "live", Name: "Live", StartTime: time.Now()},
		DevicesData: devSlice,
		Topology:    graph.GetGraphData(),
	}
	a := NewAnalyzer(fd)
	r := a.Analyze()
	fmt.Printf("📊 [HealthScore] %d/100 (%s)\n", r.HealthScore, GetHealthLabel(r.HealthScore))
}

// handleReactiveDevice is the OnSuccess work of the first scan: it stores the
// switch, then rebuilds and publishes the graph and returns it. CollectData
// runs in one goroutine per switch, so calls overlap; rebuildGraph publishes
// their graphs in the order of their snapshots.
func handleReactiveDevice(data *DeviceData) *DJGraph {
	atomic.AddInt32(&dataCollected, 1)

	// Store data for later processing: marks it reachable, keeps the tables
	// of failed walks (F57) and sets the traffic baseline for the first poll
	storeCollectedDevice(data)

	fmt.Printf("[📊] %s (%s) - %d interfaces, %d neighbors, ChassisID: %s\n",
		data.IP, data.SysName, len(data.Interfaces), len(data.Neighbors), data.ChassisID)

	// REACTIVE: Rebuild graph from current collected data.
	// rebuildGraph finishes the whole graph (hypervisors and IP
	// labels included) before it publishes it, like the periodic
	// rescans, so HTTP handlers never see a half-built graph.
	newGraph := rebuildGraph()
	fmt.Printf("  [GRAPH STATE] Nodes: %d, Edges: %d\n", len(newGraph.Nodes), countEdges(newGraph))
	return newGraph
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

// Helper to normalize Chassis IDs based on Subtype (RFC 2922)
func normalizeID(id string, subtype int) string {
	id = cleanSNMPValue(id)
	if id == "" {
		return ""
	}

	switch subtype {
	case 4: // MAC Address (6 bytes)
		// Input could be "4C AE A3 8E 42 11", any other MAC spelling or raw bytes
		if mac := canonicalMAC(id); mac != "" {
			return mac
		}
		if len(id) == 6 {
			// Raw 6 bytes (STRING octets)
			m, _ := parseMACOctets(id)
			return m.String()
		}
		// Already formatted — normalize
		return normalizeMAC(id)

	case 5: // Network Address: IANA family byte + address ("01 AC 10 01 0F")
		// Raw address bytes
		if len(id) == 4 { // IPv4
			return net.IP([]byte(id)).String()
		}
		if len(id) == 16 { // IPv6
			return net.IP([]byte(id)).String()
		}
		// Hex text; "" when it is no complete IPv4/IPv6 address
		return graphNetworkAddress(id)

	case 7: // Locally Assigned (string identifier)
		// Sometimes devices send a MAC like "f4-b5-20-19-12-5e" or
		// "FA EF EF EF AA 4F": normalize anything that spells a MAC
		if mac := canonicalMAC(id); mac != "" {
			return mac
		}
		if isPrintableString(id) {
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

// graphIsSNMPException reports whether a value is net-snmp exception text
// ("No Such Object available on this agent at this OID", "No Such Instance
// …", "No more variables …"), raw or as normalizeMAC left it in saved data.
func graphIsSNMPException(s string) bool {
	s = strings.ToLower(strings.Trim(strings.TrimSpace(s), "\""))
	s = strings.ReplaceAll(s, ":", " ")
	return strings.HasPrefix(s, "no such object") || strings.HasPrefix(s, "no such instance") ||
		strings.HasPrefix(s, "no more variables")
}

// graphLocalChassisID normalizes a switch's own lldpLocChassisId value (SNMP
// exception text must be rejected before): any MAC spelling becomes
// canonical, a 6-byte STRING is the MAC's raw octets (parseMACOctets, the
// form neighbors and the FDB see), other STRING text stays as written, and
// any other value keeps the normalizeMAC form.
func graphLocalChassisID(val string) string {
	if mac := canonicalMAC(val); mac != "" {
		return mac
	}
	v := strings.TrimSpace(val)
	if len(v) < 2 || v[0] != '"' || v[len(v)-1] != '"' {
		return normalizeMAC(v)
	}
	if m, ok := parseMACOctets(v); ok {
		return m.String()
	}
	return strings.TrimSpace(v[1 : len(v)-1])
}

// graphChassisKey is a switch's own-MAC key: its chassis id as a canonical
// MAC, or "" when the chassis id is not a MAC (exception text, a name) or is
// the null or broadcast address.
func graphChassisKey(chassisID string) string {
	m, ok := parseMAC(chassisID)
	if !ok || m.IsNull() || m.IsBroadcast() {
		return ""
	}
	return m.String()
}

// graphDeviceNodeID is the graph node id of a polled device: the chassis MAC
// in canonical form, a non-MAC chassis id as normalizeID gives it, or the
// device IP when the chassis id is empty, SNMP exception text or the null
// MAC. Every place that needs a switch's node id uses it.
func graphDeviceNodeID(d *DeviceData) string {
	if key := graphChassisKey(d.ChassisID); key != "" {
		return key
	}
	if graphIsSNMPException(d.ChassisID) || canonicalMAC(d.ChassisID) != "" {
		return d.IP
	}
	if id := normalizeID(d.ChassisID, 0); id != "" {
		return id
	}
	return d.IP
}

// graphNetworkAddress decodes an LLDP network-address id (chassis subtype 5,
// port subtype 4): an IANA address family byte and the address, printed as
// hex ("01 AC 10 01 0F" is IPv4 172.16.1.15). Anything else gives "".
func graphNetworkAddress(id string) string {
	var b []byte
	for _, f := range strings.FieldsFunc(id, func(r rune) bool { return r == ' ' || r == ':' }) {
		octet, err := hex.DecodeString(f)
		if err != nil || len(octet) != 1 {
			return ""
		}
		b = append(b, octet[0])
	}
	switch {
	case len(b) == 5 && b[0] == 1:
		return net.IP(b[1:]).String()
	case len(b) == 17 && b[0] == 2:
		return net.IP(b[1:]).String()
	}
	return ""
}

// graphNormalizePortID normalizes an LLDP port id with the port subtype
// table (1 interfaceAlias, 2 portComponent, 3 macAddress, 4 networkAddress,
// 5 interfaceName, 6 agentCircuitId, 7 local), not the chassis one: only
// a MAC port id (or a MAC-looking local one) gives a MAC, names stay names.
func graphNormalizePortID(id string, subtype int) string {
	switch subtype {
	case 3:
		return normalizeID(id, 4)
	case 4:
		return normalizeID(id, 5)
	case 7:
		return normalizeID(id, 7)
	case 1, 2, 5, 6:
		return cleanSNMPValue(id)
	default:
		return normalizeID(id, 0)
	}
}

// graphUsableTargetID reports whether an LLDP target may be a node id: a
// station MAC (usableMAC: not null, broadcast, multicast or zero-OUI), or a
// printable name or IP of 5 or more characters that is not all zeros. Names
// get no MAC bit tests ('B-318/1', 'E109-9' and '173.16.1.15' are kept).
func graphUsableTargetID(id string) bool {
	if canonicalMAC(id) != "" {
		return usableMAC(id) != ""
	}
	return isPrintableString(id) && len(id) >= 5 && strings.Trim(id, "0.:- ") != ""
}

// resolveLLDPTarget picks the graph node id and display name for one LLDP
// neighbor: the chassis id when it is a usable MAC (a locally assigned one
// only when the port id is no MAC); otherwise the port id when that is a MAC
// (RemSysName, or a chassis id that is no MAC, becomes the display name);
// otherwise the chassis id itself (a hostname or IP; "" if it is an unusable
// MAC). A null or MAC-looking chassis id is never the display name.
func resolveLLDPTarget(neighbor LLDPNeighbor) (targetID, displayName string) {
	chassisID := lldpChassisID(neighbor)
	portID := lldpPortID(neighbor)
	chassisMAC := usableMAC(chassisID)
	portMAC := usableMAC(portID)
	chassisIsName := canonicalMAC(chassisID) == ""

	if chassisMAC != "" && (neighbor.RemChassisIdSubtype != 7 || portMAC == "") {
		// ChassisID is MAC - use it
		return chassisMAC, neighbor.RemSysName
	}
	if portMAC != "" {
		// ChassisID is hostname, but PortID is MAC - use PortID as node ID
		displayName = neighbor.RemSysName
		if displayName == "" && chassisIsName {
			displayName = chassisID // Use hostname from ChassisID for display
		}
		return portMAC, displayName
	}
	if !chassisIsName {
		return "", neighbor.RemSysName // a null or multicast chassis MAC
	}
	// No MAC found - use ChassisID as fallback (could be hostname or IP)
	return chassisID, neighbor.RemSysName
}

// lldpChassisID is the normalized chassis id resolveLLDPTarget works with.
func lldpChassisID(neighbor LLDPNeighbor) string {
	return normalizeID(neighbor.RemChassisId, neighbor.RemChassisIdSubtype)
}

// lldpPortID is the normalized port id resolveLLDPTarget checks for a port
// MAC, read with the port subtype table (graphNormalizePortID).
func lldpPortID(neighbor LLDPNeighbor) string {
	return graphNormalizePortID(neighbor.RemPortId, neighbor.RemPortIdSubtype)
}

// lldpKnownMACs returns the MACs that buildGraphEdges treats as known from
// LLDP: the resolved targets of the neighbors the graph accepts (F46). FDB
// entries with these MACs get no endpoint node.
func lldpKnownMACs(data *DeviceData) map[string]bool {
	knownMACs := make(map[string]bool)
	for _, n := range data.Neighbors {
		if targetID, _, ok := graphLLDPNeighborTarget(data, n); ok {
			knownMACs[targetID] = true
		}
	}
	return knownMACs
}

// buildGraphEdges builds graph edges using ChassisID as the primary key
// switchChassisMACs maps normalized MAC -> switch node ID (to exclude switch MACs from endpoint creation)
func buildGraphEdges(graph *DJGraph, data *DeviceData, switchChassisMACs map[string]string) {
	logDebug("Analyzing Edges for Host: %s (%s) [Chassis: %s]", data.IP, data.SysName, data.ChassisID)

	// Source Node: the switch's chassis MAC, or its IP (graphDeviceNodeID)
	srcID := graphDeviceNodeID(data)

	// Ensure Source Node exists (should be added in main loop, but safety check)
	if !graph.Nodes[srcID] {
		graphAddSwitchNode(graph, data)
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

	// Add LLDP neighbors as edges
	logDebug("  Found %d LLDP neighbors", len(data.Neighbors))
	for _, neighbor := range data.Neighbors {
		// Determine Target ID - prefer MAC address for uniqueness; skip
		// garbage targets and NULL0 ports (before the node is made, so no
		// orphan node is left)
		targetID, displayName, ok := graphLLDPNeighborTarget(data, neighbor)
		if !ok {
			logDebug("    -> SKIPPED: TargetID '%s' for neighbor on port %d (empty, garbage or NULL0 port)", targetID, neighbor.LocalPortNum)
			continue
		}
		localPort := getLocalPortName(data, neighbor.LocalPortNum)
		graphAddSysText(graph, targetID, neighbor.RemSysName, neighbor.RemSysDesc)

		logDebug("    -> Neighbor: %s (ID: %s) via LocalPort: %d", displayName, targetID, neighbor.LocalPortNum)

		// ENHANCED DISCOVERY: Create LLDP Endpoint if target not scanned
		if !graph.Nodes[targetID] {
			graph.AddNode(targetID)

			// Get vendor from MAC if targetID is a MAC ("" for a name or IP)
			vendor := getMACVendor(targetID)

			// Build info from LLDP neighbor data with [LLDP-EP] marker
			var info string

			// DNS name of the neighbor (when its IP is known), for the BMC check
			dnsName := ""
			if ip := macToIP[targetID]; ip != "" {
				dnsName = resolveHostname(ip)
			}

			// Check BMC/management interface FIRST (LLDP name, DNS name)
			if bmcDetected, bmcType := graphIsBMC(targetID, displayName, dnsName); bmcDetected {
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

	// Process MAC Address Table - create endpoint nodes, with the per-port
	// rule the Shadow-IT alerts, metrics and reports share (fdbPorts).
	// Ports come in ascending order, so when a MAC is seen on two ports the
	// node is created (first creator wins) by the same port on every build.
	for _, p := range fdbPorts(data, switchChassisMACs) {
		portName := getLocalPortName(data, p.Port)
		if p.Kind == fdbHub {
			// Non-VM hub: create aggregated hub node; every member gets a
			// node (a hub has at most 20 MACs)
			nodeID := fmt.Sprintf("hub-%s-p%d", srcID, p.Port)
			nodeLabel := fmt.Sprintf("[HUB] Unmanaged\n%d devices", len(p.MACs))
			edgeLabel := fmt.Sprintf("%s|Hub", normalizePortName(portName))

			if !graph.Nodes[nodeID] {
				graph.AddNode(nodeID)
				graph.SwitchInfo[nodeID] = nodeLabel
			}
			graph.AddEdge(srcID, nodeID, edgeLabel)

			for _, mac := range p.MACs {
				graphAddFDBEndpoint(graph, data, macToIP, nodeID, mac, "")
			}
			continue
		}

		// Direct endpoints (few MACs, a VM port or an ESXi host's port):
		// every MAC is linked to the switch, so detectHypervisors() can put
		// the VMs under a hyp- node. Edge label: "GE1/0/5 [V10]|".
		// Do NOT create aggregated vm- node here — that conflicts with detectHypervisors.
		portLabel := normalizePortName(portName)
		if vlanStr := getPortVLANLabel(data.PortVLANs, p.Port); vlanStr != "" {
			portLabel = fmt.Sprintf("%s %s", portLabel, vlanStr)
		}
		for _, mac := range p.MACs {
			graphAddFDBEndpoint(graph, data, macToIP, srcID, mac, portLabel+"|")
		}
	}
}

// graphLLDPNeighborTarget resolves one LLDP neighbor of a switch to its node
// id and display name; ok is false when the graph drops the neighbor (no
// usable target, or a NULL0/"Port 0" local port).
func graphLLDPNeighborTarget(data *DeviceData, n LLDPNeighbor) (targetID, displayName string, ok bool) {
	targetID, displayName = resolveLLDPTarget(n)
	ok = graphUsableTargetID(targetID) && !isNullInterface(getLocalPortName(data, n.LocalPortNum))
	return targetID, displayName, ok
}

// fdbPortKind is what the per-port FDB rule (fdbPorts) makes of the MACs a
// switch learned on one port.
type fdbPortKind int

const (
	fdbDirect   fdbPortKind = iota // few MACs: each one is linked to the switch
	fdbHub                         // an unmanaged switch or hub: Shadow IT
	fdbVMPort                      // most MACs are virtual NICs: a hypervisor host
	fdbESXiPort                    // a hub candidate with an HTTP-confirmed ESXi host
)

// fdbPort is one port of a switch's FDB under the per-port rule.
type fdbPort struct {
	Port int
	MACs []string // canonical, after the rule's filters
	Kind fdbPortKind
	// Candidate: at least 2 MACs on a port that has no accepted LLDP
	// neighbor and is no trunk or uplink, so a hub unless it is a VM or
	// ESXi port (the experiment's shadow_it_raw counts these)
	Candidate bool
}

// fdbPorts is the one per-port Shadow-IT rule (Q14): the graph's hub nodes,
// the analyzer's Shadow-IT alerts, the experiment metrics and the audit
// report's Shadow-IT section all come from it, so the map, the alerts, the
// reports and the UI (which lists the graph's hubs) agree. It returns the
// FDB ports of one switch in port order; ports that get no nodes are left
// out. The MACs of a port are its FDB entries minus non-MACs, LLDP-known
// neighbors, the switch's own and other polled switches' chassis MACs and
// isInvalidID ones. A port with an accepted LLDP neighbor or a NULL0 name
// gets nothing. A VM-majority port is direct (also on a trunk or with more
// than 20 MACs, unless another switch's MAC is learned there); a VLAN trunk
// or a port with more than 20 MACs is otherwise an uplink (nothing, or
// direct for at most 3 MACs); 2-20 MACs are a hub unless one is an
// HTTP-confirmed ESXi host (ESXi exemption).
func fdbPorts(data *DeviceData, switchChassisMACs map[string]string) []fdbPort {
	// MACs already known via LLDP, and the ports with an accepted neighbor
	knownMACs := lldpKnownMACs(data)
	lldpPorts := make(map[int]bool)
	for _, n := range data.Neighbors {
		if _, _, ok := graphLLDPNeighborTarget(data, n); ok {
			lldpPorts[n.LocalPortNum] = true
		}
	}

	// NULL0/InLoopBack ports, looked up once per port (the alerts run this
	// rule on every FDB row of every switch)
	nullPorts := make(map[int]bool)
	isNullPort := func(port int) bool {
		null, seen := nullPorts[port]
		if !seen {
			null = isNullInterface(getLocalPortName(data, port))
			nullPorts[port] = null
		}
		return null
	}

	// Track MACs per port for Virtual Hub detection, and the ports where
	// another polled switch's MAC is learned (switch links)
	portMACs := make(map[int][]string)
	portSeesSwitch := make(map[int]bool)
	ownMAC := graphChassisKey(data.ChassisID)
	for _, macEntry := range data.MACTable {
		// The canonical MAC is both the node id and the key of every check
		normMAC := canonicalMAC(macEntry.MACAddress)
		if normMAC == "" {
			continue // not a MAC
		}

		// Skip NULL0 interface — virtual discard port, not a real connection
		if isNullPort(macEntry.PortNumber) {
			continue
		}

		// Skip if this MAC is already known via LLDP
		if knownMACs[normMAC] {
			continue
		}

		// Skip switch's own MACs (usually ports have their own MACs)
		if normMAC == ownMAC {
			continue
		}

		// Skip if this MAC belongs to another known switch (handled by MAC cross-ref)
		if _, isSwitch := switchChassisMACs[normMAC]; isSwitch {
			portSeesSwitch[macEntry.PortNumber] = true
			continue
		}

		// Skip special/invalid MAC addresses (use robust check)
		if isInvalidID(normMAC) {
			continue
		}

		portMACs[macEntry.PortNumber] = append(portMACs[macEntry.PortNumber], normMAC)
	}

	var out []fdbPort
	for _, portNum := range slices.Sorted(maps.Keys(portMACs)) {
		macs := portMACs[portNum]
		// Skip if this port already has LLDP neighbors (accepted ones)
		if lldpPorts[portNum] {
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
			logDebug("       [UPLINK] Port %d on %s has %d MACs — treating as implicit uplink", portNum, data.IP, len(macs))
		}

		// A port where most MACs are virtual NICs is a hypervisor host (ESXi,
		// Proxmox, KVM), also on a VLAN trunk or with more than 20 MACs: ESXi
		// hosts sit on trunk ports. A trunk or big port where another switch's
		// MAC is learned is a switch link, though, whatever it carries.
		vmPort := len(macs) >= 2 && isHypervisorPort(macs) && (!isTrunkPort || !portSeesSwitch[portNum])
		candidate := len(macs) >= 2 && !isTrunkPort

		port := fdbPort{Port: portNum, MACs: macs, Candidate: candidate}
		switch {
		case vmPort:
			port.Kind = fdbVMPort
		case candidate && graphPortHasConfirmedESXi(macs):
			// a port with an HTTP-confirmed ESXi host is never a Shadow-IT hub
			port.Kind = fdbESXiPort
		case candidate:
			port.Kind = fdbHub
		case len(macs) <= 3:
			// Few MACs - direct endpoint nodes
			port.Kind = fdbDirect
		default:
			continue // uplink: no nodes
		}
		out = append(out, port)
	}
	return out
}


// graphIsConfirmedESXi reports whether id is the MAC of an ESXi host
// confirmed by the HTTP probe.
func graphIsConfirmedESXi(id string) bool {
	_, ok := ConfirmedESXiMACs.Load(normalizeMAC(id))
	return ok
}

// graphPortHasConfirmedESXi reports whether one of a port's MACs is an
// HTTP-confirmed ESXi host.
func graphPortHasConfirmedESXi(macs []string) bool {
	return slices.ContainsFunc(macs, graphIsConfirmedESXi)
}

// graphIsBMC runs the BMC check with each known name of a device (LLDP
// display name, DNS name) and finally with no name.
func graphIsBMC(mac string, names ...string) (bool, string) {
	for _, name := range names {
		if name == "" {
			continue
		}
		if ok, kind := isBMC(mac, name); ok {
			return ok, kind
		}
	}
	return isBMC(mac, "")
}

// graphFDBEndpointLabel is the label of a MAC learned from the FDB (direct
// port, VM port or hub member): "[VM] <os>" for a virtual NIC (checked before
// the random-MAC rule), else "[BMC] <type>" (DNS name checked too), "[WiFi]"
// for a random MAC or "[ENDPOINT]"; then the vendor, the IP and the DNS name.
func graphFDBEndpointLabel(mac string, macToIP map[string]string, data *DeviceData) string {
	ip := macToIP[mac]
	hostname := ""
	if ip != "" {
		hostname = resolveHostname(ip)
	}
	info := "[ENDPOINT]"
	if isHypervisorMAC(mac) {
		info = fmt.Sprintf("[VM] %s", detectOSFromMAC(mac, macToIP, data))
	} else if bmcDetected, bmcType := graphIsBMC(mac, hostname); bmcDetected {
		info = fmt.Sprintf("[BMC] %s", bmcType)
	} else if isRandomMAC(mac) {
		info = "[WiFi]"
	}
	if vendor := getMACVendor(mac); vendor != "" {
		info = fmt.Sprintf("%s %s", info, vendor)
	}
	if ip != "" {
		info = fmt.Sprintf("%s\n%s", info, ip)
		if hostname != "" {
			info = fmt.Sprintf("%s\n[DNS] %s", info, hostname)
		}
	}
	return info
}

// graphLabelIP is the first label line that is an IP address, or "".
func graphLabelIP(info string) string {
	for _, line := range strings.Split(info, "\n") {
		if net.ParseIP(line) != nil {
			return line
		}
	}
	return ""
}

// graphAddFDBEndpoint creates the node of an FDB MAC unless an earlier port
// or switch created it (first creator wins) and links it from parent (the
// switch or a hub node) with label.
func graphAddFDBEndpoint(graph *DJGraph, data *DeviceData, macToIP map[string]string, parent, mac, label string) {
	if !graph.Nodes[mac] {
		graph.AddNode(mac)
		graph.SwitchInfo[mac] = graphFDBEndpointLabel(mac, macToIP, data)
		logDebug("       [NEW NODE] Created MAC endpoint node: %s", mac)
	}
	if added, _ := graph.AddEdge(parent, mac, label); added {
		logDebug("       [NEW EDGE] Added MAC endpoint link: %s -> %s", parent, mac)
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
// IfDescr is stored quoted ("\"NULL0\""), so quotes are ignored (F61).
func isNullInterface(name string) bool {
	low := strings.ToLower(strings.Trim(name, "\" \t"))
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
			recordSnapshotDiff(previousSnapshot, currentSnapshot, &report)
		}
		previousSnapshot = currentSnapshot
		previousSnapshotMutex.Unlock()
	}
}

// recordSnapshotDiff compares two snapshots, logs the changes (UI event log)
// and writes the JOIN/LEAVE events and the network summary to InfluxDB.
// Shared by startPeriodicAnalysis and runMonitor24h.
func recordSnapshotDiff(prev, curr *NetworkSnapshot, report *Report) {
	diff := CompareSnapshots(prev, curr)
	diff.LogChanges()

	// B.2: Write JOIN/LEAVE events to InfluxDB
	for _, joined := range diff.JoinedMACs {
		WriteDeviceEvent("join", joined.MAC, joined.IP, joined.SwitchIP, joined.Vendor)
	}
	for _, left := range diff.LeftMACs {
		WriteDeviceEvent("leave", left.MAC, left.IP, left.SwitchIP, left.Vendor)
	}

	// B.3: Write network summary to InfluxDB
	WriteNetworkSummary(
		len(curr.ActiveHosts),
		len(curr.ActiveMACs),
		report.Summary["shadow_it_issues"],
		curr.HealthScore,
		countRandomMACs(curr),
	)
}

// countRandomMACs counts the snapshot MACs that isRandomMAC flags (the
// random_macs field of the InfluxDB network summary).
func countRandomMACs(snapshot *NetworkSnapshot) int {
	randomMACCount := 0
	for mac := range snapshot.ActiveMACs {
		if isRandomMAC(mac) {
			randomMACCount++
		}
	}
	return randomMACCount
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
			// Log the diff and write it to InfluxDB
			recordSnapshotDiff(prevSnapshot, currentSnapshot, &report)
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

// runPing sends the single ping used by detectOSByTTL and returns its output.
// Tests replace it so no packets are sent.
var runPing = pingOnce

// pingOnce runs "ping -c 1 -W 1 ip" (killed after 3s) and returns its stdout.
func pingOnce(ip string) (string, error) {
	cmd := exec.Command("ping", "-c", "1", "-W", "1", ip)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	var outBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		return "", err
	}
	done := make(chan error, 1)
	timer := time.AfterFunc(3*time.Second, func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	})
	go func() { done <- cmd.Wait() }()
	err := <-done
	timer.Stop()
	if err != nil {
		return "", err
	}
	return outBuf.String(), nil
}

// detectOSByTTL pings an IP once and checks TTL to determine OS
func detectOSByTTL(ip string) string {
	outputStr, err := runPing(ip)
	if err != nil {
		return ""
	}

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

// DNS hostname cache to avoid repeated lookups
var (
	dnsCache      = make(map[string]string)
	dnsCacheMutex sync.RWMutex
)

// lookupAddr does the reverse DNS query for resolveHostname. Tests replace it
// so no DNS traffic is sent.
var lookupAddr = reverseLookup

// reverseLookup asks the system resolver for the PTR names of ip.
func reverseLookup(ctx context.Context, ip string) ([]string, error) {
	resolver := &net.Resolver{}
	return resolver.LookupAddr(ctx, ip)
}

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

	names, err := lookupAddr(ctx, ip)
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

	// Build global lookup with the policy of every ARP collector (F70: this
	// one used to overwrite and skip the ESXi check)
	collectMergeMACIP(arpTable, macIPClock())

	fmt.Printf("✅ Collected %d ARP entries from gateway %s\n", len(arpTable), gatewayIP)
}

// getGlobalIP looks up IP address from global MAC-IP table (any MAC text
// form; the table is keyed by canonical MACs)
func getGlobalIP(mac string) string {
	globalMACtoIPMutex.RLock()
	defer globalMACtoIPMutex.RUnlock()
	return globalMACtoIP[canonicalMAC(mac)]
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
	// Devices are visited in IP order: when two switches share a node id the
	// same one (the last, as in buildGraphFromSnapshot) owns the traffic labels.
	nodeToIP := make(map[string]string)
	collectedDataMutex.RLock()
	for _, ip := range sortedDeviceIPs(collectedData) {
		dev := collectedData[ip]
		nodeToIP[graphDeviceNodeID(dev)] = dev.IP
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

// graphAddSwitchNode adds the node of a polled device, labelled
// "SysName\nIP" ("SysName" when the node id is the IP), marks it as a
// switch and returns its id.
func graphAddSwitchNode(graph *DJGraph, d *DeviceData) string {
	id := graphDeviceNodeID(d)
	graph.AddNode(id)
	info := d.SysName
	if id != d.IP {
		info = fmt.Sprintf("%s\n%s", d.SysName, d.IP)
	}
	graph.SwitchInfo[id] = info
	if graph.graphSwitches == nil {
		graph.graphSwitches = make(map[string]bool)
	}
	graph.graphSwitches[id] = true
	graphAddSysText(graph, id, d.SysName)
	return id
}

// graphAddSysText records sysName/sysDescr text for a node (each distinct
// text once, in build order).
func graphAddSysText(graph *DJGraph, id string, texts ...string) {
	for _, text := range texts {
		text = strings.TrimSpace(text)
		if text == "" || strings.Contains(graph.graphSysText[id], text) {
			continue
		}
		if graph.graphSysText == nil {
			graph.graphSysText = make(map[string]string)
		}
		if graph.graphSysText[id] != "" {
			text = graph.graphSysText[id] + "\n" + text
		}
		graph.graphSysText[id] = text
	}
}

// graphSwitchSysMarkers are sysName/sysDescr words of switches (HPE/H3C
// Comware, Huawei VRP, Cisco IOS, SNR).
var graphSwitchSysMarkers = []string{"Comware", "HUAWEI", "Cisco", "SNR"}

// graphIsSwitchNode reports whether a node is a switch: a polled device, or
// an LLDP neighbor whose sysName/sysDescr names a switch platform. Vendor
// text in labels plays no part.
func graphIsSwitchNode(graph *DJGraph, id string) bool {
	if graph.graphSwitches[id] {
		return true
	}
	sys := graph.graphSysText[id]
	return slices.ContainsFunc(graphSwitchSysMarkers, func(m string) bool { return strings.Contains(sys, m) })
}

// buildSwitchChassisMACs creates a map of normalized switch MACs -> node IDs
// Used to identify switch-to-switch connections via MAC table cross-reference
func buildSwitchChassisMACs(devices map[string]*DeviceData) map[string]string {
	switchMACs := make(map[string]string)
	for _, ip := range sortedDeviceIPs(devices) {
		d := devices[ip]
		// Add ChassisID MAC (none for exception text or a non-MAC chassis id)
		if mac := graphChassisKey(d.ChassisID); mac != "" && !isInvalidID(mac) {
			switchMACs[mac] = graphDeviceNodeID(d)
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
	// Devices and ports are visited in order, so which side of a switch pair
	// creates the edge (and with which port label) is the same on every build.
	deviceIPs := sortedDeviceIPs(allDevices)
	for _, srcIP := range deviceIPs {
		srcDevice := allDevices[srcIP]
		srcID := graphDeviceNodeID(srcDevice)

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
		for _, portNum := range slices.Sorted(maps.Keys(portSwitchMACs)) {
			targetIDs := portSwitchMACs[portNum]
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
				for _, tdIP := range deviceIPs {
					if td := allDevices[tdIP]; graphDeviceNodeID(td) == targetID {
						graphAddSwitchNode(graph, td)
						break
					}
				}
			}

			added, _ := graph.AddEdge(srcID, targetID, label)
			_ = added
		}
	}
}

// graphBuildMutex makes snapshot, build and publish in rebuildGraph one step,
// so graphs are published in the order their snapshots were taken: when
// reactive callbacks overlap, the graph published last holds the newest
// collectedData. It is taken before collectedDataMutex and globalGraphMutex,
// so a caller of rebuildGraph must hold neither (no caller does).
var graphBuildMutex sync.Mutex

// rebuildGraph rebuilds the graph from collectedData and publishes it.
// It is the only build path: the reactive scan callback, the periodic and
// rescue rescans, LLDP discovery and UI rescans all call it.
func rebuildGraph() *DJGraph {
	graphBuildMutex.Lock()
	defer graphBuildMutex.Unlock()

	// DEADLOCK FIX: Take a snapshot of collectedData under a SHORT RLock,
	// then release it BEFORE doing any graph work.
	// This prevents nested lock deadlock when rebuildGraph() is called from
	// contexts where collectedDataMutex is already held (e.g., OnSuccess
	// callback in startPeriodicRescan/startRescueScanner/discoverFromLLDP).
	snapshot := snapshotCollectedData()

	newGraph := buildGraphFromSnapshot(snapshot)

	// Update global — AFTER all modifications are done.
	// This is the atomic swap point: HTTP handlers will see the fully built graph
	SetGlobalGraph(newGraph)
	return newGraph
}

// snapshotCollectedData copies collectedData under a short read lock. Each
// DeviceData is copied by value, so a graph build never races with the
// Unreachable flag that the SNMP failure callbacks set under the lock.
func snapshotCollectedData() map[string]*DeviceData {
	collectedDataMutex.RLock()
	defer collectedDataMutex.RUnlock()
	snapshot := make(map[string]*DeviceData, len(collectedData))
	for k, v := range collectedData {
		d := *v
		snapshot[k] = &d
	}
	return snapshot
}

// sortedDeviceIPs returns the keys of devices in IP order. Graph rules that
// depend on visiting order (first creator wins, labels of merged nodes) then
// give the same graph on every build.
func sortedDeviceIPs(devices map[string]*DeviceData) []string {
	ips := slices.Collect(maps.Keys(devices))
	slices.SortFunc(ips, compareIPs)
	return ips
}

// compareIPs orders IP strings numerically; keys that are not IPs sort after
// all IPs, by text.
func compareIPs(a, b string) int {
	ipA, errA := netip.ParseAddr(a)
	ipB, errB := netip.ParseAddr(b)
	switch {
	case errA == nil && errB == nil:
		if c := ipA.Compare(ipB); c != 0 {
			return c
		}
	case errA == nil:
		return -1
	case errB == nil:
		return 1
	}
	return strings.Compare(a, b)
}

// buildGraphFromSnapshot builds the complete graph from a device snapshot:
// switch nodes, LLDP and FDB edges, MAC cross-reference edges, hypervisor
// nodes and IP labels. Devices are visited in IP order. The graph is not
// published here; rebuildGraph does that once it is complete.
func buildGraphFromSnapshot(snapshot map[string]*DeviceData) *DJGraph {
	newGraph := NewDJGraph()
	deviceIPs := sortedDeviceIPs(snapshot)

	// 0. Build switchChassisMACs map
	switchChassisMACs := buildSwitchChassisMACs(snapshot)

	// 1. Add all Nodes (two switches with the same node id: the last one in
	// IP order sets the label)
	for _, ip := range deviceIPs {
		d := snapshot[ip]
		id := graphAddSwitchNode(newGraph, d)

		// Phase 8: Transfer unreachable status to graph
		if d.Unreachable {
			newGraph.NodeStatus[id] = "unreachable"
		}
	}

	// 2. Build Edges (with switch MAC exclusion); a node seen by several
	// switches gets its label from the first one in IP order
	for _, ip := range deviceIPs {
		buildGraphEdges(newGraph, snapshot[ip], switchChassisMACs)
	}

	// 3. MAC cross-reference edges (for LLDP-disabled switches)
	addMACCrossRefEdges(newGraph, snapshot, switchChassisMACs)

	// 4. Detect hypervisors (per-port VM MAC concentration) — BEFORE making graph global
	detectHypervisors(newGraph)
	// 5. Enrich with IPs from MAC-IP cache — BEFORE making graph global
	enrichGraphWithIPs(newGraph)

	return newGraph
}

// graphDominantHypervisorType is the most common platform among the VM MACs
// of one port (hypervisorTypeOf, the MAC registry's type of each VM NIC); a
// tie goes to the alphabetically first platform.
func graphDominantHypervisorType(vmMACs []string) string {
	counts := map[string]int{}
	for _, mac := range vmMACs {
		if t, ok := hypervisorTypeOf(mac); ok {
			counts[t]++
		}
	}
	best := ""
	for _, t := range slices.Sorted(maps.Keys(counts)) {
		if counts[t] > counts[best] {
			best = t
		}
	}
	return best
}

// graphEdgePort is the port name at the start of an edge label: the first
// field before '|' ("GE1/0/26 [T]|" and "GE1/0/9 1G ↓5M ↑3M|eth0" give
// GE1/0/26 and GE1/0/9), or "" for an empty label.
func graphEdgePort(label string) string {
	src, _, _ := strings.Cut(label, "|")
	if fields := strings.Fields(src); len(fields) > 0 {
		return fields[0]
	}
	return ""
}

// graphHubUplinkPort is the switch port of a hub node (from its "port|Hub"
// uplink edge), or "".
func graphHubUplinkPort(graph *DJGraph, hubID string) string {
	for _, src := range slices.Sorted(maps.Keys(graph.Edges)) {
		if label, ok := graph.Edges[src][hubID]; ok {
			return graphEdgePort(label)
		}
	}
	return ""
}

// detectHypervisors scans the graph for switch ports where 2+ VM MACs are seen.
// Such ports indicate a connected hypervisor server (ESXi, Proxmox, Hyper-V, QEMU, Xen, VirtualBox).
// A virtual hypervisor node is inserted between the switch port and its VM endpoints;
// VMs behind a hub get it between the hub and the VMs, keyed by the hub's switch port.
func detectHypervisors(graph *DJGraph) {
	// portVMs: switchNodeID (or hub node ID) → port key → []vmMAC
	// Edges are visited in sorted order, so each port's VM list is the same
	// on every build.
	portVMs := map[string]map[string][]string{}

	for _, src := range slices.Sorted(maps.Keys(graph.Edges)) {
		targets := graph.Edges[src]
		for _, tgt := range slices.Sorted(maps.Keys(targets)) {
			// Check if tgt MAC is a VM OUI
			if _, isVM := hypervisorTypeOf(tgt); !isVM {
				continue
			}
			// Port from the edge label ("GE1/0/26 [T]|eth0" → "GE1/0/26"); a
			// hub member's edge has no label, so the hub's uplink port is used
			port := graphEdgePort(targets[tgt])
			if port == "" && strings.HasPrefix(src, "hub-") {
				port = graphHubUplinkPort(graph, src)
			}
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

	// For each switch port with 2+ VM MACs → insert hypervisor node
	for _, switchID := range slices.Sorted(maps.Keys(portVMs)) {
		ports := portVMs[switchID]
		for _, port := range slices.Sorted(maps.Keys(ports)) {
			vmMACs := ports[port]
			if len(vmMACs) < 2 {
				continue // single VM MAC — could be real NIC, skip
			}

			// Dominant hypervisor type (majority, fixed tie-break)
			hypervisorType := graphDominantHypervisorType(vmMACs)

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

			// Replace switch→VM edges with switch→hypervisor→VM (the VM
			// nodes exist: AddEdge only links existing nodes)
			for _, vmMAC := range vmMACs {
				delete(graph.Edges[switchID], vmMAC)
				graph.AddEdge(hypID, vmMAC, "vNIC")
			}

			// Add switch→hypervisor edge (unlabelled from a hub, like the
			// hub's other members)
			parentLabel := port
			if strings.HasPrefix(switchID, "hub-") {
				parentLabel = ""
			}
			graph.AddEdge(switchID, hypID, parentLabel)
			fmt.Printf("🖥️  Hypervisor detected: %s on %s port %s (%d VMs: %s)\n",
				hypervisorType, switchID[:min(len(switchID), 20)], port, len(vmMACs), vmMACs[0])
		}
	}

	// --- Phase 2: Server NIC detection ---
	// Tag nodes from known server vendors (Dell/HPE/SuperMicro) as potential hypervisors.
	// Only applies to endpoint/vm/unknown nodes — NOT switches: the polled
	// devices of this build and LLDP neighbors whose sysName/sysDescr names
	// a switch (graphIsSwitchNode; vendor words in labels do not count).
	for _, nodeID := range slices.Sorted(maps.Keys(graph.Nodes)) {
		if strings.HasPrefix(nodeID, "hyp-") || strings.HasPrefix(nodeID, "hub-") {
			continue
		}
		if graphIsSwitchNode(graph, nodeID) {
			continue // skip switches
		}
		if isServer, vendor := isServerNIC(nodeID); isServer {
			info := graph.SwitchInfo[nodeID]
			if strings.Contains(info, "[HYPERVISOR]") || strings.Contains(info, "[BMC]") {
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
						storeCollectedDevice,
						func(ip string, err error) {
							markUnreachable(ip)
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
	uniqueMACs := analyzerUniqueMACs(devices) // the total_macs of /api/graph

	// Shadow IT with the graph's per-port rule (Q14): raw = hub candidates,
	// filtered = the hubs, vmPortCount = candidates exempt as VM/ESXi ports
	shadow := analyzerShadowCounts(devices)
	shadowITRaw := shadow.Candidates
	shadowITFiltered := shadow.Hubs
	vmPortCount := shadow.VMPorts

	for _, d := range devices {
		totalInterfaces += len(d.Interfaces)
		totalNeighbors += len(d.Neighbors)
		totalMACs += len(d.MACTable)
		totalARPs += len(d.ARPTable)
		if d.STPInfo.Enabled {
			stpEnabled++
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

	os.MkdirAll(exportsDir, 0755)
	jsonData, _ := json.MarshalIndent(report, "", "  ")
	os.WriteFile(filepath.Join(exportsDir, "experiment_metrics.json"), jsonData, 0644)

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

