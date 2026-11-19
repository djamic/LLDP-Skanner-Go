package main

import (
	"bytes"
	"cmp"
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

	// Gateway Configuration (loaded from 'gateway_ip' file at startup): the
	// first gateway, the analyzer's core (gatewayIPs lists them all)
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

	// A web login command (--user-add, --user-del, --vault-password) runs
	// alone
	if runAuthCommand() {
		return
	}

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

	// First graph from the saved hosts, with the cache's IP and DNS lines,
	// built in the background so the monitoring loops below start at once
	// (RC-1)
	startupGraphDone := startStartupGraph(savedHosts)

	// ============================================================
	// Mode dispatch: benchmark and monitor24h exit early
	// ============================================================
	if *modeFlag == "benchmark" {
		<-startupGraphDone // measure without a build running alongside
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
		// network summary twice (F52). Its first cycle waits for the startup
		// graph.
		runMonitor24h(startupGraphDone)
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

		// E.1 fix: Run Analyze() as soon as the startup graph is built
		// so Health Score widget is populated on first page load (not after 10 min)
		go func() {
			<-startupGraphDone
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
		// SNMP devices of the ranges that are no switches (checkSwitch)
		firstScanSkips := &switchSkips{}

		// Define callback function for scan results
		resultCallback := func(result ScanResult) {
			switch result.Event {
			case EventHostFound:
				atomic.AddInt32(&hostsFound, 1)

			case EventSNMPSuccess:
				atomic.AddInt32(&snmpSuccess, 1)
				fmt.Printf("[✓] SNMP: %s - %s\n", result.IP, result.SysName)

				// Trigger detailed data collection with WaitGroup (switches only)
				dataCollectionWG.Add(1)
				go func(ip, name string) {
					defer dataCollectionWG.Done()
					collectScannedSwitch(snmpObject, ip, name, firstScanSkips)
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
				firstScanSkips.print("Scan")

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
					runMonitor24h(startupGraphDone) // closed: no saved hosts, no startup graph
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
// the ARP table of every gateway is read. The first graph is built after
// that (buildStartupGraph), so it already has the IP and DNS lines (F51:
// they used to appear only after the first rescan) and the router nodes of
// the gateways that answered.
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

	// Collect the ARP tables of the gateways first (also done by MacIPService)
	if len(gatewayList()) > 0 {
		fmt.Printf("🔍 Collecting ARP tables from gateways %s...\n", gatewayListText())
	}
	collectGatewayARP()
}

// startStartupGraph builds the first graph (buildStartupGraph) in the
// background and returns a channel that is closed once it is published.
// main() starts the monitoring loops meanwhile, which cope with the empty
// graph the web server shows until then: the build looks up DNS names and
// pings VMs, and run on main()'s goroutine it held up traffic polling,
// rescans, the rescue scanner and runMonitor24h for as long as that took
// (about 27 minutes with a DNS server that does not answer, RC-1).
func startStartupGraph(savedHosts map[string]*DeviceData) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		buildStartupGraph(savedHosts)
	}()
	return done
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
// collectedData and marks the switch reachable (the OnSuccess callbacks),
// and reports whether it stored it. The tables of walks that failed in this
// poll are kept from the previous poll (F57), so is the last valid chassis
// id when this poll read none (keepPreviousChassisID), and the traffic
// counters are only updated from interfaces walked just now.
//
// A device that is not stored yet is stored only when this poll found a
// switch MIB (polledMIBs.isSwitch: BRIDGE-MIB ports or lldpLocChassisId).
// Any agent whose IF-MIB answers makes a partial success, and on 2026-10-22
// the access points that LLDP discovery polled and the FortiGate and the
// ESXi host that the rescue scan polled became isolated switch nodes that
// way. A stored device takes every successful poll as before, whatever it
// shows (F53, F57, H9).
func storeCollectedDevice(data *DeviceData) bool {
	// Phase 8: Mark as reachable
	data.Unreachable = false
	data.LastSeen = time.Now()
	collectedDataMutex.Lock()
	prev := collectedData[data.IP]
	if prev == nil && !data.polledMIBs.isSwitch() {
		collectedDataMutex.Unlock()
		fmt.Printf("🚫 [Collect] %s answered without BRIDGE-MIB ports or lldpLocChassisId: no switch, not stored\n", data.IP)
		return false
	}
	collectKeepPrevious(data, prev)
	keepPreviousChassisID(data, prev)
	keepPreviousSysName(data, prev)
	collectedData[data.IP] = data
	collectedDataMutex.Unlock()
	if !data.collectWalkFailed(collectWalkInterfaces) {
		updateTrafficCounters(data.IP, data.Interfaces)
	}
	return true
}

// storeCollected is storeCollectedDevice as an OnSuccess callback.
func storeCollected(data *DeviceData) { storeCollectedDevice(data) }

// collectedReachable reports whether ip is in collectedData and answered
// its last poll.
func collectedReachable(ip string) bool {
	collectedDataMutex.RLock()
	defer collectedDataMutex.RUnlock()
	d, ok := collectedData[ip]
	return ok && !d.Unreachable
}

// keepPreviousChassisID keeps the switch identity stable across polls: when
// this poll read no usable chassis id (an empty one, exception text the
// collector rejected, a failed walk, the null MAC) and the stored data of
// the same IP has one, the stored chassis id stays. Some agents answer
// lldpLocChassisId only now and then (172.20.230.40), and the node id would
// flip between the chassis MAC and the IP. A new usable chassis id always
// replaces the old one.
func keepPreviousChassisID(data, prev *DeviceData) {
	if prev == nil || prev == data || graphChassisKey(data.ChassisID) != "" {
		return
	}
	if graphChassisKey(prev.ChassisID) != "" {
		data.ChassisID = prev.ChassisID
	}
}

// keepPreviousSysName keeps a switch's name when this poll has none (the
// caller had none and the sysName read gave none, CollectData) and the
// stored data of the same IP has one.
func keepPreviousSysName(data, prev *DeviceData) {
	if prev != nil && prev != data && data.SysName == "" {
		data.SysName = prev.SysName
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
	return NewSNMPObject(storeCollected, func(ip string, err error) {
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
			if newGraph != nil {
				startLiveAnalysis(newGraph)
			}
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
// switch, then rebuilds and publishes the graph and returns it (nil when
// the device was not stored: no switch MIB in its poll). CollectData runs
// in one goroutine per switch, so calls overlap; rebuildGraph publishes
// their graphs in the order of their snapshots.
func handleReactiveDevice(data *DeviceData) *DJGraph {
	atomic.AddInt32(&dataCollected, 1)

	// Store data for later processing: marks it reachable, keeps the tables
	// of failed walks (F57) and sets the traffic baseline for the first poll
	if !storeCollectedDevice(data) {
		return nil
	}

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
// switchMACs maps the own MACs of the polled switches to their node ids
// (buildSwitchOwnMACs), so switch MACs get no endpoint nodes
func buildGraphEdges(graph *DJGraph, data *DeviceData, switchMACs map[string]string) {
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

	// Add LLDP neighbors as edges. rowsTo counts the accepted rows toward
	// each target (two rows: two links to it, lldpReverseFarPort)
	logDebug("  Found %d LLDP neighbors", len(data.Neighbors))
	rowsTo := make(map[string]int)
	for _, n := range data.Neighbors {
		if target, _, ok := graphLLDPNeighborTarget(data, n); ok {
			rowsTo[target]++
		}
	}
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
		graphRecordVoIPNeighbor(graph, targetID, neighbor, macToIP[targetID])

		logDebug("    -> Neighbor: %s (ID: %s) via LocalPort: %d", displayName, targetID, neighbor.LocalPortNum)

		// ENHANCED DISCOVERY: Create LLDP Endpoint if target not scanned
		if !graph.Nodes[targetID] {
			graphAddLLDPEndpoint(graph, targetID, displayName, neighbor, macToIP[targetID])
		}

		remotePort := lldpRemotePortName(neighbor)

		// Get VLAN info for local port (PortVLANs is dot1d bridge-port indexed)
		vlanStr := getPortVLANLabel(data.PortVLANs, collectBridgePort(data, neighbor.LocalPortNum))

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

		// Add Edge (Directional: Source -> Target). When the target drew the
		// link from its own view first and could not name this switch's
		// port, this switch's view names it (lldpReverseFarPort)
		added, _ := graph.AddEdge(srcID, targetID, label)
		if added {
			logDebug("       [NEW EDGE] Added connection: %s -> %s (Label: %s)", srcID, targetID, label)
		} else if port := lldpReverseFarPort(graph, data, srcID, targetID, neighbor, rowsTo[targetID]); port != "" &&
			graph.FillTargetPort(targetID, srcID, port) {
			logDebug("       [FAR PORT] %s -> %s: this switch's own port %s", targetID, srcID, port)
		} else {
			logDebug("       [DUP EDGE] Edge already exists: %s -> %s", srcID, targetID)
		}
	}

	// Process MAC Address Table - create endpoint nodes, with the per-port
	// rule the Shadow-IT alerts, metrics and reports share (fdbPorts).
	// Ports come in ascending order, so when a MAC is seen on two ports the
	// node is created (first creator wins) by the same port on every build.
	for _, p := range fdbPorts(data, switchMACs) {
		portName := getFDBPortName(data, p.Port)
		if p.Kind == fdbHub || p.Kind == fdbMiniHub {
			// Non-VM hub: create aggregated hub node; every member gets a
			// node (a hub has at most 20 MACs, a mini hub 500). A mini hub
			// is a hub- node too, so the hypervisor detection and the
			// views take it as one; its tag makes its group (minihub)
			nodeID := fmt.Sprintf("hub-%s-p%d", srcID, p.Port)
			nodeLabel := fmt.Sprintf("[HUB] Unmanaged\n%d devices", len(p.MACs))
			if p.Kind == fdbMiniHub {
				nodeLabel = fmt.Sprintf("[MINIHUB] Mini hub\n%d devices", len(p.MACs))
			}
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

// graphAddLLDPEndpoint adds the node of an LLDP neighbor that no polled
// device is (an "[LLDP-EP]" node, or "[BMC]" when its LLDP or DNS name or
// its MAC says so) with its label: the vendor, the display name, then the
// management IP or the first line of the sysDescr. ip is the neighbor's IP
// from the ARP data ("" when unknown), for the DNS name of the BMC check.
// The switches' LLDP neighbors (buildGraphEdges) and the gateways' own
// (addGatewayNodes) get their nodes here.
func graphAddLLDPEndpoint(graph *DJGraph, targetID, displayName string, neighbor LLDPNeighbor, ip string) {
	graph.AddNode(targetID)

	// Get vendor from MAC if targetID is a MAC ("" for a name or IP)
	vendor := getMACVendor(targetID)

	// Build info from LLDP neighbor data with [LLDP-EP] marker
	var info string

	// DNS name of the neighbor (when its IP is known), for the BMC check
	dnsName := ""
	if ip != "" {
		dnsName, _ = cachedHostname(ip) // looked up before the build
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

// lldpRemotePortName is the far end's port in an LLDP link label (before
// normalizePortName): the port description when it has text, else the port
// id when it names a port (lldpPortIDName), else "": the far port is
// unknown, and no name is made up for it (it used to be "Uplink" when the
// description was the neighbor's sysName and the port id empty). Both come
// as net-snmp printed them, quoted, and a description that is only quotes
// or blanks has no text: the SNR switches (f8:f0:82) send an empty one as
// `""`, so 172.20.230.51 sees 172.20.230.254 with lldpRemPortDesc `""` and
// lldpRemPortId "Ethernet1/0/10", and the far port used to stay empty. A
// description or port id that is the neighbor's sysName names no port.
func lldpRemotePortName(neighbor LLDPNeighbor) string {
	sysName := strings.TrimSpace(neighbor.RemSysName)
	if desc := cleanSNMPValue(neighbor.RemPortDesc); desc != "" && desc != sysName {
		return desc
	}
	if id := lldpPortIDName(neighbor); id != "" && id != sysName {
		return id
	}
	return ""
}

// lldpPortIDName is the port id of an LLDP neighbor when it names a port,
// else "". The port id subtype tells: an interfaceAlias (1, the FortiGate's
// "LAN"), portComponent (2) or interfaceName (5, "Ethernet1/0/10") is a
// name, and so is a local id (7, or no subtype) that spells no MAC (the SNR
// S2985G-24TC switches send their port number, "28"). A macAddress (3),
// networkAddress (4) or agentCircuitId (6) id is none, whatever its text:
// the PCs, phones and access points send their MAC there ("48 F3 17 07 58
// 7F", "00-e0-1a-ae-03-75", "AC8B.A970.A966", or the 6 raw bytes as a
// STRING), and a MAC never becomes a port name.
func lldpPortIDName(n LLDPNeighbor) string {
	switch n.RemPortIdSubtype {
	case 3, 4, 6:
		return ""
	}
	id := cleanSNMPValue(n.RemPortId)
	if id == "" || !isPrintableString(id) || canonicalMAC(id) != "" {
		return ""
	}
	return id
}

// lldpReverseFarPort is the port of this switch (data, node srcID) that
// names the far end of the link target drew from its own LLDP view before
// (the edge target -> srcID with the label "<target's port ...>|", target's
// neighbor row named no port of this switch): the interface of the local
// port of n, this switch's row toward target. The row must fit the link:
// when it names target's port (its far port or its port id) that is the
// port the label starts with (lldpSamePort), and when this switch has two
// or more rows toward target (rows: two links) it must name it. "" when no
// such edge waits for its far port, the row does not fit, or the interface
// table does not name the local port (no "Port 28" placeholder).
// buildGraphEdges visits the switches in IP order and the result depends on
// the snapshot only.
func lldpReverseFarPort(graph *DJGraph, data *DeviceData, srcID, target string, n LLDPNeighbor, rows int) string {
	near, far, isLink := strings.Cut(graph.Edges[target][srcID], "|")
	nearPort := strings.Fields(near)
	if !isLink || strings.TrimSpace(far) != "" || len(nearPort) == 0 {
		return ""
	}
	named, fits := false, false
	for _, reported := range []string{lldpRemotePortName(n), lldpPortIDName(n)} {
		if reported = normalizePortName(reported); reported != "" {
			named = true
			fits = fits || lldpSamePort(nearPort[0], reported)
		}
	}
	if named && !fits || !named && rows != 1 {
		return ""
	}
	if !slices.ContainsFunc(data.Interfaces, func(i InterfaceData) bool { return i.IfIndex == n.LocalPortNum }) {
		return ""
	}
	return normalizePortName(getLocalPortName(data, n.LocalPortNum))
}

// lldpSamePort reports whether a switch's own port name and the name a
// neighbor reported for it (both normalizePortName'd) are one port: equal
// but for case, or a bare port number that ends the name ("28" is
// "Eth1/0/28", the SNR S2985G-24TC's local port ids).
func lldpSamePort(own, reported string) bool {
	if strings.EqualFold(own, reported) {
		return true
	}
	if reported == "" || strings.Trim(reported, "0123456789") != "" {
		return false
	}
	return strings.HasSuffix(own, "/"+reported)
}

// fdbPortKind is what the per-port FDB rule (fdbPorts) makes of the MACs a
// switch learned on one port.
type fdbPortKind int

const (
	fdbDirect   fdbPortKind = iota // few MACs: each one is linked to the switch
	fdbHub                         // an unmanaged switch or hub: Shadow IT
	fdbVMPort                      // most MACs are virtual NICs: a hypervisor host
	fdbESXiPort                    // a hub candidate with an HTTP-confirmed ESXi host
	fdbMiniHub                     // a trunk or big port no polled switch is behind: its devices, no Shadow IT
)

// fdbHubMax is the most MACs a hub has: a port with more (like a VLAN
// trunk) is a mini hub, or an uplink when a polled switch is behind it.
// fdbMiniHubMax is the most a mini hub has: a port with more, even with no
// polled switch behind it, is an uplink toward switches the scanner does
// not poll (the switches' uplinks carry thousands).
const (
	fdbHubMax     = 20
	fdbMiniHubMax = 500
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
// neighbors, the own MACs of the switch and of the other polled switches
// (switchMACs, buildSwitchOwnMACs: chassis MACs and ARP aliases) and
// isInvalidID ones. A port with an accepted LLDP neighbor or a NULL0 name
// gets nothing. A VM-majority port is direct (also on a trunk or with more
// than 20 MACs, unless another switch's MAC is learned there). At most 3
// MACs are direct on any other port. A port with more where another polled
// switch's MAC is learned is an uplink to it (Netdisco's and FortiNAC's
// learned uplink) and gets nothing. Otherwise 2-20 MACs are a hub unless one
// is an HTTP-confirmed ESXi host (ESXi exemption); a VLAN trunk or a port
// with more than 20 MACs is an ESXi port, a mini hub (its devices are
// drawn, it is no Shadow IT), or, above 500 MACs, an uplink toward switches
// the scanner does not poll.
func fdbPorts(data *DeviceData, switchMACs map[string]string) []fdbPort {
	// MACs already known via LLDP, and the ports with an accepted neighbor.
	// lldpSwitchPorts keys by LocalPortNum (ifIndex, like crossReferenceSwitchMACs)
	// so switch links where BridgePort != IfIndex (Huawei dot1dBasePortIfIndex)
	// are skipped too without dropping cascaded hubs, VMs or daisy-chained PCs.
	knownMACs := lldpKnownMACs(data)
	lldpPorts := make(map[int]bool)
	lldpSwitchPorts := make(map[int]bool)
	for _, n := range data.Neighbors {
		if target, _, ok := graphLLDPNeighborTarget(data, n); ok {
			lldpPorts[n.LocalPortNum] = true
			isRouterOnly := n.RemSysCapEnabled&lldpCapRouter != 0 && n.RemSysCapEnabled&lldpCapBridge == 0
			if _, polled := switchMACs[target]; polled || isRouterOnly {
				lldpSwitchPorts[n.LocalPortNum] = true
			}
		}
	}

	// NULL0/InLoopBack ports, looked up once per port (the alerts run this
	// rule on every FDB row of every switch)
	nullPorts := make(map[int]bool)
	isNullPort := func(port int) bool {
		null, seen := nullPorts[port]
		if !seen {
			null = isNullInterface(getFDBPortName(data, port))
			nullPorts[port] = null
		}
		return null
	}

	// Track MACs per port for Virtual Hub detection, and the ports where
	// another polled switch's MAC is learned (switch links)
	portMACs := make(map[int][]string)
	portSeesSwitch := make(map[int]bool)
	ownMAC, selfID := graphChassisKey(data.ChassisID), graphDeviceNodeID(data)
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

		// Skip switch's own MACs (usually ports have their own MACs): the
		// chassis MAC and the ARP aliases of its node. Checked before
		// knownMACs so another polled switch that is also an LLDP neighbor
		// still marks portSeesSwitch on ports where BridgePort != IfIndex.
		switchID, isSwitch := switchMACs[normMAC]
		if normMAC == ownMAC || (isSwitch && switchID == selfID) {
			continue
		}

		// Skip if this MAC belongs to another known switch (handled by MAC cross-ref)
		if isSwitch {
			portSeesSwitch[macEntry.PortNumber] = true
			continue
		}

		// Skip if this MAC is already known via LLDP
		if knownMACs[normMAC] {
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
		// Skip if a 1:1 / unmapped port already has LLDP neighbors, or if its
		// mapped ifIndex is a polled-switch / router LLDP link (Huawei VRP)
		ifIdx := collectFDBIfIndex(data, portNum)
		if (ifIdx == portNum && lldpPorts[portNum]) || lldpSwitchPorts[ifIdx] {
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

		// A port with more than 20 MACs is no hub either (D 1-2 port 51 has
		// 58 MACs), like a trunk the VLAN data missed
		if len(macs) > fdbHubMax && !isTrunkPort {
			isTrunkPort = true
			logDebug("       [BIG] Port %d on %s has %d MACs — no hub", portNum, data.IP, len(macs))
		}

		// A port where most MACs are virtual NICs is a hypervisor host (ESXi,
		// Proxmox, KVM), also on a VLAN trunk or with more than 20 MACs: ESXi
		// hosts sit on trunk ports. A trunk or big port where another switch's
		// MAC is learned is a switch link, though, whatever it carries.
		uplink := portSeesSwitch[portNum]
		vmPort := len(macs) >= 2 && isHypervisorPort(macs) && (!isTrunkPort || !uplink)
		candidate := len(macs) >= 2 && !isTrunkPort && !uplink

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
			// Few MACs - direct endpoint nodes (on a switch link as well)
			port.Kind = fdbDirect
		case uplink:
			// another polled switch is behind the port: its MACs are that
			// switch's to draw
			logDebug("       [UPLINK] Port %d on %s learns a polled switch's MAC — no nodes for its %d MACs", portNum, data.IP, len(macs))
			continue
		case len(macs) > fdbMiniHubMax:
			logDebug("       [UPLINK] Port %d on %s has %d MACs — an uplink toward unpolled switches", portNum, data.IP, len(macs))
			continue
		case graphPortHasConfirmedESXi(macs):
			// an ESXi host on a trunk port
			port.Kind = fdbESXiPort
		default:
			// a trunk or big port with no polled switch behind it: what is
			// there is shown, not dropped
			port.Kind = fdbMiniHub
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
		hostname, _ = cachedHostname(ip) // looked up before the build
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

// getFDBPortName names an FDB port. MACEntry.PortNumber is a dot1d bridge
// port, which dot1dBasePortIfIndex maps to the ifIndex the interface table
// names (collectFDBIfIndex; without a mapping the bridge port is taken as
// the ifIndex, F60). Hub ids, issue ids and the VLAN table keep the bridge
// port.
func getFDBPortName(data *DeviceData, bridgePort int) string {
	return getLocalPortName(data, collectFDBIfIndex(data, bridgePort))
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

// waitStartupGraph returns once ready is closed, and says so when it has
// to wait.
func waitStartupGraph(ready <-chan struct{}) {
	select {
	case <-ready:
		return
	default:
	}
	fmt.Println("📡 Monitor24h: waiting for the startup graph before the first cycle...")
	<-ready
}

// monitorCycle is one cycle of runMonitor24h: it analyses the devices and
// the published graph, takes a snapshot, records its diff against prev
// (recordSnapshotDiff: event log and InfluxDB) and returns it. Without
// devices, or before a graph with nodes is published (main() publishes
// an empty one until the startup graph is built), it analyses nothing and
// returns prev: a snapshot of the empty graph has no core and no path
// suggestion, and the diff against it reported every path anomaly of the
// real graph as new.
func monitorCycle(prev *NetworkSnapshot) *NetworkSnapshot {
	// 1. Collect current data — snapshot under SHORT RLock to avoid nested lock deadlock
	collectedDataMutex.RLock()
	if len(collectedData) == 0 {
		collectedDataMutex.RUnlock()
		fmt.Println("   No data yet, waiting...")
		return prev
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
	if currentGlobalGraph == nil || len(currentGlobalGraph.Nodes) == 0 {
		fmt.Println("   No graph yet, waiting...")
		return prev
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

	if prev != nil {
		// Log the diff and write it to InfluxDB
		recordSnapshotDiff(prev, currentSnapshot, &report)
	}
	return currentSnapshot
}

// runMonitor24h runs continuous monitoring for the --duration flag: one
// analysis and snapshot diff per minute (monitorCycle). The first cycle
// waits until ready is closed, that is until the startup graph is
// published (startStartupGraph builds it in the background): a cycle on
// the empty graph main() publishes until then found no core and no path
// suggestion, so the next cycle reported every path anomaly as new after
// each daily restart (F2 of the gateway review).
func runMonitor24h(ready <-chan struct{}) {
	duration := parseDurationFlag(*durationFlag)
	startTime := time.Now()
	endTime := startTime.Add(duration)

	fmt.Printf("📡 Monitor24h started at %s\n", startTime.Format("15:04:05"))
	fmt.Printf("📡 Will run until %s (duration: %v)\n", endTime.Format("15:04:05"), duration)

	// Ensure output directory exists
	os.MkdirAll(*outputFlag, 0755)

	waitStartupGraph(ready)

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
			prevSnapshot = monitorCycle(prevSnapshot)
		}()

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

// ttlOSCache holds the answer of detectOSByTTL per IP until it expires, so
// a graph rebuild (every VM with an IP gets a TTL ping, about 62 in the
// fixture) pings an IP at most once per ttlOSCacheTTL. A silent IP is
// cached too: each such ping costs up to a second.
var (
	ttlOSCache      = make(map[string]ttlOSEntry)
	ttlOSCacheMutex sync.Mutex
)

// ttlOSEntry is one cached TTL answer ("" for no guess or no reply).
type ttlOSEntry struct {
	os      string
	expires time.Time
}

// ttlOSCacheTTL is how long a TTL answer is reused.
const ttlOSCacheTTL = 30 * time.Minute

// detectOSByTTL pings an IP once and checks TTL to determine OS; the answer
// is reused for ttlOSCacheTTL (ttlOSCache).
func detectOSByTTL(ip string) string {
	now := time.Now()
	ttlOSCacheMutex.Lock()
	if entry, ok := ttlOSCache[ip]; ok && now.Before(entry.expires) {
		ttlOSCacheMutex.Unlock()
		return entry.os
	}
	ttlOSCacheMutex.Unlock()

	osLabel := pingOSByTTL(ip)
	ttlOSCacheMutex.Lock()
	ttlOSCache[ip] = ttlOSEntry{os: osLabel, expires: now.Add(ttlOSCacheTTL)}
	ttlOSCacheMutex.Unlock()
	return osLabel
}

// pingOSByTTL pings ip once and guesses the OS from the reply's TTL.
func pingOSByTTL(ip string) string {
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

// Reverse DNS names for the graph labels (RC-1). Lookups run on at most
// dnsLookupWorkers goroutines, one at a time per IP. A graph build asks for
// all the names it will use first (graphResolveHostnames) and waits at most
// graphDNSWait for them; a name that arrives later is in the cache for the
// next build. A name is kept for the life of the process, a failed lookup
// for dnsNegativeTTL. The first build after a restart used to look up its
// ~800 names one after another on main()'s goroutine: with a DNS server
// that does not answer, 2 s each, about 27 minutes before any monitoring
// loop started, and every failure stayed cached for the day.
var (
	dnsCache      = make(map[string]dnsEntry)
	dnsInflight   = make(map[string]chan struct{}) // IP → closed when its lookup is done
	dnsCacheMutex sync.RWMutex                     // guards dnsCache and dnsInflight
	dnsSlots      = make(chan struct{}, dnsLookupWorkers)
)

// dnsEntry is one cached reverse lookup: the short host name, or "" with
// the time of the failed lookup.
type dnsEntry struct {
	name     string
	failedAt time.Time
}

const (
	dnsLookupWorkers = 16               // reverse lookups at the same time
	dnsLookupTimeout = 2 * time.Second  // one lookup
	dnsNegativeTTL   = 10 * time.Minute // a failed lookup is tried again after this
)

// graphDNSWait is how long a graph build waits for the reverse lookups it
// needs (graphResolveHostnames). Tests shorten it.
var graphDNSWait = 5 * time.Second

// lookupAddr does the reverse DNS query for resolveHostname. Tests replace it
// so no DNS traffic is sent.
var lookupAddr = reverseLookup

// dnsClock is the time source of the failed-lookup TTL. Tests replace it.
var dnsClock = time.Now

// reverseLookup asks the system resolver for the PTR names of ip.
func reverseLookup(ctx context.Context, ip string) ([]string, error) {
	resolver := &net.Resolver{}
	return resolver.LookupAddr(ctx, ip)
}

// resolveHostname performs DNS reverse lookup with 2s timeout and caching
// "PC-JAMIL.tuit.local." → "PC-JAMIL"; an IP being looked up already is
// not looked up twice.
func resolveHostname(ip string) string {
	if name, ok := cachedHostname(ip); ok {
		return name
	}
	<-dnsStartLookup(ip)
	name, _ := cachedHostname(ip)
	return name
}

// cachedHostname returns the cached name of ip; ok is false when the cache
// has no answer (never looked up, or a failure older than dnsNegativeTTL).
func cachedHostname(ip string) (name string, ok bool) {
	dnsCacheMutex.RLock()
	defer dnsCacheMutex.RUnlock()
	entry, found := dnsCache[ip]
	if !found || (entry.name == "" && dnsClock().Sub(entry.failedAt) >= dnsNegativeTTL) {
		return "", false
	}
	return entry.name, true
}

// resolveHostnames looks up the names of the IPs the cache has no answer
// for, at most dnsLookupWorkers at a time, and waits until they are done
// or wait has passed. Lookups still running then fill the cache later.
func resolveHostnames(ips []string, wait time.Duration) {
	var pending []<-chan struct{}
	for _, ip := range ips {
		if _, ok := cachedHostname(ip); !ok {
			pending = append(pending, dnsStartLookup(ip))
		}
	}
	if len(pending) == 0 {
		return
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	for _, done := range pending {
		select {
		case <-done:
		case <-timer.C:
			return
		}
	}
}

// dnsStartLookup starts the reverse lookup of ip unless one is running and
// returns a channel that is closed when it is done.
func dnsStartLookup(ip string) <-chan struct{} {
	dnsCacheMutex.Lock()
	if done, ok := dnsInflight[ip]; ok {
		dnsCacheMutex.Unlock()
		return done
	}
	done := make(chan struct{})
	dnsInflight[ip] = done
	dnsCacheMutex.Unlock()

	go func() {
		dnsSlots <- struct{}{}
		name := dnsLookupName(ip)
		<-dnsSlots
		dnsCacheMutex.Lock()
		if name != "" {
			dnsCache[ip] = dnsEntry{name: name}
		} else {
			dnsCache[ip] = dnsEntry{failedAt: dnsClock()}
		}
		if dnsInflight[ip] == done {
			delete(dnsInflight, ip)
		}
		dnsCacheMutex.Unlock()
		close(done)
	}()
	return done
}

// dnsLookupName does one reverse lookup of ip and returns the short host
// name ("PC-JAMIL.tuit.local." → "PC-JAMIL"), or "" when there is none.
func dnsLookupName(ip string) string {
	ctx, cancel := context.WithTimeout(context.Background(), dnsLookupTimeout)
	defer cancel()
	names, err := lookupAddr(ctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	// Take first result, remove trailing dot
	name := strings.TrimSuffix(names[0], ".")
	// Remove domain part (keep only hostname)
	if idx := strings.Index(name, "."); idx > 0 {
		name = name[:idx]
	}
	return name
}

// graphHostnameIPs lists the IPs whose reverse DNS names a build of
// snapshot uses: the IPs (the switch's ARP table first, then the MAC-IP
// cache, as buildGraphEdges looks them up) of the LLDP neighbors and of the
// FDB MACs that get nodes (fdbPorts), in IP order of the devices.
func graphHostnameIPs(snapshot map[string]*DeviceData, switchMACs map[string]string) []string {
	globalMACtoIPMutex.RLock()
	defer globalMACtoIPMutex.RUnlock()
	seen := make(map[string]bool)
	var ips []string
	for _, devIP := range sortedDeviceIPs(snapshot) {
		data := snapshot[devIP]
		local := make(map[string]string, len(data.ARPTable))
		for _, arpEntry := range data.ARPTable {
			local[normalizeMAC(arpEntry.MACAddress)] = arpEntry.IPAddress
		}
		add := func(mac string) {
			ip, ok := local[mac]
			if !ok {
				ip = globalMACtoIP[mac]
			}
			if ip != "" && !seen[ip] {
				seen[ip] = true
				ips = append(ips, ip)
			}
		}
		for _, n := range data.Neighbors {
			if targetID, _, ok := graphLLDPNeighborTarget(data, n); ok {
				add(targetID)
			}
		}
		for _, p := range fdbPorts(data, switchMACs) {
			for _, mac := range p.MACs {
				add(mac)
			}
		}
	}
	return ips
}

// graphResolveHostnames looks up, before a build, the names the build of
// snapshot will use, waiting at most graphDNSWait: the build itself only
// reads the cache, so a slow DNS server delays a build by graphDNSWait at
// most instead of 2 s per name.
func graphResolveHostnames(snapshot map[string]*DeviceData, switchMACs map[string]string) {
	resolveHostnames(graphHostnameIPs(snapshot, switchMACs), graphDNSWait)
}

// countEdges counts total edges in graph
func countEdges(graph *DJGraph) int {
	count := 0
	if graph == nil {
		return 0
	}
	for _, targets := range graph.Edges {
		count += len(targets)
	}
	return count
}

// graphNodeCount is the number of nodes of graph, 0 without a graph (a scan
// that collected no switch publishes none).
func graphNodeCount(graph *DJGraph) int {
	if graph == nil {
		return 0
	}
	return len(graph.Nodes)
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

// collectGatewayARP collects the ARP table of every gateway into the global
// MAC-IP lookup, with the policy of every ARP collector (F70: this one used
// to overwrite and skip the ESXi check), and the sysName of each gateway
// that answers, for its router node (collectGatewaysARP). A gateway that
// does not answer gets the one warning of this run.
func collectGatewayARP() {
	// Create temporary SNMP object for the gateways
	snmpObj := &SNMPObject{
		Community: "public",
		Port:      161,
		Timeout:   pollTiming.Timeout, // the walks ran with -t 5 -r 1 whatever this said
		Retries:   pollTiming.Retries,
	}

	for _, res := range collectGatewaysARP(snmpObj) {
		if res.Err == nil {
			fmt.Printf("✅ Collected %d ARP entries from gateway %s\n", res.Rows, res.IP)
		}
	}
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
		glitch := false
		if inSpeed > maxSpeed {
			inSpeed = 0
			glitch = true
		}
		if outSpeed > maxSpeed {
			outSpeed = 0
			glitch = true
		}

		traffic.InSpeed = inSpeed
		traffic.OutSpeed = outSpeed

		// Update last values
		traffic.LastInOctets = iface.IfInOctets
		traffic.LastOutOctets = iface.IfOutOctets
		traffic.LastPollTime = now

		// A glitch that leaves both directions at 0 is no sample: written,
		// it would read as an idle poll of an up port (WriteInterfaceMetric)
		if glitch && inSpeed == 0 && outSpeed == 0 {
			continue
		}

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
// are NOT in collectedData. If alive (ping) and a switch (checkSwitch),
// triggers CollectData to add them (rescueScan).
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

// runRescueScan runs rescueScan over the lines of swich_ips, with ping as
// the alive check.
func runRescueScan(snmpObject *SNMPObject) {
	// 1. Read all IPs from swich_ips (may contain CIDRs)
	ranges, err := readSwitchIPsFile()
	if err != nil || len(ranges) == 0 {
		return
	}
	rescueScan(snmpObject, ranges, NewSNMPScanner(nil).isHostAlive)
}

// rescueScan is one run of the rescue scan over ranges (swich_ips lines,
// CIDRs expanded). Every IP that is not in collectedData and is alive is
// asked checkSwitch first: a switch is polled, any other device (access
// point, firewall, hypervisor, a host without SNMP) is not, and one line
// per run names those. One that answered SNMP stays an ARP source
// (addARPSource): the MAC-IP sweeps read the FortiGate's ARP table as they
// did while it was polled. A switch counts as recovered only when its poll
// stored it and it answered; the graph is rebuilt only then. Returns the
// recovered switches in IP order and the devices skipped.
func rescueScan(snmpObject *SNMPObject, ranges []string, alive func(ip string) bool) ([]string, *switchSkips) {
	skips := &switchSkips{}
	allIPs, err := NewSNMPScanner(nil).ExpandNetworks(ranges)
	if err != nil || len(allIPs) == 0 {
		return nil, skips
	}

	// 2. Find IPs NOT in collectedData (each once: a listed IP can also be
	// inside a listed range)
	collectedDataMutex.RLock()
	var missing []string
	listed := make(map[string]bool, len(allIPs))
	for _, ip := range allIPs {
		if _, exists := collectedData[ip]; !exists && !listed[ip] {
			missing = append(missing, ip)
		}
		listed[ip] = true
	}
	collectedDataMutex.RUnlock()
	keepARPSources(listed) // a device whose line was removed is none

	if len(missing) == 0 {
		return nil, skips
	}

	fmt.Printf("🔍 [Rescue] Checking %d unknown IPs from swich_ips...\n", len(missing))

	// 3. Ping filter → switch check → CollectData for alive switches
	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, 30) // max 30 parallel pings
	var recovered []string

	for _, ip := range missing {
		wg.Add(1)
		go func(targetIP string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			if !alive(targetIP) {
				return
			}
			check := snmpObject.checkSwitch(targetIP)
			if !check.isSwitch() {
				skips.add(check)
				addARPSource(check) // its ARP table is still read (the FortiGate's)
				return
			}

			// Alive switch: poll it
			fmt.Printf("✅ [Rescue] Alive switch found: %s (%s) — starting SNMP collect\n", targetIP, check.switchMIBs)
			snmpObject.CollectData(targetIP, "")
			if collectedReachable(targetIP) {
				mu.Lock()
				recovered = append(recovered, targetIP)
				mu.Unlock()
			}
		}(ip)
	}
	wg.Wait()
	skips.print("Rescue")
	slices.SortFunc(recovered, compareIPs)

	if len(recovered) > 0 {
		fmt.Printf("🎉 [Rescue] Recovered %d switches! Rebuilding graph...\n", len(recovered))
		rebuildGraph()
	}
	return recovered, skips
}

// collectScannedSwitch polls ip, a device the first scan or the UI rescan
// found answering SNMP, when it qualifies as a switch (checkSwitch); any
// other device is recorded in skips and not polled, and stays an ARP source
// (addARPSource).
func collectScannedSwitch(obj *SNMPObject, ip, sysName string, skips *switchSkips) {
	if check := obj.checkSwitch(ip); !check.isSwitch() {
		skips.add(check)
		addARPSource(check)
		return
	}
	obj.CollectData(ip, sysName)
}

// appendSwitchIP adds a discovered switch to swich_ips (appendToSwitchIPs).
// Tests replace it so the live file is never written.
var appendSwitchIP = appendToSwitchIPs

// discoverFromLLDP polls the management IPs that the LLDP neighbors of the
// polled devices advertise and adds each one that answers to swich_ips.
// Only neighbors whose enabled capabilities say router, or bridge without
// wlanAccessPoint and telephone (lldpDiscoverable), are considered: access
// points and IP phones advertise management IPs as well (F62 made them
// visible) but are no switches, and a neighbor with unknown capabilities is
// not added automatically. Their agents must pass checkSwitch too before
// they are polled, because a neighbor's capabilities are its own claim: the
// UniFi U6-Pro access points enable bridge and not wlanAccessPoint, so on
// 2026-10-22, the first run that saw management addresses, LLDP discovery
// polled them, stored their partial polls and appended 47 lines to
// swich_ips. One line names the ones that fail. Called after each periodic
// rescan to enable "chain reaction" discovery. Returns the devices skipped
// by checkSwitch.
func discoverFromLLDP(snmpObject *SNMPObject) *switchSkips {
	skips := &switchSkips{}
	collectedDataMutex.RLock()
	seen := make(map[string]bool, len(collectedData))
	for ip := range collectedData {
		seen[ip] = true
	}

	var newIPs []string
	for _, ip := range sortedDeviceIPs(collectedData) {
		for _, n := range collectedData[ip].Neighbors {
			if n.RemMgmtIP != "" && !seen[n.RemMgmtIP] && lldpDiscoverable(n.RemSysCapEnabled) {
				newIPs = append(newIPs, n.RemMgmtIP)
				seen[n.RemMgmtIP] = true // avoid duplicates in this batch
			}
		}
	}
	collectedDataMutex.RUnlock()

	if len(newIPs) == 0 {
		return skips
	}

	fmt.Printf("🔗 [LLDP-Discovery] Found %d new switch management IPs from LLDP neighbors\n", len(newIPs))

	var wg sync.WaitGroup
	for _, ip := range newIPs {
		// Check and poll immediately
		wg.Add(1)
		go func(targetIP string) {
			defer wg.Done()
			check := snmpObject.checkSwitch(targetIP)
			if !check.isSwitch() {
				skips.add(check)
				return
			}
			fmt.Printf("🔗 [LLDP-Discovery] Polling new switch: %s (%s)\n", targetIP, check.switchMIBs)
			snmpObject.CollectData(targetIP, "")
		}(ip)
	}
	wg.Wait()
	skips.print("LLDP-Discovery")

	// Save the switches that answered to swich_ips for future rescans
	added := 0
	for _, ip := range newIPs {
		if collectedReachable(ip) {
			appendSwitchIP(ip)
			added++
		}
	}

	if added > 0 {
		fmt.Printf("🎉 [LLDP-Discovery] Added %d new switches! Rebuilding graph...\n", added)
		rebuildGraph()
	}
	return skips
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

// buildSwitchOwnMACs maps every own MAC of the polled switches to the node
// id of its switch (graphDeviceNodeID). It is the one answer to "is this MAC
// a switch, and which one" for the FDB rule (fdbPorts: a switch's own MACs
// get no node, another switch's mark a switch port), the MAC cross-reference
// links (addMACCrossRefEdges) and the router nodes (addGatewayNodes). A
// switch's own MACs are its chassis MAC (graphChassisKey; none for exception
// text or a non-MAC chassis id) and its ARP aliases (switchARPAliases). Of
// two devices with one chassis MAC the last in IP order keeps it.
func buildSwitchOwnMACs(devices map[string]*DeviceData) map[string]string {
	switchMACs := make(map[string]string)
	for _, ip := range sortedDeviceIPs(devices) {
		d := devices[ip]
		if mac := graphChassisKey(d.ChassisID); mac != "" && !isInvalidID(mac) {
			switchMACs[mac] = graphDeviceNodeID(d)
		}
	}
	for mac, id := range switchARPAliases(devices, switchMACs) {
		switchMACs[mac] = id
	}
	return switchMACs
}

// switchARPAliases gives the ARP aliases of the polled switches, each with
// the node id of its switch: the MACs the ARP data maps to a switch's
// management IP. A switch answers ARP from the MAC of the VLAN interface
// that holds the IP, which is not always its chassis MAC, and a switch that
// never sends from its chassis MAC is learned in the FDBs by that MAC only.
// The HPE 5130 172.20.230.76 (chassis 4c:ae:a3:8d:ec:c1) holds its IP on
// Vlan-interface1, MAC 4c:ae:a3:8d:ec:cb, and the SNR 172.20.230.77 (chassis
// f8:f0:82:d8:62:67) on a VLAN interface with MAC f8:f0:82:d8:62:66 (live
// SNMP, 2026-10-22). Neither chassis MAC is in an FDB, in the saved data of
// 2026-10-20 or live on 2026-10-22. In the saved data, where LLDP is off on
// .76 (it was enabled at about 18:49 on 2026-10-22, and LLDP has linked .76
// to the Aruba 6300 and to .77 since), .77's VLAN MAC is the only switch MAC
// on .76 GigabitEthernet1/0/48, the port .77 hangs on. The ARP data is the ARP
// tables of the polled devices and globalMACtoIP (the gateways' ARP tables
// and the MAC-IP cache). A MAC is an alias only when all of it maps the MAC
// to one IP, that IP is a polled device's, and the MAC is no polled device's
// chassis MAC (chassis): a MAC with two IPs (a router answering for others,
// an address that moved, a stale cache entry: the fixture cache still maps
// .76's VLAN MAC to 172.20.230.247) is nobody's alias. A configured gateway
// stored without switch data (graphKnownSwitch) gets no alias: its MAC is
// its router node's (addGatewayNodes). It reads globalMACtoIP under
// globalMACtoIPMutex, so a caller may hold collectedDataMutex but never
// globalMACtoIPMutex.
func switchARPAliases(devices map[string]*DeviceData, chassis map[string]string) map[string]string {
	ips := make(map[string]map[string]bool) // MAC -> the IPs the ARP data maps it to
	add := func(mac, ip string) {
		if ips[mac] == nil {
			ips[mac] = make(map[string]bool)
		}
		ips[mac][ip] = true
	}
	for _, d := range devices {
		for _, e := range d.ARPTable {
			if mac, ip := usableMAC(e.MACAddress), parseIPv4(e.IPAddress); mac != "" && ip != "" {
				add(mac, ip)
			}
		}
	}
	// The cache entries of the polled IPs, and of the MACs the ARP tables
	// name (whose cache IP may be a second IP); cache keys are canonical
	globalMACtoIPMutex.RLock()
	for mac, ip := range globalMACtoIP {
		if _, polled := devices[ip]; polled || ips[mac] != nil {
			add(mac, ip)
		}
	}
	globalMACtoIPMutex.RUnlock()

	aliases := make(map[string]string)
	for mac, mapped := range ips {
		if len(mapped) != 1 || usableMAC(mac) != mac || isInvalidID(mac) {
			continue
		}
		if _, isChassis := chassis[mac]; isChassis {
			continue
		}
		for ip := range mapped {
			if d, polled := devices[ip]; polled && (graphKnownSwitch(d) || !isGatewayIP(ip)) {
				aliases[mac] = graphDeviceNodeID(d)
			}
		}
	}
	return aliases
}

// addMACCrossRefEdges links the switches that LLDP does not link (LLDP off,
// or no LLDP between them) through the FDBs: a switch whose own MAC
// (buildSwitchOwnMACs: its chassis MAC or an ARP alias) another switch learned
// on a port where no other switch is learned is linked from that port
// ("GE1/0/48 [MAC-REF]|Eth1/0/24", with the far switch's own port toward
// it from its FDB when that tells, macRefFarPort; "GE1/0/48 [MAC-REF]|"
// when not). A port where two or more other switches are
// learned is a transit port (an uplink: those switches arrived through
// further switches); a switch learned there by its chassis MAC and by an
// alias counts once. A port whose accepted LLDP neighbor is a polled switch
// gets no edge either: LLDP names the switch on that port, so a switch MAC
// learned there is behind it. 172.20.230.40 has 172.20.230.44 on port 25 and
// learns the chassis MAC of the Aruba 6300 172.20.230.253 there; once its FDB
// was read, that made a direct .40-Aruba link, as 172.20.230.47 Eth1/0/25
// (LLDP neighbor 4c:ae:a3:27:8b:2a) did in the saved data of 2026-10-20. And
// 172.20.254.202 Ten-GigabitEthernet1/0/51 learns the VLAN MAC of the HPE
// 172.20.230.76 behind its LLDP neighbor, the Aruba, whose port 1/1/1 has it
// (live SNMP, 2026-10-22). A switch gets one such link, from the port of all
// these with the fewest MACs, then the first switch in IP order, then the
// lower port (the rule gatewayPort places a router node with): a switch
// learned alone on an uplink with thousands of MACs is not linked from
// there when a port closer to it has it too. No link is added where the two
// are linked already.
func addMACCrossRefEdges(graph *DJGraph, allDevices map[string]*DeviceData, switchMACs map[string]string) {
	type macRefPort struct {
		src  int // index of the switch in deviceIPs
		port int // FDB bridge port
		macs int // MACs learned on the port
	}
	// Devices and ports are visited in order, so the port a switch is linked
	// from (and its label) is the same on every build.
	best := make(map[string]macRefPort) // switch node id -> the port it is linked from
	deviceIPs := sortedDeviceIPs(allDevices)
	for srcIndex, srcIP := range deviceIPs {
		srcDevice := allDevices[srcIP]
		srcID := graphDeviceNodeID(srcDevice)

		// The ports (ifIndex) whose LLDP neighbor is a polled switch
		lldpSwitchPorts := make(map[int]bool)
		for _, n := range srcDevice.Neighbors {
			if target, _, ok := graphLLDPNeighborTarget(srcDevice, n); ok {
				if _, polled := switchMACs[target]; polled {
					lldpSwitchPorts[n.LocalPortNum] = true
				}
			}
		}

		// The MACs and the other switches learned on each port. NULL0
		// interfaces (virtual discard ports, also when only the normalized
		// name tells) are no connection.
		portMACs := make(map[int]map[string]bool)
		portSwitches := make(map[int]map[string]bool)
		nullPorts := make(map[int]bool)
		for _, macEntry := range srcDevice.MACTable {
			port := macEntry.PortNumber
			null, seen := nullPorts[port]
			if !seen {
				name := getFDBPortName(srcDevice, port)
				null = isNullInterface(name) || isNullInterface(normalizePortName(name))
				nullPorts[port] = null
			}
			if null || lldpSwitchPorts[collectFDBIfIndex(srcDevice, port)] {
				continue // no connection, or LLDP names the switch on this port
			}
			mac := usableMAC(macEntry.MACAddress)
			if mac == "" {
				continue
			}
			if portMACs[port] == nil {
				portMACs[port] = make(map[string]bool)
			}
			portMACs[port][mac] = true
			if targetID, isSwitch := switchMACs[mac]; isSwitch && targetID != srcID {
				if portSwitches[port] == nil {
					portSwitches[port] = make(map[string]bool)
				}
				portSwitches[port][targetID] = true
			}
		}

		// A port with exactly one other switch (a direct connection) is a
		// candidate for that switch's link
		for _, port := range slices.Sorted(maps.Keys(portSwitches)) {
			if len(portSwitches[port]) != 1 {
				continue // 2+ switches on the port: transit/uplink
			}
			for targetID := range portSwitches[port] {
				c := macRefPort{src: srcIndex, port: port, macs: len(portMACs[port])}
				if b, found := best[targetID]; !found || c.macs < b.macs {
					best[targetID] = c
				}
			}
		}
	}

	// The links in switch and port order: of two switches that each picked
	// a port of the other, the first in IP order draws the link
	targets := slices.Collect(maps.Keys(best))
	slices.SortFunc(targets, func(a, b string) int {
		return cmp.Or(cmp.Compare(best[a].src, best[b].src), cmp.Compare(best[a].port, best[b].port), strings.Compare(a, b))
	})
	for _, targetID := range targets {
		c := best[targetID]
		srcDevice := allDevices[deviceIPs[c.src]]
		srcID := graphDeviceNodeID(srcDevice)
		if graph.GetEdge(srcID, targetID) {
			continue // an LLDP link (or this rule from the other side) has the pair
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
		portName := normalizePortName(getFDBPortName(srcDevice, c.port))
		farPort := macRefFarPort(allDevices, deviceIPs, srcID, targetID, switchMACs)
		graph.AddEdge(srcID, targetID, fmt.Sprintf("%s [MAC-REF]|%s", portName, farPort))
	}
}

// macRefFarPort is the far port of the MAC cross-reference link srcID ->
// targetID: the port of the switch targetID (the first device in IP order
// with that node id) toward srcID, read from its own FDB, where it learns
// the own MACs of srcID (switchMACs: the chassis MAC and the ARP aliases).
// When it learns them on two or more ports, the port toward srcID is the
// one of those where no other polled switch is learned (a port toward its
// other neighbors learns those). "" (unknown) when no port or more than one
// is left, when the switch has no FDB or none that learns srcID, or when
// its interface table does not name the port; NULL0 ports are no
// connection.
func macRefFarPort(allDevices map[string]*DeviceData, deviceIPs []string, srcID, targetID string, switchMACs map[string]string) string {
	var target *DeviceData
	for _, ip := range deviceIPs {
		if d := allDevices[ip]; graphDeviceNodeID(d) == targetID {
			target = d
			break
		}
	}
	if target == nil {
		return ""
	}
	toSource := make(map[int]bool)    // the bridge ports that learn an own MAC of srcID
	otherSwitch := make(map[int]bool) // the bridge ports that learn another switch's
	for _, e := range target.MACTable {
		id, isSwitch := switchMACs[usableMAC(e.MACAddress)]
		switch {
		case !isSwitch || id == targetID:
			// no switch MAC, or the target's own
		case id == srcID:
			toSource[e.PortNumber] = true
		default:
			otherSwitch[e.PortNumber] = true
		}
	}
	var ports []int
	for _, port := range slices.Sorted(maps.Keys(toSource)) {
		if name := getFDBPortName(target, port); !isNullInterface(name) && !isNullInterface(normalizePortName(name)) {
			ports = append(ports, port)
		}
	}
	if len(ports) > 1 {
		ports = slices.DeleteFunc(ports, func(port int) bool { return otherSwitch[port] })
	}
	if len(ports) != 1 {
		return ""
	}
	ifIndex := collectFDBIfIndex(target, ports[0])
	if !slices.ContainsFunc(target.Interfaces, func(i InterfaceData) bool { return i.IfIndex == ifIndex }) {
		return ""
	}
	return normalizePortName(getLocalPortName(target, ifIndex))
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
// switch nodes, LLDP and FDB edges, MAC cross-reference edges, the router
// nodes of the gateways that answered SNMP, hypervisor nodes and IP labels.
// Devices are visited in IP order. The graph is not published here;
// rebuildGraph does that once it is complete.
func buildGraphFromSnapshot(snapshot map[string]*DeviceData) *DJGraph {
	newGraph := NewDJGraph()
	deviceIPs := sortedDeviceIPs(snapshot)

	// 0. The own MACs of the switches: chassis MACs and ARP aliases
	switchMACs := buildSwitchOwnMACs(snapshot)

	// The reverse DNS names the labels use, looked up before the build and
	// waited for at most graphDNSWait (RC-1)
	graphResolveHostnames(snapshot, switchMACs)

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
		buildGraphEdges(newGraph, snapshot[ip], switchMACs)
	}

	// 3. MAC cross-reference edges (for LLDP-disabled switches)
	addMACCrossRefEdges(newGraph, snapshot, switchMACs)

	// 3b. One router node per gateway that answered SNMP, linked where its
	// MAC is learned (gateways.go)
	addGatewayNodes(newGraph, snapshot, switchMACs, answeredGateways())

	// 3c. The access points the controllers manage that no switch showed
	// (module_inventory.go)
	addManagedAPNodes(newGraph, snapshot, switchMACs)

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

// graphESXiTag is the label line of an HTTP-confirmed ESXi host.
const graphESXiTag = "[HYPERVISOR] VMware ESXi"

// graphTagHypervisorHost puts graphESXiTag and the VM count line of one of
// its ports ("13 VMs on ge1/0/26") at the top of a confirmed ESXi host's
// label, as a virtual hypervisor node's label starts; a host with VMs on
// two ports gets the tag once and a count line per port.
func graphTagHypervisorHost(graph *DJGraph, host, count string) {
	var lines []string
	for _, l := range strings.Split(graph.SwitchInfo[host], "\n") {
		if l != "" && l != graphESXiTag {
			lines = append(lines, l)
		}
	}
	at := 0
	for at < len(lines) && strings.Contains(lines[at], " VMs on ") {
		at++
	}
	lines = slices.Insert(lines, at, count)
	graph.SwitchInfo[host] = strings.Join(append([]string{graphESXiTag}, lines...), "\n")
}

// detectHypervisors scans the graph for switch ports where 2+ VM MACs are seen.
// Such ports indicate a connected hypervisor server (ESXi, Proxmox, Hyper-V, QEMU, Xen, VirtualBox).
// A virtual hypervisor node is inserted between the switch port and its VM endpoints;
// VMs behind a hub get it between the hub and the VMs, keyed by the hub's switch port.
// When the only HTTP-confirmed ESXi host learned on a switch port is a
// physical NIC (no VM OUI: a confirmed VM NIC is a nested ESXi, one of the
// VMs), that host is the hypervisor: the VMs hang from its node, which
// names the host (MAC, IP, DNS name) where a virtual node could not
// (172.20.254.202 GE1/0/26: the ESXi host 172.20.7.106 and its 13 VMs).
// A gateway's router node stays where addGatewayNodes linked it, also when
// the gateway is a VM (the Debian router 00:0c:29:98:7b:c2), and is never
// tagged as a server NIC.
func detectHypervisors(graph *DJGraph) {
	// portVMs: switchNodeID (or hub node ID) → port key → []vmMAC, and
	// portHosts: switchNodeID → port key → the confirmed ESXi host NICs.
	// Edges are visited in sorted order, so each port's VM list is the same
	// on every build.
	portVMs := map[string]map[string][]string{}
	portHosts := map[string]map[string][]string{}

	for _, src := range slices.Sorted(maps.Keys(graph.Edges)) {
		targets := graph.Edges[src]
		for _, tgt := range slices.Sorted(maps.Keys(targets)) {
			// Check if tgt MAC is a VM OUI (a gateway's router node is no
			// VM), or a confirmed ESXi host NIC on a switch port
			_, isVM := hypervisorTypeOf(tgt)
			isHost := !isVM && !strings.HasPrefix(src, "hub-") && graphIsConfirmedESXi(tgt) && !graphIsSwitchNode(graph, tgt)
			if (!isVM && !isHost) || graph.graphRouters[tgt] {
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
			if isHost {
				if portHosts[src] == nil {
					portHosts[src] = map[string][]string{}
				}
				portHosts[src][portKey] = append(portHosts[src][portKey], tgt)
				continue
			}
			if portVMs[src] == nil {
				portVMs[src] = map[string][]string{}
			}
			portVMs[src][portKey] = append(portVMs[src][portKey], tgt)
		}
	}

	// For each switch port with 2+ VM MACs → insert hypervisor node; a
	// confirmed ESXi host takes one VM too (254.202 GE1/0/18: the host
	// 172.20.9.149 and its VM 172.20.7.22)
	for _, switchID := range slices.Sorted(maps.Keys(portVMs)) {
		ports := portVMs[switchID]
		for _, port := range slices.Sorted(maps.Keys(ports)) {
			vmMACs := ports[port]
			hosts := portHosts[switchID][port]
			if len(vmMACs) < 2 && len(hosts) != 1 {
				continue // single VM MAC — could be real NIC, skip
			}

			// The one confirmed ESXi host on the port is the hypervisor
			if len(hosts) == 1 {
				host := hosts[0]
				graphTagHypervisorHost(graph, host, fmt.Sprintf("%d VMs on %s", len(vmMACs), port))
				for _, vmMAC := range vmMACs {
					delete(graph.Edges[switchID], vmMAC)
					graph.AddEdge(host, vmMAC, "vNIC")
				}
				fmt.Printf("🖥️  Hypervisor detected: VMware ESXi host %s on %s port %s (%d VMs: %s)\n",
					host, switchID[:min(len(switchID), 20)], port, len(vmMACs), vmMACs[0])
				continue
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
		if graphIsSwitchNode(graph, nodeID) || graph.graphRouters[nodeID] {
			continue // skip switches and the gateways' router nodes
		}
		if isServer, vendor := isServerNIC(nodeID); isServer {
			info := graph.SwitchInfo[nodeID]
			if strings.Contains(info, "[HYPERVISOR]") || strings.Contains(info, "[BMC]") {
				continue
			}
			// A confirmed ESXi host is named as one, like the confirmed
			// hosts with VMs, not by its NIC's vendor
			tag := fmt.Sprintf("[HYPERVISOR] %s Server", vendor)
			if graphIsConfirmedESXi(nodeID) {
				tag = graphESXiTag
			}
			graph.SwitchInfo[nodeID] = tag + "\n" + info
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
			// SNMP devices of the ranges that are no switches (checkSwitch)
			rescanSkips := &switchSkips{}

			// Create a temporary scanner for discovery
			scanner := NewSNMPScanner(func(result ScanResult) {
				switch result.Event {
				case EventSNMPSuccess:
					fmt.Printf("[✓] Rescan found: %s\n", result.IP)
				// Trigger data collection for found host (switches only)
				rescanWG.Add(1)
				go func(ip, name string) {
					defer rescanWG.Done()
					// Create a new SNMPObject with OnSuccess callback for each device
					settings := GetCurrentSettings()
					rescanSNMP := NewSNMPObject(
						storeCollected,
						func(ip string, err error) {
							markUnreachable(ip)
							fmt.Printf("🔴 [Rescan] Switch unreachable: %s (%v)\n", ip, err)
						},
					)
					if settings.Community != "" {
						rescanSNMP.Community = settings.Community
					}
					collectScannedSwitch(rescanSNMP, ip, name, rescanSkips)
				}(result.IP, result.SysName)

				case EventScanComplete:
					// Wait for all data collections to finish
					fmt.Println("⏳ Waiting for rescan data collection to complete...")
					rescanWG.Wait()
					rescanSkips.print("Rescan")

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
		"graph_nodes":          graphNodeCount(graph),
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

