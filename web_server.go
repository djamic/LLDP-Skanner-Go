package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ExperimentStatus holds the state of a running experiment
type ExperimentStatus struct {
	Running    bool      `json:"running"`
	Mode       string    `json:"mode"`
	ExpID      string    `json:"exp_id"`
	StartTime  time.Time `json:"start_time"`
	Progress   string    `json:"progress"`
	Cycles     int       `json:"cycles"`
	Remaining  string    `json:"remaining,omitempty"`
}

var (
	globalGraph      *DJGraph
	globalGraphMutex sync.RWMutex

	// Rescan trigger channel
	rescanTrigger chan bool

	// G.4 Experiment state
	experimentStatus  ExperimentStatus
	experimentCancel  context.CancelFunc
	experimentMutex   sync.RWMutex

	// E.1/E.2 — last analysis results for UI enrichment
	lastHealthScore int
	lastAnomalyMap  map[string][]string // nodeID → anomaly types
	lastTotalMACs   int
	lastReportMutex sync.RWMutex
)

// graphDebugFile receives a copy of every /api/graph response (debug
// snapshot). Tests point it at a temporary file.
var graphDebugFile = "graphs_data.txt"

func init() {
	rescanTrigger = make(chan bool, 1)
	lastAnomalyMap = make(map[string][]string)
}

// SetLastReport stores analysis results for UI enrichment (called from analyzer)
func SetLastReport(healthScore int, anomalyMap map[string][]string, totalMACs int) {
	lastReportMutex.Lock()
	defer lastReportMutex.Unlock()
	lastHealthScore = healthScore
	if anomalyMap != nil {
		lastAnomalyMap = anomalyMap
	}
	lastTotalMACs = totalMACs
}

// SetGlobalGraph sets the global graph instance
func SetGlobalGraph(g *DJGraph) {
	globalGraphMutex.Lock()
	defer globalGraphMutex.Unlock()
	globalGraph = g
}

// GetGlobalGraph retrieves the global graph instance
func GetGlobalGraph() *DJGraph {
	globalGraphMutex.RLock()
	defer globalGraphMutex.RUnlock()
	return globalGraph
}

// TriggerRescan signals that a rescan should be performed
func TriggerRescan() {
	select {
	case rescanTrigger <- true:
	default:
		// Already pending
	}
}

// GetRescanTrigger returns the rescan trigger channel
func GetRescanTrigger() <-chan bool {
	return rescanTrigger
}

// StartWebServer starts the HTTP server for web visualization
func StartWebServer(port string) {
	// Serve static files with no-cache for JS/CSS (ensures live updates)
	staticFS := http.FileServer(http.Dir("./static"))
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Prevent browser caching for JS/CSS so changes reflect immediately
		if filepath.Ext(r.URL.Path) == ".js" || filepath.Ext(r.URL.Path) == ".css" {
			w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("Expires", "0")
		}
		staticFS.ServeHTTP(w, r)
	})

	// API endpoints
	http.HandleFunc("/api/graph", graphHandler)
	http.HandleFunc("/api/hosts", hostsHandler)
	http.HandleFunc("/api/settings", settingsHandler)
	http.HandleFunc("/api/rescan", rescanHandler)
	http.HandleFunc("/api/status", statusHandler)
	http.HandleFunc("/api/history", historyHandler)
	http.HandleFunc("/api/device-detail", deviceDetailHandler)
	http.HandleFunc("/api/bot/action", botActionHandler)

	// Capture & Analysis API
	http.HandleFunc("/api/capture/start", captureStartHandler)
	http.HandleFunc("/api/capture/stop", captureStopHandler)
	http.HandleFunc("/api/captures", capturesHandler)
	http.HandleFunc("/api/report/generate", reportGenerateHandler)
	http.HandleFunc("/api/report/download", reportDownloadHandler)
	registerReportRoutes() // F.3: /api/report/summary + /api/report/topology-svg

	// G.4 Experiment API
	http.HandleFunc("/api/experiment/start", experimentStartHandler)
	http.HandleFunc("/api/experiment/status", experimentStatusHandler)
	http.HandleFunc("/api/experiment/stop", experimentStopHandler)
	http.HandleFunc("/api/experiment/results", experimentResultsHandler)

	// Events API
	http.HandleFunc("/api/events", eventsHandler)

	// Phase 14: Network Event History API
	http.HandleFunc("/api/port-events", portEventsHandler)
	http.HandleFunc("/api/port-events/stats", portEventsStatsHandler)

	// Terminal API (SSH/Telnet/Web)
	registerTerminalRoutes()

	addr := ":" + port
	fmt.Printf("\n🌐 Web server starting on http://localhost%s\n", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

// graphHandler returns the current graph data in D3.js format
func graphHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	globalGraphMutex.RLock()
	defer globalGraphMutex.RUnlock()
	graph := globalGraph
	if graph == nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "No graph data available yet",
			"nodes": []interface{}{},
			"links": []interface{}{},
		})
		return
	}
	data := graph.GetGraphData()

	// E.1/E.2: Enrich graph data with health score and anomaly info
	lastReportMutex.RLock()
	data.HealthScore = float64(lastHealthScore)
	data.TotalMACs = lastTotalMACs
	if len(lastAnomalyMap) > 0 {
		for i, node := range data.Nodes {
			if anomalies, ok := lastAnomalyMap[node.ID]; ok {
				data.Nodes[i].Anomalies = anomalies
			}
		}
	}
	lastReportMutex.RUnlock()

	// DEBUG: Save snapshot
	if jsonData, err := json.MarshalIndent(data, "", "  "); err == nil {
		os.WriteFile(graphDebugFile, jsonData, 0644)
	}

	json.NewEncoder(w).Encode(data)
}

// hostsHandler handles host management (GET list, DELETE clear)
func hostsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, DELETE, OPTIONS")

	if r.Method == "OPTIONS" {
		return
	}

	switch r.Method {
	case "GET":
		// Primary: return in-memory collectedData (always fresh)
		collectedDataMutex.RLock()
		hostCount := len(collectedData)
		if hostCount > 0 {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"hosts":     collectedData,
				"count":     hostCount,
				"timestamp": time.Now(),
			})
			collectedDataMutex.RUnlock()
			return
		}
		collectedDataMutex.RUnlock()

		// Fallback: return saved hosts from file
		saved, err := LoadSavedData()
		if err != nil || saved == nil {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"hosts": map[string]interface{}{},
				"count": 0,
			})
			return
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"hosts":     saved.Hosts,
			"count":     len(saved.Hosts),
			"timestamp": saved.Timestamp,
		})

	case "DELETE":
		// Clear all hosts
		if err := ClearSavedData(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Clear InfluxDB data
		if err := ClearInfluxData(); err != nil {
			fmt.Printf("Warning: %v\n", err)
		}

		// Clear memory state (stop polling)
		collectedDataMutex.Lock()
		collectedData = make(map[string]*DeviceData)
		collectedDataMutex.Unlock()

		interfaceTrafficMapMutex.Lock()
		interfaceTrafficMap = make(map[string]map[int]*InterfaceTraffic)
		interfaceTrafficMapMutex.Unlock()

		// Clear graph
		SetGlobalGraph(NewDJGraph())

		json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"message": "All hosts and memory state cleared",
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// settingsHandler handles settings (GET/POST)
func settingsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	switch r.Method {
	case "GET":
		json.NewEncoder(w).Encode(GetCurrentSettings())

	case "POST":
		var settings ScanSettings
		if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON: " + err.Error()})
			return
		}
		SetCurrentSettings(settings)

		// Save with current hosts
		collectedDataMutex.RLock()
		hosts := make(map[string]*DeviceData)
		for k, v := range collectedData {
			hosts[k] = v
		}
		collectedDataMutex.RUnlock()

		if err := SaveData(hosts, settings); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": "Failed to save: " + err.Error()})
			return
		}

		json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"message": "Settings saved",
		})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// rescanHandler triggers a rescan
func rescanHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")

	if r.Method == "OPTIONS" {
		return
	}

	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	TriggerRescan()
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"message": "Rescan triggered",
	})
}

// statusHandler returns current app status
func statusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	globalGraphMutex.RLock()
	graph := globalGraph
	nodeCount := 0
	edgeCount := 0
	if graph != nil {
		nodeCount = len(graph.Nodes)
		edgeCount = countEdges(graph)
	}
	globalGraphMutex.RUnlock()

	collectedDataMutex.RLock()
	hostCount := len(collectedData)
	collectedDataMutex.RUnlock()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"hosts":    hostCount,
		"nodes":    nodeCount,
		"edges":    edgeCount,
		"settings": GetCurrentSettings(),
		"hasSaved": HasSavedData(),
	})
}

// historyHandler returns traffic history for a device
// Usage: GET /api/history?id=172.20.254.10&hours=24
func historyHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	// Get query parameters
	deviceIP := r.URL.Query().Get("id")
	if deviceIP == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "Missing 'id' parameter (device IP)",
		})
		return
	}

	// Get hours parameter (default 24)
	hoursStr := r.URL.Query().Get("hours")
	hours := 24
	if hoursStr != "" {
		if h, err := strconv.Atoi(hoursStr); err == nil && h > 0 {
			hours = h
		}
	}

	// Query InfluxDB
	points, err := QueryTrafficHistory(deviceIP, hours)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":  err.Error(),
			"device": deviceIP,
			"hours":  hours,
			"data":   []interface{}{},
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"device": deviceIP,
		"hours":  hours,
		"count":  len(points),
		"data":   points,
	})
}

// deviceDetailHandler returns full interface + VLAN + traffic detail for a device
// Usage: GET /api/device-detail?id=172.20.254.10
func deviceDetailHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	deviceIP := r.URL.Query().Get("id")
	if deviceIP == "" {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "Missing 'id' parameter (device IP)",
		})
		return
	}

	// Get device data from memory
	collectedDataMutex.RLock()
	dev, exists := collectedData[deviceIP]
	collectedDataMutex.RUnlock()

	if !exists {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error": "Device not found: " + deviceIP,
		})
		return
	}

	// Build interface detail with real-time traffic
	type InterfaceDetail struct {
		IfIndex       int    `json:"if_index"`
		IfDescr       string `json:"if_descr"`
		IfAlias       string `json:"if_alias"`
		IfOperStatus  int    `json:"if_oper_status"`
		IfAdminStatus int    `json:"if_admin_status"`
		IfSpeed       uint64 `json:"if_speed"`
		InBps         uint64 `json:"in_bps"`
		OutBps        uint64 `json:"out_bps"`
		InErrors      uint64 `json:"in_errors"`
		OutErrors     uint64 `json:"out_errors"`
		InDiscards    uint64 `json:"in_discards"`
		OutDiscards   uint64 `json:"out_discards"`
	}

	type PortVLANDetail struct {
		PortIndex int    `json:"port_index"`
		PVID      int    `json:"pvid"`
		IsTrunk   bool   `json:"is_trunk"`
		VLANs     []int  `json:"vlans"`
	}

	interfaces := make([]InterfaceDetail, 0, len(dev.Interfaces))

	// Get traffic data
	interfaceTrafficMapMutex.RLock()
	devTraffic := interfaceTrafficMap[deviceIP]
	interfaceTrafficMapMutex.RUnlock()

	for _, iface := range dev.Interfaces {
		detail := InterfaceDetail{
			IfIndex:       iface.IfIndex,
			IfDescr:       iface.IfDescr,
			IfAlias:       iface.IfAlias,
			IfOperStatus:  iface.IfOperStatus,
			IfAdminStatus: iface.IfAdminStatus,
			IfSpeed:       iface.IfSpeed,
			InErrors:      iface.IfInErrors,
			OutErrors:     iface.IfOutErrors,
			InDiscards:    iface.IfInDiscards,
			OutDiscards:   iface.IfOutDiscards,
		}

		// Add real-time traffic speeds
		if devTraffic != nil {
			if traffic, ok := devTraffic[iface.IfIndex]; ok {
				detail.InBps = traffic.InSpeed
				detail.OutBps = traffic.OutSpeed
			}
		}

		interfaces = append(interfaces, detail)
	}

	// Port VLANs
	vlans := make([]PortVLANDetail, 0, len(dev.PortVLANs))
	for _, pv := range dev.PortVLANs {
		vlans = append(vlans, PortVLANDetail{
			PortIndex: pv.PortIndex,
			PVID:      pv.PVID,
			IsTrunk:   pv.IsTrunk,
			VLANs:     pv.VLANs,
		})
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"ip":         dev.IP,
		"sys_name":   dev.SysName,
		"interfaces": interfaces,
		"port_vlans": vlans,
	})
}

// botActionHandler handles button clicks from the Telegram bot
type BotActionPayload struct {
	Action  string `json:"action"`   // "ignore" or "verify"
	IssueID string `json:"issue_id"` // e.g. "shadow_192_168_1_1_12"
}

func botActionHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")

	if r.Method == "OPTIONS" {
		return
	}
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload BotActionPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid payload", http.StatusBadRequest)
		return
	}

	switch payload.Action {
	case "ignore":
		IgnoreIssue(payload.IssueID)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": "Issue ignored"})
	case "verify":
		UnignoreIssue(payload.IssueID)
		ResetIssueCooldown(payload.IssueID)
		TriggerRescan()
		json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": "Issue un-ignored, cooldown reset, rescan triggered"})
	default:
		http.Error(w, "Unknown action", http.StatusBadRequest)
	}
}

// -- Capture & Analysis Handlers --

// captureStartHandler starts a new capture session
// POST /api/capture/start?name=MySession
func captureStartHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")

	if r.Method == "OPTIONS" {
		return
	}
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if globalCaptureManager == nil {
		http.Error(w, "Capture manager not initialized", http.StatusInternalServerError)
		return
	}

	name := r.URL.Query().Get("name")
	
	globalGraphMutex.RLock()
	graph := globalGraph
	if graph == nil {
		graph = NewDJGraph()
	}
	globalGraphMutex.RUnlock()

	id, err := globalCaptureManager.StartCapture(name, graph)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"status":     "started",
		"session_id": id,
		"message":    "Capture started successfully",
	})
}

// captureStopHandler stops the active capture session
// POST /api/capture/stop
func captureStopHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")

	if r.Method == "OPTIONS" {
		return
	}
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if globalCaptureManager == nil {
		http.Error(w, "Capture manager not initialized", http.StatusInternalServerError)
		return
	}

	id, err := globalCaptureManager.StopCapture()
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"status":     "completed",
		"session_id": id,
		"message":    "Capture stopped and saved",
	})
}

// capturesHandler lists all available captures
// GET /api/captures
func capturesHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	
	if globalCaptureManager == nil {
		http.Error(w, "Capture manager not initialized", http.StatusInternalServerError)
		return
	}

	sessions, err := globalCaptureManager.ListCaptures()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	active := globalCaptureManager.ActiveSession()
	
	json.NewEncoder(w).Encode(map[string]interface{}{
		"sessions": sessions,
		"active":   active,
	})
}

// reportGenerateHandler generates a report for a specific session
// POST /api/report/generate?id=SESSION_ID
func reportGenerateHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")

	if r.Method == "OPTIONS" {
		return
	}
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	sessionID := r.URL.Query().Get("id")
	if sessionID == "" {
		http.Error(w, "Missing 'id' parameter", http.StatusBadRequest)
		return
	}

	// In a real app, we would load the specific file.
	// For now, let's assume we load it from disk using simple file read
	// duplicating logic from analyzer or capture manager would be better
	
	// Create Analyzer
	filename := fmt.Sprintf("captures/%s_full_data.json", sessionID)
	// assuming capture manager initializes "captures/" dir relative to cwd
	
	file, err := os.Open(filename)
	if err != nil {
		http.Error(w, "Session file not found: "+err.Error(), http.StatusNotFound)
		return
	}
	defer file.Close()

	var fullData FullCaptureData
	if err := json.NewDecoder(file).Decode(&fullData); err != nil {
		http.Error(w, "Failed to decode session data: "+err.Error(), http.StatusInternalServerError)
		return
	}

	analyzer := NewAnalyzer(fullData)
	report := analyzer.Analyze()
	
	// Generate text report
	textReport := report.GenerateTextReport()

	json.NewEncoder(w).Encode(map[string]interface{}{
		"report":      report,
		"text_summary": textReport,
	})
}

// reportDownloadHandler downloads the report as a Word document (.doc)
// GET /api/report/download?id=SESSION_ID
func reportDownloadHandler(w http.ResponseWriter, r *http.Request) {
	sessionID := r.URL.Query().Get("id")
	if sessionID == "" {
		http.Error(w, "Missing 'id' parameter", http.StatusBadRequest)
		return
	}

	filename := fmt.Sprintf("captures/%s_full_data.json", sessionID)
	file, err := os.Open(filename)
	if err != nil {
		http.Error(w, "Session file not found", http.StatusNotFound)
		return
	}
	defer file.Close()

	var fullData FullCaptureData
	if err := json.NewDecoder(file).Decode(&fullData); err != nil {
		http.Error(w, "Failed to decode session data", http.StatusInternalServerError)
		return
	}

	analyzer := NewAnalyzer(fullData)
	report := analyzer.Analyze()
	htmlContent := report.GenerateHTMLReport()

	// Set headers for Word download
	w.Header().Set("Content-Type", "application/msword")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"Network_Report_%s.doc\"", sessionID))
	
	// Write BOM for UTF-8 compatibility
	w.Write([]byte("\xEF\xBB\xBF"))
	w.Write([]byte(htmlContent))
}

// ============================================================
// G.4 — Experiment API Handlers
// ============================================================

// experimentStartHandler starts an experiment in background
func experimentStartHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	if r.Method == "OPTIONS" {
		return
	}
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	experimentMutex.Lock()
	if experimentStatus.Running {
		experimentMutex.Unlock()
		w.WriteHeader(http.StatusConflict)
		json.NewEncoder(w).Encode(map[string]string{
			"error": "Experiment already running",
		})
		return
	}

	// Parse request body
	var req struct {
		Mode     string `json:"mode"`
		Workers  int    `json:"workers"`
		ExpID    string `json:"exp_id"`
		Duration string `json:"duration"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		experimentMutex.Unlock()
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid JSON"})
		return
	}

	if req.Mode == "" {
		req.Mode = "experiment"
	}
	if req.Workers <= 0 {
		req.Workers = 50
	}

	// Set flags for the experiment
	*modeFlag = req.Mode
	*workersFlag = req.Workers
	if req.ExpID != "" {
		*expIDFlag = req.ExpID
	}
	if req.Duration != "" {
		*durationFlag = req.Duration
	}

	ctx, cancel := context.WithCancel(context.Background())
	experimentCancel = cancel
	experimentStatus = ExperimentStatus{
		Running:   true,
		Mode:      req.Mode,
		ExpID:     req.ExpID,
		StartTime: time.Now(),
		Progress:  "Starting...",
	}
	experimentMutex.Unlock()

	// Run experiment in background
	go func() {
		defer func() {
			experimentMutex.Lock()
			experimentStatus.Running = false
			experimentStatus.Progress = "Completed"
			experimentMutex.Unlock()
		}()

		_ = ctx // Available for cancellation in future

		switch req.Mode {
		case "monitor24h":
			experimentMutex.Lock()
			experimentStatus.Progress = "Running monitor24h"
			experimentMutex.Unlock()
			// Note: runMonitor24h calls os.Exit, so for web API we just update status
			// In a full implementation, runMonitor24h would accept a context
			fmt.Println("[WEB API] monitor24h started via API")
		default:
			experimentMutex.Lock()
			experimentStatus.Progress = "Running experiment scan"
			experimentMutex.Unlock()
			fmt.Println("[WEB API] experiment started via API")
		}
	}()

	json.NewEncoder(w).Encode(map[string]string{
		"status":  "started",
		"mode":    req.Mode,
		"exp_id":  req.ExpID,
		"message": "Experiment started in background",
	})
}

// experimentStatusHandler returns current experiment status
func experimentStatusHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	experimentMutex.RLock()
	status := experimentStatus
	experimentMutex.RUnlock()

	response := map[string]interface{}{
		"running":    status.Running,
		"mode":       status.Mode,
		"exp_id":     status.ExpID,
		"progress":   status.Progress,
		"cycles":     status.Cycles,
	}
	if status.Running {
		response["elapsed"] = time.Since(status.StartTime).Round(time.Second).String()
		if status.Remaining != "" {
			response["remaining"] = status.Remaining
		}
	}

	json.NewEncoder(w).Encode(response)
}

// experimentStopHandler stops the running experiment
func experimentStopHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")

	if r.Method == "OPTIONS" {
		return
	}
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	experimentMutex.Lock()
	if !experimentStatus.Running {
		experimentMutex.Unlock()
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "idle",
			"message": "No experiment running",
		})
		return
	}

	if experimentCancel != nil {
		experimentCancel()
	}
	experimentStatus.Running = false
	experimentStatus.Progress = "Cancelled"
	experimentMutex.Unlock()

	json.NewEncoder(w).Encode(map[string]string{
		"status":  "stopped",
		"message": "Experiment cancelled",
	})
}

// experimentResultsHandler lists result files in the output directory
func experimentResultsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	resultsDir := "results"
	if outputFlag != nil && *outputFlag != "" {
		resultsDir = *outputFlag
	}

	var files []map[string]interface{}
	entries, err := os.ReadDir(resultsDir)
	if err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"files": []interface{}{},
			"error": "Results directory not found",
		})
		return
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		info, _ := entry.Info()
		files = append(files, map[string]interface{}{
			"name":     entry.Name(),
			"path":     filepath.Join(resultsDir, entry.Name()),
			"size":     info.Size(),
			"modified": info.ModTime().Format("2006-01-02 15:04:05"),
		})
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"files": files,
		"count": len(files),
	})
}

// ============================================================
// Phase 14 — Network Event History Handlers
// ============================================================

// portEventsHandler handles GET (query events) and DELETE (clear events)
func portEventsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, DELETE, OPTIONS")

	if r.Method == "OPTIONS" {
		return
	}

	switch r.Method {
	case "GET":
		ip := r.URL.Query().Get("ip")
		if ip == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Missing 'ip' parameter"})
			return
		}

		hours := 24
		if h := r.URL.Query().Get("hours"); h != "" {
			if v, err := strconv.Atoi(h); err == nil && v > 0 {
				hours = v
			}
		}

		var eventTypes []string
		if t := r.URL.Query().Get("type"); t != "" {
			eventTypes = strings.Split(t, ",")
		}

		portFilter := 0
		if p := r.URL.Query().Get("port"); p != "" {
			if v, err := strconv.Atoi(p); err == nil {
				portFilter = v
			}
		}

		events, err := QueryNetworkEvents(ip, hours, eventTypes, portFilter)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		if events == nil {
			events = []NetworkEventRecord{}
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"device": ip,
			"hours":  hours,
			"total":  len(events),
			"events": events,
		})

	case "DELETE":
		fromStr := r.URL.Query().Get("from")
		toStr := r.URL.Query().Get("to")

		if fromStr != "" && toStr != "" {
			// Range delete
			fromTime, err1 := time.Parse(time.RFC3339, fromStr)
			toTime, err2 := time.Parse(time.RFC3339, toStr)
			if err1 != nil || err2 != nil {
				w.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(w).Encode(map[string]string{"error": "Invalid date format, use RFC3339"})
				return
			}
			if err := DeleteNetworkEventsRange(fromTime, toTime); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "ok",
				"message": "Events in range cleared from InfluxDB",
				"range":   map[string]string{"from": fromStr, "to": toStr},
			})
		} else {
			// Clear all
			if err := DeleteAllNetworkEvents(); err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":  "ok",
				"message": "All network events cleared from InfluxDB",
			})
		}

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// portEventsStatsHandler returns aggregated port event statistics
func portEventsStatsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	ip := r.URL.Query().Get("ip")
	if ip == "" {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Missing 'ip' parameter"})
		return
	}

	hours := 24
	if h := r.URL.Query().Get("hours"); h != "" {
		if v, err := strconv.Atoi(h); err == nil && v > 0 {
			hours = v
		}
	}

	// Query all events for this device
	events, err := QueryNetworkEvents(ip, hours, nil, 0)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}

	// Compute statistics
	stats := EventStats{
		Device: ip,
		Hours:  hours,
		ByPort: make(map[int]PortEventSummary),
	}

	for _, evt := range events {
		switch evt.Type {
		case "port_down", "host_down":
			stats.PortDownCount++
			if evt.Port > 0 {
				ps := stats.ByPort[evt.Port]
				ps.DownCount++
				stats.ByPort[evt.Port] = ps
			}
		case "unreachable":
			stats.UnreachableCount++
		}

		// Track longest outage from duration_s
		if evt.DurationS != nil && *evt.DurationS > 0 {
			minutes := float64(*evt.DurationS) / 60.0
			if minutes > stats.LongestOutageMin {
				stats.LongestOutageMin = minutes
			}
			// Add to per-port total
			if evt.Port > 0 {
				ps := stats.ByPort[evt.Port]
				ps.TotalDownMinutes += minutes
				stats.ByPort[evt.Port] = ps
			}
		}
	}

	// Clean up empty ByPort
	if len(stats.ByPort) == 0 {
		stats.ByPort = nil
	}

	json.NewEncoder(w).Encode(stats)
}

// eventsHandler returns network events (MAC joins/leaves, host changes)
func eventsHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	events := GetNetworkEvents()

	// Reverse: newest first
	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
		events[i], events[j] = events[j], events[i]
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"events": events,
		"count":  len(events),
	})
}
