package main

import (
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"
)

// NetworkAnalyzer handles analysis of network capture data
type NetworkAnalyzer struct {
	Data FullCaptureData

	index *analyzerIndex // Data indexed for the checks, built on first use
}

// analyzerIndex is the analyzer input in a fixed order, with the topology
// nodes by id.
type analyzerIndex struct {
	devices []*DeviceData          // DevicesData in IP order
	byIP    map[string]*DeviceData // DevicesData by IP
	nodes   map[string]GraphNode   // Topology nodes by id
}

// idx builds the index of na.Data on first use.
func (na *NetworkAnalyzer) idx() *analyzerIndex {
	if na.index != nil {
		return na.index
	}
	ix := &analyzerIndex{byIP: make(map[string]*DeviceData), nodes: make(map[string]GraphNode)}
	for i := range na.Data.DevicesData {
		d := &na.Data.DevicesData[i]
		ix.byIP[d.IP] = d
	}
	for _, ip := range sortedDeviceIPs(ix.byIP) {
		ix.devices = append(ix.devices, ix.byIP[ip])
	}
	for _, n := range na.Data.Topology.Nodes {
		ix.nodes[n.ID] = n
	}
	na.index = ix
	return ix
}

// analyzerSwitchIDs lists the node ids the graph can give the polled switch
// d: its node id (graphDeviceNodeID, as buildGraphFromSnapshot names it),
// then its IP.
func analyzerSwitchIDs(d *DeviceData) []string {
	if id := graphDeviceNodeID(d); id != d.IP {
		return []string{id, d.IP}
	}
	return []string{d.IP}
}

// analyzerUniqueMACs returns the distinct MAC addresses (normalizeMAC) in the
// FDB tables of devices. Its size is total_macs (Q15): an address learned by
// several switches, or on several ports, counts once.
func analyzerUniqueMACs(devices []*DeviceData) map[string]bool {
	macs := make(map[string]bool)
	for _, d := range devices {
		for _, macEntry := range d.MACTable {
			if mac := normalizeMAC(macEntry.MACAddress); mac != "" {
				macs[mac] = true
			}
		}
	}
	return macs
}

// switchNode returns the topology node of the polled switch with this IP, or
// the IP itself when the topology has no node for it.
func (ix *analyzerIndex) switchNode(ip string) string {
	if d, ok := ix.byIP[ip]; ok {
		for _, id := range analyzerSwitchIDs(d) {
			if _, ok := ix.nodes[id]; ok {
				return id
			}
		}
	}
	return ip
}

// hubNode returns the hub node the graph draws for a port of switch d
// ("hub-<switch node>-p<port>"), or the switch node when there is none.
func (ix *analyzerIndex) hubNode(d *DeviceData, port int) string {
	for _, id := range analyzerSwitchIDs(d) {
		hub := fmt.Sprintf("hub-%s-p%d", id, port)
		if _, ok := ix.nodes[hub]; ok {
			return hub
		}
	}
	return ix.switchNode(d.IP)
}

// anomalyMap groups the suggestion types by the graph node /api/graph shows
// them on (F11): the hub node of a Shadow-IT port, the far node of a path
// suggestion, the switch node when Device is a polled switch's IP, and
// otherwise Device itself (the STP root bridge MAC).
func (na *NetworkAnalyzer) anomalyMap(suggestions []OptimizationSuggestion) map[string][]string {
	ix := na.idx()
	anomalies := make(map[string][]string)
	for _, sugg := range suggestions {
		key := sugg.nodeID
		if key == "" && sugg.Device != "" {
			key = ix.switchNode(sugg.Device)
		}
		if key != "" {
			anomalies[key] = append(anomalies[key], sugg.Type)
		}
	}
	return anomalies
}

// NewAnalyzer creates a new analyzer instance
func NewAnalyzer(data FullCaptureData) *NetworkAnalyzer {
	return &NetworkAnalyzer{
		Data: data,
	}
}

// OptimizationSuggestion represents a suggested improvement
type OptimizationSuggestion struct {
	IssueID     string `json:"issue_id"` // Unique ID for interactive actions
	Type        string `json:"type"`     // "path", "congestion", "stability", "shadow_it", "stp"
	Severity    string `json:"severity"` // "high", "medium", "low"
	Device      string `json:"device"`
	Description string `json:"description"`
	Value       string `json:"value"` // e.g., "5 hops", "95% util"

	nodeID string // graph node the anomaly is shown on, when Device does not name it
}

// Report represents the final analysis report
type Report struct {
	SessionID   string                   `json:"session_id"`
	GeneratedAt time.Time                `json:"generated_at"`
	Summary     map[string]int           `json:"summary"`
	Suggestions []OptimizationSuggestion `json:"suggestions"`
	Nodes       []GraphNode              `json:"nodes"`
	HealthScore int                      `json:"health_score"`
}

// Analyze runs every check (BuildReport) and publishes the result as the
// live network state: Telegram alerts, the InfluxDB anomaly summary, and the
// health score, anomalies and MAC count behind /api/graph and the reports.
// Capture reports call BuildReport instead, so they never touch that state.
func (na *NetworkAnalyzer) Analyze() Report {
	report := na.BuildReport()

	// Trigger Telegram notification if there are critical issues or health score is low
	na.notifyTelegramIfCritical(&report)

	// B.4: Write anomaly summary to InfluxDB
	WriteAnomalySummary(&report)

	// E.1/E.2: Store health score + anomaly map (by graph node) for UI
	// enrichment via /api/graph, and the suggestions for the reports
	anomalyMap := na.anomalyMap(report.Suggestions)
	totalMACs := len(analyzerUniqueMACs(na.idx().devices))
	SetLastReport(report.HealthScore, anomalyMap, totalMACs, report.Suggestions...)

	return report
}

// BuildReport performs all analysis checks and computes the health score.
// It has no side effects.
func (na *NetworkAnalyzer) BuildReport() Report {
	report := Report{
		SessionID:   na.Data.Session.ID,
		GeneratedAt: time.Now(),
		Summary:     make(map[string]int),
		Nodes:       na.Data.Topology.Nodes,
	}

	suggestions := []OptimizationSuggestion{}

	// 1. Path Optimization Analysis
	pathSuggestions := na.analyzePaths()
	suggestions = append(suggestions, pathSuggestions...)
	report.Summary["path_issues"] = len(pathSuggestions)

	// 2. Congestion Analysis
	congestionSuggestions := na.analyzeCongestion()
	suggestions = append(suggestions, congestionSuggestions...)
	report.Summary["congestion_issues"] = len(congestionSuggestions)

	// 3. Stability Analysis
	stabilitySuggestions := na.analyzeStability()
	suggestions = append(suggestions, stabilitySuggestions...)
	report.Summary["stability_issues"] = len(stabilitySuggestions)

	// 4. Shadow IT Detection (Port-MAC Ratio)
	shadowITSuggestions := na.analyzeShadowIT()
	suggestions = append(suggestions, shadowITSuggestions...)
	report.Summary["shadow_it_issues"] = len(shadowITSuggestions)

	// 5. STP Analysis (Root Bridge Audit)
	stpSuggestions := na.analyzeSTP()
	suggestions = append(suggestions, stpSuggestions...)
	report.Summary["stp_issues"] = len(stpSuggestions)

	// 6. Loopback Detection
	loopbackSuggestions := na.analyzeLoopback()
	suggestions = append(suggestions, loopbackSuggestions...)
	report.Summary["loopback_issues"] = len(loopbackSuggestions)

	report.Suggestions = suggestions

	// Calculate Health Score
	report.HealthScore = na.CalculateHealthScore(&report)

	return report
}

// Notification cooldown tracking - 1 hour between notifications for the same issue
var (
	notifiedIssues   = make(map[string]time.Time) // issueID -> last notification time
	notifiedMu       sync.Mutex
	notifyCooldown   = 1 * time.Hour
	lastSummarySent  time.Time
)

// Analyserbot relay. Tests replace postBotNotify to record the messages
// instead of posting them, set botFloodDelay to 0 and make botDispatch run
// each send synchronously.
var (
	postBotNotify = postToBot
	botFloodDelay = 500 * time.Millisecond
	botDispatch   = func(send func()) { go send() }
)

// postToBot posts one JSON payload to the analyserbot /notify endpoint.
func postToBot(body []byte) (*http.Response, error) {
	return http.Post("http://127.0.0.1:5005/notify", "application/json", bytes.NewBuffer(body))
}

// ResetIssueCooldown removes cooldown for an issue (called when "Fixed" button is pressed)
func ResetIssueCooldown(issueID string) {
	notifiedMu.Lock()
	defer notifiedMu.Unlock()
	delete(notifiedIssues, issueID)
	fmt.Printf("[Cooldown] Issue %s cooldown reset - will notify on next check\n", issueID)
}

// canNotifyIssue checks if enough time has passed to send another notification
func canNotifyIssue(issueID string) bool {
	notifiedMu.Lock()
	defer notifiedMu.Unlock()
	
	lastTime, exists := notifiedIssues[issueID]
	if !exists || time.Since(lastTime) >= notifyCooldown {
		notifiedIssues[issueID] = time.Now()
		return true
	}
	return false
}

// canSendSummary reports whether the hourly health summary may go out now
// and marks it sent. Analyze runs concurrently (a live analysis per stored
// switch during the first scan, the periodic loop), so the check and the
// mark happen under notifiedMu.
func canSendSummary() bool {
	notifiedMu.Lock()
	defer notifiedMu.Unlock()
	if time.Since(lastSummarySent) < notifyCooldown {
		return false
	}
	lastSummarySent = time.Now()
	return true
}

// notifyTelegramIfCritical sends separate messages per Shadow IT issue to the python bot
func (na *NetworkAnalyzer) notifyTelegramIfCritical(report *Report) {
	if report.HealthScore >= 90 && len(report.Suggestions) == 0 {
		return // Network is healthy
	}

	// Send a brief health summary (max once per hour)
	if canSendSummary() {
		botDispatch(func() {
			tDetect := time.Now()
			summaryText := fmt.Sprintf("📊 <b>Tarmoq holati:</b> %d/100 (%s)\n🔎 Jami topilgan muammolar: %d ta",
				report.HealthScore, GetHealthLabel(report.HealthScore), len(report.Suggestions))
			payload := map[string]interface{}{"message": summaryText}
			jsonPayload, _ := json.Marshal(payload)
			resp, err := postBotNotify(jsonPayload)
			tNotify := time.Now()
			if err != nil {
				fmt.Printf("[Telegram Bot] Umumiy xabar yuborishda xatolik: %v\n", err)
				return
			}
			resp.Body.Close()
			AddTelegramTiming("summary", "summary", tDetect, tNotify)
		})
	}

	// Send each Shadow IT and Loopback issue as a separate message with buttons (max once per hour per issue)
	for _, sugg := range report.Suggestions {
		if (sugg.Type == "shadow_it" || sugg.Type == "loopback") && sugg.IssueID != "" {
			// Check cooldown - skip if already notified within the last hour
			if !canNotifyIssue(sugg.IssueID) {
				fmt.Printf("[Telegram Bot] ⏳ Issue %s - 1 soat ichida allaqachon yuborilgan, o'tkazildi\n", sugg.IssueID)
				continue
			}

			s := sugg
			botDispatch(func() {
				// Wait a bit to avoid flooding
				time.Sleep(botFloodDelay)
				tDetect := time.Now()

				var msgText string
				if s.Type == "loopback" {
					msgText = fmt.Sprintf(
						"🔄 <b>LOOPBACK aniqlandi!</b>\n\n"+
							"🖥 <b>Switch:</b> %s\n"+
							"🔌 <b>Port:</b> %s\n"+
							"📊 <b>Holat:</b> %s\n\n"+
							"🚨 Bu port tarmoqda uzilishlarga sabab bo'lishi mumkin!",
						s.Device,
						s.Value,
						s.Description,
					)
				} else {
					msgText = fmt.Sprintf(
						"🚨 <b>Tartibsiz tarmoq (Shadow IT) aniqlandi!</b>\n\n"+
							"🖥 <b>Switch:</b> %s\n"+
							"🔌 <b>Port:</b> %s\n"+
							"📊 <b>Holat:</b> %s\n\n"+
							"⚠️ Ushbu portga boshqarilmaydigan switch yoki hub ulangan bo'lishi mumkin.",
						s.Device,
						s.Value,
						s.Description,
					)
				}

				payload := map[string]interface{}{
					"message": msgText,
					"buttons": [][]map[string]string{
						{
							{"text": "❌ E'tiborsiz qoldirish", "callback_data": fmt.Sprintf("ignore|%s", s.IssueID)},
							{"text": "✅ To'g'irlandi", "callback_data": fmt.Sprintf("verify|%s", s.IssueID)},
						},
					},
				}

				jsonPayload, _ := json.Marshal(payload)
				resp, err := postBotNotify(jsonPayload)
				tNotify := time.Now()
				if err != nil {
					fmt.Printf("[Telegram Bot] %s xabar yuborishda xatolik (%s): %v\n", s.Type, s.IssueID, err)
					return
				}
				defer resp.Body.Close()
				if resp.StatusCode == 200 {
					fmt.Printf("[Telegram Bot] ✅ %s xabar yuborildi: %s\n", s.Type, s.IssueID)
				} else {
					fmt.Printf("[Telegram Bot] ❌ Xabar qabul qilinmadi (%s): %d\n", s.IssueID, resp.StatusCode)
				}
				AddTelegramTiming(s.IssueID, s.Type, tDetect, tNotify)
			})
		}
	}
}

// analyzePaths checks for long paths: switches and routers more than 3 hops
// from the core (F19). Endpoints, hubs and VMs hang below their switch and
// are not reported.
func (na *NetworkAnalyzer) analyzePaths() []OptimizationSuggestion {
	suggestions := []OptimizationSuggestion{}

	// Calculate depths from Core Gateway
	// Uses gatewayIP from 'gateway_ip' config file
	coreID := na.coreNode()
	if coreID == "" {
		return suggestions
	}
	ix := na.idx()
	depths := analyzerHopDepths(na.Data.Topology.Links, coreID)

	for _, nodeID := range slices.Sorted(maps.Keys(depths)) {
		nodeInfo := ix.nodes[nodeID]
		if depths[nodeID] <= 3 || (nodeInfo.NodeType != "switch" && nodeInfo.NodeType != "router") {
			continue // Threshold = 3 hops
		}
		suggestions = append(suggestions, OptimizationSuggestion{
			Type:        "path",
			Severity:    "medium",
			Device:      getDataLabel(nodeInfo),
			Description: fmt.Sprintf("Device is too far from Core (%s). Consider moving it to Distribution layer.", coreID),
			Value:       "4+ hops",
			nodeID:      nodeID,
		})
	}

	return suggestions
}

// coreNode returns the topology node of the core gateway (gatewayIP): the
// node with that id, the node of the polled switch with that IP, or a node
// whose label has the gateway IP on a line of its own (for example an LLDP
// endpoint with that management IP). Otherwise it returns the first router
// node, or "" when the topology has neither.
func (na *NetworkAnalyzer) coreNode() string {
	ix := na.idx()
	ids := slices.Sorted(maps.Keys(ix.nodes))
	if gatewayIP != "" {
		if _, ok := ix.nodes[gatewayIP]; ok {
			return gatewayIP
		}
		if id := ix.switchNode(gatewayIP); id != gatewayIP {
			return id
		}
		for _, id := range ids {
			for _, line := range strings.Split(ix.nodes[id].SysName, "\n") {
				if strings.TrimSpace(line) == gatewayIP {
					return id
				}
			}
		}
	}
	for _, id := range ids {
		if ix.nodes[id].NodeType == "router" {
			return id
		}
	}
	return ""
}

// analyzerHopDepths returns the hop count from root of every node the links
// reach. Links are followed in both directions: the graph keeps one edge per
// link, pointing away from whichever switch was polled first.
func analyzerHopDepths(links []GraphLink, root string) map[string]int {
	neighbors := make(map[string][]string)
	for _, link := range links {
		neighbors[link.Source] = append(neighbors[link.Source], link.Target)
		neighbors[link.Target] = append(neighbors[link.Target], link.Source)
	}
	depths := map[string]int{root: 0}
	queue := []string{root}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, next := range neighbors[current] {
			if _, seen := depths[next]; !seen {
				depths[next] = depths[current] + 1
				queue = append(queue, next)
			}
		}
	}
	return depths
}

// analyzeCongestion checks for interface saturation and discards
func (na *NetworkAnalyzer) analyzeCongestion() []OptimizationSuggestion {
	suggestions := []OptimizationSuggestion{}

	// Map to track max utilization per interface
	interfaceUtil := make(map[string]float64)
	interfaceDiscards := make(map[string]uint64)
	interfaceErrors := make(map[string]uint64)

	// User threshold: "1000" (likely 1000 Mbps = 1 Gbps)
	// We flag if traffic exceeds 80% of 1Gbps (800 Mbps)
	const capacity1G = 1000.0 * 1000 * 1000 // 1 Gbps in bits
	const congestThreshold = capacity1G * 0.8 // 800 Mbps

	for _, metric := range na.Data.Metrics {
		key := fmt.Sprintf("%s|%s", metric.DeviceIP, metric.Interface)

		totalBps := metric.InBps + metric.OutBps

		// Check against 1Gbps threshold
		if float64(totalBps) > congestThreshold {
			if util, exists := interfaceUtil[key]; !exists || float64(totalBps) > util {
				// Store max observed utilization
				interfaceUtil[key] = float64(totalBps)
			}
		}

		if metric.InDiscards > 0 || metric.OutDiscards > 0 {
			interfaceDiscards[key] += (metric.InDiscards + metric.OutDiscards)
		}

		if metric.InErrors > 0 || metric.OutErrors > 0 {
			interfaceErrors[key] += (metric.InErrors + metric.OutErrors)
		}
	}

	// Generate suggestions (in device|interface order)
	for _, key := range slices.Sorted(maps.Keys(interfaceUtil)) {
		util := interfaceUtil[key]
		parts := strings.Split(key, "|")
		utilMbps := util / 1000000

		suggestions = append(suggestions, OptimizationSuggestion{
			Type:        "congestion",
			Severity:    "high",
			Device:      parts[0],
			Description: fmt.Sprintf("CRITICAL: Traffic on %s exceeds 800Mbps (Approaching 1G limit). Upgrade link or balance traffic.", parts[1]),
			Value:       fmt.Sprintf("%.2f Mbps", utilMbps),
		})
	}

	for _, key := range slices.Sorted(maps.Keys(interfaceDiscards)) {
		discards := interfaceDiscards[key]
		parts := strings.Split(key, "|")
		suggestions = append(suggestions, OptimizationSuggestion{
			Type:        "congestion",
			Severity:    "medium",
			Device:      parts[0],
			Description: fmt.Sprintf("Packet Loss: %s is dropping packets. Network is congested.", parts[1]),
			Value:       fmt.Sprintf("%d drops", discards),
		})
	}

	for _, key := range slices.Sorted(maps.Keys(interfaceErrors)) {
		errs := interfaceErrors[key]
		parts := strings.Split(key, "|")
		suggestions = append(suggestions, OptimizationSuggestion{
			Type:        "physical",
			Severity:    "high",
			Device:      parts[0],
			Description: fmt.Sprintf("Physical Faults: %s has CRC/Frame errors. Check cable/SFP immediately.", parts[1]),
			Value:       fmt.Sprintf("%d errors", errs),
		})
	}

	return suggestions
}

// analyzeStability checks for status changes
func (na *NetworkAnalyzer) analyzeStability() []OptimizationSuggestion {
	suggestions := []OptimizationSuggestion{}

	// Count status changes per device/interface
	flapping := make(map[string]int)

	for _, event := range na.Data.Events {
		key := fmt.Sprintf("%s|%s", event.DeviceIP, event.Interface)
		// Only count Down events (1 -> 2)
		// 2 = Down, 1 = Up
		if event.NewStatus == 2 {
			flapping[key]++
		}
	}

	for _, key := range slices.Sorted(maps.Keys(flapping)) {
		count := flapping[key]
		parts := strings.Split(key, "|")
		suggestions = append(suggestions, OptimizationSuggestion{
			Type:        "stability",
			Severity:    "high",
			Device:      parts[0],
			Description: fmt.Sprintf("Network Interruption: Interface %s went DOWN %d times.", parts[1], count),
			Value:       fmt.Sprintf("%d outages", count),
		})
	}

	return suggestions
}

// Helper to get formatted label
func getDataLabel(node GraphNode) string {
	if node.SysName != "" {
		return fmt.Sprintf("%s (%s)", node.SysName, node.ID)
	}
	return node.ID
}

// GenerateTextReport creates a human-readable report
func (r *Report) GenerateTextReport() string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("NETWORK ANALYSIS REPORT\n"))
	sb.WriteString(fmt.Sprintf("Session: %s\n", r.SessionID))
	sb.WriteString(fmt.Sprintf("Generated: %s\n", r.GeneratedAt.Format(time.RFC1123)))
	sb.WriteString("--------------------------------------------------\n\n")

	sb.WriteString("SUMMARY:\n")
	sb.WriteString(fmt.Sprintf("- Path Optimization Issues: %d\n", r.Summary["path_issues"]))
	sb.WriteString(fmt.Sprintf("- Congestion/Traffic Issues: %d\n", r.Summary["congestion_issues"]))
	sb.WriteString(fmt.Sprintf("- Stability/Outage Issues: %d\n", r.Summary["stability_issues"]))
	sb.WriteString("\n")

	if len(r.Suggestions) == 0 {
		sb.WriteString("✅ No major issues detected. Network appears healthy.\n")
		return sb.String()
	}

	// Stable: suggestions of one severity keep the analysis order (Q16)
	sort.SliceStable(r.Suggestions, func(i, j int) bool {
		return r.Suggestions[i].Severity < r.Suggestions[j].Severity // crude sort, high should be first ideally
	})

	sb.WriteString("DETAILED RECOMMENDATIONS:\n\n")

	for i, sugg := range r.Suggestions {
		icon := "ℹ️"
		if sugg.Severity == "high" {
			icon = "🔴"
		} else if sugg.Severity == "medium" {
			icon = "🟠"
		}

		sb.WriteString(fmt.Sprintf("%d. %s [%s] %s\n", i+1, icon, strings.ToUpper(sugg.Type), sugg.Device))
		sb.WriteString(fmt.Sprintf("   Problem: %s\n", sugg.Description))
		sb.WriteString(fmt.Sprintf("   Metric: %s\n\n", sugg.Value))
	}

	return sb.String()
}

// GenerateHTMLReport creates an HTML report suitable for Word export
func (r *Report) GenerateHTMLReport() string {
	var sb strings.Builder

	sb.WriteString(`
<html xmlns:o='urn:schemas-microsoft-com:office:office' xmlns:w='urn:schemas-microsoft-com:office:word' xmlns='http://www.w3.org/TR/REC-html40'>
<head>
	<meta charset="utf-8">
	<title>Network Analysis Report</title>
	<style>
		body { font-family: 'Calibri', 'Arial', sans-serif; font-size: 11pt; }
		h1 { font-size: 16pt; color: #2E74B5; border-bottom: 2px solid #2E74B5; padding-bottom: 10px; }
		h2 { font-size: 13pt; color: #2E74B5; margin-top: 20px; }
		table { width: 100%; border-collapse: collapse; margin-top: 10px; }
		th { background-color: #2E74B5; color: white; text-align: left; padding: 8px; font-weight: bold; }
		td { border: 1px solid #ddd; padding: 8px; }
		.severity-high { color: #D32F2F; font-weight: bold; }
		.severity-medium { color: #EF6C00; font-weight: bold; }
		.summary-box { background-color: #f5f5f5; padding: 15px; border-radius: 5px; border: 1px solid #ddd; }
		.footer { margin-top: 30px; font-size: 9pt; color: #777; border-top: 1px solid #ddd; padding-top: 10px; }
	</style>
</head>
<body>
`)

	sb.WriteString(fmt.Sprintf("<h1>Network Analysis Report</h1>"))
	sb.WriteString(fmt.Sprintf("<p><strong>Session ID:</strong> %s<br>", r.SessionID))
	sb.WriteString(fmt.Sprintf("<strong>Generated Date:</strong> %s</p>", r.GeneratedAt.Format("Monday, 02 Jan 2006 15:04:05")))

	// Health Score Box
	healthColor := "#4CAF50" // Green
	if r.HealthScore < 50 {
		healthColor = "#D32F2F" // Red
	} else if r.HealthScore < 70 {
		healthColor = "#EF6C00" // Orange
	} else if r.HealthScore < 90 {
		healthColor = "#FFC107" // Yellow
	}
	sb.WriteString(fmt.Sprintf("<div style='background-color: %s; color: white; padding: 20px; border-radius: 10px; text-align: center; margin: 20px 0;'>", healthColor))
	sb.WriteString(fmt.Sprintf("<h2 style='margin: 0; font-size: 24pt;'>Network Health Score: %d / 100</h2>", r.HealthScore))
	sb.WriteString(fmt.Sprintf("<p style='margin: 5px 0 0 0; font-size: 14pt;'>%s</p>", GetHealthLabel(r.HealthScore)))
	sb.WriteString("</div>")

	// Summary
	sb.WriteString("<div class='summary-box'>")
	sb.WriteString("<h2>Executive Summary</h2>")
	sb.WriteString("<table style='width: 100%;'>")
	sb.WriteString("<tr><td>Path Optimization Issues</td><td><strong>" + fmt.Sprintf("%d", r.Summary["path_issues"]) + "</strong></td></tr>")
	sb.WriteString("<tr><td>Congestion/Bandwidth Issues</td><td><strong>" + fmt.Sprintf("%d", r.Summary["congestion_issues"]) + "</strong></td></tr>")
	sb.WriteString("<tr><td>Network Stability Issues</td><td><strong>" + fmt.Sprintf("%d", r.Summary["stability_issues"]) + "</strong></td></tr>")
	sb.WriteString("<tr><td style='color: #D32F2F;'>Shadow IT (Unmanaged Switches)</td><td><strong>" + fmt.Sprintf("%d", r.Summary["shadow_it_issues"]) + "</strong></td></tr>")
	sb.WriteString("<tr><td style='color: #D32F2F;'>STP Configuration Issues</td><td><strong>" + fmt.Sprintf("%d", r.Summary["stp_issues"]) + "</strong></td></tr>")
	sb.WriteString("</table>")
	sb.WriteString("</div>")


	if len(r.Suggestions) == 0 {
		sb.WriteString("<h2>Detailed Recommendations</h2>")
		sb.WriteString("<p>✅ No critical issues detected. The network appears to be healthy and stable.</p>")
	} else {
		sb.WriteString("<h2>Detailed Recommendations</h2>")
		sb.WriteString("<table>")
		sb.WriteString("<thead><tr><th>Severity</th><th>Type</th><th>Device</th><th>Issue</th><th>Metric</th></tr></thead>")
		sb.WriteString("<tbody>")

		// Sort: High first (stable: one severity keeps the analysis order)
		sort.SliceStable(r.Suggestions, func(i, j int) bool {
			return r.Suggestions[i].Severity < r.Suggestions[j].Severity
		})

		for _, sugg := range r.Suggestions {
			severityClass := ""
			severityLabel := "LOW"
			if sugg.Severity == "high" {
				severityClass = "severity-high"
				severityLabel = "HIGH"
			} else if sugg.Severity == "medium" {
				severityClass = "severity-medium"
				severityLabel = "MEDIUM"
			}

			sb.WriteString("<tr>")
			sb.WriteString(fmt.Sprintf("<td class='%s'>%s</td>", severityClass, severityLabel))
			sb.WriteString(fmt.Sprintf("<td>%s</td>", strings.ToUpper(sugg.Type)))
			sb.WriteString(fmt.Sprintf("<td>%s</td>", sugg.Device))
			sb.WriteString(fmt.Sprintf("<td>%s</td>", sugg.Description))
			sb.WriteString(fmt.Sprintf("<td>%s</td>", sugg.Value))
			sb.WriteString("</tr>")
		}
		sb.WriteString("</tbody></table>")
	}

	sb.WriteString("<div class='footer'>")
	sb.WriteString("Generated by Network Topology Monitor System")
	sb.WriteString("</div>")
	sb.WriteString("</body></html>")

	return sb.String()
}

// ShadowITDevice represents a suspected unmanaged switch
type ShadowITDevice struct {
	DeviceIP    string   `json:"device_ip"`
	PortNumber  int      `json:"port_number"`
	MACCount    int      `json:"mac_count"`
	MACAddresses []string `json:"mac_addresses"`
}

// analyzeShadowIT reports every port that the graph draws as an unmanaged
// hub (fdbPorts, the one per-port rule, Q14) as one shadow_<ip>_<port>
// issue, in device and port order.
func (na *NetworkAnalyzer) analyzeShadowIT() []OptimizationSuggestion {
	suggestions := []OptimizationSuggestion{}
	ix := na.idx()
	switchMACs := buildSwitchChassisMACs(ix.byIP)

	for _, device := range ix.devices {
		for _, p := range fdbPorts(device, switchMACs) {
			if p.Kind != fdbHub {
				continue
			}
			issueID := fmt.Sprintf("shadow_%s_%d", strings.ReplaceAll(device.IP, ".", "_"), p.Port)

			// Skip if this issue is ignored
			if IsIssueIgnored(issueID) {
				continue
			}

			suggestions = append(suggestions, OptimizationSuggestion{
				IssueID:     issueID,
				Type:        "shadow_it",
				Severity:    "high",
				Device:      device.IP,
				Description: fmt.Sprintf("Port %d has %d MAC addresses. Likely UNMANAGED SWITCH connected (Shadow IT). Remove or replace with managed switch.", p.Port, len(p.MACs)),
				Value:       fmt.Sprintf("%d MACs on single port", len(p.MACs)),
				nodeID:      ix.hubNode(device, p.Port),
			})
		}
	}

	return suggestions
}

// analyzerShadowStats are the experiment report's Shadow-IT numbers, counted
// with the same per-port rule as the graph and the alerts.
type analyzerShadowStats struct {
	Candidates int // hub candidate ports (shadow_it_raw)
	Hubs       int // candidates drawn as hubs (shadow_it_filtered)
	VMPorts    int // candidates exempt as VM or ESXi ports (vm_ports_filtered)
}

// analyzerShadowCounts applies the per-port rule (fdbPorts) to every device
// and counts its hub candidates.
func analyzerShadowCounts(devices []*DeviceData) analyzerShadowStats {
	byIP := make(map[string]*DeviceData, len(devices))
	for _, d := range devices {
		byIP[d.IP] = d
	}
	switchMACs := buildSwitchChassisMACs(byIP)
	var stats analyzerShadowStats
	for _, ip := range sortedDeviceIPs(byIP) {
		for _, p := range fdbPorts(byIP[ip], switchMACs) {
			if !p.Candidate {
				continue
			}
			stats.Candidates++
			if p.Kind == fdbHub {
				stats.Hubs++
			} else {
				stats.VMPorts++
			}
		}
	}
	return stats
}

// analyzeLoopback detects network loops (ports looped back to the same switch)
func (na *NetworkAnalyzer) analyzeLoopback() []OptimizationSuggestion {
	suggestions := []OptimizationSuggestion{}

	for _, device := range na.idx().devices { // IP order (Q16)
		deviceIP := device.IP
		// The switch's own MAC as the graph keys it (graphChassisKey: a
		// canonical MAC, so a Cisco-dotted id matches its neighbors' view).
		// A switch without a usable chassis id cannot recognise itself: an
		// empty (or null, or exception-text) id equals every other empty id,
		// for example a neighbor whose RemChassisId was not read (F17).
		chassisMAC := graphChassisKey(device.ChassisID)
		if chassisMAC == "" || isInvalidID(chassisMAC) {
			continue
		}

		// Method 1: LLDP Self-Neighbor Detection
		// If a switch sees its own ChassisID as an LLDP neighbor = cable looped back
		for _, neighbor := range device.Neighbors {
			remoteMAC := graphChassisKey(lldpChassisID(neighbor))
			if remoteMAC == chassisMAC {
				issueID := fmt.Sprintf("loop_lldp_%s_%d", strings.ReplaceAll(deviceIP, ".", "_"), neighbor.LocalPortNum)

				if IsIssueIgnored(issueID) {
					continue
				}

				portName := fmt.Sprintf("Port %d", neighbor.LocalPortNum)
				for _, iface := range device.Interfaces {
					if iface.IfIndex == neighbor.LocalPortNum {
						portName = iface.IfDescr
						break
					}
				}

				suggestions = append(suggestions, OptimizationSuggestion{
					IssueID:     issueID,
					Type:        "loopback",
					Severity:    "high",
					Device:      deviceIP,
					Description: fmt.Sprintf("🔄 LOOPBACK: Port %s switch o'ziga qaytib ulangan! Kabel to'g'ri ulanganligini tekshiring.", portName),
					Value:       portName,
				})
			}
		}

		// Method 2: MAC Self-Reference Detection
		// If a switch's own chassis MAC appears in MAC table on a non-trunk port
		for _, macEntry := range device.MACTable {
			entryMAC := canonicalMAC(macEntry.MACAddress)
			if entryMAC == chassisMAC {
				// Check if this port is a trunk (trunks legitimately see own MAC)
				isTrunk := false
				for _, pv := range device.PortVLANs {
					if pv.PortIndex == macEntry.PortNumber && pv.IsTrunk {
						isTrunk = true
						break
					}
				}

				if !isTrunk {
					issueID := fmt.Sprintf("loop_mac_%s_%d", strings.ReplaceAll(deviceIP, ".", "_"), macEntry.PortNumber)

					if IsIssueIgnored(issueID) {
						continue
					}

					suggestions = append(suggestions, OptimizationSuggestion{
						IssueID:     issueID,
						Type:        "loopback",
						Severity:    "high",
						Device:      deviceIP,
						Description: fmt.Sprintf("🔄 LOOPBACK: Port %d da switch o'zining MAC manzilini ko'ryapti. Portda loop bo'lishi mumkin.", macEntry.PortNumber),
						Value:       fmt.Sprintf("Port %d", macEntry.PortNumber),
					})
				}
			}
		}
	}

	return suggestions
}

// analyzeSTP checks Spanning Tree Protocol configuration: it reports the root
// bridges that are not one of the polled (managed) switches. A root is on a
// managed switch when its bridge MAC is the chassis MAC, or an interface MAC,
// of a polled device. The suggestion names the root seen by the most
// devices (then the lowest MAC), so it is the same on every run (F18).
func (na *NetworkAnalyzer) analyzeSTP() []OptimizationSuggestion {
	suggestions := []OptimizationSuggestion{}
	ix := na.idx()

	// Find the root bridge from all devices
	seenBy := make(map[string]int) // root bridge MAC -> number of devices seeing this root
	for _, device := range ix.devices {
		if device.STPInfo.Enabled && device.STPInfo.RootBridgeID != "" {
			seenBy[normalizeMAC(device.STPInfo.RootBridgeID)]++
		}
	}

	// MACs of the managed switches. IfPhysAddress is not collected today,
	// so the chassis MAC (the bridge MAC of most switches) is what matches.
	managed := make(map[string]bool)
	for _, device := range ix.devices {
		managed[graphChassisKey(device.ChassisID)] = true
		for _, iface := range device.Interfaces {
			managed[normalizeMAC(iface.IfPhysAddress)] = true
		}
	}
	delete(managed, "")

	// Check if root bridge is in the core
	// PVST+ tarmoqlarda har VLAN uchun alohida root bridge bo'ladi — bu normal.
	// Faqat 1 ta suggestion beramiz.
	if len(seenBy) > 0 {
		nonCoreRoots := []string{}
		for rootMAC := range seenBy {
			if !managed[rootMAC] {
				nonCoreRoots = append(nonCoreRoots, rootMAC)
			}
		}
		slices.SortFunc(nonCoreRoots, func(a, b string) int {
			return cmp.Or(cmp.Compare(seenBy[b], seenBy[a]), strings.Compare(a, b))
		})

		// Generate only 1 summary suggestion for all non-core roots
		if len(nonCoreRoots) > 0 {
			suggestions = append(suggestions, OptimizationSuggestion{
				Type:        "stp",
				Severity:    "medium",
				Device:      nonCoreRoots[0],
				Description: fmt.Sprintf("STP: %d ta Root Bridge core switchda emas (PVST+ normal). Core switchda priority sozlang.", len(nonCoreRoots)),
				Value:       fmt.Sprintf("%d non-core roots", len(nonCoreRoots)),
			})
		}
	}

	return suggestions
}

// CalculateHealthScore computes a 0-100 network health score
func (na *NetworkAnalyzer) CalculateHealthScore(report *Report) int {
	score := 100

	// Category-level penalty caps to avoid false-positive flood
	shadowPenalty := 0
	stpPenalty := 0

	for _, sugg := range report.Suggestions {
		switch sugg.Type {
		case "shadow_it":
			shadowPenalty += 5 // Each unmanaged switch: -5 (was -10)
		case "congestion":
			if sugg.Severity == "high" {
				score -= 5
			} else {
				score -= 2
			}
		case "physical":
			score -= 2
		case "stp":
			stpPenalty += 10
		case "path":
			score -= 2
		case "stability":
			score -= 3
		case "loopback":
			score -= 20
		}
	}

	// Apply capped penalties: shadow_it max -20, stp max -15
	if shadowPenalty > 20 {
		shadowPenalty = 20
	}
	if stpPenalty > 15 {
		stpPenalty = 15
	}
	score -= shadowPenalty
	score -= stpPenalty

	if score < 0 {
		score = 0
	}

	return score
}

// GetHealthLabel returns a human-readable label for health score
func GetHealthLabel(score int) string {
	if score >= 90 {
		return "Excellent"
	} else if score >= 70 {
		return "Good"
	} else if score >= 50 {
		return "Fair"
	} else if score >= 30 {
		return "Poor"
	}
	return "Critical"
}
