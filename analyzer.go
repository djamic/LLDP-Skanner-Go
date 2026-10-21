package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

// NetworkAnalyzer handles analysis of network capture data
type NetworkAnalyzer struct {
	Data FullCaptureData
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

// Analyze performs all analysis checks
func (na *NetworkAnalyzer) Analyze() Report {
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

	// Trigger Telegram notification if there are critical issues or health score is low
	na.notifyTelegramIfCritical(&report)

	// B.4: Write anomaly summary to InfluxDB
	WriteAnomalySummary(&report)

	// E.1/E.2: Store health score + anomaly map for UI enrichment via /api/graph
	anomalyMap := make(map[string][]string)
	for _, sugg := range report.Suggestions {
		if sugg.Device != "" {
			// Extract IP from Device field (may be "IP (SysName)" format)
			deviceKey := sugg.Device
			// Try to extract pure IP if format is "IP (SysName)"
			if idx := strings.Index(deviceKey, " ("); idx > 0 {
				deviceKey = deviceKey[:idx]
			}
			anomalyMap[deviceKey] = append(anomalyMap[deviceKey], sugg.Type)
		}
	}
	totalMACs := 0
	for _, dev := range na.Data.DevicesData {
		totalMACs += len(dev.MACTable)
	}
	SetLastReport(report.HealthScore, anomalyMap, totalMACs)

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

// notifyTelegramIfCritical sends separate messages per Shadow IT issue to the python bot
func (na *NetworkAnalyzer) notifyTelegramIfCritical(report *Report) {
	if report.HealthScore >= 90 && len(report.Suggestions) == 0 {
		return // Network is healthy
	}

	// Send a brief health summary (max once per hour)
	if time.Since(lastSummarySent) >= notifyCooldown {
		lastSummarySent = time.Now()
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

// analyzePaths checks for long paths (hops > 3)
func (na *NetworkAnalyzer) analyzePaths() []OptimizationSuggestion {
	suggestions := []OptimizationSuggestion{}

	// Reconstruct graph from topology data to run BFS
	graph := NewDJGraph()
	for _, node := range na.Data.Topology.Nodes {
		graph.AddNode(node.ID)
		graph.AddNodeInfo(node.ID, node.SysName)
	}
	for _, link := range na.Data.Topology.Links {
		graph.AddEdge(link.Source, link.Target, link.Label)
	}

	// Calculate depths from Core Gateway
	// Uses gatewayIP from 'gateway_ip' config file
	coreID := gatewayIP
	// If core not in nodes, try to find a "router" type node as fallback
	if !graph.Nodes[coreID] {
		for _, node := range na.Data.Topology.Nodes {
			if node.NodeType == "router" {
				coreID = node.ID
				break
			}
		}
	}

	longPaths := graph.GetLongPaths(coreID, 3) // Threshold = 3 hops

	for _, nodeID := range longPaths {
		// Get node details
		var nodeInfo GraphNode
		for _, n := range na.Data.Topology.Nodes {
			if n.ID == nodeID {
				nodeInfo = n
				break
			}
		}

		suggestions = append(suggestions, OptimizationSuggestion{
			Type:        "path",
			Severity:    "medium",
			Device:      getDataLabel(nodeInfo),
			Description: fmt.Sprintf("Device is too far from Core (%s). Consider moving it to Distribution layer.", coreID),
			Value:       "4+ hops",
		})
	}

	return suggestions
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

	// Generate suggestions
	for key, util := range interfaceUtil {
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

	for key, discards := range interfaceDiscards {
		parts := strings.Split(key, "|")
		suggestions = append(suggestions, OptimizationSuggestion{
			Type:        "congestion",
			Severity:    "medium",
			Device:      parts[0],
			Description: fmt.Sprintf("Packet Loss: %s is dropping packets. Network is congested.", parts[1]),
			Value:       fmt.Sprintf("%d drops", discards),
		})
	}

	for key, errs := range interfaceErrors {
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

	for key, count := range flapping {
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

	sort.Slice(r.Suggestions, func(i, j int) bool {
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

		// Sort: High first
		sort.Slice(r.Suggestions, func(i, j int) bool {
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

// analyzeShadowIT detects unmanaged switches via Port-MAC Ratio algorithm
func (na *NetworkAnalyzer) analyzeShadowIT() []OptimizationSuggestion {
	suggestions := []OptimizationSuggestion{}

	// Map: DeviceIP -> PortNumber -> MAC addresses
	portMACs := make(map[string]map[int][]string)

	for _, device := range na.Data.DevicesData {
		if portMACs[device.IP] == nil {
			portMACs[device.IP] = make(map[int][]string)
		}

		// Build port to MAC mapping from MAC table
		for _, macEntry := range device.MACTable {
			portMACs[device.IP][macEntry.PortNumber] = append(
				portMACs[device.IP][macEntry.PortNumber],
				macEntry.MACAddress,
			)
		}
	}

	// Check each port: if MAC count > 1 and not a trunk port -> Shadow IT suspected
	for deviceIP, ports := range portMACs {
		for portNum, macs := range ports {
			// C.2: Filter out random MACs (Wi-Fi devices with randomized addresses)
			var realMACs []string
			for _, mac := range macs {
				if !isRandomMAC(mac) {
					realMACs = append(realMACs, mac)
				}
			}

			if len(realMACs) > 1 {
				// Check if this is a trunk port (skip if trunk)
				isTrunk := false
				for _, device := range na.Data.DevicesData {
					if device.IP == deviceIP {
						for _, pv := range device.PortVLANs {
							if pv.PortIndex == portNum && pv.IsTrunk {
								isTrunk = true
								break
							}
						}
					}
				}

				if !isTrunk {
					issueID := fmt.Sprintf("shadow_%s_%d", strings.ReplaceAll(deviceIP, ".", "_"), portNum)
					
					// Skip if this issue is ignored
					if IsIssueIgnored(issueID) {
						continue
					}

					// Skip if this is a hypervisor port (VMware, Proxmox, KVM, etc.)
					if isHypervisorPort(macs) {
						continue
					}
					// Also skip if any MAC is a confirmed ESXi host (HTTP-verified)
					isConfirmedESXi := false
					for _, mac := range macs {
						if _, ok := ConfirmedESXiMACs.Load(normalizeMAC(mac)); ok {
							isConfirmedESXi = true
							break
						}
					}
					if isConfirmedESXi {
						continue
					}

					suggestions = append(suggestions, OptimizationSuggestion{
						IssueID:     issueID,
						Type:        "shadow_it",
						Severity:    "high",
						Device:      deviceIP,
						Description: fmt.Sprintf("Port %d has %d MAC addresses. Likely UNMANAGED SWITCH connected (Shadow IT). Remove or replace with managed switch.", portNum, len(macs)),
						Value:       fmt.Sprintf("%d MACs on single port", len(macs)),
					})
				}
			}
		}
	}

	return suggestions
}

// analyzeLoopback detects network loops (ports looped back to the same switch)
func (na *NetworkAnalyzer) analyzeLoopback() []OptimizationSuggestion {
	suggestions := []OptimizationSuggestion{}

	for _, device := range na.Data.DevicesData {
		deviceIP := device.IP
		chassisMAC := normalizeMAC(device.ChassisID)
		// A switch without a usable chassis id cannot recognise itself: an
		// empty (or null) id equals every other empty id, for example a
		// neighbor whose RemChassisId was not read (F17).
		if isInvalidID(chassisMAC) {
			continue
		}

		// Method 1: LLDP Self-Neighbor Detection
		// If a switch sees its own ChassisID as an LLDP neighbor = cable looped back
		for _, neighbor := range device.Neighbors {
			remoteMAC := normalizeMAC(neighbor.RemChassisId)
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
			entryMAC := normalizeMAC(macEntry.MACAddress)
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

// analyzeSTP checks Spanning Tree Protocol configuration
func (na *NetworkAnalyzer) analyzeSTP() []OptimizationSuggestion {
	suggestions := []OptimizationSuggestion{}

	// Find the root bridge from all devices
	rootBridgeIDs := make(map[string][]string) // RootBridgeID -> list of devices seeing this root

	for _, device := range na.Data.DevicesData {
		if device.STPInfo.Enabled && device.STPInfo.RootBridgeID != "" {
			rootBridgeIDs[device.STPInfo.RootBridgeID] = append(
				rootBridgeIDs[device.STPInfo.RootBridgeID],
				device.IP,
			)
		}
	}

	// Check if root bridge is in the core
	// PVST+ tarmoqlarda har VLAN uchun alohida root bridge bo'ladi — bu normal.
	// Faqat birinchi topilgan non-core root uchun 1 ta suggestion beramiz.
	if len(rootBridgeIDs) > 0 {
		nonCoreRoots := []string{}
		for rootMAC, devices := range rootBridgeIDs {
			isCore := false
			for _, device := range na.Data.DevicesData {
				for _, iface := range device.Interfaces {
					if strings.EqualFold(iface.IfPhysAddress, rootMAC) {
						for _, node := range na.Data.Topology.Nodes {
							if node.ID == device.IP && (node.NodeType == "router" || node.NodeType == "switch") {
								isCore = true
								break
							}
						}
					}
				}
			}
			if !isCore && len(devices) > 0 {
				nonCoreRoots = append(nonCoreRoots, rootMAC)
			}
		}

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
