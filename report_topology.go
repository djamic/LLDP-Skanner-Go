package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"log"
	"math"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ============================================================
// F.1 — Topology Summary SVG Generator
// ============================================================

// TopologyNode represents a node in the summary topology
type TopologyNode struct {
	ID      string  `json:"id"`
	Label   string  `json:"label"`
	Type    string  `json:"type"` // "router", "switch"
	X       float64 `json:"x"`
	Y       float64 `json:"y"`
}

// TopologyEdge represents an edge in the summary topology
type TopologyEdge struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Label  string `json:"label"`
}

// GenerateTopologySVG creates an SVG of the switch/router-only topology
func GenerateTopologySVG(graph *DJGraph) string {
	if graph == nil {
		return ""
	}

	data := graph.GetGraphData()

	// Filter: only switch and router nodes
	var nodes []TopologyNode
	nodeSet := make(map[string]bool)

	for _, n := range data.Nodes {
		if n.Group == "switch" || n.Group == "router" {
			label := n.SysName
			if label == "" {
				label = n.ID
			}
			nodes = append(nodes, TopologyNode{
				ID:    n.ID,
				Label: label,
				Type:  n.Group,
			})
			nodeSet[n.ID] = true
		}
	}

	// Filter: edges between switches/routers only
	var edges []TopologyEdge
	for _, l := range data.Links {
		src := l.Source
		tgt := l.Target
		if nodeSet[src] && nodeSet[tgt] {
			edges = append(edges, TopologyEdge{
				Source: src,
				Target: tgt,
				Label:  l.Label,
			})
		}
	}

	// Layout: simple circular layout
	width := 900.0
	height := 700.0
	cx, cy := width/2, height/2
	n := len(nodes)
	if n == 0 {
		return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="%.0f" height="%.0f"><text x="%.0f" y="%.0f" fill="#888" text-anchor="middle">No topology data</text></svg>`, width, height, cx, cy)
	}

	radius := math.Min(width, height)*0.38
	for i := range nodes {
		angle := 2 * math.Pi * float64(i) / float64(n)
		nodes[i].X = cx + radius*math.Cos(angle)
		nodes[i].Y = cy + radius*math.Sin(angle)
	}

	nodeMap := make(map[string]*TopologyNode)
	for i := range nodes {
		nodeMap[nodes[i].ID] = &nodes[i]
	}

	// Build SVG
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" width="%.0f" height="%.0f" style="background:#0d1b2a; font-family:Arial,sans-serif;">`, width, height))

	// Title
	sb.WriteString(fmt.Sprintf(`<text x="%.0f" y="30" fill="#4A90E2" font-size="16" text-anchor="middle" font-weight="bold">Network Topology — %d switches, %d links</text>`, cx, n, len(edges)))

	// Edges
	for _, e := range edges {
		src := nodeMap[e.Source]
		tgt := nodeMap[e.Target]
		if src == nil || tgt == nil {
			continue
		}
		sb.WriteString(fmt.Sprintf(`<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="#0f3460" stroke-width="1.5"/>`,
			src.X, src.Y, tgt.X, tgt.Y))
		// Edge label at midpoint
		if e.Label != "" {
			mx := (src.X + tgt.X) / 2
			my := (src.Y + tgt.Y) / 2
			sb.WriteString(fmt.Sprintf(`<text x="%.1f" y="%.1f" fill="#555" font-size="7" text-anchor="middle">%s</text>`,
				mx, my-3, truncateLabel(e.Label, 20)))
		}
	}

	// Nodes
	for _, nd := range nodes {
		r := 6.0
		fillColor := "#4A90E2"
		if nd.Type == "router" {
			fillColor = "#E24A4A"
			r = 8.0
		}
		sb.WriteString(fmt.Sprintf(`<circle cx="%.1f" cy="%.1f" r="%.0f" fill="%s" stroke="#fff" stroke-width="1.5"/>`,
			nd.X, nd.Y, r, fillColor))
		sb.WriteString(fmt.Sprintf(`<text x="%.1f" y="%.1f" fill="#ccc" font-size="8" text-anchor="middle">%s</text>`,
			nd.X, nd.Y+r+10, truncateLabel(nd.Label, 18)))
	}

	sb.WriteString("</svg>")
	return sb.String()
}

// truncateLabel shortens a label to maxLen chars
func truncateLabel(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-2] + ".."
}

// GenerateTopologyPNG creates a PNG image of switch/router topology and returns base64 <img> tag
func GenerateTopologyPNG(graph *DJGraph) string {
	if graph == nil {
		return "<p><i>Topologiya ma'lumotlari mavjud emas</i></p>"
	}

	data := graph.GetGraphData()

	// Filter: only switch and router nodes
	type pngNode struct {
		ID, Label, Type string
		X, Y            float64
	}
	var nodes []pngNode
	nodeSet := make(map[string]bool)
	for _, n := range data.Nodes {
		if n.Group == "switch" || n.Group == "router" {
			label := n.SysName
			if label == "" {
				label = n.ID
			}
			nodes = append(nodes, pngNode{ID: n.ID, Label: label, Type: n.Group})
			nodeSet[n.ID] = true
		}
	}

	type pngEdge struct{ Source, Target string }
	var edges []pngEdge
	for _, l := range data.Links {
		if nodeSet[l.Source] && nodeSet[l.Target] {
			edges = append(edges, pngEdge{l.Source, l.Target})
		}
	}

	nCount := len(nodes)
	if nCount == 0 {
		return "<p><i>Topologiya ma'lumotlari mavjud emas</i></p>"
	}

	// Image dimensions
	const W, H = 900, 700
	img := image.NewRGBA(image.Rect(0, 0, W, H))

	// Background: white (print-friendly)
	bgColor := color.RGBA{255, 255, 255, 255}
	draw.Draw(img, img.Bounds(), &image.Uniform{bgColor}, image.Point{}, draw.Src)

	// Light border around the image
	borderColor := color.RGBA{220, 220, 220, 255}
	for x := 0; x < W; x++ {
		img.SetRGBA(x, 0, borderColor)
		img.SetRGBA(x, H-1, borderColor)
	}
	for y := 0; y < H; y++ {
		img.SetRGBA(0, y, borderColor)
		img.SetRGBA(W-1, y, borderColor)
	}

	// Layout: circular
	cx, cy := float64(W)/2, float64(H)/2
	radius := math.Min(float64(W), float64(H)) * 0.35
	for i := range nodes {
		angle := 2 * math.Pi * float64(i) / float64(nCount)
		nodes[i].X = cx + radius*math.Cos(angle)
		nodes[i].Y = cy + radius*math.Sin(angle)
	}
	nodeMap := make(map[string]*pngNode)
	for i := range nodes {
		nodeMap[nodes[i].ID] = &nodes[i]
	}

	// Draw edges: visible gray
	edgeColor := color.RGBA{160, 160, 160, 255}
	for _, e := range edges {
		src := nodeMap[e.Source]
		tgt := nodeMap[e.Target]
		if src == nil || tgt == nil {
			continue
		}
		drawLine(img, int(src.X), int(src.Y), int(tgt.X), int(tgt.Y), edgeColor)
	}

	// Draw nodes: bigger, brighter colors
	for _, nd := range nodes {
		r := 10
		nodeColor := color.RGBA{41, 128, 215, 255} // switch blue
		outlineColor := color.RGBA{25, 90, 160, 255}
		if nd.Type == "router" {
			nodeColor = color.RGBA{220, 60, 60, 255} // router red
			outlineColor = color.RGBA{160, 40, 40, 255}
			r = 12
		}
		drawCircle(img, int(nd.X), int(nd.Y), r, nodeColor)
		drawCircleOutline(img, int(nd.X), int(nd.Y), r+1, outlineColor)
	}

	// Encode to PNG
	var buf bytes.Buffer
	if err := png.Encode(&buf, img); err != nil {
		return "<p><i>Rasm generatsiya xatosi</i></p>"
	}
	b64 := base64.StdEncoding.EncodeToString(buf.Bytes())
	return fmt.Sprintf(`<img src="data:image/png;base64,%s" width="800" />`, b64)
}

// drawLine draws a line using Bresenham's algorithm
func drawLine(img *image.RGBA, x0, y0, x1, y1 int, c color.RGBA) {
	dx := abs(x1 - x0)
	dy := -abs(y1 - y0)
	sx, sy := 1, 1
	if x0 >= x1 { sx = -1 }
	if y0 >= y1 { sy = -1 }
	err := dx + dy
	for {
		if x0 >= 0 && x0 < img.Bounds().Max.X && y0 >= 0 && y0 < img.Bounds().Max.Y {
			img.SetRGBA(x0, y0, c)
			// thicken line
			if x0+1 < img.Bounds().Max.X { img.SetRGBA(x0+1, y0, c) }
			if y0+1 < img.Bounds().Max.Y { img.SetRGBA(x0, y0+1, c) }
		}
		if x0 == x1 && y0 == y1 { break }
		e2 := 2 * err
		if e2 >= dy { err += dy; x0 += sx }
		if e2 <= dx { err += dx; y0 += sy }
	}
}

// drawCircle fills a circle
func drawCircle(img *image.RGBA, cx, cy, r int, c color.RGBA) {
	for y := -r; y <= r; y++ {
		for x := -r; x <= r; x++ {
			if x*x+y*y <= r*r {
				px, py := cx+x, cy+y
				if px >= 0 && px < img.Bounds().Max.X && py >= 0 && py < img.Bounds().Max.Y {
					img.SetRGBA(px, py, c)
				}
			}
		}
	}
}

// drawCircleOutline draws a circle outline
func drawCircleOutline(img *image.RGBA, cx, cy, r int, c color.RGBA) {
	for y := -r; y <= r; y++ {
		for x := -r; x <= r; x++ {
			d := x*x + y*y
			if d >= (r-1)*(r-1) && d <= r*r {
				px, py := cx+x, cy+y
				if px >= 0 && px < img.Bounds().Max.X && py >= 0 && py < img.Bounds().Max.Y {
					img.SetRGBA(px, py, c)
				}
			}
		}
	}
}

func abs(x int) int {
	if x < 0 { return -x }
	return x
}

// SVGToBase64Img kept for API compatibility (web SVG endpoint)
func SVGToBase64Img(svg string) string {
	if svg == "" {
		return ""
	}
	b64 := base64.StdEncoding.EncodeToString([]byte(svg))
	return fmt.Sprintf(`<img src="data:image/svg+xml;base64,%s" width="800" />`, b64)
}

// ============================================================
// F.3 — Report API Endpoints
// ============================================================

// ReportSummary holds the JSON summary for /api/report/summary
type ReportSummary struct {
	HealthScore   int            `json:"health_score"`
	TotalSwitches int            `json:"total_switches"`
	TotalMACs     int            `json:"total_macs"`
	TotalNodes    int            `json:"total_nodes"`
	TotalEdges    int            `json:"total_edges"`
	Anomalies     map[string]int `json:"anomalies"`
	TopDevices    []DeviceSummary `json:"top_devices"`
}

// DeviceSummary is a short device record for report
type DeviceSummary struct {
	IP       string `json:"ip"`
	SysName  string `json:"sysname"`
	Vendor   string `json:"vendor"`
	Ports    int    `json:"ports"`
	MACs     int    `json:"macs"`
}

// reportSysNameVendors names the vendor of a polled device from keywords in
// its sysName, for chassis MACs without an OUI vendor. The first match wins.
var reportSysNameVendors = []struct {
	keywords []string
	vendor   string
}{
	{[]string{"snr"}, "SNR"},
	{[]string{"mikrotik"}, "MikroTik"},
	{[]string{"cisco"}, "Cisco"},
	{[]string{"hpe", "hp"}, "HPE"},
	{[]string{"ubiquiti", "ubnt"}, "Ubiquiti"},
	{[]string{"huawei"}, "Huawei"},
	{[]string{"fortinet", "fortigate"}, "Fortinet"},
}

// reportDeviceVendor is the vendor of a polled device in every report and
// export: the OUI vendor of its chassis MAC, else the vendor its sysName
// names, else "" (unknown).
func reportDeviceVendor(d *DeviceData) string {
	if vendor := getMACVendor(d.ChassisID); vendor != "" {
		return vendor
	}
	name := strings.ToLower(d.SysName)
	for _, rule := range reportSysNameVendors {
		for _, keyword := range rule.keywords {
			if strings.Contains(name, keyword) {
				return rule.vendor
			}
		}
	}
	return ""
}

func registerReportRoutes() {
	http.HandleFunc("/api/report/summary", reportSummaryHandler)
	http.HandleFunc("/api/report/topology-svg", reportTopologySVGHandler)
	http.HandleFunc("/api/report/full", reportFullHandler)
	http.HandleFunc("/api/report/audit-md", reportAuditMDHandler)
	http.HandleFunc("/api/report/audit-docx", reportAuditDocxHandler)
	http.HandleFunc("/api/report/audit-svg", reportAuditSVGHandler)
}

func reportSummaryHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	graph := GetGlobalGraph()

	summary := ReportSummary{
		Anomalies: make(map[string]int),
	}

	// Health Score
	lastReportMutex.RLock()
	summary.HealthScore = lastHealthScore
	summary.TotalMACs = lastTotalMACs
	lastReportMutex.RUnlock()

	if graph != nil {
		data := graph.GetGraphData()
		summary.TotalNodes = len(data.Nodes)
		summary.TotalEdges = len(data.Links)

		for _, n := range data.Nodes {
			if n.Group == "switch" || n.Group == "router" {
				summary.TotalSwitches++
			}
			for _, a := range n.Anomalies {
				summary.Anomalies[a]++
			}
		}
	}

	// Top devices
	collectedDataMutex.RLock()
	for _, dev := range collectedData {
		summary.TopDevices = append(summary.TopDevices, DeviceSummary{
			IP:      dev.IP,
			SysName: dev.SysName,
			Vendor:  reportDeviceVendor(dev),
			Ports:   len(dev.Interfaces),
			MACs:    len(dev.MACTable),
		})
	}
	collectedDataMutex.RUnlock()

	json.NewEncoder(w).Encode(summary)
}

func reportTopologySVGHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	graph := GetGlobalGraph()
	svg := GenerateTopologySVG(graph)
	w.Write([]byte(svg))
}

// reportFullHandler generates a full 7-section DOCX audit report from live data
func reportFullHandler(w http.ResponseWriter, r *http.Request) {
	graph := GetGlobalGraph()

	// Collect summary data
	lastReportMutex.RLock()
	healthScore := lastHealthScore
	totalMACs := lastTotalMACs
	lastReportMutex.RUnlock()

	// Build device table
	var deviceRows strings.Builder
	totalSwitches := 0
	collectedDataMutex.RLock()
	for _, dev := range collectedData {
		vendor := reportDeviceVendor(dev)
		deviceRows.WriteString(fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td><td>%d</td><td>%d</td></tr>\n",
			dev.IP, dev.SysName, vendor, len(dev.Interfaces), len(dev.MACTable)))
		totalSwitches++
	}
	collectedDataMutex.RUnlock()

	// Anomaly summary
	anomalyCounts := make(map[string]int)
	var anomalyRows strings.Builder
	if graph != nil {
		data := graph.GetGraphData()
		for _, n := range data.Nodes {
			for _, a := range n.Anomalies {
				anomalyCounts[a]++
				anomalyRows.WriteString(fmt.Sprintf("<tr><td>%s</td><td>%s</td><td>%s</td></tr>\n",
					a, n.ID, n.Label))
			}
		}
	}

	// Topology PNG (Word-compatible)
	topologyImg := ""
	if graph != nil {
		topologyImg = GenerateTopologyPNG(graph)
	}

	// Health label
	healthLabel := "Critical"
	healthColor := "#F44336"
	if healthScore >= 90 {
		healthLabel = "Excellent"
		healthColor = "#4CAF50"
	} else if healthScore >= 70 {
		healthLabel = "Good"
		healthColor = "#FF9800"
	}

	// Anomaly penalty summary
	var penaltyRows strings.Builder
	for aType, count := range anomalyCounts {
		penaltyRows.WriteString(fmt.Sprintf("<tr><td>%s</td><td>%d</td></tr>\n", aType, count))
	}

	// Build HTML (Word-compatible)
	now := time.Now().Format("2006-01-02 15:04")
	html := fmt.Sprintf(`<html xmlns:o="urn:schemas-microsoft-com:office:office" xmlns:w="urn:schemas-microsoft-com:office:word">
<head><meta charset="UTF-8"><style>
body { font-family: 'Times New Roman', serif; font-size: 14pt; color: #333; }
h1 { text-align: center; color: #2E74B5; font-size: 22pt; margin-top: 60px; }
h2 { color: #2E74B5; font-size: 16pt; border-bottom: 2px solid #2E74B5; padding-bottom: 4px; margin-top: 30px; }
.subtitle { text-align: center; color: #555; font-size: 12pt; }
table { border-collapse: collapse; width: 100%%; margin: 10px 0; }
th { background: #2E74B5; color: white; padding: 8px; text-align: left; font-size: 11pt; }
td { border: 1px solid #ccc; padding: 6px 8px; font-size: 11pt; }
tr:nth-child(even) { background: #f5f5f5; }
.score-box { text-align: center; font-size: 36pt; font-weight: bold; color: %s; margin: 20px 0; }
.score-label { text-align: center; font-size: 14pt; color: #555; }
.topo-img { text-align: center; margin: 20px 0; }
</style></head>
<body>
<!-- Section 1: Title -->
<h1>TARMOQ AUDIT HISOBOTI</h1>
<p class="subtitle">Sana: %s<br/>Tizim: LLDP Network Scanner v2.0</p>
<br style="page-break-after: always;" />

<!-- Section 2: General Info -->
<h2>1. Umumiy Ma'lumot</h2>
<table>
<tr><th>Parametr</th><th>Qiymat</th></tr>
<tr><td>Skanerlash vaqti</td><td>%s</td></tr>
<tr><td>Topilgan qurilmalar (SNMP)</td><td>%d</td></tr>
<tr><td>Noyob MAC manzillar</td><td>%d</td></tr>
</table>

<!-- Section 3: Health Score -->
<h2>2. Tarmoq Sog'ligi</h2>
<div class="score-box">%d/100</div>
<div class="score-label">%s</div>
<table>
<tr><th>Anomaliya turi</th><th>Soni</th></tr>
%s
</table>

<!-- Section 4: Topology -->
<h2>3. Topologiya Sxemasi</h2>
<div class="topo-img">%s</div>

<!-- Section 5: Device List -->
<h2>4. Qurilmalar Ro'yxati</h2>
<table>
<tr><th>IP</th><th>Hostname</th><th>Vendor</th><th>Portlar</th><th>MAC lar</th></tr>
%s
</table>

<!-- Section 6: Anomalies -->
<h2>5. Anomaliyalar</h2>
<table>
<tr><th>Turi</th><th>Qurilma</th><th>Tavsif</th></tr>
%s
</table>

<!-- Section 7: Recommendations -->
<h2>6. Tavsiyalar</h2>
<ul>`,
		healthColor, now, now, totalSwitches, totalMACs,
		healthScore, healthLabel,
		penaltyRows.String(),
		topologyImg,
		deviceRows.String(),
		anomalyRows.String())

	// Auto-generate recommendations
	if anomalyCounts["stp"] > 0 {
		html += "<li>STP Root Bridge core switchda sozlang (priority 0 yoki 4096)</li>"
	}
	if anomalyCounts["shadow_it"] > 0 {
		html += fmt.Sprintf("<li>%d ta boshqarilmaydigan qurilma aniqlandi — portlarni tekshiring</li>", anomalyCounts["shadow_it"])
	}
	if anomalyCounts["congestion"] > 0 {
		html += "<li>Tiqilinch aniqlangan portlarda kabel/SFP almashtirish tavsiya etiladi</li>"
	}
	if anomalyCounts["loopback"] > 0 {
		html += "<li><b>MUHIM:</b> Loop aniqlandi — darhol tekshiring!</li>"
	}
	if len(anomalyCounts) == 0 {
		html += "<li>Anomaliyalar topilmadi — tarmoq sog'lom holatda</li>"
	}

	html += "</ul></body></html>"

	// Send as Word document
	w.Header().Set("Content-Type", "application/msword")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="Network_Audit_%s.doc"`, time.Now().Format("2006-01-02")))
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Write([]byte("\xEF\xBB\xBF")) // BOM
	w.Write([]byte(html))
}

// ============================================================
// F.4 — Mermaid Topology Generator
// ============================================================

// GenerateMermaidTopology creates Mermaid graph code for selected device groups
func GenerateMermaidTopology(graph *DJGraph, groups []string) string {
	if graph == nil {
		return "graph TD\n  NoData[Topologiya ma'lumotlari mavjud emas]"
	}

	data := graph.GetGraphData()

	// Build allowed groups set
	allowedGroups := make(map[string]bool)
	for _, g := range groups {
		allowedGroups[g] = true
	}

	// Collect nodes matching allowed groups
	type mNode struct {
		ID, Label, SafeID, Group string
	}
	var nodes []mNode
	nodeSet := make(map[string]bool)
	safeIDs := make(map[string]string)
	usedNames := make(map[string]bool)

	for _, n := range data.Nodes {
		if !allowedGroups[n.Group] {
			continue
		}
		label := n.SysName
		if label == "" {
			label = n.ID
		}
		// Clean multi-line labels for Mermaid (e.g., "HPE\n172.20.230.5" → "HPE<br>172.20.230.5")
		label = strings.ReplaceAll(label, "\n", "<br>")
		// Create safe mermaid ID
		safe := sanitizeMermaidID(label)
		if safe == "" {
			safe = sanitizeMermaidID(n.ID)
		}
		// Ensure unique
		base := safe
		counter := 2
		for usedNames[safe] {
			safe = fmt.Sprintf("%s_%d", base, counter)
			counter++
		}
		usedNames[safe] = true
		safeIDs[n.ID] = safe
		nodeSet[n.ID] = true
		nodes = append(nodes, mNode{ID: n.ID, Label: label, SafeID: safe, Group: n.Group})
	}

	if len(nodes) == 0 {
		return "graph TD\n  NoData[Topologiya ma'lumotlari mavjud emas]"
	}

	// Collect edges between switches  
	type mEdge struct{ SrcSafe, DstSafe, PortLabel string }
	var edges []mEdge
	connected := make(map[string]bool)
	for _, l := range data.Links {
		if nodeSet[l.Source] && nodeSet[l.Target] {
			srcSafe := safeIDs[l.Source]
			dstSafe := safeIDs[l.Target]
			if srcSafe != "" && dstSafe != "" {
				// Extract port labels
				portLabel := ""
				if l.SourceLabel != "" && l.TargetLabel != "" {
					portLabel = l.SourceLabel + " ↔ " + l.TargetLabel
				} else if l.Label != "" {
					if strings.Contains(l.Label, "|") {
						parts := strings.SplitN(l.Label, "|", 2)
						portLabel = strings.TrimSpace(parts[0]) + " ↔ " + strings.TrimSpace(parts[1])
					} else {
						portLabel = l.Label
					}
				}
				edges = append(edges, mEdge{srcSafe, dstSafe, portLabel})
				connected[l.Source] = true
				connected[l.Target] = true
			}
		}
	}

	// Group color mapping (matches UI filters)
	groupColors := map[string][2]string{
		"switch":       {"#4A90E2", "#2A6FC2"},
		"router":       {"#E24A4A", "#C23030"},
		"hub":          {"#FF9800", "#E68A00"},
		"endpoint":     {"#8BC34A", "#6B9F30"},
		"access_point": {"#00BCD4", "#0097A7"},
		"vm":           {"#9C27B0", "#7B1FA2"},
		"hypervisor":   {"#26C6DA", "#0097A7"},
		"bmc":          {"#FF6F00", "#E65100"},
		"camera":       {"#E91E63", "#C2185B"},
		"phone":        {"#3F51B5", "#303F9F"},
		"iot":          {"#607D8B", "#455A64"},
		"wifi_random":  {"#00BCD4", "#0097A7"},
	}

	var sb strings.Builder
	sb.WriteString("graph TD\n")

	// Node definitions with shapes per group
	for _, nd := range nodes {
		switch nd.Group {
		case "hub":
			sb.WriteString(fmt.Sprintf("  %s((\"%s\"))\n", nd.SafeID, nd.Label))
		case "router":
			sb.WriteString(fmt.Sprintf("  %s{{\"%s\"}}\n", nd.SafeID, nd.Label))
		case "access_point", "wifi_random":
			sb.WriteString(fmt.Sprintf("  %s>\" %s\"]\n", nd.SafeID, nd.Label))
		default:
			sb.WriteString(fmt.Sprintf("  %s[\"%s\"]\n", nd.SafeID, nd.Label))
		}
	}

	// Edges with port labels
	for _, e := range edges {
		if e.PortLabel != "" {
			sb.WriteString(fmt.Sprintf("  %s-- \"%s\" -->%s\n", e.SrcSafe, e.PortLabel, e.DstSafe))
		} else {
			sb.WriteString(fmt.Sprintf("  %s-->%s\n", e.SrcSafe, e.DstSafe))
		}
	}

	// Style each node with its group color
	for _, nd := range nodes {
		if colors, ok := groupColors[nd.Group]; ok {
			sb.WriteString(fmt.Sprintf("  style %s fill:%s,stroke:%s,color:#fff\n", nd.SafeID, colors[0], colors[1]))
		}
	}

	return sb.String()
}

// GenerateTopologyLegend returns a markdown legend table for the topology colors
func GenerateTopologyLegend(groups []string) string {
	type legendItem struct {
		Color, Label string
	}
	allItems := map[string]legendItem{
		"switch":       {"🔵", "Switch"},
		"router":       {"🔴", "Router"},
		"hub":          {"🟠", "Hub (Shadow IT)"},
		"endpoint":     {"🟢", "Endpoint"},
		"access_point": {"🔷", "Wi-Fi AP"},
		"vm":           {"🟣", "VM"},
		"hypervisor":   {"💠", "Hypervisor"},
		"bmc":          {"🟧", "BMC/iLO"},
		"camera":       {"🩷", "Camera"},
		"phone":        {"🔵", "Phone"},
		"iot":          {"⬜", "IoT"},
		"wifi_random":  {"🔷", "Random MAC"},
	}

	var sb strings.Builder
	sb.WriteString("| Rang | Turi |\n|---|---|\n")
	for _, g := range groups {
		if item, ok := allItems[g]; ok {
			sb.WriteString(fmt.Sprintf("| %s | %s |\n", item.Color, item.Label))
		}
	}
	return sb.String()
}

// GenerateShadowDiagrams creates individual mermaid diagrams for each Shadow IT hub
func GenerateShadowDiagrams(graph *DJGraph) string {
	if graph == nil {
		return ""
	}

	data := graph.GetGraphData()

	// Find all hub nodes
	type hubInfo struct {
		ID, Label, SafeID string
	}
	var hubs []hubInfo

	for _, n := range data.Nodes {
		if n.Group != "hub" {
			continue
		}
		label := n.SysName
		if label == "" {
			label = n.ID
		}
		safeID := sanitizeMermaidID(n.ID)
		hubs = append(hubs, hubInfo{n.ID, label, safeID})
	}

	if len(hubs) == 0 {
		return ""
	}

	var md strings.Builder

	for i, hub := range hubs {
		md.WriteString(fmt.Sprintf("### Shadow IT #%d: %s\n\n", i+1, hub.Label))

		var sb strings.Builder
		sb.WriteString("graph LR\n")

		// Hub node (orange circle)
		hubDisplayLabel := strings.ReplaceAll(hub.Label, "\n", "<br>")
		sb.WriteString(fmt.Sprintf("  %s((\"%s\"))\n", hub.SafeID, hubDisplayLabel))

		// Find parent switch(es) connected TO this hub
		parentCount := 0
		for _, link := range data.Links {
			srcID := link.Source
			tgtID := link.Target
			if tgtID == hub.ID {
				// src → hub
				srcSafe := sanitizeMermaidID(srcID)
				srcLabel := srcID
				for _, n := range data.Nodes {
					if n.ID == srcID {
						if n.SysName != "" {
							// SysName contains multi-line info like "HPE\n172.20.230.5"
							// Use first line as label, add IP on next line
							lines := strings.SplitN(n.SysName, "\n", 3)
							srcLabel = strings.Join(lines[:min(len(lines), 2)], "<br>")
						}
						break
					}
				}
				// Parse pipe-separated label: "GE1/0/42 [V100]|Hub" → only show source port
				portLabel := ""
				if link.Label != "" {
					if strings.Contains(link.Label, "|") {
						parts := strings.SplitN(link.Label, "|", 2)
						portLabel = strings.TrimSpace(parts[0])
					} else {
						portLabel = link.Label
					}
				}
				sb.WriteString(fmt.Sprintf("  %s[\"%s\"]\n", srcSafe, srcLabel))
				if portLabel != "" {
					sb.WriteString(fmt.Sprintf("  %s-- \"%s\" -->%s\n", srcSafe, portLabel, hub.SafeID))
				} else {
					sb.WriteString(fmt.Sprintf("  %s-->%s\n", srcSafe, hub.SafeID))
				}
				sb.WriteString(fmt.Sprintf("  style %s fill:#4A90E2,stroke:#2A6FC2,color:#fff\n", srcSafe))
				parentCount++
			}
		}

		// Find children connected FROM this hub
		childCount := 0
		for _, link := range data.Links {
			srcID := link.Source
			tgtID := link.Target
			if srcID == hub.ID {
				// hub → child
				tgtSafe := sanitizeMermaidID(tgtID)
				// Skip phantom nodes with very short IDs (corrupt LLDP port IDs)
				if len(tgtSafe) <= 4 {
					continue
				}
				tgtLabel := tgtID
				tgtGroup := "endpoint"
				for _, n := range data.Nodes {
					if n.ID == tgtID {
						if n.SysName != "" {
							// Clean multi-line info for Mermaid display
							lines := strings.SplitN(n.SysName, "\n", 3)
							tgtLabel = strings.Join(lines[:min(len(lines), 2)], "<br>")
						}
						tgtGroup = n.Group
						break
					}
				}
				sb.WriteString(fmt.Sprintf("  %s[\"%s\"]\n", tgtSafe, tgtLabel))
				sb.WriteString(fmt.Sprintf("  %s-->%s\n", hub.SafeID, tgtSafe))
				// Color children by group
				switch tgtGroup {
				case "endpoint":
					sb.WriteString(fmt.Sprintf("  style %s fill:#8BC34A,stroke:#6B9F30,color:#fff\n", tgtSafe))
				case "phone":
					sb.WriteString(fmt.Sprintf("  style %s fill:#3F51B5,stroke:#303F9F,color:#fff\n", tgtSafe))
				case "camera":
					sb.WriteString(fmt.Sprintf("  style %s fill:#E91E63,stroke:#C2185B,color:#fff\n", tgtSafe))
				case "iot":
					sb.WriteString(fmt.Sprintf("  style %s fill:#607D8B,stroke:#455A64,color:#fff\n", tgtSafe))
				default:
					sb.WriteString(fmt.Sprintf("  style %s fill:#8BC34A,stroke:#6B9F30,color:#fff\n", tgtSafe))
				}
				childCount++
			}
		}

		// Style hub orange
		sb.WriteString(fmt.Sprintf("  style %s fill:#FF9800,stroke:#E68A00,color:#fff\n", hub.SafeID))

		md.WriteString("```mermaid\n")
		md.WriteString(sb.String())
		md.WriteString("```\n\n")
		md.WriteString(fmt.Sprintf("**Ulanganlar:** %d ta qurilma\n\n", childCount))
	}

	return md.String()
}

// GenerateHypervisorDiagrams creates individual mermaid diagrams for each Hypervisor node
func GenerateHypervisorDiagrams(graph *DJGraph) string {
	if graph == nil {
		return ""
	}

	data := graph.GetGraphData()

	// Find all hypervisor nodes
	type hypInfo struct {
		ID, Label, SafeID string
	}
	var hypervisors []hypInfo

	for _, n := range data.Nodes {
		if n.Group != "hypervisor" {
			continue
		}
		label := n.SysName
		if label == "" {
			label = n.ID
		}
		safeID := sanitizeMermaidID(n.ID)
		hypervisors = append(hypervisors, hypInfo{n.ID, label, safeID})
	}

	if len(hypervisors) == 0 {
		return ""
	}

	var md strings.Builder

	for i, hyp := range hypervisors {
		// Clean label for title
		titleLabel := strings.ReplaceAll(hyp.Label, "\n", " — ")
		md.WriteString(fmt.Sprintf("### Hypervisor #%d: %s\n\n", i+1, titleLabel))

		var sb strings.Builder
		sb.WriteString("graph LR\n")

		// Hypervisor node (cyan hexagon)
		hypDisplayLabel := strings.ReplaceAll(hyp.Label, "\n", "<br>")
		sb.WriteString(fmt.Sprintf("  %s{{\"%s\"}}\n", hyp.SafeID, hypDisplayLabel))

		// Find parent switch(es) connected TO this hypervisor
		for _, link := range data.Links {
			if link.Target == hyp.ID {
				srcSafe := sanitizeMermaidID(link.Source)
				srcLabel := link.Source
				for _, n := range data.Nodes {
					if n.ID == link.Source {
						if n.SysName != "" {
							lines := strings.SplitN(n.SysName, "\n", 3)
							srcLabel = strings.Join(lines[:min(len(lines), 2)], "<br>")
						}
						break
					}
				}
				// Parse pipe-separated label
				portLabel := ""
				if link.Label != "" {
					if strings.Contains(link.Label, "|") {
						parts := strings.SplitN(link.Label, "|", 2)
						portLabel = strings.TrimSpace(parts[0])
					} else {
						portLabel = link.Label
					}
				}
				sb.WriteString(fmt.Sprintf("  %s[\"%s\"]\n", srcSafe, srcLabel))
				if portLabel != "" {
					sb.WriteString(fmt.Sprintf("  %s-- \"%s\" -->%s\n", srcSafe, portLabel, hyp.SafeID))
				} else {
					sb.WriteString(fmt.Sprintf("  %s-->%s\n", srcSafe, hyp.SafeID))
				}
				sb.WriteString(fmt.Sprintf("  style %s fill:#4A90E2,stroke:#2A6FC2,color:#fff\n", srcSafe))
			}
		}

		// Find VM children connected FROM this hypervisor
		vmCount := 0
		for _, link := range data.Links {
			if link.Source == hyp.ID {
				tgtSafe := sanitizeMermaidID(link.Target)
				if len(tgtSafe) <= 4 {
					continue
				}
				tgtLabel := link.Target
				for _, n := range data.Nodes {
					if n.ID == link.Target {
						if n.SysName != "" {
							lines := strings.SplitN(n.SysName, "\n", 3)
							tgtLabel = strings.Join(lines[:min(len(lines), 2)], "<br>")
						}
						break
					}
				}
				sb.WriteString(fmt.Sprintf("  %s[\"%s\"]\n", tgtSafe, tgtLabel))
				sb.WriteString(fmt.Sprintf("  %s-->%s\n", hyp.SafeID, tgtSafe))
				sb.WriteString(fmt.Sprintf("  style %s fill:#9C27B0,stroke:#7B1FA2,color:#fff\n", tgtSafe))
				vmCount++
			}
		}

		// Style hypervisor cyan
		sb.WriteString(fmt.Sprintf("  style %s fill:#26C6DA,stroke:#0097A7,color:#fff\n", hyp.SafeID))

		md.WriteString("```mermaid\n")
		md.WriteString(sb.String())
		md.WriteString("```\n\n")
		md.WriteString(fmt.Sprintf("**Virtual mashinalar:** %d ta\n\n", vmCount))
	}

	return md.String()
}

// sanitizeMermaidID creates a safe mermaid node ID
func sanitizeMermaidID(s string) string {
	var result strings.Builder
	for _, ch := range s {
		if (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') || (ch >= '0' && ch <= '9') || ch == '_' {
			result.WriteRune(ch)
		} else if ch == '.' || ch == '-' || ch == ' ' {
			result.WriteRune('_')
		}
	}
	s = result.String()
	// Collapse multiple underscores
	for strings.Contains(s, "__") {
		s = strings.ReplaceAll(s, "__", "_")
	}
	return strings.Trim(s, "_")
}

// parseGroups extracts groups from query param, defaults to switch+hub
func parseGroups(r *http.Request) []string {
	groupsParam := r.URL.Query().Get("groups")
	if groupsParam == "" {
		return []string{"switch", "hub"}
	}
	return strings.Split(groupsParam, ",")
}

// reportAuditMDHandler generates a Markdown audit report with mermaid topology
func reportAuditMDHandler(w http.ResponseWriter, r *http.Request) {
	groups := parseGroups(r)
	mdContent := generateAuditMD(groups)

	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="Network_Audit_%s.md"`, time.Now().Format("2006-01-02")))
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Write([]byte(mdContent))
}

// generateAuditMD builds the full MD report content (reusable for both MD and DOCX endpoints)
func generateAuditMD(groups []string) string {
	graph := GetGlobalGraph()

	lastReportMutex.RLock()
	healthScore := lastHealthScore
	totalMACs := lastTotalMACs
	lastReportMutex.RUnlock()

	// Device table
	var deviceRows strings.Builder
	totalSwitches := 0
	collectedDataMutex.RLock()
	deviceRows.WriteString("| IP | Hostname | Vendor | Portlar | MAC lar |\n")
	deviceRows.WriteString("|---|---|---|---|---|\n")
	for _, dev := range collectedData {
		vendor := reportDeviceVendor(dev)
		deviceRows.WriteString(fmt.Sprintf("| %s | %s | %s | %d | %d |\n",
			dev.IP, dev.SysName, vendor, len(dev.Interfaces), len(dev.MACTable)))
		totalSwitches++
	}
	collectedDataMutex.RUnlock()

	// Anomalies
	anomalyCounts := make(map[string]int)
	var anomalyRows strings.Builder
	anomalyRows.WriteString("| Turi | Qurilma | Tavsif |\n")
	anomalyRows.WriteString("|---|---|---|\n")
	if graph != nil {
		data := graph.GetGraphData()
		for _, n := range data.Nodes {
			for _, a := range n.Anomalies {
				anomalyCounts[a]++
				anomalyRows.WriteString(fmt.Sprintf("| %s | %s | %s |\n", a, n.ID, n.Label))
			}
		}
	}

	var penaltyRows strings.Builder
	penaltyRows.WriteString("| Anomaliya turi | Soni |\n")
	penaltyRows.WriteString("|---|---|\n")
	for aType, count := range anomalyCounts {
		penaltyRows.WriteString(fmt.Sprintf("| %s | %d |\n", aType, count))
	}

	healthLabel := "Critical"
	if healthScore >= 90 {
		healthLabel = "Excellent"
	} else if healthScore >= 70 {
		healthLabel = "Good"
	}

	mermaidCode := ""
	if graph != nil {
		mermaidCode = GenerateMermaidTopology(graph, groups)
	}

	now := time.Now().Format("2006-01-02 15:04")
	var md strings.Builder

	md.WriteString("# TARMOQ AUDIT HISOBOTI\n\n")
	md.WriteString(fmt.Sprintf("Sana: %s\n\n", now))
	md.WriteString("Tizim: LLDP Network Scanner v2.0\n\n")

	md.WriteString("## 1. Umumiy Ma'lumot\n\n")
	md.WriteString("| Parametr | Qiymat |\n")
	md.WriteString("|---|---|\n")
	md.WriteString(fmt.Sprintf("| Skanerlash vaqti | %s |\n", now))
	md.WriteString(fmt.Sprintf("| Topilgan qurilmalar (SNMP) | %d |\n", totalSwitches))
	md.WriteString(fmt.Sprintf("| Noyob MAC manzillar | %d |\n\n", totalMACs))

	md.WriteString("## 2. Tarmoq Sog'ligi\n\n")
	md.WriteString(fmt.Sprintf("**%d/100** — %s\n\n", healthScore, healthLabel))
	md.WriteString(penaltyRows.String())
	md.WriteString("\n")

	md.WriteString("## 3. Topologiya Sxemasi\n\n")
	md.WriteString("```mermaid\n")
	md.WriteString(mermaidCode)
	md.WriteString("\n```\n\n")
	md.WriteString("**Izoh (rang kodlari):**\n\n")
	md.WriteString(GenerateTopologyLegend(groups))
	md.WriteString("\n")

	md.WriteString("## 4. Qurilmalar Ro'yxati\n\n")

	// 4.1 Switchlar (from collectedData — detailed SNMP info)
	md.WriteString("### 4.1 Switchlar\n\n")
	md.WriteString(deviceRows.String())
	md.WriteString("\n")

	// Build per-group tables from graph data
	if graph != nil {
		data := graph.GetGraphData()

		// Group order and display names
		type groupDef struct {
			key   string
			title string
		}
		groupOrder := []groupDef{
			{"endpoint", "4.2 Endpoint qurilmalar"},
			{"hypervisor", "4.3 Hypervisor serverlar"},
			{"vm", "4.4 Virtual mashinalar"},
			{"hub", "4.5 Hub / Unmanaged switch"},
			{"phone", "4.6 Telefonlar (VoIP)"},
			{"camera", "4.7 Kameralar"},
			{"iot", "4.8 IoT qurilmalar"},
			{"bmc", "4.9 BMC/iLO"},
			{"server", "4.10 Serverlar"},
			{"router", "4.11 Routerlar"},
			{"wifi_random", "4.12 Wi-Fi / Random MAC"},
		}

		// Group nodes
		grouped := make(map[string][]GraphNode)
		for _, n := range data.Nodes {
			if n.Group == "switch" || n.Group == "unknown" {
				continue // switches already in 4.1
			}
			grouped[n.Group] = append(grouped[n.Group], n)
		}

		// Build adjacency lookup for "connected to" info
		connectedTo := make(map[string]string)
		for _, link := range data.Links {
			// Find parent switch for each non-switch node
			srcGroup := ""
			tgtGroup := ""
			for _, n := range data.Nodes {
				if n.ID == link.Source {
					srcGroup = n.Group
				}
				if n.ID == link.Target {
					tgtGroup = n.Group
				}
			}
			if srcGroup == "switch" && tgtGroup != "switch" {
				// Extract port label
				port := ""
				if link.Label != "" && strings.Contains(link.Label, "|") {
					parts := strings.SplitN(link.Label, "|", 2)
					port = strings.TrimSpace(parts[0])
				} else if link.Label != "" {
					port = link.Label
				}
				parentLabel := link.Source
				for _, n := range data.Nodes {
					if n.ID == link.Source && n.SysName != "" {
						lines := strings.SplitN(n.SysName, "\n", 2)
						parentLabel = lines[0]
						break
					}
				}
				if port != "" {
					connectedTo[link.Target] = fmt.Sprintf("%s (%s)", parentLabel, port)
				} else {
					connectedTo[link.Target] = parentLabel
				}
			}
		}

		for _, gd := range groupOrder {
			nodes, ok := grouped[gd.key]
			if !ok || len(nodes) == 0 {
				continue
			}

			md.WriteString(fmt.Sprintf("### %s (%d ta)\n\n", gd.title, len(nodes)))
			md.WriteString("| # | ID / MAC | Ma'lumot | IP | Connected to |\n")
			md.WriteString("|---|---|---|---|---|\n")

			for i, n := range nodes {
				// Extract meaningful info (first line of SysName)
				info := ""
				if n.SysName != "" {
					lines := strings.SplitN(n.SysName, "\n", 2)
					info = lines[0]
				}

				ip := n.IP
				if ip == "" && n.SysName != "" {
					// Try to extract IP from info lines
					for _, line := range strings.Split(n.SysName, "\n") {
						trimmed := strings.TrimSpace(line)
						if net.ParseIP(trimmed) != nil {
							ip = trimmed
							break
						}
					}
				}

				conn := connectedTo[n.ID]
				if conn == "" {
					conn = "-"
				}

				md.WriteString(fmt.Sprintf("| %d | %s | %s | %s | %s |\n",
					i+1, n.ID, info, ip, conn))
			}
			md.WriteString("\n")
		}
	}

	// VLAN Summary Table
	md.WriteString("## 5. VLAN Ro'yxati\n\n")

	type vlanInfo struct {
		accessPorts map[string]int // switch IP → access port count
		trunkPorts  map[string]int // switch IP → trunk port count
	}
	vlanMap := make(map[int]*vlanInfo)

	collectedDataMutex.RLock()
	for _, dev := range collectedData {
		for _, pv := range dev.PortVLANs {
			vid := pv.PVID
			if vid <= 0 {
				continue
			}
			if vlanMap[vid] == nil {
				vlanMap[vid] = &vlanInfo{
					accessPorts: make(map[string]int),
					trunkPorts:  make(map[string]int),
				}
			}
			if pv.IsTrunk {
				vlanMap[vid].trunkPorts[dev.IP]++
			} else {
				vlanMap[vid].accessPorts[dev.IP]++
			}
		}
	}
	collectedDataMutex.RUnlock()

	if len(vlanMap) > 0 {
		// Sort VLAN IDs
		vlanIDs := make([]int, 0, len(vlanMap))
		for vid := range vlanMap {
			vlanIDs = append(vlanIDs, vid)
		}
		sort.Ints(vlanIDs)

		md.WriteString("| VLAN ID | Switchlar (access) | Access portlar | Trunk portlar |\n")
		md.WriteString("|---|---|---|---|\n")

		for _, vid := range vlanIDs {
			vi := vlanMap[vid]
			// Build switch list with counts
			var switchNames []string
			totalAccess := 0
			totalTrunk := 0
			for ip, cnt := range vi.accessPorts {
				// Get switch name
				name := ip
				collectedDataMutex.RLock()
				for _, dev := range collectedData {
					if dev.IP == ip && dev.SysName != "" {
						name = dev.SysName
						break
					}
				}
				collectedDataMutex.RUnlock()
				switchNames = append(switchNames, fmt.Sprintf("%s(%d)", name, cnt))
				totalAccess += cnt
			}
			for _, cnt := range vi.trunkPorts {
				totalTrunk += cnt
			}
			switchStr := strings.Join(switchNames, ", ")
			if switchStr == "" {
				switchStr = "-"
			}
			md.WriteString(fmt.Sprintf("| %d | %s | %d | %d |\n",
				vid, switchStr, totalAccess, totalTrunk))
		}
		md.WriteString("\n")
	} else {
		md.WriteString("VLAN ma'lumotlari mavjud emas\n\n")
	}

	md.WriteString("## 6. Anomaliyalar\n\n")
	md.WriteString(anomalyRows.String())
	md.WriteString("\n")

	// Shadow IT detailed diagrams
	shadowMD := GenerateShadowDiagrams(graph)
	if shadowMD != "" {
		md.WriteString("## 7. Shadow IT Tarmoqlar (batafsil)\n\n")
		md.WriteString(shadowMD)
	}

	// Hypervisor detailed diagrams
	hypMD := GenerateHypervisorDiagrams(graph)
	if hypMD != "" {
		md.WriteString("## 8. Hypervisor Serverlar (batafsil)\n\n")
		md.WriteString(hypMD)
	}

	md.WriteString("## 9. Tavsiyalar\n\n")
	if anomalyCounts["stp"] > 0 {
		md.WriteString("- STP Root Bridge core switchda sozlang (priority 0 yoki 4096)\n")
	}
	if anomalyCounts["shadow_it"] > 0 {
		md.WriteString(fmt.Sprintf("- %d ta boshqarilmaydigan qurilma aniqlandi — portlarni tekshiring\n", anomalyCounts["shadow_it"]))
	}
	if anomalyCounts["congestion"] > 0 {
		md.WriteString("- Tiqilinch aniqlangan portlarda kabel/SFP almashtirish tavsiya etiladi\n")
	}
	if anomalyCounts["loopback"] > 0 {
		md.WriteString("- **MUHIM:** Loop aniqlandi — darhol tekshiring!\n")
	}
	if len(anomalyCounts) == 0 {
		md.WriteString("- Anomaliyalar topilmadi — tarmoq sog'lom holatda\n")
	}

	return md.String()
}

// reportAuditDocxHandler: MD → Python script → DOCX → Download (full pipeline)
func reportAuditDocxHandler(w http.ResponseWriter, r *http.Request) {
	groups := parseGroups(r)
	log.Printf("[DOCX] Audit DOCX pipeline boshlandi... (groups: %v)", groups)

	// 1. Generate MD content
	mdContent := generateAuditMD(groups)

	// 2. Write to temp MD file
	tmpDir := os.TempDir()
	mdPath := filepath.Join(tmpDir, fmt.Sprintf("audit_%d.md", time.Now().UnixNano()))
	docxPath := filepath.Join(tmpDir, fmt.Sprintf("audit_%d.docx", time.Now().UnixNano()))

	if err := os.WriteFile(mdPath, []byte(mdContent), 0644); err != nil {
		log.Printf("[DOCX] MD faylga yozish xatosi: %v", err)
		http.Error(w, "MD fayl yaratishda xato: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer os.Remove(mdPath)

	// 3. Find the Python script
	exePath, _ := os.Executable()
	exeDir := filepath.Dir(exePath)
	scriptPath := filepath.Join(exeDir, "instrumens", "md2docx_gost_linux.py")

	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		// Try relative to working directory
		scriptPath = filepath.Join("instrumens", "md2docx_gost_linux.py")
		if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
			log.Printf("[DOCX] Python script topilmadi: %s", scriptPath)
			http.Error(w, "md2docx_gost_linux.py topilmadi", http.StatusInternalServerError)
			return
		}
	}

	// 4. Run Python script: python3 script.py input.md output.docx
	log.Printf("[DOCX] Script ishga tushmoqda: python3 %s %s %s", scriptPath, mdPath, docxPath)
	cmd := exec.Command("python3", scriptPath, mdPath, docxPath)
	cmd.Dir = filepath.Dir(scriptPath)
	// Ensure user-installed Python packages are visible under sudo
	homeDir, _ := os.UserHomeDir()
	if homeDir == "" || homeDir == "/root" {
		// When running as sudo, HOME might be /root - try to find user's home
		homeDir = "/home/" + os.Getenv("SUDO_USER")
		if os.Getenv("SUDO_USER") == "" {
			homeDir = "/home/qosim"
		}
	}
	cmd.Env = append(os.Environ(),
		"PYTHONPATH="+homeDir+"/.local/lib/python3.12/site-packages:"+homeDir+"/.local/lib/python3.11/site-packages",
		"HOME="+homeDir,
	)
	// Use CombinedOutput() instead of separate Stdout/Stderr pipes + Run()
	// to avoid writerDescriptor goroutine crash when pipe breaks
	combinedOut, err := cmd.CombinedOutput()

	if err != nil {
		log.Printf("[DOCX] Script xatosi: %v\nOutput: %s", err, string(combinedOut))
		http.Error(w, "DOCX generatsiya xatosi: "+err.Error()+"\n"+string(combinedOut), http.StatusInternalServerError)
		return
	}
	log.Printf("[DOCX] Script natijasi: %s", string(combinedOut))

	// 5. Read the generated DOCX
	docxData, err := os.ReadFile(docxPath)
	if err != nil {
		log.Printf("[DOCX] DOCX o'qish xatosi: %v", err)
		http.Error(w, "DOCX faylni o'qishda xato: "+err.Error(), http.StatusInternalServerError)
		return
	}
	defer os.Remove(docxPath)

	// 6. Send DOCX to browser
	fileName := fmt.Sprintf("Network_Audit_%s.docx", time.Now().Format("2006-01-02"))
	w.Header().Set("Content-Type", "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, fileName))
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(docxData)))
	w.Write(docxData)

	log.Printf("[DOCX] ✅ %s yuborildi (%d bytes)", fileName, len(docxData))
}

// reportAuditSVGHandler: Mermaid → Python(DOT) → dot -Tsvg → Download
func reportAuditSVGHandler(w http.ResponseWriter, r *http.Request) {
	groups := parseGroups(r)
	log.Printf("[SVG] Topologiya SVG boshlandi (groups: %v)", groups)

	graph := GetGlobalGraph()
	if graph == nil {
		http.Error(w, "Graf topilmadi", http.StatusInternalServerError)
		return
	}

	mermaidCode := GenerateMermaidTopology(graph, groups)

	// Write mermaid to temp file
	tmpDir := os.TempDir()
	mdPath := filepath.Join(tmpDir, fmt.Sprintf("svg_%d.md", time.Now().UnixNano()))
	mdContent := "```mermaid\n" + mermaidCode + "\n```\n"
	if err := os.WriteFile(mdPath, []byte(mdContent), 0644); err != nil {
		http.Error(w, "Temp fayl xatosi", http.StatusInternalServerError)
		return
	}
	defer os.Remove(mdPath)

	svgPath := filepath.Join(tmpDir, fmt.Sprintf("topology_%d.svg", time.Now().UnixNano()))
	defer os.Remove(svgPath)

	// Find script
	exePath, _ := os.Executable()
	exeDir := filepath.Dir(exePath)
	scriptPath := filepath.Join(exeDir, "instrumens", "md2docx_gost_linux.py")
	if _, err := os.Stat(scriptPath); os.IsNotExist(err) {
		scriptPath = filepath.Join("instrumens", "md2docx_gost_linux.py")
	}

	// Python one-liner: import script functions, convert mermaid→DOT, pipe to dot -Tsvg
	pyCode := `
import sys, os, subprocess, re
script_path = sys.argv[1]
md_path = sys.argv[2]
svg_path = sys.argv[3]
# Load only functions from script (up to pre_generate_diagrams)
with open(script_path) as sf:
    script_code = sf.read().split('def pre_generate_diagrams')[0]
exec(script_code)
with open(md_path) as f:
    content = f.read()
m = re.search(r'` + "```" + `mermaid\n(.*?)\n` + "```" + `', content, re.DOTALL)
if m:
    dot_code = mermaid_to_graphviz(m.group(1))
    # Remove DPI for SVG (vector format, DPI not needed and causes huge dimensions)
    import re as re2
    dot_code = re2.sub(r'\s*dpi=\d+;', '', dot_code)
    result = subprocess.run(['dot', '-Tsvg'], input=dot_code, capture_output=True, text=True, timeout=120)
    if result.returncode == 0:
        with open(svg_path, 'w') as f:
            f.write(result.stdout)
        print("OK")
    else:
        print("DOT_ERR:" + result.stderr[:200])
else:
    print("NO_MERMAID")
`

	cmd := exec.Command("python3", "-c", pyCode, scriptPath, mdPath, svgPath)
	cmd.Env = append(os.Environ(),
		"PYTHONPATH=/home/qosim/.local/lib/python3.12/site-packages",
		"HOME=/home/qosim",
	)
	output, err := cmd.CombinedOutput()
	outStr := strings.TrimSpace(string(output))

	if err != nil || outStr != "OK" {
		log.Printf("[SVG] Xato: %v, output: %s", err, outStr)
		http.Error(w, "SVG xatosi: "+outStr, http.StatusInternalServerError)
		return
	}

	svgData, err := os.ReadFile(svgPath)
	if err != nil {
		http.Error(w, "SVG o'qish xatosi", http.StatusInternalServerError)
		return
	}

	fileName := fmt.Sprintf("Network_Topology_%s.svg", time.Now().Format("2006-01-02"))
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, fileName))
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Write(svgData)

	log.Printf("[SVG] ✅ %s yuborildi (%d bytes)", fileName, len(svgData))
}
