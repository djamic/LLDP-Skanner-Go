package main

import (
	"cmp"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"slices"
	"strings"
	"sync"
	"time"
)

// Coordinate represents x,y position
type Coordinate struct {
	X int `json:"x"`
	Y int `json:"y"`
}

// DJGraph manages network topology graph
type DJGraph struct {
	mu         sync.RWMutex
	Nodes      map[string]bool
	Edges      map[string]map[string]string
	NodeCoords map[string]Coordinate
	SwitchInfo map[string]string
	IDs        map[string]int
	NodeStatus map[string]string // Phase 8: nodeID → "unreachable" or ""

	// graphSwitches holds the node ids of the polled devices (set by the
	// graph build): such a node is a switch, whatever its label says.
	// graphRouters holds the router nodes of the configured gateways
	// (addGatewayNodes): such a node is a router, whatever its label says.
	// graphSysText holds the sysName/sysDescr text known for a node (the
	// polled sysName, LLDP RemSysName and RemSysDesc), never vendor text.
	// graphManaged holds the nodes of the access points a controller
	// manages that no switch showed (addManagedAPNodes): such a node is an
	// access point.
	graphSwitches map[string]bool
	graphRouters  map[string]bool
	graphSysText  map[string]string
	graphManaged  map[string]bool
}

// NewDJGraph creates a new graph instance
func NewDJGraph() *DJGraph {
	return &DJGraph{
		Nodes:      make(map[string]bool),
		Edges:      make(map[string]map[string]string),
		NodeCoords: make(map[string]Coordinate),
		SwitchInfo: make(map[string]string),
		IDs:        make(map[string]int),
		NodeStatus: make(map[string]string),
	}
}

// AddNode adds a node to the graph
func (g *DJGraph) AddNode(node string) {
	g.Nodes[node] = true
}

// AddNodeCoords adds coordinates for a node
func (g *DJGraph) AddNodeCoords(node string, x, y int) error {
	if !g.Nodes[node] {
		return fmt.Errorf("node must exist in the graph")
	}
	g.NodeCoords[node] = Coordinate{X: x, Y: y}
	return nil
}

// AddNodeInfo adds info for a node
func (g *DJGraph) AddNodeInfo(node string, info string) error {
	if !g.Nodes[node] {
		return fmt.Errorf("node must exist in the graph")
	}
	g.SwitchInfo[node] = info
	return nil
}

// AddNodeID adds ID for a node
func (g *DJGraph) AddNodeID(node string, id int) error {
	if !g.Nodes[node] {
		return fmt.Errorf("node must exist in the graph")
	}
	g.IDs[node] = id
	return nil
}

// GetNodeID retrieves node ID
func (g *DJGraph) GetNodeID(node string) (int, error) {
	if !g.Nodes[node] {
		return 0, fmt.Errorf("node must exist in the graph")
	}
	return g.IDs[node], nil
}

// GetNodeInfo retrieves node info
func (g *DJGraph) GetNodeInfo(node string) (string, error) {
	if !g.Nodes[node] {
		return "", fmt.Errorf("node must exist in the graph")
	}
	return g.SwitchInfo[node], nil
}

// GetNodeCoords retrieves node coordinates
func (g *DJGraph) GetNodeCoords(node string) (int, int, error) {
	if !g.Nodes[node] {
		return 0, 0, fmt.Errorf("node must exist in the graph")
	}
	coords := g.NodeCoords[node]
	return coords.X, coords.Y, nil
}

// OptimizeCoords shifts all coordinates to be non-negative
func (g *DJGraph) OptimizeCoords() {
	if len(g.NodeCoords) == 0 {
		return
	}

	minX, minY := 0, 0
	first := true

	for _, coords := range g.NodeCoords {
		if first {
			minX, minY = coords.X, coords.Y
			first = false
		} else {
			if coords.X < minX {
				minX = coords.X
			}
			if coords.Y < minY {
				minY = coords.Y
			}
		}
	}

	shiftX, shiftY := 0, 0
	if minX < 0 {
		shiftX = -minX
	}
	if minY < 0 {
		shiftY = -minY
	}

	for node, coords := range g.NodeCoords {
		g.NodeCoords[node] = Coordinate{
			X: coords.X + shiftX,
			Y: coords.Y + shiftY,
		}
	}
}

// AddEdge adds an edge with optional label
func (g *DJGraph) AddEdge(source, target, label string) (bool, error) {
	if !g.Nodes[source] || !g.Nodes[target] {
		return false, fmt.Errorf("both nodes must exist in the graph")
	}

	// Check if edge already exists - if so, don't add duplicate
	if g.Edges[source] != nil && g.Edges[source][target] != "" {
		return false, nil // Edge already exists, skip
	}
	if g.Edges[target] != nil && g.Edges[target][source] != "" {
		return false, nil // Reverse edge exists, skip
	}

	// Add new edge
	if g.Edges[source] == nil {
		g.Edges[source] = make(map[string]string)
	}
	g.Edges[source][target] = label
	return true, nil
}

// FillTargetPort names the target's port on the edge source -> target: a
// label "<source side>|" whose target side is empty gets port there
// ("Eth1/0/28 1G|" becomes "Eth1/0/28 1G|TGE1/0/50"). A known port is
// never overwritten, and a label without the "|" of a link label is left
// alone. It reports whether the label changed.
func (g *DJGraph) FillTargetPort(source, target, port string) bool {
	label := g.Edges[source][target]
	near, far, isLink := strings.Cut(label, "|")
	if label == "" || !isLink || strings.TrimSpace(far) != "" || strings.TrimSpace(port) == "" {
		return false
	}
	g.Edges[source][target] = near + "|" + port
	return true
}

// GetEdge checks if there is a connection between two nodes
func (g *DJGraph) GetEdge(a, b string) bool {
	return (g.Edges[a] != nil && g.Edges[a][b] != "") ||
		(g.Edges[b] != nil && g.Edges[b][a] != "")
}

// GetEdgeLabel returns the label of the edge
func (g *DJGraph) GetEdgeLabel(a, b string) string {
	if g.Edges[a] != nil && g.Edges[a][b] != "" {
		return g.Edges[a][b]
	} else if g.Edges[b] != nil && g.Edges[b][a] != "" {
		return g.Edges[b][a]
	}
	return ""
}

// ExportDataJSON exports graph data in custom JSON format
func (g *DJGraph) ExportDataJSON() map[string]interface{} {
	nodes := []map[string]interface{}{}
	for node := range g.Nodes {
		nodes = append(nodes, map[string]interface{}{
			"id":         node,
			"labels":     []string{"Node"},
			"properties": map[string]string{"nodeId": node},
		})
	}

	edges := []map[string]interface{}{}
	edgeID := 1
	for source, targets := range g.Edges {
		for target, label := range targets {
			parts := strings.Split(label, ",")
			displayLabel := label

			if len(parts) > 1 {
				if strings.Contains(parts[0], source) {
					displayLabel = strings.TrimSpace(parts[1]) + " " + strings.TrimSpace(parts[0])
				} else {
					displayLabel = strings.TrimSpace(parts[0]) + " " + strings.TrimSpace(parts[1])
				}
			}

			edges = append(edges, map[string]interface{}{
				"id":        fmt.Sprintf("%d", edgeID),
				"type":      displayLabel,
				"startNode": source,
				"endNode":   target,
				"properties": map[string]string{
					"label": displayLabel,
				},
			})
			edgeID++
		}
	}

	return map[string]interface{}{
		"results": []map[string]interface{}{
			{
				"columns": []string{"user", "entity"},
				"data": []map[string]interface{}{
					{
						"graph": map[string]interface{}{
							"nodes":         nodes,
							"relationships": edges,
						},
					},
				},
			},
		},
		"errors": []interface{}{},
	}
}

// GraphNode represents a node in D3.js format
type GraphNode struct {
	ID          string   `json:"id"`
	Label       string   `json:"label"`                // Display label (usually SysName or IP)
	Group       string   `json:"group"`
	IP          string   `json:"ip,omitempty"`          // Metadata
	SysName     string   `json:"sysName,omitempty"`     // Metadata
	Hostname    string   `json:"hostname,omitempty"`    // DNS reverse lookup result
	Description string   `json:"description,omitempty"` // Metadata
	NodeType    string   `json:"type,omitempty"`        // Device type (switch, router, server, etc)
	Anomalies   []string `json:"anomalies,omitempty"`   // E.2: anomaly types for glow effect
	Unreachable bool     `json:"unreachable"` // Phase 8: device is down
	LastSeen    string   `json:"lastSeen,omitempty"`    // Phase 8: last successful poll time
	// Managed is the device a controller manages under this MAC (a UniFi
	// access point with its clients); only graphHandler sets it
	Managed *ManagedView `json:"managed,omitempty"`
	// Client is what a controller tells of the node as the client of a
	// device it manages (a Wi-Fi client's SSID, signal, ...); only
	// graphHandler sets it
	Client *ClientView `json:"client,omitempty"`
	// WLAN is what the scanner tells of a gateway's Wi-Fi clients
	// (addGatewayWLAN); only graphHandler sets it
	WLAN *WLANView `json:"wlan,omitempty"`
	X           float64  `json:"x,omitempty"`
	Y           float64  `json:"y,omitempty"`
}

// GraphLink represents a link in D3.js format
type GraphLink struct {
	Source      string `json:"source"`
	Target      string `json:"target"`
	Label       string `json:"label,omitempty"`
	SourceLabel string `json:"sourceLabel,omitempty"`
	TargetLabel string `json:"targetLabel,omitempty"`
	// Kind is "wlan" for the link of a Wi-Fi client (module_inventory.go):
	// the canvas leaves its label at the access point out, where the
	// labels of many clients meet
	Kind string `json:"kind,omitempty"`
	TrafficUp   uint64 `json:"trafficUp,omitempty"`   // Upload speed in bps
	TrafficDown uint64 `json:"trafficDown,omitempty"` // Download speed in bps
	Unreachable bool   `json:"unreachable"` // Phase 8: link endpoint is down
}

// GraphData contains nodes and links for D3.js
type GraphData struct {
	Nodes       []GraphNode `json:"nodes"`
	Links       []GraphLink `json:"links"`
	HealthScore float64     `json:"health_score"` // always included (omitempty removed)
	TotalMACs   int         `json:"total_macs"`   // always included
	// Core is the analyzer's core node (topologyCore), the root of the UI's
	// Tree tab. Only graphHandler sets it, and only when there is a core.
	Core string `json:"core,omitempty"`
}

// GetGraphData returns graph data formatted for D3.js
func (g *DJGraph) GetGraphData() GraphData {
	nodes := []GraphNode{}
	for node := range g.Nodes {
		// Calculate Label and SysName
		label := node
		info, _ := g.GetNodeInfo(node)

		// Extract hostname from info lines
		var hostname string
		if info != "" {
			infoLines := strings.Split(info, "\n")
			for _, line := range infoLines {
				if strings.HasPrefix(line, "[DNS]") {
					hostname = strings.TrimPrefix(line, "[DNS] ")
				}
			}
		}

		// Build label based on info content
		if info != "" {
			// For endpoints, info is just "[ENDPOINT]" or "[WiFi]" etc.
			if strings.HasPrefix(info, "[ENDPOINT]") || strings.HasPrefix(info, "[LLDP-EP]") || strings.HasPrefix(info, "[HUB]") || strings.HasPrefix(info, "[VM]") || strings.HasPrefix(info, "[WiFi]") {
				// Prioritize hostname in label if available
				if hostname != "" {
					label = fmt.Sprintf("%s\n%s", hostname, node)
				} else {
					label = fmt.Sprintf("%s\n%s", info, node)
				}
			} else {
				// For switches/routers — prioritize hostname over SysName
				if hostname != "" {
					label = fmt.Sprintf("%s\n%s", hostname, node)
				} else {
					label = fmt.Sprintf("%s\n%s", info, node)
				}
			}
		}

		// Determine group based on device info (or node ID itself)
		group := g.determineDeviceGroup(node, info)

		graphNode := GraphNode{
			ID:       node,
			Label:    label,
			Group:    group,
			NodeType: group,
			SysName:  info,
			Hostname: hostname,
		}

		// Phase 8: Check if node is unreachable
		if status, ok := g.NodeStatus[node]; ok && status == "unreachable" {
			graphNode.Unreachable = true
		}

		// Set IP address if node ID looks like an IP address
		if net.ParseIP(node) != nil {
			graphNode.IP = node
		}

		// Add coordinates if available
		if coord, ok := g.NodeCoords[node]; ok {
			graphNode.X = float64(coord.X)
			graphNode.Y = float64(coord.Y)
		}

		nodes = append(nodes, graphNode)
	}

	links := []GraphLink{}

	// normalizePortLabel normalizes port name prefix while keeping speed/VLAN/traffic suffixes
	normalizePortLabel := func(label string) string {
		fields := strings.Fields(label)
		if len(fields) == 0 {
			return label
		}
		// Normalize first field (port name) and keep rest as-is
		fields[0] = normalizePortName(fields[0])
		return strings.Join(fields, " ")
	}

	for source, targets := range g.Edges {
		for target, label := range targets {
			link := GraphLink{
				Source: source,
				Target: target,
				Label:  label,
			}

			// Phase 8: Mark link as unreachable if either endpoint is down
			srcStatus, _ := g.NodeStatus[source]
			tgtStatus, _ := g.NodeStatus[target]
			if srcStatus == "unreachable" || tgtStatus == "unreachable" {
				link.Unreachable = true
			}

			// Parse dual label format "SrcPort|DstPort"
			if strings.Contains(label, "|") {
				parts := strings.SplitN(label, "|", 2)
				if len(parts) == 2 {
					link.SourceLabel = normalizePortLabel(strings.TrimSpace(parts[0]))
					link.TargetLabel = normalizePortLabel(strings.TrimSpace(parts[1]))
				}
			} else if label != "" && label != "vNIC" {
				// Single label (e.g. hypervisor port "ge1/0/22") — show on source side
				link.SourceLabel = normalizePortLabel(label)
			}

			links = append(links, link)
		}
	}

	// Nodes by id and links by source and target, so /api/graph, the reports
	// and the captures do not depend on map order (Q16)
	slices.SortFunc(nodes, func(a, b GraphNode) int { return strings.Compare(a.ID, b.ID) })
	slices.SortFunc(links, func(a, b GraphLink) int {
		return cmp.Or(strings.Compare(a.Source, b.Source), strings.Compare(a.Target, b.Target))
	})

	return GraphData{
		Nodes: nodes,
		Links: links,
	}
}

// determineDeviceGroup categorizes devices based on their info
func (g *DJGraph) determineDeviceGroup(node, info string) string {
	// A configured gateway's router node is a router: its label is a
	// sysName and IPs ("debian216\n172.20.1.254", "FortiGate-600F\n...").
	if g.graphRouters[node] {
		return "router"
	}
	if g.graphManaged[node] {
		return "access_point"
	}

	// A polled device is grouped by its own name only (server, router or
	// switch), even when its label is empty.
	if g.graphSwitches[node] {
		return graphNameGroup(node, info, true)
	}

	// An HTTP-confirmed ESXi host is a hypervisor whatever tag its label
	// has ([ENDPOINT], [LLDP-EP], [WiFi], [BMC]); a switch never is.
	if graphIsConfirmedESXi(node) && !graphIsSwitchNode(g, node) {
		return "hypervisor"
	}

	// Check for Wi-Fi random MAC endpoints
	if strings.Contains(info, "[WiFi]") {
		return "wifi_random"
	}

	// Check for Endpoints — use OUI vendor categorization
	if strings.Contains(info, "[LLDP-EP]") || strings.Contains(info, "[ENDPOINT]") {
		// Try to extract MAC from node ID for vendor lookup
		if len(node) >= 8 && (strings.Contains(node, ":") || strings.Contains(node, "-")) {
			vendor := lookupVendor(node)
			if vendor != "Unknown" {
				category := categorizeVendor(vendor)
				if category != "endpoint" && category != "network" {
					return category
				}
			}
		}
		return "endpoint"
	}

	// Check for Virtual Hub (unmanaged switch)
	if strings.Contains(info, "[HUB]") || strings.HasPrefix(node, "hub-") {
		return "hub"
	}

	// Check for BMC/IPMI management interface (iDRAC, iLO, XCC, CIMC, iRMC)
	if strings.Contains(info, "[BMC]") || strings.HasPrefix(node, "bmc-") {
		return "bmc"
	}

	// Check for Hypervisor (VMware ESXi, Hyper-V, QEMU, Xen, VirtualBox)
	if strings.Contains(info, "[HYPERVISOR]") || strings.HasPrefix(node, "hyp-") {
		return "hypervisor"
	}

	// Check for VM Server
	if strings.Contains(info, "[VM]") || strings.HasPrefix(node, "vm-") {
		return "vm"
	}

	return graphNameGroup(node, info, false)
}

// graphNameGroup is the group of an untagged node from its name and label:
// server, switch or router, else switch when it has a label or is a polled
// device, else unknown.
func graphNameGroup(node, info string, polled bool) string {
	infoLower := strings.ToLower(info)
	nodeLower := strings.ToLower(node)

	// Check for server indicators
	if strings.Contains(infoLower, "linux") || strings.Contains(infoLower, "windows") || strings.Contains(infoLower, "server") ||
		strings.Contains(nodeLower, "linux") || strings.Contains(nodeLower, "windows") || strings.Contains(nodeLower, "server") {
		return "server"
	}

	// Check for switch indicators
	if strings.Contains(infoLower, "hpe") ||
		strings.Contains(infoLower, "snr") ||
		strings.Contains(infoLower, "switch") ||
		strings.Contains(infoLower, "cisco") ||
		strings.Contains(nodeLower, "switch") {
		return "switch"
	}

	// Check for router indicators
	if strings.Contains(infoLower, "router") ||
		strings.Contains(nodeLower, "router") {
		return "router"
	}

	// Default to "switch" for any discovered device with info
	if info != "" || polled {
		return "switch"
	}

	// Default to unknown
	return "unknown"
}

// GenerateZabbixTemplate generates template list based on device info
func (g *DJGraph) GenerateZabbixTemplate(node string) []map[string]string {
	templates := []map[string]string{
		{"name": "Network Generic Device by SNMP"},
	}

	// SNR devices by their sysName/sysDescr (polled sysName, LLDP), never by
	// the vendor text in the label
	if !g.Nodes[node] {
		return templates
	}

	if strings.Contains(g.graphSysText[node], "SNR") {
		templates = []map[string]string{
			{"name": "Template SNR Broadcast-Multicast-Unicast"},
			{"name": "Template SNR CPU Usage"},
			{"name": "Template SNR Error and Discared Packets"},
			{"name": "Template SNR Interfaces Statistic"},
			{"name": "Template SNR Memory Information"},
			{"name": "Template SNR POE Power"},
		}
	}

	return templates
}

// ExportHostsToZabbix exports hosts to Zabbix JSON format: one SNMP host per
// polled device (reportZabbixHosts)
func (g *DJGraph) ExportHostsToZabbix(filePath string) error {
	hosts := []map[string]interface{}{}

	for _, zh := range reportZabbixHosts(g) {
		templates := g.GenerateZabbixTemplate(zh.node)

		host := map[string]interface{}{
			"host":      zh.ip,
			"name":      zh.name,
			"templates": templates,
			"groups": []map[string]string{
				{"name": "Templates/Network devices"},
			},
			"interfaces": []map[string]interface{}{
				{
					"type": "SNMP",
					"ip":   zh.ip,
					"port": "161",
					"details": map[string]string{
						"community": "{$SNMP_COMMUNITY}",
					},
					"interface_ref": "if1",
				},
			},
			"inventory_mode": "DISABLED",
		}
		hosts = append(hosts, host)
	}

	zabbixExport := map[string]interface{}{
		"zabbix_export": map[string]interface{}{
			"version": "6.0",
			"date":    time.Now().UTC().Format("2006-01-02T15:04:05Z"),
			"groups": []map[string]string{
				{
					"uuid": "36bff6c29af64692839d077febfc7078",
					"name": "Templates/Network devices",
				},
			},
			"hosts": hosts,
		},
	}

	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(zabbixExport)
}

// reportZabbixHost is one Zabbix host: a polled device, the graph node it
// is drawn as ("" when the graph has none) and its management IP.
type reportZabbixHost struct {
	node, ip, name string
}

// reportZabbixHosts lists the polled devices (collectedData) in IP order.
// Only they answer SNMP; endpoints and hub-/hyp- nodes are not Zabbix hosts.
// The IP is also the technical host name: it is unique, while node ids are
// mostly MACs, which Zabbix rejects. The visible name adds the sysName.
func reportZabbixHosts(g *DJGraph) []reportZabbixHost {
	collectedDataMutex.RLock()
	defer collectedDataMutex.RUnlock()
	var hosts []reportZabbixHost
	for _, ip := range sortedDeviceIPs(collectedData) {
		d := collectedData[ip]
		name := d.IP
		if d.SysName != "" {
			name = fmt.Sprintf("%s (%s)", d.SysName, d.IP)
		}
		hosts = append(hosts, reportZabbixHost{node: reportDeviceNode(g, d), ip: d.IP, name: name})
	}
	return hosts
}

// ExportToMap exports to Zabbix map format: one element per host of
// ExportHostsToZabbix
func (g *DJGraph) ExportToMap(filePath string) error {
	elements := []map[string]interface{}{}
	id := 0

	for _, zh := range reportZabbixHosts(g) {
		id++

		x, y, _ := g.GetNodeCoords(zh.node)

		element := map[string]interface{}{
			"elementtype":      "0",
			"elements":         []map[string]string{{"host": zh.ip}},
			"label":            "{HOST.IP}",
			"label_location":   "-1",
			"x":                fmt.Sprintf("%d", x),
			"y":                fmt.Sprintf("%d", y),
			"elementsubtype":   "0",
			"areatype":         "0",
			"width":            "200",
			"height":           "200",
			"viewtype":         "0",
			"use_iconmap":      "0",
			"selementid":       fmt.Sprintf("%d", id),
			"icon_off":         map[string]string{"name": "Server_(96)"},
			"icon_on":          []interface{}{},
			"icon_disabled":    []interface{}{},
			"icon_maintenance": []interface{}{},
			"urls":             []interface{}{},
			"evaltype":         "0",
		}
		elements = append(elements, element)
	}

	zabbixExport := map[string]interface{}{
		"zabbix_export": map[string]interface{}{
			"version": "6.0",
			"date":    "2024-06-22T04:35:33Z",
			"images": []map[string]interface{}{
				{
					"name":         "Server_(96)",
					"imagetype":    "1",
					"encodedImage": "iVBORw0KGgoAAAANSUhEUgAAAEgAAABgCAYAAAC+EjQcAAAABHNCSVQICAgIfAhkiAAAAAlwSFlzAAAKYQAACmEB/MxKJQAAABl0RVh0U29mdHdhcmUAd3d3Lmlua3NjYXBlLm9yZ5vuPBoAABnHSURBVHjazV1bbxzZda7Tt7nyKpISJVGXlda7tiwFXtlGHAeIk3Xit8AOAgdB/JKn/ILkPziP/gN5SGwgCwRBHAQIEthGjBi+ZePY3vWud7UriqJI8T7kkHPvPqmvzjndPcMRL7KWnJFaPdM9lz7VVV/VV1XnSGmt6TSPr371q9FGt1L2eknFp17ZI6+ceLpaKgSTXhBOeZ7PG02Q9qq+p4vK96PAV5FSXuQpP/R8ihR55rXnRb5HEck5fo/nhXt7uzOPllbaKvC/Hfr66//57TeW6Bwf6jgB/cnX/upvpyfGv6QU8SB4IL4XBL4f+gEP3AujIFQF3w8in0fq+z75LAF+g+xJ8V/+oPwQ75V5Ins5Ln+zPQ4tLa/Qd//rR6R1QqVScT0Ko595offNC8X4W2+88UZ81gIKjntD6HsXFq7O33MDkKGo/kGR3aeDZZnHiRlLrxdTHCeUxF3qJpp0HFM3Nsd63R5NTU3Q9OSEfA63Su6XMvt2pzMXx/GXwjh4fSsO//oP//jP/zsKva//2z9989HICAhXrXlg7qK3trdpfX2bYupR3Et4wJothCjB4PmuJ/yRbrtDXR48mwwLKqFCGIoAcY7fSh0+12l3KQgD+vgrt2hqYpx/hr9Hq0y1yQqc5LsDNse7vV5yl7T60y99+S9+xvtvTRQ6//BRa9WxAkrkrmqyN5aazTZt12piTp6nxJwKYSEzLTY1CBKv/VDx64DCgDfeKz7HI5W9L88D6sU9SrQWrdNyExL5Hd0nKtZkFnK1EvL7k9lut/tHXuC/Xu8W/ub3v/KXn//eP/9d7fw0CEKSAbCQWA1uXl+gP/i9z8lzT5mhwIyctsmXBr5gDQSLt8h5J2FtzvMA2exi+uCDR6yhiXyfsjfjEFDiDJus5xdhuzQ+VoWZ+61W+3LrYL94viZGxsS0xRb5B4PhgcCsYsGULr8HY2ATgwbweeyBMzgeJz17TsseUoIgYH7NVovCKDR64gBIWTAXkDeHwkKBBd0T4XZ5P1apUKvdHgEMYiOD2rvb/3Bxmb73/R+ZwWq+q/ynUIjknZ71WG3GoB5/JmAzShijcN4ToWnZYzwDsJjNKy+/RGOsEZSamLb4k5kXHp1Ol8aqFRES4xH1oFEAv4/44R2vPcbEoEXYm7tsBuFpLz+GFFrx15PRetbL5QerrMdSqXZoEXaS7gcNDI9SsSDnYK4QEMzy8HvP1cQyL5PGNiwfj8E6FC/FgMygjYsPQj/FGoizGLEGIS7ih+8rMT2YZpiFCYFCYHgOYfL14D2y50cMLeHnDZiRi3ZzUfJH7jnUi/yNFylMaCZiHBZgzPgSw01/VGZ0ZgL6DYWpjsmOnsuF/j9FJM8ySeQDFgAAAABJRU5ErkJggg==",
				},
			},
			"maps": []map[string]interface{}{
				{
					"name":                   "LAN",
					"width":                  "1024",
					"height":                 "768",
					"label_type":             "0",
					"label_location":         "0",
					"highlight":              "0",
					"expandproblem":          "1",
					"markelements":           "0",
					"show_unack":             "0",
					"severity_min":           "0",
					"show_suppressed":        "0",
					"grid_size":              "50",
					"grid_show":              "1",
					"grid_align":             "1",
					"label_format":           "1",
					"label_type_host":        "1",
					"label_type_hostgroup":   "2",
					"label_type_trigger":     "3",
					"label_type_map":         "2",
					"label_type_image":       "2",
					"label_string_host":      "",
					"label_string_hostgroup": "",
					"label_string_trigger":   "",
					"label_string_map":       "",
					"label_string_image":     "",
					"expand_macros":          "0",
					"background":             []interface{}{},
					"iconmap":                []interface{}{},
					"urls":                   []interface{}{},
					"selements":              elements,
					"shapes":                 []interface{}{},
					"lines":                  []interface{}{},
					"links":                  []interface{}{},
				},
			},
		},
	}

	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(zabbixExport)
}

// CalculateDepths calculates hop count from a root node (BFS). A link is
// followed both ways: an edge's direction only says which switch reported
// it, so following outgoing edges alone missed every node reached through a
// link its far side reported (the analyzer's path check does the same, F19).
func (g *DJGraph) CalculateDepths(rootID string) map[string]int {
	depths := make(map[string]int)
	if !g.Nodes[rootID] {
		return depths
	}

	neighbors := make(map[string][]string)
	for src, targets := range g.Edges {
		for tgt := range targets {
			neighbors[src] = append(neighbors[src], tgt)
			neighbors[tgt] = append(neighbors[tgt], src)
		}
	}

	queue := []string{rootID}
	depths[rootID] = 0
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, next := range neighbors[current] {
			if _, seen := depths[next]; !seen && g.Nodes[next] {
				depths[next] = depths[current] + 1
				queue = append(queue, next)
			}
		}
	}

	return depths
}

// GetLongPaths returns nodes that are further than threshold hops from root
func (g *DJGraph) GetLongPaths(rootID string, threshold int) []string {
	depths := g.CalculateDepths(rootID)
	var longPaths []string

	for node, depth := range depths {
		if depth > threshold {
			longPaths = append(longPaths, node)
		}
	}
	return longPaths
}
