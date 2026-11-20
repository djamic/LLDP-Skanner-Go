package main

import (
	"fmt"
	"slices"
)

// groupDef is one device group, a node's Group: how the graph, the filter
// bar, the info panel, the Tree tab, the history page and the reports name,
// colour, size and order it.
//
// deviceGroups is the one list of them. The reports read it here; the web UI
// (static/app.js, static/tree.js, static/index.html, static/history.html)
// carries generated copies of its tables between "BEGIN groups.go" and
// "END groups.go" lines, which TestGroupTables checks and, with -update,
// rewrites. A new group is a row here, an SVG symbol topo-icon-<key> in
// app.js, and `go test -run TestGroupTables -update`.
type groupDef struct {
	Key   string // the node's Group
	Name  string // the type name after Emoji ("🔗 Mini hub")
	Emoji string // the info panel's, the Tree tab's and the type name's icon
	Color string // fill in the graph, the filter bar and the reports

	CanvasColor string // the graph's fill when brighter on its dark canvas; "" = Color
	IconSize    int    // the graph icon's size; 0 = 36
	TreeRank    int    // Tree tab child order: 0 before 1 before 2

	Filter      string // the filter bar's label
	FilterTitle string // the filter bar's tooltip
	FilterOff   bool   // the filter checkbox is unchecked on load

	LongName    string // the report legend's and the export popup's name; "" = Name
	ExportEmoji string // the export popup's icon; "" = Emoji
	ExportOn    bool   // checked in the export popup
	Via         string // the history page's "behind a hub"; "" = the key

	Stroke    string // the report diagrams' stroke; "" = not in the reports
	Dot       string // the report legend's colour emoji
	Section   string // the report's table title, numbered 4.<SectionNo>
	SectionNo int
	Shape     string // the Mermaid node shape: "circle", "hexagon", "flag" or "" (a box)
}

// deviceGroups in the filter bar's order (and the export popup's).
var deviceGroups = []groupDef{
	{Key: "switch", Name: "Switch", Emoji: "🔀", Color: "#4A90E2", IconSize: 44, TreeRank: 0,
		Filter: "Switch", ExportOn: true,
		Stroke: "#2A6FC2", Dot: "🔵"},
	// An LLDP neighbor that is a bridge or router by its LLDP capabilities
	// and is not polled (classifyNode, ClassifySettings.LLDPCaps): no ports,
	// no port history, not one of the report's switches
	{Key: "lldp_switch", Name: "Unpolled switch", Emoji: "🔀", Color: "#64B5F6", IconSize: 40, TreeRank: 1,
		Filter: "Unpolled", FilterTitle: "Unpolled switch: an LLDP neighbor that is a bridge or router by its LLDP capabilities, never polled (no IP to poll, or no answer)",
		Stroke: "#1E88E5", Dot: "🔹", Section: "Poll qilinmagan switch'lar (LLDP)", SectionNo: 16},
	{Key: "router", Name: "Router", Emoji: "🌐", Color: "#E24A4A", IconSize: 44, TreeRank: 0,
		Filter: "Router",
		Stroke: "#C23030", Dot: "🔴", Section: "Routerlar", SectionNo: 11, Shape: "hexagon"},
	{Key: "hub", Name: "Hub", Emoji: "🔌", Color: "#FF9800", IconSize: 40, TreeRank: 1,
		Filter:   "Hub",
		LongName: "Hub (Shadow IT)", ExportEmoji: "⚠️", ExportOn: true, Via: "a hub",
		Stroke: "#E68A00", Dot: "🟠", Section: "Hub / Unmanaged switch", SectionNo: 5, Shape: "circle"},
	// A trunk or big port no polled switch is behind (fdbPorts): no Shadow IT
	{Key: "minihub", Name: "Mini hub", Emoji: "🔗", Color: "#FFC107", IconSize: 40, TreeRank: 1,
		Filter: "MiniHub", FilterTitle: "Mini hub: the devices behind a trunk or big port no polled switch is behind (no Shadow IT)",
		Stroke: "#FFA000", Dot: "🟡", Section: "Mini hub (trunk yoki ko'p MAC'li port)", SectionNo: 15, Shape: "circle"},
	// Access points behind an unmanaged (PoE) switch, seen by LLDP
	// (lldpPortPlans): no Shadow IT unless Settings make it one
	{Key: "ap_hub", Name: "AP hub", Emoji: "📡", Color: "#4DB6AC", IconSize: 40, TreeRank: 1,
		Filter: "AP hub", FilterTitle: "AP hub: access points behind an unmanaged (PoE) switch that LLDP shows (no Shadow IT unless Settings say so)",
		Via:    "an AP hub",
		Stroke: "#00897B", Dot: "🟩", Section: "AP hub (boshqarilmaydigan switch ortidagi AP'lar)", SectionNo: 17, Shape: "circle"},
	{Key: "endpoint", Name: "Endpoint", Emoji: "💻", Color: "#8BC34A", TreeRank: 2,
		Filter: "Endpoint",
		Stroke: "#6B9F30", Dot: "🟢", Section: "Endpoint qurilmalar", SectionNo: 2},
	// Not hub orange: the legend's and the reports' colour
	{Key: "access_point", Name: "Wi-Fi AP", Emoji: "📡", Color: "#00BCD4", IconSize: 40, TreeRank: 2,
		Filter: "Wi-Fi AP", Via: "an access point",
		Stroke: "#0097A7", Dot: "🔷", Section: "Wi-Fi nuqtalari (Access Point)", SectionNo: 13, Shape: "flag"},
	{Key: "vm", Name: "VM", Emoji: "🖥️", Color: "#9C27B0", TreeRank: 2,
		Filter: "VM",
		Stroke: "#7B1FA2", Dot: "🟣", Section: "Virtual mashinalar", SectionNo: 4},
	{Key: "hypervisor", Name: "Hypervisor", Emoji: "🏗️", Color: "#26C6DA", IconSize: 44, TreeRank: 1,
		Filter:      "Hyp",
		ExportEmoji: "☁️", Via: "a hypervisor",
		Stroke: "#0097A7", Dot: "💠", Section: "Hypervisor serverlar", SectionNo: 3},
	// Server management (iDRAC, iLO, XCC, CIMC, iRMC)
	{Key: "bmc", Name: "BMC", Emoji: "🔧", Color: "#FF6F00", TreeRank: 2,
		Filter:   "BMC",
		LongName: "BMC/iLO",
		Stroke:   "#E65100", Dot: "🟧", Section: "BMC/iLO", SectionNo: 9},
	{Key: "camera", Name: "Camera", Emoji: "📹", Color: "#E91E63", TreeRank: 2,
		Filter:      "Cam",
		ExportEmoji: "📷",
		Stroke:      "#C2185B", Dot: "🩷", Section: "Kameralar", SectionNo: 7},
	// An IP phone: the voip engine's, a dedicated VoIP vendor's OUI, a PBX's
	{Key: "phone", Name: "Phone", Emoji: "📞", Color: "#3F51B5", CanvasColor: "#5C6BC0", TreeRank: 2,
		Filter: "Phone", FilterTitle: "Phone: an IP phone (VoIP)",
		Stroke: "#303F9F", Dot: "🔵", Section: "Telefonlar (VoIP)", SectionNo: 6},
	// A smartphone or tablet by its maker's OUI (OUI category "mobile",
	// ClassifySettings.MobileGroup; off, they are phones)
	{Key: "mobile", Name: "Mobile", Emoji: "📱", Color: "#9575CD", TreeRank: 2,
		Filter: "Mobile", FilterTitle: "Mobile: a smartphone or tablet by its maker's OUI (Apple, Samsung, Xiaomi, OPPO, vivo, ...), not an IP phone",
		Stroke: "#5E35B1", Dot: "🟪", Section: "Smartfon va planshetlar", SectionNo: 18},
	{Key: "iot", Name: "IoT", Emoji: "🔌", Color: "#607D8B", TreeRank: 2,
		Filter:      "IoT",
		ExportEmoji: "🌡️",
		Stroke:      "#455A64", Dot: "⬜", Section: "IoT qurilmalar", SectionNo: 8},
	{Key: "wifi_random", Name: "Random MAC", Emoji: "🎲", Color: "#00BCD4", TreeRank: 2,
		Filter: "Rnd",
		Stroke: "#0097A7", Dot: "🔷", Section: "Wi-Fi / Random MAC", SectionNo: 12, Shape: "flag"},
	// A WLAN client of a UniFi access point, or in a gateway's ARP table
	// (module_inventory.go): set at /api/graph time, never in the reports
	{Key: "wifi_client", Name: "WLAN client", Emoji: "📶", Color: "#80DEEA", TreeRank: 2,
		Filter: "WLAN", FilterOff: true},
	{Key: "printer", Name: "Printer", Emoji: "🖨️", Color: "#795548", CanvasColor: "#A1887F", TreeRank: 2,
		Filter: "Printer",
		Stroke: "#5D4037", Dot: "🟤", Section: "Printerlar", SectionNo: 14},
	{Key: "server", Name: "Server", Emoji: "🖲️", Color: "#FF5722", IconSize: 44, TreeRank: 2,
		Filter: "Server",
		Stroke: "#E64A19", Dot: "🔶", Section: "Serverlar", SectionNo: 10},
	{Key: "unknown", Name: "Unknown", Emoji: "❓", Color: "#9E9E9E", TreeRank: 2,
		Filter: "Unknown",
		Stroke: "#757575", Dot: "⚪"},
}

// longName is the group's name in the report legend and the export popup.
func (d groupDef) longName() string {
	if d.LongName != "" {
		return d.LongName
	}
	return d.Name
}

// reportGroupColors are the fill and stroke colours of each group in the
// report's Mermaid diagrams, the UI's colours; the DOCX converter
// (instrumens/md2docx_gost_linux.py group_label_map) names each fill colour
// in its legend.
var reportGroupColors = func() map[string][2]string {
	colors := make(map[string][2]string)
	for _, d := range deviceGroups {
		if d.Stroke != "" {
			colors[d.Key] = [2]string{d.Color, d.Stroke}
		}
	}
	return colors
}()

// reportGroupShapes are the Mermaid shapes of the groups not drawn as a box.
var reportGroupShapes = func() map[string]string {
	shapes := make(map[string]string)
	for _, d := range deviceGroups {
		if d.Shape != "" {
			shapes[d.Key] = d.Shape
		}
	}
	return shapes
}()

// reportGroupDef is a report section: a group and its numbered title.
type reportGroupDef struct {
	key   string
	title string
}

// reportGroupSections are the report's per-group tables, by section number.
func reportGroupSections() []reportGroupDef {
	var groups []groupDef
	for _, d := range deviceGroups {
		if d.Section != "" {
			groups = append(groups, d)
		}
	}
	slices.SortFunc(groups, func(a, b groupDef) int { return a.SectionNo - b.SectionNo })
	sections := make([]reportGroupDef, len(groups))
	for i, d := range groups {
		sections[i] = reportGroupDef{d.Key, fmt.Sprintf("4.%d %s", d.SectionNo, d.Section)}
	}
	return sections
}
