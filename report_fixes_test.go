package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"unicode/utf8"
)

// Tests for the report and export fixes (F71-F76, Q16). Except for
// TestReportAuditDeterministic they use hand-made devices or graphs, not
// the fixture.

// reportSetDevices replaces collectedData with the given devices.
func reportSetDevices(devices ...*DeviceData) {
	collectedDataMutex.Lock()
	collectedData = make(map[string]*DeviceData, len(devices))
	for _, d := range devices {
		collectedData[d.IP] = d
	}
	collectedDataMutex.Unlock()
}

// reportBuildGraph builds the graph from collectedData like rebuildGraph.
func reportBuildGraph() *DJGraph {
	return buildGraphFromSnapshot(snapshotCollectedData())
}

// reportMDSection returns the part of md from the first line starting with
// start up to the next line starting with one of the ends (or the end).
func reportMDSection(md, start string, ends ...string) string {
	i := strings.Index(md, "\n"+start)
	if i < 0 {
		return ""
	}
	rest := md[i+1:]
	cut := len(rest)
	for _, end := range ends {
		if j := strings.Index(rest[1:], "\n"+end); j >= 0 && j+2 < cut {
			cut = j + 2
		}
	}
	return rest[:cut]
}

var reportHTMLDeviceRow = regexp.MustCompile(`<tr><td>([0-9.]+)</td><td>[^<]*</td><td>([^<]*)</td>`)

// TestReportDeviceVendorConsistent (F71): every report and export shows the
// same vendor for a device, and so do the snapshot hosts (H11). The OUI vendor comes first; without one the
// sysName keywords decide; unknown is "" in the device rows and the
// "Unknown" bucket in vendor_stats.json.
func TestReportDeviceVendorConsistent(t *testing.T) {
	resetState(t)
	devices := []*DeviceData{
		{IP: "10.0.71.1", SysName: "HP", ChassisID: ""},
		{IP: "10.0.71.2", SysName: "FortiGate-60F", ChassisID: ""},
		{IP: "10.0.71.3", SysName: "", ChassisID: ""},
		{IP: "10.0.71.4", SysName: "HUAWEI", ChassisID: "No Such Object available on this agent at this OID"},
		{IP: "10.0.71.5", SysName: "HUAWEI", ChassisID: "00:0c:29:71:00:05"},
		{IP: "10.0.71.6", SysName: "core-cisco", ChassisID: ""},
	}
	ouiVendor := getMACVendor("00:0c:29:71:00:05")
	if ouiVendor == "" {
		t.Fatalf("precondition: 00:0c:29 has no vendor")
	}
	want := map[string]string{
		"10.0.71.1": "HPE",
		"10.0.71.2": "Fortinet",
		"10.0.71.3": "",
		"10.0.71.4": "Huawei",
		"10.0.71.5": ouiVendor, // the OUI wins over the sysName
		"10.0.71.6": "Cisco",
	}
	reportSetDevices(devices...)
	got := map[string]map[string]string{}
	record := func(source, ip, vendor string) {
		if got[ip] == nil {
			got[ip] = map[string]string{}
		}
		got[ip][source] = vendor
	}

	// /api/report/summary
	rr := httptest.NewRecorder()
	reportSummaryHandler(rr, httptest.NewRequest(http.MethodGet, "/api/report/summary", nil))
	var summary ReportSummary
	if err := json.Unmarshal(rr.Body.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}
	for _, d := range summary.TopDevices {
		record("summary", d.IP, d.Vendor)
	}

	// /api/report/full (Word HTML)
	rr = httptest.NewRecorder()
	reportFullHandler(rr, httptest.NewRequest(http.MethodGet, "/api/report/full", nil))
	for _, m := range reportHTMLDeviceRow.FindAllStringSubmatch(rr.Body.String(), -1) {
		record("full", m[1], m[2])
	}

	// Audit Markdown, section 4.1
	for _, line := range strings.Split(generateAuditMD([]string{"switch"}), "\n") {
		if cells := strings.Split(line, " | "); len(cells) == 5 && strings.HasPrefix(cells[0], "| 10.0.71.") {
			record("audit", strings.TrimPrefix(cells[0], "| "), cells[2])
		}
	}

	// health_scores.json and vendor_stats.json
	dir := t.TempDir()
	exportsDir = dir
	ExportHealthScores(devices, nil)
	ExportVendorStats(devices)
	var health HealthScoreExport
	reportReadJSON(t, filepath.Join(dir, "health_scores.json"), &health)
	for _, d := range health.Devices {
		record("health", d.IP, d.Vendor)
	}
	var stats VendorStatsExport
	reportReadJSON(t, filepath.Join(dir, "vendor_stats.json"), &stats)

	// Snapshot hosts (InfluxDB device events, the event log), H11
	for ip, host := range CreateSnapshot(devices, nil, nil).ActiveHosts {
		record("snapshot", ip, host.Vendor)
	}
	gotBuckets := map[string]int{}
	for _, v := range stats.Vendors {
		gotBuckets[v.Vendor] = v.DeviceCount
	}

	wantBuckets := map[string]int{}
	for ip, vendor := range want {
		for _, source := range []string{"summary", "full", "audit", "health", "snapshot"} {
			if v, ok := got[ip][source]; !ok || v != vendor {
				t.Errorf("%s: %s vendor = %q (present %v), want %q", ip, source, v, ok, vendor)
			}
		}
		if vendor == "" {
			vendor = "Unknown"
		}
		wantBuckets[vendor]++
	}
	if fmt.Sprint(gotBuckets) != fmt.Sprint(wantBuckets) {
		t.Errorf("vendor_stats buckets = %v, want %v", gotBuckets, wantBuckets)
	}
	// Q16: the buckets come in vendor order
	if !slices.IsSortedFunc(stats.Vendors, func(a, b VendorStat) int { return strings.Compare(a.Vendor, b.Vendor) }) {
		t.Errorf("vendor_stats buckets are not in vendor order: %v", stats.Vendors)
	}
}

// TestReportDeviceVendorRules (F71) pins the sysName keyword fallback.
func TestReportDeviceVendorRules(t *testing.T) {
	for _, c := range []struct{ sysName, want string }{
		{"SNR-S2985G-24TC", "SNR"}, {"A_padval_SNR", "SNR"}, {"MikroTik RB4011", "MikroTik"},
		{"core-cisco", "Cisco"}, {"HPE", "HPE"}, {"HP", "HPE"}, {"hp-2920", "HPE"},
		{"UBNT-AP", "Ubiquiti"}, {"Ubiquiti EdgeSwitch", "Ubiquiti"}, {"HUAWEI", "Huawei"},
		{"FortiGate-60F", "Fortinet"}, {"fortinet-fw", "Fortinet"},
		{"SNR HP", "SNR"}, // first rule wins
		{"Huawe", ""}, {"B-318/1", ""}, {"", ""},
	} {
		if got := reportDeviceVendor(&DeviceData{SysName: c.sysName}); got != c.want {
			t.Errorf("reportDeviceVendor(sysName %q) = %q, want %q", c.sysName, got, c.want)
		}
	}
	d := &DeviceData{SysName: "HUAWEI", ChassisID: "00:0c:29:71:00:05"}
	if got, want := reportDeviceVendor(d), getMACVendor(d.ChassisID); got != want || want == "" {
		t.Errorf("reportDeviceVendor with an OUI vendor = %q, want the OUI vendor %q", got, want)
	}
}

func reportReadJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
}

// reportShadowHubs returns the hub ids GenerateShadowDiagrams drew, sorted.
func reportShadowHubs(g *DJGraph, md string) []string {
	var hubs []string
	for id := range g.Nodes {
		if strings.HasPrefix(id, "hub-") && strings.Contains(md, "  "+sanitizeMermaidID(id)+"((") {
			hubs = append(hubs, id)
		}
	}
	slices.Sort(hubs)
	return hubs
}

// TestReportShadowSectionSkipsESXiPorts (F72, Q14): section 7 lists the graph's
// hub nodes, except hubs whose port carries an HTTP-confirmed ESXi host,
// also when the host is confirmed after the graph was built and when it is
// a member beyond the fifth (the graph drew only five before F29).
func TestReportShadowSectionSkipsESXiPorts(t *testing.T) {
	resetState(t)
	var macs []MACEntry
	macs = append(macs, macEntries(3, "00:1b:21:72:03:01", "00:1b:21:72:03:02", "c4:34:6b:72:03:03")...)
	macs = append(macs, macEntries(5, "00:1b:21:72:05:01", "00:1b:21:72:05:02", "00:1b:21:72:05:03",
		"00:1b:21:72:05:04", "00:1b:21:72:05:05", "00:1b:21:72:05:06", "c4:34:6b:72:05:07")...)
	macs = append(macs, macEntries(6, "00:1b:21:72:06:01", "00:1b:21:72:06:02")...)
	sw := &DeviceData{IP: "10.0.72.2", SysName: "sw-72", ChassisID: "4c:ae:a3:72:00:02",
		Interfaces: gigabitPorts(8, nil), MACTable: macs}
	reportSetDevices(sw)
	hubP3, hubP5, hubP6 := "hub-4c:ae:a3:72:00:02-p3", "hub-4c:ae:a3:72:00:02-p5", "hub-4c:ae:a3:72:00:02-p6"

	g := reportBuildGraph()
	if got := reportShadowHubs(g, GenerateShadowDiagrams(g)); !slices.Equal(got, []string{hubP3, hubP5, hubP6}) {
		t.Fatalf("before ESXi confirmation: Shadow IT hubs = %v, want %v", got, []string{hubP3, hubP5, hubP6})
	}

	// Confirmed after the build: the graph still has the hubs.
	ConfirmedESXiMACs.Store("c4:34:6b:72:03:03", true)
	ConfirmedESXiMACs.Store("c4:34:6b:72:05:07", true)
	md := GenerateShadowDiagrams(g)
	if got := reportShadowHubs(g, md); !slices.Equal(got, []string{hubP6}) {
		t.Errorf("after ESXi confirmation: Shadow IT hubs = %v, want [%s]", got, hubP6)
	}
	if n := strings.Count(md, "### Shadow IT #"); n != 1 {
		t.Errorf("after ESXi confirmation: %d Shadow IT diagrams, want 1", n)
	}

	// Confirmed before the build.
	g = reportBuildGraph()
	SetGlobalGraph(g)
	audit := generateAuditMD([]string{"switch", "hub"})
	section := reportMDSection(audit, "## 7.", "## 8.", "## 9.")
	if n := strings.Count(section, "### Shadow IT #"); n != 1 || !strings.Contains(section, sanitizeMermaidID(hubP6)+"((") {
		t.Errorf("audit section 7 after a rebuild has %d diagrams, want only %s:\n%s", n, hubP6, section)
	}
}

func TestReportParseHubID(t *testing.T) {
	for _, c := range []struct {
		id, switchID string
		port         int
		ok           bool
	}{
		{"hub-4c:ae:a3:72:00:02-p3", "4c:ae:a3:72:00:02", 3, true},
		{"hub-10.0.72.9-p12", "10.0.72.9", 12, true},
		{"hub-sw-pod-p7", "sw-pod", 7, true},
		{"hub-x", "", 0, false},
		{"hub-sw-pX", "", 0, false},
		{"hyp-4c:ae:a3:72:00:02-ge1_0_3", "", 0, false},
	} {
		switchID, port, ok := reportParseHubID(c.id)
		if switchID != c.switchID || port != c.port || ok != c.ok {
			t.Errorf("reportParseHubID(%q) = %q, %d, %v; want %q, %d, %v", c.id, switchID, port, ok, c.switchID, c.port, c.ok)
		}
	}
}

// reportHypDiagrams splits GenerateHypervisorDiagrams output into its
// diagrams, keyed by the hypervisor node's mermaid id.
func reportHypDiagrams(md string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(md, "### Hypervisor #")[1:] {
		m := regexp.MustCompile("(?m)^```mermaid\ngraph LR\n  (\\w+)\\{\\{").FindStringSubmatch(part)
		if m == nil {
			out["?"+part] = part
			continue
		}
		out[m[1]] = part
	}
	return out
}

func reportVMCount(part string) string {
	m := regexp.MustCompile(`\*\*Virtual mashinalar:\*\* (\d+) ta`).FindStringSubmatch(part)
	if m == nil {
		return "?"
	}
	return m[1]
}

// TestReportHypervisorDiagramsMergeHost (F73): one diagram per hypervisor
// port. A confirmed ESXi host's NIC on the port is the hypervisor itself
// (detectHypervisors), and its diagram has the VMs. A host NIC nothing
// confirmed (a server NIC the graph tags as a hypervisor), which the graph
// keeps as a separate node on the same switch port, is shown inside the
// hyp- diagram instead of as a second hypervisor with 0 VMs, and only vNIC
// links count as VMs. Two confirmed host NICs on one port leave the hyp-
// node there, with both as its hosts.
func TestReportHypervisorDiagramsMergeHost(t *testing.T) {
	resetState(t)
	var macs []MACEntry
	macs = append(macs, macEntries(4, "d4:f5:ef:73:04:01", "00:0c:29:73:04:02", "00:0c:29:73:04:03", "00:0c:29:73:04:04")...)
	macs = append(macs, macEntries(6, "d4:f5:ef:73:06:01", "00:0c:29:73:06:02", "00:0c:29:73:06:03")...)
	macs = append(macs, macEntries(8, "d4:f5:ef:73:08:01", "d4:f5:ef:73:08:02", "00:0c:29:73:08:03", "00:0c:29:73:08:04", "00:0c:29:73:08:05")...)
	sw := &DeviceData{IP: "10.0.73.2", SysName: "sw-73", ChassisID: "4c:ae:a3:73:00:02",
		Interfaces: gigabitPorts(8, nil), MACTable: macs}
	reportSetDevices(sw)
	globalMACtoIPMutex.Lock()
	globalMACtoIP["d4:f5:ef:73:04:01"] = "10.0.73.69"
	globalMACtoIP["00:0c:29:73:04:02"] = "10.0.73.66"
	globalMACtoIPMutex.Unlock()
	ConfirmedESXiMACs.Store("d4:f5:ef:73:04:01", true) // the host NIC on GE1/0/4
	ConfirmedESXiMACs.Store("00:0c:29:73:06:03", true) // vNIC child of hyp-…-ge1_0_6
	ConfirmedESXiMACs.Store("d4:f5:ef:73:08:01", true) // two hosts on GE1/0/8
	ConfirmedESXiMACs.Store("d4:f5:ef:73:08:02", true)
	g := reportBuildGraph()

	host4, hyp4, hyp6, hyp8 := "d4:f5:ef:73:04:01", "hyp-4c:ae:a3:73:00:02-ge1_0_4", "hyp-4c:ae:a3:73:00:02-ge1_0_6", "hyp-4c:ae:a3:73:00:02-ge1_0_8"
	if g.Nodes[hyp4] || len(g.Edges[host4]) != 3 || !g.Nodes[hyp6] || !g.Nodes[hyp8] {
		t.Fatalf("precondition: %s drawn %v, %s links %v, %s drawn %v, %s drawn %v; want the VMs of GE1/0/4 below the confirmed host, hyp- nodes on GE1/0/6 and GE1/0/8",
			hyp4, g.Nodes[hyp4], host4, g.Edges[host4], hyp6, g.Nodes[hyp6], hyp8, g.Nodes[hyp8])
	}
	md := GenerateHypervisorDiagrams(g)
	diagrams := reportHypDiagrams(md)
	if len(diagrams) != 3 {
		t.Errorf("%d hypervisor diagrams, want 3 (one per hypervisor port):\n%s", len(diagrams), md)
	}
	d4 := diagrams[sanitizeMermaidID(host4)]
	if c := reportVMCount(d4); c != "3" || !strings.Contains(d4, "10.0.73.69") {
		t.Errorf("%s: %s VMs, want 3 below the host with its IP:\n%s", host4, c, d4)
	}
	d8 := diagrams[sanitizeMermaidID(hyp8)]
	if c := reportVMCount(d8); c != "3" || !strings.Contains(d8, "Host: d4:f5:ef:73:08:01") || !strings.Contains(d8, "Host: d4:f5:ef:73:08:02") {
		t.Errorf("%s: %s VMs, want 3 and both host NICs named:\n%s", hyp8, c, d8)
	}
	// The confirmed ESXi vNIC child (a nested ESXi) is one of the VMs, drawn
	// in the hypervisor colour, and has no diagram of its own.
	d6 := diagrams[sanitizeMermaidID(hyp6)]
	if c := reportVMCount(d6); c != "2" {
		t.Errorf("%s: %s VMs, want 2", hyp6, c)
	}
	nested := sanitizeMermaidID("00:0c:29:73:06:03")
	if !strings.Contains(d6, "  style "+nested+" fill:#26C6DA,") {
		t.Errorf("%s diagram does not draw its ESXi child as a hypervisor:\n%s", hyp6, d6)
	}

	// A hypervisor host on a port without a hyp- node keeps its own diagram.
	// Only vNIC links lead to VMs: a node relabelled as a hypervisor (here a
	// switch, see F36) gets no VMs from its other links.
	h := NewDJGraph()
	addInfoNode(h, "4c:ae:a3:73:00:09", "sw-x\n10.0.73.9")
	addInfoNode(h, "5c:ed:8c:73:09:01", "[HYPERVISOR] HPE ProLiant Server\n[VM] 🐧 Linux\n10.0.73.91")
	h.AddEdge("4c:ae:a3:73:00:09", "5c:ed:8c:73:09:01", "GE1/0/9 [T]")
	addInfoNode(h, "4c:ae:a3:73:00:0a", "[HYPERVISOR] VMware ESXi\nsw-y\n10.0.73.10")
	addInfoNode(h, "00:1b:21:73:0a:01", "[ENDPOINT]")
	h.AddEdge("4c:ae:a3:73:00:09", "4c:ae:a3:73:00:0a", "GE1/0/24|GE1/0/1")
	h.AddEdge("4c:ae:a3:73:00:0a", "00:1b:21:73:0a:01", "GE1/0/3|")
	got := reportHypDiagrams(GenerateHypervisorDiagrams(h))
	if len(got) != 2 {
		t.Errorf("standalone hypervisor hosts: %d diagrams, want 2", len(got))
	}
	relabelled := got[sanitizeMermaidID("4c:ae:a3:73:00:0a")]
	if c := reportVMCount(relabelled); c != "0" || strings.Contains(relabelled, sanitizeMermaidID("00:1b:21:73:0a:01")) {
		t.Errorf("non-vNIC links of a hypervisor are drawn or counted as VMs (%s VMs):\n%s", c, relabelled)
	}
}

// TestReportAuditListsEveryGroup (F74): section 4 has a table for every
// group except switch (section 4.1) and unknown, so access points and
// printers are no longer dropped; the Mermaid colours and the legend cover
// every group the backend emits.
func TestReportAuditListsEveryGroup(t *testing.T) {
	resetState(t)
	sw := "4c:ae:a3:74:00:01"
	g := NewDJGraph()
	addInfoNode(g, sw, "sw-74\n10.0.74.1")
	nodes := map[string]string{
		"e4:38:83:74:00:02": "[ENDPOINT] Ubiquiti\n10.0.74.2", // access point
		"00:26:ab:74:00:03": "[ENDPOINT] Epson\n10.0.74.3",    // printer
		"00:1b:21:74:00:04": "[ENDPOINT] Intel\n10.0.74.4",    // endpoint
		"10.0.74.5":         "Linux server\n10.0.74.5",        // server
		"10.0.74.6":         "edge router\n10.0.74.6",         // router
		"10.0.74.7":         "",                               // unknown (a switch without a name)
	}
	for id, info := range nodes {
		addInfoNode(g, id, info)
		g.AddEdge(sw, id, "GE1/0/5|")
	}
	SetGlobalGraph(g)
	data := g.GetGraphData()
	groups := map[string]string{}
	for _, n := range data.Nodes {
		groups[n.ID] = n.Group
	}
	if groups["e4:38:83:74:00:02"] != "access_point" || groups["00:26:ab:74:00:03"] != "printer" || groups["10.0.74.7"] != "unknown" {
		t.Fatalf("precondition: groups = %v", groups)
	}

	all := []string{"switch", "router", "hub", "endpoint", "access_point", "vm", "hypervisor", "bmc",
		"camera", "phone", "iot", "wifi_random", "printer", "server", "unknown"}
	md := generateAuditMD(all)
	section4 := reportMDSection(md, "## 4.", "## 5.")
	for id, group := range groups {
		if group == "switch" || group == "unknown" {
			continue
		}
		if !strings.Contains(section4, "| "+id+" |") {
			t.Errorf("section 4 does not list %s (group %s)", id, group)
		}
	}

	// Every node of the topology gets its group's fill colour.
	mermaid := GenerateMermaidTopology(g, all)
	for _, n := range data.Nodes {
		label := strings.ReplaceAll(n.SysName, "\n", "<br>")
		if label == "" {
			label = n.ID
		}
		if !strings.Contains(mermaid, "  style "+sanitizeMermaidID(label)+" fill:#") {
			t.Errorf("Mermaid topology has no colour for %s (group %s)", n.ID, n.Group)
		}
	}
	legend := GenerateTopologyLegend(all)
	if rows := strings.Count(legend, "\n") - 2; rows != len(all) {
		t.Errorf("legend has %d rows for %d groups:\n%s", rows, len(all), legend)
	}
}

// TestReportZabbixExportUsesDeviceIPs (F75): the Zabbix exports list the SNMP
// devices with their management IPs (not node ids, which are mostly MACs),
// one host per device, and no endpoints or hub-/hyp- nodes.
func TestReportZabbixExportUsesDeviceIPs(t *testing.T) {
	resetState(t)
	noSuch := "No Such Object available on this agent at this OID"
	reportSetDevices(
		&DeviceData{IP: "10.0.75.2", SysName: "SNR-S2985G-24TC", ChassisID: "f8:f0:82:75:00:02",
			Interfaces: gigabitPorts(8, nil),
			MACTable:   append(macEntries(3, "00:1b:21:75:03:01", "00:1b:21:75:03:02"), macEntries(4, "00:1b:21:75:04:01")...)},
		&DeviceData{IP: "10.0.75.3", SysName: "HPE", ChassisID: "", Interfaces: gigabitPorts(8, nil)},
		&DeviceData{IP: "10.0.75.4", SysName: "sw-4", ChassisID: noSuch, Interfaces: gigabitPorts(8, nil)},
		&DeviceData{IP: "10.0.75.5", SysName: "sw-5", ChassisID: noSuch, Interfaces: gigabitPorts(8, nil)},
	)
	g := reportBuildGraph()
	dir := t.TempDir()
	if err := g.ExportHostsToZabbix(filepath.Join(dir, "hosts.json")); err != nil {
		t.Fatal(err)
	}
	if err := g.ExportToMap(filepath.Join(dir, "map.json")); err != nil {
		t.Fatal(err)
	}
	var hosts struct {
		Export struct {
			Hosts []struct {
				Host       string              `json:"host"`
				Name       string              `json:"name"`
				Templates  []map[string]string `json:"templates"`
				Interfaces []map[string]any    `json:"interfaces"`
			} `json:"hosts"`
		} `json:"zabbix_export"`
	}
	reportReadJSON(t, filepath.Join(dir, "hosts.json"), &hosts)
	var gotHosts, names []string
	for _, h := range hosts.Export.Hosts {
		gotHosts = append(gotHosts, h.Host)
		names = append(names, h.Name)
		ip, _ := h.Interfaces[0]["ip"].(string)
		if net.ParseIP(ip) == nil || ip != h.Host {
			t.Errorf("host %q has SNMP interface ip %q, want its IP", h.Host, ip)
		}
		if h.Host == "10.0.75.2" && !strings.Contains(fmt.Sprint(h.Templates), "SNR") {
			t.Errorf("SNR switch got templates %v", h.Templates)
		}
	}
	wantHosts := []string{"10.0.75.2", "10.0.75.3", "10.0.75.4", "10.0.75.5"}
	if !slices.Equal(gotHosts, wantHosts) {
		t.Errorf("Zabbix hosts = %v, want %v", gotHosts, wantHosts)
	}
	slices.Sort(names)
	if len(slices.Compact(names)) != len(hosts.Export.Hosts) {
		t.Errorf("visible host names are not unique: %v", names)
	}

	var zmap struct {
		Export struct {
			Maps []struct {
				Selements []struct {
					ID       string              `json:"selementid"`
					Elements []map[string]string `json:"elements"`
				} `json:"selements"`
			} `json:"maps"`
		} `json:"zabbix_export"`
	}
	reportReadJSON(t, filepath.Join(dir, "map.json"), &zmap)
	var mapHosts []string
	for _, e := range zmap.Export.Maps[0].Selements {
		mapHosts = append(mapHosts, e.Elements[0]["host"])
	}
	if !slices.Equal(mapHosts, wantHosts) {
		t.Errorf("Zabbix map elements = %v, want %v", mapHosts, wantHosts)
	}
}

// reportBFSExport runs ExportBFSDepths and returns bfs_depths.json.
func reportBFSExport(t *testing.T, g *DJGraph) BFSDepthExport {
	t.Helper()
	dir := t.TempDir()
	exportsDir = dir
	defer func() { exportsDir = guardExportsDir }()
	ExportBFSDepths(g)
	var out BFSDepthExport
	reportReadJSON(t, filepath.Join(dir, "bfs_depths.json"), &out)
	return out
}

// reportBFSCore runs ExportBFSDepths and returns core_switch_ip.
func reportBFSCore(t *testing.T, g *DJGraph) string {
	t.Helper()
	return reportBFSExport(t, g).CoreSwitchIP
}

// TestReportBFSRoot (F76, R6): the BFS root is the gateway's switch node,
// never a VM or endpoint whose label merely contains the gateway IP, on
// every run. Without a gateway node there is no root: bfs_depths.json says
// so instead of measuring from a guessed switch.
func TestReportBFSRoot(t *testing.T) {
	resetState(t)
	gw := "aa:bb:cc:76:00:01"
	g := NewDJGraph()
	addInfoNode(g, gw, "GW\n"+gatewayIP)
	addInfoNode(g, "00:0c:29:76:00:02", "[VM] 🐧 Linux VMware\n"+gatewayIP)
	addInfoNode(g, "aa:bb:cc:76:00:03", "sw-3\n10.0.76.3")
	addInfoNode(g, "00:1b:21:76:00:04", "[ENDPOINT] Intel\n10.0.76.4")
	g.AddEdge(gw, "aa:bb:cc:76:00:03", "GE1/0/1|GE1/0/24")
	g.AddEdge("aa:bb:cc:76:00:03", "00:0c:29:76:00:02", "GE1/0/2 [T]")
	g.AddEdge("aa:bb:cc:76:00:03", "00:1b:21:76:00:04", "GE1/0/3|")
	reportSetDevices(&DeviceData{IP: gatewayIP, SysName: "GW", ChassisID: gw})
	for i := 0; i < 40; i++ {
		if core := reportBFSCore(t, g); core != gw {
			t.Fatalf("run %d: BFS root = %s, want the gateway switch %s", i, core, gw)
		}
	}
	// Not polled: the switch whose label has the gateway IP as a line.
	reportSetDevices()
	for i := 0; i < 40; i++ {
		if core := reportBFSCore(t, g); core != gw {
			t.Fatalf("run %d without the polled gateway: BFS root = %s, want %s", i, core, gw)
		}
	}

	// The gateway is neither a node nor polled, and the endpoint's label
	// contains the gateway IP as a substring only: no core, and the file
	// says so (the busiest switch used to be taken, R6).
	reportSetDevices()
	setGatewayIPs([]string{"10.0.76.1"})
	t.Cleanup(func() { setGatewayIPs([]string{fixedGatewayIP}) })
	h := NewDJGraph()
	addInfoNode(h, "aa:bb:cc:76:00:11", "sw-11\n10.0.76.11")
	addInfoNode(h, "aa:bb:cc:76:00:12", "sw-12\n10.0.76.12")
	addInfoNode(h, "00:1b:21:76:00:13", "[ENDPOINT] Intel\n10.0.76.13")
	addInfoNode(h, "00:1b:21:76:00:14", "[ENDPOINT] Intel\n10.0.76.14")
	h.AddEdge("aa:bb:cc:76:00:11", "00:1b:21:76:00:13", "GE1/0/3|")
	h.AddEdge("aa:bb:cc:76:00:12", "00:1b:21:76:00:14", "GE1/0/3|")
	out := reportBFSExport(t, h)
	if out.CoreFound || out.CoreSwitchIP != "" || out.TotalNodes != 0 || len(out.DeepDevices) != 0 || !strings.Contains(out.Note, "10.0.76.1") {
		t.Errorf("no gateway node: bfs_depths.json = %+v, want no core and a note naming the gateway", out)
	}
}

// TestReportAuditDeterministic (Q16): the report parts built from the
// devices (collectedData, a map) and the graph come out the same on every
// call.
func TestReportAuditDeterministic(t *testing.T) {
	SetGlobalGraph(buildFixtureGraph(t))
	parts := func() []string {
		md := generateAuditMD([]string{"switch", "hub", "endpoint", "vm", "hypervisor"})
		rr := httptest.NewRecorder()
		reportSummaryHandler(rr, httptest.NewRequest(http.MethodGet, "/api/report/summary", nil))
		return []string{reportMDSection(md, "## 3.", "## 6."), reportMDSection(md, "## 7.", "## 9."), rr.Body.String()}
	}
	first := parts()
	for call := 2; call <= 4; call++ {
		for i, part := range parts() {
			if part != first[i] {
				t.Fatalf("call %d: part %d differs from the first call:\n%s", call, i, lineDiff([]byte(first[i]), []byte(part), 10))
			}
		}
	}
}

// TestDocxLegendNamesReportColours (H13): the DOCX converter the audit
// download runs (instrumens/md2docx_gost_linux.py) names every fill colour
// the report's diagrams use in its legend (group_label_map), so no group
// shows up as a bare hex code; its twin md2docx_gost_cyrillic_linux.py has
// the same map.
func TestDocxLegendNamesReportColours(t *testing.T) {
	entry := regexp.MustCompile(`'(#[0-9A-Fa-f]{6})':\s*'([^']+)'`)
	for _, script := range []string{"md2docx_gost_linux.py", "md2docx_gost_cyrillic_linux.py"} {
		src, err := os.ReadFile(filepath.Join("instrumens", script))
		if err != nil {
			t.Fatal(err)
		}
		start := strings.Index(string(src), "group_label_map = {")
		end := strings.Index(string(src)[start:], "}")
		if start < 0 || end < 0 {
			t.Fatalf("%s: no group_label_map", script)
		}
		labels := map[string]string{}
		for _, m := range entry.FindAllStringSubmatch(string(src)[start:start+end], -1) {
			labels[strings.ToUpper(m[1])] = m[2]
		}
		for group, colors := range reportGroupColors {
			if labels[strings.ToUpper(colors[0])] == "" {
				t.Errorf("%s: group_label_map has no label for %s (%s)", script, colors[0], group)
			}
		}
	}
}

// docxRootCheck runs the DOCX converter's mermaid_to_graphviz (taken out of
// the script with ast, so python-docx and pypandoc are not needed) on every
// Mermaid block of a Markdown file and prints, per block, the BFS root's
// DOT line (the node with penwidth=3.5, or the old #FF9800 root line) and
// the root's fill in the Mermaid styles.
const docxRootCheck = `
import ast, json, re, sys
script, md = sys.argv[1], sys.argv[2]
tree = ast.parse(open(script, encoding='utf-8').read())
funcs = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name in ('parse_mermaid_nodes_edges', 'mermaid_to_graphviz')]
ns = {'re': re}
exec(compile(ast.Module(body=funcs, type_ignores=[]), script, 'exec'), ns)
out = []
for block in re.findall(r'` + "```" + `mermaid\n(.*?)\n` + "```" + `', open(md, encoding='utf-8').read(), re.DOTALL):
    dot = ns['mermaid_to_graphviz'](block)
    lines = [l.strip() for l in dot.split('\n') if 'penwidth=3.5' in l or 'fillcolor="#FF9800", fontcolor="white", color="#E65100", penwidth=2.5' in l]
    if not lines:
        continue
    root = lines[0].split('"')[1]
    style = re.search(r'^\s*style\s+' + re.escape(root) + r'\s+fill:(#\w+)', block, re.MULTILINE)
    out.append({'root': root, 'line': lines[0], 'style_fill': style.group(1) if style else ''})
print(json.dumps(out))
`

// TestDocxRootKeepsGroupColour (R3): the DOCX converters draw the BFS root
// (the core) in its own group colour, marked by a thick dark border, not
// filled #FF9800, which their legend names "Hub": the core switch looked
// like a Shadow-IT hub in the section-3 topology and in
// /api/report/audit-svg. Checked on the golden audit's diagrams. Skipped
// without python3.
func TestDocxRootKeepsGroupColour(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not installed, so the DOCX converters are not checked")
	}
	md := filepath.Join("testdata", "golden", "audit_default.md")
	for _, script := range []string{"md2docx_gost_linux.py", "md2docx_gost_cyrillic_linux.py"} {
		cmd := exec.Command(python, "-I", "-c", docxRootCheck, filepath.Join("instrumens", script), md)
		cmd.Env = []string{}
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("%s: %v", script, err)
		}
		var roots []struct {
			Root, Line string
			StyleFill  string `json:"style_fill"`
		}
		if err := json.Unmarshal(out, &roots); err != nil {
			t.Fatalf("%s: %v\n%s", script, err, out)
		}
		if len(roots) == 0 {
			t.Fatalf("%s: no diagram root found in %s", script, md)
		}
		for _, r := range roots {
			want := `fillcolor="` + r.StyleFill + `"`
			if r.StyleFill == "" {
				want = `color="#212121", penwidth=3.5`
			}
			if !strings.Contains(r.Line, want) || (r.StyleFill != "#FF9800" && strings.Contains(r.Line, "#FF9800")) {
				t.Errorf("%s: root %s is drawn as %q, want its own fill %q and a dark border", script, r.Root, r.Line, r.StyleFill)
			}
		}
	}
}

// TestCalculateDepthsFollowsLinksBothWays (F19 in bfs_depths.json): an
// edge's direction only says which switch reported the link, so the BFS
// from the core follows edges both ways; before, it reached only what the
// core and its successors reported.
func TestCalculateDepthsFollowsLinksBothWays(t *testing.T) {
	g := NewDJGraph()
	for _, id := range []string{"core", "a", "b", "c", "lonely"} {
		g.AddNode(id)
	}
	g.AddEdge("core", "a", "GE1/0/1|")
	g.AddEdge("b", "a", "GE1/0/2|") // b reported its link to a
	g.AddEdge("c", "b", "GE1/0/3|")
	want := map[string]int{"core": 0, "a": 1, "b": 2, "c": 3}
	if got := g.CalculateDepths("core"); fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("CalculateDepths = %v, want %v", got, want)
	}
	if got := g.CalculateDepths("missing"); len(got) != 0 {
		t.Errorf("CalculateDepths of a missing root = %v", got)
	}
}

// TestAuditPickerOffersEveryReportGroup (reports and UI handoffs, F74, F77):
// the audit export dialog of static/app.js offers every node group the
// report can draw and colour (reportGroupColors), so printers, servers and
// unknown nodes can be put into the topology diagram too.
func TestAuditPickerOffersEveryReportGroup(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("static", "app.js"))
	if err != nil {
		t.Fatal(err)
	}
	js := string(src)
	start := strings.Index(js, "function downloadAuditReport()")
	end := strings.Index(js[max(start, 0):], "let checkboxesHTML")
	if start < 0 || end < 0 {
		t.Fatal("app.js: no audit group picker (downloadAuditReport groupOptions)")
	}
	offered := map[string]bool{}
	for _, m := range regexp.MustCompile(`\{ id: '([a-z_]+)'`).FindAllStringSubmatch(js[start:start+end], -1) {
		offered[m[1]] = true
	}
	for group := range reportGroupColors {
		if !offered[group] {
			t.Errorf("the audit picker does not offer group %q", group)
		}
	}
}

// svgWellFormed decodes svg as XML to the end and returns the first error.
func svgWellFormed(svg string) error {
	dec := xml.NewDecoder(strings.NewReader(svg))
	for {
		if _, err := dec.Token(); err == io.EOF {
			return nil
		} else if err != nil {
			return fmt.Errorf("at byte %d: %w", dec.InputOffset(), err)
		}
	}
}

// TestTopologySVGWellFormed (R4): /api/report/topology-svg writes device
// names and port labels as escaped XML text, and shortens them by
// characters, so the document stays well-formed: the fixture switch
// "TTJ-3&4" made browsers show an XML parse error instead of the
// topology, and a byte cut could split a UTF-8 character.
func TestTopologySVGWellFormed(t *testing.T) {
	svg := GenerateTopologySVG(buildFixtureGraph(t))
	if err := svgWellFormed(svg); err != nil {
		t.Errorf("fixture topology SVG is not well-formed XML: %v", err)
	}
	if !strings.Contains(svg, "TTJ-3&amp;4") {
		t.Error("precondition: the fixture SVG has no escaped TTJ-3&4 label")
	}

	resetState(t)
	g := NewDJGraph()
	addInfoNode(g, "4c:ae:a3:09:84:01", "<script>alert(1)</script>\n10.0.9.84")
	addInfoNode(g, "4c:ae:a3:09:84:02", "Коммутатор-корпус-2\n10.0.9.85")
	g.AddEdge("4c:ae:a3:09:84:01", "4c:ae:a3:09:84:02", `GE1/0/1 "uplink" & <b>|GE1/0/48`)
	svg = GenerateTopologySVG(g)
	if err := svgWellFormed(svg); err != nil {
		t.Errorf("SVG with markup and Cyrillic labels is not well-formed XML: %v\n%s", err, svg)
	}
	if !utf8.ValidString(svg) || strings.Contains(svg, "<script") || !strings.Contains(svg, "Коммутатор-корпу..") {
		t.Errorf("labels not escaped or not cut by characters:\n%s", svg)
	}
	if got, want := truncateLabel("Коммутатор-корпус-2", 18), "Коммутатор-корпу.."; got != want { // 16 characters and ".."
		t.Errorf("truncateLabel = %q, want %q", got, want)
	}
}
