package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// Tests for the report and export fixes (F71-F76). They use hand-made
// devices or graphs, so they do not depend on the fixture.

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
// same vendor for a device. The OUI vendor comes first; without one the
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
	gotBuckets := map[string]int{}
	for _, v := range stats.Vendors {
		gotBuckets[v.Vendor] = v.DeviceCount
	}

	wantBuckets := map[string]int{}
	for ip, vendor := range want {
		for _, source := range []string{"summary", "full", "audit", "health"} {
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

// reportShadowHubs returns the hub ids GenerateShadowDiagrams draws, in order.
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
// not one of the (at most 5) member nodes the graph draws.
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
// port. The ESXi host's own NIC, which the graph keeps as a separate node on
// the same switch port, is shown inside the hyp- diagram instead of as a
// second hypervisor with 0 VMs, and only vNIC links count as VMs.
func TestReportHypervisorDiagramsMergeHost(t *testing.T) {
	resetState(t)
	var macs []MACEntry
	macs = append(macs, macEntries(4, "d4:f5:ef:73:04:01", "00:0c:29:73:04:02", "00:0c:29:73:04:03", "00:0c:29:73:04:04")...)
	macs = append(macs, macEntries(6, "d4:f5:ef:73:06:01", "00:0c:29:73:06:02", "00:0c:29:73:06:03")...)
	sw := &DeviceData{IP: "10.0.73.2", SysName: "sw-73", ChassisID: "4c:ae:a3:73:00:02",
		Interfaces: gigabitPorts(8, nil), MACTable: macs}
	reportSetDevices(sw)
	globalMACtoIPMutex.Lock()
	globalMACtoIP["d4:f5:ef:73:04:01"] = "10.0.73.69"
	globalMACtoIP["00:0c:29:73:04:02"] = "10.0.73.66"
	globalMACtoIPMutex.Unlock()
	ConfirmedESXiMACs.Store("d4:f5:ef:73:04:01", true) // host NIC next to hyp-…-ge1_0_4
	ConfirmedESXiMACs.Store("00:0c:29:73:06:03", true) // vNIC child of hyp-…-ge1_0_6
	g := reportBuildGraph()

	hyp4, hyp6 := "hyp-4c:ae:a3:73:00:02-ge1_0_4", "hyp-4c:ae:a3:73:00:02-ge1_0_6"
	for _, id := range []string{hyp4, hyp6} {
		if !g.Nodes[id] {
			t.Fatalf("precondition: graph has no %s", id)
		}
	}
	md := GenerateHypervisorDiagrams(g)
	diagrams := reportHypDiagrams(md)
	if len(diagrams) != 2 {
		t.Errorf("%d hypervisor diagrams, want 2 (one per hypervisor port):\n%s", len(diagrams), md)
	}
	d4 := diagrams[sanitizeMermaidID(hyp4)]
	if c := reportVMCount(d4); c != "3" {
		t.Errorf("%s: %s VMs, want 3", hyp4, c)
	}
	if !strings.Contains(d4, "Host: d4:f5:ef:73:04:01 (10.0.73.69)") {
		t.Errorf("%s diagram does not name its host NIC:\n%s", hyp4, d4)
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
