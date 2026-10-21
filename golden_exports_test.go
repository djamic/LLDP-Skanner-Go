package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"
)

// Durations passed to generateExperimentReport (normally measured by main).
const (
	expScanDuration       = 1500 * time.Millisecond
	expCollectionDuration = 2500 * time.Millisecond
	expTotalDuration      = 4 * time.Second
)

const timePlaceholder = "<time>"

// readJSONFile decodes a JSON file with numbers kept exact.
func readJSONFile(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var out map[string]any
	if err := dec.Decode(&out); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return out
}

// sortRecords sorts a JSON array of objects by the given keys.
func sortRecords(v any, keys ...string) {
	list, _ := v.([]any)
	sort.SliceStable(list, func(i, j int) bool {
		a, _ := list[i].(map[string]any)
		b, _ := list[j].(map[string]any)
		for _, k := range keys {
			x, y := fmt.Sprint(a[k]), fmt.Sprint(b[k])
			if x != y {
				return x < y
			}
		}
		return false
	})
}

// runExperimentReport runs generateExperimentReport on the devices in
// collectedData (IP order) and returns the directory it wrote to.
func runExperimentReport(t *testing.T, graph *DJGraph) string {
	t.Helper()
	dir := t.TempDir()
	exportsDir = dir
	defer func() { exportsDir = guardExportsDir }()
	collectedDataMutex.RLock()
	devices := sortedDevices(collectedData)
	collectedDataMutex.RUnlock()
	resetBot()
	generateExperimentReport(devices, expScanDuration, expCollectionDuration, expTotalDuration, graph)
	return dir
}

// experimentMetrics returns results/experiment_metrics.json for the graph.
func experimentMetrics(t *testing.T, graph *DJGraph) map[string]any {
	t.Helper()
	return readJSONFile(t, filepath.Join(runExperimentReport(t, graph), "experiment_metrics.json"))
}

// TestGoldenExperimentExports runs generateExperimentReport on the fixture
// and pins the five files it writes (experiment_metrics, health_scores,
// bfs_depths, vendor_stats, telegram_timing) with timestamps replaced and
// map-order lists sorted.
func TestGoldenExperimentExports(t *testing.T) {
	graph := buildFixtureGraph(t)
	dir := runExperimentReport(t, graph)

	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, f := range files {
		names = append(names, f.Name())
	}

	metrics := readJSONFile(t, filepath.Join(dir, "experiment_metrics.json"))
	metrics["experiment_date"] = timePlaceholder

	health := readJSONFile(t, filepath.Join(dir, "health_scores.json"))
	health["export_time"] = timePlaceholder
	for _, d := range health["devices"].([]any) {
		dev := d.(map[string]any)
		if list, ok := dev["anomalies"].([]any); ok {
			sort.Slice(list, func(i, j int) bool { return fmt.Sprint(list[i]) < fmt.Sprint(list[j]) })
		}
	}

	bfs := readJSONFile(t, filepath.Join(dir, "bfs_depths.json"))
	bfs["export_time"] = timePlaceholder
	sortRecords(bfs["deep_devices"], "node_id")

	vendors := readJSONFile(t, filepath.Join(dir, "vendor_stats.json"))
	vendors["export_time"] = timePlaceholder
	sortRecords(vendors["vendors"], "vendor")

	timing := readJSONFile(t, filepath.Join(dir, "telegram_timing.json"))
	timing["export_time"] = timePlaceholder
	timing["average_latency_ms"] = 0
	timing["max_latency_ms"] = 0
	if entries, ok := timing["entries"].([]any); ok {
		for _, e := range entries {
			entry := e.(map[string]any)
			entry["detect_time"] = timePlaceholder
			entry["notify_time"] = timePlaceholder
			entry["latency_ms"] = 0
		}
		sortRecords(entries, "issue_id", "issue_type")
	}

	rec := map[string]any{
		"files":              names,
		"experiment_metrics": metrics,
		"health_scores":      health,
		"bfs_depths":         bfs,
		"vendor_stats":       vendors,
		"telegram_timing":    timing,
	}
	checkGolden(t, "experiment_exports.json", goldenJSON(t, rec, 3))
}

// TestGoldenTelegramTimingEntries pins the telegram_timing.json format for
// known entries (the fixture run above only records wall-clock values).
func TestGoldenTelegramTimingEntries(t *testing.T) {
	resetState(t)
	dir := t.TempDir()
	exportsDir = dir
	AddTelegramTiming("summary", "summary", fixedTime, fixedTime.Add(120*time.Millisecond))
	AddTelegramTiming("shadow_172_20_230_4_12", "shadow_it", fixedTime, fixedTime.Add(380*time.Millisecond))
	ExportTelegramTiming()
	timing := readJSONFile(t, filepath.Join(dir, "telegram_timing.json"))
	timing["export_time"] = timePlaceholder
	checkGolden(t, "telegram_timing.json", goldenJSON(t, timing, 3))
}

// TestGoldenZabbixHosts pins ExportHostsToZabbix for the fixture graph. The
// fields that are the same for every host are listed once; per host the
// golden keeps the name, the SNMP interface IP and the template set.
func TestGoldenZabbixHosts(t *testing.T) {
	graph := buildFixtureGraph(t)
	path := filepath.Join(t.TempDir(), "zabbix_hosts.json")
	if err := graph.ExportHostsToZabbix(path); err != nil {
		t.Fatal(err)
	}
	export := readJSONFile(t, path)["zabbix_export"].(map[string]any)
	export["date"] = timePlaceholder

	type hostView struct {
		Name      string `json:"name"`
		IP        string `json:"ip"`
		Templates string `json:"templates"`
	}
	hosts := map[string]hostView{}
	templateSets := map[string][]string{}
	var common map[string]any
	for _, h := range export["hosts"].([]any) {
		host := h.(map[string]any)
		iface := host["interfaces"].([]any)[0].(map[string]any)
		var tnames []string
		for _, tp := range host["templates"].([]any) {
			tnames = append(tnames, tp.(map[string]any)["name"].(string))
		}
		setID := "generic"
		if strings.Contains(strings.Join(tnames, ","), "SNR") {
			setID = "snr"
		}
		if prev, ok := templateSets[setID]; ok && !slices.Equal(prev, tnames) {
			t.Errorf("template set %q differs between hosts: %v vs %v", setID, prev, tnames)
		}
		templateSets[setID] = tnames
		hosts[host["host"].(string)] = hostView{Name: host["name"].(string), IP: iface["ip"].(string), Templates: setID}

		// Everything else must be identical for every host.
		rest := map[string]any{"groups": host["groups"], "inventory_mode": host["inventory_mode"]}
		ifaceRest := map[string]any{}
		for k, v := range iface {
			if k != "ip" {
				ifaceRest[k] = v
			}
		}
		rest["interface"] = ifaceRest
		if common == nil {
			common = rest
		} else if a, b := fmt.Sprint(common), fmt.Sprint(rest); a != b {
			t.Errorf("host %v has different constant fields: %s vs %s", host["host"], b, a)
		}
	}
	delete(export, "hosts")
	rec := map[string]any{
		"export":        export,
		"host_count":    len(hosts),
		"host_common":   common,
		"template_sets": templateSets,
		"hosts":         hosts,
	}
	checkGolden(t, "zabbix_export.json", goldenJSON(t, rec, 2))
}

// reportFixture builds the fixture graph, publishes it and runs Analyze()
// once, which is the state the report endpoints read in production.
func reportFixture(t *testing.T) (*DJGraph, Report) {
	t.Helper()
	graph := buildFixtureGraph(t)
	SetGlobalGraph(graph)
	report, _ := analyzeFixture(t, graph)
	return graph, report
}

// TestGoldenReports pins the report endpoints built from the graph:
// /api/report/summary, the anomaly enrichment and totals of /api/graph, and
// the audit Markdown report (default groups and a VM/hypervisor/BMC set).
func TestGoldenReports(t *testing.T) {
	_, report := reportFixture(t)
	_, stpDevice := suggestionRecords(report)
	graphDebugFile = filepath.Join(t.TempDir(), "graphs_data.txt")

	// /api/report/summary
	rr := httptest.NewRecorder()
	reportSummaryHandler(rr, httptest.NewRequest(http.MethodGet, "/api/report/summary", nil))
	var summary ReportSummary
	if err := json.Unmarshal(rr.Body.Bytes(), &summary); err != nil {
		t.Fatal(err)
	}
	slices.SortFunc(summary.TopDevices, func(a, b DeviceSummary) int { return compareIPs(a.IP, b.IP) })

	// /api/graph: the same nodes and links as GetGraphData, plus the
	// analysis results attached by graphHandler.
	rr = httptest.NewRecorder()
	graphHandler(rr, httptest.NewRequest(http.MethodGet, "/api/graph", nil))
	var api GraphData
	if err := json.Unmarshal(rr.Body.Bytes(), &api); err != nil {
		t.Fatal(err)
	}
	// The stp root is chosen by map order (F18) and is a graph node only in
	// some runs, so it is checked here and left out of the golden.
	nodeAnomalies := map[string][]string{}
	for _, n := range api.Nodes {
		if len(n.Anomalies) == 0 {
			continue
		}
		if n.ID == stpDevice {
			if !slices.Contains(n.Anomalies, "stp") {
				t.Errorf("stp root node %s has anomalies %v", n.ID, n.Anomalies)
			}
			continue
		}
		nodeAnomalies[n.ID] = slices.Sorted(slices.Values(n.Anomalies))
	}
	debug, err := os.ReadFile(graphDebugFile)
	if err != nil {
		t.Fatalf("graphHandler debug snapshot: %v", err)
	}
	var debugData GraphData
	if err := json.Unmarshal(debug, &debugData); err != nil || len(debugData.Nodes) != len(api.Nodes) {
		t.Errorf("graphs_data.txt snapshot does not match the /api/graph response (err=%v)", err)
	}
	rec := map[string]any{
		"report_summary": summary,
		"api_graph": map[string]any{
			"health_score":   api.HealthScore,
			"total_macs":     api.TotalMACs,
			"nodes":          len(api.Nodes),
			"links":          len(api.Links),
			"node_anomalies": nodeAnomalies,
		},
	}
	checkGolden(t, "reports.json", goldenJSON(t, rec, 3))

	checkGolden(t, "audit_default.md", []byte(canonicalAuditMD(generateAuditMD([]string{"switch", "hub"}))))

	// Only section 3 (Mermaid topology and legend) depends on the groups.
	// This set has every other group, also those with no nodes in the
	// fixture or no legend row (printer, server, unknown).
	servers := canonicalAuditMD(generateAuditMD([]string{"switch", "router", "hypervisor", "vm", "bmc", "server", "access_point", "wifi_random", "printer", "unknown"}))
	checkGolden(t, "audit_servers_section3.md", []byte(auditSections(t, servers, "## 3.", "## 4.")))
}

// auditSections returns the part of an audit report from the heading that
// starts with from up to the heading that starts with to.
func auditSections(t *testing.T, md, from, to string) string {
	t.Helper()
	start := strings.Index(md, "\n"+from)
	end := strings.Index(md, "\n"+to)
	if start < 0 || end < start {
		t.Fatalf("audit report has no %q ... %q part", from, to)
	}
	return md[start+1 : end+1]
}

var (
	auditDateLine = regexp.MustCompile(`(?m)^Sana: .*$`)
	auditScanTime = regexp.MustCompile(`(?m)^\| Skanerlash vaqti \| .* \|$`)
)

// canonicalAuditMD replaces the timestamps in generateAuditMD output and sorts
// the parts that come from map iteration over collectedData or anomaly
// counts: the section 2 penalty rows, the section 4.1 switch rows (only
// 4.1, not 4.10-4.14), and the switch list inside each section 5 VLAN row. Everything that comes from
// GetGraphData is reproducible as is, because TestMain sets sortGraphData.
func canonicalAuditMD(md string) string {
	md = auditDateLine.ReplaceAllString(md, "Sana: "+timePlaceholder)
	md = auditScanTime.ReplaceAllString(md, "| Skanerlash vaqti | "+timePlaceholder+" |")
	lines := strings.Split(md, "\n")
	section := ""
	var out []string
	var run []string
	flush := func() {
		slices.Sort(run)
		out = append(out, run...)
		run = nil
	}
	for _, line := range lines {
		if strings.HasPrefix(line, "## ") || strings.HasPrefix(line, "### ") {
			flush()
			section = line
		}
		isRow := strings.HasPrefix(line, "| ") && !strings.HasPrefix(line, "|---")
		switch {
		case strings.HasPrefix(section, "## 2.") && isRow && !strings.HasPrefix(line, "| Anomaliya turi |"):
			run = append(run, line)
			continue
		case strings.HasPrefix(section, "### 4.1 ") && isRow && !strings.HasPrefix(line, "| IP |"):
			run = append(run, line)
			continue
		case strings.HasPrefix(section, "## 5.") && isRow && !strings.HasPrefix(line, "| VLAN ID |"):
			cells := strings.Split(line, " | ")
			if len(cells) > 1 {
				names := strings.Split(cells[1], ", ")
				slices.Sort(names)
				cells[1] = strings.Join(names, ", ")
			}
			line = strings.Join(cells, " | ")
		}
		flush()
		out = append(out, line)
	}
	flush()
	return strings.Join(out, "\n")
}

// TestCanonicalAuditMDSections (H14): only the rows of section 4.1 are
// sorted; the rows of 4.10-4.14 keep their order.
func TestCanonicalAuditMDSections(t *testing.T) {
	md := strings.Join([]string{
		"### 4.1 Switchlar", "| IP | Hostname |", "|---|---|", "| 10.0.0.2 | b |", "| 10.0.0.1 | a |",
		"### 4.12 Wi-Fi / Random MAC (2 ta)", "| # | MAC |", "|---|---|", "| 2 | da:a1:19:00:00:02 |", "| 10 | da:a1:19:00:00:01 |",
	}, "\n")
	want := strings.Join([]string{
		"### 4.1 Switchlar", "| IP | Hostname |", "|---|---|", "| 10.0.0.1 | a |", "| 10.0.0.2 | b |",
		"### 4.12 Wi-Fi / Random MAC (2 ta)", "| # | MAC |", "|---|---|", "| 2 | da:a1:19:00:00:02 |", "| 10 | da:a1:19:00:00:01 |",
	}, "\n")
	if got := canonicalAuditMD(md); got != want {
		t.Errorf("canonicalAuditMD =\n%s\nwant\n%s", got, want)
	}
}
