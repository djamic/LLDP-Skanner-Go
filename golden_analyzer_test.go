package main

import (
	"slices"
	"strings"
	"testing"
)

// analyzeFixture runs Analyze() on the devices in collectedData (in IP order)
// and the given graph, with every bot message recorded instead of sent.
func analyzeFixture(t *testing.T, graph *DJGraph) (Report, []botMessage) {
	t.Helper()
	collectedDataMutex.RLock()
	devices := sortedDevices(collectedData)
	collectedDataMutex.RUnlock()
	resetBot()
	report := NewAnalyzer(captureData("golden", devices, graph)).Analyze()
	return report, bot.taken()
}

type goldenSuggestion struct {
	Type        string `json:"type"`
	Severity    string `json:"severity"`
	Device      string `json:"device"`
	IssueID     string `json:"issue_id,omitempty"`
	Value       string `json:"value"`
	Description string `json:"description"`
}

// suggestionRecords sorts the suggestions. It also returns the stp
// suggestion's Device, the root bridge analyzeSTP names (empty when there is
// no stp suggestion).
func suggestionRecords(r Report) ([]goldenSuggestion, string) {
	var out []goldenSuggestion
	stpDevice := ""
	for _, s := range r.Suggestions {
		g := goldenSuggestion{Type: s.Type, Severity: s.Severity, Device: s.Device, IssueID: s.IssueID, Value: s.Value, Description: s.Description}
		if s.Type == "stp" {
			stpDevice = s.Device
		}
		out = append(out, g)
	}
	slices.SortFunc(out, func(a, b goldenSuggestion) int {
		for _, c := range [][2]string{{a.Type, b.Type}, {a.Device, b.Device}, {a.IssueID, b.IssueID}, {a.Value, b.Value}, {a.Description, b.Description}} {
			if d := strings.Compare(c[0], c[1]); d != 0 {
				return d
			}
		}
		return 0
	})
	return out, stpDevice
}

// lastReportRecord reads what Analyze stored for /api/graph (SetLastReport),
// with each type list sorted.
func lastReportRecord() map[string]any {
	lastReportMutex.RLock()
	defer lastReportMutex.RUnlock()
	anomalies := map[string][]string{}
	for k, v := range lastAnomalyMap {
		types := slices.Clone(v)
		slices.Sort(types)
		anomalies[k] = types
	}
	return map[string]any{
		"health_score": lastHealthScore,
		"total_macs":   lastTotalMACs,
		"anomaly_map":  anomalies,
	}
}

// stpRoots lists the distinct root bridge ids reported by STP-enabled
// devices: the set the stp suggestion's Device is chosen from.
func stpRoots(devices []*DeviceData) []string {
	var roots []string
	for _, d := range devices {
		if d.STPInfo.Enabled && d.STPInfo.RootBridgeID != "" && !slices.Contains(roots, d.STPInfo.RootBridgeID) {
			roots = append(roots, d.STPInfo.RootBridgeID)
		}
	}
	slices.Sort(roots)
	return roots
}

// TestGoldenAnalyzer runs Analyze() on the fixture and its graph and pins the
// suggestions, health score, summary counts, what Analyze stores for the UI
// (health, total_macs, anomaly map), the analyserbot messages and the
// anomaly_summary point written to InfluxDB.
func TestGoldenAnalyzer(t *testing.T) {
	graph := buildFixtureGraph(t)
	collectedDataMutex.RLock()
	devices := sortedDevices(collectedData)
	collectedDataMutex.RUnlock()

	influxRec.start("anomaly_summary")
	report, msgs := analyzeFixture(t, graph)
	points := influxRec.stop()

	suggestions, stpDevice := suggestionRecords(report)
	roots := stpRoots(devices)
	if stpDevice != "" && !slices.Contains(roots, stpDevice) {
		t.Errorf("stp suggestion device %q is not one of the reported root bridges", stpDevice)
	}
	rec := map[string]any{
		"health_score":   report.HealthScore,
		"health_label":   GetHealthLabel(report.HealthScore),
		"summary":        report.Summary,
		"report_nodes":   len(report.Nodes),
		"stp_roots":      roots,
		"last_report":    lastReportRecord(),
		"suggestions":    suggestions,
		"bot_messages":   msgs,
		"influx_written": points,
	}
	checkGolden(t, "analyzer.json", goldenJSON(t, rec, 2))
}
