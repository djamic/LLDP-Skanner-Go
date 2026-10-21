package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"testing"
	"time"
)

// exportTimes matches the timestamps the export files carry.
var exportTimes = regexp.MustCompile(`"(export_time|experiment_date|date|detect_time|notify_time)": "[^"]*"|"(latency_ms|average_latency_ms|max_latency_ms)": [0-9.]+`)

// TestProductionOrderDeterminism runs the producers whose output can depend
// on map iteration order with production settings: the devices taken from
// collectedData in map order, as main() passes them. Each producer runs
// several times on the same input, and the raw output bytes (timestamps
// blanked) must be equal. A producer with a reason is known to depend on map
// order and is skipped when its runs differ; since Q16 none has one, so this
// test guards all of them. The graph build itself is checked by
// TestGoldenGraph (two builds).
func TestProductionOrderDeterminism(t *testing.T) {
	graph := buildFixtureGraph(t)
	SetGlobalGraph(graph)
	dir := t.TempDir()
	graphDebugFile = filepath.Join(dir, "graphs_data.txt")
	exportsDir = filepath.Join(dir, "results")

	mapOrder := func() []*DeviceData {
		collectedDataMutex.RLock()
		defer collectedDataMutex.RUnlock()
		devices := make([]*DeviceData, 0, len(collectedData))
		for _, d := range collectedData {
			devices = append(devices, d)
		}
		return devices
	}
	analyze := func() Report {
		resetBot()
		data := FullCaptureData{
			Session:     CaptureSession{ID: "live", Name: "Live", StartTime: fixedTime},
			DevicesData: deviceValues(mapOrder()),
			Topology:    graph.GetGraphData(),
		}
		report := NewAnalyzer(data).Analyze()
		bot.taken()
		report.GeneratedAt = time.Time{}
		return report
	}
	report := analyze()
	marshal := func(v any) []byte {
		data, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	readFile := func(name string) []byte {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return exportTimes.ReplaceAll(data, []byte(`"<time>"`))
	}

	producers := []struct {
		name  string
		known string // why the output depends on map order today
		run   func() []byte
	}{
		{"analyzer_health_and_issue_set", "", func() []byte {
			r := analyze()
			var ids []string
			for _, s := range r.Suggestions {
				if s.Type != "stp" {
					ids = append(ids, s.Type+" "+s.IssueID+" "+s.Device+" "+s.Value)
				}
			}
			slices.Sort(ids)
			return marshal(map[string]any{"health": r.HealthScore, "summary": r.Summary, "issues": ids})
		}},
		{"analyzer_report", "", func() []byte {
			return marshal(analyze())
		}},
		{"GetGraphData", "", func() []byte {
			return marshal(graph.GetGraphData())
		}},
		{"api_graph", "", func() []byte {
			return []byte(serveGraph())
		}},
		{"snapshot", "", func() []byte {
			s := CreateSnapshot(mapOrder(), graph, &report)
			s.Timestamp = time.Time{}
			return marshal(s)
		}},
		{"bfs_depths", "", func() []byte {
			ExportBFSDepths(graph)
			return readFile("results/bfs_depths.json")
		}},
		{"zabbix_hosts", "", func() []byte {
			if err := graph.ExportHostsToZabbix(filepath.Join(dir, "zabbix_hosts.json")); err != nil {
				t.Fatal(err)
			}
			return readFile("zabbix_hosts.json")
		}},
		{"zabbix_map", "", func() []byte {
			if err := graph.ExportToMap(filepath.Join(dir, "zabbix_map.json")); err != nil {
				t.Fatal(err)
			}
			return readFile("zabbix_map.json")
		}},
		{"audit_md", "", func() []byte {
			md := generateAuditMD([]string{"switch", "hub"})
			md = auditDateLine.ReplaceAllString(md, "Sana: <time>")
			return []byte(auditScanTime.ReplaceAllString(md, "| Skanerlash vaqti | <time> |"))
		}},
		{"experiment_exports", "", func() []byte {
			resetBot()
			generateExperimentReport(mapOrder(), expScanDuration, expCollectionDuration, expTotalDuration, graph)
			bot.taken()
			var all []byte
			for _, name := range []string{"experiment_metrics.json", "health_scores.json", "bfs_depths.json", "vendor_stats.json", "telegram_timing.json"} {
				all = append(all, readFile("results/"+name)...)
			}
			return all
		}},
	}
	const runs = 4
	for _, p := range producers {
		t.Run(p.name, func(t *testing.T) {
			first := p.run()
			for i := 2; i <= runs; i++ {
				if got := p.run(); !bytes.Equal(got, first) {
					if p.known != "" {
						t.Skipf("depends on map order until Q16: %s", p.known)
					}
					t.Fatalf("run %d differs from run 1: %s", i, firstDifference(first, got))
				}
			}
			if p.known != "" {
				t.Logf("%d runs gave the same output; if that keeps holding, drop the known reason (%s)", runs, p.known)
			}
		})
	}
}

// firstDifference shows where two outputs start to differ.
func firstDifference(a, b []byte) string {
	i := 0
	for i < len(a) && i < len(b) && a[i] == b[i] {
		i++
	}
	from := max(i-80, 0)
	return fmt.Sprintf("at byte %d:\n  run 1: %q\n  later: %q", i, a[from:min(i+120, len(a))], b[from:min(i+120, len(b))])
}
