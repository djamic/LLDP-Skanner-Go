package main

import (
	"encoding/json"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestUIHistoryPage runs testdata/ui/history_probe.js: static/history.html
// opened for a device on a switch port, for a port it cannot find and for
// a switch with its uplink. Skipped when Node.js is not installed.
func TestUIHistoryPage(t *testing.T) {
	node := nodeBinary(t)
	cmd := exec.Command(node, filepath.Join("testdata", "ui", "history_probe.js"), filepath.Join("static", "history.html"))
	cmd.Env = []string{}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("history_probe.js: %v\n%s", err, out)
	}
}

// TestFluxString checks that a value goes into a Flux query as one string
// literal: quotes, backslashes and "${" interpolation are escaped.
func TestFluxString(t *testing.T) {
	for in, want := range map[string]string{
		"172.20.230.50":             `"172.20.230.50"`,
		`"GigabitEthernet1/0/15"`:   `"\"GigabitEthernet1/0/15\""`,
		`a\b`:                       `"a\\b"`,
		`x" or r._measurement != "`: `"x\" or r._measurement != \""`,
		"${r._value}":               `"\${r._value}"`,
		"":                          `""`,
	} {
		if got := fluxString(in); got != want {
			t.Errorf("fluxString(%q) = %s, want %s", in, got, want)
		}
	}
}

// TestTrafficHistoryQuery pins the query of a whole device, of one port
// (its if_name tag as polled, quotes and all) and the aggregation windows.
func TestTrafficHistoryQuery(t *testing.T) {
	whole := trafficHistoryQuery("172.20.230.50", "", 24)
	if want := `|> filter(fn: (r) => r["_measurement"] == "interface_metrics" and r["device_ip"] == "172.20.230.50")
			|> pivot(`; !strings.Contains(whole, want) {
		t.Errorf("whole device, 24h: %s\nwant %s", whole, want)
	}
	if !strings.Contains(whole, `from(bucket: "traffic_metrics")`) || !strings.Contains(whole, "range(start: -24h)") ||
		strings.Contains(whole, "aggregateWindow") || strings.Contains(whole, "if_name") {
		t.Errorf("whole device, 24h: %s", whole)
	}

	port := trafficHistoryQuery("172.20.230.50", `"GigabitEthernet1/0/15"`, 168)
	if want := `r["device_ip"] == "172.20.230.50" and r["if_name"] == "\"GigabitEthernet1/0/15\"")
			|> aggregateWindow(every: 5m, fn: max, createEmpty: false)
			|> pivot(`; !strings.Contains(port, want) {
		t.Errorf("one port, 7 days: %s\nwant %s", port, want)
	}
	if month := trafficHistoryQuery("10.0.0.1", "", 720); !strings.Contains(month, "aggregateWindow(every: 30m, fn: max") {
		t.Errorf("30 days: %s", month)
	}

	hostile := trafficHistoryQuery(`1.2.3.4") or (r) => true or ("`, "", 1)
	if !strings.Contains(hostile, `r["device_ip"] == "1.2.3.4\") or (r) => true or (\"")`) {
		t.Errorf("a hostile id is not one string literal: %s", hostile)
	}

	for hours, want := range map[int]string{1: "", 6: "", 24: "", 25: "5m", 168: "5m", 169: "30m", 720: "30m"} {
		if got := historyWindow(hours); got != want {
			t.Errorf("historyWindow(%d) = %q, want %q", hours, got, want)
		}
	}
}

// historyTestSwitch is a polled switch with the IfDescr the agents send:
// quoted, the long names.
func historyTestSwitch() *DeviceData {
	return &DeviceData{IP: "10.0.1.2", SysName: "dist-2", Interfaces: []InterfaceData{
		{IfIndex: 5, IfDescr: `"GigabitEthernet1/0/5"`, IfOperStatus: 1},
		{IfIndex: 52, IfDescr: `"Ten-GigabitEthernet1/0/52"`, IfOperStatus: 1},
		{IfIndex: 600, IfDescr: `"Vlan-interface10"`, IfOperStatus: 1},
	}}
}

// TestHistoryPort checks that a port as a graph link names it, or as the
// IfDescr, finds the interface of the polled switch.
func TestHistoryPort(t *testing.T) {
	resetState(t)
	collectedDataMutex.Lock()
	collectedData["10.0.1.2"] = historyTestSwitch()
	collectedDataMutex.Unlock()

	for port, want := range map[string]int{
		"GE1/0/5":                   5,
		"ge1/0/5":                   5,
		"GigabitEthernet1/0/5":      5,
		`"GigabitEthernet1/0/5"`:    5,
		"TGE1/0/52":                 52,
		"Ten-GigabitEthernet1/0/52": 52,
		"Vlan-interface10":          600,
	} {
		if iface, ok := historyPort("10.0.1.2", port); !ok || iface.IfIndex != want {
			t.Errorf("historyPort(%q) = %d %v, want ifIndex %d", port, iface.IfIndex, ok, want)
		}
	}
	for _, c := range []struct{ ip, port string }{
		{"10.0.1.2", "GE1/0/6"},
		{"10.0.1.2", "GE1/0/50"},
		{"10.0.1.2", ""},
		{"10.0.1.2", `""`},
		{"10.0.1.9", "GE1/0/5"}, // not a polled device
	} {
		if iface, ok := historyPort(c.ip, c.port); ok {
			t.Errorf("historyPort(%q, %q) found ifIndex %d", c.ip, c.port, iface.IfIndex)
		}
	}
}

// TestHistoryHandlerPort checks the answer of /api/history for one port:
// the port it found, or why there is no data, and the window.
// InfluxDB is not connected in the tests, so the data is empty.
func TestHistoryHandlerPort(t *testing.T) {
	resetState(t)
	collectedDataMutex.Lock()
	collectedData["10.0.1.2"] = historyTestSwitch()
	collectedDataMutex.Unlock()

	get := func(query string) map[string]any {
		t.Helper()
		w := httptest.NewRecorder()
		historyHandler(w, httptest.NewRequest("GET", "/api/history?"+query, nil))
		var resp map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("%s: %v\n%s", query, err, w.Body.String())
		}
		return resp
	}

	resp := get("id=10.0.1.2&hours=168&port=GE1%2F0%2F5")
	port, _ := resp["port"].(map[string]any)
	if port == nil || port["name"] != "GE1/0/5" || port["if_name"] != `"GigabitEthernet1/0/5"` || port["if_index"] != float64(5) {
		t.Errorf("port: %v", resp)
	}
	if resp["window"] != "5m" || resp["port_error"] != nil || resp["error"] != "InfluxDB not connected" || resp["device"] != "10.0.1.2" {
		t.Errorf("answer: %v", resp)
	}

	// a port it does not find: no data (not the other ports), no query
	resp = get("id=10.0.1.2&port=GE1%2F0%2F9")
	if data, _ := resp["data"].([]any); resp["port"] != nil || resp["port_error"] != "10.0.1.2 has no port GE1/0/9" ||
		data == nil || len(data) != 0 || resp["count"] != float64(0) || resp["error"] != nil || resp["hours"] != float64(24) {
		t.Errorf("unknown port: %v", resp)
	}

	resp = get("id=10.0.1.2&hours=720")
	if resp["port"] != nil || resp["port_error"] != nil || resp["window"] != "30m" {
		t.Errorf("whole device: %v", resp)
	}
}

// TestTrafficCountersWriteIdleUpPorts checks the points updateTrafficCounters
// writes: an idle up port gets 0 bps (no gap in its history), a down port
// with no traffic none, and a counter glitch on both directions none.
func TestTrafficCountersWriteIdleUpPorts(t *testing.T) {
	resetState(t)
	const ip = "10.0.1.2"
	ifaces := []InterfaceData{
		{IfIndex: 1, IfDescr: `"GE-busy"`, IfOperStatus: 1, IfSpeed: 1_000_000_000, IfInOctets: 1_000_000 + 7_500_000, IfOutOctets: 2_000_000},
		{IfIndex: 2, IfDescr: `"GE-idle"`, IfOperStatus: 1, IfSpeed: 1_000_000_000, IfInOctets: 500, IfOutOctets: 600},
		{IfIndex: 3, IfDescr: `"GE-down"`, IfOperStatus: 2, IfSpeed: 1_000_000_000, IfInOctets: 0, IfOutOctets: 0},
		{IfIndex: 4, IfDescr: `"GE-glitch"`, IfOperStatus: 1, IfSpeed: 10_000_000, IfInOctets: 1 << 40, IfOutOctets: 1 << 40},
	}
	// the baseline of the poll a minute ago
	before := time.Now().Add(-60 * time.Second)
	interfaceTrafficMapMutex.Lock()
	interfaceTrafficMap[ip] = map[int]*InterfaceTraffic{
		1: {LastInOctets: 1_000_000, LastOutOctets: 2_000_000, LastPollTime: before},
		2: {LastInOctets: 500, LastOutOctets: 600, LastPollTime: before},
		3: {LastPollTime: before},
		4: {LastPollTime: before},
	}
	interfaceTrafficMapMutex.Unlock()

	influxRec.start("interface_metrics")
	updateTrafficCounters(ip, ifaces)
	points := influxRec.stop()

	got := map[string]map[string]any{}
	for _, p := range points {
		got[p.Tags["if_name"]] = p.Fields
	}
	if len(got) != 2 || got[`"GE-busy"`] == nil || got[`"GE-idle"`] == nil {
		t.Fatalf("points for %v, want GE-busy and GE-idle only", got)
	}
	if in, _ := got[`"GE-busy"`]["in_bps"].(int64); in < 900_000 || in > 1_100_000 {
		t.Errorf("GE-busy in_bps = %v, want about 1 Mbps", got[`"GE-busy"`]["in_bps"])
	}
	if f := got[`"GE-idle"`]; f["in_bps"] != int64(0) || f["out_bps"] != int64(0) || f["oper_status"] != int64(1) {
		t.Errorf("GE-idle: %v, want 0 bps up", f)
	}
}
