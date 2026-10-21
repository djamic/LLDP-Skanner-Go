package main

import (
	"context"
	"fmt"
	"sync"
	"time"

	influxdb2 "github.com/influxdata/influxdb-client-go/v2"
	"github.com/influxdata/influxdb-client-go/v2/api"
	"github.com/influxdata/influxdb-client-go/v2/api/write"
)

// InfluxDB configuration
const (
	influxURL    = "http://localhost:8086"
	influxToken  = "lldp-network-monitor-token"
	influxOrg    = "net_monitor"
	influxBucket = "traffic_metrics"
)

var (
	influxClient   influxdb2.Client
	influxWriteAPI api.WriteAPI
	influxMutex    sync.Mutex
	influxEnabled  bool
)

// Test seams: influxReady reports whether points can be written and
// influxWritePoint queues one point. Tests replace both to record points.
var (
	influxReady      = influxWritable
	influxWritePoint = queueInfluxPoint
)

// influxWritable reports whether the client is connected and has a write API.
func influxWritable() bool {
	return influxEnabled && influxWriteAPI != nil
}

// queueInfluxPoint hands one point to the non-blocking write API.
func queueInfluxPoint(p *write.Point) {
	influxWriteAPI.WritePoint(p)
}

// InitInfluxClient initializes the InfluxDB client
func InitInfluxClient() error {
	influxMutex.Lock()
	defer influxMutex.Unlock()

	// Create client
	influxClient = influxdb2.NewClientWithOptions(influxURL, influxToken,
		influxdb2.DefaultOptions().
			SetBatchSize(100).
			SetFlushInterval(5000). // 5 seconds
			SetRetryInterval(5000))

	// Get non-blocking write API
	influxWriteAPI = influxClient.WriteAPI(influxOrg, influxBucket)

	// Handle write errors in background
	go func() {
		for err := range influxWriteAPI.Errors() {
			fmt.Printf("[InfluxDB] Write error: %v\n", err)
		}
	}()

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	health, err := influxClient.Health(ctx)
	if err != nil {
		return fmt.Errorf("InfluxDB health check failed: %v", err)
	}

	if health.Status != "pass" {
		return fmt.Errorf("InfluxDB unhealthy: %s", health.Status)
	}

	influxEnabled = true
	fmt.Println("✅ InfluxDB connected successfully")
	return nil
}

// CloseInfluxClient closes the InfluxDB client
func CloseInfluxClient() {
	influxMutex.Lock()
	defer influxMutex.Unlock()

	if influxClient != nil {
		influxWriteAPI.Flush()
		influxClient.Close()
		influxEnabled = false
		fmt.Println("📊 InfluxDB connection closed")
	}
}

// WriteInterfaceMetric writes interface traffic and diagnostic metrics to InfluxDB
func WriteInterfaceMetric(deviceIP, ifName, ifDescr string,
	inBps, outBps, inOctets, outOctets uint64,
	inErrors, outErrors, inDiscards, outDiscards uint64,
	operStatus int) {
	if !influxReady() {
		return
	}

	// Skip initial baseline polls where no speed is calculated yet
	// This prevents graph starting at 0 and spiking up
	if inBps == 0 && outBps == 0 {
		return
	}

	// Create point with all diagnostic fields
	p := influxdb2.NewPointWithMeasurement("interface_metrics").
		AddTag("device_ip", deviceIP).
		AddTag("if_name", ifName).
		AddTag("if_descr", ifDescr).
		// Traffic speeds
		AddField("in_bps", int64(inBps)).
		AddField("out_bps", int64(outBps)).
		// Raw counters
		AddField("in_octets", int64(inOctets)).
		AddField("out_octets", int64(outOctets)).
		// Diagnostic: Errors (CRC, frame errors - indicates bad cable/SFP)
		AddField("in_errors", int64(inErrors)).
		AddField("out_errors", int64(outErrors)).
		// Diagnostic: Discards (buffer full, congestion)
		AddField("in_discards", int64(inDiscards)).
		AddField("out_discards", int64(outDiscards)).
		// Availability: 1=Up, 2=Down
		AddField("oper_status", operStatus).
		SetTime(time.Now())

	// Write asynchronously
	influxWritePoint(p)
}

// WriteDeviceMetric writes device-level metric
func WriteDeviceMetric(deviceIP, sysName string, interfaceCount, neighborCount int) {
	if !influxReady() {
		return
	}

	p := influxdb2.NewPointWithMeasurement("device_status").
		AddTag("device_ip", deviceIP).
		AddTag("sys_name", sysName).
		AddField("interface_count", interfaceCount).
		AddField("neighbor_count", neighborCount).
		SetTime(time.Now())

	influxWritePoint(p)
}

// ClearInfluxData deletes all data from the InfluxDB bucket
func ClearInfluxData() error {
	if !influxEnabled || influxClient == nil {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Get delete API
	deleteAPI := influxClient.DeleteAPI()

	// Delete all data from bucket (from beginning of time to now)
	start := time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	stop := time.Now().Add(time.Hour)

	// Use DeleteWithName which accepts string org and bucket names
	err := deleteAPI.DeleteWithName(ctx, influxOrg, influxBucket, start, stop, "")
	if err != nil {
		return fmt.Errorf("failed to clear InfluxDB data: %v", err)
	}

	fmt.Println("🗑️ InfluxDB data cleared")
	return nil
}

// IsInfluxEnabled returns whether InfluxDB is connected
func IsInfluxEnabled() bool {
	return influxEnabled
}

// TrafficHistoryPoint represents a single traffic data point
type TrafficHistoryPoint struct {
	Time        string `json:"time"`
	InBps       int64  `json:"in_bps"`
	OutBps      int64  `json:"out_bps"`
	InErrors    int64  `json:"in_errors"`
	OutErrors   int64  `json:"out_errors"`
	InDiscards  int64  `json:"in_discards"`
	OutDiscards int64  `json:"out_discards"`
	IfName      string `json:"if_name"`
}

// QueryTrafficHistory queries InfluxDB for device traffic history
func QueryTrafficHistory(deviceIP string, hours int) ([]TrafficHistoryPoint, error) {
	if !influxEnabled || influxClient == nil {
		return nil, fmt.Errorf("InfluxDB not connected")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Get query API
	queryAPI := influxClient.QueryAPI(influxOrg)

	// Flux query - get last N hours of data for this device
	query := fmt.Sprintf(`
		from(bucket: "%s")
			|> range(start: -%dh)
			|> filter(fn: (r) => r["_measurement"] == "interface_metrics")
			|> filter(fn: (r) => r["device_ip"] == "%s")
			|> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")
			|> sort(columns: ["_time"], desc: false)
	`, influxBucket, hours, deviceIP)

	result, err := queryAPI.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query failed: %v", err)
	}
	defer result.Close()

	var points []TrafficHistoryPoint
	for result.Next() {
		record := result.Record()

		point := TrafficHistoryPoint{
			Time:   record.Time().Format(time.RFC3339),
			IfName: fmt.Sprintf("%v", record.ValueByKey("if_name")),
		}

		// Safely extract values
		if v, ok := record.ValueByKey("in_bps").(int64); ok {
			point.InBps = v
		}
		if v, ok := record.ValueByKey("out_bps").(int64); ok {
			point.OutBps = v
		}
		if v, ok := record.ValueByKey("in_errors").(int64); ok {
			point.InErrors = v
		}
		if v, ok := record.ValueByKey("out_errors").(int64); ok {
			point.OutErrors = v
		}
		if v, ok := record.ValueByKey("in_discards").(int64); ok {
			point.InDiscards = v
		}
		if v, ok := record.ValueByKey("out_discards").(int64); ok {
			point.OutDiscards = v
		}

		points = append(points, point)
	}

	if result.Err() != nil {
		return nil, fmt.Errorf("query error: %v", result.Err())
	}

	return points, nil
}

// QueryRangeMetrics queries InfluxDB for metrics within a specific time range
func QueryRangeMetrics(start, end time.Time) ([]TrafficMetrics, []StatusEvent, error) {
	if !influxEnabled || influxClient == nil {
		return nil, nil, fmt.Errorf("InfluxDB not connected")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	queryAPI := influxClient.QueryAPI(influxOrg)

	// Flux query for metrics
	query := fmt.Sprintf(`
		from(bucket: "%s")
			|> range(start: %s, stop: %s)
			|> filter(fn: (r) => r["_measurement"] == "interface_metrics")
			|> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")
			|> sort(columns: ["_time"], desc: false)
	`, influxBucket, start.Format(time.RFC3339), end.Format(time.RFC3339))

	result, err := queryAPI.Query(ctx, query)
	if err != nil {
		return nil, nil, fmt.Errorf("query failed: %v", err)
	}
	defer result.Close()

	var metrics []TrafficMetrics
	var events []StatusEvent

	for result.Next() {
		record := result.Record()
		
		// Traffic Metrics
		tm := TrafficMetrics{
			Timestamp: record.Time(),
			DeviceIP:  fmt.Sprintf("%v", record.ValueByKey("device_ip")),
			Interface: fmt.Sprintf("%v", record.ValueByKey("if_name")),
		}
		
		if v, ok := record.ValueByKey("in_bps").(int64); ok { tm.InBps = uint64(v) }
		if v, ok := record.ValueByKey("out_bps").(int64); ok { tm.OutBps = uint64(v) }
		if v, ok := record.ValueByKey("in_discards").(int64); ok { tm.InDiscards = uint64(v) }
		if v, ok := record.ValueByKey("out_discards").(int64); ok { tm.OutDiscards = uint64(v) }
		if v, ok := record.ValueByKey("in_errors").(int64); ok { tm.InErrors = uint64(v) }
		if v, ok := record.ValueByKey("out_errors").(int64); ok { tm.OutErrors = uint64(v) }
		
		metrics = append(metrics, tm)

		// Check for status events (Availability analysis)
		if v, ok := record.ValueByKey("oper_status").(int64); ok {
			status := int(v)
			// Ideally we would compare with previous status to detect change,
			// but here we just capturing raw points. Analyzer can deduce events.
			// Or we can query specifically for status changes.
			// For simplicity in this implementation, we just store all points as metrics
			// and let Analyzer detect transitions.
			tm.OperStatus = status
		}
	}

	if result.Err() != nil {
		return nil, nil, fmt.Errorf("query error: %v", result.Err())
	}

	return metrics, events, nil
}

// ============================================================
// B.2 — DEVICE_JOIN / DEVICE_LEAVE events
// ============================================================

// WriteDeviceEvent writes a device join or leave event to InfluxDB
func WriteDeviceEvent(eventType, mac, ip, switchIP, vendor string) {
	if !influxReady() {
		return
	}

	p := influxdb2.NewPointWithMeasurement("device_events").
		AddTag("event_type", eventType). // "join" or "leave"
		AddTag("vendor", vendor).
		AddField("mac", mac).
		AddField("ip", ip).
		AddField("switch_ip", switchIP).
		SetTime(time.Now())

	influxWritePoint(p)
}

// ============================================================
// B.3 — Network Summary metric
// ============================================================

// WriteNetworkSummary writes overall network state to InfluxDB
func WriteNetworkSummary(activeHosts, uniqueMACs, shadowITPorts, healthScore, randomMACs int) {
	if !influxReady() {
		return
	}

	p := influxdb2.NewPointWithMeasurement("network_summary").
		AddField("active_hosts", activeHosts).
		AddField("unique_macs", uniqueMACs).
		AddField("shadow_it_ports", shadowITPorts).
		AddField("health_score", healthScore).
		AddField("random_macs", randomMACs). // Populated in Phase 3 (isRandomMAC)
		SetTime(time.Now())

	influxWritePoint(p)
}

// ============================================================
// B.4 — Anomaly Summary metric
// ============================================================

// WriteAnomalySummary writes anomaly counts per type to InfluxDB
func WriteAnomalySummary(report *Report) {
	if !influxReady() {
		return
	}
	if report == nil {
		return
	}

	p := influxdb2.NewPointWithMeasurement("anomaly_summary").
		AddField("shadow_it_count", report.Summary["shadow_it_issues"]).
		AddField("loopback_count", report.Summary["loopback_issues"]).
		AddField("congestion_count", report.Summary["congestion_issues"]).
		AddField("flapping_count", report.Summary["stability_issues"]).
		AddField("stp_count", report.Summary["stp_issues"]).
		AddField("path_count", report.Summary["path_issues"]).
		SetTime(time.Now())

	influxWritePoint(p)
}

// ============================================================
// Phase 14 — Network Event History (Persistent InfluxDB Storage)
// ============================================================

// NetworkEventRecord represents an event read from InfluxDB
type NetworkEventRecord struct {
	Time      string `json:"time"`
	Type      string `json:"type"`
	SwitchIP  string `json:"switch_ip,omitempty"`
	Port      int    `json:"port,omitempty"`
	MAC       string `json:"mac,omitempty"`
	IP        string `json:"ip,omitempty"`
	Vendor    string `json:"vendor,omitempty"`
	Message   string `json:"message"`
	DurationS *int   `json:"duration_s,omitempty"` // nil = open event, value = closed
}

// EventStats holds uptime/downtime statistics for a device
type EventStats struct {
	Device              string                   `json:"device"`
	Hours               int                      `json:"hours"`
	PortDownCount       int                      `json:"port_down_count"`
	UnreachableCount    int                      `json:"unreachable_count"`
	LongestOutageMin    float64                  `json:"longest_outage_minutes"`
	ByPort              map[int]PortEventSummary `json:"by_port,omitempty"`
}

// PortEventSummary holds per-port down count and total down time
type PortEventSummary struct {
	DownCount        int     `json:"down_count"`
	TotalDownMinutes float64 `json:"total_down_minutes"`
}

// WriteNetworkEventToInflux writes a single network event to InfluxDB
func WriteNetworkEventToInflux(evt NetworkEvent, durationS int) {
	if !influxReady() {
		return
	}

	// Use SwitchIP if available, otherwise fall back to IP
	switchIPTag := evt.SwitchIP
	if switchIPTag == "" {
		switchIPTag = evt.IP
	}

	p := influxdb2.NewPointWithMeasurement("network_events").
		AddTag("event_type", evt.Type).
		AddTag("switch_ip", switchIPTag).
		AddField("message", evt.Message)

	if evt.Port > 0 {
		p.AddTag("port", fmt.Sprintf("%d", evt.Port))
	}
	if evt.MAC != "" {
		p.AddTag("mac", evt.MAC)
	}
	if evt.IP != "" {
		p.AddField("ip", evt.IP)
	}
	if evt.Vendor != "" {
		p.AddField("vendor", evt.Vendor)
	}
	if durationS > 0 {
		p.AddField("duration_s", durationS)
	}

	p.SetTime(time.Now())
	influxWritePoint(p)
}

// QueryNetworkEvents queries InfluxDB for network events with filters
func QueryNetworkEvents(ip string, hours int, eventTypes []string, portFilter int) ([]NetworkEventRecord, error) {
	if !influxEnabled || influxClient == nil {
		return nil, fmt.Errorf("InfluxDB not connected")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	queryAPI := influxClient.QueryAPI(influxOrg)

	// Build Flux query
	filters := fmt.Sprintf(`r["_measurement"] == "network_events"`)
	if ip != "" {
		filters += fmt.Sprintf(` and r["switch_ip"] == "%s"`, ip)
	}
	if portFilter > 0 {
		filters += fmt.Sprintf(` and r["port"] == "%d"`, portFilter)
	}

	// Event type filter
	if len(eventTypes) > 0 {
		typeFilter := ""
		for i, t := range eventTypes {
			if i > 0 {
				typeFilter += " or "
			}
			typeFilter += fmt.Sprintf(`r["event_type"] == "%s"`, t)
		}
		filters += fmt.Sprintf(` and (%s)`, typeFilter)
	}

	query := fmt.Sprintf(`
		from(bucket: "%s")
			|> range(start: -%dh)
			|> filter(fn: (r) => %s)
			|> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")
			|> sort(columns: ["_time"], desc: true)
			|> limit(n: 500)
	`, influxBucket, hours, filters)

	result, err := queryAPI.Query(ctx, query)
	if err != nil {
		return nil, fmt.Errorf("query failed: %v", err)
	}
	defer result.Close()

	var events []NetworkEventRecord
	for result.Next() {
		record := result.Record()

		evt := NetworkEventRecord{
			Time:     record.Time().Format(time.RFC3339),
			Type:     fmt.Sprintf("%v", record.ValueByKey("event_type")),
			SwitchIP: fmt.Sprintf("%v", record.ValueByKey("switch_ip")),
		}

		if v := record.ValueByKey("message"); v != nil {
			evt.Message = fmt.Sprintf("%v", v)
		}
		if v := record.ValueByKey("ip"); v != nil {
			evt.IP = fmt.Sprintf("%v", v)
		}
		if v := record.ValueByKey("vendor"); v != nil {
			evt.Vendor = fmt.Sprintf("%v", v)
		}
		if v := record.ValueByKey("mac"); v != nil {
			evt.MAC = fmt.Sprintf("%v", v)
		}
		if v := record.ValueByKey("port"); v != nil {
			if ps, ok := v.(string); ok {
				if pn, err2 := fmt.Sscanf(ps, "%d", new(int)); err2 == nil && pn > 0 {
					fmt.Sscanf(ps, "%d", &evt.Port)
				}
			}
		}
		if v, ok := record.ValueByKey("duration_s").(int64); ok {
			d := int(v)
			evt.DurationS = &d
		}

		events = append(events, evt)
	}

	if result.Err() != nil {
		return nil, fmt.Errorf("query error: %v", result.Err())
	}

	return events, nil
}

// DeleteNetworkEventsRange deletes network events in a time range from InfluxDB
func DeleteNetworkEventsRange(from, to time.Time) error {
	if !influxEnabled || influxClient == nil {
		return fmt.Errorf("InfluxDB not connected")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	deleteAPI := influxClient.DeleteAPI()
	predicate := `_measurement="network_events"`
	err := deleteAPI.DeleteWithName(ctx, influxOrg, influxBucket, from, to, predicate)
	if err != nil {
		return fmt.Errorf("failed to delete network events: %v", err)
	}

	return nil
}

// DeleteAllNetworkEvents deletes all network events from InfluxDB
func DeleteAllNetworkEvents() error {
	start := time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	stop := time.Now().Add(time.Hour)
	return DeleteNetworkEventsRange(start, stop)
}

