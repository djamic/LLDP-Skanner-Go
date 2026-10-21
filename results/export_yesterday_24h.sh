#!/bin/bash
# ============================================================
# Kechagi 24 soat (10-Aprel 05:00 dan 11-Aprel 05:00 gacha) InfluxDB dan export
# ============================================================

INFLUX_URL="http://localhost:8086"
TOKEN="lldp-network-monitor-token"
ORG="net_monitor"
BUCKET="traffic_metrics"
OUT_DIR="results/yesterday_24h"

mkdir -p "$OUT_DIR"

# Vaqt oraliqlari (UTC hisobida, +5 soat farqi bilan 05:00 -> 00:00Z ga aylanadi)
START_TIME="2026-04-10T00:00:00Z"
STOP_TIME="2026-04-11T00:00:00Z"

query_influx() {
  local name="$1"
  local flux="$2"
  echo "📊 Exporting: $name (Start: $START_TIME, Stop: $STOP_TIME)..."
  curl -s -X POST "$INFLUX_URL/api/v2/query?org=$ORG" \
    -H "Authorization: Token $TOKEN" \
    -H "Accept: text/csv" \
    -H "Content-Type: application/vnd.flux" \
    -d "$flux" > "$OUT_DIR/${name}.csv"
  lines=$(wc -l < "$OUT_DIR/${name}.csv")
  echo "   ✅ $name: $lines rows → $OUT_DIR/${name}.csv"
}

# 1. Active Hosts
query_influx "active_hosts" '
from(bucket: "'"$BUCKET"'")
  |> range(start: '"$START_TIME"', stop: '"$STOP_TIME"')
  |> filter(fn: (r) => r._measurement == "network_summary")
  |> filter(fn: (r) => r._field == "active_hosts")
  |> sort(columns: ["_time"])
'

# 2. Health Score
query_influx "health_score" '
from(bucket: "'"$BUCKET"'")
  |> range(start: '"$START_TIME"', stop: '"$STOP_TIME"')
  |> filter(fn: (r) => r._measurement == "network_summary")
  |> filter(fn: (r) => r._field == "health_score")
  |> sort(columns: ["_time"])
'

# 3. Device Events
query_influx "device_events" '
from(bucket: "'"$BUCKET"'")
  |> range(start: '"$START_TIME"', stop: '"$STOP_TIME"')
  |> filter(fn: (r) => r._measurement == "device_events")
  |> group(columns: ["event_type"])
  |> sort(columns: ["_time"])
'

# 4. Anomaly Summary
query_influx "anomaly_summary" '
from(bucket: "'"$BUCKET"'")
  |> range(start: '"$START_TIME"', stop: '"$STOP_TIME"')
  |> filter(fn: (r) => r._measurement == "anomaly_summary")
  |> pivot(rowKey: ["_time"], columnKey: ["_field"], valueColumn: "_value")
  |> sort(columns: ["_time"])
'

# 5. Traffic Metrics (aggregated window: 5 minutes)
query_influx "traffic_metrics" '
from(bucket: "'"$BUCKET"'")
  |> range(start: '"$START_TIME"', stop: '"$STOP_TIME"')
  |> filter(fn: (r) => r._measurement == "interface_metrics")
  |> filter(fn: (r) => r._field == "in_bps" or r._field == "out_bps")
  |> aggregateWindow(every: 5m, fn: mean)
  |> sort(columns: ["_time"])
'

echo "============================================================"
echo "✅ Kechagi 24 soatlik ma'lumotlar eksporti tugadi:"
echo "============================================================"
ls -la "$OUT_DIR"/*.csv
