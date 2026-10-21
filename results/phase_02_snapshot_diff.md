# Phase 2: Snapshot Diff Engine — Natijalar

**Holat:** ✅ Bajarilgan  
**Sana:** 2026-03-26

## Maqsad
Tarmoq holatini vaqti-vaqti bilan snapshot qilib, o'zgarishlarni (DEVICE_JOIN/LEAVE) aniqlash.

## Bajarilgan ishlar

### B.1 — Snapshot Diff Engine
- `snapshot_diff.go` → `CreateSnapshot()` + `CompareSnapshots()`
- **NetworkSnapshot** strukturasi:
  - `ActiveMACs` — barcha MAC manzillar (IP, Switch, Port, Vendor bilan)
  - `ActiveHosts` — SNMP-reachable hostlar (SysName, Vendor, Health)
  - `Anomalies` — har qurilma uchun anomaliya ro'yxati
  - `HealthScore`, `GraphNodes`, `GraphEdges`

### B.2 — DEVICE_JOIN / DEVICE_LEAVE
- `SnapshotDiff` → JoinedMACs, LeftMACs, NewHosts, LostHosts
- `NewAnomalies`, `FixedAnomalies` — anomaliya o'zgarishlari
- `HealthDelta`, `MACCountDelta` — umumiy o'zgarish
- InfluxDB ga `device_events` measurement yozish

### B.3 — Network Summary
- `WriteNetworkSummary()` → InfluxDB ga umumiy holat
- Fields: active_hosts, unique_macs, shadow_it_ports, health_score, random_macs

### B.4 — Anomaly Summary
- `WriteAnomalySummary()` → InfluxDB ga anomaliya statistikasi
- Fields: shadow_it_count, loopback_count, congestion_count, flapping_count, stp_count, path_count

### Network Events Panel
- `AddNetworkEvent()` → 200 ta event log (FIFO)
- Event turlari: join, leave, host_up, host_down, anomaly, fixed
- `/api/events` endpoint orqali UI da ko'rinadi

## Asosiy fayllar
| Fayl | Tavsif |
|------|--------|
| `snapshot_diff.go` | Snapshot diff engine (449 qator) |
| `influx_client.go` | InfluxDB yozish (374 qator) |
