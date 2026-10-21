# Phase 14 — Network Event History (Doimiy Saqlash, Vizualizatsiya va Boshqaruv)

## Maqsad

`monitor24h` rejimida aniqlanadigan **barcha** tarmoq hodisalari (port UP/DOWN, switch
unreachable/restored, MAC join/leave, anomaliya) hozirda faqat **RAM da 200 ta** cheklangan log
sifatida saqlanadi va restart bo'lsa butunlay yo'qoladi.

Bu faza uchta asosiy yo'nalishda kengayadi:

1. **Doimiy saqlash** — barcha event turlari InfluxDB ga yoziladi
2. **Vizualizatsiya** — `history.html` da vaqt bo'yicha timeline va jadval
3. **Boshqaruv** — Clear All va oraliq bo'yicha Clear imkoniyatlari

---

## Holat

| Belgi | Ma'nosi |
|-------|---------|
| ✅ | Implement qilingan |
| 🔲 | Bu fazada implement qilinadi |

**Joriy holat (2026-03-28):** Backend to'liq ✅ | Frontend asosiy jadval ✅ | Gantt chart 🔲

---

## 1. Saqlaniladigan Event Turlari

### 1.1 Port Hodisalari
| Event turi | Trigger | Misol |
|-----------|---------|-------|
| `port_down` | Port oper status 1→2 | Port DOWN: 172.20.230.49 port 11 |
| `port_up`   | Port oper status 2→1 | Port UP: 172.20.230.49 port 11 |

### 1.2 Switch Hodisalari
| Event turi | Trigger | Misol |
|-----------|---------|-------|
| `unreachable` | SNMP walk 7/7 fail | Switch unreachable: 172.20.230.4 |
| `restored`    | SNMP walk muvaffaqiyatli | Switch restored: 172.20.230.4 |

### 1.3 MAC/Host Hodisalari
| Event turi | Trigger | Misol |
|-----------|---------|-------|
| `join`      | Yangi MAC MAC-table da paydo bo'ldi | 6e:3b:85:... → 172.15.182.90 on .46:48 |
| `leave`     | MAC MAC-table dan yo'qoldi | aa:bb:cc:... left .46:12 |
| `host_down` | Host SNMP ga javob bermadi | Host down: 172.20.230.15 |
| `host_up`   | Host qayta javob berdi | Host up: 172.20.230.15 |

### 1.4 Anomaliya Hodisalari
| Event turi | Trigger | Misol |
|-----------|---------|-------|
| `anomaly` | Yangi shadow_it/loopback/stp | Anomaly: shadow_it on 172.20.230.36 |
| `fixed`   | Anomaliya yo'qoldi | Fixed: shadow_it on 172.20.230.36 |

---

## 2. InfluxDB Saqlash Strukturasi

### Measurement: `network_events`
```
tags:
  event_type  = "port_down" | "port_up" | "unreachable" | "restored" |
                "join" | "leave" | "host_down" | "host_up" | "anomaly" | "fixed"
  switch_ip   = "172.20.230.49"     (switch IP, bo'lsa)
  port        = "11"                (port raqami, bo'lsa)
  mac         = "6e:3b:85:cb:36:55" (MAC, bo'lsa)

fields:
  message     = "Port DOWN: 172.20.230.49 port 11"
  ip          = "172.15.182.90"     (qurilma IP, bo'lsa)
  vendor      = "HPE"               (MAC vendor, bo'lsa)
  duration_s  = 226                 (soniya, faqat *_up da: oldingi down vaqtidan hisob)

time: RFC3339 (UTC)
```

### Duration hisoblash logic
```
port_down @ T1 → InfluxDB ga yoz, "open_events" cache ga qo'sh
port_up   @ T2 → duration_s = T2 - T1, InfluxDB ga yoz (duration bilan)
           → "open_events" cache dan o'chir

unreachable @ T1 → "open_events" cache ga qo'sh
restored    @ T2 → duration_s = T2 - T1 → InfluxDB ga yoz
```

---

## 3. API Endpointlar

### 3.1 Event tarixi olish
```
GET /api/port-events?ip=172.20.230.49&hours=24&type=port_down,port_up
```
```json
{
  "device": "172.20.230.49",
  "hours": 24,
  "total": 14,
  "events": [
    {
      "time": "2026-03-28T19:47:28Z",
      "type": "port_down",
      "port": 11,
      "message": "Port DOWN: 172.20.230.49 port 11",
      "duration_s": null
    },
    {
      "time": "2026-03-28T19:51:14Z",
      "type": "port_up",
      "port": 11,
      "message": "Port UP: 172.20.230.49 port 11",
      "duration_s": 226
    }
  ]
}
```

**Query parametrlari:**
| Parametr | Default | Tavsif |
|----------|---------|--------|
| `ip` | — (majburiy) | Switch/qurilma IP |
| `hours` | 24 | Necha soat orqaga |
| `type` | (hammasi) | Vergul bilan ajratilgan event turlari |
| `port` | (hammasi) | Faqat muayyan port raqami |
| `from` | — | ISO datetime (oraliq filtri) |
| `to` | — | ISO datetime (oraliq filtri) |

---

### 3.2 Barcha eventlarni o'chirish (Clear All)
```
DELETE /api/port-events
```
```json
{ "status": "ok", "deleted": 1842, "message": "All network events cleared from InfluxDB" }
```

---

### 3.3 Oraliq bo'yicha o'chirish (Clear Range)
```
DELETE /api/port-events?from=2026-03-28T00:00:00Z&to=2026-03-28T12:00:00Z
```
```json
{
  "status": "ok",
  "deleted": 437,
  "range": {
    "from": "2026-03-28T00:00:00Z",
    "to":   "2026-03-28T12:00:00Z"
  },
  "message": "Events in range cleared"
}
```

---

### 3.4 Umumiy statistika
```
GET /api/port-events/stats?ip=172.20.230.49&hours=24
```
```json
{
  "device": "172.20.230.49",
  "hours": 24,
  "uptime_percent": 97.4,
  "downtime_minutes": 37.8,
  "port_down_count": 5,
  "unreachable_count": 1,
  "longest_outage_minutes": 18.2,
  "by_port": {
    "11": { "down_count": 2, "total_down_minutes": 6.5 },
    "40": { "down_count": 3, "total_down_minutes": 31.3 }
  }
}
```

---

## 4. history.html Vizualizatsiya

### 4.1 Tab tizimi

```
[ 📊 Traffic History ]  [ 🔌 Port Events ]  [ 📋 Switch Log ]
```

---

### 4.2 "Port Events" Tab

#### Port Timeline Grafigi (D3.js Gantt-style)
```
         12:00      15:00      18:00      21:00      00:00
Port 11  ▐████████████████████████░░░░░░███████████████▌ UP 97%
Port 40  ▐████████░░░░░░░░░░░░░░░░░░░░░░████████████████▌ UP 61%
Port 22  ▐████████████████████████████████████████░░░░░▌ UP 94%

         ██ = UP (yashil)   ░░ = DOWN (qizil)
```

- X o'qi: vaqt (so'nggi N soat)
- Y o'qi: port raqamlari (faqat kamida 1 marta event bo'lgan portlar)
- Hover: "Port 11 o'chiq edi: 3 daqiqa 46 soniya (19:47 - 19:51)"
- Click → o'sha portga filtr qo'yiladi  

#### Event Jadvali (Table)

| Vaqt | Tur | Port | Davomiyligi | Xabar |
|------|-----|------|------------|-------|
| 19:47:28 | 🔴 port_down | 11 | — | Port DOWN: ...49 port 11 |
| 19:51:14 | 🟢 port_up | 11 | 3 min 46 s | Port UP: ...49 port 11 |
| 19:47:28 | 🔴 port_down | 40 | — | Port DOWN: ...15 port 40 |

**Filtrlar:**
- IP bo'yicha
- Event turi bo'yicha checkbox (port_down ✅, port_up ✅, unreachable ✅, ...)
- Vaqt oralig'i (DateTimePicker)
- **"Clear Range"** tugmasi (tanlangan oraliqni o'chirish)
- **"Clear All"** tugmasi (confirm dialog bilan)

---

### 4.3 "Switch Log" Tab

#### Switch Availability Timeline

```
172.20.230.49  ▐████████████████████████████▌ 99.8% uptime  ▲ 1 outage
172.20.230.15  ▐████████████████░░░░░░███████▌ 84.5% uptime  ▲ 3 outages
172.20.230.50  ▐██████████████████████████░░░▌ 96.3% uptime  ▲ 1 outage
```

- Har switch uchun **uptime %**
- Outage soni va umumiy downtime
- Eng uzun uzilish davomiyligi

#### Unreachable Log Jadvali

| Vaqt | Switch | Davomiyligi | Sabab |
|------|--------|------------|-------|
| 12:01:05 | 172.20.230.15 | 18 min 12 s | All SNMP walks failed (7/7) |
| 14:33:48 | 172.20.230.49 | 2 min 05 s | All SNMP walks failed (7/7) |

---

## 5. Implement Qilish Ketma-ketligi

### A. Backend (Go)

#### A1. `influx_client.go`
```go
// Yangi funksiyalar:
func WriteNetworkEvent(evt NetworkEvent) error
func QueryNetworkEvents(ip string, hours int, types []string) ([]NetworkEvent, error)
func QueryNetworkEventStats(ip string, hours int) (*EventStats, error)
func DeleteNetworkEvents(from, to time.Time) (int, error)  // Clear Range
func DeleteAllNetworkEvents() (int, error)                  // Clear All
```

#### A2. `snapshot_diff.go`
```go
// AddNetworkEvent() ga qo'shiladi:
func AddNetworkEvent(evt NetworkEvent) {
    // 1. RAM log ga qo'sh (mavjud)
    networkEventLog = append(networkEventLog, evt)
    
    // 2. InfluxDB ga yoz (YANGI)
    go WriteNetworkEvent(evt)  // async, bloklamaydi
    
    // 3. Duration hisoblash (YANGI)
    trackEventDuration(evt)
}

// Yangi funksiya:
var openEvents = map[string]time.Time{}  // key: "switch_ip:port:type"

func trackEventDuration(evt NetworkEvent) {
    key := fmt.Sprintf("%s:%d", evt.SwitchIP, evt.Port)
    if isOpenEvent(evt.Type) {         // port_down, unreachable
        openEvents[key] = time.Now()
    } else if isCloseEvent(evt.Type) { // port_up, restored
        if start, ok := openEvents[key]; ok {
            evt.DurationS = int(time.Since(start).Seconds())
            delete(openEvents, key)
        }
    }
}
```

#### A3. `web_server.go` ✅ Bajarildi
```go
http.HandleFunc("/api/port-events",       portEventsHandler)   // GET + DELETE
http.HandleFunc("/api/port-events/stats", portEventsStatsHandler) // GET
```

---

### B. Frontend (`history.html` + `history.js`)

1. **Tab tizimi** — Traffic / Port Events / Switch Log
2. **Gantt chart** — D3.js yoki Chart.js `bar` chart horizontal
3. **Event table** — vaqt, tur, port, davomiylik ustunlari
4. **Clear All tugmasi** — `DELETE /api/port-events` + confirm dialog
5. **Clear Range** — DateTimePicker + `DELETE /api/port-events?from=...&to=...`
6. **Switch Log tab** — availability bar + unreachable table

---

## 6. Tekshirish Rejasi

```bash
# 1. InfluxDB ga event tushganini tekshirish
influx query '
  from(bucket:"network_monitor")
  |> range(start:-1h)
  |> filter(fn: r => r._measurement == "network_events")
  |> limit(n:10)
'

# 2. API — event tarixi
curl "http://localhost:8088/api/port-events?ip=172.20.230.49&hours=24"

# 3. API — statistika
curl "http://localhost:8088/api/port-events/stats?ip=172.20.230.49&hours=24"

# 4. Clear Range
curl -X DELETE "http://localhost:8088/api/port-events?from=2026-03-28T00:00:00Z&to=2026-03-28T12:00:00Z"

# 5. Clear All
curl -X DELETE "http://localhost:8088/api/port-events"

# 6. history.html da ko'rinish
# Browser: http://localhost:8088/history.html?id=172.20.230.49
# → "Port Events" va "Switch Log" tablarga o'tish
```

---

## 7. Bog'liq Fazalar

| Faza | Nom | Bog'liqlik |
|------|-----|-----------|
| Phase 2 | Snapshot Diff | `CompareSnapshots()` → eventlar manbai |
| Phase 8 | Graph Resilience | `Unreachable` / `Restored` event turlari |
| Phase 10 | Capture & History | `history.html` asosi — shu sahifaga tab qo'shiladi |
| Phase 12 | Alerting & Telegram | Port DOWN → Telegram ham parallel; bu faza InfluxDB ga ham yozadi |

---

## 8. Kutilayotgan Natija

| Xususiyat | Tavsif |
|-----------|--------|
| ✅ Doimiy saqlash | Restart bo'lsa ham tarix saqlanadi (InfluxDB) |
| ✅ Barcha event turlari | port_down/up, unreachable/restored, join/leave, anomaly/fixed |
| ✅ Duration hisoblash | Portning qancha vaqt o'chiq qolganini avtomatik hisoblash |
| ✅ Switch uptime % | 24 soatda har switch uchun mavjudlik foizi |
| ✅ Clear All | Bir tugma bilan barcha tarixni tozalash |
| ✅ Clear Range | Tanlangan vaqt oralig'ini o'chirish |
| ✅ history.html jadval | Event turlari, vaqt, port, davomiylik, xabar ustunlari |
| ✅ Filtr imkoniyati | IP, event turi (10 ta checkbox), vaqt oraligi bo'yicha |

---

## 9. Implementatsiya Natijalari (2026-03-28)

### O'zgartirilgan fayllar

| # | Fayl | O'zgartirish | Yangi qatorlar |
|---|------|--------------|---------|
| 1 | `influx_client.go` | `WriteNetworkEventToInflux()`, `QueryNetworkEvents()`, `DeleteNetworkEventsRange()`, `DeleteAllNetworkEvents()` + 3 struct (`NetworkEventRecord`, `EventStats`, `PortEventSummary`) | +186 |
| 2 | `snapshot_diff.go` | `AddNetworkEvent()` ga `go persistEventToInflux()` hook, `openEventTimes` duration cache, `persistEventToInflux()` funksiya | +35 |
| 3 | `web_server.go` | `portEventsHandler()` (GET/DELETE), `portEventsStatsHandler()` (GET), 2 ta route registration, `strings` import | +175 |
| 4 | `static/history.html` | Tab tizimi (Traffic History / Port Events), 10 ta event turi checkbox, event table, stats kartalar, Clear All, JS funksiyalar | +210 |

### Topilgan va tuzatilgan buglar

| # | Bug | Tuzatish |
|---|-----|----------|
| 1 | Port status eventlarda `host_down`/`host_up` ishlatilgan | `port_down`/`port_up` ga o'zgartirildi |
| 2 | `SwitchIP` tag InfluxDB da bo'sh yozilgan | `WriteNetworkEventToInflux()` da `SwitchIP` bo'sh bo'lsa `IP` fallback qo'shildi |
| 3 | Port eventda `IP` fieldiga yozilgan, `SwitchIP` kerak edi | `SwitchIP: p.SwitchIP` ga o'zgartirildi |
| 4 | `anomaly`/`fixed` checkbox'lar frontend filter'da yo'q edi | Qo'shildi (checked holda) |

### API Tekshirish natijalari

```bash
# ✅ GET — event qaytdi
curl "http://localhost:8088/api/port-events?ip=172.20.230.28&hours=1"
# {"device":"172.20.230.28","hours":1,"total":1,"events":[...]}

# ✅ GET — stats ishladi
curl "http://localhost:8088/api/port-events/stats?ip=172.20.230.28&hours=1"
# {"device":"172.20.230.28","hours":1,"port_down_count":0,...}

# ✅ go build . — OK
# ✅ go test ./... — OK
```
