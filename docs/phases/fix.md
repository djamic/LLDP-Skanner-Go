# Tuzatishlar va Bilimlar Bazasi

> Sana: 2026-03-04 | Loyiha: `lldp_go` network scanner

---

## 1. MAC Address Normalizatsiya

### Muammo
MAC addresslar turli formatlarda keladi va bir xil qurilma grafda **duplikat node** sifatida ko'rinadi:
```
4c:ae:a3:27:84:ca   ← colon (SNMP ChassisID)
4c-ae-a3-27-84-ca   ← dash (LLDP subtype 7)
4C AE A3 27 84 CA   ← space (Hex-STRING SNMP walk)
4C:AE:A3:27:84:CA   ← uppercase
```

### Yechim
`oui_lookup.go` ga `normalizeMAC()` funksiya qo'shildi:
```go
func normalizeMAC(mac string) string {
    mac = strings.Trim(mac, "\" \t\r\n")
    mac = strings.ReplaceAll(mac, "-", ":")
    mac = strings.ReplaceAll(mac, " ", ":")
    mac = strings.ToLower(mac)
    for strings.Contains(mac, "::") {
        mac = strings.ReplaceAll(mac, "::", ":")
    }
    return strings.Trim(mac, ":")
}
```

### Qayerlarda ishlatildi (14 ta joy, 5 fayl)
| Fayl | Joy | O'zgarish |
|------|-----|-----------|
| `oui_lookup.go` | `lookupVendor()` | normalizeMAC qo'shildi |
| `example_usage.go` | `hexStringToMAC()` body | → normalizeMAC() |
| `example_usage.go` | `normalizeID()` subtype 4 | → normalizeMAC() |
| `example_usage.go` | `normalizeID()` subtype 7 | dash-li MAC → normalizeMAC() |
| `example_usage.go` | `normalizeID()` default | dash bilan ham ishlaydi |
| `example_usage.go` | L838 `knownMACs` | ReplaceAll → normalizeMAC |
| `example_usage.go` | L862 `knownMACs[mac]` | normalizeMAC(macEntry.MACAddress) |
| `example_usage.go` | L867 ChassisID taqqoslash | normalizeMAC() ikki tomonda |
| `example_usage.go` | `detectOSFromMAC()` | macLower → macNorm |
| `snmp_object.go` | `normalizeChassisID()` | → normalizeMAC() |
| `analyzer.go` | `analyzeLoopback()` chassisMAC | → normalizeMAC() |
| `analyzer.go` | `analyzeLoopback()` remoteMAC | → normalizeMAC() |
| `analyzer.go` | `analyzeLoopback()` entryMAC | → normalizeMAC() |
| `snapshot_diff.go` | `CreateSnapshot()` mac | → normalizeMAC() |

---

## 2. Null MAC Filtri

### Muammo
LLDP dan `00 00 00 00 00 00` (probel bilan) null MAC addresslar kelmoqda va grafda node yaratilmoqda.

### Yechim
`example_usage.go` — `isInvalidID()` funksiyasiga qo'shimcha filtlar:
```go
// Space-separated null MAC
if id == "00 00 00 00 00 00" || id == "00-00-00-00-00-00" {
    return true
}
// Generic all-zero check
stripped := strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(id, ":", ""), "-", ""), " ", "")
if stripped == "000000000000" {
    return true
}
// Prefix check
if strings.HasPrefix(id, "00 00 00") || strings.HasPrefix(id, "00-00-00") {
    return true
}
```

---

## 3. Trunk Port Detection Tuzatish

### Muammo
`snmp_object.go` — `collectPortVLANs()` da trunk heuristik **buzilgan** edi:
```go
// NOTO'G'RI — barcha portlarni har VLAN qatoriga qo'shadi
for portIdx := range portPVIDs {
    portVLANCount[portIdx]++  // har port har VLAN uchun ++
}
```
**Natija:** `D 1-2` (172.20.230.48) switch da **barcha 52 port IsTrunk=True** bo'lib qoldi.

### Yechim
Hex-STRING bitmask to'g'ri parse qilinadi:
```go
// TO'G'RI — har bayt 8 portni ifodalaydi (MSB first)
hexBytes := strings.Fields(valPart)
for byteIdx, hexByte := range hexBytes {
    b, _ := strconv.ParseUint(hexByte, 16, 8)
    for bit := 7; bit >= 0; bit-- {
        if b&(1<<uint(bit)) != 0 {
            portNum := byteIdx*8 + (7 - bit) + 1
            portVLANCount[portNum]++
        }
    }
}
```

**IsTrunk heuristic** (o'zgarishsiz):
```go
isTrunk := portVLANCount[portIndex] > 5  // 5+ VLAN = trunk
```

### Hub Filtri
`example_usage.go` — hub yaratishdan oldin trunk check:
```go
// Skip trunk ports — ularda ko'p MAC normal holat
isTrunkPort := false
for _, pv := range data.PortVLANs {
    if pv.PortIndex == portNum && pv.IsTrunk {
        isTrunkPort = true
        break
    }
}
if len(macs) > 3 && !hasLLDPNeighbor && !isTrunkPort {
    // hub yaratish
}
```

---

## 4. MAC Vendor Detection (OUI)

### Holat
- `klauspost/oui` library integratsiya qilindi (`oui_lookup.go`)
- IEEE OUI database yuklab olishga urinadi (`http://standards-oui.ieee.org/oui.txt`)
- Agar yuklab bo'lmasa — mahalliy 225+ prefixdan iborat `extendedVendorDB` ishlatiladi
- Detection darajasi: ~51% (oldin 18%)

### Qurilma Kategoriyalash (`categorizeVendor`)
| Kategoriya | Vendorlar | Graf rangi |
|-----------|-----------|------------|
| `camera` | Hikvision, Dahua, Uniview | 🟣 E91E63 |
| `access_point` | Ubiquiti, Aruba, Ruckus | 🟡 FF9800 |
| `printer` | Epson, Canon, Brother | 🟤 795548 |
| `phone` | Samsung, Xiaomi, Apple, OPPO | 🔵 3F51B5 |
| `iot` | ESP/Espressif, Phicomm | ⚫ 607D8B |
| `vm` | VMware, Hyper-V, KVM, Xen | 🔵 00BCD4 |
| `network` | SNR, Cisco, MikroTik, HP | 🟠 FF5722 |
| `endpoint` | default | 🟢 4CAF50 |

---

## 5. Hub Node Tushuntirish

### hub-MAC-pN format nima?
```
hub-4c:ae:a3:a2:15:ec-p52
│    │                  │
│    └── Switch ChassisID  └── Port raqami
└── Bu switch portida boshqarilmaydigan qurilma bor
```

- Bu **virtual node** — haqiqiy qurilma emas
- Har portda 4+ MAC (va LLDP neighbor yo'q, trunk emas) bo'lsa yaratiladi
- `group=hub` → "Unmanaged Hub" sifatida grafda ko'rsatiladi

### Qachon hub yaratILMAYDI
1. Port da LLDP neighbor bor (`hasLLDPNeighbor = true`)
2. Port trunk (`isTrunkPort = true`) — **yangi filtr**
3. MAC soni ≤ 3 (direct endpoint yaratiladi)
4. MAC invalid yoki null

### VM Server detection
Agar portdagi MAClar VMware/KVM/Hyper-V prefixiga tegishli bo'lsa:
```
hub-          → vm-
[HUB] Unmanaged  → [VM] Hypervisor
```

---

## 6. LLDP Endpoint Tushuntirish

```
[LLDP-EP] node = LLDP orqali topilgan, lekin SNMP bilan scan qilinmagan qurilma
```
- `RemChassisId` MAC bo'lsa — MAC node ID sifatida ishlatiladi
- `RemChassisId` hostname bo'lsa — hostname node ID
- `RemPortId` MAC bo'lsa — portID node ID

---

## 7. Muhim Konstantalar va Chegaralar

| Parametr | Qiymat | Joyi |
|----------|--------|------|
| Hub threshold | `> 3 MAC` | `example_usage.go` L894 |
| Trunk threshold | `> 5 VLAN` | `snmp_object.go` L1031 |
| VM detection | VMware/KVM/Hyper-V/Xen prefix | `example_usage.go` isHypervisorPort() |
| Max endpoints per hub | 5 | `example_usage.go` L923 |

---

## 8. Switch Identifikatsiya

### 4c:ae:a3:XX:XX:XX nima?
- Bu `SNR` vendor prefix
- Tarmoqda 20+ ta SNR switch bor
- Barcha SNR switchlar `4c:ae:a3` bilan boshlanadi

### D 1-2 (172.20.230.48) — kuzatuvlar
- ChassisID: `4c:ae:a3:a2:15:ec`
- LLDP neighbors: 0 (LLDP o'chirilgan yoki bloklangan)
- MAC table: 2639 ta yozuv
- Port 52 (`10GE 1/0/52`): 2514 MAC — **uplink trunk**
- Port 51 (`10GE 1/0/51`): 70 MAC — **ikkinchi trunk**
- Qolgan portlar: haqiqiy hub/endpoint portlar

---

## 9. Backup

- **Joyi:** `/home/qosim/Desktop/lldp_go_backup_20260304_093748.tar.gz`
- **Hajmi:** 47MB
- **Sana:** 2026-03-04 09:37:48
- **Tarkib:** Barcha Go fayllar, static/, docs/ (lldp_scanner binary va vendor/ dan tashqari)

---

## 10. MAC Cross-Reference Discovery (Faza 3 qo'shimchasi)

> Sana: 2026-03-04 | Seans: "Implementing MAC Cross-Reference"

### Muammo
LLDP o'chirilgan kommutatorlar (masalan, HUAWEI S5720) LLDP qo'shni jadvali orqali topilmaydi. Grafda ular izolyatsiyalangan ko'rinadi, lekin aslida boshqa switchlarga ulangan.

### Yechim: `addMACCrossRefEdges()` — `example_usage.go`
Agar A switchining MAC-jadvalida B switchining ChassisID (MAC) mavjud bo'lsa → ular orasiga bog'lanish qo'shiladi.

```go
func addMACCrossRefEdges(graph *DJGraph, allDevices map[string]*DeviceData, switchChassisMACs map[string]string)
```

**Mantiq:**
1. `switchChassisMACs` xaritasi quriladi: `normalizedMAC → nodeID`
2. Har bir qurilmaning MAC-jadvalidagi har yozuv uchun: agar bu MAC boshqa switch ChassisID si bo'lsa — bog'lanish qo'shiladi
3. LLDP yo'nalishida allaqachon bog'lanish bor bo'lsa — takrorlanmaydi

**Chaqirilish joylari:** Grafni yangilashning 3 ta joyida (skanerlash vaqtida, rescan vaqtida, rebuild vaqtida).

**Natija:** HUAWEI S5720 (172.20.254.249) grafda to'g'ri joylashtirildi.

---

## 11. UI Menyusi Tekshiruvi — ishlash holati

> Sana: 2026-03-05 | Seans: "Verifying UI Menu Functions"

| Menyu elementi | API endpoint | Holat |
|----------------|-------------|-------|
| **Clean Hosts** | `DELETE /api/hosts` | ✅ Ishlaydi — hostlar + xotira + InfluxDB tozalanadi |
| **Rescan** | `POST /api/rescan` | ✅ Ishlaydi — `rescanTrigger` kanaliga signal yuboradi |
| **Settings** | `GET/POST /api/settings` | ✅ Ishlaydi — IP diapazonlar, community saqlanadi |
| **Captures** | `GET /api/captures` | ✅ Ishlaydi — sessiyalar ro'yxati |
| **Events** | `GET /api/events` | ✅ Ishlaydi — 200 ta oxirgi hodisa |

**Rescan mexanizmi:** `TriggerRescan()` → `rescanTrigger <- true` → `handleRescanRequests()` da `<-ch` bilan qabul qilinadi. Qayta skanerlash incremental emas — oldingi ma'lumotlar saqlanib, yangilari ustiga qo'yiladi.

---

## 12. Faza 1 (A) — Eksperiment Infratuzilmasi ✅ BAJARILGAN

> Sana: 2026-03-03 | Seans: "Testing Experiment Exports"

### Nima qilindi

**`experiment_exports.go`** — yangi fayl yaratildi:
- `generateExperimentReport()` — 6 ta JSON faylni `results/` ga yozadi
- `AddTelegramTiming()` / `GetTelegramTimings()` — Telegram vaqt loglash

**`example_usage.go`** —
- `--experiment` / `--test` va `--benchmark` legacy flaglar → `--mode experiment/benchmark` yangi tizim
- `--mode`, `--workers`, `--exp-id`, `--duration`, `--output`, `--networks`, `--community` CLI flaglar qo'shildi
- Skanerlash vaqtlari o'lchanadi: `experimentScanStart`, `experimentScanEnd`, `experimentCollectionEnd`

**Yaratilgan fayllar (`results/`):**

| Fayl | Tarkib |
|------|--------|
| `experiment_metrics.json` | Jami skanerlash vaqti, host soni, SNMP muvaffaqiyat % |
| `health_scores.json` | Har qurilma uchun Health Score + anomaliyalar |
| `bfs_depths.json` | Core switchdan har tugunga BFS chuqurligi, taqsimot |
| `vendor_stats.json` | Ishlab chiqaruvchilar statistikasi |
| `telegram_timing.json` | Anomaliya → Telegram xabar yuborish vaqt farqi (ms) |

---

## 13. Faza 2 (B) — Snapshot Diff Engine ✅ BAJARILGAN

> Sana: 2026-03-03–04

### Nima qilindi

**`snapshot_diff.go`** — yangi fayl yaratildi:

```
NetworkSnapshot  — tarmoq holati bir lahzada
SnapshotDiff     — ikki lahza orasidagi farqlar
NetworkEvent     — UI uchun hodisa log (max 200)
```

- `CreateSnapshot()` — joriy `collectedData`, graf va `Report` dan snapshot yasaydi
- `CompareSnapshots()` — JOIN/LEAVE/NewHost/LostHost/NewAnomaly/FixedAnomaly aniqlaydi
- `AddNetworkEvent()` / `GetNetworkEvents()` — thread-safe hodisa jurnali
- `diff.LogChanges()` — konsol + `NetworkEvent` log ga yozadi

**`influx_client.go`** — 3 ta yangi funksiya:
- `WriteDeviceEvent()` → `device_events` measurement (JOIN/LEAVE)
- `WriteNetworkSummary()` → `network_summary` measurement
- `WriteAnomalySummary()` → `anomaly_summary` measurement

**`web_server.go`** —
- `GET /api/events` — `eventsHandler()` qo'shildi

**`snapshot_diff_test.go`** — unit testlar yozildi (JOIN/LEAVE, anomaly diff)

---

## 14. Faza 3 (C) — Qurilma Identity ✅ BAJARILGAN

> Sana: 2026-03-04–05

### C.1. DNS Reverse Lookup — `example_usage.go`

```go
func resolveHostname(ip string) string {
    names, err := net.LookupAddr(ip)
    // domen qismi olinib tashlanadi: "PC-JAMIL.tuit.local." → "PC-JAMIL"
}
```

- Har yangi tugun uchun background goroutine da chaqiriladi (bloklash yo'q)
- Hostname `SwitchInfo` xaritasiga `[DNS] hostname` formatida qo'shiladi
- `/api/graph` javobida `hostname` maydoni paydo bo'ldi (`GraphNode` struct)

### C.2. `isRandomMAC()` — `example_usage.go` L1367

Wi-Fi qurilmalarning tasodifiy MAC lari: ikkinchi hex belgisi `2, 6, A, E` (locally-administered bit).

```go
func isRandomMAC(mac string) bool {
    // 2-belgini tekshiradi: 2, 6, a, e → true
}
```

- Shadow IT tahlilida random MAC lar hisobga olinmaydi (`analyzer.go` L565)
- `isHypervisorPort()` ham shu faylda — VMware/KVM/Hyper-V/Xen OUI

### C.3. Wi-Fi va VM kategoriyasi — `dj_graph.go`

`determineDeviceGroup()` funksiyasiga yangi shartlar:
- `[WiFi]` marker → `wifi_random` tur
- `[VM]` marker → `vm` tur

**`identity_test.go`** — yangi test fayl:
- `isRandomMAC()` uchun 10+ test holati

---

## 15. Faza 4 (G) — Eksperiment Boshqaruvi ✅ BAJARILGAN

> Sana: 2026-03-05

### G.1. CLI flag tizimi — `example_usage.go`

```
--mode      normal | experiment | benchmark | monitor24h
--workers   50 (standart)
--exp-id    eksperiment identifikatori
--duration  24h | 1h | 30m
--output    results/
--networks  172.20.254.0/24,...
--community public
```

Backward-compatibility: `--experiment` → `--mode experiment`, `--benchmark` → `--mode benchmark`.

### G.2. Eksperiment rejimi

`--mode experiment` → bitta skanerlash + 6 ta JSON eksport → `os.Exit(0)`.

### G.3. 24h monitoring rejimi

`--mode monitor24h` — belgilangan davr davomida har skanerlash tsiklida:
1. Skanerlash + tahlil
2. Snapshot Diff → JOIN/LEAVE aniqlash
3. InfluxDB ga `WriteNetworkSummary`, `WriteDeviceEvent`, `WriteAnomalySummary`
4. 60 sekund kutish

### G.4. Web panel API — `web_server.go`

4 ta yangi endpoint qo'shildi:

| Endpoint | Metod | Vazifa |
|----------|:-----:|--------|
| `/api/experiment/start` | POST | Orqa fonda eksperiment boshlash |
| `/api/experiment/status` | GET | Progress, elapsed vaqt |
| `/api/experiment/stop` | POST | Bekor qilish (`context.CancelFunc`) |
| `/api/experiment/results` | GET | `results/` papkasidagi fayllar |

`ExperimentStatus` struct va `sync.RWMutex` bilan thread-safe holat boshqaruvi.

---

## 16. Joriy Holat (2026-03-23)

| Faza | Guruh | Holat |
|------|-------|:-----:|
| Faza 1 — Eksperiment Infra | A | ✅ Bajarilgan |
| Faza 2 — Snapshot Diff | B | ✅ Bajarilgan |
| Faza 3 — Qurilma Identity | C | ✅ Bajarilgan |
| Faza 4 — Eksperiment Mgmt | G | ✅ Bajarilgan |
| **Faza 5 — UI Yaxshilash** | E | ✅ **Bajarilgan** |
| Faza 6 — Hisobot Tizimi | F | ✅ **Bajarilgan** (9 bo'limli MD + GOST DOCX pipeline) |
| Faza 7 — Screenshotlar | D | ❌ Bajarilmagan |

**Keyingi faza — Faza 6 (F): Hisobot Tizimi**

---

## 17. Faza 5 (E) — UI Yaxshilash ✅ BAJARILGAN

> Sana: 2026-03-23

### E.1. Health Score Widget — `static/index.html`, `static/style.css`, `static/app.js`

Header qismiga Health Score kartasi qo'shildi:
- `#healthScoreVal` — katta raqam (0–100)
- `.health-score.good` (yashil) / `.warning` (sariq) / `.danger` (qizil) — rang sinflari
- `.health-bar-fill` — 4px gradient progress bar (qizildan yashilgacha)
- `updateHealthWidget(score)` funksiyasi — `/api/graph` dan `health_score` olib yangilaydi
- 10 soniyada avtomatik yangilanadi (`setInterval → refreshData`)

### E.2. Anomaly Glow Effekti — `static/style.css`, `static/app.js`

- `.node.anomaly-loopback` — qizil `stroke` + `pulse-anomaly-shadow` 2s animatsiya
- `.node.anomaly-shadow` — to'q sariq `stroke` + 2.5s animatsiya
- `@keyframes pulse-anomaly-shadow` — drop-shadow 6px↔14px o'zgarib turadi
- D3 `nodeUpdate.attr('class', ...)` — `d.anomalies` massivi asosida sinf qo'yiladi

### E.3. Legend yangilash — `static/index.html`

- `📡 Random Wi-Fi` — `#00BCD4` rang
- `⚠️ Anomaly` — `#FF5252` + `pulse-anomaly` animatsiya bilan tirik yonib turadi

### E.4. Node label hostname prioritet — `static/app.js`

```javascript
const displayText = d.hostname || d.sysName || d.label || d.id;
```
Graf tugunlar labelida: `hostname` → `sysName` → `label` → `id` tartibi.

### E.5. Status Bar — `static/index.html`, `static/style.css`, `static/app.js`

Ekran pastki qismida header stilida footer:
- `🕐 Last scan` — har refresh vaqti
- `📡 Switches` — switch/router tugunlar soni
- `💻 MACs` — `data.total_macs` yoki nodes soni
- `⚠️ Anomalies` — anomaliyali nodlar soni (qizil/yashil rang)
- `🏥 Health` — health score (rang dinamik)

### E.6. Backend yangilanishlar — `dj_graph.go`, `web_server.go`, `analyzer.go`

**`dj_graph.go`:**
- `GraphNode` ga `Anomalies []string` maydoni qo'shildi
- `GraphData` ga `HealthScore float64`, `TotalMACs int` maydonlari qo'shildi

**`web_server.go`:**
- `lastHealthScore`, `lastAnomalyMap`, `lastTotalMACs` global o'zgaruvchilar
- `SetLastReport(healthScore, anomalyMap, totalMACs)` — thread-safe setter
- `graphHandler` da node `Anomalies` va `HealthScore`, `TotalMACs` to'ldiriladi

**`analyzer.go`:**
- `Analyze()` oxirida `SetLastReport()` chaqiriladi
- `Device` maydonidan IP ajratib olib anomaly xaritasi yaratiladi
- `na.Data.DevicesData` dan `totalMACs` hisoblanadi

### ✅ Tekshirish ro'yxati (Faza 5)
- [x] Health Score widget header da ko'rinadi va rangi to'g'ri
- [x] Anomaliyali node lar qizil glow bilan "yonib-o'chib" ko'rinadi
- [x] Legend da Random Wi-Fi va Anomaly elementlari bor
- [x] Node labelda hostname prioritet bilan ko'rsatiladi
- [x] Status bar ekranning pastida to'g'ri ma'lumot ko'rsatadi
- [x] `/api/graph` javobida `health_score`, `total_macs`, `anomalies` mavjud
- [x] `go build` xatosiz tugaydi ✅


---

## Phase 8: MAC-IP Discovery Service + Graph Resilience ✅ BAJARILGAN

### 8.1 MAC-IP Discovery Service
**Holat:** ✅ Bajarilgan  
**Hujjat:** [mac-service.md](mac-service.md)

**Maqsad:** Barcha skanerlangan switchlardan vaqti-vaqti bilan ARP jadvalini so'rab, to'liq IP-MAC mapping bazasini yaratish.

**Asosiy komponentlar:**
- `mac_ip_service.go` — yaratilgan
- `startMacIPService()` — har 5 daqiqada barcha switchlardan `.1.3.6.1.2.1.4.22.1.2` OID so'rash
- `mac_ip_cache.json` — persistentlik uchun JSON cache (366KB)
- `enrichGraphWithIPs()` — `detectHypervisors()` dan keyin chaqiriladi

**Natija:** VM MAC lari va hypervisor node lari grafda IP bilan ko'rinadi.

### 8.2 Graph Resilience (2026-03-28)
**Holat:** ✅ Bajarilgan  
**Hujjat:** [phase_8_graph_resilience.md](phase_8_graph_resilience.md)

**Muammo:** Switch yoki port o'chganda `CollectData()` bo'sh data qaytarib, eski ma'lumotni o'chirib yuborar va node grafdan yo'qolib ketar edi.

**Yechim (6 ta fayl o'zgartirildi):**

| Fayl | O'zgartirish |
|------|--------------|
| `snmp_object.go` | `DeviceData` ga `Unreachable bool` + `LastSeen time.Time` qo'shildi. `CollectData()` da 7/7 SNMP fail → `OnFailure` chaqiradi, `OnSuccess` emas |
| `example_usage.go` | 4 ta `NewSNMPObject` callback + 2 ta `rebuildGraph()` NodeStatus yozish |
| `dj_graph.go` | `DJGraph.NodeStatus`, `GraphNode.Unreachable`, `GraphLink.Unreachable` JSON fieldlar (omitempty olib tashlandi). `GetGraphData()` da status enrichment |
| `snapshot_diff.go` | `HostInfo.Unreachable`, `Ports map`, `PortStatusChange` struct, `CompareSnapshots()` da unreachable↔restored + port up↔down detection, `LogChanges()` da host_down/host_up/port events |
| `static/app.js` | Unreachable node → qizil glow + pulsation. Link → dashed qizil. Info panel → "🔴 UNREACHABLE / 🟢 Online" + Last Seen. Property change detection (re-render trigger) |
| `static/style.css` | `@keyframes pulse-unreachable` (1.5s), `.anomaly-unreachable`, `.link-unreachable` CSS sinflari |

---

## Phase 9: Web Terminal va Remote Connect ✅ BAJARILGAN

**Holat:** ✅ Bajarilgan  
**Fayl:** `terminal_handler.go`, `static/app.js` (xterm.js panel)

**Bajarilgan:**
- `checkPortsHandler` — SSH(22), Telnet(23), HTTP(80), HTTPS(443) portlarini avtomatik skanerlash
- `terminalHandler` — WebSocket `/api/terminal` endpoint
- `handleSSHSession()` — xterm.js ↔ WebSocket ↔ SSH tunnel (PTY, xterm-256color)
- `handleTelnetSession()` — xterm.js ↔ WebSocket ↔ raw TCP + IAC filtri
- `filterTelnetIAC()` — Telnet IAC buyruqlarini avtomatik boshqarish (WILL/DO/WONT/DONT)
- Frontend: floating draggable terminal panel (xterm.js) — HPE switchga SSH muvaffaqiyatli ulangan ✅
- Context menu orqali qurilmaga o'ng tugma → Connect → SSH/Telnet tanlash

**Kelajak rejalari:**

| # | Vazifa | Ustuvorlik | Tavsif |
|---|--------|-----------:|--------|
| 1 | **Connection History** | Yuqori | Har bir SSH/Telnet ulanishni log qilish: IP, foydalanuvchi, boshlanish/tugash vaqti, davomiyligi. `connection_history.json` yoki InfluxDB ga saqlash |
| 2 | **Saved Credentials** | Yuqori | Har qurilma uchun login/parolni shifrlangan holda saqlash. UI da "Quick Connect" tugmasi — oldingi ma'lumotlar bilan darhol ulanish |
| 3 | **Multi-Tab Terminal** | O'rta | Bir vaqtda bir nechta qurilmaga ulanish (tab lar bilan). Har tab — alohida WebSocket sessiya |
| 4 | **Command History** | O'rta | Terminal da yuborilgan buyruqlarni saqlash va qayta ishlatish (↑↓ tugmalari) |
| 5 | **Session Recording** | Past | Terminal sessiyani to'liq yozib olish (asciinema formati). Keyin qayta ko'rish imkoniyati |
| 6 | **SSH Key Authentication** | Past | Paroldan tashqari SSH key bilan autentifikatsiya |
| 7 | **Config Diff** | Past | Qurilma konfiguratsiyasini olish va oldingi versiya bilan solishtirish |

---

## Phase 10: Capture & History Tizimi ✅ BAJARILGAN

**Holat:** ✅ Bajarilgan  
**Fayl:** `capture.go`, `web_server.go`, `influx_client.go`

**Bajarilgan:**
- `CaptureManager` — sessiya boshqaruvi (start/stop/list)
- `FullCaptureData` — topologiya + metrikalar + hodisalar + qurilma ma'lumotlari
- `captures/` papkasiga JSON sifatida saqlash
- API: `/api/capture/start`, `/api/capture/stop`, `/api/captures`
- History API: `/api/history` — qurilma bo'yicha tarixiy ma'lumotlar
- **History sahifasi** (`/history.html`) — to'liq ishlaydi ✅:
  - Qurilma tanlash (Device IP dropdown)
  - Vaqt oralig'i (Last 1 Hour / 6h / 24h / 7d)
  - Port tanlash (GigabitEthernet1/0/1–48)
  - Metrika turi (Traffic bps, Errors, Discards)
  - **Ethernet Ports vizualizatsiya** — rangli grid (Up/Down/Admin Down/No Data/Trunk/Access VLAN)
  - **Uplink Ports (10G+)** — alohida qator
  - **Traffic Over Time** grafik — real-time InfluxDB dan 17,000+ data point
  - O'rtacha Download/Upload tezlik (23.2 / 23.4 Mbps)
  - **Connect** tugmasi — History dan to'g'ridan-to'g'ri SSH/Telnet terminal ochish

**Kelajak rejalari:**

| # | Vazifa | Ustuvorlik | Tavsif |
|---|--------|-----------:|--------|
| 1 | **Capture Replay** | Yuqori | Saqlangan sessiyani vaqt bo'yicha qayta «ko'rish» — topologiya o'zgarishlarini animatsiya qilish |
| 2 | **Capture Compare** | Yuqori | Ikki capture ni solishtirish — nima o'zgardi (yangi/yo'qolgan qurilmalar, link lar) |
| 3 | **Auto-Capture** | O'rta | Har kuni/hafta avtomatik capture olish (cron-style scheduler) |
| 4 | **Capture Export** | O'rta | Capture ni PDF/DOCX hisobot sifatida eksport qilish |
| 5 | **History Timeline** | Past | UI da timeline slider — sanani tanlash va o'sha paytdagi topologiyani ko'rish |
| 6 | **Capacity Planning** | Past | Tarixiy ma'lumotlardan trend analiz — port/bandwidth o'sish tezligi |

---

## Phase 11: SNMP Konfiguratsiya Backup 📋 Rejalashtirilgan

**Holat:** 📋 Rejalashtirilgan  
**Yangi fayl:** `config_backup.go`

**Maqsad:** Har bir switch/router konfiguratsiyasini SNMP yoki SSH orqali avtomatik backup qilish.

| # | Vazifa | Ustuvorlik | Tavsif |
|---|--------|-----------:|--------|
| 1 | **SSH Config Pull** | Yuqori | `show running-config` (SNR/Cisco), `display current-configuration` (Huawei/HPE) — avtomatik vendor detect |
| 2 | **Config Storage** | Yuqori | `configs/` papkasida versiyalangan saqlash: `{ip}_{date}.cfg` |
| 3 | **Config Diff** | Yuqori | Ikki versiya orasidagi farqni ko'rsatish (git-style diff) |
| 4 | **Scheduled Backup** | O'rta | Har kun/hafta avtomatik backup (timer) |
| 5 | **Change Alert** | O'rta | Konfiguratsiya o'zgarganda Telegram xabar yuborish |
| 6 | **Rollback** | Past | Oldingi konfiguratsiyani qaytarish (SSH orqali) |
| 7 | **Compliance Check** | Past | GOST/CIS standartlariga moslik tekshiruvi (SSH password complexity, VLAN policies) |

---

## Phase 12: Alerting va Notification ✅ BAJARILGAN

**Holat:** ✅ Bajarilgan  
**Fayllar:** `analyzer.go`, `ignored_issues.go`, `experiment_exports.go`, `bot/analyserbot.py`, `web_server.go`

**Bajarilgan:**
- **6 ta anomaliya turi aniqlash:** Shadow IT, Loopback, Congestion, STP, Path, Stability
- **Telegram Bot integratsiya** (`http://127.0.0.1:5005/notify`):
  - Har bir Shadow IT va Loopback uchun alohida xabar yuborish
  - Inline tugmalar: "❌ E'tiborsiz qoldirish" va "✅ To'g'rilandi"
  - Health Score umumiy xulosa xabar (soatlik)
- **Cooldown tizimi** — 1 soat ichida bir issue uchun takroriy xabar yo'q
- **Ignored Issues** (`ignored_issues.go`) — `ignored_issues.json` ga persistent saqlash
- **Bot Action API** (`/api/bot/action`) — Ignore/Verify tugmalarining Go backend handler
- **Telegram Timing Export** — `results/telegram_timing.json` (latency statistikasi)
- **Network Events Panel** (`/api/events`) — 200 ta event log (join/leave/host_up/host_down/anomaly/fixed)
- **Snapshot Diff Engine** (`snapshot_diff.go`) — DEVICE_JOIN/LEAVE aniqlash, anomaly diff, health delta
- **InfluxDB Anomaly Summary** — har tahlildan keyin `anomaly_summary` measurement ga yozish

**Kelajak rejalari:**

| # | Vazifa | Ustuvorlik | Tavsif |
|---|--------|-----------:|--------|
| 1 | **Email Notification** | Yuqori | SMTP orqali muhim anomaliyalar haqida email yuborish (critical/warning threshold) |
| 2 | **Webhook Integration** | O'rta | Custom webhook URL ga POST so'rov — tashqi tizimlar integratsiyasi (Zabbix, PagerDuty) |
| 3 | **Alert Rules Engine** | O'rta | Foydalanuvchi o'zi qoida yaratishi: "Agar Health Score < 50 → email" yoki "Agar yangi qurilma topilsa → Telegram" |
| 4 | **Alert Dashboard** | O'rta | UI da barcha alertlar tarixi — qachon yuborildi, kim javob berdi, holat |
| 5 | **Escalation** | Past | Alert javobsiz qolsa — 30 daqiqadan keyin yuqori darajali administrator ga yuborish |
| 6 | **Maintenance Window** | Past | Ma'lum vaqt oralig'ida alert larni to'xtatish (reglament ishlar uchun) |

---

## Phase 13: Dashboard va Analitika ✅ BAJARILGAN

**Holat:** ✅ Bajarilgan  
**Fayllar:** `static/index.html`, `static/app.js`, `static/style.css`, `static/history.html`, `web_server.go`, `dj_graph.go`, `oui_lookup.go`, `experiment_exports.go`

**Bajarilgan:**
- **D3.js Force-Directed Topologiya** — 12 ta qurilma guruhi bilan rangli vizualizatsiya
- **Health Score Widget** — 0-100 real-time ko'rsatkich (anomaly-based penalty)
- **Device Detail Panel** (`/api/device-detail`) — har qurilma uchun per-port traffic, VLAN, errors
- **Real-time Traffic Labels** — grafda link ustida Mbps ko'rsatish (periodic refresh)
- **Events Panel** (`/api/events`) — MAC join/leave, host up/down, anomaly log
- **Anomaly Glow Effect** — anomaliyali node lar yonib ko'rinadi (E.2)
- **Context Menu** — node ustida o'ng tugma: Connect (SSH/Telnet), History, Detail
- **OUI Vendor Database** (`oui_lookup.go`) — 280+ lokal vendor + IEEE database + 8 ta kategoriya
- **Zabbix Integration** (`dj_graph.go`):
  - `ExportHostsToZabbix()` — qurilmalarni Zabbix JSON formatida eksport (SNR templates)
  - `ExportToMap()` — topologiyani Zabbix Map formatida eksport
- **Experiment Exports** (`experiment_exports.go`):
  - `ExportHealthScores()` — per-device health JSON
  - `ExportBFSDepths()` — BFS topologiya chuqurlik analizi
  - `ExportVendorStats()` — vendor bo'yicha SNMP/LLDP/FDB statistikasi
  - `ExportBenchmarkResults()` — scanner performance benchmark
- **Scan Settings API** (`/api/settings`) — UI dan IPRanges, community, timeout sozlash
- **Rescan API** (`/api/rescan`) — tugma bilan qayta skanerlash

| # | Vazifa | Ustuvorlik | Tavsif |
|---|--------|-----------:|--------|
| 1 | **Traffic Heatmap** | Yuqori | Har bir switch portining traffic intensivligini rang bilan ko'rsatish (yashil→sariq→qizil) |
| 2 | **Bandwidth Grafik** | Yuqori | Real-time per-port traffic grafik (Chart.js/D3.js) — tanlangan qurilma uchun |
| 3 | **Topology Map Modes** | O'rta | Turli ko'rinishlar: Layer 2 (MAC), Layer 3 (IP/Subnet), VLAN segmentlar, fizik joylashuv |
| 4 | **Search & Filter** | O'rta | Qurilmani qidirish: IP, MAC, hostname, vendor bo'yicha. Topilgan qurilmaga zoom |
| 5 | **Custom Dashboard** | O'rta | Foydalanuvchi o'zi widget larni joylashtirishi — drag-and-drop layout |
| 6 | **SLA Monitoring** | Past | Uptime hisoboti: har qurilma necha % vaqt online bo'lgan (InfluxDB asosida) |
| 7 | **Inventory Export** | Past | Barcha qurilmalar ro'yxatini CSV/Excel eksport (audit uchun) |
| 8 | **Multi-Site** | Past | Bir nechta tarmoqni bitta paneldan monitoring qilish (remote scanner agent lar) |

---

## Phase 14: Network Event History ✅ BAJARILGAN

**Holat:** ✅ Bajarilgan (2026-03-28)  
**Hujjat:** [phase_14_port_event_history.md](phase_14_port_event_history.md)

**Muammo:** Tarmoq hodisalari (port DOWN/UP, switch unreachable/restored, anomaliya) faqat RAM da 200 ta cheklangan log sifatida saqlangan va restart bo'lsa yo'qolgan.

**Yechim (4 ta fayl o'zgartirildi):**

| Fayl | O'zgartirish |
|------|--------------|
| `influx_client.go` | +186 qator: `WriteNetworkEventToInflux()` (SwitchIP/IP fallback), `QueryNetworkEvents()` (ip, hours, type[], port filter), `DeleteNetworkEventsRange()`, `DeleteAllNetworkEvents()`. 3 struct: `NetworkEventRecord`, `EventStats`, `PortEventSummary` |
| `snapshot_diff.go` | +35 qator: `AddNetworkEvent()` ga `go persistEventToInflux()` async hook, `openEventTimes` duration cache, port eventlarda `port_down`/`port_up` tur tuzatish |
| `web_server.go` | +175 qator: `portEventsHandler()` (GET/DELETE), `portEventsStatsHandler()` (GET aggregated stats), 2 ta route, `strings` import |
| `static/history.html` | +210 qator: Tab tizimi (📊 Traffic History / 🔌 Port Events), 10 ta event turi checkbox (anomaly + fixed qo'shildi), event jadvali, statistika kartalar, Clear All JS, `switchTab()`, `loadPortEvents()` funksiyalar |

**API Endpointlar:**
- `GET /api/port-events?ip=...&hours=24&type=port_down,port_up` — eventlar ro'yxati (InfluxDB dan)
- `GET /api/port-events/stats?ip=...&hours=24` — port_down soni, unreachable soni, eng uzun uzilish
- `DELETE /api/port-events` — barcha eventlarni o'chirish
- `DELETE /api/port-events?from=...&to=...` — vaqt oralig'ini o'chirish

**Topilgan buglar (4 ta):** Port eventlarda noto'g'ri event turi, SwitchIP fallback, anomaly/fixed checkbox yo'qligi.

---

## Fazalar Xulosa Jadvali (2026-03-28)

| Faza | Nomi | Holat |
|:----:|------|:-----:|
| 1 | Eksperiment Infra | ✅ |
| 2 | Snapshot Diff | ✅ |
| 3 | Qurilma Identity | ✅ |
| 4 | Experiment Mgmt | ✅ |
| 5 | UI Yaxshilash | ✅ |
| 6 | Hisobot Tizimi | ✅ |
| 7 | ESXi + Screenshots | ⚠️ (ESXi ✅, Screenshots ❌) |
| 8 | MAC-IP Service + Graph Resilience | ✅ |
| 9 | Web Terminal & Connect | ✅ |
| 10 | Capture & History | ✅ |
| 11 | SNMP Config Backup | 📋 Reja |
| 12 | Alerting & Notification | ✅ |
| 13 | Dashboard & Analytics | ✅ |
| 14 | Network Event History | ✅ |
| 15 | Dynamic Discovery & Dead Node Recovery | ✅ |

---

## 15. Phase 15: Dynamic Discovery (2026-03-28) ✅

**Muammo:** `startPeriodicRescan()` faqat `collectedData` dagi IPlarni poll qiladi. Dastlabki skanerlashda o'chiq bo'lgan switchlar umuman grafga kirmay qoladi.

**Yechim:** A+B Gibrid Algoritm

| Komponent | Nima qiladi | Interval |
|-----------|-------------|----------|
| `startRescueScanner()` | `swich_ips` dan yo'qolgan IPlarni ping + SNMP bilan tiklash | 7 daqiqa |
| `discoverFromLLDP()` | LLDP `RemMgmtIP` dan yangi switchlar topish | Har rescan dan keyin |
| `appendToSwitchIPs()` | Yangi IPni duplikatsiz `swich_ips` ga saqlash | - |

**O'zgartirilgan fayllar:**
- `example_usage.go` — `startRescueScanner()`, `runRescueScan()`, `discoverFromLLDP()` (+~130 qator)
- `settings.go` — `appendToSwitchIPs()` (+28 qator)

**Qo'shimcha (UI):**
- Port grid: kattalashtirildi (42×34px), VLAN tag qora rang, shrift 10px
- Chart legend: port status ranglari (🟢🔴🟠⚫🔵), to'liq port nomi
- Port Description: `ifAlias` SNMP OID + API + tooltip

