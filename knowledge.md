# LLDP Tarmoq Skaneri — Chuqur Kod Tahlili (Deep Code Analysis)

> **Hujjat maqsadi:** Loyihadagi 18 ta Go faylning (jami 12,356 qator) har bir funksiyasi, strukturasi va algoritmini to'liq hujjatlashtirish.
> **Yangilangan:** 2026-yil, 12-Aprel. Barcha `.go` fayllari qatorma-qator o'qilgan holda yozilgan.
> **Funksional modullar xaritasi:** [modules.md](modules.md) — 40 ta modul, 12 guruh, DB strukturasi, Mermaid diagrammalar

---

## 1. Fayl Hajmlari va Arxitektura Xaritasi

| Fayl | Qatorlar | Vazifasi |
|------|----------|----------|
| `example_usage.go` | 3,097 | Asosiy yadro: `main()`, CLI rejimlar, graf qurish, OS fingerprinting, trafik monitoring, rescue scan |
| `report_topology.go` | 1,523 | SVG/PNG/Mermaid topologiya chizish, GOST DOCX audit hisobot generatsiyasi |
| `web_server.go` | 1,127 | 30+ HTTP API endpoint (graph, hosts, settings, experiments, events, terminal, report) |
| `snmp_object.go` | 951 | SNMP ma'lumot yig'ish: interfaces, LLDP neighbors, MAC table, ARP, STP, VLAN |
| `analyzer.go` | 833 | 6 xil tarmoq tahlili, Health Score (0-100), Telegram ogohlantirish |
| `dj_graph.go` | 684 | Graf tuzilmasi: Nodes, Edges, BFS, koordinata optimallashtirish, Zabbix eksport |
| `mac_ip_service.go` | 609 | ARP kesh, gateway subnet kashfiyoti, ESXi HTTP validatsiya |
| `snapshot_diff.go` | 592 | Tarmoq holati qiyoslash: JOIN/LEAVE, port UP/DOWN, anomaliya o'zgarishlari |
| `influx_client.go` | 567 | InfluxDB v2 mijoz: trafik, eventlar, anomaliyalar, tarmoq xulosasi yozish/o'qish |
| `experiment_exports.go` | 481 | Benchmark, Health, BFS, Vendor, Telegram timing JSON eksportlari |
| `oui_lookup.go` | 429 | IEEE OUI + kengaytirilgan vendor bazasi (280+ vendor), MAC → vendor aniqlash |
| `terminal_handler.go` | 406 | WebSocket SSH/Telnet terminal, port avtoskanerlash |
| `snmp_scanner.go` | 340 | Worker Pool skaneri: CIDR kengaytirish, ICMP ping, SNMP test, parallel scan |
| `settings.go` | 202 | `network_data.json` saqlash/yuklash, `swich_ips` boshqarish, `gateway_ip` |
| `capture.go` | 197 | Capture sessiya menejeri: start/stop/list |
| `snapshot_diff_test.go` | 186 | Unit testlar: JOIN/LEAVE, NoChanges, MassJoin |
| `ignored_issues.go` | 78 | Muammolarni e'tiborsiz qoldirish (JSON persist) |
| `identity_test.go` | 54 | `isRandomMAC` va `resolveHostname` testlari |

---

## 2. Dastur Ishga Tushishi va Rejimlar (`example_usage.go`)

### 2.1. `main()` funksiyasi (qator 101-574)

**Ishga tushish ketma-ketligi:**
1. `signal.Ignore(syscall.SIGPIPE)` — snmpwalk/ping pipe buzilishidan himoya
2. CLI flaglar parse: `--mode`, `--workers`, `--exp-id`, `--duration`, `--output`, `--networks`, `--community`
3. `initDebugLog()` → `debug_edges_analysis.log` fayl ochiladi
4. `InitCaptureManager(".")` → capture sessiya menejeri
5. `initOUIDatabase()` → IEEE OUI vendor bazasi yuklanadi
6. `SetGlobalGraph(NewDJGraph())` → bo'sh graf HTTP uchun tayyor
7. `InitInfluxClient()` → InfluxDB ulanishi (muvaffaqiyatsiz bo'lsa davom etadi)
8. `LoadSavedData()` → `network_data.json` dan oldingi scan natijalari yuklanadi
9. `startMacIPService()` → orqa fon ARP kesh xizmati boshlanadi
10. `collectGatewayARP()` → gateway ARP jadvalidan MAC→IP mapping
11. `go StartWebServer("8088")` → HTTP server boshlanadi

**4 ta rejim:**

| Rejim | Buyruq | Xatti-harakat |
|-------|--------|---------------|
| `normal` | `./lldp_scanner` | Scan → Graph → Web server → Traffic polling → Alerts → Rescan loop |
| `experiment` | `--mode experiment` | Bir martalik scan → 6 ta JSON eksport → Chiqish |
| `benchmark` | `--mode benchmark` | W=1,10,25,50,100 ketma-ket scan → `benchmark_results.json` → Chiqish |
| `monitor24h` | `--mode monitor24h --duration 24h` | Uzluksiz tsikl: har 60s Snapshot+Diff+InfluxDB. Panic recovery har tsikl. |

### 2.2. Global O'zgaruvchilar va Mutex Strategiyasi

| O'zgaruvchi | Turi | Mutex | Maqsad |
|-------------|------|-------|--------|
| `collectedData` | `map[string]*DeviceData` | `collectedDataMutex` (RWMutex) | Barcha SNMP qurilmalar keshi |
| `globalGraph` | `*DJGraph` | `globalGraphMutex` (RWMutex) | D3.js uchun joriy topologiya |
| `interfaceTrafficMap` | `map[string]map[int]*InterfaceTraffic` | `interfaceTrafficMapMutex` (RWMutex) | Har port trafik tezligi |
| `globalMACtoIP` | `map[string]string` | `globalMACtoIPMutex` (RWMutex) | Gateway ARP dan MAC→IP |
| `dnsCache` | `map[string]string` | `dnsCacheMutex` (RWMutex) | DNS reverse lookup keshi |
| `previousSnapshot` | `*NetworkSnapshot` | `previousSnapshotMutex` (Mutex) | Diff uchun oldingi holat |
| `notifiedIssues` | `map[string]time.Time` | `notifiedMu` (Mutex) | Telegram cooldown tracking |

**Qulf tartibi (Lock Ordering) qoidasi:**
`collectedDataMutex` (#1) → `globalGraphMutex` (#2). Teskari tartibda olish deadlock keltirib chiqaradi. `refreshGraphEdgeLabels()` va `rebuildGraph()` funksiyalari aynan shu tartibga rioya qiladi.

---

## 3. Graf Qurish Logikasi

### 3.1. `buildGraphEdges()` (qator 677-1043)
Har bir qurilma uchun:
1. **LLDP Neighbors** → `RemChassisId` ni normalize qilib edge yaratadi. ChassisID subtype (4=MAC, 5=IP, 7=Locally Assigned) bo'yicha turlicha parse.
2. **MAC Table** → LLDP'dan tanilmagan MAClar uchun endpoint node yaratadi. Filtrlash: switch o'z MACi, boshqa switch MACi, NULL0 port, special/broadcast MAC, trunk port (>20 MAC = implicit uplink).
3. **Hub Detection** → 1 ta access portda 2+ non-VM MAC → `hub-{switch}-p{port}` node yaratiladi, 5 tagacha endpoint ulanadi.
4. **VM Detection** → `isHypervisorPort()` True bo'lsa, har VM MAC alohida node qilib switch→MAC edge yaratiladi (keyin `detectHypervisors` guruhlaydi).

### 3.2. `addMACCrossRefEdges()` (qator 2518-2596)
LLDP qo'llab-quvvatlamaydigan switchlar uchun: Switch A ning MACTable'ida Switch B ning ChassisID MAC ko'rinsa, va bu port faqat **1 ta** switch MAC tutgan bo'lsa → to'g'ridan-to'g'ri ulanish (`[MAC-REF]` label). 2+ switch MAC = transit port, o'tkazib yuboriladi.

### 3.3. `rebuildGraph()` (qator 2598-2652)
`collectedData` dan snapshot olib, qisqa RLock ichida nusxa ko'chiradi. Keyin:
1. Barcha nodlar qo'shiladi (Unreachable holat saqlanadi)
2. `buildGraphEdges()` chaqiriladi
3. `addMACCrossRefEdges()` chaqiriladi
4. `detectHypervisors()` → VM guruhlash
5. `enrichGraphWithIPs()` → MAC-IP keshdan IP boyitish
6. `SetGlobalGraph(newGraph)` → **Atomic swap** — HTTP handlerlar endi yangi grafni ko'radi

### 3.4. `detectHypervisors()` (qator 2654-2806)
**Faza 1:** VM OUI prefixlar (VMware `00:0c:29`, `00:50:56`; KVM `52:54:00`; Hyper-V `00:15:5d`; Xen `00:16:3e`; VirtualBox `08:00:27`) bo'yicha switch→VM edge'larni guruhlaydi. 1 ta portda 2+ VM MAC → `hyp-{switch}-{port}` hypervisor node qo'yiladi, switch→hyp→VM zanjiri yaratiladi.
**Faza 2:** Server NIC OUI (Dell, HPE, SuperMicro, Lenovo, Cisco UCS, Fujitsu, IBM) bo'yicha endpoint node'larni `[HYPERVISOR]` deb belgilaydi. SNMP-managed switch'larni o'tkazib yuboradi.

### 3.5. `refreshGraphEdgeLabels()` (qator 2195-2286)
Har 30 soniyada chaqiriladi. `collectedDataMutex.RLock` → nodeToIP mapping oladi → `globalGraphMutex.Lock` → `graph.Edges` **deep clone** qiladi → klonda trafik ma'lumotlarini yangilaydi (`↓5M ↑3M` format) → `graph.Edges = newEdges` **atomic swap**.

---

## 4. OS Fingerprinting Algoritmi

### 4.1. `detectOSFromMAC()` (qator 1636-1678)
3 bosqichli gibrid identifikatsiya:
1. **LLDP hostname tahlili:** `RemSysName` da "DESKTOP-", "WIN-", "ubuntu", "linux" izlaydi → 🪟/🐧
2. **TTL Fingerprinting:** `detectOSByTTL(ip)` — 1 ta ping, TTL≤64 → Linux, 65-128 → Windows
3. **MAC OUI fallback:** VMware=`00:50:56`/`00:0c:29`, KVM=`52:54:00`, Hyper-V=`00:15:5d`

### 4.2. `detectOSByTTL()` (qator 1680-1720)
`cmd.Start()` + `time.AfterFunc(3s, Kill)` + `go cmd.Wait()` — **zero-goroutine leak** pattern. `exec.CommandContext` ishlatilMAYDI (u har safar `watchCtx` goroutine yaratadi).

### 4.3. `isBMC()` (qator 1769-1874)
2 bosqichli BMC aniqlash:
- **OUI match:** Dell iDRAC (8 ta prefix), HPE iLO (7 ta), Lenovo XCC (5 ta), Supermicro IPMI, IBM IMM, Cisco CIMC, Fujitsu iRMC, ASRock, Inspur, H3C, Huawei iBMC
- **LLDP keyword:** "idrac", "ilo", "ipmi", "bmc", "xclarity", "cimc", "irmc", "asmb" va boshqalar

### 4.4. `isRandomMAC()` (qator 1754-1767)
MAC'ning birinchi oktetining ikkinchi hex belgisi `{2, 6, a, e}` ga teng bo'lsa → locally administered (Wi-Fi random). Masalan: `da:a1:19:...` → 'a' ∈ {2,6,a,e} → random ✅

---

## 5. Orqa Fon Jarayonlar (Background Goroutines)

| Jarayon | Interval | Funksiya | Fayl |
|---------|----------|----------|------|
| **Traffic Polling** | 10s | `startTrafficPolling()` → har qurilma uchun SNMP IF-MIB counterlar o'qiladi, delta hisoblanib bps ga aylanadi. `pollingInProgress sync.Map` bilan takroriy poll oldini oladi. | `example_usage.go:2155` |
| **Label Refresh** | 30s | `startPeriodicLabelRefresh()` → `refreshGraphEdgeLabels()` trafik ko'rsatkichlarini edge label'larga qo'shadi. | `example_usage.go:2308` |
| **Periodic Rescan** | 5min | `startPeriodicRescan()` → barcha ma'lum switch'larni qayta SNMP poll qiladi, `rebuildGraph()`, `discoverFromLLDP()`. | `example_usage.go:2317` |
| **Rescue Scanner** | 7min | `startRescueScanner()` → `swich_ips` faylidan `collectedData` da yo'q IP'larni topib, ping → CollectData. | `example_usage.go:2379` |
| **Periodic Analysis** | 60s | `startPeriodicAnalysis()` → `Analyze()` + Snapshot Diff + InfluxDB write (summary, events). | `example_usage.go:1204` |
| **MAC-IP Service** | 5min | `startMacIPService()` → barcha switch'lardan ARP yig'ish, `mac_ip_cache.json` saqlash. | `mac_ip_service.go` |

### Trafik Hisoblash Algoritmi (`updateTrafficCounters`, qator 2052-2139)
```
InDelta = current.IfInOctets - previous.IfInOctets  (agar current < previous → 0, reset deb qabul qilinadi)
InSpeed = InDelta * 8 / timeDelta  (bps)
Sanity check: speed > linkSpeed * 1.1 → 0 ga reset (counter glitch)
```
Counter wrap (64-bit HC counters bilan) o'nlab yillarda bo'ladi — shuning uchun current < previous holat faqat qurilma restart deb qabul qilinadi.

---

## 6. Tarmoq Tahlili (`analyzer.go`)

### 6.1. 6 xil tahlil moduli

| # | Modul | Funksiya | Algoritm |
|---|-------|----------|----------|
| 1 | **Path** | `analyzePaths()` | BFS chuqurligi > 3 hop → "Core'dan uzoq" ogohlantirish |
| 2 | **Congestion** | `analyzeCongestion()` | Trafik > 800Mbps (80% of 1G) → critical. InDiscards/InErrors → packet loss |
| 3 | **Stability** | `analyzeStability()` | IfOperStatus 1→2 (Down) hodisalar soni → flapping |
| 4 | **Shadow IT** | `analyzeShadowIT()` | Port MAC > 1, non-trunk, non-VM, non-ESXi, non-ignored → unmanaged switch |
| 5 | **STP** | `analyzeSTP()` | Root Bridge MAC core switch'da emasmi tekshiradi |
| 6 | **Loopback** | `analyzeLoopback()` | (a) LLDP self-neighbor: RemChassisId == o'z ChassisID. (b) MAC self-ref: o'z MAC non-trunk portda |

### 6.2. Health Score Formula (qator 774-834)
```
Score = 100
- shadow_it: min(30, count * 5)    // har biri -5, max -30
- congestion (high): -5
- congestion (medium): -2
- physical errors: -2
- stp: min(10, count * 10)         // max -10
- path: -2
- stability: -3
- loopback: -20                    // eng og'ir jarima
Score = max(0, Score)
```

### 6.3. Telegram Bot Integratsiyasi (qator 150-241)
- `notifyTelegramIfCritical()` → `http://127.0.0.1:5005/notify` ga POST
- Har issue uchun 1 soatlik cooldown (`canNotifyIssue()`)
- Shadow IT va Loopback uchun inline keyboard tugmalari: "❌ E'tiborsiz qoldirish" / "✅ To'g'irlandi"
- `AddTelegramTiming()` → xabar yuborish vaqtini `telegram_timing.json` ga eksport

---

## 7. Snapshot Diff Engine (`snapshot_diff.go`)

### 7.1. `CreateSnapshot()` (qator 168-279)
Hozirgi `collectedData` dan `NetworkSnapshot` yaratadi:
- `ActiveMACs`: har qurilmaning MACTable dan (special MAC'lar filtrlanadi)
- `ActiveHosts`: IP → {SysName, Vendor, Health, Unreachable}
- `Ports`: SwitchIP → PortIndex → IfOperStatus (Phase 8 uchun)
- `Anomalies`: Report Suggestions dan per-device anomaly turlar ro'yxati

### 7.2. `CompareSnapshots()` (qator 282-406)
$V_{new} = V_{t2} \setminus V_{t1}$ formulasi asosida:
- **MAC JOIN/LEAVE**: hozirgi-oldingi (va aksincha) farqi
- **Host JOIN/LEAVE**: SNMP-reachable xostlar farqi
- **Unreachable/Restored** (Phase 8): `Unreachable` flag o'zgarishi
- **Port Status Changes** (Phase 8): IfOperStatus 1↔2 o'zgarishlar
- **Anomaly New/Fixed**: anomaliya turlarining paydo/yo'qolishi

### 7.3. Event → InfluxDB (`persistEventToInflux`, qator 136-156)
Phase 14: `openEventTimes` keshida port_down/host_down boshlanish vaqtini saqlaydi. port_up/host_up kelganda duration hisoblanadi va `WriteNetworkEventToInflux()` ga uzatiladi.

---

## 8. SNMP Ma'lumot Yig'ish

### 8.1. `SNMPObject` (`snmp_object.go`, 951 qator)
`CollectData(ip, sysName)` funksiyasi `snmpbulkwalk` orqali quyidagilarni yig'adi:

| MIB | OID | Nima olinadi |
|-----|-----|-------------|
| LLDP-MIB | `1.0.8802.1.1.2.1.3` | Local ChassisID, ChassisIdSubtype |
| LLDP-MIB RemTable | `1.0.8802.1.1.2.1.4.1.1` | RemChassisId, RemPortId, RemSysName, RemSysDesc, RemMgmtAddr |
| IF-MIB | `1.3.6.1.2.1.2.2.1` | ifDescr, ifSpeed, ifOperStatus, ifAdminStatus, ifPhysAddress |
| IF-MIB HC | `1.3.6.1.2.1.31.1.1.1` | ifHCInOctets, ifHCOutOctets (64-bit), ifAlias, ifInErrors, ifOutErrors, ifInDiscards, ifOutDiscards |
| BRIDGE-MIB | `1.3.6.1.2.1.17.4.3.1` | dot1dTpFdbAddress → MAC Table (port mapping via dot1dBasePort→ifIndex) |
| IP-ARP | `1.3.6.1.2.1.4.22.1` | ipNetToMediaPhysAddress → ARP Table |
| Q-BRIDGE | `1.3.6.1.2.1.17.7.1.4.5.1` | dot1qPvid → Port VLAN IDs, Trunk detection |
| STP | `1.3.6.1.2.1.17.2.5` | dot1dStpDesignatedRoot → Root Bridge ID |

Yig'ish `cmd.Start() + time.AfterFunc(timeout, Kill)` bilan — goroutine leak yo'q.

### 8.2. `SNMPScanner` (`snmp_scanner.go`, 340 qator)
- `ScanFromFile("swich_ips")` → IP/CIDR ro'yxat o'qiladi → `ExpandNetworks()` → individual IP'lar
- `Scan(ips)` → `MaxWorkers` ta goroutine (standart 50) `workerChan` dan IP o'qib `scanIP()` chaqiradi
- `scanIP()` → `isHostAlive(ip)` (ping) → `testSNMP(ip)` (sysDescr/sysName/sysUpTime GET)
- `pingHost()` → zero-goroutine ICMP: `cmd.Start()` + `time.AfterFunc` kill + `go cmd.Wait()`

---

## 9. MAC-IP Service va Subnet Kashfiyoti (`mac_ip_service.go`)

### 9.1. Orqa fon ARP yig'ish (`startMacIPService`)
Har 5 daqiqada `collectARPFromAllSwitches()`:
1. `collectedData` dagi barcha switch IP'larni oladi
2. Har biriga parallel SNMP ARP table so'rovi
3. Natijalarni `macIPCache` (global map) ga birlashtiradi
4. `mac_ip_cache.json` ga saqlaydi

### 9.2. Gateway Subnet Discovery (`discoverGatewaySubnets`)
`gateway_ip` dagi har bir gateway'dan SNMP orqali (umumiy subnet bir marta):
1. `ipAdEntAddr` (1.3.6.1.2.1.4.20.1.1) → SVI IP'lar ro'yxati
2. `ipAdEntNetMask` (1.3.6.1.2.1.4.20.1.3) → subnet maskalari
3. `SubnetInfo{Net, Prefix, SVIIP}` strukturasi qaytariladi

### 9.3. ESXi HTTP Validatsiya (`queueESXiValidation`)
- 100 ta parallel goroutine (`esxiCheckWorker`) `esxiQueue` kanalidan ish olinadi
- `https://{ip}:443` ga ulanib, javobda "VMware ESXi" yozuvi izlanadi
- Tasdiqlangan MAC'lar `ConfirmedESXiMACs` (sync.Map) ga qo'shiladi → Shadow IT filtrda ishlatiladi

### 9.4. `enrichGraphWithIPs()` (qator 534-580)
Global graf node'larini MAC-IP keshdan boyitadi: agar node ID MAC formatida va keshda IP topilsa → `SwitchInfo[nodeID]` ga IP qo'shiladi.

---

## 10. REST API (`web_server.go`, 1,127 qator)

### 10.1. Asosiy API Endpointlar

| Endpoint | Method | Handler | Vazifasi |
|----------|--------|---------|----------|
| `/api/graph` | GET | `graphHandler` | D3.js graf: nodes (anomaliyalar bilan), links (trafik bilan), healthScore, totalMACs |
| `/api/hosts` | GET/DELETE | `hostsHandler` | Barcha qurilmalar ro'yxati / hammasini o'chirish |
| `/api/settings` | GET/POST | `settingsHandler` | IP ranges, community, timeout, workers sozlamalari |
| `/api/rescan` | POST | `rescanHandler` | To'liq qayta skanerlashni boshlash |
| `/api/status` | GET | `statusHandler` | hosts/nodes/edges soni, settings, hasSaved |
| `/api/history` | GET | `historyHandler` | InfluxDB dan trafik tarixi (`?id=IP&hours=24`) |
| `/api/device-detail` | GET | `deviceDetailHandler` | Qurilma interfeyslari, VLAN, real-time trafik |
| `/api/bot/action` | POST | `botActionHandler` | Telegram "Ignore"/"Verify" tugmalari |
| `/api/capture/start` | POST | `captureStartHandler` | Capture sessiya boshlash |
| `/api/capture/stop` | POST | `captureStopHandler` | Capture sessiya to'xtatish |
| `/api/captures` | GET | `capturesHandler` | Capture sessiyalar ro'yxati |
| `/api/report/generate` | POST | `reportGenerateHandler` | Capture uchun tahlil hisobot |
| `/api/report/download` | GET | `reportDownloadHandler` | MS Word (.doc) yuklab olish |
| `/api/report/summary` | GET | `reportSummaryHandler` | Topologiya xulosasi JSON |
| `/api/report/topology-svg` | GET | `reportTopologySVGHandler` | Topologiya SVG rasmi |
| `/api/report/audit-md` | GET | `reportAuditMDHandler` | GOST Markdown hisobot |
| `/api/report/audit-docx` | GET | `reportAuditDocxHandler` | GOST DOCX hisobot (Python orqali) |
| `/api/experiment/start` | POST | `experimentStartHandler` | Eksperiment boshlash |
| `/api/experiment/status` | GET | `experimentStatusHandler` | Eksperiment holati |
| `/api/experiment/stop` | POST | `experimentStopHandler` | Eksperiment to'xtatish |
| `/api/experiment/results` | GET | `experimentResultsHandler` | `results/` papkadagi JSON fayllar |
| `/api/events` | GET | `eventsHandler` | So'nggi 200 ta network event |
| `/api/port-events` | GET/DELETE | `portEventsHandler` | InfluxDB dan event tarixi (10 tur, filter) |
| `/api/port-events/stats` | GET | `portEventsStatsHandler` | Port event statistikasi |
| `/api/terminal` | WS | `terminalHandler` | WebSocket SSH/Telnet |
| `/api/check-ports` | GET | `checkPortsHandler` | SSH/Telnet port skanerlash |

### 10.2. `graphHandler` boyitish (qator 145-181)
`globalGraphMutex.RLock()` ichida graf olinadi. `lastReportMutex.RLock()` ichida anomaliya ma'lumotlari har node'ga qo'shiladi. Natija `graphs_data.txt` ga ham yoziladi (debug).

---

## 11. InfluxDB Integratsiya (`influx_client.go`)

| Funksiya | Measurement | Yozadigan maydonlar |
|----------|-------------|---------------------|
| `WriteInterfaceMetric()` | `interface_metrics` | in_bps, out_bps, in_octets, out_octets, in_errors, out_errors, in_discards, out_discards, oper_status |
| `WriteDeviceEvent()` | `device_events` | event_type (join/leave), mac, ip, switch_ip, vendor |
| `WriteNetworkSummary()` | `network_summary` | active_hosts, unique_macs, shadow_it_ports, health_score, random_macs |
| `WriteAnomalySummary()` | `anomaly_summary` | path_issues, congestion_issues, stability_issues, shadow_it_issues, stp_issues, loopback_issues |
| `WriteNetworkEventToInflux()` | `network_events` | event_type, switch_ip, port, mac, ip, message, duration_s |
| `QueryTrafficHistory()` | ← `interface_metrics` | deviceIP bo'yicha so'nggi N soat trafik tarixi |
| `QueryNetworkEvents()` | ← `network_events` | IP, soat, event turi bo'yicha filtrlangan tarix |

---

## 12. Hisobot Generatsiya (`report_topology.go`)

### 12.1. `GenerateTopologySVG()` — SVG formatda topologiya chizish
Node'lar doira, edge'lar chiziq, rangli kodlash (switch=ko'k, router=yashil, hypervisor=binafsha).

### 12.2. `generateAuditMD()` — GOST Markdown hisobot
Barcha qurilmalar jadvali, per-group topologiya diagrammalari (Mermaid), Shadow IT/Hypervisor diagrammalari, VLAN xulosasi.

### 12.3. `reportAuditDocxHandler()` — Word DOCX
Markdown → DOCX: Python `md2docx_gost_linux.py` skripti tashqi jarayon sifatida chaqiriladi. SVG → Base64 img tag orqali hujjatga joylashtiriladi.

---

## 13. Terminal Handler (`terminal_handler.go`)

- `scanPorts(ip)` → SSH (22, 2222, 830, 8022) va Telnet (23, 2323) portlarni tekshiradi
- `terminalHandler()` → WebSocket ulanishi ochiladi, parametrlar: `type=ssh|telnet`, `ip`, `user`, `pass`, `cols`, `rows`
- `handleSSHSession()` → `golang.org/x/crypto/ssh` orqali PTY sessiya
- `handleTelnetSession()` → TCP ulanishi + IAC buyruqlar filtri (`filterTelnetIAC`)

---

## 14. Dynamic Discovery (Phase 15)

### 14.1. `startRescueScanner()` — O'lik Node Recovery
Har 7 daqiqada `swich_ips` faylidagi IP'lardan `collectedData` da yo'qlarini topib, ping → alive bo'lsa `CollectData()` → `rebuildGraph()`.

### 14.2. `discoverFromLLDP()` — LLDP Zanjir Kashfiyoti
Barcha yig'ilgan qurilmalarning LLDP `RemMgmtIP` maydonlaridan hali skanqilinmagan IP'lar topiladi → `appendToSwitchIPs()` bilan `swich_ips` ga qo'shiladi → darhol `CollectData()` → `rebuildGraph()`. Bu "chain reaction" kashfiyot imkonini beradi.

---

## 15. Benchmark Natijalari (`results/benchmark_results.json`)

| Workers | Vaqt | Qurilmalar | SNMP OK |
|---------|------|------------|---------|
| W=1 | 31 daqiqa 44s | 69 | 68 |
| W=10 | 3 daqiqa 10s | 69 | 68 |
| W=25 | 1 daqiqa 16s | 69 | 68 |
| W=50 | 38.2s | 69 | 68 |
| W=100 | **20.0s** | 68 | 67 |

**Tezlashuv:** W=1 vs W=100 = **~95x speedup**.

---

## 16. 24-Soat Monitoring Barqarorligi

Cron (`start_monitor.sh`) har kuni 05:00 da `--mode=monitor24h --duration=24h` rejimida ishga tushadi.
- **Isbotlangan natija:** 24 soat ichida **1,451 tsikl**, **900,000+ InfluxDB record**, **0 crash**.
- Har tsikl `recover()` bilan o'ralgan — bitta tsikl panic bo'lsa ham keyingisi davom etadi.
- InfluxDB eksport skripti: `results/24h/export_influx_graphs.sh` → 5 ta CSV (active_hosts, health_score, device_events, anomaly_summary, traffic_metrics).
