# DASTURNI YANGILASH REJASI (UPGRADE PLAN)

> **Bu fayl nima:** `lldp_go` dasturiga qo'shiladigan barcha o'zgartirishlarning umumiy navigatsiya fayli.
> **Kim uchun:** Keyingi AI agent yoki dasturchi uchun.
> **Batafsil instruksiyalar:** Har bir faza alohida faylda → `docs/phases/` papkasida.
> **Natijalar:** Har bir faza uchun natija fayli → `results/` papkasida.

---

## Fazalar Ketma-ketligi

```
Faza 1 → 2 → 3 → 4 → 5 → 6 → 7 → 8 → 9 → 10 → 11 → 12 → 13
```

| # | Faza | Holat | Nima qilinadi | Natija fayli |
|---|------|:-----:|---------------|--------------|
| 0 | [📋 Umumiy Ko'rinish](phases/phase_0_overview.md) | — | Dependency diagramma | — |
| 1 | [🔬 Eksperiment Infra](phases/phase_1_experiment_infra.md) | ✅ | Benchmark, export, timing, vendor stats | [phase_01](../results/phase_01_experiment_infra.md) |
| 2 | [🔄 Snapshot Diff](phases/phase_2_snapshot_diff.md) | ✅ | Diff engine, InfluxDB events, summaries | [phase_02](../results/phase_02_snapshot_diff.md) |
| 3 | [🔍 Qurilma Identity](phases/phase_3_device_identity.md) | ✅ | DNS lookup, isRandomMAC, OUI vendor DB | [phase_03](../results/phase_03_device_identity.md) |
| 4 | [🎛 Experiment Mgmt](phases/phase_4_experiment_mgmt.md) | ✅ | CLI flags, rejimlar, web panel API | [phase_04](../results/phase_04_experiment_mgmt.md) |
| 5 | [🎨 UI Yaxshilash](phases/phase_5_ui_improvements.md) | ✅ | Health widget, glow, legend, status bar | [phase_05](../results/phase_05_ui_improvements.md) |
| 6 | [📄 Hisobot Tizimi](phases/phase_6_report_system.md) | ✅ | 9 bo'limli GOST DOCX, 6 API endpoint | [phase_06](../results/phase_06_report_system.md) |
| 7 | [📸 ESXi + Screenshots](phases/phase_7_discovery_and_esxi.md) | ⚠️ | ESXi detect ✅, 23 screenshot ❌ | [phase_07](../results/phase_07_discovery_esxi.md) |
| 8 | [🔗 MAC-IP Service](phases/mac-service.md) | ✅ | ARP polling, MAC→IP cache, graf boyitish | [phase_08](../results/phase_08_mac_ip_service.md) |
| 9 | 🖥 Web Terminal | ✅ | SSH/Telnet WebSocket proxy, xterm.js | [phase_09](../results/phase_09_web_terminal.md) |
| 10 | 📊 Capture & History | ✅ | Capture sessiya, InfluxDB, History UI | [phase_10](../results/phase_10_capture_history.md) |
| 11 | 💾 SNMP Config Backup | 📋 | SSH config pull, versiyalash, diff | — |
| 12 | 🔔 Alerting & Notification | ✅ | 6 anomaly, Telegram bot, Cooldown | [phase_12](../results/phase_12_alerting.md) |
| 13 | 📈 Dashboard & Analytics | ✅ | D3.js, Zabbix export, OUI, Settings | [phase_13](../results/phase_13_dashboard.md) |

**Holat:** 12/13 faza bajarilgan ✅ | 1 ta rejalashtirilgan 📋

---

## Muhim Qoidalar

1. **Ketma-ketlik saqlanishi shart** — har bir faza oldingisiga tayanadi
2. **Har bir faza tugaganda** `go build` muvaffaqiyatli bo'lishi kerak
3. **Natijalar** `results/` papkasida MD va JSON formatida saqlanadi
4. **Bilimlar bazasi:** `docs/phases/fix.md` — barcha bugfix va yechimlar

---

## Yaratilgan Fayllar (Fazalar bo'yicha)

| Fayl | Faza | Tavsif |
|------|:----:|--------|
| `snmp_scanner.go` | 1 | SNMP scanner (CIDR, ping, parallel) |
| `experiment_exports.go` | 1 | 6 ta eksport funksiyasi |
| `snapshot_diff.go` | 2 | Snapshot diff + events |
| `influx_client.go` | 2 | InfluxDB client (4 measurement) |
| `oui_lookup.go` | 3 | OUI vendor lookup (280+ entry) |
| `dj_graph.go` | 3,13 | Graf + Zabbix export |
| `web_server.go` | 4,5 | 30+ API endpoint |
| `report_topology.go` | 6 | Hisobot generatsiya (1525 qator) |
| `instrumens/md2docx_gost_linux.py` | 6 | GOST DOCX konvertor |
| `snmp_object.go` | 7 | ESXi detect, hypervisor logic |
| `mac_ip_service.go` | 8 | MAC-IP discovery service |
| `terminal_handler.go` | 9 | SSH/Telnet WebSocket proxy |
| `capture.go` | 10 | Capture manager |
| `analyzer.go` | 12 | 6 analysis + Telegram bot |
| `ignored_issues.go` | 12 | Ignore/Verify persistence |
| `settings.go` | 13 | Scan settings boshqaruvi |
| `static/index.html` | 5,13 | Dashboard HTML |
| `static/app.js` | 5,9,13 | D3.js + xterm.js logika |
| `static/history.html` | 10 | History sahifasi |

---

## Asl Guruhlardan Fazalarga Mapping

| Asl Guruh (upgrade.md) | Faza | Izoh |
|-------------------------|------|------|
| A (Eksperiment Infra) | Faza 1 | ✅ To'liq |
| B (Snapshot Diff) | Faza 2 | ✅ To'liq |
| C (Qurilma Identity) | Faza 3 | ✅ To'liq |
| G (Eksperiment Mgmt) | Faza 4 | ✅ To'liq |
| E (UI Yaxshilash) | Faza 5 | ✅ To'liq |
| F (Hisobot Tizimi) | Faza 6 | ✅ To'liq (9 bo'lim, GOST DOCX) |
| D (Screenshotlar) | Faza 7 | ⚠️ ESXi ✅, Screenshots ❌ |
| — (Yangi) | Faza 8 | ✅ MAC-IP Service |
| — (Yangi) | Faza 9 | ✅ Web Terminal |
| — (Yangi) | Faza 10 | ✅ Capture & History |
| — (Yangi) | Faza 11 | 📋 SNMP Config Backup |
| — (Yangi) | Faza 12 | ✅ Alerting & Notification |
| — (Yangi) | Faza 13 | ✅ Dashboard & Analytics |

> **Yangilangan:** 2026-03-26. Asl 7 fazaga 6 ta yangi faza qo'shildi (8–13).

