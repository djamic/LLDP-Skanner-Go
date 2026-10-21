# FAZA 2: SNAPSHOT DIFF ENGINE

> **Guruh:** B (upgrade.md dan)
> **Maqsad:** 24 soatlik monitoring va qurilmalar dinamikasini kuzatish uchun diff tizimi yaratish
> **Oldingi dependency:** Faza 1 (eksperiment infratuzilmasi)
> **Taxminiy vaqt:** 1 kun

---

## Umumiy Ko'rinish

Bu faza yangi modul yaratadi — har skanerlash yakunida oldingi natija bilan hozirgi natijani avtomatik solishtiradigan tizim. Natijalar InfluxDB ga yoziladi.

---

## B.1. Snapshot Diff Engine — asosiy modul

**Yangi fayl:** `snapshot_diff.go`

Ikkita asosiy struct kerak:

### NetworkSnapshot — bitta skanerlash natijasi
- Vaqt tamg'asi
- Faol MAC lar xaritasi (MAC → IP, port, switch, vendor ma'lumoti)
- Faol hostlar xaritasi (IP → sysName, vendor, health score)
- Anomaliyalar xaritasi (IP → anomaliya turlari ro'yxati)
- Health Score
- Graf tugun va bog'lanishlar soni

### SnapshotDiff — ikki snapshot orasidagi farq
- Yangi paydo bo'lgan MAC lar ro'yxati (**DEVICE_JOIN**)
- Yo'qolgan MAC lar ro'yxati (**DEVICE_LEAVE**)
- Yangi topilgan SNMP qurilmalar
- Javob bermay qolgan SNMP qurilmalar
- Yangi anomaliyalar
- Tuzatilgan (yo'qolgan) anomaliyalar
- Health Score farqi
- MAC soni farqi

### CompareSnapshots funksiyasi
Oldingi va hozirgi snapshot ni qabul qilib, `SnapshotDiff` qaytaradi.

**Mantiq:**
- Hozirgi MAC larda bor lekin oldingida yo'q → **JOIN**
- Oldingida bor lekin hozirda yo'q → **LEAVE**
- Xuddi shu mantiq anomaliyalar uchun ham

### Integratsiya (`example_usage.go` → `startPeriodicAnalysis`)
1. Dastur boshlanadi → `previousSnapshot = nil`
2. Har skanerlash tugaganda → `currentSnapshot` yaratiladi
3. Agar `previousSnapshot != nil` → `diff = CompareSnapshots(previousSnapshot, currentSnapshot)`
4. diff asosida: log yozish, InfluxDB ga yozish, Telegram xabar (yangi anomaliya bo'lsa)
5. `previousSnapshot = currentSnapshot` → keyingi tsiklda foydalanish uchun

---

## B.2. DEVICE_JOIN / DEVICE_LEAVE InfluxDB ga yozish

**Fayl:** `influx_client.go` ga yangi funksiya

Har bir JOIN/LEAVE hodisasini InfluxDB ga yozadigan funksiya kerak.

| Parametr | Qiymat |
|----------|--------|
| Measurement | `device_events` |
| Tags | `event_type` ("join" / "leave"), `vendor` |
| Fields | `mac`, `ip`, `switch_ip` |

Bu funksiya Diff Engine topgan har bir JOIN va LEAVE uchun chaqiriladi.

---

## B.3. network_summary metrikasi

**Fayl:** `influx_client.go` ga yangi funksiya

Har skanerlash tsiklida tarmoqning umumiy holatini InfluxDB ga yozadigan funksiya.

| Parametr | Qiymat |
|----------|--------|
| Measurement | `network_summary` |
| Fields | `active_hosts`, `unique_macs`, `shadow_it_ports`, `health_score`, `random_macs` |

---

## B.4. anomaly_summary metrikasi

**Fayl:** `analyzer.go` — `Analyze()` funksiyasi yakunida

Har tahlil tsiklida barcha anomaliya turlarining sonini InfluxDB ga yozish.

| Parametr | Qiymat |
|----------|--------|
| Measurement | `anomaly_summary` |
| Fields | `shadow_it_count`, `loopback_count`, `congestion_count`, `flapping_count`, `stp_count` |

---

## Tekshirish Ro'yxati

- [ ] `snapshot_diff.go` yangi fayl yaratilgan
- [ ] `NetworkSnapshot` va `SnapshotDiff` struct'lari to'g'ri
- [ ] `CompareSnapshots()` JOIN/LEAVE ni to'g'ri aniqlaydi
- [ ] `startPeriodicAnalysis()` ga Snapshot Diff integratsiya qilingan
- [ ] InfluxDB ga `device_events` yozilmoqda
- [ ] InfluxDB ga `network_summary` yozilmoqda
- [ ] InfluxDB ga `anomaly_summary` yozilmoqda
- [ ] `go build` xatosiz tugaydi
