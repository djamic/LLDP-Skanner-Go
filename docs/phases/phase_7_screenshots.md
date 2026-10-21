# FAZA 7: SCREENSHOTLAR VA HISOBOTLAR

> **Guruh:** D (upgrade.md dan)
> **Maqsad:** Barcha o'zgartirishlardan keyin screenshotlar olish
> **Oldingi dependency:** Barcha fazalar (1–6) tugagan bo'lishi kerak
> **Taxminiy vaqt:** 0.5 kun

---

## ⚠️ Muhim

Bu faza **kod o'zgartirish emas** — faqat screenshotlar ro'yxati. Barcha o'zgartirishlar qo'shilgandan keyin olinadi.

---

## D.1. Interfeys screenshotlari (5 ta)

| # | Screenshot | Izoh |
|---|-----------|------|
| 1 | **D3.js Topologiya** | To'liq holda, barcha switchlar, routerlar, endpointlar |
| 2 | **Topologiya zoom** | Bitta switch va unga ulangan qurilmalar |
| 3 | **Topologiya hostname bilan** | Qurilmalar IP o'rniga nomlar bilan (C.1 dan keyin) |
| 4 | **Topologiya Wi-Fi** | Random MAC lar alohida rangda (C.3 dan keyin) |
| 5 | **Topologiya anomaliya** | Shadow IT portlari qizil glow bilan (E.2 dan keyin) |

---

## D.2. Telegram Bot screenshotlari (3 ta)

| # | Screenshot | Izoh |
|---|-----------|------|
| 1 | **Shadow IT xabarnomasi** | Ignore/Verify tugmalari bilan |
| 2 | **Loopback ogohlantirish** | Qizil emoji bilan |
| 3 | **Ignore/Verify javob** | Ma'mur tugmani bosgandan keyin tizim reaksiyasi |

---

## D.3. Hisobot screenshotlari (3 ta)

| # | Screenshot | Izoh |
|---|-----------|------|
| 1 | **DOCX Audit** | Word faylining birinchi sahifasi (sarlavha, sana, umumiy ma'lumot) |
| 2 | **DOCX anomaliyalar jadvali** | Hisobotdagi anomaliyalar bo'limi |
| 3 | **DOCX topologiya** | Hisobotga kiritilgan tarmoq sxemasi rasmi |

---

## D.4. InfluxDB / Grafana screenshotlari (5 ta, 24 soatlik sinov uchun)

| # | Screenshot | Ma'lumot manbai |
|---|-----------|-----------------|
| 1 | **Faol qurilmalar soni** — 24 soat grafik | `network_summary` → `active_hosts` |
| 2 | **Tarmoq bandligi** — 24 soat grafik | `traffic_metrics` |
| 3 | **Health Score** — 24 soat grafik | `network_summary` → `health_score` |
| 4 | **DEVICE_JOIN/LEAVE timeline** — 24 soat grafik | `device_events` |
| 5 | **Anomaliyalar stacked chart** — 24 soat grafik | `anomaly_summary` |

---

## D.5. Terminal va Log screenshotlari (7 ta)

| # | Screenshot | Izoh |
|---|-----------|------|
| 1 | Dastur ishga tushganda | Splash screen, versiya, parametrlar |
| 2 | ICMP Discovery jarayoni | Faol qurilmalar topilmoqda |
| 3 | SNMP Data Collection | Ma'lumot yig'ilmoqda |
| 4 | Anomaliya aniqlandi | Logda Shadow IT/Loopback xabari |
| 5 | Benchmark natijasi | W=1,10,25,50,100 vaqtlari |
| 6 | DEVICE_JOIN log | Yangi qurilmalar paydo bo'lmoqda (ertalab) |
| 7 | DEVICE_LEAVE log | Qurilmalar o'chmoqda (kechqurun) |

---

## Jami Screenshotlar: 23 ta

| Kategoriya | Soni |
|-----------|------|
| Interfeys | 5 |
| Telegram | 3 |
| Hisobot | 3 |
| InfluxDB/Grafana | 5 |
| Terminal/Log | 7 |
| **Jami** | **23** |
