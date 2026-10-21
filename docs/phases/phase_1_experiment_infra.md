# FAZA 1: EKSPERIMENT INFRATUZILMASI

> **Guruh:** A (upgrade.md dan)
> **Maqsad:** Eksperiment natijalarini yig'ish va saqlash uchun infratuzilma yaratish
> **Oldingi dependency:** Yo'q (birinchi faza)
> **Taxminiy vaqt:** 1–2 kun

---

## Umumiy Ko'rinish

Bu faza dasturga eksperiment rejimi, benchmark, va turli metrikalar eksportini qo'shadi. Barcha natijalar `results/` papkasiga JSON formatida saqlanadi.

---

## A.1. Eksperiment rejimi (`--experiment` flag)

**Fayl:** `example_usage.go`

Dasturga `--experiment` CLI flag qo'shish kerak. Bu flag yoqilganda dastur har bir bosqichning (ICMP discovery, SNMP collection, graph build, analysis) bajarilish vaqtini millisekundlarda o'lchab, natijalarni JSON faylga saqlashi kerak.

**JSON faylda quyidagi maydonlar bo'lishi kerak:**
- Eksperiment ID si
- Worker soni
- Jami IP lar soni
- ICMP discovery vaqti (ms)
- SNMP collection vaqti (ms)
- Jami vaqt (ms)
- Topilgan qurilmalar soni
- Yig'ilgan MAC lar soni
- LLDP qo'shnilar soni
- Graf node va edge lari soni
- Vaqt tamg'asi

**Natija fayli:** `results/experiment_YYYY-MM-DD_HH-MM-SS.json`

---

## A.2. Worker Benchmark rejimi (`--benchmark` flag)

**Fayl:** `snmp_scanner.go` va `example_usage.go`

Dasturga `--benchmark` CLI flag qo'shish kerak. Bu flag yoqilganda dastur bir xil tarmoqni ketma-ket 5 marta skanerlaydi: W=1, W=10, W=25, W=50, W=100 worker bilan. Har bir skanerlashning vaqti o'lchanib, natijalar bitta JSON faylga yoziladi.

Bu rejim `MaxWorkers` parametrini o'zgartiradi va har safar yangi `SNMPScanner` yaratadi. Natija — 5 ta yozuvdan iborat JSON massiv, har birida worker soni va mos keluvchi vaqt.

**Natija fayli:** `results/benchmark_results.json`

> Bu ma'lumotdan keyin grafik chiziladi (X: worker soni, Y: skanerlash vaqti).

---

## A.3. Individual HealthScore export

**Fayl:** `analyzer.go`

Har bir SNMP qurilma (switch/router) uchun alohida Health Score va aniqlangan anomaliyalar ro'yxatini JSON faylga yozadigan funksiya qo'shish kerak.

**JSON tuzilmasi:**

Har bir qurilma uchun:
- IP manzili
- sysName
- Vendor nomi
- Health score (0–100)
- Anomaliyalar ro'yxati (masalan: `["shadow_it", "congestion"]`)
- Port soni, MAC soni

Umuman tarmoq bo'yicha:
- O'rtacha Health Score
- Minimal va maksimal ball
- Jami anomaliyalar soni

**Natija fayli:** `results/health_scores.json`

---

## A.4. BFS Depth export

**Fayl:** `analyzer.go` — `analyzePaths` funksiyasi ichida

BFS (Breadth-First Search) natijasida har bir qurilmaning Core switchdan hop uzoqligini JSON ga yozish kerak.

**JSON tuzilmasi:**
- Core switch IP si
- Depth taqsimoti (Hop=0: nechta, Hop=1: nechta, ...)
- Maksimal depth
- O'rtacha depth
- Depth > 3 bo'lgan qurilmalar ro'yxati

**Natija fayli:** `results/bfs_depths.json`

---

## A.5. Telegram vaqt loglash

**Fayl:** `analyzer.go` — `notifyTelegramIfCritical` funksiyasi ichida

Anomaliya aniqlangandan Telegram xabar yuborilguncha o'tgan vaqtni (millisekundlarda) qayd etish kerak.

**Ishlash tartibi:**
1. Anomaliya aniqlangan paytda `t_detect = time.Now()` yoziladi
2. Telegram ga yuborilgandan keyin `t_notify = time.Now()` yoziladi
3. Farqi logga va JSON ga saqlanadi

**Natija fayli:** `results/telegram_timing.json`

---

## A.6. Vendor statistikasi

**Fayl:** `snmp_scanner.go`

Har bir vendor (HPE, SNR, Huawei, Fortinet, Ubiquiti va boshqalar) uchun quyidagi statistikani hisoblash va JSON ga yozish kerak:
- Vendor nomi
- Jami qurilmalar soni
- SNMP muvaffaqiyat/xatolik soni
- LLDP muvaffaqiyat/xatolik soni
- FDB muvaffaqiyat/xatolik soni

**Natija fayli:** `results/vendor_stats.json`

---

## Tekshirish Ro'yxati

- [ ] `--experiment` flag ishlaydi va JSON yaratadi
- [ ] `--benchmark` flag W=1,10,25,50,100 bilan ishlaydi
- [ ] `results/health_scores.json` to'g'ri formatda yaratiladi
- [ ] `results/bfs_depths.json` BFS natijalarini o'z ichiga oladi
- [ ] `results/telegram_timing.json` vaqtlarni qayd qiladi
- [ ] `results/vendor_stats.json` vendor statistikasini saqlaydi
- [ ] `go build` xatosiz tugaydi
