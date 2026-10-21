# FAZA 4: EKSPERIMENT BOSHQARUVI

> **Guruh:** G (upgrade.md dan)
> **Maqsad:** Eksperimentlarni oson boshqarish uchun CLI rejimlar va Web API
> **Oldingi dependency:** Faza 1 (infra), Faza 2 (snapshot diff), Faza 3 (identity)
> **Taxminiy vaqt:** 1 kun

---

## Umumiy Ko'rinish

Bu faza dasturni 4 ta rejimda ishga tushirish imkonini beradi va web panel orqali eksperimentlarni boshqarish uchun API qo'shadi.

---

## G.1. CLI flag tizimi

**Fayl:** `example_usage.go` — `main` funksiyasi

### Flaglar

| Flag | Tavsif | Standart |
|------|--------|----------|
| `--mode` | Ish rejimi: `normal`, `experiment`, `benchmark`, `monitor24h` | `normal` |
| `--workers` | Parallel ishchilar soni | `50` |
| `--exp-id` | Eksperiment identifikatori (masalan: `"tuit_w50_march"`) | — |
| `--duration` | Monitoring davomiyligi (masalan: `"24h"`, `"1h"`, `"30m"`) | — |
| `--output` | Natijalar papkasi | `"results"` |
| `--networks` | IP diapazoni (masalan: `"172.20.254.0/24,172.20.253.0/24"`) | — |
| `--community` | SNMP community string | `"public"` |

### Rejimlar

- **`normal`** — oddiy rejim (web server + davriy skanerlash, hozirgi xatti-harakat)
- **`experiment`** — bir martalik skanerlash, barcha natijalarni JSON ga yozish (6 ta fayl)
- **`benchmark`** — W=1,10,25,50,100 bilan ketma-ket skanerlash, natijalarni bitta JSON ga yozish
- **`monitor24h`** — belgilangan davr uzluksiz har minutda skanerlash, InfluxDB ga yozish

---

## G.2. Eksperiment rejimi (runExperimentMode)

**Fayl:** `example_usage.go` — yangi funksiya

Bu funksiya bitta to'liq skanerlash tsiklini bajarib, barcha natijalarni JSON fayllar sifatida saqlaydi.

**Bosqichlar:**
1. `results/` papkasini yaratish
2. ICMP Discovery — vaqtini o'lchash
3. SNMP Data Collection — vaqtini o'lchash
4. Graph Build — tugun va bog'lanishlar sonini saqlash
5. Analysis — anomaliyalar, Health Score, BFS depth, vendor statistika
6. Jami 6 ta JSON faylni saqlash: metrics, health, bfs, vendors, anomalies, graph
7. Konsolga xulosa chiqarish

**Fayllar nomi:** `{exp-id}_metrics.json`, `{exp-id}_health.json`, va hokazo.

---

## G.3. 24 soatlik monitoring rejimi (runMonitor24h)

**Fayl:** `example_usage.go` — yangi funksiya

Bu funksiya belgilangan davr davomida (masalan 24 soat) har minutda skanerlash, Snapshot Diff Engine orqali o'zgarishlarni aniqlash, va natijalarni InfluxDB ga yozish.

**Ishlash mantiqi:**
1. Boshlash vaqti va tugash vaqtini hisoblash
2. `previousSnapshot = nil`
3. Tsikl: `time.Now() < endTime` bo'lgunga qadar:
   - Skanerlash (Scan + Analyze)
   - `currentSnapshot` yaratish
   - Agar `previousSnapshot` bor → `CompareSnapshots` → diff
   - diff asosida: InfluxDB ga `WriteNetworkSummary`, `WriteDeviceEvent` (har JOIN/LEAVE uchun), `WriteAnomalySummary`
   - JOIN/LEAVE larni logga yozish
   - `previousSnapshot = currentSnapshot`
   - 60 sekund kutish (skanerlash vaqtini hisobga olib)
4. Tsikl tugaganda yakuniy xulosa JSON saqlanadi:
   - Boshlash vaqti, tugash vaqti
   - Jami tsikllar soni
   - Umumiy davomiylik

---

## G.4. Web panel orqali eksperiment boshqarish

### Backend — 4 ta yangi API endpoint

**Fayl:** `web_server.go`

| Endpoint | Method | Vazifasi |
|----------|--------|----------|
| `/api/experiment/start` | POST | Eksperimentni boshlash (body: mode, workers, exp_id, duration). Background goroutine da ishga tushiradi |
| `/api/experiment/status` | GET | Hozirgi holat (running/idle, progress, qolgan vaqt) |
| `/api/experiment/stop` | POST | Ishlayotgan eksperimentni to'xtatish |
| `/api/experiment/results` | GET | Tayyor natijalar ro'yxati (`results/` papkasidagi JSON fayllar) |

### Frontend — Experiments panel

**Fayl:** `static/index.html`

Menu bar ga yangi tugma: **"🧪 Experiments"**. Bosilganda modal oynasi ochiladi (mavjud Settings modal ga o'xshash stil).

**Modal ichida:**
- Mode tanlash (dropdown): Single Experiment, Worker Benchmark, 24h Monitoring
- Experiment ID (matn kiritish)
- Workers soni (raqam kiritish, standart 50)
- Duration (faqat monitor24h rejimida ko'rsatiladi)
- **"▶️ Start"** tugmasi — API ga so'rov
- **"Cancel"** tugmasi — modalni yopadi

> Mode o'zgarganida "Duration" maydonini ko'rsatish/yashirish (faqat monitor24h uchun kerak).

---

## Tekshirish Ro'yxati

- [ ] `--mode experiment` bilan dastur bitta skanerlash qiladi va 6 ta JSON yaratadi
- [ ] `--mode benchmark` bilan W=1,10,25,50,100 skanerlash ishlaydi
- [ ] `--mode monitor24h --duration 5m` bilan qisqa monitoring ishlaydi
- [ ] `--mode normal` hozirgi xatti-harakatni saqlab qoladi
- [ ] `POST /api/experiment/start` eksperimentni boshlaydi
- [ ] `GET /api/experiment/status` to'g'ri holat qaytaradi
- [ ] Web panel modal to'g'ri ochiladi va ishlaydi
- [ ] `go build` xatosiz tugaydi
