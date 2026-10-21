# Phase 4: Experiment Management — Natijalar

**Holat:** ✅ Bajarilgan  
**Sana:** 2026-03-26

## Maqsad
CLI flag tizimi va Web panel orqali eksperimentlarni boshqarish.

## Bajarilgan ishlar

### G.1 — CLI Flag System
- `example_usage.go` → `flag` paketi orqali buyruq qatori parametrlari:
  - `-mode` — ishlash rejimi (scan/monitor24h/experiment/benchmark)
  - `-workers` — parallel worker soni (default: 50)
  - `-exp-id` — eksperiment identifikatori
  - `-duration` — monitoring davomiyligi
  - `-output` — natija papkasi

### G.2 — Experiment API (Web Panel)
- `web_server.go` → 4 ta endpoint:
  - `POST /api/experiment/start` — eksperiment boshlash (mode, workers, exp_id, duration)
  - `GET /api/experiment/status` — holat (running, progress, cycles, remaining)
  - `POST /api/experiment/stop` — to'xtatish (context cancel)
  - `GET /api/experiment/results` — results/ papkasidagi fayllar ro'yxati

### G.3 — Background Execution
- `context.WithCancel` orqali fon rejimida ishlash
- `experimentStatus` — global holat (Running, Mode, ExpID, StartTime, Progress, Cycles)
- Monitor24h, Benchmark, Experiment rejimlarini web panel dan boshlash

### G.4 — Results Management
- `results/` papkasiga barcha natijalar JSON formatda saqlash
- Fayl ro'yxati: nom, path, size, modified vaqti
- Web panel dan yuklab olish imkoniyati

## Asosiy fayllar
| Fayl | Tavsif |
|------|--------|
| `web_server.go` | Experiment API handlers (937 qator) |
| `example_usage.go` | CLI flags va main logic |
