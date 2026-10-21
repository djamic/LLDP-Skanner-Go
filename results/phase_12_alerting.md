# Phase 12: Alerting va Notification — Natijalar

**Holat:** ✅ Bajarilgan  
**Sana:** 2026-03-26

## Maqsad
Tarmoq anomaliyalarini aniqlash va administratorga xabar yuborish.

## Bajarilgan ishlar

### L.1 — 6 ta Anomaliya Turi
| # | Turi | Severity | Tavsif |
|---|------|----------|--------|
| 1 | `shadow_it` | high | Port da >1 MAC (trunk emas) → boshqarilmaydigan switch |
| 2 | `loopback` | high | LLDP self-neighbor yoki MAC self-reference |
| 3 | `congestion` | high/medium | Traffic >800Mbps yoki packet discards |
| 4 | `physical` | high | CRC/Frame errors → kabel/SFP muammo |
| 5 | `stp` | medium | Root Bridge core switchda emas |
| 6 | `stability` | high | Interface flapping (port down events) |
| 7 | `path` | medium | >3 hop from core (BFS) |

### L.2 — Telegram Bot Integration
- `analyzer.go` → `notifyTelegramIfCritical()`
- **Python Bot** (`bot/analyserbot.py`): `http://127.0.0.1:5005/notify`
- Har Shadow IT/Loopback uchun alohida xabar:
  - Switch IP, Port, Tavsif
  - Inline tugmalar: "❌ E'tiborsiz" / "✅ To'g'rilandi"
- Health Score umumiy xulosa (soatlik)

### L.3 — Cooldown & Ignore System
- `canNotifyIssue()` → 1 soat cooldown per issue
- `ignored_issues.go` → persistent `ignored_issues.json`
- `/api/bot/action` → Ignore/Verify handler:
  - Ignore: issue ID ni bazaga qo'shish
  - Verify: ignore dan chiqarish + cooldown reset + rescan trigger

### L.4 — Network Events
- `snapshot_diff.go` → `LogChanges()`
- 200 ta event log (FIFO): join, leave, host_up, host_down, anomaly, fixed
- `/api/events` → UI Events panel

### L.5 — Health Score
- `CalculateHealthScore()` → 100 dan boshlab penalty:
  - shadow_it: -5/ta, loopback: -20, congestion: -5/-2
  - stp: -10 (capped), path: -2, stability: -3, physical: -2
- Category-level cap (shadow: max -25, stp: max -10)

### L.6 — Telegram Timing
- `AddTelegramTiming()` → latency (detect → notify) saqlash
- `results/telegram_timing.json` — avg/max latency statistikasi

## Asosiy fayllar
| Fayl | Tavsif |
|------|--------|
| `analyzer.go` | 6 analysis + Telegram (834 qator) |
| `ignored_issues.go` | Ignore/Verify (79 qator) |
| `snapshot_diff.go` | Snapshot diff + events (449 qator) |
| `bot/analyserbot.py` | Telegram bot |
