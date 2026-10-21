# FAZA 1 — TEST INSTRUKTSIYASI

> **Maqsad:** Faza 1 (Eksperiment Infratuzilmasi) barcha komponentlarini tekshirish
> **Kerakli vaqt:** ~15 daqiqa
> **Oldindan tayyorgarlik:** `go build -o lldp_scanner .` muvaffaqiyatli bo'lishi kerak

---

## 1. ASOSIY BUILD TEKSHIRISH

```bash
cd /home/qosim/Desktop/lldp_go
go build -o lldp_scanner .
echo $?   # 0 bo'lishi kerak
```

**Kutilgan natija:** Xatosiz build, exit code = 0

---

## 2. CLI FLAGLARNI TEKSHIRISH

```bash
./lldp_scanner --help
```

**Kutilgan natija:** 3 ta flag ko'rinishi kerak:
```
  -benchmark    Run benchmark: scan with W=1,10,25,50,100 workers
  -experiment   Run experiment: scan once, save all metrics to results/
  -test         Run in test mode (scan once, save data, and exit)
```

---

## 3. EXPERIMENT REJIMINI ISHLATISH

```bash
# Eski natijalarni tozalash
rm -f results/experiment_metrics.json results/health_scores.json results/bfs_depths.json results/vendor_stats.json results/telegram_timing.json

# Experiment rejimda ishga tushirish
./lldp_scanner --experiment
```

**Kutilgan natija:**
- Dastur tarmoqni skanerlaydi (ICMP → SNMP → Graph → Analysis)
- 5 ta JSON fayl `results/` papkasida hosil bo'ladi
- Dastur o'zi to'xtaydi (Ctrl+C kerak emas)

**Vaqt:** ~10–15 daqiqa (TUIT tarmog'ida)

---

## 4. HOSIL BO'LGAN FAYLLARNI TEKSHIRISH

### 4.1 Fayllar borligini tekshirish

```bash
ls -la results/*.json
```

**Kutilgan natija:** 5 ta fayl (barchasi `qosim` egasida, bugungi sana bilan):
```
results/experiment_metrics.json   ← A.1
results/health_scores.json        ← A.3
results/bfs_depths.json           ← A.4
results/telegram_timing.json      ← A.5
results/vendor_stats.json         ← A.6
```

### 4.2 experiment_metrics.json (A.1)

```bash
cat results/experiment_metrics.json | python3 -m json.tool
```

**Tekshirish:**
- [ ] `experiment_date` — bugungi sana
- [ ] `devices_found` — 60+ (TUIT tarmog'ida)
- [ ] `total_duration` — vaqt ko'rsatilgan
- [ ] `total_duration_sec` — soniyalarda
- [ ] `discovery_duration` va `collection_duration` — alohida bosqichlar
- [ ] `snmp_success` + `snmp_failure` = topilgan qurilmalar
- [ ] `unique_macs` — 1000+ (odatda 1500+)
- [ ] `graph_nodes` va `graph_edges` — noldan katta
- [ ] `shadow_it_raw` va `shadow_it_filtered` — bor

### 4.3 health_scores.json (A.3)

```bash
# Umumiy statistika
python3 -c "
import json
d = json.load(open('results/health_scores.json'))
print(f'Qurilmalar: {d[\"total_devices\"]}')
print(f'O-rtacha health: {d[\"average_health\"]:.1f}')
print(f'Min/Max: {d[\"min_health\"]}/{d[\"max_health\"]}')
print(f'Jami anomaliyalar: {d[\"total_anomalies\"]}')
print()
# Anomaliyali qurilmalar
for dev in d['devices']:
    if dev['anomalies']:
        print(f'  ⚠️ {dev[\"ip\"]} ({dev[\"sys_name\"]}) — health={dev[\"health_score\"]}, anomalies={dev[\"anomalies\"]}')
"
```

**Tekshirish:**
- [ ] Har bir qurilmada `ip`, `sys_name`, `vendor`, `health_score`, `port_count`, `mac_count` bor
- [ ] `health_score` 0–100 orasida
- [ ] Anomaliyali qurilmalar uchun `anomalies` ro'yxati bo'sh emas
- [ ] `vendor` — "SNR", "HPE", "Huawei" va boshqalar

### 4.4 bfs_depths.json (A.4)

```bash
cat results/bfs_depths.json | python3 -m json.tool
```

**Tekshirish:**
- [ ] `core_switch_ip` — core switch ID si (MAC yoki IP)
- [ ] `depth_distribution` — `{"0": 1, "1": N, "2": M, ...}` formatda
- [ ] `max_depth` — eng uzoq hop
- [ ] `average_depth` — o'rtacha hop
- [ ] `total_nodes` — BFS ni bosib o'tgan tugunlar soni
- [ ] `deep_devices` — depth > 3 bo'lgan qurilmalar (bo'sh bo'lishi ham mumkin)

### 4.5 telegram_timing.json (A.5)

```bash
cat results/telegram_timing.json | python3 -m json.tool
```

**Tekshirish:**
- [ ] `total_messages` — yuborilgan xabarlar soni
- [ ] Agar bot ishlamayotgan bo'lsa yoki cooldown aktiv bo'lsa — `entries` bo'sh, bu normal
- [ ] Agar bot ishlasa va yangi anomaliya topilsa — har bir entry da:
  - `issue_id` — masalan "shadow_172_20_230_51_25"
  - `detect_time` va `notify_time` — vaqt formati
  - `latency_ms` — kechikish millisekundlarda

> **Eslatma:** Telegram timing uchun bot ishlashi kerak:
> ```bash
> cd /home/qosim/Desktop/lldp_go/bot
> source venv/bin/activate
> python analyserbot.py &
> # keyin experiment ni qayta ishga tushiring
> ```

### 4.6 vendor_stats.json (A.6)

```bash
python3 -c "
import json
d = json.load(open('results/vendor_stats.json'))
print(f'Vendorlar soni: {d[\"total_vendors\"]}')
for v in d['vendors']:
    print(f'  {v[\"vendor\"]}: {v[\"device_count\"]} ta — SNMP:{v[\"snmp_success\"]}/{v[\"snmp_success\"]+v[\"snmp_failure\"]}, LLDP:{v[\"lldp_success\"]}/{v[\"lldp_success\"]+v[\"lldp_failure\"]}, FDB:{v[\"fdb_success\"]}/{v[\"fdb_success\"]+v[\"fdb_failure\"]}')
"
```

**Tekshirish:**
- [ ] Har bir vendor uchun `device_count`, `snmp_success/failure`, `lldp_success/failure`, `fdb_success/failure` bor
- [ ] `snmp_success` = `device_count` (barchasi muvaffaqiyatli)
- [ ] SNR eng ko'p qurilmalarga ega

---

## 5. BENCHMARK REJIMINI TEKSHIRISH (IXTIYORIY)

> ⚠️ **Diqqat:** Benchmark ~50 daqiqa davom etadi (5 marta skan: W=1, W=10, W=25, W=50, W=100)
> Hozircha benchmark funksiyasi tayyor, lekin main() da unga chaqirish hali faqat flag sifatida mavjud.
> Benchmark to'liq implementatsiya Faza 4 da amalga oshiriladi.

```bash
# Faqat build tekshirish (ishga tushirmasdan):
./lldp_scanner --help | grep benchmark
# Natija: "-benchmark  Run benchmark: scan with W=1,10,25,50,100 workers"
```

---

## 6. XULOSA MATRITSASI

| # | Komponent | Fayl | Tekshirish |
|---|-----------|------|------------|
| A.1 | `--experiment` flag | `experiment_metrics.json` | `cat` bilan ko'rish |
| A.2 | `--benchmark` flag | `--help` da ko'rinishi | Flag bor, Faza 4 da to'liq |
| A.3 | Health scores | `health_scores.json` | Per-device health + anomaliyalar |
| A.4 | BFS depths | `bfs_depths.json` | Core dan masofalar |
| A.5 | Telegram timing | `telegram_timing.json` | Bot ishlasa — latency |
| A.6 | Vendor stats | `vendor_stats.json` | Vendor bo'yicha statistika |

---

## 7. MUAMMOLAR VA YECHIMLAR

### `experiment_metrics.json` yaratilmadi
**Sabab:** Eski fayl `root` egasida edi, yangi fayl ustiga yozolmadi.
**Yechim:**
```bash
# Agar fayl root egasida bo'lsa:
sudo chown qosim:qosim results/experiment_metrics.json
# Yoki o'chirish:
rm results/experiment_metrics.json
# Keyin qayta ishga tushirish
```

### `telegram_timing.json` bo'sh
**Sabab:** Telegram bot ishlamayotgan, yoki oxirgi 1 soat ichida xabar yuborilgan (cooldown).
**Yechim:** Botni ishga tushiring va 1 soat kutib qayta skan qiling.

### `bfs_depths.json` da `total_nodes` kam
**Sabab:** BFS faqat o'zaro bog'langan (connected component) tugunlarni hisoblaydi. LLDP endpoint tugunlari (one-way edge) hisobga olinmasligi mumkin.
**Yechim:** Normal holat — faqat switch/router orasidagi topologiya.
