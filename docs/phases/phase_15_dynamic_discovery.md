# Phase 15 — Dynamic Discovery & Dead Node Recovery (Ko'r Zonalarni Tiklash)

## 📌 Muammo Ta'rifi (Blind Spot Diagnostics)

Dasturning hozirgi arxitekturasida "ko'r zona" mavjud bo'lib, quyidagi ssenariyni keltirib chiqaradi:
1. Tizim ishga tushganda dastlabki **Initial Scan** amalga oshiriladi (berilgan subnetlar yoki `swich_ips` fayli orqali).
2. Skan vaqtida muvaffaqiyatli so'rovga javob bergan qurilmalargina **`collectedData`** xotirasiga kiritiladi.
3. Asosiy monitoring tsikli bo'lgan `startPeriodicRescan()` (har 5 daqiqada ishlovchi funksiya) **faqatgina xotiradagi** (`collectedData`) IP manzillarni ustida aylanib chiqadi.
4. **Oqibat:** Agar biror kommutator ilk skanerlash vaqtida javob bermasa – u *umuman tizimga kirmay qolib ketadi*.

---

## ✅ Implementatsiya (2026-03-28)

### Tanlangan Yechim: A+B Gibrid Algoritm

**Yechim A: Rescue Scanner** (alohida goroutine, 7 daqiqa interval)
- `swich_ips` faylidagi barcha IPlarni expand qiladi (CIDR → individual)
- `collectedData` da **yo'q** bo'lgan IPlarni ping bilan filtrlaydi
- Alive hostlarga `CollectData()` chaqirib, `collectedData` ga kiritadi
- 30 ta parallel ping worker, 2 daqiqadan keyin birinchi run

**Yechim B: LLDP Chain Discovery** (har rescan dan keyin)
- Barcha `DeviceData.Neighbors` dagi `RemMgmtIP` larni tekshirish
- `collectedData` da yo'q IP topilsa → `swich_ips` ga saqlash + `CollectData()`
- Zanjir reaksiya: yangi switch o'z qo'shnilarini ham keltiradi

### O'zgartirilgan Fayllar

| Fayl | O'zgartirish | Qator |
|------|-------------|-------|
| `settings.go` | `appendToSwitchIPs()` — duplikatsiz yozish helper | +28 qator |
| `example_usage.go` | `startRescueScanner()` — 7 daqiqalik goroutine | +15 qator |
| `example_usage.go` | `runRescueScan()` — swich_ips scan + ping filter | +50 qator |
| `example_usage.go` | `discoverFromLLDP()` — LLDP zanjir kashfiyoti | +45 qator |
| `example_usage.go` | Startup integration (2 joyda) | +2 qator |
| `example_usage.go` | `startPeriodicRescan` oxirida LLDP trigger | +2 qator |

### Ishlash Diagrammasi

```
┌─────────────────────────────────────────────────┐
│                   Startup                        │
│  startPeriodicRescan(5min) ← mavjud, tegmaslik   │
│  startRescueScanner(7min) ← YANGI                │
└──────────┬─────────────────────────┬─────────────┘
           │                         │
     ┌─────▼──────┐          ┌──────▼───────┐
     │ Rescan Loop │          │ Rescue Loop  │
     │  (5 min)    │          │  (7 min)     │
     │             │          │              │
     │ collectedData          │ swich_ips    │
     │ → CollectData          │ → ExpandCIDR │
     │ → rebuildGraph         │ → missing?   │
     │ → discoverFromLLDP ←─┐ │ → ping alive │
     └────────────┘         │ │ → CollectData│
                            │ └──────────────┘
                 ┌──────────┘
                 │ LLDP RemMgmtIP
                 │ → collectedData da yo'q?
                 │ → appendToSwitchIPs
                 │ → CollectData
                 │ → rebuildGraph
                 └────────────────────
```

### API Ta'siri
Hech qanday API o'zgarmadi. Mavjud endpointlar o'z holatida ishlaydi.

### Xavfsizlik
- `startPeriodicRescan` ga **tegmaslik** — u stabil funksiya
- Rescue Scanner alohida goroutine — asosiy loop ga ta'sir qilmaydi  
- 30 ta parallel ping limiti — tarmoqni yuklamaslik
- `appendToSwitchIPs` duplikat himoyasi bor

---

## 📝 Session da Qo'shimcha Bajarilgan Ishlar

### Port Grid UI Yaxshilashlari (history.html)
1. **Port slot kattalashtirildi:** 36×28 → 42×34 px, shrift 8→10px
2. **VLAN tag fonti:** 6→8px bold, rang qora (#000) qilindi
3. **Uplink portlar:** 50×34 → 56×38 px
4. **Chart legend rang moslashtirish:**
   - Katakcha rangi = chart chizig'i rangi (mos)
   - 🟢🔴🟠⚫🔵 status dot indicator
5. **Port nomi truncation tuzatildi:** `port.substring(0,20)+'...'` → to'liq nom
6. **Port Description (ifAlias):** SNMP OID `.1.3.6.1.2.1.31.1.1.1.18` qo'shildi
   - `InterfaceData.IfAlias` field
   - Tooltip da "Description" qatori (bo'sh = "—")
   - API: `if_alias` JSON field

### ifAlias SNMP Integration
- `snmp_object.go` → `IfAlias` field + SNMP walk
- `web_server.go` → `if_alias` JSON API field
- `history.html` → Tooltip Description row (moviy rang)
