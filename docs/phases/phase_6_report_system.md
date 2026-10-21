# FAZA 6: HISOBOT GENERATSIYA TIZIMI

> **Guruh:** F (upgrade.md dan)
> **Maqsad:** Hisobot tizimini to'liq qayta yozish — professional audit DOCX
> **Oldingi dependency:** Barcha oldingi fazalar (hostname, health score, vendor stats, topologiya)
> **Taxminiy vaqt:** 1–2 kun

---

## Umumiy Ko'rinish

Hozirgi `GenerateHTMLReport` faqat oddiy anomaliyalar jadvalini chiqaradi. Tarmoq topologiyasi 550+ node — uni to'g'ridan-to'g'ri Word ga sig'dirish mumkin emas. Bu fazada hisobot tizimi to'liq qayta yoziladi.

---

## F.1. Topologiya rasmini Word ga kiritish yechimi

**Muammo:** D3.js topologiya interaktiv SVG — Word ga SVG kiritib bo'lmaydi. 550+ node li grafni rasm qilib chiqarish o'qilmaydi.

### Yechim A — Summary View (Go da) ⭐ Tavsiya

**Yangi fayl:** `report_topology.go`

1. Grafdan faqat **switch va router** tugunlarini olish (endpoint larni olib tashlash)
2. Qolgan ~67 ta tugun orasidagi bog'lanishlarni oddiy SVG sifatida chiqarish
3. SVG ni base64 kodlab, HTML (DOCX) ichiga `<img>` tag sifatida kiritish
4. O'lchami: ~800×600 px — Word sahifasiga sig'adi

### Yechim B — Headless Chrome screenshot (Qo'shimcha)

`chromedp` (Go kutubxonasi) orqali:
1. Brauzersiz `http://localhost:8080` sahifasini ochish
2. D3.js grafni render qilish
3. To'liq ekran screenshot olish → PNG fayl

> En to'liq rasm, lekin Chrome kerak bo'ladi serverda.

### Yechim C — Mermaid diagramma ⭐ Tavsiya

Switchlar orasidagi topologiyani Mermaid format matni sifatida chiqarish:
```
CoreSW --- A332
CoreSW --- A445
A332 --- B112
```

Bu matni `mermaid-cli` yoki Pandoc orqali PNG ga aylantirish mumkin.

> **Tavsiya:** A va C ni qo'shish — Summary SVG to'liq hisobot uchun, Mermaid tez eksport uchun.

---

## F.2. DOCX hisobot tuzilmasi

**Fayl:** `web_server.go` — `GenerateHTMLReport` funksiyasini qayta yozish

Oddiy anomaliyalar jadvalini **7 bo'limli to'liq audit hisobot** bilan almashtirish:

### 1. Sarlavha sahifasi
- "TARMOQ AUDIT HISOBOTI" sarlavhasi
- Korxona nomi, sana, tizim versiyasi

### 2. Umumiy ma'lumot
Jadval ko'rinishida:
- Skanerlash vaqti, IP diapazoni
- Topilgan qurilmalar soni, noyob MAC lar
- LLDP qo'shnilar, random MAC lar soni

### 3. Tarmoq sog'ligi
- Umumiy Health Score (masalan: 87/100)
- Anomaliya turlari bo'yicha ballar jadvali:
  - Shadow IT: 35 ta × -10 = -350
  - Loopback: 0
  - STP: 0
  - Congestion: 3 ta × -5 = -15

### 4. Topologiya sxemasi
- F.1 dagi yechim orqali olingan PNG rasm
- Base64 kodlab HTML `<img>` tag ichiga
- Rasm kengligi: 700px

### 5. Qurilmalar ro'yxati
Jadval: IP, Hostname, Vendor, Port soni, Health Score

**Ranglash:**
| Health Score | Rang |
|-------------|------|
| < 70 | 🔴 Qizil |
| 70–89 | 🟡 Sariq |
| 90+ | 🟢 Yashil |

### 6. Anomaliyalar ro'yxati
Jadval: anomaliya turi, qurilma (IP + sysName), port, tavsif

### 7. Tavsiyalar
Anomaliyalar asosida avtomatik generatsiya:
- Shadow IT → "Port tekshirish kerak"
- Congestion → "Kabel/SFP almashtirish tavsiya etiladi"
- BFS depth > 3 → "Qurilmani Core switchga yaqinroq joylashtirish"

### Stil talablari
- **Shrift:** Times New Roman 14pt (GOST standarti)
- **Jadval chegaralari:** qora
- **Header rangi:** ko'k (#2E74B5, oq matn)
- **Encoding:** UTF-8 BOM + Microsoft Office XML namespace

---

## F.3. Hisobot API yangilash

**Fayl:** `web_server.go`

Mavjud endpointlar saqlanadi. 3 ta yangi endpoint:

| Endpoint | Method | Vazifasi |
|----------|--------|----------|
| `/api/report/topology-png` | GET | Topologiyaning PNG rasmini qaytaradi (F.1 dan) |
| `/api/report/summary` | GET | Tarmoq holatining JSON xulosa ma'lumoti (UI/tashqi tizimlar uchun) |
| `/api/report/full` | GET | Yangi formatlangan to'liq DOCX audit hisobot |

---

## Tekshirish Ro'yxati

- [ ] `report_topology.go` yangi fayl yaratilgan
- [ ] Summary SVG faqat switch/router tugunlarini ko'rsatadi
- [ ] DOCX hisobotda 7 ta bo'lim mavjud
- [ ] Hisobot Times New Roman 14pt da Word da to'g'ri ochiladi
- [ ] UTF-8 kirill harflar to'g'ri ko'rinadi
- [ ] `/api/report/topology-png` PNG rasmni qaytaradi
- [ ] `/api/report/summary` JSON xulosa to'g'ri
- [ ] `/api/report/full` to'liq DOCX generatsiya qiladi
- [ ] `go build` xatosiz tugaydi
