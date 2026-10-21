# FAZA 5: INTERFEYS (UI) YAXSHILASH

> **Guruh:** E (upgrade.md dan)
> **Maqsad:** Web interfeysni yaxshilash — yangi widgetlar, animatsiyalar, panellar
> **Oldingi dependency:** Faza 3 (hostname), Faza 2 (snapshot diff panel uchun)
> **Taxminiy vaqt:** 1–2 kun

---

## Umumiy Ko'rinish

Hozirgi UI yaxshi bazaga ega: dark theme (#1a1a2e, gradient header), D3.js topologiya grafi, device list panel, settings/reports modal, context menu, legend. Quyidagi yaxshilashlar qo'shiladi.

---

## E.1. Health Score Dashboard Widget

**Fayllar:** `static/index.html` va `static/style.css`

Header qismiga Health Score vidjetini qo'shish:
- Raqam (masalan "87") katta shriftda
- Ostida "Health Score" label
- Pastda progress bar (4px balandlikda)

**Ranglash:**
| Diapazoni | Rang | Rang kodi |
|-----------|------|-----------|
| 90–100 | Yashil | `#4CAF50` |
| 70–89 | Sariq | `#FF9800` |
| 0–69 | Qizil | `#F44336` |

Progress bar gradient bo'lishi kerak (qizildan yashilgacha).

**JS:** `/api/graph` dan `health_score` ni olib, har 10 sekundda yangilab turish.

---

## E.2. Anomaliya portlarini grafda belgilash (Glow Effect)

**Fayllar:** `static/app.js` va `static/style.css`

D3.js da node chizish qismida:
- Anomaliya bor node → qizil `stroke` + `drop-shadow` CSS filtri
- **Loopback** anomaliyasi → kuchliroq glow (12px)
- **Shadow IT** → oddiyroq glow (8px)

**CSS keyframe animatsiya** (`pulse-anomaly`):
- Glow intensivligi 2 sekundda o'zgarib turadi: 6px → 14px → 6px
- Anomaliyali qurilmalar vizual ravishda "yonib-o'chib" ko'rinadi

---

## E.3. Legend yangilash

**Fayllar:** `static/index.html` va `static/style.css`

Mavjud legend ga 3 ta yangi element:

| Element | Rang | Rang kodi | Izoh |
|---------|------|-----------|------|
| Virtual Machine | Binafsha | `#9C27B0` | — |
| Wi-Fi Random MAC | Ko'k-yashil | `#00BCD4` | — |
| Anomaly Detected | Qizil | `#FF5252` | Pulse animatsiya bilan |

---

## E.4. Node label da hostname ko'rsatish

**Fayl:** `static/app.js`

Grafda node label chizish qismida prioritet:
1. `hostname` maydoni bor → uni ko'rsatish
2. `sysName` maydoni bor → uni ko'rsatish  
3. Ikkalasi ham yo'q → IP manzilni ko'rsatish

> Bu Go backenddan kelgan `hostname` maydoniga bog'liq (Faza 3, C.1 dan).

---

## E.5. Status Bar (pastki satr)

**Fayllar:** `static/index.html` va `static/style.css`

Ekranning eng pastki qismiga footer:

| Ikonka | Ma'lumot |
|--------|----------|
| 🕐 | Oxirgi skanerlash vaqti |
| 📡 | Faol switchlar soni |
| 💻 | MAC lar soni |
| ⚠️ | Anomaliyalar soni (sariq rang) |
| 🏥 | Health Score (yashil rang) |

**Stil:** Header bilan bir xil gradient fon, mayda shrift (12px), oq rangli raqamlar.

---

## E.6. Snapshot Diff paneli

**Fayllar:** `static/index.html`, `static/app.js`, `web_server.go`

### Frontend
O'ng device list panel ga "Recent Changes" tab (yoki alohida panel):

| Ikonka | Hodisa turi | Rang |
|--------|-------------|------|
| 🟢 | JOIN | Yashil |
| 🔴 | LEAVE | Qizil |
| ⚠️ | NEW_ANOMALY | Sariq |
| ✅ | FIXED | Ko'k |

Har bir element: ikonka + matn (masalan: `"PC-JAMIL joined (08:05)"`) + vaqt.
Yangi hodisalar tepada. Maksimal 50 ta.

### Backend
**Yangi endpoint:** `GET /api/diff/recent` — oxirgi o'zgarishlar JSON ro'yxati (`web_server.go`).

---

## Tekshirish Ro'yxati

- [ ] Health Score widget header da ko'rinadi va rangi to'g'ri
- [ ] Anomaliyali node lar qizil glow bilan "yonib-o'chib" ko'rinadi
- [ ] Legend da 3 ta yangi element bor
- [ ] Node label larda hostname prioritet bilan ko'rsatiladi
- [ ] Status bar ekranning pastida to'g'ri ma'lumot ko'rsatadi
- [ ] "Recent Changes" paneli JOIN/LEAVE hodisalarini ko'rsatadi
- [ ] `/api/diff/recent` endpoint to'g'ri javob qaytaradi
- [ ] `go build` xatosiz tugaydi
