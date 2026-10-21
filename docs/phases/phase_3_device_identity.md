# FAZA 3: QURILMALARNI CHUQURROQ IDENTIFIKATSIYA QILISH

> **Guruh:** C (upgrade.md dan)
> **Maqsad:** Qurilmalarni aniqroq tanish va Wi-Fi cheklovlarini bartaraf etish
> **Oldingi dependency:** Faza 2 (Snapshot Diff Engine)
> **Taxminiy vaqt:** 0.5 kun

---

## Umumiy Ko'rinish

Bu faza qurilma identifikatsiyasini yaxshilaydi: DNS orqali hostname aniqlash, tasodifiy MAC larni filtrlash, va Wi-Fi qurilmalar uchun yangi vizual kategoriya.

---

## C.1. DNS Reverse Lookup (Hostname aniqlash)

**Fayl:** `snmp_scanner.go` yoki `example_usage.go`

Go standarti kutubxonasidagi `net.LookupAddr(ip)` funksiyasidan foydalanib, har bir topilgan IP manzil uchun hostname aniqlash kerak.

**Muhim nuanslar:**
- DNS javobida nuqtali qo'shimchalar bo'lishi mumkin (masalan: `"PC-JAMIL.tuit.local."`)
- Oxirgi nuqtani va domen qismini olib tashlab, faqat kompyuter nomini olish kerak → `"PC-JAMIL"`
- Hostname qurilma ob'yektiga yangi maydon sifatida qo'shiladi
- Graf API (`/api/graph`) javobida ham `hostname` maydoni bo'lishi kerak

> **Qo'shimcha dependency kerak emas** — `net` Go standarti kutubxonasiga kiradi.

---

## C.2. isRandomMAC() filtri

**Fayl:** `example_usage.go` yoki `snmp_scanner.go`

Wi-Fi qurilmalar (Android 10+, iOS 14+) tarmoqqa ulanganida tasodifiy MAC manzil ishlatadi. Bunday MAC larni aniqlash uchun oddiy tekshiruv funksiyasi kerak.

**Qoida:** MAC manzilning ikkinchi hex belgisi **2, 6, A yoki E** bo'lsa — bu locally administered (tasodifiy) MAC.

**Misollar:**
- `da:a1:19:...` — ikkinchi belgi "a" → **random** ✅
- `00:1a:2b:...` — ikkinchi belgi "0" → **real** ❌

**Ishlatilish joylari:**
- MAC manzil yig'ish vaqtida har bir MAC uchun chaqiriladi
- Random MAC flagi (`IsRandom: true`) bilan belgilanadi
- **Shadow IT algoritmida random MAC lar hisobga olinmasligi kerak** (false positive ni kamaytirish uchun)

---

## C.3. Wi-Fi qurilmalar kategoriyasi (Graf vizualizatsiya)

### Backend (Go) — `dj_graph.go`

Node turini aniqlashda yangi shartlar qo'shish:
- Agar MAC random bo'lsa → `nodeType = "wifi_random"`
- Agar MAC hypervisor (VMware/VirtualBox) bo'lsa → `nodeType = "vm"`
- Aks holda → `"endpoint"`

### Frontend (D3.js) — `static/app.js`

Ranglash xaritasiga yangi turlar qo'shish:
| Node turi | Rang | Rang kodi |
|-----------|------|-----------|
| `wifi_random` | Ko'k-yashil | `#00BCD4` |
| `vm` | Binafsha | `#9C27B0` |

Label uchun: random MAC bo'lsa `"[WiFi] " + hostname` tegini qo'shish.

---

## Tekshirish Ro'yxati

- [ ] `net.LookupAddr()` orqali hostname aniqlanadi
- [ ] Hostname dan domen qismi olib tashlanadi (faqat PC nomi qoladi)
- [ ] `/api/graph` javobida `hostname` maydoni bor
- [ ] `isRandomMAC()` funksiyasi to'g'ri ishlaydi (2,6,A,E)
- [ ] Random MAC lar Shadow IT da hisobga olinmaydi
- [ ] Grafda Wi-Fi qurilmalar `#00BCD4` rangda ko'rinadi
- [ ] Grafda VM qurilmalar `#9C27B0` rangda ko'rinadi
- [ ] `go build` xatosiz tugaydi
