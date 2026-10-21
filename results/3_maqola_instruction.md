# 3-MAQOLA UCHUN INSTRUKTSIYA VA KONTEKST

> **Fayl maqsadi:** AI keyingi sessiyalarda maqola_3.md ustida ishlashni davom ettirishi uchun barcha kontekst, qoidalar va qarorlar shu yerda saqlanadi. Foydalanuvchi tadqiqot natijalarini ko'rib chiqib, keyinchalik davom ettirish uchun beradi.

---

## 1. MAQOLA HAQIDA UMUMIY MA'LUMOT

| Parametr | Qiymat |
|---|---|
| **Fayl joyi** | `md_docs/maqola_3.md` |
| **Mavzu** | Betartib ko'p-vendorli tarmoqlarda avtomatik inventarizatsiya va topologik modellash arxitekturasi |
| **Til** | O'zbek Kirill yozuvi (OAK/GOST standarti) |
| **Struktura** | Xalqaro jurnal 5-bo'limli shablon |
| **Mualliflar** | Qalandarov J.J., Omonov Z.H., Akmalov E.I. |
| **UDK** | 004.732.056 |
| **Adabiyotlar** | 20 ta (IEEE, RFC, Springer, Pearson, Cisco Press, ACM) |

## 2. JURNAL STRUKTURASI (QATIY RIOYA QILISH!)

Maqola quyidagi 5-bo'limli xalqaro standart strukturaga ega:

```
SARLAVHA (≤15 so'z)
MUALLIFLAR + AFFILIATSIYA
ANNOTATSIYA (150-250 so'z, strukturalashgan: Muammo→Maqsad→Metod→Natija→Xulosa)
  - O'zbekcha, Ruscha, Inglizcha (OAK talabi)
KALIT SO'ZLAR (3 tilda)

1. КИРИШ (INTRODUCTION) — 4 xatboshi:
   1) Umumiy muammo ta'rifi
   2) Adabiyotlar tahlili (10+ olim havolasi)
   3) Ilmiy bo'shliqlar (4 ta Research Gap)
   4) Maqsad + Ilmiy gipoteza

2. МЕТОДОЛОГИЯ ВА МАТЕРИАЛЛАР — 3 bo'lim:
   2.1 Tadqiqot obyekti (sinov muhiti, Go arxitektura, 6 modul)
   2.2 Ma'lumot yig'ish (SNMP/MIB, normalizatsiya, OS Fingerprinting, InfluxDB)
   2.3 Tahlil usullari (Graf model, BFS, Congestion, PLR, Flapping, Health Score, Snapshot Diff)

3. НАТИЖАЛАР (RESULTS) — faqat raqamlar, shaxsiy fikr yo'q:
   3.1 Skanerlash tezligi (150x speedup jadvali)
   3.2 OS Fingerprinting aniqligi (97% FP kamaytirish jadvali)
   3.3 Qiyosiy tahlil (10 mezon × 4 tizim jadvali)

4. МУҲОКАМА (DISCUSSION) — 5 xatboshi:
   1) Asosiy topilmalar qisqacha
   2) Boshqa olimlar bilan solishtirish
   3) Amaliy/ilmiy ahamiyat
   4) Limitatsiyalar (4 ta)

5. ХУЛОСА (CONCLUSION) — 2 xatboshi:
   1) Yakuniy xulosa (yangi ma'lumot yoki havola QO'SHILMAYDI)
   2) Kelajak tadqiqotlar uchun tavsiyalar (3 ta)

ADABIYOTLAR — 20 ta
```

## 3. MAVJUD MATEMATIK MODELLAR

Maqolada quyidagi formulalar ishlatilgan:

| # | Model | Formula | Maqsad |
|---|---|---|---|
| 1 | Graf modeli | $G = (V, E, W)$ | Tarmoq topologiyasini modellash |
| 2 | BFS chuqurlik | $Depth(v_i, v_{core}) > H_{max}$ | Daisy-chain anomaliya |
| 3 | Congestion | $U_e = F(e)/C(e) \ge 0.80$ | Kanal zo'riqishi |
| 4 | PLR | $PLR(p) = Err(p)/(Pkts(p)+Err(p))$ | Paket yo'qotilishi |
| 5 | Flapping | $N_{flaps}(p) > T_{max}$ | Port tebranishi |
| 6 | Health Score | $H(S) = max(0, 100 - \sum \omega_i \cdot x_i)$ | Tarmoq sog'ligi |
| 7 | Session | $Session(t) = \langle G_t, Anomalies, Metrics, Inventory \rangle$ | Snapshot |
| 8 | Diff | $V_{new} = V_{t_2} \setminus V_{t_1}$ | Tarixiy solishtirish |

## 4. MAVJUD MERMAID DIAGRAMMALAR (5 ta)

1. **Tizim arxitekturasi** — Scanner → Normalizatsiya → Topology → Anomaly → Alerting → InfluxDB
2. **Normalizatsiya jarayoni** — Hex/Text → Tozalash → Guruhla → LLDP parcha → Pivoting → JSON
3. **OS Fingerprinting** — OUI → Hostname → TTL → Tasniflash
4. **BFS algoritmi** — Root → Queue → Visit → Dist → Threshold → Anomaly
5. **Session Diff** — Session(t₁) vs Session(t₂) → Vnew, Vremoved, Echanged → Report

## 5. SINOV NATIJALARI (HOZIRGI HOLATDA)

> ⚠️ **MUHIM:** Foydalanuvchi sinov natijalarini ko'rib chiqmoqda. Quyidagi raqamlar keyinchalik o'zgarishi mumkin!

| Ko'rsatkich | Hozirgi qiymat |
|---|---|
| Skanerlash vaqti | 18 sekund (320+ qurilma) |
| Speedup | ~150x |
| False Positive (FPsiz) | 149 ta |
| False Positive (FP bilan) | 4 ta |
| FP kamaytirish | 97% |
| Precision (FPsiz) | 20.3% |
| Precision (FP bilan) | 90.5% |
| Haqiqiy Shadow IT | 38 ta port |

## 6. QOIDALAR VA CHEKLOVLAR

### Yozuv qoidalari:
- **Faqat Kirill** yozuvida yozish — Lotin aralashtirilMAYDI
- Texnik terminlar (SNMP, LLDP, MAC, BFS, Go, InfluxDB) inglizcha qoldiriladi
- OAK/GOST formatiga mos bo'lishi shart
- Annotatsiya 3 tilda (O'zbekcha, Ruscha, Inglizcha)

### Overlap yo'qligi:
- **Maqola 1** (`maqola1.md`) — Gibrid skanerlash algoritmlari → TAKRORLANMASIN
- **Maqola 2** (`maqola2_2.md`) — Health Score modeli → TAKRORLANMASIN
- **Maqola 3** — Kontseptual arxitektura, normalizatsiya, OS Fingerprinting, Time-Series

### Imlo tekshiruvi:
- `cyr2lat.py` — Kirill→Lotin konversiya
- `md2docx_gost.py` — DOCX generatsiya
- `ignore_words.txt` — konversiyadan chiqariladigan so'zlar

## 7. KEYINGI QADAMLAR (FOYDALANUVCHI QAYTGANDA)

1. [ ] Foydalanuvchi sinov natijalarini tasdiqlab/o'zgartirib beradi
2. [ ] Natijalar bo'limi (Section 3) yangilanadi
3. [ ] Muhokama bo'limi natijalar asosida qayta yoziladi
4. [ ] Xulosa yangilanadi
5. [ ] Annotatsiyalardagi raqamlar yangilanadi
6. [ ] `cyr2lat.py` orqali Lotin versiya generatsiya qilinadi
7. [ ] `md2docx_gost.py` orqali DOCX generatsiya qilinadi
8. [ ] Yakuniy ko'rib chiqish va tasdiqlanishi

## 8. FAYLLAR XARITASI

```
AI/
├── md_docs/
│   ├── maqola_3.md              ← ASOSIY MAQOLA FAYILI
│   ├── 3_maqola_instruction.md  ← SHU FAYL (instruktsiya)
│   ├── maqola1.md               ← Maqola 1 (Kirill) — overlap tekshirish uchun
│   ├── maqola2_2.md             ← Maqola 2 (Kirill) — overlap tekshirish uchun
│   └── ...
├── instruments/
│   ├── cyr2lat.py               ← Kirill→Lotin konvertor
│   ├── md2docx_gost.py          ← DOCX generatsiya
│   └── ignore_words.txt         ← Konversiya ignore list
└── AI_handover.md               ← Umumiy handover hujjat
```

---

## 9. KORXONADA 0 DAN TADQIQOT O'TKAZISH YO'RIQNOMASI

> Siz yangi korxona tarmog'ida noldan sinov o'tkazasiz. Quyidagi savollar/vazifalar ro'yxati orqali real natijalar to'plang.

---

### 🔴 BOSQICH 1: SINOV OLDIDAN TAYYORGARLIK

Korxona tarmog'iga kirishdan OLDIN quyidagilarni aniqlang:

| # | Savol | Yozib qo'ying |
|---|---|---|
| 1.1 | Korxona nomi (yoki shartli kodi) — maqolada nomsiz yoziladi | _____ |
| 1.2 | Tarmoq diapazoni nima? (masalan 10.0.0.0/8 yoki 192.168.0.0/16) | _____ |
| 1.3 | SNMP community string (SNMPv2c) yoki SNMPv3 credentials bormi? | _____ |
| 1.4 | Tarmoqda qaysi vendorlar qurilmalari bor? (Cisco, Huawei, MikroTik, HP, Juniper...) | _____ |
| 1.5 | Taxminiy faol tarmoq qurilmalari (switch/router) soni qancha? | _____ |
| 1.6 | Taxminiy oxirgi foydalanuvchi qurilmalari (kompyuter, printer, telefon) soni qancha? | _____ |
| 1.7 | Tarmoqda virtualizatsiya (VMware, Hyper-V, KVM) mavjudmi? | _____ |
| 1.8 | Tarmoq ma'muri ruxsat berdimi? Qaysi vaqtda sinov o'tkazish mumkin? | _____ |

---

### 🟡 BOSQICH 2: SKANERLASH SINOVLARI (Tezlik o'lchash)

lldp_go dasturini ishga tushiring va quyidagilarni yozib boring:

| # | Nima o'lchanadi | Qanday o'lchash kerak | Natija |
|---|---|---|---|
| 2.1 | **Bizning tizim bilan skanerlash vaqti** | lldp_go ni ishga tushiring, CIDR kiriting, boshlash→tugash vaqtini yozing | _____ sek |
| 2.2 | **Goroutine ishchilar soni** | Dastur sozlamalaridan W qiymatni yozing | W = _____ |
| 2.3 | **Topilgan faol qurilmalar soni** | Skan natijasida nechta qurilma topildi | _____ ta |
| 2.4 | **An'anaviy usul bilan skanerlash vaqti** | SNMPwalk yoki Nmap bilan xuddi shu diapazonda kema-ket skanerlang, vaqtni yozing | _____ daq |
| 2.5 | **Speedup (tezlik oshishi)** | = (An'anaviy vaqt) / (Bizning vaqt) | _____ x |

> **MUHIM:** An'anaviy usul sifatida `snmpwalk` yoki `nmap -sn` dan foydalaning. Boshlash va tugash vaqtini aniq yozing!

---

### 🟠 BOSQICH 3: OS FINGERPRINTING SINOVI (Shadow IT aniqlash)

Bu eng muhim sinov — False Positive kamaytirish samaradorligini o'lchash:

| # | Nima o'lchanadi | Qanday o'lchash kerak | Natija |
|---|---|---|---|
| 3.1 | **OS Fingerprinting O'CHIRILGAN holda** Shadow IT ogohlantirish soni | Dasturda OS Fingerprinting ni o'chiring, nechta port "Shadow IT" deb belgilandi? | _____ ta port |
| 3.2 | **OS Fingerprinting YOQILGAN holda** Shadow IT ogohlantirish soni | OS Fingerprinting ni yoqing, nechta port "Shadow IT" qoldi? | _____ ta port |
| 3.3 | **Haqiqiy Shadow IT soni** | Qolgan ogohlantirish portlarini QOQDA tekshiring — real ruxsatsiz qurilma nechta? | _____ ta port |
| 3.4 | **False Positive (FP siz)** | = (3.1) - (3.3) | _____ ta |
| 3.5 | **False Positive (FP bilan)** | = (3.2) - (3.3) | _____ ta |
| 3.6 | **Precision (FP siz)** | = (3.3) / (3.1) × 100% | _____ % |
| 3.7 | **Precision (FP bilan)** | = (3.3) / (3.2) × 100% | _____ % |
| 3.8 | **FP kamaytirish foizi** | = ((3.4) - (3.5)) / (3.4) × 100% | _____ % |

> **MUHIM:** "Qo'lda tekshirish" — har bir ogohlantirish portiga borlib, ulangan qurilma nimaligini aniqlang. VM hostmi? Ruxsatsiz switchmi? Printer mi?

---

### 🟢 BOSQICH 4: QIYOSIY TAHLIL MA'LUMOTLARI

Agar korxonada Zabbix, PRTG yoki SolarWinds o'rnatilgan bo'lsa:

| # | Savol | Javob |
|---|---|---|
| 4.1 | Korxonada qaysi NMS tizimi ishlatiladi? | _____ |
| 4.2 | Bu tizim tarmoqdagi barcha qurilmalarni avtomatik topib beradimi? | Ha / Yo'q |
| 4.3 | Bu tizim Shadow IT ni aniqlana oladimi? | Ha / Yo'q |
| 4.4 | Bu tizim VM hostlarni ruxsatsiz qurilmadan ajratib beradimi? | Ha / Yo'q |
| 4.5 | Bu tizimning qurilma qo'shish jarayoni qanday? (qo'lda / avtomatik) | _____ |
| 4.6 | Bu tizim tarmoq tarixini (Snapshot) saqlaydimi? | Ha / Yo'q |
| 4.7 | Agar mavjud NMS yo'q bo'lsa — bu ham natija (yozing!) | _____ |

---

### 🔵 BOSQICH 5: MENGA QAYTIB BERISH UCHUN

Barcha natijalarni to'plab, menga (yoki keyingi agentga) quyidagicha bering:

```
3_maqola_instruction.md ni o'qi.

Sinov natijalari:
- Korxona: [nomi yoki kodi]
- Tarmoq diapazoni: [masalan 10.0.0.0/8]
- Vendorlar: [Cisco, Huawei, ...]
- Qurilmalar soni: [raqam]
- Skanerlash vaqti (bizning): [raqam] sek
- Skanerlash vaqti (an'anaviy): [raqam] daq
- Speedup: [raqam]x
- Shadow IT (FP siz): [raqam] ta
- Shadow IT (FP bilan): [raqam] ta
- Haqiqiy Shadow IT: [raqam] ta
- False Positive (FP siz / bilan): [raqam] / [raqam]
- Precision (FP siz / bilan): [raqam]% / [raqam]%

Vazifa: maqola_3.md ning 3-bo'lim (Natijalar) va 4-bo'lim (Muhokama) ni
shu raqamlar bilan yangilab, annotatsiyalarni ham yangilab ber.
```
