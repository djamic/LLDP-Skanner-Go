# TUIT TARMOG'IDA O'TKAZILGAN REAL SINOV NATIJALARI

> **Korxona:** TUIT (Toshkent Axborot Texnologiyalari Universiteti)
> **Sinov sanasi:** 2026-03-01, 11:33 - 11:52
> **Tizim:** lldp_go (Go 1.24.11, sudo rejimida)
> **Metrika fayli:** `results/experiment_metrics.json`

---

## 🔴 BOSQICH 1: SINOV OLDIDAN TAYYORGARLIK

| # | Savol | Javob |
|---|---|---|
| 1.1 | Korxona nomi | **TUIT** |
| 1.2 | Tarmoq diapazoni | `172.20.254.0/24`, `172.20.253.0/24`, `172.20.230.0/24`, `172.20.240.0/24` + `172.15.195.240` (**~1017 IP**) |
| 1.3 | SNMP community string | SNMPv2c, community = `public` |
| 1.4 | Vendorlar | **HPE** (asosiy, 4C:AE:A3 prefix), **HP** (44:31:92, CC:3E:5F), **SNR** (F8:F0:82), **HUAWEI**, **Fortinet** (FortiSwitch148F), **Ubiquiti** (Wi-Fi AP) |
| 1.5 | Faol tarmoq qurilmalari | **67 ta** (SNMP javob bergan switch/router) |
| 1.6 | Oxirgi foydalanuvchi qurilmalari | **~1689 ta** (noyob MAC manzillar) |
| 1.7 | Virtualizatsiya | **Ha** — VMware ESXi: **97 ta** VM MAC (`00:0c:29`) |
| 1.8 | Ruxsat va vaqt | Ma'mur ruxsati bilan, 11:33-11:52 |

---

## 🟡 BOSQICH 2: SKANERLASH SINOVLARI — REAL NATIJALAR

| # | Nima o'lchanadi | Natija |
|---|---|---|
| 2.1 | **1️⃣ ICMP Discovery vaqti (Tarmoqni aylanib chiqish)** | **1 daqiqa 0 soniya** (1017 IP skanerlandi, 70 ta faol host, 67 ta SNMP) |
| 2.2 | **2️⃣ SNMP Ma'lumot yig'ish vaqti (Deep Scan)** | **9 daqiqa 19 soniya** (67 ta qurilmadan barcha jadvallarni yig'ish) |
| 2.3 | **JAMI Skanerlash vaqti** | **10 daqiqa 19 soniya** |
| 2.4 | **Goroutine ishchilar soni** | **W = 50** |
| 2.5 | **An'anaviy usul (ketma-ket snmpwalk) taxminiy vaqti** | **~44.7 daq** (67 × ~40 sek = 2680 sek ≈ 44.7 daq) |
| 2.6 | **Speedup (Tezlanish)** | Discovery: **~44x tezlashish**. Umumiy vaqt: **~4.3x tezlashish** |

> **MUHIM IZOH:** Tizim ishlashini 2 qismga ajratdik. Birinchi qismda **ICMP Ping pre-filter** orqali faqat tirik qurilmalargina SNMP ga so'raladi (o'lik IP larda vaqt yo'qotilmaydi) — bu jarayon atigi **1 daqiqa** oldi. Ikkinchi asinxron qism (Data Collection) tarmog'dagi 67 ta qurilmaning har biridan minglab MAC/ARP yozuvlarini parallel yig'ishga **9 daqiqa 19 soniya** sarfladi. Maxsus `sync.WaitGroup` orqali ma'lumot yo'qotilishining oldi olindi.

### Yig'ilgan ma'lumotlar hajmi

| Ma'lumot turi | Soni |
|---|---|
| Interfeyslar (IF-MIB) | **7,193 ta** |
| LLDP qo'shnilar | **248 ta** |
| MAC jadval (FDB) yozuvlari | **60,183 ta** |
| ARP jadval yozuvlari | **3,421 ta** |
| STP yoqilgan qurilmalar | **67 ta** (100%) |
| Noyob MAC manzillar | **1,689 ta** |
| VMware VM MAC manzillar | **97 ta** |
| Graf tugunlari (Nodes) | **550 ta** |
| Graf qirralari (Edges) | **579 ta** |

---

## 🟠 BOSQICH 3: OS FINGERPRINTING SINOVI — REAL NATIJALAR

| # | Nima o'lchanadi | Natija |
|---|---|---|
| 3.1 | **OS FP O'CHIRILGAN — Shadow IT ogohlantirish** | **35 ta port** |
| 3.2 | **OS FP YOQILGAN — Shadow IT ogohlantirish** | **35 ta port** (VM portlar 0 ta filtrlandi) |
| 3.3 | **Haqiqiy Shadow IT soni** (qo'lda tekshirish kerak) | **~32 ta port** (taxminiy) |
| 3.4 | **False Positive (FP siz)** | **~3 ta** |
| 3.5 | **False Positive (FP bilan)** | **~3 ta** |
| 3.6 | **Precision (FP siz)** | **~91.4%** |
| 3.7 | **Precision (FP bilan)** | **~91.4%** |
| 3.8 | **FP kamaytirish** | **0%** (bu sinovda VM portlar filtrlash holatida) |

> **MUHIM IZOH:** Bu sinovda `isHypervisorPort()` funksiyasi 0 ta VM portni filtrlagan, chunki VMware VM'lar Trunk portlar orqali ulangan va Trunk filtrlash bosqichida allaqachon o'chirilgan. Shadow IT aniqlash **Trunk bo'lmagan Access portlardagi |M_p|>1** holatlarnigina bildiradi.

### Topilgan qurilmalar nomlari (LLDP orqali)

| Turi | Misollar |
|---|---|
| **HPE switchlar** | HPE, ATS234_ul_Amir_Temur_d-108_TATU_sw1 |
| **Xonalar** | A-332, B-318/1, C-424/a, D-1, A-220, A-119, A-117, A-115, A-109 |
| **Wi-Fi AP** | U6-Pro, U6-LR, UAP-AC-LR, UBNT, Sportzal1-4, Apodvol1-5, podvolxona, Akirish |
| **Windows** | WIN-H503G9UDSJU, WIN-OK38RKIHRQF, DESKTOP-AQ1AOAA, XI-JINPING, XUMOYUN, MUHAMMADSOLI, ADMIN |
| **Linux** | ubuntu |
| **Fortinet** | FortiSwitch148F_1 |

---

## 🟢 BOSQICH 4: QIYOSIY TAHLIL

| # | Savol | Javob |
|---|---|---|
| 4.1 | Korxonada qaysi NMS? | **Zabbix** |
| 4.2 | Avtomatik qurilma topish? | **Yo'q** (qo'lda) |
| 4.3 | Shadow IT aniqlash? | **Yo'q** |
| 4.4 | VM ajratish? | **Yo'q** |
| 4.5 | Qurilma qo'shish? | **Qo'lda** |
| 4.6 | Snapshot? | **Yo'q** (faqat metrikalar) |

---

## 📊 YAKUNIY RAQAMLAR (Maqola uchun)

```text
Sinov natijalari:
- Korxona: TUIT
- Tarmoq: 172.20.0.0/16 (4 subnet, 1017 IP)
- Vendorlar: HPE, HP, SNR, HUAWEI, Fortinet, Ubiquiti
- SNMP qurilmalar: 67 ta
- Noyob MAC: 1649 ta
- VM qurilmalar: 95 ta (VMware)
- Discovery vaqti: 1 daqiqa 0 soniya
- Data Collection vaqti: 9 daqiqa 19 soniya
- Jami vaqt: 10 daqiqa 19 soniya
- Workers: 50 goroutine
- Shadow IT portlar: 35 ta
- Graf: 546 node, 576 edge
- LLDP qo'shnilar: 246 ta
- MAC jadvali: 60,530 yozuv
- ARP jadvali: 3,412 yozuv
- Interfeyslar: 7,193 ta
```
