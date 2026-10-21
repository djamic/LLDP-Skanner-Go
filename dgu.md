
# ЭВМ УЧУН ДАСТУР / DASTUR UCHUN DAVLAT GUVOHNOMASI

---

## РЕФЕРАТ / ANNOTATSIYA

**Rus tilida:**

Программа для ЭВМ «Система сетевого мониторинга и визуализации топологии на основе протоколов LLDP/SNMP» предназначена для автоматического обнаружения сетевых устройств (коммутаторов) в корпоративной локальной вычислительной сети, построения актуальной карты топологии, анализа работоспособности сети и своевременного оповещения администратора о выявленных неисправностях.

**O'zbek tilida:**

«LLDP/SNMP protokollari asosida tarmoq monitoringi va topologiyasini vizualizatsiya qilish tizimi» nomli EHM uchun dastur korporativ mahalliy hisoblash tarmog'idagi tarmoq qurilmalarini (kommutatorlarni) avtomatik aniqlash, tarmoq topologiyasi xaritasini qurish, tarmoq ish holatini tahlil qilish va aniqlangan nosozliklar haqida ma'murni o'z vaqtida xabardor qilish uchun mo'ljallangan.

---

## I. UMUMIY MA'LUMOTLAR / ОБЩИЕ СВЕДЕНИЯ

**1.1. Dastur nomi / Название программы:**
«LLDP/SNMP protokollari asosida tarmoq monitoringi va topologiyasini vizualizatsiya qilish tizimi»
«Система сетевого мониторинга и визуализации топологии на основе протоколов LLDP/SNMP»

**1.2. Dasturlash tili / Язык программирования:**
Go (Golang) 1.21+

**1.3. Operatsion tizim / Операционная система:**
GNU/Linux (64-bit)

**1.4. Dastur hajmi / Объём программы:**
Asosiy manba kodi: ~12 000 qator (Go); Yordamchi modullari: ~3 000 qator (JavaScript, HTML, CSS)

**1.5. Qo'llanish sohasi / Область применения:**
Korporativ tarmoq infratuzilmasini boshqarish; tarmoq administratorlari va IT xavfsizlik bo'limlari.

---

## II. FUNKSIONAL TAVSIF / ФУНКЦИОНАЛЬНОЕ ОПИСАНИЕ

### 2.1. Tarmoqni avtomatik skanerlash

SNMP v2c protokoli va ICMP echo-so'rovlar (ping) yordamida belgilangan IP-diapazonlardagi faol tarmoq qurilmalari avtomatik tarzda aniqlanadi. Skanerlash 50 tagacha parallel ish jarayoni (goroutine) orqali amalga oshiriladi, bu esa katta tarmoqlarda yuqori unumdorlikni ta'minlaydi. Skanerlash natijalari hodisa kanali (`EventHostFound`, `EventSNMPSuccess`, `EventSNMPFailure`, `EventScanComplete`) vositasida asosiy boshqaruv jarayoniga uzatiladi.

**Сканирование сети в автоматическом режиме:**
С использованием протокола SNMP v2c и ICMP echo-запросов (ping) производится автоматическое обнаружение активных сетевых устройств в заданных IP-диапазонах. Сканирование осуществляется с использованием до 50 параллельных рабочих процессов (горутин), что обеспечивает высокую производительность в крупных сетях.

---

### 2.2. SNMP orqali ma'lumot to'plash

Muvaffaqiyatli aniqlangan har bir qurilmadan quyidagi ma'lumotlar parallel tarzda to'planadi:

| № | Ma'lumot turi | Foydalanilgan MIB / OID |
|---|---------------|------------------------|
| 1 | Qurilmaning noyob identifikatori (ChassisID) | `lldpLocChassisId` (.1.0.8802.1.1.2.1.3.2.0) |
| 2 | Tarmoq interfeyslari holati va statistikasi | `IF-MIB` (.1.3.6.1.2.1.2.2.1.*) |
| 3 | LLDP qo'shni qurilmalar ro'yxati | `lldpRemTable` (.1.0.8802.1.1.2.1.4.1.1) |
| 4 | MAC-manzillar jadvali (ko'priq jadvali) | `dot1dTpFdb` (.1.3.6.1.2.1.17.4.3.1.2) |
| 5 | ARP-jadvali (IP ↔ MAC moslik) | `ipNetToMedia` (.1.3.6.1.2.1.4.22.1.*) |
| 6 | Port VLAN konfiguratsiyasi | `Q-BRIDGE-MIB` |
| 7 | Spanning Tree protokoli holati | `BRIDGE-MIB` (.1.3.6.1.2.1.17.2.*) |

Barcha MAC-manzillar `normalizeMAC()` funksiyasi orqali yagona formatga (`aa:bb:cc:dd:ee:ff`) keltiriladi. LLDP ChassisID uchun subtype kodi (4=MAC, 5=IP, 7=mahalliy belgilash) inobatga olinadi.

**Сбор данных посредством SNMP:**
С каждого успешно обнаруженного устройства параллельно собираются данные согласно таблице выше. Все MAC-адреса нормализуются функцией `normalizeMAC()` к единому формату.

---

### 2.3. Tarmoq topologiyasi grafini qurish

To'plangan ma'lumotlar asosida yo'naltirilgan graf quriladi. Har bir qurilma graf **tuguni** sifatida, qurilmalar orasidagi fizik ulanish esa graf **bog'lanishi** sifatida ifodalanadi.

**Bog'lanish qurish algoritmi:**

1. Har bir kommutatorning LLDP qo'shnilari ko'rib chiqiladi.
2. Qo'shni qurilmaning ChassisID turi (MAC yoki IP) aniqlanadi.
3. Grafda mavjud bo'lmagan qo'shni uchun `[LLDP-EP]` markerli yangi tugun yaratiladi.
4. Bog'lanishga mahalliy va masofaviy port nomlari, VLAN raqami, kanal tezligi va trafik ma'lumotlari biriktiriladi.
5. Takroriy bog'lanishlarning oldini olish uchun ikkala yo'nalish tekshiriladi.

**MAC cross-reference mexanizmi:** LLDP protokoli o'chirilgan kommutatorlarni aniqlash uchun MAC-jadvallarni o'zaro taqqoslash usuli qo'llaniladi. Agar A kommutatorining MAC-jadvalida B kommutatorining ChassisID manzili mavjud bo'lsa, ular orasida fizik ulanish mavjud deb qabul qilinadi.

**Qurilma turi tasnifi:**

| Tur | Aniqlash belgisi |
|-----|-----------------|
| `switch` (kommutator) | HPE, SNR, Cisco, Huawei OUI yoki boshqariluvchi qurilma belgilari |
| `router` (marshrutizator) | «router» kalit so'zi |
| `server` (server) | Linux, Windows, server belgilari |
| `endpoint` (terminal qurilma) | MAC orqali aniqlangan oddiy qurilma |
| `hub` (boshqarilmaydigan kommutator) | Trunk bo'lmagan portda 4–20 ta MAC |
| `vm` (virtual mashina serveri) | VMware (`00:50:56`, `00:0C:29`), Proxmox, KVM OUI |
| `wifi_random` (Wi-Fi qurilma) | Tasodifiy MAC-manzil (`locally-administered bit`) |

**Построение графа топологии сети:**
На основе собранных данных строится ориентированный граф. Каждое устройство представляется узлом графа, а физическое соединение — ребром. Применяется механизм MAC cross-reference для обнаружения коммутаторов с отключённым LLDP.

---

### 2.4. Tarmoq holatini avtomatik tahlil qilish

Skanerlash yakunlangandan so'ng va har 10 daqiqada `NetworkAnalyzer.Analyze()` funksiyasi tomonidan 6 turdagi tahlil amalga oshiriladi:

**2.4.1. Yo'l optimizatsiyasi tahlili (Path Analysis)**
Kenglik bo'yicha qidiruv (BFS) algoritmi yordamida har bir tarmoq tugunining asosiy shlyuzdan (172.20.1.254) masofasi xop soni bilan aniqlanadi. 3 ta xopdan uzoqdagi qurilmalar tizim tomonidan muammo sifatida qayd etiladi.

**2.4.2. Tarmoq tiqilinchi tahlili (Congestion Analysis)**
Har bir interfeys uchun kiruvchi va chiquvchi trafik yig'indisi hisoblanadi. 1 Gbit/s ning 80 foizidan (800 Mbit/s) oshgan yuklanma, shuningdek, paketlarni yo'qotish (`InDiscards`, `OutDiscards`) va fizik xatolar (`InErrors`, `OutErrors`) muammo sifatida qayd etiladi.

**2.4.3. Barqarorlik tahlili (Stability Analysis)**
Interfeys holat o'zgarishlari (Up → Down o'tishlari) sanaladi. Har bir o'chish `stability` turi muammo sifatida hisobga olinadi.

**2.4.4. Boshqarilmaydigan qurilmalarni aniqlash (Shadow IT Detection)**
Trunk bo'lmagan portda ikki va undan ortiq real (tasodifiy bo'lmagan) MAC-manzil mavjudligi boshqarilmaydigan kommutator (hub) ulanganligidan dalolat beradi. Tasodifiy MAC va gipervizor OUI larining filtrlash algoritmi qo'llaniladi.

**2.4.5. STP audit (Spanning Tree Protocol Audit)**
Barcha qurilmalardan Root Bridge identifikatori olinadi. Root Bridge asosiy kommutatordan boshqasida joylashgan holat noto'g'ri STP konfiguratsiyasi sifatida qayd etiladi.

**2.4.6. Halqalarni aniqlash (Loopback Detection)**
Ikki usul qo'llaniladi:
- **LLDP usuli:** Kommutator o'z ChassisID ni LLDP qo'shni sifatida ko'rsa — halqa mavjud.
- **MAC usuli:** Kommutator o'z MAC-manzilini MAC-jadvalda trunk bo'lmagan portda ko'rsa — halqa mavjud.

**Tarmoq salomatligi balli (Health Score):**
Tarmoq umumiy holati 0 dan 100 gacha bo'lgan ball bilan ifodalanadi.

| Muammo turi | Jarima (ball) |
|-------------|:-------------:|
| Halqa (Loopback) | −20 |
| STP noto'g'ri sozlash | −15 |
| Boshqarilmaydigan kommutator (Shadow IT) | −10 |
| Trafik tiqilinchi (yuqori) | −5 |
| Interfeys o'chishi (Stability) | −3 |
| Trafik tiqilinchi (o'rta) / Fizik xato | −2 |
| Uzun yo'l (Path) | −2 |

| Ball | Holat darrajasi |
|:----:|:---------------:|
| 90–100 | Excellent (A'lo) |
| 70–89 | Good (Yaxshi) |
| 50–69 | Fair (Qoniqarli) |
| 30–49 | Poor (Yomon) |
| 0–29 | Critical (Kritik) |

---

### 2.5. Telegram orqali avtomatik ogohlantirish

Tahlil natijasida aniqlangan muammolar haqida tizim administratorga Telegram messenjer orqali xabar jo'natadi. Ushbu funksiya Python dasturlash tilida yozilgan yordamchi bot moduli (`localhost:5005`) vositasida amalga oshiriladi.

- Har bir muammo uchun noyob identifikator (`issueID`) tayinlanadi.
- Bir xil muammo uchun takroriy bildirishnoma 1 soat davomida yuborilmaydi.
- Bildirishnomaga interaktiv tugmalar biriktiriladi: «E'tiborsiz qoldirish» va «To'g'irlandi».
- «To'g'irlandi» tugmasi bosilganda muammo uchun sovutish vaqti tiklanadiъ va qayta skanerlash boshlanadi.

**Автоматическое оповещение через Telegram:**
При обнаружении проблем система отправляет администратору уведомления через мессенджер Telegram посредством вспомогательного модуля-бота. Для каждой проблемы назначается уникальный идентификатор. Повторные уведомления об одной проблеме не отправляются в течение 1 часа.

---

### 2.6. Vaqtli qatorlar ma'lumotlar bazasi bilan integratsiya (InfluxDB)

Tarmoq qurilmalarining trafik ko'rsatkichlari InfluxDB 2.x ma'lumotlar bazasiga har 10 soniyada yozib boriladi.

Saqlanadigan ko'rsatkichlar:

| Ko'rsatkich | Ma'no |
|-------------|-------|
| `in_bps` / `out_bps` | Kiruvchi/chiquvchi trafik tezligi (bit/s) |
| `in_octets` / `out_octets` | Kiruvchi/chiquvchi baytlar soni |
| `in_errors` / `out_errors` | CRC va fizik xatolar soni |
| `in_discards` / `out_discards` | Yo'qolgan paketlar soni |
| `oper_status` | Interfeys operatsion holati (1=Up, 2=Down) |

Bundan tashqari, qurilma qo'shilish/ketish hodisalari (`device_events`), tarmoq umumiy holati (`network_summary`) va anomaliya statistikasi (`anomaly_summary`) saqlanadi.

**Интеграция с базой данных временных рядов InfluxDB:**
Показатели трафика сетевых устройств записываются в базу данных InfluxDB 2.x каждые 10 секунд согласно таблице выше.

---

### 2.7. Tarmoq holati snapshotlari va farqlar tahlili

Har skanerlashdan so'ng tarmoqning joriy holati `NetworkSnapshot` ob'ektida saqlaniladi va oldingi holat bilan taqqoslanadi. Taqqoslash natijasida quyidagi o'zgarishlar aniqlanadi:

- Yangi ulanган qurilmalar (MAC-manzil asosida) — `DEVICE_JOIN`
- Tarmoqdan chiqqan qurilmalar — `DEVICE_LEAVE`
- Yangi SNMP-javob beruvchi hostlar / javob berishni to'xtatgan hostlar
- Yangi paydo bo'lgan yoki hal qilingan anomaliyalar
- Tarmoq salomatligi ballining o'zgarishi (±)

Barcha hodisalar `NetworkEvent` jurnalida saqlanadi (oxirgi 200 ta hodisa). Hodisalar REST API orqali foydalanuvchi interfeysi moduli tomonidan o'qiladi.

---

### 2.8. Ma'lumotlarni diskda saqlash

Tarmoqdan toplangan barcha qurilmalar ma'lumotlari (`DeviceData`) va skanerlash sozlamalari `network_data.json` faylida saqlanadi. Dastur qayta ishga tushirilganda saqlangan ma'lumotlar yuklanadi va yangi skanerlashsiz tarmoq holati tiklanadiъ.

---

### 2.9. REST API va HTTP-server

Dastur `http://localhost:8088` manzilida HTTP-server ishlatadi va quyidagi API-endpointlarni ta'minlaydi:

**Asosiy boshqaruv:**

| Endpoint | Metod | Vazifa |
|----------|:-----:|--------|
| `/api/graph` | GET | Grafning tugunlar va bog'lanishlar ro'yxati (D3.js JSON formati) |
| `/api/hosts` | GET | Saqlangan qurilmalar ro'yxati |
| `/api/hosts` | DELETE | Barcha ma'lumotlarni tozalash |
| `/api/settings` | GET/POST | Skanerlash sozlamalarini o'qish/yozish |
| `/api/rescan` | POST | Qayta skanerlashni boshlash |
| `/api/status` | GET | Joriy holat: host, tugun va bog'lanishlar soni |
| `/api/history` | GET | InfluxDB dan trafik tarixi (`?id=IP&hours=N`) |
| `/api/events` | GET | Tarmoq hodisalari jurnali |
| `/api/bot/action` | POST | Bot tugmasi harakati: `ignore` yoki `verify` |

**Sessiyalar va hisobotlar:**

| Endpoint | Metod | Vazifa |
|----------|:-----:|--------|
| `/api/capture/start` | POST | Yangi monitoring sessiyasini boshlash |
| `/api/capture/stop` | POST | Sessiyani to'xtatish va JSON formatda saqlash |
| `/api/captures` | GET | Barcha sessiyalar ro'yxati |
| `/api/report/generate` | POST | Tahlil hisobotini generatsiya qilish (JSON + matn) |
| `/api/report/download` | GET | Hisobotni Word (.doc) formatida yuklab olish |

**Eksperiment boshqaruvi:**

| Endpoint | Metod | Vazifa |
|----------|:-----:|--------|
| `/api/experiment/start` | POST | Eksperiment rejimini orqa fonda ishga tushirish |
| `/api/experiment/status` | GET | Eksperiment holati va bosib o'tilgan vaqt |
| `/api/experiment/stop` | POST | Eksperimentni to'xtatish |
| `/api/experiment/results` | GET | Natija fayllari ro'yxati |

---

### 2.10. Zabbix monitoring tizimiga eksport

Tarmoq skanerlash natijalari Zabbix 6.0 monitoring tizimi formatida eksport qilinadi:

- `zabbix_hosts.json` — SNMP-qurilmalar ro'yxati (Zabbix import formati, shablonlar va guruhlar bilan)
- `zabbix_map.json` — Tarmoq xaritasi (qurilmalar koordinatalari bilan)

---

### 2.11. OUI bazasi asosida vendor (ishlab chiqaruvchi) aniqlash

Wireshark loyihasining OUI (Organizationally Unique Identifier) ma'lumotlar bazasi asosida har bir MAC-manzilning dastlabki 3 baytidan qurilma ishlab chiqaruvchisi aniqlanadi. Qurilma toifasi (switch, router, server, printer, kamera, Wi-Fi nuqtasi va boshq.) avtomatik tarzda belgilanadi.

Tasodifiy MAC-manzillarni aniqlash (`isRandomMAC`) va gipervizor portlarini aniqlash (`isHypervisorPort`) algoritmlari mavjud bo'lib, ular Shadow IT tahlilida noto'g'ri ijobiy natijalarni kamaytiradi.

---

### 2.12. Ishga tushirish rejimlari

| Rejim | Bayroq | Tavsif |
|-------|--------|--------|
| Oddiy | `--mode normal` | Uzluksiz skanerlash, trafik kuzatuvi va HTTP-server |
| Eksperiment | `--mode experiment` | Bir martalik skanerlash va JSON-eksport, so'ng dastur tugaydi |
| Samaradorlik testi | `--mode benchmark` | 1/10/25/50/100 parallel jarayon bilan ketma-ket skanerlash |
| 24 soatlik kuzatuv | `--mode monitor24h` | 24 soat davomida uzluksiz monitoring va tahlil |

---

## III. TEXNIK XUSUSIYATLAR / ТЕХНИЧЕСКИЕ ХАРАКТЕРИСТИКИ

| Xususiyat | Qiymat |
|-----------|--------|
| Dasturlash tili | Go (Golang) 1.21+ |
| SNMP kutubxonasi | Tizim `snmpwalk` buyrug'i (Net-SNMP) |
| Ma'lumotlar bazasi | InfluxDB 2.x (Docker konteynerida) |
| HTTP-server porti | 8088 (TCP) |
| Parallel jarayonlar soni | 50 (standart, sozlanadi) |
| Trafik polling davri | 10 soniya |
| Tahlil davri | 10 daqiqa |
| Vaqtli xabarlar cooldown | 1 soat |
| Hodisalar jurnali hajmi | 200 ta oxirgi hodisa |
| Eksport formatlar | JSON, Word (.doc), Zabbix 6.0 XML |
| Foydalanilgan protokollar | SNMP v2c, LLDP-MIB, BRIDGE-MIB, IF-MIB, ICMP |
| Tashqi integratsiyalar | Telegram Bot API, Zabbix 6.0 |

---

## IV. TARKIBIY MODULLAR / СОСТАВ ПРОГРАММНЫХ МОДУЛЕЙ

| Modul fayli | Vazifasi |
|-------------|----------|
| `example_usage.go` | Asosiy boshqaruv jarayoni, ishga tushirish rejimlari, graf yangilash |
| `snmp_scanner.go` | ICMP ping va SNMP v2c asosida tarmoq skanerlovchisi |
| `snmp_object.go` | MIB jadvallaridan parallel ma'lumot to'plash |
| `dj_graph.go` | Graf tuzilmasi, D3.js formati, Zabbix eksport |
| `analyzer.go` | 6 turli tarmoq tahlili, Health Score, Telegram integratsiyasi |
| `snapshot_diff.go` | Tarmoq holati snapshotlari va farqlar tahlili |
| `influx_client.go` | InfluxDB 2.x bilan ulanish va metrik yozish |
| `web_server.go` | HTTP-server va REST API endpointlari |
| `settings.go` | Sozlamalar va ma'lumotlarni diskda saqlash |
| `oui_lookup.go` | OUI bazasi asosida vendor va qurilma turi aniqlash |
| `capture.go` | Monitoring sessiyalarini boshqarish |
| `experiment_exports.go` | Eksperiment rejimi uchun JSON eksport |
| `ignored_issues.go` | E'tiborsiz qoldirilgan muammolar ro'yxatini boshqarish |
| `static/index.html` | Asosiy veb-interfeys sahifasi |
| `static/app.js` | D3.js topologiya ko'rinishi va foydalanuvchi interfeysi |
| `static/style.css` | Interfeys uslublari |
| `bot/` | Telegram bot yordamchi moduli (Python) |

---

*Hujjat sanasi: 2026-yil 11-mart*
*Дата составления: 11 марта 2026 года*
