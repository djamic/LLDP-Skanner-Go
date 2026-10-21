# Phase 7: ESXi Detection, Gateway Discovery & Health Score

> **Holati:** 🟡 Jarayonda (90% tugallangan)
> **O'zgartirilgan fayllar:** `mac_ip_service.go`, `example_usage.go`, `analyzer.go`, `static/app.js`

---

## 1. ESXi Hypervisor Detection — 3 bosqichli tizim

### 1.1 MAC Count on Port ✅
- Switch portda 2+ VM OUI MAC (VMware `00:0c:29`, KVM, Hyper-V) → avtomatik `hyp-` node yaratiladi
- Hub emas, bevosita switch→MAC edge ishlatiladi

### 1.2 Server NIC Detection ✅
- `isServerNIC(mac)` — Dell PowerEdge, HPE ProLiant, SuperMicro OUI larni aniqlaydi
- HPE switch OUI (`4c:ae:a3`) dan farqlash qo'shilgan
- Label: `[HYPERVISOR] <Vendor> Server (potential ESXi host)`

### 1.3 Active HTTP Fingerprinting ✅ (YANGI)
- **Worker Pool:** 100 goroutine `esxiCheckWorker`
- **Mantiq:** TCP dial port 443 → HTTPS GET `/ui/` → body da `esxUiApp` yoki `VMware ESXi` izlash
- **Performance:** 500ms dial timeout, 1s response timeout, `io.LimitReader(4KB)`
- **Natija:** `ConfirmedESXiMACs` sync.Map da saqlanadi, thread-safe
- **Sinov natijasi:** 2700+ IP skanerlandi, 12 ta ESXi host 100% aniqlik bilan topildi
- **Kanal:** Non-blocking `select/default` — asosiy scan loop ni sekinlashtirmaydi

---

## 2. Gateway Subnet Auto-Discovery ✅
- `RunSubnetDiscovery()` — gateway `ipAddrTable` dan SVI lar va subnet masklarni oladi
- Kichik subnetlar (≤/22): barcha IP larni SNMP bilan probing
- Katta subnetlar (>/22): faqat ARP cache dagi faol IP larni probing
- Yangi SNMP-javob beruvchi qurilmalar `swich_ips` ga avtomatik qo'shiladi

---

## 3. Graph Enrichment Bug Fix ✅ (YANGI)
**Muammo:** `enrichGraphWithIPs` da `if ip == "" { continue }` — IP si yo'q MAC lar SKIP bo'layotgan edi, shuning uchun `ConfirmedESXiMACs` dagi MAC lar `[HYPERVISOR]` belgisini olmayotgan edi.

**Fix (`mac_ip_service.go` L513):**
- IP bo'lmasa ham `ConfirmedESXiMACs` dagi MAC lar `[HYPERVISOR] VMware ESXi` belgisini oladi
- `changed` flag bilan ortiqcha yozishning oldini oladi

---

## 4. Shadow IT Classification Fix ✅ (YANGI)

### 4.1 Frontend — `static/app.js`
VMware/hypervisor node lar Shadow IT panelidan chiqarildi:
- `hypervisor`, `vm`, `bmc` group → exclude
- `[HYPERVISOR]`, `VMware ESXi`, `[VM]` label → exclude
- Hub node → ulangan VM/hypervisor bor bo'lsa exclude

### 4.2 Backend Statistika — `example_usage.go`
Shadow IT statistikada `ConfirmedESXiMACs` check qo'shildi — HTTP orqali tasdiqlangan ESXi portlar `shadowITFiltered` ga tushmaydi.

### 4.3 Analyzer — `analyzer.go`
`analyzeShadowIT` da `ConfirmedESXiMACs.Load()` check qo'shildi — aks holda 12 ta shadow_it suggestion yaratib health_score ni 0 ga tushirayotgan edi.

---

## 5. Health Score System Fix ✅ (YANGI)

### 5.1 Immediate Analyze()
**Muammo:** `Analyze()` faqat 60 soniyalik periodic ticker da chaqirilayotgan edi → UI da birinchi daqiqada `health_score: 0`.

**Fix (`example_usage.go` L287):** `OnComplete` callback ichida — graf qurilgandan keyin darhol goroutine da `Analyze()` chaqiriladi.

### 5.2 STP PVST+ Fix
**Muammo:** PVST+ tarmoqlarda har VLAN uchun alohida root bridge → 6 ta STP suggestion × (−15) = −90.

**Fix (`analyzer.go` L740):** Barcha non-core root lar uchun **1 ta summary** suggestion yaratiladi.

### 5.3 CalculateHealthScore Formula
**Muammo:** `shadow_it × (−10) + stp × (−15) = −210 → 0`

**Fix (`analyzer.go` L774):**
- `shadow_it`: −5 per port, **cap −20** (12 ta bo'lsa ham max −20)
- `stp`: −10 per suggestion, **cap −15**
- Kutilgan natija: `100 − 20 − 10 = 70` (Good)

---

## 6. Bridge Table Topilmalari

### HPE Comware 5130 (172.20.254.10)
- **Standart bridge** (`dot1dTpFdbTable`) — **bo'sh qaytaradi**
- **Q-BRIDGE** (`dot1qTpFdbTable`) — to'g'ri ishlaydi
- Bu texnik farqlilik hozir scanner da hisobga olinmagan

### ESXi MAC lar (10.10.10.69/70)
- `d4:f5:ef:4d:b5:cf` va `98:f2:b3:22:5c:18` — hech qaysi switch bridge table da topilmadi
- Sabab: ESXi VMkernel MAC (`00:50:56:xx`) switch portda ko'rinadi, fizik NIC MAC emas
- Bu HTTP fingerprinting qoidasining afzalligini tasdiqlaydi

---

## 7. Qolgan ishlar

| # | Vazifa | Ustuvorlik |
|---|--------|-----------|
| 1 | **Health Score UI tekshirish** — yangi formula natijasini brauzerda ko'rish | Yuqori |
| 2 | **Q-BRIDGE qo'llab-quvvatlash** — HPE Comware uchun `dot1qTpFdbTable` fallback | O'rta |
| 3 | **Debug loglarni tozalash** — `DEBUG [Analyze]` loglarini o'chirish | Past |
| 4 | **Periodic subnet discovery** — har 30 daqiqada yangilash | Past |
| 5 | **Duplicate swich_ips** — fayl yozishda dublikat tekshirish | Past |
