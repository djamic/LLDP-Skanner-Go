# Phase 7: ESXi Discovery va Screenshots — Natijalar

**Holat:** ⚠️ Qisman (ESXi ✅, Screenshots ❌)  
**Sana:** 2026-03-26

## Maqsad
ESXi hypervisor avtomatik aniqlash va loyiha screenshotlarini olish.

## Bajarilgan ishlar

### D.1 — ESXi HTTP Fingerprinting
- `snmp_object.go` → `detectESXiHTTP()` orqali 80/443 portga HTTP so'rov
- VMware ESXi login sahifasini aniqlash (title/meta tag)
- `ConfirmedESXiMACs` — tasdiqlangan ESXi hostlar ro'yxati
- Shadow IT analizida ESXi portlari chiqarib tashlanadi

### D.2 — Gateway Subnet Discovery
- `discoverGatewaySubnet()` → gatewayga ping → ARP jadval → yangi IP lar
- Topilgan IP lar `swich_ips` fayliga qo'shiladi
- Periodic rescan (har 30 daqiqa) — Phase 7 docs da rejalashtirilgan

### D.3 — Hypervisor Detection
- VMware (00:0c:29, 00:50:56), Hyper-V (00:15:5d)
- QEMU/KVM (52:54:00), Xen (00:16:3e), VirtualBox (08:00:27)
- `detectHypervisors()` → grafda hypervisor + VM node lari yaratish
- Grafda alohida rang: hypervisor (cyan), VM (purple)

## Bajarilmagan ishlar
- **23 ta screenshot** — hali olinmagan (code o'zgartirish talab qilinmaydi)
- Ro'yxat `docs/phases/phase_7_screenshots.md` da

## Asosiy fayllar
| Fayl | Tavsif |
|------|--------|
| `snmp_object.go` | ESXi detection, hypervisor logic |
| `docs/phases/phase_7_discovery_and_esxi.md` | Batafsil reja |
