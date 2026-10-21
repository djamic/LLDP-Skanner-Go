# Phase 3: Qurilma Identity — Natijalar

**Holat:** ✅ Bajarilgan  
**Sana:** 2026-03-26

## Maqsad
DNS hostname resolution va random MAC filtrlash orqali qurilmalarni aniq identifikatsiya qilish.

## Bajarilgan ishlar

### C.1 — DNS Reverse Lookup
- Har qurilma IP uchun `net.LookupAddr()` orqali hostname aniqlash
- Hostname grafda label sifatida ko'rinadi (IP o'rniga)
- `[DNS]` prefix bilan info ga qo'shiladi

### C.2 — Random MAC Filtering
- `isRandomMAC()` — Wi-Fi random MAC adreslarni aniqlash
- Bit 1 of byte 0 = locally administered → random
- Shadow IT analizida random MAC lar hisobga olinmaydi
- Grafda `wifi_random` guruhi sifatida ko'rinadi

### C.3 — OUI Vendor Database
- `oui_lookup.go` → 280+ lokal vendor entry
- IEEE OUI database yuklab olish (`oui.txt`)
- Fallback: kengaytirilgan lokal bazaga
- **8 ta kategoriya:** camera, access_point, printer, phone, iot, vm, network, endpoint
- **Vendorlar:** SNR, Ubiquiti, HPE, Cisco, MikroTik, Huawei, Dell, VMware, Dahua, Hikvision, Samsung, Xiaomi va boshqalar

### C.4 — 12 Device Groups
- `determineDeviceGroup()` → qurilma turini avtomatik aniqlash:
  1. `switch` — SNR, HPE, Cisco, Huawei
  2. `router` — router keyword
  3. `endpoint` — oddiy qurilmalar
  4. `hypervisor` — VMware ESXi, Proxmox
  5. `vm` — virtual mashinalar
  6. `hub` — boshqarilmaydigan switch
  7. `phone` — Samsung, Xiaomi, OPPO, vivo
  8. `camera` — Hikvision, Dahua
  9. `iot` — ESP/Espressif, Tuya
  10. `bmc` — iDRAC, iLO, iRMC
  11. `server` — Linux/Windows server
  12. `wifi_random` — random MAC

## Asosiy fayllar
| Fayl | Tavsif |
|------|--------|
| `oui_lookup.go` | OUI vendor lookup (430 qator) |
| `dj_graph.go` | Device group classification (666 qator) |
