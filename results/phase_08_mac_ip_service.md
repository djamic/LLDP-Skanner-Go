# Phase 8: MAC-IP Discovery Service — Natijalar

**Holat:** ✅ Bajarilgan  
**Sana:** 2026-03-26

## Maqsad
Switchlardan ARP jadvalini yig'ib, MAC → IP mapping bazasini yaratish.

## Bajarilgan ishlar

### H.1 — ARP Table Polling
- `mac_ip_service.go` → `startMacIPService()`
- Har 5 daqiqada barcha switchlardan SNMP orqali ARP jadval so'rash
- OID: `.1.3.6.1.2.1.4.22.1.2` (ipNetToMediaPhysAddress)

### H.2 — MAC-IP Cache
- `mac_ip_cache.json` — persistent JSON cache (366KB)
- `globalMACtoIP` — in-memory map (goroutine-safe)
- Restart dan keyin cache dan yuklash

### H.3 — Graph Enrichment
- `enrichGraphWithIPs()` — `detectHypervisors()` dan keyin chaqiriladi
- VM va endpoint node lariga IP manzil qo'shish
- Grafda IP ko'rinishi: label va tooltip da

### H.4 — Snapshot Integration
- `CreateSnapshot()` da MAC → IP resolve qilish
- Event log da IP bilan birga ko'rsatish

## Asosiy fayllar
| Fayl | Tavsif |
|------|--------|
| `mac_ip_service.go` | MAC-IP service |
| `mac_ip_cache.json` | Persistent cache (366KB) |
