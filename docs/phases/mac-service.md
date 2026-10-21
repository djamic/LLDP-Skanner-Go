# MAC-IP Discovery Service

**Maqsad:** Barcha skanerlangan switchlardan vaqti-vaqti bilan ARP jadvalini so'rash orqali IP-MAC mapping lar bazasini to'ldirish. Bu hypervisor VM lari, VLAN ichidagi qurilmalar va boshqa IP si aniqlanmagan MAC lar uchun muhim.

## Muammo

Hozirgi holat:
- `collectGatewayARP()` — faqat **bitta gateway** (`172.20.1.254`) dan ARP olinadi
- Natijada `macToIP` map to'liq emas — ko'p VM va endpoint MAC lar IPsiz qoladi
- Masalan: `172.20.254.199` ARP jadvalida `00:0c:29` VM MACs bor, lekin ular grafda IP ko'rsatmasdan `[VM]` deb ko'rinadi

## Yechim: `MacIPService`

Barcha skanerlangan switchlardan `.1.3.6.1.2.1.4.22.1.2` (ipNetToMediaPhysAddress) OID ni so'rash — `collectGatewayARP()` ni kengaytirish emas, alohida servis.

```
Har 5 daqiqada:
  for each switch in collectedData:
    snmpwalk .1.3.6.1.2.1.4.22.1.2 → []ARPEntry{IP, MAC}
    macToIP[MAC] = IP  // global map ni yangilash
    if MAC in graph.Nodes && graph.SwitchInfo[MAC] has no IP:
        graph.SwitchInfo[MAC] += "\n" + IP
```

## Arxitektura

```
┌─────────────────────────────────────────────────────────┐
│  MacIPService (goroutine)                               │
│  ┌─────────────────┐    ┌───────────────────────────┐  │
│  │  Switch list    │───▶│  SNMP ARP Walk            │  │
│  │  (collectedData)│    │  .1.3.6.1.2.1.4.22.1.2    │  │
│  └─────────────────┘    └───────────┬───────────────┘  │
│                                     │                   │
│  ┌──────────────────────────────────▼───────────────┐  │
│  │  macToIPGlobal  map[MAC]→IP  (thread-safe)       │  │
│  └──────────────────────────────────────────────────┘  │
│                          │                              │
│           ┌──────────────▼──────────────┐              │
│           │  graph.SwitchInfo yangilanadi│              │
│           │  (IP label qo'shiladi)       │              │
│           └─────────────────────────────┘              │
└─────────────────────────────────────────────────────────┘
```

## Saqlash strategiyasi

### Variant A: In-memory (oddiy, hozircha yetarli) ✅
- `macToIPGlobal sync.Map` — thread-safe
- Dastur to'xtasa yo'qoladi, qayta o'qiladi
- Hozirgi `macToIP map[string]string` ni kengaytirish

### Variant B: JSON fayl (persistence) 🔄
```json
// mac_ip_cache.json
{
  "00:0c:29:98:7b:c2": {"ip": "172.20.1.254", "updated": "2026-03-23T12:00:00Z"},
  "00:50:56:6b:e9:5d": {"ip": "172.20.0.2",   "updated": "2026-03-23T12:00:00Z"}
}
```
- Dastur qayta ishga tushsa ham saqlanadi
- `hosts.json` ga o'xshash — startup da yuklanadi

### Variant C: InfluxDB/SQLite (kelajak) 🔮
- Track qilish: qachon, qaysi switch dan ko'rilgan
- IP tarixini saqlash (DHCP o'zgarganini aniqlash)
- Ko'p resurs talab qiladi

**Tavsiya: Variant B (JSON fayl)** — oddiy va persistent.

## Fayl tuzilishi

```
// mac_ip_service.go (yangi fayl)

var macIPCacheMu sync.RWMutex
var macIPCache = map[string]string{} // mac → ip

// loadMacIPCache — startup da mac_ip_cache.json yuklanadi
// saveMacIPCache — yangilanishdan keyin saqlandi
// startMacIPService — goroutine, har 5 daqiqada switchlarni so'raydi
// enrichGraphWithIPs — macIPCache → graph.SwitchInfo IP qo'shadi
```

## Qo'shimcha afzalliklar

1. **Hypervisor VM lari uchun IP**: `detectHypervisors` topgan `hyp-` node larga VM IPlarini ko'rsatish
2. **MAC-to-hostname**: `macToIP` → `resolveHostname(ip)` → node labelga hostname
3. **DHCP tracking**: MAC bir IP dan boshqa IPga o'tganini aniqlash (anomaly)
4. **Supernet coverage**: `172.20.x.x` rangida bo'lgan barcha subnetlar ko'rinadi

## Trigger shartlar

| Holat | Harakat |
|-------|---------|
| Startup | `mac_ip_cache.json` yuklanadi |
| Har 5 daqiqada | Barcha switchlardan ARP so'raladi |
| Yangi switch topilsa | Darhol ARP so'raladi |
| `macToIP` yangilansa | Graf node lari boyitiladi |

## Implementatsiya bosqichlari

- [ ] `mac_ip_service.go` yaratish
- [ ] `loadMacIPCache()` / `saveMacIPCache()` yozish
- [ ] `startMacIPService()` goroutine — ticker 5 daqiqa
- [ ] `enrichGraphWithIPs(graph)` — `detectHypervisors` dan keyin chaqirish
- [ ] `example_usage.go` da `go startMacIPService()` qo'shish
- [ ] VM nodlar uchun IP label ko'rsatish (grafda)

## OID ma'lumotnomasi

```
ipNetToMediaPhysAddress  .1.3.6.1.2.1.4.22.1.2.<ifIndex>.<ip1>.<ip2>.<ip3>.<ip4>
                                                ↑
                          718.172.20.1.254 → 00:0C:29:98:7B:C2
```

---

## VLAN-Aware ARP Discovery

### Muammo
`arp-scan 10.10.20.0/24` — faqat biz **o'sha L2 segmentda** bo'lsak ishlaydi.
Biz `172.20.22.103` da — VLAN 160 (`10.10.20.x`) ga L2 yetish yo'q.

### Yechim: L3 router/gateway ARP

```
Router (172.20.1.254) ARP:
  10.10.20.10.30 → bc:9b:5e:47:63:20  (VLAN 160 PC) ✅
  10.10.20.5.101 → bc:9b:5e:47:65:fd  ✅
```
→ `collectARPTable(gateway_ip)` yetarli!

### Kengaytma: Switch SVI IP lari ham

Ba'zi switchlar VLAN uchun gateway:
```go
// ipAddrTable → switch ning barcha IP interface lari
// Har biridan collectARPTable() → macIPCache
func collectARPFromSwitchAllInterfaces(snmpObj, switchIP)
```

### arp-scan variant (kelajak, trunk port kerak)
```bash
ip link add link eno1 name eno1.160 type vlan id 160
arp-scan --interface=eno1.160 10.10.20.0/24
```
`mac_ip_service.go` da `exec.Command("arp-scan", "--interface="+iface, subnet)` orqali qo'shish mumkin — agar VLAN trunk mavjud bo'lsa.
