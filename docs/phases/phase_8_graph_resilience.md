# Phase 8 — Graph Resilience & Port/Link Down Handling

## Muammo

Hozir switch yoki port o'chganda:
- `CollectData` bo'sh/xatolik data qaytaradi
- `collectedData[IP]` bo'sh data bilan **overwrite** bo'ladi
- `rebuildGraph()` da node va edge lar yo'qoladi
- Graph dan butunlay o'chib ketadi — tarix yo'qoladi

## Maqsad

Port/switch o'chganda graph **barqaror qolishi** kerak:
- Node qoladi, lekin **qizil rang** (unreachable)
- Edge lar **dashed** (kesik chiziq) bo'ladi
- MAC lar "last seen" timestamp bilan saqlanadi
- Telegram alert yuboriladi

---

## 8.1 — CollectData Resilience

### Fayl: `snmp_object.go`

**Hozirgi muammo:** `CollectData` xatolik bo'lsa ham `OnSuccess(bo'sh data)` chaqiradi → eski data o'chadi.

**Tuzatish:**
```go
// CollectData oxirida:
if len(errs) == totalJobs {
    // Barcha SNMP walk lar xatolik berdi — switch unreachable
    if s.OnFailure != nil {
        s.OnFailure(ip, fmt.Errorf("all SNMP walks failed"))
    }
    return // OnSuccess CHAQIRILMAYDI
}
// Kamida biror data olindi — partial success
s.OnSuccess(data)
```

### Fayl: `example_usage.go`

**OnFailure callback qo'shish:**
```go
snmpObj := NewSNMPObject(
    func(data *DeviceData) {
        // OnSuccess — yangi data bilan yangilash
        collectedDataMutex.Lock()
        collectedData[data.IP] = data
        collectedDataMutex.Unlock()
    },
    func(ip string, err error) {
        // OnFailure — eski data ni SAQLAB QOLISH
        collectedDataMutex.Lock()
        if existing, ok := collectedData[ip]; ok {
            existing.Unreachable = true
            existing.LastSeen = existing.Timestamp
            // data O'CHIRILMAYDI
        }
        collectedDataMutex.Unlock()
        fmt.Printf("🔴 [Rescan] Switch unreachable: %s (%v)\n", ip, err)
    },
)
```

---

## 8.2 — DeviceData ga yangi fieldlar

### Fayl: `snmp_object.go`

```go
type DeviceData struct {
    // ... mavjud fieldlar ...
    Unreachable bool      // true = oxirgi rescan da javob bermadi
    LastSeen    time.Time // oxirgi marta muvaffaqiyatli poll qilingan vaqt
}
```

---

## 8.3 — Port Status Change Detection

### Fayl: `snapshot_diff.go`

**Yangi struct:**
```go
type PortStatusChange struct {
    SwitchIP  string
    PortIndex int
    PortName  string
    OldStatus int // 1=up, 2=down
    NewStatus int
    AffectedMACs int
}
```

**CompareSnapshots ga qo'shish:**
- Har bir switch ning har bir interface ni solishtirish
- `IfOperStatus` 1→2 (up→down) yoki 2→1 (down→up) o'zgarishni aniqlash
- Ta'sirlangan MAC larni hisoblash

---

## 8.4 — Graph Visual Indicators

### Fayl: `web_server.go` (GraphData response)

Unreachable node lar uchun:
```json
{
    "id": "172.20.230.17",
    "status": "unreachable",
    "lastSeen": "2026-03-28T10:30:00",
    "color": "#ff4444"
}
```

Down link lar uchun:
```json
{
    "source": "172.20.254.202",
    "target": "172.20.230.17",
    "status": "down",
    "style": "dashed",
    "lastSeen": "2026-03-28T10:30:00"
}
```

### Fayl: `static/index.html` (D3.js)

- Unreachable node: **qizil rang + pulsating animation**
- Down link: **kesik chiziq (dashed) + och qizil**
- Tooltip da "Last seen: 5 min ago" ko'rsatish

---

## 8.5 — Telegram Alerts

### Fayl: `telegram.go`

**Yangi alert turlari:**
```
🔴 PORT DOWN: 172.20.254.202 GE1/0/25
   → Switch behind: 172.20.230.17
   → Affected MACs: 47
   → Last seen: 10:30:00

🟢 PORT UP: 172.20.254.202 GE1/0/25
   → Switch restored: 172.20.230.17
   → MACs returned: 45

❌ SWITCH UNREACHABLE: 172.20.230.17
   → SNMP timeout after 3 retries
   → Connected via: 172.20.254.202 port 25
   → Affected devices: 47 MACs, 2 sub-switches
```

---

## 8.6 — LLDP Neighbor Change Detection

### Fayl: `snapshot_diff.go`

```go
type NeighborChange struct {
    SwitchIP      string
    LocalPort     string
    RemoteSysName string
    RemoteChassisID string
    ChangeType    string // "lost", "new"
}
```

- Oldingi va hozirgi LLDP neighbor ro'yxatini solishtirish
- Yo'qolgan neighbor = link uzildi
- Yangi neighbor = link qayta tiklandi

---

## Amalga oshirish tartibi

| # | Vazifa | Fayl | Muhimlik |
|---|--------|------|----------|
| 1 | CollectData resilience | `snmp_object.go` | 🔴 Yuqori |
| 2 | DeviceData.Unreachable | `snmp_object.go` | 🔴 Yuqori |
| 3 | OnFailure callback | `example_usage.go` | 🔴 Yuqori |
| 4 | Port status diff | `snapshot_diff.go` | 🟡 O'rta |
| 5 | Telegram port/host alerts | `telegram.go` | 🟡 O'rta |
| 6 | Graph visual indicators | `web_server.go`, `static/` | 🟢 Past |
| 7 | LLDP neighbor diff | `snapshot_diff.go` | 🟢 Past |

## Tekshirish

1. Switchni o'chirish → node qizil bo'lishi, edge dashed bo'lishi
2. Portni o'chirish → Telegram alert kelishi
3. Qayta yoqish → node yashil, edge solid, Telegram "restored"
4. 24h monitoring davomida crash yo'qligi
