# Faza 8: Graph Resilience (Graf Barqarorligi) Implemetatsiyasi

Loyiha hujjatlari va yozilgan `knowledge.md` asosida, Faza 8 ("Graph Resilience") g'oyasi rejalashtirilgan bo'lsa-da, kodda hali to'liq amalga oshirilmaganligini aniqladim. 

Ushbu rejaning maqsadi: **Tarmoqdagi qurilma yoxud kommutator o'chib qolsa (yokı uzilsa), uni xaritadan (grafdan) to'satdan yo'q qilib tashlamaslik, balki uning holatini `Unreachable` (Aloqa yo'q) deb o'zgartirib, oxirgi ko'ringan vaqtini (`LastSeen`) yozib qo'yishdir.**

## User Review Required

> [!IMPORTANT]
> Dasturning asosiy `DeviceData` tuzilmasi, SNMP polling arxitekturasi va D3.js frontend ob'ektlariga o'zgartirish kiritiladi. Bu eski "xato bergan node'ni o'chirish" amaliyotini o'zgartiradi. Iltimos, quyidagi kod o'zgarishlari rejasini tasdiqlang.

## Proposed Changes

---

### Backend Components

#### [MODIFY] [snmp_object.go](file:///home/qosim/Desktop/lldp_go/snmp_object.go)
- `DeviceData` tuzilmasiga quyidagi yangi maydonlarni qo'shish:
  - `Unreachable bool`
  - `LastSeen time.Time`
- Qurilmadan javob kelmaganda (masalan, `chassisID` butunlay xato berganda yoki timeout bo'lganda) `OnFailure` funksiyasini chaqirish mexanizmini to'liq ishonchli qilish kafolatlanadi.

#### [MODIFY] [example_usage.go](file:///home/qosim/Desktop/lldp_go/example_usage.go)
- `NewSNMPObject` ga uzatiladigan `onFailure` callback (qayta ishlash) funksiyasini yangilash.
- Agar IP javob bermasa (fail bo'lsa), xotiradagi (goroutine cache'dagi) qadimgi ma'lumotni o'chirib yubormaslik.
- Buning o'rniga: `device.Unreachable = true` va `device.LastSeen = time.Now()` qilib o'rnatish.
- Keyingi muvaffaqiyatli skanda uni yana `Unreachable = false` holatiga qaytarib, tarmoq ishga tushganligini qayd etish.

#### [MODIFY] [dj_graph.go](file:///home/qosim/Desktop/lldp_go/dj_graph.go)
- D3.js frontendiga jo'natiladigan `GraphNode` JSON modeliga `Unreachable bool \`json:"unreachable"\`` qo'shish.
- Node yasalayotganda, qachonki `Unreachable == true` bo'lsa, uni Frontend bilsin deb Labeliga `(DOWN - Last Seen: hh:mm)` yozuvini qo'shib yuborish.

---

### Frontend Components

#### [MODIFY] [static/app.js](file:///home/qosim/Desktop/lldp_go/static/app.js) // yoki frontend qismi
- Agar node `d.unreachable == true` bo'lsa, uning xaritasidagi halqasini qizil tuman (red glow) ga, chiziqlarini esa "dashed" (kesilgan-kesilgan uzuq chiziqlar) ko'rinishiga o'tkazish logikasini tekshirish/qo'shish. Shunda administrator aynan qaysi qurilma o'chib qolganini real-vaqt rejimida yaqqol ko'radi.

## Open Questions

- Tarmoq qurilmasi qanchalik uzoq vaqt `Unreachable` turishi kerak? Masalan, 24 soatdan so'ng uni "grafdan butunlay olib tashlash" (Garbage Collection) qoidasini ham kiritishimiz kerakmi, yoki u doimiy "Down" bo'lib turaversinmi?
- Faza 8 ni hozir kodga yozishni (Execute) boshlaymi?

## Verification Plan

### Automated / Manual Verification
1. Skanerni oddiy holatda o'chirib yoqaman (`--mode normal`).
2. Skaner topgan birorta IP ni kod darajasida sun'iy "Timeout" holatiga solib ko'raman.
3. Graf API ni chaqiraman (`GET /api/graph`). U yerdan o'sha IP "Unreachable: true" deb qaytayotganini tekshiraman.
4. Uning chiziqlari va node xolati vizual uzilganligiga ishonch hosil qilaman.
