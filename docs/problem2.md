# Muammo 2: Vizual Illuziya (D3.js) va Izolyatsiyalangan Nomlar

Ushbu hujjatda tarmoq topologiyasi grafida (Web UI) yuzaga kelgan tushunmovchiliklar, xususan, uzilgan switchlarning ulangan bo'lib ko'rinishi va aniqlangan omillar hujjatlashtirilgan.

## 1. Asosiy Muammo (Foydalanuvchi shikoyati)
Foydalanuvchi UI grafida 3 ta qurilma: **HUAWEI (172.20.254.249)**, **Jamic (172.20.254.226)** va **HP (172.20.254.223)** o'zaro uchburchak shaklida (halqa) bog'lanib qolganini kuzatdi. Foydalanuvchi bu switchlar amalda bunday ulanmaganini aytib, xatolik borligini bildirdi.

## 2. Chuqur Tahlil Natijalari (Backend API va SNMP)
Biz `http://localhost:8088/api/graph` endpoints va to'g'ridan-to'g'ri `snmpwalk` orqali vaziyatni tahlil qildik:

| Qurilma | IP | API dagi aloqalar soni (Edges) | Tasdiqlangan aloqalar |
|---------|-----|--------------------------------|----------------------|
| **HUAWEI** | `172.20.254.249` | 2 | Jamic (Port 2), TTJ-3&4 (GE0/0/14) |
| **Jamic** | `172.20.254.226` | 10 (switch+endpoints) | HUAWEI (Port 52), va boshqalar |
| **HP** | `172.20.254.223` | **0 (Nol)** | **Hech kimga ulanmagan** |

**SNMP orqali tekshiruv quyidagilarni ko'rsatdi:**
*   **HUAWEI ↔ Jamic aloqasi HAQIQIY**: HUAWEI ning MAC jadvalida Jamic ning MAC manzili (e0:d9...) 2-portda yotibdi. Jamic ning MAC jadvalida HUAWEI ning MAC manzili (48:43...) 52-portda yotibdi. Bu erda haqiqiy *cross-reference* bor.
*   **HP (172.20.254.223) holati**:
    *   LLDP butunlay o'chirilgan (`No Such Instance`).
    *   **MAC jadvali butunlay bo'sh** (0 ta yozuv). 
    *   Shuning uchun bizning skanerimiz uni boshqa hech qaysi qurilmaga bog'lay olmaydi. U API da **0 ta edge** bilan mutlaqo izolyatsiya qilingan (isolated) holatda turibdi.

## 3. Nega ular ekranda birga ko'rindi? (Vizual Illuziya)
Frontend D3.js (`static/app.js`) kutubxonasidan, xususan **Force-Directed Graph (Fizika simulyatsiyasi)** layautidan foydalanadi:
```javascript
simulation = d3.forceSimulation(nodes)
    .force('charge', d3.forceManyBody().strength(-400))
    .force('center', d3.forceCenter(width / 2, height / 2))
```
**Nima yuz berdi?**
Tarmoqda hech kimga bog'lanmagan (0 ta chizig'i bor) yakkalanib qolgan tugunlar (HP kabi) fizika qonuniyatlariga ko'ra markaziy tortishish kuchi (`forceCenter`) sababli grafning o'rtasiga, eng ko'p tugunlar yig'ilgan joyga (ya'ni Jamic va HUAWEI yoniga) qarab suzib boradi. Ularning orasida **chiziq (edge) yo'q**, lekin joylashuvi juda yaqin bo'lgani uchun vizual jihatdan "ulangan guruh"dek taassurot (illuziya) uyg'otadi. Ular orasida halqa (loop) emas, fizika simulyatsiyasining tortishish effekti ishlagan.

## 4. HUAWEI ga oid qo'shimcha bilimlar (Bugs & Finds)
Tahlil davomida HUAWEI S5720 (172.20.254.249) haqida quyidagi muhim jihat aniqlandi:
*   Bu model standart LLDP MIB larini (1.0.8802.1.1.2...) qo'llab-quvvatlamaydi (`No Such Object` qaytaradi).
*   Mahalliy **ChassisID** so'ralganda ham MIB xatoligi qaytgan. Natijada `example_usage.go` qurilmaning ID si sifatida tushib qolgan xatolik matnini o'zlashtirib olgan:
    *   `Node ID: "no:such:object:available:on:this:agent:at:this:oid"`
*   Bunga qaramay, biz ishlab chiqqan **MAC Cross-Reference Discovery** algoritmi bu xatolikka qaramay HUAWEI ni Jamic va boshqa switchlar bilan muvaffaqiyatli bog'lay oldi.

## Xulosa va Keyingi Qadamlar
1.  **D3.js Rendering**: Izolyatsiyalangan (0 edges) tugunlarni markaziy massadan uzoqroqqa itaradigan yoki ularni vizual ajratib turadigan qo'shimcha "Gravity" yoki "Positioning" qoidalari yozilishi tavsiya etiladi, toki foydalanuvchida illuziya paydo bo'lmasin.
2.  **HP 172.20.254.223**: Qurilmaga kiritilib LLDP yoqilishi hamda MAC jadvali ishlayotgani (interface state) tekshirilishi kerak. Konfiguratsiya saqlanmagan (write memory) bo'lishi ehtimoli bor.
3.  **HUAWEI ID Xatosi**: Kodda ChassisID "No Such Object" matnini o'zlashtirib olishining oldini oluvchi filtr (`strings.Contains("no such object")`) qo'shilishi, bu holatda qurilmaning IP yoki IF-MIB dagi o'z MAC manzilini fallback sifatida ishlatish mexanizmi qo'shilishi kerak.
