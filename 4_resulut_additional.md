### 4.2.1. Qurilmalar Faolligining 24 Soatlik Tahlili (Dynamic Discovery)

InfluxDB tizimidagi 24 soatlik monitoring doirasida jami **24 MB lik tarmoq hodisalari jurnali (log.csv)** tahlil qilindi va tarmoq trafigi, kompyuterlar faolligi hamda kritik yuklanish vaqtlari bo'yicha quyidagi aniq raqamli ko'rsatkichlar qayd etildi.

#### 1-Task. 4 soatlik intervallarda kompyuterlar faolligi (Yongan va o'chgan qurilmalar)

Tarmoqdagi jami 7,989 ta noyob qurilma faolligi 4 soatlik davriylik bilan tahlil qilinganda, qurilmalarning tarmoqqa qachon kirishi (JOIN) va qachon uzilishi (LEAVE) bo'yicha quyidagi jadval shakllantirildi:

| Vaqt Oralig'i | Tarmoqqa Yongan (JOIN) | Tarmoqdan O'chgan (LEAVE) | Jami Harakatlar Soni |
|:---:|:---:|:---:|:---:|
| **08:00 – 12:00** | 7,822 ta qurilma | 7,349 ta qurilma | 15,171 ta |
| **12:00 – 16:00** | 2,976 ta qurilma | 6,060 ta qurilma | 9,036 ta |
| **16:00 – 20:00** | 3,094 ta qurilma | 3,528 ta qurilma | 6,622 ta |
| **20:00 – 00:00** | 2,704 ta qurilma | 2,780 ta qurilma | 5,484 ta |
| **00:00 – 08:00** (Tungi smena) | 14,234 ta qurilma | 13,415 ta qurilma | 27,649 ta |

Yuqoridagi natijalardan ko'rinib turibdiki, eng katta umumiy sakrash tungi tizim qayta ishga tushadigan va tarmoqda DHCP-ijaralar avtomatik yangilanadigan **00:00 - 08:00** smenasida (27 mingta operatsiya) ro'y bergan. Ish kunining ochiq faoliyati davrida esa **08:00 – 12:00** oralig'ida foydalanuvchilar yoppasiga tizimga kirgan va tarmoqda katta faollik yuzaga kelgan.

#### 2-Task. Eng katta "Pik" vaqtlari (Tarmoq yuklanishining eng avj nuqtalari)

Tizim jurnali 30 daqiqalik intervallarga bo'lib vizualizatsiya qilinganda, tarmoqda kunlik eng og'ir "Pik" soatlar (Tarmoq Sakrashlari) aniqlandi. Eng ko'p kompyuterlar tarmog'ida siljish, yoqish-o'chirish jarayonlari quyidagi yarim soatlik intervallarda aniqlandi:

1. **05:00 – 05:30 oralig'i:** 3,580 ta hodisa (Ertalabki avtomatlashtirilgan cron job va tarmoq monitoring reset jarayonlari hisobiga tarmoqda eng yirik texnik siljish qayd etilgan).
2. **10:00 – 10:30 oralig'i:** 3,506 ta hodisa (Haqiqiy foydalanuvchilar qatlamida eng ko'p ish jarayonining avj olgan nuqtasi, kompyuterlarning eng faol ishlash jarayoni).
3. **00:00 – 00:30 oralig'i:** 3,317 ta hodisa (Davriy DHCP release/renew munosabati hisobiga yuzaga kelgan tunda yig'ilgan texnik sakrash).
4. **15:30 – 16:00 oralig'i:** 3,272 ta hodisa (Xodimlarning ish vaqti sekinlik bilan tugab borar ekan, tarmoq faoliyati susayishni va qurilmalar passiv rejimga o'tishni boshlagan jarayon).
5. **07:00 – 07:30 oralig'i:** 3,128 ta hodisa (Ilk ertalabki xodimlarning ish ofislariga kelib kompyuter va noutbuklarni ommaviy ishga tushirishi ro'y bergan payt).

**Xulosa:** 4 soatlik monitoringda inson omiliga (foydalanuvchilarga) bog'liq bo'lgan eng katta yirik tarmoq siljishi aynan ertalab **07:00 va 10:30** oralig'iga to'g'ri keldi.

#### 3-Task. Uzoq vaqt OFFLINE holatda qolgan (Dead Nodes) qurilmalar tahlili

Tarmoqqa kirib faoliyat yuritgan jami 7,989 ta qurilmaning hayot-mamot siklini (Lifecycle) tahlil qilganda ularning uzluksiz emasligi yaqqol ko'zga tashlanadi:

- **24 soat ohiridagi Offline-status (Tun yakuni):** 7,877 ta qurilmaning eng oxirgi holati tarmoqda **LEAVE** ekanligi aniqlangan. Bu shuni anglatadiki, ish kuni yakunida kompyuterlarning 98% foizi shunchaki "Uyqu (Sleep)" rejimida qoldirilmaydi, balki quvvatdan butunlay tarmoqdan uzib o'chiriladi.
- **Dead Nodes (Tarmoqda doimiy ochiq qurilmalar):** Tizim tarixiga yozilganlar ichidan jami **745 ta qurilma** oxirgi 24 soatlik doirada doimiy ravishda tarmoqqa qaytib umuman (JOIN) qilmagan, ya'ni ularning kuchi o'chirilgan holida davriy uzilishlardan so'ng boshqa ko'rinish bermagan. Bular ofisda uzoq muddat (shifoxona, o'quv markazlari holatiga qarab) foydalanmayotgan jihozlar bo'lishi kuchli taxmin qilinadi.
