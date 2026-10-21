#!/bin/bash
# ============================================================
# LLDP Network Scanner - Har kungi Cron Ishga tushiruvchi
# Ushbu skript har kuni ertalab 5:00 da cron orqali ishlaydi
# ============================================================

cd /home/qosim/Desktop/lldp_go || exit 1

# 1. Eski jarayonlarni xavfsiz to'xtatish (agar 24 soat to'lmasdan qotib qolgan bo'lsa ham)
echo "ilo1991!" | sudo -S pkill -f "lldp_scanner" 2>/dev/null
sleep 3

# 2. Yangi sikl boshlanishidan oldin toza boshlash (Ixtiyoriy)
# rm -f network_data.json mac_ip_cache.json 
# Agar har safar noldan toza sweep boshlamoqchi bo'lmasangiz, yuqoridagi qator "//" bo'lib tursin

# Log yozishni boshlash
echo "======================================================" >> results/cron.log
echo "🚀 [CRON] Monitor 24h ishga tushirildi: $(date)" >> results/cron.log

# 3. Dasturni fonda, loglarni cron.log ga yozadigan qilib ishga tushirish
echo "ilo1991!" | sudo -S env GOTRACEBACK=none ./lldp_scanner \
  --mode=monitor24h \
  --duration=24h \
  --output=results/24h \
  >> results/cron.log 2>&1 &

echo "✅ [CRON] Background task yuborildi." >> results/cron.log
