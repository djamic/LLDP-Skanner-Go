#!/bin/bash
# ============================================================
# LLDP Network Scanner — Offline O'rnatish Skripti
# ============================================================
# Bu skript Docker imijlarni yuklaydi va tizimni ishga tushiradi.
# Internet talab qilinmaydi!
# ============================================================

set -e

echo "╔══════════════════════════════════════════════════╗"
echo "║   LLDP Network Scanner — Offline O'rnatish       ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""

# 1. Docker o'rnatilganligini tekshirish
if ! command -v docker &> /dev/null; then
    echo "❌ Docker topilmadi! Oldin Docker o'rnating."
    echo "   Ubuntu: sudo apt install docker.io docker-compose-plugin"
    exit 1
fi

echo "✅ Docker topildi: $(docker --version)"
echo ""

# 2. Docker imijlarni yuklash
echo "📦 Docker imijlar yuklanmoqda (lldp_images.tar)..."
docker load -i lldp_images.tar
echo "✅ Docker imijlar muvaffaqiyatli yuklandi!"
echo ""

# 3. Kerakli papkalarni yaratish
mkdir -p results/24h captures influxdb/data influxdb/config
echo "✅ Papkalar yaratildi"

# 4. Cron job sozlash (har kuni soat 05:00)
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
chmod +x "$SCRIPT_DIR/start_monitor.sh"

# Oldingi LLDP cron larni o'chirish va yangisini qo'shish
(crontab -l 2>/dev/null | grep -v 'start_docker_monitor' | grep -v 'start_monitor' | grep -v 'start_daily_monitor'; \
 echo "0 5 * * * $SCRIPT_DIR/start_monitor.sh") | crontab -
echo "✅ Cron job sozlandi: har kuni 05:00 da avtomatik ishga tushadi"
echo ""

# 5. swich_ips faylini tahrirlash
echo "⚠️  MUHIM: swich_ips faylini tekshiring!"
echo "   Hozirgi IP manzillar:"
cat swich_ips
echo ""
echo "   Kerak bo'lsa tahrirlang: nano $SCRIPT_DIR/swich_ips"
echo ""

# 6. Tizimni ishga tushirish
echo "🚀 Tizim ishga tushirilmoqda..."
docker compose up -d influxdb
sleep 5
nohup "$SCRIPT_DIR/start_monitor.sh" > /dev/null 2>&1 &
echo ""

# 7. Natija
echo "╔══════════════════════════════════════════════════╗"
echo "║   ✅ O'rnatish muvaffaqiyatli yakunlandi!        ║"
echo "╠══════════════════════════════════════════════════╣"
echo "║   Web UI:     http://localhost:8088              ║"
echo "║   InfluxDB:   http://localhost:8086              ║"
echo "║   Cron:       Har kuni 05:00                    ║"
echo "╠══════════════════════════════════════════════════╣"
echo "║   Foydali buyruqlar:                            ║"
echo "║   ./start_monitor.sh            — qayta ishlatish║"
echo "║   docker compose down           — to'xtatish     ║"
echo "╚══════════════════════════════════════════════════╝"
