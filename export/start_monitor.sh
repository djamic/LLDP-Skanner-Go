#!/bin/bash
# ============================================================
# LLDP Network Scanner — Cron orqali ishga tushirish skripti
# Dockersiz, to'g'ridan-to'g'ri binary ishlatadi
# Har kuni soat 05:00 da cron orqali avtomatik ishga tushadi
# ============================================================

WORKDIR="$(cd "$(dirname "$0")" && pwd)"
LOGFILE="$WORKDIR/results/cron_monitor.log"
BINARY="$WORKDIR/lldp_scanner"

echo "========================================" >> "$LOGFILE"
echo "$(date '+%Y-%m-%d %H:%M:%S') — Cron: Monitor boshlanyapti..." >> "$LOGFILE"

# Agar oldingi process ishlayotgan bo'lsa — to'xtatish
pkill -f "lldp_scanner" 2>/dev/null
sleep 2

# InfluxDB konteyner ishlayotganligini tekshirish, kerak bo'lsa ishga tushirish
if ! docker ps --format '{{.Names}}' | grep -q "lldp_influxdb"; then
    echo "$(date '+%Y-%m-%d %H:%M:%S') — InfluxDB konteyner ishga tushirilmoqda..." >> "$LOGFILE"
    cd "$WORKDIR" && docker compose up -d influxdb >> "$LOGFILE" 2>&1
    sleep 5
fi

# Binary ni ishga tushirish (background)
cd "$WORKDIR"
"$BINARY" --mode=monitor24h --duration=24h --output=results/24h >> "$LOGFILE" 2>&1 &

echo "$(date '+%Y-%m-%d %H:%M:%S') — Cron: Monitor ishga tushdi! PID: $!" >> "$LOGFILE"
