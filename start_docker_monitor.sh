#!/bin/bash
# Har kuni soat 05:00 da cron orqali ishga tushirish uchun
# Eski konteynerni to'xtatib, yangi skanerlashni boshlaydi

WORKDIR="/home/qosim/Desktop/lldp_go"
LOGFILE="$WORKDIR/results/cron_docker.log"

echo "========================================" >> "$LOGFILE"
echo "$(date '+%Y-%m-%d %H:%M:%S') — Cron: Monitor boshlanyapti..." >> "$LOGFILE"

cd "$WORKDIR"

# Eski app konteynerini to'xtatish (influxdb ishlayveradi)
docker compose stop app >> "$LOGFILE" 2>&1
docker compose rm -f app >> "$LOGFILE" 2>&1

# Yangi app konteynerini ishga tushirish
docker compose up -d >> "$LOGFILE" 2>&1

echo "$(date '+%Y-%m-%d %H:%M:%S') — Cron: Monitor ishga tushdi!" >> "$LOGFILE"
