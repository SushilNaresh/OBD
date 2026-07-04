#!/bin/bash
# run.sh — Start OBD missed call service
#
# Usage: ./run.sh [foreground|bg]

MODE="${1:-foreground}"
CONFIG_FILE="${OBD_CONFIG_FILE:-$(dirname "$0")/obd.conf}"

if [ ! -f "$CONFIG_FILE" ]; then
    echo "Missing config file: $CONFIG_FILE"
    exit 1
fi

echo "=== OBD Missed Call Service ==="
echo "  Config file  : ${CONFIG_FILE}"
echo "==============================="
echo ""

if [ "$MODE" = "bg" ]; then
    nohup ./obd --config "$CONFIG_FILE" > /var/log/obd.log 2>&1 &
    echo "Started in background (PID: $!)"
    echo "Logs: tail -f /var/log/obd.log | jq ."
else
    ./obd --config "$CONFIG_FILE"
fi
