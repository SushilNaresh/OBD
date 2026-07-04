#!/bin/bash
# stop.sh — Graceful shutdown of OBD service

PIDS=$(pgrep -f './obd')
if [ -z "$PIDS" ]; then
    echo "OBD service not running."
    exit 0
fi

echo "Stopping OBD service..."
echo "  PIDs: $PIDS"

# Send SIGTERM (graceful)
kill -TERM $PIDS 2>/dev/null
sleep 2

# Check if still running
REMAINING=$(pgrep -f './obd')
if [ -n "$REMAINING" ]; then
    echo "  Force killing remaining: $REMAINING"
    kill -9 $REMAINING 2>/dev/null
    sleep 1
fi

# Cleanup Unix sockets
rm -f /tmp/obd_worker_*.sock /tmp/obd_hb_*.sock 2>/dev/null

echo "Stopped."
