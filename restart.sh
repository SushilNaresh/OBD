#!/bin/bash
# Clean OBD restart — waits for RTP sockets to drain before starting.
set -e

OBD_BIN=${1:-./obd}
OBD_CONF=${2:-obd.conf}
RTP_LOW=20000
RTP_HIGH=40000
DRAIN_TIMEOUT=15

echo "Stopping obd..."
pkill -TERM obd 2>/dev/null || true
sleep 1
pkill -9 obd 2>/dev/null || true

echo "Waiting for RTP sockets to drain (ports $RTP_LOW-$RTP_HIGH)..."
for i in $(seq 1 $DRAIN_TIMEOUT); do
    count=$(ss -ulnp 2>/dev/null | awk -F'[: ]+' -v lo=$RTP_LOW -v hi=$RTP_HIGH \
        'NR>1 && $5+0 >= lo && $5+0 <= hi {c++} END {print c+0}')
    [ "$count" -eq 0 ] && break
    echo "  ${i}s: $count sockets still bound..."
    sleep 1
done

remaining=$(ss -ulnp 2>/dev/null | awk -F'[: ]+' -v lo=$RTP_LOW -v hi=$RTP_HIGH \
    'NR>1 && $5+0 >= lo && $5+0 <= hi {c++} END {print c+0}')
if [ "$remaining" -gt 0 ]; then
    echo "WARNING: $remaining sockets still bound after ${DRAIN_TIMEOUT}s — starting anyway (SO_REUSEADDR will handle it)"
fi

echo "Starting obd..."
exec "$OBD_BIN" --config "$OBD_CONF"
