#!/bin/bash
# send_udp_tps.sh — Send UDP requests at precise TPS using a single Python process
#
# Usage: ./send_udp_tps.sh [TPS] [duration_sec] [target_ip] [target_port] [response_port] [callingMSISDN] [calledMSISDN] [destID]

TPS="${1}"
DURATION="${2}"

if [ -z "$TPS" ] || [ -z "$DURATION" ]; then
    echo "Error: Missing mandatory parameters."
    echo "Usage: $0 <TPS> <DURATION_SEC> [target_ip] [target_port] [response_port] [callingMSISDN] [calledMSISDN] [destID]"
    exit 1
fi

TARGET_IP="${3:-10.20.10.119}"
TARGET_PORT="${4:-9070}"
RESPONSE_PORT="${5:-9080}"
CALLING="${6:-2348162002720}"
CALLED="${7:-+2349167536622}"
DEST_ID="${8:-10.20.10.120}"

TOTAL_REQUESTS=$((TPS * DURATION))
PCAP_FILE="obd_test_$(date +%Y%m%d_%H%M%S).pcap"

echo "============================================"
echo "  OBD Service — Scaled Rate-Limit Test"
echo "============================================"
echo "  Target IP      : ${TARGET_IP}:${TARGET_PORT}"
echo "  Response Port  : ${RESPONSE_PORT}"
echo "  Calling        : ${CALLING}"
echo "  Called         : ${CALLED}"
echo "  destID         : ${DEST_ID}"
echo "  Target Rate    : ${TPS} TPS"
echo "  Duration       : ${DURATION} seconds"
echo "  Total Requests : ${TOTAL_REQUESTS}"
echo "  PCAP Output    : ${PCAP_FILE}"
echo "============================================"
echo ""

# Start tcpdump
echo "[*] Starting packet capture..."
tcpdump -i any -s 0 -w "$PCAP_FILE" "udp" > /dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 1

echo "[*] Launching sender + listener via Python (TPS=${TPS}, duration=${DURATION}s)..."
echo ""

python3 - <<PYEOF
import socket
import time
import threading
import json

TARGET_IP     = "${TARGET_IP}"
TARGET_PORT   = int("${TARGET_PORT}")
RESPONSE_PORT = int("${RESPONSE_PORT}")
CALLING       = "${CALLING}"
CALLED        = "${CALLED}"
DEST_ID       = "${DEST_ID}"
TPS           = int("${TPS}")
DURATION      = int("${DURATION}")
TOTAL         = TPS * DURATION

# Response wait: full duration + 30s settle for slow/queued responses
RECV_TIMEOUT  = DURATION + 30

results   = []
results_lock = threading.Lock()
send_done = threading.Event()

# ── Receiver thread ──────────────────────────────────────────────────
# Stays alive until all TOTAL responses received OR RECV_TIMEOUT expires
def receiver():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('0.0.0.0', RESPONSE_PORT))
    sock.settimeout(1)
    deadline = time.monotonic() + RECV_TIMEOUT
    while time.monotonic() < deadline:
        # Stop early only if all responses received
        with results_lock:
            received = len(results)
        if received >= TOTAL and send_done.is_set():
            break
        try:
            data, _ = sock.recvfrom(4096)
            msg = data.decode().strip()
            if not msg:
                continue
            with results_lock:
                results.append(msg)
            try:
                obj = json.loads(msg)
                req_id  = obj.get('requestId', 'N/A')
                status  = obj.get('deliveryStatus', 'N/A')
                ts      = obj.get('deliveryTimestamp', '')
                called  = obj.get('calledMsisdn', '')
                with results_lock:
                    idx = len(results)
                print(f'  << [{idx}] {req_id} | {status} | {called} | {ts}')
            except Exception:
                print(f'  << [raw] {msg}')
        except socket.timeout:
            pass
        except Exception as e:
            print('Receiver error:', e)
            break
    sock.close()

rx_thread = threading.Thread(target=receiver, daemon=True)
rx_thread.start()
time.sleep(0.3)

# ── Sender — single socket, token-bucket rate limiter ────────────────
send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
send_sock.connect((TARGET_IP, TARGET_PORT))

sent      = 0
interval  = 1.0 / TPS
next_send = time.monotonic()
start_time = time.monotonic()

print(f'[*] Sending {TOTAL} requests at {TPS} TPS...')
print('')

for i in range(1, TOTAL + 1):
    ts_ns  = int(time.time() * 1e9)
    req_id = f"REQ-OBD-{ts_ns}-{i}"
    msg = json.dumps({
        "callingMSISDN": CALLING,
        "calledMSISDN":  CALLED,
        "requestId":     req_id,
        "destID":        DEST_ID
    })
    try:
        send_sock.send(msg.encode())
        sent += 1
    except Exception as e:
        print(f'Send error on req {i}: {e}')

    # Token-bucket: sleep only the remaining gap to next slot
    next_send += interval
    gap = next_send - time.monotonic()
    if gap > 0:
        time.sleep(gap)

elapsed    = time.monotonic() - start_time
actual_tps = sent / elapsed if elapsed > 0 else 0
send_sock.close()
send_done.set()

print(f'[*] Sent {sent}/{TOTAL} in {elapsed:.2f}s — actual TPS: {actual_tps:.1f}')
print(f'[*] Waiting up to {RECV_TIMEOUT}s for all responses...')

rx_thread.join(timeout=RECV_TIMEOUT)

# ── Final report ─────────────────────────────────────────────────────
counters = {'SUCCESS': 0, 'FAILED': 0, 'NOT_REACHABLE': 0, 'UNKNOWN': 0}

with results_lock:
    snapshot = list(results)

total_received = len(snapshot)

print('')
print('============================================')
print('  FINAL REPORT')
print('============================================')

for idx, line in enumerate(snapshot, 1):
    try:
        obj     = json.loads(line)
        req_id  = obj.get('requestId', 'N/A')
        status  = obj.get('deliveryStatus', 'UNKNOWN')
        ts      = obj.get('deliveryTimestamp', '')
        called  = obj.get('calledMsisdn', '')
        counters[status] = counters.get(status, 0) + 1
    except Exception:
        counters['UNKNOWN'] += 1

print('')
print('--------------------------------------------')
print('  SUMMARY')
print('--------------------------------------------')
print(f'  Sent           : {TOTAL}')
print(f'  Received       : {total_received}')
print(f'  SUCCESS        : {counters.get("SUCCESS", 0)}')
print(f'  FAILED         : {counters.get("FAILED", 0)}')
print(f'  NOT_REACHABLE  : {counters.get("NOT_REACHABLE", 0)}')
print(f'  UNKNOWN        : {counters.get("UNKNOWN", 0)}')
print(f'  Lost           : {TOTAL - total_received}')
print('--------------------------------------------')
PYEOF

# Stop packet capture
kill $TCPDUMP_PID 2>/dev/null
wait $TCPDUMP_PID 2>/dev/null

echo ""
echo "  PCAP Output    : $PCAP_FILE"
echo "  Inspect Command: tshark -r $PCAP_FILE -Y sip"
echo "--------------------------------------------"

exit 0
