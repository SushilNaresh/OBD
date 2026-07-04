#!/bin/bash
# send_udp.sh — Send UDP requests in PARALLEL to OBD service, capture pcap, receive responses
#
# Usage: ./send_udp.sh [target_ip] [target_port] [response_port] [callingMSISDN] [calledMSISDN] [destID] [count]

TARGET_IP="${1:-10.20.10.119}"
TARGET_PORT="${2:-9070}"
RESPONSE_PORT="${3:-9080}"
CALLING="${4:-2348162002720}"
CALLED="${5:-+2349167536622}"
DEST_ID="${6:-10.20.10.120}"
TOTAL_REQUESTS="${7:-1000}"

PCAP_FILE="obd_test_$(date +%Y%m%d_%H%M%S).pcap"
RESULT_FILE="/tmp/obd_test_results_$$.txt"
> "$RESULT_FILE"

echo "============================================"
echo "  OBD Service — Parallel Test"
echo "============================================"
echo "  Target       : ${TARGET_IP}:${TARGET_PORT}"
echo "  Response port: ${RESPONSE_PORT}"
echo "  Calling      : ${CALLING}"
echo "  Called       : ${CALLED}"
echo "  destID       : ${DEST_ID}"
echo "  Requests     : ${TOTAL_REQUESTS} (parallel)"
echo "  PCAP         : ${PCAP_FILE}"
echo "============================================"
echo ""

# Start tcpdump
echo "[*] Starting packet capture..."
tcpdump -i any -s 0 -w "$PCAP_FILE" "udp" > /dev/null 2>&1 &
TCPDUMP_PID=$!
sleep 1

# Start response listener
echo "[*] Starting response listener on port ${RESPONSE_PORT}..."
python3 -c "
import socket, time
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(('0.0.0.0', ${RESPONSE_PORT}))
sock.settimeout(1)
start = time.time()
while time.time() - start < 30:
    try:
        data, addr = sock.recvfrom(4096)
        msg = data.decode()
        with open('$RESULT_FILE', 'a') as f:
            f.write(msg + '\n')
            f.flush()
        print('  << ' + msg)
    except socket.timeout:
        pass
    except:
        break
sock.close()
" &
LISTENER_PID=$!
sleep 1

# Send all requests in parallel
echo ""
echo "[*] Sending ${TOTAL_REQUESTS} requests in parallel..."
echo ""

for i in $(seq 1 $TOTAL_REQUESTS); do
    REQ_ID="REQ-OBD-$(date +%s%N)-${i}"
    MSG="{\"callingMSISDN\":\"${CALLING}\",\"calledMSISDN\":\"${CALLED}\",\"requestId\":\"${REQ_ID}\",\"destID\":\"${DEST_ID}\"}"
    echo "  [${i}] ${REQ_ID}"
    echo -n "$MSG" | nc -u -w1 "$TARGET_IP" "$TARGET_PORT" &
done

# Wait for all nc to finish
wait $(jobs -p | grep -v "$TCPDUMP_PID" | grep -v "$LISTENER_PID") 2>/dev/null
echo ""
echo "[*] All requests sent. Waiting 25s for responses..."
sleep 25

# Stop listener and tcpdump
kill $LISTENER_PID 2>/dev/null
wait $LISTENER_PID 2>/dev/null
sleep 1
kill $TCPDUMP_PID 2>/dev/null
wait $TCPDUMP_PID 2>/dev/null

# Print results
echo ""
echo "============================================"
echo "  FINAL REPORT"
echo "============================================"
echo ""

MISSED_CALL=0
NO_ANSWER=0
UNAVAILABLE=0
UNREACHABLE=0
BUSY=0
CF_MCA=0
NETWORK_DOWN=0
REJECTED=0
UNKNOWN=0
TOTAL_RECEIVED=0

if [ -s "$RESULT_FILE" ]; then
    while IFS= read -r line; do
        if [ -z "$line" ]; then continue; fi
        TOTAL_RECEIVED=$((TOTAL_RECEIVED + 1))

        REQ_ID=$(echo "$line" | grep -oP '"requestId"\s*:\s*"\K[^"]+' 2>/dev/null)
        OUTCOME=$(echo "$line" | grep -oP '"outcome"\s*:\s*"\K[^"]+' 2>/dev/null)
        SIP_CODE=$(echo "$line" | grep -oP '"sipCode"\s*:\s*\K[0-9]+' 2>/dev/null)
        DURATION=$(echo "$line" | grep -oP '"durationMs"\s*:\s*\K[0-9]+' 2>/dev/null)

        case "$OUTCOME" in
            MISSED_CALL)  MISSED_CALL=$((MISSED_CALL + 1)) ;;
            NO_ANSWER)    NO_ANSWER=$((NO_ANSWER + 1)) ;;
            UNAVAILABLE)  UNAVAILABLE=$((UNAVAILABLE + 1)) ;;
            UNREACHABLE)  UNREACHABLE=$((UNREACHABLE + 1)) ;;
            BUSY)         BUSY=$((BUSY + 1)) ;;
            CF_MCA)       CF_MCA=$((CF_MCA + 1)) ;;
            NETWORK_DOWN) NETWORK_DOWN=$((NETWORK_DOWN + 1)) ;;
            REJECTED)     REJECTED=$((REJECTED + 1)) ;;
            *)            UNKNOWN=$((UNKNOWN + 1)) ;;
        esac

        echo "  [$TOTAL_RECEIVED] $REQ_ID | $OUTCOME | SIP:$SIP_CODE | ${DURATION}ms"
    done < "$RESULT_FILE"
else
    echo "  No responses received!"
fi

echo ""
echo "--------------------------------------------"
echo "  SUMMARY"
echo "--------------------------------------------"
echo "  Sent         : $TOTAL_REQUESTS"
echo "  Received     : $TOTAL_RECEIVED"
echo "  MISSED_CALL  : $MISSED_CALL"
echo "  UNAVAILABLE  : $UNAVAILABLE"
echo "  UNREACHABLE  : $UNREACHABLE"
echo "  NO_ANSWER    : $NO_ANSWER"
echo "  BUSY         : $BUSY"
echo "  CF_MCA       : $CF_MCA"
echo "  REJECTED     : $REJECTED"
echo "  NETWORK_DOWN : $NETWORK_DOWN"
echo "  UNKNOWN      : $UNKNOWN"
echo "  Lost         : $((TOTAL_REQUESTS - TOTAL_RECEIVED))"
echo "--------------------------------------------"
echo ""
echo "  PCAP         : $PCAP_FILE"
echo "  View         : tshark -r $PCAP_FILE -Y sip"
echo "--------------------------------------------"

# Cleanup
rm -f "$RESULT_FILE"
exit 0
