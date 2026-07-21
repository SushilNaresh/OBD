#!/usr/bin/env bash
# =============================================================================
# monitor.sh — Remote OBD live monitor over SSH
# Usage:
#   ./monitor.sh [options]
#
# Options:
#   -h HOST       Server hostname or IP         (default: $OBD_HOST or prompt)
#   -u USER       SSH username                  (default: $OBD_USER or prompt)
#   -P PASS       SSH password                  (default: $OBD_PASS or prompt)
#   -i KEY        SSH identity file             (optional, skips password)
#   -p PORT       SSH port                      (default: 22)
#   -l LOGFILE    Remote log path               (default: /u03/photonlogs/obd_runtime.log)
#   -t TOTAL      Total requests sent (--total) (default: none)
#   -n LEVEL      OBD log level filter          (default: 3 = INFO)
#   -w INTERVAL   Watch interval seconds        (default: 30)
#   -o            One-shot: run once and exit
#   -s            Live system stats only (no analyze)
#   -a            Analyze only (no live stats)
#   -r            Tail raw log lines live
#   --norot       Pass --norot to analyze.py
#   --save        Save connection profile to ~/.obd_monitor
#   --load        Load saved profile from ~/.obd_monitor
# =============================================================================
set -euo pipefail

# ── Defaults ──────────────────────────────────────────────────────────────────
HOST="${OBD_HOST:-}"
SSHUSER="${OBD_USER:-}"
PASS="${OBD_PASS:-}"
KEY="${OBD_KEY:-}"
SSH_PORT=22
REMOTE_LOG="/u03/photonlogs/obd_runtime.log"
TOTAL=""
LEVEL=3
INTERVAL=30
ONE_SHOT=0
LIVE_STATS=1
DO_ANALYZE=1
TAIL_LOG=0
NOROT=""
SAVE_PROFILE=0
LOAD_PROFILE=0
ANALYZE_PY="$(cd "$(dirname "$0")" && pwd)/analyze.py"
PROFILE="$HOME/.obd_monitor"

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; YEL='\033[0;33m'; GRN='\033[0;32m'
CYN='\033[0;36m'; BLD='\033[1m'; RST='\033[0m'

die() { echo -e "${RED}ERROR: $*${RST}" >&2; exit 1; }

# ── Argument parsing ──────────────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h)      HOST="$2";       shift 2 ;;
        -u)      SSHUSER="$2";    shift 2 ;;
        -P)      PASS="$2";       shift 2 ;;
        -i)      KEY="$2";        shift 2 ;;
        -p)      SSH_PORT="$2";   shift 2 ;;
        -l)      REMOTE_LOG="$2"; shift 2 ;;
        -t)      TOTAL="$2";      shift 2 ;;
        -n)      LEVEL="$2";      shift 2 ;;
        -w)      INTERVAL="$2";   shift 2 ;;
        -o)      ONE_SHOT=1;      shift   ;;
        -s)      DO_ANALYZE=0;    shift   ;;
        -a)      LIVE_STATS=0;    shift   ;;
        -r)      TAIL_LOG=1;      shift   ;;
        --norot) NOROT="--norot"; shift   ;;
        --save)  SAVE_PROFILE=1;  shift   ;;
        --load)  LOAD_PROFILE=1;  shift   ;;
        --help)
            grep '^#' "$0" | grep -v '#!/' | sed 's/^# \{0,2\}//'
            exit 0 ;;
        *) die "Unknown option: $1" ;;
    esac
done

# ── Load saved profile ────────────────────────────────────────────────────────
if [[ "$LOAD_PROFILE" -eq 1 ]]; then
    [[ -f "$PROFILE" ]] || die "No saved profile found at $PROFILE. Run with --save first."
    # shellcheck source=/dev/null
    source "$PROFILE"
    echo -e "${GRN}Loaded profile from $PROFILE${RST}"
fi

# ── Interactive prompts for missing fields ────────────────────────────────────
if [[ -z "$HOST" ]]; then
    read -rp "Server host/IP: " HOST
fi
[[ -z "$HOST" ]] && die "No host specified"

if [[ -z "$SSHUSER" ]]; then
    read -rp "Username [root]: " SSHUSER
    SSHUSER="${SSHUSER:-root}"
fi

# ── Auth: key takes priority over password ────────────────────────────────────
USE_SSHPASS=0
if [[ -n "$KEY" && -f "$KEY" ]]; then
    USE_SSHPASS=0
else
    USE_SSHPASS=1
    if [[ -z "$PASS" ]]; then
        read -rsp "Password for ${SSHUSER}@${HOST}: " PASS
        echo ""
    fi
    [[ -z "$PASS" ]] && die "No password provided and no SSH key found"
fi

# ── Manual sshpass build from source (macOS fallback) ───────────────────────
_install_sshpass_manual() {
    echo -e "${YEL}Building sshpass from source...${RST}"
    local ver="1.10"
    local url="https://sourceforge.net/projects/sshpass/files/sshpass/${ver}/sshpass-${ver}.tar.gz"
    local tmp
    tmp=$(mktemp -d)
    curl -fsSL "$url" -o "${tmp}/sshpass.tar.gz" \
        || die "Failed to download sshpass source from SourceForge"
    tar -xzf "${tmp}/sshpass.tar.gz" -C "$tmp"
    pushd "${tmp}/sshpass-${ver}" > /dev/null
    ./configure --prefix="$HOME/.local" > /dev/null 2>&1 \
        && make > /dev/null 2>&1 \
        && make install > /dev/null 2>&1 \
        || die "sshpass build failed. Install Xcode CLI tools: xcode-select --install"
    popd > /dev/null
    rm -rf "$tmp"
    # Add ~/.local/bin to PATH for this session
    export PATH="$HOME/.local/bin:$PATH"
    echo -e "${GRN}sshpass built and installed to ~/.local/bin${RST}"
}

# ── Ensure sshpass is available ───────────────────────────────────────────────
if [[ "$USE_SSHPASS" -eq 1 ]]; then
    if ! command -v sshpass &>/dev/null; then
        echo -e "${YEL}sshpass not found — attempting install...${RST}"
        if command -v brew &>/dev/null; then
            # Try direct formula first (works on most macOS + Apple Silicon)
            if brew install sshpass 2>/dev/null; then
                echo -e "${GRN}sshpass installed via brew.${RST}"
            elif brew install hudochenkov/sshpass/sshpass 2>/dev/null; then
                echo -e "${GRN}sshpass installed via hudochenkov tap.${RST}"
            else
                echo -e "${YEL}brew install failed — trying manual build...${RST}"
                _install_sshpass_manual
            fi
        elif command -v apt-get &>/dev/null; then
            sudo apt-get install -y sshpass || die "Could not install sshpass"
        elif command -v yum &>/dev/null; then
            sudo yum install -y sshpass || die "Could not install sshpass"
        else
            _install_sshpass_manual
        fi
        # Final check
        command -v sshpass &>/dev/null || die "sshpass install failed. Try manually:\n  brew install hudochenkov/sshpass/sshpass\n  or: https://sourceforge.net/projects/sshpass/"
    fi
fi

# ── Save profile ──────────────────────────────────────────────────────────────
if [[ "$SAVE_PROFILE" -eq 1 ]]; then
    cat > "$PROFILE" <<PROF
HOST="$HOST"
SSHUSER="$SSHUSER"
PASS="$PASS"
KEY="$KEY"
SSH_PORT=$SSH_PORT
REMOTE_LOG="$REMOTE_LOG"
PROF
    chmod 600 "$PROFILE"
    echo -e "${GRN}Profile saved to $PROFILE (chmod 600)${RST}"
fi

# ── SSH / SCP command builders ────────────────────────────────────────────────

SSH_OPTS_COMMON="-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o LogLevel=ERROR -p $SSH_PORT"
SCP_OPTS_COMMON="-o StrictHostKeyChecking=no -o ConnectTimeout=10 -o LogLevel=ERROR -P $SSH_PORT"

if [[ "$USE_SSHPASS" -eq 1 ]]; then
    # Disable pubkey auth entirely so SSH doesn't burn MaxAuthTries on ~/.ssh/* keys
    # before sshpass can inject the password.
    SSH_OPTS="$SSH_OPTS_COMMON -o PubkeyAuthentication=no -o IdentitiesOnly=yes"
    SCP_OPTS="$SCP_OPTS_COMMON -o PubkeyAuthentication=no -o IdentitiesOnly=yes"
    SSH_CMD="sshpass -p $PASS ssh $SSH_OPTS"
    SCP_CMD="sshpass -p $PASS scp -q $SCP_OPTS"
else
    SSH_OPTS="$SSH_OPTS_COMMON"
    SCP_OPTS="$SCP_OPTS_COMMON"
    SSH_CMD="ssh $SSH_OPTS -o BatchMode=yes -i $KEY"
    SCP_CMD="scp -q $SCP_OPTS -i $KEY"
fi

ssh_run() { $SSH_CMD "${SSHUSER}@${HOST}" "$@"; }
scp_put()  { $SCP_CMD "$1" "${SSHUSER}@${HOST}:$2"; }

# ── Verify connectivity ───────────────────────────────────────────────────────
echo -e "${CYN}Connecting to ${SSHUSER}@${HOST}:${SSH_PORT}...${RST}"
if ! ssh_run "echo ok" > /dev/null 2>&1; then
    die "SSH connection failed to ${SSHUSER}@${HOST}:${SSH_PORT}
  - Check VPN is connected
  - Verify host / username / password
  - Try manually: ssh ${SSHUSER}@${HOST} -p ${SSH_PORT}"
fi
echo -e "${GRN}Connected.${RST}\n"

# ── Upload analyze.py ─────────────────────────────────────────────────────────
if [[ "$DO_ANALYZE" -eq 1 ]]; then
    [[ -f "$ANALYZE_PY" ]] || die "analyze.py not found at $ANALYZE_PY"
    scp_put "$ANALYZE_PY" "/tmp/obd_analyze.py"
fi

# ── Tail raw log (blocking) ───────────────────────────────────────────────────
if [[ "$TAIL_LOG" -eq 1 ]]; then
    echo -e "${BLD}=== LIVE LOG TAIL: ${REMOTE_LOG} ===${RST}"
    echo -e "${YEL}Press Ctrl+C to stop${RST}\n"
    ssh_run "tail -F ${REMOTE_LOG} 2>/dev/null" | python3 - <<'PYEOF'
import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        o = json.loads(line)
        ll  = str(o.get('ll', 3))
        ev  = o.get('ev', '')
        w   = o.get('w', '')
        req = o.get('req', '')
        dt  = o.get('dt', '')
        col = {'1':'\033[0;31m','2':'\033[0;33m','3':'','4':'\033[0;36m','5':'\033[2m'}.get(ll,'')
        rst = '\033[0m' if col else ''
        extra = {k:v for k,v in o.items() if k not in ('dt','ll','file','line','ts','pid','w','req','ev')}
        print(f"{col}{dt}  {w:<6}  {ev:<35}  {req[:36]:<36}  {json.dumps(extra)}{rst}")
    except Exception:
        print(line)
PYEOF
    exit 0
fi

# ── Run analyze.py on server ──────────────────────────────────────────────────
run_analyze() {
    local total_arg=""
    [[ -n "$TOTAL" ]] && total_arg="--total $TOTAL"
    ssh_run "python3 /tmp/obd_analyze.py ${REMOTE_LOG} ${NOROT} ${total_arg} --level ${LEVEL}"
}

# ── Live system stats (runs entirely on server) ───────────────────────────────
run_live_stats() {
    ssh_run bash <<'REMOTE'
echo "=== PROCESS ==="
PROCS=$(pgrep -c obd 2>/dev/null || echo 0)
echo "  obd processes alive     : $PROCS  (expect 801 = 800 workers + 1 dispatcher)"

echo ""
echo "=== SIP SOCKET DISTRIBUTION (127.0.0.x:15xxx) ==="
ss -nup 2>/dev/null \
    | awk '{print $5}' \
    | grep -E '^127\.[0-9]+\.[0-9]+\.[0-9]+:1[5-9][0-9]{3}$' \
    | awk -F: '{print $1}' | sort | uniq -c \
    | awk '{printf "  %-18s : %d workers\n", $2, $1}' \
    || echo "  (none found)"

echo ""
echo "=== RTP SOCKET BIND ADDRESS DISTRIBUTION ==="
ss -nup 2>/dev/null \
    | awk '{print $5}' \
    | grep -E ':[2-3][0-9]{4}$' \
    | awk -F: '{print $1}' | sort | uniq -c | sort -rn \
    | awk '{printf "  %-18s : %d sockets\n", $2, $1}' \
    || echo "  (none found)"

echo ""
echo "=== RTP 0.0.0.0 LEAK CHECK ==="
LEAK=$(ss -nup 2>/dev/null \
    | awk '{print $5}' \
    | grep -cE '^0\.0\.0\.0:[2-3][0-9]{4}$' || true)
if [ "${LEAK:-0}" -gt 0 ] 2>/dev/null; then
    echo "  *** WARNING: $LEAK RTP sockets on 0.0.0.0 — dangling pointer bug still active ***"
else
    echo "  OK — no RTP sockets on 0.0.0.0"
fi

echo ""
echo "=== RTP PORT RANGE TOTALS ==="
TOTAL_RTP=$(ss -nup 2>/dev/null \
    | awk '{print $5}' \
    | grep -cE ':[2-3][0-9]{4}$' || true)
echo "  Total RTP/RTCP sockets  : ${TOTAL_RTP:-0}  (expect ~$(( 800 * 125 * 2 )) at full load)"

echo ""
echo "=== UNIX WORKER SOCKETS ==="
WSOCKS=$(ls /tmp/obd_worker_*.sock 2>/dev/null | wc -l)
echo "  /tmp/obd_worker_*.sock  : $WSOCKS  (expect 800)"

echo ""
echo "=== CPU / LOAD ==="
uptime
top -bn1 2>/dev/null | grep -E '^(%Cpu|Cpu)' | head -2 || true

echo ""
echo "=== MEMORY ==="
free -h 2>/dev/null || true

echo ""
echo "=== LOG FILE SIZES ==="
ls -lh /u03/photonlogs/obd_runtime.log* 2>/dev/null \
    || ls -lh /var/log/obd/obd_runtime.log* 2>/dev/null \
    || echo "  log not found at default paths"

echo ""
echo "=== RTP EADDRINUSE RATE (last 60s from pjsip log) ==="
python3 -c "
import glob, time, re, os
from datetime import datetime, timezone
now = time.time()
cutoff = now - 60
log_pattern = '/u03/photonlogs/obd_runtime.log*.pjsip'
files = glob.glob(log_pattern)
if not files:
    print('  (no pjsip log found at', log_pattern, ')')
else:
    count = 0
    total = 0
    ports = {}
    workers = {}
    for f in sorted(files):
        try:
            stat = os.stat(f)
            if stat.st_mtime < cutoff - 300:
                continue  # skip files not touched in last 5 min
            with open(f, errors='replace') as fh:
                for line in fh:
                    total += 1
                    if 'Address already in use' not in line:
                        continue
                    if 'RTP' not in line and 'RTCP' not in line:
                        continue
                    # Extract timestamp — try ISO first (OBD log), then HH:MM:SS.mmm (PJSIP log)
                    ts = None
                    tm = re.search(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+)', line)
                    if tm:
                        try:
                            ts = datetime.fromisoformat(tm.group(1)).timestamp()
                        except: pass
                    if ts is None:
                        tm = re.search(r'(\d{2}:\d{2}:\d{2}\.\d{3})', line)
                        if tm:
                            try:
                                today = datetime.now().strftime('%Y-%m-%d')
                                ts = datetime.strptime(today + ' ' + tm.group(1), '%Y-%m-%d %H:%M:%S.%f').timestamp()
                            except: pass
                    if ts is not None and ts < cutoff:
                        continue
                    count += 1
                    m = re.search(r'(127\.(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.(?:[0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])):([0-9]{1,5})(?:[^0-9]|$)', line)
                    if m:
                        ip = m.group(1)
                        port = int(m.group(2))
                        if port > 1024:
                            ports[port] = ports.get(port, 0) + 1
                            workers[ip] = workers.get(ip, 0) + 1
        except: pass
    print(f'  EADDRINUSE hits (last 60s): {count}')
    if workers:
        print('  By loopback IP:')
        for ip, cnt in sorted(workers.items(), key=lambda x: -x[1]):
            print(f'    {ip:<18}: {cnt}')
    if ports:
        top = sorted(ports.items(), key=lambda x: -x[1])[:5]
        print('  Top 5 colliding ports:')
        for port, cnt in top:
            print(f'    port {port:<6}: {cnt} hits')
    else:
        print('  No EADDRINUSE in last 60s — OK')
" 2>/dev/null || echo "  (pjsip log not accessible)"

echo ""
echo "=== RTP SOCKET STATE ON LOOPBACK (TIME_WAIT / CLOSE_WAIT) ==="
ss -nup state time-wait 2>/dev/null \
    | grep -cE '127\.[0-9]+\.[0-9]+\.[0-9]+:[2-9][0-9]{4}' \
    | xargs -I{} echo "  UDP TIME_WAIT on loopback RTP range: {}" \
    || echo "  (ss not available)"
ss -nup 2>/dev/null \
    | awk '{print $5}' \
    | grep -E '^127\.[0-9]+\.[0-9]+\.[0-9]+:[2-9][0-9]{4}$' \
    | wc -l \
    | xargs -I{} echo "  Active UDP sockets on loopback RTP range: {}"
python3 -c "
import os, glob, json
log = '/u03/photonlogs/obd_runtime.log'
rotated = sorted([p for p in glob.glob(log+'.*') if p.rsplit('.',1)[-1].isdigit()],
                 key=lambda p: int(p.rsplit('.',1)[-1]), reverse=True)
files = rotated + ([log] if os.path.exists(log) else [])
errors = []
for f in files:
    try:
        with open(f, errors='replace') as fh:
            for line in fh:
                try:
                    o = json.loads(line)
                    if o.get('ll',3) <= 2:
                        errors.append(f\"  {o.get('dt','')}  {o.get('w',''):<6}  {o.get('ev',''):<30}  {o.get('req','')[:36]}\")
                except: pass
    except: pass
if errors:
    for e in errors[-20:]: print(e)
else:
    print('  (none found across all log files)')
" 2>/dev/null || echo "  (log not accessible)"
REMOTE
}

# ── Print header ──────────────────────────────────────────────────────────────
print_header() {
    clear
    echo -e "${BLD}${CYN}╔══════════════════════════════════════════════════════════════════╗${RST}"
    printf "${BLD}${CYN}║  OBD Monitor  %-20s  %s  ║${RST}\n" "${SSHUSER}@${HOST}" "$(date '+%Y-%m-%d %H:%M:%S')"
    echo -e "${BLD}${CYN}╚══════════════════════════════════════════════════════════════════╝${RST}"
    echo ""
}

# ── Single full refresh ───────────────────────────────────────────────────────
run_once() {
    print_header

    if [[ "$LIVE_STATS" -eq 1 ]]; then
        echo -e "${BLD}${YEL}━━━ LIVE SYSTEM STATS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
        run_live_stats
        echo ""
    fi

    if [[ "$DO_ANALYZE" -eq 1 ]]; then
        echo -e "${BLD}${YEL}━━━ LOG ANALYSIS ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RST}"
        run_analyze
    fi

    if [[ "$ONE_SHOT" -eq 0 ]]; then
        echo ""
        echo -e "${CYN}Refreshing every ${INTERVAL}s — Ctrl+C to exit${RST}"
    fi
}

# ── One-shot or watch loop ────────────────────────────────────────────────────
if [[ "$ONE_SHOT" -eq 1 ]]; then
    run_once
    exit 0
fi

trap 'echo -e "\n${YEL}Stopped.${RST}"; exit 0' INT TERM

while true; do
    run_once
    sleep "$INTERVAL"
done
