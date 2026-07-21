#!/usr/bin/env python3
"""
OBD traffic analyzer — reads obd_runtime.log + all rotated backups.
Usage: python3 analyze.py [logfile] [--norot] [--total N] [--seq] [--udp-drop]
  --norot      : current file only, skip rotated .1 .2 ...
  --total N    : total requests sent by sender (for receipt gap analysis)
  --seq        : scan request_id sequence for gaps (network-level drops)
  --udp-drop   : show kernel UDP socket drop counters via /proc/net/udp
"""
import json, collections, sys, os, glob

log      = next((a for a in sys.argv[1:] if not a.startswith("--")), "/var/log/obd/obd_runtime.log")
no_rot     = "--norot" in sys.argv
check_seq  = "--seq" in sys.argv
udp_drop   = "--udp-drop" in sys.argv
total_sent = next((int(sys.argv[i+1]) for i, a in enumerate(sys.argv) if a == "--total" and i+1 < len(sys.argv)), None)
max_level  = next((int(sys.argv[i+1]) for i, a in enumerate(sys.argv) if a == "--level" and i+1 < len(sys.argv)), 5)

if not os.path.exists(log):
    print(f"File not found: {log}"); sys.exit(1)

if no_rot:
    log_files = [log]
else:
    rotated = [p for p in glob.glob(log + ".*") if p.rsplit(".", 1)[-1].isdigit()]
    rotated.sort(key=lambda p: int(p.rsplit(".", 1)[-1]), reverse=True)
    log_files = rotated + [log]

print(f"Reading {len(log_files)} file(s):")
for f in log_files:
    print(f"  {f}  ({os.path.getsize(f)/1024/1024:.1f} MB)")
print()

pipeline = [
    ("received",              "Received at dispatcher"),
    ("routed",                "Routed by dispatcher"),
    ("invite_sent",           "Received by worker"),
    ("leg_allocated",         "Call slot allocated"),
    ("leg_acc_added",         "SIP account created"),
    ("leg_invite_initiating", "INVITE initiating"),
    ("call_make_success",     "pjsua_call_make_call OK"),
    ("leg_invite_sent",       "INVITE on wire"),
    ("sent",                  "Completed"),
]

drops = [
    "acc_pool_full", "slab_alloc_failed", "local_capacity_reached",
    "leg_acc_add_failed", "leg_invite_failed",
    "no_workers_available", "route_failed", "dedup_drop",
    "recvq_overflow", "dispatch_slow",
]

counts           = collections.Counter()
first_dt         = {}
last_dt          = {}
received_seq_ids = []   # request_ids seen at 'received' event, for gap analysis
workers          = collections.Counter()
outcomes         = collections.Counter()
sip_codes        = collections.Counter()
tsx_codes        = collections.Counter()
tsx_methods      = collections.Counter()
dispatch_slow_ms = []
dispatcher_rates = []
recvq_stats      = []
worker_health    = []
duration_ms_list = []
teardown_triggers = collections.Counter()
parse_errors     = 0

# per-minute timeline buckets
per_minute       = collections.Counter()  # minute_str -> routed count

for log_file in log_files:
    with open(log_file, errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except Exception:
                parse_errors += 1
                continue
            ev = obj.get("ev", "")
            dt = obj.get("dt", "")
            w  = obj.get("w", "")
            ll = obj.get("ll", 3)   # default INFO if field absent (old logs)
            if not ev:
                continue
            if ll > max_level:
                continue
            counts[ev] += 1
            if ev not in first_dt:
                first_dt[ev] = dt
            last_dt[ev] = dt

            if ev == "received" and check_seq:
                rid = obj.get("request_id", "")
                if rid:
                    received_seq_ids.append(rid)
            if ev == "invite_sent" and w:
                workers[w] += 1
            elif ev == "routed" and dt:
                per_minute[dt[:16]] += 1   # YYYY-MM-DDTHH:MM
            elif ev == "sent":
                outcomes[obj.get("outcome", "?")] += 1
                sip_codes[str(obj.get("sip", "?"))] += 1
                ms = obj.get("ms")
                if ms is not None:
                    try: duration_ms_list.append(int(ms))
                    except: pass
            elif ev == "dispatch_slow":
                try: dispatch_slow_ms.append(int(obj.get("dispatch_ms", 0)))
                except: pass
            elif ev == "dispatcher_rate":
                dispatcher_rates.append(obj)
            elif ev == "worker_recvq_stats":
                recvq_stats.append(obj)
            elif ev == "worker_health":
                worker_health.append(obj)
            elif ev == "leg_tsx_update":
                code = obj.get("status_code", 0)
                if code >= 100:
                    tsx_codes[str(code)] += 1
                    tsx_methods[str(obj.get("method", "?"))] += 1
            elif ev == "leg_teardown_initiating":
                teardown_triggers[obj.get("trigger", "?")] += 1

# ── NETWORK-LEVEL DROP DETECTION (sequence gap analysis) ────────────
if check_seq and received_seq_ids:
    print("=== NETWORK-LEVEL DROP DETECTION (--seq) ===")
    # Extract numeric suffix from request_id (e.g. "req-000042" → 42, or pure int)
    def extract_seq(rid):
        parts = rid.replace("-", " ").replace("_", " ").split()
        for p in reversed(parts):
            if p.isdigit():
                return int(p)
        return None

    seqs = []
    non_numeric = 0
    for rid in received_seq_ids:
        n = extract_seq(rid)
        if n is not None:
            seqs.append(n)
        else:
            non_numeric += 1

    if non_numeric:
        print(f"  WARNING: {non_numeric:,} request_ids have no numeric suffix — gap check may be incomplete")

    if seqs:
        seqs.sort()
        lo, hi = seqs[0], seqs[-1]
        expected = set(range(lo, hi + 1))
        seen     = set(seqs)
        gaps     = sorted(expected - seen)
        dupes    = len(seqs) - len(seen)
        print(f"  Sequence range   : {lo} → {hi}  (span={hi-lo+1:,})")
        print(f"  Received         : {len(seen):,} unique")
        print(f"  Gaps (missing)   : {len(gaps):,}  ({len(gaps)/(hi-lo+1)*100:.2f}% of span)")
        if dupes:
            print(f"  Duplicates       : {dupes:,}")
        if gaps:
            # Show first 20 gap ranges
            ranges, start, prev = [], gaps[0], gaps[0]
            for g in gaps[1:]:
                if g == prev + 1:
                    prev = g
                else:
                    ranges.append((start, prev))
                    start = prev = g
            ranges.append((start, prev))
            print(f"  First 20 gap ranges:")
            for s, e in ranges[:20]:
                if s == e:
                    print(f"    missing seq {s}")
                else:
                    print(f"    missing seq {s}–{e}  ({e-s+1} consecutive)")
            if len(ranges) > 20:
                print(f"    ... and {len(ranges)-20} more ranges")
    print()

# ── UDP SOCKET DROP COUNTERS (/proc/net/udp) ─────────────────────────
if udp_drop:
    print("=== UDP SOCKET DROP COUNTERS (/proc/net/udp) ===")

    def parse_proc_udp(path):
        """Parse /proc/net/udp or /proc/net/udp6. Returns list of (port, recv_q, drops)."""
        rows = []
        try:
            with open(path) as f:
                for line in f:
                    parts = line.split()
                    if len(parts) < 13 or not parts[1][0].isdigit():
                        continue  # skip header
                    local = parts[1]          # hex IP:PORT
                    recv_q_hex = parts[4]     # hex recv_q:send_q
                    drops = int(parts[12])    # column 13 (0-indexed 12)
                    port = int(local.split(":")[1], 16)
                    recv_q = int(recv_q_hex.split(":")[0], 16)
                    rows.append((port, recv_q, drops))
        except FileNotFoundError:
            pass
        return rows

    total_drops = 0
    total_recvq = 0
    any_found   = False

    for proc_file in ("/proc/net/udp", "/proc/net/udp6"):
        rows = parse_proc_udp(proc_file)
        if not rows:
            continue
        any_found = True
        file_drops = sum(d for _, _, d in rows)
        file_recvq = sum(r for _, r, _ in rows)
        total_drops += file_drops
        total_recvq += file_recvq
        nonzero = [(p, r, d) for p, r, d in rows if d > 0 or r > 0]
        print(f"  {proc_file}: {len(rows)} sockets, total_drops={file_drops:,}, total_recv_q={file_recvq:,}")
        if nonzero:
            print(f"    {'Port':>6}  {'Recv-Q':>8}  {'Drops':>8}")
            for port, rq, dr in sorted(nonzero, key=lambda x: -x[2])[:20]:
                print(f"    {port:>6}  {rq:>8,}  {dr:>8,}")
        else:
            print(f"    (no sockets with drops or backlog)")

    if not any_found:
        print("  /proc/net/udp not found — run this on the Linux server, not locally")
        print("  Manual commands to run on server:")
        print("    awk 'NR>1 {drops+=$13} END {print \"total UDP drops:\", drops}' /proc/net/udp")
        print("    awk 'NR>1 {if($13>0) printf \"port=%d drops=%d\\n\",strtonum(\"0x\"substr($2,index($2,\":\")+1)),$13}' /proc/net/udp")
        print("    cat /proc/net/snmp | grep -E '^Udp:'")
    else:
        print(f"  TOTAL across all UDP sockets: drops={total_drops:,}  recv_q={total_recvq:,}")
        # Also show global kernel UDP error counters from /proc/net/snmp
        try:
            with open("/proc/net/snmp") as f:
                snmp = f.read()
            keys_line = vals_line = ""
            for line in snmp.splitlines():
                if line.startswith("Udp:"):
                    if not keys_line:
                        keys_line = line
                    else:
                        vals_line = line
                        break
            if keys_line and vals_line:
                keys = keys_line.split()[1:]
                vals = vals_line.split()[1:]
                snmp_map = dict(zip(keys, vals))
                interesting = ["InErrors", "RcvbufErrors", "InDatagrams", "NoPorts", "IgnoredMulti"]
                print(f"  /proc/net/snmp (global UDP counters):")
                for k in interesting:
                    if k in snmp_map:
                        print(f"    {k:<20}: {int(snmp_map[k]):>12,}")
        except FileNotFoundError:
            pass
    print()

# ── RECEIPT GAP ─────────────────────────────────────────────────────
print("=== MESSAGE RECEIPT ANALYSIS ===")
sent_by_sender  = total_sent
received_disp   = counts["received"]
routed          = counts["routed"]
received        = counts["invite_sent"]
completed       = counts["sent"]

# Peak pktq_dropped from dispatcher_rate snapshots
peak_pktq_dropped = max((int(r.get("pktq_dropped", 0)) for r in dispatcher_rates), default=0)

if sent_by_sender:
    not_received = sent_by_sender - received_disp
    print(f"  Sent by load generator          : {sent_by_sender:>10,}")
    print(f"  Received at dispatcher          : {received_disp:>10,}  ({received_disp/sent_by_sender*100:.1f}% of sent)")
    print(f"  NOT received at dispatcher      : {not_received:>10,}  ({not_received/sent_by_sender*100:.1f}% lost before OBD)")
    if peak_pktq_dropped:
        print(f"  Peak pktq_dropped (queue full)  : {peak_pktq_dropped:>10,}  ← packets dropped before routing")
    else:
        print(f"  Peak pktq_dropped (queue full)  : {peak_pktq_dropped:>10,}  (none — queue never overflowed)")
else:
    print(f"  Received at dispatcher          : {received_disp:>10,}  (pass --total N to show sender gap)")
    print(f"  Routed to worker                : {routed:>10,}")

print(f"  Received by worker              : {received:>10,}  ({received/routed*100:.1f}% of routed)" if routed else "")
print(f"  Completed (sent report)         : {completed:>10,}")

# Explain completed > routed (cross-run carryover)
if completed > routed:
    carryover = completed - routed
    print(f"  Carryover from prev run         : {carryover:>10,}  (calls started before log window)")

drop_total = sum(counts[d] for d in drops if d != "dispatch_slow")
print(f"  Dropped inside OBD              : {drop_total:>10,}")
print()

# ── WHAT HAPPENED TO EACH REQUEST ───────────────────────────────────
print("=== WHAT HAPPENED TO REQUESTS ===")
total_in = routed
if total_in:
    completed_ok  = counts["sent"]
    dropped_inner = drop_total
    in_flight_est = total_in - completed_ok - dropped_inner
    in_flight_est = max(in_flight_est, 0)
    print(f"  {total_in:>10,}  entered OBD (routed)")
    print(f"  {completed_ok:>10,}  completed and reported  ({completed_ok/total_in*100:.1f}%)")
    print(f"  {dropped_inner:>10,}  dropped before SIP      ({dropped_inner/total_in*100:.1f}%)")
    if in_flight_est:
        print(f"  {in_flight_est:>10,}  estimated still in-flight / log gap")
print()

# ── FUNNEL ──────────────────────────────────────────────────────────
# Map each funnel stage to the drop events that consume requests between
# this stage and the next, so gaps are explained inline.
stage_drops = {
    "invite_sent":           ["local_capacity_reached", "slab_alloc_failed"],
    "leg_allocated":         ["acc_pool_full"],
    "leg_acc_added":         ["leg_acc_add_failed"],
    "leg_invite_initiating": ["leg_invite_failed"],
}

print("=== INVITE FUNNEL ===")
prev = None
for ev, label in pipeline:
    n = counts[ev]
    if prev is None:
        print(f"  {label:<40}: {n:>10,}")
    else:
        pct  = (n / prev * 100) if prev else 0
        flag = "  <<<" if pct < 90 and prev > 100 else ""
        print(f"  {label:<40}: {n:>10,}  ({pct:.1f}% of prev){flag}")
        # Show which drop events account for the gap at this stage
        for dev in stage_drops.get(ev, []):
            dc = counts[dev]
            if dc:
                print(f"    └─ {dev:<36}: {dc:>10,}")
    if n > 0:
        prev = n

# ── TIMELINE ────────────────────────────────────────────────────────
print("\n=== TIMELINE ===")
for ev, label in pipeline:
    if ev in first_dt:
        print(f"  {ev:<30} {first_dt[ev]}  →  {last_dt[ev]}")

# ── PER-MINUTE RATE ─────────────────────────────────────────────────
if per_minute:
    print("\n=== PER-MINUTE ROUTED RATE ===")
    for minute in sorted(per_minute):
        n   = per_minute[minute]
        bar = "█" * (n // 50)
        print(f"  {minute}  {n:>6,}/min  {bar}")

# ── DROP REASONS ────────────────────────────────────────────────────
print("\n=== DROP REASONS ===")
any_drop = False
for ev in drops:
    n = counts[ev]
    if n:
        print(f"  {ev:<35}: {n:>10,}")
        any_drop = True
if not any_drop:
    print("  (none)")

# ── OUTCOMES ────────────────────────────────────────────────────────
if outcomes:
    total = sum(outcomes.values())
    print(f"\n=== CALL OUTCOMES (total={total:,}) ===")
    for o, n in outcomes.most_common():
        print(f"  {o:<30}: {n:>8,}  ({n/total*100:.1f}%)")

# ── CALL DURATION ───────────────────────────────────────────────────
if duration_ms_list:
    duration_ms_list.sort()
    n = len(duration_ms_list)
    print(f"\n=== CALL DURATION (ms) — {n:,} calls ===")
    print(f"  min   : {duration_ms_list[0]:>8,} ms")
    print(f"  median: {duration_ms_list[n//2]:>8,} ms")
    print(f"  p95   : {duration_ms_list[int(n*0.95)]:>8,} ms")
    print(f"  p99   : {duration_ms_list[int(n*0.99)]:>8,} ms")
    print(f"  max   : {duration_ms_list[-1]:>8,} ms")
    avg = sum(duration_ms_list) / n
    print(f"  avg   : {avg:>8,.0f} ms")

# ── SIP FINAL STATUS ────────────────────────────────────────────────
if sip_codes:
    print("\n=== SIP FINAL STATUS CODES ===")
    for code, n in sip_codes.most_common():
        print(f"  {code:<10}: {n:>8,}")

# ── TSX STATUS CODES ────────────────────────────────────────────────
if tsx_codes:
    print("\n=== SIP TRANSACTION STATUS CODES (leg_tsx_update) ===")
    for code, n in tsx_codes.most_common(20):
        print(f"  {code:<10}: {n:>8,}")

# ── TEARDOWN TRIGGERS ───────────────────────────────────────────────
if teardown_triggers:
    print("\n=== TEARDOWN TRIGGERS ===")
    total_td = sum(teardown_triggers.values())
    for t, n in teardown_triggers.most_common():
        print(f"  {t:<45}: {n:>8,}  ({n/total_td*100:.1f}%)")

# ── DISPATCHER RATE ─────────────────────────────────────────────────
if dispatcher_rates:
    active_rates = [r for r in dispatcher_rates if r.get("recv_per_sec", 0) > 0]
    print(f"\n=== DISPATCHER RATE SNAPSHOTS ({len(active_rates)} active of {len(dispatcher_rates)} total) ===")
    print(f"  {'time':<25} {'recv/s':>8} {'routed/s':>10} {'drop_total':>12} {'inflight_tot':>13} {'inf_min':>8} {'inf_max':>8}")
    for r in active_rates:
        print(f"  {r.get('dt',''):<25}"
              f" {r.get('recv_per_sec',0):>8}"
              f" {r.get('routed_per_sec',0):>10}"
              f" {r.get('drop_total',0):>12}"
              f" {r.get('inflight_total',0):>13}"
              f" {r.get('inflight_min',0):>8}"
              f" {r.get('inflight_max',0):>8}")

# ── WORKER RECVQ STATS ───────────────────────────────────────────────
if recvq_stats:
    max_depth    = max(int(r.get("recvq_depth",    0)) for r in recvq_stats)
    max_dropped  = max(int(r.get("recvq_dropped",  0)) for r in recvq_stats)
    max_recv     = max(int(r.get("recv_total",     0)) for r in recvq_stats)
    max_dispatch = max(int(r.get("dispatch_total", 0)) for r in recvq_stats)
    print(f"\n=== WORKER RECVQ STATS (peak across all workers, {len(recvq_stats):,} snapshots) ===")
    print(f"  max recvq_depth     : {max_depth:>10,}")
    print(f"  max recv_total      : {max_recv:>10,}")
    print(f"  max dispatch_total  : {max_dispatch:>10,}")
    print(f"  max recvq_dropped   : {max_dropped:>10,}")

# ── DISPATCH SLOW ───────────────────────────────────────────────────
if dispatch_slow_ms:
    dispatch_slow_ms.sort()
    n = len(dispatch_slow_ms)
    total_dispatched = counts.get("invite_sent", 1)
    print(f"\n=== DISPATCH SLOW >50ms ({n:,} / {total_dispatched:,} = {n/total_dispatched*100:.2f}%) ===")
    print(f"  min   : {dispatch_slow_ms[0]:>8} ms")
    print(f"  median: {dispatch_slow_ms[n//2]:>8} ms")
    print(f"  p95   : {dispatch_slow_ms[int(n*0.95)]:>8} ms")
    print(f"  max   : {dispatch_slow_ms[-1]:>8} ms")

# ── WORKER HEALTH ───────────────────────────────────────────────────
if worker_health:
    max_active = max(int(r.get("active_calls", 0)) for r in worker_health)
    avg_active = sum(int(r.get("active_calls", 0)) for r in worker_health) / len(worker_health)
    print(f"\n=== WORKER HEALTH ({len(worker_health):,} snapshots) ===")
    print(f"  max active_calls (any worker): {max_active:>6}")
    print(f"  avg active_calls              : {avg_active:>6.1f}")

# ── ACTIVE WORKERS ──────────────────────────────────────────────────
print(f"\n=== ACTIVE WORKERS ({len(workers):,} total) ===")
if workers:
    vals = sorted(workers.values())
    n    = len(vals)
    print(f"  min calls/worker: {vals[0]:>6,}")
    print(f"  med calls/worker: {vals[n//2]:>6,}")
    print(f"  max calls/worker: {vals[-1]:>6,}")
    print(f"  top 10:")
    for w, c in workers.most_common(10):
        print(f"    {w:<12}: {c:>6,}")

# ── ERRORS / CRASHES ────────────────────────────────────────────────
crash_evs = ["worker_crash", "worker_dead", "worker_restarted",
             "circuit_breaker_open", "sip_stack_init_failed"]
crash_found = False
for ev in crash_evs:
    if counts[ev]:
        if not crash_found:
            print("\n=== ERRORS / CRASHES ===")
            crash_found = True
        print(f"  {ev:<35}: {counts[ev]:>8,}")

# ── ALL EVENTS ──────────────────────────────────────────────────────
print(f"\n=== ALL EVENTS (by count, parse_errors={parse_errors:,}) ===")
for ev, n in counts.most_common():
    print(f"  {ev:<40}: {n:>10,}")
