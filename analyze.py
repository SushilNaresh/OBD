#!/usr/bin/env python3
"""
OBD traffic analyzer — reads obd_runtime.log + all rotated backups.
Usage: python3 analyze.py [logfile] [--norot] [--total N]
  --norot    : current file only, skip rotated .1 .2 ...
  --total N  : total requests sent by sender (for receipt gap analysis)
"""
import json, collections, sys, os, glob

log      = next((a for a in sys.argv[1:] if not a.startswith("--")), "/var/log/obd/obd_runtime.log")
no_rot   = "--norot" in sys.argv
total_sent = next((int(sys.argv[i+1]) for i, a in enumerate(sys.argv) if a == "--total" and i+1 < len(sys.argv)), None)

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
            if not ev:
                continue
            counts[ev] += 1
            if ev not in first_dt:
                first_dt[ev] = dt
            last_dt[ev] = dt

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

# ── RECEIPT GAP ─────────────────────────────────────────────────────
print("=== MESSAGE RECEIPT ANALYSIS ===")
sent_by_sender  = total_sent
received_disp   = counts["received"]
routed          = counts["routed"]
received        = counts["invite_sent"]
completed       = counts["sent"]

if sent_by_sender:
    not_received = sent_by_sender - received_disp
    print(f"  Sent by load generator          : {sent_by_sender:>10,}")
    print(f"  Received at dispatcher          : {received_disp:>10,}  ({received_disp/sent_by_sender*100:.1f}% of sent)")
    print(f"  NOT received at dispatcher      : {not_received:>10,}  ({not_received/sent_by_sender*100:.1f}% lost before OBD)")
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
