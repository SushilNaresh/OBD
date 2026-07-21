#!/usr/bin/env python3
"""
OBD Traffic Summary — requests received vs sent to network.
Usage: python3 traffic.py [logfile]
"""
import json, sys, os, glob, collections
from datetime import datetime

log = sys.argv[1] if len(sys.argv) > 1 else "/var/log/obd/obd_runtime.log"
if not os.path.exists(log):
    print(f"File not found: {log}"); sys.exit(1)

# Collect rotated files oldest-first
rotated = glob.glob(log + ".*")
def rot_key(p):
    try: return int(p.rsplit(".", 1)[-1])
    except ValueError: return 0
rotated.sort(key=rot_key, reverse=True)
log_files = rotated + [log]

print(f"Reading {len(log_files)} file(s):")
for f in log_files:
    print(f"  {f}  ({os.path.getsize(f)/1024/1024:.1f} MB)")
print()

# Counters
received        = 0   # UDP requests received by dispatcher (routed + no_workers + route_failed)
routed          = 0   # dispatcher successfully sent to a worker socket
no_workers      = 0   # dispatcher: no available worker
route_failed    = 0   # dispatcher: send() to worker failed
dedup_drop      = 0   # duplicate request dropped
invite_sent     = 0   # worker received and passed to sip_engine
slab_fail       = 0   # sip_engine: no call slot
acc_pool_full   = 0   # sip_engine: PJSUA_MAX_ACC hit
acc_add_fail    = 0   # sip_engine: pjsua_acc_add failed
capacity        = 0   # sip_engine: OBD_CALLS_PER_WORKER hit
invite_init     = 0   # sip_engine: about to call pjsua_call_make_call
invite_ok       = 0   # sip_engine: pjsua_call_make_call returned OK  (= on wire)
invite_fail     = 0   # sip_engine: pjsua_call_make_call failed
completed       = 0   # worker: report sent back to caller

outcomes        = collections.Counter()
sip_codes       = collections.Counter()
tsx_503         = 0
first_dt        = None
last_dt         = None
parse_errors    = 0

# Per-minute buckets for rate chart
per_minute      = collections.Counter()  # key = "HH:MM", value = routed count

for lf in log_files:
    with open(lf, errors="replace") as f:
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
            if not ev:
                continue

            if dt:
                if first_dt is None or dt < first_dt:
                    first_dt = dt
                if last_dt is None or dt > last_dt:
                    last_dt = dt

            if ev == "routed":
                routed += 1
                received += 1
                if dt and len(dt) >= 16:
                    per_minute[dt[:16]] += 1
            elif ev == "no_workers_available":
                no_workers += 1
                received += 1
            elif ev == "route_failed":
                route_failed += 1
                received += 1
            elif ev == "dedup_drop":
                dedup_drop += 1
                received += 1
            elif ev == "invite_sent":
                invite_sent += 1
            elif ev == "slab_alloc_failed":
                slab_fail += 1
            elif ev == "acc_pool_full":
                acc_pool_full += 1
            elif ev == "leg_acc_add_failed":
                acc_add_fail += 1
            elif ev == "local_capacity_reached":
                capacity += 1
            elif ev == "leg_invite_initiating":
                invite_init += 1
            elif ev == "call_make_success":
                invite_ok += 1
            elif ev == "leg_invite_failed":
                invite_fail += 1
            elif ev == "sent":
                completed += 1
                outcomes[obj.get("outcome", "?")] += 1
                sip_codes[str(obj.get("sip", "?"))] += 1
            elif ev == "leg_tsx_update":
                if obj.get("status_code") == 503:
                    tsx_503 += 1

# ── SUMMARY ─────────────────────────────────────────────────────────
print("=" * 60)
print("  TRAFFIC SUMMARY")
print("=" * 60)
print(f"  Period : {first_dt}  →  {last_dt}")
print()

print("── INBOUND (requests into OBD) ─────────────────────────────")
print(f"  Total received by dispatcher : {received:>10,}")
print(f"    Routed to a worker         : {routed:>10,}  ({routed/received*100:.1f}% of received)" if received else "")
print(f"    No workers available       : {no_workers:>10,}")
print(f"    Route failed (send error)  : {route_failed:>10,}")
print(f"    Dedup dropped              : {dedup_drop:>10,}")
print()

print("── WORKER PROCESSING ───────────────────────────────────────")
print(f"  Received by worker           : {invite_sent:>10,}  ({invite_sent/routed*100:.1f}% of routed)" if routed else "")
worker_drop = invite_sent - invite_ok
print(f"    Slab alloc failed          : {slab_fail:>10,}")
print(f"    Acc pool full              : {acc_pool_full:>10,}")
print(f"    Acc add failed             : {acc_add_fail:>10,}")
print(f"    Local capacity reached     : {capacity:>10,}")
print(f"    pjsua_call_make_call failed: {invite_fail:>10,}")
print()

print("── NETWORK (SIP INVITEs sent to carrier) ───────────────────")
print(f"  INVITEs sent to network      : {invite_ok:>10,}  ({invite_ok/received*100:.1f}% of received)" if received else "")
print(f"  Completed (report sent)      : {completed:>10,}")
print(f"  503 from network (tsx)       : {tsx_503:>10,}")
print()

print("── CONVERSION FUNNEL ───────────────────────────────────────")
stages = [
    ("Received by dispatcher", received),
    ("Routed to worker",       routed),
    ("Worker received",        invite_sent),
    ("INVITE on wire",         invite_ok),
    ("Completed",              completed),
]
base = received if received else 1
for label, n in stages:
    bar = "#" * int(n / base * 40)
    print(f"  {label:<28}: {n:>8,}  {n/base*100:5.1f}%  |{bar}")
print()

print("── CALL OUTCOMES ───────────────────────────────────────────")
total_out = sum(outcomes.values())
for o, n in outcomes.most_common():
    print(f"  {o:<30}: {n:>8,}  ({n/total_out*100:.1f}%)" if total_out else "")
print()

print("── SIP FINAL STATUS CODES ──────────────────────────────────")
for code, n in sip_codes.most_common():
    print(f"  {code:<10}: {n:>8,}")
print()

# ── PER-MINUTE RATE ─────────────────────────────────────────────────
if per_minute:
    print("── REQUESTS PER MINUTE (routed) ────────────────────────────")
    peak = max(per_minute.values())
    for minute in sorted(per_minute):
        n = per_minute[minute]
        bar = "#" * int(n / peak * 30)
        print(f"  {minute}  {n:>6,}/min  |{bar}")
    print()

print(f"  (parse_errors={parse_errors:,} — non-JSON lines, usually PJSIP internal logs)")
