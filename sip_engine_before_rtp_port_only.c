/*
 * Version: 2.0.9
 * sip_engine.c — Slab pool, async dispatch, PJSIP callbacks, outcome classification with high-fidelity leg tracing
 * Incorporates dynamic port hunting to resolve and prevent EADDRINUSE startup collisions.
 */
#include <pjsua-lib/pjsua.h>
#include <pjsip/sip_util.h>
#include <pjsip-ua/sip_100rel.h>
#include <pjsip/sip_module.h>
#include <pj/ioqueue.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <stdatomic.h>
#include <arpa/inet.h>
#include <errno.h>
#include "obd.h"

#define SLAB_EXTRA 64

/* ================================================================== */
/* CallCtxEx — per-call context (slab-allocated)                       */
/* ================================================================== */
typedef struct CallCtxEx {
    struct CallCtxEx *next_free;     /* slab free-list link */
    OBDRequest       req;
    pjsua_call_id    call_id;
    pjsua_acc_id     acc_id;
    pj_timer_entry   timer;
    pj_bool_t        early_progress;
    pj_bool_t        ringing;
    pj_bool_t        prack_sent;
    pj_bool_t        cancel_sent;
    pj_bool_t        ack_sent;
    pj_bool_t        done;
    pj_bool_t        prack_pending;   /* a reliable provisional is unacknowledged */
    pj_bool_t        cancel_after_prack; /* send CANCEL as soon as pending PRACK completes */
    int              last_rseq;       /* RSeq of last reliable provisional received */
    int              final_sip_status;  /* authoritative final status from INVITE tsx */
    struct timespec   start_time;
    _Atomic int       active;
} CallCtxEx;

/* ================================================================== */
/* Slab pool (OPT1) — lock-free CAS free-list                         */
/* ================================================================== */
static CallCtxEx *g_slab_pool;
static _Atomic(CallCtxEx *) g_slab_free;
static int g_slab_size;
static _Atomic int g_active_calls = 0;

static void slab_init(void)
{
    g_slab_size = OBD_CALLS_PER_WORKER + SLAB_EXTRA;
    g_slab_pool = calloc(g_slab_size, sizeof(CallCtxEx));

    /* Build free-list */
    for (int i = 0; i < g_slab_size - 1; i++)
        g_slab_pool[i].next_free = &g_slab_pool[i + 1];
    g_slab_pool[g_slab_size - 1].next_free = NULL;
    atomic_store(&g_slab_free, &g_slab_pool[0]);
}

static CallCtxEx *slab_alloc(void)
{
    CallCtxEx *head;
    do {
        head = atomic_load(&g_slab_free);
        if (!head) return NULL;
    } while (!atomic_compare_exchange_weak(&g_slab_free, &head, head->next_free));
    memset(head, 0, sizeof(*head));
    atomic_store(&head->active, 1);
    atomic_fetch_add(&g_active_calls, 1);
    return head;
}

static void slab_free(CallCtxEx *ctx)
{
    atomic_store(&ctx->active, 0);
    CallCtxEx *head;
    do {
        head = atomic_load(&g_slab_free);
        ctx->next_free = head;
    } while (!atomic_compare_exchange_weak(&g_slab_free, &head, ctx));
}

/* ================================================================== */
/* Globals                                                              */
/* ================================================================== */
static LFQueue *g_compq;
static WorkerConfig g_wcfg;
static char g_tag[16];
static void (*g_signal_report_fn)(void) = NULL;  /* callback to wake report thread */

static int sip_mux_enabled(void)
{
    return worker_cfg_use_mux(&g_wcfg);
}

static void on_timeout(pj_timer_heap_t *ht, pj_timer_entry *entry);

int sip_engine_get_active_calls(void)
{
    return atomic_load(&g_active_calls);
}

static const char *pj_status_text(pj_status_t status, char *buf, pj_size_t sz)
{
    if (!buf || sz == 0) return "";
    pj_strerror(status, buf, sz);
    buf[sz - 1] = '\0';
    return buf;
}

static void log_sip_init_failure(const char *stage, const WorkerConfig *cfg, pj_status_t status)
{
    char errbuf[128];
    /* Derive native OS error if status is in the PJ_ERRNO_START_USER range (120000 on POSIX) */
    int native_os_err = (status >= 120000) ? (status - 120000) : (int)status;

    LOG(g_tag, "", "sip_stack_init_failed",
        ",\"stage\":\"%s\",\"sip_port\":%d,\"heartbeat_port\":%d,\"bind_ip\":\"%s\",\"status\":%d,\"native_os_err\":%d,\"reason\":\"%s\",\"sys_errno\":%d,\"sys_err_str\":\"%s\"",
        stage, cfg->sip_port, cfg->heartbeat_port,
        cfg->local_ip[0] ? cfg->local_ip : "0.0.0.0",
        status, native_os_err, pj_status_text(status, errbuf, sizeof(errbuf)),
        errno, strerror(errno));
}

static void ensure_proxy_route_header(pjsip_tx_data *tdata)
{
    pj_str_t route_name = pj_str("Route");

    if (pjsip_msg_find_hdr_by_name(tdata->msg, &route_name, NULL))
        return;

    char route_buf[256];
    snprintf(route_buf, sizeof(route_buf), "<sip:%s:%d;transport=udp;lr>",
             g_wcfg.default_proxy, g_wcfg.proxy_port);
    pj_str_t route_val = pj_str(route_buf);
    pjsip_generic_string_hdr *h =
        pjsip_generic_string_hdr_create(tdata->pool, &route_name, &route_val);
    pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr *)h);
}

static void force_proxy_transport_target(pjsip_tx_data *tdata)
{
    if (!g_wcfg.default_proxy[0] || g_wcfg.proxy_port <= 0)
        return;

    char target_buf[320];
    if (strchr(g_wcfg.default_proxy, ':') && g_wcfg.default_proxy[0] != '[') {
        snprintf(target_buf, sizeof(target_buf), "[%s]:%d",
                 g_wcfg.default_proxy, g_wcfg.proxy_port);
    } else {
        snprintf(target_buf, sizeof(target_buf), "%s:%d",
                 g_wcfg.default_proxy, g_wcfg.proxy_port);
    }

    pj_str_t target = pj_str(target_buf);
    if (pj_sockaddr_parse(pj_AF_UNSPEC(), 0, &target, &tdata->tp_info.dst_addr) != PJ_SUCCESS)
        return;

    tdata->tp_info.dst_addr_len = pj_sockaddr_get_len(&tdata->tp_info.dst_addr);
    tdata->tp_info.dst_port = g_wcfg.proxy_port;
    snprintf(tdata->tp_info.dst_name, sizeof(tdata->tp_info.dst_name), "%s",
             g_wcfg.default_proxy);
}

/* ================================================================== */
/* Header override module                                               */
/* ================================================================== */
static pj_bool_t on_tx_request(pjsip_tx_data *tdata)
{
    /* When MUX is enabled, rewrite Via sent-by port so carrier responses
     * come back to the configured shared listener instead of the worker port. */
    pjsip_via_hdr *via = (pjsip_via_hdr *)
        pjsip_msg_find_hdr(tdata->msg, PJSIP_H_VIA, NULL);
    if (via && sip_mux_enabled())
        via->sent_by.port = g_wcfg.sip_mux_port;

    pjsip_hdr *hdr;
    pjsip_method *method = NULL;
    if (tdata->msg->type == PJSIP_REQUEST_MSG)
        method = &tdata->msg->line.req.method;

    /* User-Agent */
    pj_str_t ua_name = pj_str("User-Agent");
    hdr = (pjsip_hdr *)pjsip_msg_find_hdr_by_name(tdata->msg, &ua_name, NULL);
    if (hdr) pj_list_erase(hdr);
    pj_str_t ua_val = pj_str("CallCollectService");
    pjsip_generic_string_hdr *ua_h = pjsip_generic_string_hdr_create(tdata->pool, &ua_name, &ua_val);
    pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr *)ua_h);

    /* Allow */
    pj_str_t allow_name = pj_str("Allow");
    hdr = (pjsip_hdr *)pjsip_msg_find_hdr_by_name(tdata->msg, &allow_name, NULL);
    if (hdr) pj_list_erase(hdr);
    pj_str_t allow_val;
    if (method && (pj_strcmp2(&method->name, "PRACK") == 0 ||
                   pj_strcmp2(&method->name, "CANCEL") == 0 ||
                   pj_strcmp2(&method->name, "ACK") == 0)) {
        allow_val = pj_str("ACK, BYE, CANCEL, INFO, INVITE, NOTIFY, OPTIONS, PRACK, REFER, REGISTER, SUBSCRIBE");
    } else {
        allow_val = pj_str("ACK, BYE, CANCEL, INFO, INVITE, MESSAGE, NOTIFY, OPTIONS, PRACK, PUBLISH, REFER, REGISTER, SUBSCRIBE, UPDATE");
    }
    pjsip_generic_string_hdr *allow_h = pjsip_generic_string_hdr_create(tdata->pool, &allow_name, &allow_val);
    pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr *)allow_h);

    /* Supported — INVITE only */
    pj_str_t sup_name = pj_str("Supported");
    if (method && pj_strcmp2(&method->name, "INVITE") == 0) {
        while ((hdr = (pjsip_hdr *)pjsip_msg_find_hdr_by_name(tdata->msg, &sup_name, NULL)))
            pj_list_erase(hdr);
        pj_str_t sup_val = pj_str("100rel, timer, replaces, norefersub, histinfo");
        pjsip_generic_string_hdr *h = pjsip_generic_string_hdr_create(tdata->pool, &sup_name, &sup_val);
        pjsip_msg_add_hdr(tdata->msg, (pjsip_hdr *)h);
    } else {
        while ((hdr = (pjsip_hdr *)pjsip_msg_find_hdr_by_name(tdata->msg, &sup_name, NULL)))
            pj_list_erase(hdr);
    }

    /* Keep in-dialog requests on the configured proxy when the far side
     * does not Record-Route and instead advertises a direct Contact port. */
    if (method &&
        (pj_strcmp2(&method->name, "PRACK") == 0 ||
         pj_strcmp2(&method->name, "CANCEL") == 0 ||
         pj_strcmp2(&method->name, "ACK") == 0 ||
         pj_strcmp2(&method->name, "BYE") == 0 ||
         pj_strcmp2(&method->name, "UPDATE") == 0 ||
         pj_strcmp2(&method->name, "INFO") == 0)) {
        ensure_proxy_route_header(tdata);
        force_proxy_transport_target(tdata);
    }

    return PJ_FALSE;
}

static pjsip_module mod_sip_handler = {
    NULL, NULL,
    { "mod-obd-handler", 15 },
    -1,
    PJSIP_MOD_PRIORITY_APPLICATION,
    NULL, NULL, NULL, NULL,
    NULL, NULL,
    &on_tx_request,
    NULL, NULL
};

/* ================================================================== */
/* find_ctx — Race-Free Dual Lookup Strategy                          */
/* ================================================================== */
static CallCtxEx *find_ctx(pjsua_call_id call_id)
{
    /* 1. Fast path: Match by call_id */
    for (int i = 0; i < g_slab_size; i++) {
        if (atomic_load(&g_slab_pool[i].active) && g_slab_pool[i].call_id == call_id)
            return &g_slab_pool[i];
    }

    /* 2. Slow/Race path: If call_id lookup fails, check if we are in the middle of
     * pjsua_call_make_call(). Retrieve call info to match by the unique acc_id. */
    if (call_id != PJSUA_INVALID_ID && pjsua_call_is_active(call_id)) {
        pjsua_call_info ci;
        if (pjsua_call_get_info(call_id, &ci) == PJ_SUCCESS) {
            for (int i = 0; i < g_slab_size; i++) {
                if (atomic_load(&g_slab_pool[i].active) && g_slab_pool[i].acc_id == ci.acc_id) {
                    /* Bind call_id now to enable fast path lookup for all future callbacks */
                    g_slab_pool[i].call_id = call_id;
                    return &g_slab_pool[i];
                }
            }
        }
    }

    LOG("sip_engine", "", "call_ctx_missing", ",\"call_id\":%d", call_id);
    return NULL;
}

/* ================================================================== */
/* Outcome classification                                               */
/* ================================================================== */
static CallOutcome classify_outcome(CallCtxEx *ctx, int sip_status)
{
    /* CANCEL-driven outcomes — ordered: 180 ringing takes priority over 183 */
    if (ctx->cancel_sent && ctx->ringing && sip_status == 487)
        return OUTCOME_MISSED_CALL;   	/* 180 seen, CANCEL sent → SUCCESS */
    if (ctx->cancel_sent && ctx->early_progress && sip_status == 487)
        return OUTCOME_NO_ANSWER;     	/* 183 only, CANCEL sent → SUCCESS */
    if (ctx->cancel_sent && !ctx->early_progress && sip_status == 487)
        return OUTCOME_UNREACHABLE;   	/* CANCEL before any progress → NOT_REACHABLE */

    /* Network-driven final responses */
    if (sip_status == 200)
        return OUTCOME_CF_MCA;        	/* answered by MCA → SUCCESS */
    if (sip_status == 181 || sip_status == 302)
        return OUTCOME_CF_NUMBER;     	/* forwarded → FAILED */
    if (sip_status == 486 || sip_status == 600)
        return OUTCOME_BUSY;          	/* busy → FAILED */
    if (sip_status == 603)
        return OUTCOME_REJECTED;      	/* declined → FAILED */
    if (sip_status == 480 || sip_status == 404 || sip_status == 410)
        return OUTCOME_UNAVAILABLE;   	/* not found/unavailable → NOT_REACHABLE */
    if (sip_status == 408 && ctx->early_progress)
        return OUTCOME_NO_ANSWER;     	/* timeout after progress → SUCCESS */
    if (sip_status == 408 || sip_status == 487)
        return OUTCOME_UNREACHABLE;   	/* timeout/cancel no progress → NOT_REACHABLE */
    if (sip_status == 503 || sip_status == 504 || sip_status == 502)
        return OUTCOME_NETWORK_DOWN;  	/* network error → NOT_REACHABLE */
    if (sip_status >= 400 && sip_status < 500)
        return OUTCOME_UNAVAILABLE;   	/* other 4xx → NOT_REACHABLE */
    if (sip_status >= 500)
        return OUTCOME_NETWORK_DOWN;  	/* other 5xx/6xx → NOT_REACHABLE */
    return OUTCOME_UNKNOWN;
}

/* ================================================================== */
/* finish_call — push report to LFQueue, free slab                     */
/* ================================================================== */
static void finish_call(CallCtxEx *ctx, int sip_status)
{
    if (ctx->done) return;
    ctx->done = PJ_TRUE;

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    int duration_ms = (int)((now.tv_sec - ctx->start_time.tv_sec) * 1000 +
                            (now.tv_nsec - ctx->start_time.tv_nsec) / 1000000);

    OBDReport report;
    memset(&report, 0, sizeof(report));
    strncpy(report.calling_msisdn, ctx->req.calling_msisdn, sizeof(report.calling_msisdn) - 1);
    strncpy(report.called_msisdn, ctx->req.called_msisdn, sizeof(report.called_msisdn) - 1);
    strncpy(report.request_id, ctx->req.request_id, sizeof(report.request_id) - 1);
    report.outcome = classify_outcome(ctx, sip_status);
    report.sip_final_status = sip_status;
    report.duration_ms = duration_ms;

    lfq_push(g_compq, &report);
    if (g_signal_report_fn) g_signal_report_fn();

    /* Leg Teardown Complete Diagnostic Log */
    LOG(g_tag, ctx->req.request_id, "leg_teardown_complete",
        ",\"call_id\":%d,\"sip_status\":%d,\"duration_ms\":%d,\"outcome\":\"%s\"",
        ctx->call_id, sip_status, duration_ms, outcome_str(report.outcome));

    /* Delete per-call account */
    if (ctx->acc_id != PJSUA_INVALID_ID) {
        pjsua_acc_del(ctx->acc_id);
        LOG(g_tag, ctx->req.request_id, "acc_del", ",\"acc_id\":%d", ctx->acc_id);
        ctx->acc_id = PJSUA_INVALID_ID;
    }

    int active_after = atomic_fetch_sub(&g_active_calls, 1) - 1;
    if (active_after < 0) {
        LOG(g_tag, ctx->req.request_id, "active_calls_underflow",
            ",\"active_calls_after\":%d", active_after);
    }
    LOG(g_tag, ctx->req.request_id, "slab_free", ",\"active_calls\":%d", active_after);
    slab_free(ctx);
}

static void arm_progress_cancel_timer(CallCtxEx *ctx)
{
    pj_timer_heap_t *th = pjsip_endpt_get_timer_heap(pjsua_get_pjsip_endpt());
    pj_time_val delay = { g_wcfg.cancel_ring_ms / 1000,
                          (g_wcfg.cancel_ring_ms % 1000) * 1000 };

    pj_timer_heap_cancel(th, &ctx->timer);
    pj_timer_entry_init(&ctx->timer, 1, ctx, &on_timeout);
    pj_timer_heap_schedule(th, &ctx->timer, &delay);
}

/* ================================================================== */
/* Timeout callback                                                     */
/* ================================================================== */
static void on_timeout(pj_timer_heap_t *ht, pj_timer_entry *entry)
{
    (void)ht;
    CallCtxEx *ctx = (CallCtxEx *)entry->user_data;
    if (!ctx || !atomic_load(&ctx->active)) return;

    if (entry->id == 1) {
        /* Fallback timer — fires if 180 never arrives after 183.
         * If a PRACK is still outstanding, defer: set cancel_after_prack
         * so CANCEL fires as soon as PRACK completes. */
        if (!ctx->cancel_sent) {
            if (ctx->prack_pending) {
                ctx->cancel_after_prack = PJ_TRUE;
                LOG(g_tag, ctx->req.request_id, "leg_teardown_deferred",
                    ",\"call_id\":%d,\"trigger\":\"timer_prack_still_pending\"", ctx->call_id);
            } else {
                ctx->cancel_sent = PJ_TRUE;
                LOG(g_tag, ctx->req.request_id, "leg_teardown_initiating",
                    ",\"call_id\":%d,\"trigger\":\"progress_timeout_no_180\"", ctx->call_id);
                if (ctx->call_id != PJSUA_INVALID_ID)
                    pjsua_call_hangup(ctx->call_id, 0, NULL, NULL);
            }
        }
        return;
    }

    /* Main timeout (id=0) — no useful provisional progress received at all */
    ctx->cancel_sent = PJ_TRUE;
    LOG(g_tag, ctx->req.request_id, "leg_teardown_initiating", 
        ",\"call_id\":%d,\"trigger\":\"main_timeout_no_18x_progress\"", ctx->call_id);
    if (ctx->call_id != PJSUA_INVALID_ID)
        pjsua_call_hangup(ctx->call_id, 0, NULL, NULL);
}

/* ================================================================== */
/* on_call_state — High-Fidelity Call Leg Tracing                     */
/* ================================================================== */
static void on_call_state(pjsua_call_id call_id, pjsip_event *e)
{
    (void)e;
    pjsua_call_info ci;
    pjsua_call_get_info(call_id, &ci);
    CallCtxEx *ctx = find_ctx(call_id);
    if (!ctx) return;

    /* Structured JSON Tracing on INVITE Session States */
    switch (ci.state) {
        case PJSIP_INV_STATE_CALLING:
            LOG(g_tag, ctx->req.request_id, "leg_invite_sent",
                ",\"call_id\":%d,\"sip_status\":%d,\"dest\":\"%s\"", 
                call_id, ci.last_status, ctx->req.called_msisdn);
            break;

        case PJSIP_INV_STATE_EARLY:
            if (ci.last_status == 180) {
                ctx->early_progress     = PJ_TRUE;
                ctx->ringing            = PJ_TRUE;
                ctx->prack_pending      = PJ_TRUE;
                ctx->cancel_after_prack = PJ_TRUE;  /* CANCEL immediately after 200 PRACK */
                /* cancel any 183 timer still running — 180 supersedes it */
                pj_timer_heap_t *th180 = pjsip_endpt_get_timer_heap(pjsua_get_pjsip_endpt());
                pj_timer_heap_cancel(th180, &ctx->timer);
                LOG(g_tag, ctx->req.request_id, "leg_ringing_180",
                    ",\"call_id\":%d,\"role\":\"UAC\"", call_id);
            } else if (ci.last_status == 183) {
                ctx->early_progress = PJ_TRUE;
                ctx->prack_pending  = PJ_TRUE;
                /* Do NOT arm timer here — timer starts after 200 PRACK is received.
                 * Arm a safety watchdog only in case 200 PRACK never arrives. */
                arm_progress_cancel_timer(ctx);
                LOG(g_tag, ctx->req.request_id, "leg_early_media_183",
                    ",\"call_id\":%d,\"handling\":\"awaiting_prack_then_timer\"", call_id);
            } else {
                LOG(g_tag, ctx->req.request_id, "leg_state_change",
                    ",\"call_id\":%d,\"state\":%d,\"state_name\":\"EARLY\",\"sip_status\":%d",
                    call_id, ci.state, ci.last_status);
            }
            break;

        case PJSIP_INV_STATE_CONNECTING:
            LOG(g_tag, ctx->req.request_id, "leg_connecting_200ok",
                ",\"call_id\":%d,\"sip_status\":%d", call_id, ci.last_status);
            pj_timer_heap_t *th = pjsip_endpt_get_timer_heap(pjsua_get_pjsip_endpt());
            pj_timer_heap_cancel(th, &ctx->timer);
            break;

        case PJSIP_INV_STATE_CONFIRMED:
            ctx->ack_sent = PJ_TRUE;
            LOG(g_tag, ctx->req.request_id, "leg_established_ack",
                ",\"call_id\":%d", call_id);
            LOG(g_tag, ctx->req.request_id, "leg_teardown_initiating", 
                ",\"call_id\":%d,\"trigger\":\"mca_answered_hangup\"", call_id);
            pjsua_call_hangup(call_id, 0, NULL, NULL);
            break;

        case PJSIP_INV_STATE_DISCONNECTED: {
            pj_timer_heap_t *th_disc = pjsip_endpt_get_timer_heap(pjsua_get_pjsip_endpt());
            pj_timer_heap_cancel(th_disc, &ctx->timer);
            /* If CANCEL is in flight and we don't have the authoritative INVITE
             * final status yet, defer finish_call — it will fire from
             * on_call_tsx_state when the 487 INVITE tsx completes. */
            if (ctx->cancel_sent && !ctx->final_sip_status) {
                LOG(g_tag, ctx->req.request_id, "leg_state_change",
                    ",\"call_id\":%d,\"state_name\":\"DISCONNECTED\",\"action\":\"deferred_awaiting_487\"",
                    call_id);
                break;
            }
            int status = ctx->final_sip_status ? ctx->final_sip_status : ci.last_status;
            LOG(g_tag, ctx->req.request_id, "leg_state_change",
                ",\"call_id\":%d,\"state\":%d,\"state_name\":\"DISCONNECTED\",\"sip_status\":%d,\"reason\":\"%.*s\"",
                call_id, ci.state, status,
                (int)ci.last_status_text.slen, ci.last_status_text.ptr);
            finish_call(ctx, status);
            break;
        }

        default:
            LOG(g_tag, ctx->req.request_id, "leg_state_change",
                ",\"call_id\":%d,\"state\":%d,\"state_name\":\"UNKNOWN\",\"sip_status\":%d", 
                call_id, ci.state, ci.last_status);
            break;
    }
}

/* ================================================================== */
/* on_call_tsx_state — High-Fidelity Leg Transaction Handshakes       */
/* ================================================================== */
static void on_call_tsx_state(pjsua_call_id call_id, pjsip_transaction *tsx, pjsip_event *e)
{
    (void)e;
    if (!tsx) return;
    CallCtxEx *ctx = find_ctx(call_id);
    if (!ctx) return;

    /* Trace transient SIP transaction events (PRACK, CANCEL, BYE) */
    LOG(g_tag, ctx->req.request_id, "leg_tsx_update",
        ",\"call_id\":%d,\"method\":\"%.*s\",\"role\":\"%s\",\"status_code\":%d,\"state\":\"%s\"",
        call_id, (int)tsx->method.name.slen, tsx->method.name.ptr,
        (tsx->role == PJSIP_ROLE_UAC) ? "UAC" : "UAS",
        tsx->status_code, pjsip_tsx_state_str(tsx->state));

    /* Capture authoritative final status from INVITE transaction and
     * call finish_call here when deferred from DISCONNECTED (cancel in flight). */
    if (tsx->role == PJSIP_ROLE_UAC &&
        tsx->state == PJSIP_TSX_STATE_COMPLETED &&
        pj_strcmp2(&tsx->method.name, "INVITE") == 0 &&
        tsx->status_code >= 300)
    {
        ctx->final_sip_status = tsx->status_code;
        LOG(g_tag, ctx->req.request_id, "leg_invite_final_status",
            ",\"call_id\":%d,\"sip_status\":%d", call_id, tsx->status_code);
        /* If DISCONNECTED already fired but deferred, complete the report now */
        if (ctx->cancel_sent && !ctx->done)
            finish_call(ctx, tsx->status_code);
        return;
    }

    /* 181/302 — call forwarding */
    if (tsx->state == PJSIP_TSX_STATE_COMPLETED &&
        (tsx->status_code == 181 || tsx->status_code == 302)) {
        pj_timer_heap_t *th = pjsip_endpt_get_timer_heap(pjsua_get_pjsip_endpt());
        pj_timer_heap_cancel(th, &ctx->timer);
        LOG(g_tag, ctx->req.request_id, "leg_teardown_initiating", 
            ",\"call_id\":%d,\"trigger\":\"redirection_response\"", call_id);
        pjsua_call_hangup(call_id, 0, NULL, NULL);
        return;
    }

    /* PRACK 200 OK — clear pending flag and send CANCEL if 180 was already seen */
    if (tsx->role == PJSIP_ROLE_UAC &&
        tsx->state == PJSIP_TSX_STATE_COMPLETED &&
        tsx->status_code == 200 &&
        pj_strcmp2(&tsx->method.name, "PRACK") == 0)
    {
        ctx->prack_pending = PJ_FALSE;
        if (ctx->ringing && !ctx->cancel_sent) {
            /* 180 path: CANCEL immediately after PRACK acked regardless of any timer */
            ctx->cancel_sent = PJ_TRUE;
            pj_timer_heap_t *th = pjsip_endpt_get_timer_heap(pjsua_get_pjsip_endpt());
            pj_timer_heap_cancel(th, &ctx->timer);
            LOG(g_tag, ctx->req.request_id, "leg_teardown_initiating",
                ",\"call_id\":%d,\"trigger\":\"cancel_after_180_prack_acked\"", call_id);
            pjsua_call_hangup(call_id, 0, NULL, NULL);
        } else if (ctx->early_progress && !ctx->ringing && !ctx->cancel_sent) {
            /* 183-only path: PRACK acked, start cancel_ring_ms guard timer now */
            pj_timer_heap_t *th = pjsip_endpt_get_timer_heap(pjsua_get_pjsip_endpt());
            pj_timer_heap_cancel(th, &ctx->timer);
            arm_progress_cancel_timer(ctx);
            LOG(g_tag, ctx->req.request_id, "leg_cancel_timer_started",
                ",\"call_id\":%d,\"cancel_ring_ms\":%d", call_id, g_wcfg.cancel_ring_ms);
        }
    }
}

/* ================================================================== */
/* on_call_media_state — High-Fidelity Leg Media Negotiation Tracking */
/* ================================================================== */
static void on_call_media_state(pjsua_call_id call_id) 
{ 
    pjsua_call_info ci;
    pjsua_call_get_info(call_id, &ci);
    CallCtxEx *ctx = find_ctx(call_id);
    if (!ctx) return;

    LOG(g_tag, ctx->req.request_id, "leg_media_change",
        ",\"call_id\":%d,\"media_status\":%d,\"status_name\":\"%s\"",
        call_id, ci.media_status,
        (ci.media_status == PJSUA_CALL_MEDIA_NONE ? "NONE" :
         ci.media_status == PJSUA_CALL_MEDIA_ACTIVE ? "ACTIVE" :
         ci.media_status == PJSUA_CALL_MEDIA_LOCAL_HOLD ? "LOCAL_HOLD" : "ERROR"));
}

/* ================================================================== */
/* sip_engine_init                                                      */
/* ================================================================== */
int sip_engine_init(WorkerConfig *cfg, LFQueue *compq, void (*signal_fn)(void))
{
    memcpy(&g_wcfg, cfg, sizeof(g_wcfg));
    g_compq = compq;
    g_signal_report_fn = signal_fn;
    snprintf(g_tag, sizeof(g_tag), "w%d", cfg->worker_id);

    slab_init();

    /* Crucial Diagnostic: Dump compile-time variables upon initialization */
#ifdef PJ_IOQUEUE_MAX_HANDLERS
    int current_max_handlers = PJ_IOQUEUE_MAX_HANDLERS;
#else
    int current_max_handlers = -1;
#endif

    LOG(g_tag, "", "pjsip_compile_limits", 
        ",\"PJSUA_MAX_CALLS\":%d,\"PJSUA_MAX_ACC\":%d,\"PJ_IOQUEUE_MAX_HANDLERS\":%d", 
        PJSUA_MAX_CALLS, PJSUA_MAX_ACC, current_max_handlers);

    pj_status_t st = pjsua_create();
    if (st != PJ_SUCCESS) {
        log_sip_init_failure("pjsua_create", cfg, st);
        return -1;
    }

    pjsua_config pj_cfg;
    static char global_proxy[128];
    snprintf(global_proxy, sizeof(global_proxy), "sip:%s:%d;transport=udp;lr", cfg->default_proxy, cfg->proxy_port);
    pjsua_config_default(&pj_cfg);
    pj_cfg.outbound_proxy_cnt = 1;
    pj_cfg.outbound_proxy[0]  = pj_str(global_proxy);

    pj_cfg.cb.on_call_state       = &on_call_state;
    pj_cfg.cb.on_call_media_state = &on_call_media_state;
    pj_cfg.cb.on_call_tsx_state   = &on_call_tsx_state;
    pj_cfg.max_calls              = OBD_CALLS_PER_WORKER;
    pj_cfg.stun_srv_cnt           = 0;
    pj_cfg.user_agent             = pj_str("CallCollectService");
    pj_cfg.thread_cnt             = 1;  /* 1 SIP worker thread per process, not 2 */

    pjsua_logging_config log_cfg;
    pjsua_logging_config_default(&log_cfg);
    
    log_cfg.level         = g_wcfg.sip_log_level;   /* ← from config */
    log_cfg.console_level = g_wcfg.sip_log_level;   /* ← from config */

    pjsua_media_config med_cfg;
    pjsua_media_config_default(&med_cfg);
    med_cfg.no_vad            = PJ_TRUE;
    med_cfg.enable_ice        = PJ_FALSE;
    med_cfg.clock_rate        = 8000;
    med_cfg.audio_frame_ptime = 20;
    med_cfg.max_media_ports   = OBD_CALLS_PER_WORKER * 2 + 4;
    if (obd_flag_enabled(cfg->use_rtp, 0)) {
        med_cfg.has_ioqueue  = PJ_TRUE;   /* enable media ioqueue for RTP processing */
        med_cfg.thread_cnt   = 1;         /* media clock thread needed for RTP timing */
    } else {
        med_cfg.has_ioqueue  = PJ_FALSE;  /* no RTP processing needed */
        med_cfg.thread_cnt   = 0;         /* no media clock thread */
    }
LOG(g_tag, "", "proxy_config_check",
    ",\"proxy_ptr\":\"%p\",\"proxy_val\":\"%.*s\",\"proxy_cnt\":%d",
    (void *)pj_cfg.outbound_proxy[0].ptr,
    (int)pj_cfg.outbound_proxy[0].slen,
    pj_cfg.outbound_proxy[0].ptr,
    pj_cfg.outbound_proxy_cnt);

    st = pjsua_init(&pj_cfg, &log_cfg, &med_cfg);
    if (st != PJ_SUCCESS) {
        log_sip_init_failure("pjsua_init", cfg, st);
        pjsua_destroy();
        return -1;
    }

    /* SIP T1 tuning (OPT4) */
    pjsip_cfg()->tsx.t1 = g_wcfg.sip_t1_ms;
    pjsip_cfg()->tsx.t2 = g_wcfg.sip_t2_ms;

    /* Register header module */
    st = pjsip_endpt_register_module(pjsua_get_pjsip_endpt(), &mod_sip_handler);
    if (st != PJ_SUCCESS) {
        log_sip_init_failure("pjsip_endpt_register_module", cfg, st);
        pjsua_destroy();
        return -1;
    }

    /* Transport with dynamic port fallback / auto-hunting (OPT6-ext) */
    pjsua_transport_config tp_cfg;
    pjsua_transport_config_default(&tp_cfg);
    
    int base_port = cfg->sip_port;
    int max_attempts = 100; /* Try up to 100 alternative ports in case of port allocation conflicts */
    st = PJ_SUCCESS;

    for (int attempt = 0; attempt < max_attempts; attempt++) {
        tp_cfg.port = base_port + attempt;
        if (cfg->local_ip[0]) {
            tp_cfg.bound_addr  = pj_str(cfg->local_ip);
            tp_cfg.public_addr = pj_str(cfg->local_ip);
        }

        st = pjsua_transport_create(PJSIP_TRANSPORT_UDP, &tp_cfg, NULL);
        if (st == PJ_SUCCESS) {
            /* Successfully bound! Update the config so our Contact / Via headers align correctly */
            cfg->sip_port = tp_cfg.port;
            g_wcfg.sip_port = tp_cfg.port;
            LOG(g_tag, "", "sip_port_bound_success", 
                ",\"target_port\":%d,\"actual_bound_port\":%d,\"advertised_port\":%d,\"attempts\":%d,\"use_mux\":\"%s\"", 
                base_port, cfg->sip_port,
                sip_mux_enabled() ? g_wcfg.sip_mux_port : cfg->sip_port,
                attempt + 1, sip_mux_enabled() ? "yes" : "no");
            break;
        }

        /* If the error is not 'Address already in use' (120098), fail immediately */
        int os_err = (st >= 120000) ? (st - 120000) : (int)st;
        if (os_err != EADDRINUSE) {
            break;
        }
    }

    if (st != PJ_SUCCESS) {
        log_sip_init_failure("pjsua_transport_create", cfg, st);
        pjsua_destroy();
        return -1;
    }

    st = pjsua_start();
    if (st != PJ_SUCCESS) {
        log_sip_init_failure("pjsua_start", cfg, st);
        pjsua_destroy();
        return -1;
    }

    pjsua_set_null_snd_dev();

    /* Codecs: PCMU + telephone-event only */
    pj_str_t all_c = pj_str("*");
    pj_str_t pcmu_c = pj_str("PCMU/8000");
    pj_str_t te_c = pj_str("telephone-event/8000");
    pjsua_codec_set_priority(&all_c, 0);
    pjsua_codec_set_priority(&pcmu_c, 255);
    pjsua_codec_set_priority(&te_c, 254);

    return 0;
}

/* ================================================================== */
/* sip_engine_dispatch — non-blocking call initiation                   */
/* ================================================================== */
void sip_engine_dispatch(const OBDRequest *req)
{
    CallCtxEx *ctx = slab_alloc();
    if (!ctx) {
        LOG(g_tag, req->request_id, "slab_alloc_failed", ",\"active_calls\":%d,\"max_calls\":%d", atomic_load(&g_active_calls), OBD_CALLS_PER_WORKER);
        /* All slots busy — push reject report */
        OBDReport report;
        memset(&report, 0, sizeof(report));
        strncpy(report.request_id, req->request_id, sizeof(report.request_id) - 1);
        strncpy(report.called_msisdn, req->called_msisdn, sizeof(report.called_msisdn) - 1);
        strncpy(report.calling_msisdn, req->calling_msisdn, sizeof(report.calling_msisdn) - 1);
        report.outcome = OUTCOME_NETWORK_DOWN;
        report.sip_final_status = 503;
        lfq_push(g_compq, &report);
        return;
    }

    memcpy(&ctx->req, req, sizeof(OBDRequest));
    ctx->call_id = PJSUA_INVALID_ID;
    ctx->acc_id  = PJSUA_INVALID_ID;
    clock_gettime(CLOCK_MONOTONIC, &ctx->start_time);
    
    /* Leg Creation Stage 1: Leg Allocated */
    LOG(g_tag, ctx->req.request_id, "leg_allocated", ",\"active_calls\":%d", atomic_load(&g_active_calls));

    /* Determine dest */
    const char *dest = req->dest_id[0] ? req->dest_id : g_wcfg.default_proxy;

    /* Build target URI */
    char target_uri[256];
    const char *num = req->called_msisdn;
    if (num[0] == '+') num++;
    snprintf(target_uri, sizeof(target_uri), "<sip:%s@%s;user=phone>", num, dest);
    pj_str_t dst = pj_str(target_uri);

    /* Per-call account */
    pjsua_acc_config acc_cfg;
    pjsua_acc_config_default(&acc_cfg);
    char from_uri[256];
    snprintf(from_uri, sizeof(from_uri), "\"+%s\" <sip:+%s@%s;user=phone>",
             req->calling_msisdn, req->calling_msisdn,
             g_wcfg.local_ip[0] ? g_wcfg.local_ip : dest);
    char contact_uri[256];
    acc_cfg.id                  = pj_str(from_uri);
    acc_cfg.reg_uri             = pj_str("");
    acc_cfg.register_on_acc_add = PJ_FALSE;
    acc_cfg.cred_count          = 0;
    acc_cfg.require_100rel      = (strcasecmp(g_wcfg.require_100rel, "no") == 0) ?
                                   PJSUA_100REL_OPTIONAL : PJSUA_100REL_MANDATORY;

    if (sip_mux_enabled()) {
        snprintf(contact_uri, sizeof(contact_uri), "<sip:CallCollectService@%s:%d>",
                 g_wcfg.local_ip[0] ? g_wcfg.local_ip : "127.0.0.1", g_wcfg.sip_mux_port);
        acc_cfg.force_contact = pj_str(contact_uri);
    } else if (g_wcfg.local_ip[0]) {
        snprintf(contact_uri, sizeof(contact_uri), "<sip:CallCollectService@%s:%d>",
                 g_wcfg.local_ip, g_wcfg.sip_port);
        acc_cfg.force_contact = pj_str(contact_uri);
    }

    /* RTP port: use config base + per-worker offset to avoid collisions */
    if (obd_flag_enabled(g_wcfg.use_rtp, 0)) {
        acc_cfg.rtp_cfg.port       = g_wcfg.rtp_base_port + (g_wcfg.worker_id * 2);
        acc_cfg.rtp_cfg.port_range = 1;
    } else {
        acc_cfg.rtp_cfg.port       = 20000 + (g_wcfg.worker_id * 2); /* bind for SDP only */
        acc_cfg.rtp_cfg.port_range = 1;
    }
    acc_cfg.media_stun_use     = PJSUA_STUN_USE_DISABLED;
    acc_cfg.call_hold_type     = PJSUA_CALL_HOLD_TYPE_RFC3264;

    pj_status_t st = pjsua_acc_add(&acc_cfg, PJ_FALSE, &ctx->acc_id);
    if (st == PJ_SUCCESS) {
        /* Leg Creation Stage 2: Account Registered */
        LOG(g_tag, ctx->req.request_id, "leg_acc_added", ",\"acc_id\":%d", ctx->acc_id);
    } else {
        char errbuf[128];
        int active_calls = atomic_load(&g_active_calls);
        OBDReport report;
        memset(&report, 0, sizeof(report));
        strncpy(report.request_id, req->request_id, sizeof(report.request_id) - 1);
        strncpy(report.called_msisdn, req->called_msisdn, sizeof(report.called_msisdn) - 1);
        strncpy(report.calling_msisdn, req->calling_msisdn, sizeof(report.calling_msisdn) - 1);
        report.outcome = OUTCOME_NETWORK_DOWN;
        report.sip_final_status = 503;
        lfq_push(g_compq, &report);
        
        /* Critical failure log when PJSIP Account capacity limit is reached */
        LOG(g_tag, req->request_id, "leg_acc_add_failed",
            ",\"status\":%d,\"reason\":\"%s\",\"active_calls\":%d,\"max_acc_limit\":%d",
            st, pj_status_text(st, errbuf, sizeof(errbuf)), active_calls, PJSUA_MAX_ACC);
            
        slab_free(ctx);
        return;
    }

    /* Extra headers */
    pjsua_msg_data msg_data;
    pjsua_msg_data_init(&msg_data);

    char pai_val[256];
    snprintf(pai_val, sizeof(pai_val), "<sip:%s@%s;user=phone>", req->calling_msisdn, dest);
    pj_str_t pai_hn = pj_str("P-Asserted-Identity");
    pj_str_t pai_hv = pj_str(pai_val);
    pjsip_generic_string_hdr pai_hdr;
    pjsip_generic_string_hdr_init2(&pai_hdr, &pai_hn, &pai_hv);
    pj_list_push_back(&msg_data.hdr_list, &pai_hdr);

    pj_str_t pem_hn = pj_str("P-Early-Media");
    pj_str_t pem_hv = pj_str("Supported");
    pjsip_generic_string_hdr pem_hdr;
    pjsip_generic_string_hdr_init2(&pem_hdr, &pem_hn, &pem_hv);
    pj_list_push_back(&msg_data.hdr_list, &pem_hdr);

    /* Route is already injected via pj_cfg.outbound_proxy — no manual Route needed */

    pjsua_call_setting call_opt;
    pjsua_call_setting_default(&call_opt);
    call_opt.aud_cnt = 1;
    call_opt.vid_cnt = 0;
    if (obd_flag_enabled(g_wcfg.use_rtp, 0)) {
        /* use_rtp=yes: sendrecv — RTP flows in both directions */
        call_opt.flag |= PJSUA_CALL_SET_MEDIA_DIR;
        call_opt.media_dir[0] = PJMEDIA_DIR_ENCODING_DECODING;
    } else {
        /* use_rtp=no: inactive — SDP negotiated but no RTP packets sent/received */
        call_opt.flag |= PJSUA_CALL_SET_MEDIA_DIR;
        call_opt.media_dir[0] = PJMEDIA_DIR_NONE;
    }

    int active_calls = atomic_load(&g_active_calls);
    if (active_calls >= OBD_CALLS_PER_WORKER) {
        OBDReport report;
        memset(&report, 0, sizeof(report));
        strncpy(report.request_id, req->request_id, sizeof(report.request_id) - 1);
        strncpy(report.called_msisdn, req->called_msisdn, sizeof(report.called_msisdn) - 1);
        strncpy(report.calling_msisdn, req->calling_msisdn, sizeof(report.calling_msisdn) - 1);
        report.outcome = OUTCOME_NETWORK_DOWN;
        report.sip_final_status = 503;
        lfq_push(g_compq, &report);
        LOG(g_tag, req->request_id, "local_capacity_reached",
            ",\"active_calls\":%d,\"max_calls\":%d",
            active_calls, OBD_CALLS_PER_WORKER);
        pjsua_acc_del(ctx->acc_id);
        ctx->acc_id = PJSUA_INVALID_ID;
        slab_free(ctx);
        return;
    }

    /* Leg Creation Stage 3: Attempting Outbound Invite */
    LOG(g_tag, ctx->req.request_id, "leg_invite_initiating", 
        ",\"target_uri\":\"%s\",\"from_uri\":\"%s\",\"acc_id\":%d", target_uri, from_uri, ctx->acc_id);
        
    st = pjsua_call_make_call(ctx->acc_id, &dst, &call_opt, NULL, &msg_data, &ctx->call_id);
    if (st != PJ_SUCCESS) {
        char errbuf[128];
        OBDReport report;
        memset(&report, 0, sizeof(report));
        strncpy(report.request_id, req->request_id, sizeof(report.request_id) - 1);
        strncpy(report.called_msisdn, req->called_msisdn, sizeof(report.called_msisdn) - 1);
        strncpy(report.calling_msisdn, req->calling_msisdn, sizeof(report.calling_msisdn) - 1);
        report.outcome = OUTCOME_NETWORK_DOWN;
        report.sip_final_status = 503;
        lfq_push(g_compq, &report);
        
        LOG(g_tag, req->request_id, "leg_invite_failed",
            ",\"status\":%d,\"reason\":\"%s\",\"active_calls\":%d",
            st, pj_status_text(st, errbuf, sizeof(errbuf)), active_calls);
            
        pjsua_acc_del(ctx->acc_id);
        ctx->acc_id = PJSUA_INVALID_ID;
        slab_free(ctx);
        return;
    }

    /* Set transaction fallback watchdog timer */
    pj_timer_heap_t *th = pjsip_endpt_get_timer_heap(pjsua_get_pjsip_endpt());
    pj_time_val delay = { req->timeout_sec, 0 };
    pj_timer_entry_init(&ctx->timer, 0, ctx, &on_timeout);
    pj_timer_heap_schedule(th, &ctx->timer, &delay);
    
    LOG(g_tag, ctx->req.request_id, "call_make_success", ",\"call_id\":%d", ctx->call_id);
}

void sip_engine_shutdown(void)
{
    pjsua_call_hangup_all();
    pjsua_destroy();
    free(g_slab_pool);
}