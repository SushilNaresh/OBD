/*
 * sip_engine.c — Slab pool, async dispatch, PJSIP callbacks, outcome classification
 */
#include <pjsua-lib/pjsua.h>
#include <pjsip/sip_util.h>
#include <pjsip-ua/sip_100rel.h>
#include <pjsip/sip_module.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <stdatomic.h>
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
    pj_bool_t        ringing;
    pj_bool_t        prack_sent;
    pj_bool_t        cancel_sent;
    pj_bool_t        ack_sent;
    pj_bool_t        done;
    struct timespec   start_time;
    _Atomic int       active;
} CallCtxEx;

/* ================================================================== */
/* Slab pool (OPT1) — lock-free CAS free-list                         */
/* ================================================================== */
static CallCtxEx *g_slab_pool;
static _Atomic(CallCtxEx *) g_slab_free;
static int g_slab_size;

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
static _Atomic int g_active_calls = 0;
static pjsua_acc_id g_shared_acc_id = PJSUA_INVALID_ID;

/* ================================================================== */
/* Header override module                                               */
/* ================================================================== */
static pj_bool_t on_tx_request(pjsip_tx_data *tdata)
{
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

    /* Route in CANCEL */
    if (method && pj_strcmp2(&method->name, "CANCEL") == 0) {
        pj_str_t route_name = pj_str("Route");
        if (!pjsip_msg_find_hdr_by_name(tdata->msg, &route_name, NULL)) {
            /* Get dest from call context — use first slot's dest_id as fallback */
            /* For now use a generic route based on Request-URI host */
        }
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
/* Find context by call_id                                              */
/* ================================================================== */
static CallCtxEx *find_ctx(pjsua_call_id call_id)
{
    for (int i = 0; i < g_slab_size; i++) {
        if (atomic_load(&g_slab_pool[i].active) && g_slab_pool[i].call_id == call_id)
            return &g_slab_pool[i];
    }
    return NULL;
}

/* ================================================================== */
/* Outcome classification                                               */
/* ================================================================== */
static CallOutcome classify_outcome(CallCtxEx *ctx, int sip_status)
{
    if (ctx->cancel_sent && ctx->ringing && sip_status == 487)
        return OUTCOME_MISSED_CALL;
    if (ctx->cancel_sent && !ctx->ringing && sip_status == 487)
        return OUTCOME_UNREACHABLE;
    if (ctx->ringing && (sip_status == 408 || sip_status == 487))
        return OUTCOME_NO_ANSWER;
    if (sip_status == 486 || sip_status == 600)
        return OUTCOME_BUSY;
    if (sip_status == 603)
        return OUTCOME_REJECTED;
    if (sip_status == 480)
        return OUTCOME_UNAVAILABLE;
    if (sip_status == 408 && !ctx->ringing)
        return OUTCOME_UNREACHABLE;
    if (sip_status == 503 || sip_status == 504)
        return OUTCOME_NETWORK_DOWN;
    if (sip_status == 200)
        return OUTCOME_CF_MCA;
    if (sip_status == 181 || sip_status == 302)
        return OUTCOME_CF_NUMBER;
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

    LOG(g_tag, ctx->req.request_id, "call_done",
        ",\"outcome\":\"%s\",\"sip\":%d,\"ms\":%d",
        outcome_str(report.outcome), sip_status, duration_ms);

    /* Delete per-call account — no longer needed, using shared account */

    atomic_fetch_sub(&g_active_calls, 1);
    slab_free(ctx);
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
        /* Cancel-after-ring timer (500ms) — non-reliable 180, send CANCEL now */
        if (!ctx->cancel_sent) {
            ctx->cancel_sent = PJ_TRUE;
            LOG(g_tag, ctx->req.request_id, "non_reliable_180_cancel", "");
            if (ctx->call_id != PJSUA_INVALID_ID)
                pjsua_call_hangup(ctx->call_id, 0, NULL, NULL);
        }
        return;
    }

    /* Main timeout (id=0) — no 180 received at all */
    ctx->cancel_sent = PJ_TRUE;
    if (ctx->call_id != PJSUA_INVALID_ID)
        pjsua_call_hangup(ctx->call_id, 0, NULL, NULL);
}

/* ================================================================== */
/* on_call_state                                                        */
/* ================================================================== */
static void on_call_state(pjsua_call_id call_id, pjsip_event *e)
{
    (void)e;
    pjsua_call_info ci;
    pjsua_call_get_info(call_id, &ci);
    CallCtxEx *ctx = find_ctx(call_id);
    if (!ctx) return;

    /* 180 Ringing — cancel main timeout, arm short cancel timer */
    if (ci.state == PJSIP_INV_STATE_EARLY && ci.last_status == 180) {
        ctx->ringing = PJ_TRUE;
        pj_timer_heap_t *th = pjsip_endpt_get_timer_heap(pjsua_get_pjsip_endpt());
        pj_timer_heap_cancel(th, &ctx->timer);
        LOG(g_tag, ctx->req.request_id, "180_ringing", "");

        /* Arm short timer (500ms) — if PRACK 200 OK comes first, it will
           cancel this timer and send CANCEL. If timer fires, 180 was
           non-reliable so send CANCEL directly. */
        pj_time_val delay = { 0, 500 };  /* 500ms */
        pj_timer_entry_init(&ctx->timer, 1, ctx, &on_timeout);  /* id=1 means cancel-after-ring */
        pj_timer_heap_schedule(th, &ctx->timer, &delay);
    }

    /* CONNECTING — 200 OK to INVITE (CF_MCA scenario) */
    if (ci.state == PJSIP_INV_STATE_CONNECTING) {
        pj_timer_heap_t *th = pjsip_endpt_get_timer_heap(pjsua_get_pjsip_endpt());
        pj_timer_heap_cancel(th, &ctx->timer);
        /* Do NOT hangup — ACK not sent yet. Wait for CONFIRMED. */
        LOG(g_tag, ctx->req.request_id, "connecting_200ok", "");
    }

    /* CONFIRMED — ACK sent, now safe to BYE */
    if (ci.state == PJSIP_INV_STATE_CONFIRMED) {
        ctx->ack_sent = PJ_TRUE;
        LOG(g_tag, ctx->req.request_id, "confirmed_ack_bye", "");
        pjsua_call_hangup(call_id, 0, NULL, NULL);
    }

    /* DISCONNECTED — final */
    if (ci.state == PJSIP_INV_STATE_DISCONNECTED) {
        pj_timer_heap_t *th = pjsip_endpt_get_timer_heap(pjsua_get_pjsip_endpt());
        pj_timer_heap_cancel(th, &ctx->timer);
        finish_call(ctx, ci.last_status);
    }
}

/* ================================================================== */
/* on_call_tsx_state — PRACK 200 OK → CANCEL                           */
/* ================================================================== */
static void on_call_tsx_state(pjsua_call_id call_id, pjsip_transaction *tsx, pjsip_event *e)
{
    (void)e;
    if (!tsx) return;
    CallCtxEx *ctx = find_ctx(call_id);
    if (!ctx) return;

    /* 181/302 — call forwarding */
    if (tsx->state == PJSIP_TSX_STATE_COMPLETED &&
        (tsx->status_code == 181 || tsx->status_code == 302)) {
        pj_timer_heap_t *th = pjsip_endpt_get_timer_heap(pjsua_get_pjsip_endpt());
        pj_timer_heap_cancel(th, &ctx->timer);
        pjsua_call_hangup(call_id, 0, NULL, NULL);
        return;
    }

    /* PRACK 200 OK after ringing → send CANCEL */
    if (ctx->ringing && !ctx->cancel_sent &&
        tsx->role == PJSIP_ROLE_UAC &&
        tsx->state == PJSIP_TSX_STATE_COMPLETED &&
        tsx->status_code == 200 &&
        pj_strcmp2(&tsx->method.name, "PRACK") == 0)
    {
        ctx->cancel_sent = PJ_TRUE;
        /* Cancel the fallback timer */
        pj_timer_heap_t *th = pjsip_endpt_get_timer_heap(pjsua_get_pjsip_endpt());
        pj_timer_heap_cancel(th, &ctx->timer);
        LOG(g_tag, ctx->req.request_id, "prack_ok_cancel", "");
        pjsua_call_hangup(call_id, 0, NULL, NULL);
    }
}

static void on_call_media_state(pjsua_call_id call_id) { (void)call_id; }

/* ================================================================== */
/* sip_engine_init                                                      */
/* ================================================================== */
int sip_engine_init(WorkerConfig *cfg, LFQueue *compq)
{
    memcpy(&g_wcfg, cfg, sizeof(g_wcfg));
    g_compq = compq;
    snprintf(g_tag, sizeof(g_tag), "w%d", cfg->worker_id);

    slab_init();

    pj_status_t st = pjsua_create();
    if (st != PJ_SUCCESS) return -1;

    pjsua_config pj_cfg;
    pjsua_config_default(&pj_cfg);
    pj_cfg.cb.on_call_state       = &on_call_state;
    pj_cfg.cb.on_call_media_state = &on_call_media_state;
    pj_cfg.cb.on_call_tsx_state   = &on_call_tsx_state;
    pj_cfg.max_calls              = OBD_CALLS_PER_WORKER;
    pj_cfg.stun_srv_cnt           = 0;
    pj_cfg.user_agent             = pj_str("CallCollectService");

    pjsua_logging_config log_cfg;
    pjsua_logging_config_default(&log_cfg);
    log_cfg.console_level = 1;

    pjsua_media_config med_cfg;
    pjsua_media_config_default(&med_cfg);
    med_cfg.no_vad            = PJ_TRUE;
    med_cfg.enable_ice        = PJ_FALSE;
    med_cfg.has_ioqueue       = PJ_FALSE;
    med_cfg.clock_rate        = 8000;
    med_cfg.audio_frame_ptime = 20;
    med_cfg.max_media_ports   = OBD_CALLS_PER_WORKER * 2 + 4;

    st = pjsua_init(&pj_cfg, &log_cfg, &med_cfg);
    if (st != PJ_SUCCESS) { pjsua_destroy(); return -1; }

    /* SIP T1 tuning (OPT4) */
    pjsip_cfg()->tsx.t1 = OBD_SIP_T1_MS;
    pjsip_cfg()->tsx.t2 = OBD_SIP_T2_MS;

    /* Register header module */
    pjsip_endpt_register_module(pjsua_get_pjsip_endpt(), &mod_sip_handler);

    /* Transport */
    pjsua_transport_config tp_cfg;
    pjsua_transport_config_default(&tp_cfg);
    tp_cfg.port = cfg->sip_port;
    if (cfg->local_ip[0]) {
        tp_cfg.bound_addr  = pj_str(cfg->local_ip);
        tp_cfg.public_addr = pj_str(cfg->local_ip);
    }
    st = pjsua_transport_create(PJSIP_TRANSPORT_UDP, &tp_cfg, NULL);
    if (st != PJ_SUCCESS) { pjsua_destroy(); return -1; }

    st = pjsua_start();
    if (st != PJ_SUCCESS) { pjsua_destroy(); return -1; }

    pjsua_set_null_snd_dev();

    /* Codecs: PCMU + telephone-event only */
    pj_str_t all_c = pj_str("*");
    pj_str_t pcmu_c = pj_str("PCMU/8000");
    pj_str_t te_c = pj_str("telephone-event/8000");
    pjsua_codec_set_priority(&all_c, 0);
    pjsua_codec_set_priority(&pcmu_c, 255);
    pjsua_codec_set_priority(&te_c, 254);

    /* Create one shared account for all calls */
    pjsua_acc_config acc_cfg;
    pjsua_acc_config_default(&acc_cfg);
    char from_uri[256];
    snprintf(from_uri, sizeof(from_uri), "\"CallCollectService\" <sip:CallCollectService@%s;user=phone>",
             cfg->local_ip[0] ? cfg->local_ip : "127.0.0.1");
    char contact_uri[256];
    snprintf(contact_uri, sizeof(contact_uri), "<sip:CallCollectService@%s:%d>",
             cfg->local_ip[0] ? cfg->local_ip : "127.0.0.1", cfg->sip_port);
    acc_cfg.id                  = pj_str(from_uri);
    acc_cfg.force_contact       = pj_str(contact_uri);
    acc_cfg.reg_uri             = pj_str("");
    acc_cfg.register_on_acc_add = PJ_FALSE;
    acc_cfg.cred_count          = 0;
    acc_cfg.require_100rel      = (strcasecmp(g_wcfg.require_100rel, "no") == 0) ?
                                   PJSUA_100REL_OPTIONAL : PJSUA_100REL_MANDATORY;
    acc_cfg.rtp_cfg.port        = 10000 + (cfg->worker_id * 10000);

    st = pjsua_acc_add(&acc_cfg, PJ_TRUE, &g_shared_acc_id);
    if (st != PJ_SUCCESS) { pjsua_destroy(); return -1; }

    return 0;
}

/* ================================================================== */
/* sip_engine_dispatch — non-blocking call initiation                   */
/* ================================================================== */
void sip_engine_dispatch(const OBDRequest *req)
{
    CallCtxEx *ctx = slab_alloc();
    if (!ctx) {
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
    ctx->acc_id  = g_shared_acc_id;
    clock_gettime(CLOCK_MONOTONIC, &ctx->start_time);

    /* Determine dest */
    const char *dest = req->dest_id[0] ? req->dest_id : g_wcfg.default_proxy;

    /* Build target URI */
    char target_uri[256];
    const char *num = req->called_msisdn;
    if (num[0] == '+') num++;
    snprintf(target_uri, sizeof(target_uri), "<sip:%s@%s;user=phone>", num, dest);
    pj_str_t dst = pj_str(target_uri);

    /* Extra headers (including From override) */
    pjsua_msg_data msg_data;
    pjsua_msg_data_init(&msg_data);

    /* From header override */
    char from_val[256];
    snprintf(from_val, sizeof(from_val), "\"+%s\" <sip:+%s@%s;user=phone>",
             req->calling_msisdn, req->calling_msisdn,
             g_wcfg.local_ip[0] ? g_wcfg.local_ip : dest);
    pj_str_t from_hn = pj_str("From");
    pj_str_t from_hv = pj_str(from_val);
    pjsip_generic_string_hdr from_hdr;
    pjsip_generic_string_hdr_init2(&from_hdr, &from_hn, &from_hv);
    pj_list_push_back(&msg_data.hdr_list, &from_hdr);

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

    char route_val[256];
    snprintf(route_val, sizeof(route_val), "<sip:%s:5060;transport=udp;lr>", dest);
    pj_str_t route_hn = pj_str("Route");
    pj_str_t route_hv = pj_str(route_val);
    pjsip_generic_string_hdr route_hdr;
    pjsip_generic_string_hdr_init2(&route_hdr, &route_hn, &route_hv);
    pj_list_push_back(&msg_data.hdr_list, &route_hdr);

    pjsua_call_setting call_opt;
    pjsua_call_setting_default(&call_opt);
    call_opt.aud_cnt = (strcasecmp(g_wcfg.use_rtp, "no") == 0) ? 0 : 1;
    call_opt.vid_cnt = 0;

    pj_status_t st = pjsua_call_make_call(g_shared_acc_id, &dst, &call_opt, NULL, &msg_data, &ctx->call_id);
    if (st != PJ_SUCCESS) {
        /* Push failure report */
        OBDReport report;
        memset(&report, 0, sizeof(report));
        strncpy(report.request_id, req->request_id, sizeof(report.request_id) - 1);
        strncpy(report.called_msisdn, req->called_msisdn, sizeof(report.called_msisdn) - 1);
        strncpy(report.calling_msisdn, req->calling_msisdn, sizeof(report.calling_msisdn) - 1);
        report.outcome = OUTCOME_NETWORK_DOWN;
        report.sip_final_status = 503;
        lfq_push(g_compq, &report);
        LOG(g_tag, req->request_id, "make_call_failed", ",\"reason\":\"PJ_ETOOMANY\"");
        slab_free(ctx);
        return;
    }

    /* Arm timeout */
    int timeout = req->timeout_sec > 0 ? req->timeout_sec : OBD_DEFAULT_TIMEOUT;
    pj_time_val delay = { timeout, 0 };
    pj_timer_entry_init(&ctx->timer, 0, ctx, &on_timeout);
    pj_timer_heap_t *th = pjsip_endpt_get_timer_heap(pjsua_get_pjsip_endpt());
    pj_timer_heap_schedule(th, &ctx->timer, &delay);

    atomic_fetch_add(&g_active_calls, 1);
}

void sip_engine_shutdown(void)
{
    pjsua_call_hangup_all();
    pjsua_destroy();
    free(g_slab_pool);
}
