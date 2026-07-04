/*
 * Version: 2.0.7
 * obd.h — OBD Service shared types, constants, and inline primitives
 * Added use_mux parameter to WorkerConfig for runtime MUX bypassing.
 */
#ifndef OBD_H
#define OBD_H

#include <stdint.h>
#include <stdatomic.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>

/* ================================================================== */
/* Compile-time constants (override via make tune)                      */
/* ================================================================== */
#ifndef OBD_NUM_WORKERS
#define OBD_NUM_WORKERS         4
#endif
#ifndef OBD_CALLS_PER_WORKER
#define OBD_CALLS_PER_WORKER    2500
#endif
#ifndef OBD_DISPATCH_THREADS
#define OBD_DISPATCH_THREADS    2
#endif
#ifndef OBD_REPORT_THREADS
#define OBD_REPORT_THREADS      4
#endif
#ifndef OBD_COMPQ_SIZE
#define OBD_COMPQ_SIZE          16384   /* must be power of 2 */
#endif
#ifndef OBD_DEFAULT_TIMEOUT
#define OBD_DEFAULT_TIMEOUT     15
#endif
#ifndef OBD_UDP_LISTEN_PORT
#define OBD_UDP_LISTEN_PORT     9090
#endif
#ifndef OBD_SIP_PORT_BASE
#define OBD_SIP_PORT_BASE       15060   /* worker internal SIP port base (loopback) */
#endif
#ifndef OBD_SIP_MUX_PORT
#define OBD_SIP_MUX_PORT        5060    /* public-facing SIP port when MUX is enabled */
#endif
#ifndef OBD_PROXY_PORT_DEFAULT
#define OBD_PROXY_PORT_DEFAULT  5060    /* outbound carrier/proxy SIP port */
#endif
#ifndef OBD_SIP_T1_MS
#define OBD_SIP_T1_MS           200
#endif
#ifndef OBD_SIP_T2_MS
#define OBD_SIP_T2_MS           1600
#endif
#ifndef OBD_CANCEL_RING_MS
#define OBD_CANCEL_RING_MS      500     /* ms after 180 Ringing before CANCEL is sent */
#endif
#ifndef OBD_HEARTBEAT_PORT_OFFSET
#define OBD_HEARTBEAT_PORT_OFFSET 1000
#endif
#ifndef OBD_RTP_BASE
#define OBD_RTP_BASE            20000
#endif
#ifndef OBD_WATCHDOG_INTERVAL
#define OBD_WATCHDOG_INTERVAL   1
#endif
#ifndef OBD_WATCHDOG_TIMEOUT
#define OBD_WATCHDOG_TIMEOUT    5
#endif
#ifndef OBD_LOG_FILE_MAX
#define OBD_LOG_FILE_MAX        256
#endif
#ifndef OBD_LOG_ROTATE_SIZE
#define OBD_LOG_ROTATE_SIZE     (100 * 1024 * 1024)  /* 100 MB default max log size */
#endif
#ifndef OBD_LOG_ROTATE_COUNT
#define OBD_LOG_ROTATE_COUNT    5                    /* keep 5 rotated backups */
#endif
#ifndef OBD_DEDUP_BUCKETS
#define OBD_DEDUP_BUCKETS       65536   /* power of 2 */
#endif
#ifndef OBD_DEDUP_TTL_SEC
#define OBD_DEDUP_TTL_SEC       120
#endif

/* ================================================================== */
/* Call Outcome enum                                                    */
/* ================================================================== */
typedef enum {
    OUTCOME_MISSED_CALL = 0,
    OUTCOME_NO_ANSWER,
    OUTCOME_BUSY,
    OUTCOME_UNAVAILABLE,
    OUTCOME_UNREACHABLE,
    OUTCOME_CF_MCA,
    OUTCOME_CF_NUMBER,
    OUTCOME_REJECTED,
    OUTCOME_NETWORK_DOWN,
    OUTCOME_UNKNOWN
} CallOutcome;

static inline const char *outcome_str(CallOutcome o)
{
    switch (o) {
        case OUTCOME_MISSED_CALL:  return "MISSED_CALL";
        case OUTCOME_NO_ANSWER:    return "NO_ANSWER";
        case OUTCOME_BUSY:         return "BUSY";
        case OUTCOME_UNAVAILABLE:  return "UNAVAILABLE";
        case OUTCOME_UNREACHABLE:  return "UNREACHABLE";
        case OUTCOME_CF_MCA:       return "CF_MCA";
        case OUTCOME_CF_NUMBER:    return "CF_NUMBER";
        case OUTCOME_REJECTED:     return "REJECTED";
        case OUTCOME_NETWORK_DOWN: return "NETWORK_DOWN";
        default:                   return "UNKNOWN";
    }
}

/* ================================================================== */
/* OBDRequest — wire struct from A (via dispatcher → worker)           */
/* ================================================================== */
typedef struct {
    char calling_msisdn[64];
    char called_msisdn[64];
    char request_id[128];
    char dest_id[64];           /* operator NE IP */
    int  timeout_sec;
} OBDRequest;

/* ================================================================== */
/* OBDReport — completion report (internal + wire to B)                */
/* ================================================================== */
typedef struct {
    char        calling_msisdn[64];
    char        called_msisdn[64];
    char        request_id[128];
    CallOutcome outcome;
    int         sip_final_status;
    int         duration_ms;
} OBDReport;

/* ================================================================== */
/* WorkerConfig                                                         */
/* ================================================================== */
typedef struct {
    int  worker_id;
    int  sip_port;
    int  sip_port_base;
    int  sip_mux_port;
    int  proxy_port;
    int  heartbeat_port;
    int  rtp_base_port;
    char local_ip[64];
    char report_ip[64];
    int  report_port;
    int  cpu_core;
    int  sip_t1_ms;
    int  sip_t2_ms;
    char require_100rel[16];  /* "yes" or "no" */
    char default_proxy[64];   /* fallback proxy if destID empty */
    char use_rtp[8];          /* "yes" sends RTP, "no" receives RTP only */
    char use_mux[8];          /* "yes" or "no" — bypass or enable multiplexing */
    int  sip_log_level;
    int  cancel_ring_ms;      /* ms after 180 Ringing before CANCEL is sent */
    char log_file[OBD_LOG_FILE_MAX];
} WorkerConfig;

static inline int obd_flag_enabled(const char *value, int default_value)
{
    if (!value || !value[0])
        return default_value;

    return !(strcasecmp(value, "no") == 0 ||
             strcasecmp(value, "false") == 0 ||
             strcmp(value, "0") == 0);
}

static inline int worker_cfg_use_mux(const WorkerConfig *cfg)
{
    return obd_flag_enabled(cfg ? cfg->use_mux : NULL, 1);
}

/* ================================================================== */
/* Lock-Free MPSC Queue (OPT2)                                         */
/* Power-of-2 ring, per-slot sequence numbers                          */
/* ================================================================== */
typedef struct {
    OBDReport           slots[OBD_COMPQ_SIZE];
    _Atomic uint64_t    seq[OBD_COMPQ_SIZE];
    _Atomic uint64_t    head;   /* producers CAS this */
    _Atomic uint64_t    tail;   /* single consumer advances */
} LFQueue;

static inline void lfq_init(LFQueue *q)
{
    memset(q, 0, sizeof(*q));
    for (uint64_t i = 0; i < OBD_COMPQ_SIZE; i++)
        atomic_store_explicit(&q->seq[i], i, memory_order_relaxed);
    atomic_store_explicit(&q->head, 0, memory_order_relaxed);
    atomic_store_explicit(&q->tail, 0, memory_order_relaxed);
}

static inline int lfq_push(LFQueue *q, const OBDReport *report)
{
    uint64_t pos;
    for (;;) {
        pos = atomic_load_explicit(&q->head, memory_order_relaxed);
        uint64_t seq = atomic_load_explicit(&q->seq[pos & (OBD_COMPQ_SIZE - 1)], memory_order_acquire);
        int64_t diff = (int64_t)seq - (int64_t)pos;
        if (diff == 0) {
            if (atomic_compare_exchange_weak_explicit(&q->head, &pos, pos + 1,
                    memory_order_relaxed, memory_order_relaxed))
                break;
        } else if (diff < 0) {
            return -1;  /* queue full */
        }
    }
    uint64_t idx = pos & (OBD_COMPQ_SIZE - 1);
    q->slots[idx] = *report;
    atomic_store_explicit(&q->seq[idx], pos + 1, memory_order_release);
    return 0;
}

static inline int lfq_pop(LFQueue *q, OBDReport *report)
{
    uint64_t pos = atomic_load_explicit(&q->tail, memory_order_relaxed);
    uint64_t idx = pos & (OBD_COMPQ_SIZE - 1);
    uint64_t seq = atomic_load_explicit(&q->seq[idx], memory_order_acquire);
    int64_t diff = (int64_t)seq - (int64_t)(pos + 1);
    if (diff < 0)
        return -1;  /* empty */
    q->tail = pos + 1;  /* single consumer — no CAS needed */
    *report = q->slots[idx];
    atomic_store_explicit(&q->seq[idx], pos + OBD_COMPQ_SIZE, memory_order_release);
    return 0;
}

/* ================================================================== */
/* Structured JSON Logging (OPT9)                                      */
/* ================================================================== */
int obd_log_init(const char *path);
void obd_log_set_rotation(size_t max_size_bytes, int max_backups);
const char *obd_log_path(void);
void obd_log_close(void);
void obd_log_write_json(const char *file, int line, const char *worker_tag,
                        const char *req_id, const char *event,
                        const char *fmt, ...);

#define LOG(worker_tag, req_id, event, ...) \
    obd_log_write_json(__FILE__, __LINE__, (worker_tag), (req_id), (event), __VA_ARGS__)

/* ================================================================== */
/* Module interfaces                                                    */
/* ================================================================== */

/* dispatcher.c */
void dispatcher_run(const char *local_ip, int listen_port,
                    const char *report_ip, int report_port,
                    const WorkerConfig *worker_cfgs,
                    const pid_t *worker_pids);

/* worker.c */
void worker_run(WorkerConfig *cfg);

/* sip_engine.c */
int  sip_engine_init(WorkerConfig *cfg, LFQueue *compq, void (*signal_fn)(void));
void sip_engine_dispatch(const OBDRequest *req);
void sip_engine_log_health(void);
void sip_engine_shutdown(void);

/* dedup.c */
void dedup_init(void);
int  dedup_check_and_set(const char *request_id);  /* returns 1 if duplicate */
void dedup_cleanup(void);

/* udp_report.c */
void udp_report_init(const char *report_ip, int report_port);
void udp_report_send(const OBDReport *report);
void udp_report_shutdown(void);

#endif /* OBD_H */
