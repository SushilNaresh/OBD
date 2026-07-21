/*
 * Version: 2.0.8
 * worker.c — Worker process: Unix socket recv, dispatch + report + heartbeat threads
 * Fix: large SO_RCVBUF on Unix socket + dedicated fast-recv thread to prevent datagram drops
 * Diag: recvq overflow counter, dispatch latency, periodic throughput stats
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <pjsua-lib/pjsua.h>
#include "obd.h"

int sip_engine_get_active_calls(void);

/* Internal recv queue — decouples fast socket drain from slow sip_engine_dispatch() */
#define RECVQ_SIZE  4096   /* must be power of 2; holds OBDRequest structs */
typedef struct {
    OBDRequest      slots[RECVQ_SIZE];
    _Atomic uint64_t head;
    _Atomic uint64_t tail;
} RecvQueue;

static volatile int w_running = 1;
static int w_unix_sock = -1;
static LFQueue w_compq;
static pthread_mutex_t w_compq_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  w_compq_cond  = PTHREAD_COND_INITIALIZER;
static WorkerConfig w_cfg;
static char w_tag[16];
static RecvQueue w_recvq;
static pthread_mutex_t w_recvq_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  w_recvq_cond  = PTHREAD_COND_INITIALIZER;
static _Atomic uint64_t w_recv_total     = 0;  /* datagrams pulled from Unix socket */
static _Atomic uint64_t w_recvq_dropped  = 0;  /* dropped: recvq full */
static _Atomic uint64_t w_dispatch_total = 0;  /* dispatched to sip_engine */

static void recvq_init(RecvQueue *q)
{
    memset(q, 0, sizeof(*q));
}

static int recvq_push(RecvQueue *q, const OBDRequest *req)
{
    uint64_t head = atomic_load_explicit(&q->head, memory_order_relaxed);
    uint64_t tail = atomic_load_explicit(&q->tail, memory_order_acquire);
    if (head - tail >= RECVQ_SIZE)
        return -1;  /* full */
    q->slots[head & (RECVQ_SIZE - 1)] = *req;
    atomic_store_explicit(&q->head, head + 1, memory_order_release);
    return 0;
}

static int recvq_pop(RecvQueue *q, OBDRequest *req)
{
    uint64_t tail = atomic_load_explicit(&q->tail, memory_order_relaxed);
    uint64_t head = atomic_load_explicit(&q->head, memory_order_acquire);
    if (tail >= head)
        return -1;  /* empty */
    *req = q->slots[tail & (RECVQ_SIZE - 1)];
    atomic_store_explicit(&q->tail, tail + 1, memory_order_release);
    return 0;
}

static void worker_sig_handler(int sig)
{
    (void)sig;
    w_running = 0;
    if (w_unix_sock >= 0) {
        close(w_unix_sock);
        w_unix_sock = -1;
    }
}

static void worker_crash_handler(int sig)
{
    /* Log crash signal synchronously before the process dies.
     * Only async-signal-safe calls (write/snprintf) are used here. */
    char buf[256];
    int n = snprintf(buf, sizeof(buf),
        "{\"ev\":\"worker_crash\",\"w\":\"%s\",\"signal\":%d,\"signal_name\":\"%s\"}\n",
        w_tag,
        sig,
        sig == 11 ? "SIGSEGV" : sig == 6 ? "SIGABRT" : sig == 8 ? "SIGFPE" : sig == 4 ? "SIGILL" : "OTHER");
    if (n > 0) {
        /* obd_log_write_json is not async-signal-safe; write directly to stderr */
        (void)write(STDERR_FILENO, buf, (size_t)n);
    }
    /* Re-raise to get the default core/signal behaviour */
    signal(sig, SIG_DFL);
    raise(sig);
}

/* Called by sip_engine after pushing a report to wake the report thread */
void worker_signal_report(void)
{
    pthread_mutex_lock(&w_compq_mutex);
    pthread_cond_signal(&w_compq_cond);
    pthread_mutex_unlock(&w_compq_mutex);
}

/* Fast recv thread — drains Unix socket into w_recvq as quickly as possible.
 * Never calls sip_engine_dispatch() — keeps the socket buffer from filling up. */
static void *recv_thread(void *arg)
{
    (void)arg;
    OBDRequest req;

    while (w_running) {
        ssize_t n = recv(w_unix_sock, &req, sizeof(req), MSG_WAITALL);
        if (n <= 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) continue;
            break;
        }
        if (n != sizeof(req)) continue;

        atomic_fetch_add(&w_recv_total, 1);
        pthread_mutex_lock(&w_recvq_mutex);
        if (recvq_push(&w_recvq, &req) != 0) {
            atomic_fetch_add(&w_recvq_dropped, 1);
            LOG(OBD_LOG_WARN, w_tag, req.request_id, "recvq_overflow",
                ",\"dropped_total\":%" PRIu64, atomic_load(&w_recvq_dropped));
        } else {
            pthread_cond_signal(&w_recvq_cond);
        }
        pthread_mutex_unlock(&w_recvq_mutex);
    }
    return NULL;
}

/* Dispatch thread — pops from w_recvq, calls sip_engine_dispatch() */
static void *dispatch_thread(void *arg)
{
    (void)arg;
    OBDRequest req;

    /* Register this thread with PJLIB */
    pj_thread_desc desc;
    pj_thread_t *thread;
    pj_thread_register("dispatch", desc, &thread);

    while (w_running) {
        pthread_mutex_lock(&w_recvq_mutex);
        while (recvq_pop(&w_recvq, &req) != 0 && w_running) {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += 1;
            pthread_cond_timedwait(&w_recvq_cond, &w_recvq_mutex, &ts);
        }
        pthread_mutex_unlock(&w_recvq_mutex);

        if (!w_running) break;

        LOG(OBD_LOG_INFO, w_tag, req.request_id, "invite_sent",
            ",\"to\":\"%s\",\"dest\":\"%s\"",
            req.called_msisdn, req.dest_id);
        struct timespec t_ds, t_de;
        clock_gettime(CLOCK_MONOTONIC, &t_ds);
        sip_engine_dispatch(&req);
        clock_gettime(CLOCK_MONOTONIC, &t_de);
        atomic_fetch_add(&w_dispatch_total, 1);
        int dispatch_ms = (int)((t_de.tv_sec - t_ds.tv_sec) * 1000 +
                                (t_de.tv_nsec - t_ds.tv_nsec) / 1000000);
        if (dispatch_ms > 50)
            LOG(OBD_LOG_WARN, w_tag, req.request_id, "dispatch_slow",
                ",\"dispatch_ms\":%d", dispatch_ms);
    }
    return NULL;
}

/* Report thread — drain LFQueue, send UDP reports */
static void *report_thread(void *arg)
{
    (void)arg;
    OBDReport report;

    while (w_running) {
        pthread_mutex_lock(&w_compq_mutex);
        /* Wait under the mutex so worker_signal_report() can never fire
         * between the pop-check and the wait — eliminates the missed-signal
         * busy loop that caused 0.7% idle CPU per worker. */
        while (lfq_pop(&w_compq, &report) != 0 && w_running) {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            ts.tv_sec += 1;
            pthread_cond_timedwait(&w_compq_cond, &w_compq_mutex, &ts);
        }
        pthread_mutex_unlock(&w_compq_mutex);

        if (!w_running) break;

        udp_report_send(&report);
        LOG(OBD_LOG_INFO, w_tag, report.request_id, "sent",
            ",\"outcome\":\"%s\",\"sip\":%d,\"ms\":%d",
            outcome_str(report.outcome), report.sip_final_status, report.duration_ms);
    }
    return NULL;
}

/* Heartbeat thread — sends worker_id to dispatcher every interval */
static void *heartbeat_thread(void *arg)
{
    (void)arg;
    int hb_sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in hb_addr;
    memset(&hb_addr, 0, sizeof(hb_addr));
    hb_addr.sin_family = AF_INET;
    hb_addr.sin_port = htons(w_cfg.heartbeat_port);
    inet_pton(AF_INET, "127.0.0.1", &hb_addr.sin_addr);

    /* Register this thread with PJLIB so pjsua_* calls are safe */
    pj_thread_desc hb_desc;
    pj_thread_t *hb_thread;
    pj_thread_register("heartbeat", hb_desc, &hb_thread);

    char msg[32];
    int hb_count = 0;
    while (w_running) {
        snprintf(msg, sizeof(msg), "%d:%d", w_cfg.worker_id, sip_engine_get_active_calls());
        sendto(hb_sock, msg, strlen(msg), 0,
               (struct sockaddr *)&hb_addr, sizeof(hb_addr));
        /* Log worker health every 30 heartbeats (~30 seconds) */
        if (++hb_count % 30 == 0) {
            sip_engine_log_health();
            sip_engine_reap_orphans();
            uint64_t head  = atomic_load_explicit(&w_recvq.head, memory_order_acquire);
            uint64_t tail  = atomic_load_explicit(&w_recvq.tail, memory_order_acquire);
            uint64_t depth = (head >= tail) ? (head - tail) : 0;
            LOG(OBD_LOG_INFO, w_tag, "", "worker_recvq_stats",
                ",\"recvq_depth\":%" PRIu64
                ",\"recv_total\":%" PRIu64
                ",\"dispatch_total\":%" PRIu64
                ",\"recvq_dropped\":%" PRIu64,
                depth,
                atomic_load(&w_recv_total),
                atomic_load(&w_dispatch_total),
                atomic_load(&w_recvq_dropped));
        }
        sleep(OBD_WATCHDOG_INTERVAL);
    }
    close(hb_sock);
    return NULL;
}

void worker_run(WorkerConfig *cfg)
{
    signal(SIGINT,  worker_sig_handler);
    signal(SIGTERM, worker_sig_handler);
    signal(SIGPIPE, SIG_IGN);
    signal(SIGSEGV, worker_crash_handler);
    signal(SIGABRT, worker_crash_handler);
    signal(SIGFPE,  worker_crash_handler);
    signal(SIGILL,  worker_crash_handler);

    /* Each worker needs its own independent lock fd — inherited fds share
     * the parent's open file description, making flock() non-exclusive. */
    obd_log_reopen_lock();
    memcpy(&w_cfg, cfg, sizeof(w_cfg));
    snprintf(w_tag, sizeof(w_tag), "w%d", cfg->worker_id);

    /* Init LFQueue */
    lfq_init(&w_compq);

    /* Init UDP report sender */
    udp_report_init(cfg->report_ip, cfg->report_port);

    /* Init SIP engine */
    if (sip_engine_init(cfg, &w_compq, worker_signal_report) != 0) {
        LOG(OBD_LOG_ERROR, w_tag, "", "sip_init_failed",
            ",\"sip_port\":%d,\"heartbeat_port\":%d,\"bind_ip\":\"%s\"",
            cfg->sip_port, cfg->heartbeat_port,
            cfg->local_ip[0] ? cfg->local_ip : "0.0.0.0");
        _exit(1);
    }

    /* Init internal recv queue */
    recvq_init(&w_recvq);

    /* Create Unix DGRAM socket */
    w_unix_sock = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (w_unix_sock < 0) {
        LOG(OBD_LOG_ERROR, w_tag, "", "worker_socket_create_failed",
            ",\"reason\":\"%s\"", strerror(errno));
        _exit(1);
    }

    /* Large receive buffer — prevents datagram drops when dispatcher bursts requests.
     * Default Unix DGRAM queue is only ~10-212 datagrams; set to 4MB. */
    int rcvbuf = 4 * 1024 * 1024;
    setsockopt(w_unix_sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "/tmp/obd_worker_%d.sock", cfg->worker_id);
    unlink(addr.sun_path);
    if (bind(w_unix_sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG(OBD_LOG_ERROR, w_tag, "", "worker_socket_bind_failed",
            ",\"path\":\"%s\",\"reason\":\"%s\"",
            addr.sun_path, strerror(errno));
        _exit(1);
    }

    LOG(OBD_LOG_INFO, w_tag, "", "sip_ready",
        ",\"sip_port\":%d,\"advertised_port\":%d,\"heartbeat_port\":%d,\"max_calls\":%d,\"t1_ms\":%d,\"use_mux\":\"%s\",\"pjsua_max_calls\":%d,\"pjsua_max_acc\":%d,\"recvq_size\":%d",
        cfg->sip_port,
        worker_cfg_use_mux(cfg) ? cfg->sip_mux_port : cfg->sip_port,
        cfg->heartbeat_port, OBD_CALLS_PER_WORKER, cfg->sip_t1_ms,
        worker_cfg_use_mux(cfg) ? "yes" : "no",
        PJSUA_MAX_CALLS, PJSUA_MAX_ACC, RECVQ_SIZE);

    /* Start fast recv thread — single thread drains socket into w_recvq */
    pthread_t recv_tid;
    pthread_create(&recv_tid, NULL, recv_thread, NULL);

    /* Start dispatch threads — pop from w_recvq, call sip_engine_dispatch() */
    pthread_t dispatch_tids[OBD_DISPATCH_THREADS];
    for (int i = 0; i < OBD_DISPATCH_THREADS; i++)
        pthread_create(&dispatch_tids[i], NULL, dispatch_thread, NULL);

    /* Start report threads */
    pthread_t report_tids[OBD_REPORT_THREADS];
    for (int i = 0; i < OBD_REPORT_THREADS; i++)
        pthread_create(&report_tids[i], NULL, report_thread, NULL);

    /* Start heartbeat thread */
    pthread_t hb_tid;
    pthread_create(&hb_tid, NULL, heartbeat_thread, NULL);

    /* Wait (main thread just sleeps) */
    while (w_running) {
        sleep(1);
    }

    /* Cleanup */
    sip_engine_shutdown();
    udp_report_shutdown();
    if (w_unix_sock >= 0)
        close(w_unix_sock);
    unlink(addr.sun_path);
}
