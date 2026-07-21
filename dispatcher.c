/*
 * Version: 2.1.0
 * dispatcher.c — UDP recv, JSON parse, dedup, least-loaded routing, watchdog with grace periods
 * Features an integrated, ultra-high-speed stateless SIP UDP Multiplexer (SIP-MUX) to force all
 * carrier-facing traffic through a configured shared SIP port.
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
#include <sys/wait.h>
#include <sched.h>
#include <stdatomic.h>
#include <limits.h>
#include <inttypes.h>
#include <sys/ioctl.h>
#include <stdint.h>
#include "obd.h"

#define OBD_WATCHDOG_INIT_TIMEOUT 30  /* 30 seconds startup grace period for heavy PJSIP initialization */

/* ================================================================== */
/* SIP Multiplexer (SIP-MUX) Hash Map & Definitions                    */
/* ================================================================== */
#define MUX_HASH_SIZE    131072  /* Power of 2 for fast modulo operations */
#define MUX_SHARDS       32      /* Shards to minimize spinlock contention under heavy loads */
#define MUX_PROBE_LIMIT  4       /* Cache line boundaries for probing */

typedef struct {
    char     call_id[128];
    uint16_t worker_port;
    time_t   expires;
} MuxEntry;

typedef struct {
    MuxEntry           entries[MUX_PROBE_LIMIT];
    pthread_mutex_t lock;
} MuxShard;

static MuxShard g_mux[MUX_SHARDS];

/* High-speed FNV-1a Hash */
static inline uint32_t mux_fnv1a(const char *s, size_t len)
{
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < len; i++) {
        h ^= (uint8_t)s[i];
        h *= 16777619u;
    }
    return h;
}

static void mux_init(void)
{
    memset(g_mux, 0, sizeof(g_mux));
    for (int i = 0; i < MUX_SHARDS; i++) {
        pthread_mutex_init(&g_mux[i].lock, NULL);
    }
}

static void mux_cleanup(void)
{
    for (int i = 0; i < MUX_SHARDS; i++) {
        pthread_mutex_destroy(&g_mux[i].lock);
    }
}

/* Store Call-ID -> Worker Port association (Outbound flow registration) */
static void mux_set(const char *call_id, size_t len, uint16_t port)
{
    uint32_t hash = mux_fnv1a(call_id, len);
    int shard_idx = hash % MUX_SHARDS;
    MuxShard *shard = &g_mux[shard_idx];
    time_t now = time(NULL);

    pthread_mutex_lock(&shard->lock);

    int free_idx = -1;
    for (int i = 0; i < MUX_PROBE_LIMIT; i++) {
        if (shard->entries[i].call_id[0] == '\0' || shard->entries[i].expires <= now) {
            free_idx = i;
            break;
        }
    }

    /* Fallback: Evict the oldest slot if full */
    if (free_idx < 0) {
        free_idx = 0;
    }

    size_t copy_len = len < 127 ? len : 127;
    memcpy(shard->entries[free_idx].call_id, call_id, copy_len);
    shard->entries[free_idx].call_id[copy_len] = '\0';
    shard->entries[free_idx].worker_port = port;
    shard->entries[free_idx].expires = now + 1800; /* Cache entries for 30 minutes */

    pthread_mutex_unlock(&shard->lock);
}

/* Retrieve Worker Port by Call-ID (Inbound flow lookup) */
static uint16_t mux_get(const char *call_id, size_t len)
{
    uint32_t hash = mux_fnv1a(call_id, len);
    int shard_idx = hash % MUX_SHARDS;
    MuxShard *shard = &g_mux[shard_idx];
    time_t now = time(NULL);
    uint16_t port = 0;

    pthread_mutex_lock(&shard->lock);

    for (int i = 0; i < MUX_PROBE_LIMIT; i++) {
        if (shard->entries[i].call_id[0] != '\0' && shard->entries[i].expires > now) {
            if (strncmp(shard->entries[i].call_id, call_id, len) == 0 && shard->entries[i].call_id[len] == '\0') {
                port = shard->entries[i].worker_port;
                shard->entries[i].expires = now + 1800; /* Touch entry lifespan */
                break;
            }
        }
    }

    pthread_mutex_unlock(&shard->lock);
    return port;
}

/* Zero-allocation, high-speed micro-scanner to isolate the Call-ID header */
static const char *mux_extract_call_id(const char *payload, size_t len, size_t *out_len)
{
    const char *ptr = payload;
    const char *end = payload + len;

    while (ptr < end) {
        if (end - ptr >= 8 && strncasecmp(ptr, "call-id:", 8) == 0) {
            ptr += 8;
            while (ptr < end && (*ptr == ' ' || *ptr == '\t')) ptr++;
            const char *val_start = ptr;
            while (ptr < end && *ptr != '\r' && *ptr != '\n') ptr++;
            *out_len = (size_t)(ptr - val_start);
            return val_start;
        } else if (end - ptr >= 2 && strncasecmp(ptr, "i:", 2) == 0) { /* Compact form */
            ptr += 2;
            while (ptr < end && (*ptr == ' ' || *ptr == '\t')) ptr++;
            const char *val_start = ptr;
            while (ptr < end && *ptr != '\r' && *ptr != '\n') ptr++;
            *out_len = (size_t)(ptr - val_start);
            return val_start;
        }
        while (ptr < end && *ptr != '\n') ptr++;
        ptr++;
    }
    return NULL;
}

/* ================================================================== */
/* Raw packet queue — decouples fast UDP drain from slow routing       */
/* ================================================================== */
#ifndef OBD_PKTQ_SIZE
#define OBD_PKTQ_SIZE  524288  /* power of 2; ~500K slots, handles sustained 50K+ CPS bursts */
#endif
#define PKTQ_SIZE  OBD_PKTQ_SIZE
/* 512 bytes covers any realistic JSON OBD request; avoids 2GB+ BSS with large slot counts */
#define PKTQ_SLOT_SIZE 512
typedef struct { char data[PKTQ_SLOT_SIZE]; int len; } RawPkt;
typedef struct {
    RawPkt           *slots;   /* heap-allocated — keeps BSS small regardless of PKTQ_SIZE */
    _Atomic uint64_t head;
    _Atomic uint64_t tail;
} PktQueue;
static PktQueue          g_pktq;
static _Atomic uint64_t  g_pktq_dropped = 0;

#include <semaphore.h>
static sem_t g_pktq_sem;  /* routing threads sleep here when queue is empty */

static int pktq_push(const char *data, int len)
{
    if (len > PKTQ_SLOT_SIZE - 1) len = PKTQ_SLOT_SIZE - 1;  /* truncate oversized; JSON requests are always small */
    uint64_t head = atomic_load_explicit(&g_pktq.head, memory_order_relaxed);
    uint64_t tail = atomic_load_explicit(&g_pktq.tail, memory_order_acquire);
    if (head - tail >= PKTQ_SIZE) return -1;
    RawPkt *slot = &g_pktq.slots[head & (PKTQ_SIZE - 1)];
    memcpy(slot->data, data, len);
    slot->data[len] = '\0';
    slot->len = len;
    atomic_store_explicit(&g_pktq.head, head + 1, memory_order_release);
    sem_post(&g_pktq_sem);  /* wake one routing thread */
    return 0;
}

static int pktq_pop(RawPkt *out)
{
    uint64_t tail, head;
    for (;;) {
        tail = atomic_load_explicit(&g_pktq.tail, memory_order_relaxed);
        head = atomic_load_explicit(&g_pktq.head, memory_order_acquire);
        if (tail >= head) return -1;
        if (atomic_compare_exchange_weak_explicit(&g_pktq.tail, &tail, tail + 1,
                memory_order_acq_rel, memory_order_relaxed))
            break;
    }
    *out = g_pktq.slots[tail & (PKTQ_SIZE - 1)];
    return 0;
}

/* ================================================================== */
/* Globals & Signal Handlers                                           */
/* ================================================================== */
static volatile sig_atomic_t g_running = 1;
static _Atomic int g_worker_inflight[OBD_NUM_WORKERS];
static _Atomic int g_next_worker = 0;
static int g_worker_socks[OBD_NUM_WORKERS];
static pid_t g_worker_pids[OBD_NUM_WORKERS];
static time_t g_worker_heartbeat[OBD_NUM_WORKERS];
static WorkerConfig g_worker_cfgs[OBD_NUM_WORKERS];
static int g_heartbeat_port = OBD_UDP_LISTEN_PORT + 1000;
/* Throughput counters for dispatcher rate logging */
static _Atomic uint64_t g_recv_total   = 0;  /* UDP requests received */
static _Atomic uint64_t g_routed_total = 0;  /* successfully sent to a worker */
static _Atomic uint64_t g_drop_total   = 0;  /* no_workers_available + route_failed */

/* Circuit breaker state per worker (Issue 1 & 3) */
#define CB_MAX_FAILURES     3       /* consecutive failures before tripping */
#define CB_COOLDOWN_SEC     2       /* seconds before attempting reconnect */
static _Atomic int g_worker_fail_count[OBD_NUM_WORKERS];
static _Atomic int g_worker_circuit_open[OBD_NUM_WORKERS];  /* 1 = tripped/unhealthy */
static time_t g_worker_circuit_trip_time[OBD_NUM_WORKERS];
static pthread_mutex_t g_sock_lock[OBD_NUM_WORKERS];

static int dispatcher_use_mux(void)
{
    return worker_cfg_use_mux(&g_worker_cfgs[0]);
}

/* Reconnect dispatcher socket to a worker's Unix DGRAM endpoint (Issue 2) */
static int reconnect_worker_sock(int worker_id)
{
    pthread_mutex_lock(&g_sock_lock[worker_id]);

    if (g_worker_socks[worker_id] >= 0)
        close(g_worker_socks[worker_id]);

    g_worker_socks[worker_id] = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (g_worker_socks[worker_id] < 0) {
        pthread_mutex_unlock(&g_sock_lock[worker_id]);
        return -1;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    snprintf(addr.sun_path, sizeof(addr.sun_path), "/tmp/obd_worker_%d.sock", worker_id);

    int rc = connect(g_worker_socks[worker_id], (struct sockaddr *)&addr, sizeof(addr));
    pthread_mutex_unlock(&g_sock_lock[worker_id]);

    if (rc == 0) {
        atomic_store(&g_worker_fail_count[worker_id], 0);
        atomic_store(&g_worker_circuit_open[worker_id], 0);
        LOG(OBD_LOG_INFO, "dispatcher", "", "worker_reconnected", ",\"worker\":%d", worker_id);
    }
    return rc;
}

/* Trip the circuit breaker for a worker (Issue 1: stop routing to it) */
static void trip_circuit_breaker(int worker_id)
{
    atomic_store(&g_worker_circuit_open[worker_id], 1);
    g_worker_circuit_trip_time[worker_id] = time(NULL);
    LOG(OBD_LOG_WARN, "dispatcher", "", "circuit_breaker_open",
        ",\"worker\":%d,\"pid\":%d,\"failures\":%d",
        worker_id, g_worker_pids[worker_id],
        atomic_load(&g_worker_fail_count[worker_id]));
}

static void sig_handler(int sig) { (void)sig; g_running = 0; }

static void set_worker_affinity(int cpu_core)
{
#ifdef __linux__
    cpu_set_t cpuset;
    long cpu_count = sysconf(_SC_NPROCESSORS_ONLN);

    if (cpu_count <= 0)
        return;

    CPU_ZERO(&cpuset);
    CPU_SET(cpu_core % cpu_count, &cpuset);
    sched_setaffinity(0, sizeof(cpuset), &cpuset);
#else
    (void)cpu_core;
#endif
}

static pid_t spawn_worker_from_cfg(int worker_id)
{
    pid_t pid = fork();

    if (pid == 0) {
        WorkerConfig wcfg = g_worker_cfgs[worker_id];
        set_worker_affinity(wcfg.cpu_core);
        worker_run(&wcfg);
        _exit(0);
    }

    return pid;
}

static void stop_worker_pid(int worker_id, int force_kill)
{
    pid_t pid = g_worker_pids[worker_id];
    int status;

    if (pid <= 0)
        return;

    if (kill(pid, 0) == 0) {
        int sig = force_kill ? SIGKILL : SIGTERM;
        kill(pid, sig);
    } else if (errno != ESRCH) {
        LOG(OBD_LOG_WARN, "dispatcher", "", "worker_signal_failed",
            ",\"worker\":%d,\"pid\":%d,\"reason\":\"%s\"",
            worker_id, pid, strerror(errno));
    }

    for (int i = 0; i < 20; i++) {
        pid_t done = waitpid(pid, &status, WNOHANG);
        if (done == pid) {
            g_worker_pids[worker_id] = 0;
            return;
        }
        if (done < 0 && errno == ECHILD) {
            g_worker_pids[worker_id] = 0;
            return;
        }
        usleep(100000);
    }

    if (!force_kill && kill(pid, 0) == 0) {
        kill(pid, SIGKILL);
        waitpid(pid, &status, 0);
    }

    g_worker_pids[worker_id] = 0;
}

static void stop_all_workers(void)
{
    for (int i = 0; i < OBD_NUM_WORKERS; i++)
        stop_worker_pid(i, 0);
}

/* Simple JSON field extractor */
static int json_get(const char *json, const char *key, char *out, int sz)
{
    char pat[128];
    snprintf(pat, sizeof(pat), "\"%s\":", key);
    const char *p = strstr(json, pat);
    if (!p) return -1;
    p += strlen(pat);
    while (*p == ' ' || *p == '\t') p++;
    if (*p == '"') {
        p++;
        const char *e = strchr(p, '"');
        if (!e) return -1;
        int len = (int)(e - p);
        if (len >= sz) len = sz - 1;
        memcpy(out, p, len);
        out[len] = '\0';
    }
    return 0;
}

/* Watchdog thread (OPT7) with grace periods, reconnect, and auto-healing */
static void *watchdog_thread(void *arg)
{
    (void)arg;
    time_t last_rate_log = time(NULL);
    uint64_t last_routed = 0, last_recv = 0;
    while (g_running) {
        sleep(OBD_WATCHDOG_INTERVAL);
        time_t now = time(NULL);

        /* Periodic dispatcher rate log every 30 seconds */
        if (now - last_rate_log >= 30) {
            uint64_t cur_recv   = atomic_load(&g_recv_total);
            uint64_t cur_routed = atomic_load(&g_routed_total);
            uint64_t cur_drop   = atomic_load(&g_drop_total);
            long elapsed = (long)(now - last_rate_log);
            uint64_t recv_delta   = cur_recv   - last_recv;
            uint64_t routed_delta = cur_routed - last_routed;
            /* Per-worker inflight snapshot */
            int min_inf = INT_MAX, max_inf = 0, total_inf = 0;
            for (int i = 0; i < OBD_NUM_WORKERS; i++) {
                int inf = atomic_load(&g_worker_inflight[i]);
                if (inf < min_inf) min_inf = inf;
                if (inf > max_inf) max_inf = inf;
                total_inf += inf;
            }
            LOG(OBD_LOG_INFO, "dispatcher", "", "dispatcher_rate",
                ",\"recv_total\":%" PRIu64
                ",\"routed_total\":%" PRIu64
                ",\"drop_total\":%" PRIu64
                ",\"pktq_dropped\":%" PRIu64
                ",\"recv_per_sec\":%" PRIu64
                ",\"routed_per_sec\":%" PRIu64
                ",\"inflight_total\":%d"
                ",\"inflight_min\":%d"
                ",\"inflight_max\":%d",
                cur_recv, cur_routed, cur_drop,
                atomic_load(&g_pktq_dropped),
                recv_delta / (uint64_t)elapsed,
                routed_delta / (uint64_t)elapsed,
                total_inf, min_inf, max_inf);
            last_rate_log = now;
            last_recv     = cur_recv;
            last_routed   = cur_routed;
        }

        for (int i = 0; i < OBD_NUM_WORKERS; i++) {

            /* Auto-heal: attempt reconnect for circuit-broken workers (Issue 3) */
            if (atomic_load(&g_worker_circuit_open[i]) &&
                (now - g_worker_circuit_trip_time[i] >= CB_COOLDOWN_SEC)) {

                if (g_worker_pids[i] > 0 && kill(g_worker_pids[i], 0) == 0) {
                    /* Worker process is alive — just reconnect the socket */
                    if (reconnect_worker_sock(i) == 0) {
                        LOG(OBD_LOG_INFO, "dispatcher", "", "circuit_breaker_healed",
                            ",\"worker\":%d,\"pid\":%d", i, g_worker_pids[i]);
                    }
                }
            }

            /* Dead worker detection via heartbeat timeout */
            if (now > g_worker_heartbeat[i] && (now - g_worker_heartbeat[i] > OBD_WATCHDOG_TIMEOUT)) {
                /* Collect exit status before stopping to capture crash signal */
                int wstatus = 0;
                int exit_code = -1;
                int crash_signal = 0;
                if (g_worker_pids[i] > 0) {
                    pid_t r = waitpid(g_worker_pids[i], &wstatus, WNOHANG);
                    if (r == g_worker_pids[i]) {
                        if (WIFEXITED(wstatus))   exit_code    = WEXITSTATUS(wstatus);
                        if (WIFSIGNALED(wstatus)) crash_signal = WTERMSIG(wstatus);
                    }
                }
                /* Log unread requests still buffered in the dead worker's socket */
                int unread_bytes = 0;
                int lost_requests = 0;
                if (g_worker_socks[i] >= 0) {
                    ioctl(g_worker_socks[i], FIONREAD, &unread_bytes);
                    lost_requests = unread_bytes / (int)sizeof(OBDRequest);
                }
                LOG(OBD_LOG_ERROR, "dispatcher", "", "worker_dead",
                    ",\"worker\":%d,\"pid\":%d,\"last_seen_sec\":%ld,\"exit_code\":%d,\"signal\":%d,\"lost_requests\":%d,\"action\":\"restart\"",
                    i, g_worker_pids[i], (long)(now - g_worker_heartbeat[i]),
                    exit_code, crash_signal, lost_requests);

                stop_worker_pid(i, 1);  /* Force SIGKILL to ensure immediate port release */

                /* Wait for kernel to fully release the SIP UDP port (TIME_WAIT/linger) */
                usleep(500000);  /* 500ms grace for port release */

                pid_t pid = spawn_worker_from_cfg(i);
                if (pid < 0) {
                    LOG(OBD_LOG_ERROR, "dispatcher", "", "worker_restart_failed",
                        ",\"worker\":%d,\"reason\":\"%s\"",
                        i, strerror(errno));
                    continue;
                }

                g_worker_pids[i] = pid;
                g_worker_heartbeat[i] = time(NULL) + (OBD_WATCHDOG_INIT_TIMEOUT - OBD_WATCHDOG_TIMEOUT);
                atomic_store(&g_worker_inflight[i], 0);

                /* Reconnect socket to the new worker with retries (Issue 2) */
                int connected = 0;
                for (int retry = 0; retry < 50; retry++) {
                    usleep(200000); /* 200ms — give worker time to init PJSIP + bind unix sock */
                    if (reconnect_worker_sock(i) == 0) {
                        connected = 1;
                        break;
                    }
                }
                if (!connected) {
                    LOG(OBD_LOG_ERROR, "dispatcher", "", "worker_reconnect_failed_after_restart",
                        ",\"worker\":%d,\"pid\":%d", i, pid);
                    trip_circuit_breaker(i);
                }

                LOG(OBD_LOG_WARN, "dispatcher", "", "worker_restarted",
                    ",\"worker\":%d,\"pid\":%d,\"sip_port\":%d,\"heartbeat_port\":%d,\"connected\":%d",
                    i, pid, g_worker_cfgs[i].sip_port, g_worker_cfgs[i].heartbeat_port, connected);
            }
        }
    }
    return NULL;
}

/* Heartbeat receiver thread — parses active call telemetry load */
static void *heartbeat_recv_thread(void *arg)
{
    (void)arg;
    int hb_sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in hb_addr;
    memset(&hb_addr, 0, sizeof(hb_addr));
    hb_addr.sin_family = AF_INET;
    hb_addr.sin_port = htons(g_heartbeat_port);
    hb_addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(hb_sock, (struct sockaddr *)&hb_addr, sizeof(hb_addr)) < 0) {
        LOG(OBD_LOG_ERROR, "dispatcher", "", "heartbeat_bind_failed",
            ",\"port\":%d,\"reason\":\"%s\"",
            g_heartbeat_port, strerror(errno));
        close(hb_sock);
        g_running = 0;
        return NULL;
    }

    char buf[64];
    while (g_running) {
        struct sockaddr_in src;
        socklen_t slen = sizeof(src);
        ssize_t n = recvfrom(hb_sock, buf, sizeof(buf) - 1, 0,
                             (struct sockaddr *)&src, &slen);
        if (n > 0) {
            buf[n] = '\0';
            int wid = -1;
            int active_calls = 0;
            /* Parse telemetry load correctly */
            if (sscanf(buf, "%d:%d", &wid, &active_calls) == 2) {
                if (wid >= 0 && wid < OBD_NUM_WORKERS) {
                    g_worker_heartbeat[wid] = time(NULL);
                    atomic_store(&g_worker_inflight[wid], active_calls);
                }
            }
        }
    }
    close(hb_sock);
    return NULL;
}

/* ================================================================== */
/* SIP-MUX Kernel-level UDP Routing Loop Thread                        */
/* ================================================================== */
static void *sip_mux_thread(void *arg)
{
    (void)arg;
    int mux_port = g_worker_cfgs[0].sip_mux_port;
    int proxy_port = g_worker_cfgs[0].proxy_port;
    int mux_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (mux_sock < 0) {
        LOG(OBD_LOG_ERROR, "dispatcher", "", "mux_socket_create_failed", ",\"reason\":\"%s\"", strerror(errno));
        return NULL;
    }

    /* Set socket options for extreme scaling throughput (SO_REUSEPORT + SO_RCVBUF) */
    int reuse = 1;
    setsockopt(mux_sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
#ifdef SO_REUSEPORT
    setsockopt(mux_sock, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
#endif

    int rcvbuf = 32 * 1024 * 1024; /* 32 MB buffers to prevent socket drops at 10,000 TPS */
    setsockopt(mux_sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));
    setsockopt(mux_sock, SOL_SOCKET, SO_SNDBUF, &rcvbuf, sizeof(rcvbuf));

    struct sockaddr_in bind_addr;
    memset(&bind_addr, 0, sizeof(bind_addr));
    bind_addr.sin_family = AF_INET;
    bind_addr.sin_port = htons(mux_port);
    bind_addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(mux_sock, (struct sockaddr *)&bind_addr, sizeof(bind_addr)) < 0) {
        LOG(OBD_LOG_ERROR, "dispatcher", "", "mux_bind_failed",
            ",\"port\":%d,\"reason\":\"%s\"", mux_port, strerror(errno));
        close(mux_sock);
        return NULL;
    }

    LOG(OBD_LOG_INFO, "dispatcher", "", "mux_started", ",\"bind_ip\":\"0.0.0.0\",\"port\":%d", mux_port);

    /* Prep carrier target address for outbound delivery routing */
    struct sockaddr_in carrier_addr;
    memset(&carrier_addr, 0, sizeof(carrier_addr));
    carrier_addr.sin_family = AF_INET;
    carrier_addr.sin_port = htons(proxy_port);
    inet_pton(AF_INET, g_worker_cfgs[0].default_proxy, &carrier_addr.sin_addr);
    printf("carrier_addr.sin_port %d",carrier_addr.sin_port);
LOG(OBD_LOG_DEBUG, "dispatcher", "", "carrier_addr.sin_port", ",\"bind_ip\":\"0.0.0.0\",\"port\":%d", carrier_addr.sin_port);
    char buf[4096];
    struct sockaddr_in src_addr;
    socklen_t slen;

    while (g_running) {
        slen = sizeof(src_addr);
        ssize_t n = recvfrom(mux_sock, buf, sizeof(buf), 0, (struct sockaddr *)&src_addr, &slen);
        if (n <= 0) {
            if (errno == EINTR) continue;
            break;
        }

        size_t cid_len = 0;
        const char *cid = mux_extract_call_id(buf, n, &cid_len);
        if (!cid || cid_len == 0) {
            /* Drop non-SIP payloads or missing Call-ID immediately */
            continue;
        }

        /* Check the packet source IP to identify transaction routing direction */
        if (src_addr.sin_addr.s_addr == inet_addr("127.0.0.1")) {
            /* direction: OUTBOUND (Worker local socket --> Carrier) */
            uint16_t worker_port = ntohs(src_addr.sin_port);
            
            /* Record transaction mapping */
            mux_set(cid, cid_len, worker_port);

            /* Route the UDP payload facing the carrier */
            sendto(mux_sock, buf, n, 0, (struct sockaddr *)&carrier_addr, sizeof(carrier_addr));
        } else {
            /* direction: INBOUND (Carrier response --> Local loopback worker) */
            uint16_t target_port = mux_get(cid, cid_len);
            if (target_port > 0) {
                struct sockaddr_in worker_dst;
                memset(&worker_dst, 0, sizeof(worker_dst));
                worker_dst.sin_family = AF_INET;
                worker_dst.sin_port = htons(target_port);
                inet_pton(AF_INET, "127.0.0.1", &worker_dst.sin_addr);

                /* Route the UDP response locally to the loopback worker */
                sendto(mux_sock, buf, n, 0, (struct sockaddr *)&worker_dst, sizeof(worker_dst));
            }
        }
    }

    close(mux_sock);
    return NULL;
}

/* Routing thread: parse + dedup + route — all slow work off the recv path */
static void *routing_thread(void *arg)
{
    (void)arg;
    RawPkt pkt;

    while (g_running) {
        /* Sleep until a packet arrives — eliminates busy-poll CPU burn */
        if (pktq_pop(&pkt) != 0) {
            sem_wait(&g_pktq_sem);
            continue;
        }

        if (!g_running) break;

        OBDRequest req;
        memset(&req, 0, sizeof(req));
        req.timeout_sec = OBD_DEFAULT_TIMEOUT;

        json_get(pkt.data, "callingMSISDN", req.calling_msisdn, sizeof(req.calling_msisdn));
        json_get(pkt.data, "calledMSISDN",  req.called_msisdn,  sizeof(req.called_msisdn));
        json_get(pkt.data, "requestId",     req.request_id,     sizeof(req.request_id));
        json_get(pkt.data, "destID",        req.dest_id,        sizeof(req.dest_id));

        char timeout_str[16] = "";
        if (json_get(pkt.data, "timeout", timeout_str, sizeof(timeout_str)) == 0 && timeout_str[0]) {
            char *end;
            long val = strtol(timeout_str, &end, 10);
            if (end != timeout_str && *end == '\0' && val > 0 && val <= INT_MAX)
                req.timeout_sec = (int)val;
        }

        if (!req.called_msisdn[0] || !req.request_id[0]) continue;

        atomic_fetch_add(&g_recv_total, 1);
        LOG(OBD_LOG_INFO, "dispatcher", req.request_id, "received",
            ",\"called\":\"%s\",\"calling\":\"%s\"",
            req.called_msisdn, req.calling_msisdn);

        if (dedup_check_and_set(req.request_id)) {
            LOG(OBD_LOG_DEBUG, "dispatcher", req.request_id, "dedup_drop", "");
            continue;
        }

        int w = -1;
        time_t current_time = time(NULL);

        /* O(1) round-robin: atomic increment wraps across all workers.
         * Skip circuit-open or dead workers with a bounded retry. */
        for (int attempt = 0; attempt < OBD_NUM_WORKERS; attempt++) {
            int idx = (int)(atomic_fetch_add(&g_next_worker, 1) % OBD_NUM_WORKERS);
            if (atomic_load(&g_worker_circuit_open[idx])) continue;
            if (g_worker_pids[idx] > 0 &&
                current_time - g_worker_heartbeat[idx] <= OBD_WATCHDOG_TIMEOUT) {
                w = idx;
                break;
            }
        }

        if (w != -1) {
            ssize_t sent = send(g_worker_socks[w], &req, sizeof(req), MSG_DONTWAIT);
            if (sent > 0) {
                atomic_fetch_add(&g_worker_inflight[w], 1);
                atomic_store(&g_worker_fail_count[w], 0);
                atomic_fetch_add(&g_routed_total, 1);
                LOG(OBD_LOG_INFO, "dispatcher", req.request_id, "routed",
                    ",\"worker\":%d", w);
            } else {
                int err = errno;
                int fails = atomic_fetch_add(&g_worker_fail_count[w], 1) + 1;
                atomic_fetch_add(&g_drop_total, 1);
                LOG(OBD_LOG_WARN, "dispatcher", req.request_id, "route_failed",
                    ",\"worker\":%d,\"errno\":%d,\"reason\":\"%s\",\"failures\":%d",
                    w, err, strerror(err), fails);
                if (fails >= CB_MAX_FAILURES) trip_circuit_breaker(w);
            }
        } else {
            atomic_fetch_add(&g_drop_total, 1);
            LOG(OBD_LOG_WARN, "dispatcher", req.request_id, "no_workers_available", "");
        }
    }
    return NULL;
}

/* ================================================================== */
/* dispatcher_run                                                      */
/* ================================================================== */
void dispatcher_run(const char *local_ip, int listen_port,
                    const char *report_ip, int report_port,
                    const WorkerConfig *worker_cfgs,
                    const pid_t *worker_pids)
{
    int use_mux;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Init worker tracking with initial boot grace period */
    time_t now = time(NULL);
    for (int i = 0; i < OBD_NUM_WORKERS; i++) {
        g_worker_cfgs[i] = worker_cfgs[i];
        g_worker_pids[i] = worker_pids ? worker_pids[i] : 0;
        atomic_store(&g_worker_inflight[i], 0);
        /* Pad the initial heartbeat so the watchdog grants them initialization time */
        g_worker_heartbeat[i] = now + (OBD_WATCHDOG_INIT_TIMEOUT - OBD_WATCHDOG_TIMEOUT);
    }
    g_heartbeat_port = g_worker_cfgs[0].heartbeat_port;
    use_mux = dispatcher_use_mux();

    /* Initialize per-worker mutexes and circuit breaker state */
    for (int i = 0; i < OBD_NUM_WORKERS; i++) {
        pthread_mutex_init(&g_sock_lock[i], NULL);
        atomic_store(&g_worker_fail_count[i], 0);
        atomic_store(&g_worker_circuit_open[i], 0);
        g_worker_circuit_trip_time[i] = 0;
    }

    /* Create Unix DGRAM sockets to workers with retry for startup race (Issue 2) */
    for (int i = 0; i < OBD_NUM_WORKERS; i++) {
        g_worker_socks[i] = socket(AF_UNIX, SOCK_DGRAM, 0);
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        snprintf(addr.sun_path, sizeof(addr.sun_path), "/tmp/obd_worker_%d.sock", i);

        int connected = 0;
        for (int retry = 0; retry < 50; retry++) {
            if (connect(g_worker_socks[i], (struct sockaddr *)&addr, sizeof(addr)) == 0) {
                connected = 1;
                break;
            }
            usleep(100000); /* 100ms retry — wait for worker to bind */
        }
        if (!connected) {
            LOG(OBD_LOG_ERROR, "dispatcher", "", "worker_socket_connect_failed",
                ",\"worker\":%d,\"path\":\"%s\",\"reason\":\"%s\"",
                i, addr.sun_path, strerror(errno));
            trip_circuit_breaker(i);
        }
    }

    /* Initialize the SIP-MUX table only when carrier traffic is shared on one SIP port */
    if (use_mux)
        mux_init();

    sem_init(&g_pktq_sem, 0, 0);  /* routing threads block here when queue empty */

    /* Heap-allocate pktq slots — 524288 * 512 = 256MB on heap, not BSS */
    g_pktq.slots = calloc(PKTQ_SIZE, sizeof(RawPkt));
    if (!g_pktq.slots) {
        LOG(OBD_LOG_ERROR, "dispatcher", "", "pktq_alloc_failed",
            ",\"slots\":%d,\"slot_bytes\":%zu", PKTQ_SIZE, sizeof(RawPkt));
        exit(1);
    }
    atomic_store(&g_pktq.head, 0);
    atomic_store(&g_pktq.tail, 0);

    /* Init dedup (OPT8) */
    dedup_init();

    /* Start watchdog thread, heartbeat receiver, and optionally the SIP MUX thread */
    pthread_t wd_tid, hb_tid, mux_tid;
    pthread_create(&wd_tid, NULL, watchdog_thread, NULL);
    pthread_create(&hb_tid, NULL, heartbeat_recv_thread, NULL);
    if (use_mux) {
        pthread_create(&mux_tid, NULL, sip_mux_thread, NULL);
    } else {
        LOG(OBD_LOG_INFO, "dispatcher", "", "mux_disabled", ",\"mode\":\"worker_ports\"");
    }

    /* Bind UDP listen socket for JSON requests on port 9090 */
    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    /* SO_REUSEPORT (OPT6) */
    int reuse = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
#ifdef SO_REUSEPORT
    setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
#endif

    /* Large recv buffer */
    int rcvbuf = 16 * 1024 * 1024;
    setsockopt(sock, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(listen_port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        LOG(OBD_LOG_ERROR, "dispatcher", "", "listen_bind_failed",
            ",\"port\":%d,\"reason\":\"%s\"",
            listen_port, strerror(errno));
        exit(1);
    }

    LOG(OBD_LOG_INFO, "dispatcher", "", "listening",
        ",\"bind_ip\":\"%s\",\"port\":%d,\"report_ip\":\"%s\",\"report_port\":%d,\"heartbeat_port\":%d,\"workers\":%d,\"use_mux\":\"%s\",\"advertised_sip_port\":%d",
        local_ip && local_ip[0] ? local_ip : "0.0.0.0",
        listen_port, report_ip, report_port, g_heartbeat_port, OBD_NUM_WORKERS,
        use_mux ? "yes" : "no",
        use_mux ? g_worker_cfgs[0].sip_mux_port : g_worker_cfgs[0].sip_port);

    /* Routing threads: count from config (routing_threads=N in obd.conf) */
    int num_route_threads = g_worker_cfgs[0].routing_threads;
    if (num_route_threads < 1)  num_route_threads = 1;
    if (num_route_threads > 64) num_route_threads = 64;
    pthread_t *route_tids = calloc(num_route_threads, sizeof(pthread_t));
    for (int i = 0; i < num_route_threads; i++)
        pthread_create(&route_tids[i], NULL, routing_thread, NULL);
    LOG(OBD_LOG_INFO, "dispatcher", "", "routing_threads_started",
        ",\"count\":%d", num_route_threads);

    /* Fast recv loop: batch-drain with recvmmsg() on Linux, recvfrom() fallback on macOS.
     * Lock-free push to pktq — no mutex on hot path. */
#define RECV_BATCH 64
#ifdef __linux__
    struct mmsghdr msgs[RECV_BATCH];
    struct iovec   iovecs[RECV_BATCH];
    char           bufs[RECV_BATCH][4096];
    struct sockaddr_in src_addrs[RECV_BATCH];

    for (int i = 0; i < RECV_BATCH; i++) {
        iovecs[i].iov_base = bufs[i];
        iovecs[i].iov_len  = sizeof(bufs[i]) - 1;
        msgs[i].msg_hdr.msg_iov        = &iovecs[i];
        msgs[i].msg_hdr.msg_iovlen     = 1;
        msgs[i].msg_hdr.msg_name       = &src_addrs[i];
        msgs[i].msg_hdr.msg_namelen    = sizeof(src_addrs[i]);
        msgs[i].msg_hdr.msg_control    = NULL;
        msgs[i].msg_hdr.msg_controllen = 0;
        msgs[i].msg_hdr.msg_flags      = 0;
    }

    while (g_running) {
        int count = recvmmsg(sock, msgs, RECV_BATCH, MSG_WAITFORONE, NULL);
        if (count <= 0) {
            if (errno == EINTR) continue;
            break;
        }
        for (int i = 0; i < count; i++) {
            int len = (int)msgs[i].msg_len;
            bufs[i][len] = '\0';
            if (pktq_push(bufs[i], len) != 0)
                atomic_fetch_add(&g_pktq_dropped, 1);
            msgs[i].msg_hdr.msg_namelen = sizeof(src_addrs[i]);
        }
    }
#else
    char buf[4096];
    while (g_running) {
        ssize_t n = recvfrom(sock, buf, sizeof(buf) - 1, 0, NULL, NULL);
        if (n <= 0) {
            if (errno == EINTR) continue;
            break;
        }
        buf[n] = '\0';
        if (pktq_push(buf, (int)n) != 0)
            atomic_fetch_add(&g_pktq_dropped, 1);
    }
#endif

    /* Cleanup */
    close(sock);
    /* Wake all routing threads so they can exit */
    for (int i = 0; i < num_route_threads; i++)
        sem_post(&g_pktq_sem);
    sem_destroy(&g_pktq_sem);
    free(g_pktq.slots);
    free(route_tids);
    for (int i = 0; i < OBD_NUM_WORKERS; i++)
        close(g_worker_socks[i]);
    dedup_cleanup();
    stop_all_workers();
    if (use_mux)
        mux_cleanup(); /* Clear spinlocks and clean memory maps */

    LOG(OBD_LOG_INFO, "dispatcher", "", "stopped", "");
}
