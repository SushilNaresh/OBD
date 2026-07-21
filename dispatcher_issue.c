/*
 * dispatcher.c — UDP recv, JSON parse, dedup, least-loaded routing, watchdog
 */
#define _GNU_SOURCE
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
#include "obd.h"

static volatile sig_atomic_t g_running = 1;
static _Atomic int g_worker_inflight[OBD_NUM_WORKERS];
static int g_next_worker = 0;
static int g_worker_socks[OBD_NUM_WORKERS];
static pid_t g_worker_pids[OBD_NUM_WORKERS];
static time_t g_worker_heartbeat[OBD_NUM_WORKERS];
static char g_local_ip[64];
static char g_report_ip[64];
static int  g_report_port;

static void sig_handler(int sig) { (void)sig; g_running = 0; }

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

/* Pick least-loaded worker */
static int pick_worker(void)
{
    int best = 0, best_load = atomic_load(&g_worker_inflight[0]);
    for (int i = 1; i < OBD_NUM_WORKERS; i++) {
        int load = atomic_load(&g_worker_inflight[i]);
        if (load < best_load) {
            best = i;
            best_load = load;
        }
    }
    return best;
}

/* Watchdog thread (OPT7) */
static void *watchdog_thread(void *arg)
{
    (void)arg;
    while (g_running) {
        sleep(OBD_WATCHDOG_INTERVAL);
        time_t now = time(NULL);
        for (int i = 0; i < OBD_NUM_WORKERS; i++) {
            if (now - g_worker_heartbeat[i] > OBD_WATCHDOG_TIMEOUT) {
                LOG("dispatcher", "", "worker_dead",
                    ",\"worker\":%d,\"action\":\"restart\"", i);

                /* Kill and restart */
                if (g_worker_pids[i] > 0) {
                    kill(g_worker_pids[i], SIGKILL);
                    waitpid(g_worker_pids[i], NULL, 0);
                }

                /* Re-fork */
                pid_t pid = fork();
                if (pid == 0) {
                    WorkerConfig wcfg;
                    memset(&wcfg, 0, sizeof(wcfg));
                    wcfg.worker_id = i;
                    wcfg.sip_port  = OBD_SIP_PORT_BASE + i;
                    wcfg.cpu_core  = i;
                    wcfg.report_port = g_report_port;
                    strncpy(wcfg.local_ip, g_local_ip, sizeof(wcfg.local_ip) - 1);
                    strncpy(wcfg.report_ip, g_report_ip, sizeof(wcfg.report_ip) - 1);
#ifdef __linux__
                    cpu_set_t cpuset;
                    CPU_ZERO(&cpuset);
                    CPU_SET(i % sysconf(_SC_NPROCESSORS_ONLN), &cpuset);
                    sched_setaffinity(0, sizeof(cpuset), &cpuset);
#endif
                    worker_run(&wcfg);
                    _exit(0);
                }
                g_worker_pids[i] = pid;
                g_worker_heartbeat[i] = now;
                atomic_store(&g_worker_inflight[i], 0);

                LOG("dispatcher", "", "worker_restarted",
                    ",\"worker\":%d,\"pid\":%d", i, pid);
            }
        }
    }
    return NULL;
}

/* Heartbeat receiver thread */
static void *heartbeat_recv_thread(void *arg)
{
    (void)arg;
    /* Create heartbeat UDP socket */
    int hb_sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in hb_addr;
    memset(&hb_addr, 0, sizeof(hb_addr));
    hb_addr.sin_family = AF_INET;
    hb_addr.sin_port = htons(OBD_UDP_LISTEN_PORT + 1000);  /* heartbeat port */
    hb_addr.sin_addr.s_addr = INADDR_ANY;
    bind(hb_sock, (struct sockaddr *)&hb_addr, sizeof(hb_addr));

    char buf[64];
    while (g_running) {
        struct sockaddr_in src;
        socklen_t slen = sizeof(src);
        ssize_t n = recvfrom(hb_sock, buf, sizeof(buf) - 1, 0,
                             (struct sockaddr *)&src, &slen);
        if (n > 0) {
            buf[n] = '\0';
            int wid = atoi(buf);
            if (wid >= 0 && wid < OBD_NUM_WORKERS)
                g_worker_heartbeat[wid] = time(NULL);
        }
    }
    close(hb_sock);
    return NULL;
}

void dispatcher_run(const char *local_ip, int listen_port,
                    const char *report_ip, int report_port)
{
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    strncpy(g_local_ip, local_ip ? local_ip : "", sizeof(g_local_ip) - 1);
    strncpy(g_report_ip, report_ip, sizeof(g_report_ip) - 1);
    g_report_port = report_port;

    /* Init worker tracking */
    time_t now = time(NULL);
    for (int i = 0; i < OBD_NUM_WORKERS; i++) {
        atomic_store(&g_worker_inflight[i], 0);
        g_worker_heartbeat[i] = now;
    }

    /* Create Unix DGRAM sockets to workers */
    for (int i = 0; i < OBD_NUM_WORKERS; i++) {
        g_worker_socks[i] = socket(AF_UNIX, SOCK_DGRAM, 0);
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        snprintf(addr.sun_path, sizeof(addr.sun_path), "/tmp/obd_worker_%d.sock", i);
        /* Connect so we can use send() */
        connect(g_worker_socks[i], (struct sockaddr *)&addr, sizeof(addr));
    }

    /* Init dedup (OPT8) */
    dedup_init();

    /* Start watchdog thread (OPT7) */
    pthread_t wd_tid, hb_tid;
    pthread_create(&wd_tid, NULL, watchdog_thread, NULL);
    pthread_create(&hb_tid, NULL, heartbeat_recv_thread, NULL);

    /* Bind UDP listen socket */
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
        perror("dispatcher bind");
        exit(1);
    }

    LOG("dispatcher", "", "listening",
        ",\"port\":%d,\"workers\":%d", listen_port, OBD_NUM_WORKERS);

    /* Main recv loop */
    char buf[4096];
    while (g_running) {
        struct sockaddr_in src;
        socklen_t slen = sizeof(src);
        ssize_t n = recvfrom(sock, buf, sizeof(buf) - 1, 0,
                             (struct sockaddr *)&src, &slen);
        if (n <= 0) {
            if (errno == EINTR) continue;
            break;
        }
        buf[n] = '\0';

        /* Parse JSON */
        OBDRequest req;
        memset(&req, 0, sizeof(req));
        req.timeout_sec = OBD_DEFAULT_TIMEOUT;

        json_get(buf, "callingMSISDN", req.calling_msisdn, sizeof(req.calling_msisdn));
        json_get(buf, "calledMSISDN", req.called_msisdn, sizeof(req.called_msisdn));
        json_get(buf, "requestId", req.request_id, sizeof(req.request_id));
        json_get(buf, "destID", req.dest_id, sizeof(req.dest_id));

        char timeout_str[16] = "";
        if (json_get(buf, "timeout", timeout_str, sizeof(timeout_str)) == 0 && timeout_str[0])
            req.timeout_sec = atoi(timeout_str);

        if (!req.called_msisdn[0] || !req.request_id[0]) continue;

        /* Dedup check (OPT8) */
        if (dedup_check_and_set(req.request_id)) {
            LOG("dispatcher", req.request_id, "dedup_drop", "");
            continue;
        }

        /* Route to next worker (round-robin) */
        int w = g_next_worker;
        g_next_worker = (g_next_worker + 1) % OBD_NUM_WORKERS;
        ssize_t sent = send(g_worker_socks[w], &req, sizeof(req), MSG_DONTWAIT);
        if (sent > 0) {
            LOG("dispatcher", req.request_id, "routed", ",\"worker\":%d", w);
        } else {
            LOG("dispatcher", req.request_id, "route_failed", ",\"worker\":%d", w);
        }
    }

    /* Cleanup */
    close(sock);
    for (int i = 0; i < OBD_NUM_WORKERS; i++)
        close(g_worker_socks[i]);
    dedup_cleanup();

    LOG("dispatcher", "", "stopped", "");
}
