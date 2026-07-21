/*
 * Version: 2.0.7
 * main.c — OBD Service entry point
 * Forks N worker processes, assigns CPU cores, becomes dispatcher.
 * Multi-IP: workers distributed across 127.0.0.1–127.0.0.10 by worker_id % 10.
 * Preflight validates each local IP exists on the machine before forking.
 */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sched.h>
#include "obd.h"

static int g_sip_log_level = 0;   /* default silent */
static char g_report_ip[64]  = "127.0.0.1";
static int  g_report_port    = 9100;
static char g_local_ip[64]      = "";   /* worker SIP bind IP */
static char g_rtp_ip[64]        = "";   /* RTP bind IP; empty = loopback pool 127.0.0.1-10 */
static char g_dispatcher_ip[64] = "";   /* dispatcher UDP recv bind IP; empty = 0.0.0.0 */
static int  g_routing_threads = OBD_ROUTING_THREADS;
static int  g_listen_port    = OBD_UDP_LISTEN_PORT;
static int  g_heartbeat_port = -1;
static int  g_sip_port_base  = OBD_SIP_PORT_BASE;
static int  g_sip_mux_port   = OBD_SIP_MUX_PORT;
static int  g_proxy_port     = OBD_PROXY_PORT_DEFAULT;
static int  g_sip_t1_ms      = OBD_SIP_T1_MS;
static int  g_sip_t2_ms      = OBD_SIP_T2_MS;
static int  g_rtp_base_port  = OBD_RTP_BASE;
static int  g_cancel_ring_ms = OBD_CANCEL_RING_MS;
static char g_require_100rel[16] = "yes";
static char g_default_proxy[64] = "102.89.52.50";
static char g_use_rtp[8] = "yes";
static char g_use_mux[8] = "yes";
static char g_log_file[OBD_LOG_FILE_MAX] = "";
static int  g_log_rotate_size_mb = OBD_LOG_ROTATE_SIZE / (1024 * 1024);  /* in MB for config */
static int  g_log_rotate_count = OBD_LOG_ROTATE_COUNT;
static int  g_obd_log_level = OBD_LOG_TRACE;  /* default: emit everything */

static char *trim_ws(char *s)
{
    char *end;

    while (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')
        s++;

    end = s + strlen(s);
    while (end > s && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r' || end[-1] == '\n'))
        *--end = '\0';

    return s;
}

static int parse_positive_int(const char *text, int *out, int max_value)
{
    char *end;
    long value;

    errno = 0;
    value = strtol(text, &end, 10);
    end = trim_ws(end);
    if (errno != 0 || end == text || *end != '\0' || value <= 0 || value > max_value)
        return -1;

    *out = (int)value;
    return 0;
}

static int parse_port_value(const char *text, int *out)
{
    return parse_positive_int(text, out, 65535);
}

static int apply_config_kv(const char *key, const char *value)
{
    if (strcmp(key, "report_ip") == 0) {
        strncpy(g_report_ip, value, sizeof(g_report_ip) - 1);
    } else if (strcmp(key, "report_port") == 0) {
        return parse_port_value(value, &g_report_port);
    } else if (strcmp(key, "local_ip") == 0) {
        strncpy(g_local_ip, value, sizeof(g_local_ip) - 1);
    } else if (strcmp(key, "rtp_ip") == 0) {
        strncpy(g_rtp_ip, value, sizeof(g_rtp_ip) - 1);
    } else if (strcmp(key, "dispatcher_ip") == 0) {
        strncpy(g_dispatcher_ip, value, sizeof(g_dispatcher_ip) - 1);
    } else if (strcmp(key, "listen_port") == 0) {
        return parse_port_value(value, &g_listen_port);
    } else if (strcmp(key, "routing_threads") == 0) {
        return parse_positive_int(value, &g_routing_threads, 64);
    } else if (strcmp(key, "heartbeat_port") == 0) {
        return parse_port_value(value, &g_heartbeat_port);
    } else if (strcmp(key, "sip_port_base") == 0) {
        return parse_port_value(value, &g_sip_port_base);
    } else if (strcmp(key, "sip_mux_port") == 0) {
        return parse_port_value(value, &g_sip_mux_port);
    } else if (strcmp(key, "proxy_port") == 0) {
        return parse_port_value(value, &g_proxy_port);
    } else if (strcmp(key, "sip_t1_ms") == 0) {
        return parse_positive_int(value, &g_sip_t1_ms, INT_MAX);
    } else if (strcmp(key, "sip_t2_ms") == 0) {
        return parse_positive_int(value, &g_sip_t2_ms, INT_MAX);
    } else if (strcmp(key, "rtp_base_port") == 0) {
        return parse_port_value(value, &g_rtp_base_port);
    } else if (strcmp(key, "require_100rel") == 0) {
        strncpy(g_require_100rel, value, sizeof(g_require_100rel) - 1);
    } else if (strcmp(key, "default_proxy") == 0) {
        strncpy(g_default_proxy, value, sizeof(g_default_proxy) - 1);
    } else if (strcmp(key, "use_rtp") == 0) {
        strncpy(g_use_rtp, value, sizeof(g_use_rtp) - 1);
    } else if (strcmp(key, "use_mux") == 0) {
        strncpy(g_use_mux, value, sizeof(g_use_mux) - 1);
    } else if (strcmp(key, "sip_log_level") == 0) {
        return parse_positive_int(value, &g_sip_log_level, 6);
    } else if (strcmp(key, "cancel_ring_ms") == 0) {
        return parse_positive_int(value, &g_cancel_ring_ms, INT_MAX);
    } else if (strcmp(key, "log_file") == 0) {
        strncpy(g_log_file, value, sizeof(g_log_file) - 1);
    } else if (strcmp(key, "log_rotate_size_mb") == 0) {
        return parse_positive_int(value, &g_log_rotate_size_mb, 10240);
    } else if (strcmp(key, "log_rotate_count") == 0) {
        return parse_positive_int(value, &g_log_rotate_count, 100);
    } else if (strcmp(key, "obd_log_level") == 0) {
        return parse_positive_int(value, &g_obd_log_level, OBD_LOG_TRACE);
    } else {
        return -1;
    }

    return 0;
}

static int load_config_file(const char *path)
{
    FILE *fp = fopen(path, "r");
    char line[512];
    int line_no = 0;

    if (!fp) {
        fprintf(stderr, "failed to open config file %s: %s\n", path, strerror(errno));
        return -1;
    }

    while (fgets(line, sizeof(line), fp)) {
        char *key;
        char *value;
        char *eq;
        char *comment;

        line_no++;
        key = trim_ws(line);
        if (!key[0] || key[0] == '#')
            continue;

        eq = strchr(key, '=');
        if (!eq) {
            fprintf(stderr, "invalid config line %d in %s: missing '='\n", line_no, path);
            fclose(fp);
            return -1;
        }

        *eq = '\0';
        value = trim_ws(eq + 1);
        comment = strchr(value, '#');
        if (comment) {
            *comment = '\0';
            value = trim_ws(value);
        }
        key = trim_ws(key);

        if (apply_config_kv(key, value) != 0) {
            fprintf(stderr, "invalid config entry %s=%s on line %d in %s\n", key, value, line_no, path);
            fclose(fp);
            return -1;
        }
    }

    fclose(fp);
    return 0;
}

static void finalize_runtime_config(void)
{
    if (g_heartbeat_port <= 0)
        g_heartbeat_port = g_listen_port + OBD_HEARTBEAT_PORT_OFFSET;
}

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

/* Verify a local IP exists on this machine by attempting a test bind.
 * Returns 0 if OK, -1 if the IP is missing or invalid. */
static int verify_local_ip(const char *ip, char *reason, size_t reason_sz)
{
    struct in_addr addr;
    if (inet_pton(AF_INET, ip, &addr) != 1) {
        snprintf(reason, reason_sz, "invalid IPv4 address format");
        return -1;
    }

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        snprintf(reason, reason_sz, "socket: %s", strerror(errno));
        return -1;
    }

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_addr        = addr;
    sa.sin_port        = 0;   /* any port — we just want to confirm the IP exists */

    if (bind(sock, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        snprintf(reason, reason_sz, "%s", strerror(errno));
        close(sock);
        return -1;
    }

    close(sock);
    reason[0] = '\0';
    return 0;
}

/* Assign RTP bind IP for a given worker.
 * If rtp_ip is explicitly set, all workers use it.
 * Otherwise distribute across 127.0.0.1–127.0.0.10 by worker_id % 10. */
static void assign_worker_rtp_ip(int worker_id, char *out, size_t out_sz)
{
    if (g_rtp_ip[0]) {
        strncpy(out, g_rtp_ip, out_sz - 1);
        out[out_sz - 1] = '\0';
        return;
    }
    snprintf(out, out_sz, "127.0.0.%d", (worker_id / (OBD_NUM_WORKERS / OBD_NUM_LOCAL_IPS)) + 1);
}

static void build_worker_cfg(WorkerConfig *wcfg, int worker_id)
{
    memset(wcfg, 0, sizeof(*wcfg));
    wcfg->worker_id = worker_id;
    wcfg->routing_threads = g_routing_threads;
    wcfg->sip_port_base = g_sip_port_base;
    wcfg->sip_port = g_sip_port_base + worker_id;
    wcfg->sip_mux_port = g_sip_mux_port;
    wcfg->proxy_port = g_proxy_port;
    wcfg->heartbeat_port = g_heartbeat_port;
    wcfg->rtp_base_port = g_rtp_base_port;
    wcfg->cpu_core = worker_id;
    wcfg->report_port = g_report_port;
    wcfg->sip_t1_ms = g_sip_t1_ms;
    wcfg->sip_t2_ms = g_sip_t2_ms;
    wcfg->sip_log_level = g_sip_log_level;
    wcfg->cancel_ring_ms = g_cancel_ring_ms;
    strncpy(wcfg->local_ip, g_local_ip, sizeof(wcfg->local_ip) - 1);
    assign_worker_rtp_ip(worker_id, wcfg->rtp_ip, sizeof(wcfg->rtp_ip));
    strncpy(wcfg->report_ip, g_report_ip, sizeof(wcfg->report_ip) - 1);
    strncpy(wcfg->require_100rel, g_require_100rel, sizeof(wcfg->require_100rel) - 1);
    strncpy(wcfg->default_proxy, g_default_proxy, sizeof(wcfg->default_proxy) - 1);
    strncpy(wcfg->use_rtp, g_use_rtp, sizeof(wcfg->use_rtp) - 1);
    strncpy(wcfg->use_mux, g_use_mux, sizeof(wcfg->use_mux) - 1);
    strncpy(wcfg->log_file, g_log_file, sizeof(wcfg->log_file) - 1);
}

static pid_t spawn_worker(const WorkerConfig *wcfg)
{
    pid_t pid = fork();
    if (pid == 0) {
        WorkerConfig child_cfg = *wcfg;
        set_worker_affinity(child_cfg.cpu_core);
        worker_run(&child_cfg);
        _exit(0);
    }
    return pid;
}

static int preflight_udp_bind(const char *bind_ip, int port, char *reason, size_t reason_sz)
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        snprintf(reason, reason_sz, "%s", strerror(errno));
        return -1;
    }

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (bind_ip && bind_ip[0]) {
        if (inet_pton(AF_INET, bind_ip, &addr.sin_addr) != 1) {
            close(sock);
            snprintf(reason, reason_sz, "invalid IPv4 bind address");
            return -1;
        }
    } else {
        addr.sin_addr.s_addr = INADDR_ANY;
    }

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        snprintf(reason, reason_sz, "%s", strerror(errno));
        close(sock);
        return -1;
    }

    close(sock);
    reason[0] = '\0';
    return 0;
}

static int startup_preflight(const WorkerConfig *worker_cfgs)
{
    char reason[128];

    /* Verify each unique local IP exists on this machine before forking any worker.
     * Checks 127.0.0.1–127.0.0.10 (or just g_local_ip if explicitly set). */
    /* Verify SIP bind IP if set */
    if (g_local_ip[0]) {
        if (verify_local_ip(g_local_ip, reason, sizeof(reason)) != 0) {
            LOG(OBD_LOG_ERROR, "main", "", "local_ip_missing",
                ",\"ip\":\"%s\",\"reason\":\"%s\"",
                g_local_ip, reason);
            fprintf(stderr, "ERROR: local_ip %s is not configured on this machine: %s\n",
                    g_local_ip, reason);
            return -1;
        }
        LOG(OBD_LOG_INFO, "main", "", "local_ip_verified",
            ",\"ip\":\"%s\",\"role\":\"sip\"", g_local_ip);
    }

    /* Verify RTP bind IPs */
    if (g_rtp_ip[0]) {
        if (verify_local_ip(g_rtp_ip, reason, sizeof(reason)) != 0) {
            LOG(OBD_LOG_ERROR, "main", "", "rtp_ip_missing",
                ",\"ip\":\"%s\",\"reason\":\"%s\"",
                g_rtp_ip, reason);
            fprintf(stderr, "ERROR: rtp_ip %s is not configured on this machine: %s\n",
                    g_rtp_ip, reason);
            return -1;
        }
        LOG(OBD_LOG_INFO, "main", "", "rtp_ip_verified",
            ",\"ip\":\"%s\",\"mode\":\"single\"", g_rtp_ip);
    } else {
        /* Multi-IP RTP pool: verify all 10 loopback IPs exist */
        int missing = 0;
        for (int idx = 0; idx < OBD_NUM_LOCAL_IPS; idx++) {
            char ip[32];
            snprintf(ip, sizeof(ip), "127.0.0.%d", idx + 1);
            if (verify_local_ip(ip, reason, sizeof(reason)) != 0) {
                LOG(OBD_LOG_ERROR, "main", "", "rtp_ip_missing",
                    ",\"ip\":\"%s\",\"index\":%d,\"reason\":\"%s\"",
                    ip, idx, reason);
                fprintf(stderr, "ERROR: RTP IP %s not found on this machine: %s\n"
                                "Run: ip addr add %s/8 dev lo\n",
                        ip, reason, ip);
                missing++;
            } else {
                LOG(OBD_LOG_INFO, "main", "", "rtp_ip_verified",
                    ",\"ip\":\"%s\",\"index\":%d,\"workers_on_ip\":%d",
                    ip, idx, OBD_NUM_WORKERS / OBD_NUM_LOCAL_IPS);
            }
        }
        if (missing > 0) {
            fprintf(stderr, "ERROR: %d RTP IP(s) missing. Add them with:\n", missing);
            fprintf(stderr, "  for i in $(seq 2 10); do ip addr add 127.0.0.$i/8 dev lo; done\n");
            return -1;
        }
    }

    if (preflight_udp_bind("", g_listen_port, reason, sizeof(reason)) != 0) {
        LOG(OBD_LOG_ERROR, "main", "", "startup_port_conflict",
            ",\"scope\":\"dispatcher\",\"bind_ip\":\"0.0.0.0\",\"port\":%d,\"reason\":\"%s\"",
            g_listen_port, reason);
        return -1;
    }

    if (preflight_udp_bind("", worker_cfgs[0].heartbeat_port, reason, sizeof(reason)) != 0) {
        LOG(OBD_LOG_ERROR, "main", "", "startup_port_conflict",
            ",\"scope\":\"heartbeat\",\"bind_ip\":\"0.0.0.0\",\"port\":%d,\"reason\":\"%s\"",
            worker_cfgs[0].heartbeat_port, reason);
        return -1;
    }

    for (int i = 0; i < OBD_NUM_WORKERS; i++) {
        const char *bind_ip = worker_cfgs[i].local_ip[0] ? worker_cfgs[i].local_ip : "0.0.0.0";
        if (preflight_udp_bind(worker_cfgs[i].local_ip, worker_cfgs[i].sip_port,
                               reason, sizeof(reason)) != 0) {
            LOG(OBD_LOG_ERROR, "main", "", "startup_port_conflict",
                ",\"scope\":\"worker_sip\",\"worker\":%d,\"bind_ip\":\"%s\",\"port\":%d,\"reason\":\"%s\"",
                i, bind_ip, worker_cfgs[i].sip_port, reason);
            return -1;
        }
    }

    if (worker_cfg_use_mux(&worker_cfgs[0]) &&
        preflight_udp_bind("", g_sip_mux_port, reason, sizeof(reason)) != 0) {
        LOG(OBD_LOG_ERROR, "main", "", "startup_port_conflict",
            ",\"scope\":\"sip_mux\",\"bind_ip\":\"0.0.0.0\",\"port\":%d,\"reason\":\"%s\"",
            g_sip_mux_port, reason);
        return -1;
    }

    return 0;
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s --config <path>\n"
        "       %s <report_ip> <report_port> [local_ip] [listen_port] [require_100rel] [default_proxy] [use_rtp] [use_mux]\n\n"
        "Config file format: key=value, one setting per line.\n"
        "Common keys: report_ip, report_port, local_ip, listen_port, heartbeat_port,\n"
        "             sip_port_base, sip_mux_port, proxy_port, sip_t1_ms, sip_t2_ms,\n"
        "             rtp_base_port, require_100rel, default_proxy, use_rtp, use_mux,\n"
        "             log_file.\n\n"
        "  report_ip      : B's IP address for UDP reports\n"
        "  report_port    : B's UDP port\n"
        "  local_ip       : (optional) Local NIC IP to bind\n"
        "  listen_port    : (optional) UDP recv port [%d]\n"
        "  require_100rel : (optional) 'yes' (default) or 'no'\n"
        "  default_proxy  : (optional) Default SIP proxy [102.89.52.50]\n"
        "  use_rtp        : (optional) 'yes' (default) or 'no' — no means RTP recvonly\n"
        "  use_mux        : (optional) 'yes' (default) or 'no' — share public SIP port %d\n"
        "  log_file       : (optional) Application/PJSIP log file path; empty logs to stdout\n\n"
        "Build-time config:\n"
        "  Workers: %d, Calls/worker: %d, Total: %d\n"
        "  Default ports: listen=%d, sip_base=%d, mux=%d, proxy=%d, rtp_base=%d\n",
        prog, prog, OBD_UDP_LISTEN_PORT, OBD_SIP_MUX_PORT,
        OBD_NUM_WORKERS, OBD_CALLS_PER_WORKER,
        OBD_NUM_WORKERS * OBD_CALLS_PER_WORKER,
        OBD_UDP_LISTEN_PORT, OBD_SIP_PORT_BASE, OBD_SIP_MUX_PORT,
        OBD_PROXY_PORT_DEFAULT, OBD_RTP_BASE);
    exit(1);
}

int main(int argc, char *argv[])
{
    WorkerConfig worker_cfgs[OBD_NUM_WORKERS];
    pid_t worker_pids[OBD_NUM_WORKERS];

    if (argc >= 3 && strcmp(argv[1], "--config") == 0) {
        if (load_config_file(argv[2]) != 0)
            return 1;
    } else {
        if (argc < 3) usage(argv[0]);

        strncpy(g_report_ip, argv[1], sizeof(g_report_ip) - 1);
        g_report_port = atoi(argv[2]);
        if (argc > 3) {
            strncpy(g_local_ip,      argv[3], sizeof(g_local_ip) - 1);
            strncpy(g_dispatcher_ip, argv[3], sizeof(g_dispatcher_ip) - 1);
        }
        if (argc > 4) g_listen_port = atoi(argv[4]);
        if (argc > 5) strncpy(g_require_100rel, argv[5], sizeof(g_require_100rel) - 1);
        if (argc > 6) strncpy(g_default_proxy, argv[6], sizeof(g_default_proxy) - 1);
        if (argc > 7) strncpy(g_use_rtp, argv[7], sizeof(g_use_rtp) - 1);
        if (argc > 8) strncpy(g_use_mux, argv[8], sizeof(g_use_mux) - 1);
    }

    finalize_runtime_config();

    signal(SIGPIPE, SIG_IGN);
    obd_log_init(g_log_file);
    obd_log_set_rotation((size_t)g_log_rotate_size_mb * 1024 * 1024, g_log_rotate_count);
    obd_log_set_level(g_obd_log_level);

    LOG(OBD_LOG_INFO, "main", "", "starting",
        ",\"workers\":%d,\"total_capacity\":%d,\"listen_port\":%d,\"heartbeat_port\":%d"
        ",\"sip_port_base\":%d,\"mux_port\":%d,\"proxy_port\":%d,\"rtp_base_port\":%d"
        ",\"use_mux\":\"%s\",\"dispatcher_ip\":\"%s\",\"sip_ip\":\"%s\",\"rtp_ip_mode\":\"%s\",\"routing_threads\":%d,\"log_file\":\"%s\"",
        OBD_NUM_WORKERS, OBD_NUM_WORKERS * OBD_CALLS_PER_WORKER,
        g_listen_port, g_heartbeat_port, g_sip_port_base, g_sip_mux_port, g_proxy_port,
        g_rtp_base_port, obd_flag_enabled(g_use_mux, 1) ? "yes" : "no",
        g_dispatcher_ip[0] ? g_dispatcher_ip : "0.0.0.0",
        g_local_ip[0] ? g_local_ip : "0.0.0.0",
        g_rtp_ip[0] ? g_rtp_ip : "multi:127.0.0.1-127.0.0.10",
        g_routing_threads,
        obd_log_path() ? obd_log_path() : "stdout");

    for (int i = 0; i < OBD_NUM_WORKERS; i++)
        build_worker_cfg(&worker_cfgs[i], i);

    if (startup_preflight(worker_cfgs) != 0)
        return 1;

    /* Fork workers */
    for (int i = 0; i < OBD_NUM_WORKERS; i++) {
        pid_t pid = spawn_worker(&worker_cfgs[i]);
        if (pid < 0) {
            perror("fork");
            exit(1);
        }
        worker_pids[i] = pid;

        LOG(OBD_LOG_INFO, "main", "", "worker_forked",
            ",\"worker\":%d,\"pid\":%d,\"sip_port\":%d,\"advertised_port\":%d,\"core\":%d,\"use_mux\":\"%s\"",
            i, pid, worker_cfgs[i].sip_port,
            worker_cfg_use_mux(&worker_cfgs[i]) ? worker_cfgs[i].sip_mux_port : worker_cfgs[i].sip_port,
            i, worker_cfg_use_mux(&worker_cfgs[i]) ? "yes" : "no");
    }

    /* Parent — become dispatcher */
    sleep(2);  /* let workers init */
    dispatcher_run(g_dispatcher_ip, g_listen_port, g_report_ip, g_report_port,
                   worker_cfgs, worker_pids);

    return 0;
}
