/*
 * udp_report.c — Send UDP JSON reports to B
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "obd.h"

static int g_report_sock = -1;
static struct sockaddr_in g_report_addr;

void udp_report_init(const char *report_ip, int report_port)
{
    g_report_sock = socket(AF_INET, SOCK_DGRAM, 0);
    memset(&g_report_addr, 0, sizeof(g_report_addr));
    g_report_addr.sin_family = AF_INET;
    g_report_addr.sin_port   = htons(report_port);
    inet_pton(AF_INET, report_ip, &g_report_addr.sin_addr);
}

void udp_report_send(const OBDReport *report)
{
    char buf[512];
    time_t now = time(NULL);
    struct tm *tm_info = gmtime(&now);
    char ts_buf[32];
    strftime(ts_buf, sizeof(ts_buf), "%Y-%m-%dT%H:%M:%SZ", tm_info);

    /* Map outcome to deliveryStatus */
    const char *status;
    switch (report->outcome) {
        case OUTCOME_MISSED_CALL:  status = "SUCCESS";       break;  /* 180 ringing + CANCEL + 487 */
        case OUTCOME_NO_ANSWER:    status = "SUCCESS";       break;  /* 183 only + CANCEL + 487 — network delivered */
        case OUTCOME_CF_MCA:       status = "SUCCESS";       break;  /* 200 OK — MCA answered */
        case OUTCOME_BUSY:         status = "FAILED";        break;  /* 486/600 */
        case OUTCOME_REJECTED:     status = "FAILED";        break;  /* 603 */
        case OUTCOME_CF_NUMBER:    status = "FAILED";        break;  /* 181/302 forwarded */
        case OUTCOME_UNAVAILABLE:  status = "NOT_REACHABLE"; break;  /* 480 */
        case OUTCOME_UNREACHABLE:  status = "NOT_REACHABLE"; break;  /* 408/487 no progress */
        case OUTCOME_NETWORK_DOWN: status = "NOT_REACHABLE"; break;  /* 503/504/internal */
        default:                   status = "NOT_REACHABLE"; break;  /* UNKNOWN — safe default */
    }

    snprintf(buf, sizeof(buf),
             "{\"requestId\":\"%s\",\"calledMsisdn\":\"%s\",\"deliveryStatus\":\"%s\",\"deliveryTimestamp\":\"%s\"}",
             report->request_id, report->called_msisdn, status, ts_buf);

    sendto(g_report_sock, buf, strlen(buf), 0,
           (struct sockaddr *)&g_report_addr, sizeof(g_report_addr));
}

void udp_report_shutdown(void)
{
    if (g_report_sock >= 0) {
        close(g_report_sock);
        g_report_sock = -1;
    }
}
