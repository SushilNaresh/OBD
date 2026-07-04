/*
 * obd_logger.c — process-safe structured JSON logging with date/time and log rotation
 */
#include "obd.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>

static int g_log_fd = STDOUT_FILENO;
static int g_lock_fd = -1;          /* separate lock file — survives log rotation */
static char g_log_path[OBD_LOG_FILE_MAX];
static char g_lock_path[OBD_LOG_FILE_MAX + 8];
static size_t g_log_max_size = OBD_LOG_ROTATE_SIZE;
static int g_log_max_backups = OBD_LOG_ROTATE_COUNT;
static pthread_mutex_t g_log_mutex = PTHREAD_MUTEX_INITIALIZER;

static size_t get_file_size(int fd)
{
    struct stat st;
    if (fstat(fd, &st) == 0)
        return (size_t)st.st_size;
    return 0;
}

static void rotate_logs(void)
{
    char old_path[OBD_LOG_FILE_MAX + 16];
    char new_path[OBD_LOG_FILE_MAX + 16];

    if (!g_log_path[0] || g_log_fd == STDOUT_FILENO || g_log_fd == STDERR_FILENO)
        return;

    /* Close current log */
    close(g_log_fd);
    g_log_fd = -1;

    /* Rotate: remove oldest, shift .N-1 -> .N, ... .1 -> .2, current -> .1 */
    snprintf(old_path, sizeof(old_path), "%s.%d", g_log_path, g_log_max_backups);
    unlink(old_path);

    for (int i = g_log_max_backups - 1; i >= 1; i--) {
        snprintf(old_path, sizeof(old_path), "%s.%d", g_log_path, i);
        snprintf(new_path, sizeof(new_path), "%s.%d", g_log_path, i + 1);
        rename(old_path, new_path);
    }

    snprintf(new_path, sizeof(new_path), "%s.1", g_log_path);
    rename(g_log_path, new_path);

    /* Open fresh log file */
    g_log_fd = open(g_log_path, O_CREAT | O_WRONLY | O_APPEND, 0644);
    if (g_log_fd < 0)
        g_log_fd = STDOUT_FILENO;
}

int obd_log_init(const char *path)
{
    int fd;

    if (!path || !path[0] || strcmp(path, "-") == 0 || strcmp(path, "stdout") == 0) {
        g_log_fd = STDOUT_FILENO;
        g_log_path[0] = '\0';
        return 0;
    }

    fd = open(path, O_CREAT | O_WRONLY | O_APPEND, 0644);
    if (fd < 0) {
        dprintf(STDERR_FILENO, "failed to open log file %s: %s\n", path, strerror(errno));
        g_log_fd = STDOUT_FILENO;
        g_log_path[0] = '\0';
        return -1;
    }

    if (g_log_fd != STDOUT_FILENO && g_log_fd != STDERR_FILENO)
        close(g_log_fd);

    g_log_fd = fd;
    snprintf(g_log_path, sizeof(g_log_path), "%s", path);

    /* Open a dedicated lock file that persists across log rotations.
     * All 800+ worker processes share this lock file for rotation serialization. */
    snprintf(g_lock_path, sizeof(g_lock_path), "%s.lock", path);
    if (g_lock_fd < 0) {
        g_lock_fd = open(g_lock_path, O_CREAT | O_WRONLY, 0644);
    }
    return 0;
}

void obd_log_set_rotation(size_t max_size_bytes, int max_backups)
{
    if (max_size_bytes > 0)
        g_log_max_size = max_size_bytes;
    if (max_backups >= 0)
        g_log_max_backups = max_backups;
}

const char *obd_log_path(void)
{
    return g_log_path[0] ? g_log_path : NULL;
}

void obd_log_close(void)
{
    if (g_log_fd != STDOUT_FILENO && g_log_fd != STDERR_FILENO) {
        close(g_log_fd);
        g_log_fd = STDOUT_FILENO;
    }
    if (g_lock_fd >= 0) {
        close(g_lock_fd);
        g_lock_fd = -1;
    }
    g_log_path[0] = '\0';
}

void obd_log_write_json(const char *file, int line, const char *worker_tag,
                        const char *req_id, const char *event,
                        const char *fmt, ...)
{
    char buf[4096];
    int off;
    va_list ap;
    struct timespec ts;
    struct tm tm_info;
    char datetime[64];

    /* Generate ISO 8601 timestamp with milliseconds: 2025-06-28T14:30:05.123 */
    clock_gettime(CLOCK_REALTIME, &ts);
    localtime_r(&ts.tv_sec, &tm_info);
    int dt_len = (int)strftime(datetime, sizeof(datetime), "%Y-%m-%dT%H:%M:%S", &tm_info);
    snprintf(datetime + dt_len, sizeof(datetime) - (size_t)dt_len, ".%03ld", ts.tv_nsec / 1000000);

    /* Extract just the filename from full path */
    const char *basename = file;
    if (file) {
        const char *slash = strrchr(file, '/');
        if (slash)
            basename = slash + 1;
    }

    off = snprintf(buf, sizeof(buf),
        "{\"dt\":\"%s\",\"file\":\"%s\",\"line\":%d,\"ts\":%ld,\"pid\":%ld,\"w\":\"%s\",\"req\":\"%s\",\"ev\":\"%s\"",
        datetime,
        basename ? basename : "", line, (long)ts.tv_sec, (long)getpid(),
        worker_tag ? worker_tag : "", req_id ? req_id : "", event ? event : "");

    if (off < 0)
        return;

    if ((size_t)off >= sizeof(buf))
        off = (int)sizeof(buf) - 1;

    if (fmt && fmt[0] && (size_t)off < sizeof(buf) - 1) {
        va_start(ap, fmt);
        off += vsnprintf(buf + off, sizeof(buf) - (size_t)off, fmt, ap);
        va_end(ap);

        if (off < 0)
            return;
        if ((size_t)off >= sizeof(buf))
            off = (int)sizeof(buf) - 1;
    }

    if ((size_t)off < sizeof(buf) - 2) {
        buf[off++] = '}';
        buf[off++] = '\n';
        buf[off] = '\0';
    } else {
        buf[sizeof(buf) - 3] = '}';
        buf[sizeof(buf) - 2] = '\n';
        buf[sizeof(buf) - 1] = '\0';
        off = (int)sizeof(buf) - 1;
    }

    size_t len = (size_t)off;

    pthread_mutex_lock(&g_log_mutex);

    /* Check rotation — use dedicated lock file so lock survives log rename.
     * Only one process rotates at a time; others reopen after lock released. */
    if (g_log_max_size > 0 && g_log_path[0] &&
        g_log_fd != STDOUT_FILENO && g_log_fd != STDERR_FILENO &&
        g_lock_fd >= 0) {
        flock(g_lock_fd, LOCK_EX);
        /* Recheck size after acquiring lock — another process may have rotated */
        struct stat st;
        if (fstat(g_log_fd, &st) != 0 || st.st_nlink == 0) {
            /* Our fd was rotated away by another process — reopen */
            int new_fd = open(g_log_path, O_CREAT | O_WRONLY | O_APPEND, 0644);
            if (new_fd >= 0) { close(g_log_fd); g_log_fd = new_fd; }
        } else if ((size_t)st.st_size + len > g_log_max_size) {
            rotate_logs();
        }
        flock(g_lock_fd, LOCK_UN);
    }

    size_t remaining = len;
    while (remaining > 0) {
        ssize_t written = write(g_log_fd, buf + (len - remaining), remaining);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        remaining -= (size_t)written;
    }

    pthread_mutex_unlock(&g_log_mutex);
}
