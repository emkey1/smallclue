/* utmp_rec.c -- /var/run/utmp and /var/log/wtmp, by offset in the guest's
 * layout. See utmp_rec.h for why the layout is spelled out. */

#include "utmp_rec.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <unistd.h>

#if defined(PSCAL_TARGET_IOS)
#include <pthread.h>
#include <pwd.h>
#include <time.h>
#endif

/* Offsets common to both layouts. */
#define OFF_TYPE    0
#define OFF_PID     4
#define OFF_LINE    8
#define OFF_ID     40
#define OFF_USER   44
#define OFF_HOST   76
#define OFF_EXIT  332
#define OFF_SESS  336
#define LEN_LINE   32
#define LEN_ID      4
#define LEN_USER   32
#define LEN_HOST  256
#define MAX_RECORD 400

/* The 384-byte layout keeps 32-bit time: ut_session and ut_tv's two fields are
 * int32_t, at 336, 340 and 344. The 400-byte one has a long ut_session at 336
 * and a struct timeval of two 64-bit fields at 344 and 352. */
static bool layoutIs64(void) {
    static int cached = -1;
    if (cached < 0) {
        struct utsname u;
        cached = 1;
        if (uname(&u) == 0) {
            const char *m = u.machine;
            if (strcmp(m, "x86_64") == 0 ||
                (m[0] == 'i' && m[1] >= '3' && m[1] <= '6' && strcmp(m + 2, "86") == 0)) {
                cached = 0;
            }
        }
    }
    return cached == 1;
}

size_t smallclueUtmpRecordSize(void) {
    return layoutIs64() ? 400 : 384;
}

static void getField(char *dst, size_t dstSize, const unsigned char *rec, size_t off, size_t width) {
    size_t n = width < dstSize - 1 ? width : dstSize - 1;
    memcpy(dst, rec + off, n);
    dst[n] = '\0';
    dst[strnlen(dst, n)] = '\0';
}

static void putField(unsigned char *rec, size_t off, size_t width, const char *src) {
    size_t n = strnlen(src, width);
    memset(rec + off, 0, width);
    memcpy(rec + off, src, n);
}

static void decode(const unsigned char *rec, SmallclueUtmp *out) {
    memset(out, 0, sizeof(*out));
    int16_t type;
    memcpy(&type, rec + OFF_TYPE, sizeof(type));
    out->type = type;
    memcpy(&out->pid, rec + OFF_PID, sizeof(out->pid));
    getField(out->line, sizeof(out->line), rec, OFF_LINE, LEN_LINE);
    getField(out->id, sizeof(out->id), rec, OFF_ID, LEN_ID);
    getField(out->user, sizeof(out->user), rec, OFF_USER, LEN_USER);
    getField(out->host, sizeof(out->host), rec, OFF_HOST, LEN_HOST);
    memcpy(&out->exitTermination, rec + OFF_EXIT, 2);
    memcpy(&out->exitStatus, rec + OFF_EXIT + 2, 2);
    if (layoutIs64()) {
        memcpy(&out->session, rec + OFF_SESS, 8);
        memcpy(&out->sec, rec + 344, 8);
        memcpy(&out->usec, rec + 352, 8);
    } else {
        int32_t s32, sec, usec;
        memcpy(&s32, rec + OFF_SESS, 4);
        memcpy(&sec, rec + 340, 4);
        memcpy(&usec, rec + 344, 4);
        out->session = s32;
        out->sec = sec;
        out->usec = usec;
    }
}

static void encode(const SmallclueUtmp *in, unsigned char *rec) {
    memset(rec, 0, MAX_RECORD);
    int16_t type = in->type;
    memcpy(rec + OFF_TYPE, &type, sizeof(type));
    memcpy(rec + OFF_PID, &in->pid, sizeof(in->pid));
    putField(rec, OFF_LINE, LEN_LINE, in->line);
    /* ut_id is four bytes with no terminator of its own. */
    memcpy(rec + OFF_ID, in->id, strnlen(in->id, LEN_ID));
    putField(rec, OFF_USER, LEN_USER, in->user);
    putField(rec, OFF_HOST, LEN_HOST, in->host);
    memcpy(rec + OFF_EXIT, &in->exitTermination, 2);
    memcpy(rec + OFF_EXIT + 2, &in->exitStatus, 2);
    if (layoutIs64()) {
        memcpy(rec + OFF_SESS, &in->session, 8);
        memcpy(rec + 344, &in->sec, 8);
        memcpy(rec + 352, &in->usec, 8);
    } else {
        int32_t s32 = (int32_t) in->session, sec = (int32_t) in->sec, usec = (int32_t) in->usec;
        memcpy(rec + OFF_SESS, &s32, 4);
        memcpy(rec + 340, &sec, 4);
        memcpy(rec + 344, &usec, 4);
    }
}

void smallclueUtmpStamp(SmallclueUtmp *rec) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    rec->sec = tv.tv_sec;
    rec->usec = tv.tv_usec;
}

#if defined(PSCAL_TARGET_IOS)
/* Every tab and command of the app is one process, and a record lock is the
 * process's, so it keeps nobody out there: two tabs opening together would find
 * the same free slot and one login would be lost. This keeps them apart. A
 * command's thread can be cancelled, and must not end holding it. */
static pthread_mutex_t gWriterLock = PTHREAD_MUTEX_INITIALIZER;
static int gWriterCancelState;

static void writerEnter(void) {
    int cancelState;
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancelState);
    pthread_mutex_lock(&gWriterLock);
    gWriterCancelState = cancelState;
}

static void writerLeave(void) {
    int cancelState = gWriterCancelState;
    pthread_mutex_unlock(&gWriterLock);
    pthread_setcancelstate(cancelState, NULL);
}
#else
static void writerEnter(void) {}
static void writerLeave(void) {}
#endif

/* The whole-file write lock glibc's utmp functions take, so the guest's own
 * glibc writers (login, sshd, utempter) and these do not interleave. */
static int lockFile(int fd, short type) {
    writerEnter();
    struct flock fl;
    memset(&fl, 0, sizeof(fl));
    fl.l_type = type;
    fl.l_whence = SEEK_SET;
    int rc;
    do {
        rc = fcntl(fd, F_SETLKW, &fl);
    } while (rc < 0 && errno == EINTR);
    if (rc < 0)
        writerLeave();
    return rc;
}

static void unlockFile(int fd) {
    struct flock fl;
    memset(&fl, 0, sizeof(fl));
    fl.l_type = F_UNLCK;
    fl.l_whence = SEEK_SET;
    fcntl(fd, F_SETLK, &fl);
    writerLeave();
}

static int openRecords(const char *path, int flags) {
#if defined(SMALLCLUE_APP_HOOKS_H) && defined(PSCAL_TARGET_IOS)
    /* open is the vproc's shim, which translates a path only for a thread with a
     * task. A tab's logout can come after its shell's task has gone, or from the
     * queue that removes the tab, and would look on the host's filesystem. */
    char expanded[PATH_MAX];
    path = pscalPathVirtualized_hostPath(path, expanded);
#endif
    int fd = open(path, flags | O_CLOEXEC, 0664);
    return fd;
}

static ssize_t readAt(int fd, void *buf, size_t len, off_t off) {
    size_t done = 0;
    while (done < len) {
        ssize_t n = pread(fd, (char *) buf + done, len - done, off + (off_t) done);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return n < 0 ? -1 : (ssize_t) done;
        done += (size_t) n;
    }
    return (ssize_t) done;
}

static int writeAt(int fd, const void *buf, size_t len, off_t off) {
    size_t done = 0;
    while (done < len) {
        ssize_t n = pwrite(fd, (const char *) buf + done, len - done, off + (off_t) done);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return -1;
        done += (size_t) n;
    }
    return 0;
}

/* The end of the last whole record. glibc cuts a partial record off before
 * appending, so the file stays a whole number of records. */
static off_t wholeEnd(int fd, size_t size) {
    struct stat st;
    if (fstat(fd, &st) != 0)
        return -1;
    off_t end = st.st_size - st.st_size % (off_t) size;
    if (end != st.st_size)
        (void) ftruncate(fd, end);
    return end;
}

int smallclueUtmpReadAll(const char *path, SmallclueUtmp **out) {
    *out = NULL;
    int fd = openRecords(path, O_RDONLY);
    if (fd < 0)
        return -1;
    size_t size = smallclueUtmpRecordSize();
    int count = 0, cap = 0;
    unsigned char rec[MAX_RECORD];
    for (off_t off = 0;; off += (off_t) size) {
        if (readAt(fd, rec, size, off) != (ssize_t) size)
            break;
        if (count == cap) {
            int ncap = cap ? cap * 2 : 16;
            SmallclueUtmp *grown = realloc(*out, (size_t) ncap * sizeof(**out));
            if (grown == NULL)
                break;
            *out = grown;
            cap = ncap;
        }
        decode(rec, &(*out)[count++]);
    }
    close(fd);
    return count;
}

static bool isProcessType(short type) {
    return type == SMALLCLUE_UT_INIT_PROCESS || type == SMALLCLUE_UT_LOGIN_PROCESS ||
           type == SMALLCLUE_UT_USER_PROCESS || type == SMALLCLUE_UT_DEAD_PROCESS;
}

static bool matches(const SmallclueUtmp *a, const SmallclueUtmp *b) {
    if (isProcessType(b->type))
        return isProcessType(a->type) && strncmp(a->id, b->id, LEN_ID) == 0;
    if (b->type == SMALLCLUE_UT_RUN_LVL || b->type == SMALLCLUE_UT_BOOT_TIME ||
        b->type == SMALLCLUE_UT_NEW_TIME || b->type == SMALLCLUE_UT_OLD_TIME)
        return a->type == b->type;
    return false;
}

int smallclueUtmpPut(const char *path, const SmallclueUtmp *rec) {
    int fd = openRecords(path, O_RDWR | O_CREAT);
    if (fd < 0)
        return -1;
    if (lockFile(fd, F_WRLCK) != 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    size_t size = smallclueUtmpRecordSize();
    unsigned char buf[MAX_RECORD];
    off_t at = -1;
    for (off_t off = 0;; off += (off_t) size) {
        if (readAt(fd, buf, size, off) != (ssize_t) size)
            break;
        SmallclueUtmp cur;
        decode(buf, &cur);
        if (matches(&cur, rec)) {
            at = off;
            break;
        }
    }
    if (at < 0)
        at = wholeEnd(fd, size);
    int rc = -1;
    if (at >= 0) {
        encode(rec, buf);
        rc = writeAt(fd, buf, size, at);
    }
    int saved = errno;
    unlockFile(fd);
    close(fd);
    errno = saved;
    return rc;
}

int smallclueWtmpAppend(const char *path, const SmallclueUtmp *rec) {
    int fd = openRecords(path, O_RDWR | O_CREAT);
    if (fd < 0)
        return -1;
    if (lockFile(fd, F_WRLCK) != 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    size_t size = smallclueUtmpRecordSize();
    unsigned char buf[MAX_RECORD];
    encode(rec, buf);
    off_t at = wholeEnd(fd, size);
    int rc = at >= 0 ? writeAt(fd, buf, size, at) : -1;
    int saved = errno;
    unlockFile(fd);
    close(fd);
    errno = saved;
    return rc;
}

int smallclueUtmpFilter(const char *path, bool (*keep)(const SmallclueUtmp *rec, void *ctx), void *ctx) {
    int fd = openRecords(path, O_RDWR | O_CREAT);
    if (fd < 0)
        return -1;
    if (lockFile(fd, F_WRLCK) != 0) {
        int saved = errno;
        close(fd);
        errno = saved;
        return -1;
    }
    size_t size = smallclueUtmpRecordSize();
    unsigned char buf[MAX_RECORD];
    off_t in = 0, out = 0;
    int rc = 0;
    for (;; in += (off_t) size) {
        if (readAt(fd, buf, size, in) != (ssize_t) size)
            break;
        SmallclueUtmp cur;
        decode(buf, &cur);
        if (!keep(&cur, ctx))
            continue;
        if (out != in && writeAt(fd, buf, size, out) != 0) {
            rc = -1;
            break;
        }
        out += (off_t) size;
    }
    if (rc == 0 && ftruncate(fd, out) != 0)
        rc = -1;
    int saved = errno;
    unlockFile(fd);
    close(fd);
    errno = saved;
    return rc;
}

bool smallclueUtmpLineForFd(int fd, char line[33], char id[5]) {
    const char *name = isatty(fd) ? ttyname(fd) : NULL;
    if (name == NULL)
        return false;
    if (strncmp(name, "/dev/", 5) == 0)
        name += 5;
    snprintf(line, 33, "%s", name);
    size_t len = strlen(line);
    snprintf(id, 5, "%s", line + (len > 4 ? len - 4 : 0));
    return true;
}

void smallclueUtmpLogin(pid_t pid, const char *line, const char *id, const char *user, const char *host) {
    SmallclueUtmp rec;
    memset(&rec, 0, sizeof(rec));
    rec.type = SMALLCLUE_UT_USER_PROCESS;
    rec.pid = pid;
    snprintf(rec.line, sizeof(rec.line), "%s", line);
    snprintf(rec.id, sizeof(rec.id), "%s", id);
    snprintf(rec.user, sizeof(rec.user), "%s", user);
    snprintf(rec.host, sizeof(rec.host), "%s", host ? host : "");
    rec.session = getsid(0);
    smallclueUtmpStamp(&rec);
    (void) smallclueUtmpPut(SMALLCLUE_UTMP_PATH, &rec);
    (void) smallclueWtmpAppend(SMALLCLUE_WTMP_PATH, &rec);
}

void smallclueUtmpProcessEnded(pid_t pid) {
    SmallclueUtmp *recs = NULL;
    int n = smallclueUtmpReadAll(SMALLCLUE_UTMP_PATH, &recs);
    for (int i = 0; i < n; i++) {
        SmallclueUtmp *r = &recs[i];
        if (r->pid != pid || (r->type != SMALLCLUE_UT_USER_PROCESS &&
                              r->type != SMALLCLUE_UT_LOGIN_PROCESS &&
                              r->type != SMALLCLUE_UT_INIT_PROCESS))
            continue;
        /* What glibc's logout() and logwtmp(line, "", "") write: the slot
         * kept, the name and host cleared, DEAD_PROCESS; and in wtmp the same
         * line with no name, which last(1) pairs with the login. */
        r->type = SMALLCLUE_UT_DEAD_PROCESS;
        memset(r->user, 0, sizeof(r->user));
        memset(r->host, 0, sizeof(r->host));
        smallclueUtmpStamp(r);
        (void) smallclueUtmpPut(SMALLCLUE_UTMP_PATH, r);
        (void) smallclueWtmpAppend(SMALLCLUE_WTMP_PATH, r);
    }
    free(recs);
}

static bool keepSinceBoot(const SmallclueUtmp *rec, void *ctx) {
    int64_t boot = *(const int64_t *) ctx;
    return rec->sec >= boot && (rec->type == SMALLCLUE_UT_USER_PROCESS ||
                                rec->type == SMALLCLUE_UT_LOGIN_PROCESS ||
                                rec->type == SMALLCLUE_UT_INIT_PROCESS);
}

static void runlevelRecord(SmallclueUtmp *rec, char level, char previous, const char *user) {
    memset(rec, 0, sizeof(*rec));
    rec->type = SMALLCLUE_UT_RUN_LVL;
    /* sysvinit's encoding, which who -r and runlevel(8) decode. */
    rec->pid = (unsigned char) level + 256 * (unsigned char) previous;
    snprintf(rec->line, sizeof(rec->line), "~");
    snprintf(rec->id, sizeof(rec->id), "~~");
    snprintf(rec->user, sizeof(rec->user), "%s", user);
    struct utsname u;
    if (uname(&u) == 0)
        snprintf(rec->host, sizeof(rec->host), "%s", u.release);
    smallclueUtmpStamp(rec);
}

void smallclueUtmpBoot(int64_t bootTime, char runlevel) {
    (void) smallclueUtmpFilter(SMALLCLUE_UTMP_PATH, keepSinceBoot, &bootTime);
    SmallclueUtmp rec;
    memset(&rec, 0, sizeof(rec));
    rec.type = SMALLCLUE_UT_BOOT_TIME;
    snprintf(rec.line, sizeof(rec.line), "~");
    snprintf(rec.id, sizeof(rec.id), "~~");
    snprintf(rec.user, sizeof(rec.user), "reboot");
    struct utsname u;
    if (uname(&u) == 0)
        snprintf(rec.host, sizeof(rec.host), "%s", u.release);
    rec.sec = bootTime;
    (void) smallclueUtmpPut(SMALLCLUE_UTMP_PATH, &rec);
    (void) smallclueWtmpAppend(SMALLCLUE_WTMP_PATH, &rec);
    runlevelRecord(&rec, runlevel, 'N', "runlevel");
    (void) smallclueUtmpPut(SMALLCLUE_UTMP_PATH, &rec);
    (void) smallclueWtmpAppend(SMALLCLUE_WTMP_PATH, &rec);
}

void smallclueUtmpShutdown(bool utmpToo) {
    SmallclueUtmp rec;
    if (utmpToo) {
        runlevelRecord(&rec, '0', '2', "runlevel");
        (void) smallclueUtmpPut(SMALLCLUE_UTMP_PATH, &rec);
    }
    /* last(1) reads a RUN_LVL record named "shutdown" as the system going
     * down, and ends every session still open at it. */
    runlevelRecord(&rec, '0', '2', "shutdown");
    snprintf(rec.line, sizeof(rec.line), "~~");
    (void) smallclueWtmpAppend(SMALLCLUE_WTMP_PATH, &rec);
}

#if defined(PSCAL_TARGET_IOS)
/* What wtmp may reach before a launch moves it aside: nothing else here rotates it. */
#define WTMP_ROTATE_BYTES (1024 * 1024)

typedef struct TerminalLogin {
    uint64_t session;
    pid_t pid;
    struct TerminalLogin *next;
} TerminalLogin;

static TerminalLogin *gTerminalLogins = NULL;
static pthread_mutex_t gTerminalLoginsLock = PTHREAD_MUTEX_INITIALIZER;

/* A launch of the app is its boot. /run is a tmpfs on Linux, so utmp starts each
 * boot empty, and it has to here: iOS ends the app without warning, and the last
 * run's tabs would stay in the file as logins nobody has. In wtmp they stay with
 * no logout, as after a crash on Linux. */
static void terminalsBoot(void) {
    (void) mkdir("/var", 0755);
    (void) mkdir("/var/run", 0755);
    (void) mkdir("/var/log", 0755);
    (void) unlink(SMALLCLUE_UTMP_PATH);
    struct stat st;
    if (stat(SMALLCLUE_WTMP_PATH, &st) == 0 && st.st_size >= WTMP_ROTATE_BYTES)
        (void) rename(SMALLCLUE_WTMP_PATH, SMALLCLUE_WTMP_PATH ".1");
    smallclueUtmpBoot((int64_t) time(NULL), '2');
}

void smallclueUtmpTerminalOpened(uint64_t session, pid_t pid) {
    static pthread_once_t boot = PTHREAD_ONCE_INIT;
    pthread_once(&boot, terminalsBoot);

    char line[33], id[5];
    if (!smallclueUtmpLineForFd(STDIN_FILENO, line, id))
        return;
    TerminalLogin *login = malloc(sizeof(*login));
    if (login == NULL)
        return;

    /* What whoami prints. getpwuid is the app's own, from its /etc/passwd, where
     * getpwuid_r is the host's and knows only a number here. */
    char name[33];
    uid_t uid = geteuid();
    struct passwd *found = getpwuid(uid);
    if (found != NULL && found->pw_name != NULL && found->pw_name[0] != '\0')
        snprintf(name, sizeof(name), "%s", found->pw_name);
    else
        snprintf(name, sizeof(name), "%u", (unsigned) uid);
    smallclueUtmpLogin(pid, line, id, name, NULL);

    login->session = session;
    login->pid = pid;
    pthread_mutex_lock(&gTerminalLoginsLock);
    login->next = gTerminalLogins;
    gTerminalLogins = login;
    pthread_mutex_unlock(&gTerminalLoginsLock);
}

void smallclueUtmpTerminalClosed(uint64_t session) {
    TerminalLogin *login = NULL;
    pthread_mutex_lock(&gTerminalLoginsLock);
    for (TerminalLogin **at = &gTerminalLogins; *at != NULL; at = &(*at)->next) {
        if ((*at)->session == session) {
            login = *at;
            *at = login->next;
            break;
        }
    }
    pthread_mutex_unlock(&gTerminalLoginsLock);
    if (login == NULL)
        return;
    smallclueUtmpProcessEnded(login->pid);
    free(login);
}
#endif
