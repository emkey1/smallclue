#ifndef SMALLCLUE_UTMP_REC_H
#define SMALLCLUE_UTMP_REC_H

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

/* The login records -- /var/run/utmp (who is on now) and /var/log/wtmp (every
 * login, logout, boot and shutdown) -- in the guest's own Linux layout, read
 * and written by offset.
 *
 * Not <utmp.h>: SmallCLUE also runs as host code inside iSH-AOK, where the
 * system's struct (Darwin's utmpx) has nothing to do with the guest's files.
 * And the Linux layout is not one layout. glibc's struct utmp is 384 bytes on
 * x86_64 and i386, which keep 32-bit time fields for compatibility, and 400 on
 * aarch64 and riscv64, where ut_session is a long and ut_tv a struct timeval
 * (measured: four records from glibc's pututline on Devuan arm64 made a
 * 1600-byte file). A reader that assumed 384 everywhere read an arm64 utmp as
 * garbage from the second record on. The layout follows the guest's machine,
 * which is what the guest's own glibc programs use. */

enum {
    SMALLCLUE_UT_EMPTY = 0,
    SMALLCLUE_UT_RUN_LVL = 1,
    SMALLCLUE_UT_BOOT_TIME = 2,
    SMALLCLUE_UT_NEW_TIME = 3,
    SMALLCLUE_UT_OLD_TIME = 4,
    SMALLCLUE_UT_INIT_PROCESS = 5,
    SMALLCLUE_UT_LOGIN_PROCESS = 6,
    SMALLCLUE_UT_USER_PROCESS = 7,
    SMALLCLUE_UT_DEAD_PROCESS = 8,
};

#define SMALLCLUE_UTMP_PATH "/var/run/utmp"
#define SMALLCLUE_WTMP_PATH "/var/log/wtmp"

typedef struct {
    short type;
    int32_t pid;
    char line[33];     /* 32 in the file, kept NUL-terminated here */
    char id[5];        /* 4 in the file */
    char user[33];
    char host[257];
    int16_t exitTermination;
    int16_t exitStatus;
    int64_t session;
    int64_t sec;
    int64_t usec;
} SmallclueUtmp;

/* The record size the guest's glibc uses: 384 or 400. */
size_t smallclueUtmpRecordSize(void);

/* Every record in PATH, as a malloc'd array (free it). Returns the count, or
 * -1 when the file cannot be opened. A partial record at the end is ignored. */
int smallclueUtmpReadAll(const char *path, SmallclueUtmp **out);

/* What glibc's pututline does: replace the record that matches REC -- the same
 * ut_id for INIT, LOGIN, USER and DEAD records, the same type for RUN_LVL,
 * BOOT_TIME, NEW_TIME and OLD_TIME -- or append. Under a write lock. Creates
 * the file (0664) when it is missing. Returns 0 or -1 with errno. */
int smallclueUtmpPut(const char *path, const SmallclueUtmp *rec);

/* What glibc's updwtmp does: append REC to PATH under a write lock. Unlike
 * updwtmp it creates a missing file (0664), since nothing else here will. */
int smallclueWtmpAppend(const char *path, const SmallclueUtmp *rec);

/* Rewrite PATH keeping only the records KEEP accepts. Under a write lock. */
int smallclueUtmpFilter(const char *path, bool (*keep)(const SmallclueUtmp *rec, void *ctx), void *ctx);

/* REC's time: now. */
void smallclueUtmpStamp(SmallclueUtmp *rec);

/* The terminal of FD as utmp names it -- "pts/3", "tty1" -- and the four-byte
 * id for it: the last four characters, as utempter and the getty/login pair
 * on most systems use, so pts/1 and tty1 do not collide. False when FD is not
 * a terminal. */
bool smallclueUtmpLineForFd(int fd, char line[33], char id[5]);

/* A login: a USER_PROCESS record for PID on LINE in utmp, and the same in
 * wtmp. Failure is not fatal to anything and is ignored by callers. */
void smallclueUtmpLogin(pid_t pid, const char *line, const char *id, const char *user, const char *host);

/* PID has exited: if utmp has a login for it, mark it DEAD_PROCESS and append
 * the logout to wtmp, as init does for the sessions it reaps. */
void smallclueUtmpProcessEnded(pid_t pid);

/* Boot: drop what utmp says about a previous boot -- every record older than
 * BOOT_TIME (seconds since the epoch), except logins that began since, which
 * raced ahead of init -- then record the boot and runlevel RUNLEVEL in utmp
 * and wtmp, as sysvinit does. */
void smallclueUtmpBoot(int64_t bootTime, char runlevel);

/* Shutdown: the "shutdown" record in wtmp that last(1) reads as the system
 * going down, and with UTMP_TOO runlevel 0 in utmp (halt -w writes only the
 * wtmp record). */
void smallclueUtmpShutdown(bool utmpToo);

#endif /* SMALLCLUE_UTMP_REC_H */
