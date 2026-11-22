/* w, last, finger -- who is on, who was, and who someone is.
 *
 * All three read the login records through utmp_rec.c (the guest's own Linux
 * utmp/wtmp layout, whatever the host), so they work the same as guest
 * programs and as AOK-iSH's native ones. The output is that of the programs
 * Debian ships, measured against them byte for byte on the same utmp and wtmp
 * (Debian bookworm, arm64): procps-ng's w, util-linux's last and netkit's
 * bsd-finger. Where AOK-iSH differs from Linux it says so below.
 *
 * Terminals are matched to processes by name, not by stat: "pts/N" is device
 * 136:N and "ttyN" 4:N, which is what both Linux and AOK-iSH put in
 * /proc/<pid>/stat's tty_nr. A native program's stat() is Darwin-shaped, so
 * its st_rdev is not a number to compare that with. */

#include "login_apps.h"
#include "utmp_rec.h"

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <pwd.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* ---------------------------------------------------------------- shared */

static bool isLoginRecord(const SmallclueUtmp *r) {
    return r->type == SMALLCLUE_UT_USER_PROCESS && r->user[0] != '\0';
}

/* The tty_nr /proc/<pid>/stat gives a process on LINE, or 0 if LINE names no
 * terminal this knows. Linux's new_encode_dev. */
static unsigned long ttyNumberForLine(const char *line) {
    unsigned major, minor;
    if (strncmp(line, "/dev/", 5) == 0)
        line += 5;
    if (strncmp(line, "pts/", 4) == 0 && isdigit((unsigned char) line[4])) {
        major = 136;
        minor = (unsigned) strtoul(line + 4, NULL, 10);
    } else if (strncmp(line, "tty", 3) == 0 && isdigit((unsigned char) line[3])) {
        major = 4;
        minor = (unsigned) strtoul(line + 3, NULL, 10);
    } else if (strcmp(line, "console") == 0) {
        major = 5;
        minor = 1;
    } else {
        return 0;
    }
    return (minor & 0xff) | (major << 8) | ((minor & ~0xffu) << 12);
}

/* The fields of /proc/<pid>/stat that w wants. */
typedef struct {
    int pgrp;
    unsigned long ttyNr;
    int tpgid;
    unsigned long long cpuTicks;   /* utime + stime */
    unsigned long long start;      /* starttime, in ticks */
} ProcStat;

static bool readProcStat(int pid, ProcStat *out) {
    char path[64], buf[1024];
    snprintf(path, sizeof(path), "/proc/%d/stat", pid);
    FILE *f = fopen(path, "r");
    if (f == NULL)
        return false;
    size_t n = fread(buf, 1, sizeof(buf) - 1, f);
    fclose(f);
    buf[n] = '\0';
    /* The command is in parentheses and may hold anything, spaces and ')'
     * included: the fields resume after the LAST ')'. */
    char *p = strrchr(buf, ')');
    if (p == NULL)
        return false;
    p += 2;
    /* state ppid pgrp session tty_nr tpgid flags minflt cminflt majflt
     * cmajflt utime stime cutime cstime priority nice threads itrealvalue
     * starttime */
    char state;
    int ppid, session;
    unsigned long flags, minflt, cminflt, majflt, cmajflt, utime, stime;
    long cutime, cstime, priority, nice, threads, itreal;
    unsigned long long start;
    if (sscanf(p, "%c %d %d %d %lu %d %lu %lu %lu %lu %lu %lu %lu %ld %ld %ld %ld %ld %ld %llu",
               &state, &ppid, &out->pgrp, &session, &out->ttyNr, &out->tpgid, &flags,
               &minflt, &cminflt, &majflt, &cmajflt, &utime, &stime, &cutime, &cstime,
               &priority, &nice, &threads, &itreal, &start) != 20)
        return false;
    out->cpuTicks = (unsigned long long) utime + stime;
    out->start = start;
    return true;
}

/* /proc/<pid>/cmdline with its NULs as spaces, or the command name in square
 * brackets for a process with no arguments to show, as procps does. */
static void readCommandLine(int pid, char *out, size_t size) {
    char path[64];
    out[0] = '\0';
    snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
    FILE *f = fopen(path, "r");
    size_t n = 0;
    if (f != NULL) {
        n = fread(out, 1, size - 1, f);
        fclose(f);
    }
    while (n > 0 && out[n - 1] == '\0')
        n--;
    out[n] = '\0';
    for (size_t i = 0; i < n; i++)
        if (out[i] == '\0')
            out[i] = ' ';
    if (n > 0)
        return;
    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
    f = fopen(path, "r");
    char comm[64] = "";
    if (f != NULL) {
        if (fgets(comm, sizeof(comm), f) == NULL)
            comm[0] = '\0';
        fclose(f);
    }
    comm[strcspn(comm, "\n")] = '\0';
    if (comm[0] != '\0')
        snprintf(out, size, "[%s]", comm);
}

/* -------------------------------------------------------------------- w */

static int screenWidth(void) {
    const char *cols = getenv("COLUMNS");
    if (cols != NULL && atoi(cols) > 0)
        return atoi(cols);
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0)
        return ws.ws_col;
    return 80;
}

/* procps' print_time_ival7. */
static void printInterval7(long long t, int centi) {
    if (t < 0)
        printf("   ?   ");
    else if (t >= 48 * 60 * 60)
        printf(" %2lldays", t / (24 * 60 * 60));
    else if (t >= 60 * 60)
        printf(" %2lld:%02dm", t / (60 * 60), (int) ((t / 60) % 60));
    else if (t > 60)
        printf(" %2lld:%02d ", t / 60, (int) (t % 60));
    else
        printf(" %2lld.%02ds", t, centi);
}

/* procps' print_logintime: today as HH:MM, this week as the day and hour,
 * earlier as the date. */
static void printLoginTime(time_t when, time_t now) {
    static const char *days[] = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" };
    static const char *months[] = { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
                                    "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
    struct tm cur, at;
    localtime_r(&now, &cur);
    localtime_r(&when, &at);
    if (now - when > 12 * 60 * 60 && at.tm_yday != cur.tm_yday) {
        if (now - when > 6 * 24 * 60 * 60)
            printf(" %02d%3s%02d", at.tm_mday, months[at.tm_mon], at.tm_year % 100);
        else
            printf(" %3s%02d  ", days[at.tm_wday], at.tm_hour);
    } else {
        printf(" %02d:%02d  ", at.tm_hour, at.tm_min);
    }
}

/* procps' print_host: printable characters, '-' for the first one that is
 * not (and stop), '-' for an empty host, padded to WIDTH. */
static void printHost(const char *host, int width) {
    int used = 0;
    for (; used < width && host[used] != '\0'; used++) {
        unsigned char c = (unsigned char) host[used];
        if (isprint(c) && c != ' ') {
            putchar(c);
        } else {
            putchar('-');
            used++;
            break;
        }
    }
    if (used == 0) {
        putchar('-');
        used = 1;
    }
    for (; used < width; used++)
        putchar(' ');
}

static void printUptimeLine(time_t now, int users) {
    struct tm tm;
    localtime_r(&now, &tm);
    printf(" %02d:%02d:%02d up ", tm.tm_hour, tm.tm_min, tm.tm_sec);
    double up = 0;
    FILE *f = fopen("/proc/uptime", "r");
    if (f != NULL) {
        if (fscanf(f, "%lf", &up) != 1)
            up = 0;
        fclose(f);
    }
    long secs = (long) up;
    long days = secs / 86400, hours = (secs / 3600) % 24, mins = (secs / 60) % 60;
    if (days > 0)
        printf("%ld day%s, ", days, days == 1 ? "" : "s");
    if (hours > 0)
        printf("%2ld:%02ld, ", hours, mins);
    else
        printf("%ld min, ", mins);
    printf("%2d user%s, ", users, users == 1 ? "" : "s");
    double l1 = 0, l5 = 0, l15 = 0;
    f = fopen("/proc/loadavg", "r");
    if (f != NULL) {
        if (fscanf(f, "%lf %lf %lf", &l1, &l5, &l15) != 3)
            l1 = l5 = l15 = 0;
        fclose(f);
    }
    printf(" load average: %.2f, %.2f, %.2f\n", l1, l5, l15);
}

/* procps' find_best_proc: JCPU is every process on the terminal; PCPU and
 * WHAT are the foreground process started last, else the login process. */
static void bestProcess(const SmallclueUtmp *u, unsigned long long *jcpu,
                        unsigned long long *pcpu, char *what, size_t whatSize) {
    unsigned long tty = ttyNumberForLine(u->line);
    unsigned long long bestStart = 0;
    bool haveBest = false;
    *jcpu = 0;
    *pcpu = 0;
    what[0] = '\0';
    DIR *d = opendir("/proc");
    if (d == NULL)
        return;
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
        if (!isdigit((unsigned char) e->d_name[0]))
            continue;
        int pid = atoi(e->d_name);
        ProcStat ps;
        if (!readProcStat(pid, &ps))
            continue;
        if (pid == u->pid && !haveBest) {
            *pcpu = ps.cpuTicks;
            readCommandLine(pid, what, whatSize);
        }
        if (tty == 0 || ps.ttyNr != tty)
            continue;
        *jcpu += ps.cpuTicks;
        if (ps.tpgid != -1 && ps.pgrp == ps.tpgid && (!haveBest || ps.start > bestStart)) {
            haveBest = true;
            bestStart = ps.start;
            *pcpu = ps.cpuTicks;
            readCommandLine(pid, what, whatSize);
        }
    }
    closedir(d);
}

int smallclueWCommand(int argc, char **argv) {
    bool header = true, longForm = true, from = true;
    const char *onlyUser = NULL;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--help") == 0) {
            printf("usage: w [-hsfuoi] [USER]\n");
            return 0;
        }
        if (strcmp(a, "--no-header") == 0) { header = false; continue; }
        if (strcmp(a, "--short") == 0) { longForm = false; continue; }
        if (strcmp(a, "--from") == 0) { from = !from; continue; }
        if (a[0] == '-' && a[1] != '\0' && a[1] != '-') {
            for (const char *p = a + 1; *p; p++) {
                switch (*p) {
                    case 'h': header = false; break;
                    case 's': longForm = false; break;
                    case 'f': from = !from; break;
                    case 'u': case 'o': case 'i': break;   /* no other uid, old style or address to show */
                    default:
                        fprintf(stderr, "w: invalid option -- '%c'\n", *p);
                        fprintf(stderr, "usage: w [-hsfuoi] [USER]\n");
                        return 1;
                }
            }
        } else if (onlyUser == NULL) {
            onlyUser = a;
        }
    }

    SmallclueUtmp *recs = NULL;
    int n = smallclueUtmpReadAll(SMALLCLUE_UTMP_PATH, &recs);
    if (n < 0)
        n = 0;
    time_t now = time(NULL);
    long hz = sysconf(_SC_CLK_TCK);
    if (hz <= 0)
        hz = 100;
    const int userLen = 8, fromLen = 16;

    if (header) {
        int users = 0;
        for (int i = 0; i < n; i++)
            if (isLoginRecord(&recs[i]))
                users++;
        printUptimeLine(now, users);
        printf("%-*s TTY      ", userLen, "USER");
        if (from)
            printf("%-*s", fromLen - 1, "FROM");
        printf(longForm ? "  LOGIN@   IDLE   JCPU   PCPU WHAT\n" : "   IDLE WHAT\n");
    }

    int maxCmd = screenWidth() - 21 - userLen - (from ? fromLen : 0) - (longForm ? 20 : 0);
    if (maxCmd < 3)
        maxCmd = 3;
    for (int i = 0; i < n; i++) {
        const SmallclueUtmp *u = &recs[i];
        if (!isLoginRecord(u))
            continue;
        if (onlyUser != NULL && strcmp(onlyUser, u->user) != 0)
            continue;
        unsigned long long jcpu, pcpu;
        char what[4096];
        bestProcess(u, &jcpu, &pcpu, what, sizeof(what));
        /* procps: a terminal it cannot stat is idle 0. One with no access
         * time (AOK-iSH's) is unknown, "?", not idle since 1970. */
        long idle = 0;
        {
            char path[300];
            struct stat st;
            snprintf(path, sizeof(path), "/dev/%s", u->line);
            if (stat(path, &st) == 0)
                idle = st.st_atime == 0 ? -1 : (now > st.st_atime ? (long) (now - st.st_atime) : 0);
        }
        printf("%-*.*s%-9.8s", userLen + 1, userLen, u->user, u->line);
        if (from)
            printHost(u->host, fromLen);
        if (longForm)
            printLoginTime((time_t) u->sec, now);
        printInterval7(idle, 0);
        if (longForm) {
            printInterval7((long long) (jcpu / hz), (int) ((jcpu % hz) * 100 / hz));
            if (pcpu > 0)
                printInterval7((long long) (pcpu / hz), (int) ((pcpu % hz) * 100 / hz));
            else
                printf("   ?   ");
        }
        printf(" %.*s\n", maxCmd, what);
    }
    free(recs);
    return 0;
}

/* ----------------------------------------------------------------- last */

enum { LAST_NORMAL, LAST_NOW, LAST_REBOOT, LAST_CRASH, LAST_DOWN, LAST_PHANTOM, LAST_TIMECHANGE };

typedef struct {
    bool extended, full, showHost, hostLast, wide;
    int limit, shown;
    const char **names;
    int nameCount;
    time_t now, bootTime;
} LastOptions;

/* The person or terminal filter: names and lines, as util-linux matches them
 * ("pts/0" also matches as "0", a bare tty number). */
static bool lastWanted(const LastOptions *o, const SmallclueUtmp *u) {
    if (o->nameCount == 0)
        return true;
    for (int i = 0; i < o->nameCount; i++) {
        const char *w = o->names[i];
        if (strcmp(w, u->user) == 0 || strcmp(w, u->line) == 0)
            return true;
        if (strncmp(u->line, "tty", 3) == 0 && strcmp(w, u->line + 3) == 0)
            return true;
    }
    return false;
}

/* util-linux's is_phantom: a login with no logout whose process is gone, or
 * belongs to somebody else now. */
static bool lastIsPhantom(const LastOptions *o, const SmallclueUtmp *u) {
    if (u->sec < o->bootTime)
        return true;
    struct passwd *pw = getpwnam(u->user);
    if (pw == NULL)
        return true;
    char path[300];
    snprintf(path, sizeof(path), "/proc/%d/loginuid", u->pid);
    if (access(path, R_OK) == 0) {
        FILE *f = fopen(path, "r");
        if (f == NULL)
            return true;
        unsigned int loginuid;
        int got = fscanf(f, "%u", &loginuid);
        fclose(f);
        if (got != 1)
            return true;
        return pw->pw_uid != loginuid;
    }
    snprintf(path, sizeof(path), "/dev/%s", u->line);
    struct stat st;
    if (stat(path, &st) != 0)
        return true;
    return pw->pw_uid != st.st_uid;
}

static void lastFormat(const char *fmt, time_t t, char *buf, size_t size) {
    struct tm tm;
    localtime_r(&t, &tm);
    if (strftime(buf, size, fmt, &tm) == 0)
        buf[0] = '\0';
}

/* One line of util-linux's list(). Returns true when the -n limit is met. */
static bool lastPrint(LastOptions *o, const SmallclueUtmp *u, const char *user, const char *line,
                      time_t logout, int why) {
    if (!lastWanted(o, u))
        return false;
    const char *inFmt = o->full ? "%a %b %e %H:%M:%S %Y" : "%a %b %e %H:%M";
    const char *outFmt = o->full ? "%a %b %e %H:%M:%S %Y" : "%H:%M";
    int inLen = o->full ? 24 : 16, outLen = o->full ? 26 : 7;
    char loginTime[64], logoutTime[96] = "", length[64] = "";
    lastFormat(inFmt, (time_t) u->sec, loginTime, sizeof(loginTime));

    if (logout == o->now) {
        if (o->full) {
            snprintf(logoutTime, sizeof(logoutTime), "  still running");
        } else {
            snprintf(logoutTime, sizeof(logoutTime), "  still");
            snprintf(length, sizeof(length), "running");
        }
    } else {
        char t[64];
        lastFormat(outFmt, logout, t, sizeof(t));
        snprintf(logoutTime, sizeof(logoutTime), "- %s", t);
        long secs = (long) (logout - (time_t) u->sec);
        if (secs < 0)
            secs = 0;
        long mins = (secs / 60) % 60, hours = (secs / 3600) % 24, days = secs / 86400;
        if (days > 0)
            snprintf(length, sizeof(length), " (%ld+%02ld:%02ld)", days, hours, mins);
        else
            snprintf(length, sizeof(length), " (%02ld:%02ld)", hours, mins);
    }
    switch (why) {
        case LAST_CRASH:
            snprintf(logoutTime, sizeof(logoutTime), "- crash");
            break;
        case LAST_DOWN:
            snprintf(logoutTime, sizeof(logoutTime), "- down ");
            break;
        case LAST_NOW:
            if (o->full) {
                snprintf(logoutTime, sizeof(logoutTime), "  still logged in");
                length[0] = '\0';
            } else {
                snprintf(logoutTime, sizeof(logoutTime), "  still");
                snprintf(length, sizeof(length), "logged in");
            }
            break;
        case LAST_PHANTOM:
            if (o->full) {
                snprintf(logoutTime, sizeof(logoutTime), "  gone - no logout");
                length[0] = '\0';
            } else {
                snprintf(logoutTime, sizeof(logoutTime), "   gone");
                snprintf(length, sizeof(length), "- no logout");
            }
            break;
        case LAST_TIMECHANGE:
            logoutTime[0] = '\0';
            length[0] = '\0';
            break;
        default:
            break;
    }

    int nameLen = o->wide ? 32 : 8;
    int hostLen = o->wide ? 256 : 16;
    char out[1024];
    int len;
    if (o->showHost && !o->hostLast)
        len = snprintf(out, sizeof(out), "%-8.*s %-12.12s %-16.*s %-*.*s %-*.*s %s",
                       nameLen, user, line, hostLen, u->host, inLen, inLen, loginTime,
                       outLen, outLen, logoutTime, length);
    else
        len = snprintf(out, sizeof(out), "%-8.*s %-12.12s %-*.*s %-*.*s %s",
                       nameLen, user, line, inLen, inLen, loginTime,
                       outLen, outLen, logoutTime, length);
    if (len < 0)
        return false;
    if (o->hostLast && o->showHost)
        snprintf(out + strlen(out), sizeof(out) - strlen(out), "%*s %s",
                 (int) strlen(length) < 12 ? 12 - (int) strlen(length) : 0, "", u->host);
    /* util-linux trims the padding off the end of each line. */
    size_t end = strlen(out);
    while (end > 0 && out[end - 1] == ' ')
        out[--end] = '\0';
    printf("%s\n", out);
    o->shown++;
    return o->limit > 0 && o->shown >= o->limit;
}

int smallclueLastCommand(int argc, char **argv) {
    LastOptions o;
    memset(&o, 0, sizeof(o));
    o.showHost = true;
    const char *file = SMALLCLUE_WTMP_PATH;
    const char **names = calloc((size_t) argc + 1, sizeof(char *));
    if (names == NULL)
        return 1;
    o.names = names;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--help") == 0) {
            printf("usage: last [-axwFR] [-n NUM | -NUM] [-f FILE] [USER | TTY ...]\n");
            free(names);
            return 0;
        }
        if (a[0] == '-' && isdigit((unsigned char) a[1])) {
            o.limit = atoi(a + 1);
            continue;
        }
        if (a[0] == '-' && a[1] != '\0') {
            for (const char *p = a + 1; *p; p++) {
                switch (*p) {
                    case 'x': o.extended = true; break;
                    case 'F': o.full = true; break;
                    case 'R': o.showHost = false; break;
                    case 'a': o.hostLast = true; break;
                    case 'w': o.wide = true; break;
                    case 'd': case 'i': break;   /* no other host form to show */
                    case 'n': case 'f': {
                        const char *v = p[1] ? p + 1 : (i + 1 < argc ? argv[++i] : NULL);
                        if (v == NULL) {
                            fprintf(stderr, "last: option requires an argument -- '%c'\n", *p);
                            free(names);
                            return 1;
                        }
                        if (*p == 'n')
                            o.limit = atoi(v);
                        else
                            file = v;
                        p += strlen(p) - 1;
                        break;
                    }
                    default:
                        fprintf(stderr, "last: invalid option -- '%c'\n", *p);
                        fprintf(stderr, "Try 'last --help' for more information.\n");
                        free(names);
                        return 1;
                }
            }
            continue;
        }
        names[o.nameCount++] = a;
    }

    SmallclueUtmp *recs = NULL;
    int n = smallclueUtmpReadAll(file, &recs);
    if (n < 0) {
        fprintf(stderr, "last: cannot open %s: %s\n", file, strerror(errno));
        free(names);
        return 1;
    }
    o.now = time(NULL);
    double up = 0;
    FILE *f = fopen("/proc/uptime", "r");
    if (f != NULL) {
        if (fscanf(f, "%lf", &up) != 1)
            up = 0;
        fclose(f);
    }
    o.bootTime = o.now - (time_t) up;

    /* Logouts seen so far (walking backwards), by line. */
    typedef struct { char line[33]; time_t when; } Logout;
    Logout *logouts = calloc((size_t) n + 1, sizeof(Logout));
    int logoutCount = 0;
    time_t lastBoot = 0, lastDown = o.now, lastRunlevel = o.now;
    int whyDown = LAST_CRASH;
    bool quit = false;
    for (int i = n - 1; i >= 0 && !quit; i--) {
        SmallclueUtmp u = recs[i];
        bool down = false, shutdown = false;
        int type = u.type;
        /* A runlevel record from "shutdown" is a shutdown, as util-linux
         * reads it. */
        if (type == SMALLCLUE_UT_RUN_LVL && strcmp(u.user, "shutdown") == 0)
            type = -1;
        if (type == SMALLCLUE_UT_DEAD_PROCESS || (type == SMALLCLUE_UT_USER_PROCESS && u.user[0] == '\0'))
            type = SMALLCLUE_UT_DEAD_PROCESS;
        switch (type) {
            case -1:
                if (o.extended)
                    quit = lastPrint(&o, &u, "shutdown", "system down", lastBoot ? lastBoot : o.now, LAST_NORMAL);
                lastDown = lastRunlevel = (time_t) u.sec;
                down = shutdown = true;
                break;
            case SMALLCLUE_UT_OLD_TIME:
            case SMALLCLUE_UT_NEW_TIME:
                if (o.extended)
                    quit = lastPrint(&o, &u, u.user, type == SMALLCLUE_UT_NEW_TIME ? "new time" : "old time",
                                     0, LAST_TIMECHANGE);
                break;
            case SMALLCLUE_UT_BOOT_TIME:
                quit = lastPrint(&o, &u, "reboot", "system boot", lastDown, LAST_REBOOT);
                lastBoot = (time_t) u.sec;
                down = true;
                break;
            case SMALLCLUE_UT_RUN_LVL: {
                char level = (char) (u.pid & 255);
                if (o.extended) {
                    char line[16];
                    snprintf(line, sizeof(line), "(to lvl %c)", level);
                    quit = lastPrint(&o, &u, u.user, line, lastRunlevel, LAST_NORMAL);
                }
                if (level == '0' || level == '6') {
                    lastDown = (time_t) u.sec;
                    down = shutdown = true;
                }
                lastRunlevel = (time_t) u.sec;
                break;
            }
            case SMALLCLUE_UT_USER_PROCESS: {
                int found = -1;
                for (int k = 0; k < logoutCount; k++)
                    if (strcmp(logouts[k].line, u.line) == 0) {
                        found = k;
                        break;
                    }
                if (found >= 0) {
                    quit = lastPrint(&o, &u, u.user, u.line, logouts[found].when, LAST_NORMAL);
                    logouts[found] = logouts[--logoutCount];
                } else if (lastBoot == 0) {
                    quit = lastPrint(&o, &u, u.user, u.line, o.now,
                                     lastIsPhantom(&o, &u) ? LAST_PHANTOM : LAST_NOW);
                } else {
                    quit = lastPrint(&o, &u, u.user, u.line, lastBoot, whyDown);
                }
                /* This login is accounted for: a later login on the line
                 * may not take its logout. */
                Logout lo;
                memset(&lo, 0, sizeof(lo));
                snprintf(lo.line, sizeof(lo.line), "%s", u.line);
                lo.when = (time_t) u.sec;
                logouts[logoutCount++] = lo;
                break;
            }
            case SMALLCLUE_UT_DEAD_PROCESS:
                if (u.line[0] != '\0') {
                    int found = -1;
                    for (int k = 0; k < logoutCount; k++)
                        if (strcmp(logouts[k].line, u.line) == 0) {
                            found = k;
                            break;
                        }
                    if (found < 0)
                        found = logoutCount++;
                    snprintf(logouts[found].line, sizeof(logouts[found].line), "%s", u.line);
                    logouts[found].when = (time_t) u.sec;
                }
                break;
            default:
                break;
        }
        /* As util-linux: a login before this record and still open after it
         * ended with it -- "down" when the record was a shutdown, "crash"
         * when it was a boot with no shutdown before it. */
        if (down) {
            lastBoot = (time_t) u.sec;
            whyDown = shutdown ? LAST_DOWN : LAST_CRASH;
            logoutCount = 0;
        }
    }

    char begins[64] = "";
    time_t first = n > 0 ? (time_t) recs[0].sec : o.now;
    if (n == 0) {
        struct stat st;
        if (stat(file, &st) == 0)
            first = st.st_mtime;
    }
    lastFormat("%a %b %e %H:%M:%S %Y", first, begins, sizeof(begins));
    const char *base = strrchr(file, '/');
    printf("\n%s begins %s\n", base ? base + 1 : file, begins);
    free(logouts);
    free(recs);
    free(names);
    return 0;
}

/* --------------------------------------------------------------- finger */

typedef struct {
    char line[33];
    char host[257];
    time_t loginAt;
    long idle;          /* seconds; 0 when unknown */
    bool writable;
    bool statFailed;    /* the terminal could not be stat'ed */
} FingerWhere;

typedef struct {
    char name[33];
    char realName[256];
    char office[128], officePhone[64], homePhone[64];
    char dir[512], shell[256];
    FingerWhere *where;
    int whereCount;
} FingerPerson;

/* GECOS: name, office, office phone, home phone; '&' in the name is the login
 * with its first letter capitalised. */
static void fingerGecos(FingerPerson *p, const struct passwd *pw) {
    char gecos[512];
    snprintf(gecos, sizeof(gecos), "%s", pw->pw_gecos ? pw->pw_gecos : "");
    char *fields[4] = { gecos, NULL, NULL, NULL };
    for (int i = 1; i < 4; i++) {
        char *c = fields[i - 1] ? strchr(fields[i - 1], ',') : NULL;
        if (c == NULL)
            break;
        *c = '\0';
        fields[i] = c + 1;
    }
    size_t at = 0;
    for (const char *s = fields[0]; *s && at + 1 < sizeof(p->realName); s++) {
        if (*s == '&') {
            for (const char *l = pw->pw_name; *l && at + 1 < sizeof(p->realName); l++)
                p->realName[at++] = (l == pw->pw_name) ? (char) toupper((unsigned char) *l) : *l;
        } else {
            p->realName[at++] = *s;
        }
    }
    p->realName[at] = '\0';
    snprintf(p->office, sizeof(p->office), "%s", fields[1] ? fields[1] : "");
    snprintf(p->officePhone, sizeof(p->officePhone), "%s", fields[2] ? fields[2] : "");
    snprintf(p->homePhone, sizeof(p->homePhone), "%s", fields[3] ? fields[3] : "");
}

static void fingerFromPasswd(FingerPerson *p, const struct passwd *pw) {
    memset(p, 0, sizeof(*p));
    snprintf(p->name, sizeof(p->name), "%s", pw->pw_name);
    snprintf(p->dir, sizeof(p->dir), "%s", pw->pw_dir ? pw->pw_dir : "");
    snprintf(p->shell, sizeof(p->shell), "%s", pw->pw_shell && *pw->pw_shell ? pw->pw_shell : "/bin/sh");
    fingerGecos(p, pw);
}

static void fingerAddWhere(FingerPerson *p, const SmallclueUtmp *u, time_t now) {
    FingerWhere *grown = realloc(p->where, (size_t) (p->whereCount + 1) * sizeof(FingerWhere));
    if (grown == NULL)
        return;
    p->where = grown;
    FingerWhere *w = &p->where[p->whereCount++];
    memset(w, 0, sizeof(*w));
    snprintf(w->line, sizeof(w->line), "%s", u->line);
    snprintf(w->host, sizeof(w->host), "%s", u->host);
    w->loginAt = (time_t) u->sec;
    w->writable = false;
    char path[300];
    snprintf(path, sizeof(path), "/dev/%s", u->line);
    struct stat st;
    /* netkit's spelling of the path, double slash and all. */
    char shown[300];
    snprintf(shown, sizeof(shown), "/dev//%s", u->line);
    if (stat(path, &st) != 0) {
        fprintf(stderr, "finger: %s: %s\n", shown, strerror(errno));
        w->statFailed = true;
        return;
    }
    /* AOK-iSH's terminals keep no access time: no idle time, rather than
     * idle since 1970. */
    if (st.st_atime != 0 && now > st.st_atime)
        w->idle = (long) (now - st.st_atime);
    /* netkit's TALKABLE: owner and group may write. */
    w->writable = (st.st_mode & 0220) == 0220;
}

/* netkit's prphone: digits only get dashes; anything else is the user's own
 * formatting, left alone. */
static const char *fingerPhone(const char *num, char *buf, size_t size) {
    size_t len = 0;
    for (const char *p = num; *p; p++, len++)
        if (!isdigit((unsigned char) *p))
            return num;
    switch (len) {
        case 11: snprintf(buf, size, "+%c-%.3s-%.3s-%.4s", num[0], num + 1, num + 4, num + 7); return buf;
        case 10: snprintf(buf, size, "%.3s-%.3s-%.4s", num, num + 3, num + 6); return buf;
        case 7: snprintf(buf, size, "%.3s-%.4s", num, num + 3); return buf;
        case 5: snprintf(buf, size, "x%c-%.4s", num[0], num + 1); return buf;
        case 4: snprintf(buf, size, "x%.4s", num); return buf;
        default: return num;
    }
}

/* netkit's stimeprint: the short format's idle column. */
static void fingerShortIdle(long idle) {
    long days = idle / 86400, hours = (idle / 3600) % 24, mins = (idle / 60) % 60;
    if (days == 0) {
        if (hours == 0) {
            if (mins == 0)
                printf("    ");
            else
                printf("%4ld", mins);
        } else {
            printf("%ld:%02ld", hours, mins);   /* Debian's: no leading space */
        }
    } else {
        printf("%3ldd", days);
    }
}

/* The short format. Debian's finger sizes the first two columns to fit: the
 * login column is the longest login plus one (at least 10), the name column
 * the longest name plus two (at least 10), the two together at most 32, and a
 * name is cut to its column less one. ANYONE is the no-argument listing,
 * where a terminal that cannot be stat'ed is shown writable; given names, it
 * is not. */
static void fingerShort(FingerPerson *people, int count, time_t now, bool anyone) {
    int loginWidth = 10, nameWidth = 10;
    for (int i = 0; i < count; i++) {
        int l = (int) strlen(people[i].name) + 1, r = (int) strlen(people[i].realName) + 2;
        if (l > loginWidth)
            loginWidth = l;
        if (r > nameWidth)
            nameWidth = r;
    }
    if (nameWidth > 32 - loginWidth)
        nameWidth = 32 - loginWidth;
    if (nameWidth < 1)
        nameWidth = 1;
    printf("%-*s%-*s Tty      Idle  Login Time   Office     Office Phone\n",
           loginWidth, "Login", nameWidth, "Name");
    for (int i = 0; i < count; i++) {
        FingerPerson *p = &people[i];
        int rows = p->whereCount > 0 ? p->whereCount : 1;
        for (int r = 0; r < rows; r++) {
            printf("%-*.*s%-*.*s", loginWidth, loginWidth - 1, p->name,
                   nameWidth, nameWidth - 1, p->realName);
            FingerWhere *w = p->whereCount > 0 ? &p->where[r] : NULL;
            if (w == NULL) {
                printf("  *     *  No logins   ");
            } else {
                bool flagged = w->statFailed ? !anyone : !w->writable;
                putchar(flagged ? '*' : ' ');
                printf("%-8.8s ", w->line);
                fingerShortIdle(w->idle);
                printf("  ");
                char t[32];
                struct tm tm;
                localtime_r(&w->loginAt, &tm);
                strftime(t, sizeof(t), "%b %d", &tm);
                printf("%.6s", t);
                if (now - w->loginAt >= 86400L * 365 / 2) {
                    strftime(t, sizeof(t), "%Y", &tm);
                    printf("  %.4s", t);
                } else {
                    strftime(t, sizeof(t), "%H:%M", &tm);
                    printf(" %-5.5s", t);
                }
            }
            if (w != NULL && w->host[0] != '\0') {
                printf(" (%s)", w->host);
            } else {
                char buf[32];
                if (p->office[0] != '\0')
                    printf(" %-10.10s", p->office);
                else if (p->officePhone[0] != '\0')
                    printf(" %-10.10s", " ");
                if (p->officePhone[0] != '\0')
                    printf(" %-.15s", fingerPhone(p->officePhone, buf, sizeof(buf)));
            }
            putchar('\n');
        }
    }
}

/* netkit's demi_print: two fields to a line, the second at column 40. */
static int fingerDemiPrint(const char *str, int oddField, int *lenLast) {
    int lenThis = (int) strlen(str);
    if (oddField) {
        if (*lenLast <= 40 && lenThis + 40 <= 80) {
            int col = *lenLast;
            while (col < 40) {
                putchar('\t');
                col = (col + 8) & ~7;
            }
            printf("%s\n", str);
            return 0;
        }
        putchar('\n');
    }
    printf("%s", str);
    *lenLast = lenThis;
    return 1;
}

/* A dotfile in the person's home, shown under its heading, or false. */
static bool fingerShowFile(const char *dir, const char *name, const char *heading) {
    char path[700];
    snprintf(path, sizeof(path), "%s/%s", dir, name);
    FILE *f = fopen(path, "r");
    if (f == NULL)
        return false;
    printf("%s\n", heading);
    int c, last = '\n';
    while ((c = fgetc(f)) != EOF) {
        /* Control characters as ^X, as netkit's vis-like output does. */
        if (c != '\n' && c != '\t' && c < 32) {
            printf("^%c", c + '@');
        } else if (c == 127) {
            printf("^?");
        } else {
            putchar(c);
        }
        last = c;
    }
    fclose(f);
    if (last != '\n')
        putchar('\n');
    return true;
}

static void fingerLong(FingerPerson *p, bool plans, time_t now) {
    printf("Login: %-15s\t\t\tName: %s\nDirectory: %-25s\tShell: %-s\n",
           p->name, p->realName, p->dir, p->shell);
    int odd = 0, lenLast = 0;
    char buf[300], phone[32];
    if (p->office[0] != '\0' && p->officePhone[0] != '\0' &&
        strlen(p->office) + strlen(p->officePhone) + sizeof("Office") + 2 <= 40) {
        snprintf(buf, sizeof(buf), "Office: %s, %s", p->office,
                 fingerPhone(p->officePhone, phone, sizeof(phone)));
        odd = fingerDemiPrint(buf, odd, &lenLast);
    } else {
        if (p->office[0] != '\0') {
            snprintf(buf, sizeof(buf), "Office: %s", p->office);
            odd = fingerDemiPrint(buf, odd, &lenLast);
        }
        if (p->officePhone[0] != '\0') {
            snprintf(buf, sizeof(buf), "Office Phone: %s", fingerPhone(p->officePhone, phone, sizeof(phone)));
            odd = fingerDemiPrint(buf, odd, &lenLast);
        }
    }
    if (p->homePhone[0] != '\0') {
        snprintf(buf, sizeof(buf), "Home Phone: %s", fingerPhone(p->homePhone, phone, sizeof(phone)));
        odd = fingerDemiPrint(buf, odd, &lenLast);
    }
    if (odd)
        putchar('\n');

    if (p->whereCount == 0) {
        printf("Never logged in.\n");
    }
    size_t maxLine = 0;
    for (int i = 0; i < p->whereCount; i++)
        if (strlen(p->where[i].line) > maxLine)
            maxLine = strlen(p->where[i].line);
    for (int i = 0; i < p->whereCount; i++) {
        FingerWhere *w = &p->where[i];
        struct tm tm;
        localtime_r(&w->loginAt, &tm);
        char t[32], zone[16];
        strftime(t, sizeof(t), "%a %b %e %H:%M", &tm);
        strftime(zone, sizeof(zone), "%Z", &tm);
        /* Debian's lprint: the host follows the terminal, and the idle time
         * is spelled out after it -- on a line of its own when there was a
         * host -- with "(messages off)" on the next line. */
        printf("On since %.16s (%s) on %s", t, zone, w->line);
        if (w->host[0] != '\0')
            printf(" from %s", w->host);
        long days = w->idle / 86400, hours = (w->idle / 3600) % 24;
        long mins = (w->idle / 60) % 60, secs = w->idle % 60;
        bool idleShown = w->idle > 0;
        if (idleShown) {
            if (w->host[0] != '\0')
                putchar('\n');
            printf("%-*s", (int) (maxLine - strlen(w->line) + 3), "");
            if (days > 0)
                printf("%ld day%s ", days, days == 1 ? "" : "s");
            if (hours > 0)
                printf("%ld hour%s ", hours, hours == 1 ? "" : "s");
            if (mins > 0 && days == 0)
                printf("%ld minute%s ", mins, mins == 1 ? "" : "s");
            if (secs > 0 && days == 0 && hours == 0)
                printf("%ld second%s ", secs, secs == 1 ? "" : "s");
            printf("idle");
        }
        if (!w->writable && !w->statFailed) {
            if (idleShown)
                putchar('\n');
            printf("     (messages off)");
        }
        putchar('\n');
    }

    char mail[400];
    snprintf(mail, sizeof(mail), "/var/mail/%s", p->name);
    struct stat st;
    if (stat(mail, &st) != 0 || st.st_size == 0) {
        printf("No mail.\n");
    } else {
        char t[64];
        struct tm tm;
        if (st.st_mtime > st.st_atime) {
            localtime_r(&st.st_mtime, &tm);
            strftime(t, sizeof(t), "%a %b %e %H:%M %Y (%Z)", &tm);
            printf("New mail received %s\n", t);
            localtime_r(&st.st_atime, &tm);
            strftime(t, sizeof(t), "%a %b %e %H:%M %Y (%Z)", &tm);
            printf("     Unread since %s\n", t);
        } else {
            localtime_r(&st.st_atime, &tm);
            strftime(t, sizeof(t), "%a %b %e %H:%M %Y (%Z)", &tm);
            printf("Mail last read %s\n", t);
        }
    }
    (void) now;
    if (plans) {
        fingerShowFile(p->dir, ".pgpkey", "PGP key:");
        fingerShowFile(p->dir, ".project", "Project:");
        if (!fingerShowFile(p->dir, ".plan", "Plan:"))
            printf("No Plan.\n");
    }
}

static int fingerByLogin(const void *a, const void *b) {
    return strcmp(((const FingerPerson *) a)->name, ((const FingerPerson *) b)->name);
}

int smallclueFingerCommand(int argc, char **argv) {
    bool shortForm = false, longForm = false, plans = true;
    int firstArg = argc;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--help") == 0) {
            printf("usage: finger [-lmps] [login ...]\n");
            return 0;
        }
        if (a[0] != '-' || a[1] == '\0') {
            firstArg = i;
            break;
        }
        for (const char *p = a + 1; *p; p++) {
            switch (*p) {
                case 's': shortForm = true; break;
                case 'l': longForm = true; break;
                case 'p': plans = false; break;
                case 'm': break;   /* names are matched exactly anyway, as Debian's */
                case 'o': case 'h': break;
                default:
                    fprintf(stderr, "finger: invalid option -- '%c'\n", *p);
                    fprintf(stderr, "usage: finger [-lmps] [login ...]\n");
                    return 1;
            }
        }
    }

    time_t now = time(NULL);
    SmallclueUtmp *recs = NULL;
    int n = smallclueUtmpReadAll(SMALLCLUE_UTMP_PATH, &recs);
    if (n < 0)
        n = 0;

    FingerPerson *people = NULL;
    int count = 0;
    if (firstArg >= argc) {
        /* Everyone logged in, in utmp order, one entry per person. */
        for (int i = 0; i < n; i++) {
            if (!isLoginRecord(&recs[i]))
                continue;
            int k;
            for (k = 0; k < count; k++)
                if (strcmp(people[k].name, recs[i].user) == 0)
                    break;
            if (k == count) {
                struct passwd *pw = getpwnam(recs[i].user);
                FingerPerson *grown = realloc(people, (size_t) (count + 1) * sizeof(FingerPerson));
                if (grown == NULL)
                    break;
                people = grown;
                if (pw != NULL) {
                    fingerFromPasswd(&people[count], pw);
                } else {
                    memset(&people[count], 0, sizeof(FingerPerson));
                    snprintf(people[count].name, sizeof(people[count].name), "%s", recs[i].user);
                    snprintf(people[count].realName, sizeof(people[count].realName), "???");
                }
                count++;
            }
            fingerAddWhere(&people[k], &recs[i], now);
        }
        if (count == 0) {
            printf("No one logged on.\n");
            free(recs);
            return 0;
        }
        qsort(people, (size_t) count, sizeof(FingerPerson), fingerByLogin);
        if (longForm && !shortForm) {
            for (int i = 0; i < count; i++) {
                if (i > 0)
                    putchar('\n');
                fingerLong(&people[i], plans, now);
            }
        } else {
            fingerShort(people, count, now, true);
        }
    } else {
        for (int i = firstArg; i < argc; i++) {
            const char *who = argv[i];
            int before = count;
            struct passwd *pw = getpwnam(who);
            if (pw != NULL) {
                FingerPerson *grown = realloc(people, (size_t) (count + 1) * sizeof(FingerPerson));
                if (grown == NULL)
                    break;
                people = grown;
                fingerFromPasswd(&people[count++], pw);
            }
            if (count == before)
                fprintf(stderr, "finger: %s: no such user.\n", who);
        }
        for (int k = 0; k < count; k++)
            for (int i = 0; i < n; i++)
                if (isLoginRecord(&recs[i]) && strcmp(recs[i].user, people[k].name) == 0)
                    fingerAddWhere(&people[k], &recs[i], now);
        qsort(people, (size_t) count, sizeof(FingerPerson), fingerByLogin);
        if (shortForm) {
            if (count > 0)
                fingerShort(people, count, now, false);
        } else {
            for (int i = 0; i < count; i++) {
                if (i > 0)
                    putchar('\n');
                fingerLong(&people[i], plans, now);
            }
        }
    }
    for (int i = 0; i < count; i++)
        free(people[i].where);
    free(people);
    free(recs);
    return 0;
}
