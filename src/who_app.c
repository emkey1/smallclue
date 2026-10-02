/* who, users -- who is logged in, from /var/run/utmp (utmp_rec.c).
 *
 * The output is coreutils': who prints NAME, LINE, TIME as "%Y-%m-%d %H:%M"
 * and the host in parentheses; -b the boot, -r the runlevel, -q the names
 * and a count, -H a header, -u the idle time and pid, -m (or `who am i`)
 * only the terminal on standard input. users prints the names, sorted, on
 * one line. A FILE argument reads that file instead of /var/run/utmp, as
 * coreutils' does (`who /var/log/wtmp` lists every login there). */

#include "who_app.h"
#include "utmp_rec.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static void whoTime(int64_t sec, char *buf, size_t size) {
    time_t t = (time_t) sec;
    struct tm tm;
    if (localtime_r(&t, &tm) == NULL || strftime(buf, size, "%Y-%m-%d %H:%M", &tm) == 0)
        snprintf(buf, size, "?");
}

/* Idle time as coreutils prints it: "." under a minute, "old" over a day,
 * else HH:MM -- from the terminal's last access. */
static void whoIdle(const char *line, char *buf, size_t size) {
    char path[64];
    snprintf(path, sizeof(path), "/dev/%s", line);
    struct stat st;
    if (stat(path, &st) != 0) {
        snprintf(buf, size, "  ?  ");
        return;
    }
    time_t idle = time(NULL) - st.st_atime;
    if (idle < 60)
        snprintf(buf, size, "  .  ");
    else if (idle >= 24 * 60 * 60)
        snprintf(buf, size, " old ");
    else
        snprintf(buf, size, "%02d:%02d", (int) (idle / 3600), (int) ((idle % 3600) / 60));
}

static int cmpNames(const void *a, const void *b) {
    return strcmp(*(char *const *) a, *(char *const *) b);
}

static bool isLogin(const SmallclueUtmp *r) {
    return r->type == SMALLCLUE_UT_USER_PROCESS && r->user[0] != '\0';
}

int smallclueWhoCommand(int argc, char **argv) {
    bool boot = false, runlevel = false, quick = false, heading = false, idle = false, me = false;
    const char *file = SMALLCLUE_UTMP_PATH;
    int args = 0;
    const char *words[2] = { NULL, NULL };
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (a[0] == '-' && a[1] != '\0') {
            if (strcmp(a, "--help") == 0) {
                printf("usage: who [-bHmqru] [FILE | am i]\n");
                return 0;
            }
            for (const char *p = a + 1; *p; p++) {
                switch (*p) {
                    case 'b': boot = true; break;
                    case 'r': runlevel = true; break;
                    case 'q': quick = true; break;
                    case 'H': heading = true; break;
                    case 'u': idle = true; break;
                    case 'm': me = true; break;
                    case 's': break;   /* the default format */
                    default:
                        fprintf(stderr, "who: invalid option -- '%c'\n", *p);
                        fprintf(stderr, "usage: who [-bHmqru] [FILE | am i]\n");
                        return 1;
                }
            }
        } else if (args < 2) {
            words[args++] = a;
        } else {
            fprintf(stderr, "who: extra operand '%s'\n", a);
            return 1;
        }
    }
    if (args == 2) {
        me = true;   /* who am i, who mom likes: any two words */
    } else if (args == 1) {
        file = words[0];
    }

    char myLine[33] = "", myId[5];
    if (me && !smallclueUtmpLineForFd(STDIN_FILENO, myLine, myId))
        return 0;   /* not on a terminal: nothing is "this" session */

    SmallclueUtmp *recs = NULL;
    int n = smallclueUtmpReadAll(file, &recs);
    if (n < 0) {
        /* coreutils prints nothing for a missing utmp, and succeeds. */
        return 0;
    }

    if (quick) {
        int users = 0;
        for (int i = 0; i < n; i++) {
            if (!isLogin(&recs[i]))
                continue;
            printf("%s%s", users ? " " : "", recs[i].user);
            users++;
        }
        printf("\n# users=%d\n", users);
        free(recs);
        return 0;
    }

    if (heading)
        printf("%-8s %-12s %-16s %s\n", "NAME", "LINE", "TIME", idle ? "IDLE          PID COMMENT" : "COMMENT");
    bool loginsWanted = !boot && !runlevel;
    for (int i = 0; i < n; i++) {
        const SmallclueUtmp *r = &recs[i];
        char when[32];
        whoTime(r->sec, when, sizeof(when));
        if (boot && r->type == SMALLCLUE_UT_BOOT_TIME) {
            printf("%-8s %-12s %s\n", "", "system boot", when);
        } else if (runlevel && r->type == SMALLCLUE_UT_RUN_LVL) {
            int level = r->pid & 0xff, last = (r->pid >> 8) & 0xff;
            char what[16];
            snprintf(what, sizeof(what), "run-level %c", level ? level : '?');
            printf("%-8s %-12s %s", "", what, when);
            if (last && last != 'N')
                printf("%*slast=%c", 17 - (int) strlen(when), "", last);
            printf("\n");
        } else if (loginsWanted && isLogin(r)) {
            if (me && strcmp(r->line, myLine) != 0)
                continue;
            printf("%-8s %-12s %s", r->user, r->line, when);
            if (idle) {
                char idleBuf[16];
                whoIdle(r->line, idleBuf, sizeof(idleBuf));
                printf(" %s %10d", idleBuf, (int) r->pid);
            }
            if (r->host[0])
                printf(" (%s)", r->host);
            printf("\n");
        }
    }
    free(recs);
    return 0;
}

int smallclueUsersCommand(int argc, char **argv) {
    const char *file = SMALLCLUE_UTMP_PATH;
    if (argc > 2) {
        fprintf(stderr, "users: extra operand '%s'\n", argv[2]);
        return 1;
    }
    if (argc == 2) {
        if (strcmp(argv[1], "--help") == 0) {
            printf("usage: users [FILE]\n");
            return 0;
        }
        file = argv[1];
    }
    SmallclueUtmp *recs = NULL;
    int n = smallclueUtmpReadAll(file, &recs);
    if (n <= 0) {
        free(recs);
        return 0;
    }
    char **names = calloc((size_t) n, sizeof(*names));
    int count = 0;
    for (int i = 0; names && i < n; i++) {
        if (isLogin(&recs[i]))
            names[count++] = recs[i].user;
    }
    if (count) {
        qsort(names, (size_t) count, sizeof(*names), cmpNames);
        for (int i = 0; i < count; i++)
            printf("%s%s", i ? " " : "", names[i]);
        printf("\n");
    }
    free(names);
    free(recs);
    return 0;
}
