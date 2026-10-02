/* init, runit, sv, and halt/poweroff/reboot: a small service system.
 *
 * init is pid 1. It runs /etc/rc once, then reaps whatever is reparented to
 * it for as long as the system is up, and shuts the system down when it is
 * signalled to -- the sysvinit/busybox shape:
 *
 *     SIGTERM  reboot        SIGUSR1  halt        SIGUSR2  poweroff
 *
 * which is also what halt, poweroff and reboot send it. Shutting down means
 * /etc/rc.shutdown, then SIGTERM to everything, a grace period, and SIGKILL.
 * On a system where pid 1 exiting ends everything (iSH-AOK: the app shows
 * "System Halted"), returning from init IS the halt.
 *
 * runit supervises /etc/service/<name>/run: it starts each, restarts one that
 * dies (with a backoff), honours a `down` file, and takes `sv` commands. Its
 * state lives in /run/service/<name>/ (pid, stat, since) so that `sv status`
 * and a restarted runit can read it.
 *
 * None of this forks: children are started through smallclueSpawn (spawn.h),
 * because on a platform running smallclue as host code inside one process
 * there is no fork() to return twice.
 *
 * Restore: a platform that checkpoints and restores processes (iSH-AOK) may
 * re-launch init and runit from their argv after restoring the processes they
 * had started. smallclueHostWasRestored() says so, and both then carry on with
 * what is already running instead of starting it all a second time.
 */

#include "init_app.h"
#include "spawn.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* Provided by an embedding host that can restore a process: true while the
 * running program is one the host re-launched after a restore. */
bool smallclueHostWasRestored(void) __attribute__((weak));

static bool initWasRestored(void) {
    return smallclueHostWasRestored != NULL && smallclueHostWasRestored();
}

static const char *initBaseName(const char *path) {
    const char *slash = path ? strrchr(path, '/') : NULL;
    return slash ? slash + 1 : (path ? path : "");
}

static time_t initNow(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return time(NULL);
    }
    return ts.tv_sec;
}

/* ------------------------------------------------------------------ init */

static volatile sig_atomic_t initShutdownSignal = 0;

static void initOnShutdownSignal(int sig) {
    initShutdownSignal = sig;
}

/* Start SCRIPT (or, failing that, SCRIPT under exsh -- PSCAL's own roots have
 * an rc that is an exsh script) and return its pid, or -1. */
static pid_t initStartScript(const char *script) {
    char *argv[] = { (char *)script, NULL };
    SmallclueSpawnAttempt attempts[2];
    size_t count = 0;
    attempts[count++] = (SmallclueSpawnAttempt){ script, argv, 0 };
    char exshPath[PATH_MAX];
    char *exshArgv[] = { exshPath, (char *)script, NULL };
    if (smallclueResolveExshPath(exshPath, sizeof(exshPath))) {
        attempts[count++] = (SmallclueSpawnAttempt){ exshPath, exshArgv, 0 };
    }
    SmallclueSpawnRequest request = { attempts, count, 0 };
    return smallclueSpawn(&request);
}

/* Reap until PID has exited, the deadline (seconds from now; 0 = none) passes,
 * or a shutdown is requested while STOP_ON_SHUTDOWN. Every other child that
 * exits meanwhile is reaped too: init is the parent of every orphan. Returns
 * true when PID was reaped. */
static bool initWaitFor(pid_t pid, int timeoutSeconds, bool stopOnShutdown, int *statusOut) {
    time_t deadline = timeoutSeconds > 0 ? initNow() + timeoutSeconds : 0;
    for (;;) {
        if (stopOnShutdown && initShutdownSignal) {
            return false;
        }
        int status = 0;
        pid_t reaped = waitpid(-1, &status, deadline ? WNOHANG : 0);
        if (reaped == pid) {
            if (statusOut) {
                *statusOut = status;
            }
            return true;
        }
        if (reaped > 0) {
            continue;
        }
        if (reaped < 0 && errno == ECHILD) {
            return false;
        }
        if (deadline) {
            if (initNow() >= deadline) {
                return false;
            }
            usleep(100000);
        }
        /* EINTR: a signal; loop and look at the flag. */
    }
}

/* Reap everything that has exited, for up to SECONDS; stop early once there
 * are no children left at all. */
static void initReapFor(int seconds) {
    time_t deadline = initNow() + seconds;
    while (initNow() < deadline) {
        int status = 0;
        pid_t reaped = waitpid(-1, &status, WNOHANG);
        if (reaped > 0) {
            continue;
        }
        if (reaped < 0 && errno == ECHILD) {
            return;
        }
        usleep(100000);
    }
}

static void initRunRc(void) {
    char rcPath[PATH_MAX];
    if (!smallclueResolveEtcEntry("rc", F_OK, rcPath, sizeof(rcPath))) {
        return;   /* no rc: nothing to start, and that is fine */
    }
    pid_t pid = initStartScript(rcPath);
    if (pid < 0) {
        fprintf(stderr, "init: cannot run %s: %s\n", rcPath, strerror(errno));
        return;
    }
    int status = 0;
    if (initWaitFor(pid, 0, true, &status)) {
        if (WIFEXITED(status) && WEXITSTATUS(status) != 0) {
            fprintf(stderr, "init: %s exited with status %d\n", rcPath, WEXITSTATUS(status));
        } else if (WIFSIGNALED(status)) {
            fprintf(stderr, "init: %s terminated by signal %d\n", rcPath, WTERMSIG(status));
        }
    }
}

static void initShutdown(bool isPid1) {
    char path[PATH_MAX];
    if (smallclueResolveEtcEntry("rc.shutdown", F_OK, path, sizeof(path))) {
        pid_t pid = initStartScript(path);
        if (pid > 0 && !initWaitFor(pid, 10, false, NULL)) {
            kill(pid, SIGKILL);
        }
    }
    if (!isPid1) {
        return;   /* service mode: everything else is not ours to stop */
    }
    kill(-1, SIGTERM);
    kill(-1, SIGCONT);
    initReapFor(3);
    kill(-1, SIGKILL);
    initReapFor(1);
}

int smallclueInitCommand(int argc, char **argv) {
    bool allowNonPid1 = false;
    for (int i = 1; i < argc; ++i) {
        const char *arg = argv[i] ? argv[i] : "";
        if (strcmp(arg, "--service-mode") == 0 ||
            strcmp(arg, "--allow-non-pid1") == 0 ||
            strcmp(arg, "-S") == 0) {
            allowNonPid1 = true;
            continue;
        }
        if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
            printf("usage: init [--service-mode|-S|--allow-non-pid1]\n");
            printf("  --service-mode        allow init compatibility mode when PID != 1\n");
            printf("  --allow-non-pid1      same as --service-mode\n");
            return 0;
        }
        fprintf(stderr, "init: unknown option '%s'\n", arg);
        fprintf(stderr, "usage: init [--service-mode|-S|--allow-non-pid1]\n");
        return 1;
    }
    bool isPid1 = getpid() == 1;
    if (!isPid1 && !allowNonPid1) {
        fprintf(stderr, "init: must be run as PID 1\n");
        fprintf(stderr, "init: use --service-mode to run in compatibility mode on iOS/iPadOS\n");
        return 1;
    }

    /* No SA_RESTART: a shutdown signal has to interrupt the wait below. */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = initOnShutdownSignal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGUSR1, &sa, NULL);
    sigaction(SIGUSR2, &sa, NULL);
    signal(SIGINT, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);
    signal(SIGTSTP, SIG_IGN);
    signal(SIGHUP, SIG_IGN);

    /* After a restore, what rc started is running again already. */
    if (!initWasRestored()) {
        initRunRc();
    }

    /* Then be the reaper of last resort until told to stop. A system whose rc
     * is its whole session (PSCAL's runs exsh) ends it with `poweroff`. */
    while (!initShutdownSignal) {
        int status = 0;
        pid_t reaped = waitpid(-1, &status, 0);
        if (reaped < 0 && errno == ECHILD) {
            sleep(1);
        }
    }

    initShutdown(isPid1);
    return 0;
}

/* ------------------------------------------------- halt, poweroff, reboot */

/* halt, poweroff and reboot share one applet, told apart by argv[0], and take
 * sysvinit's option set because that is what Debian's own rc scripts pass:
 *
 *     /etc/init.d/halt:63        halt -d -f $netdown $poweroff $hddown
 *     /etc/init.d/reboot:25      reboot -d -f ${netdown}
 *     /etc/init.d/umountnfs.sh:36  halt -w
 *
 * Most of them describe hardware and bookkeeping this system does not have --
 * there is no wtmp to write (-d, -w), no interfaces of its own to bring down
 * (-i), and no disks to spin down (-h, -H) -- so they are accepted and do
 * nothing, which is the honest behaviour rather than a refusal that breaks the
 * script.
 *
 * -w is the exception and must not be lumped in with them: it means "write the
 * wtmp record and DO NOT halt". umountnfs.sh runs it midway through shutdown,
 * so treating it as just another no-op flag would turn that line into a real
 * halt. It returns without stopping anything.
 *
 * The request itself goes to init, as busybox's does: USR1 halt, USR2
 * poweroff, TERM reboot. -f would call reboot(2) directly on Linux; a system
 * that refuses that (iSH-AOK does) has init as its only way down, so -f asks
 * init too. These used to print "System halt requested" and exit 0 having
 * halted nothing. */
int smallclueHaltCommand(int argc, char **argv) {
    static const char *usage = "usage: halt|poweroff|reboot [-dfhHinpw]\n";
    const char *cmd = initBaseName(argc > 0 ? argv[0] : "halt");
    int recordOnly = 0;
    int poweroff = strcmp(cmd, "poweroff") == 0;

    for (int argi = 1; argi < argc; ++argi) {
        const char *arg = argv[argi];
        if (strcmp(arg, "--") == 0) {
            break;
        }
        if (arg[0] != '-' || arg[1] == '\0') {
            continue;
        }
        if (arg[1] == '-') {
            const char *lopt = arg + 2;
            if (strcmp(lopt, "wtmp-only") == 0) {
                recordOnly = 1;
            } else if (strcmp(lopt, "poweroff") == 0) {
                poweroff = 1;
            } else if (strcmp(lopt, "force") == 0 || strcmp(lopt, "no-wtmp") == 0 ||
                       strcmp(lopt, "no-wall") == 0 || strcmp(lopt, "halt") == 0 ||
                       strcmp(lopt, "hddown") == 0 || strcmp(lopt, "ifdown") == 0 ||
                       strcmp(lopt, "no-sync") == 0) {
                /* Nothing here keeps a wtmp, an interface list or a disk. */
            } else if (strcmp(lopt, "help") == 0) {
                fputs(usage, stdout);
                return 0;
            } else {
                fprintf(stderr, "%s: unrecognized option '%s'\n", cmd, arg);
                fputs(usage, stderr);
                return 1;
            }
            continue;
        }
        for (const char *p = arg + 1; *p; ++p) {
            switch (*p) {
                case 'w': recordOnly = 1; break;
                case 'p': poweroff = 1; break;
                case 'f': /* no reboot(2) to call: init is the way down */ break;
                case 'd': /* skip the wtmp record: there is none */ break;
                case 'n': /* skip the sync: nothing is buffered here */ break;
                case 'i': /* bring interfaces down: none are ours */ break;
                case 'h': case 'H': /* park the disks: there are none */ break;
                default:
                    fprintf(stderr, "%s: illegal option -- %c\n", cmd, *p);
                    fputs(usage, stderr);
                    return 1;
            }
        }
    }

    if (recordOnly) {
        /* -w records and returns; stopping here is the whole point of it. */
        return 0;
    }

#if defined(PSCAL_TARGET_IOS)
    /* The PSCAL app has no init to ask: ending the shell runtime is the halt. */
    printf("System %s requested...\n", cmd);
    exit(0);
#else
    int sig = SIGUSR1;
    if (strcmp(cmd, "reboot") == 0) {
        sig = SIGTERM;
    } else if (poweroff) {
        sig = SIGUSR2;
    }
    if (kill(1, sig) != 0) {
        fprintf(stderr, "%s: cannot signal init: %s\n", cmd, strerror(errno));
        return 1;
    }
    return 0;
#endif
}

/* ------------------------------------------------------------- runit, sv */

#define RUNIT_DEFAULT_DIR "/etc/service"
#define RUNIT_STATE_DIR "/run/service"
#define RUNIT_PIDFILE RUNIT_STATE_DIR "/.runit.pid"
#define RUNIT_MAX_SERVICES 128
#define RUNIT_MAX_BACKOFF 60
#define RUNIT_STOP_GRACE 5

typedef struct {
    char name[NAME_MAX + 1];
    char dir[PATH_MAX];
    pid_t pid;
    bool wantUp;
    bool present;          /* still in the service directory */
    bool stopping;
    time_t since;          /* wall clock: when the state last changed */
    time_t startedMono;
    time_t nextStartMono;  /* backoff: not before this */
    time_t killAtMono;     /* stopping: SIGKILL after this */
    int backoff;
    bool restartNow;       /* sv restart: no backoff once it is down */
} RunitService;

static RunitService runitServices[RUNIT_MAX_SERVICES];
static int runitServiceCount = 0;
static volatile sig_atomic_t runitTerm = 0;
static volatile sig_atomic_t runitHup = 0;

static void runitOnTerm(int sig) { (void)sig; runitTerm = 1; }
static void runitOnHup(int sig) { (void)sig; runitHup = 1; }

static void runitMkdirs(const char *name) {
    mkdir("/run", 0755);
    mkdir(RUNIT_STATE_DIR, 0755);
    if (name) {
        char path[PATH_MAX];
        snprintf(path, sizeof(path), RUNIT_STATE_DIR "/%s", name);
        mkdir(path, 0755);
    }
}

static void runitWriteFile(const char *name, const char *file, const char *text) {
    char path[PATH_MAX], tmp[PATH_MAX];
    snprintf(path, sizeof(path), RUNIT_STATE_DIR "/%s/%s", name, file);
    snprintf(tmp, sizeof(tmp), "%s.new", path);
    FILE *f = fopen(tmp, "w");
    if (!f) {
        return;
    }
    fputs(text, f);
    fclose(f);
    rename(tmp, path);
}

static bool runitReadFile(const char *name, const char *file, char *buf, size_t size) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), RUNIT_STATE_DIR "/%s/%s", name, file);
    FILE *f = fopen(path, "r");
    if (!f) {
        return false;
    }
    size_t n = fread(buf, 1, size - 1, f);
    fclose(f);
    buf[n] = '\0';
    char *nl = strchr(buf, '\n');
    if (nl) {
        *nl = '\0';
    }
    return true;
}

static void runitPublish(RunitService *s) {
    char text[64];
    const char *stat = s->pid > 0 ? (s->stopping ? "stopping" : "run")
                     : (s->wantUp ? "backoff" : "down");
    runitMkdirs(s->name);
    snprintf(text, sizeof(text), "%s\n", stat);
    runitWriteFile(s->name, "stat", text);
    snprintf(text, sizeof(text), "%d\n", s->pid > 0 ? (int)s->pid : 0);
    runitWriteFile(s->name, "pid", text);
    snprintf(text, sizeof(text), "%lld\n", (long long)s->since);
    runitWriteFile(s->name, "since", text);
}

static RunitService *runitFind(const char *name) {
    for (int i = 0; i < runitServiceCount; i++) {
        if (strcmp(runitServices[i].name, name) == 0) {
            return &runitServices[i];
        }
    }
    return NULL;
}

static RunitService *runitFindPid(pid_t pid) {
    for (int i = 0; i < runitServiceCount; i++) {
        if (runitServices[i].pid == pid) {
            return &runitServices[i];
        }
    }
    return NULL;
}

static void runitStart(RunitService *s) {
    char run[PATH_MAX];
    snprintf(run, sizeof(run), "%s/run", s->dir);
    char *argv[] = { run, NULL };
    /* runit runs ./run in the service directory, in a process group of its
     * own so that stopping it reaches whatever it started. */
    char cwd[PATH_MAX];
    bool haveCwd = getcwd(cwd, sizeof(cwd)) != NULL;
    if (chdir(s->dir) != 0) {
        haveCwd = false;
    }
    SmallclueSpawnAttempt attempt = { run, argv, 0 };
    SmallclueSpawnRequest request = { &attempt, 1, 1 };
    pid_t pid = smallclueSpawn(&request);
    if (haveCwd) {
        (void)chdir(cwd);
    } else {
        (void)chdir("/");
    }
    if (pid < 0) {
        fprintf(stderr, "runit: %s: cannot start: %s\n", s->name, strerror(errno));
        s->backoff = s->backoff ? s->backoff * 2 : 1;
        if (s->backoff > RUNIT_MAX_BACKOFF) {
            s->backoff = RUNIT_MAX_BACKOFF;
        }
        s->nextStartMono = initNow() + s->backoff;
        return;
    }
    s->pid = pid;
    s->stopping = false;
    s->startedMono = initNow();
    s->since = time(NULL);
    runitPublish(s);
}

static void runitStop(RunitService *s) {
    s->wantUp = false;
    if (s->pid > 0 && !s->stopping) {
        kill(-s->pid, SIGTERM);
        kill(s->pid, SIGTERM);
        kill(-s->pid, SIGCONT);
        s->stopping = true;
        s->killAtMono = initNow() + RUNIT_STOP_GRACE;
    }
    runitPublish(s);
}

/* Look at the service directory again: new services are added (up unless
 * they have a `down` file), vanished ones are stopped and forgotten. */
static void runitScan(const char *serviceDir, bool restored) {
    for (int i = 0; i < runitServiceCount; i++) {
        runitServices[i].present = false;
    }
    DIR *dir = opendir(serviceDir);
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_name[0] == '.') {
                continue;
            }
            char run[PATH_MAX];
            snprintf(run, sizeof(run), "%s/%s/run", serviceDir, entry->d_name);
            if (access(run, X_OK) != 0) {
                continue;
            }
            RunitService *s = runitFind(entry->d_name);
            if (!s) {
                if (runitServiceCount >= RUNIT_MAX_SERVICES) {
                    continue;
                }
                s = &runitServices[runitServiceCount++];
                memset(s, 0, sizeof(*s));
                snprintf(s->name, sizeof(s->name), "%s", entry->d_name);
                snprintf(s->dir, sizeof(s->dir), "%s/%s", serviceDir, entry->d_name);
                char down[PATH_MAX];
                snprintf(down, sizeof(down), "%s/down", s->dir);
                s->wantUp = access(down, F_OK) != 0;
                s->since = time(NULL);
                if (restored) {
                    /* Restored with the rest of the system: adopt what the
                     * earlier runit started rather than starting it again. */
                    char buf[64];
                    if (runitReadFile(s->name, "pid", buf, sizeof(buf))) {
                        pid_t pid = (pid_t)strtol(buf, NULL, 10);
                        if (pid > 0 && kill(pid, 0) == 0) {
                            s->pid = pid;
                            s->startedMono = initNow();
                        }
                    }
                    if (runitReadFile(s->name, "since", buf, sizeof(buf))) {
                        s->since = (time_t)strtoll(buf, NULL, 10);
                    }
                }
                runitPublish(s);
            }
            s->present = true;
        }
        closedir(dir);
    }
    for (int i = 0; i < runitServiceCount; i++) {
        if (!runitServices[i].present && runitServices[i].wantUp) {
            runitStop(&runitServices[i]);
        }
    }
}

/* Act on what `sv` asked for: /run/service/<name>/want holds up, down,
 * restart or once, and is consumed. */
static void runitTakeRequests(void) {
    for (int i = 0; i < runitServiceCount; i++) {
        RunitService *s = &runitServices[i];
        char want[32];
        if (!runitReadFile(s->name, "want", want, sizeof(want))) {
            continue;
        }
        char path[PATH_MAX];
        snprintf(path, sizeof(path), RUNIT_STATE_DIR "/%s/want", s->name);
        unlink(path);
        if (strcmp(want, "down") == 0) {
            runitStop(s);
        } else if (strcmp(want, "up") == 0) {
            s->wantUp = true;
            s->backoff = 0;
            s->nextStartMono = 0;
        } else if (strcmp(want, "restart") == 0) {
            if (s->pid > 0) {
                runitStop(s);
                s->restartNow = true;
            }
            s->wantUp = true;
            s->backoff = 0;
            s->nextStartMono = 0;
        }
        runitPublish(s);
    }
}

int smallclueRunitCommand(int argc, char **argv) {
    const char *serviceDir = argc > 1 ? argv[1] : RUNIT_DEFAULT_DIR;
    if (argc > 1 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
        printf("usage: runit [DIR]\n"
               "  Supervise DIR/<name>/run (default " RUNIT_DEFAULT_DIR "); see sv.\n");
        return 0;
    }
    struct stat st;
    if (stat(serviceDir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "runit: cannot open service directory '%s': %s\n",
                serviceDir, strerror(errno ? errno : ENOTDIR));
        return 1;
    }
    bool restored = initWasRestored();
    runitMkdirs(NULL);
    {
        char text[32];
        snprintf(text, sizeof(text), "%d\n", (int)getpid());
        FILE *f = fopen(RUNIT_PIDFILE, "w");
        if (f) {
            fputs(text, f);
            fclose(f);
        }
    }

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = runitOnTerm;
    sigaction(SIGTERM, &sa, NULL);
    sa.sa_handler = runitOnHup;
    sigaction(SIGHUP, &sa, NULL);
    signal(SIGINT, SIG_IGN);

    runitScan(serviceDir, restored);
    time_t nextScan = initNow() + 5;
    while (!runitTerm) {
        if (runitHup || initNow() >= nextScan) {
            runitHup = 0;
            runitScan(serviceDir, false);
            nextScan = initNow() + 5;
        }
        runitTakeRequests();

        int status = 0;
        pid_t pid;
        while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
            RunitService *s = runitFindPid(pid);
            if (!s) {
                continue;
            }
            time_t ran = initNow() - s->startedMono;
            s->pid = 0;
            s->stopping = false;
            s->since = time(NULL);
            if (s->wantUp && s->restartNow) {
                s->restartNow = false;
                s->backoff = 0;
                s->nextStartMono = 0;
            } else if (s->wantUp) {
                /* A service that ran a while restarts at once; one that keeps
                 * dying waits longer each time. */
                s->backoff = ran >= 10 ? 1 : (s->backoff ? s->backoff * 2 : 1);
                if (s->backoff > RUNIT_MAX_BACKOFF) {
                    s->backoff = RUNIT_MAX_BACKOFF;
                }
                s->nextStartMono = initNow() + s->backoff;
            }
            runitPublish(s);
        }

        time_t now = initNow();
        for (int i = 0; i < runitServiceCount; i++) {
            RunitService *s = &runitServices[i];
            if (s->wantUp && s->pid == 0 && s->present && now >= s->nextStartMono) {
                runitStart(s);
            }
            if (s->stopping && s->pid > 0 && now >= s->killAtMono) {
                kill(-s->pid, SIGKILL);
                kill(s->pid, SIGKILL);
            }
        }
        sleep(1);
    }

    /* Stopping: everything down, then wait out the grace period. */
    for (int i = 0; i < runitServiceCount; i++) {
        runitStop(&runitServices[i]);
    }
    time_t deadline = initNow() + RUNIT_STOP_GRACE;
    for (;;) {
        bool any = false;
        int status = 0;
        pid_t pid;
        while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
            RunitService *s = runitFindPid(pid);
            if (s) {
                s->pid = 0;
                s->stopping = false;
                s->since = time(NULL);
                runitPublish(s);
            }
        }
        for (int i = 0; i < runitServiceCount; i++) {
            if (runitServices[i].pid > 0) {
                any = true;
            }
        }
        if (!any) {
            break;
        }
        if (initNow() >= deadline) {
            for (int i = 0; i < runitServiceCount; i++) {
                if (runitServices[i].pid > 0) {
                    kill(-runitServices[i].pid, SIGKILL);
                    kill(runitServices[i].pid, SIGKILL);
                }
            }
            initReapFor(1);
            break;
        }
        usleep(100000);
    }
    unlink(RUNIT_PIDFILE);
    return 0;
}

static pid_t svRunitPid(void) {
    FILE *f = fopen(RUNIT_PIDFILE, "r");
    if (!f) {
        return -1;
    }
    int pid = -1;
    if (fscanf(f, "%d", &pid) != 1) {
        pid = -1;
    }
    fclose(f);
    if (pid <= 0 || kill((pid_t)pid, 0) != 0) {
        return -1;
    }
    return (pid_t)pid;
}

static void svUsage(FILE *out) {
    fprintf(out, "usage: sv [-w SEC] status|up|down|restart|start|stop SERVICE...\n"
                 "  SERVICE is a name under " RUNIT_DEFAULT_DIR " or a path to one\n");
}

static int svStatus(const char *arg, const char *name) {
    char stat[32], pidText[32], sinceText[32];
    if (!runitReadFile(name, "stat", stat, sizeof(stat))) {
        printf("fail: %s: runit has not seen this service\n", arg);
        return 1;
    }
    pid_t pid = 0;
    if (runitReadFile(name, "pid", pidText, sizeof(pidText))) {
        pid = (pid_t)strtol(pidText, NULL, 10);
    }
    long long since = 0;
    if (runitReadFile(name, "since", sinceText, sizeof(sinceText))) {
        since = strtoll(sinceText, NULL, 10);
    }
    long long age = since > 0 ? (long long)time(NULL) - since : 0;
    if (age < 0) {
        age = 0;
    }
    if (pid > 0) {
        printf("run: %s: (pid %d) %llds%s\n", arg, (int)pid, age,
               strcmp(stat, "stopping") == 0 ? ", want down" : "");
    } else {
        printf("down: %s: %llds%s\n", arg, age,
               strcmp(stat, "backoff") == 0 ? ", want up" : "");
    }
    return 0;
}

int smallclueSvCommand(int argc, char **argv) {
    int waitSeconds = 7;
    int argi = 1;
    while (argi < argc && argv[argi][0] == '-') {
        if (strcmp(argv[argi], "-w") == 0 && argi + 1 < argc) {
            waitSeconds = atoi(argv[argi + 1]);
            argi += 2;
        } else if (strcmp(argv[argi], "-h") == 0 || strcmp(argv[argi], "--help") == 0) {
            svUsage(stdout);
            return 0;
        } else if (strcmp(argv[argi], "-v") == 0) {
            argi++;
        } else {
            svUsage(stderr);
            return 1;
        }
    }
    if (argc - argi < 2) {
        svUsage(stderr);
        return 1;
    }
    const char *command = argv[argi++];
    const char *want = NULL;
    bool status = false;
    switch (command[0]) {
        case 's':
            if (strcmp(command, "stop") == 0) {
                want = "down";
            } else if (strcmp(command, "start") == 0) {
                want = "up";
            } else {
                status = true;   /* status, s */
            }
            break;
        case 'u': want = "up"; break;
        case 'd': want = "down"; break;
        case 't': want = "restart"; break;   /* t: runit's "term" */
        case 'r': want = "restart"; break;
        default:
            svUsage(stderr);
            return 1;
    }

    pid_t runitPid = svRunitPid();
    int failures = 0;
    for (; argi < argc; argi++) {
        const char *arg = argv[argi];
        char trimmed[PATH_MAX];
        snprintf(trimmed, sizeof(trimmed), "%s", arg);
        size_t len = strlen(trimmed);
        while (len > 1 && trimmed[len - 1] == '/') {
            trimmed[--len] = '\0';
        }
        const char *name = initBaseName(trimmed);
        char dir[PATH_MAX];
        if (strchr(arg, '/')) {
            snprintf(dir, sizeof(dir), "%s", trimmed);
        } else {
            snprintf(dir, sizeof(dir), RUNIT_DEFAULT_DIR "/%s", name);
        }
        struct stat st;
        if (stat(dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
            printf("fail: %s: unable to change to service directory: %s\n",
                   arg, strerror(errno ? errno : ENOTDIR));
            failures++;
            continue;
        }
        if (runitPid < 0) {
            printf("fail: %s: runsv not running\n", arg);
            failures++;
            continue;
        }
        if (status) {
            failures += svStatus(arg, name);
            continue;
        }
        runitMkdirs(name);
        char text[32];
        snprintf(text, sizeof(text), "%s\n", want);
        runitWriteFile(name, "want", text);
        kill(runitPid, SIGHUP);

        /* Wait for it to take effect, as sv does with -w. */
        bool wantRun = strcmp(want, "down") != 0;
        time_t deadline = initNow() + waitSeconds;
        bool ok = false;
        for (;;) {
            char stat2[32], pidText[32], wantLeft[32];
            bool pending = runitReadFile(name, "want", wantLeft, sizeof(wantLeft));
            pid_t pid = 0;
            if (runitReadFile(name, "pid", pidText, sizeof(pidText))) {
                pid = (pid_t)strtol(pidText, NULL, 10);
            }
            if (!pending && runitReadFile(name, "stat", stat2, sizeof(stat2))) {
                if (wantRun ? (pid > 0 && strcmp(stat2, "run") == 0)
                            : (pid == 0)) {
                    ok = true;
                    break;
                }
            }
            if (initNow() >= deadline) {
                break;
            }
            usleep(100000);
        }
        if (ok) {
            svStatus(arg, name);
        } else {
            printf("timeout: %s\n", arg);
            failures++;
        }
    }
    return failures > 0 ? 1 : 0;
}
