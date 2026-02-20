/*
 * NOTE: For iPadOS/iOS, every new smallclue applet must also be wired into
 * src/smallclue/integration.c and src/shell/builtins.c so exsh can invoke it.
 * See Docs/notes_smallclu_ios.md for the full checklist before landing changes.
 */
#include "smallclue.h"

#include "common/runtime_tty.h"
#include "nextvi_app.h"
#include "openssh_app.h"
#include "common/runtime_clipboard.h"
#if defined(PSCAL_HAS_LIBCURL)
#include <curl/curl.h>
#endif
#if defined(PSCAL_TARGET_IOS)
#include "common/path_virtualization.h"
#include "ios/vproc.h"
#include "ios/tty/pscal_tty.h"
#endif
#include "core/build_info.h"
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <fnmatch.h>
#include <grp.h>
#include <limits.h>
#include <libgen.h>
#include <pwd.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <signal.h>
#include <stdatomic.h>
#include <sys/select.h>
#include <glob.h>
#include "common/pscal_hosts.h"
#if defined(__APPLE__)
#include <TargetConditionals.h>
#include <sys/sysctl.h>
#include <mach/mach.h>
#include <mach/mach_host.h>
#include <mach/host_info.h>
#include "common/path_truncate.h"
#include "common/path_virtualization.h"
void pscalRuntimeDebugLog(const char *message) __attribute__((weak));
#endif
#include <signal.h>
#if defined(PSCAL_TARGET_IOS)
__attribute__((weak_import)) void PSCALRuntimeUpdateWindowSize(int columns, int rows);
__attribute__((weak)) void PSCALRuntimeUpdateWindowSize(int columns, int rows) { (void)columns; (void)rows; }
void PSCALRuntimeBeginScriptCapture(const char *path, int append) __attribute__((weak));
void PSCALRuntimeEndScriptCapture(void) __attribute__((weak));
int PSCALRuntimeScriptCaptureActive(void) __attribute__((weak));
int pscalRuntimeOpenShellTab(void) __attribute__((weak));
#ifndef PSCAL_RUNTIME_CAPTURE_IMPL
__attribute__((weak)) void PSCALRuntimeBeginScriptCapture(const char *path, int append) { (void)path; (void)append; }
__attribute__((weak)) void PSCALRuntimeEndScriptCapture(void) {}
__attribute__((weak)) int PSCALRuntimeScriptCaptureActive(void) { return 0; }
__attribute__((weak)) int pscalRuntimeOpenShellTab(void) { errno = ENOSYS; return -1; }
#endif
__attribute__((weak)) char *pscalRuntimeCopyMarketingVersion(void) { return NULL; }
#endif
#include <termios.h>
#include "termios_shim.h"
#include <time.h>
#include <unistd.h>
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__DragonFly__)
#include <sys/param.h>
#include <sys/mount.h>
#define SMALLCLUE_HAVE_STATFS 1
#else
#include <sys/statvfs.h>
#define SMALLCLUE_HAVE_STATVFS 1
#endif
#if SMALLCLUE_HAS_IFADDRS
#include <ifaddrs.h>
#include <net/if.h>
#endif

#if !defined(PSCAL_TARGET_IOS)
void PSCALRuntimeBeginScriptCapture(const char *path, int append) { (void)path; (void)append; }
void PSCALRuntimeEndScriptCapture(void) {}
int PSCALRuntimeScriptCaptureActive(void) { return 0; }
#endif

int smallclueVprocTestCommand(int argc, char **argv);

static const char *smallclueResolvePath(const char *path, char *buffer, size_t buflen) {
    if (!path) {
        return NULL;
    }
#if defined(PSCAL_TARGET_IOS)
    if (pathTruncateExpand(path, buffer, buflen)) {
        return buffer;
    }
#endif
    (void)buffer;
    (void)buflen;
    return path;
}

static const char *smallclueDisplayPath(const char *path, char *buffer, size_t buflen) {
    if (!path) {
        return "";
    }
    if (!buffer || buflen == 0) {
        return path;
    }
#if defined(__APPLE__)
    bool stripped = false;
    const char *home = getenv("HOME");
    if (home && home[0] == '/') {
        bool prefer_home_virtual = false;
        if (strstr(home, "/Containers/Data/Application/") != NULL ||
            strstr(path, "/Containers/Data/Application/") != NULL) {
            prefer_home_virtual = true;
        }
        const char *container_root = getenv("PSCALI_CONTAINER_ROOT");
        if (!prefer_home_virtual && container_root && container_root[0] == '/') {
            prefer_home_virtual = true;
        }
        if (prefer_home_virtual) {
            size_t home_len = strlen(home);
            while (home_len > 1 && home[home_len - 1] == '/') {
                home_len--;
            }
            if (strncmp(path, home, home_len) == 0 &&
                (path[home_len] == '\0' || path[home_len] == '/')) {
                const char *suffix = path + home_len;
                int written = snprintf(buffer, buflen, "/home%s", suffix);
                if (written >= 0 && (size_t)written < buflen) {
                    return buffer;
                }
            }
        }
    }
    stripped = pathTruncateStrip(path, buffer, buflen);
    if (stripped && strcmp(buffer, path) != 0) {
        return buffer;
    }
    if (stripped) {
        return buffer;
    }
#endif
    return path;
}

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__DragonFly__)
#define SMALLCLUE_GETOPT_NEEDS_OPTRESET 1
#else
#define SMALLCLUE_GETOPT_NEEDS_OPTRESET 0
#endif

#if SMALLCLUE_GETOPT_NEEDS_OPTRESET
extern int optreset;
#endif

#if defined(__APPLE__)
extern bool shellRuntimeConsumeExitRequested(void) __attribute__((weak_import));
#elif defined(__GNUC__)
extern bool shellRuntimeConsumeExitRequested(void) __attribute__((weak));
#else
bool shellRuntimeConsumeExitRequested(void);
#endif

extern bool pscalRuntimeConsumeSigint(void);
extern bool pscalRuntimeConsumeSigtstp(void);
#if defined(PSCAL_TARGET_IOS)
#if defined(__APPLE__)
extern char *pscalRuntimeCopySessionLog(void) __attribute__((weak_import));
extern void pscalRuntimeResetSessionLog(void) __attribute__((weak_import));
#elif defined(__GNUC__)
extern char *pscalRuntimeCopySessionLog(void) __attribute__((weak));
extern void pscalRuntimeResetSessionLog(void) __attribute__((weak));
#else
char *pscalRuntimeCopySessionLog(void);
void pscalRuntimeResetSessionLog(void);
#endif

// Provide weak fallbacks so smallclue can link when the Swift bridge is absent.
__attribute__((weak)) char *pscalRuntimeCopySessionLog(void) { return NULL; }
__attribute__((weak)) void pscalRuntimeResetSessionLog(void) { }
#endif

__attribute__((weak)) bool shellRuntimeConsumeExitRequested(void) {
    return false;
}

static void smallclueClearPendingSignals(void) {
    sigset_t watchset;
    sigemptyset(&watchset);
    sigaddset(&watchset, SIGINT);
    sigaddset(&watchset, SIGTSTP);
    sigset_t oldset;
    if (sigprocmask(SIG_BLOCK, &watchset, &oldset) != 0) {
        return;
    }
    sigset_t pending;
    while (sigpending(&pending) == 0 &&
           (sigismember(&pending, SIGINT) || sigismember(&pending, SIGTSTP))) {
        int signo = 0;
        if (sigwait(&watchset, &signo) != 0) {
            break;
        }
        (void)signo;
    }
    sigprocmask(SIG_SETMASK, &oldset, NULL);
}

static bool smallclueShouldAbort(int *out_status) {
    const char *dbg = getenv("SMALLCLUE_DEBUG");
    bool allow_cooperative_sigtstp = true;
    int cur_pid = 0;
#if defined(PSCAL_TARGET_IOS)
    VProc *vp = vprocCurrent();
    if (vp) {
        int shell_pid = vprocGetShellSelfPid();
        cur_pid = vprocPid(vp);
        if (cur_pid > 0 && !vprocGetStopUnsupported(cur_pid)) {
            allow_cooperative_sigtstp = false;
        }
        if (shell_pid <= 0 || vprocPid(vp) != shell_pid) {
            (void)vprocWaitIfStopped(vp);
        }
        if (dbg && *dbg) {
            fprintf(stderr,
                    "[smallclue] shouldAbort pid=%d shell_pid=%d stop_unsupported=%d allow_coop=%d\n",
                    cur_pid,
                    shell_pid,
                    (int)vprocGetStopUnsupported(cur_pid),
                    (int)allow_cooperative_sigtstp);
        }
    }
#endif
    if (pscalRuntimeConsumeSigint()) {
        if (out_status) {
            *out_status = 130;
        }
        if (dbg && *dbg) {
            fprintf(stderr, "[smallclue] abort via runtime SIGINT\n");
        }
        return true;
    }
    if (allow_cooperative_sigtstp && pscalRuntimeConsumeSigtstp()) {
        if (out_status) {
            *out_status = 128 + SIGTSTP;
        }
        if (dbg && *dbg) {
            fprintf(stderr, "[smallclue] abort via runtime SIGTSTP\n");
        }
        return true;
    }

#if defined(PSCAL_TARGET_IOS)
    /* Fallback: drain pending vproc signals so Ctrl-C/Z delivered via vprocKillShim
     * interrupt in-process applets even when the runtime bridge is absent. */
    if (cur_pid <= 0) {
        cur_pid = vprocGetPidShim();
    }
    if (cur_pid <= 0) {
        cur_pid = vprocGetShellSelfPid();
    }
    if (cur_pid > 0) {
        sigset_t pending;
        sigemptyset(&pending);
        if (vprocSigpending(cur_pid, &pending) == 0 &&
            (sigismember(&pending, SIGINT) || sigismember(&pending, SIGTSTP))) {
            sigset_t watchset;
            sigemptyset(&watchset);
            sigaddset(&watchset, SIGINT);
            sigaddset(&watchset, SIGTSTP);
            int signo = 0;
            if (vprocSigwait(cur_pid, &watchset, &signo) == 0) {
                if (signo == SIGTSTP && !allow_cooperative_sigtstp) {
                    if (dbg && *dbg) {
                        fprintf(stderr, "[smallclue] ignore vproc SIGTSTP for non-coop stop\n");
                    }
                    return false;
                }
                if (out_status) {
                    *out_status = 128 + signo;
                }
                if (dbg && *dbg) {
                    fprintf(stderr, "[smallclue] abort via vproc signal %d\n", signo);
                }
                return true;
            }
        }
    }
#endif

    if (shellRuntimeConsumeExitRequested) {
        if (shellRuntimeConsumeExitRequested()) {
            if (out_status) {
                *out_status = 130;
            }
            if (dbg && *dbg) {
                fprintf(stderr, "[smallclue] abort via shell exit request\n");
            }
            return true;
        }
    }

    sigset_t watchset;
    sigemptyset(&watchset);
    sigaddset(&watchset, SIGINT);
    sigaddset(&watchset, SIGTSTP);
    sigset_t oldset;
    if (sigprocmask(SIG_BLOCK, &watchset, &oldset) == 0) {
        sigset_t pending;
        if (sigpending(&pending) == 0 &&
            (sigismember(&pending, SIGINT) || sigismember(&pending, SIGTSTP))) {
            int signo = 0;
            if (sigwait(&watchset, &signo) == 0) {
                if (signo == SIGTSTP && !allow_cooperative_sigtstp) {
                    sigprocmask(SIG_SETMASK, &oldset, NULL);
                    if (dbg && *dbg) {
                        fprintf(stderr, "[smallclue] ignore host SIGTSTP for non-coop stop\n");
                    }
                    return false;
                }
                if (out_status) {
                    *out_status = 128 + signo;
                }
                sigprocmask(SIG_SETMASK, &oldset, NULL);
                if (dbg && *dbg) {
                    fprintf(stderr, "[smallclue] abort via host pending signal %d\n", signo);
                }
                return true;
            }
        }
        sigprocmask(SIG_SETMASK, &oldset, NULL);
    }
    return false;
}

static void smallclueResetGetopt(void) {
    optind = 1;
#if SMALLCLUE_GETOPT_NEEDS_OPTRESET
    optreset = 1;
#endif
}

static void smallclueEnvClearAll(void) {
    extern char **environ;
    if (!environ) {
        return;
    }
    size_t count = 0;
    for (char **envp = environ; *envp; ++envp) {
        count++;
    }
    if (count == 0) {
        return;
    }
    char **names = (char **)calloc(count, sizeof(char *));
    if (!names) {
        return;
    }
    size_t idx = 0;
    for (char **envp = environ; *envp; ++envp) {
        char *eq = strchr(*envp, '=');
        if (!eq) {
            continue;
        }
        size_t len = (size_t)(eq - *envp);
        char *name = (char *)malloc(len + 1);
        if (!name) {
            continue;
        }
        memcpy(name, *envp, len);
        name[len] = '\0';
        names[idx++] = name;
    }
    for (size_t i = 0; i < idx; ++i) {
        if (names[i]) {
            unsetenv(names[i]);
            free(names[i]);
        }
    }
    free(names);
}

enum {
    PAGER_KEY_ARROW_UP = 1000,
    PAGER_KEY_ARROW_DOWN,
    PAGER_KEY_PAGE_UP,
    PAGER_KEY_PAGE_DOWN,
    PAGER_KEY_RESIZE
};

typedef struct {
    FILE *file;
    size_t *offsets;
    size_t offset_count;
    size_t line_count;
    size_t length;
} PagerBuffer;

typedef struct {
    char **items;
    size_t count;
    size_t capacity;
} SmallclueLineVector;

typedef struct MarkdownLinkEntry {
    char *text;
    char *target;
} MarkdownLinkEntry;

typedef struct MarkdownLinkList {
    MarkdownLinkEntry *items;
    size_t count;
    size_t capacity;
} MarkdownLinkList;

static int smallclueEchoCommand(int argc, char **argv);
static int smallclueLsCommand(int argc, char **argv);
static int smallclueCatCommand(int argc, char **argv);
static int smallcluePagerCommand(int argc, char **argv);
static int smallclueClearCommand(int argc, char **argv);
static int smallclueRmCommand(int argc, char **argv);
static int smallclueCpCommand(int argc, char **argv);
static int smallclueMvCommand(int argc, char **argv);
static int smallcluePwdCommand(int argc, char **argv);
static int smallclueEnvCommand(int argc, char **argv);
static int smallclueChmodCommand(int argc, char **argv);
static int smallclueDateCommand(int argc, char **argv);
static int smallclueCalCommand(int argc, char **argv);
static int smallclueHeadCommand(int argc, char **argv);
static int smallclueGrepCommand(int argc, char **argv);
static int smallclueWcCommand(int argc, char **argv);
static int smallclueDuCommand(int argc, char **argv);
static int smallclueFindCommand(int argc, char **argv);
static int smallclueTailCommand(int argc, char **argv);
static int smallclueTouchCommand(int argc, char **argv);
static int smallclueSttyCommand(int argc, char **argv);
static int smallclueTsetCommand(int argc, char **argv);
static int smallclueTtyCommand(int argc, char **argv);
static int smallclueResizeCommand(int argc, char **argv);
static int smallclueSortCommand(int argc, char **argv);
static int smallclueUniqCommand(int argc, char **argv);
static int smallclueSedCommand(int argc, char **argv);
static int smallclueCutCommand(int argc, char **argv);
static int smallclueTrCommand(int argc, char **argv);
static int smallclueIdCommand(int argc, char **argv);
static void smallclueDfFormatSize(char *buf, size_t bufsize, unsigned long long bytes, bool human);
static int smallclueTrueCommand(int argc, char **argv);
static int smallclueFalseCommand(int argc, char **argv);
static int smallclueYesCommand(int argc, char **argv);
static int smallclueNoCommand(int argc, char **argv);
static int smallclueVersionCommand(int argc, char **argv);
static int smallclueSumCommand(int argc, char **argv);
static int smallclueSleepCommand(int argc, char **argv);
static int smallclueTimeCommand(int argc, char **argv);
static int smallclueWatchCommand(int argc, char **argv);
static int smallclueBasenameCommand(int argc, char **argv);
static int smallclueDirnameCommand(int argc, char **argv);
static int smallclueTeeCommand(int argc, char **argv);
static int smallclueScriptCommand(int argc, char **argv);
static int smallclueTestCommand(int argc, char **argv);
static int smallclueBracketCommand(int argc, char **argv);
static int smallclueXargsCommand(int argc, char **argv);
static int smallcluePsCommand(int argc, char **argv);
static int smallclueKillCommand(int argc, char **argv);
static int smallclueMkdirCommand(int argc, char **argv);
static void smallclueEmitTerminalSane(void);
#if defined(PSCAL_TARGET_IOS)
static bool smallclueSessionPtyName(char *buf, size_t buf_len);
#endif
static int smallclueRmdirCommand(int argc, char **argv);
static int smallclueLnCommand(int argc, char **argv);
static int smallclueTypeCommand(int argc, char **argv);
static int smallclueFileCommand(int argc, char **argv);
static int smallclueStatCommand(int argc, char **argv);
static int __attribute__((unused)) smallclueLicensesCommand(int argc, char **argv);
static const char *smallclueLeafName(const char *path);
static int smallclueBuildPath(char *buf, size_t buf_size, const char *dir, const char *leaf);
static void smallclueTrimTrailingSlashes(char *path);
static bool smallclueChopParentDirectory(char *path);
static int smallclueRemovePathWithLabel(const char *label, const char *path, bool recursive, bool force);
static int smallclueCopyFile(const char *label, const char *src, const char *dst);
static int smallclueMkdirParents(const char *path, mode_t mode);
static void smallclueGetTerminalSize(int *rows, int *cols);
static int smallclueEditorCommand(int argc, char **argv);
static int smallclueSshCommand(int argc, char **argv);
static int smallclueScpCommand(int argc, char **argv);
static int smallclueSftpCommand(int argc, char **argv);
static int smallclueSshKeygenCommand(int argc, char **argv);
static int smallclueSshCopyIdCommand(int argc, char **argv);
static int smallcluePbcopyCommand(int argc, char **argv);
static int smallcluePbpasteCommand(int argc, char **argv);
#if defined(SMALLCLUE_WITH_EXSH)
extern int exsh_main(int argc, char **argv);
static int smallclueShCommand(int argc, char **argv);
#endif
static int smallclueUptimeCommand(int argc, char **argv);
static int smallclueUnameCommand(int argc, char **argv);
static int smallcluePingCommand(int argc, char **argv);
static int smallclueMarkdownCommand(int argc, char **argv);
static int smallclueCurlCommand(int argc, char **argv);
static int smallclueWgetCommand(int argc, char **argv);
static int smallclueHttpFetch(const char *cmd_name, const char *url, const char *destinationPath);
static int smallclueHttpFetchToMemory(const char *cmd_name, const char *url, char **data_out, size_t *len_out);
static int smallclueTelnetCommand(int argc, char **argv);
static int smallclueTracerouteCommand(int argc, char **argv);
static int smallclueNslookupCommand(int argc, char **argv);
static int smallclueHostCommand(int argc, char **argv);
#if SMALLCLUE_HAS_IFADDRS
static int smallclueIpAddrCommand(int argc, char **argv);
#endif
static int smallclueDfCommand(int argc, char **argv);
#if defined(PSCAL_TARGET_IOS)
static int smallclueTopCommand(int argc, char **argv);
static int smallclueDmesgCommand(int argc, char **argv);
static int smallclueHelpCommand(int argc, char **argv);
static int smallclueAddTabCommand(int argc, char **argv);
#endif

static int smallclueNslookupCommand(int argc, char **argv) {
    const char *usage = "usage: nslookup [-v] host [port]\n";
    bool verbose = false;
    smallclueResetGetopt();
    int opt;
    while ((opt = getopt(argc, argv, "v")) != -1) {
        switch (opt) {
            case 'v':
                verbose = true;
                break;
            default:
            fputs(usage, stderr);
            return 1;
        }
    }
    if (verbose) {
        pscalHostsSetLogEnabled(1);
    } else {
        pscalHostsSetLogEnabled(-1);
    }
    if (optind >= argc) {
        fputs(usage, stderr);
        return 1;
    }
    const char *host = argv[optind];
    const char *service = (optind + 1 < argc) ? argv[optind + 1] : "53";

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_family = AF_UNSPEC;
    struct addrinfo *res = NULL;
    int gai = pscalHostsGetAddrInfo(host, service, &hints, &res);
    if (gai != 0 || !res) {
#if defined(PSCAL_TARGET_IOS)
        fprintf(stderr, "nslookup: hosts lookup paths: %s first, then /etc/hosts\n",
                getenv("PSCALI_CONTAINER_ROOT") ? pscalHostsGetContainerPath() : "(no PSCALI_CONTAINER_ROOT)");
#endif
        fprintf(stderr, "nslookup: %s: %s\n", host, gai_strerror(gai));
        return 1;
    }
    printf("Non-authoritative answer for %s:\n", host);
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        char hostbuf[NI_MAXHOST];
        char servbuf[NI_MAXSERV];
        if (getnameinfo(ai->ai_addr, (socklen_t)ai->ai_addrlen,
                        hostbuf, sizeof(hostbuf),
                        servbuf, sizeof(servbuf),
                        NI_NUMERICHOST | NI_NUMERICSERV) == 0) {
            printf("  %s (port %s) family %d\n", hostbuf, servbuf, ai->ai_family);
        }
    }
    pscalHostsFreeAddrInfo(res);
    return 0;
}

static int smallclueHostCommand(int argc, char **argv) {
    const char *usage = "usage: host [-4|-6] [-v] [-t TYPE] host [server]\n";
    int family = AF_UNSPEC;
    bool verbose = false;
    smallclueResetGetopt();
    int opt;
    while ((opt = getopt(argc, argv, "46vt:")) != -1) {
        switch (opt) {
            case '4': family = AF_INET; break;
            case '6': family = AF_INET6; break;
            case 'v': verbose = true; break;
            case 't':
                if (strcasecmp(optarg, "A") == 0) family = AF_INET;
                else if (strcasecmp(optarg, "AAAA") == 0) family = AF_INET6;
                break;
            default:
                fputs(usage, stderr);
                return 1;
        }
    }
    if (verbose) {
        pscalHostsSetLogEnabled(1);
    } else {
        pscalHostsSetLogEnabled(-1);
    }
    if (optind >= argc) {
        fputs(usage, stderr);
        return 1;
    }
    const char *host = argv[optind];
    if (optind + 1 < argc) {
        fprintf(stderr, "host: server override not supported; ignoring '%s'\n", argv[optind + 1]);
    }

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *res = NULL;
    int gai = pscalHostsGetAddrInfo(host, NULL, &hints, &res);
    if (gai != 0 || !res) {
        fprintf(stderr, "%s not found: %s\n", host, gai_strerror(gai));
        return 1;
    }
    bool printed = false;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        if (family == AF_INET && ai->ai_family != AF_INET) continue;
        if (family == AF_INET6 && ai->ai_family != AF_INET6) continue;
        char addrbuf[NI_MAXHOST];
        if (getnameinfo(ai->ai_addr, (socklen_t)ai->ai_addrlen,
                        addrbuf, sizeof(addrbuf),
                        NULL, 0, NI_NUMERICHOST) == 0) {
            if (ai->ai_family == AF_INET6) {
                printf("%s has IPv6 address %s\n", host, addrbuf);
            } else {
                printf("%s has address %s\n", host, addrbuf);
            }
            printed = true;
        }
    }
    pscalHostsFreeAddrInfo(res);
    if (!printed) {
        fprintf(stderr, "No records found for %s\n", host);
        return 1;
    }
    return 0;
}

typedef struct SmallclueAppletHelp {
    const char *name;
    const char *usage;
} SmallclueAppletHelp;

static const SmallclueApplet kSmallclueApplets[] = {
    {"[", smallclueBracketCommand, "Evaluate expressions"},
    {"basename", smallclueBasenameCommand, "Strip directory prefix"},
    {"cal", smallclueCalCommand, "Show a simple calendar"},
    {"cat", smallclueCatCommand, "Concatenate files"},
    {"chmod", smallclueChmodCommand, "Change file permissions"},
    {"clear", smallclueClearCommand, "Clear the terminal"},
    {"cls", smallclueClearCommand, "Clear the terminal"},
    {"cp", smallclueCpCommand, "Copy files"},
    {"curl", smallclueCurlCommand, "Transfer data from URLs"},
    {"cut", smallclueCutCommand, "Extract fields from lines"},
    {"date", smallclueDateCommand, "Display current date/time"},
    {"dirname", smallclueDirnameCommand, "Strip last path component"},
    {"du", smallclueDuCommand, "Summarize disk usage"},
    {"echo", smallclueEchoCommand, "Print arguments"},
    {"nextvi", smallclueEditorCommand, "Nextvi text editor"},
    {"env", smallclueEnvCommand, "Display or update environment"},
    {"false", smallclueFalseCommand, "Do nothing, unsuccessfully"},
    {"file", smallclueFileCommand, "Identify file types"},
    {"find", smallclueFindCommand, "Search for files"},
    {"grep", smallclueGrepCommand, "Search for patterns"},
    {"head", smallclueHeadCommand, "Print the first lines of files"},
    {"id", smallclueIdCommand, "Print user identity information"},
#if SMALLCLUE_HAS_IFADDRS
    {"ipaddr", smallclueIpAddrCommand, "Show interface IP addresses"},
#endif
    {"host", smallclueHostCommand, "DNS lookup utility"},
    {"kill", smallclueKillCommand, "Send signals to processes"},
    {"less", smallcluePagerCommand, "Paginate file contents"},
    {"ln", smallclueLnCommand, "Create links"},
    {"ls", smallclueLsCommand, "List directory contents"},
    {"md", smallclueMarkdownCommand, "Read Markdown documents"},
    {"mkdir", smallclueMkdirCommand, "Create directories"},
    {"more", smallcluePagerCommand, "Paginate file contents"},
    {"mv", smallclueMvCommand, "Move or rename files"},
    {"nslookup", smallclueNslookupCommand, "DNS lookup utility"},
    {"no", smallclueNoCommand, "Repeatedly print strings (exit 1)"},
    {"pbcopy", smallcluePbcopyCommand, "Copy stdin to the system clipboard"},
    {"pbpaste", smallcluePbpasteCommand, "Paste the system clipboard to stdout"},
    {"ping", smallcluePingCommand, "TCP ping utility"},
    {"ps", smallcluePsCommand, "Show simple process information"},
    {"pwd", smallcluePwdCommand, "Print working directory"},
    {"resize", smallclueResizeCommand, "Synchronize terminal rows/columns"},
    {"rm", smallclueRmCommand, "Remove files"},
    {"rmdir", smallclueRmdirCommand, "Remove empty directories"},
    {"sed", smallclueSedCommand, "Stream editor for simple substitutions"},
    {"sleep", smallclueSleepCommand, "Delay for a number of seconds"},
    {"sort", smallclueSortCommand, "Sort lines of text"},
    {"stat", smallclueStatCommand, "Display file status"},
    {"stty", smallclueSttyCommand, "Report terminal settings"},
#if defined(SMALLCLUE_WITH_EXSH)
    {"sh", smallclueShCommand, "Run the PSCAL shell front end"},
#endif
    {"scp", smallclueScpCommand, "Securely copy files over SSH"},
    {"sftp", smallclueSftpCommand, "Interactive SFTP client"},
    {"script", smallclueScriptCommand, "Record terminal output to a file"},
    {"ssh", smallclueSshCommand, "OpenSSH client"},
    {"ssh-keygen", smallclueSshKeygenCommand, "Generate SSH key pairs"},
    {"ssh-copy-id", smallclueSshCopyIdCommand, "Install SSH public keys on a remote host"},
    {"tail", smallclueTailCommand, "Print the last lines of files"},
    {"tee", smallclueTeeCommand, "Copy stdin to files and stdout"},
    {"telnet", smallclueTelnetCommand, "Simple TCP telnet client"},
    {"test", smallclueTestCommand, "Evaluate expressions"},
    {"time", smallclueTimeCommand, "Measure command runtime"},
    {"tset", smallclueTsetCommand, "Initialize terminal settings"},
    {"touch", smallclueTouchCommand, "Update file timestamps"},
    {"tty", smallclueTtyCommand, "Print terminal name"},
    {"traceroute", smallclueTracerouteCommand, "Trace network path to a host"},
    {"tr", smallclueTrCommand, "Translate or delete characters"},
    {"true", smallclueTrueCommand, "Do nothing, successfully"},
    {"sum", smallclueSumCommand, "Checksum (BSD/SysV)"},
    {"type", smallclueTypeCommand, "Describe command names"},
    {"uname", smallclueUnameCommand, "Show system information"},
    {"uniq", smallclueUniqCommand, "Report or omit repeated lines"},
    {"uptime", smallclueUptimeCommand, "Show system uptime"},
    {"version", smallclueVersionCommand, "Show app version"},
    {"vproc-test", smallclueVprocTestCommand, "Run vproc/terminal diagnostics"},
    {"watch", smallclueWatchCommand, "Periodically run a command"},
    {"vi", smallclueEditorCommand, "Alias for Nextvi text editor"},
    {"wc", smallclueWcCommand, "Count lines/words/bytes"},
    {"wget", smallclueWgetCommand, "Download files via HTTP(S)"},
    {"yes", smallclueYesCommand, "Repeatedly print strings"},
    {"xargs", smallclueXargsCommand, "Build command lines from stdin"},
    {"df", smallclueDfCommand, "Report filesystem usage"},
#if defined(PSCAL_TARGET_IOS)
    {"addt", smallclueAddTabCommand, "Open an additional shell tab"},
    {"tabadd", smallclueAddTabCommand, "Alias for addt: open an additional shell tab"},
    {"tadd", smallclueAddTabCommand, "Alias for addt: open an additional shell tab"},
    {"smallclue-help", smallclueHelpCommand, "List available smallclue applets"},
    {"licenses", smallclueLicensesCommand, "View third-party licenses"},
    {"dmesg", smallclueDmesgCommand, "Show PSCAL runtime log for this session"},
    {"top", smallclueTopCommand, "Show PSCAL virtual processes"},
#endif
};

static const SmallclueAppletHelp kSmallclueAppletHelp[] = {
    {"[", "[ expression ]\n"
          "  Alias for test; see 'test' for operators"},
    {"basename", "basename PATH [SUFFIX]\n"
                 "  Strip directory prefix and optional suffix"},
    {"cal", "cal [month] [year]\n"
            "  Show a simple calendar"},
    {"cat", "cat [FILE ...]\n"
            "  Concatenate files to stdout"},
    {"chmod", "chmod MODE FILE ...\n"
              "  MODE forms: u+rwx,g-w,o=r, a-wx, 755, 0644"},
    {"clear", "clear\n"
              "  Clear the terminal"},
    {"cls", "cls\n"
            "  Clear the terminal (alias)"},
    {"cp", "cp [-r] SRC... DEST\n"
           "  -r  recursive copy"},
    {"curl", "curl [options] URL...\n"
             "  Common: -o FILE,\n"
             "  -O (remote name)\n"
             "  -L (follow)\n"
             "  -d DATA\n"
             "  -H HEADER"},
    {"cut", "cut -d DELIM -f LIST [FILE...]\n"
            "  -d delimiter (default tab)\n"
            "  -f fields (e.g. 1,3-5)"},
    {"date", "date [+FORMAT]\n"
             "  Show date/time"},
    {"dirname", "dirname PATH\n"
                "  Strip last path component"},
    {"du", "du [-h] [PATH...]\n"
           "  -h human-readable sizes"},
    {"echo", "echo [args...]\n"
             "  Print arguments"},
    {"env", "env [-i] [NAME=VALUE ...] [command]\n"
            "  -i start with empty environment"},
    {"false", "false\n"
              "  Exit with status 1"},
    {"file", "file FILE...\n"
             "  Identify file types"},
    {"find", "find PATH... [expression]\n"
             "  Common: -name PATTERN -type f|d"},
    {"grep", "grep [-i] [-n] [-v] PATTERN [FILE...]\n"
             "  -i ignore case\n"
             "  -n line numbers\n"
             "  -v invert match"},
    {"head", "head [-n N] [FILE...]\n"
             "  Default N=10"},
    {"id", "id\n"
           "  Show uid/gid info"},
#if SMALLCLUE_HAS_IFADDRS
    {"ipaddr", "ipaddr\n"
               "  Show interface IP addresses"},
#endif
    {"kill", "kill [-SIGNAL] PID...\n"
             "  Signals: HUP INT TERM KILL etc."},
    {"less", "less [FILE...]\n"
             "  Pager; navigation: j/k, /, n, g/G, q"},
    {"ln", "ln [-s] TARGET LINK\n"
           "  -s symbolic link"},
    {"ls", "ls [-a] [-A] [-l] [-n] [-t] [-h] [-d] [--color[=auto|always|never]] [path ...]\n"
           "  -a show entries starting with '.' (including . and ..)\n"
           "  -A show entries starting with '.' (excluding . and ..)\n"
           "  -l long format with permissions, ownership, size, time\n"
           "  -n numeric uid/gid (implies -l)\n"
           "  -t sort by modification time\n"
           "  -h human-readable sizes (with -l)\n"
           "  -d list directories themselves, not their contents"},
    {"md", "md [-i] [FILE|URL]\n"
           "  View Markdown/HTML document; press 'o' to open links in-page\n"
           "  -i interactive mode.  Makes ~/Docs browsable"},
    {"mkdir", "mkdir [-p] DIR...\n"
              "  -p create parents as needed"},
    {"more", "more [FILE...]\n"
             "  Pager (alias of less)"},
    {"mv", "mv SRC... DEST\n"
           "  Move or rename files"},
    {"nslookup", "nslookup [-v] host [port]\n"
                 "  DNS lookup utility (UDP port defaults to 53).\n"
                 "  -v prints hosts lookup debugging."},
    {"nextvi", "nextvi [FILE]\n"
               "  Full-screen text editor"},
    {"host", "host [-4|-6] [-v] [-t TYPE] host [server]\n"
             "  -4 IPv4 only\n"
             "  -6 IPv6 only\n"
             "  -t A|AAAA select record type\n"
             "  -v verbose (hosts debug)\n"
             "Server override is ignored."},
    {"pbcopy", "pbcopy\n"
               "  Copy stdin to system clipboard"},
    {"pbpaste", "pbpaste\n"
                "  Paste system clipboard to stdout"},
    {"ping", "ping HOST [PORT]\n"
             "  TCP ping (default port 80)"},
    {"ps", "ps\n"
           "  Show simple process list"},
    {"pwd", "pwd\n"
            "  Print working directory"},
    {"resize", "resize [COLUMNS ROWS]\n"
               "  Report or set terminal size"},
    {"rm", "rm [-r] [-f] FILE...\n"
           "  -r recursive\n"
           "  -f force"},
    {"rmdir", "rmdir DIR...\n"
              "  Remove empty directories"},
    {"sed", "sed 's/old/new/g' [FILE...]\n"
            "  Simple substitution support"},
    {"sleep", "sleep SECONDS\n"
              "  Pause execution"},
    {"sort", "sort [-r] [-n]\n"
             "  -r reverse\n"
             "  -n numeric"},
    {"stat", "stat [-L] FILE...\n"
             "  -L follow symlinks"},
    {"stty", "stty [reset] [sane]\n"
             "  Report terminal settings; apply reset/sane"},
#if defined(SMALLCLUE_WITH_EXSH)
    {"sh", "sh\n"
           "  Launch PSCAL shell front end"},
#endif
    {"scp", "scp [-P PORT] SRC... DEST\n"
            "  Uses OpenSSH scp"},
    {"sftp", "sftp [-P PORT] [USER@]HOST\n"
             "  Interactive SFTP client"},
    {"script", "script [-a] [-e] [FILE]\n"
               "  Record terminal output to FILE (default: typescript)\n"
               "  -a append to FILE\n"
               "  -e stop active capture"},
    {"ssh", "ssh [-p PORT] [USER@]HOST [command]\n"
            "  OpenSSH client"},
    {"ssh-keygen", "ssh-keygen [-t TYPE] [-f FILE] [-C COMMENT]\n"
                   "  Generate SSH key pairs"},
    {"ssh-copy-id", "ssh-copy-id [-f] [-n] [-s] [-i [IDENTITY_FILE]] [USER@]HOST\n"
                    "  Install local public key(s) to remote authorized_keys"},
    {"tail", "tail [-n N] [FILE...]\n"
             "  Default N=10"},
    {"tee", "tee [-a] FILE...\n"
            "  -a append"},
    {"telnet", "telnet [-p PORT] HOST\n"
               "  Connect to HOST over TCP (default port 23) and relay stdin/stdout"},
    {"traceroute", "traceroute HOST [PORT]\n"
                   "  Trace network path using the system traceroute command"},
    {"test", "test EXPRESSION\n"
             "  File: -f -d -e; String: = != -z; Int: -eq -ne -lt -le -gt -ge"},
    {"time", "time command [args...]\n"
             "  Run a smallclue applet and print real/user/sys timing"},
    {"tset", "tset [-IQqs] [-e CH] [-i CH] [-k CH] [-r] [TERM]\n"
             "  Set TERM and initialize terminal\n"
             "  -s emit shell commands\n"
             "  -r report terminal type\n"
             "  -Q quiet, -I skip init\n"
             "  -e/-i/-k set erase/intr/kill chars"},
    {"touch", "touch FILE...\n"
              "  Update timestamps or create empty file"},
    {"sum", "sum [-r|-s] [FILE...]\n"
            "  BSD (-r, default): rotate-right checksum, 1K blocks.\n"
            "  SysV (-s, --sysv): simple sum, 512-byte blocks.\n"
            "  With no FILE or FILE '-', read standard input.\n"
            "  Prints: <checksum> <blocks> [filename]\n"},
    {"tty", "tty [-s]\n"
            "  Print terminal name"},
    {"tr", "tr SET1 SET2\n"
           "  Translate/delete characters"},
    {"true", "true\n"
             "  Exit status 0"},
    {"type", "type NAME...\n"
             "  Describe how a name is resolved"},
    {"uname", "uname [-asnrvmp]\n"
              "  -a show all fields\n"
              "  -s system name\n"
              "  -n nodename\n"
              "  -r release\n"
              "  -v version\n"
              "  -m machine\n"
              "  -p processor"},
    {"uniq", "uniq [-c] [-d] [-u] [FILE]\n"
             "  -c count\n"
             "  -d duplicates only\n"
             "  -u unique only"},
    {"uptime", "uptime\n"
               "  Show system uptime"},
    {"version", "version\n"
                "  Show PSCAL app marketing version"},
    {"vproc-test", "vproc-test [--help]\n"
                   "  Run vproc/session/spawn diagnostics\n"
                   "  --session  Only run session input checks\n"
                   "  --vproc    Only run vproc stdin checks\n"
                   "  --spawn    Only run vproc spawn checks\n"
                   "  --readpass Run an SSH-style passphrase read test"},
    {"vi", "vi [FILE]\n"
           "  Alias for nextvi"},
    {"watch", "watch [-n SECONDS] [-c COUNT|--count COUNT] command...\n"
              "  Periodically run a command"},
    {"wc", "wc [-l] [-w] [-c] [FILE...]\n"
           "  Count lines/words/bytes"},
    {"wget", "wget [options] URL...\n"
             "  Common: -O FILE\n"
             "  --header\n"
             "  --post-data\n"
             "  -q\n"
             "  -nv"},
    {"yes", "yes [STRING...]\n"
            "  Repeatedly print STRING (default: y)"},
    {"no", "no [STRING...]\n"
           "  Repeatedly print STRING (default: n) and exit 1 on stop"},
    {"xargs", "xargs [-n N] [-0]\n"
              "  Build command lines from stdin"},
    {"df", "df [-h]\n"
           "  -h human-readable sizes"},
    {"nslookup", "nslookup [-v] host [port]\n"
                 "  DNS lookup utility (UDP port defaults to 53). -v prints hosts lookup debugging."},
#if defined(PSCAL_TARGET_IOS)
    {"addt", "addt\n"
             "  Open an additional shell tab"},
    {"smallclue-help", "smallclue-help [command]\n"
                       "  Without arguments: list all applets\n"
                       "  With a command: show usage if available"},
    {"licenses", "licenses\n"
                 "  Browse PSCAL and third-party licenses; use arrows/enter to view"},
    {"dmesg", "dmesg [-T]\n"
              "  Show PSCAL runtime log for this session\n"
              "  -T  show human-readable timestamps"},
    {"top", "top\n"
            "  Show PSCAL virtual processes and CPU ticks"},
#endif
    {NULL, NULL}
};

static size_t kSmallclueAppletCount = sizeof(kSmallclueApplets) / sizeof(kSmallclueApplets[0]);

static const char * __attribute__((unused)) smallclueLookupHelp(const char *name) {
    for (const SmallclueAppletHelp *h = kSmallclueAppletHelp; h && h->name; ++h) {
        if (strcmp(h->name, name) == 0) {
            return h->usage;
        }
    }
    return NULL;
}

static const char *pager_command_name(const char *name);
static int pager_read_key(void);
static char *pagerReadLogicalLine(const PagerBuffer *buffer, size_t line_index, bool *had_newline);

static void pagerBell(void) {
    fputc('\a', stdout);
    fflush(stdout);
}

static bool pagerBufferEnsureOffsetCapacity(size_t **offsets,
                                            size_t *capacity,
                                            size_t required) {
    if (!offsets || !capacity) {
        return false;
    }
    if (required <= *capacity) {
        return true;
    }
    size_t new_capacity = (*capacity == 0) ? 1024 : *capacity;
    while (new_capacity < required) {
        new_capacity *= 2;
    }
    size_t *resized = (size_t *)realloc(*offsets, new_capacity * sizeof(size_t));
    if (!resized) {
        return false;
    }
    *offsets = resized;
    *capacity = new_capacity;
    return true;
}

static void pagerBufferFree(PagerBuffer *buffer) {
    if (!buffer) {
        return;
    }
    if (buffer->file) {
        fclose(buffer->file);
    }
    free(buffer->offsets);
    buffer->file = NULL;
    buffer->offsets = NULL;
    buffer->offset_count = 0;
    buffer->line_count = 0;
    buffer->length = 0;
}

static bool smallclueLineVectorAppend(SmallclueLineVector *vec, const char *data, size_t len) {
    if (!vec || !data) {
        return false;
    }
    if (vec->count == vec->capacity) {
        size_t newcap = vec->capacity ? vec->capacity * 2 : 64;
        char **ptr = (char **)realloc(vec->items, newcap * sizeof(char *));
        if (!ptr) {
            return false;
        }
        vec->items = ptr;
        vec->capacity = newcap;
    }
    char *copy = (char *)malloc(len + 1);
    if (!copy) {
        return false;
    }
    memcpy(copy, data, len);
    copy[len] = '\0';
    vec->items[vec->count++] = copy;
    return true;
}

static void smallclueLineVectorFree(SmallclueLineVector *vec) {
    if (!vec) {
        return;
    }
    for (size_t i = 0; i < vec->count; ++i) {
        free(vec->items[i]);
    }
    free(vec->items);
    vec->items = NULL;
    vec->count = 0;
    vec->capacity = 0;
}

static ssize_t smallclueReadStdin(void *buf, size_t count, int *out_errno) {
    if (out_errno) {
        *out_errno = 0;
    }
    if (!buf || count == 0) {
        return 0;
    }
    while (true) {
        ssize_t res = 0;
#if defined(PSCAL_TARGET_IOS)
        res = vprocReadShim(STDIN_FILENO, buf, count);
#else
        res = read(STDIN_FILENO, buf, count);
#endif
        if (res < 0) {
            if (errno == EINTR) {
                continue;
            }
            if (out_errno) {
                *out_errno = errno ? errno : EIO;
            }
            return -1;
        }
        return res;
    }
}

static ssize_t smallclueReadStream(FILE *stream, void *buf, size_t count, int *out_errno) {
    if (out_errno) {
        *out_errno = 0;
    }
    if (!stream || !buf || count == 0) {
        return 0;
    }
    if (stream == stdin) {
        return smallclueReadStdin(buf, count, out_errno);
    }
    size_t read_bytes = fread(buf, 1, count, stream);
    if (read_bytes < count && ferror(stream)) {
        if (out_errno) {
            *out_errno = errno ? errno : EIO;
        }
    }
    return (ssize_t)read_bytes;
}

static int smallclueGetcStream(FILE *stream, int *out_errno) {
    if (out_errno) {
        *out_errno = 0;
    }
    if (!stream) {
        if (out_errno) {
            *out_errno = EBADF;
        }
        errno = EBADF;
        return EOF;
    }
    if (stream != stdin) {
        int ch = fgetc(stream);
        if (ch == EOF && ferror(stream)) {
            if (out_errno) {
                *out_errno = errno ? errno : EIO;
            }
        }
        return ch;
    }
    unsigned char ch = 0;
    int read_err = 0;
    ssize_t res = smallclueReadStdin(&ch, 1, &read_err);
    if (res <= 0) {
        if (read_err && out_errno) {
            *out_errno = read_err;
        }
        return EOF;
    }
    return (int)ch;
}

static ssize_t smallclueGetlineStream(char **line, size_t *cap, FILE *stream, int *out_errno) {
    if (out_errno) {
        *out_errno = 0;
    }
    if (!line || !cap || !stream) {
        if (out_errno) {
            *out_errno = EINVAL;
        }
        errno = EINVAL;
        return -1;
    }
    if (stream != stdin) {
        ssize_t len = getline(line, cap, stream);
        if (len < 0 && ferror(stream)) {
            if (out_errno) {
                *out_errno = errno ? errno : EIO;
            }
        }
        return len;
    }
    if (!*line || *cap == 0) {
        size_t newcap = 128;
        char *buf = (char *)malloc(newcap);
        if (!buf) {
            if (out_errno) {
                *out_errno = ENOMEM;
            }
            errno = ENOMEM;
            return -1;
        }
        *line = buf;
        *cap = newcap;
    }
    size_t len = 0;
    while (true) {
        unsigned char ch = 0;
        int read_err = 0;
        ssize_t res = smallclueReadStdin(&ch, 1, &read_err);
        if (res < 0) {
            if (out_errno) {
                *out_errno = read_err ? read_err : (errno ? errno : EIO);
            }
            return -1;
        }
        if (res == 0) {
            if (len == 0) {
                return -1;
            }
            break;
        }
        if (len + 1 >= *cap) {
            size_t newcap = (*cap) * 2;
            if (newcap < *cap + 2) {
                newcap = *cap + 2;
            }
            char *resized = (char *)realloc(*line, newcap);
            if (!resized) {
                if (out_errno) {
                    *out_errno = ENOMEM;
                }
                errno = ENOMEM;
                return -1;
            }
            *line = resized;
            *cap = newcap;
        }
        (*line)[len++] = (char)ch;
        if (ch == '\n') {
            break;
        }
    }
    (*line)[len] = '\0';
    return (ssize_t)len;
}

static bool smallclueReadTokensFromStdin(SmallclueLineVector *vec) {
    char *token = NULL;
    size_t tokcap = 0;
    size_t toklen = 0;
    int ch;
    int read_err = 0;
    while ((ch = smallclueGetcStream(stdin, &read_err)) != EOF) {
        if (isspace((unsigned char)ch)) {
            if (toklen > 0) {
                if (!smallclueLineVectorAppend(vec, token, toklen)) {
                    free(token);
                    return false;
                }
                toklen = 0;
            }
            continue;
        }
        if (toklen + 1 >= tokcap) {
            size_t newcap = tokcap ? tokcap * 2 : 64;
            char *tmp = (char *)realloc(token, newcap);
            if (!tmp) {
                free(token);
                return false;
            }
            token = tmp;
            tokcap = newcap;
        }
        token[toklen++] = (char)ch;
    }
    if (read_err) {
        free(token);
        return false;
    }
    if (toklen > 0) {
        bool ok = smallclueLineVectorAppend(vec, token, toklen);
        free(token);
        return ok;
    }
    free(token);
    return true;
}

static int smallcluePsCommand(int argc, char **argv) {
    (void)argc;
    (void)argv;
    pid_t pid = getpid();
    pid_t ppid = getppid();
    uid_t uid = getuid();
    const char *cmd = argv && argv[0] ? argv[0] : "ps";
    printf(" PID   PPID   UID COMMAND\n");
    printf("%4d %6d %5d %s\n", (int)pid, (int)ppid, (int)uid, cmd);
    return 0;
}

#if defined(PSCAL_TARGET_IOS)
#include "ios/vproc_tree.h"
static const char *smallclueTopState(const VProcSnapshot *snap) {
    if (!snap) {
        return "unknown";
    }
    if (snap->zombie) {
        return "zombie";
    }
    if (snap->stopped) {
        return "stopped";
    }
    if (snap->continued) {
        return "continued";
    }
    if (snap->exited) {
        return "exited";
    }
    if (snap->sigchld_pending) {
        return "sigchld";
    }
    return "running";
}

static bool smallclueWriteAll(int fd, const char *data, size_t len) {
    if (!data || len == 0) {
        return true;
    }
    size_t off = 0;
    while (off < len) {
        ssize_t wrote = write(fd, data + off, len - off);
        if (wrote < 0) {
            if (errno == EINTR) {
                continue;
            }
            return false;
        }
        off += (size_t)wrote;
    }
    return true;
}

#if defined(__APPLE__)
static bool smallclueReadMemStats(size_t *used_kb, size_t *free_kb) {
    if (!used_kb || !free_kb) return false;
    uint64_t memsize = 0;
    size_t memlen = sizeof(memsize);
    if (sysctlbyname("hw.memsize", &memsize, &memlen, NULL, 0) != 0 || memsize == 0) {
        return false;
    }
    mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;
    vm_statistics64_data_t vmstat;
    if (host_statistics64(mach_host_self(), HOST_VM_INFO64, (host_info64_t)&vmstat, &count) != KERN_SUCCESS) {
        return false;
    }
    vm_size_t page_size = 0;
    if (host_page_size(mach_host_self(), &page_size) != KERN_SUCCESS || page_size == 0) {
        return false;
    }
    uint64_t free_pages = vmstat.free_count + vmstat.speculative_count;
    uint64_t used_bytes = memsize - (free_pages * (uint64_t)page_size);
    uint64_t free_bytes = memsize - used_bytes;
    *free_kb = (size_t)(free_bytes / 1024);
    *used_kb = (size_t)(used_bytes / 1024);
    return true;
}

static bool smallclueReadCpuStats(double *usr, double *sys, double *nice, double *idle) {
    static uint64_t prev_user = 0, prev_sys = 0, prev_nice = 0, prev_idle = 0;
    host_cpu_load_info_data_t cpuinfo;
    mach_msg_type_number_t count = HOST_CPU_LOAD_INFO_COUNT;
    if (host_statistics(mach_host_self(), HOST_CPU_LOAD_INFO, (host_info_t)&cpuinfo, &count) != KERN_SUCCESS) {
        return false;
    }
    uint64_t user = cpuinfo.cpu_ticks[CPU_STATE_USER];
    uint64_t system = cpuinfo.cpu_ticks[CPU_STATE_SYSTEM];
    uint64_t nice_ticks = cpuinfo.cpu_ticks[CPU_STATE_NICE];
    uint64_t idle_ticks = cpuinfo.cpu_ticks[CPU_STATE_IDLE];
    if (prev_user == 0 && prev_sys == 0 && prev_nice == 0 && prev_idle == 0) {
        prev_user = user;
        prev_sys = system;
        prev_nice = nice_ticks;
        prev_idle = idle_ticks;
        return false;
    }
    uint64_t du = user - prev_user;
    uint64_t ds = system - prev_sys;
    uint64_t dn = nice_ticks - prev_nice;
    uint64_t di = idle_ticks - prev_idle;
    uint64_t total = du + ds + dn + di;
    prev_user = user;
    prev_sys = system;
    prev_nice = nice_ticks;
    prev_idle = idle_ticks;
    if (total == 0) {
        return false;
    }
    if (usr) *usr = (double)du * 100.0 / (double)total;
    if (sys) *sys = (double)ds * 100.0 / (double)total;
    if (nice) *nice = (double)dn * 100.0 / (double)total;
    if (idle) *idle = (double)di * 100.0 / (double)total;
    return true;
}
#endif

static int smallclueTopCommand(int argc, char **argv) {
    bool tree = true;
    bool hide_kernel = false;
    for (int i = 1; i < argc; ++i) {
        const char *arg = argv[i];
        if (!arg) {
            continue;
        }
        if (strcmp(arg, "--flat") == 0) {
            tree = false;
        } else if (strcmp(arg, "--tree") == 0) {
            tree = true;
        } else if (strcmp(arg, "--no-kernel") == 0 || strcmp(arg, "--hide-kernel") == 0) {
            hide_kernel = true;
        } else if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
            const char *help =
                "top [--tree|--flat] [--no-kernel]\n"
                "  Show PSCAL virtual processes.\n"
                "  --tree (default) render parent/child tree.\n"
                "  --flat show a flat list.\n"
                "  --no-kernel hide the synthetic kernel row.\n";
            (void)smallclueWriteAll(STDOUT_FILENO, help, strlen(help));
            return 0;
        } else {
            fprintf(stderr, "top: unsupported option '%s'\n", arg);
            return 1;
        }
    }
    VProc *self_vp = vprocCurrent();
    int self_pid = self_vp ? vprocPid(self_vp) : (int)vprocGetPidShim();

    size_t snapshot_cap = 0;
    VProcSnapshot *snapshots = NULL;

#if defined(__APPLE__)
    /* Prime CPU counters so a single render still shows utilization. */
    (void)smallclueReadCpuStats(NULL, NULL, NULL, NULL);
    struct timespec prime_sleep = {.tv_sec = 0, .tv_nsec = 100000000};
    nanosleep(&prime_sleep, &prime_sleep);
#endif

    while (1) {
        size_t needed = vprocSnapshot(NULL, 0);
        if (needed > snapshot_cap) {
            VProcSnapshot *resized = (VProcSnapshot *)realloc(snapshots, needed * sizeof(VProcSnapshot));
            if (!resized) {
                free(snapshots);
                fprintf(stderr, "top: out of memory\n");
                return 1;
            }
            snapshots = resized;
            snapshot_cap = needed;
        }
        size_t snapshot_count = snapshots ? vprocSnapshot(snapshots, snapshot_cap) : 0;

        /* Clear and render. */
        fputs("\x1b[2J\x1b[H", stdout);

#if defined(__APPLE__)
        size_t mem_used_kb = 0, mem_free_kb = 0;
        if (smallclueReadMemStats(&mem_used_kb, &mem_free_kb)) {
            char mem_line[160];
            int mn = snprintf(mem_line, sizeof(mem_line),
                              "Mem: %zuK used, %zuK free\n",
                              mem_used_kb, mem_free_kb);
            if (mn > 0) {
                (void)smallclueWriteAll(STDOUT_FILENO, mem_line, (size_t)mn);
            }
        }
        double cpu_usr = 0, cpu_sys = 0, cpu_nice = 0, cpu_idle = 0;
        if (smallclueReadCpuStats(&cpu_usr, &cpu_sys, &cpu_nice, &cpu_idle)) {
            char cpu_line[160];
            int cn = snprintf(cpu_line, sizeof(cpu_line),
                              "CPU: %3.0f%% usr %3.0f%% sys %3.0f%% nic %3.0f%% idle\n\n",
                              cpu_usr, cpu_sys, cpu_nice, cpu_idle);
            if (cn > 0) {
                (void)smallclueWriteAll(STDOUT_FILENO, cpu_line, (size_t)cn);
            }
        }
#endif

        char header[160];
        int hn = snprintf(header, sizeof(header),
                          "%-6s %-6s %-6s %-6s %-3s %-10s %-6s %-6s %s\n",
                          "PID", "PPID", "PGID", "SID", "FG", "STATE", "UTIME", "STIME", "CMD");
        if (hn > 0) {
            (void)smallclueWriteAll(STDOUT_FILENO, header, (size_t)hn);
        }

        if (tree) {
            size_t row_cap = snapshot_count ? snapshot_count : 1;
            VProcTreeRow *rows = (VProcTreeRow *)calloc(row_cap, sizeof(VProcTreeRow));
            size_t row_count = rows ? vprocBuildTreeRows(snapshots, snapshot_count, rows, row_cap) : 0;
            if (rows && row_count > row_cap) {
                VProcTreeRow *grown = (VProcTreeRow *)realloc(rows, row_count * sizeof(VProcTreeRow));
                if (grown) {
                    rows = grown;
                    row_cap = row_count;
                }
                row_count = rows ? vprocBuildTreeRows(snapshots, snapshot_count, rows, row_cap) : 0;
            }
            if (rows) {
                for (size_t r = 0; r < row_count && r < row_cap; ++r) {
                    const VProcTreeRow *row = &rows[r];
                    if (!row || row->snapshot_index >= snapshot_count) {
                        continue;
                    }
                    VProcSnapshot *snap = &snapshots[row->snapshot_index];
                    if (!snap || snap->pid <= 0) {
                        continue;
                    }
                    if (hide_kernel &&
                        ((snap->command[0] && strcmp(snap->command, "kernel") == 0) ||
                         (snap->comm[0] && strcmp(snap->comm, "kernel") == 0))) {
                        continue;
                    }
                    const char *state = smallclueTopState(snap);
                    bool fg = (snap->fg_pgid > 0 && snap->pgid == snap->fg_pgid);
                    const char *cmd = snap->command[0] ? snap->command
                                    : (snap->comm[0] ? snap->comm
                                    : ((snap->pid == vprocGetShellSelfPid()) ? "shell" : "task"));
                    if (snap->pid == self_pid) {
                        cmd = "top";
                    }

                    char indent[96];
                    size_t used = 0;
                    for (int d = 0; d < row->depth && used + 2 < sizeof(indent); ++d) {
                        indent[used++] = ' ';
                        indent[used++] = ' ';
                    }
                    indent[used] = '\0';

                    double ut_s = 0.0, st_s = 0.0;
                    vprocFormatCpuTimes(snap->rusage_utime, snap->rusage_stime, &ut_s, &st_s);
                    char line[320];
                    int n = snprintf(line, sizeof(line),
                                     "%-6d %-6d %-6d %-6d %-3s %-10s %-6.1f %-6.1f %s%s\n",
                                     snap->pid, snap->parent_pid, snap->pgid, snap->sid,
                                     fg ? "fg" : "", state, ut_s, st_s, indent, cmd);
                    if (n > 0) {
                        (void)smallclueWriteAll(STDOUT_FILENO, line, (size_t)n);
                    }
                }
                free(rows);
            }
        } else {
            for (size_t i = 0; i < snapshot_count; ++i) {
                VProcSnapshot *snap = &snapshots[i];
                if (!snap || snap->pid <= 0) {
                    continue;
                }
                if (hide_kernel &&
                    ((snap->command[0] && strcmp(snap->command, "kernel") == 0) ||
                     (snap->comm[0] && strcmp(snap->comm, "kernel") == 0))) {
                    continue;
                }
                const char *state = smallclueTopState(snap);
                bool fg = (snap->fg_pgid > 0 && snap->pgid == snap->fg_pgid);
                const char *cmd = snap->command[0] ? snap->command
                                : (snap->comm[0] ? snap->comm
                                : ((snap->pid == vprocGetShellSelfPid()) ? "shell" : "task"));
                if (snap->pid == self_pid) {
                    cmd = "top";
                }
                double ut_s = 0.0, st_s = 0.0;
                vprocFormatCpuTimes(snap->rusage_utime, snap->rusage_stime, &ut_s, &st_s);
                char line[320];
                int n = snprintf(line, sizeof(line),
                                 "%-6d %-6d %-6d %-6d %-3s %-10s %-6.1f %-6.1f %s\n",
                                 snap->pid, snap->parent_pid, snap->pgid, snap->sid,
                                 fg ? "fg" : "", state, ut_s, st_s, cmd);
                if (n > 0) {
                    (void)smallclueWriteAll(STDOUT_FILENO, line, (size_t)n);
                }
            }
        }

        fflush(stdout);
        break;
    }

    free(snapshots);
    return 0;
}
#endif

typedef struct {
    const char *name;
    int value;
} SmallclueSignalName;

static const SmallclueSignalName kSignalNames[] = {
#ifdef SIGHUP
    {"HUP", SIGHUP},
#endif
#ifdef SIGINT
    {"INT", SIGINT},
#endif
#ifdef SIGQUIT
    {"QUIT", SIGQUIT},
#endif
#ifdef SIGILL
    {"ILL", SIGILL},
#endif
#ifdef SIGABRT
    {"ABRT", SIGABRT},
#endif
#ifdef SIGKILL
    {"KILL", SIGKILL},
#endif
#ifdef SIGALRM
    {"ALRM", SIGALRM},
#endif
#ifdef SIGTERM
    {"TERM", SIGTERM},
#endif
#ifdef SIGUSR1
    {"USR1", SIGUSR1},
#endif
#ifdef SIGUSR2
    {"USR2", SIGUSR2},
#endif
#ifdef SIGPIPE
    {"PIPE", SIGPIPE},
#endif
};

static bool smallclueParseSignal(const char *spec, int *out) {
    if (!spec || !*spec) {
        return false;
    }
    if (isdigit((unsigned char)spec[0])) {
        char *end = NULL;
        errno = 0;
        long val = strtol(spec, &end, 10);
        if (errno != 0 || !end || *end != '\0' || val <= 0 || val > NSIG) {
            return false;
        }
        *out = (int)val;
        return true;
    }
    if (spec[0] == 'S' && spec[1] == 'I' && spec[2] == 'G') {
        spec += 3;
    }
    for (size_t i = 0; i < sizeof(kSignalNames) / sizeof(kSignalNames[0]); ++i) {
        if (strcasecmp(spec, kSignalNames[i].name) == 0) {
            *out = kSignalNames[i].value;
            return true;
        }
    }
    return false;
}

static void smallclueKillListSignals(void) {
    for (size_t i = 0; i < sizeof(kSignalNames) / sizeof(kSignalNames[0]); ++i) {
        printf("%s ", kSignalNames[i].name);
    }
    putchar('\n');
}

static int smallclueKillCommandOriginal(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: kill [-SIGNAL] pid...\n");
        return 1;
    }
    int signo = SIGTERM;
    int idx = 1;
    if (idx < argc && argv[idx][0] == '-') {
        const char *spec = argv[idx] + 1;
        if (strcmp(spec, "l") == 0 || strcmp(spec, "L") == 0) {
            smallclueKillListSignals();
            return 0;
        }
        if (!smallclueParseSignal(spec, &signo)) {
            fprintf(stderr, "kill: invalid signal '%s'\n", spec);
            return 1;
        }
        idx++;
    }
    if (idx >= argc) {
        fprintf(stderr, "usage: kill [-SIGNAL] pid...\n");
        return 1;
    }
    int status = 0;
    for (; idx < argc; ++idx) {
        char *end = NULL;
        errno = 0;
        const char *arg = argv[idx];
        long pid_val = -1;

#if defined(PSCAL_TARGET_IOS)
        if (arg && arg[0] == '%') {
            const char *p = arg + 1;
            while (isspace((unsigned char)*p)) {
                ++p;
            }
            errno = 0;
            long vis = strtol(p, &end, 10);
            while (end && *end && isspace((unsigned char)*end)) {
                ++end;
            }
            bool ok = (errno == 0 && end && *end == '\0' && vis > 0);
            if (ok) {
                size_t cap = vprocSnapshot(NULL, 0);
                VProcSnapshot *snaps = (cap > 0) ? (VProcSnapshot *)calloc(cap, sizeof(VProcSnapshot)) : NULL;
                size_t count = snaps ? vprocSnapshot(snaps, cap) : 0;
                /* Prefer matching by synthetic job id to keep numbering stable. */
                for (size_t i = 0; i < count; ++i) {
                    const VProcSnapshot *s = &snaps[i];
                    if (!s || s->pid <= 0) {
                        continue;
                    }
                    int jid = vprocGetJobId(s->pid);
                    if (jid > 0 && jid == vis) {
                        pid_val = s->pid;
                        break;
                    }
                }
                size_t visible = 0;
                for (size_t i = 0; i < count; ++i) {
                    const VProcSnapshot *s = &snaps[i];
                    if (!s || s->pid <= 0) {
                        continue;
                    }
                    if (s->pid == vprocGetShellSelfPid() || pthread_equal(s->tid, pthread_self())) {
                        continue;
                    }
                    if (pid_val > 0) {
                        break;
                    }
                    ++visible;
                    if (visible == (size_t)vis) {
                        pid_val = s->pid;
                        break;
                    }
                }
                free(snaps);
                if (pid_val < 0) {
                    fprintf(stderr, "kill: invalid job '%s'\n", arg);
                    status = 1;
                    continue;
                }
            } else {
                fprintf(stderr, "kill: invalid pid '%s'\n", arg);
                status = 1;
                continue;
            }
        }
#endif

        if (pid_val < 0) {
            pid_val = strtol(arg, &end, 10);
        }

        if (errno != 0 || !end || *end != '\0' || pid_val <= 0) {
            fprintf(stderr, "kill: invalid pid '%s'\n", arg ? arg : "");
            status = 1;
            continue;
        }

#if defined(PSCAL_TARGET_IOS)
        if (vprocKillShim((pid_t)pid_val, signo) != 0) {
            fprintf(stderr, "kill: %s: %s\n", arg, strerror(errno));
            status = 1;
        }
#else
        if (kill((pid_t)pid_val, signo) != 0) {
            fprintf(stderr, "kill: %s: %s\n", arg, strerror(errno));
            status = 1;
        }
#endif
    }
    return status;
}

static int smallclueKillCommand(int argc, char **argv) {
    return smallclueKillCommandOriginal(argc, argv);
}

static int smallclueXargsCommand(int argc, char **argv) {
    smallclueResetGetopt();
    int opt;
    while ((opt = getopt(argc, argv, "")) != -1) {
        fprintf(stderr, "usage: xargs command [initial-args]\n");
        return 1;
    }
    if (optind >= argc) {
        fprintf(stderr, "xargs: missing command name\n");
        return 1;
    }
    int base_count = argc - optind;
    char **base_args = &argv[optind];
    const SmallclueApplet *target = smallclueFindApplet(base_args[0]);
    if (!target) {
        fprintf(stderr, "xargs: '%s' not found\n", base_args[0]);
        return 127;
    }
    SmallclueLineVector extra = {0};
    if (!smallclueReadTokensFromStdin(&extra)) {
        perror("xargs");
        smallclueLineVectorFree(&extra);
        return 1;
    }
    size_t total = (size_t)base_count + extra.count;
    char **cmd_argv = (char **)calloc(total + 1, sizeof(char *));
    if (!cmd_argv) {
        perror("xargs");
        smallclueLineVectorFree(&extra);
        return 1;
    }
    size_t index = 0;
    for (int i = 0; i < base_count; ++i) {
        cmd_argv[index] = strdup(base_args[i]);
        if (!cmd_argv[index]) {
            perror("xargs");
            for (size_t k = 0; k < index; ++k) {
                free(cmd_argv[k]);
            }
            free(cmd_argv);
            smallclueLineVectorFree(&extra);
            return 1;
        }
        index++;
    }
    for (size_t i = 0; i < extra.count; ++i) {
        cmd_argv[index++] = extra.items[i];
        extra.items[i] = NULL;
    }
    int status = smallclueDispatchApplet(target, (int)total, cmd_argv);
    for (size_t i = 0; i < total; ++i) {
        free(cmd_argv[i]);
    }
    free(cmd_argv);
    smallclueLineVectorFree(&extra);
    return status;
}


static int smallclueLineVectorLoadStream(FILE *fp, const char *path, const char *cmd_name, SmallclueLineVector *vec) {
    char *line = NULL;
    size_t cap = 0;
    int status = 0;
    while (true) {
        int read_err = 0;
        ssize_t len = smallclueGetlineStream(&line, &cap, fp, &read_err);
        if (len < 0) {
            if (read_err) {
                fprintf(stderr, "%s: %s: %s\n", cmd_name, path ? path : "(stdin)", strerror(read_err));
                status = 1;
            }
            break;
        }
        if (!smallclueLineVectorAppend(vec, line, (size_t)len)) {
            fprintf(stderr, "%s: %s: out of memory\n", cmd_name, path ? path : "(stdin)");
            status = 1;
            break;
        }
    }
    free(line);
    return status;
}

static int smallclueStringCompare(const void *a, const void *b) {
    const char *const *lhs = (const char *const *)a;
    const char *const *rhs = (const char *const *)b;
    return strcmp(*lhs, *rhs);
}

static int pagerCollectLines(const char *cmd_name, const char *path, FILE *stream, PagerBuffer *buffer) {
    if (!stream || !buffer) {
        return 1;
    }

    memset(buffer, 0, sizeof(*buffer));
    const char *tmp_root = getenv("TMPDIR");
    if (!tmp_root || !*tmp_root) {
        tmp_root = "/tmp";
    }
    char tmpl[PATH_MAX];
    snprintf(tmpl, sizeof(tmpl), "%s/smallclue-pager-XXXXXX", tmp_root);
    int fd = mkstemp(tmpl);
    if (fd < 0) {
        fprintf(stderr, "%s: failed to allocate pager storage: %s\n",
                pager_command_name(cmd_name), strerror(errno));
        return 1;
    }
    FILE *fp = fdopen(fd, "w+b");
    if (!fp) {
        close(fd);
        unlink(tmpl);
        fprintf(stderr, "%s: failed to open pager storage: %s\n",
                pager_command_name(cmd_name), strerror(errno));
        return 1;
    }
    unlink(tmpl);

    size_t *offsets = NULL;
    size_t offset_cap = 0;
    size_t offset_count = 0;
    if (!pagerBufferEnsureOffsetCapacity(&offsets, &offset_cap, 1)) {
        fprintf(stderr, "%s: out of memory\n", pager_command_name(cmd_name));
        fclose(fp);
        return 1;
    }
    offsets[offset_count++] = 0;

    char buf[8192];
    size_t total = 0;
    while (true) {
        int read_err = 0;
        ssize_t read_bytes = smallclueReadStream(stream, buf, sizeof(buf), &read_err);
        if (read_bytes < 0) {
            fprintf(stderr, "%s: %s: %s\n",
                    pager_command_name(cmd_name),
                    path ? path : "(stdin)",
                    strerror(read_err ? read_err : errno));
            free(offsets);
            fclose(fp);
            return 1;
        }
        if (read_bytes > 0) {
            size_t written = fwrite(buf, 1, (size_t)read_bytes, fp);
            if (written != (size_t)read_bytes) {
                fprintf(stderr, "%s: failed to buffer pager input\n",
                        pager_command_name(cmd_name));
                free(offsets);
                fclose(fp);
                return 1;
            }
            for (size_t i = 0; i < (size_t)read_bytes; ++i) {
                if (buf[i] == '\n') {
                    if (!pagerBufferEnsureOffsetCapacity(&offsets, &offset_cap, offset_count + 1)) {
                        fprintf(stderr, "%s: out of memory\n", pager_command_name(cmd_name));
                        free(offsets);
                        fclose(fp);
                        return 1;
                    }
                    offsets[offset_count++] = total + i + 1;
                }
            }
            total += (size_t)read_bytes;
        }
        if (read_err) {
            fprintf(stderr, "%s: %s: %s\n",
                    pager_command_name(cmd_name),
                    path ? path : "(stdin)",
                    strerror(read_err));
            free(offsets);
            fclose(fp);
            return 1;
        }
        if (read_bytes == 0) {
            break;
        }
    }

    if (offset_count == 0 || offsets[offset_count - 1] != total) {
        if (!pagerBufferEnsureOffsetCapacity(&offsets, &offset_cap, offset_count + 1)) {
            fprintf(stderr, "%s: out of memory\n", pager_command_name(cmd_name));
            free(offsets);
            fclose(fp);
            return 1;
        }
        offsets[offset_count++] = total;
    }

    buffer->file = fp;
    buffer->offsets = offsets;
    buffer->offset_count = offset_count;
    buffer->line_count = (offset_count > 0) ? (offset_count - 1) : 0;
    buffer->length = total;
    if (fseeko(fp, 0, SEEK_SET) != 0) {
        pagerBufferFree(buffer);
        return 1;
    }
    return 0;
}

static void pagerRenderPage(const PagerBuffer *buffer, size_t start, int page_rows, const char *highlight_target) {
    if (!buffer || !buffer->file || !buffer->offsets) {
        return;
    }
    if (page_rows < 1) {
        page_rows = 1;
    }
    fputs("\x1b[2J\x1b[H", stdout);
    size_t end = start + (size_t)page_rows;
    if (end > buffer->line_count) {
        end = buffer->line_count;
    }
    for (size_t i = start; i < end; ++i) {
        bool had_newline = false;
        char *line = pagerReadLogicalLine(buffer, i, &had_newline);
        if (!line) {
            continue;
        }
        if (highlight_target && *highlight_target) {
            char *hit = strstr(line, highlight_target);
            if (hit) {
                size_t prefix_len = (size_t)(hit - line);
                fwrite(line, 1, prefix_len, stdout);
                fputs("\x1b[7m", stdout);
                fwrite(hit, 1, strlen(highlight_target), stdout);
                fputs("\x1b[0m", stdout);
                fputs(hit + strlen(highlight_target), stdout);
            } else {
                fputs(line, stdout);
            }
        } else {
            fputs(line, stdout);
        }
        fputc('\n', stdout);
        free(line);
    }
    fflush(stdout);
}

static size_t pagerMaxTop(const PagerBuffer *buffer, int page_rows) {
    if (!buffer || buffer->line_count == 0) {
        return 0;
    }
    size_t page = (size_t)(page_rows > 0 ? page_rows : 1);
    if (buffer->line_count <= page) {
        return 0;
    }
    return buffer->line_count - page;
}

static int pagerPromptAndRead(const char *cmd_name) {
    const char *label = pager_command_name(cmd_name);
    bool md_mode = (label && strcmp(label, "md") == 0);
    if (md_mode) {
        fprintf(stdout, "\r--%s-- (Space=next, b=prev, arrows=scroll, [ ]=pick link, Enter=open, o=links, q=back, Q=quit) ", label);
    } else {
        fprintf(stdout, "\r--%s-- (Space=next, b=prev, arrows=scroll, q=quit) ", label);
    }
    fflush(stdout);
    int key = pager_read_key();
    fputs("\r\x1b[K", stdout);
    fflush(stdout);
    return key;
}

static _Thread_local int pager_last_exit_key = 'q';
static _Thread_local int pager_last_md_link_index = -1;
static _Thread_local const MarkdownLinkList *pager_active_md_links = NULL;

static int pagerLastExitKey(void) {
    return pager_last_exit_key;
}

static int pagerLastMdLinkIndex(void) {
    return pager_last_md_link_index;
}

static void pagerSetActiveMarkdownLinks(const MarkdownLinkList *links) {
    pager_active_md_links = links;
}

static char *pagerReadLogicalLine(const PagerBuffer *buffer, size_t line_index, bool *had_newline) {
    if (!buffer || !buffer->file || !buffer->offsets || line_index >= buffer->line_count) {
        return NULL;
    }
    size_t begin = buffer->offsets[line_index];
    size_t finish = buffer->offsets[line_index + 1];
    if (finish > buffer->length) {
        finish = buffer->length;
    }
    size_t raw_len = (finish > begin) ? (finish - begin) : 0;
    char *line = (char *)malloc(raw_len + 1);
    if (!line) {
        return NULL;
    }
    if (had_newline) {
        *had_newline = false;
    }
    if (raw_len == 0) {
        line[0] = '\0';
        return line;
    }
    if (fseeko(buffer->file, (off_t)begin, SEEK_SET) != 0) {
        free(line);
        return NULL;
    }
    size_t read_bytes = fread(line, 1, raw_len, buffer->file);
    if (read_bytes != raw_len) {
        free(line);
        return NULL;
    }
    size_t len = raw_len;
    if (len > 0 && line[len - 1] == '\n') {
        len--;
        if (had_newline) {
            *had_newline = true;
        }
    }
    line[len] = '\0';
    return line;
}

static int markdownLinkListFindTargetIndex(const MarkdownLinkList *links, const char *target) {
    if (!links || !target || !*target) {
        return -1;
    }
    for (size_t i = 0; i < links->count; ++i) {
        if (links->items[i].target && strcmp(links->items[i].target, target) == 0) {
            return (int)i;
        }
    }
    return -1;
}

static bool pagerIndexListContains(const size_t *items, size_t count, size_t value) {
    for (size_t i = 0; i < count; ++i) {
        if (items[i] == value) {
            return true;
        }
    }
    return false;
}

static size_t pagerFindIndexPosition(const size_t *items, size_t count, size_t value) {
    for (size_t i = 0; i < count; ++i) {
        if (items[i] == value) {
            return i;
        }
    }
    return SIZE_MAX;
}

static size_t *pagerCollectVisibleMdLinkIndices(const PagerBuffer *buffer,
                                                size_t start,
                                                int page_rows,
                                                const MarkdownLinkList *links,
                                                size_t *count_out) {
    if (count_out) {
        *count_out = 0;
    }
    if (!buffer || !links || !count_out || links->count == 0) {
        return NULL;
    }
    if (page_rows < 1) {
        page_rows = 1;
    }
    size_t end = start + (size_t)page_rows;
    if (end > buffer->line_count) {
        end = buffer->line_count;
    }

    size_t *indices = NULL;
    size_t count = 0;
    size_t capacity = 0;

    for (size_t line_index = start; line_index < end; ++line_index) {
        bool had_newline = false;
        char *line = pagerReadLogicalLine(buffer, line_index, &had_newline);
        if (!line) {
            continue;
        }
        const char *p = line;
        while (*p) {
            const char *open = strchr(p, '[');
            if (!open) {
                break;
            }
            const char *digits = open + 1;
            if (!isdigit((unsigned char)*digits)) {
                p = open + 1;
                continue;
            }
            char *endptr = NULL;
            long marker = strtol(digits, &endptr, 10);
            if (endptr && *endptr == ']' && marker > 0) {
                size_t link_index = (size_t)(marker - 1);
                if (link_index < links->count && !pagerIndexListContains(indices, count, link_index)) {
                    if (count == capacity) {
                        size_t new_capacity = (capacity == 0) ? 8 : capacity * 2;
                        size_t *resized = (size_t *)realloc(indices, new_capacity * sizeof(size_t));
                        if (!resized) {
                            free(line);
                            free(indices);
                            *count_out = 0;
                            return NULL;
                        }
                        indices = resized;
                        capacity = new_capacity;
                    }
                    indices[count++] = link_index;
                }
                p = endptr + 1;
                continue;
            }
            p = open + 1;
        }
        free(line);
    }
    *count_out = count;
    return indices;
}

static volatile sig_atomic_t g_pager_sigwinch_received = 0;

static void pagerSigwinchHandler(int signo) {
    if (signo == SIGWINCH) {
        g_pager_sigwinch_received = 1;
    }
}

static int pager_terminal_rows(void);

static int pagerInteractiveSession(const char *cmd_name, PagerBuffer *buffer, int page_rows) {
    if (!buffer || buffer->line_count == 0) {
        pager_last_exit_key = 'q';
        pager_last_md_link_index = -1;
        return 0;
    }
    if (page_rows < 1) {
        page_rows = 1;
    }

    struct sigaction sa, old_sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = pagerSigwinchHandler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGWINCH, &sa, &old_sa);

    const char *label = pager_command_name(cmd_name);
    bool md_mode = (label && strcmp(label, "md") == 0);
    const MarkdownLinkList *md_links = md_mode ? pager_active_md_links : NULL;
    size_t top = 0;
    bool redraw = true;
    size_t selected_md_link_index = SIZE_MAX;
    int ret = 0;

    while (1) {
        if (redraw) {
            char *highlight = NULL;
            if (md_links && selected_md_link_index != SIZE_MAX &&
                selected_md_link_index < md_links->count) {
                char marker[32];
                snprintf(marker, sizeof(marker), "[%zu]", selected_md_link_index + 1);
                size_t marker_len = strlen(marker);
                highlight = (char *)malloc(marker_len + 1);
                if (highlight) {
                    memcpy(highlight, marker, marker_len + 1);
                }
            }
            pagerRenderPage(buffer, top, page_rows, highlight);
            free(highlight);
            redraw = false;
        }
        int key = pagerPromptAndRead(cmd_name);
        switch (key) {
            case PAGER_KEY_RESIZE:
                g_pager_sigwinch_received = 0;
                {
                    int new_rows = pager_terminal_rows();
                    page_rows = (new_rows > 1) ? new_rows - 1 : new_rows;
                    if (page_rows < 1) page_rows = 1;
                }
                redraw = true;
                break;
            case 'q':
            case 'Q':
            case 3:
            case 4:
                pager_last_exit_key = key;
                pager_last_md_link_index = -1;
                goto done;
            case 'o':
            case 'O':
                pager_last_exit_key = key;
                pager_last_md_link_index = -1;
                goto done;
            case ' ':
            case PAGER_KEY_PAGE_DOWN: {
                size_t max_top = pagerMaxTop(buffer, page_rows);
                if (top < max_top) {
                    size_t new_top = top + (size_t)page_rows;
                    if (new_top > max_top) {
                        new_top = max_top;
                    }
                    top = new_top;
                    redraw = true;
                } else {
                    pagerBell();
                }
                break;
            }
            case 'b':
            case 'B':
            case PAGER_KEY_PAGE_UP: {
                if (top > 0) {
                    size_t delta = (size_t)page_rows;
                    if (delta > top) {
                        top = 0;
                    } else {
                        top -= delta;
                    }
                    redraw = true;
                } else {
                    pagerBell();
                }
                break;
            }
            case '[':
            case ']': {
                if (!md_links || md_links->count == 0) {
                    pagerBell();
                    break;
                }
                size_t visible_count = 0;
                size_t *visible = pagerCollectVisibleMdLinkIndices(buffer, top, page_rows, md_links, &visible_count);
                if (!visible || visible_count == 0) {
                    free(visible);
                    pagerBell();
                    break;
                }
                bool reverse = (key == '[');
                size_t pos = pagerFindIndexPosition(visible, visible_count, selected_md_link_index);
                if (pos == SIZE_MAX) {
                    pos = reverse ? (visible_count - 1) : 0;
                } else if (reverse) {
                    pos = (pos == 0) ? (visible_count - 1) : (pos - 1);
                } else {
                    pos = (pos + 1) % visible_count;
                }
                selected_md_link_index = visible[pos];
                pager_last_md_link_index = (int)selected_md_link_index;
                free(visible);
                redraw = true;
                break;
            }
            case '\n':
            case '\r':
                if (md_links &&
                    selected_md_link_index != SIZE_MAX &&
                    selected_md_link_index < md_links->count) {
                    pager_last_md_link_index = (int)selected_md_link_index;
                    pager_last_exit_key = 'o';
                    goto done;
                }
                /* fall through */
            case PAGER_KEY_ARROW_DOWN: {
                size_t page = (size_t)page_rows;
                if (top + page < buffer->line_count) {
                    top++;
                    redraw = true;
                } else {
                    pagerBell();
                }
                break;
            }
            case PAGER_KEY_ARROW_UP: {
                if (top > 0) {
                    top--;
                    redraw = true;
                } else {
                    pagerBell();
                }
                break;
            }
            default:
                // Ignore other keys
                break;
        }
    }
    pager_last_exit_key = 'q';
    pager_last_md_link_index = -1;
done:
    sigaction(SIGWINCH, &old_sa, NULL);
    return ret;
}

static int print_file(const char *path, FILE *stream) {
    char buffer[4096];
    bool dbg = getenv("PSCALI_PIPE_DEBUG") != NULL;
    while (true) {
        int read_err = 0;
        ssize_t n = smallclueReadStream(stream, buffer, sizeof(buffer), &read_err);
        if (n < 0) {
            fprintf(stderr, "cat: %s: %s\n",
                    path ? path : "(stdin)",
                    strerror(read_err ? read_err : errno));
            return 1;
        }
        if (n == 0) {
            break;
        }
        if (fwrite(buffer, 1, (size_t)n, stdout) != (size_t)n) {
            perror("cat: write error");
            return 1;
        }
        if (dbg) {
            fprintf(stderr, "[cat] wrote chunk=%zu bytes\n", (size_t)n);
        }
        if (read_err) {
            fprintf(stderr, "cat: %s: %s\n",
                    path ? path : "(stdin)",
                    strerror(read_err));
            return 1;
        }
    }
    return 0;
}

static const char *pager_command_name(const char *name) {
    return (name && *name) ? name : "pager";
}

static bool pagerDebugEnabled(void) {
    static int enabled = -1;
    if (enabled < 0) {
        const char *env = getenv("PSCALI_PAGER_DEBUG");
        enabled = (env && *env && strcmp(env, "0") != 0) ? 1 : 0;
    }
    return enabled == 1;
}

static void pagerDebugLogf(const char *format, ...) {
    if (!pagerDebugEnabled() || !format) {
        return;
    }
    char buf[512];
    va_list args;
    va_start(args, format);
    vsnprintf(buf, sizeof(buf), format, args);
    va_end(args);
#if defined(PSCAL_TARGET_IOS)
    if (pscalRuntimeDebugLog) {
        pscalRuntimeDebugLog(buf);
        return;
    }
#endif
    fprintf(stderr, "%s\n", buf);
}

static bool pager_test_input_initialized = false;
static const char *pager_test_input_cursor = NULL;
static size_t pager_test_input_remaining = 0;

static void pagerInitTestInput(void) {
    if (pager_test_input_initialized) {
        return;
    }
    pager_test_input_initialized = true;
    const char *env = getenv("PSCALI_PAGER_TEST_INPUT");
    if (env && *env) {
        pager_test_input_cursor = env;
        pager_test_input_remaining = strlen(env);
    }
}

static bool pagerTestInputHasData(void) {
    pagerInitTestInput();
    return pager_test_input_cursor && pager_test_input_remaining > 0;
}

static int pagerTestInputNext(void) {
    if (!pagerTestInputHasData()) {
        return EOF;
    }
    int ch = (unsigned char)*pager_test_input_cursor;
    pager_test_input_cursor++;
    pager_test_input_remaining--;
    return ch;
}

static _Thread_local int pager_control_fd_value = -2;
#if defined(PSCAL_TARGET_IOS)
static _Thread_local bool pager_session_queue_enabled = false;
#endif

// Duplicate an FD for pager control input only if it can be read from.
static int pagerDupForRead(int fd) {
    int dup_fd = dup(fd);
    if (dup_fd < 0) {
        return -1;
    }
    int flags = fcntl(dup_fd, F_GETFL, 0);
    if (flags >= 0 && (flags & O_ACCMODE) != O_WRONLY) {
        return dup_fd;
    }
    close(dup_fd);
    return -1;
}

static int pager_control_fd(void) {
    if (pager_control_fd_value != -2) {
        return pager_control_fd_value;
    }
#ifdef _WIN32
    pager_control_fd_value = -1;
#else
    if (pagerDebugEnabled()) {
        pagerDebugLogf("[pager] control fd init stdin_tty=%d stdout_tty=%d",
                       pscalRuntimeStdinIsInteractive() ? 1 : 0,
                       pscalRuntimeStdoutIsInteractive() ? 1 : 0);
    }
    int fd = open("/dev/tty", O_RDONLY | O_CLOEXEC);
    if (pagerDebugEnabled()) {
        int err = (fd < 0) ? errno : 0;
        pagerDebugLogf("[pager] open /dev/tty fd=%d err=%d (%s)",
                       fd, err, (fd < 0) ? strerror(err) : "ok");
    }
#if defined(PSCAL_TARGET_IOS)
    if (fd >= 0 && !pscalRuntimeFdIsInteractive(fd)) {
        if (pagerDebugEnabled()) {
            pagerDebugLogf("[pager] /dev/tty not interactive, closing fd=%d", fd);
        }
        close(fd);
        fd = -1;
    }
    if (fd < 0) {
        char session_tty[64];
        if (smallclueSessionPtyName(session_tty, sizeof(session_tty))) {
            fd = open(session_tty, O_RDONLY | O_CLOEXEC);
            if (pagerDebugEnabled()) {
                int err = (fd < 0) ? errno : 0;
                pagerDebugLogf("[pager] open session tty %s fd=%d err=%d (%s)",
                               session_tty,
                               fd,
                               err,
                               (fd < 0) ? strerror(err) : "ok");
            }
            if (fd >= 0 && !pscalRuntimeFdIsInteractive(fd)) {
                if (pagerDebugEnabled()) {
                    pagerDebugLogf("[pager] session tty not interactive, closing fd=%d", fd);
                }
                close(fd);
                fd = -1;
            }
        }
    }
    bool try_stdout = true;
#else
    bool try_stdout = pscalRuntimeStdoutIsInteractive();
#endif
    if (fd < 0 && try_stdout) {
        const char *tty = ttyname(STDOUT_FILENO);
        if (pagerDebugEnabled()) {
            pagerDebugLogf("[pager] ttyname(stdout)=%s", tty ? tty : "(null)");
        }
        if (tty && *tty) {
            fd = open(tty, O_RDONLY | O_CLOEXEC);
            if (pagerDebugEnabled()) {
                int err = (fd < 0) ? errno : 0;
                pagerDebugLogf("[pager] open stdout tty fd=%d err=%d (%s)",
                               fd, err, (fd < 0) ? strerror(err) : "ok");
            }
        }
        if (fd < 0) {
            fd = pagerDupForRead(STDOUT_FILENO);
            if (pagerDebugEnabled()) {
                int err = (fd < 0) ? errno : 0;
                pagerDebugLogf("[pager] dup stdout fd=%d err=%d (%s)",
                               fd, err, (fd < 0) ? strerror(err) : "ok");
            }
        }
    }
#if defined(PSCAL_TARGET_IOS)
    if (fd >= 0 && !pscalRuntimeFdIsInteractive(fd)) {
        if (pagerDebugEnabled()) {
            pagerDebugLogf("[pager] stdout fallback not interactive, closing fd=%d", fd);
        }
        close(fd);
        fd = -1;
    }
    bool try_stdin = true;
#else
    bool try_stdin = pscalRuntimeStdinIsInteractive();
#endif
    if (fd < 0 && try_stdin) {
        const char *tty = ttyname(STDIN_FILENO);
        if (pagerDebugEnabled()) {
            pagerDebugLogf("[pager] ttyname(stdin)=%s", tty ? tty : "(null)");
        }
        if (tty && *tty) {
            fd = open(tty, O_RDONLY | O_CLOEXEC);
            if (pagerDebugEnabled()) {
                int err = (fd < 0) ? errno : 0;
                pagerDebugLogf("[pager] open stdin tty fd=%d err=%d (%s)",
                               fd, err, (fd < 0) ? strerror(err) : "ok");
            }
        }
        if (fd < 0) {
            fd = pagerDupForRead(STDIN_FILENO);
            if (pagerDebugEnabled()) {
                int err = (fd < 0) ? errno : 0;
                pagerDebugLogf("[pager] dup stdin fd=%d err=%d (%s)",
                               fd, err, (fd < 0) ? strerror(err) : "ok");
            }
        }
    }
#if defined(PSCAL_TARGET_IOS)
    if (fd >= 0 && !pscalRuntimeFdIsInteractive(fd)) {
        if (pagerDebugEnabled()) {
            pagerDebugLogf("[pager] stdin fallback not interactive, closing fd=%d", fd);
        }
        close(fd);
        fd = -1;
    }
#endif
    pager_control_fd_value = fd;
    if (pagerDebugEnabled()) {
        pagerDebugLogf("[pager] control fd resolved=%d", pager_control_fd_value);
    }
#endif
    return pager_control_fd_value;
}

static void pager_control_fd_reset(void) {
    if (pager_control_fd_value >= 0) {
        if (pager_control_fd_value > STDERR_FILENO) {
            close(pager_control_fd_value);
        }
        pager_control_fd_value = -2;
    }
}

#if defined(PSCAL_TARGET_IOS)
static bool pagerUseSessionInputQueue(void) {
    VProcSessionStdio *session = vprocSessionStdioCurrent();
    if (!session) {
        return false;
    }
    bool has_pscal_stdin = session->stdin_pscal_fd &&
                           session->stdin_pscal_fd->ops &&
                           session->stdin_pscal_fd->ops->read;
    bool has_session_stdin = (session->stdin_host_fd >= 0) ||
                             has_pscal_stdin ||
                             (session->input != NULL);
    if (!has_session_stdin) {
        return false;
    }
    return pscalRuntimeStdinIsInteractive() ||
           pscalRuntimeStdoutIsInteractive() ||
           pscalRuntimeStderrIsInteractive() ||
           has_pscal_stdin;
}

static ssize_t pagerReadSessionByte(unsigned char *out, bool nonblocking) {
    if (!out) {
        errno = EINVAL;
        return -1;
    }
    return vprocSessionReadInputShimMode(out, 1, nonblocking);
}
#endif

static ssize_t pagerReadByteWithTimeout(int fd,
                                        bool use_session_queue,
                                        unsigned char *out,
                                        bool required,
                                        int timeout_ms) {
    if (!out) {
        errno = EINVAL;
        return -1;
    }
#if defined(PSCAL_TARGET_IOS)
    if (use_session_queue) {
        if (required) {
            for (;;) {
                if (g_pager_sigwinch_received) {
                    return -2;
                }
                ssize_t n = pagerReadSessionByte(out, false);
                if (n < 0 && errno == EINTR) {
                    if (g_pager_sigwinch_received) {
                        return -2;
                    }
                    continue;
                }
                return n;
            }
        }
        int waited_ms = 0;
        while (true) {
            if (g_pager_sigwinch_received) {
                return -2;
            }
            ssize_t n = pagerReadSessionByte(out, true);
            if (n == 1) {
                return 1;
            }
            if (n < 0 && errno == EINTR) {
                if (g_pager_sigwinch_received) {
                    return -2;
                }
                continue;
            }
            if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                return n;
            }
            if (timeout_ms <= 0 || waited_ms >= timeout_ms) {
                return 0;
            }
            struct timespec nap = {0};
            nap.tv_nsec = 1000000L; /* 1ms */
            (void)nanosleep(&nap, NULL);
            waited_ms++;
        }
    }
#else
    (void)use_session_queue;
#endif
    if (fd < 0) {
        errno = EBADF;
        return -1;
    }
    for (;;) {
        if (g_pager_sigwinch_received) {
            return -2;
        }
        struct pollfd pfd = { .fd = fd, .events = POLLIN };
        int wait_ms = required ? -1 : timeout_ms;
        int poll_rc = poll(&pfd, 1, wait_ms);
        if (poll_rc < 0) {
            if (errno == EINTR) {
                if (g_pager_sigwinch_received) {
                    return -2;
                }
                continue;
            }
            return -1;
        }
        if (poll_rc == 0) {
            return 0;
        }
        if ((pfd.revents & (POLLIN | POLLHUP)) == 0) {
            return 0;
        }
        ssize_t n = read(fd, out, 1);
        if (n < 0 && errno == EINTR) {
            if (g_pager_sigwinch_received) {
                return -2;
            }
            continue;
        }
        return n;
    }
}

static int pagerDecodeCsiSequence(const char *seq) {
    if (!seq || !*seq) {
        return '\x1b';
    }
    size_t len = strlen(seq);
    char final = seq[len - 1];
    if (final == 'A' || final == 'B' || final == 'a' || final == 'b') {
        bool is_up = (final == 'A' || final == 'a');
        return is_up ? PAGER_KEY_ARROW_UP : PAGER_KEY_ARROW_DOWN;
    }
    if (final == '~') {
        int code = atoi(seq);
        if (code == 5) {
            return PAGER_KEY_PAGE_UP;
        }
        if (code == 6) {
            return PAGER_KEY_PAGE_DOWN;
        }
    }
    return '\x1b';
}

static int pager_read_key(void) {
    pagerInitTestInput();
    int scripted = pagerTestInputNext();
    if (scripted != EOF) {
        return scripted;
    }
    if (pager_test_input_cursor) {
        return 'q';
    }
    int fd = pager_control_fd();
#if defined(PSCAL_TARGET_IOS)
    bool use_session_queue = pager_session_queue_enabled && pagerUseSessionInputQueue();
#else
    bool use_session_queue = false;
#endif
    if (fd < 0) {
        if (!use_session_queue) {
            return 'q';
        }
    }
    int fd_is_tty = (fd >= 0 && pscalRuntimeFdIsInteractive(fd)) ? 1 : 0;
    if (pagerDebugEnabled()) {
        pagerDebugLogf("[pager] read key fd=%d isatty=%d use_session=%d",
                       fd, fd_is_tty, use_session_queue ? 1 : 0);
    }
    if (!fd_is_tty && !use_session_queue) {
        return 'q';
    }
    struct termios orig;
    int tcget_rc = (fd >= 0) ? smallclueTcgetattr(fd, &orig) : -1;
    bool have_termios = (tcget_rc == 0);
    if (pagerDebugEnabled()) {
        int err = (tcget_rc != 0) ? errno : 0;
        pagerDebugLogf("[pager] tcgetattr rc=%d err=%d (%s)",
                       tcget_rc, err, (tcget_rc != 0) ? strerror(err) : "ok");
        if (have_termios) {
            pagerDebugLogf("[pager] termios orig iflag=0x%lx oflag=0x%lx lflag=0x%lx",
                           (unsigned long)orig.c_iflag,
                           (unsigned long)orig.c_oflag,
                           (unsigned long)orig.c_lflag);
        }
    }
    struct termios raw;
    if (have_termios) {
        raw = orig;
        raw.c_lflag &= ~(ICANON | ECHO);
        raw.c_iflag &= ~(IXON | ICRNL);
        raw.c_cc[VMIN] = 1;
        raw.c_cc[VTIME] = 0;
        int tcset_rc = smallclueTcsetattr(fd, TCSAFLUSH, &raw);
        if (pagerDebugEnabled()) {
            int err = (tcset_rc != 0) ? errno : 0;
            pagerDebugLogf("[pager] tcsetattr raw rc=%d err=%d (%s)",
                           tcset_rc, err, (tcset_rc != 0) ? strerror(err) : "ok");
        }
    }
    int result = 'q';
    const int seq_timeout_ms = 120;
    for (;;) {
        unsigned char ch = 0;
        ssize_t n = pagerReadByteWithTimeout(fd, use_session_queue, &ch, true, seq_timeout_ms);
        if (n == -2) {
            result = PAGER_KEY_RESIZE;
            break;
        }
        if (pagerDebugEnabled()) {
            if (n <= 0) {
                int err = errno;
                pagerDebugLogf("[pager] read rc=%zd err=%d (%s)",
                               n, err, strerror(err));
            } else {
                pagerDebugLogf("[pager] read ch=0x%02x", (unsigned int)ch);
            }
        }
        if (n <= 0) {
            break;
        }
        if (ch == '\x1b') {
            unsigned char leader = 0;
            ssize_t leader_n = pagerReadByteWithTimeout(fd, use_session_queue, &leader, false, seq_timeout_ms);
            if (leader_n != 1) {
                result = '\x1b';
            } else if (leader == '[') {
                char seq[32];
                size_t seq_len = 0;
                while (seq_len + 1 < sizeof(seq)) {
                    unsigned char next = 0;
                    ssize_t next_n = pagerReadByteWithTimeout(fd, use_session_queue, &next, false, seq_timeout_ms);
                    if (next_n != 1) {
                        break;
                    }
                    seq[seq_len++] = (char)next;
                    if (next >= 0x40 && next <= 0x7e) {
                        break;
                    }
                }
                seq[seq_len] = '\0';
                result = pagerDecodeCsiSequence(seq);
            } else if (leader == 'O') {
                unsigned char final = 0;
                ssize_t final_n = pagerReadByteWithTimeout(fd, use_session_queue, &final, false, seq_timeout_ms);
                if (final_n == 1 && final == 'A') {
                    result = PAGER_KEY_ARROW_UP;
                } else if (final_n == 1 && final == 'B') {
                    result = PAGER_KEY_ARROW_DOWN;
                } else {
                    result = '\x1b';
                }
            } else {
                result = '\x1b';
            }
        } else {
            result = ch;
        }
        break;
    }
    if (have_termios) {
        int tcset_rc = smallclueTcsetattr(fd, TCSAFLUSH, &orig);
        if (pagerDebugEnabled()) {
            int err = (tcset_rc != 0) ? errno : 0;
            pagerDebugLogf("[pager] tcsetattr restore rc=%d err=%d (%s)",
                           tcset_rc, err, (tcset_rc != 0) ? strerror(err) : "ok");
        }
    }
    return result;
}

static int pager_terminal_rows(void) {
    int parsed = 0;
    const char *lines = getenv("LINES");
    if (lines && *lines) {
        parsed = atoi(lines);
#if defined(PSCAL_TARGET_IOS)
        if (parsed > 0) {
            return parsed;
        }
#endif
    }
    struct winsize ws;
    if (isatty(STDOUT_FILENO) && ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0) {
        if (ws.ws_row > 0) {
            return ws.ws_row;
        }
    }
    int ctrl_fd = pager_control_fd();
    if (ctrl_fd >= 0 && ioctl(ctrl_fd, TIOCGWINSZ, &ws) == 0) {
        if (ws.ws_row > 0) {
            return ws.ws_row;
        }
    }
    if (parsed > 0) {
        return parsed;
    }
    int fallback = 24;
    char buf[16];
    snprintf(buf, sizeof(buf), "%d", parsed > 0 ? parsed : fallback);
    setenv("LINES", buf, 1);
    return (parsed > 0) ? parsed : fallback;
}

static int pager_terminal_cols(void) {
    int parsed = 0;
    const char *cols = getenv("COLUMNS");
    if (cols && *cols) {
        parsed = atoi(cols);
#if defined(PSCAL_TARGET_IOS)
        if (parsed > 0) {
            return parsed;
        }
#endif
    }
    struct winsize ws;
    if (isatty(STDOUT_FILENO) && ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0) {
        if (ws.ws_col > 0) {
            return ws.ws_col;
        }
    }
    int ctrl_fd = pager_control_fd();
    if (ctrl_fd >= 0 && ioctl(ctrl_fd, TIOCGWINSZ, &ws) == 0) {
        if (ws.ws_col > 0) {
            return ws.ws_col;
        }
    }
    if (parsed > 0) {
        return parsed;
    }
    int fallback = 80;
    char buf[16];
    snprintf(buf, sizeof(buf), "%d", parsed > 0 ? parsed : fallback);
    setenv("COLUMNS", buf, 1);
    return (parsed > 0) ? parsed : fallback;
}

static int pagerParseEnvBool(const char *value) {
    if (!value) {
        return -1;
    }
    while (*value && isspace((unsigned char)*value)) {
        value++;
    }
    if (*value == '\0') {
        return -1;
    }
    if (strcasecmp(value, "1") == 0 || strcasecmp(value, "true") == 0 ||
        strcasecmp(value, "yes") == 0 || strcasecmp(value, "on") == 0) {
        return 1;
    }
    if (strcasecmp(value, "0") == 0 || strcasecmp(value, "false") == 0 ||
        strcasecmp(value, "no") == 0 || strcasecmp(value, "off") == 0) {
        return 0;
    }
    return -1;
}

static int pagerPassthroughStream(FILE *stream) {
    if (!stream) {
        return 1;
    }
    char chunk[8192];
    while (true) {
        int read_err = 0;
        ssize_t n = smallclueReadStream(stream, chunk, sizeof(chunk), &read_err);
        if (n < 0) {
            if (read_err) {
                errno = read_err;
            }
            return 1;
        }
        if (n == 0) {
            break;
        }
        if (fwrite(chunk, 1, (size_t)n, stdout) != (size_t)n) {
            perror("pager: write error");
            return 1;
        }
    }
    return 0;
}

static bool pagerStreamIsInteractive(FILE *stream) {
    if (!stream) {
        return false;
    }
    int fd = fileno(stream);
    if (fd < 0) {
        return false;
    }
    return isatty(fd) != 0;
}

static int pager_file(const char *cmd_name, const char *path, FILE *stream) {
    pager_control_fd_reset();
    pager_last_exit_key = 'q';
    pager_last_md_link_index = -1;
    int force_env = pagerParseEnvBool(getenv("PSCALI_PAGER_FORCE"));
#if defined(PSCAL_TARGET_IOS)
    /* iOS safety: when pager input is a pipe and no control TTY is available,
     * fall back to passthrough to avoid wedging. If a control TTY is available,
     * keep normal interactive paging behavior. Set PSCALI_PAGER_FORCE=0 to
     * force passthrough, or PSCALI_PAGER_FORCE=1 to force interactive. */
    bool piped_stdin = (stream == stdin) && !pagerStreamIsInteractive(stream);
    int pre_ctrl_fd = pager_control_fd();
    bool pre_have_ctrl = (pre_ctrl_fd >= 0) && pscalRuntimeFdIsInteractive(pre_ctrl_fd);
    if (pagerDebugEnabled()) {
        pagerDebugLogf("[pager] iOS mode piped_stdin=%d force_env=%d pre_ctrl_fd=%d pre_have_ctrl=%d test_input=%d",
                       piped_stdin ? 1 : 0,
                       force_env,
                       pre_ctrl_fd,
                       pre_have_ctrl ? 1 : 0,
                       pagerTestInputHasData() ? 1 : 0);
    }
    if (piped_stdin && force_env == 0) {
        int status = pagerPassthroughStream(stream);
        pager_control_fd_reset();
        return status;
    }
    if (piped_stdin && force_env < 0 && !pre_have_ctrl && !pagerTestInputHasData()) {
        int status = pagerPassthroughStream(stream);
        pager_control_fd_reset();
        return status;
    }
#endif
    PagerBuffer buffer = {0};
    if (pagerCollectLines(cmd_name, path, stream, &buffer) != 0) {
        return 1;
    }

    int ctrl_fd = pager_control_fd();
    bool have_ctrl = (ctrl_fd >= 0) && pscalRuntimeFdIsInteractive(ctrl_fd);
    bool force_interactive = false;
    bool disable_interactive = false;
    if (force_env > 0) {
        force_interactive = true;
    } else if (force_env == 0) {
        disable_interactive = true;
    }
    if (pagerTestInputHasData()) {
        force_interactive = true;
    }
    if (disable_interactive) {
        force_interactive = false;
    }

    bool interactive = (have_ctrl || force_interactive) && !disable_interactive;
    /* If we have no viable control fd and no interactive stdio, force a
     * non-interactive dump so pipelines still produce output when no TTY. */
    if (!force_interactive) {
        if (!have_ctrl &&
            !pscalRuntimeStdinIsInteractive() &&
            !pscalRuntimeStdoutIsInteractive() &&
            !pscalRuntimeStderrIsInteractive()) {
            interactive = false;
        }
    }
    if (!interactive) {
        /* No interactive input available; dump what we collected. */
        if (buffer.file) {
            if (fseeko(buffer.file, 0, SEEK_SET) == 0) {
                char chunk[8192];
                while (true) {
                    size_t n = fread(chunk, 1, sizeof(chunk), buffer.file);
                    if (n == 0) {
                        break;
                    }
                    if (fwrite(chunk, 1, n, stdout) != n) {
                        perror("pager: write error");
                        pagerBufferFree(&buffer);
                        return 1;
                    }
                    if (n < sizeof(chunk)) {
                        break;
                    }
                }
            }
        }
        pagerBufferFree(&buffer);
        pager_control_fd_reset();
        return 0;
    }

    int rows = pager_terminal_rows();
    int page_rows = rows > 1 ? rows - 1 : rows;
    if (page_rows < 1) {
        page_rows = 1;
    }

    int status = 0;
#if defined(PSCAL_TARGET_IOS)
    bool prev_session_queue = pager_session_queue_enabled;
    pager_session_queue_enabled = true;
    status = pagerInteractiveSession(cmd_name, &buffer, page_rows);
    pager_session_queue_enabled = prev_session_queue;
#else
    status = pagerInteractiveSession(cmd_name, &buffer, page_rows);
#endif
    pagerBufferFree(&buffer);
    pager_control_fd_reset();
    return status;
}

#define MARKDOWN_WRAP_WIDTH 78
#define MARKDOWN_MAX_TABLE_ROWS 500
#define MARKDOWN_MAX_TABLE_COLS 50
#define MARKDOWN_MIN_COL_WIDTH 10

typedef enum {
    MARKDOWN_INPUT_MODE_MARKDOWN = 0,
    MARKDOWN_INPUT_MODE_HTML,
    MARKDOWN_INPUT_MODE_AUTO
} MarkdownInputMode;

typedef struct {
    char *cells[MARKDOWN_MAX_TABLE_COLS];
    int col_count;
} MarkdownTableRow;

typedef struct {
    char *name;
    char *title;
    char *path;
} MarkdownDocEntry;

static _Thread_local MarkdownLinkList *gMarkdownActiveLinks = NULL;

static char *markdownExtractTitle(const char *path);

static void markdownDocEntryFree(MarkdownDocEntry *entry) {
    if (!entry) return;
    free(entry->name);
    free(entry->title);
    free(entry->path);
    entry->name = NULL;
    entry->title = NULL;
    entry->path = NULL;
}

static void markdownLinkListFree(MarkdownLinkList *links) {
    if (!links) {
        return;
    }
    for (size_t i = 0; i < links->count; ++i) {
        free(links->items[i].text);
        free(links->items[i].target);
        links->items[i].text = NULL;
        links->items[i].target = NULL;
    }
    free(links->items);
    links->items = NULL;
    links->count = 0;
    links->capacity = 0;
}

static char *markdownDupTrimmed(const char *text) {
    if (!text) {
        return strdup("");
    }
    const char *start = text;
    while (*start && isspace((unsigned char)*start)) {
        start++;
    }
    const char *end = start + strlen(start);
    while (end > start && isspace((unsigned char)end[-1])) {
        end--;
    }
    size_t len = (size_t)(end - start);
    char *dup = (char *)malloc(len + 1);
    if (!dup) {
        return NULL;
    }
    if (len > 0) {
        memcpy(dup, start, len);
    }
    dup[len] = '\0';
    return dup;
}

static bool markdownLinkListContainsTarget(const MarkdownLinkList *links, const char *target) {
    if (!links || !target || !*target) {
        return false;
    }
    for (size_t i = 0; i < links->count; ++i) {
        if (links->items[i].target && strcmp(links->items[i].target, target) == 0) {
            return true;
        }
    }
    return false;
}

static bool markdownLinkListAppend(MarkdownLinkList *links, const char *text, const char *target) {
    if (!links || !target || !*target) {
        return false;
    }
    if (markdownLinkListContainsTarget(links, target)) {
        return true;
    }
    if (links->count == links->capacity) {
        size_t new_capacity = (links->capacity == 0) ? 8 : links->capacity * 2;
        MarkdownLinkEntry *resized = (MarkdownLinkEntry *)realloc(links->items, new_capacity * sizeof(MarkdownLinkEntry));
        if (!resized) {
            return false;
        }
        links->items = resized;
        links->capacity = new_capacity;
    }
    char *text_dup = markdownDupTrimmed(text ? text : "");
    char *target_dup = markdownDupTrimmed(target);
    if (!text_dup || !target_dup) {
        free(text_dup);
        free(target_dup);
        return false;
    }
    if (text_dup[0] == '\0') {
        free(text_dup);
        text_dup = strdup(target_dup);
        if (!text_dup) {
            free(target_dup);
            return false;
        }
    }
    links->items[links->count].text = text_dup;
    links->items[links->count].target = target_dup;
    links->count++;
    return true;
}

static bool markdownInlineAppendSpan(char **buffer, size_t *length, size_t *capacity, const char *text, size_t text_len);

static int markdownRegisterLinkAndGetDisplayNumber(MarkdownLinkList *links, const char *text, const char *target) {
    if (!links || !target || !*target) {
        return -1;
    }
    int existing = markdownLinkListFindTargetIndex(links, target);
    if (existing >= 0) {
        return existing + 1;
    }
    size_t before = links->count;
    if (!markdownLinkListAppend(links, text, target)) {
        return -1;
    }
    if (links->count > before) {
        return (int)links->count;
    }
    existing = markdownLinkListFindTargetIndex(links, target);
    return (existing >= 0) ? (existing + 1) : -1;
}

static bool markdownInlineAppendLinkMarker(char **buffer,
                                           size_t *length,
                                           size_t *capacity,
                                           int link_display_number) {
    if (!buffer || !length || !capacity) {
        return false;
    }
    if (link_display_number > 0) {
        char marker[32];
        snprintf(marker, sizeof(marker), " [%d]", link_display_number);
        return markdownInlineAppendSpan(buffer, length, capacity, marker, strlen(marker));
    }
    return markdownInlineAppendSpan(buffer, length, capacity, " [link]", 7);
}

static int markdownEnumerateDocuments(MarkdownDocEntry **entries_out,
                                      size_t *count_out,
                                      char *docs_dir_out,
                                      size_t docs_dir_len) {
    if (entries_out) *entries_out = NULL;
    if (count_out) *count_out = 0;
    const char *home = getenv("HOME");
    if (!home || !*home) {
        fprintf(stderr, "md: HOME is not set\n");
        return 1;
    }
    char docs_dir[PATH_MAX];
    if (smallclueBuildPath(docs_dir, sizeof(docs_dir), home, "Docs") != 0) {
        fprintf(stderr, "md: unable to resolve Docs directory\n");
        return 1;
    }
    if (docs_dir_out && docs_dir_len > 0) {
        strncpy(docs_dir_out, docs_dir, docs_dir_len - 1);
        docs_dir_out[docs_dir_len - 1] = '\0';
    }
    DIR *dir = opendir(docs_dir);
    if (!dir) {
        fprintf(stderr, "md: %s: %s\n", docs_dir, strerror(errno));
        return 1;
    }
    MarkdownDocEntry *entries = NULL;
    size_t count = 0;
    size_t capacity = 0;
    struct dirent *dent;
    while ((dent = readdir(dir)) != NULL) {
        if (dent->d_name[0] == '.') {
            continue;
        }
        const char *dot = strrchr(dent->d_name, '.');
        if (!dot || strcasecmp(dot, ".md") != 0) {
            continue;
        }
        char path[PATH_MAX];
        if (smallclueBuildPath(path, sizeof(path), docs_dir, dent->d_name) != 0) {
            continue;
        }
        struct stat st;
        if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
            continue;
        }
        if (count == capacity) {
            size_t new_cap = capacity == 0 ? 8 : capacity * 2;
            MarkdownDocEntry *resized = (MarkdownDocEntry *)realloc(entries, new_cap * sizeof(MarkdownDocEntry));
            if (!resized) {
                continue;
            }
            entries = resized;
            capacity = new_cap;
        }
        entries[count].name = strdup(dent->d_name);
        if (entries[count].name) {
            char *ext = strrchr(entries[count].name, '.');
            if (ext) *ext = '\0';
        }
        entries[count].title = markdownExtractTitle(path);
        entries[count].path = strdup(path);
        count++;
    }
    closedir(dir);
    if (entries_out) {
        *entries_out = entries;
    } else {
        for (size_t i = 0; i < count; ++i) {
            markdownDocEntryFree(&entries[i]);
        }
        free(entries);
    }
    if (count_out) {
        *count_out = count;
    }
    return 0;
}

static void markdownParagraphAppendWithSeparator(char **buffer,
                                                 size_t *length,
                                                 size_t *capacity,
                                                 const char *text,
                                                 const char *separator) {
    if (!text || !*text) {
        return;
    }
    if (!separator) {
        separator = " ";
    }
    size_t text_len = strlen(text);
    size_t sep_len = (*length > 0) ? strlen(separator) : 0;
    size_t needed = *length + sep_len + text_len + 1;
    if (needed > *capacity) {
        size_t new_capacity = (*capacity == 0) ? 128 : *capacity * 2;
        while (new_capacity < needed) {
            new_capacity *= 2;
        }
        char *resized = (char *)realloc(*buffer, new_capacity);
        if (!resized) {
            return;
        }
        *buffer = resized;
        *capacity = new_capacity;
    }
    if (*length > 0 && sep_len > 0) {
        memcpy(*buffer + *length, separator, sep_len);
        *length += sep_len;
    }
    memcpy(*buffer + *length, text, text_len);
    *length += text_len;
    (*buffer)[*length] = '\0';
}

static const char *markdownSkipSoftWhitespace(const char *text);
static bool markdownLooksLikeNewsMetaLine(const char *line);

static bool markdownLineLooksLikeLinkOnly(const char *line) {
    if (!line || !*line) {
        return false;
    }
    const char *probe = markdownSkipSoftWhitespace(line);
    if (!*probe) {
        return false;
    }
    if (!(probe[0] == '[' ||
          (probe[0] == '-' && probe[1] == ' ' && probe[2] == '[') ||
          (probe[0] == '*' && probe[1] == ' ' && probe[2] == '[') ||
          (probe[0] == '+' && probe[1] == ' ' && probe[2] == '[') ||
          ((unsigned char)probe[0] == 0xE2 && (unsigned char)probe[1] == 0x80 &&
           (unsigned char)probe[2] == 0xA2 && probe[3] == ' ' && probe[4] == '['))) {
        return false;
    }
    return strstr(probe, "](") != NULL;
}

static void markdownAppendTokenFixed(char *buffer, size_t *length, size_t capacity, const char *text) {
    if (!buffer || !length || capacity == 0 || !text || !*text) {
        return;
    }
    size_t text_len = strlen(text);
    size_t room = (capacity > *length) ? (capacity - *length - 1) : 0;
    if (room == 0) {
        return;
    }
    if (*length > 0) {
        if (room <= 1) {
            return;
        }
        buffer[(*length)++] = ' ';
        room--;
    }
    if (text_len > room) {
        text_len = room;
    }
    if (text_len > 0) {
        memcpy(buffer + *length, text, text_len);
        *length += text_len;
        buffer[*length] = '\0';
    }
}

static bool markdownIsEmailTokenChar(char ch) {
    unsigned char u = (unsigned char)ch;
    return isalnum(u) || ch == '.' || ch == '_' || ch == '%' || ch == '+' || ch == '-';
}

static bool markdownCanInsertSpace(char *buffer, size_t *length, size_t capacity, size_t at) {
    if (!buffer || !length || *length + 1 >= capacity || at > *length) {
        return false;
    }
    memmove(buffer + at + 1, buffer + at, *length - at + 1);
    buffer[at] = ' ';
    (*length)++;
    return true;
}

static void markdownReplaceAllInPlace(char *buffer,
                                      size_t *length,
                                      size_t capacity,
                                      const char *from,
                                      const char *to) {
    if (!buffer || !length || !from || !to) {
        return;
    }
    size_t from_len = strlen(from);
    size_t to_len = strlen(to);
    if (from_len == 0 || from_len >= capacity) {
        return;
    }
    char *pos = strstr(buffer, from);
    while (pos) {
        size_t at = (size_t)(pos - buffer);
        if (to_len > from_len) {
            size_t grow = to_len - from_len;
            if (*length + grow + 1 > capacity) {
                break;
            }
            memmove(buffer + at + to_len, buffer + at + from_len, *length - at - from_len + 1);
            *length += grow;
        } else if (to_len < from_len) {
            size_t shrink = from_len - to_len;
            memmove(buffer + at + to_len, buffer + at + from_len, *length - at - from_len + 1);
            *length -= shrink;
        }
        if (to_len > 0) {
            memcpy(buffer + at, to, to_len);
        }
        pos = strstr(buffer + at + to_len, from);
    }
}

static void markdownNormalizeDisplaySpacing(const char *input, char *output, size_t output_size) {
    if (!output || output_size == 0) {
        return;
    }
    output[0] = '\0';
    if (!input || !*input) {
        return;
    }
    if (strstr(input, "://")) {
        snprintf(output, output_size, "%s", input);
        return;
    }
    size_t out_len = 0;
    for (size_t i = 0; input[i]; ++i) {
        char ch = input[i];
        if (out_len > 0) {
            char prev = output[out_len - 1];
            char next = input[i + 1];
            bool insert_space = false;
            if (islower((unsigned char)prev) && isupper((unsigned char)ch)) {
                insert_space = true;
            } else if (isdigit((unsigned char)prev) && isalpha((unsigned char)ch)) {
                insert_space = true;
            } else if (isalnum((unsigned char)prev) && ch == '[') {
                insert_space = true;
            } else if (isalnum((unsigned char)prev) && ch == '#') {
                insert_space = true;
            } else if (isupper((unsigned char)prev) && isupper((unsigned char)ch) &&
                       islower((unsigned char)next)) {
                insert_space = true;
            }
            if (insert_space && !isspace((unsigned char)prev)) {
                if (!markdownCanInsertSpace(output, &out_len, output_size, out_len)) {
                    break;
                }
            }
        }
        if (out_len + 1 >= output_size) {
            break;
        }
        output[out_len++] = ch;
        output[out_len] = '\0';
        if (ch == '@' && out_len >= 2) {
            size_t local_start = out_len - 1;
            while (local_start > 0 && markdownIsEmailTokenChar(output[local_start - 1])) {
                local_start--;
            }
            if (local_start > 0 &&
                isalnum((unsigned char)output[local_start - 1]) &&
                !isspace((unsigned char)output[local_start - 1])) {
                if (!markdownCanInsertSpace(output, &out_len, output_size, local_start)) {
                    break;
                }
            }
        }
    }
    markdownReplaceAllInPlace(output, &out_len, output_size, "inquirespress@", "inquires press@");
    markdownReplaceAllInPlace(output, &out_len, output_size, "inquiriessupport@", "inquiries support@");
    markdownReplaceAllInPlace(output, &out_len, output_size, "inquiressupport@", "inquires support@");
    markdownReplaceAllInPlace(output, &out_len, output_size, "assetsDownload", "assets Download");
    output[out_len] = '\0';
}

static char *markdownTrimAsciiInPlace(char *text) {
    if (!text) {
        return text;
    }
    while (*text && isspace((unsigned char)*text)) {
        text++;
    }
    char *end = text + strlen(text);
    while (end > text && isspace((unsigned char)end[-1])) {
        *--end = '\0';
    }
    return text;
}

static bool markdownExtractFragmentLinkLabel(const char *line,
                                             char *label_out,
                                             size_t label_out_size,
                                             char *meta_out,
                                             size_t meta_out_size) {
    if (!line || !label_out || label_out_size == 0) {
        return false;
    }
    label_out[0] = '\0';
    if (meta_out && meta_out_size > 0) {
        meta_out[0] = '\0';
    }
    char normalized[4096];
    markdownNormalizeDisplaySpacing(line, normalized, sizeof(normalized));
    char *probe = markdownTrimAsciiInPlace(normalized);
    if (!*probe || strcmp(probe, "[") == 0 || strcmp(probe, "]") == 0) {
        return false;
    }

    char local_meta[512];
    local_meta[0] = '\0';
    const char *title = probe;
    char *heading = strstr(probe, "####");
    if (heading) {
        *heading = '\0';
        char *meta = markdownTrimAsciiInPlace(probe);
        title = markdownTrimAsciiInPlace(heading + 4);
        if (*meta && markdownLooksLikeNewsMetaLine(meta)) {
            snprintf(local_meta, sizeof(local_meta), "%s", meta);
        }
    } else {
        while (*title == '#') {
            title++;
        }
        while (*title && isspace((unsigned char)*title)) {
            title++;
        }
    }

    if (*title == '\0' && *probe) {
        title = probe;
    }
    if (markdownLooksLikeNewsMetaLine(title)) {
        if (meta_out && meta_out_size > 0) {
            snprintf(meta_out, meta_out_size, "%s", title);
        }
        return false;
    }

    if (meta_out && meta_out_size > 0 && local_meta[0]) {
        snprintf(meta_out, meta_out_size, "%s", local_meta);
    }
    snprintf(label_out, label_out_size, "%s", title);
    return label_out[0] != '\0';
}

static bool markdownIsFragmentedBulletLinkOpen(const char *line, const char **prefix_out) {
    if (prefix_out) {
        *prefix_out = NULL;
    }
    if (!line || !*line) {
        return false;
    }
    const char *probe = markdownSkipSoftWhitespace(line);
    if (strcmp(probe, "• [") == 0) {
        if (prefix_out) *prefix_out = "• ";
        return true;
    }
    if (strcmp(probe, "- [") == 0) {
        if (prefix_out) *prefix_out = "- ";
        return true;
    }
    if (strcmp(probe, "* [") == 0) {
        if (prefix_out) *prefix_out = "* ";
        return true;
    }
    if (strcmp(probe, "+ [") == 0) {
        if (prefix_out) *prefix_out = "+ ";
        return true;
    }
    return false;
}

static bool markdownIsFragmentedLinkOpen(const char *line, const char **prefix_out) {
    if (prefix_out) {
        *prefix_out = NULL;
    }
    if (!line || !*line) {
        return false;
    }
    const char *probe = markdownSkipSoftWhitespace(line);
    if (strcmp(probe, "[") == 0) {
        if (prefix_out) {
            *prefix_out = "";
        }
        return true;
    }
    return markdownIsFragmentedBulletLinkOpen(line, prefix_out);
}

static bool markdownParseFragmentedLinkClose(const char *line,
                                             char *target_out,
                                             size_t target_out_size,
                                             const char **suffix_out) {
    if (suffix_out) {
        *suffix_out = NULL;
    }
    if (!line || !target_out || target_out_size == 0) {
        return false;
    }
    target_out[0] = '\0';
    const char *probe = markdownSkipSoftWhitespace(line);
    if (strncmp(probe, "](", 2) != 0) {
        return false;
    }
    const char *target_start = probe + 2;
    const char *target_end = strchr(target_start, ')');
    if (!target_end || target_end == target_start) {
        return false;
    }
    size_t target_len = (size_t)(target_end - target_start);
    if (target_len >= target_out_size) {
        target_len = target_out_size - 1;
    }
    memcpy(target_out, target_start, target_len);
    target_out[target_len] = '\0';
    if (suffix_out) {
        const char *suffix = target_end + 1;
        while (*suffix && isspace((unsigned char)*suffix)) {
            suffix++;
        }
        *suffix_out = suffix;
    }
    return true;
}

static bool markdownInlineEnsureCapacity(char **buffer, size_t *capacity, size_t needed) {
    if (!buffer || !capacity) {
        return false;
    }
    if (needed <= *capacity) {
        return true;
    }
    size_t new_capacity = (*capacity == 0) ? 128 : *capacity;
    while (new_capacity < needed) {
        if (new_capacity > SIZE_MAX / 2) {
            return false;
        }
        new_capacity *= 2;
    }
    char *resized = (char *)realloc(*buffer, new_capacity);
    if (!resized) {
        return false;
    }
    *buffer = resized;
    *capacity = new_capacity;
    return true;
}

static bool markdownInlineAppendSpan(char **buffer, size_t *length, size_t *capacity, const char *text, size_t text_len) {
    if (!buffer || !length || !capacity || !text) {
        return false;
    }
    size_t needed = *length + text_len + 1;
    if (!markdownInlineEnsureCapacity(buffer, capacity, needed)) {
        return false;
    }
    if (text_len > 0) {
        memcpy(*buffer + *length, text, text_len);
        *length += text_len;
    }
    (*buffer)[*length] = '\0';
    return true;
}

static bool markdownInlineAppendChar(char **buffer, size_t *length, size_t *capacity, char ch) {
    return markdownInlineAppendSpan(buffer, length, capacity, &ch, 1);
}

static bool markdownHtmlExtractAttr(const char *attrs, const char *name, char *out, size_t out_size) {
    if (!attrs || !name || !out || out_size == 0) {
        return false;
    }
    out[0] = '\0';
    const size_t name_len = strlen(name);
    const char *p = attrs;

    while (*p) {
        while (*p && isspace((unsigned char)*p)) {
            p++;
        }
        if (*p == '\0' || *p == '/' || *p == '>') {
            break;
        }

        const char *key_start = p;
        while (*p && (isalnum((unsigned char)*p) || *p == '-' || *p == '_' || *p == ':')) {
            p++;
        }
        size_t key_len = (size_t)(p - key_start);
        if (key_len == 0) {
            p++;
            continue;
        }

        while (*p && isspace((unsigned char)*p)) {
            p++;
        }

        const char *value_start = "";
        size_t value_len = 0;
        if (*p == '=') {
            p++;
            while (*p && isspace((unsigned char)*p)) {
                p++;
            }
            if (*p == '"' || *p == '\'') {
                char quote = *p++;
                value_start = p;
                while (*p && *p != quote) {
                    p++;
                }
                value_len = (size_t)(p - value_start);
                if (*p == quote) {
                    p++;
                }
            } else {
                value_start = p;
                while (*p && !isspace((unsigned char)*p) && *p != '/' && *p != '>') {
                    p++;
                }
                value_len = (size_t)(p - value_start);
            }
        }

        if (key_len == name_len && strncasecmp(key_start, name, name_len) == 0) {
            if (value_len >= out_size) {
                value_len = out_size - 1;
            }
            memcpy(out, value_start, value_len);
            out[value_len] = '\0';
            return true;
        }
    }

    return false;
}

static bool markdownHtmlTagSupported(const char *name) {
    if (!name || !*name) {
        return false;
    }
    return strcmp(name, "a") == 0 ||
           strcmp(name, "img") == 0 ||
           strcmp(name, "p") == 0 ||
           strcmp(name, "div") == 0 ||
           strcmp(name, "span") == 0 ||
           strcmp(name, "strong") == 0 ||
           strcmp(name, "em") == 0 ||
           strcmp(name, "b") == 0 ||
           strcmp(name, "i") == 0 ||
           strcmp(name, "u") == 0 ||
           strcmp(name, "picture") == 0 ||
           strcmp(name, "source") == 0 ||
           strcmp(name, "br") == 0 ||
           strcmp(name, "hr") == 0 ||
           strcmp(name, "center") == 0 ||
           strcmp(name, "small") == 0 ||
           strcmp(name, "sub") == 0 ||
           strcmp(name, "sup") == 0 ||
           strcmp(name, "mark") == 0 ||
           strcmp(name, "code") == 0 ||
           strcmp(name, "kbd") == 0 ||
           strcmp(name, "blockquote") == 0;
}

static char *markdownSimplifyInline(const char *text) {
    if (!text) {
        return strdup("");
    }
    size_t len = strlen(text);
    size_t cap = len * 2 + 64;
    char *buffer = (char *)malloc(cap);
    if (!buffer) {
        return strdup(text);
    }
    size_t dst = 0;
    bool anchor_active = false;
    size_t anchor_start = 0;
    char anchor_href[1024];
    anchor_href[0] = '\0';

    for (size_t i = 0; text[i]; ) {
        char ch = text[i];
        if (ch == '<') {
            size_t close = i + 1;
            while (text[close] && text[close] != '>') {
                close++;
            }
            if (text[close] == '>') {
                char tag[1024];
                size_t raw_len = close - (i + 1);
                size_t copy_len = raw_len < sizeof(tag) - 1 ? raw_len : sizeof(tag) - 1;
                memcpy(tag, text + i + 1, copy_len);
                tag[copy_len] = '\0';

                char *work = tag;
                while (*work && isspace((unsigned char)*work)) {
                    work++;
                }
                bool closing = false;
                if (*work == '/') {
                    closing = true;
                    work++;
                    while (*work && isspace((unsigned char)*work)) {
                        work++;
                    }
                }

                if (isalpha((unsigned char)*work)) {
                    char *name_start = work;
                    while (*work && (isalnum((unsigned char)*work) || *work == '-' || *work == '_')) {
                        *work = (char)tolower((unsigned char)*work);
                        work++;
                    }
                    char *name_end = work;
                    while (*work && isspace((unsigned char)*work)) {
                        work++;
                    }
                    char *attrs = work;
                    char *tail = tag + strlen(tag);
                    while (tail > attrs && isspace((unsigned char)tail[-1])) {
                        *--tail = '\0';
                    }
                    bool self_closing = false;
                    if (tail > attrs && tail[-1] == '/') {
                        self_closing = true;
                        *--tail = '\0';
                        while (tail > attrs && isspace((unsigned char)tail[-1])) {
                            *--tail = '\0';
                        }
                    }

                    *name_end = '\0';
                    const char *name = name_start;

                    if (!markdownHtmlTagSupported(name)) {
                        size_t original_len = close - i + 1;
                        if (!markdownInlineAppendSpan(&buffer, &dst, &cap, text + i, original_len)) {
                            free(buffer);
                            return strdup(text);
                        }
                        i = close + 1;
                        continue;
                    }

                    if (strcmp(name, "a") == 0) {
                        if (closing) {
                            if (anchor_active && anchor_href[0] != '\0') {
                                size_t content_len = (dst > anchor_start) ? (dst - anchor_start) : 0;
                                char *anchor_label = NULL;
                                if (content_len > 0) {
                                    anchor_label = (char *)malloc(content_len + 1);
                                    if (anchor_label) {
                                        memcpy(anchor_label, buffer + anchor_start, content_len);
                                        anchor_label[content_len] = '\0';
                                    }
                                }
                                int link_display_number = -1;
                                if (gMarkdownActiveLinks) {
                                    link_display_number =
                                        markdownRegisterLinkAndGetDisplayNumber(gMarkdownActiveLinks,
                                                                                anchor_label ? anchor_label : anchor_href,
                                                                                anchor_href);
                                }
                                if (content_len == 0) {
                                    if (!markdownInlineAppendSpan(&buffer, &dst, &cap, "link", 4)) {
                                        free(anchor_label);
                                        free(buffer);
                                        return strdup(text);
                                    }
                                }
                                if (!markdownInlineAppendLinkMarker(&buffer, &dst, &cap, link_display_number)) {
                                    free(anchor_label);
                                    free(buffer);
                                    return strdup(text);
                                }
                                free(anchor_label);
                            }
                            anchor_active = false;
                            anchor_href[0] = '\0';
                        } else {
                            anchor_active = true;
                            anchor_start = dst;
                            if (!markdownHtmlExtractAttr(attrs, "href", anchor_href, sizeof(anchor_href))) {
                                anchor_href[0] = '\0';
                            }
                            if (self_closing) {
                                anchor_active = false;
                            }
                        }
                        i = close + 1;
                        continue;
                    }

                    if (!closing && strcmp(name, "img") == 0) {
                        char alt[512];
                        if (markdownHtmlExtractAttr(attrs, "alt", alt, sizeof(alt)) && alt[0] != '\0') {
                            if (!markdownInlineAppendSpan(&buffer, &dst, &cap, alt, strlen(alt))) {
                                free(buffer);
                                return strdup(text);
                            }
                        } else {
                            char src[1024];
                            if (markdownHtmlExtractAttr(attrs, "src", src, sizeof(src)) && src[0] != '\0') {
                                if (!markdownInlineAppendSpan(&buffer, &dst, &cap, src, strlen(src))) {
                                    free(buffer);
                                    return strdup(text);
                                }
                            }
                        }
                        i = close + 1;
                        continue;
                    }

                    if (!closing && (strcmp(name, "br") == 0 || strcmp(name, "hr") == 0)) {
                        if (!markdownInlineAppendChar(&buffer, &dst, &cap, ' ')) {
                            free(buffer);
                            return strdup(text);
                        }
                        i = close + 1;
                        continue;
                    }

                    /* Drop all other HTML tags but keep surrounding text. */
                    i = close + 1;
                    continue;
                }
            }
        }
        if (ch == '`') {
            i++;
            continue;
        }
        if ((ch == '*' || ch == '_')) {
            size_t advance = 1;
            if (text[i + 1] == ch) {
                advance = 2;
            }
            i += advance;
            continue;
        }
        if (ch == '[') {
            size_t close = i + 1;
            while (text[close] && text[close] != ']') {
                close++;
            }
            if (text[close] == ']' && text[close + 1] == '(') {
                size_t url_start = close + 2;
                size_t url_end = url_start;
                while (text[url_end] && text[url_end] != ')') {
                    url_end++;
                }
                if (text[url_end] == ')') {
                    size_t link_label_len = close - (i + 1);
                    size_t link_url_len = url_end - url_start;
                    char *link_label = NULL;
                    char *link_url = NULL;
                    int link_display_number = -1;
                    if (gMarkdownActiveLinks) {
                        link_label = (char *)malloc(link_label_len + 1);
                        link_url = (char *)malloc(link_url_len + 1);
                        if (link_label && link_url) {
                            memcpy(link_label, text + i + 1, link_label_len);
                            link_label[link_label_len] = '\0';
                            memcpy(link_url, text + url_start, link_url_len);
                            link_url[link_url_len] = '\0';
                            link_display_number =
                                markdownRegisterLinkAndGetDisplayNumber(gMarkdownActiveLinks, link_label, link_url);
                        }
                    }
                    if (link_label_len > 0) {
                        for (size_t j = i + 1; j < close; ++j) {
                            if (!markdownInlineAppendChar(&buffer, &dst, &cap, text[j])) {
                                free(link_label);
                                free(link_url);
                                free(buffer);
                                return strdup(text);
                            }
                        }
                    } else if (!markdownInlineAppendSpan(&buffer, &dst, &cap, "link", 4)) {
                        free(link_label);
                        free(link_url);
                        free(buffer);
                        return strdup(text);
                    }
                    if (!markdownInlineAppendLinkMarker(&buffer, &dst, &cap, link_display_number)) {
                        free(link_label);
                        free(link_url);
                        free(buffer);
                        return strdup(text);
                    }
                    free(link_label);
                    free(link_url);
                    i = url_end + 1;
                    continue;
                }
            }
        }
        if (!markdownInlineAppendChar(&buffer, &dst, &cap, ch)) {
            free(buffer);
            return strdup(text);
        }
        i++;
    }
    buffer[dst] = '\0';
    return buffer;
}

static void markdownWrapAndWrite(FILE *out, const char *text, const char *firstPrefix, const char *subPrefix, int width) {
    if (!out) {
        return;
    }
    if (!text || !*text) {
        if (firstPrefix && *firstPrefix) {
            fputs(firstPrefix, out);
        }
        fputc('\n', out);
        return;
    }
    const char *prefix_first = firstPrefix ? firstPrefix : "";
    const char *prefix_sub = subPrefix ? subPrefix : prefix_first;
    size_t prefix_first_len = strlen(prefix_first);
    size_t prefix_sub_len = strlen(prefix_sub);
    int wrap_width = width > 20 ? width : MARKDOWN_WRAP_WIDTH;

    char *copy = strdup(text);
    if (!copy) {
        return;
    }
    char *saveptr = NULL;
    char *token = strtok_r(copy, " \t\r\n", &saveptr);
    size_t current = prefix_first_len;
    fputs(prefix_first, out);
    bool first_word = true;
    while (token) {
        size_t tok_len = strlen(token);
        size_t extra = first_word ? tok_len : tok_len + 1;
        if (!first_word && (int)(current + extra) > wrap_width) {
            fputc('\n', out);
            fputs(prefix_sub, out);
            current = prefix_sub_len;
            first_word = true;
            extra = tok_len;
        }
        if (!first_word) {
            fputc(' ', out);
            current++;
        }
        fputs(token, out);
        current += tok_len;
        first_word = false;
        token = strtok_r(NULL, " \t\r\n", &saveptr);
    }
    fputc('\n', out);
    free(copy);
}

static int markdownTermWidth(void) {
    struct winsize w;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &w) == 0 && w.ws_col > 0) {
        return w.ws_col;
    }
    const char *cols = getenv("COLUMNS");
    if (cols && *cols) {
        int parsed = atoi(cols);
        if (parsed > 0) {
            return parsed;
        }
    }
    return MARKDOWN_WRAP_WIDTH;
}

static char *markdownTrimInline(char *str) {
    if (!str) return str;
    while (*str && isspace((unsigned char)*str)) {
        str++;
    }
    char *end = str + strlen(str);
    while (end > str && isspace((unsigned char)*(end - 1))) {
        *(--end) = '\0';
    }
    return str;
}

static void markdownParseTableRow(char *line, MarkdownTableRow *row) {
    if (!row) return;
    row->col_count = 0;
    if (!line) return;
    char *start = line;
    if (*start == '|') {
        start++;
    }
    while (start) {
        char *delim = strchr(start, '|');
        if (delim) {
            *delim = '\0';
            if (row->col_count < MARKDOWN_MAX_TABLE_COLS) {
                row->cells[row->col_count++] = strdup(markdownTrimInline(start));
            }
            start = delim + 1;
            if (*start == '\0') {
                break;
            }
            continue;
        }
        if (row->col_count < MARKDOWN_MAX_TABLE_COLS) {
            row->cells[row->col_count++] = strdup(markdownTrimInline(start));
        }
        break;
    }
}

static int markdownIsSeparatorRow(const MarkdownTableRow *row) {
    if (!row || row->col_count == 0) return 0;
    for (int i = 0; i < row->col_count; ++i) {
        const char *cell = row->cells[i];
        if (!cell) return 0;
        int has_dash = 0;
        for (const char *p = cell; *p; ++p) {
            if (*p == '-') {
                has_dash = 1;
            } else if (*p == ':' || isspace((unsigned char)*p)) {
                continue;
            } else {
                return 0;
            }
        }
        if (!has_dash) {
            return 0;
        }
    }
    return 1;
}

static int markdownTableWrapLen(const char *text, int max_width, int offset) {
    int len = (int)strlen(text);
    int remaining = len - offset;
    if (remaining <= max_width) return remaining;
    for (int k = max_width; k > 0; --k) {
        char prev = text[offset + k - 1];
        if (prev == ' ') return k;
        if (prev == '/' || prev == '-' || prev == '_' || prev == ',' || prev == '.') {
            return k;
        }
    }
    return max_width;
}

static void markdownPrintSeparator(FILE *out, const int *col_widths, int cols) {
    fputs("  +", out);
    for (int j = 0; j < cols; ++j) {
        for (int k = 0; k < col_widths[j] + 2; ++k) {
            fputc('-', out);
        }
        fputc('+', out);
    }
    fputc('\n', out);
}

static void markdownRenderTable(FILE *out, MarkdownTableRow *rows, int row_count) {
    if (!rows || row_count <= 0) return;
    if (!out) return;

    int term_width = markdownTermWidth();
    int col_widths[MARKDOWN_MAX_TABLE_COLS] = {0};
    int max_cols = 0;

    for (int i = 0; i < row_count; ++i) {
        if (rows[i].col_count > max_cols) {
            max_cols = rows[i].col_count;
        }
        if (!markdownIsSeparatorRow(&rows[i])) {
            for (int j = 0; j < rows[i].col_count; ++j) {
                int len = (int)strlen(rows[i].cells[j]);
                if (len > col_widths[j]) {
                    col_widths[j] = len;
                }
            }
        }
    }

    int total_padding = (max_cols * 3) + 1;
    int available = term_width - total_padding;
    int current_total = 0;
    for (int j = 0; j < max_cols; ++j) current_total += col_widths[j];
    if (available > 0 && current_total > available && max_cols > 0) {
        int avg = available / max_cols;
        if (avg < MARKDOWN_MIN_COL_WIDTH) avg = MARKDOWN_MIN_COL_WIDTH;
        for (int j = 0; j < max_cols; ++j) {
            if (col_widths[j] > avg) col_widths[j] = avg;
        }
    }

    markdownPrintSeparator(out, col_widths, max_cols);
    for (int i = 0; i < row_count; ++i) {
        if (markdownIsSeparatorRow(&rows[i])) {
            markdownPrintSeparator(out, col_widths, max_cols);
            continue;
        }
        int offsets[MARKDOWN_MAX_TABLE_COLS] = {0};
        while (true) {
            bool has_remaining = false;
            for (int j = 0; j < max_cols; ++j) {
                const char *text = (j < rows[i].col_count && rows[i].cells[j]) ? rows[i].cells[j] : "";
                if (offsets[j] < (int)strlen(text)) {
                    has_remaining = true;
                    break;
                }
            }
            if (!has_remaining) {
                break;
            }
            fputs("  |", out);
            for (int j = 0; j < max_cols; ++j) {
                const char *text = (j < rows[i].col_count && rows[i].cells[j]) ? rows[i].cells[j] : "";
                int width = col_widths[j];
                int len = (int)strlen(text);
                int off = offsets[j];
                if (off < len) {
                    int take = markdownTableWrapLen(text, width, off);
                    fprintf(out, " %-*.*s", width, take, text + off);
                    offsets[j] += take;
                    if (offsets[j] < len && text[offsets[j]] == ' ') {
                        offsets[j]++;
                    }
                } else {
                    fprintf(out, " %-*s", width, "");
                }
                fputs(" |", out);
            }
            fputc('\n', out);
        }
    }
    markdownPrintSeparator(out, col_widths, max_cols);
    fputc('\n', out);

    for (int i = 0; i < row_count; ++i) {
        for (int j = 0; j < rows[i].col_count; ++j) {
            free(rows[i].cells[j]);
            rows[i].cells[j] = NULL;
        }
    }
}

static bool markdownIsHorizontalRule(const char *text) {
    if (!text) return false;
    size_t dash_count = 0;
    for (const char *p = text; *p; ++p) {
        if (*p == '-' || *p == '_' || *p == '*') {
            dash_count++;
        } else if (!isspace((unsigned char)*p)) {
            return false;
        }
    }
    return dash_count >= 3;
}

static int markdownHeadingLevel(const char *text) {
    if (!text) return 0;
    int level = 0;
    const char *p = text;
    while (*p == '#') {
        level++;
        p++;
    }
    if (level > 0 && (*p == ' ' || *p == '\t')) {
        return level;
    }
    return 0;
}

static int markdownSetextHeadingLevel(const char *text) {
    if (!text) return 0;
    char marker = 0;
    int count = 0;
    for (const char *p = text; *p; ++p) {
        if (isspace((unsigned char)*p)) {
            continue;
        }
        if (*p != '=' && *p != '-') {
            return 0;
        }
        if (marker == 0) {
            marker = *p;
        } else if (*p != marker) {
            return 0;
        }
        count++;
    }
    if (count < 3) {
        return 0;
    }
    return (marker == '=') ? 1 : 2;
}

static char markdownFenceMarker(const char *text) {
    if (!text || !*text) {
        return '\0';
    }
    if (*text != '`' && *text != '~') {
        return '\0';
    }
    char marker = *text;
    int count = 0;
    while (*text == marker) {
        count++;
        text++;
    }
    if (count >= 3) {
        return marker;
    }
    return '\0';
}

static void markdownWriteHeading(FILE *out, const char *text, int level) {
    if (!text || !*text) return;
    char *formatted = markdownSimplifyInline(text);
    if (!formatted) return;
    fprintf(out, "%s\n", formatted);
    char underline = (level == 1) ? '=' : '-';
    size_t len = strlen(formatted);
    size_t underline_len = len > MARKDOWN_WRAP_WIDTH ? MARKDOWN_WRAP_WIDTH : len;
    for (size_t i = 0; i < underline_len; ++i) {
        fputc(underline, out);
    }
    fputc('\n', out);
    free(formatted);
}

static void markdownBuildPrefix(char *buffer, size_t buffer_size, int spaces, const char *suffix) {
    if (!buffer || buffer_size == 0) {
        return;
    }
    if (spaces < 0) spaces = 0;
    if ((size_t)(spaces + 1) > buffer_size) {
        spaces = (int)buffer_size - 1;
    }
    size_t suffix_len = suffix ? strlen(suffix) : 0;
    if ((size_t)spaces + suffix_len + 1 > buffer_size) {
        if (suffix_len + 1 > buffer_size) {
            suffix_len = buffer_size - 1;
        }
        spaces = 0;
    }
    memset(buffer, ' ', (size_t)spaces);
    if (suffix_len > 0) {
        memcpy(buffer + spaces, suffix, suffix_len);
    }
    buffer[spaces + suffix_len] = '\0';
}

static bool markdownExtractListItem(char *line, char **content, char *firstPrefix, size_t firstSize, char *subPrefix, size_t subSize) {
    if (!line || !content || !firstPrefix || !subPrefix) {
        return false;
    }
    char *p = line;
    int indent = 0;
    while (*p == ' ' || *p == '\t') {
        indent += (*p == '\t') ? 4 : 1;
        p++;
    }
    if ((*p == '-' || *p == '*' || *p == '+') && (p[1] == ' ' || p[1] == '\t')) {
        p++;
        while (*p == ' ' || *p == '\t') p++;
        if (p[0] == '[' &&
            (p[1] == ' ' || p[1] == 'x' || p[1] == 'X') &&
            p[2] == ']' &&
            (p[3] == ' ' || p[3] == '\t')) {
            const char *checkbox = (p[1] == ' ') ? "• [ ] " : "• [x] ";
            p += 4;
            while (*p == ' ' || *p == '\t') p++;
            *content = p;
            markdownBuildPrefix(firstPrefix, firstSize, indent, checkbox);
            markdownBuildPrefix(subPrefix, subSize, indent + 6, "      ");
            return true;
        }
        *content = p;
        markdownBuildPrefix(firstPrefix, firstSize, indent, "• ");
        markdownBuildPrefix(subPrefix, subSize, indent + 2, "  ");
        return true;
    }
    if (isdigit((unsigned char)*p)) {
        const char *start = p;
        while (isdigit((unsigned char)*p)) {
            p++;
        }
        if (*p == '.' && (p[1] == ' ' || p[1] == '\t')) {
            int value = atoi(start);
            p++;
            while (*p == ' ' || *p == '\t') p++;
            *content = p;
            char suffix[16];
            snprintf(suffix, sizeof(suffix), "%d. ", value);
            markdownBuildPrefix(firstPrefix, firstSize, indent, suffix);
            size_t suffix_len = strlen(suffix);
            markdownBuildPrefix(subPrefix, subSize, indent + (int)suffix_len, "  ");
            return true;
        }
    }
    return false;
}

static void markdownFlushParagraph(FILE *out, char **paragraph, size_t *length) {
    if (!paragraph || !*paragraph || !length || *length == 0) {
        return;
    }
    (*paragraph)[*length] = '\0';
    const char *text = *paragraph;
    /* Naive table detection: look for '|' separators with at least two columns. */
    int pipe_count = 0;
    for (const char *p = text; *p; ++p) {
        if (*p == '|') {
            pipe_count++;
        }
    }
    if (pipe_count >= 2 && strchr(text, '\n') == NULL) {
        /* Single-line paragraph that looks like a table row; just print it. */
        fprintf(out, "%s\n\n", text);
    } else {
        char *formatted = markdownSimplifyInline(text);
        if (formatted) {
            markdownWrapAndWrite(out, formatted, "", "", MARKDOWN_WRAP_WIDTH);
            free(formatted);
        }
        fputc('\n', out);
    }
    *length = 0;
    **paragraph = '\0';
}

static bool markdownTextEnsureCapacity(char **buffer, size_t *capacity, size_t needed) {
    if (!buffer || !capacity) {
        return false;
    }
    if (needed <= *capacity) {
        return true;
    }
    size_t new_capacity = (*capacity == 0) ? 256 : *capacity;
    while (new_capacity < needed) {
        if (new_capacity > SIZE_MAX / 2) {
            return false;
        }
        new_capacity *= 2;
    }
    char *resized = (char *)realloc(*buffer, new_capacity);
    if (!resized) {
        return false;
    }
    *buffer = resized;
    *capacity = new_capacity;
    return true;
}

static bool markdownTextAppendSpan(char **buffer, size_t *length, size_t *capacity, const char *text, size_t text_len) {
    if (!buffer || !length || !capacity || (!text && text_len > 0)) {
        return false;
    }
    size_t needed = *length + text_len + 1;
    if (!markdownTextEnsureCapacity(buffer, capacity, needed)) {
        return false;
    }
    if (text_len > 0) {
        memcpy(*buffer + *length, text, text_len);
        *length += text_len;
    }
    (*buffer)[*length] = '\0';
    return true;
}

static bool markdownTextAppendChar(char **buffer, size_t *length, size_t *capacity, char ch) {
    return markdownTextAppendSpan(buffer, length, capacity, &ch, 1);
}

static bool markdownTextAppendNewlines(char **buffer, size_t *length, size_t *capacity, size_t count) {
    if (!buffer || !length || !capacity) {
        return false;
    }
    size_t existing = 0;
    while (existing < *length && (*buffer)[*length - existing - 1] == '\n') {
        existing++;
    }
    size_t required = (count > existing) ? (count - existing) : 0;
    for (size_t i = 0; i < required; ++i) {
        if (!markdownTextAppendChar(buffer, length, capacity, '\n')) {
            return false;
        }
    }
    return true;
}

static bool markdownHtmlDecodeEntity(const char *html, size_t *index, char *decoded) {
    if (!html || !index || !decoded) {
        return false;
    }
    size_t i = *index;
    if (html[i] != '&') {
        return false;
    }
    const char *p = html + i;
    if (strncmp(p, "&amp;", 5) == 0) {
        *decoded = '&';
        *index += 5;
        return true;
    }
    if (strncmp(p, "&lt;", 4) == 0) {
        *decoded = '<';
        *index += 4;
        return true;
    }
    if (strncmp(p, "&gt;", 4) == 0) {
        *decoded = '>';
        *index += 4;
        return true;
    }
    if (strncmp(p, "&quot;", 6) == 0) {
        *decoded = '"';
        *index += 6;
        return true;
    }
    if (strncmp(p, "&#39;", 5) == 0 || strncmp(p, "&apos;", 6) == 0) {
        *decoded = '\'';
        *index += (p[2] == '3') ? 5 : 6;
        return true;
    }
    if (strncmp(p, "&nbsp;", 6) == 0) {
        *decoded = ' ';
        *index += 6;
        return true;
    }
    if (strncmp(p, "&copy;", 6) == 0) {
        *decoded = 'c';
        *index += 6;
        return true;
    }
    if (strncmp(p, "&raquo;", 7) == 0 || strncmp(p, "&raquo", 6) == 0) {
        *decoded = '>';
        *index += (p[6] == ';') ? 7 : 6;
        return true;
    }
    if (strncmp(p, "&laquo;", 7) == 0 || strncmp(p, "&laquo", 6) == 0) {
        *decoded = '<';
        *index += (p[6] == ';') ? 7 : 6;
        return true;
    }
    if (strncmp(p, "&middot;", 8) == 0) {
        *decoded = '.';
        *index += 8;
        return true;
    }
    if (strncmp(p, "&bull;", 6) == 0) {
        *decoded = '*';
        *index += 6;
        return true;
    }
    if (strncmp(p, "&ndash;", 7) == 0 || strncmp(p, "&mdash;", 7) == 0) {
        *decoded = '-';
        *index += 7;
        return true;
    }
    if (p[1] == '#') {
        size_t j = 2;
        int base = 10;
        if (p[j] == 'x' || p[j] == 'X') {
            base = 16;
            j++;
        }
        unsigned value = 0;
        bool have_digit = false;
        while (p[j] && p[j] != ';') {
            unsigned digit;
            if (p[j] >= '0' && p[j] <= '9') {
                digit = (unsigned)(p[j] - '0');
            } else if (base == 16 && p[j] >= 'a' && p[j] <= 'f') {
                digit = (unsigned)(10 + (p[j] - 'a'));
            } else if (base == 16 && p[j] >= 'A' && p[j] <= 'F') {
                digit = (unsigned)(10 + (p[j] - 'A'));
            } else {
                have_digit = false;
                break;
            }
            have_digit = true;
            value = value * (unsigned)base + digit;
            if (value > 0x10FFFFu) {
                have_digit = false;
                break;
            }
            j++;
        }
        if (have_digit && p[j] == ';') {
            *index += j + 1;
            if (value == 0x27u) {
                *decoded = '\'';
                return true;
            }
            if (value == 0x22u) {
                *decoded = '"';
                return true;
            }
            if (value == 0x26u) {
                *decoded = '&';
                return true;
            }
            if (value == 0x3Cu) {
                *decoded = '<';
                return true;
            }
            if (value == 0x3Eu) {
                *decoded = '>';
                return true;
            }
            if (value == 0xA0u) {
                *decoded = ' ';
                return true;
            }
            if (value >= 32u && value <= 126u) {
                *decoded = (char)value;
                return true;
            }
            *decoded = ' ';
            return true;
        }
    }
    return false;
}

static bool markdownParseHtmlTag(const char *raw, char *name_out, size_t name_out_size,
                                 char *attrs_out, size_t attrs_out_size, bool *closing, bool *self_closing) {
    if (!raw || !name_out || name_out_size == 0 || !attrs_out || attrs_out_size == 0 || !closing || !self_closing) {
        return false;
    }
    name_out[0] = '\0';
    attrs_out[0] = '\0';
    *closing = false;
    *self_closing = false;

    const char *p = raw;
    while (*p && isspace((unsigned char)*p)) {
        p++;
    }
    if (*p == '/') {
        *closing = true;
        p++;
        while (*p && isspace((unsigned char)*p)) {
            p++;
        }
    }
    if (!isalpha((unsigned char)*p)) {
        return false;
    }
    size_t name_len = 0;
    while (*p && (isalnum((unsigned char)*p) || *p == '-' || *p == '_')) {
        if (name_len + 1 < name_out_size) {
            name_out[name_len++] = (char)tolower((unsigned char)*p);
        }
        p++;
    }
    name_out[name_len] = '\0';

    while (*p && isspace((unsigned char)*p)) {
        p++;
    }
    size_t attrs_len = strlen(p);
    while (attrs_len > 0 && isspace((unsigned char)p[attrs_len - 1])) {
        attrs_len--;
    }
    if (attrs_len > 0 && p[attrs_len - 1] == '/') {
        *self_closing = true;
        attrs_len--;
        while (attrs_len > 0 && isspace((unsigned char)p[attrs_len - 1])) {
            attrs_len--;
        }
    }
    if (attrs_len >= attrs_out_size) {
        attrs_len = attrs_out_size - 1;
    }
    if (attrs_len > 0) {
        memcpy(attrs_out, p, attrs_len);
    }
    attrs_out[attrs_len] = '\0';
    return name_len > 0;
}

static int markdownHeadingLevelFromTag(const char *tag_name) {
    if (!tag_name || strlen(tag_name) != 2 || tag_name[0] != 'h') {
        return 0;
    }
    if (tag_name[1] >= '1' && tag_name[1] <= '6') {
        return tag_name[1] - '0';
    }
    return 0;
}

static bool markdownIsLikelyHtmlDocument(const char *content) {
    if (!content || !*content) {
        return false;
    }
    const char *scan = content;
    while (*scan && isspace((unsigned char)*scan)) {
        scan++;
    }
    if (strncasecmp(scan, "<!doctype html", 14) == 0) {
        return true;
    }
    if (strncasecmp(scan, "<html", 5) == 0) {
        return true;
    }
    if (strstr(content, "<html") || strstr(content, "<body") || strstr(content, "</html>")) {
        return true;
    }
    return false;
}

static const char *markdownFindIgnoreCase(const char *text, const char *needle) {
    if (!text || !needle || !*needle) {
        return text;
    }
    size_t needle_len = strlen(needle);
    for (const char *p = text; *p; ++p) {
        if (strncasecmp(p, needle, needle_len) == 0) {
            return p;
        }
    }
    return NULL;
}

static const char *markdownFindIgnoreCaseBounded(const char *text, const char *limit, const char *needle) {
    if (!text || !limit || !needle || !*needle || text >= limit) {
        return NULL;
    }
    size_t needle_len = strlen(needle);
    if (needle_len == 0) {
        return text;
    }
    for (const char *p = text; p < limit; ++p) {
        size_t remaining = (size_t)(limit - p);
        if (remaining < needle_len) {
            break;
        }
        if (strncasecmp(p, needle, needle_len) == 0) {
            return p;
        }
    }
    return NULL;
}

static char *markdownConvertHtmlToMarkdownish(const char *html) {
    if (!html) {
        return strdup("");
    }
    size_t len = strlen(html);
    size_t start_index = 0;
    size_t stop_index = len;
    const char *body_tag = markdownFindIgnoreCase(html, "<body");
    if (body_tag) {
        const char *body_open = strchr(body_tag, '>');
        if (body_open && body_open[1] != '\0') {
            start_index = (size_t)((body_open + 1) - html);
            const char *body_close = markdownFindIgnoreCase(body_open + 1, "</body");
            if (body_close && body_close > body_open) {
                stop_index = (size_t)(body_close - html);
            }
        }
    }
    size_t cap = len * 2 + 256;
    char *out = (char *)malloc(cap);
    if (!out) {
        return strdup("");
    }
    out[0] = '\0';
    size_t dst = 0;

    bool in_script = false;
    bool in_style = false;
    bool in_noscript = false;
    bool in_template = false;
    bool in_svg = false;
    bool in_iframe = false;
    bool in_canvas = false;
    bool in_object = false;
    bool in_embed = false;
    bool anchor_active = false;
    bool anchor_suppress_text = false;
    char anchor_href[2048];
    anchor_href[0] = '\0';

    for (size_t i = start_index; i < stop_index && html[i]; ) {
        if (in_script || in_style || in_noscript || in_template ||
            in_svg || in_iframe || in_canvas || in_object || in_embed) {
            const char *tag_name = NULL;
            if (in_script) tag_name = "script";
            else if (in_style) tag_name = "style";
            else if (in_noscript) tag_name = "noscript";
            else if (in_template) tag_name = "template";
            else if (in_svg) tag_name = "svg";
            else if (in_iframe) tag_name = "iframe";
            else if (in_canvas) tag_name = "canvas";
            else if (in_object) tag_name = "object";
            else if (in_embed) tag_name = "embed";

            char close_needle[64];
            snprintf(close_needle, sizeof(close_needle), "</%s", tag_name ? tag_name : "");
            const char *close_tag = markdownFindIgnoreCaseBounded(html + i,
                                                                  html + stop_index,
                                                                  close_needle);
            if (!close_tag) {
                break;
            }
            const char *close_gt = close_tag;
            while (close_gt < html + stop_index && *close_gt && *close_gt != '>') {
                close_gt++;
            }
            if (close_gt >= html + stop_index || !*close_gt) {
                break;
            }
            i = (size_t)(close_gt - html) + 1;
            in_script = false;
            in_style = false;
            in_noscript = false;
            in_template = false;
            in_svg = false;
            in_iframe = false;
            in_canvas = false;
            in_object = false;
            in_embed = false;
            continue;
        }
        if (html[i] == '<') {
            size_t close = i + 1;
            while (close < stop_index && html[close] && html[close] != '>') {
                close++;
            }
            if (close >= stop_index || !html[close]) {
                break;
            }
            size_t raw_len = close - (i + 1);
            char raw_tag[2048];
            size_t copy_len = raw_len < sizeof(raw_tag) - 1 ? raw_len : sizeof(raw_tag) - 1;
            memcpy(raw_tag, html + i + 1, copy_len);
            raw_tag[copy_len] = '\0';

            if (strncmp(raw_tag, "!--", 3) == 0) {
                const char *comment_end = strstr(html + i + 4, "-->");
                if (comment_end && (size_t)(comment_end - html) < stop_index) {
                    i = (size_t)(comment_end - html) + 3;
                } else {
                    i = close + 1;
                }
                continue;
            }

            char tag_name[64];
            char attrs[2048];
            bool closing = false;
            bool self_closing = false;
            if (!markdownParseHtmlTag(raw_tag, tag_name, sizeof(tag_name), attrs, sizeof(attrs), &closing, &self_closing)) {
                i = close + 1;
                continue;
            }

            if (!closing && strcmp(tag_name, "script") == 0) {
                in_script = true;
                i = close + 1;
                continue;
            }
            if (!closing && strcmp(tag_name, "style") == 0) {
                in_style = true;
                i = close + 1;
                continue;
            }
            if (!closing && strcmp(tag_name, "noscript") == 0) {
                in_noscript = true;
                i = close + 1;
                continue;
            }
            if (!closing && strcmp(tag_name, "template") == 0) {
                in_template = true;
                i = close + 1;
                continue;
            }
            if (!closing && strcmp(tag_name, "svg") == 0) {
                in_svg = true;
                i = close + 1;
                continue;
            }
            if (!closing && strcmp(tag_name, "iframe") == 0) {
                in_iframe = true;
                i = close + 1;
                continue;
            }
            if (!closing && strcmp(tag_name, "canvas") == 0) {
                in_canvas = true;
                i = close + 1;
                continue;
            }
            if (!closing && strcmp(tag_name, "object") == 0) {
                in_object = true;
                i = close + 1;
                continue;
            }
            if (!closing && strcmp(tag_name, "embed") == 0) {
                in_embed = true;
                i = close + 1;
                continue;
            }

            int heading_level = markdownHeadingLevelFromTag(tag_name);
            if (!closing && heading_level > 0) {
                if (!markdownTextAppendNewlines(&out, &dst, &cap, 2)) {
                    free(out);
                    return strdup("");
                }
                for (int h = 0; h < heading_level; ++h) {
                    if (!markdownTextAppendChar(&out, &dst, &cap, '#')) {
                        free(out);
                        return strdup("");
                    }
                }
                if (!markdownTextAppendChar(&out, &dst, &cap, ' ')) {
                    free(out);
                    return strdup("");
                }
                i = close + 1;
                continue;
            }
            if (closing && heading_level > 0) {
                if (!markdownTextAppendNewlines(&out, &dst, &cap, 2)) {
                    free(out);
                    return strdup("");
                }
                i = close + 1;
                continue;
            }

            if (!closing && strcmp(tag_name, "a") == 0) {
                if (markdownHtmlExtractAttr(attrs, "href", anchor_href, sizeof(anchor_href))) {
                    if (anchor_href[0] == '#' ||
                        strncasecmp(anchor_href, "javascript:", 11) == 0) {
                        anchor_active = false;
                        anchor_suppress_text = true;
                    } else {
                        anchor_active = true;
                        anchor_suppress_text = false;
                        if (!markdownTextAppendChar(&out, &dst, &cap, '[')) {
                            free(out);
                            return strdup("");
                        }
                    }
                } else {
                    anchor_active = false;
                    anchor_suppress_text = false;
                    anchor_href[0] = '\0';
                }
                i = close + 1;
                continue;
            }
            if (closing && strcmp(tag_name, "a") == 0) {
                if (anchor_active && anchor_href[0] != '\0') {
                    if (!markdownTextAppendSpan(&out, &dst, &cap, "](", 2) ||
                        !markdownTextAppendSpan(&out, &dst, &cap, anchor_href, strlen(anchor_href)) ||
                        !markdownTextAppendChar(&out, &dst, &cap, ')')) {
                        free(out);
                        return strdup("");
                    }
                }
                anchor_active = false;
                anchor_suppress_text = false;
                anchor_href[0] = '\0';
                i = close + 1;
                continue;
            }

            if (!closing && strcmp(tag_name, "img") == 0) {
                char alt[1024];
                if (markdownHtmlExtractAttr(attrs, "alt", alt, sizeof(alt)) && alt[0] != '\0') {
                    if (!markdownTextAppendSpan(&out, &dst, &cap, alt, strlen(alt))) {
                        free(out);
                        return strdup("");
                    }
                }
                i = close + 1;
                continue;
            }

            if (!closing && (strcmp(tag_name, "li") == 0)) {
                if (!markdownTextAppendNewlines(&out, &dst, &cap, 1) ||
                    !markdownTextAppendSpan(&out, &dst, &cap, "- ", 2)) {
                    free(out);
                    return strdup("");
                }
                i = close + 1;
                continue;
            }

            if (!closing && (strcmp(tag_name, "br") == 0 || strcmp(tag_name, "hr") == 0)) {
                if (!markdownTextAppendNewlines(&out, &dst, &cap, 1)) {
                    free(out);
                    return strdup("");
                }
                i = close + 1;
                continue;
            }

            if (!closing &&
                (strcmp(tag_name, "p") == 0 || strcmp(tag_name, "div") == 0 ||
                 strcmp(tag_name, "section") == 0 || strcmp(tag_name, "article") == 0 ||
                 strcmp(tag_name, "header") == 0 || strcmp(tag_name, "footer") == 0 ||
                 strcmp(tag_name, "blockquote") == 0 || strcmp(tag_name, "table") == 0 ||
                 strcmp(tag_name, "tr") == 0 || strcmp(tag_name, "ul") == 0 || strcmp(tag_name, "ol") == 0)) {
                if (!markdownTextAppendNewlines(&out, &dst, &cap, 2)) {
                    free(out);
                    return strdup("");
                }
                i = close + 1;
                continue;
            }

            if (closing &&
                (strcmp(tag_name, "p") == 0 || strcmp(tag_name, "div") == 0 ||
                 strcmp(tag_name, "section") == 0 || strcmp(tag_name, "article") == 0 ||
                 strcmp(tag_name, "header") == 0 || strcmp(tag_name, "footer") == 0 ||
                 strcmp(tag_name, "blockquote") == 0 || strcmp(tag_name, "table") == 0 ||
                 strcmp(tag_name, "tr") == 0)) {
                if (!markdownTextAppendNewlines(&out, &dst, &cap, 2)) {
                    free(out);
                    return strdup("");
                }
                i = close + 1;
                continue;
            }

            i = close + 1;
            continue;
        }

        if (html[i] == '&') {
            char decoded = '\0';
            size_t next = i;
            if (markdownHtmlDecodeEntity(html, &next, &decoded)) {
                if (!markdownTextAppendChar(&out, &dst, &cap, decoded)) {
                    free(out);
                    return strdup("");
                }
                i = next;
                continue;
            }
        }

        char ch = html[i++];
        if (anchor_suppress_text) {
            continue;
        }
        if (!markdownTextAppendChar(&out, &dst, &cap, ch)) {
            free(out);
            return strdup("");
        }
    }

    if (anchor_active && anchor_href[0] != '\0') {
        (void)markdownTextAppendSpan(&out, &dst, &cap, "](", 2);
        (void)markdownTextAppendSpan(&out, &dst, &cap, anchor_href, strlen(anchor_href));
        (void)markdownTextAppendChar(&out, &dst, &cap, ')');
    }
    out[dst] = '\0';
    return out;
}

static int markdownReadAll(FILE *input, char **out_data, size_t *out_len) {
    if (!input || !out_data || !out_len) {
        return -1;
    }
    *out_data = NULL;
    *out_len = 0;
    size_t cap = 0;
    size_t len = 0;
    char chunk[8192];
    while (true) {
        int read_err = 0;
        ssize_t n = smallclueReadStream(input, chunk, sizeof(chunk), &read_err);
        if (n < 0) {
            free(*out_data);
            *out_data = NULL;
            *out_len = 0;
            errno = read_err ? read_err : errno;
            return -1;
        }
        if (n == 0) {
            break;
        }
        size_t needed = len + (size_t)n + 1;
        if (needed > cap) {
            size_t new_cap = (cap == 0) ? 16384 : cap;
            while (new_cap < needed) {
                if (new_cap > SIZE_MAX / 2) {
                    free(*out_data);
                    *out_data = NULL;
                    *out_len = 0;
                    errno = ENOMEM;
                    return -1;
                }
                new_cap *= 2;
            }
            char *resized = (char *)realloc(*out_data, new_cap);
            if (!resized) {
                free(*out_data);
                *out_data = NULL;
                *out_len = 0;
                errno = ENOMEM;
                return -1;
            }
            *out_data = resized;
            cap = new_cap;
        }
        memcpy(*out_data + len, chunk, (size_t)n);
        len += (size_t)n;
    }
    if (!*out_data) {
        *out_data = strdup("");
        if (!*out_data) {
            errno = ENOMEM;
            return -1;
        }
    } else {
        (*out_data)[len] = '\0';
    }
    *out_len = len;
    return 0;
}

static bool markdownContainsIgnoreCase(const char *text, const char *needle) {
    if (!text || !needle) {
        return false;
    }
    size_t needle_len = strlen(needle);
    if (needle_len == 0) {
        return true;
    }
    size_t text_len = strlen(text);
    if (needle_len > text_len) {
        return false;
    }
    for (size_t i = 0; i + needle_len <= text_len; ++i) {
        if (strncasecmp(text + i, needle, needle_len) == 0) {
            return true;
        }
    }
    return false;
}

static bool markdownLooksLikeNewsMetaLine(const char *line) {
    if (!line || !*line) {
        return false;
    }
    const char *probe = markdownSkipSoftWhitespace(line);
    if (!*probe) {
        return false;
    }
    if (markdownContainsIgnoreCase(probe, "announcement") ||
        markdownContainsIgnoreCase(probe, "press release") ||
        markdownContainsIgnoreCase(probe, "updated ")) {
        return true;
    }
    static const char *months[] = {
        "january", "february", "march", "april", "may", "june",
        "july", "august", "september", "october", "november", "december",
        "jan ", "feb ", "mar ", "apr ", "jun ", "jul ", "aug ", "sep ", "sept ", "oct ", "nov ", "dec "
    };
    bool month_hit = false;
    for (size_t i = 0; i < sizeof(months) / sizeof(months[0]); ++i) {
        if (markdownContainsIgnoreCase(probe, months[i])) {
            month_hit = true;
            break;
        }
    }
    if (!month_hit) {
        return false;
    }
    int digit_count = 0;
    for (const char *p = probe; *p; ++p) {
        if (isdigit((unsigned char)*p)) {
            digit_count++;
        }
    }
    return digit_count >= 3;
}

static bool markdownLooksLikeCssSelectorLine(const char *line) {
    if (!line || !*line) {
        return false;
    }
    const char *probe = markdownSkipSoftWhitespace(line);
    if (!*probe) {
        return false;
    }
    if (strstr(probe, "://") || strchr(probe, ';')) {
        return false;
    }
    const char *brace = strchr(probe, '{');
    if (!brace) {
        return false;
    }
    /* CSS keyframe selectors like 0%{ / 100%{ */
    if (brace > probe && brace[-1] == '%') {
        bool digits_only = true;
        for (const char *p = probe; p < brace - 1; ++p) {
            if (!isdigit((unsigned char)*p) && !isspace((unsigned char)*p)) {
                digits_only = false;
                break;
            }
        }
        if (digits_only) {
            return true;
        }
    }
    bool saw_alpha = false;
    for (const char *p = probe; p < brace; ++p) {
        unsigned char ch = (unsigned char)*p;
        if (isalpha(ch)) {
            saw_alpha = true;
            continue;
        }
        if (isdigit(ch) || isspace(ch) || ch == '.' || ch == '#' || ch == '[' || ch == ']' ||
            ch == ':' || ch == '-' || ch == '_' || ch == ',' || ch == '>' || ch == '+' ||
            ch == '~' || ch == '*' || ch == '(' || ch == ')' || ch == '%') {
            continue;
        }
        return false;
    }
    if (!saw_alpha) {
        return false;
    }
    for (const char *p = brace + 1; *p; ++p) {
        if (!isspace((unsigned char)*p) && *p != '}') {
            return false;
        }
    }
    return true;
}

static const char *markdownSkipSoftWhitespace(const char *text) {
    if (!text) {
        return "";
    }
    const unsigned char *p = (const unsigned char *)text;
    while (*p) {
        if (isspace(*p)) {
            p++;
            continue;
        }
        /* UTF-8 NBSP */
        if (p[0] == 0xC2 && p[1] == 0xA0) {
            p += 2;
            continue;
        }
        /* UTF-8 zero-width spaces */
        if (p[0] == 0xE2 && p[1] == 0x80 &&
            (p[2] == 0x8B || p[2] == 0x8C || p[2] == 0x8D)) {
            p += 3;
            continue;
        }
        break;
    }
    return (const char *)p;
}

static bool markdownLooksLikeWebNoiseLine(const char *line) {
    if (!line || !*line) {
        return false;
    }
    const char *probe = markdownSkipSoftWhitespace(line);
    if (!*probe) {
        return false;
    }

    if (markdownContainsIgnoreCase(probe, "<script") ||
        markdownContainsIgnoreCase(probe, "</script") ||
        markdownContainsIgnoreCase(probe, "<style") ||
        markdownContainsIgnoreCase(probe, "</style")) {
        return true;
    }

    if (strstr(probe, "localStorage.") ||
        strstr(probe, "document.") ||
        strstr(probe, "window.") ||
        strstr(probe, "getElement") ||
        strstr(probe, "w-mod-") ||
        strstr(probe, "intellimize") ||
        strstr(probe, "webflow") ||
        strstr(probe, "var(--") ||
        strstr(probe, "@media") ||
        strstr(probe, ":root") ||
        strstr(probe, "!important") ||
        strstr(probe, "minmax(") ||
        strstr(probe, "calc(") ||
        strstr(probe, "/*") ||
        strstr(probe, "*/")) {
        return true;
    }
    if (markdownLooksLikeCssSelectorLine(probe)) {
        return true;
    }

    size_t len = strlen(probe);
    if (strcmp(probe, "/") == 0) {
        return true;
    }
    if (strcmp(probe, "-") == 0) {
        return true;
    }
    if (markdownContainsIgnoreCase(probe, "skip to main content") ||
        markdownContainsIgnoreCase(probe, "skip to footer")) {
        return true;
    }
    if (strcmp(probe, "[") == 0 || strcmp(probe, "]") == 0) {
        return true;
    }
    if (strncmp(probe, "](#", 3) == 0 || strncmp(probe, "[#", 2) == 0) {
        return true;
    }
    if (strncmp(probe, "](", 2) == 0) {
        const char *target = probe + 2;
        const char *close = strchr(target, ')');
        if (close && close > target) {
            size_t target_len = (size_t)(close - target);
            if ((target_len >= 7 && strncasecmp(target, "http://", 7) == 0) ||
                (target_len >= 8 && strncasecmp(target, "https://", 8) == 0) ||
                (target_len >= 7 && strncasecmp(target, "mailto:", 7) == 0) ||
                target[0] == '/' || target[0] == '#') {
                return true;
            }
        }
    }
    if ((strcmp(probe, "- [") == 0 || strcmp(probe, "* [") == 0 || strcmp(probe, "• [") == 0)) {
        return true;
    }
    if (markdownContainsIgnoreCase(probe, "@-webkit-keyframes") ||
        markdownContainsIgnoreCase(probe, "@keyframes")) {
        return true;
    }
    if (probe[0] == '@' &&
        (markdownContainsIgnoreCase(probe, "keyframes") || markdownContainsIgnoreCase(probe, "media"))) {
        return true;
    }
    if (probe[0] == '/' && strchr(probe, ' ') && !strstr(probe, "://")) {
        return true;
    }
    if (strcmp(probe, "{") == 0 || strcmp(probe, "}") == 0 ||
        strcmp(probe, "};") == 0 || strcmp(probe, "{;") == 0) {
        return true;
    }
    if (len > 4 && probe[0] == '/' && strchr(probe, ' ') && strchr(probe + 1, '/')) {
        return true;
    }
    if (strstr(probe, ":where(") || strstr(probe, ":has(") || strstr(probe, "::")) {
        return true;
    }
    if (strchr(probe, '{') &&
        (strchr(probe, '.') || strchr(probe, '#') || strchr(probe, '[') || strchr(probe, ':') ||
         strchr(probe, '>') || strchr(probe, '~') || strchr(probe, '+') ||
         strstr(probe, "html") || strstr(probe, "body") || strstr(probe, "dialog") || strstr(probe, "button"))) {
        return true;
    }
    if (len > 8 && probe[len - 1] == ',' &&
        (strchr(probe, '.') || strchr(probe, '[') || strchr(probe, ':'))) {
        return true;
    }
    if (len > 1 && len <= 6 && probe[len - 1] == ',' &&
        isalpha((unsigned char)probe[0]) && !strstr(probe, "://")) {
        bool tiny_selector = true;
        for (size_t i = 0; i + 1 < len; ++i) {
            unsigned char ch = (unsigned char)probe[i];
            if (!(isalnum(ch) || ch == '-' || ch == '_')) {
                tiny_selector = false;
                break;
            }
        }
        if (tiny_selector) {
            return true;
        }
    }
    int comma_count = 0;
    for (const char *p = probe; *p; ++p) {
        if (*p == ',') {
            comma_count++;
        }
    }
    if (comma_count >= 2 &&
        (strchr(probe, '.') || strchr(probe, '[') || strchr(probe, ':') || strstr(probe, "button") || strstr(probe, "html"))) {
        return true;
    }
    if (len > 2 && probe[0] == '-' && probe[1] == '-' && strchr(probe, ':')) {
        return true;
    }
    if ((probe[0] == '.' || probe[0] == '#' || probe[0] == '[' || probe[0] == ':' || probe[0] == '@') &&
        strchr(probe, '{')) {
        return true;
    }
    if (len < 28) {
        return false;
    }

    size_t visible = 0;
    size_t punctuation = 0;
    size_t letters = 0;
    for (const char *p = probe; *p; ++p) {
        unsigned char ch = (unsigned char)*p;
        if (isspace(ch)) {
            continue;
        }
        visible++;
        if (isalnum(ch)) {
            if (isalpha(ch)) {
                letters++;
            }
        } else {
            punctuation++;
        }
    }
    if (visible == 0) {
        return false;
    }

    bool css_shape = (strchr(probe, '{') && strchr(probe, '}') &&
                      strchr(probe, ':') && strchr(probe, ';'));
    bool js_shape = (strstr(probe, "=>") || strstr(probe, "function(") || strstr(probe, "||") || strstr(probe, "&&"));
    if (css_shape || js_shape) {
        return true;
    }

    const char *colon = strchr(probe, ':');
    const char *semi = strchr(probe, ';');
    if (colon && semi && colon < semi &&
        !strstr(probe, "http://") && !strstr(probe, "https://")) {
        const char *next_colon = strchr(semi + 1, ':');
        if (next_colon) {
            return true;
        }
        size_t prop_len = (size_t)(colon - probe);
        if (prop_len > 0 && prop_len <= 40) {
            bool prop_ok = true;
            bool has_letter = false;
            for (size_t i = 0; i < prop_len; ++i) {
                unsigned char ch = (unsigned char)probe[i];
                if (isspace(ch) || ch == '-' || ch == '_') {
                    continue;
                }
                if (isalpha(ch)) {
                    has_letter = true;
                    continue;
                }
                prop_ok = false;
                break;
            }
            if (prop_ok && has_letter) {
                return true;
            }
        }
    }

    int css_hits = 0;
    if (markdownContainsIgnoreCase(probe, "display:")) css_hits++;
    if (markdownContainsIgnoreCase(probe, "margin-")) css_hits++;
    if (markdownContainsIgnoreCase(probe, "padding")) css_hits++;
    if (markdownContainsIgnoreCase(probe, "max-width")) css_hits++;
    if (markdownContainsIgnoreCase(probe, "min-width")) css_hits++;
    if (markdownContainsIgnoreCase(probe, "min-height")) css_hits++;
    if (markdownContainsIgnoreCase(probe, "max-height")) css_hits++;
    if (markdownContainsIgnoreCase(probe, "height:")) css_hits++;
    if (markdownContainsIgnoreCase(probe, "width:")) css_hits++;
    if (markdownContainsIgnoreCase(probe, "overflow")) css_hits++;
    if (markdownContainsIgnoreCase(probe, "font-")) css_hits++;
    if (markdownContainsIgnoreCase(probe, "line-height")) css_hits++;
    if (markdownContainsIgnoreCase(probe, "letter-spacing")) css_hits++;
    if (markdownContainsIgnoreCase(probe, "background")) css_hits++;
    if (markdownContainsIgnoreCase(probe, "border")) css_hits++;
    if (markdownContainsIgnoreCase(probe, "opacity:")) css_hits++;
    if (markdownContainsIgnoreCase(probe, "transform:")) css_hits++;
    if (markdownContainsIgnoreCase(probe, "position:")) css_hits++;
    if (markdownContainsIgnoreCase(probe, "text-align")) css_hits++;
    if (markdownContainsIgnoreCase(probe, "grid-")) css_hits++;
    if (markdownContainsIgnoreCase(probe, "align-")) css_hits++;
    if (markdownContainsIgnoreCase(probe, "justify-")) css_hits++;
    if (markdownContainsIgnoreCase(probe, "object-fit")) css_hits++;
    if (css_hits >= 2) {
        return true;
    }
    if (css_hits >= 1 && strchr(probe, ';') && strchr(probe, ':')) {
        return true;
    }

    /* Dense symbol-heavy lines with very low natural-language signal. */
    return (punctuation * 100 / visible) >= 28 && letters * 100 / visible < 60;
}

static bool markdownShouldStartCssNoiseBlock(const char *line) {
    if (!line || !*line) {
        return false;
    }
    const char *probe = markdownSkipSoftWhitespace(line);
    if (!*probe) {
        return false;
    }
    if (strstr(probe, "!important") ||
        strstr(probe, "var(--") ||
        strstr(probe, "@media") ||
        strstr(probe, "@keyframes") ||
        strstr(probe, "@-webkit-keyframes") ||
        strstr(probe, ":root") ||
        strstr(probe, "calc(") ||
        strstr(probe, "minmax(") ||
        strstr(probe, ":where(") ||
        strstr(probe, ":has(") ||
        strstr(probe, "::") ||
        strstr(probe, "/*") ||
        strstr(probe, "*/")) {
        return true;
    }
    if (markdownLooksLikeCssSelectorLine(probe)) {
        return true;
    }
    if ((probe[0] == '-' && probe[1] == '-') || probe[0] == '.' || probe[0] == '#' ||
        probe[0] == '[' || probe[0] == ':' || probe[0] == '@') {
        return true;
    }
    if (probe[0] == '/' && strchr(probe, ' ') && !strstr(probe, "://")) {
        return true;
    }
    size_t len = strlen(probe);
    if (len > 0 && probe[len - 1] == ',' &&
        (strchr(probe, '.') || strchr(probe, '[') || strchr(probe, ':'))) {
        return true;
    }
    return strchr(probe, '{') || strchr(probe, '}');
}

static int markdownRenderStream(const char *label, FILE *input, FILE *output) {
    if (!input || !output) {
        return 1;
    }
    char *line = NULL;
    size_t line_cap = 0;
    ssize_t line_len;
    char code_fence = '\0';
    bool in_table = false;
    char *paragraph = NULL;
    size_t paragraph_len = 0;
    size_t paragraph_cap = 0;
    MarkdownTableRow table_rows[MARKDOWN_MAX_TABLE_ROWS];
    int table_row_count = 0;
    bool has_blank_separator = false;
    bool suppress_script_block = false;
    bool suppress_style_block = false;
    bool suppress_css_noise_block = false;
    bool fragmented_link_active = false;
    char fragmented_link_prefix[8] = {0};
    char fragmented_link_text[4096] = {0};
    size_t fragmented_link_text_len = 0;
    int fragmented_link_line_count = 0;
    bool fragmented_link_label_locked = false;
    char fragmented_link_meta[512] = {0};
    bool paragraph_link_only_chain = false;

    if (label && *label) {
        fprintf(output, "%s\n", label);
        size_t underline_len = strlen(label);
        if (underline_len > MARKDOWN_WRAP_WIDTH) {
            underline_len = MARKDOWN_WRAP_WIDTH;
        }
        for (size_t i = 0; i < underline_len; ++i) {
            fputc('=', output);
        }
        fputc('\n', output);
        fputc('\n', output);
        has_blank_separator = true;
    }

    while (true) {
        int read_err = 0;
        line_len = smallclueGetlineStream(&line, &line_cap, input, &read_err);
        if (line_len < 0) {
            break;
        }
        while (line_len > 0 && (line[line_len - 1] == '\n' || line[line_len - 1] == '\r')) {
            line[--line_len] = '\0';
        }
        for (char *p = line; *p; ++p) {
            if (*p == '\t') {
                *p = ' ';
            }
        }
        char *trimmed = line;
        while (*trimmed && isspace((unsigned char)*trimmed)) {
            trimmed++;
        }
        char *end = trimmed + strlen(trimmed);
        while (end > trimmed && isspace((unsigned char)end[-1])) {
            *--end = '\0';
        }
        char reconstructed_line[8192];
        reconstructed_line[0] = '\0';
        char normalized_line[8192];
        normalized_line[0] = '\0';
        const char *fragment_prefix = NULL;
        if (fragmented_link_active) {
            if (*trimmed == '\0') {
                continue;
            }
            if (markdownIsFragmentedLinkOpen(trimmed, &fragment_prefix)) {
                snprintf(fragmented_link_prefix, sizeof(fragmented_link_prefix), "%s", fragment_prefix ? fragment_prefix : "");
                fragmented_link_text[0] = '\0';
                fragmented_link_text_len = 0;
                fragmented_link_line_count = 0;
                fragmented_link_label_locked = false;
                fragmented_link_meta[0] = '\0';
                continue;
            }
            char close_target[2048];
            const char *close_suffix = NULL;
            if (markdownParseFragmentedLinkClose(trimmed, close_target, sizeof(close_target), &close_suffix)) {
                const char *suffix_probe = markdownSkipSoftWhitespace(close_suffix ? close_suffix : "");
                bool chained_open = (*suffix_probe == '[');
                bool suppress_target = (close_target[0] == '#') ||
                                       (strncasecmp(close_target, "javascript:", 11) == 0);
                if (!suppress_target && fragmented_link_text_len > 0) {
                    if (fragmented_link_meta[0] != '\0') {
                        if (in_table) {
                            markdownRenderTable(output, table_rows, table_row_count);
                            table_row_count = 0;
                            in_table = false;
                            has_blank_separator = true;
                            paragraph_link_only_chain = false;
                        }
                        if (paragraph_len > 0) {
                            markdownFlushParagraph(output, &paragraph, &paragraph_len);
                            has_blank_separator = true;
                            paragraph_link_only_chain = false;
                        }
                        char *meta_formatted = markdownSimplifyInline(fragmented_link_meta);
                        if (meta_formatted && *meta_formatted) {
                            fprintf(output, "%s\n", meta_formatted);
                            has_blank_separator = false;
                        }
                        free(meta_formatted);
                    }
                    if (close_suffix && *close_suffix && !chained_open) {
                        snprintf(reconstructed_line, sizeof(reconstructed_line), "%s[%s](%s) %s",
                                 fragmented_link_prefix, fragmented_link_text, close_target, close_suffix);
                    } else {
                        snprintf(reconstructed_line, sizeof(reconstructed_line), "%s[%s](%s)",
                                 fragmented_link_prefix, fragmented_link_text, close_target);
                    }
                    trimmed = reconstructed_line;
                } else {
                    trimmed = "";
                }
                fragmented_link_active = chained_open;
                fragmented_link_prefix[0] = '\0';
                fragmented_link_text[0] = '\0';
                fragmented_link_text_len = 0;
                fragmented_link_line_count = 0;
                fragmented_link_label_locked = false;
                fragmented_link_meta[0] = '\0';
                if (*trimmed == '\0') {
                    continue;
                }
            } else {
                if (markdownIsHorizontalRule(trimmed) && fragmented_link_text_len > 0) {
                    fragmented_link_label_locked = true;
                    continue;
                }
                if (fragmented_link_label_locked) {
                    continue;
                }
                if (strcmp(trimmed, "[") != 0 && strcmp(trimmed, "]") != 0) {
                    char label_piece[4096];
                    char meta_piece[512];
                    if (!markdownExtractFragmentLinkLabel(trimmed,
                                                          label_piece, sizeof(label_piece),
                                                          meta_piece, sizeof(meta_piece))) {
                        if (meta_piece[0] != '\0' && fragmented_link_meta[0] == '\0') {
                            snprintf(fragmented_link_meta, sizeof(fragmented_link_meta), "%s", meta_piece);
                        }
                        continue;
                    }
                    if (meta_piece[0] != '\0' && fragmented_link_meta[0] == '\0') {
                        snprintf(fragmented_link_meta, sizeof(fragmented_link_meta), "%s", meta_piece);
                    }
                    if (fragmented_link_line_count < 1) {
                        markdownAppendTokenFixed(fragmented_link_text, &fragmented_link_text_len,
                                                 sizeof(fragmented_link_text), label_piece);
                        fragmented_link_line_count++;
                    }
                }
                continue;
            }
        } else {
            char close_target[2048];
            const char *close_suffix = NULL;
            if (markdownParseFragmentedLinkClose(trimmed, close_target, sizeof(close_target), &close_suffix)) {
                const char *suffix_probe = markdownSkipSoftWhitespace(close_suffix ? close_suffix : "");
                if (*suffix_probe == '[') {
                    fragmented_link_active = true;
                    fragmented_link_prefix[0] = '\0';
                    fragmented_link_text[0] = '\0';
                    fragmented_link_text_len = 0;
                    fragmented_link_line_count = 0;
                    fragmented_link_label_locked = false;
                    fragmented_link_meta[0] = '\0';
                }
                /* Drop dangling close fragments like ](/...) and ](/...)[ */
                continue;
            }
            if (markdownIsFragmentedLinkOpen(trimmed, &fragment_prefix)) {
                fragmented_link_active = true;
                snprintf(fragmented_link_prefix, sizeof(fragmented_link_prefix), "%s", fragment_prefix ? fragment_prefix : "");
                fragmented_link_text[0] = '\0';
                fragmented_link_text_len = 0;
                fragmented_link_line_count = 0;
                fragmented_link_label_locked = false;
                fragmented_link_meta[0] = '\0';
                continue;
            }
        }

        markdownNormalizeDisplaySpacing(trimmed, normalized_line, sizeof(normalized_line));
        if (normalized_line[0]) {
            trimmed = normalized_line;
        }

        if (code_fence == '\0') {
        if (suppress_css_noise_block) {
            if (*trimmed == '\0') {
                suppress_css_noise_block = false;
                continue;
            }
            if (markdownLooksLikeWebNoiseLine(trimmed)) {
                continue;
            }
            suppress_css_noise_block = false;
        }

        if (suppress_script_block) {
            if (markdownContainsIgnoreCase(trimmed, "</script")) {
                suppress_script_block = false;
            }
            continue;
        }
        if (suppress_style_block) {
            if (markdownContainsIgnoreCase(trimmed, "</style")) {
                suppress_style_block = false;
            }
            continue;
        }
        if (markdownContainsIgnoreCase(trimmed, "<script")) {
            if (!markdownContainsIgnoreCase(trimmed, "</script")) {
                suppress_script_block = true;
            }
            if (in_table) {
                markdownRenderTable(output, table_rows, table_row_count);
                table_row_count = 0;
                in_table = false;
                has_blank_separator = true;
                paragraph_link_only_chain = false;
            }
            if (paragraph_len > 0) {
                markdownFlushParagraph(output, &paragraph, &paragraph_len);
                has_blank_separator = true;
                paragraph_link_only_chain = false;
            }
            continue;
        }
        if (markdownContainsIgnoreCase(trimmed, "<style")) {
            if (!markdownContainsIgnoreCase(trimmed, "</style")) {
                suppress_style_block = true;
            }
            if (in_table) {
                markdownRenderTable(output, table_rows, table_row_count);
                table_row_count = 0;
                in_table = false;
                has_blank_separator = true;
                paragraph_link_only_chain = false;
            }
            if (paragraph_len > 0) {
                markdownFlushParagraph(output, &paragraph, &paragraph_len);
                has_blank_separator = true;
                paragraph_link_only_chain = false;
            }
            continue;
        }
        if (strchr(trimmed, ':') && strchr(trimmed, ';') &&
            !strstr(trimmed, "http://") && !strstr(trimmed, "https://") &&
            !strstr(trimmed, "](")) {
            if (in_table) {
                markdownRenderTable(output, table_rows, table_row_count);
                table_row_count = 0;
                in_table = false;
                has_blank_separator = true;
                paragraph_link_only_chain = false;
            }
            if (paragraph_len > 0) {
                markdownFlushParagraph(output, &paragraph, &paragraph_len);
                has_blank_separator = true;
                paragraph_link_only_chain = false;
            }
            if (markdownShouldStartCssNoiseBlock(trimmed)) {
                suppress_css_noise_block = true;
            }
            continue;
        }
        if (markdownLooksLikeWebNoiseLine(trimmed)) {
            if (markdownShouldStartCssNoiseBlock(trimmed)) {
                suppress_css_noise_block = true;
            }
            if (in_table) {
                markdownRenderTable(output, table_rows, table_row_count);
                table_row_count = 0;
                in_table = false;
                has_blank_separator = true;
                paragraph_link_only_chain = false;
            }
            if (paragraph_len > 0) {
                markdownFlushParagraph(output, &paragraph, &paragraph_len);
                has_blank_separator = true;
                paragraph_link_only_chain = false;
            }
            continue;
        }
        }

        char fence = markdownFenceMarker(trimmed);
        if (fence != '\0') {
            bool had_paragraph = paragraph_len > 0;
            markdownFlushParagraph(output, &paragraph, &paragraph_len);
            if (had_paragraph) {
                has_blank_separator = true;
                paragraph_link_only_chain = false;
            }
            if (code_fence == '\0') {
                code_fence = fence;
                has_blank_separator = false;
            } else if (code_fence == fence) {
                code_fence = '\0';
                fputc('\n', output);
                has_blank_separator = true;
            }
            continue;
        }

        if (code_fence != '\0') {
            /* Preserve leading whitespace/tabs inside fenced code blocks. */
            fprintf(output, "    %s\n", line);
            has_blank_separator = false;
            continue;
        }

        if (*trimmed == '\0') {
            if (in_table) {
                markdownRenderTable(output, table_rows, table_row_count);
                table_row_count = 0;
                in_table = false;
                has_blank_separator = true;
                paragraph_link_only_chain = false;
            }
            if (paragraph_len > 0) {
                markdownFlushParagraph(output, &paragraph, &paragraph_len);
                has_blank_separator = true;
                paragraph_link_only_chain = false;
            } else if (!has_blank_separator) {
                fputc('\n', output);
                has_blank_separator = true;
            }
            paragraph_link_only_chain = false;
            continue;
        }

        int setext_heading = markdownSetextHeadingLevel(trimmed);
        if (setext_heading > 0 && paragraph_len > 0) {
            if (in_table) {
                markdownRenderTable(output, table_rows, table_row_count);
                table_row_count = 0;
                in_table = false;
                has_blank_separator = true;
                paragraph_link_only_chain = false;
            }
            paragraph[paragraph_len] = '\0';
            char *heading_text = markdownTrimInline(paragraph);
            if (heading_text && *heading_text) {
                markdownWriteHeading(output, heading_text, setext_heading);
                has_blank_separator = true;
            }
            paragraph_len = 0;
            paragraph[0] = '\0';
            paragraph_link_only_chain = false;
            continue;
        }

        if (markdownIsHorizontalRule(trimmed)) {
            bool had_paragraph = paragraph_len > 0;
            markdownFlushParagraph(output, &paragraph, &paragraph_len);
            if (had_paragraph) {
                has_blank_separator = true;
                paragraph_link_only_chain = false;
            }
            for (int i = 0; i < MARKDOWN_WRAP_WIDTH; ++i) {
                fputc('-', output);
            }
            fputc('\n', output);
            fputc('\n', output);
            has_blank_separator = true;
            continue;
        }

        int heading = markdownHeadingLevel(trimmed);
        if (heading > 0) {
            if (in_table) {
                markdownRenderTable(output, table_rows, table_row_count);
                table_row_count = 0;
                in_table = false;
                has_blank_separator = true;
                paragraph_link_only_chain = false;
            }
            bool had_paragraph = paragraph_len > 0;
            markdownFlushParagraph(output, &paragraph, &paragraph_len);
            if (had_paragraph) {
                has_blank_separator = true;
                paragraph_link_only_chain = false;
            }
            const char *heading_text = trimmed + heading;
            while (*heading_text == ' ' || *heading_text == '\t') heading_text++;
            markdownWriteHeading(output, heading_text, heading);
            has_blank_separator = true;
            continue;
        }

        if (*trimmed == '>') {
            if (in_table) {
                markdownRenderTable(output, table_rows, table_row_count);
                table_row_count = 0;
                in_table = false;
                has_blank_separator = true;
                paragraph_link_only_chain = false;
            }
            bool had_paragraph = paragraph_len > 0;
            markdownFlushParagraph(output, &paragraph, &paragraph_len);
            if (had_paragraph) {
                has_blank_separator = true;
                paragraph_link_only_chain = false;
            }
            char *quote = trimmed + 1;
            while (*quote == ' ' || *quote == '\t') quote++;
            char *formatted = markdownSimplifyInline(quote);
            if (formatted) {
                markdownWrapAndWrite(output, formatted, "> ", "> ", MARKDOWN_WRAP_WIDTH);
                free(formatted);
            }
            has_blank_separator = true;
            continue;
        }

        int pipe_count = 0;
        for (const char *p = trimmed; *p; ++p) {
            if (*p == '|') {
                pipe_count++;
            }
        }
        if (pipe_count >= 2) {
            if (!in_table) {
                bool had_paragraph = paragraph_len > 0;
                markdownFlushParagraph(output, &paragraph, &paragraph_len);
                if (had_paragraph) {
                    has_blank_separator = true;
                    paragraph_link_only_chain = false;
                }
                in_table = true;
                table_row_count = 0;
            }
            if (table_row_count < MARKDOWN_MAX_TABLE_ROWS) {
                char *dup = strdup(trimmed);
                if (dup) {
                    markdownParseTableRow(dup, &table_rows[table_row_count]);
                    free(dup);
                    table_row_count++;
                }
            }
            continue;
        } else if (in_table) {
            markdownRenderTable(output, table_rows, table_row_count);
            table_row_count = 0;
            in_table = false;
            has_blank_separator = true;
            paragraph_link_only_chain = false;
        }

        char *list_text = NULL;
        char prefix_first[32];
        char prefix_sub[32];
        if (markdownExtractListItem(line, &list_text, prefix_first, sizeof(prefix_first), prefix_sub, sizeof(prefix_sub))) {
            bool had_paragraph = paragraph_len > 0;
            markdownFlushParagraph(output, &paragraph, &paragraph_len);
            if (had_paragraph) {
                has_blank_separator = true;
                paragraph_link_only_chain = false;
            }
            char *formatted = markdownSimplifyInline(list_text);
            if (formatted) {
                markdownWrapAndWrite(output, formatted, prefix_first, prefix_sub, MARKDOWN_WRAP_WIDTH);
                free(formatted);
            }
            has_blank_separator = false;
            paragraph_link_only_chain = false;
            continue;
        }
        bool link_only_line = markdownLineLooksLikeLinkOnly(trimmed);
        const char *separator = " ";
        if (paragraph_len > 0 && paragraph_link_only_chain && link_only_line) {
            separator = " · ";
        }
        markdownParagraphAppendWithSeparator(&paragraph, &paragraph_len, &paragraph_cap, trimmed, separator);
        paragraph_link_only_chain = link_only_line;
        has_blank_separator = false;
    }

    bool had_paragraph = paragraph_len > 0;
    markdownFlushParagraph(output, &paragraph, &paragraph_len);
    if (had_paragraph) {
        has_blank_separator = true;
        paragraph_link_only_chain = false;
    }
    if (in_table) {
        markdownRenderTable(output, table_rows, table_row_count);
        has_blank_separator = true;
    }
    free(paragraph);
    free(line);
    return 0;
}

static int markdownResolvePath(const char *input, char *resolved, size_t resolved_size) {
    if (!input || !resolved || resolved_size == 0) {
        errno = EINVAL;
        return -1;
    }
    if (strcmp(input, "-") == 0) {
        errno = EINVAL;
        return -1;
    }
    struct stat st;
    if (stat(input, &st) == 0 && S_ISREG(st.st_mode)) {
        if (realpath(input, resolved)) {
            return 0;
        }
        strncpy(resolved, input, resolved_size - 1);
        resolved[resolved_size - 1] = '\0';
        return 0;
    }
    if (strchr(input, '/')) {
        return -1;
    }
    const char *home = getenv("HOME");
    if (!home || !*home) {
        return -1;
    }
    char docs_directory[PATH_MAX];
    if (smallclueBuildPath(docs_directory, sizeof(docs_directory), home, "Docs") != 0) {
        return -1;
    }
    char candidate[PATH_MAX];
    if (smallclueBuildPath(candidate, sizeof(candidate), docs_directory, input) == 0 &&
        stat(candidate, &st) == 0 && S_ISREG(st.st_mode)) {
        strncpy(resolved, candidate, resolved_size - 1);
        resolved[resolved_size - 1] = '\0';
        return 0;
    }
    char with_ext[PATH_MAX];
    snprintf(with_ext, sizeof(with_ext), "%s.md", input);
    if (smallclueBuildPath(candidate, sizeof(candidate), docs_directory, with_ext) == 0 &&
        stat(candidate, &st) == 0 && S_ISREG(st.st_mode)) {
        strncpy(resolved, candidate, resolved_size - 1);
        resolved[resolved_size - 1] = '\0';
        return 0;
    }
    return -1;
}

static bool markdownHasHtmlExtension(const char *path) {
    if (!path) {
        return false;
    }
    const char *dot = strrchr(path, '.');
    if (!dot) {
        return false;
    }
    return strcasecmp(dot, ".html") == 0 || strcasecmp(dot, ".htm") == 0;
}

static MarkdownInputMode markdownInputModeForFilePath(const char *path) {
    return markdownHasHtmlExtension(path) ? MARKDOWN_INPUT_MODE_HTML : MARKDOWN_INPUT_MODE_MARKDOWN;
}

static int smallclueMarkdownDisplayDataEx(const char *label,
                                          const char *raw_data,
                                          MarkdownInputMode input_mode,
                                          MarkdownLinkList *links_out,
                                          int *exit_key_out,
                                          int *selected_link_index_out) {
    if (exit_key_out) {
        *exit_key_out = 'q';
    }
    if (selected_link_index_out) {
        *selected_link_index_out = -1;
    }

    const char *source_data = raw_data ? raw_data : "";
    char *converted_html = NULL;
    const char *render_source = source_data;
    bool convert_html = (input_mode == MARKDOWN_INPUT_MODE_HTML) ||
                        (input_mode == MARKDOWN_INPUT_MODE_AUTO && markdownIsLikelyHtmlDocument(source_data));
    if (convert_html) {
        converted_html = markdownConvertHtmlToMarkdownish(source_data);
        if (converted_html) {
            render_source = converted_html;
        }
    }

    FILE *source = tmpfile();
    if (!source) {
        free(converted_html);
        return 1;
    }
    if (*render_source) {
        size_t source_len = strlen(render_source);
        if (fwrite(render_source, 1, source_len, source) != source_len) {
            fclose(source);
            free(converted_html);
            return 1;
        }
    }
    fflush(source);
    rewind(source);

    FILE *buffer = tmpfile();
    bool direct = false;
    if (!buffer) {
        buffer = stdout;
        direct = true;
    }

    MarkdownLinkList *previous_links = gMarkdownActiveLinks;
    gMarkdownActiveLinks = links_out;
    int render_status = markdownRenderStream(label, source, buffer);
    gMarkdownActiveLinks = previous_links;
    fclose(source);
    free(converted_html);

    if (render_status != 0) {
        if (!direct) {
            fclose(buffer);
        }
        return 1;
    }
    if (direct) {
        fflush(buffer);
        if (exit_key_out) {
            *exit_key_out = 'q';
        }
        return 0;
    }
    fflush(buffer);
    rewind(buffer);
    const MarkdownLinkList *prev_active_links = pager_active_md_links;
    pagerSetActiveMarkdownLinks(links_out);
    int status = pager_file("md", label ? label : "(stdin)", buffer);
    pagerSetActiveMarkdownLinks(prev_active_links);
    if (exit_key_out) {
        *exit_key_out = pagerLastExitKey();
    }
    if (selected_link_index_out) {
        *selected_link_index_out = pagerLastMdLinkIndex();
    }
    fclose(buffer);
    return status;
}

static int smallclueMarkdownDisplayStreamEx(const char *label,
                                            FILE *input,
                                            MarkdownInputMode input_mode,
                                            MarkdownLinkList *links_out,
                                            int *exit_key_out,
                                            int *selected_link_index_out) {
    if (exit_key_out) {
        *exit_key_out = 'q';
    }
    if (selected_link_index_out) {
        *selected_link_index_out = -1;
    }
    if (!input) {
        return 1;
    }

    char *raw_data = NULL;
    size_t raw_len = 0;
    if (markdownReadAll(input, &raw_data, &raw_len) != 0) {
        return 1;
    }
    (void)raw_len;
    int status = smallclueMarkdownDisplayDataEx(label,
                                                raw_data,
                                                input_mode,
                                                links_out,
                                                exit_key_out,
                                                selected_link_index_out);
    free(raw_data);
    return status;
}

static bool markdownIsRemoteTarget(const char *target) {
    if (!target) {
        return false;
    }
    return strncasecmp(target, "http://", 7) == 0 ||
           strncasecmp(target, "https://", 8) == 0;
}

static bool markdownLooksLikeUrl(const char *value) {
    if (!value) {
        return false;
    }
    return markdownIsRemoteTarget(value) ||
           strncasecmp(value, "mailto:", 7) == 0;
}

static int markdownFetchUrlToMemory(const char *url, char **data_out, size_t *len_out) {
    if (!url || !data_out || !len_out) {
        errno = EINVAL;
        return -1;
    }
    *data_out = NULL;
    *len_out = 0;
    if (smallclueHttpFetchToMemory("md", url, data_out, len_out) != 0) {
        if (*data_out) {
            free(*data_out);
            *data_out = NULL;
        }
        *len_out = 0;
        errno = EIO;
        return -1;
    }
    return 0;
}

static char *markdownResolveLinkTarget(const char *base, const char *href) {
    if (!href || !*href) {
        return NULL;
    }
    while (*href && isspace((unsigned char)*href)) {
        href++;
    }
    if (*href == '\0') {
        return NULL;
    }
    if (href[0] == '#') {
        return base ? strdup(base) : NULL;
    }
    if (markdownLooksLikeUrl(href)) {
        return strdup(href);
    }
    if (base && markdownIsRemoteTarget(base)) {
        const char *scheme_end = strstr(base, "://");
        if (!scheme_end) {
            return strdup(href);
        }
        if (strncmp(href, "//", 2) == 0) {
            size_t scheme_len = (size_t)(scheme_end - base);
            size_t href_len = strlen(href);
            char *combined = (char *)malloc(scheme_len + 1 + href_len + 1);
            if (!combined) {
                return NULL;
            }
            memcpy(combined, base, scheme_len);
            combined[scheme_len] = ':';
            memcpy(combined + scheme_len + 1, href, href_len + 1);
            return combined;
        }
        const char *origin_end = strchr(scheme_end + 3, '/');
        size_t origin_len = origin_end ? (size_t)(origin_end - base) : strlen(base);
        if (href[0] == '/') {
            size_t href_len = strlen(href);
            char *combined = (char *)malloc(origin_len + href_len + 1);
            if (!combined) {
                return NULL;
            }
            memcpy(combined, base, origin_len);
            memcpy(combined + origin_len, href, href_len + 1);
            return combined;
        }

        char base_copy[PATH_MAX * 2];
        strncpy(base_copy, base, sizeof(base_copy) - 1);
        base_copy[sizeof(base_copy) - 1] = '\0';
        char *query = strchr(base_copy, '?');
        if (query) *query = '\0';
        char *fragment = strchr(base_copy, '#');
        if (fragment) *fragment = '\0';
        char *last_slash = strrchr(base_copy, '/');
        if (!last_slash || (size_t)(last_slash - base_copy) < origin_len) {
            size_t copy_len = origin_len;
            if (copy_len + 1 >= sizeof(base_copy)) {
                return NULL;
            }
            base_copy[copy_len] = '/';
            base_copy[copy_len + 1] = '\0';
        } else {
            last_slash[1] = '\0';
        }
        size_t dir_len = strlen(base_copy);
        size_t href_len = strlen(href);
        char *combined = (char *)malloc(dir_len + href_len + 1);
        if (!combined) {
            return NULL;
        }
        memcpy(combined, base_copy, dir_len);
        memcpy(combined + dir_len, href, href_len + 1);
        return combined;
    }

    if (href[0] == '/') {
        return strdup(href);
    }

    if (base && *base) {
        char resolved_base[PATH_MAX];
        const char *base_path = base;
        if (!markdownIsRemoteTarget(base) && markdownResolvePath(base, resolved_base, sizeof(resolved_base)) == 0) {
            base_path = resolved_base;
        }
        char work[PATH_MAX];
        strncpy(work, base_path, sizeof(work) - 1);
        work[sizeof(work) - 1] = '\0';
        char *slash = strrchr(work, '/');
        if (slash) {
            slash[1] = '\0';
        } else {
            work[0] = '\0';
        }
        size_t work_len = strlen(work);
        size_t href_len = strlen(href);
        char *combined = (char *)malloc(work_len + href_len + 1);
        if (!combined) {
            return NULL;
        }
        memcpy(combined, work, work_len);
        memcpy(combined + work_len, href, href_len + 1);
        return combined;
    }
    return strdup(href);
}

static int markdownInteractiveSelectLink(const MarkdownLinkList *links, const char *source_label) {
    if (!links || links->count == 0) {
        return -1;
    }
    size_t cursor = 0;
    size_t top = 0;
    bool running = true;

    while (running) {
        int rows = pager_terminal_rows();
        int cols = pager_terminal_cols();
        if (rows < 1) rows = 1;
        size_t reserved = 2;
        size_t window = (size_t)rows > reserved ? (size_t)rows - reserved : 1;
        if (window > links->count) window = links->count;

        if (cursor < top) top = cursor;
        if (cursor >= top + window) top = cursor - window + 1;
        if (top + window > links->count) {
            top = (links->count > window) ? (links->count - window) : 0;
        }

        printf("\x1b[2J\x1b[H");
        if (source_label && *source_label) {
            printf("Links in %s (%zu/%zu)  [Arrows=move Enter=open q=cancel]\n",
                   source_label, cursor + 1, links->count);
        } else {
            printf("Links (%zu/%zu)  [Arrows=move Enter=open q=cancel]\n",
                   cursor + 1, links->count);
        }

        size_t end = top + window;
        if (end > links->count) end = links->count;
        for (size_t i = top; i < end; ++i) {
            bool active = (i == cursor);
            const char *text = links->items[i].text ? links->items[i].text : "(link)";
            const char *target = links->items[i].target ? links->items[i].target : "";
            char line[PATH_MAX * 3];
            snprintf(line, sizeof(line), "%3zu. %s (%s)", i + 1, text, target);
            if (active) printf("\x1b[7m");
            if (cols > 0 && (int)strlen(line) > cols) {
                if (cols > 3) {
                    fwrite(line, 1, (size_t)(cols - 3), stdout);
                    fputs("...", stdout);
                } else {
                    fwrite(line, 1, (size_t)cols, stdout);
                }
                fputc('\n', stdout);
            } else {
                printf("%s\n", line);
            }
            if (active) printf("\x1b[0m");
        }
        fflush(stdout);

        int key = pager_read_key();
        switch (key) {
            case PAGER_KEY_ARROW_DOWN:
                if (cursor + 1 < links->count) cursor++;
                else pagerBell();
                break;
            case PAGER_KEY_ARROW_UP:
                if (cursor > 0) cursor--;
                else pagerBell();
                break;
            case PAGER_KEY_PAGE_DOWN:
            case ' ':
                if (cursor + window < links->count) cursor += window;
                else if (cursor + 1 < links->count) cursor = links->count - 1;
                else pagerBell();
                break;
            case PAGER_KEY_PAGE_UP:
            case 'b':
            case 'B':
                if (cursor >= window) cursor -= window;
                else if (cursor > 0) cursor = 0;
                else pagerBell();
                break;
            case '\n':
            case '\r':
                printf("\x1b[2J\x1b[H");
                fflush(stdout);
                return (int)cursor;
            case 'q':
            case 'Q':
            case 3:
                printf("\x1b[2J\x1b[H");
                fflush(stdout);
                return -1;
            default:
                break;
        }
    }
    return -1;
}

static int smallclueMarkdownBrowseTarget(const char *initial_target) {
    if (!initial_target || !*initial_target) {
        return 1;
    }

    char **stack = NULL;
    size_t depth = 0;
    size_t capacity = 0;
    int overall_status = 0;

    char *root = strdup(initial_target);
    if (!root) {
        return 1;
    }
    capacity = 4;
    stack = (char **)calloc(capacity, sizeof(char *));
    if (!stack) {
        free(root);
        return 1;
    }
    stack[depth++] = root;

    while (depth > 0) {
        const char *current = stack[depth - 1];
        MarkdownLinkList links = {0};
        int exit_key = 'q';
        int selected_link_index = -1;
        int status = 0;

        if (markdownIsRemoteTarget(current)) {
            char *remote_data = NULL;
            size_t remote_len = 0;
            if (markdownFetchUrlToMemory(current, &remote_data, &remote_len) != 0) {
                status = 1;
            } else {
                (void)remote_len;
                status = smallclueMarkdownDisplayDataEx(current,
                                                        remote_data,
                                                        MARKDOWN_INPUT_MODE_AUTO,
                                                        &links,
                                                        &exit_key,
                                                        &selected_link_index);
                free(remote_data);
            }
        } else {
            char resolved[PATH_MAX];
            if (markdownResolvePath(current, resolved, sizeof(resolved)) != 0) {
                fprintf(stderr, "md: %s: %s\n", current, strerror(errno));
                status = 1;
            } else {
                FILE *fp = fopen(resolved, "r");
                if (!fp) {
                    fprintf(stderr, "md: %s: %s\n", resolved, strerror(errno));
                    status = 1;
                } else {
                    status = smallclueMarkdownDisplayStreamEx(resolved,
                                                              fp,
                                                              markdownInputModeForFilePath(resolved),
                                                              &links,
                                                              &exit_key,
                                                              &selected_link_index);
                    fclose(fp);
                }
            }
        }

        if (status != 0) {
            markdownLinkListFree(&links);
            overall_status = 1;
            break;
        }

        if ((exit_key == 'o' || exit_key == 'O')) {
            if (links.count == 0) {
                pagerBell();
                markdownLinkListFree(&links);
                continue;
            }
            int selected = -1;
            if (selected_link_index >= 0 && (size_t)selected_link_index < links.count) {
                selected = selected_link_index;
            } else {
                selected = markdownInteractiveSelectLink(&links, current);
            }
            if (selected >= 0 && (size_t)selected < links.count) {
                char *next_target = markdownResolveLinkTarget(current, links.items[selected].target);
                if (!next_target || !*next_target) {
                    free(next_target);
                    pagerBell();
                    markdownLinkListFree(&links);
                    continue;
                }
                if (markdownLooksLikeUrl(next_target) && !markdownIsRemoteTarget(next_target)) {
                    fprintf(stderr, "md: unsupported link target: %s\n", next_target);
                    free(next_target);
                    markdownLinkListFree(&links);
                    continue;
                }
                if (!markdownIsRemoteTarget(next_target) && !markdownLooksLikeUrl(next_target)) {
                    char resolved_next[PATH_MAX];
                    if (markdownResolvePath(next_target, resolved_next, sizeof(resolved_next)) == 0) {
                        free(next_target);
                        next_target = strdup(resolved_next);
                    }
                }
                if (!next_target) {
                    markdownLinkListFree(&links);
                    overall_status = 1;
                    break;
                }
                if (depth == capacity) {
                    size_t new_capacity = capacity * 2;
                    char **resized = (char **)realloc(stack, new_capacity * sizeof(char *));
                    if (!resized) {
                        free(next_target);
                        markdownLinkListFree(&links);
                        overall_status = 1;
                        break;
                    }
                    stack = resized;
                    capacity = new_capacity;
                }
                stack[depth++] = next_target;
                markdownLinkListFree(&links);
                continue;
            }
            markdownLinkListFree(&links);
            continue;
        }

        markdownLinkListFree(&links);
        if (exit_key == 'q' && depth > 1) {
            free(stack[depth - 1]);
            stack[depth - 1] = NULL;
            depth--;
            continue;
        }
        break;
    }

    for (size_t i = 0; i < depth; ++i) {
        free(stack[i]);
    }
    free(stack);
    return overall_status;
}

static int smallclueMarkdownDisplayPath(const char *path) {
    return smallclueMarkdownBrowseTarget(path);
}

static char *markdownExtractTitle(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) {
        return NULL;
    }
    char *line = NULL;
    size_t cap = 0;
    ssize_t len;
    char *title = NULL;
    while (true) {
        int read_err = 0;
        len = smallclueGetlineStream(&line, &cap, fp, &read_err);
        if (len < 0) {
            break;
        }
        while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = '\0';
        }
        char *trimmed = line;
        while (*trimmed && isspace((unsigned char)*trimmed)) trimmed++;
        if (*trimmed == '\0') {
            continue;
        }
        if (trimmed[0] == '#') {
            while (*trimmed == '#') trimmed++;
            if (*trimmed == ' ' || *trimmed == '\t') trimmed++;
            char *formatted = markdownSimplifyInline(trimmed);
            title = formatted;
            break;
        }
    }
    free(line);
    fclose(fp);
    if (!title) {
        title = strdup("(untitled)");
    }
    return title;
}

static int markdownDocEntryCompare(const void *a, const void *b) {
    const MarkdownDocEntry *left = (const MarkdownDocEntry *)a;
    const MarkdownDocEntry *right = (const MarkdownDocEntry *)b;
    if (!left->name || !right->name) {
        return 0;
    }
    return strcasecmp(left->name, right->name);
}

static int smallclueMarkdownListDocuments(void) {
    MarkdownDocEntry *entries = NULL;
    size_t count = 0;
    char docs_dir[PATH_MAX];
    char docs_dir_display[PATH_MAX];
    const char *visible_docs_dir = NULL;
    if (markdownEnumerateDocuments(&entries, &count, docs_dir, sizeof(docs_dir)) != 0) {
        return 1;
    }
    visible_docs_dir = smallclueDisplayPath(docs_dir, docs_dir_display, sizeof(docs_dir_display));
    if (count == 0) {
        printf("No Markdown documents found in %s\n", visible_docs_dir);
        free(entries);
        return 1;
    }
    qsort(entries, count, sizeof(MarkdownDocEntry), markdownDocEntryCompare);
    printf("Markdown documents in %s:\n\n", visible_docs_dir);
    for (size_t i = 0; i < count; ++i) {
        const char *title = entries[i].title ? entries[i].title : "";
        printf("  %-24s %s\n", entries[i].name ? entries[i].name : "(unknown)", title);
        markdownDocEntryFree(&entries[i]);
    }
    free(entries);
    return 0;
}

static void markdownInteractiveRenderList(MarkdownDocEntry *entries,
                                          size_t count,
                                          size_t top,
                                          size_t cursor,
                                          size_t window,
                                          const char *docs_dir,
                                          int term_cols,
                                          bool show_docs_dir) {
    printf("\x1b[2J\x1b[H");
    char header[256];
    snprintf(header, sizeof(header),
             "Markdown docs (Arrows=move, Enter=open, q=quit) [%zu/%zu]",
             cursor + 1, count);
    if (term_cols > 0 && (int)strlen(header) > term_cols) {
        if (term_cols <= 3) {
            fwrite(header, 1, (size_t)term_cols, stdout);
        } else {
            fwrite(header, 1, (size_t)(term_cols - 3), stdout);
            fputs("...", stdout);
        }
        fputc('\n', stdout);
    } else {
        printf("%s\n", header);
    }
    size_t end = top + window;
    if (end > count) {
        end = count;
    }
    for (size_t idx = top; idx < end; ++idx) {
        char line[PATH_MAX * 2];
        bool highlight = (idx == cursor);
        const char *name = entries[idx].name ? entries[idx].name : "(unknown)";
        const char *title = entries[idx].title ? entries[idx].title : "";
        snprintf(line, sizeof(line), " %-24.24s %s", name, title);
        if (highlight) {
            printf("\x1b[7m");
        }
        if (term_cols > 0 && (int)strlen(line) > term_cols) {
            if (term_cols <= 3) {
                fwrite(line, 1, (size_t)term_cols, stdout);
            } else {
                fwrite(line, 1, (size_t)(term_cols - 3), stdout);
                fputs("...", stdout);
            }
            fputc('\n', stdout);
        } else {
            printf("%s\n", line);
        }
        if (highlight) {
            printf("\x1b[0m");
        }
    }
    if (show_docs_dir) {
        char docs_dir_display[PATH_MAX];
        const char *visible_docs_dir = smallclueDisplayPath(docs_dir, docs_dir_display, sizeof(docs_dir_display));
        char footer[PATH_MAX + 32];
        snprintf(footer, sizeof(footer), "Docs: %s", visible_docs_dir);
        if (term_cols > 0 && (int)strlen(footer) > term_cols) {
            if (term_cols <= 3) {
                fwrite(footer, 1, (size_t)term_cols, stdout);
            } else {
                fwrite(footer, 1, (size_t)(term_cols - 3), stdout);
                fputs("...", stdout);
            }
            fputc('\n', stdout);
        } else {
            printf("%s\n", footer);
        }
    }
    fflush(stdout);
}

static int markdownInteractiveSelectDocument(void) {
    MarkdownDocEntry *entries = NULL;
    size_t count = 0;
    char docs_dir[PATH_MAX];
    char docs_dir_display[PATH_MAX];
    const char *visible_docs_dir = NULL;
    if (markdownEnumerateDocuments(&entries, &count, docs_dir, sizeof(docs_dir)) != 0) {
        return 1;
    }
    visible_docs_dir = smallclueDisplayPath(docs_dir, docs_dir_display, sizeof(docs_dir_display));
    if (count == 0) {
        printf("No Markdown documents found in %s\n", visible_docs_dir);
        free(entries);
        return 1;
    }
    qsort(entries, count, sizeof(MarkdownDocEntry), markdownDocEntryCompare);
    if (!pscalRuntimeStdoutIsInteractive()) {
        printf("Markdown documents in %s:\n\n", visible_docs_dir);
        for (size_t i = 0; i < count; ++i) {
            const char *title = entries[i].title ? entries[i].title : "";
            printf("  %-24s %s\n", entries[i].name ? entries[i].name : "(unknown)", title);
            markdownDocEntryFree(&entries[i]);
        }
        free(entries);
        return 0;
    }

    size_t cursor = 0;
    size_t top = 0;
    char selected[PATH_MAX];
    bool running = true;
    bool has_selection = false;

    while (running) {
        int rows = pager_terminal_rows();
        int cols = pager_terminal_cols();
        if (rows < 1) {
            rows = 1;
        }
        bool show_docs_dir = rows >= 4;
        size_t reserved_lines = show_docs_dir ? 2 : 1; /* header + optional docs footer */
        size_t window = 1;
        if ((size_t)rows > reserved_lines) {
            window = (size_t)rows - reserved_lines;
        }
        if (window > count) {
            window = count;
        }

        if (cursor < top) {
            top = cursor;
        } else if (cursor >= top + window) {
            top = cursor - window + 1;
        }
        if (top + window > count) {
            top = (count > window) ? (count - window) : 0;
        }

        markdownInteractiveRenderList(entries, count, top, cursor, window, docs_dir, cols, show_docs_dir);

        int key = pager_read_key();
        switch (key) {
            case PAGER_KEY_ARROW_DOWN:
                if (cursor + 1 < count) {
                    cursor++;
                } else {
                    pagerBell();
                }
                break;
            case PAGER_KEY_ARROW_UP:
                if (cursor > 0) {
                    cursor--;
                } else {
                    pagerBell();
                }
                break;
            case PAGER_KEY_PAGE_DOWN:
            case ' ':
                if (cursor + window < count) {
                    cursor += window;
                } else if (cursor != count - 1) {
                    cursor = count - 1;
                } else {
                    pagerBell();
                }
                break;
            case PAGER_KEY_PAGE_UP:
                if (cursor >= window) {
                    cursor -= window;
                } else if (cursor != 0) {
                    cursor = 0;
                } else {
                    pagerBell();
                }
                break;
            case '\r':
            case '\n':
                if (entries[cursor].path) {
                    strncpy(selected, entries[cursor].path, sizeof(selected) - 1);
                    selected[sizeof(selected) - 1] = '\0';
                    has_selection = true;
                }
                running = false;
                break;
            case 'q':
            case 'Q':
            case 0x03: // Ctrl-C
                running = false;
                break;
            default:
                break;
        }
    }

    printf("\x1b[2J\x1b[H");
    fflush(stdout);

    for (size_t i = 0; i < count; ++i) {
        markdownDocEntryFree(&entries[i]);
    }
    free(entries);

    if (!has_selection) {
        return 0;
    }
    int status = smallclueMarkdownBrowseTarget(selected);
    if (status == 0) {
        // After viewing a document, return to the list.
        return markdownInteractiveSelectDocument();
    }
    return status;
}

#if defined(PSCAL_HAS_LIBCURL)
typedef struct {
    char *data;
    size_t len;
    size_t cap;
} SmallclueCurlMemory;

static void smallclueCurlApplyCommonOptions(CURL *curl, const char *url) {
    if (!curl) {
        return;
    }
    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 10L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "smallclue-http/1.0");
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");
    curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
}

static size_t smallclueCurlWriteCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    FILE *dest = (FILE *)userp;
    size_t bytes = size * nmemb;
    if (bytes == 0) return 0;
    if (fwrite(contents, 1, bytes, dest) != bytes) {
        return 0;
    }
    return bytes;
}

static size_t smallclueCurlWriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    SmallclueCurlMemory *buffer = (SmallclueCurlMemory *)userp;
    size_t bytes = size * nmemb;
    if (!buffer || bytes == 0) {
        return bytes;
    }
    size_t needed = buffer->len + bytes + 1;
    if (needed > buffer->cap) {
        size_t new_cap = (buffer->cap == 0) ? 16384 : buffer->cap;
        while (new_cap < needed) {
            if (new_cap > SIZE_MAX / 2) {
                return 0;
            }
            new_cap *= 2;
        }
        char *resized = (char *)realloc(buffer->data, new_cap);
        if (!resized) {
            return 0;
        }
        buffer->data = resized;
        buffer->cap = new_cap;
    }
    memcpy(buffer->data + buffer->len, contents, bytes);
    buffer->len += bytes;
    buffer->data[buffer->len] = '\0';
    return bytes;
}
#endif

static void smallclueUrlSuggestFilename(const char *url, char *buffer, size_t buffer_size) {
    if (!buffer || buffer_size == 0) {
        return;
    }
    buffer[0] = '\0';
    if (!url || !*url) {
        strncpy(buffer, "index.html", buffer_size - 1);
        buffer[buffer_size - 1] = '\0';
        return;
    }
    const char *start = strstr(url, "://");
    start = start ? start + 3 : url;
    const char *leaf = strrchr(start, '/');
    leaf = (leaf && leaf[1] != '\0') ? leaf + 1 : start;
    while (*leaf == '/') {
        leaf++;
    }
    const char *end = leaf;
    while (*end && *end != '?' && *end != '#') {
        end++;
    }
    size_t len = (size_t)(end - leaf);
    if (len == 0) {
        strncpy(buffer, "index.html", buffer_size - 1);
        buffer[buffer_size - 1] = '\0';
        return;
    }
    if (len >= buffer_size) {
        len = buffer_size - 1;
    }
    memcpy(buffer, leaf, len);
    buffer[len] = '\0';
}

static int smallclueHttpFetch(const char *cmd_name, const char *url, const char *destinationPath) {
#if !defined(PSCAL_HAS_LIBCURL)
    fprintf(stderr, "%s: networking support is unavailable in this build.\n", cmd_name ? cmd_name : "curl");
    return 1;
#else
    if (!url || !*url) {
        fprintf(stderr, "%s: missing URL\n", cmd_name ? cmd_name : "curl");
        return 1;
    }
    CURL *curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "%s: failed to initialise libcurl\n", cmd_name ? cmd_name : "curl");
        return 1;
    }
    FILE *dest = stdout;
    bool close_dest = false;
    if (destinationPath && destinationPath[0] != '\0' && strcmp(destinationPath, "-") != 0) {
        dest = fopen(destinationPath, "wb");
        if (!dest) {
            fprintf(stderr, "%s: %s: %s\n", cmd_name ? cmd_name : "curl", destinationPath, strerror(errno));
            curl_easy_cleanup(curl);
            return 1;
        }
        close_dest = true;
    }
    smallclueCurlApplyCommonOptions(curl, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, smallclueCurlWriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, dest);
    CURLcode res = curl_easy_perform(curl);
    if (close_dest) {
        fclose(dest);
    } else {
        fflush(dest);
    }
    if (res != CURLE_OK) {
        fprintf(stderr, "%s: %s: %s\n", cmd_name ? cmd_name : "curl", url, curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        return 1;
    }
    curl_easy_cleanup(curl);
    return 0;
#endif
}

static int smallclueHttpFetchToMemory(const char *cmd_name, const char *url, char **data_out, size_t *len_out) {
#if !defined(PSCAL_HAS_LIBCURL)
    (void)data_out;
    (void)len_out;
    fprintf(stderr, "%s: networking support is unavailable in this build.\n", cmd_name ? cmd_name : "curl");
    return 1;
#else
    if (!data_out || !len_out) {
        return 1;
    }
    *data_out = NULL;
    *len_out = 0;
    if (!url || !*url) {
        fprintf(stderr, "%s: missing URL\n", cmd_name ? cmd_name : "curl");
        return 1;
    }
    CURL *curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "%s: failed to initialise libcurl\n", cmd_name ? cmd_name : "curl");
        return 1;
    }
    SmallclueCurlMemory buffer = {0};
    smallclueCurlApplyCommonOptions(curl, url);
    bool is_md_fetch = (cmd_name && strcmp(cmd_name, "md") == 0);
    if (is_md_fetch) {
        /* Keep md browsing responsive on problematic endpoints. */
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 25L);
        curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, 64L);
        curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, 10L);
    }
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, smallclueCurlWriteMemoryCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &buffer);
    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        fprintf(stderr, "%s: %s: %s\n", cmd_name ? cmd_name : "curl", url, curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        free(buffer.data);
        return 1;
    }
    if (!buffer.data) {
        buffer.data = strdup("");
        if (!buffer.data) {
            curl_easy_cleanup(curl);
            return 1;
        }
        buffer.len = 0;
    }
    *data_out = buffer.data;
    *len_out = buffer.len;
    curl_easy_cleanup(curl);
    return 0;
#endif
}

static int cat_file(const char *path) {
    int status = 0;
    bool dbg = getenv("PSCALI_PIPE_DEBUG") != NULL;
    if (!path || strcmp(path, "-") == 0) {
        if (dbg) fprintf(stderr, "[cat] reading stdin\n");
        return print_file("(stdin)", stdin);
    }
    char resolved[PATH_MAX];
    const char *open_path = smallclueResolvePath(path, resolved, sizeof(resolved));
    if (!open_path || *open_path == '\0') {
        open_path = path;
    }
    FILE *fp = fopen(open_path, "rb");
    if (!fp) {
        fprintf(stderr, "cat: %s: %s\n", path, strerror(errno));
        return 1;
    }
    if (dbg) {
        struct stat st;
        if (fstat(fileno(fp), &st) == 0) {
            fprintf(stderr, "[cat] opened %s size=%lld\n", open_path, (long long)st.st_size);
        } else {
            fprintf(stderr, "[cat] opened %s (size unknown)\n", open_path);
        }
    }
    status = print_file(path, fp);
    fclose(fp);
    return status;
}

static void print_permissions(mode_t mode) {
    putchar(S_ISDIR(mode) ? 'd' : S_ISLNK(mode) ? 'l' : '-');
    putchar(mode & S_IRUSR ? 'r' : '-');
    putchar(mode & S_IWUSR ? 'w' : '-');
    putchar(mode & S_IXUSR ? 'x' : '-');
    putchar(mode & S_IRGRP ? 'r' : '-');
    putchar(mode & S_IWGRP ? 'w' : '-');
    putchar(mode & S_IXGRP ? 'x' : '-');
    putchar(mode & S_IROTH ? 'r' : '-');
    putchar(mode & S_IWOTH ? 'w' : '-');
    putchar(mode & S_IXOTH ? 'x' : '-');
}

static void print_long_listing(const char *filename, const struct stat *s, bool human, bool numeric_ids) {
    print_permissions(s->st_mode);
    printf(" %2llu", (unsigned long long)s->st_nlink);

    if (numeric_ids) {
        printf(" %-8u", (unsigned int)s->st_uid);
        printf(" %-8u", (unsigned int)s->st_gid);
    } else {
        struct passwd *pw = getpwuid(s->st_uid);
        printf(" %-8s", pw ? pw->pw_name : "?");

        struct group *gr = getgrgid(s->st_gid);
        printf(" %-8s", gr ? gr->gr_name : "?");
    }

    if (human) {
        char sizebuf[32];
        smallclueDfFormatSize(sizebuf, sizeof(sizebuf), (unsigned long long)s->st_size, true);
        printf(" %8s", sizebuf);
    } else {
        printf(" %8lld", (long long)s->st_size);
    }
    char time_buf[64];
    strftime(time_buf, sizeof(time_buf), "%b %d %H:%M", localtime(&s->st_mtime));
    printf(" %s %s", time_buf, filename);

    if (S_ISLNK(s->st_mode)) {
        char link_target[1024];
        ssize_t len = readlink(filename, link_target, sizeof(link_target) - 1);
        if (len >= 0) {
            link_target[len] = '\0';
            printf(" -> %s", link_target);
        }
    }
    putchar('\n');
}

static int print_path_entry_with_stat(const char *path,
                                      const char *label,
                                      bool long_format,
                                      bool human,
                                      bool numeric_ids,
                                      const struct stat *stat_buf,
                                      int color_mode,
                                      int classify) {
    struct stat local_stat;
    const struct stat *st = stat_buf;
    if (!st) {
        if (lstat(path, &local_stat) == -1) {
            fprintf(stderr, "ls: %s: %s\n", path, strerror(errno));
            return 1;
        }
        st = &local_stat;
    }

    int color = 0;
    if (color_mode > 0 && st) {
        if (S_ISDIR(st->st_mode)) color = 34;       /* blue */
        else if (S_ISLNK(st->st_mode)) color = 36;  /* cyan */
        else if (S_ISCHR(st->st_mode) || S_ISBLK(st->st_mode)) color = 33; /* yellow */
        else if (st->st_mode & S_IXUSR) color = 32; /* green executables */
    }

    char decorated[PATH_MAX];
    const char *display = label ? label : path;
    const char *out = display;
    if (classify && st) {
        char suffix = '\0';
        if (S_ISDIR(st->st_mode)) suffix = '/';
        else if (S_ISLNK(st->st_mode)) suffix = '@';
        else if (S_ISSOCK(st->st_mode)) suffix = '=';
        else if (S_ISFIFO(st->st_mode)) suffix = '|';
        else if (st->st_mode & S_IXUSR) suffix = '*';
        if (suffix != '\0') {
            snprintf(decorated, sizeof(decorated), "%s%c", display, suffix);
            decorated[sizeof(decorated) - 1] = '\0';
            out = decorated;
        }
    }
    if (long_format) {
        if (color)
            printf("\033[%dm", color);
        print_long_listing(out, st, human, numeric_ids);
        if (color)
            printf("\033[0m");
    } else {
        if (color)
            printf("\033[%dm%s\033[0m\n", color, out);
        else
            printf("%s\n", out);
    }
    return 0;
}

static char *join_path(const char *base, const char *name) {
    if (!base || !*base || strcmp(base, ".") == 0) {
        return strdup(name);
    }
    size_t base_len = strlen(base);
    bool needs_sep = base_len > 0 && base[base_len - 1] != '/';
    size_t total = base_len + strlen(name) + (needs_sep ? 2 : 1);
    char *joined = (char *)malloc(total);
    if (!joined) {
        return NULL;
    }
    strcpy(joined, base);
    if (needs_sep) {
        strcat(joined, "/");
    }
    strcat(joined, name);
    return joined;
}

static __attribute__((unused)) int print_path_entry(const char *path, const char *label, bool long_format, bool human, int color_mode, int classify) {
    return print_path_entry_with_stat(path, label, long_format, human, false, NULL, color_mode, classify);
}

typedef struct {
    char *name;
    char *full_path;
    struct stat stat_buf;
} SmallclueLsEntry;

static void free_ls_entries(SmallclueLsEntry *entries, size_t count) {
    if (!entries) {
        return;
    }
    for (size_t i = 0; i < count; ++i) {
        free(entries[i].name);
        free(entries[i].full_path);
    }
    free(entries);
}

static int compare_ls_entries_by_mtime(const void *lhs, const void *rhs) {
    const SmallclueLsEntry *a = (const SmallclueLsEntry *)lhs;
    const SmallclueLsEntry *b = (const SmallclueLsEntry *)rhs;
    if (a->stat_buf.st_mtime > b->stat_buf.st_mtime) {
        return -1;
    }
    if (a->stat_buf.st_mtime < b->stat_buf.st_mtime) {
        return 1;
    }
    return strcmp(a->name, b->name);
}

static void print_ls_columns(const SmallclueLsEntry *entries, size_t count, int color_mode, int classify) {
    if (count == 0) {
        return;
    }

    int term_cols = pscalRuntimeDetectWindowCols();
    if (term_cols <= 0) {
        term_cols = 80;
    }

    size_t max_len = 0;
    for (size_t i = 0; i < count; ++i) {
        size_t len = strlen(entries[i].name);
        if (len > max_len) {
            max_len = len;
        }
    }

    size_t col_width = max_len + 2; /* padding between columns */
    if (col_width == 0) {
        return;
    }

    int cols = term_cols / (int)col_width;
    if (cols < 1) {
        cols = 1;
    }
    int rows = (int)((count + (size_t)cols - 1) / (size_t)cols);

    for (int r = 0; r < rows; ++r) {
        for (int c = 0; c < cols; ++c) {
            size_t idx = (size_t)c * (size_t)rows + (size_t)r;
            if (idx >= count) {
                continue;
            }
            const struct stat *st = &entries[idx].stat_buf;
            const char *name = entries[idx].name;
            char decorated[PATH_MAX];
            const char *out = name;
            if (classify) {
                char suffix = '\0';
                if (S_ISDIR(st->st_mode)) suffix = '/';
                else if (S_ISLNK(st->st_mode)) suffix = '@';
                else if (S_ISSOCK(st->st_mode)) suffix = '=';
                else if (S_ISFIFO(st->st_mode)) suffix = '|';
                else if (st->st_mode & S_IXUSR) suffix = '*';
                if (suffix != '\0') {
                    snprintf(decorated, sizeof(decorated), "%s%c", name, suffix);
                    decorated[sizeof(decorated) - 1] = '\0';
                    out = decorated;
                }
            }
            int color = 0;
            if (color_mode > 0) {
                if (S_ISDIR(st->st_mode)) color = 34;
                else if (S_ISLNK(st->st_mode)) color = 36;
                else if (S_ISCHR(st->st_mode) || S_ISBLK(st->st_mode)) color = 33;
                else if (st->st_mode & S_IXUSR) color = 32;
            }
            if (c == cols - 1 || (size_t)((c + 1) * rows + r) >= count) {
                if (color) printf("\033[%dm%s\033[0m", color, out); else printf("%s", out);
            } else {
                if (color) printf("\033[%dm%-*s\033[0m", color, (int)col_width, out);
                else printf("%-*s", (int)col_width, out);
            }
        }
        putchar('\n');
    }
}

static int list_directory(const char *path,
                          bool show_all,
                          bool show_almost_all,
                          bool long_format,
                          bool sort_by_time,
                          bool human,
                          bool numeric_ids,
                          int color_mode,
                          int classify) {
    DIR *d = opendir(path);
    if (!d) {
        fprintf(stderr, "ls: %s: %s\n", path, strerror(errno));
        return 1;
    }

    SmallclueLsEntry *entries = NULL;
    size_t count = 0;
    size_t capacity = 0;
    int status = 0;

    struct dirent *dir;
    while ((dir = readdir(d)) != NULL) {
        const char *filename = dir->d_name;
        if (filename[0] == '.') {
            if (!show_all) {
                if (!show_almost_all) {
                    continue;
                }
                if (strcmp(filename, ".") == 0 || strcmp(filename, "..") == 0) {
                    continue;
                }
            }
        }

        char *full_path = join_path(path, filename);
        if (!full_path) {
            fprintf(stderr, "ls: %s/%s: %s\n", path, filename, strerror(ENOMEM));
            status = 1;
            break;
        }

        struct stat stat_buf;
        if (lstat(full_path, &stat_buf) == -1) {
            fprintf(stderr, "ls: %s: %s\n", full_path, strerror(errno));
            free(full_path);
            status = 1;
            continue;
        }

        char *name_copy = strdup(filename);
        if (!name_copy) {
            fprintf(stderr, "ls: %s/%s: %s\n", path, filename, strerror(ENOMEM));
            free(full_path);
            status = 1;
            break;
        }

        if (count == capacity) {
            size_t new_capacity = capacity ? capacity * 2 : 64;
            SmallclueLsEntry *new_entries = (SmallclueLsEntry *)realloc(entries,
                                                                      new_capacity * sizeof(SmallclueLsEntry));
            if (!new_entries) {
                fprintf(stderr, "ls: %s: %s\n", path, strerror(ENOMEM));
                free(name_copy);
                free(full_path);
                status = 1;
                break;
            }
            entries = new_entries;
            capacity = new_capacity;
        }

        entries[count].name = name_copy;
        entries[count].full_path = full_path;
        entries[count].stat_buf = stat_buf;
        ++count;
    }
    closedir(d);

    if (sort_by_time && count > 1) {
        qsort(entries, count, sizeof(entries[0]), compare_ls_entries_by_mtime);
    }

        if (long_format) {
            for (size_t i = 0; i < count; ++i) {
                status |= print_path_entry_with_stat(entries[i].full_path,
                                                     entries[i].name,
                                                     true,
                                                     human,
                                                     numeric_ids,
                                                     &entries[i].stat_buf,
                                                     color_mode,
                                                     classify);
            }
        } else {
        print_ls_columns(entries, count, color_mode, classify);
    }

    free_ls_entries(entries, count);
    return status ? 1 : 0;
}

static void smallcluePrintAppletList(FILE *out, const char *heading) {
    if (!out) {
        return;
    }
    if (heading && *heading) {
        fprintf(out, "%s\n", heading);
    }
    for (size_t i = 0; i < kSmallclueAppletCount; ++i) {
        const SmallclueApplet *applet = &kSmallclueApplets[i];
        fprintf(out, "  %-14s %s\n", applet->name, applet->description ? applet->description : "");
    }
}


static void print_usage(void) {
    fprintf(stderr, "This is smallclue. Usage:\n");
    fprintf(stderr, "  smallclue <applet> [arguments...]\n\n");
    fprintf(stderr, "Available applets:\n");
    smallcluePrintAppletList(stderr, NULL);
    fprintf(stderr, "\nYou can symlink applets to 'smallclue' or invoke them directly.\n");
}

static int smallclueEchoCommand(int argc, char **argv) {
    int print_newline = 1;
    int start_index = 1;
    if (argc > 1 && strcmp(argv[1], "-n") == 0) {
        print_newline = 0;
        start_index = 2;
    }
    for (int i = start_index; i < argc; i++) {
        printf("%s", argv[i]);
        if (i < argc - 1) {
            putchar(' ');
        }
    }
    if (print_newline) {
        putchar('\n');
    }
    return 0;
}

static bool smallclueLsValidateShortOptions(const char *arg,
                                            int *show_all,
                                            int *show_almost_all,
                                            int *long_format,
                                            int *sort_by_time,
                                            int *list_dirs_only,
                                            int *human_sizes,
                                            int *classify,
                                            int *numeric_ids) {
    if (!arg) {
        return true;
    }
    for (const char *cursor = arg; *cursor; ++cursor) {
        switch (*cursor) {
            case 'a':
                *show_all = 1;
                *show_almost_all = 0;
                break;
            case 'A':
                if (!*show_all) {
                    *show_almost_all = 1;
                }
                break;
            case 'l':
                *long_format = 1;
                break;
            case 't':
                *sort_by_time = 1;
                break;
            case 'h':
                *human_sizes = 1;
                break;
            case 'd':
                *list_dirs_only = 1;
                break;
            case 'F':
                *classify = 1;
                break;
            case 'n':
                *numeric_ids = 1;
                *long_format = 1;
                break;
            default:
                fprintf(stderr, "ls: invalid option -- '%c'\n", *cursor);
                return false;
        }
    }
    return true;
}

static bool smallclueLsAcceptColorValue(const char *option_name, const char *value) {
    if (!value) {
        return true;
    }
    if (*value == '\0') {
        fprintf(stderr, "ls: invalid argument '' for '%s'\n", option_name);
        return false;
    }
    if (strcasecmp(value, "auto") == 0 ||
        strcasecmp(value, "always") == 0 ||
        strcasecmp(value, "never") == 0 ||
        strcasecmp(value, "none") == 0) {
        return true;
    }
    fprintf(stderr, "ls: invalid argument '%s' for '%s'\n", value, option_name);
    return false;
}

static bool smallclueLsHandleLongOption(const char *arg) {
    if (!arg) {
        return true;
    }
    if (strcmp(arg, "--color") == 0) {
        return smallclueLsAcceptColorValue("--color", NULL);
    }
    if (strcmp(arg, "--colour") == 0) {
        return smallclueLsAcceptColorValue("--colour", NULL);
    }
    if (strncmp(arg, "--color=", 8) == 0) {
        return smallclueLsAcceptColorValue("--color", arg + 8);
    }
    if (strncmp(arg, "--colour=", 9) == 0) {
        return smallclueLsAcceptColorValue("--colour", arg + 9);
    }
    fprintf(stderr, "ls: unrecognized option '%s'\n", arg);
    return false;
}

static int smallclueLsCommand(int argc, char **argv) {
    int show_all = 0;
    int show_almost_all = 0;
    int long_format = 0;
    int sort_by_time = 0;
    int list_dirs_only = 0;
    int human_sizes = 0;
    int classify = 0;
    int numeric_ids = 0;
    int color_mode = 0; /* 0=auto, 1=always, -1=never */
    smallclueResetGetopt();

    int idx = 1;
    while (idx < argc) {
        const char *arg = argv[idx];
        if (!arg || arg[0] != '-' || arg[1] == '\0') {
            break;
        }
        if (strcmp(arg, "--") == 0) {
            idx++;
            break;
        }
        if (arg[1] == '-') {
            if (!smallclueLsHandleLongOption(arg)) {
                return 1;
            }
            if (strcmp(arg, "--color") == 0 || strcmp(arg, "--colour") == 0) {
                color_mode = 1;
            } else if (strncmp(arg, "--color=", 8) == 0) {
                const char *val = arg + 8;
                if (strcasecmp(val, "always") == 0) color_mode = 1;
                else if (strcasecmp(val, "never") == 0 || strcasecmp(val, "none") == 0) color_mode = -1;
                else color_mode = 0;
            } else if (strncmp(arg, "--colour=", 9) == 0) {
                const char *val = arg + 9;
                if (strcasecmp(val, "always") == 0) color_mode = 1;
                else if (strcasecmp(val, "never") == 0 || strcasecmp(val, "none") == 0) color_mode = -1;
                else color_mode = 0;
            }
            idx++;
            continue;
        }
        if (!smallclueLsValidateShortOptions(arg + 1,
                                             &show_all,
                                             &show_almost_all,
                                             &long_format,
                                             &sort_by_time,
                                             &list_dirs_only,
                                             &human_sizes,
                                             &classify,
                                             &numeric_ids)) {
            return 1;
        }
        idx++;
    }

    if (color_mode == 0) {
        color_mode = pscalRuntimeStdoutIsInteractive() ? 1 : -1;
    }

    int status = 0;
    int paths_start = idx;
    if (paths_start >= argc) {
        if (list_dirs_only) {
            return print_path_entry_with_stat(".", ".", long_format, human_sizes, numeric_ids, NULL, color_mode, classify) ? 1 : 0;
        }
        return list_directory(".", show_all, show_almost_all, long_format,
                              sort_by_time, human_sizes, numeric_ids, color_mode, classify);
    }

    int remaining = argc - paths_start;
    for (int i = paths_start; i < argc; ++i) {
        const char *path = argv[i];
        struct stat stat_buf;
        if (lstat(path, &stat_buf) == -1) {
            fprintf(stderr, "ls: %s: %s\n", path, strerror(errno));
            status = 1;
            continue;
        }
        bool is_dir = S_ISDIR(stat_buf.st_mode);
        if (is_dir && !list_dirs_only) {
            if (remaining > 1) {
                if (i > paths_start) {
                    putchar('\n');
                }
                printf("%s:\n", path);
            }
            status |= list_directory(path, show_all, show_almost_all, long_format,
                                     sort_by_time, human_sizes, numeric_ids, color_mode, classify);
        } else {
            status |= print_path_entry_with_stat(path, path, long_format, human_sizes, numeric_ids, &stat_buf, color_mode, classify);
        }
    }
    return status ? 1 : 0;
}

static int smallcluePwdCommand(int argc, char **argv) {
    (void)argc;
    (void)argv;
    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof(cwd))) {
        perror("pwd");
        return 1;
    }
    puts(cwd);
    return 0;
}

#define SMALLCLUE_CHMOD_TARGET_USER 0x1u
#define SMALLCLUE_CHMOD_TARGET_GROUP 0x2u
#define SMALLCLUE_CHMOD_TARGET_OTHER 0x4u
#define SMALLCLUE_CHMOD_TARGET_ALL (SMALLCLUE_CHMOD_TARGET_USER | SMALLCLUE_CHMOD_TARGET_GROUP | SMALLCLUE_CHMOD_TARGET_OTHER)

#define SMALLCLUE_CHMOD_PERM_READ 0x1u
#define SMALLCLUE_CHMOD_PERM_WRITE 0x2u
#define SMALLCLUE_CHMOD_PERM_EXEC 0x4u
#define SMALLCLUE_CHMOD_PERM_ALL (SMALLCLUE_CHMOD_PERM_READ | SMALLCLUE_CHMOD_PERM_WRITE | SMALLCLUE_CHMOD_PERM_EXEC)

typedef struct {
    unsigned targets;
    unsigned perms;
    char op;
} SmallclueChmodOp;

typedef struct {
    SmallclueChmodOp ops[16];
    size_t count;
} SmallclueChmodSpec;

static bool smallclueChmodParseOctal(const char *spec, mode_t *out_mode) {
    if (!spec || !out_mode) {
        return false;
    }
    char *end = NULL;
    errno = 0;
    long value = strtol(spec, &end, 8);
    if (errno != 0 || !end || *end != '\0' || value < 0 || value > 07777) {
        return false;
    }
    *out_mode = (mode_t)value;
    return true;
}

static bool smallclueChmodParseSymbolic(const char *spec, SmallclueChmodSpec *out_spec) {
    if (!spec || !out_spec) {
        return false;
    }
    out_spec->count = 0;
    const char *cursor = spec;
    while (*cursor) {
        if (out_spec->count >= sizeof(out_spec->ops) / sizeof(out_spec->ops[0])) {
            return false;
        }
        unsigned targets = 0;
        bool saw_target = false;
        while (*cursor == 'u' || *cursor == 'g' || *cursor == 'o' || *cursor == 'a') {
            saw_target = true;
            if (*cursor == 'u') targets |= SMALLCLUE_CHMOD_TARGET_USER;
            else if (*cursor == 'g') targets |= SMALLCLUE_CHMOD_TARGET_GROUP;
            else if (*cursor == 'o') targets |= SMALLCLUE_CHMOD_TARGET_OTHER;
            else if (*cursor == 'a') targets |= SMALLCLUE_CHMOD_TARGET_ALL;
            cursor++;
        }
        if (!saw_target) {
            targets = SMALLCLUE_CHMOD_TARGET_ALL;
        }
        char op = *cursor;
        if (op != '+' && op != '-' && op != '=') {
            return false;
        }
        cursor++;
        unsigned perms = 0;
        while (*cursor == 'r' || *cursor == 'w' || *cursor == 'x') {
            if (*cursor == 'r') perms |= SMALLCLUE_CHMOD_PERM_READ;
            else if (*cursor == 'w') perms |= SMALLCLUE_CHMOD_PERM_WRITE;
            else if (*cursor == 'x') perms |= SMALLCLUE_CHMOD_PERM_EXEC;
            cursor++;
        }
        if (op != '=' && perms == 0) {
            return false;
        }
        SmallclueChmodOp *entry = &out_spec->ops[out_spec->count++];
        entry->targets = targets;
        entry->perms = perms;
        entry->op = op;
        if (*cursor == ',') {
            cursor++;
            continue;
        } else if (*cursor == '\0') {
            break;
        } else {
            return false;
        }
    }
    return out_spec->count > 0;
}

static mode_t smallclueChmodMaskForTargets(unsigned targets, unsigned perms) {
    mode_t mask = 0;
    if (perms & SMALLCLUE_CHMOD_PERM_READ) {
        if (targets & SMALLCLUE_CHMOD_TARGET_USER) mask |= S_IRUSR;
        if (targets & SMALLCLUE_CHMOD_TARGET_GROUP) mask |= S_IRGRP;
        if (targets & SMALLCLUE_CHMOD_TARGET_OTHER) mask |= S_IROTH;
    }
    if (perms & SMALLCLUE_CHMOD_PERM_WRITE) {
        if (targets & SMALLCLUE_CHMOD_TARGET_USER) mask |= S_IWUSR;
        if (targets & SMALLCLUE_CHMOD_TARGET_GROUP) mask |= S_IWGRP;
        if (targets & SMALLCLUE_CHMOD_TARGET_OTHER) mask |= S_IWOTH;
    }
    if (perms & SMALLCLUE_CHMOD_PERM_EXEC) {
        if (targets & SMALLCLUE_CHMOD_TARGET_USER) mask |= S_IXUSR;
        if (targets & SMALLCLUE_CHMOD_TARGET_GROUP) mask |= S_IXGRP;
        if (targets & SMALLCLUE_CHMOD_TARGET_OTHER) mask |= S_IXOTH;
    }
    return mask;
}

static mode_t smallclueChmodApplySpec(mode_t current, const SmallclueChmodSpec *spec) {
    mode_t result = current;
    if (!spec) {
        return result;
    }
    for (size_t i = 0; i < spec->count; ++i) {
        const SmallclueChmodOp *op = &spec->ops[i];
        mode_t mask = smallclueChmodMaskForTargets(op->targets, op->perms);
        switch (op->op) {
            case '+':
                result |= mask;
                break;
            case '-':
                result &= ~mask;
                break;
            case '=': {
                mode_t clearMask = smallclueChmodMaskForTargets(op->targets, SMALLCLUE_CHMOD_PERM_ALL);
                result &= ~clearMask;
                result |= mask;
                break;
            }
            default:
                break;
        }
    }
    return result;
}

static int smallclueChmodApplySymbolic(const SmallclueChmodSpec *spec, const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) {
        fprintf(stderr, "chmod: %s: %s\n", path, strerror(errno));
        return -1;
    }
    mode_t desired = smallclueChmodApplySpec(st.st_mode, spec);
    if (chmod(path, desired) != 0) {
        fprintf(stderr, "chmod: %s: %s\n", path, strerror(errno));
        return -1;
    }
    return 0;
}

static int smallclueChmodCommand(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: chmod mode file...\n");
        return 1;
    }
    mode_t octalMode = 0;
    SmallclueChmodSpec symbolicSpec;
    bool useOctal = smallclueChmodParseOctal(argv[1], &octalMode);
    bool useSymbolic = false;
    if (!useOctal) {
        useSymbolic = smallclueChmodParseSymbolic(argv[1], &symbolicSpec);
    }
    if (!useOctal && !useSymbolic) {
        fprintf(stderr, "chmod: invalid mode: %s\n", argv[1]);
        return 1;
    }
    int status = 0;
    for (int i = 2; i < argc; ++i) {
        if (useOctal) {
            if (chmod(argv[i], octalMode) != 0) {
                fprintf(stderr, "chmod: %s: %s\n", argv[i], strerror(errno));
                status = 1;
            }
        } else {
            if (smallclueChmodApplySymbolic(&symbolicSpec, argv[i]) != 0) {
                status = 1;
            }
        }
    }
    return status;
}

static int smallclueTrueCommand(int argc, char **argv) {
    (void)argc;
    (void)argv;
    return 0;
}

static int smallclueFalseCommand(int argc, char **argv) {
    (void)argc;
    (void)argv;
    return 1;
}

static char *smallclueYesNoPayload(int argc, char **argv, const char *fallback) {
    if (!fallback) {
        fallback = "";
    }
    if (argc <= 1) {
        return strdup(fallback);
    }
    size_t total = 0;
    for (int i = 1; i < argc; ++i) {
        if (argv[i]) {
            total += strlen(argv[i]);
        }
        if (i + 1 < argc) {
            total += 1; /* space */
        }
    }
    char *buf = (char *)malloc(total + 1);
    if (!buf) {
        return NULL;
    }
    size_t pos = 0;
    for (int i = 1; i < argc; ++i) {
        const char *part = argv[i] ? argv[i] : "";
        size_t len = strlen(part);
        if (len > 0) {
            memcpy(buf + pos, part, len);
            pos += len;
        }
        if (i + 1 < argc) {
            buf[pos++] = ' ';
        }
    }
    buf[pos] = '\0';
    return buf;
}

static int smallclueYesNoLoop(const char *text, int initial_status) {
    if (!text) {
        return initial_status;
    }
    size_t len = strlen(text);
    char *line = (char *)malloc(len + 2);
    if (!line) {
        return 1;
    }
    memcpy(line, text, len);
    line[len] = '\n';
    line[len + 1] = '\0';
    size_t line_len = len + 1;
    int status = initial_status;
    while (true) {
        if (smallclueShouldAbort(&status)) {
            break;
        }
        size_t written = fwrite(line, 1, line_len, stdout);
        if (written != line_len) {
            status = errno ? errno : status;
            break;
        }
        if (fflush(stdout) != 0) {
            status = errno ? errno : status;
            break;
        }
    }
    free(line);
    return status;
}

static int smallclueYesCommand(int argc, char **argv) {
    smallclueClearPendingSignals();
    char *payload = smallclueYesNoPayload(argc, argv, "y");
    if (!payload) {
        return 1;
    }
    int status = smallclueYesNoLoop(payload, 0);
    free(payload);
    return status;
}

static int smallclueNoCommand(int argc, char **argv) {
    smallclueClearPendingSignals();
    char *payload = smallclueYesNoPayload(argc, argv, "n");
    if (!payload) {
        return 1;
    }
    int status = smallclueYesNoLoop(payload, 1);
    free(payload);
    return status;
}

typedef enum {
    SMALLCLUE_SUM_BSD,
    SMALLCLUE_SUM_SYSV
} SmallclueSumMode;

static uint16_t smallclueBsdSum(FILE *f, unsigned long long *out_blocks) {
    uint16_t sum = 0;
    unsigned long long total = 0;
    int c;
    while ((c = fgetc(f)) != EOF) {
        sum = (uint16_t)((sum >> 1) | ((sum & 1) << 15));
        sum = (uint16_t)((sum + (uint16_t)c) & 0xFFFF);
        total++;
    }
    if (out_blocks) {
        *out_blocks = (total + 1023ULL) / 1024ULL; /* 1K blocks */
    }
    return sum;
}

static uint16_t smallclueSysvSum(FILE *f, unsigned long long *out_blocks) {
    uint32_t sum = 0;
    unsigned long long total = 0;
    int c;
    while ((c = fgetc(f)) != EOF) {
        sum += (uint8_t)c;
        total++;
    }
    /* Fold to 16 bits */
    sum = (sum & 0xFFFF) + (sum >> 16);
    sum = (sum & 0xFFFF) + (sum >> 16);
    if (out_blocks) {
        *out_blocks = (total + 511ULL) / 512ULL; /* 512-byte blocks */
    }
    return (uint16_t)(sum & 0xFFFF);
}

static int smallclueSumCommand(int argc, char **argv) {
    SmallclueSumMode mode = SMALLCLUE_SUM_BSD; /* -r default */
    int idx = 1;
    while (idx < argc && argv[idx][0] == '-') {
        const char *opt = argv[idx];
        if (strcmp(opt, "--") == 0) { idx++; break; }
        if (strcmp(opt, "-r") == 0) { mode = SMALLCLUE_SUM_BSD; idx++; continue; }
        if (strcmp(opt, "-s") == 0 || strcmp(opt, "--sysv") == 0) { mode = SMALLCLUE_SUM_SYSV; idx++; continue; }
        if (strcmp(opt, "--help") == 0) {
            fputs("usage: sum [-r|-s] [FILE...]\n", stdout);
            fputs("  -r        BSD algorithm, 1K blocks (default)\n", stdout);
            fputs("  -s, --sysv System V algorithm, 512-byte blocks\n", stdout);
            return 0;
        }
        if (strcmp(opt, "--version") == 0) {
            fputs("sum (smallclue) 1.0\n", stdout);
            return 0;
        }
        /* Unknown option */
        fprintf(stderr, "sum: unknown option '%s'\n", opt);
        return 1;
    }

    int file_count = argc - idx;
    if (file_count <= 0) {
        argv[idx] = "-";
        file_count = 1;
    }

    for (int i = 0; i < file_count; ++i) {
        const char *path = argv[idx + i];
        FILE *f = NULL;
        bool from_stdin = (strcmp(path, "-") == 0);
        if (from_stdin) {
            f = stdin;
        } else {
            f = fopen(path, "rb");
            if (!f) {
                fprintf(stderr, "sum: %s: %s\n", path, strerror(errno));
                continue;
            }
        }

        unsigned long long blocks = 0;
        uint16_t checksum = (mode == SMALLCLUE_SUM_BSD)
                                ? smallclueBsdSum(f, &blocks)
                                : smallclueSysvSum(f, &blocks);

        if (!from_stdin) {
            fclose(f);
        } else {
            clearerr(stdin);
        }

        if (from_stdin && file_count == 1) {
            printf("%u %llu\n", (unsigned)checksum, blocks);
        } else {
            printf("%u %llu %s\n", (unsigned)checksum, blocks, path);
        }
    }
    return 0;
}

static bool smallclueFormatBuildTimestamp(const char *programVersion, char *out, size_t out_len) {
    if (!out || out_len == 0) {
        return false;
    }
    out[0] = '\0';
    const char *p = programVersion;
    if (!p) {
        return false;
    }
    /* Expect YYYYMMDD.HHMM... */
    for (int i = 0; i < 8; ++i) {
        if (!isdigit((unsigned char)p[i])) {
            return false;
        }
    }
    if (p[8] != '.') {
        return false;
    }
    for (int i = 9; i < 13; ++i) {
        if (!isdigit((unsigned char)p[i])) {
            return false;
        }
    }
    int written = snprintf(out, out_len, "%c%c%c%c%c%c%c%c-%c%c:%c%c",
                           p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
                           p[9], p[10], p[11], p[12]);
    if (written < 0 || (size_t)written >= out_len) {
        out[0] = '\0';
        return false;
    }
    return true;
}

static int smallclueVersionCommand(int argc, char **argv) {
    (void)argc;
    (void)argv;
    char *version = NULL;
#if defined(PSCAL_TARGET_IOS)
    extern char *pscalRuntimeCopyMarketingVersion(void) __attribute__((weak));
    if (pscalRuntimeCopyMarketingVersion) {
        version = pscalRuntimeCopyMarketingVersion();
    }
#endif
#ifdef PROGRAM_VERSION
    const char *fallback = PROGRAM_VERSION;
#else
    const char *fallback = NULL;
#endif
    if (!version && fallback) {
        version = strdup(fallback);
    }
    if (!version) {
        printf("version: unknown\n");
        return 1;
    }
    const char *programVersion = pscal_program_version_string();
    char buildStamp[32];
    if (smallclueFormatBuildTimestamp(programVersion, buildStamp, sizeof(buildStamp))) {
        printf("version: %s (%s)\n", version, buildStamp);
    } else {
        printf("version: %s\n", version);
    }
    free(version);
    return 0;
}

#if defined(PSCAL_TARGET_IOS)

typedef struct {
    const char *name;
    const char *filename;
} SmallclueLicense;

static const SmallclueLicense kSmallclueLicenses[] = {
    {"PSCAL", "pscal_LICENSE.txt"},
    {"OpenSSH", "openssh_LICENSE.txt"},
    {"curl", "curl_LICENSE.txt"},
    {"OpenSSL", "openssl_LICENSE.txt"},
    {"SDL2", "sdl_LICENSE.txt"},
    {"Nextvi", "nextvi_LICENSE.txt"},
    {"yyjson", "yyjson_LICENSE.txt"},
    {"hterm", "hterm_LICENSE.txt"},
};

static size_t smallclueLicensesCount(void) {
    return sizeof(kSmallclueLicenses) / sizeof(kSmallclueLicenses[0]);
}

static bool smallclueLicensesResolvePath(const char *filename, char *out, size_t out_size) {
    if (!filename || !out || out_size == 0) {
        return false;
    }
    struct stat st;
    const char *docs_root = getenv("PSCALI_DOCS_ROOT");
    if (docs_root && *docs_root) {
        char docs_dir[PATH_MAX];
        if (smallclueBuildPath(docs_dir, sizeof(docs_dir), docs_root, "Licenses") == 0 &&
            smallclueBuildPath(out, out_size, docs_dir, filename) == 0 &&
            stat(out, &st) == 0 && S_ISREG(st.st_mode)) {
            return true;
        }
    }
    const char *home = getenv("HOME");
    if (home && *home) {
        char docs_dir[PATH_MAX];
        if (smallclueBuildPath(docs_dir, sizeof(docs_dir), home, "Docs") == 0 &&
            smallclueBuildPath(docs_dir, sizeof(docs_dir), docs_dir, "Licenses") == 0 &&
            smallclueBuildPath(out, out_size, docs_dir, filename) == 0 &&
            stat(out, &st) == 0 && S_ISREG(st.st_mode)) {
            return true;
        }
    }
    if (smallclueBuildPath(out, out_size, "/home/Docs/Licenses", filename) == 0 &&
        stat(out, &st) == 0 && S_ISREG(st.st_mode)) {
        return true;
    }
    return false;
}

static void smallclueLicensesRenderMenu(size_t selected) {
    printf("\033[2J\033[H");
    printf("PSCAL & Third-Party Licenses\n");
    printf("Use arrows to navigate, Enter to view, q to quit.\n\n");
    size_t total = smallclueLicensesCount();
    for (size_t i = 0; i < total; ++i) {
        const char *marker = (i == selected) ? ">" : " ";
        printf("%s %s\n", marker, kSmallclueLicenses[i].name);
    }
    fflush(stdout);
}

static int smallclueLicensesCommand(int argc, char **argv) {
    (void)argc;
    (void)argv;
    pager_control_fd_reset();
    size_t total = smallclueLicensesCount();
    if (total == 0) {
        fprintf(stderr, "licenses: no entries available\n");
        return 1;
    }
    size_t selected = 0;
    bool running = true;
    while (running) {
        smallclueLicensesRenderMenu(selected);
        int key = pager_read_key();
        switch (key) {
            case PAGER_KEY_ARROW_UP:
                selected = (selected == 0) ? (total - 1) : (selected - 1);
                break;
            case PAGER_KEY_ARROW_DOWN:
                selected = (selected + 1) % total;
                break;
            case '\r':
            case '\n': {
                const SmallclueLicense *entry = &kSmallclueLicenses[selected];
                char resolved[PATH_MAX];
                if (!smallclueLicensesResolvePath(entry->filename, resolved, sizeof(resolved))) {
                    smallclueLicensesRenderMenu(selected);
                    fprintf(stdout, "\nlicenses: %s: not found\n", entry->filename);
                    fprintf(stdout, "Press any key to continue.");
                    fflush(stdout);
                    (void)pager_read_key();
                    break;
                }
                (void)smallclueMarkdownDisplayPath(resolved);
                break;
            }
            case 'q':
            case 'Q':
            case 0x1b:
                running = false;
                break;
            default:
                break;
        }
    }
    printf("\033[2J\033[H");
    fflush(stdout);
    pager_control_fd_reset();
    smallclueEmitTerminalSane();
    return 0;
}

static int smallclueHelpCommand(int argc, char **argv) {
    int status = 0;
    char *buffer = NULL;
    size_t buflen = 0;
    FILE *mem = open_memstream(&buffer, &buflen);
    if (!mem) {
        fprintf(stderr, "smallclue-help: unable to allocate buffer\n");
        return 1;
    }

    if (argc <= 1) {
        smallcluePrintAppletList(mem, "Available smallclue applets:");
    } else {
        for (int i = 1; i < argc; ++i) {
            const char *target = argv[i];
            const SmallclueApplet *applet = smallclueFindApplet(target);
            if (!applet) {
                fprintf(mem, "smallclue-help: '%s' not found\n", target);
                status = 1;
                continue;
            }
            const char *usage = smallclueLookupHelp(applet->name);
            fprintf(mem, "%s - %s\n", applet->name, applet->description ? applet->description : "");
            if (usage) {
                fprintf(mem, "Usage:\n%s\n", usage);
            } else {
                fprintf(mem, "(No detailed help available for this applet)\n\n");
            }
        }
    }
    fflush(mem);
    fclose(mem);

    if (!buffer) {
        return status;
    }

    bool interactive_out = pscalRuntimeStdoutIsInteractive();
    if (interactive_out) {
        FILE *r = fmemopen(buffer, buflen, "r");
        if (!r) {
            interactive_out = false;
        } else {
            int rows = 0;
            int cols = 0;
            smallclueGetTerminalSize(&rows, &cols);
            if (rows <= 0) {
                rows = INT_MAX;
            }
            int line_count = 0;
            for (char *p = buffer; *p; ++p) {
                if (*p == '\n') line_count++;
            }
            if (line_count >= rows) {
                pager_file("smallclue-help", "(internal)", r);
            } else {
                // Print directly if it fits on one screen
                fwrite(buffer, 1, buflen, stdout);
            }
            fclose(r);
        }
    } else {
        fwrite(buffer, 1, buflen, stdout);
    }
    free(buffer);
    return status;
}
#endif

#if defined(SMALLCLUE_WITH_EXSH)
static int smallclueShCommand(int argc, char **argv) {
    return exsh_main(argc, argv);
}
#endif

#if defined(__APPLE__)
static bool smallclueUnameCopySysctl(const char *name, char *buffer, size_t buffer_len) {
    if (!name || !buffer || buffer_len == 0) {
        return false;
    }
    size_t len = buffer_len;
    if (sysctlbyname(name, buffer, &len, NULL, 0) != 0 || len == 0) {
        buffer[0] = '\0';
        return false;
    }
    buffer[buffer_len - 1] = '\0';
    return buffer[0] != '\0';
}

static const char *smallclueUnameMachine(char *buffer, size_t buffer_len) {
    const char *sim = getenv("SIMULATOR_MODEL_IDENTIFIER");
    if (sim && *sim) {
        snprintf(buffer, buffer_len, "%s", sim);
        return buffer;
    }
    if (smallclueUnameCopySysctl("hw.machine", buffer, buffer_len)) {
        return buffer;
    }
    return NULL;
}
#endif

#if defined(PSCAL_TARGET_IOS)
static const char *smallclueUnameIOSName(const char *machine) {
    if (machine) {
        if (strncmp(machine, "iPad", 4) == 0) {
            return "iPadOS_PSCAL";
        }
        if (strncmp(machine, "iPhone", 6) == 0 || strncmp(machine, "iPod", 4) == 0) {
            return "iOS_PSCAL";
        }
    }
    return "iOS_PSCAL";
}
#endif

static int smallclueUnameCommand(int argc, char **argv) {
    bool show_sysname = false;
    bool show_nodename = false;
    bool show_release = false;
    bool show_version = false;
    bool show_machine = false;
    bool show_processor = false;
    bool show_all = false;
    smallclueResetGetopt();
    int opt;
    while ((opt = getopt(argc, argv, "asnrvmp")) != -1) {
        switch (opt) {
            case 'a':
                show_all = true;
                break;
            case 's':
                show_sysname = true;
                break;
            case 'n':
                show_nodename = true;
                break;
            case 'r':
                show_release = true;
                break;
            case 'v':
                show_version = true;
                break;
            case 'm':
                show_machine = true;
                break;
            case 'p':
                show_processor = true;
                break;
            default:
                fputs("usage: uname [-asnrvmp]\n", stderr);
                return 1;
        }
    }

    if (!show_sysname && !show_nodename && !show_release &&
        !show_version && !show_machine && !show_processor) {
        show_sysname = true;
    }
    if (show_all) {
        show_sysname = true;
        show_nodename = true;
        show_release = true;
        show_version = true;
        show_machine = true;
    }

    struct utsname info;
    if (uname(&info) != 0) {
        fprintf(stderr, "uname: %s\n", strerror(errno));
        return 1;
    }

    const char *sysname = info.sysname;
    const char *nodename = info.nodename;
    const char *release = info.release;
    const char *version = info.version;
    const char *machine = info.machine;
    const char *processor = info.machine;
#if defined(__APPLE__)
    char machine_buf[64];
    if (smallclueUnameMachine(machine_buf, sizeof(machine_buf))) {
        machine = machine_buf;
        processor = machine_buf;
    }
#endif
#if defined(PSCAL_TARGET_IOS)
    const char *ios_name = smallclueUnameIOSName(machine);
    if (ios_name) {
        sysname = ios_name;
    }
#if defined(__APPLE__)
    char product_version[64];
    if (smallclueUnameCopySysctl("kern.osproductversion",
                                 product_version,
                                 sizeof(product_version))) {
        release = product_version;
    }
#endif
#endif

    bool first = true;
    if (show_sysname) {
        fputs(sysname && *sysname ? sysname : "unknown", stdout);
        first = false;
    }
    if (show_nodename) {
        if (!first) {
            putchar(' ');
        }
        fputs(nodename && *nodename ? nodename : "unknown", stdout);
        first = false;
    }
    if (show_release) {
        if (!first) {
            putchar(' ');
        }
        fputs(release && *release ? release : "unknown", stdout);
        first = false;
    }
    if (show_version) {
        if (!first) {
            putchar(' ');
        }
        fputs(version && *version ? version : "unknown", stdout);
        first = false;
    }
    if (show_machine) {
        if (!first) {
            putchar(' ');
        }
        fputs(machine && *machine ? machine : "unknown", stdout);
        first = false;
    }
    if (show_processor) {
        if (!first) {
            putchar(' ');
        }
        fputs(processor && *processor ? processor : "unknown", stdout);
    }
    putchar('\n');
    return 0;
}

static int64_t smallclueUptimeSeconds(void) {
#if defined(__APPLE__)
    struct timeval boottv;
    size_t len = sizeof(boottv);
    int mib[2] = {CTL_KERN, KERN_BOOTTIME};
    if (sysctl(mib, 2, &boottv, &len, NULL, 0) == 0 && boottv.tv_sec > 0) {
        struct timeval now;
        gettimeofday(&now, NULL);
        time_t secs = now.tv_sec - boottv.tv_sec;
        if (secs < 0) {
            secs = 0;
        }
        return (int64_t)secs;
    }
#endif
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        return (int64_t)ts.tv_sec;
    }
    return -1;
}

static int smallclueUptimeCommand(int argc, char **argv) {
    (void)argc;
    (void)argv;
    int64_t seconds = smallclueUptimeSeconds();
    if (seconds < 0) {
        fprintf(stderr, "uptime: unavailable\n");
        return 1;
    }
    int days = (int)(seconds / 86400);
    seconds %= 86400;
    int hours = (int)(seconds / 3600);
    seconds %= 3600;
    int minutes = (int)(seconds / 60);
    int secs = (int)(seconds % 60);
    if (days > 0) {
        printf("up %d day%s, %02d:%02d:%02d\n", days, days == 1 ? "" : "s", hours, minutes, secs);
    } else {
        printf("up %02d:%02d:%02d\n", hours, minutes, secs);
    }
    return 0;
}

static double smallclueTimevalDiffSeconds(const struct timeval *end, const struct timeval *start) {
    if (!end || !start) {
        return 0.0;
    }
    double seconds = (double)(end->tv_sec - start->tv_sec);
    seconds += ((double)(end->tv_usec - start->tv_usec) / 1000000.0);
    if (seconds < 0.0) {
        return 0.0;
    }
    return seconds;
}

static void smallclueTimePrintMetric(const char *label, double seconds) {
    if (!label) {
        return;
    }
    if (seconds < 0.0) {
        seconds = 0.0;
    }
    long minutes = (long)(seconds / 60.0);
    double remainder = seconds - ((double)minutes * 60.0);
    if (remainder < 0.0) {
        remainder = 0.0;
    }
    printf("%s\t%ldm%.3fs\n", label, minutes, remainder);
}

static int smallclueTimeCommand(int argc, char **argv) {
    if (argc < 2 || !argv[1] || argv[1][0] == '\0') {
        fprintf(stderr, "usage: time command [args...]\n");
        return 1;
    }

    const SmallclueApplet *applet = smallclueFindApplet(argv[1]);
    if (!applet) {
        fprintf(stderr, "time: %s: command not found\n", argv[1]);
        return 127;
    }

    struct timespec start_real = {0};
    struct timespec end_real = {0};
    struct rusage start_usage = {0};
    struct rusage end_usage = {0};
    bool have_real = (clock_gettime(CLOCK_MONOTONIC, &start_real) == 0);
    bool have_usage = (getrusage(RUSAGE_SELF, &start_usage) == 0);

    int status = smallclueDispatchApplet(applet, argc - 1, &argv[1]);

    if (have_real) {
        have_real = (clock_gettime(CLOCK_MONOTONIC, &end_real) == 0);
    }
    if (have_usage) {
        have_usage = (getrusage(RUSAGE_SELF, &end_usage) == 0);
    }

    double real_seconds = 0.0;
    if (have_real) {
        real_seconds = (double)(end_real.tv_sec - start_real.tv_sec);
        real_seconds += ((double)(end_real.tv_nsec - start_real.tv_nsec) / 1000000000.0);
        if (real_seconds < 0.0) {
            real_seconds = 0.0;
        }
    }
    double user_seconds = have_usage ? smallclueTimevalDiffSeconds(&end_usage.ru_utime, &start_usage.ru_utime) : 0.0;
    double sys_seconds = have_usage ? smallclueTimevalDiffSeconds(&end_usage.ru_stime, &start_usage.ru_stime) : 0.0;

    smallclueTimePrintMetric("real", real_seconds);
    smallclueTimePrintMetric("user", user_seconds);
    smallclueTimePrintMetric("sys", sys_seconds);
    return status;
}

static int smallclueWatchRunApplet(const SmallclueApplet *applet, int argc, char **argv) {
    if (!applet) {
        fprintf(stderr, "watch: %s: command not found\n", argv[0]);
        return 127;
    }
    const char *dbg = getenv("SMALLCLUE_DEBUG");
#if !defined(PSCAL_TARGET_IOS)
    return smallclueDispatchApplet(applet, argc, argv);
#else
    char label[96] = {0};
    size_t used = 0;
    for (int i = 0; i < argc && used + 1 < sizeof(label); ++i) {
        const char *part = argv[i] ? argv[i] : "";
        size_t len = strlen(part);
        if (used + len + 1 >= sizeof(label)) {
            len = sizeof(label) - used - 1;
        }
        memcpy(label + used, part, len);
        used += len;
        if (used + 1 < sizeof(label) && i + 1 < argc) {
            label[used++] = ' ';
        }
    }
    label[used] = '\0';

    VProc *active_vp = vprocCurrent();
    int shell_pid = vprocGetShellSelfPid();
    bool force_new_vproc = !(active_vp && vprocPid(active_vp) > 0 && vprocPid(active_vp) != shell_pid);
    VProcCommandScope scope;
    bool scoped = vprocCommandScopeBegin(&scope,
                                         label[0] ? label : (argv && argv[0] ? argv[0] : applet->name),
                                         force_new_vproc,
                                         false);
    int status = smallclueDispatchApplet(applet, argc, argv);
    if (scoped) {
        vprocCommandScopeEnd(&scope, status);
        if (dbg && *dbg) {
            fprintf(stderr, "[smallclue] vproc end pid=%d status=%d\n", scope.pid, status);
        }
    }
    return status;
#endif
}

static int smallclueWatchCommand(int argc, char **argv) {
    smallclueResetGetopt();
    smallclueClearPendingSignals();
    double interval = 2.0;
    int max_iterations = -1;
    int idx = 1;
    while (idx < argc) {
        const char *arg = argv[idx];
        if (!arg || arg[0] != '-') {
            break;
        }
        if (strcmp(arg, "--") == 0) {
            idx++;
            break;
        }
        if (strcmp(arg, "-n") == 0) {
            if (idx + 1 >= argc) {
                fprintf(stderr, "watch: option requires an argument -- n\n");
                return 1;
            }
            char *endptr = NULL;
            interval = strtod(argv[idx + 1], &endptr);
            if (!endptr || *endptr != '\0' || interval <= 0.0) {
                fprintf(stderr, "watch: invalid interval '%s'\n", argv[idx + 1]);
                return 1;
            }
            idx += 2;
            continue;
        }
        if (strcmp(arg, "-c") == 0 || strcmp(arg, "--count") == 0) {
            if (idx + 1 >= argc) {
                fprintf(stderr, "watch: option requires an argument -- count\n");
                return 1;
            }
            char *endptr = NULL;
            long count = strtol(argv[idx + 1], &endptr, 10);
            if (!endptr || *endptr != '\0' || count <= 0 || count > INT_MAX) {
                fprintf(stderr, "watch: invalid count '%s'\n", argv[idx + 1]);
                return 1;
            }
            max_iterations = (int)count;
            idx += 2;
            continue;
        }
        fprintf(stderr, "watch: unsupported option '%s'\n", arg);
        return 1;
    }

    int cmd_argc = argc - idx;
    if (cmd_argc < 1) {
        fprintf(stderr, "watch: command required\n");
        return 1;
    }
    char *cmdline = NULL;
    size_t cmdlen = 0;
    for (int i = idx; i < argc; ++i) {
        size_t part = strlen(argv[i]);
        char *next = (char *)realloc(cmdline, cmdlen + part + 2);
        if (!next) {
            free(cmdline);
            fprintf(stderr, "watch: out of memory\n");
            return 1;
        }
        cmdline = next;
        memcpy(cmdline + cmdlen, argv[i], part);
        cmdlen += part;
        cmdline[cmdlen++] = (i + 1 < argc) ? ' ' : '\0';
    }
#if defined(PSCAL_TARGET_IOS)
    /* Do not overwrite this process label with the watched command. The header
     * already displays the command line, and keeping the label stable ensures
     * vproc listings show both `watch` and the command it runs as distinct
     * synthetic tasks. */
#endif

    const SmallclueApplet *applet = smallclueFindApplet(argv[idx]);

    int status = 0;
    int iterations = 0;
    while (1) {
        int abort_status = 0;
        if (smallclueShouldAbort(&abort_status)) {
            status = abort_status;
            break;
        }
        /* Match the clear behavior of the standalone `clear` applet: clear
         * scrollback, home cursor, then clear the visible viewport. */
        fputs("\x1b[3J\x1b[H\x1b[2J", stdout);
        printf("Every %.2fs: %s\n\n", interval, cmdline ? cmdline : argv[idx]);
        fflush(stdout);
        status = smallclueWatchRunApplet(applet, cmd_argc, &argv[idx]);
        fflush(stdout);
        if (status >= 128 && status < 128 + NSIG) {
            int sig = status - 128;
            if (sig == SIGINT || sig == SIGTSTP || sig == SIGSTOP ||
                sig == SIGTTIN || sig == SIGTTOU) {
                goto watch_done;
            }
        }
        if (smallclueShouldAbort(&abort_status)) {
            status = abort_status;
            goto watch_done;
        }
        if (max_iterations > 0) {
            iterations++;
            if (iterations >= max_iterations) {
                break;
            }
        }
        struct timespec ts;
        ts.tv_sec = (time_t)interval;
        ts.tv_nsec = (long)((interval - (double)ts.tv_sec) * 1e9);
        if (ts.tv_nsec < 0) {
            ts.tv_nsec = 0;
        }
    while (nanosleep(&ts, &ts) == -1 && errno == EINTR) {
        if (smallclueShouldAbort(&abort_status)) {
            status = abort_status;
            goto watch_done;
        }
        continue;
    }
}

watch_done:
    free(cmdline);
#if defined(PSCAL_TARGET_IOS)
    /* label unchanged */
#endif
    return status;
}

static int smallclueSleepCommand(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: sleep seconds\n");
        return 1;
    }
    errno = 0;
    char *end = NULL;
    double seconds = strtod(argv[1], &end);
    if (errno != 0 || !end || *end != '\0' || seconds < 0) {
        fprintf(stderr, "sleep: invalid time interval '%s'\n", argv[1]);
        return 1;
    }
    struct timespec req;
    req.tv_sec = (time_t)seconds;
    req.tv_nsec = (long)((seconds - (double)req.tv_sec) * 1e9);
    if (req.tv_nsec < 0) {
        req.tv_nsec = 0;
    }
    struct timespec start;
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
        while (nanosleep(&req, &req) == -1 && errno == EINTR) {
            int abort_status = 0;
            if (smallclueShouldAbort(&abort_status)) {
                return abort_status;
            }
        }
        return 0;
    }
    struct timespec deadline = start;
    deadline.tv_sec += req.tv_sec;
    deadline.tv_nsec += req.tv_nsec;
    if (deadline.tv_nsec >= 1000000000L) {
        deadline.tv_sec += 1;
        deadline.tv_nsec -= 1000000000L;
    }
    while (true) {
        int abort_status = 0;
        if (smallclueShouldAbort(&abort_status)) {
            return abort_status;
        }
        struct timespec now;
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
            break;
        }
        if (now.tv_sec > deadline.tv_sec ||
            (now.tv_sec == deadline.tv_sec && now.tv_nsec >= deadline.tv_nsec)) {
            break;
        }
        double remaining = (double)(deadline.tv_sec - now.tv_sec) +
                           ((double)(deadline.tv_nsec - now.tv_nsec) / 1e9);
        if (remaining < 0.0) {
            break;
        }
        double slice = remaining > 0.1 ? 0.1 : remaining;
        struct timespec chunk;
        chunk.tv_sec = (time_t)slice;
        chunk.tv_nsec = (long)((slice - (double)chunk.tv_sec) * 1e9);
        if (chunk.tv_nsec < 0) {
            chunk.tv_nsec = 0;
        }
        (void)nanosleep(&chunk, NULL);
    }
    return 0;
}

static int smallclueBasenameCommand(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "basename: missing operand\n");
        return 1;
    }
    char *path = strdup(argv[1]);
    if (!path) {
        perror("basename");
        return 1;
    }
    char *base = basename(path);
    if (base) {
        puts(base);
    }
    free(path);
    return base ? 0 : 1;
}

static int smallclueDirnameCommand(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "dirname: missing operand\n");
        return 1;
    }
    char *path = strdup(argv[1]);
    if (!path) {
        perror("dirname");
        return 1;
    }
    char *dir = dirname(path);
    if (dir) {
        puts(dir);
    }
    free(path);
    return dir ? 0 : 1;
}

static int smallclueTeeCommand(int argc, char **argv) {
    smallclueResetGetopt();
    int append = 0;
    int opt;
    while ((opt = getopt(argc, argv, "a")) != -1) {
        if (opt == 'a') {
            append = 1;
        } else {
            fprintf(stderr, "usage: tee [-a] [file...]\n");
            return 1;
        }
    }
    int file_count = argc - optind;
    FILE **files = NULL;
    if (file_count > 0) {
        files = (FILE **)calloc((size_t)file_count, sizeof(FILE *));
        if (!files) {
            perror("tee");
            return 1;
        }
        for (int i = 0; i < file_count; ++i) {
            const char *mode = append ? "ab" : "wb";
            files[i] = fopen(argv[optind + i], mode);
            if (!files[i]) {
                fprintf(stderr, "tee: %s: %s\n", argv[optind + i], strerror(errno));
            }
        }
    }
    int status = 0;
    char buffer[4096];
    while (true) {
        int read_err = 0;
        ssize_t nread = smallclueReadStream(stdin, buffer, sizeof(buffer), &read_err);
        if (nread < 0) {
            perror("tee");
            status = 1;
            break;
        }
        if (nread == 0) {
            break;
        }
        if (fwrite(buffer, 1, (size_t)nread, stdout) != (size_t)nread) {
            perror("tee");
            status = 1;
            break;
        }
        for (int i = 0; i < file_count; ++i) {
            if (!files[i]) {
                continue;
            }
            if (fwrite(buffer, 1, (size_t)nread, files[i]) != (size_t)nread) {
                fprintf(stderr, "tee: %s: %s\n", argv[optind + i], strerror(errno));
                fclose(files[i]);
                files[i] = NULL;
                status = 1;
            }
        }
        if (read_err) {
            perror("tee");
            status = 1;
            break;
        }
    }
    if (files) {
        for (int i = 0; i < file_count; ++i) {
            if (files[i]) {
                fclose(files[i]);
            }
        }
        free(files);
    }
    return status;
}

static int smallclueScriptCommand(int argc, char **argv) {
    smallclueResetGetopt();
    int append = 0;
    int stop = 0;
    int opt;
    while ((opt = getopt(argc, argv, "ae")) != -1) {
        if (opt == 'a') {
            append = 1;
        } else if (opt == 'e') {
            stop = 1;
        } else {
            fprintf(stderr, "usage: script [-a] [-e] [file]\n");
            return 1;
        }
    }

    const char *path = (optind < argc) ? argv[optind] : "typescript";

    if (stop) {
        if (&PSCALRuntimeEndScriptCapture) {
            PSCALRuntimeEndScriptCapture();
            printf("Script capture stopped\n");
            return 0;
        }
        fprintf(stderr, "script: capture not available on this platform\n");
        return 1;
    }

    if (!&PSCALRuntimeBeginScriptCapture) {
        fprintf(stderr, "script: capture not available on this platform\n");
        return 1;
    }

    PSCALRuntimeBeginScriptCapture(path, append);
    if (&PSCALRuntimeScriptCaptureActive && !PSCALRuntimeScriptCaptureActive()) {
        fprintf(stderr, "script: failed to start capture for %s\n", path);
        return 1;
    }
    printf("Script started, file is %s%s\n", path, append ? " (append)" : "");
    return 0;
}

static int smallclueEditorCommand(int argc, char **argv) {
    return smallclueRunEditor(argc, argv);
}
static int smallclueSshCommand(int argc, char **argv) {
    return smallclueRunSsh(argc, argv);
}
static int smallclueScpCommand(int argc, char **argv) {
    return smallclueRunScp(argc, argv);
}
static int smallclueSftpCommand(int argc, char **argv) {
    return smallclueRunSftp(argc, argv);
}
static int smallclueSshKeygenCommand(int argc, char **argv) {
    return smallclueRunSshKeygen(argc, argv);
}
static int smallclueSshCopyIdCommand(int argc, char **argv) {
    return smallclueRunSshCopyId(argc, argv);
}
#if defined(PSCAL_TARGET_IOS)
static int smallclueAddTabCommand(int argc, char **argv) {
    (void)argc;
    (void)argv;
    if (!pscalRuntimeOpenShellTab) {
        fprintf(stderr, "addt: command unavailable\n");
        return 1;
    }
    int rc = pscalRuntimeOpenShellTab();
    if (rc != 0) {
        if (rc < 0) {
            errno = -rc;
        } else if (errno == 0) {
            errno = EIO;
        }
        fprintf(stderr, "addt: unable to open shell tab: %s\n", strerror(errno));
        return 1;
    }
    return 0;
}
#endif
#if SMALLCLUE_HAS_IFADDRS
static void smallclueIpAddrUsage(void) {
    fputs("usage: ipaddr [-4|-6] [-a]\n", stderr);
}

static bool smallclueShouldSkipInterface(const struct ifaddrs *ifa, int family, bool show_all) {
    if (show_all || !ifa) {
        return false;
    }
    if (ifa->ifa_flags & IFF_LOOPBACK) {
        return true;
    }
#if defined(AF_INET6)
    if (family == AF_INET6 && ifa->ifa_addr) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)ifa->ifa_addr;
        if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr) || IN6_IS_ADDR_MULTICAST(&sin6->sin6_addr)) {
            return true;
        }
    }
#endif
    return false;
}

static int smallclueIpAddrCommand(int argc, char **argv) {
    bool request_v4 = false;
    bool request_v6 = false;
    bool show_all = false;
    smallclueResetGetopt();
    int opt;
    while ((opt = getopt(argc, argv, "46ah")) != -1) {
        switch (opt) {
            case '4':
                request_v4 = true;
                break;
            case '6':
                request_v6 = true;
                break;
            case 'a':
                show_all = true;
                break;
            case 'h':
            default:
                smallclueIpAddrUsage();
                return 1;
        }
    }
    if (optind != argc) {
        smallclueIpAddrUsage();
        return 1;
    }
    bool show_v4 = request_v4 || (!request_v4 && !request_v6);
    bool show_v6 = request_v6 || (!request_v4 && !request_v6);

    struct ifaddrs *ifaddr = NULL;
    if (getifaddrs(&ifaddr) != 0) {
        fprintf(stderr, "ipaddr: getifaddrs failed: %s\n", strerror(errno));
        return 1;
    }

    bool printed = false;
    for (struct ifaddrs *ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) {
            continue;
        }
        int family = ifa->ifa_addr->sa_family;
        if (family == AF_INET) {
            if (!show_v4) continue;
        }
#if defined(AF_INET6)
        else if (family == AF_INET6) {
            if (!show_v6) continue;
        }
#endif
        else {
            continue;
        }
        if (smallclueShouldSkipInterface(ifa, family, show_all)) {
            continue;
        }

        char host[NI_MAXHOST];
        socklen_t addrlen = (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
        int flags = NI_NUMERICHOST;
        if (getnameinfo(ifa->ifa_addr, addrlen, host, sizeof(host), NULL, 0, flags) != 0) {
            continue;
        }
        printf("%-12s %-4s %s\n",
            ifa->ifa_name ? ifa->ifa_name : "(unknown)",
            (family == AF_INET) ? "IPv4" : "IPv6",
            host);
        printed = true;
    }
    freeifaddrs(ifaddr);
    if (!printed) {
        fprintf(stderr, "ipaddr: no matching interfaces\n");
        return 1;
    }
    return 0;
}
#endif

typedef struct {
    unsigned long long total_bytes;
    unsigned long long free_bytes;
    unsigned long long avail_bytes;
#if defined(SMALLCLUE_HAVE_STATFS) && defined(MNAMELEN)
    char mount_point[MNAMELEN];
#else
    char mount_point[PATH_MAX];
#endif
} SmallclueDfStats;

static bool smallclueDfQuery(const char *path, SmallclueDfStats *out) {
    if (!path || !*path || !out) {
        errno = EINVAL;
        return false;
    }
    memset(out, 0, sizeof(*out));
#if defined(SMALLCLUE_HAVE_STATVFS)
    struct statvfs st;
    if (statvfs(path, &st) != 0) {
        return false;
    }
    unsigned long long block_size = st.f_frsize ? st.f_frsize : st.f_bsize;
#elif defined(SMALLCLUE_HAVE_STATFS)
    struct statfs st;
    if (statfs(path, &st) != 0) {
        return false;
    }
    unsigned long long block_size = st.f_bsize ? st.f_bsize : st.f_iosize;
#else
#error "Either statvfs or statfs must be available for df command"
#endif
    if (block_size == 0) {
        errno = EINVAL;
        return false;
    }
#if defined(SMALLCLUE_HAVE_STATVFS)
    unsigned long long total_blocks = st.f_blocks;
    unsigned long long free_blocks = st.f_bfree;
    unsigned long long avail_blocks = st.f_bavail;
#else
    unsigned long long total_blocks = st.f_blocks;
    unsigned long long free_blocks = st.f_bfree;
    unsigned long long avail_blocks = st.f_bavail;
#endif
    out->total_bytes = total_blocks * block_size;
    out->free_bytes = free_blocks * block_size;
    out->avail_bytes = avail_blocks * block_size;
#if defined(SMALLCLUE_HAVE_STATFS) && defined(MNAMELEN)
    if (st.f_mntonname[0]) {
        strncpy(out->mount_point, st.f_mntonname, sizeof(out->mount_point) - 1);
        out->mount_point[sizeof(out->mount_point) - 1] = '\0';
    }
#endif
    if (out->mount_point[0] == '\0') {
        const char *label = path;
        char resolved[PATH_MAX];
        if (realpath(path, resolved)) {
            label = resolved;
        }
        strncpy(out->mount_point, label, sizeof(out->mount_point) - 1);
        out->mount_point[sizeof(out->mount_point) - 1] = '\0';
    }
    return true;
}

static void smallclueDfFormatSize(char *buf, size_t bufsize,
                                  unsigned long long bytes, bool human) {
    if (!buf || bufsize == 0) {
        return;
    }
    if (!human) {
        unsigned long long blocks = (bytes + 1023ULL) / 1024ULL;
        snprintf(buf, bufsize, "%llu", blocks);
        return;
    }
    static const char *suffixes[] = {"B", "K", "M", "G", "T", "P"};
    size_t idx = 0;
    long double value = (long double)bytes;
    while (value >= 1024.0L && idx + 1 < sizeof(suffixes) / sizeof(suffixes[0])) {
        value /= 1024.0L;
        idx++;
    }
    if (idx == 0) {
        /* Bytes should not show fractional values. */
        snprintf(buf, bufsize, "%.0Lf%s", value, suffixes[idx]);
    } else if (value >= 100.0L) {
        snprintf(buf, bufsize, "%.0Lf%s", value, suffixes[idx]);
    } else if (value >= 10.0L) {
        snprintf(buf, bufsize, "%.1Lf%s", value, suffixes[idx]);
    } else {
        snprintf(buf, bufsize, "%.2Lf%s", value, suffixes[idx]);
    }
}

static void smallclueDfPrintHeader(bool human) {
    printf("%-24s %12s %12s %12s %6s %s\n",
           "Filesystem",
           human ? "Size" : "1K-blocks",
           human ? "Used" : "Used",
           human ? "Avail" : "Avail",
           "Use%",
           "Mounted on");
}

static int smallclueDfCommand(int argc, char **argv) {
    const char *usage = "usage: df [-h] [path ...]\n";
    bool human = false;
    smallclueResetGetopt();
    int opt;
    while ((opt = getopt(argc, argv, "h")) != -1) {
        switch (opt) {
            case 'h':
                human = true;
                break;
            default:
                fputs(usage, stderr);
                return 1;
        }
    }
    int path_start = optind;
    int path_count = (optind < argc) ? (argc - optind) : 0;
    smallclueDfPrintHeader(human);
    int status = 0;
    for (int i = 0; i < (path_count > 0 ? path_count : 1); ++i) {
        const char *path = (path_count > 0) ? argv[path_start + i] : ".";
        SmallclueDfStats stats;
        if (!smallclueDfQuery(path, &stats)) {
            fprintf(stderr, "df: %s: %s\n", path ? path : "(null)", strerror(errno));
            status = 1;
            continue;
        }
        unsigned long long used_bytes = (stats.total_bytes > stats.free_bytes)
                                            ? stats.total_bytes - stats.free_bytes
                                            : 0;
        unsigned long long avail_bytes = stats.avail_bytes;
        long double denom = (long double)used_bytes + (long double)avail_bytes;
        long double percent = (denom > 0.0L) ? (long double)used_bytes / denom * 100.0L : 0.0L;
        char total_buf[32];
        char used_buf[32];
        char avail_buf[32];
        smallclueDfFormatSize(total_buf, sizeof total_buf, stats.total_bytes, human);
        smallclueDfFormatSize(used_buf, sizeof used_buf, used_bytes, human);
        smallclueDfFormatSize(avail_buf, sizeof avail_buf, avail_bytes, human);
        printf("%-24s %12s %12s %12s %5.0Lf%% %s\n",
               stats.mount_point[0] ? stats.mount_point : (path ? path : ""),
               total_buf,
               used_buf,
               avail_buf,
               percent,
               path ? path : stats.mount_point);
    }
    return status;
}
static int smallcluePingAttempt(const struct sockaddr *addr, socklen_t addrlen, int family, int timeout_ms, double *out_ms, int probe_port) {
    int sock = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (sock < 0) {
        return -1;
    }
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    }
    struct timespec start, end;
    clock_gettime(CLOCK_MONOTONIC, &start);
    int rc = -1;
    // If a specific port was provided, override it in the sockaddr.
    if (probe_port > 0) {
        if (addr->sa_family == AF_INET && addrlen >= sizeof(struct sockaddr_in)) {
            struct sockaddr_in tmp;
            memcpy(&tmp, addr, sizeof(tmp));
            tmp.sin_port = htons((uint16_t)probe_port);
            rc = connect(sock, (struct sockaddr *)&tmp, sizeof(tmp));
        } else if (addr->sa_family == AF_INET6 && addrlen >= sizeof(struct sockaddr_in6)) {
            struct sockaddr_in6 tmp6;
            memcpy(&tmp6, addr, sizeof(tmp6));
            tmp6.sin6_port = htons((uint16_t)probe_port);
            rc = connect(sock, (struct sockaddr *)&tmp6, sizeof(tmp6));
        } else {
            rc = connect(sock, addr, addrlen);
        }
    } else {
        rc = connect(sock, addr, addrlen);
    }
    if (rc < 0 && errno == EINPROGRESS) {
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(sock, &wfds);
        struct timeval tv;
        tv.tv_sec = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;
        rc = select(sock + 1, NULL, &wfds, NULL, &tv);
        if (rc <= 0) {
            close(sock);
            errno = (rc == 0) ? ETIMEDOUT : errno;
            return -1;
        }
        int so_error = 0;
        socklen_t slen = sizeof(so_error);
        if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &so_error, &slen) < 0 || so_error != 0) {
            if (so_error != 0) {
                errno = so_error;
            }
            close(sock);
            return -1;
        }
    } else if (rc < 0) {
        close(sock);
        return -1;
    }
    clock_gettime(CLOCK_MONOTONIC, &end);
    close(sock);
    if (out_ms) {
        double start_ms = (double)start.tv_sec * 1000.0 + (double)start.tv_nsec / 1e6;
        double end_ms = (double)end.tv_sec * 1000.0 + (double)end.tv_nsec / 1e6;
        *out_ms = end_ms - start_ms;
    }
    return 0;
}

static int smallcluePingCommand(int argc, char **argv) {
    const char *usage = "usage: ping [-c count] [-p port] [-t timeout_ms] host\n";
    if (argc <= 1) {
        fputs(usage, stderr);
        return 1;
    }
    smallclueResetGetopt();
    int count = 4;
    int timeout_ms = 3000;
    int probe_port = 80;
    int opt;
    while ((opt = getopt(argc, argv, "c:p:t:")) != -1) {
        switch (opt) {
            case 'c':
                count = atoi(optarg);
                if (count <= 0) count = 4;
                break;
            case 'p':
                probe_port = atoi(optarg);
                if (probe_port <= 0 || probe_port > 65535) {
                    fprintf(stderr, "ping: invalid port '%s'\n", optarg);
                    return 1;
                }
                break;
            case 't':
                timeout_ms = atoi(optarg);
                if (timeout_ms <= 0) timeout_ms = 3000;
                break;
            default:
                fputs(usage, stderr);
                return 1;
        }
    }
    if (optind >= argc) {
        fputs(usage, stderr);
        return 1;
    }
    const char *host = argv[optind];
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    struct addrinfo *res = NULL;
    char portbuf[16];
    snprintf(portbuf, sizeof(portbuf), "%d", probe_port);
    int gai = pscalHostsGetAddrInfo(host, portbuf, &hints, &res);
    if (gai != 0) {
        fprintf(stderr, "ping: %s: %s\n", host, gai_strerror(gai));
        return 1;
    }
    struct addrinfo *selected = res;
    if (!selected) {
        fprintf(stderr, "ping: no addresses resolved for %s\n", host);
        freeaddrinfo(res);
        return 1;
    }
    struct sockaddr_storage target_addr;
    memcpy(&target_addr, selected->ai_addr, selected->ai_addrlen);
    socklen_t target_len = (socklen_t)selected->ai_addrlen;
    char addrbuf[NI_MAXHOST];
    if (getnameinfo((struct sockaddr *)&target_addr, target_len,
            addrbuf, sizeof(addrbuf), NULL, 0, NI_NUMERICHOST) != 0) {
        strncpy(addrbuf, "unknown", sizeof(addrbuf));
        addrbuf[sizeof(addrbuf) - 1] = '\0';
    }
    printf("PING %s (%s) TCP port %d, %d probes, timeout %d ms\n",
        host, addrbuf, probe_port, count, timeout_ms);
    int successes = 0;
    double min_ms = 0.0, max_ms = 0.0, total_ms = 0.0;
    for (int i = 0; i < count; ++i) {
        double elapsed = 0.0;
        int rc = smallcluePingAttempt((struct sockaddr *)&target_addr, target_len,
            selected->ai_family, timeout_ms, &elapsed, probe_port);
        if (rc == 0) {
            successes++;
            if (successes == 1 || elapsed < min_ms) min_ms = elapsed;
            if (elapsed > max_ms) max_ms = elapsed;
            total_ms += elapsed;
            printf("attempt %d: connected in %.2f ms\n", i + 1, elapsed);
        } else {
            printf("attempt %d: failed (%s)\n", i + 1, strerror(errno));
        }
        fflush(stdout);
        if (i + 1 < count) {
            usleep(500000);
        }
    }
    printf("--- %s ping statistics ---\n", host);
    printf("%d probes sent, %d successful, %d failed\n",
        count, successes, count - successes);
    if (successes > 0) {
        printf("round-trip min/avg/max = %.2f/%.2f/%.2f ms (TCP port %d)\n",
            min_ms, total_ms / successes, max_ms, probe_port);
    }
    pscalHostsFreeAddrInfo(res);
    return (successes > 0) ? 0 : 1;
}

#define TELNET_DEFAULT_PORT 23
#define TELNET_BUF_SIZE 4096

static int smallclueTelnetCommand(int argc, char **argv) {
    smallclueResetGetopt();
    int port = TELNET_DEFAULT_PORT;
    int opt;
    while ((opt = getopt(argc, argv, "p:")) != -1) {
        switch (opt) {
            case 'p':
                port = atoi(optarg);
                if (port <= 0 || port > 65535) {
                    fprintf(stderr, "telnet: invalid port '%s'\n", optarg);
                    return 1;
                }
                break;
            default:
                fprintf(stderr, "usage: telnet [-p PORT] HOST\n");
                return 1;
        }
    }
    if (optind >= argc) {
        fprintf(stderr, "usage: telnet [-p PORT] HOST\n");
        return 1;
    }
    const char *host = argv[optind];
    char port_str[16];
    snprintf(port_str, sizeof(port_str), "%d", port);

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;

    struct addrinfo *res = NULL;
    int gai = pscalHostsGetAddrInfo(host, port_str, &hints, &res);
    if (gai != 0 || !res) {
        fprintf(stderr, "telnet: %s: %s\n", host, gai_strerror(gai));
        return 1;
    }

    int sock = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock < 0) {
            continue;
        }
        if (connect(sock, ai->ai_addr, ai->ai_addrlen) == 0) {
            break;
        }
        close(sock);
        sock = -1;
    }
    pscalHostsFreeAddrInfo(res);
    if (sock < 0) {
        fprintf(stderr, "telnet: unable to connect to %s:%d\n", host, port);
        return 1;
    }

    int status = 0;
    bool running = true;
    while (running) {
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(sock, &rfds);
        FD_SET(STDIN_FILENO, &rfds);
        int maxfd = (sock > STDIN_FILENO) ? sock : STDIN_FILENO;
        int rv = select(maxfd + 1, &rfds, NULL, NULL, NULL);
        if (rv < 0) {
            if (errno == EINTR) continue;
            status = 1;
            break;
        }
        if (FD_ISSET(sock, &rfds)) {
            char buf[TELNET_BUF_SIZE];
            ssize_t n = read(sock, buf, sizeof(buf));
            if (n <= 0) {
                running = false;
            } else {
                ssize_t off = 0;
                while (off < n) {
                    ssize_t w = write(STDOUT_FILENO, buf + off, (size_t)(n - off));
                    if (w < 0) {
                        if (errno == EINTR) continue;
                        running = false;
                        status = 1;
                        break;
                    }
                    off += w;
                }
            }
        }
        if (FD_ISSET(STDIN_FILENO, &rfds)) {
            char buf[TELNET_BUF_SIZE];
            ssize_t n = read(STDIN_FILENO, buf, sizeof(buf));
            if (n <= 0) {
                shutdown(sock, SHUT_WR);
            } else {
                ssize_t off = 0;
                while (off < n) {
                    ssize_t w = write(sock, buf + off, (size_t)(n - off));
                    if (w < 0) {
                        if (errno == EINTR) continue;
                        running = false;
                        status = 1;
                        break;
                    }
                    off += w;
                }
            }
        }
    }
    close(sock);
    return status;
}

static int smallclueTracerouteCommand(int argc, char **argv) {
    // Simple, in-process traceroute using UDP probes and ICMP replies (IPv4 only).
    smallclueResetGetopt();
    int max_hops = 30;
    int probes = 3;
    int timeout_ms = 1500;
    int dest_port = 33434;

    int opt;
    while ((opt = getopt(argc, argv, "m:q:w:p:")) != -1) {
        switch (opt) {
            case 'm': max_hops = atoi(optarg); break;
            case 'q': probes = atoi(optarg); break;
            case 'w': timeout_ms = atoi(optarg); break;
            case 'p': dest_port = atoi(optarg); break;
            default:
                fprintf(stderr, "usage: traceroute [-m max_hops] [-q probes] [-w timeout_ms] [-p port] HOST\n");
                return 1;
        }
    }
    if (optind >= argc) {
        fprintf(stderr, "usage: traceroute [-m max_hops] [-q probes] [-w timeout_ms] [-p port] HOST\n");
        return 1;
    }
    const char *host = argv[optind];

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    struct addrinfo *res = NULL;
    char portbuf[16];
    snprintf(portbuf, sizeof(portbuf), "%d", dest_port);
    int gai = pscalHostsGetAddrInfo(host, portbuf, &hints, &res);
    if (gai != 0 || !res) {
        fprintf(stderr, "traceroute: %s: %s\n", host, gai_strerror(gai));
        return 1;
    }

    int recv_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (recv_sock < 0) {
        fprintf(stderr, "traceroute: unable to open ICMP socket: %s\n", strerror(errno));
        pscalHostsFreeAddrInfo(res);
        return 1;
    }

    int send_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (send_sock < 0) {
        fprintf(stderr, "traceroute: unable to open UDP socket: %s\n", strerror(errno));
        close(recv_sock);
        pscalHostsFreeAddrInfo(res);
        return 1;
    }

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(recv_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    printf("traceroute to %s (%s), %d hops max\n", host,
           inet_ntoa(((struct sockaddr_in *)res->ai_addr)->sin_addr), max_hops);

    bool reached = false;
    for (int ttl = 1; ttl <= max_hops && !reached; ttl++) {
        if (setsockopt(send_sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
            fprintf(stderr, "traceroute: setsockopt(IP_TTL) failed: %s\n", strerror(errno));
            break;
        }

        printf("%2d ", ttl);
        fflush(stdout);
        bool got_reply = false;

        for (int p = 0; p < probes; p++) {
            struct sockaddr_in dest;
            memcpy(&dest, res->ai_addr, sizeof(dest));
            dest.sin_port = htons((uint16_t)(dest_port + ttl + p));

            struct timeval start, end;
            gettimeofday(&start, NULL);
            sendto(send_sock, "", 0, 0, (struct sockaddr *)&dest, sizeof(dest));

            unsigned char buf[1500];
            struct sockaddr_in reply_addr;
            socklen_t rlen = sizeof(reply_addr);
            ssize_t n = recvfrom(recv_sock, buf, sizeof(buf), 0, (struct sockaddr *)&reply_addr, &rlen);
            if (n < (ssize_t)(sizeof(struct ip) + sizeof(struct icmp))) {
                printf(" *");
                fflush(stdout);
                continue;
            }

            gettimeofday(&end, NULL);
            double rtt = (end.tv_sec - start.tv_sec) * 1000.0 + (end.tv_usec - start.tv_usec) / 1000.0;

            struct ip *ip_hdr = (struct ip *)buf;
            int ip_hdr_len = ip_hdr->ip_hl << 2;
            struct icmp *icmp_hdr = (struct icmp *)(buf + ip_hdr_len);

            printf(" %s  %.3f ms", inet_ntoa(reply_addr.sin_addr), rtt);
            got_reply = true;

            if (icmp_hdr->icmp_type == ICMP_UNREACH && icmp_hdr->icmp_code == ICMP_UNREACH_PORT) {
                reached = true;
            }
        }

        if (!got_reply) {
            printf(" *");
        }
        printf("\n");
    }

    close(send_sock);
    close(recv_sock);
    freeaddrinfo(res);
    return reached ? 0 : 1;
}

#if defined(PSCAL_TARGET_IOS)
static bool smallclueParseRuntimeLogLine(const char *line, time_t *out_seconds, int *out_millis, const char **out_message) {
    if (!line || line[0] != '[') {
        return false;
    }
    const char *end = strchr(line, ']');
    if (!end) {
        return false;
    }
    const char *ts_start = line + 1;
    const char *dot = memchr(ts_start, '.', (size_t)(end - ts_start));
    if (!dot) {
        return false;
    }
    errno = 0;
    char *sec_end = NULL;
    long long seconds = strtoll(ts_start, &sec_end, 10);
    if (errno != 0 || sec_end != dot) {
        return false;
    }
    const char *ms_start = dot + 1;
    if (ms_start >= end) {
        return false;
    }
    int millis = 0;
    int digits = 0;
    for (const char *p = ms_start; p < end; ++p) {
        if (!isdigit((unsigned char)*p)) {
            return false;
        }
        if (digits < 3) {
            millis = (millis * 10) + (*p - '0');
        }
        digits++;
    }
    if (digits == 0) {
        return false;
    }
    if (digits == 1) {
        millis *= 100;
    } else if (digits == 2) {
        millis *= 10;
    }
    if (out_seconds) {
        *out_seconds = (time_t)seconds;
    }
    if (out_millis) {
        *out_millis = millis;
    }
    if (out_message) {
        const char *message = end + 1;
        if (*message == ' ') {
            message++;
        }
        *out_message = message;
    }
    return true;
}

static void smallclueDmesgPrintLineHuman(const char *line) {
    time_t seconds = 0;
    int millis = 0;
    const char *message = NULL;
    if (!smallclueParseRuntimeLogLine(line, &seconds, &millis, &message)) {
        fputs(line, stdout);
        fputc('\n', stdout);
        return;
    }
    struct tm tm_val;
    char time_buf[64];
    if (!localtime_r(&seconds, &tm_val) ||
        strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", &tm_val) == 0) {
        fputs(line, stdout);
        fputc('\n', stdout);
        return;
    }
    if (message && *message) {
        fprintf(stdout, "[%s.%03d] %s\n", time_buf, millis, message);
    } else {
        fprintf(stdout, "[%s.%03d]\n", time_buf, millis);
    }
}

static int smallclueDmesgCommand(int argc, char **argv) {
    smallclueResetGetopt();
    int human = 0;
    int opt;
    while ((opt = getopt(argc, argv, "T")) != -1) {
        switch (opt) {
            case 'T':
                human = 1;
                break;
            default:
                fprintf(stderr, "usage: dmesg [-T]\n");
                return 1;
        }
    }
    if (optind < argc) {
        fprintf(stderr, "usage: dmesg [-T]\n");
        return 1;
    }
    if (pscalRuntimeCopySessionLog) {
        char *snapshot = pscalRuntimeCopySessionLog();
        if (snapshot) {
            if (!human) {
                fputs(snapshot, stdout);
                size_t len = strlen(snapshot);
                if (len > 0 && snapshot[len - 1] != '\n') {
                    fputc('\n', stdout);
                }
            } else {
                char *cursor = snapshot;
                while (cursor && *cursor) {
                    char *line_end = strchr(cursor, '\n');
                    if (line_end) {
                        *line_end = '\0';
                    }
                    if (*cursor != '\0') {
                        smallclueDmesgPrintLineHuman(cursor);
                    }
                    if (!line_end) {
                        break;
                    }
                    cursor = line_end + 1;
                }
            }
            fflush(stdout);
            free(snapshot);
            return 0;
        }
    }
    fprintf(stderr, "dmesg: session log unavailable\n");
    return 1;
}
#endif

static int smallclueCatCommand(int argc, char **argv) {
    int status = 0;
    if (argc <= 1) {
        return cat_file(NULL);
    }
    for (int i = 1; i < argc; ++i) {
        status |= cat_file(argv[i]);
    }
    return status ? 1 : 0;
}

static int smallcluePagerCommand(int argc, char **argv) {
    const char *cmd_name = pager_command_name(argv && argc > 0 ? argv[0] : NULL);
    int status = 0;
    if (argc <= 1) {
        if (pscalRuntimeStdinIsInteractive()) {
            fprintf(stderr, "%s: missing filename\n", cmd_name);
            return 1;
        }
        return pager_file(cmd_name, "(stdin)", stdin);
    }
    for (int i = 1; i < argc; ++i) {
        const char *path = argv[i];
        if (!path || strcmp(path, "-") == 0) {
            status |= pager_file(cmd_name, "(stdin)", stdin);
            continue;
        }
        FILE *fp = fopen(path, "r");
        if (!fp) {
            fprintf(stderr, "%s: %s: %s\n", cmd_name, path, strerror(errno));
            status = 1;
            continue;
        }
        status |= pager_file(cmd_name, path, fp);
        fclose(fp);
    }
    return status ? 1 : 0;
}

static int smallclueMarkdownCommand(int argc, char **argv) {
    smallclueResetGetopt();
    int list_only = 0;
    int interactive = 0;
    int opt;
    while ((opt = getopt(argc, argv, "il")) != -1) {
        switch (opt) {
            case 'i':
                interactive = 1;
                break;
            case 'l':
                list_only = 1;
                break;
            default:
                fprintf(stderr, "usage: md [-i | -l] [file|url ...]\n");
                return 1;
        }
    }
    if (interactive) {
        if (optind < argc) {
            fprintf(stderr, "md: -i cannot be combined with file arguments\n");
            return 1;
        }
        return markdownInteractiveSelectDocument();
    }
    if (list_only || optind >= argc) {
        return smallclueMarkdownListDocuments();
    }
    int status = 0;
    for (int i = optind; i < argc; ++i) {
        status |= smallclueMarkdownBrowseTarget(argv[i]);
    }
    return status ? 1 : 0;
}

static int smallclueCurlCommand(int argc, char **argv) {
    smallclueResetGetopt();
    const char *output_path = NULL;
    int use_remote_name = 0;
    int opt;
    while ((opt = getopt(argc, argv, "o:O")) != -1) {
        switch (opt) {
            case 'o':
                output_path = optarg;
                break;
            case 'O':
                use_remote_name = 1;
                break;
            default:
                fprintf(stderr, "usage: curl [-o file | -O] url...\n");
                return 1;
        }
    }
    if (output_path && use_remote_name) {
        fprintf(stderr, "curl: -o and -O may not be used together\n");
        return 1;
    }
    if (optind >= argc) {
        fprintf(stderr, "curl: missing URL\n");
        return 1;
    }
    if (output_path && (argc - optind) != 1) {
        fprintf(stderr, "curl: -o is only supported with a single URL\n");
        return 1;
    }
    int status = 0;
    for (int i = optind; i < argc; ++i) {
        const char *url = argv[i];
        const char *destination = NULL;
        char derived[PATH_MAX];
        if (output_path) {
            destination = output_path;
        } else if (use_remote_name) {
            smallclueUrlSuggestFilename(url, derived, sizeof(derived));
            destination = derived;
        }
        status |= smallclueHttpFetch("curl", url, destination);
    }
    return status ? 1 : 0;
}

static int smallclueWgetCommand(int argc, char **argv) {
    smallclueResetGetopt();
    const char *output_path = NULL;
    int opt;
    while ((opt = getopt(argc, argv, "O:")) != -1) {
        switch (opt) {
            case 'O':
                output_path = optarg;
                break;
            default:
                fprintf(stderr, "usage: wget [-O file] url...\n");
                return 1;
        }
    }
    if (optind >= argc) {
        fprintf(stderr, "wget: missing URL\n");
        return 1;
    }
    if (output_path && (argc - optind) != 1) {
        fprintf(stderr, "wget: -O is only supported with a single URL\n");
        return 1;
    }
    int status = 0;
    for (int i = optind; i < argc; ++i) {
        const char *url = argv[i];
        const char *destination = output_path;
        char derived[PATH_MAX];
        if (!destination) {
            smallclueUrlSuggestFilename(url, derived, sizeof(derived));
            destination = derived;
        }
        int rc = smallclueHttpFetch("wget", url, destination);
        if (rc == 0) {
            printf("Saved %s -> %s\n", url, destination ? destination : "(stdout)");
        }
        status |= rc;
    }
    return status ? 1 : 0;
}

static int smallclueClearCommand(int argc, char **argv) {
    (void)argc;
    (void)argv;
    /* Clear screen and scrollback, then home cursor. */
    fputs("\x1b[3J\x1b[H\x1b[2J", stdout);
    fflush(stdout);
    return 0;
}

static int smallclueDateCommand(int argc, char **argv) {
    int arg_index = 1;
    int use_utc = 0;
    const char *format = "%a %b %e %T %Z %Y";

    while (arg_index < argc && argv[arg_index] && argv[arg_index][0] == '-') {
        const char *opt = argv[arg_index];
        if (strcmp(opt, "-u") == 0 || strcmp(opt, "--utc") == 0 || strcmp(opt, "--universal") == 0) {
            use_utc = 1;
            arg_index++;
            continue;
        }
        if (strcmp(opt, "--") == 0) {
            arg_index++;
            break;
        }
        fprintf(stderr, "date: unsupported option '%s'\n", opt);
        return 1;
    }

    if (arg_index < argc) {
        const char *fmt = argv[arg_index];
        if (fmt && fmt[0] == '+') {
            format = fmt + 1;
            arg_index++;
        } else {
            fprintf(stderr, "date: invalid format specifier '%s'\n", fmt ? fmt : "(null)");
            return 1;
        }
    }

    if (arg_index < argc) {
        fprintf(stderr, "date: too many operands\n");
        return 1;
    }

    time_t now = time(NULL);
    if (now == (time_t)-1) {
        perror("date");
        return 1;
    }
    struct tm tm_buf;
    struct tm *tm_val = use_utc ? gmtime(&now) : localtime(&now);
    if (!tm_val) {
        perror("date");
        return 1;
    }
    tm_buf = *tm_val;
    char buffer[256];
    size_t len = strftime(buffer, sizeof(buffer), format, &tm_buf);
    if (len == 0) {
        fprintf(stderr, "date: failed to format date\n");
        return 1;
    }
    printf("%s\n", buffer);
    return 0;
}

static bool smallclueParseInt(const char *text, int min, int max, int *out_value) {
    if (!text || !*text) {
        return false;
    }
    char *endptr = NULL;
    long value = strtol(text, &endptr, 10);
    if (!endptr || *endptr != '\0') {
        return false;
    }
    if (value < min || value > max) {
        return false;
    }
    if (out_value) {
        *out_value = (int)value;
    }
    return true;
}

static bool smallclueIsLeapYear(int year) {
    return ((year % 4 == 0 && year % 100 != 0) || (year % 400 == 0));
}

static int smallclueDaysInMonth(int month, int year) {
    static const int days_per_month[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    if (month < 1 || month > 12) {
        return 30;
    }
    if (month == 2 && smallclueIsLeapYear(year)) {
        return 29;
    }
    return days_per_month[month - 1];
}

static int smallclueFirstWeekdayOfMonth(int month, int year) {
    struct tm tm_buf;
    memset(&tm_buf, 0, sizeof(tm_buf));
    tm_buf.tm_year = year - 1900;
    tm_buf.tm_mon = month - 1;
    tm_buf.tm_mday = 1;
    tm_buf.tm_isdst = -1;
    if (mktime(&tm_buf) == (time_t)-1) {
        return 0;
    }
    return tm_buf.tm_wday; /* 0 = Sunday */
}

static int smallclueCalCommand(int argc, char **argv) {
    int month = 0;
    int year = 0;

    if (argc == 1) {
        time_t now = time(NULL);
        if (now == (time_t)-1) {
            perror("cal");
            return 1;
        }
        struct tm *tm_now = localtime(&now);
        if (!tm_now) {
            perror("cal");
            return 1;
        }
        month = tm_now->tm_mon + 1;
        year = tm_now->tm_year + 1900;
    } else if (argc == 3) {
        if (!smallclueParseInt(argv[1], 1, 12, &month) || !smallclueParseInt(argv[2], 1, 9999, &year)) {
            fprintf(stderr, "cal: usage: cal [month] [year]\n");
            return 1;
        }
    } else {
        fprintf(stderr, "cal: usage: cal [month] [year]\n");
        return 1;
    }

    struct tm display_tm;
    memset(&display_tm, 0, sizeof(display_tm));
    display_tm.tm_year = year - 1900;
    display_tm.tm_mon = month - 1;
    display_tm.tm_mday = 1;
    char header[64];
    if (strftime(header, sizeof(header), "%B %Y", &display_tm) == 0) {
        snprintf(header, sizeof(header), "Month %d", year);
    }

    printf("      %s\n", header);
    printf("Su Mo Tu We Th Fr Sa\n");

    int first_wday = smallclueFirstWeekdayOfMonth(month, year);
    int days = smallclueDaysInMonth(month, year);
    int current_wday = 0;

    for (current_wday = 0; current_wday < first_wday; ++current_wday) {
        fputs("   ", stdout);
    }

    for (int day = 1; day <= days; ++day) {
        printf("%2d", day);
        current_wday++;
        if (current_wday % 7 == 0) {
            putchar('\n');
        } else {
            putchar(' ');
        }
    }
    if (current_wday % 7 != 0) {
        putchar('\n');
    }
    return 0;
}

static const char *smallclueStrCaseStr(const char *haystack, const char *needle, int ignore_case) {
    if (!haystack || !needle || !*needle) {
        return haystack;
    }
    size_t needle_len = strlen(needle);
    for (const char *p = haystack; *p; ++p) {
        size_t i = 0;
        for (; i < needle_len; ++i) {
            char hc = p[i];
            char nc = needle[i];
            if (!hc) {
                break;
            }
            if (ignore_case) {
                hc = (char)tolower((unsigned char)hc);
                nc = (char)tolower((unsigned char)nc);
            }
            if (hc != nc) {
                break;
            }
        }
        if (i == needle_len) {
            return p;
        }
    }
    return NULL;
}

static bool smallclueParseDashLineCount(const char *arg, long *value) {
    if (!arg || !value || arg[0] != '-' || arg[1] == '\0') {
        return false;
    }
    if (arg[1] == '-') {
        return false;
    }
    const char *p = arg + 1;
    while (*p) {
        if (*p < '0' || *p > '9') {
            return false;
        }
        p++;
    }
    char *endptr = NULL;
    long parsed = strtol(arg + 1, &endptr, 10);
    if (!endptr || *endptr != '\0') {
        return false;
    }
    *value = parsed;
    return true;
}

static int smallclueHeadStream(FILE *fp, const char *label, long lines) {
    if (lines <= 0) {
        return 0;
    }
    char *line = NULL;
    size_t cap = 0;
    long remaining = lines;
    int status = 0;
    while (remaining > 0) {
        int read_err = 0;
        ssize_t len = smallclueGetlineStream(&line, &cap, fp, &read_err);
        if (len < 0) {
            if (read_err) {
                fprintf(stderr, "head: %s: %s\n",
                        label ? label : "(stdin)",
                        strerror(read_err));
                status = 1;
            }
            break;
        }
        fwrite(line, 1, (size_t)len, stdout);
        remaining--;
    }
    free(line);
    return status;
}

static int smallclueHeadCommand(int argc, char **argv) {
    long lines = 10;
    int index = 1;
    while (index < argc) {
        const char *arg = argv[index];
        if (!arg || arg[0] != '-') {
            break;
        }
        if (strcmp(arg, "--") == 0) {
            index++;
            break;
        }
        if (strcmp(arg, "-n") == 0) {
            if (index + 1 >= argc) {
                fprintf(stderr, "head: option requires an argument -- n\n");
                return 1;
            }
            char *endptr = NULL;
            lines = strtol(argv[index + 1], &endptr, 10);
            if (!endptr || *endptr != '\0') {
                fprintf(stderr, "head: invalid line count '%s'\n", argv[index + 1]);
                return 1;
            }
            index += 2;
            continue;
        }
        long dashLines = 0;
        if (smallclueParseDashLineCount(arg, &dashLines)) {
            lines = dashLines;
            index += 1;
            continue;
        }
        fprintf(stderr, "head: unsupported option '%s'\n", arg);
        return 1;
    }

    int status = 0;
    if (index >= argc) {
        status = smallclueHeadStream(stdin, "(stdin)", lines);
    } else {
        for (int i = index; i < argc; ++i) {
            const char *path = argv[i];
            FILE *fp = fopen(path, "r");
            if (!fp) {
                fprintf(stderr, "head: %s: %s\n", path, strerror(errno));
                status = 1;
                continue;
            }
            status |= smallclueHeadStream(fp, path, lines);
            fclose(fp);
        }
    }
    return status ? 1 : 0;
}

static int smallclueTailStream(FILE *fp, const char *label, long lines) {
    if (lines <= 0) {
        return 0;
    }
    char **ring = (char **)calloc((size_t)lines, sizeof(char *));
    if (!ring) {
        fprintf(stderr, "tail: %s: out of memory\n", label ? label : "(stdin)");
        return 1;
    }
    char *line = NULL;
    size_t cap = 0;
    long count = 0;
    int status = 0;
    while (1) {
        int read_err = 0;
        ssize_t len = smallclueGetlineStream(&line, &cap, fp, &read_err);
        if (len < 0) {
            if (read_err) {
                fprintf(stderr, "tail: %s: %s\n",
                        label ? label : "(stdin)",
                        strerror(read_err));
                status = 1;
            }
            break;
        }
        char *copy = (char *)malloc((size_t)len + 1);
        if (!copy) {
            fprintf(stderr, "tail: %s: out of memory\n", label ? label : "(stdin)");
            status = 1;
            break;
        }
        memcpy(copy, line, (size_t)len);
        copy[len] = '\0';
        long slot = count % lines;
        free(ring[slot]);
        ring[slot] = copy;
        count++;
    }
    if (status == 0) {
        long start = count > lines ? count - lines : 0;
        for (long i = start; i < count; ++i) {
            char *entry = ring[i % lines];
            if (entry) {
                fputs(entry, stdout);
            }
        }
    }
    free(line);
    for (long i = 0; i < lines; ++i) {
        free(ring[i]);
    }
    free(ring);
    return status;
}

static int smallclueTailFollow(FILE *fp, const char *label, long lines) {
    int status = smallclueTailStream(fp, label, lines);
    if (status != 0) {
        return status;
    }
    int fd = fileno(fp);
    if (fd < 0) {
        fprintf(stderr, "tail: %s: bad file descriptor\n", label ? label : "(stdin)");
        return 1;
    }

    /* Start following from the current end-of-file position. */
    off_t lastPos;
#if defined(__APPLE__)
    lastPos = ftello(fp);
#else
    lastPos = ftell(fp);
#endif
    if (lastPos < 0) {
        lastPos = 0;
    }

    char *line = NULL;
    size_t cap = 0;
    while (1) {
        if (smallclueShouldAbort(&status)) {
            break;
        }

        struct stat st;
        if (fstat(fd, &st) != 0) {
            if (errno == EINTR) {
                continue;
            }
            fprintf(stderr, "tail: %s: %s\n", label ? label : "(stdin)", strerror(errno));
            status = 1;
            break;
        }

        /* Handle truncation/rotation. */
        if (st.st_size < lastPos) {
            fseeko(fp, st.st_size, SEEK_SET);
            lastPos = st.st_size;
            usleep(200000);
            continue;
        }

        if (st.st_size > lastPos) {
            /* New content available. */
            if (fseeko(fp, lastPos, SEEK_SET) != 0) {
                fprintf(stderr, "tail: %s: %s\n", label ? label : "(stdin)", strerror(errno));
                status = 1;
                break;
            }
            while (lastPos < st.st_size) {
                int read_err = 0;
                ssize_t len = smallclueGetlineStream(&line, &cap, fp, &read_err);
                if (len < 0) {
                    if (read_err == EINTR) {
                        clearerr(fp);
                        continue;
                    }
                    if (read_err == 0) {
                        clearerr(fp);
                        break;
                    }
                    fprintf(stderr, "tail: %s: %s\n",
                            label ? label : "(stdin)",
                            strerror(read_err));
                    status = 1;
                    break;
                }
                fwrite(line, 1, (size_t)len, stdout);
                fflush(stdout);
#if defined(__APPLE__)
                lastPos = ftello(fp);
#else
                lastPos = ftell(fp);
#endif
                if (lastPos < 0) {
                    lastPos = st.st_size;
                    break;
                }
            }
            if (status != 0) {
                break;
            }
        } else {
            /* No new data; sleep before polling again. */
            usleep(200000); /* 200ms */
        }
    }

    free(line);
    return status;
}

#if defined(PSCAL_TARGET_IOS)
static void smallclueLogPathExpansion(const char *label, const char *path) {
    if (!pscalRuntimeDebugLog) {
        return;
    }
    char expanded[PATH_MAX];
    const char *resolved = path;
    if (path && pathTruncateExpand(path, expanded, sizeof(expanded))) {
        resolved = expanded;
    }
    char logbuf[PATH_MAX * 2];
    snprintf(logbuf, sizeof(logbuf), "[smallclue][%s] path=%s resolved=%s",
             label ? label : "touch",
             path ? path : "(null)",
             resolved ? resolved : "(null)");
    pscalRuntimeDebugLog(logbuf);
}

static FILE *smallclueTailOpenFile(const char *path, char *resolved, size_t resolved_len) {
    const char *open_path = smallclueResolvePath(path, resolved, resolved_len);
    const char *target = (open_path && *open_path) ? open_path : path;
    smallclueLogPathExpansion("tail-open", path);
    return pscalPathVirtualized_fopen(target, "r");
}
#else
static FILE *smallclueTailOpenFile(const char *path, char *resolved, size_t resolved_len) {
    const char *open_path = smallclueResolvePath(path, resolved, resolved_len);
    const char *target = (open_path && *open_path) ? open_path : path;
    (void)resolved;
    (void)resolved_len;
    return fopen(target, "r");
}
#endif

static int smallclueTailCommand(int argc, char **argv) {
    smallclueClearPendingSignals();
    long lines = 10;
    bool follow = false;
    int index = 1;
    while (index < argc) {
        const char *arg = argv[index];
        if (!arg || arg[0] != '-') {
            break;
        }
        if (strcmp(arg, "--") == 0) {
            index++;
            break;
        }
        if (strcmp(arg, "-f") == 0) {
            follow = true;
            index += 1;
            continue;
        }
        if (strcmp(arg, "-n") == 0) {
            if (index + 1 >= argc) {
                fprintf(stderr, "tail: option requires an argument -- n\n");
                return 1;
            }
            char *endptr = NULL;
            lines = strtol(argv[index + 1], &endptr, 10);
            if (!endptr || *endptr != '\0') {
                fprintf(stderr, "tail: invalid line count '%s'\n", argv[index + 1]);
                return 1;
            }
            index += 2;
            continue;
        }
        long dashLines = 0;
        if (smallclueParseDashLineCount(arg, &dashLines)) {
            lines = dashLines;
            index += 1;
            continue;
        }
        fprintf(stderr, "tail: unsupported option '%s'\n", arg);
        return 1;
    }
    if (follow && (argc - index) > 1) {
        fprintf(stderr, "tail: -f currently supports a single input\n");
        return 1;
    }
    int status = 0;
    if (index >= argc) {
        status = follow ? smallclueTailFollow(stdin, "(stdin)", lines)
                        : smallclueTailStream(stdin, "(stdin)", lines);
    } else {
        for (int i = index; i < argc; ++i) {
            const char *path = argv[i];
            char resolved[PATH_MAX];
            FILE *fp = smallclueTailOpenFile(path, resolved, sizeof(resolved));
            if (!fp) {
                fprintf(stderr, "tail: %s: %s\n", path, strerror(errno));
                status = 1;
                continue;
            }
            if (follow) {
                status |= smallclueTailFollow(fp, path, lines);
                fclose(fp);
                break;
            } else {
                status |= smallclueTailStream(fp, path, lines);
                fclose(fp);
            }
        }
    }
    return status ? 1 : 0;
}

static int smallclueTouchCommand(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "touch: missing file operand\n");
        return 1;
    }
    int status = 0;
    struct timeval times[2];
    if (gettimeofday(&times[0], NULL) != 0) {
        times[0].tv_sec = time(NULL);
        times[0].tv_usec = 0;
    }
    times[1] = times[0];
    for (int i = 1; i < argc; ++i) {
        const char *path = argv[i];
        if (!path || !*path) {
            fprintf(stderr, "touch: invalid path\n");
            status = 1;
            continue;
        }
        const char *target = path;
#if defined(PSCAL_TARGET_IOS)
        char expanded[PATH_MAX];
        if (pathTruncateExpand(path, expanded, sizeof(expanded))) {
            target = expanded;
        }
#endif
        int fd = openat(AT_FDCWD, target, O_WRONLY | O_CREAT, 0666);
        if (fd < 0) {
            fprintf(stderr, "touch: %s: %s\n", target, strerror(errno));
#if defined(PSCAL_TARGET_IOS)
            smallclueLogPathExpansion("touch-open-failed", target);
#endif
            status = 1;
            continue;
        }
        if (futimes(fd, times) != 0) {
            fprintf(stderr, "touch: %s: %s\n", target, strerror(errno));
#if defined(PSCAL_TARGET_IOS)
            smallclueLogPathExpansion("touch-futimes-failed", target);
#endif
            status = 1;
        }
        close(fd);
    }
    return status ? 1 : 0;
}

static long smallclueParseLong(const char *text) {
    if (!text) {
        return -1;
    }
    char *endptr = NULL;
    long value = strtol(text, &endptr, 10);
    if (!endptr || *endptr != '\0') {
        return -1;
    }
    return value;
}

static void smallclueEmitTerminalReset(void) {
    fputs("\x1b" "c", stdout); // RIS: full reset
    fflush(stdout);
}

static void smallclueEmitTerminalSane(void) {
    fputs("\x1b[0m\x1b[?7h\x1b[?25h", stdout); // reset attributes, enable wrap & cursor
    fflush(stdout);
}

static void smallcluePrintTsetUsage(FILE *out) {
    if (!out) {
        out = stderr;
    }
    fprintf(out,
            "Usage: tset [-IQqs] [-e CH] [-i CH] [-k CH] [-r] [TERM]\n"
            "  -s emit shell commands\n"
            "  -r report terminal type\n"
            "  -Q quiet, -I skip init\n"
            "  -e/-i/-k set erase/intr/kill chars\n");
}

static bool smallclueParseControlValue(const char *text, cc_t *out) {
    if (!text || !*text || !out) {
        return false;
    }
    if (strcasecmp(text, "undef") == 0 || strcasecmp(text, "disable") == 0) {
#ifdef _POSIX_VDISABLE
        *out = _POSIX_VDISABLE;
        return true;
#else
        return false;
#endif
    }
    if (text[0] == '^' && text[1] != '\0') {
        char c = text[1];
        if (c == '?') {
            *out = 127;
            return true;
        }
        if (c >= 'a' && c <= 'z') {
            c = (char)(c - 'a' + 'A');
        }
        *out = (cc_t)(c & 0x1f);
        return true;
    }
    if (text[0] == '\\' && text[1] != '\0' && text[2] == '\0') {
        switch (text[1]) {
            case 'n':
                *out = '\n';
                return true;
            case 'r':
                *out = '\r';
                return true;
            case 't':
                *out = '\t';
                return true;
            case 'b':
                *out = '\b';
                return true;
            case 'e':
                *out = 27;
                return true;
            case '0':
                *out = '\0';
                return true;
            default:
                break;
        }
    }
    if (text[1] == '\0') {
        *out = (unsigned char)text[0];
        return true;
    }
    char *endptr = NULL;
    long value = strtol(text, &endptr, 0);
    if (endptr && *endptr == '\0' && value >= 0 && value <= 255) {
        *out = (cc_t)value;
        return true;
    }
    return false;
}

static int smallclueApplyTsetControlChars(bool quiet,
                                          bool has_erase,
                                          cc_t erase_char,
                                          bool has_intr,
                                          cc_t intr_char,
                                          bool has_kill,
                                          cc_t kill_char) {
    if (!has_erase && !has_intr && !has_kill) {
        return 0;
    }
    if (!pscalRuntimeStdinHasRealTTY()) {
        if (!quiet) {
            fprintf(stderr, "tset: stdin is not a tty (cannot set control chars)\n");
        }
        return 0;
    }
    struct termios tio;
    if (smallclueTcgetattr(STDIN_FILENO, &tio) != 0) {
        if (!quiet) {
            perror("tset");
        }
        return 1;
    }
#ifdef VERASE
    if (has_erase) {
        tio.c_cc[VERASE] = erase_char;
    }
#else
    if (has_erase && !quiet) {
        fprintf(stderr, "tset: erase control not supported\n");
    }
#endif
#ifdef VINTR
    if (has_intr) {
        tio.c_cc[VINTR] = intr_char;
    }
#else
    if (has_intr && !quiet) {
        fprintf(stderr, "tset: intr control not supported\n");
    }
#endif
#ifdef VKILL
    if (has_kill) {
        tio.c_cc[VKILL] = kill_char;
    }
#else
    if (has_kill && !quiet) {
        fprintf(stderr, "tset: kill control not supported\n");
    }
#endif
    if (smallclueTcsetattr(STDIN_FILENO, TCSANOW, &tio) != 0) {
        if (!quiet) {
            perror("tset");
        }
        return 1;
    }
    return 0;
}

static int smallclueTsetCommand(int argc, char **argv) {
    bool quiet = false;
    bool emit_shell = false;
    bool report = false;
    bool do_init = true;
    bool has_erase = false;
    bool has_intr = false;
    bool has_kill = false;
    cc_t erase_char = 0;
    cc_t intr_char = 0;
    cc_t kill_char = 0;
    const char *term_override = NULL;

    for (int i = 1; i < argc; ++i) {
        const char *arg = argv[i];
        if (!arg || *arg == '\0') {
            continue;
        }
        if (strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
            smallcluePrintTsetUsage(stdout);
            return 0;
        }
        if (strcmp(arg, "--") == 0) {
            if (i + 1 < argc) {
                term_override = argv[++i];
                if (i + 1 < argc) {
                    fprintf(stderr, "tset: unexpected argument '%s'\n", argv[i + 1]);
                    return 1;
                }
            }
            break;
        }
        if (arg[0] != '-' || arg[1] == '\0') {
            if (!term_override) {
                term_override = arg;
                continue;
            }
            fprintf(stderr, "tset: unexpected argument '%s'\n", arg);
            return 1;
        }

        size_t len = strlen(arg);
        for (size_t pos = 1; pos < len; ++pos) {
            char opt = arg[pos];
            const char *value = NULL;
            switch (opt) {
                case 'Q':
                case 'q':
                    quiet = true;
                    break;
                case 's':
                    emit_shell = true;
                    break;
                case 'r':
                    report = true;
                    break;
                case 'I':
                    do_init = false;
                    break;
                case 'V':
                    printf("tset (smallclue)\n");
                    return 0;
                case 'e':
                case 'i':
                case 'k':
                case 'm':
                    if (pos + 1 < len) {
                        value = arg + pos + 1;
                        pos = len;
                    } else if (i + 1 < argc) {
                        value = argv[++i];
                    } else {
                        fprintf(stderr, "tset: option -%c requires an argument\n", opt);
                        return 1;
                    }
                    if (opt == 'm') {
                        break;
                    }
                    {
                        cc_t parsed = 0;
                        if (!smallclueParseControlValue(value, &parsed)) {
                            fprintf(stderr, "tset: invalid control char '%s'\n", value);
                            return 1;
                        }
                        if (opt == 'e') {
                            has_erase = true;
                            erase_char = parsed;
                        } else if (opt == 'i') {
                            has_intr = true;
                            intr_char = parsed;
                        } else if (opt == 'k') {
                            has_kill = true;
                            kill_char = parsed;
                        }
                    }
                    break;
                default:
                    fprintf(stderr, "tset: unsupported option '-%c'\n", opt);
                    return 1;
            }
        }
    }

    const char *term = term_override;
    if (!term || !*term) {
        term = getenv("TERM");
    }
    if (!term || !*term) {
        term = "xterm-256color";
    }
    setenv("TERM", term, 1);

    if (do_init && !emit_shell && isatty(STDOUT_FILENO)) {
        smallclueEmitTerminalSane();
    }

    if (emit_shell && !quiet) {
        printf("TERM=%s; export TERM;\n", term);
    }
    if (!quiet && (report || !emit_shell)) {
        FILE *out = emit_shell ? stderr : stdout;
        fprintf(out, "%s\n", term);
    }

    return smallclueApplyTsetControlChars(quiet, has_erase, erase_char, has_intr, intr_char,
                                          has_kill, kill_char);
}

#if defined(PSCAL_TARGET_IOS)
static bool smallclueSessionPtyName(char *buf, size_t buf_len) {
    if (!buf || buf_len == 0) {
        return false;
    }
    VProcSessionStdio *session = vprocSessionStdioCurrent();
    if (!session || !session->pty_active || !session->pty_slave || !session->pty_slave->tty) {
        return false;
    }
    int num = session->pty_slave->tty->num;
    if (num < 0) {
        return false;
    }
    int written = snprintf(buf, buf_len, "/dev/pts/%d", num);
    return written > 0 && (size_t)written < buf_len;
}
#endif

static int smallclueTtyCommand(int argc, char **argv) {
    bool silent = false;
    if (argc > 2) {
        fprintf(stderr, "tty: too many arguments\n");
        return 1;
    }
    if (argc == 2) {
        if (strcmp(argv[1], "-s") == 0 || strcmp(argv[1], "--silent") == 0) {
            silent = true;
        } else if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
            printf("Usage: tty [-s]\n");
            return 0;
        } else {
            fprintf(stderr, "tty: unsupported option '%s'\n", argv[1]);
            return 1;
        }
    }

    if (!pscalRuntimeStdinHasRealTTY()) {
        if (!silent) {
            printf("not a tty\n");
        }
        return 1;
    }

    const char *name = NULL;
#if defined(PSCAL_TARGET_IOS)
    char session_name[64];
    if (smallclueSessionPtyName(session_name, sizeof(session_name))) {
        name = session_name;
    }
#endif
    if (!name || !*name) {
        name = ttyname(STDIN_FILENO);
    }
    if (!name || !*name) {
        name = ttyname(STDOUT_FILENO);
    }
    if (!name || !*name) {
        name = "/dev/tty";
    }
    if (!silent) {
        printf("%s\n", name);
    }
    return 0;
}

static void smallclueGetTerminalSize(int *rows, int *cols) {
    int r = -1;
    int c = -1;
    struct winsize ws;
    if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0) {
        r = ws.ws_row;
        c = ws.ws_col;
    } else if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == 0) {
        r = ws.ws_row;
        c = ws.ws_col;
    }
    if (r <= 0) {
        const char *env = getenv("LINES");
        if (env) {
            long val = smallclueParseLong(env);
            if (val > 0) r = (int)val;
        }
    }
    if (c <= 0) {
        const char *env = getenv("COLUMNS");
        if (env) {
            long val = smallclueParseLong(env);
            if (val > 0) c = (int)val;
        }
    }
    if (rows) *rows = r;
    if (cols) *cols = c;
}

static void smallclueApplyWindowSize(int rows, int cols) {
    if (rows > 0 && cols > 0) {
        char buffer[32];
        snprintf(buffer, sizeof(buffer), "%d", rows);
        setenv("LINES", buffer, 1);
        snprintf(buffer, sizeof(buffer), "%d", cols);
        setenv("COLUMNS", buffer, 1);

        if (isatty(STDOUT_FILENO)) {
            struct winsize ws;
            ws.ws_row = (unsigned short)rows;
            ws.ws_col = (unsigned short)cols;
            ws.ws_xpixel = 0;
            ws.ws_ypixel = 0;
            ioctl(STDOUT_FILENO, TIOCSWINSZ, &ws);
        }
        if (isatty(STDIN_FILENO)) {
            struct winsize ws;
            ws.ws_row = (unsigned short)rows;
            ws.ws_col = (unsigned short)cols;
            ws.ws_xpixel = 0;
            ws.ws_ypixel = 0;
            ioctl(STDIN_FILENO, TIOCSWINSZ, &ws);
        }
        printf("\x1b[8;%d;%dt", rows, cols);
        fflush(stdout);

#if defined(PSCAL_TARGET_IOS)
        // On iOS we drive the runtime through the bridge so the master PTY
        // and any downstream consumers see the updated geometry immediately.
        if (PSCALRuntimeUpdateWindowSize) {
            PSCALRuntimeUpdateWindowSize(cols, rows);
        }
#endif
    }
}

static const char *smallclueBaudLabel(speed_t speed) {
#define CASE_BAUD(val) case val: return #val
    switch (speed) {
    CASE_BAUD(B0);
    CASE_BAUD(B50);
    CASE_BAUD(B75);
    CASE_BAUD(B110);
    CASE_BAUD(B134);
    CASE_BAUD(B150);
    CASE_BAUD(B200);
    CASE_BAUD(B300);
    CASE_BAUD(B600);
    CASE_BAUD(B1200);
    CASE_BAUD(B1800);
    CASE_BAUD(B2400);
    CASE_BAUD(B4800);
    CASE_BAUD(B9600);
#ifdef B19200
    CASE_BAUD(B19200);
#endif
#ifdef B38400
    CASE_BAUD(B38400);
#endif
#ifdef B57600
    CASE_BAUD(B57600);
#endif
#ifdef B115200
    CASE_BAUD(B115200);
#endif
#ifdef B230400
    CASE_BAUD(B230400);
#endif
    default:
        break;
    }
    static char unknown[32];
    snprintf(unknown, sizeof(unknown), "%lu", (unsigned long)speed);
    return unknown;
#undef CASE_BAUD
}

static void smallclueDescribeControlChar(const char *label, cc_t value) {
    const char *repr = NULL;
    char buffer[8];
#ifdef _POSIX_VDISABLE
    if (value == _POSIX_VDISABLE) {
        repr = "undef";
    } else
#endif
    if (value == 0) {
        repr = "^@";
    } else if (value < 32) {
        buffer[0] = '^';
        buffer[1] = (char)('A' + value - 1);
        buffer[2] = '\0';
        repr = buffer;
    } else if (value == 127) {
        repr = "^?";
    } else if (isprint((unsigned char)value)) {
        buffer[0] = (char)value;
        buffer[1] = '\0';
        repr = buffer;
    } else {
        snprintf(buffer, sizeof(buffer), "%u", (unsigned)value);
        repr = buffer;
    }
    printf("%s = %s; ", label, repr);
}

static int smallclueSttyReport(void) {
    if (!pscalRuntimeStdinHasRealTTY()) {
        fprintf(stderr, "stty: stdin is not a tty (running in virtual terminal)\n");
        int rows = pscalRuntimeDetectWindowRows();
        int cols = pscalRuntimeDetectWindowCols();
        if (rows <= 0) rows = 24;
        if (cols <= 0) cols = 80;
        printf("speed ? baud; rows %d; columns %d;\n", rows, cols);
        return 0;
    }
    struct termios tio;
    if (smallclueTcgetattr(STDIN_FILENO, &tio) != 0) {
        perror("stty");
        return 1;
    }
    speed_t ospeed = cfgetospeed(&tio);
    struct winsize ws;
    int rows = -1;
    int cols = -1;
    if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) == 0) {
        rows = ws.ws_row;
        cols = ws.ws_col;
    }
    if (rows <= 0) {
        rows = pscalRuntimeDetectWindowRows();
    }
    if (cols <= 0) {
        cols = pscalRuntimeDetectWindowCols();
    }
    if (rows <= 0) rows = 24;
    if (cols <= 0) cols = 80;
    const char *baud_label = smallclueBaudLabel(ospeed);
    bool emit_speed = true;
#ifdef B0
    if (ospeed == B0) {
#ifdef B115200
        baud_label = "B115200";
#else
        emit_speed = false;
#endif
    }
#endif
    if (emit_speed && baud_label) {
        printf("speed %s baud; rows %d; columns %d;\n", baud_label, rows, cols);
    } else {
        printf("rows %d; columns %d;\n", rows, cols);
    }

#ifdef VINTR
    smallclueDescribeControlChar("intr", tio.c_cc[VINTR]);
#endif
#ifdef VQUIT
    smallclueDescribeControlChar("quit", tio.c_cc[VQUIT]);
#endif
#ifdef VERASE
    smallclueDescribeControlChar("erase", tio.c_cc[VERASE]);
#endif
#ifdef VKILL
    smallclueDescribeControlChar("kill", tio.c_cc[VKILL]);
#endif
#ifdef VEOF
    smallclueDescribeControlChar("eof", tio.c_cc[VEOF]);
#endif
#ifdef VSTART
    smallclueDescribeControlChar("start", tio.c_cc[VSTART]);
#endif
#ifdef VSTOP
    smallclueDescribeControlChar("stop", tio.c_cc[VSTOP]);
#endif
#ifdef VSUSP
    smallclueDescribeControlChar("susp", tio.c_cc[VSUSP]);
#endif
    printf("\n");
#ifdef VMIN
    printf("min = %u; ", (unsigned)tio.c_cc[VMIN]);
#endif
#ifdef VTIME
    printf("time = %u;", (unsigned)tio.c_cc[VTIME]);
#endif
    printf("\n");
    return 0;
}

static int smallclueSttyCommand(int argc, char **argv) {
    if (argc <= 1) {
        return smallclueSttyReport();
    }
    bool requestReset = false;
    bool requestSane = false;
    int index = 1;
    while (index < argc) {
        const char *arg = argv[index];
        if (strcmp(arg, "reset") == 0) {
            requestReset = true;
            index += 1;
            continue;
        }
        if (strcmp(arg, "sane") == 0) {
            requestSane = true;
            index += 1;
            continue;
        }
        if (strcmp(arg, "rows") == 0 || strcmp(arg, "cols") == 0 ||
            strcmp(arg, "columns") == 0 || strcmp(arg, "size") == 0) {
            fprintf(stderr, "stty: rows/columns are not supported; use resize\n");
            return 1;
        }
        fprintf(stderr, "stty: unsupported argument '%s'\n", arg);
        return 1;
    }

    if (requestReset) {
        smallclueEmitTerminalReset();
    }
    if (requestSane) {
        smallclueEmitTerminalSane();
    }

    if (requestReset || requestSane) {
        return 0;
    }
    fprintf(stderr, "Usage: stty [reset] [sane]\n");
    return 1;
}

static int smallclueResizeCommand(int argc, char **argv) {
    (void)argv;
    if (argc > 1) {
        fprintf(stderr, "resize: does not accept arguments\n");
        return 1;
    }
    int rows = pscalRuntimeDetectWindowRows();
    int cols = pscalRuntimeDetectWindowCols();
    if (rows <= 0 || cols <= 0) {
        fprintf(stderr, "resize: unable to determine current window size\n");
        return 1;
    }
    smallclueApplyWindowSize(rows, cols);
    return 0;
}

static int smallclueSortCommand(int argc, char **argv) {
    int reverse = 0;
    int index = 1;
    while (index < argc) {
        const char *arg = argv[index];
        if (!arg || arg[0] != '-') {
            break;
        }
        if (strcmp(arg, "--") == 0) {
            index++;
            break;
        }
        if (strcmp(arg, "-r") == 0) {
            reverse = 1;
            index++;
            continue;
        }
        fprintf(stderr, "sort: unsupported option '%s'\n", arg);
        return 1;
    }

    SmallclueLineVector vec = {0};
    int status = 0;
    if (index >= argc) {
        status = smallclueLineVectorLoadStream(stdin, NULL, "sort", &vec);
    } else {
        for (int i = index; i < argc && status == 0; ++i) {
            FILE *fp = fopen(argv[i], "r");
            if (!fp) {
                fprintf(stderr, "sort: %s: %s\n", argv[i], strerror(errno));
                status = 1;
                break;
            }
            status = smallclueLineVectorLoadStream(fp, argv[i], "sort", &vec);
            fclose(fp);
        }
    }
    if (status == 0 && vec.count > 1) {
        qsort(vec.items, vec.count, sizeof(char *), smallclueStringCompare);
    }
    if (status == 0) {
        if (reverse) {
            for (size_t i = vec.count; i-- > 0;) {
                fputs(vec.items[i], stdout);
            }
        } else {
            for (size_t i = 0; i < vec.count; ++i) {
                fputs(vec.items[i], stdout);
            }
        }
    }
    smallclueLineVectorFree(&vec);
    return status;
}

static int smallclueUniqStream(FILE *fp, const char *path, int print_counts) {
    char *line = NULL;
    size_t cap = 0;
    char *prev = NULL;
    long count = 0;
    int status = 0;
    while (true) {
        int read_err = 0;
        ssize_t len = smallclueGetlineStream(&line, &cap, fp, &read_err);
        if (len < 0) {
            if (read_err) {
                fprintf(stderr, "uniq: %s: %s\n",
                        path ? path : "(stdin)",
                        strerror(read_err));
                status = 1;
            }
            break;
        }
        if (!prev || strcmp(prev, line) != 0) {
            if (prev) {
                if (print_counts) {
                    printf("%7ld %s", count, prev);
                } else {
                    fputs(prev, stdout);
                }
                free(prev);
            }
            prev = strdup(line);
            if (!prev) {
                fprintf(stderr, "uniq: out of memory\n");
                status = 1;
                break;
            }
            count = 1;
        } else {
            count++;
        }
    }
    if (status == 0 && prev) {
        if (print_counts) {
            printf("%7ld %s", count, prev);
        } else {
            fputs(prev, stdout);
        }
    }
    free(prev);
    free(line);
    return status;
}

static int smallclueUniqCommand(int argc, char **argv) {
    int print_counts = 0;
    int index = 1;
    while (index < argc) {
        const char *arg = argv[index];
        if (!arg || arg[0] != '-') {
            break;
        }
        if (strcmp(arg, "--") == 0) {
            index++;
            break;
        }
        if (strcmp(arg, "-c") == 0) {
            print_counts = 1;
            index++;
            continue;
        }
        fprintf(stderr, "uniq: unsupported option '%s'\n", arg);
        return 1;
    }
    if (index >= argc) {
        return smallclueUniqStream(stdin, "(stdin)", print_counts);
    }
    int status = 0;
    for (int i = index; i < argc; ++i) {
        FILE *fp = fopen(argv[i], "r");
        if (!fp) {
            fprintf(stderr, "uniq: %s: %s\n", argv[i], strerror(errno));
            status = 1;
            continue;
        }
        status |= smallclueUniqStream(fp, argv[i], print_counts);
        fclose(fp);
    }
    return status;
}

static bool smallclueSedParseExpr(const char *expr, char **pattern, char **replacement, bool *global) {
    if (!expr || expr[0] != 's' || expr[1] == '\0') {
        return false;
    }
    char delim = expr[1];
    const char *pat_start = expr + 2;
    const char *pat_end = strchr(pat_start, delim);
    if (!pat_end) {
        return false;
    }
    const char *rep_start = pat_end + 1;
    const char *rep_end = strchr(rep_start, delim);
    if (!rep_end) {
        return false;
    }
    size_t pat_len = (size_t)(pat_end - pat_start);
    size_t rep_len = (size_t)(rep_end - rep_start);
    *pattern = (char *)malloc(pat_len + 1);
    *replacement = (char *)malloc(rep_len + 1);
    if (!*pattern || !*replacement) {
        free(*pattern);
        free(*replacement);
        return false;
    }
    memcpy(*pattern, pat_start, pat_len);
    (*pattern)[pat_len] = '\0';
    memcpy(*replacement, rep_start, rep_len);
    (*replacement)[rep_len] = '\0';
    *global = (strchr(rep_end + 1, 'g') != NULL);
    return true;
}

static char *smallclueSedApply(const char *line, const char *pattern, const char *replacement, bool global) {
    size_t pat_len = strlen(pattern);
    size_t rep_len = strlen(replacement);
    size_t line_len = strlen(line);
    size_t cap = line_len + 1 + ((rep_len > pat_len) ? (rep_len - pat_len) * 4 : 0);
    char *out = (char *)malloc(cap);
    if (!out) {
        return NULL;
    }
    size_t out_len = 0;
    const char *cursor = line;
    bool replaced = false;
    while (*cursor) {
        if (pat_len > 0 && strncmp(cursor, pattern, pat_len) == 0) {
            size_t needed = out_len + rep_len + (line_len - (cursor - line)) + 1;
            if (needed > cap) {
                cap = needed + 32;
                char *resized = (char *)realloc(out, cap);
                if (!resized) {
                    free(out);
                    return NULL;
                }
                out = resized;
            }
            memcpy(out + out_len, replacement, rep_len);
            out_len += rep_len;
            cursor += pat_len;
            replaced = true;
            if (!global) {
                memcpy(out + out_len, cursor, strlen(cursor) + 1);
                return out;
            }
            continue;
        }
        if (out_len + 2 > cap) {
            cap *= 2;
            char *resized = (char *)realloc(out, cap);
            if (!resized) {
                free(out);
                return NULL;
            }
            out = resized;
        }
        out[out_len++] = *cursor++;
    }
    out[out_len] = '\0';
    if (!replaced) {
        free(out);
        return strdup(line);
    }
    return out;
}

static int smallclueSedCommand(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "sed: missing expression\n");
        return 1;
    }
    char *pattern = NULL;
    char *replacement = NULL;
    bool global = false;
    if (!smallclueSedParseExpr(argv[1], &pattern, &replacement, &global)) {
        fprintf(stderr, "sed: invalid expression '%s'\n", argv[1]);
        return 1;
    }
    int status = 0;
    char *line = NULL;
    size_t cap = 0;
    int index = 2;
    if (index >= argc) {
        while (!status) {
            int read_err = 0;
            ssize_t len = smallclueGetlineStream(&line, &cap, stdin, &read_err);
            if (len < 0) {
                if (read_err) {
                    fprintf(stderr, "sed: %s\n", strerror(read_err));
                    status = 1;
                }
                break;
            }
            char *out = smallclueSedApply(line, pattern, replacement, global);
            if (!out) {
                fprintf(stderr, "sed: out of memory\n");
                status = 1;
                break;
            }
            fputs(out, stdout);
            free(out);
        }
    } else {
        for (int i = index; i < argc && status == 0; ++i) {
            FILE *fp = fopen(argv[i], "r");
            if (!fp) {
                fprintf(stderr, "sed: %s: %s\n", argv[i], strerror(errno));
                status = 1;
                break;
            }
            while (true) {
                int read_err = 0;
                ssize_t len = smallclueGetlineStream(&line, &cap, fp, &read_err);
                if (len < 0) {
                    if (read_err) {
                        fprintf(stderr, "sed: %s: %s\n", argv[i], strerror(read_err));
                        status = 1;
                    }
                    break;
                }
                char *out = smallclueSedApply(line, pattern, replacement, global);
                if (!out) {
                    fprintf(stderr, "sed: out of memory\n");
                    status = 1;
                    break;
                }
                fputs(out, stdout);
                free(out);
            }
            fclose(fp);
        }
    }
    free(pattern);
    free(replacement);
    free(line);
    return status;
}

static void smallclueCutPrintField(const char *line, char delim, int field) {
    if (field <= 0) {
        return;
    }
    int current = 1;
    const char *start = line;
    const char *ptr = line;
    while (true) {
        if (*ptr == delim || *ptr == '\0' || *ptr == '\n') {
            if (current == field) {
                size_t slice = (size_t)(ptr - start);
                fwrite(start, 1, slice, stdout);
                if (slice == 0 || start[slice - 1] != '\n') {
                    putchar('\n');
                }
                return;
            }
            if (*ptr == '\0') {
                break;
            }
            current++;
            start = ptr + 1;
        }
        if (*ptr == '\0') {
            break;
        }
        ptr++;
    }
    putchar('\n');
}

static int smallclueCutCommand(int argc, char **argv) {
    char delimiter = '\t';
    int field = -1;
    int index = 1;
    while (index < argc) {
        const char *arg = argv[index];
        if (!arg || arg[0] != '-') {
            break;
        }
        if (strcmp(arg, "--") == 0) {
            index++;
            break;
        }
        if (strcmp(arg, "-d") == 0) {
            if (index + 1 >= argc || !argv[index + 1][0]) {
                fprintf(stderr, "cut: missing delimiter\n");
                return 1;
            }
            delimiter = argv[index + 1][0];
            index += 2;
            continue;
        }
        if (strcmp(arg, "-f") == 0) {
            if (index + 1 >= argc) {
                fprintf(stderr, "cut: missing field number\n");
                return 1;
            }
            field = (int)smallclueParseLong(argv[index + 1]);
            if (field <= 0) {
                fprintf(stderr, "cut: invalid field '%s'\n", argv[index + 1]);
                return 1;
            }
            index += 2;
            continue;
        }
        fprintf(stderr, "cut: unsupported option '%s'\n", arg);
        return 1;
    }
    if (field <= 0) {
        fprintf(stderr, "cut: missing -f option\n");
        return 1;
    }
    char *line = NULL;
    size_t cap = 0;
    int status = 0;
    if (index >= argc) {
        while (true) {
            int read_err = 0;
            ssize_t len = smallclueGetlineStream(&line, &cap, stdin, &read_err);
            if (len < 0) {
                if (read_err) {
                    fprintf(stderr, "cut: %s\n", strerror(read_err));
                    status = 1;
                }
                break;
            }
            smallclueCutPrintField(line, delimiter, field);
        }
    } else {
        for (int i = index; i < argc; ++i) {
            FILE *fp = fopen(argv[i], "r");
            if (!fp) {
                fprintf(stderr, "cut: %s: %s\n", argv[i], strerror(errno));
                status = 1;
                continue;
            }
            while (true) {
                int read_err = 0;
                ssize_t len = smallclueGetlineStream(&line, &cap, fp, &read_err);
                if (len < 0) {
                    if (read_err) {
                        fprintf(stderr, "cut: %s: %s\n", argv[i], strerror(read_err));
                        status = 1;
                    }
                    break;
                }
                smallclueCutPrintField(line, delimiter, field);
            }
            fclose(fp);
        }
    }
    free(line);
    return status;
}

static int smallclueTrCommand(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "tr: missing operand\n");
        return 1;
    }
    const char *set1 = argv[1];
    const char *set2 = argv[2];
    size_t len1 = strlen(set1);
    size_t len2 = strlen(set2);
    unsigned char map[256];
    bool delete_map[256];
    bool delete_only = (len2 == 0);
    for (int i = 0; i < 256; ++i) {
        map[i] = (unsigned char)i;
        delete_map[i] = false;
    }
    if (delete_only) {
        for (size_t i = 0; i < len1; ++i) {
            delete_map[(unsigned char)set1[i]] = true;
        }
    } else {
        for (size_t i = 0; i < len1; ++i) {
            unsigned char from = (unsigned char)set1[i];
            unsigned char to = (unsigned char)(i < len2 ? set2[i] : set2[len2 - 1]);
            map[from] = to;
        }
    }
    int ch;
    while ((ch = getchar()) != EOF) {
        unsigned char c = (unsigned char)ch;
        if (delete_only) {
            if (delete_map[c]) {
                continue;
            }
            putchar(c);
        } else {
            putchar(map[c]);
        }
    }
    return 0;
}

static int smallclueIdCommand(int argc, char **argv) {
    (void)argv;
    if (argc > 1) {
        fprintf(stderr, "id: no user lookup support in smallclue\n");
    }
    uid_t uid = getuid();
    uid_t euid = geteuid();
    gid_t gid = getgid();
    gid_t egid = getegid();
    struct passwd *pw = getpwuid(uid);
    struct passwd *epw = getpwuid(euid);
    struct group *gr = getgrgid(gid);
    struct group *egr = getgrgid(egid);
    printf("uid=%u(%s) gid=%u(%s)", (unsigned)uid, pw ? pw->pw_name : "?", (unsigned)gid, gr ? gr->gr_name : "?");
    if (euid != uid) {
        printf(" euid=%u(%s)", (unsigned)euid, epw ? epw->pw_name : "?");
    }
    if (egid != gid) {
        printf(" egid=%u(%s)", (unsigned)egid, egr ? egr->gr_name : "?");
    }
    int ngroups = getgroups(0, NULL);
    if (ngroups > 0) {
        gid_t *groups = (gid_t *)malloc((size_t)ngroups * sizeof(gid_t));
        if (groups && getgroups(ngroups, groups) >= 0) {
            printf(" groups=");
            for (int i = 0; i < ngroups; ++i) {
                struct group *gg = getgrgid(groups[i]);
                if (i > 0) {
                    putchar(',');
                }
                printf("%u(%s)", (unsigned)groups[i], gg ? gg->gr_name : "?");
            }
        }
        free(groups);
    }
    putchar('\n');
    return 0;
}

static int smallclueEnvCommand(int argc, char **argv) {
    smallclueResetGetopt();
    int clear_env = 0;
    int opt;
    while ((opt = getopt(argc, argv, "i")) != -1) {
        if (opt == 'i') {
            clear_env = 1;
        } else {
            fprintf(stderr, "usage: env [-i] [name=value ...] [command [args...]]\n");
            return 1;
        }
    }
    if (clear_env) {
        smallclueEnvClearAll();
    }
    int index = optind;
    while (index < argc) {
        const char *arg = argv[index];
        const char *eq = arg ? strchr(arg, '=') : NULL;
        if (!eq) {
            break;
        }
        if (eq == arg) {
            fprintf(stderr, "env: invalid assignment '%s'\n", arg);
            return 1;
        }
        size_t name_len = (size_t)(eq - arg);
        char *name = (char *)malloc(name_len + 1);
        if (!name) {
            perror("env");
            return 1;
        }
        memcpy(name, arg, name_len);
        name[name_len] = '\0';
        const char *value = eq + 1;
        if (setenv(name, value, 1) != 0) {
            fprintf(stderr, "env: failed to set %s: %s\n", name, strerror(errno));
            free(name);
            return 1;
        }
        free(name);
        index++;
    }
    if (index >= argc) {
        extern char **environ;
        if (environ) {
            for (char **envp = environ; *envp; ++envp) {
                puts(*envp);
            }
        }
        return 0;
    }
    execvp(argv[index], &argv[index]);
    fprintf(stderr, "env: %s: %s\n", argv[index], strerror(errno));
    if (errno == ENOENT) {
        return 127;
    }
    return 126;
}

static int smallclueGrepCommand(int argc, char **argv) {
    int index = 1;
    int number_lines = 0;
    int ignore_case = 0;
    int invert_match = 0;
    while (index < argc) {
        const char *arg = argv[index];
        if (!arg || arg[0] != '-') {
            break;
        }
        if (strcmp(arg, "--") == 0) {
            index++;
            break;
        }
        if (strncmp(arg, "--", 2) == 0) {
            /* Support common long forms and treat unknown long opts as end of options. */
            if (strcmp(arg, "--ignore-case") == 0 || strcmp(arg, "--ignore") == 0) {
                ignore_case = 1;
                index++;
                continue;
            }
            if (strcmp(arg, "--invert-match") == 0 || strcmp(arg, "--invert") == 0) {
                invert_match = 1;
                index++;
                continue;
            }
            if (strcmp(arg, "--line-number") == 0 || strcmp(arg, "--number") == 0) {
                number_lines = 1;
                index++;
                continue;
            }
            if (strncmp(arg, "--color", 7) == 0 || strncmp(arg, "--colour", 8) == 0) {
                /* Accept --color[=auto|never|always] without changing behaviour. */
                index++;
                continue;
            }
            /* Unrecognized long option: treat as start of pattern/paths. */
            break;
        }
        for (const char *opt = arg + 1; *opt; ++opt) {
            if (*opt == 'n') {
                number_lines = 1;
            } else if (*opt == 'i') {
                ignore_case = 1;
            } else if (*opt == 'v') {
                invert_match = 1;
            } else {
                fprintf(stderr, "grep: unsupported option -%c\n", *opt);
                return 1;
            }
        }
        index++;
    }
    if (index >= argc) {
        fprintf(stderr, "grep: missing pattern\n");
        return 1;
    }
    const char *pattern = argv[index++];
    int paths = argc - index;
    int status = 1;
    char *line = NULL;
    size_t cap = 0;
    if (paths <= 0) {
        ssize_t len;
        long line_no = 0;
        while (true) {
            int read_err = 0;
            len = smallclueGetlineStream(&line, &cap, stdin, &read_err);
            if (len < 0) {
                if (read_err) {
                    fprintf(stderr, "grep: %s\n", strerror(read_err));
                }
                break;
            }
            line_no++;
            int found = smallclueStrCaseStr(line, pattern, ignore_case) != NULL;
            if (invert_match ? !found : found) {
                if (number_lines) {
                    printf("%ld:", line_no);
                }
                fwrite(line, 1, (size_t)len, stdout);
                status = 0;
            }
        }
    } else {
        for (int i = index; i < argc; ++i) {
            const char *path = argv[i];
            FILE *fp = fopen(path, "r");
            if (!fp) {
                fprintf(stderr, "grep: %s: %s\n", path, strerror(errno));
                continue;
            }
            ssize_t len;
            long line_no = 0;
            while (true) {
                int read_err = 0;
                len = smallclueGetlineStream(&line, &cap, fp, &read_err);
                if (len < 0) {
                    if (read_err) {
                        fprintf(stderr, "grep: %s: %s\n", path, strerror(read_err));
                    }
                    break;
                }
                line_no++;
                int found = smallclueStrCaseStr(line, pattern, ignore_case) != NULL;
                if (invert_match ? !found : found) {
                    if (paths > 1) {
                        printf("%s:", path);
                    }
                    if (number_lines) {
                        printf("%ld:", line_no);
                    }
                    fwrite(line, 1, (size_t)len, stdout);
                    status = 0;
                }
            }
            fclose(fp);
        }
    }
    free(line);
    return status;
}

typedef struct {
    uint64_t lines;
    uint64_t words;
    uint64_t bytes;
} SmallclueWcCounts;

static int smallclueWcProcessFile(const char *path, SmallclueWcCounts *counts) {
    FILE *fp = NULL;
    if (path) {
        fp = fopen(path, "r");
        if (!fp) {
            fprintf(stderr, "wc: %s: %s\n", path, strerror(errno));
            return 1;
        }
    } else {
        fp = stdin;
    }
    int c;
    int in_word = 0;
    counts->lines = counts->words = counts->bytes = 0;
    int read_err = 0;
    while ((c = smallclueGetcStream(fp, &read_err)) != EOF) {
        counts->bytes++;
        if (c == '\n') {
            counts->lines++;
        }
        if (isspace(c)) {
            in_word = 0;
        } else if (!in_word) {
            counts->words++;
            in_word = 1;
        }
    }
    if (fp != stdin) {
        fclose(fp);
    }
    if (read_err) {
        fprintf(stderr, "wc: %s: read error\n", path ? path : "(stdin)");
        return 1;
    }
    return 0;
}

static void smallclueWcPrint(const SmallclueWcCounts *counts, int show_lines, int show_words, int show_bytes, const char *label) {
    if (show_lines) {
        printf("%12" PRIu64, counts->lines);
    }
    if (show_words) {
        printf("%12" PRIu64, counts->words);
    }
    if (show_bytes) {
        printf("%12" PRIu64, counts->bytes);
    }
    if (label) {
        printf(" %s", label);
    }
    putchar('\n');
}

static int smallclueWcCommand(int argc, char **argv) {
    int show_lines = 0, show_words = 0, show_bytes = 0;
    int index = 1;
    while (index < argc) {
        const char *arg = argv[index];
        if (!arg || arg[0] != '-') {
            break;
        }
        if (strcmp(arg, "--") == 0) {
            index++;
            break;
        }
        for (const char *opt = arg + 1; *opt; ++opt) {
            if (*opt == 'l') show_lines = 1;
            else if (*opt == 'w') show_words = 1;
            else if (*opt == 'c') show_bytes = 1;
            else {
                fprintf(stderr, "wc: invalid option -- %c\n", *opt);
                return 1;
            }
        }
        index++;
    }
    if (!show_lines && !show_words && !show_bytes) {
        show_lines = show_words = show_bytes = 1;
    }
    int paths = argc - index;
    int status = 0;
    SmallclueWcCounts counts;
    SmallclueWcCounts total = {0, 0, 0};
    if (paths <= 0) {
        if (smallclueWcProcessFile(NULL, &counts) != 0) {
            return 1;
        }
        smallclueWcPrint(&counts, show_lines, show_words, show_bytes, NULL);
    } else {
        for (int i = index; i < argc; ++i) {
            if (smallclueWcProcessFile(argv[i], &counts) != 0) {
                status = 1;
                continue;
            }
            smallclueWcPrint(&counts, show_lines, show_words, show_bytes, argv[i]);
            total.lines += counts.lines;
            total.words += counts.words;
            total.bytes += counts.bytes;
        }
        if (paths > 1) {
            smallclueWcPrint(&total, show_lines, show_words, show_bytes, "total");
        }
    }
    return status;
}

typedef struct {
    int summarize_only;
    int use_kilobytes;
    int human_readable;
} SmallclueDuOptions;

static void smallclueDuPrintSize(long long bytes,
                                const char *path,
                                const SmallclueDuOptions *opts) {
    if (opts && opts->human_readable) {
        static const char units[] = {'B', 'K', 'M', 'G', 'T', 'P', 'E'};
        double value = (double)bytes;
        size_t unit = 0;
        while (value >= 1024.0 && unit < (sizeof(units) / sizeof(units[0])) - 1) {
            value /= 1024.0;
            unit++;
        }
        if (unit == 0 || value >= 10.0) {
            printf("%.0f%c\t%s\n", value, units[unit], path);
        } else {
            printf("%.1f%c\t%s\n", value, units[unit], path);
        }
        return;
    }

    long long value = bytes;
    if (opts && opts->use_kilobytes) {
        if (value >= 0) {
            value = (value + 1023) / 1024;
        } else {
            value = -(((-value) + 1023) / 1024);
        }
    }
    printf("%lld\t%s\n", value, path);
}

static long long smallclueDuVisit(const char *path,
                                 int *status,
                                 const SmallclueDuOptions *opts,
                                 int depth) {
    struct stat st;
    if (lstat(path, &st) != 0) {
        fprintf(stderr, "du: %s: %s\n", path, strerror(errno));
        if (status) *status = 1;
        return 0;
    }
    long long total = st.st_size;
    if (S_ISDIR(st.st_mode)) {
        DIR *dir = opendir(path);
        if (!dir) {
            fprintf(stderr, "du: %s: %s\n", path, strerror(errno));
            if (status) *status = 1;
            return total;
        }
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
                continue;
            }
            char child[PATH_MAX];
            if (smallclueBuildPath(child, sizeof(child), path, entry->d_name) != 0) {
                fprintf(stderr, "du: %s/%s: %s\n", path, entry->d_name, strerror(errno));
                if (status) *status = 1;
                continue;
            }
            total += smallclueDuVisit(child, status, opts, depth + 1);
        }
        closedir(dir);
    }
    if (!opts || !opts->summarize_only || depth == 0) {
        smallclueDuPrintSize(total, path, opts);
    }
    return total;
}

static int smallclueDuCommand(int argc, char **argv) {
    SmallclueDuOptions opts = {0, 0, 0};
    int opt;
    smallclueResetGetopt();
    while ((opt = getopt(argc, argv, "skh")) != -1) {
        switch (opt) {
            case 's':
                opts.summarize_only = 1;
                break;
            case 'k':
                opts.use_kilobytes = 1;
                break;
            case 'h':
                opts.human_readable = 1;
                break;
            default:
                return 1;
        }
    }

    int status = 0;
    if (optind >= argc) {
        smallclueDuVisit(".", &status, &opts, 0);
    } else {
        for (int i = optind; i < argc; ++i) {
            smallclueDuVisit(argv[i], &status, &opts, 0);
        }
    }
    return status ? 1 : 0;
}

static int smallclueFindVisit(const char *path, const char *pattern, int *status) {
    struct stat st;
    if (lstat(path, &st) != 0) {
        fprintf(stderr, "find: %s: %s\n", path, strerror(errno));
        if (status) *status = 1;
        return 1;
    }
    const char *leaf = smallclueLeafName(path);
    if (!pattern || fnmatch(pattern, leaf, 0) == 0) {
        printf("%s\n", path);
    }
    if (S_ISDIR(st.st_mode)) {
        DIR *dir = opendir(path);
        if (!dir) {
            fprintf(stderr, "find: %s: %s\n", path, strerror(errno));
            if (status) *status = 1;
            return 1;
        }
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
                continue;
            }
            char child[PATH_MAX];
            if (smallclueBuildPath(child, sizeof(child), path, entry->d_name) != 0) {
                fprintf(stderr, "find: %s/%s: %s\n", path, entry->d_name, strerror(errno));
                if (status) *status = 1;
                continue;
            }
            smallclueFindVisit(child, pattern, status);
        }
        closedir(dir);
    }
    return 0;
}

static int smallclueFindCommand(int argc, char **argv) {
    const char *start = ".";
    const char *pattern = NULL;
    int index = 1;
    if (index < argc && argv[index] && argv[index][0] != '-') {
        start = argv[index++];
    }
    while (index < argc) {
        const char *arg = argv[index++];
        if (strcmp(arg, "-name") == 0) {
            if (index >= argc) {
                fprintf(stderr, "find: missing argument to -name\n");
                return 1;
            }
            pattern = argv[index++];
        } else {
            fprintf(stderr, "find: unsupported predicate '%s'\n", arg);
            return 1;
        }
    }
    int status = 0;
    smallclueFindVisit(start, pattern, &status);
    return status ? 1 : 0;
}

static const char *smallclueLeafName(const char *path) {
    if (!path) {
        return "";
    }
    const char *start = path;
    const char *end = path + strlen(path);
    while (end > start && end[-1] == '/') {
        --end;
    }
    if (end == start) {
        return path;
    }
    const char *leaf = end;
    while (leaf > start && leaf[-1] != '/') {
        --leaf;
    }
    return leaf;
}

static int smallclueBuildPath(char *buf, size_t buf_size, const char *dir, const char *leaf) {
    if (!buf || buf_size == 0 || !dir || !leaf) {
        errno = EINVAL;
        return -1;
    }
    size_t dir_len = strlen(dir);
    int need_slash = (dir_len > 0 && dir[dir_len - 1] != '/');
    int written = snprintf(buf, buf_size, need_slash ? "%s/%s" : "%s%s", dir, leaf);
    if (written < 0 || (size_t)written >= buf_size) {
        errno = ENAMETOOLONG;
        return -1;
    }
    return 0;
}

static void smallclueTrimTrailingSlashes(char *path) {
    if (!path) {
        return;
    }
    size_t len = strlen(path);
    while (len > 1 && path[len - 1] == '/') {
        path[--len] = '\0';
    }
    if (len == 1 && path[0] == '/') {
        path[1] = '\0';
    }
}

static bool smallclueChopParentDirectory(char *path) {
    if (!path || path[0] == '\0') {
        return false;
    }
    smallclueTrimTrailingSlashes(path);
    size_t len = strlen(path);
    if (len == 0) {
        return false;
    }
    char *slash = strrchr(path, '/');
    if (!slash) {
        path[0] = '\0';
        return false;
    }
    if (slash == path) {
        return false;
    }
    *slash = '\0';
    smallclueTrimTrailingSlashes(path);
    return path[0] != '\0';
}

static bool smallclueConfirmDelete(const char *label, const char *path) {
    if (!isatty(STDIN_FILENO)) {
        fprintf(stderr, "%s: cannot prompt on non-interactive input for '%s' (use -f to force)\n",
                label, path);
        return false;
    }
    fprintf(stderr, "%s: remove '%s'? [y/N] ", label, path);
    fflush(stderr);
    int c = getchar();
    /* consume the rest of the line */
    int d;
    while ((d = getchar()) != '\n' && d != EOF) { }
    return c == 'y' || c == 'Y';
}

static int smallclueRemovePathWithLabel(const char *label, const char *path, bool recursive, bool force) {
    const char *target = path;
#if defined(PSCAL_TARGET_IOS)
    char expanded[PATH_MAX];
    if (path && pathTruncateExpand(path, expanded, sizeof(expanded))) {
        target = expanded;
    }
#endif
    struct stat st;
    if (lstat(target, &st) != 0) {
        if (!force) {
            fprintf(stderr, "%s: %s: %s\n", label, target, strerror(errno));
        }
        return force ? 0 : -1;
    }
    if (S_ISDIR(st.st_mode)) {
        if (!recursive) {
            fprintf(stderr, "%s: %s: is a directory\n", label, target);
            return -1;
        }
        if (!force && !smallclueConfirmDelete(label, target)) {
            return 1;
        }
        DIR *dir = opendir(target);
        if (!dir) {
            fprintf(stderr, "%s: %s: %s\n", label, target, strerror(errno));
            return -1;
        }
        struct dirent *entry;
        int status = 0;
        while ((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
                continue;
            }
            char child_path[PATH_MAX];
            if (smallclueBuildPath(child_path, sizeof(child_path), path, entry->d_name) != 0) {
                fprintf(stderr, "%s: %s/%s: %s\n", label, target, entry->d_name, strerror(errno));
                status = -1;
                break;
            }
            if (smallclueRemovePathWithLabel(label, child_path, true, force) != 0) {
                status = -1;
            }
        }
        closedir(dir);
        if (status != 0) {
            return -1;
        }
        if (rmdir(target) != 0) {
            fprintf(stderr, "%s: %s: %s\n", label, target, strerror(errno));
            return -1;
        }
        return 0;
    }
    if (unlink(target) != 0) {
        if (!force) {
            fprintf(stderr, "%s: %s: %s\n", label, target, strerror(errno));
            return -1;
        }
        return 0;
    }
    return 0;
}

static int smallclueCopyFile(const char *label, const char *src, const char *dst) {
    char resolved_src[PATH_MAX];
    char resolved_dst[PATH_MAX];
    const char *src_path = smallclueResolvePath(src, resolved_src, sizeof(resolved_src));
    const char *dst_path = smallclueResolvePath(dst, resolved_dst, sizeof(resolved_dst));

    int in_fd = open(src_path, O_RDONLY);
    if (in_fd < 0) {
        fprintf(stderr, "%s: %s: %s\n", label, src, strerror(errno));
        return -1;
    }
    struct stat st;
    if (fstat(in_fd, &st) != 0) {
        fprintf(stderr, "%s: %s: %s\n", label, src, strerror(errno));
        close(in_fd);
        return -1;
    }
    if (S_ISDIR(st.st_mode)) {
        fprintf(stderr, "%s: %s: is a directory\n", label, src);
        close(in_fd);
        return -1;
    }
    mode_t mode = st.st_mode & 0777;
    int out_fd = open(dst_path, O_WRONLY | O_CREAT | O_TRUNC, mode);
    if (out_fd < 0) {
        fprintf(stderr, "%s: %s: %s\n", label, dst, strerror(errno));
        close(in_fd);
        return -1;
    }
    char buffer[16384];
    ssize_t nread;
    int status = 0;
    while ((nread = read(in_fd, buffer, sizeof(buffer))) > 0) {
        ssize_t written = 0;
        while (written < nread) {
            ssize_t nwrite = write(out_fd, buffer + written, (size_t)(nread - written));
            if (nwrite < 0) {
                fprintf(stderr, "%s: %s: %s\n", label, dst, strerror(errno));
                status = -1;
                break;
            }
            written += nwrite;
        }
        if (status != 0) {
            break;
        }
    }
    if (nread < 0) {
        fprintf(stderr, "%s: %s: %s\n", label, src, strerror(errno));
        status = -1;
    }
    if (close(out_fd) != 0) {
        fprintf(stderr, "%s: %s: %s\n", label, dst, strerror(errno));
        status = -1;
    }
    close(in_fd);
    if (status != 0) {
        unlink(dst);
    }
    return status;
}

static int smallclueMkdirParents(const char *path, mode_t mode) {
    if (!path || !*path) {
        errno = EINVAL;
        return -1;
    }
    char *mutable_path = strdup(path);
    if (!mutable_path) {
        errno = ENOMEM;
        return -1;
    }
    size_t len = strlen(mutable_path);
    while (len > 1 && mutable_path[len - 1] == '/') {
        mutable_path[len - 1] = '\0';
        len--;
    }
    if (len == 0) {
        free(mutable_path);
        errno = EINVAL;
        return -1;
    }
    for (char *cursor = mutable_path + 1; *cursor; ++cursor) {
        if (*cursor == '/') {
            *cursor = '\0';
            if (mutable_path[0] != '\0') {
                if (mkdir(mutable_path, mode) != 0 && errno != EEXIST) {
                    int err = errno;
                    free(mutable_path);
                    errno = err;
                    return -1;
                }
            }
            *cursor = '/';
            while (*(cursor + 1) == '/') {
                cursor++;
            }
        }
    }
    if (mkdir(path, mode) != 0) {
        if (errno == EEXIST) {
            struct stat st;
            if (stat(path, &st) == 0 && S_ISDIR(st.st_mode)) {
                free(mutable_path);
                return 0;
            }
        }
        int err = errno;
        free(mutable_path);
        errno = err;
        return -1;
    }
    free(mutable_path);
    return 0;
}

static int smallclueRmCommand(int argc, char **argv) {
    int recursive = 0;
    int force = 0;
    int opt;
    smallclueResetGetopt();
    while ((opt = getopt(argc, argv, "rf")) != -1) {
        switch (opt) {
            case 'r':
                recursive = 1;
                break;
            case 'f':
                force = 1;
                break;
            default:
                fprintf(stderr, "rm: invalid option -- %c\n", optopt);
                return 1;
        }
    }
    if (optind >= argc) {
        if (!force) {
            fprintf(stderr, "rm: missing operand\n");
            return 1;
        }
        return 0;
    }
    int status = 0;
    for (int i = optind; i < argc; ++i) {
        const char *input = argv[i];
        const char *expanded = input;
#if defined(PSCAL_TARGET_IOS)
        char pathbuf[PATH_MAX];
        if (pathTruncateExpand(input, pathbuf, sizeof(pathbuf))) {
            expanded = pathbuf;
        }
#endif
        if (strpbrk(expanded, "*?[")) {
            glob_t matches;
            memset(&matches, 0, sizeof(matches));
            int gret = glob(expanded, GLOB_NOCHECK, NULL, &matches);
            if (gret != 0) {
                globfree(&matches);
                if (!force) {
                    status = 1;
                }
                continue;
            }
            for (size_t m = 0; m < matches.gl_pathc; ++m) {
                if (smallclueRemovePathWithLabel("rm", matches.gl_pathv[m], recursive != 0, force != 0) != 0) {
                    if (!force) {
                        status = 1;
                    }
                }
            }
            globfree(&matches);
        } else {
            if (smallclueRemovePathWithLabel("rm", expanded, recursive != 0, force != 0) != 0) {
                if (!force) {
                    status = 1;
                }
            }
        }
    }
    return status;
}

static int smallclueRmdirPath(const char *path, bool parents) {
    if (rmdir(path) != 0) {
        fprintf(stderr, "rmdir: %s: %s\n", path, strerror(errno));
        return -1;
    }
    if (!parents) {
        return 0;
    }
    char *mutable_path = strdup(path);
    if (!mutable_path) {
        fprintf(stderr, "rmdir: %s\n", strerror(errno));
        return -1;
    }
    while (smallclueChopParentDirectory(mutable_path)) {
        if (mutable_path[0] == '\0' || strcmp(mutable_path, ".") == 0 ||
            strcmp(mutable_path, "/") == 0) {
            break;
        }
        if (rmdir(mutable_path) != 0) {
            fprintf(stderr, "rmdir: %s: %s\n", mutable_path, strerror(errno));
            free(mutable_path);
            return -1;
        }
    }
    free(mutable_path);
    return 0;
}

static int smallclueRmdirCommand(int argc, char **argv) {
    int parents = 0;
    int opt;
    smallclueResetGetopt();
    while ((opt = getopt(argc, argv, "p")) != -1) {
        if (opt == 'p') {
            parents = 1;
        } else {
            fprintf(stderr, "usage: rmdir [-p] dir...\n");
            return 1;
        }
    }
    if (optind >= argc) {
        fprintf(stderr, "rmdir: missing operand\n");
        return 1;
    }
    int status = 0;
    for (int i = optind; i < argc; ++i) {
        if (smallclueRmdirPath(argv[i], parents != 0) != 0) {
            status = 1;
        }
    }
    return status;
}

static int smallclueMkdirCommand(int argc, char **argv) {
    int parents = 0;
    int opt;
    smallclueResetGetopt();
    while ((opt = getopt(argc, argv, "p")) != -1) {
        switch (opt) {
            case 'p':
                parents = 1;
                break;
            default:
                fprintf(stderr, "mkdir: invalid option -- %c\n", optopt);
                return 1;
        }
    }
    if (optind >= argc) {
        fprintf(stderr, "mkdir: missing operand\n");
        return 1;
    }
    int status = 0;
    for (int i = optind; i < argc; ++i) {
        const char *target = argv[i];
        if (parents) {
            if (smallclueMkdirParents(target, 0777) != 0) {
                fprintf(stderr, "mkdir: %s: %s\n", target, strerror(errno));
                status = 1;
            }
        } else {
            if (mkdir(target, 0777) != 0) {
                fprintf(stderr, "mkdir: %s: %s\n", target, strerror(errno));
                status = 1;
            }
        }
    }
    return status;
}

static int smallclueFileCommand(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "file: missing operand\n");
        return 1;
    }
    int status = 0;
    unsigned char buffer[512];
    for (int i = 1; i < argc; ++i) {
        const char *path = argv[i];
        struct stat st;
        if (lstat(path, &st) != 0) {
            fprintf(stderr, "file: %s: %s\n", path, strerror(errno));
            status = 1;
            continue;
        }
        printf("%s: ", path);
        if (S_ISDIR(st.st_mode)) {
            printf("directory\n");
        } else if (S_ISLNK(st.st_mode)) {
            char target[PATH_MAX];
            ssize_t len = readlink(path, target, sizeof(target) - 1);
            if (len >= 0) {
                target[len] = '\0';
                printf("symbolic link to '%s'\n", target);
            } else {
                printf("symbolic link (unreadable target)\n");
            }
        } else if (S_ISCHR(st.st_mode)) {
            printf("character device\n");
        } else if (S_ISBLK(st.st_mode)) {
            printf("block device\n");
        } else if (S_ISFIFO(st.st_mode)) {
            printf("named pipe\n");
        } else if (S_ISSOCK(st.st_mode)) {
            printf("socket\n");
        } else if (S_ISREG(st.st_mode)) {
            FILE *fp = fopen(path, "rb");
            if (!fp) {
                printf("regular file (unreadable)\n");
                status = 1;
                continue;
            }
            size_t read_bytes = fread(buffer, 1, sizeof(buffer), fp);
            fclose(fp);
            int is_text = 1;
            for (size_t b = 0; b < read_bytes; ++b) {
                unsigned char c = buffer[b];
                if (c == 0 || (c < 0x09) || (c > 0x0D && c < 0x20 && c != 0x1B)) {
                    is_text = 0;
                    break;
                }
            }
            printf(is_text ? "ASCII text\n" : "binary data\n");
        } else {
            printf("unknown file type\n");
        }
    }
    return status;
}

static const char *smallclueStatTypeLabel(const struct stat *st) {
    if (S_ISREG(st->st_mode)) return "regular file";
    if (S_ISDIR(st->st_mode)) return "directory";
    if (S_ISLNK(st->st_mode)) return "symbolic link";
    if (S_ISCHR(st->st_mode)) return "character special file";
    if (S_ISBLK(st->st_mode)) return "block special file";
    if (S_ISFIFO(st->st_mode)) return "fifo";
    if (S_ISSOCK(st->st_mode)) return "socket";
    return "unknown";
}

static void smallclueStatFormatPerms(char *buf, size_t buflen, mode_t mode) {
    if (!buf || buflen < 11) {
        return;
    }
    buf[0] = S_ISDIR(mode) ? 'd' : S_ISLNK(mode) ? 'l' : '-';
    buf[1] = (mode & S_IRUSR) ? 'r' : '-';
    buf[2] = (mode & S_IWUSR) ? 'w' : '-';
    buf[3] = (mode & S_IXUSR) ? 'x' : '-';
    buf[4] = (mode & S_IRGRP) ? 'r' : '-';
    buf[5] = (mode & S_IWGRP) ? 'w' : '-';
    buf[6] = (mode & S_IXGRP) ? 'x' : '-';
    buf[7] = (mode & S_IROTH) ? 'r' : '-';
    buf[8] = (mode & S_IWOTH) ? 'w' : '-';
    buf[9] = (mode & S_IXOTH) ? 'x' : '-';
    buf[10] = '\0';
}

static void smallclueStatPrintTime(const char *label, time_t value) {
    char buf[64];
    struct tm tm_val;
    if (localtime_r(&value, &tm_val)) {
        strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_val);
    } else {
        snprintf(buf, sizeof(buf), "%lld", (long long)value);
    }
    printf("%s: %s\n", label, buf);
}

static int smallclueStatPath(const char *path, bool follow) {
    char resolved[PATH_MAX];
    const char *target = smallclueResolvePath(path, resolved, sizeof(resolved));
    if (!target || *target == '\0') {
        target = path;
    }
    struct stat st;
    if ((follow ? stat(target, &st) : lstat(target, &st)) != 0) {
        fprintf(stderr, "stat: %s: %s\n", path, strerror(errno));
        return 1;
    }
    const char *type = smallclueStatTypeLabel(&st);
    char display_buf[PATH_MAX * 2];
    const char *display = path;
    if (!follow && S_ISLNK(st.st_mode)) {
        char link_target[PATH_MAX];
        ssize_t len = readlink(target, link_target, sizeof(link_target) - 1);
        if (len >= 0) {
            link_target[len] = '\0';
            snprintf(display_buf, sizeof(display_buf), "%s -> %s", path, link_target);
            display = display_buf;
        }
    }
    printf("  File: %s\n", display);
    printf("  Size: %lld\tBlocks: %lld\tIO Block: %ld\t%s\n",
           (long long)st.st_size,
           (long long)st.st_blocks,
           (long)st.st_blksize,
           type);
    printf("Device: %llu\tInode: %llu\tLinks: %llu\n",
           (unsigned long long)st.st_dev,
           (unsigned long long)st.st_ino,
           (unsigned long long)st.st_nlink);
    char perms[11];
    smallclueStatFormatPerms(perms, sizeof(perms), st.st_mode);
    struct passwd *pw = getpwuid(st.st_uid);
    struct group *gr = getgrgid(st.st_gid);
    printf("Access: (%04o/%s)  Uid: (%u/%s)   Gid: (%u/%s)\n",
           (unsigned)(st.st_mode & 07777),
           perms,
           (unsigned)st.st_uid,
           pw ? pw->pw_name : "?",
           (unsigned)st.st_gid,
           gr ? gr->gr_name : "?");
    smallclueStatPrintTime("Access", st.st_atime);
    smallclueStatPrintTime("Modify", st.st_mtime);
    smallclueStatPrintTime("Change", st.st_ctime);
    return 0;
}

static int smallclueStatCommand(int argc, char **argv) {
    smallclueResetGetopt();
    int follow = 0;
    int opt;
    while ((opt = getopt(argc, argv, "L")) != -1) {
        switch (opt) {
            case 'L':
                follow = 1;
                break;
            default:
                fprintf(stderr, "stat: usage: stat [-L] FILE...\n");
                return 1;
        }
    }
    if (optind >= argc) {
        fprintf(stderr, "stat: missing operand\n");
        return 1;
    }
    int status = 0;
    for (int i = optind; i < argc; ++i) {
        if (smallclueStatPath(argv[i], follow) != 0) {
            status = 1;
        } else if (i + 1 < argc) {
            putchar('\n');
        }
    }
    return status;
}

static int smallclueLnCommand(int argc, char **argv) {
    int symbolic = 0;
    int opt;
    smallclueResetGetopt();
    while ((opt = getopt(argc, argv, "s")) != -1) {
        switch (opt) {
            case 's':
                symbolic = 1;
                break;
            default:
                fprintf(stderr, "ln: invalid option -- %c\n", optopt);
                return 1;
        }
    }
    if (argc - optind < 2) {
        fprintf(stderr, "ln: missing file operand\n");
        return 1;
    }
    const char *target = argv[optind];
    const char *linkname = argv[optind + 1];
    int status = 0;
    if (symbolic) {
        if (symlink(target, linkname) != 0) {
            fprintf(stderr, "ln: cannot create symbolic link '%s': %s\n", linkname, strerror(errno));
            status = 1;
        }
    } else {
        if (link(target, linkname) != 0) {
            fprintf(stderr, "ln: cannot create link '%s': %s\n", linkname, strerror(errno));
            status = 1;
        }
    }
    return status;
}

static char *smallclueSearchPath(const char *name) {
    if (!name || !*name) {
        return NULL;
    }
    if (strchr(name, '/')) {
        if (access(name, X_OK) == 0) {
            return strdup(name);
        }
        return NULL;
    }
    const char *env = getenv("PATH");
    if (!env || !*env) {
        return NULL;
    }
    char *copy = strdup(env);
    if (!copy) {
        return NULL;
    }
    char *token = strtok(copy, ":");
    while (token) {
        char candidate[PATH_MAX];
        if (snprintf(candidate, sizeof(candidate), "%s/%s", token, name) < (int)sizeof(candidate)) {
            if (access(candidate, X_OK) == 0) {
                char *result = strdup(candidate);
                free(copy);
                return result;
            }
        }
        token = strtok(NULL, ":");
    }
    free(copy);
    return NULL;
}

static int smallclueTypeCommand(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "type: missing operand\n");
        return 1;
    }
    int status = 0;
    for (int i = 1; i < argc; ++i) {
        const char *name = argv[i];
        const SmallclueApplet *applet = smallclueFindApplet(name);
        if (applet) {
            printf("%s is a smallclue applet\n", name);
            continue;
        }
        char *path = smallclueSearchPath(name);
        if (path) {
            printf("%s is %s\n", name, path);
            free(path);
        } else {
            fprintf(stderr, "type: %s not found\n", name);
            status = 1;
        }
    }
    return status;
}

static int smallclueCpCommand(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "cp: missing file operand\n");
        return 1;
    }
    const char *dest = argv[argc - 1];
    char resolved_dest_root[PATH_MAX];
    const char *dest_real = smallclueResolvePath(dest, resolved_dest_root, sizeof(resolved_dest_root));
    struct stat dest_stat;
    int dest_exists = (stat(dest_real, &dest_stat) == 0);
    bool dest_is_dir = dest_exists && S_ISDIR(dest_stat.st_mode);
    int source_count = argc - 2;
    if (source_count > 1 && !dest_is_dir) {
        fprintf(stderr, "cp: target '%s' is not a directory\n", dest);
        return 1;
    }
    int status = 0;
    for (int i = 1; i <= source_count; ++i) {
        char resolved_src[PATH_MAX];
        const char *src = smallclueResolvePath(argv[i], resolved_src, sizeof(resolved_src));
        struct stat src_stat;
        if (stat(src, &src_stat) != 0) {
            fprintf(stderr, "cp: %s: %s\n", src, strerror(errno));
            status = 1;
            continue;
        }
        if (S_ISDIR(src_stat.st_mode)) {
            fprintf(stderr, "cp: %s: is a directory\n", src);
            status = 1;
            continue;
        }
        char target_path[PATH_MAX];
        char resolved_dest[PATH_MAX];
        const char *target = smallclueResolvePath(dest, resolved_dest, sizeof(resolved_dest));
        if (dest_is_dir) {
            if (smallclueBuildPath(target_path, sizeof(target_path), dest_real, smallclueLeafName(src)) != 0) {
                fprintf(stderr, "cp: %s/%s: %s\n", dest, smallclueLeafName(src), strerror(errno));
                status = 1;
                continue;
            }
            target = target_path;
        }
        struct stat target_stat;
        if (stat(target, &target_stat) == 0) {
            if (target_stat.st_dev == src_stat.st_dev && target_stat.st_ino == src_stat.st_ino) {
                fprintf(stderr, "cp: '%s' and '%s' are the same file\n", src, target);
                status = 1;
                continue;
            }
        }
        if (smallclueCopyFile("cp", src, target) != 0) {
            status = 1;
        }
    }
    return status;
}

static int smallclueMvCommand(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "mv: missing file operand\n");
        return 1;
    }
    const char *dest = argv[argc - 1];
    char resolved_dest_root[PATH_MAX];
    const char *dest_real = smallclueResolvePath(dest, resolved_dest_root, sizeof(resolved_dest_root));
    struct stat dest_stat;
    int dest_exists = (stat(dest_real, &dest_stat) == 0);
    bool dest_is_dir = dest_exists && S_ISDIR(dest_stat.st_mode);
    int source_count = argc - 2;
    if (source_count > 1 && !dest_is_dir) {
        fprintf(stderr, "mv: target '%s' is not a directory\n", dest);
        return 1;
    }
    int status = 0;
    for (int i = 1; i <= source_count; ++i) {
        char resolved_src[PATH_MAX];
        const char *src = smallclueResolvePath(argv[i], resolved_src, sizeof(resolved_src));
        char target_path[PATH_MAX];
        char resolved_dest_dir[PATH_MAX];
        const char *dest_base = dest;
        if (!dest_is_dir) {
            dest_base = smallclueResolvePath(dest, resolved_dest_dir, sizeof(resolved_dest_dir));
        }
        const char *target = dest_base;
        if (dest_is_dir) {
            const char *dir_root = smallclueResolvePath(dest, resolved_dest_dir, sizeof(resolved_dest_dir));
            if (smallclueBuildPath(target_path, sizeof(target_path), dir_root, smallclueLeafName(src)) != 0) {
                fprintf(stderr, "mv: %s/%s: %s\n", dir_root, smallclueLeafName(src), strerror(errno));
                status = 1;
                continue;
            }
            target = target_path;
        }
        if (rename(src, target) == 0) {
            continue;
        }
        if (errno == EXDEV) {
            if (smallclueCopyFile("mv", src, target) != 0) {
                status = 1;
                continue;
            }
            if (smallclueRemovePathWithLabel("mv", src, false, true) != 0) {
                fprintf(stderr, "mv: %s: unable to remove after copy\n", src);
                status = 1;
            }
        } else {
            fprintf(stderr, "mv: %s -> %s: %s\n", src, target, strerror(errno));
            status = 1;
        }
    }
    return status;
}

const SmallclueApplet *smallclueGetApplets(size_t *count) {
    if (count) {
        *count = kSmallclueAppletCount;
    }
    return kSmallclueApplets;
}

const SmallclueApplet *smallclueFindApplet(const char *name) {
    if (!name || !*name) {
        return NULL;
    }
    for (size_t i = 0; i < kSmallclueAppletCount; ++i) {
        if (strcasecmp(kSmallclueApplets[i].name, name) == 0) {
            return &kSmallclueApplets[i];
        }
    }
    return NULL;
}

int smallclueDispatchApplet(const SmallclueApplet *applet, int argc, char **argv) {
    if (!applet || !applet->entry) {
        return 127;
    }
    optind = 1;
    return applet->entry(argc, argv);
}

static void smallclueRedirectFromEnv(void) {
    const char *stdout_path = getenv("PSCALI_BG_STDOUT");
    const char *stdout_append = getenv("PSCALI_BG_STDOUT_APPEND");
    const char *stderr_path = getenv("PSCALI_BG_STDERR");
    const char *stderr_append = getenv("PSCALI_BG_STDERR_APPEND");

    if (stdout_path && *stdout_path) {
        int flags = O_CREAT | O_WRONLY | ((stdout_append && strcmp(stdout_append, "1") == 0) ? O_APPEND : O_TRUNC);
        int fd = open(stdout_path, flags, 0666);
        if (fd >= 0) {
            dup2(fd, STDOUT_FILENO);
            close(fd);
        }
    }
    if (stderr_path && *stderr_path) {
        int flags = O_CREAT | O_WRONLY | ((stderr_append && strcmp(stderr_append, "1") == 0) ? O_APPEND : O_TRUNC);
        int fd = open(stderr_path, flags, 0666);
        if (fd >= 0) {
            dup2(fd, STDERR_FILENO);
            close(fd);
        }
    }
}

int smallclueMain(int argc, char **argv) {
    smallclueRedirectFromEnv();
    const SmallclueApplet *applet = NULL;
    char *call_name = basename(argv[0]);
    const char *direct_url_target = NULL;
    bool invoked_via_smallclue_name = false;

    if (strcmp(call_name, "smallclue") == 0 || strcmp(call_name, "smallclu") == 0) {
        invoked_via_smallclue_name = true;
        if (argc < 2) {
            print_usage();
            return 1;
        }
        if (markdownIsRemoteTarget(argv[1])) {
            direct_url_target = argv[1];
        }
        call_name = argv[1];
        argv++;
        argc--;
    }

    applet = smallclueFindApplet(call_name);
    if (!applet && invoked_via_smallclue_name && direct_url_target) {
        applet = smallclueFindApplet("md");
        if (applet) {
            char *md_argv[3];
            md_argv[0] = (char *)"md";
            md_argv[1] = (char *)direct_url_target;
            md_argv[2] = NULL;
            return smallclueDispatchApplet(applet, 2, md_argv);
        }
    }
    if (!applet) {
        fprintf(stderr, "smallclue: '%s' applet not found.\n\n", call_name);
        print_usage();
        return 127;
    }

    return smallclueDispatchApplet(applet, argc, argv);
}
static bool smallclueIsInteger(const char *s, long long *out) {
    if (!s || !*s) {
        return false;
    }
    char *end = NULL;
    errno = 0;
    long long value = strtoll(s, &end, 10);
    if (errno != 0 || !end || *end != '\0') {
        return false;
    }
    if (out) {
        *out = value;
    }
    return true;
}

static bool smallclueTestEvaluate(int argc, char **argv) {
    if (argc <= 0) {
        return false;
    }
    if (strcmp(argv[0], "!") == 0) {
        return !smallclueTestEvaluate(argc - 1, argv + 1);
    }
    if (argc == 1) {
        return argv[0][0] != '\0';
    }
    if (argc == 2) {
        const char *op = argv[0];
        const char *arg = argv[1];
        if (strcmp(op, "-z") == 0) {
            return arg[0] == '\0';
        }
        if (strcmp(op, "-n") == 0) {
            return arg[0] != '\0';
        }
        if (strcmp(op, "-e") == 0) {
            return access(arg, F_OK) == 0;
        }
        if (strcmp(op, "-f") == 0) {
            struct stat st;
            return stat(arg, &st) == 0 && S_ISREG(st.st_mode);
        }
        if (strcmp(op, "-d") == 0) {
            struct stat st;
            return stat(arg, &st) == 0 && S_ISDIR(st.st_mode);
        }
        if (strcmp(op, "-r") == 0) {
            return access(arg, R_OK) == 0;
        }
        if (strcmp(op, "-w") == 0) {
            return access(arg, W_OK) == 0;
        }
    }
    if (argc == 3) {
        const char *left = argv[0];
        const char *op = argv[1];
        const char *right = argv[2];
        if (strcmp(op, "=") == 0) {
            return strcmp(left, right) == 0;
        }
        if (strcmp(op, "!=") == 0) {
            return strcmp(left, right) != 0;
        }
        long long lhs, rhs;
        if (smallclueIsInteger(left, &lhs) && smallclueIsInteger(right, &rhs)) {
            if (strcmp(op, "-eq") == 0) return lhs == rhs;
            if (strcmp(op, "-ne") == 0) return lhs != rhs;
            if (strcmp(op, "-gt") == 0) return lhs > rhs;
            if (strcmp(op, "-ge") == 0) return lhs >= rhs;
            if (strcmp(op, "-lt") == 0) return lhs < rhs;
            if (strcmp(op, "-le") == 0) return lhs <= rhs;
        }
    }
    fprintf(stderr, "test: unsupported expression\n");
    return false;
}

static int smallclueTestWithArgs(int argc, char **argv) {
    if (argc <= 0) {
        return 1;
    }
    bool result = smallclueTestEvaluate(argc, argv);
    return result ? 0 : 1;
}

static int smallclueTestCommand(int argc, char **argv) {
    return smallclueTestWithArgs(argc - 1, argv + 1);
}

static int smallclueBracketCommand(int argc, char **argv) {
    if (argc < 2 || strcmp(argv[argc - 1], "]") != 0) {
        fprintf(stderr, "[: missing ']'\n");
        return 1;
    }
    return smallclueTestWithArgs(argc - 2, argv + 1);
}

static int smallcluePbcopyCommand(int argc, char **argv) {
    (void)argv;
    if (argc > 1) {
        fprintf(stderr, "pbcopy: takes no arguments\n");
        return 1;
    }
    smallclueResetGetopt();
    char buf[4096];
    size_t total = 0;
    size_t cap = 4096;
    char *data = (char *)malloc(cap);
    if (!data) {
        fprintf(stderr, "pbcopy: out of memory\n");
        return 1;
    }
    ssize_t n;
    while ((n = read(STDIN_FILENO, buf, sizeof(buf))) > 0) {
        if (total + (size_t)n > cap) {
            size_t newcap = cap * 2;
            while (newcap < total + (size_t)n) newcap *= 2;
            char *tmp = (char *)realloc(data, newcap);
            if (!tmp) {
                free(data);
                fprintf(stderr, "pbcopy: out of memory\n");
                return 1;
            }
            data = tmp;
            cap = newcap;
        }
        memcpy(data + total, buf, (size_t)n);
        total += (size_t)n;
    }
    int rc = runtimeClipboardSet(data, total);
    free(data);
    if (rc != 0) {
        fprintf(stderr, "pbcopy: clipboard unavailable\n");
        return 1;
    }
    return 0;
}

static int smallcluePbpasteCommand(int argc, char **argv) {
    (void)argv;
    if (argc > 1) {
        fprintf(stderr, "pbpaste: takes no arguments\n");
        return 1;
    }
    smallclueResetGetopt();
    size_t len = 0;
    char *text = runtimeClipboardGet(&len);
    if (!text) {
        fprintf(stderr, "pbpaste: clipboard unavailable\n");
        return 1;
    }
    ssize_t written = write(STDOUT_FILENO, text, len);
    free(text);
    return written < 0 ? 1 : 0;
}
