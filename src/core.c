/*
 * NOTE: For iPadOS/iOS, every new smallclue applet must also be wired into
 * src/smallclue/integration.c and src/shell/builtins.c so exsh can invoke it.
 * See Docs/notes_smallclu_ios.md for the full checklist before landing changes.
 */
#include "smallclue.h"

#include "common/runtime_tty.h"
#include "dvtm_app.h"
#include "micro_app.h"
#include "nextvi_app.h"
#include "openssh_app.h"
#include "openrsync_app.h"
#include "tar_app.h"
#include "gzip_app.h"
#include "readlink_app.h"
#include "checksum_app.h"
#include "diff_app.h"
#include "patch_app.h"
#include "printf_app.h"
#include "expr_app.h"
#include "chown_app.h"
#include "base64_app.h"
#include "nohup_app.h"
#include "cmp_app.h"
#include "dd_app.h"
#include "od_app.h"
#include "seq_app.h"
#include "nl_app.h"
#include "tac_app.h"
#include "rev_app.h"
#include "fold_app.h"
#include "paste_app.h"
#include "split_app.h"
#include "fmt_app.h"
#include "comm_app.h"
#include "awk_app.h"
#include "common/runtime_clipboard.h"
#if defined(PSCAL_HAS_LIBCURL)
#include <curl/curl.h>
#endif
#if defined(PSCAL_HAS_LIBGIT2)
#include <git2.h>
#endif
#if defined(PSCAL_TARGET_IOS)
#include "common/path_virtualization.h"
#include "ios/vproc.h"
#include "ios/tty/pscal_tty.h"
#endif
#if defined(__has_include)
#if __has_include("../../core/build_info.h")
#include "../../core/build_info.h"
#else
#include "core/build_info.h"
#endif
#else
#include "core/build_info.h"
#endif
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <poll.h>
#include <fnmatch.h>
#include <regex.h>
#include <grp.h>
#include <limits.h>
#include <libgen.h>
#include <locale.h>
#include <wchar.h>
#include <pwd.h>
#if defined(__linux__) || defined(linux) || defined(__linux)
#include <shadow.h>
#include <crypt.h>
#include <sys/klog.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#endif
#include <sys/resource.h>
#include <sys/wait.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>
#if defined(__linux__) || defined(linux) || defined(__linux)
#include <sys/sysmacros.h>
#endif
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <signal.h>
#include <stdatomic.h>
#include <sys/select.h>
#include <glob.h>
#include <pthread.h>
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
char *pscalRuntimePickMountSourceDirectory(void) __attribute__((weak));
extern int PSCALRuntimePingHost(const char *host,
    int count,
    int timeout_ms,
    char **out_output) __attribute__((weak_import));
extern void *PSCALRuntimeGetCurrentRuntimeContext(void) __attribute__((weak_import));
extern void PSCALRuntimeSetCurrentRuntimeContext(void *ctx) __attribute__((weak_import));
#if !defined(__APPLE__)
extern int PSCALRuntimePingHost(const char *host,
    int count,
    int timeout_ms,
    char **out_output) __attribute__((weak));
extern void *PSCALRuntimeGetCurrentRuntimeContext(void) __attribute__((weak));
extern void PSCALRuntimeSetCurrentRuntimeContext(void *ctx) __attribute__((weak));
#endif
#ifndef PSCAL_RUNTIME_CAPTURE_IMPL
__attribute__((weak)) void PSCALRuntimeBeginScriptCapture(const char *path, int append) { (void)path; (void)append; }
__attribute__((weak)) void PSCALRuntimeEndScriptCapture(void) {}
__attribute__((weak)) int PSCALRuntimeScriptCaptureActive(void) { return 0; }
__attribute__((weak)) int pscalRuntimeOpenShellTab(void) { errno = ENOSYS; return -1; }
__attribute__((weak)) char *pscalRuntimePickMountSourceDirectory(void) { errno = ENOSYS; return NULL; }
__attribute__((weak)) void *PSCALRuntimeGetCurrentRuntimeContext(void) { return NULL; }
__attribute__((weak)) void PSCALRuntimeSetCurrentRuntimeContext(void *ctx) { (void)ctx; }
#endif
__attribute__((weak)) char *pscalRuntimeCopyMarketingVersion(void) { return NULL; }
#endif
#include <termios.h>
#include "termios_shim.h"
#include <time.h>
#include <unistd.h>
#if defined(__linux__) || defined(linux) || defined(__linux)
#include <sys/mount.h>
#endif

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
int smallclueGitCommand(int argc, char **argv);

static ssize_t smallclueGetlineStream(char **line, size_t *cap, FILE *stream, int *out_errno);
static uint64_t gSmallclueProcessStartMonoNs = 0;

static uint64_t smallclueNowMonoNs(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
    }
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000000000ull + (uint64_t)tv.tv_usec * 1000ull;
}

__attribute__((constructor)) static void smallclueCaptureProcessStart(void) {
    gSmallclueProcessStartMonoNs = smallclueNowMonoNs();
}

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

#if defined(PSCAL_TARGET_IOS)
static char *smallclueHostRealpathPath(const char *path, char *resolved, size_t resolved_size) {
    if (!path || !resolved || resolved_size == 0) {
        errno = EINVAL;
        return NULL;
    }
    typedef char *(*SmallclueRealpathFn)(const char *, char *);
    static SmallclueRealpathFn realpath_fn = NULL;
    static bool attempted = false;
    if (!attempted) {
        attempted = true;
        realpath_fn = (SmallclueRealpathFn)dlsym(RTLD_NEXT, "realpath");
        if (!realpath_fn) {
            realpath_fn = (SmallclueRealpathFn)dlsym(RTLD_DEFAULT, "realpath");
        }
    }
    if (!realpath_fn) {
        errno = ENOSYS;
        return NULL;
    }
    return realpath_fn(path, resolved);
}

static int smallclueHostStatPath(const char *path, struct stat *st) {
    if (!path || !st) {
        errno = EINVAL;
        return -1;
    }
    typedef int (*SmallclueStatFn)(const char *, struct stat *);
    static SmallclueStatFn stat_fn = NULL;
    static bool attempted = false;
    if (!attempted) {
        attempted = true;
        stat_fn = (SmallclueStatFn)dlsym(RTLD_NEXT, "stat");
        if (!stat_fn) {
            stat_fn = (SmallclueStatFn)dlsym(RTLD_DEFAULT, "stat");
        }
    }
    if (!stat_fn) {
        errno = ENOSYS;
        return -1;
    }
    return stat_fn(path, st);
}
#endif

static bool smallclueCopyPath(char *out, size_t outSize, const char *value) {
    if (!out || outSize == 0 || !value) {
        return false;
    }
    int written = snprintf(out, outSize, "%s", value);
    return written > 0 && (size_t)written < outSize;
}

static bool smallclueJoinPath2(char *out,
                               size_t outSize,
                               const char *left,
                               const char *right) {
    if (!out || outSize == 0 || !left || !right) {
        return false;
    }
    int written = snprintf(out, outSize, "%s/%s", left, right);
    return written > 0 && (size_t)written < outSize;
}

static bool smallclueResolveEtcEntry(const char *entryName,
                                     int accessMode,
                                     char *outPath,
                                     size_t outPathSize) {
    if (!entryName || entryName[0] == '\0' || !outPath || outPathSize == 0) {
        return false;
    }
    outPath[0] = '\0';

    char candidate[PATH_MAX];
    const char *etcRoot = getenv("PSCALI_ETC_ROOT");
    if (etcRoot && etcRoot[0] == '/') {
        if (smallclueJoinPath2(candidate, sizeof(candidate), etcRoot, entryName) &&
            access(candidate, accessMode) == 0 &&
            smallclueCopyPath(outPath, outPathSize, candidate)) {
            return true;
        }
    }

    const char *containerRoot = getenv("PSCALI_CONTAINER_ROOT");
    if (containerRoot && containerRoot[0] == '/') {
        int written = snprintf(candidate,
                               sizeof(candidate),
                               "%s/Documents/etc/%s",
                               containerRoot,
                               entryName);
        if (written > 0 &&
            (size_t)written < sizeof(candidate) &&
            access(candidate, accessMode) == 0 &&
            smallclueCopyPath(outPath, outPathSize, candidate)) {
            return true;
        }
    }

    if (smallclueJoinPath2(candidate, sizeof(candidate), "/etc", entryName) &&
        access(candidate, accessMode) == 0 &&
        smallclueCopyPath(outPath, outPathSize, candidate)) {
        return true;
    }
    return false;
}

static bool smallclueResolveExshPath(char *outPath, size_t outPathSize) {
    if (!outPath || outPathSize == 0) {
        return false;
    }
    outPath[0] = '\0';

    char candidate[PATH_MAX];
    const char *workspaceRoot = getenv("PSCALI_WORKSPACE_ROOT");
    if (workspaceRoot && workspaceRoot[0] == '/') {
        int written = snprintf(candidate,
                               sizeof(candidate),
                               "%s/bin/exsh",
                               workspaceRoot);
        if (written > 0 &&
            (size_t)written < sizeof(candidate) &&
            access(candidate, X_OK) == 0 &&
            smallclueCopyPath(outPath, outPathSize, candidate)) {
            return true;
        }
    }

    const char *containerRoot = getenv("PSCALI_CONTAINER_ROOT");
    if (containerRoot && containerRoot[0] == '/') {
        int written = snprintf(candidate,
                               sizeof(candidate),
                               "%s/Documents/bin/exsh",
                               containerRoot);
        if (written > 0 &&
            (size_t)written < sizeof(candidate) &&
            access(candidate, X_OK) == 0 &&
            smallclueCopyPath(outPath, outPathSize, candidate)) {
            return true;
        }
    }

    char resolved[PATH_MAX];
    const char *expanded = smallclueResolvePath("/bin/exsh", resolved, sizeof(resolved));
    if (expanded &&
        access(expanded, X_OK) == 0 &&
        smallclueCopyPath(outPath, outPathSize, expanded)) {
        return true;
    }

    if (smallclueJoinPath2(candidate, sizeof(candidate), "/bin", "exsh") &&
        access(candidate, X_OK) == 0 &&
        smallclueCopyPath(outPath, outPathSize, candidate)) {
        return true;
    }
    return false;
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

static bool smallcluePathHasShebang(const char *path) {
    if (!path || !*path) {
        return false;
    }
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return false;
    }
    char header[2];
    ssize_t n = read(fd, header, sizeof(header));
    close(fd);
    return n == 2 && header[0] == '#' && header[1] == '!';
}

static bool smallclueResolveCommandPathForExec(const char *name, char *resolved, size_t resolved_size);

#if defined(PSCAL_TARGET_IOS)
static bool smallclueReadShebangInterpreter(const char *path,
                                            char *interpreter,
                                            size_t interpreter_size,
                                            char *interpreter_arg,
                                            size_t interpreter_arg_size) {
    if (!path || !*path || !interpreter || interpreter_size == 0 ||
        !interpreter_arg || interpreter_arg_size == 0) {
        return false;
    }
    interpreter[0] = '\0';
    interpreter_arg[0] = '\0';
    FILE *fp = fopen(path, "r");
    if (!fp) {
        return false;
    }
    char line[PATH_MAX + 64];
    if (!fgets(line, sizeof(line), fp)) {
        fclose(fp);
        return false;
    }
    fclose(fp);
    if (line[0] != '#' || line[1] != '!') {
        return false;
    }
    char *cursor = line + 2;
    while (*cursor && isspace((unsigned char)*cursor)) {
        cursor++;
    }
    if (!*cursor) {
        return false;
    }
    char *interp_start = cursor;
    while (*cursor && !isspace((unsigned char)*cursor)) {
        cursor++;
    }
    char *interp_end = cursor;
    while (*cursor && isspace((unsigned char)*cursor)) {
        cursor++;
    }
    char *arg_start = cursor;
    while (*cursor && *cursor != '\n' && *cursor != '\r') {
        cursor++;
    }
    *interp_end = '\0';
    *cursor = '\0';
    if (snprintf(interpreter, interpreter_size, "%s", interp_start) <= 0 ||
        interpreter[0] == '\0') {
        return false;
    }
    if (*arg_start) {
        if (snprintf(interpreter_arg, interpreter_arg_size, "%s", arg_start) <= 0) {
            interpreter_arg[0] = '\0';
        }
    }
    return true;
}

typedef int (*SmallclueToolEntryFn)(int argc, char **argv);

static SmallclueToolEntryFn smallclueLookupToolEntrySymbol(const char *symbol_name) {
    if (!symbol_name || !*symbol_name) {
        return NULL;
    }
    return (SmallclueToolEntryFn)dlsym(RTLD_DEFAULT, symbol_name);
}

static const char *smallclueResolveShebangToolName(const char *interpreter) {
    if (!interpreter || !*interpreter) {
        return NULL;
    }
    const char *base = strrchr(interpreter, '/');
    base = base ? (base + 1) : interpreter;
    if (strcasecmp(base, "pascal") == 0) return "pascal";
    if (strcasecmp(base, "clike") == 0) return "clike";
    if (strcasecmp(base, "rea") == 0) return "rea";
    if (strcasecmp(base, "pscalvm") == 0) return "pscalvm";
    if (strcasecmp(base, "pscaljson2bc") == 0) return "pscaljson2bc";
#ifdef BUILD_DASCAL
    if (strcasecmp(base, "dascal") == 0) return "dascal";
#endif
#ifdef BUILD_PSCALD
    if (strcasecmp(base, "pscald") == 0) return "pscald";
    if (strcasecmp(base, "pscalasm") == 0) return "pscalasm";
#endif
#if defined(SMALLCLUE_WITH_EXSH)
    if (strcasecmp(base, "sh") == 0) return "exsh";
    if (strcasecmp(base, "exsh") == 0) return "exsh";
#elif defined(SMALLCLUE_WITH_SH)
    if (strcasecmp(base, "sh") == 0) return "sh";
    if (strcasecmp(base, "ash") == 0) return "sh";
#endif
    return NULL;
}

static SmallclueToolEntryFn smallclueResolveShebangToolEntry(const char *tool_name) {
    if (!tool_name || !*tool_name) {
        return NULL;
    }
    if (strcmp(tool_name, "pascal") == 0) return smallclueLookupToolEntrySymbol("pascal_main");
    if (strcmp(tool_name, "clike") == 0) return smallclueLookupToolEntrySymbol("clike_main");
    if (strcmp(tool_name, "rea") == 0) return smallclueLookupToolEntrySymbol("rea_main");
    if (strcmp(tool_name, "pscalvm") == 0) return smallclueLookupToolEntrySymbol("pscalvm_main");
    if (strcmp(tool_name, "pscaljson2bc") == 0) return smallclueLookupToolEntrySymbol("pscaljson2bc_main");
#ifdef BUILD_DASCAL
    if (strcmp(tool_name, "dascal") == 0) return smallclueLookupToolEntrySymbol("dascal_main");
#endif
#ifdef BUILD_PSCALD
    if (strcmp(tool_name, "pscald") == 0) return smallclueLookupToolEntrySymbol("pscald_main");
    if (strcmp(tool_name, "pscalasm") == 0) return smallclueLookupToolEntrySymbol("pscalasm_main");
#endif
#if defined(SMALLCLUE_WITH_EXSH)
    if (strcmp(tool_name, "exsh") == 0) return smallclueLookupToolEntrySymbol("exsh_main");
#endif
    return NULL;
}

#if defined(PSCAL_TARGET_IOS)
#ifndef SMALLCLUE_TOOL_THREAD_STACK_SZ
#define SMALLCLUE_TOOL_THREAD_STACK_SZ (8 * 1024 * 1024)
#endif

typedef struct SmallclueToolThreadContext {
    SmallclueToolEntryFn entry;
    int argc;
    char **argv;
    VProcSessionStdio *session_stdio;
    VProc *session_vproc;
    void *runtime_ctx;
    int status;
} SmallclueToolThreadContext;

static bool smallclueShebangToolNeedsWorkerThread(const char *tool_name) {
    if (!tool_name || !*tool_name) {
        return false;
    }
    if (strcmp(tool_name, "exsh") == 0) {
        return false;
    }
    return true;
}

static void *smallclueToolThreadMain(void *opaque) {
    SmallclueToolThreadContext *ctx = (SmallclueToolThreadContext *)opaque;
    if (!ctx || !ctx->entry) {
        if (ctx) {
            ctx->status = 127;
        }
        return NULL;
    }

    void *prev_runtime_ctx = NULL;
    VProcSessionStdio *prev_stdio = vprocSessionStdioCurrent();
    bool runtime_ctx_swapped = false;
    bool vproc_active = false;
    if (PSCALRuntimeGetCurrentRuntimeContext) {
        prev_runtime_ctx = PSCALRuntimeGetCurrentRuntimeContext();
    }
    if (PSCALRuntimeSetCurrentRuntimeContext && ctx->runtime_ctx) {
        PSCALRuntimeSetCurrentRuntimeContext(ctx->runtime_ctx);
        runtime_ctx_swapped = true;
    }
    if (ctx->session_stdio) {
        vprocSessionStdioActivate(ctx->session_stdio);
    }
    if (ctx->session_vproc) {
        vprocRegisterThread(ctx->session_vproc, pthread_self());
        vprocActivate(ctx->session_vproc);
        vproc_active = true;
        int worker_pid = vprocPid(ctx->session_vproc);
        if (worker_pid > 0) {
            vprocSetStopUnsupported(worker_pid, false);
            vprocSetCooperativeStopWait(worker_pid, false);
        }
    }

    sigset_t unblock_mask;
    sigemptyset(&unblock_mask);
    sigaddset(&unblock_mask, SIGINT);
    sigaddset(&unblock_mask, SIGTSTP);
    (void)pthread_sigmask(SIG_UNBLOCK, &unblock_mask, NULL);

    ctx->status = ctx->entry(ctx->argc, ctx->argv);

    if (ctx->session_stdio) {
        vprocSessionStdioActivate(prev_stdio);
    }
    if (vproc_active) {
        vprocDeactivate();
    }
    if (runtime_ctx_swapped && PSCALRuntimeSetCurrentRuntimeContext) {
        PSCALRuntimeSetCurrentRuntimeContext(prev_runtime_ctx);
    }
    return NULL;
}

static int smallclueRunToolEntryInWorkerThread(SmallclueToolEntryFn entry, int argc, char **argv) {
    if (!entry) {
        return 127;
    }

    SmallclueToolThreadContext ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.entry = entry;
    ctx.argc = argc;
    ctx.argv = argv;
    ctx.status = 127;
    ctx.session_stdio = vprocSessionStdioCurrent();
    ctx.session_vproc = vprocCurrent();
    ctx.runtime_ctx = PSCALRuntimeGetCurrentRuntimeContext
        ? PSCALRuntimeGetCurrentRuntimeContext()
        : NULL;

    struct termios stdin_termios;
    bool stdin_termios_valid = (tcgetattr(STDIN_FILENO, &stdin_termios) == 0);

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    (void)pthread_attr_setstacksize(&attr, SMALLCLUE_TOOL_THREAD_STACK_SZ);
    pthread_t worker_thread;
    int create_rc = pthread_create(&worker_thread, &attr, smallclueToolThreadMain, &ctx);
    pthread_attr_destroy(&attr);
    if (create_rc != 0) {
        return entry(argc, argv);
    }

    pthread_join(worker_thread, NULL);
    if (stdin_termios_valid) {
        (void)tcsetattr(STDIN_FILENO, TCSAFLUSH, &stdin_termios);
    }
    return ctx.status;
}
#endif

static int smallclueRunShebangTool(const char *path, char *const *argv) {
    if (!path || !*path) {
        return -1;
    }

    char interpreter[PATH_MAX];
    char interpreter_arg[PATH_MAX];
    if (!smallclueReadShebangInterpreter(path,
                                         interpreter,
                                         sizeof(interpreter),
                                         interpreter_arg,
                                         sizeof(interpreter_arg))) {
        return -1;
    }

    char arg_words[PATH_MAX];
    arg_words[0] = '\0';
    if (interpreter_arg[0]) {
        snprintf(arg_words, sizeof(arg_words), "%s", interpreter_arg);
    }
    char *words[16];
    size_t word_count = 0;
    char *cursor = arg_words;
    while (*cursor && word_count < (sizeof(words) / sizeof(words[0]))) {
        while (*cursor && isspace((unsigned char)*cursor)) {
            cursor++;
        }
        if (!*cursor) {
            break;
        }
        words[word_count++] = cursor;
        while (*cursor && !isspace((unsigned char)*cursor)) {
            cursor++;
        }
        if (*cursor) {
            *cursor++ = '\0';
        }
    }
    const char *tool_name = NULL;
    size_t shebang_arg_start = 0;
    const char *base = strrchr(interpreter, '/');
    base = base ? (base + 1) : interpreter;
    if (strcmp(base, "env") == 0) {
        if (word_count == 0) {
            return -1;
        }
        tool_name = smallclueResolveShebangToolName(words[0]);
        shebang_arg_start = 1;
    } else {
        tool_name = smallclueResolveShebangToolName(interpreter);
        shebang_arg_start = 0;
    }
    SmallclueToolEntryFn entry = smallclueResolveShebangToolEntry(tool_name);
    if (!tool_name || !entry) {
        return -1;
    }

    size_t shebang_argc = (word_count > shebang_arg_start)
                              ? (word_count - shebang_arg_start)
                              : 0;
    size_t script_argc = 0;
    if (argv) {
        while (argv[1 + script_argc]) {
            script_argc++;
        }
    }

    size_t total_args = 1 + shebang_argc + 1 + script_argc;
    char **tool_argv = (char **)calloc(total_args + 1, sizeof(char *));
    if (!tool_argv) {
        return EXIT_FAILURE;
    }

    bool ok = true;
    size_t idx = 0;
    tool_argv[idx++] = strdup(tool_name);
    if (!tool_argv[idx - 1]) {
        ok = false;
    }
    for (size_t i = 0; ok && i < shebang_argc; ++i) {
        tool_argv[idx++] = strdup(words[shebang_arg_start + i]);
        if (!tool_argv[idx - 1]) {
            ok = false;
        }
    }
    if (ok) {
        tool_argv[idx++] = strdup(path);
        if (!tool_argv[idx - 1]) {
            ok = false;
        }
    }
    for (size_t i = 0; ok && i < script_argc; ++i) {
        const char *arg = argv[1 + i];
        tool_argv[idx++] = strdup(arg ? arg : "");
        if (!tool_argv[idx - 1]) {
            ok = false;
        }
    }
    tool_argv[idx] = NULL;

    int status = EXIT_FAILURE;
    if (ok) {
 #if defined(PSCAL_TARGET_IOS)
        if (smallclueShebangToolNeedsWorkerThread(tool_name)) {
            status = smallclueRunToolEntryInWorkerThread(entry, (int)total_args, tool_argv);
        } else {
            status = entry((int)total_args, tool_argv);
        }
 #else
        status = entry((int)total_args, tool_argv);
 #endif
    } else {
        fprintf(stderr, "%s: out of memory launching tool runner\n", tool_name);
    }

    for (size_t i = 0; i < idx; ++i) {
        free(tool_argv[i]);
    }
    free(tool_argv);
    return status;
}

static bool smallclueWatchExecViaShebang(const char *script_path, int argc, char **argv) {
    if (!script_path || !*script_path || argc <= 0 || !argv || !argv[0]) {
        return false;
    }
    char interpreter[PATH_MAX];
    char interpreter_arg[PATH_MAX];
    if (!smallclueReadShebangInterpreter(script_path,
                                         interpreter,
                                         sizeof(interpreter),
                                         interpreter_arg,
                                         sizeof(interpreter_arg))) {
        return false;
    }
    char arg_words[PATH_MAX];
    arg_words[0] = '\0';
    if (interpreter_arg[0]) {
        snprintf(arg_words, sizeof(arg_words), "%s", interpreter_arg);
    }
    char *words[16];
    size_t word_count = 0;
    char *cursor = arg_words;
    while (*cursor && word_count < (sizeof(words) / sizeof(words[0]))) {
        while (*cursor && isspace((unsigned char)*cursor)) {
            cursor++;
        }
        if (!*cursor) {
            break;
        }
        words[word_count++] = cursor;
        while (*cursor && !isspace((unsigned char)*cursor)) {
            cursor++;
        }
        if (*cursor) {
            *cursor++ = '\0';
        }
    }
    const char *interp_leaf = strrchr(interpreter, '/');
    interp_leaf = interp_leaf ? (interp_leaf + 1) : interpreter;

    char resolved_interpreter[PATH_MAX];
    const char *interp_cmd = interpreter;
    const char *interp_exec = interpreter;
    bool using_env_style = (interp_leaf && strcmp(interp_leaf, "env") == 0);
    if (using_env_style && word_count > 0) {
        interp_cmd = words[0];
        if (smallclueResolveCommandPathForExec(words[0],
                                               resolved_interpreter,
                                               sizeof(resolved_interpreter))) {
            interp_exec = resolved_interpreter;
        } else {
            interp_exec = words[0];
        }
    } else if (smallclueResolveCommandPathForExec(interpreter,
                                                  resolved_interpreter,
                                                  sizeof(resolved_interpreter))) {
        interp_exec = resolved_interpreter;
    } else if (strchr(interpreter, '/')) {
        const char *base = strrchr(interpreter, '/');
        base = base ? (base + 1) : interpreter;
        if (base && *base) {
            interp_cmd = base;
            if (smallclueResolveCommandPathForExec(base,
                                                   resolved_interpreter,
                                                   sizeof(resolved_interpreter))) {
                interp_exec = resolved_interpreter;
            } else {
                interp_exec = base;
            }
        }
    }

    size_t interpreter_word_start = (using_env_style && word_count > 0) ? 1u : 0u;
    size_t interpreter_word_count = (word_count > interpreter_word_start)
                                        ? (word_count - interpreter_word_start)
                                        : 0u;
    size_t child_argc = (size_t)argc + interpreter_word_count + 1u;
    char **child_argv = (char **)calloc(child_argc + 1u, sizeof(char *));
    if (!child_argv) {
        errno = ENOMEM;
        return false;
    }
    size_t out = 0;
    child_argv[out++] = (char *)interp_exec;
    for (size_t i = 0; i < interpreter_word_count; ++i) {
        child_argv[out++] = words[interpreter_word_start + i];
    }
    child_argv[out++] = (char *)script_path;
    for (int i = 1; i < argc; ++i) {
        child_argv[out++] = argv[i];
    }
    child_argv[out] = NULL;
    execv(interp_exec, child_argv);
    int saved = errno;
    if ((saved == ENOENT || saved == EACCES) &&
        strcmp(interp_exec, interp_cmd) != 0) {
        child_argv[0] = (char *)interp_cmd;
        execvp(interp_cmd, child_argv);
        saved = errno;
    }
    free(child_argv);
    errno = saved;
    return false;
}
#endif

static bool smallclueCommandPathRunnable(const char *path) {
    if (!path || !*path) {
        return false;
    }
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
        return false;
    }
    if (access(path, X_OK) == 0) {
        return true;
    }
#if defined(PSCAL_TARGET_IOS)
    if ((st.st_mode & 0111) != 0) {
        return true;
    }
    if (access(path, R_OK) == 0 && smallcluePathHasShebang(path)) {
        return true;
    }
#endif
    return false;
}

static bool smallclueResolveExecutableCandidate(const char *candidate, char *resolved, size_t resolved_size) {
    if (!candidate || !*candidate || !resolved || resolved_size == 0) {
        return false;
    }
    const char *probes[4];
    size_t probe_count = 0;
#if defined(PSCAL_TARGET_IOS)
    char expanded[PATH_MAX];
    char stripped[PATH_MAX];
    char stripped_expanded[PATH_MAX];
    if (candidate[0] == '/' &&
        pathTruncateExpand(candidate, expanded, sizeof(expanded)) &&
        strcmp(expanded, candidate) != 0) {
        probes[probe_count++] = expanded;
    }
#endif
    probes[probe_count++] = candidate;
#if defined(PSCAL_TARGET_IOS)
    if (candidate[0] == '/' &&
        pathTruncateStrip(candidate, stripped, sizeof(stripped)) &&
        strcmp(stripped, candidate) != 0) {
        probes[probe_count++] = stripped;
        if (pathTruncateExpand(stripped, stripped_expanded, sizeof(stripped_expanded)) &&
            strcmp(stripped_expanded, stripped) != 0) {
            probes[probe_count++] = stripped_expanded;
        }
    }
#endif
    for (size_t i = 0; i < probe_count; ++i) {
        const char *path = probes[i];
        if (!path || !*path) {
            continue;
        }
        if (!smallclueCommandPathRunnable(path)) {
            continue;
        }
        int copied = snprintf(resolved, resolved_size, "%s", path);
        return copied >= 0 && (size_t)copied < resolved_size;
    }
    return false;
}

static bool smallclueResolveCommandPathForExec(const char *name, char *resolved, size_t resolved_size) {
    if (!name || !*name || !resolved || resolved_size == 0) {
        return false;
    }
    if (strchr(name, '/')) {
        return smallclueResolveExecutableCandidate(name, resolved, resolved_size);
    }
    const char *path = getenv("PATH");
    if (path && *path) {
        char *copy = strdup(path);
        if (copy) {
            char *saveptr = NULL;
            for (char *token = strtok_r(copy, ":", &saveptr);
                 token;
                 token = strtok_r(NULL, ":", &saveptr)) {
                const char *dir = (*token == '\0') ? "." : token;
                char candidate[PATH_MAX];
                int written = snprintf(candidate, sizeof(candidate), "%s/%s", dir, name);
                if (written <= 0 || (size_t)written >= sizeof(candidate)) {
                    continue;
                }
                if (smallclueResolveExecutableCandidate(candidate, resolved, resolved_size)) {
                    free(copy);
                    return true;
                }
            }
            free(copy);
        }
    }
#if defined(PSCAL_TARGET_IOS)
    const char *fallback_dirs[] = { "/bin", "/Documents/bin" };
    for (size_t i = 0; i < sizeof(fallback_dirs) / sizeof(fallback_dirs[0]); ++i) {
        char candidate[PATH_MAX];
        int written = snprintf(candidate, sizeof(candidate), "%s/%s", fallback_dirs[i], name);
        if (written <= 0 || (size_t)written >= sizeof(candidate)) {
            continue;
        }
        if (smallclueResolveExecutableCandidate(candidate, resolved, resolved_size)) {
            return true;
        }
    }
#endif
    return false;
}

#if defined(PSCAL_TARGET_IOS)
static bool smallclueResolveExecutableFromBaseCwd(const char *base_cwd,
                                                  const char *name,
                                                  char *resolved,
                                                  size_t resolved_size) {
    if (!name || !*name || !resolved || resolved_size == 0) {
        return false;
    }
    if (name[0] == '/') {
        return smallclueResolveExecutableCandidate(name, resolved, resolved_size);
    }
    if (base_cwd && base_cwd[0] == '/' && strchr(name, '/')) {
        char candidate[PATH_MAX];
        int written = snprintf(candidate, sizeof(candidate), "%s/%s", base_cwd, name);
        if (written > 0 &&
            (size_t)written < sizeof(candidate) &&
            smallclueResolveExecutableCandidate(candidate, resolved, resolved_size)) {
            return true;
        }
    }
    return smallclueResolveCommandPathForExec(name, resolved, resolved_size);
}
#endif

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
    bool cooperative_stop_entry = false;
    int cur_pid = 0;
#if defined(PSCAL_TARGET_IOS)
    VProc *vp = vprocCurrent();
    if (vp) {
        int shell_pid = vprocGetShellSelfPid();
        cur_pid = vprocPid(vp);
        if (cur_pid > 0) {
            cooperative_stop_entry = vprocGetStopUnsupported(cur_pid);
        }
        if (cur_pid > 0 && !cooperative_stop_entry) {
            allow_cooperative_sigtstp = false;
        }
        if (!cooperative_stop_entry &&
            (shell_pid <= 0 || vprocPid(vp) != shell_pid)) {
            (void)vprocWaitIfStopped(vp);
        }
        if (dbg && *dbg) {
            fprintf(stderr,
                    "[smallclue] shouldAbort pid=%d shell_pid=%d stop_unsupported=%d allow_coop=%d\n",
                    cur_pid,
                    shell_pid,
                    (int)cooperative_stop_entry,
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
    bool raw_mode;
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
static int smallclueInstallCommand(int argc, char **argv);
static int smallclueRsyncCommand(int argc, char **argv);
static int smallcluePwdCommand(int argc, char **argv);
static int smallclueEnvCommand(int argc, char **argv);
static int smallclueChmodCommand(int argc, char **argv);
static int smallclueDateCommand(int argc, char **argv);
static int smallclueCalCommand(int argc, char **argv);
static int smallclueHeadCommand(int argc, char **argv);
static int smallclueHistoryCommand(int argc, char **argv);
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
static int smallclueTimeoutCommand(int argc, char **argv);
static int smallclueMkdirCommand(int argc, char **argv);
static int smallclueMknodCommand(int argc, char **argv);
static int smallclueMountCommand(int argc, char **argv);
static int smallclueUmountCommand(int argc, char **argv);
static int smallclueWhoamiCommand(int argc, char **argv);
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
static int smallclueRemovePathWithLabel(const char *label, const char *path, bool recursive, bool force, bool interactive);
static int smallclueCopyFile(const char *label, const char *src, const char *dst);
static int smallclueMkdirParents(const char *path, mode_t mode, bool verbose);
static void smallclueGetTerminalSize(int *rows, int *cols);
static int smallclueEditorCommand(int argc, char **argv);
static int smallclueMicroCommand(int argc, char **argv);
#if defined(SMALLCLUE_WITH_DVTM)
static int smallclueDvtmCommand(int argc, char **argv);
#endif
static int smallclueSshCommand(int argc, char **argv);
static int smallclueScpCommand(int argc, char **argv);
static int smallclueSftpCommand(int argc, char **argv);
static int smallclueSshKeygenCommand(int argc, char **argv);
static int smallclueSshCopyIdCommand(int argc, char **argv);
static int smallcluePbcopyCommand(int argc, char **argv);
static int smallcluePbpasteCommand(int argc, char **argv);
static int smallclueInitCommand(int argc, char **argv);
static int smallclueRunitCommand(int argc, char **argv);
static int smallclueMdevCommand(int argc, char **argv);
static int smallclueHaltCommand(int argc, char **argv);
#if defined(SMALLCLUE_WITH_EXSH)
extern int exsh_main(int argc, char **argv);
static int smallclueShCommand(int argc, char **argv);
#elif defined(SMALLCLUE_WITH_SH)
static int smallclueNativeShCommand(int argc, char **argv);
#endif
static int smallclueUptimeCommand(int argc, char **argv);
static int smallclueUnameCommand(int argc, char **argv);
static int smallcluePingCommand(int argc, char **argv);
static int smallclueMarkdownCommand(int argc, char **argv);
static int smallclueCurlCommand(int argc, char **argv);
static int smallclueWgetCommand(int argc, char **argv);
static int smallclueWhichCommand(int argc, char **argv);
typedef struct {
    const char *method;   /* NULL = default (GET, or POST if postData is set) */
    char **headers;       /* array of "Key: Value" strings */
    int headerCount;
    const char *postData; /* NULL = no request body */
    const char *userpwd;  /* NULL = no auth; else "user:password" */
    bool insecureTls;     /* true = skip TLS certificate/host verification */
} SmallclueHttpRequestOptions;

static int smallclueHttpFetch(const char *cmd_name, const char *url, const char *destinationPath,
                              const SmallclueHttpRequestOptions *reqOpts);
static int smallclueHttpFetchToMemory(const char *cmd_name, const char *url, char **data_out, size_t *len_out,
                                      const SmallclueHttpRequestOptions *reqOpts);
static int smallclueTelnetCommand(int argc, char **argv);
static int smallclueTracerouteCommand(int argc, char **argv);
static int smallclueNslookupCommand(int argc, char **argv);
static int smallclueHostCommand(int argc, char **argv);
static int smallclueHostnameCommand(int argc, char **argv);
#if SMALLCLUE_HAS_IFADDRS
static int smallclueIpAddrCommand(int argc, char **argv);
#endif
static int smallclueDfCommand(int argc, char **argv);
static int smallclueTopCommand(int argc, char **argv);
#if defined(PSCAL_TARGET_IOS)
static int smallclueHelpCommand(int argc, char **argv);
static int smallclueAddTabCommand(int argc, char **argv);
#endif
static int smallclueDmesgCommand(int argc, char **argv);


/* Builds the reverse-DNS query name real nslookup/host display for a PTR
 * lookup (e.g. "8.8.8.8" -> "8.8.8.8.in-addr.arpa", "::1" ->
 * "1.0.0...0.ip6.arpa") -- purely for display, matching what those tools
 * print; the actual lookup itself goes through getnameinfo(), which
 * doesn't need this string. IPv6 uses nibble-reversed hex per RFC 3596,
 * verified against real host/nslookup in Docker. */
static void smallclueBuildReverseDnsName(int family, const void *addr, char *out, size_t outSize) {
    if (family == AF_INET) {
        const unsigned char *b = (const unsigned char *)addr;
        snprintf(out, outSize, "%u.%u.%u.%u.in-addr.arpa", b[3], b[2], b[1], b[0]);
    } else {
        const unsigned char *b = (const unsigned char *)addr;
        size_t pos = 0;
        for (int i = 15; i >= 0 && pos + 4 < outSize; --i) {
            pos += (size_t)snprintf(out + pos, outSize - pos, "%x.%x.", b[i] & 0xF, (b[i] >> 4) & 0xF);
        }
        snprintf(out + pos, outSize - pos, "ip6.arpa");
    }
}

/* Detects an IP-address-shaped query and performs a PTR (reverse) lookup
 * instead of the usual forward A/AAAA lookup, matching real
 * nslookup/host's auto-detection. Returns true if `host` was IP-shaped
 * (whether or not the lookup itself succeeded, in which case an error
 * was already printed and *exitStatus set). */
static bool smallclueTryReverseDnsLookup(const char *label, const char *host, bool nslookupStyle, int *exitStatus) {
    struct in_addr addr4;
    struct in6_addr addr6;
    int family;
    const void *addrBytes;
    struct sockaddr_storage sa;
    socklen_t saLen;
    memset(&sa, 0, sizeof(sa));
    if (inet_pton(AF_INET, host, &addr4) == 1) {
        family = AF_INET;
        addrBytes = &addr4;
        struct sockaddr_in *sin = (struct sockaddr_in *)&sa;
        sin->sin_family = AF_INET;
        sin->sin_addr = addr4;
        saLen = sizeof(*sin);
    } else if (inet_pton(AF_INET6, host, &addr6) == 1) {
        family = AF_INET6;
        addrBytes = &addr6;
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&sa;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_addr = addr6;
        saLen = sizeof(*sin6);
    } else {
        return false;
    }

    char revname[256];
    smallclueBuildReverseDnsName(family, addrBytes, revname, sizeof(revname));

    char hostbuf[NI_MAXHOST];
    int rc = getnameinfo((struct sockaddr *)&sa, saLen, hostbuf, sizeof(hostbuf), NULL, 0, NI_NAMEREQD);
    if (rc != 0) {
        fprintf(stderr, "%s: %s: %s\n", label, revname, gai_strerror(rc));
        *exitStatus = 1;
        return true;
    }
    if (nslookupStyle) {
        printf("%s\tname = %s.\n", revname, hostbuf);
    } else {
        printf("%s domain name pointer %s.\n", revname, hostbuf);
    }
    *exitStatus = 0;
    return true;
}

/* ---- Minimal raw DNS client, for querying an explicit server (nslookup/
 * host's optional trailing SERVER argument) -- getaddrinfo/getnameinfo
 * have no per-call server override, so a custom-server query needs a
 * real (if minimal) DNS message encoder/decoder over UDP. Supports A
 * (1), AAAA (28), and PTR (12) queries against a recursive resolver;
 * CNAME records in the answer section are skipped rather than followed
 * (a normal recursive resolver returns the final A/AAAA alongside any
 * CNAME in the same response, so this covers the common case without
 * needing a second round-trip). */

#define SMALLCLUE_DNS_TYPE_A 1
#define SMALLCLUE_DNS_TYPE_NS 2
#define SMALLCLUE_DNS_TYPE_CNAME 5
#define SMALLCLUE_DNS_TYPE_PTR 12
#define SMALLCLUE_DNS_TYPE_MX 15
#define SMALLCLUE_DNS_TYPE_TXT 16
#define SMALLCLUE_DNS_TYPE_AAAA 28
#define SMALLCLUE_DNS_TYPE_SRV 33

static size_t smallclueDnsEncodeName(const char *name, unsigned char *buf, size_t bufSize) {
    size_t pos = 0;
    const char *p = name;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t labelLen = dot ? (size_t)(dot - p) : strlen(p);
        if (labelLen == 0 || labelLen > 63 || pos + labelLen + 1 >= bufSize) return 0;
        buf[pos++] = (unsigned char)labelLen;
        memcpy(buf + pos, p, labelLen);
        pos += labelLen;
        p += labelLen;
        if (*p == '.') p++;
    }
    if (pos + 1 >= bufSize) return 0;
    buf[pos++] = 0;
    return pos;
}

/* Decodes a (possibly compressed) name starting at `pos` into `out`,
 * and advances `*afterPos` past the name AS IT APPEARS AT `pos` (i.e.
 * past the pointer itself if compressed, not into the target it points
 * to) -- the correct semantics for skipping past a name inline in the
 * message. Returns false on a malformed/truncated name. */
static bool smallclueDnsDecodeName(const unsigned char *msg, size_t msgLen, size_t pos,
                                    char *out, size_t outSize, size_t *afterPos) {
    size_t outLen = 0;
    if (out && outSize > 0) out[0] = '\0';
    bool first = true;
    bool jumped = false;
    size_t cur = pos;
    size_t guard = 0;
    for (;;) {
        if (guard++ > 128 || cur >= msgLen) return false;
        unsigned char lenByte = msg[cur];
        if (lenByte == 0) {
            cur++;
            if (!jumped) *afterPos = cur;
            break;
        }
        if ((lenByte & 0xC0) == 0xC0) {
            if (cur + 1 >= msgLen) return false;
            size_t offset = (size_t)((lenByte & 0x3F) << 8) | msg[cur + 1];
            if (!jumped) *afterPos = cur + 2;
            jumped = true;
            cur = offset;
            continue;
        }
        if ((lenByte & 0xC0) != 0) return false; /* reserved bits set */
        size_t labelLen = lenByte;
        cur++;
        if (cur + labelLen > msgLen) return false;
        if (out) {
            if (!first && outLen + 1 < outSize) out[outLen++] = '.';
            for (size_t i = 0; i < labelLen && outLen + 1 < outSize; ++i) out[outLen++] = (char)msg[cur + i];
            out[outLen] = '\0';
        }
        first = false;
        cur += labelLen;
    }
    return true;
}

/* Sends one query to `server` (IPv4/IPv6 literal or hostname) for
 * `qname`/`qtype`, and appends every matching answer record's value
 * (an IP address string for A/AAAA, or a hostname for PTR) to
 * `*outAnswers`. Returns 0 on success (even with zero answers -- caller
 * checks *outCount), or a negative value on a real query failure
 * (unreachable server, timeout, malformed response). */
static const char *smallclueDnsRcodeName(int rcode) {
    static const char *rcodeNames[] = {
        "no error", "format error", "server failure", "name error (NXDOMAIN)",
        "not implemented", "refused"
    };
    return (rcode >= 0 && rcode < 6) ? rcodeNames[rcode] : "unknown error";
}

/* send()/recv() aren't guaranteed to move the whole buffer in one
 * call, which matters for the DNS-over-TCP fallback below (length-
 * prefixed messages need every byte accounted for). Returns 0 on
 * success, -1 on error. */
static int smallclueSendAll(int fd, const void *buf, size_t len) {
    const unsigned char *p = (const unsigned char *)buf;
    size_t sent = 0;
    while (sent < len) {
        ssize_t w = send(fd, p + sent, len - sent, 0);
        if (w <= 0) return -1;
        sent += (size_t)w;
    }
    return 0;
}

/* Returns the number of bytes read (== len on success), 0 on a clean
 * EOF before len bytes arrived, or -1 on error. */
static ssize_t smallclueRecvAll(int fd, void *buf, size_t len) {
    unsigned char *p = (unsigned char *)buf;
    size_t got = 0;
    while (got < len) {
        ssize_t r = recv(fd, p + got, len - got, 0);
        if (r < 0) return -1;
        if (r == 0) return (ssize_t)got > 0 ? -1 : 0;
        got += (size_t)r;
    }
    return (ssize_t)got;
}

static int smallclueDnsQueryServer(const char *server, const char *qname, int qtype,
                                    char ***outAnswers, int *outCount, int *outRcode) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    struct addrinfo *res = NULL;
    if (getaddrinfo(server, "53", &hints, &res) != 0 || !res) {
        fprintf(stderr, "dns: %s: server address not found\n", server);
        return -1;
    }

    int sock = socket(res->ai_family, SOCK_DGRAM, 0);
    if (sock < 0) {
        freeaddrinfo(res);
        return -1;
    }
    struct timeval tv = { 5, 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    unsigned char query[512];
    memset(query, 0, sizeof(query));
    uint16_t qid = (uint16_t)(getpid() & 0xffff);
    query[0] = (unsigned char)(qid >> 8);
    query[1] = (unsigned char)(qid & 0xff);
    query[2] = 0x01; /* RD=1 */
    query[3] = 0x00;
    query[4] = 0x00; query[5] = 0x01; /* QDCOUNT=1 */
    /* ANCOUNT/NSCOUNT/ARCOUNT already zero */
    size_t nameLen = smallclueDnsEncodeName(qname, query + 12, sizeof(query) - 12);
    if (nameLen == 0) {
        fprintf(stderr, "dns: %s: name too long\n", qname);
        close(sock);
        freeaddrinfo(res);
        return -1;
    }
    size_t qlen = 12 + nameLen;
    query[qlen++] = 0; query[qlen++] = (unsigned char)qtype;
    query[qlen++] = 0; query[qlen++] = 1; /* QCLASS=IN */

    if (sendto(sock, query, qlen, 0, res->ai_addr, res->ai_addrlen) < 0) {
        fprintf(stderr, "dns: %s: %s\n", server, strerror(errno));
        close(sock);
        freeaddrinfo(res);
        return -1;
    }
    freeaddrinfo(res);

    unsigned char replyBuf[2048];
    unsigned char *reply = replyBuf;
    unsigned char *tcpReply = NULL;
    ssize_t n = recv(sock, replyBuf, sizeof(replyBuf), 0);
    close(sock);
    if (n < 12) {
        fprintf(stderr, "dns: %s: no reply (timed out or unreachable)\n", server);
        return -1;
    }
    uint16_t rid = (uint16_t)((replyBuf[0] << 8) | replyBuf[1]);
    if (rid != qid) {
        fprintf(stderr, "dns: %s: reply ID mismatch\n", server);
        return -1;
    }

    /* TC (truncated) bit: the UDP reply didn't fit (common for TXT
     * records on well-populated domains, since we don't advertise an
     * EDNS0 buffer size, so servers default to the original 512-byte
     * UDP limit). Per RFC 1035 4.2.1, retry the identical query over
     * TCP to get the untruncated answer. */
    if (replyBuf[2] & 0x02) {
        if (getaddrinfo(server, "53", &hints, &res) != 0 || !res) {
            fprintf(stderr, "dns: %s: server address not found\n", server);
            return -1;
        }
        hints.ai_socktype = SOCK_STREAM;
        int tsock = socket(res->ai_family, SOCK_STREAM, 0);
        if (tsock < 0) {
            freeaddrinfo(res);
            fprintf(stderr, "dns: %s: %s\n", server, strerror(errno));
            return -1;
        }
        setsockopt(tsock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(tsock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        if (connect(tsock, res->ai_addr, res->ai_addrlen) < 0) {
            fprintf(stderr, "dns: %s: %s\n", server, strerror(errno));
            close(tsock);
            freeaddrinfo(res);
            return -1;
        }
        freeaddrinfo(res);

        unsigned char lenPrefix[2] = { (unsigned char)(qlen >> 8), (unsigned char)(qlen & 0xff) };
        if (smallclueSendAll(tsock, lenPrefix, sizeof(lenPrefix)) < 0 ||
            smallclueSendAll(tsock, query, qlen) < 0) {
            fprintf(stderr, "dns: %s: %s\n", server, strerror(errno));
            close(tsock);
            return -1;
        }
        unsigned char respLenBuf[2];
        if (smallclueRecvAll(tsock, respLenBuf, sizeof(respLenBuf)) <= 0) {
            fprintf(stderr, "dns: %s: no TCP reply (timed out)\n", server);
            close(tsock);
            return -1;
        }
        size_t tcpLen = (size_t)((respLenBuf[0] << 8) | respLenBuf[1]);
        tcpReply = (unsigned char *)malloc(tcpLen);
        if (!tcpReply) {
            close(tsock);
            return -1;
        }
        ssize_t got = smallclueRecvAll(tsock, tcpReply, tcpLen);
        close(tsock);
        if (got <= 0 || (size_t)got != tcpLen) {
            fprintf(stderr, "dns: %s: incomplete TCP reply\n", server);
            free(tcpReply);
            return -1;
        }
        reply = tcpReply;
        n = (ssize_t)tcpLen;
    }

    int rcode = reply[3] & 0x0F;
    uint16_t qdcount = (uint16_t)((reply[4] << 8) | reply[5]);
    uint16_t ancount = (uint16_t)((reply[6] << 8) | reply[7]);
    if (outRcode) *outRcode = rcode;
    if (rcode != 0) {
        /* Left to the caller to report (once, not once per record type
         * queried) -- querying A then AAAA separately would otherwise
         * print the same NXDOMAIN/SERVFAIL/etc. twice. */
        *outCount = 0;
        free(tcpReply);
        return 0;
    }

    size_t pos = 12;
    for (int i = 0; i < qdcount; ++i) {
        size_t after;
        if (!smallclueDnsDecodeName(reply, (size_t)n, pos, NULL, 0, &after)) {
            fprintf(stderr, "dns: %s: malformed reply\n", server);
            free(tcpReply);
            return -1;
        }
        pos = after + 4; /* QTYPE + QCLASS */
    }

    char **answers = NULL;
    int count = 0;
    for (int i = 0; i < ancount; ++i) {
        char nameBuf[256];
        size_t after;
        if (!smallclueDnsDecodeName(reply, (size_t)n, pos, nameBuf, sizeof(nameBuf), &after)) break;
        pos = after;
        if (pos + 10 > (size_t)n) break;
        int rtype = (reply[pos] << 8) | reply[pos + 1];
        uint16_t rdlength = (uint16_t)((reply[pos + 8] << 8) | reply[pos + 9]);
        size_t rdataPos = pos + 10;
        if (rdataPos + rdlength > (size_t)n) break;

        if (rtype == qtype && qtype == SMALLCLUE_DNS_TYPE_A && rdlength == 4) {
            char addrStr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, reply + rdataPos, addrStr, sizeof(addrStr));
            answers = (char **)realloc(answers, sizeof(char *) * (size_t)(count + 1));
            answers[count++] = strdup(addrStr);
        } else if (rtype == qtype && qtype == SMALLCLUE_DNS_TYPE_AAAA && rdlength == 16) {
            char addrStr[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, reply + rdataPos, addrStr, sizeof(addrStr));
            answers = (char **)realloc(answers, sizeof(char *) * (size_t)(count + 1));
            answers[count++] = strdup(addrStr);
        } else if (rtype == qtype && qtype == SMALLCLUE_DNS_TYPE_PTR) {
            char ptrName[256];
            size_t ptrAfter;
            if (smallclueDnsDecodeName(reply, (size_t)n, rdataPos, ptrName, sizeof(ptrName), &ptrAfter)) {
                answers = (char **)realloc(answers, sizeof(char *) * (size_t)(count + 1));
                answers[count++] = strdup(ptrName);
            }
        } else if (rtype == qtype && qtype == SMALLCLUE_DNS_TYPE_NS) {
            char nsName[256];
            size_t nsAfter;
            if (smallclueDnsDecodeName(reply, (size_t)n, rdataPos, nsName, sizeof(nsName), &nsAfter)) {
                answers = (char **)realloc(answers, sizeof(char *) * (size_t)(count + 1));
                answers[count++] = strdup(nsName);
            }
        } else if (rtype == qtype && qtype == SMALLCLUE_DNS_TYPE_MX && rdlength >= 2) {
            unsigned preference = (unsigned)((reply[rdataPos] << 8) | reply[rdataPos + 1]);
            char mxName[256];
            size_t mxAfter;
            if (smallclueDnsDecodeName(reply, (size_t)n, rdataPos + 2, mxName, sizeof(mxName), &mxAfter)) {
                char formatted[300];
                snprintf(formatted, sizeof(formatted), "%u %s", preference, mxName);
                answers = (char **)realloc(answers, sizeof(char *) * (size_t)(count + 1));
                answers[count++] = strdup(formatted);
            }
        } else if (rtype == qtype && qtype == SMALLCLUE_DNS_TYPE_TXT && rdlength > 0) {
            char text[512];
            size_t textLen = 0;
            size_t txtPos = rdataPos;
            size_t txtEnd = rdataPos + rdlength;
            while (txtPos < txtEnd) {
                unsigned char segLen = reply[txtPos++];
                if (txtPos + segLen > txtEnd) break;
                for (unsigned char i = 0; i < segLen && textLen + 1 < sizeof(text); ++i)
                    text[textLen++] = (char)reply[txtPos + i];
                txtPos += segLen;
            }
            text[textLen] = '\0';
            char formatted[520];
            snprintf(formatted, sizeof(formatted), "\"%s\"", text);
            answers = (char **)realloc(answers, sizeof(char *) * (size_t)(count + 1));
            answers[count++] = strdup(formatted);
        } else if (rtype == qtype && qtype == SMALLCLUE_DNS_TYPE_SRV && rdlength >= 6) {
            unsigned priority = (unsigned)((reply[rdataPos] << 8) | reply[rdataPos + 1]);
            unsigned weight = (unsigned)((reply[rdataPos + 2] << 8) | reply[rdataPos + 3]);
            unsigned port = (unsigned)((reply[rdataPos + 4] << 8) | reply[rdataPos + 5]);
            char srvName[256];
            size_t srvAfter;
            if (smallclueDnsDecodeName(reply, (size_t)n, rdataPos + 6, srvName, sizeof(srvName), &srvAfter)) {
                char formatted[300];
                snprintf(formatted, sizeof(formatted), "%u %u %u %s", priority, weight, port, srvName);
                answers = (char **)realloc(answers, sizeof(char *) * (size_t)(count + 1));
                answers[count++] = strdup(formatted);
            }
        }
        /* CNAME and any other record type in the answer section is
         * skipped -- rdlength already lets us jump past it uniformly. */
        pos = rdataPos + rdlength;
    }
    *outAnswers = answers;
    *outCount = count;
    free(tcpReply);
    return 0;
}

static void smallclueDnsFreeAnswers(char **answers, int count) {
    for (int i = 0; i < count; ++i) free(answers[i]);
    free(answers);
}

/* Reads the first "nameserver X" line from /etc/resolv.conf, for
 * MX/NS/TXT/SRV lookups with no explicit server argument (getaddrinfo
 * has no notion of these record types, so there's no system-resolver
 * fallback path the way there is for plain A/AAAA lookups -- a raw
 * query needs an actual server address to send it to). */
/* Maps a -t/-type= record-type name to its wire-format type value, for
 * the types getaddrinfo can't do (MX/NS/TXT/SRV). Returns 0 for A/AAAA
 * or anything unrecognized, since those go through the existing
 * address-family path instead. */
static int smallclueDnsTypeFromName(const char *name) {
    if (strcasecmp(name, "MX") == 0) return SMALLCLUE_DNS_TYPE_MX;
    if (strcasecmp(name, "TXT") == 0) return SMALLCLUE_DNS_TYPE_TXT;
    if (strcasecmp(name, "NS") == 0) return SMALLCLUE_DNS_TYPE_NS;
    if (strcasecmp(name, "SRV") == 0) return SMALLCLUE_DNS_TYPE_SRV;
    return 0;
}

static bool smallclueDnsDefaultServer(char *buf, size_t bufSize) {
    FILE *fp = fopen("/etc/resolv.conf", "r");
    if (!fp) return false;
    char line[256];
    bool found = false;
    while (fgets(line, sizeof(line), fp)) {
        char ip[128];
        if (sscanf(line, " nameserver %127s", ip) == 1) {
            snprintf(buf, bufSize, "%s", ip);
            found = true;
            break;
        }
    }
    fclose(fp);
    return found;
}

/* Handles nslookup/host's -t/-type= record-type selector for the
 * types getaddrinfo has no concept of: MX/NS/TXT/SRV. Always issues a
 * single raw query of exactly that type (no A/AAAA dual-query dance,
 * no reverse-lookup auto-detection -- those only make sense for
 * address types). Uses SERVER if given, else the first nameserver in
 * /etc/resolv.conf. Returns true if it handled the whole command
 * (this type was requested), setting *exitStatus. */
static bool smallclueTryTypedDnsLookup(const char *label, const char *hostArg,
                                        const char *server, int qtype,
                                        bool nslookupStyle, int *exitStatus) {
    char resolvBuf[128];
    const char *useServer = server;
    if (!useServer) {
        if (!smallclueDnsDefaultServer(resolvBuf, sizeof(resolvBuf))) {
            fprintf(stderr, "%s: no DNS server available (checked /etc/resolv.conf)\n", label);
            *exitStatus = 1;
            return true;
        }
        useServer = resolvBuf;
    }

    if (nslookupStyle) {
        printf("Server:\t\t%s\n", useServer);
        printf("Address:\t%s#53\n\n", useServer);
    }

    char **answers = NULL;
    int count = 0;
    int rcode = 0;
    if (smallclueDnsQueryServer(useServer, hostArg, qtype, &answers, &count, &rcode) != 0) {
        *exitStatus = 1;
        return true;
    }
    if (count == 0) {
        if (rcode != 0) {
            fprintf(stderr, "%s: %s: %s\n", label, hostArg, smallclueDnsRcodeName(rcode));
        } else {
            fprintf(stderr, "%s: %s: no records found via %s\n", label, hostArg, useServer);
        }
        *exitStatus = 1;
        smallclueDnsFreeAnswers(answers, count);
        return true;
    }
    for (int i = 0; i < count; ++i) {
        if (nslookupStyle) {
            printf("%s\t%s\n", hostArg, answers[i]);
        } else {
            printf("%s %s\n", hostArg, answers[i]);
        }
    }
    smallclueDnsFreeAnswers(answers, count);
    *exitStatus = 0;
    return true;
}

/* Handles nslookup/host's optional trailing SERVER argument by actually
 * querying that server (A, then AAAA, unless -4/-6 restricts it) rather
 * than rejecting/ignoring it. Returns true if it handled the whole
 * command (a server was given), setting *exitStatus; false if no server
 * was given and the caller should fall through to the normal
 * getaddrinfo-based path. */
static bool smallclueTryServerDnsLookup(const char *label, const char *host, const char *server,
                                        int forcedFamily, bool nslookupStyle, int *exitStatus) {
    if (!server) return false;

    struct in_addr addr4;
    struct in6_addr addr6;
    bool isReverse = inet_pton(AF_INET, host, &addr4) == 1 || inet_pton(AF_INET6, host, &addr6) == 1;

    if (nslookupStyle) {
        printf("Server:\t\t%s\n", server);
        printf("Address:\t%s#53\n\n", server);
    }

    if (isReverse) {
        int family = inet_pton(AF_INET, host, &addr4) == 1 ? AF_INET : AF_INET6;
        const void *addrBytes = (family == AF_INET) ? (void *)&addr4 : (void *)&addr6;
        char revname[256];
        smallclueBuildReverseDnsName(family, addrBytes, revname, sizeof(revname));
        char **answers = NULL;
        int count = 0;
        int rcode = 0;
        if (smallclueDnsQueryServer(server, revname, SMALLCLUE_DNS_TYPE_PTR, &answers, &count, &rcode) != 0) {
            *exitStatus = 1;
            return true;
        }
        if (count == 0) {
            if (rcode != 0) {
                fprintf(stderr, "%s: %s: %s\n", label, host, smallclueDnsRcodeName(rcode));
            } else {
                fprintf(stderr, "%s: %s: no PTR record found via %s\n", label, host, server);
            }
            *exitStatus = 1;
            smallclueDnsFreeAnswers(answers, count);
            return true;
        }
        for (int i = 0; i < count; ++i) {
            if (nslookupStyle) printf("%s\tname = %s.\n", revname, answers[i]);
            else printf("%s domain name pointer %s.\n", revname, answers[i]);
        }
        smallclueDnsFreeAnswers(answers, count);
        *exitStatus = 0;
        return true;
    }

    bool printed = false;
    int status = 0;
    int lastRcode = 0;
    bool haveRcode = false;
    if (forcedFamily != AF_INET6) {
        char **answers = NULL; int count = 0; int rcode = 0;
        if (smallclueDnsQueryServer(server, host, SMALLCLUE_DNS_TYPE_A, &answers, &count, &rcode) == 0) {
            for (int i = 0; i < count; ++i) {
                if (nslookupStyle) {
                    if (!printed) printf("Non-authoritative answer:\n");
                    printf("Name:\t%s\nAddress: %s\n", host, answers[i]);
                } else {
                    printf("%s has address %s\n", host, answers[i]);
                }
                printed = true;
            }
            if (count == 0 && rcode != 0) { lastRcode = rcode; haveRcode = true; }
        } else {
            status = 1;
        }
        smallclueDnsFreeAnswers(answers, count);
    }
    if (forcedFamily != AF_INET) {
        char **answers = NULL; int count = 0; int rcode = 0;
        if (smallclueDnsQueryServer(server, host, SMALLCLUE_DNS_TYPE_AAAA, &answers, &count, &rcode) == 0) {
            for (int i = 0; i < count; ++i) {
                if (nslookupStyle) {
                    if (!printed) printf("Non-authoritative answer:\n");
                    printf("Name:\t%s\nAddress: %s\n", host, answers[i]);
                } else {
                    printf("%s has IPv6 address %s\n", host, answers[i]);
                }
                printed = true;
            }
            if (count == 0 && rcode != 0) { lastRcode = rcode; haveRcode = true; }
        } else {
            status = 1;
        }
        smallclueDnsFreeAnswers(answers, count);
    }
    if (!printed && status == 0) {
        if (haveRcode) {
            fprintf(stderr, "%s: %s: %s\n", label, host, smallclueDnsRcodeName(lastRcode));
        } else {
            fprintf(stderr, "%s: %s: no records found via %s\n", label, host, server);
        }
        status = 1;
    }
    *exitStatus = status;
    return true;
}

static int smallclueNslookupCommand(int argc, char **argv) {
    const char *usage = "usage: nslookup [-v] [-type=TYPE] host [server]\n";
    bool verbose = false;
    int typedQtype = 0;

    /* nslookup's -type=/-q=/-query=TYPE options use BIND-style "=value"
     * single-token syntax rather than a getopt-friendly separate
     * argument, so pull them out of argv (compacting in place) before
     * the normal getopt loop ever sees them. */
    int writeIdx = 1;
    for (int readIdx = 1; readIdx < argc; ++readIdx) {
        const char *arg = argv[readIdx];
        const char *val = NULL;
        if (strncmp(arg, "-type=", 6) == 0) val = arg + 6;
        else if (strncmp(arg, "-query=", 7) == 0) val = arg + 7;
        else if (strncmp(arg, "-q=", 3) == 0) val = arg + 3;
        if (val) {
            int qt = smallclueDnsTypeFromName(val);
            if (qt != 0) typedQtype = qt;
            continue;
        }
        argv[writeIdx++] = argv[readIdx];
    }
    argc = writeIdx;

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
    const char *server = (optind + 1 < argc) ? argv[optind + 1] : NULL;

    if (typedQtype != 0) {
        int typedStatus = 0;
        smallclueTryTypedDnsLookup("nslookup", host, server, typedQtype, true, &typedStatus);
        return typedStatus;
    }

    int serverStatus = 0;
    if (smallclueTryServerDnsLookup("nslookup", host, server, AF_UNSPEC, true, &serverStatus)) {
        return serverStatus;
    }

    int reverseStatus = 0;
    if (smallclueTryReverseDnsLookup("nslookup", host, true, &reverseStatus)) {
        return reverseStatus;
    }

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_family = AF_UNSPEC;
    struct addrinfo *res = NULL;
    int gai = pscalHostsGetAddrInfo(host, "53", &hints, &res);
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
    int typedQtype = 0;
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
                else typedQtype = smallclueDnsTypeFromName(optarg);
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
    const char *server = (optind + 1 < argc) ? argv[optind + 1] : NULL;

    if (typedQtype != 0) {
        int typedStatus = 0;
        smallclueTryTypedDnsLookup("host", host, server, typedQtype, false, &typedStatus);
        return typedStatus;
    }

    int serverStatus = 0;
    if (smallclueTryServerDnsLookup("host", host, server, family, false, &serverStatus)) {
        return serverStatus;
    }

    int reverseStatus = 0;
    if (smallclueTryReverseDnsLookup("host", host, false, &reverseStatus)) {
        return reverseStatus;
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

static int smallclueHostnameCommand(int argc, char **argv) {
    if (argc > 1) {
        fprintf(stderr, "hostname: setting hostname not supported\n");
        return 1;
    }

    char path[PATH_MAX];
    if (smallclueResolveEtcEntry("hostname", R_OK, path, sizeof(path))) {
        FILE *fp = fopen(path, "r");
        if (fp) {
            char buf[256];
            if (fgets(buf, sizeof(buf), fp)) {
                size_t len = strlen(buf);
                if (len > 0 && buf[len - 1] == '\n') {
                    buf[len - 1] = '\0';
                }
                puts(buf);
                fclose(fp);
                return 0;
            }
            fclose(fp);
        }
    }

    puts("unknown");
    fprintf(stderr, "hostname: host name not found; create /etc/hostname to set it\n");
    return 0;
}

typedef struct SmallclueAppletHelp {
    const char *name;
    const char *usage;
} SmallclueAppletHelp;

static int smallclueSuCommand(int argc, char **argv) {
    const char *usage = "usage: su [-] [username] [-c command]\n";
    const char *user = "root";
    const char *command = NULL;
    bool login = false;

    /* Sentinel: Sanitize environment to prevent privilege escalation via LD_PRELOAD/PATH injection */
    unsetenv("LD_PRELOAD");
    unsetenv("LD_LIBRARY_PATH");
    unsetenv("LD_DEBUG");
    unsetenv("IFS");
    setenv("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin", 1);

    int arg_idx = 1;
    if (arg_idx < argc && strcmp(argv[arg_idx], "-") == 0) {
        login = true;
        arg_idx++;
    }

    if (arg_idx < argc && argv[arg_idx][0] != '-') {
        user = argv[arg_idx++];
    }

    if (arg_idx < argc) {
        if (strcmp(argv[arg_idx], "-c") == 0) {
            if (arg_idx + 1 >= argc) {
                fputs(usage, stderr);
                return 1;
            }
            command = argv[arg_idx + 1];
            arg_idx += 2;
        } else if (strcmp(argv[arg_idx], "-") == 0) {
             if (!login) {
                 login = true;
                 arg_idx++;
             }
        }
    }

    struct passwd *pw = getpwnam(user);
    if (!pw) {
        fprintf(stderr, "su: user %s does not exist\n", user);
        return 1;
    }

    uid_t current_uid = getuid();
    if (current_uid != 0 && current_uid != pw->pw_uid) {
        fprintf(stderr, "su: permission denied (must be root)\n");
        return 1;
    }

    if (initgroups(user, pw->pw_gid) != 0) {
        perror("su: initgroups");
        return 1;
    }
    if (setgid(pw->pw_gid) != 0) {
        perror("su: setgid");
        return 1;
    }
    if (setuid(pw->pw_uid) != 0) {
        perror("su: setuid");
        return 1;
    }

    if (login) {
        setenv("HOME", pw->pw_dir, 1);
        setenv("SHELL", pw->pw_shell, 1);
        setenv("USER", pw->pw_name, 1);
        setenv("LOGNAME", pw->pw_name, 1);
        if (chdir(pw->pw_dir) != 0) {
            fprintf(stderr, "su: warning: cannot change directory to %s: %s\n", pw->pw_dir, strerror(errno));
        }
    }

    const char *shell = pw->pw_shell;
    if (!shell || !*shell) {
        shell = "/bin/sh";
    }
    char resolved_shell[PATH_MAX];
    if (smallclueResolveCommandPathForExec(shell, resolved_shell, sizeof(resolved_shell))) {
        shell = resolved_shell;
    }

    if (command) {
        execl(shell, shell, "-c", command, (char *)NULL);
        perror("su: exec");
        return 127;
    } else {
        const char *arg0 = shell;
        if (login) {
             const char *base = strrchr(shell, '/');
             if (base) base++; else base = shell;
             char *dashed = (char *)malloc(strlen(base) + 2);
             if (dashed) {
                 dashed[0] = '-';
                 strcpy(dashed + 1, base);
                 arg0 = dashed;
             }
        }
        execl(shell, arg0, (char *)NULL);
        perror("su: exec");
        return 127;
    }
}

static void smallclueSecureMemzero(void *ptr, size_t len) {
    if (!ptr) return;
    volatile unsigned char *p = (volatile unsigned char *)ptr;
    while (len--) {
        *p++ = 0;
    }
}

#if defined(__linux__) || defined(linux) || defined(__linux)
static char *smallclueGetPass(const char *prompt);
#endif

static int smallclueSudoCommand(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: sudo command [args...]\n");
        return 1;
    }

    /* Sentinel: Sanitize environment to prevent privilege escalation via LD_PRELOAD/PATH injection */
    unsetenv("LD_PRELOAD");
    unsetenv("LD_LIBRARY_PATH");
    unsetenv("LD_DEBUG");
    unsetenv("IFS");
    setenv("PATH", "/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin", 1);

    if (getuid() != 0) {
        if (geteuid() == 0) {
#if defined(__linux__) || defined(linux) || defined(__linux)
            struct spwd *sp = getspnam("root");
            if (!sp || !sp->sp_pwdp || strcmp(sp->sp_pwdp, "*") == 0 || strcmp(sp->sp_pwdp, "!") == 0) {
                fprintf(stderr, "sudo: root account locked or cannot read shadow\n");
                return 1;
            }
            char *pass = smallclueGetPass("[sudo] password for root: ");
            if (!pass) return 1;
            char *encrypted = crypt(pass, sp->sp_pwdp);
            smallclueSecureMemzero(pass, strlen(pass));
            free(pass);
            if (!encrypted || strcmp(encrypted, sp->sp_pwdp) != 0) {
                fprintf(stderr, "sudo: authentication failure\n");
                return 1;
            }
#else
            fprintf(stderr, "sudo: authentication not supported on this platform\n");
            return 1;
#endif
        }

        if (setuid(0) != 0 || setgid(0) != 0) {
             fprintf(stderr, "sudo: permission denied (must be setuid root)\n");
             return 1;
        }
    }

    char resolved_exec[PATH_MAX];
    const char *exec_path = argv[1];
    if (smallclueResolveCommandPathForExec(argv[1], resolved_exec, sizeof(resolved_exec))) {
        exec_path = resolved_exec;
    }
    execv(exec_path, &argv[1]);
    execvp(argv[1], &argv[1]);
    fprintf(stderr, "sudo: %s: %s\n", argv[1], strerror(errno));
    return (errno == ENOENT) ? 127 : 126;
}

#if defined(__linux__) || defined(linux) || defined(__linux)
static char *smallclueGetPass(const char *prompt) {
    static char buf[128];
    struct termios old, new;
    int fd = fileno(stdin);

    smallclueSecureMemzero(buf, sizeof(buf));

    if (tcgetattr(fd, &old) != 0) {
        return NULL;
    }
    new = old;
    new.c_lflag &= ~ECHO;
    if (tcsetattr(fd, TCSAFLUSH, &new) != 0) {
        return NULL;
    }

    fprintf(stderr, "%s", prompt);
    if (fgets(buf, sizeof(buf), stdin) == NULL) {
        tcsetattr(fd, TCSAFLUSH, &old);
        smallclueSecureMemzero(buf, sizeof(buf));
        return NULL;
    }
    tcsetattr(fd, TCSAFLUSH, &old);
    fprintf(stderr, "\n");

    size_t len = strlen(buf);
    if (len > 0 && buf[len - 1] == '\n') {
        buf[len - 1] = '\0';
    } else if (len == sizeof(buf) - 1) {
        /* Sentinel: If the password exceeded the buffer size, flush the remaining
         * input up to the newline to prevent residual password fragments from
         * leaking into subsequent stdin reads. */
        int c;
        while ((c = fgetc(stdin)) != '\n' && c != EOF) {
            /* discard */
        }
    }
    char *result = strdup(buf);
    smallclueSecureMemzero(buf, sizeof(buf));
    return result;
}
#endif

static int smallcluePasswdCommand(int argc, char **argv) {
#if defined(__linux__) || defined(linux) || defined(__linux)
    const char *username = NULL;
    if (argc > 1) {
        username = argv[1];
    } else {
        struct passwd *pw = getpwuid(getuid());
        if (pw) {
            username = pw->pw_name;
        }
    }

    if (!username) {
        fprintf(stderr, "passwd: cannot determine username\n");
        return 1;
    }

    uid_t uid = getuid();
    if (uid != 0 && argc > 1) {
        struct passwd *pw = getpwnam(username);
        if (!pw || pw->pw_uid != uid) {
            fprintf(stderr, "passwd: permission denied\n");
            return 1;
        }
    }

    // Lock shadow file
    if (lckpwdf() != 0) {
        fprintf(stderr, "passwd: password file busy\n");
        return 1;
    }

    struct spwd *sp = getspnam(username);
    if (!sp) {
        fprintf(stderr, "passwd: user '%s' not found in shadow file\n", username);
        ulckpwdf();
        return 1;
    }

    // If not root, ask for old password
    if (uid != 0 && sp->sp_pwdp && strcmp(sp->sp_pwdp, "*") != 0 && strcmp(sp->sp_pwdp, "!") != 0 && sp->sp_pwdp[0] != '\0') {
        char *pass = smallclueGetPass("Old password: ");
        if (!pass) {
            ulckpwdf();
            return 1;
        }
        char *encrypted = crypt(pass, sp->sp_pwdp);
        smallclueSecureMemzero(pass, strlen(pass));
        free(pass);
        if (!encrypted || strcmp(encrypted, sp->sp_pwdp) != 0) {
            fprintf(stderr, "passwd: authentication failure\n");
            ulckpwdf();
            return 1;
        }
    }

    char *new_pass = smallclueGetPass("New password: ");
    if (!new_pass || !*new_pass) {
        if (new_pass) free(new_pass);
        fprintf(stderr, "passwd: password unchanged\n");
        ulckpwdf();
        return 1;
    }
    char *new_pass_copy = strdup(new_pass);
    smallclueSecureMemzero(new_pass, strlen(new_pass));
    free(new_pass);
    if (!new_pass_copy) {
        fprintf(stderr, "passwd: out of memory\n");
        ulckpwdf();
        return 1;
    }

    char *confirm_pass = smallclueGetPass("Retype new password: ");
    if (!confirm_pass || strcmp(new_pass_copy, confirm_pass) != 0) {
        fprintf(stderr, "passwd: passwords do not match\n");
        if (confirm_pass) {
            smallclueSecureMemzero(confirm_pass, strlen(confirm_pass));
            free(confirm_pass);
        }
        smallclueSecureMemzero(new_pass_copy, strlen(new_pass_copy));
        free(new_pass_copy);
        ulckpwdf();
        return 1;
    }
    if (confirm_pass) {
        smallclueSecureMemzero(confirm_pass, strlen(confirm_pass));
        free(confirm_pass);
    }

    // Generate salt
    char salt[64];
    const char *salt_chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./";
    unsigned char random_bytes[16];
    FILE *f = fopen("/dev/urandom", "rb");
    if (f) {
        size_t n = fread(random_bytes, 1, sizeof(random_bytes), f);
        fclose(f);
        if (n != sizeof(random_bytes)) {
            fprintf(stderr, "passwd: failed to read random source\n");
            ulckpwdf();
            return 1;
        }
    } else {
        fprintf(stderr, "passwd: cannot open /dev/urandom\n");
        ulckpwdf();
        return 1;
    }

    // SHA-512 salt format: $6$salt$
    strcpy(salt, "$6$");
    int salt_idx = 3;
    for (int i = 0; i < 16 && salt_idx < 19; ++i) {
        salt[salt_idx++] = salt_chars[random_bytes[i] % 64];
    }
    salt[salt_idx] = '\0';

    char *hashed = crypt(new_pass_copy, salt);
    smallclueSecureMemzero(new_pass_copy, strlen(new_pass_copy));
    free(new_pass_copy);

    if (!hashed) {
        fprintf(stderr, "passwd: encryption failed\n");
        ulckpwdf();
        return 1;
    }

    // Update shadow file
    FILE *fp = fopen("/etc/shadow", "r");
    if (!fp) {
        perror("passwd: /etc/shadow");
        ulckpwdf();
        return 1;
    }

    /* Sentinel: Fix TOCTOU race condition by using O_EXCL and 0600 at creation. */
    unlink("/etc/shadow.tmp");
    int fd = open("/etc/shadow.tmp", O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0) {
        perror("passwd: /etc/shadow.tmp");
        fclose(fp);
        ulckpwdf();
        return 1;
    }

    FILE *out_fp = fdopen(fd, "w");
    if (!out_fp) {
        perror("passwd: fdopen");
        close(fd);
        fclose(fp);
        unlink("/etc/shadow.tmp");
        ulckpwdf();
        return 1;
    }

    struct spwd *entry;
    int found = 0;
    while ((entry = fgetspent(fp)) != NULL) {
        if (strcmp(entry->sp_namp, username) == 0) {
            entry->sp_pwdp = hashed;
            entry->sp_lstchg = time(NULL) / (24 * 3600);
            found = 1;
        }
        if (putspent(entry, out_fp) != 0) {
            fprintf(stderr, "passwd: error writing to temporary file\n");
            fclose(fp);
            fclose(out_fp);
            unlink("/etc/shadow.tmp");
            ulckpwdf();
            return 1;
        }
    }

    fclose(fp);
    fclose(out_fp);

    if (!found) {
        fprintf(stderr, "passwd: user '%s' not found during update\n", username);
        unlink("/etc/shadow.tmp");
        ulckpwdf();
        return 1;
    }

    if (rename("/etc/shadow.tmp", "/etc/shadow") != 0) {
        perror("passwd: rename");
        unlink("/etc/shadow.tmp");
        ulckpwdf();
        return 1;
    }

    ulckpwdf();
    printf("passwd: password updated successfully\n");
    return 0;
#else
    (void)argc;
    (void)argv;
    fprintf(stderr, "passwd: not supported on this platform\n");
    return 1;
#endif
}

static int smallclueHistoryCommand(int argc, char **argv) {
    (void)argc;
    (void)argv;
    const char *home = getenv("HOME");
    if (!home) {
        fprintf(stderr, "history: HOME not set\n");
        return 1;
    }
    char path[PATH_MAX];
    int w = snprintf(path, sizeof(path), "%s/.sh_history", home);
    if (w < 0 || (size_t)w >= sizeof(path)) {
        fprintf(stderr, "history: path too long\n");
        return 1;
    }
    FILE *fp = fopen(path, "r");
    if (!fp) {
        return 0;
    }
    char *line = NULL;
    size_t cap = 0;
    int index = 1;
    while (true) {
        int read_err = 0;
        ssize_t len = smallclueGetlineStream(&line, &cap, fp, &read_err);
        if (len < 0) {
            break;
        }
        printf("%5d  %s", index++, line);
        if (len > 0 && line[len-1] != '\n') {
            putchar('\n');
        }
    }
    free(line);
    fclose(fp);
    return 0;
}

static const SmallclueApplet kSmallclueApplets[] = {
    {"[", smallclueBracketCommand, "Evaluate expressions"},
    {"basename", smallclueBasenameCommand, "Strip directory prefix"},
    {"cal", smallclueCalCommand, "Show a simple calendar"},
    {"cat", smallclueCatCommand, "Concatenate files"},
    {"chmod", smallclueChmodCommand, "Change file permissions"},
    {"chown", smallclueChownCommand, "Change file owner and group"},
    {"chgrp", smallclueChgrpCommand, "Change file group ownership"},
    {"clear", smallclueClearCommand, "Clear the terminal"},
    {"cls", smallclueClearCommand, "Clear the terminal"},
    {"cp", smallclueCpCommand, "Copy files and directories"},
    {"rsync", smallclueRsyncCommand, "Synchronize files and directories"},
    {"curl", smallclueCurlCommand, "Transfer data from URLs"},
    {"cut", smallclueCutCommand, "Extract fields from lines"},
    {"date", smallclueDateCommand, "Display current date/time"},
    {"dd", smallclueDdCommand, "Convert and copy a file block by block"},
    {"diff", smallclueDiffCommand, "Compare files line by line"},
    {"cmp", smallclueCmpCommand, "Compare two files byte by byte"},
    {"dirname", smallclueDirnameCommand, "Strip last path component"},
    {"du", smallclueDuCommand, "Summarize disk usage"},
#if defined(SMALLCLUE_WITH_DVTM)
    {"dvtm", smallclueDvtmCommand, "Dynamic virtual terminal manager"},
#endif
    {"echo", smallclueEchoCommand, "Print arguments"},
    {"micro", smallclueMicroCommand, "Micro text editor"},
    {"nextvi", smallclueEditorCommand, "Nextvi text editor"},
    {"env", smallclueEnvCommand, "Display or update environment"},
    {"expr", smallclueExprCommand, "Evaluate expressions"},
    {"false", smallclueFalseCommand, "Do nothing, unsuccessfully"},
    {"file", smallclueFileCommand, "Identify file types"},
    {"find", smallclueFindCommand, "Search for files"},
    {"grep", smallclueGrepCommand, "Search for patterns"},
    {"git", smallclueGitCommand, "Git plumbing and porcelain"},
    {"gzip", smallclueGzipCommand, "Compress files"},
    {"gunzip", smallclueGunzipCommand, "Decompress files"},
    {"zcat", smallclueZcatCommand, "Decompress files to standard output"},
    {"head", smallclueHeadCommand, "Print the first lines of files"},
    {"history", smallclueHistoryCommand, "Show command history"},
    {"id", smallclueIdCommand, "Print user identity information"},
#if SMALLCLUE_HAS_IFADDRS
    {"ipaddr", smallclueIpAddrCommand, "Show interface IP addresses"},
#endif
    {"halt", smallclueHaltCommand, "Halt the system"},
    {"host", smallclueHostCommand, "DNS lookup utility"},
    {"hostname", smallclueHostnameCommand, "Show system hostname"},
    {"init", smallclueInitCommand, "System initialization"},
    {"kill", smallclueKillCommand, "Send signals to processes"},
    {"less", smallcluePagerCommand, "Paginate file contents"},
    {"ln", smallclueLnCommand, "Create links"},
    {"ls", smallclueLsCommand, "List directory contents"},
    {"md", smallclueMarkdownCommand, "Read Markdown documents"},
    {"mdev", smallclueMdevCommand, "Device manager"},
    {"mkdir", smallclueMkdirCommand, "Create directories"},
    {"mknod", smallclueMknodCommand, "Create special files"},
    {"mount", smallclueMountCommand, "Mount filesystems"},
    {"umount", smallclueUmountCommand, "Unmount filesystems"},
    {"more", smallcluePagerCommand, "Paginate file contents"},
    {"mv", smallclueMvCommand, "Move or rename files"},
    {"install", smallclueInstallCommand, "Copy files and set attributes (or create directories)"},
    {"base64", smallclueBase64Command, "Base64 encode or decode"},
    {"md5sum", smallclueMd5sumCommand, "Compute or check MD5 digests"},
    {"sha1sum", smallclueSha1sumCommand, "Compute or check SHA-1 digests"},
    {"sha256sum", smallclueSha256sumCommand, "Compute or check SHA-256 digests"},
    {"od", smallclueOdCommand, "Dump files in octal/hex/decimal/character format"},
    {"seq", smallclueSeqCommand, "Print a sequence of numbers"},
    {"nl", smallclueNlCommand, "Number lines of files"},
    {"tac", smallclueTacCommand, "Concatenate and print files in reverse"},
    {"rev", smallclueRevCommand, "Reverse the characters of each line"},
    {"fold", smallclueFoldCommand, "Wrap each line to a given width"},
    {"paste", smallcluePasteCommand, "Merge lines of files"},
    {"split", smallclueSplitCommand, "Split a file into pieces"},
    {"fmt", smallclueFmtCommand, "Reflow text into filled paragraphs"},
    {"comm", smallclueCommCommand, "Compare two sorted files line by line"},
    {"awk", smallclueAwkCommand, "Pattern scanning and processing language"},
    {"nslookup", smallclueNslookupCommand, "DNS lookup utility"},
    {"no", smallclueNoCommand, "Repeatedly print strings (exit 1)"},
    {"nohup", smallclueNohupCommand, "Run a command immune to hangups"},
    {"passwd", smallcluePasswdCommand, "Change user password"},
    {"patch", smallcluePatchCommand, "Apply a unified diff to files"},
    {"printf", smallcluePrintfCommand, "Format and print data"},
    {"pbcopy", smallcluePbcopyCommand, "Copy stdin to the system clipboard"},
    {"pbpaste", smallcluePbpasteCommand, "Paste the system clipboard to stdout"},
    {"ping", smallcluePingCommand, "ICMP echo utility"},
    {"poweroff", smallclueHaltCommand, "Power off the system"},
    {"ps", smallcluePsCommand, "Show simple process information"},
    {"pwd", smallcluePwdCommand, "Print working directory"},
    {"reboot", smallclueHaltCommand, "Reboot the system"},
    {"resize", smallclueResizeCommand, "Synchronize terminal rows/columns"},
    {"readlink", smallclueReadlinkCommand, "Print resolved symbolic links or canonical paths"},
    {"realpath", smallclueRealpathCommand, "Print the canonicalized absolute path"},
    {"rm", smallclueRmCommand, "Remove files"},
    {"rmdir", smallclueRmdirCommand, "Remove empty directories"},
    {"runit", smallclueRunitCommand, "System service supervisor"},
    {"sed", smallclueSedCommand, "Stream editor for simple substitutions"},
    {"sleep", smallclueSleepCommand, "Delay for a number of seconds"},
    {"sort", smallclueSortCommand, "Sort lines of text"},
    {"stat", smallclueStatCommand, "Display file status"},
    {"stty", smallclueSttyCommand, "Report terminal settings"},
#if defined(SMALLCLUE_WITH_EXSH)
    {"exsh", smallclueShCommand, "Run the PSCAL shell front end"},
    {"sh", smallclueShCommand, "Run the PSCAL shell front end"},
#elif defined(SMALLCLUE_WITH_SH)
    {"ash", smallclueNativeShCommand, "POSIX shell (BusyBox-ash compatible)"},
    {"sh", smallclueNativeShCommand, "POSIX shell (BusyBox-ash compatible)"},
#endif
    {"scp", smallclueScpCommand, "Securely copy files over SSH"},
    {"sftp", smallclueSftpCommand, "Interactive SFTP client"},
    {"script", smallclueScriptCommand, "Record terminal output to a file"},
    {"ssh", smallclueSshCommand, "OpenSSH client"},
    {"ssh-keygen", smallclueSshKeygenCommand, "Generate SSH key pairs"},
    {"ssh-copy-id", smallclueSshCopyIdCommand, "Install SSH public keys on a remote host"},
    {"su", smallclueSuCommand, "Change user ID or become superuser"},
    {"sudo", smallclueSudoCommand, "Execute a command as another user"},
    {"tail", smallclueTailCommand, "Print the last lines of files"},
    {"tar", smallclueTarCommand, "Create, extract, or list tar archives"},
    {"tee", smallclueTeeCommand, "Copy stdin to files and stdout"},
    {"telnet", smallclueTelnetCommand, "Simple TCP telnet client"},
    {"test", smallclueTestCommand, "Evaluate expressions"},
    {"time", smallclueTimeCommand, "Measure command runtime"},
    {"tset", smallclueTsetCommand, "Initialize terminal settings"},
    {"touch", smallclueTouchCommand, "Update file timestamps"},
    {"timeout", smallclueTimeoutCommand, "Run a command with a time limit"},
    {"tty", smallclueTtyCommand, "Print terminal name"},
    {"traceroute", smallclueTracerouteCommand, "Trace network path to a host"},
    {"tr", smallclueTrCommand, "Translate or delete characters"},
    {"true", smallclueTrueCommand, "Do nothing, successfully"},
    {"sum", smallclueSumCommand, "Checksum (BSD/SysV)"},
    {"type", smallclueTypeCommand, "Describe command names"},
    {"uname", smallclueUnameCommand, "Show system information"},
    {"uniq", smallclueUniqCommand, "Report or omit repeated lines"},
    {"uptime", smallclueUptimeCommand, "Show app uptime (use -s for system uptime)"},
    {"version", smallclueVersionCommand, "Show app version"},
    {"vproc-test", smallclueVprocTestCommand, "Run vproc/terminal diagnostics"},
    {"watch", smallclueWatchCommand, "Periodically run a command"},
    {"vi", smallclueEditorCommand, "Alias for Nextvi text editor"},
    {"wc", smallclueWcCommand, "Count lines/words/bytes"},
    {"wget", smallclueWgetCommand, "Download files via HTTP(S)"},
    {"which", smallclueWhichCommand, "Locate a command"},
    {"whoami", smallclueWhoamiCommand, "Print effective user name"},
    {"yes", smallclueYesCommand, "Repeatedly print strings"},
    {"xargs", smallclueXargsCommand, "Build command lines from stdin"},
    {"df", smallclueDfCommand, "Report filesystem usage"},
    {"dmesg", smallclueDmesgCommand, "Print the kernel ring buffer"},

#if defined(PSCAL_TARGET_IOS)
    {"addt", smallclueAddTabCommand, "Open an additional shell tab"},
    {"tabadd", smallclueAddTabCommand, "Alias for addt: open an additional shell tab"},
    {"tadd", smallclueAddTabCommand, "Alias for addt: open an additional shell tab"},
    {"smallclue-help", smallclueHelpCommand, "List available smallclue applets"},
    {"licenses", smallclueLicensesCommand, "View third-party licenses"},
    {"top", smallclueTopCommand, "Show PSCAL virtual processes"},
#else
    {"top", smallclueTopCommand, "Show running processes (sorted by %CPU)"},
#endif
};

static const SmallclueAppletHelp kSmallclueAppletHelp[] = {
    {"[", "[ expression ]\n"
          "  Alias for test; see 'test' for operators"},
    {"basename", "basename PATH [SUFFIX] | basename -a|-s SUFFIX PATH...\n"
                 "  Strip directory prefix and optional suffix\n"
                 "  -a/--multiple: treat every operand as a PATH (no positional SUFFIX)\n"
                 "  -s/--suffix=SUFFIX: strip SUFFIX from every PATH (implies -a)\n"
                 "  -z/--zero: NUL-terminate output instead of newline"},
    {"cal", "cal [month] [year]\n"
            "  Show a simple calendar"},
    {"cat", "cat [-n|-b] [-E] [-T] [-A] [-s] [FILE ...]\n"
            "  Concatenate files to stdout\n"
            "  -n number all lines  -b number non-blank lines only\n"
            "  -E show $ at line end  -T show tabs as ^I  -A = -E -T\n"
            "  -s squeeze runs of blank lines to one\n"
            "  (previously any flag was silently treated as a filename)"},
    {"chmod", "chmod [-R] MODE FILE ...\n"
              "  MODE forms: u+rwx,g-w,o=r, a-wx, 755, 0644\n"
              "  -R recursive"},
    {"chown", "chown [-R] [-h] OWNER[:[GROUP]] FILE ...\n"
              "  Change owner (and optionally group) of each FILE\n"
              "  OWNER[:GROUP]: both numeric IDs and names accepted\n"
              "  \"user:\" changes owner only; \":group\" changes group only\n"
              "  -R recursive  -h affect symlinks themselves, not their targets"},
    {"chgrp", "chgrp [-R] [-h] GROUP FILE ...\n"
              "  Change group ownership of each FILE (numeric ID or name)\n"
              "  -R recursive  -h affect symlinks themselves, not their targets"},
    {"clear", "clear\n"
              "  Clear the terminal"},
    {"cls", "cls\n"
            "  Clear the terminal (alias)"},
    {"cp", "cp [-r|-R] [-a] [-p] SRC... DEST\n"
           "  -r/-R  recursive copy (directories)\n"
           "  -a     archive: recursive + preserve timestamps\n"
           "  -p     preserve timestamps"},
    {"curl", "curl [options] URL...\n"
             "  Common: -o FILE,\n"
             "  -O (remote name)\n"
             "  -L (follow)\n"
             "  -X METHOD\n"
             "  -d DATA (repeatable, joined with '&')\n"
             "  -H HEADER (repeatable)\n"
             "  -u USER:PASS (basic auth)\n"
             "  -k (skip TLS verification)"},
    {"cut", "cut -f LIST [-d DELIM] [-s] [FILE...]\n"
            "       cut -c LIST [FILE...]\n"
            "  -f fields, -c characters/bytes: LIST is N, N-M, N-, or -M,\n"
            "     comma-separated (e.g. 1,3-5)\n"
            "  -d delimiter (default tab)\n"
            "  -s suppress lines with no delimiter (default: print unchanged)"},
    {"date", "date [-u] [-d STRING] [-s STRING] [+FORMAT]\n"
             "  Show (or set) date/time\n"
             "  -u: use UTC instead of local time\n"
             "  -d/--date=STRING: display STRING's time instead of now\n"
             "  -s/--set=STRING: set the system clock to STRING, then display it\n"
             "  STRING accepts \"YYYY-MM-DD[ HH:MM[:SS]]\" (also T-separated\n"
             "  and '/'-separated) -- not full natural-language date parsing"},
    {"dd", "dd [if=FILE] [of=FILE] [bs=N] [count=N] [skip=N] [seek=N] [conv=notrunc]\n"
           "  Block-copy if= to of= (default stdin to stdout, bs=512)\n"
           "  N accepts k/M/G/b/w size suffixes\n"
           "  skip=N/seek=N: skip N input/output blocks before copying\n"
           "  conv=notrunc: don't truncate an existing output file first\n"
           "  Prints a records-in/records-out/bytes summary to stderr"},
    {"diff", "diff [-u] [-q] FILE1 FILE2\n"
             "  Unified diff (only mode implemented); -q brief \"differ\" message\n"
             "  Exit status: 0 same, 1 differ, 2 error. No directory comparison."},
    {"cmp", "cmp [-s] [-l] FILE1 FILE2\n"
            "  Byte-for-byte comparison; default prints the first differing\n"
            "  byte/line offset (or an EOF message if one file is a prefix\n"
            "  of the other). FILE may be '-' for stdin (only one side).\n"
            "  -s: silent, exit status only\n"
            "  -l: list every differing byte offset with both octal values\n"
            "  Exit status: 0 same, 1 differ, 2 error"},
    {"dirname", "dirname PATH...\n"
                "  Strip last path component from each PATH, one per line\n"
                "  -z/--zero: NUL-terminate output instead of newline"},
    {"du", "du [-s] [-h] [-k] [-c] [-x] [-d N|--max-depth=N] [PATH...]\n"
           "  Default: print a subtotal for every directory (not files)\n"
           "  -s: only the grand total per PATH argument\n"
           "  -h: human-readable sizes  -k: force 1K-block units\n"
           "  -c: print a grand total after all arguments\n"
           "  -x: don't cross onto a different filesystem\n"
           "  -d N/--max-depth=N: only print subtotals down to depth N"},
#if defined(SMALLCLUE_WITH_DVTM)
    {"dvtm", "dvtm\n"
             "  Launch dvtm terminal multiplexer"},
#endif
    {"echo", "echo [-neE] [args...]\n"
             "  Print arguments\n"
             "  -n: suppress the trailing newline\n"
             "  -e: interpret backslash escapes (\\n \\t \\\\ \\0NNN \\xHH etc; \\c\n"
             "      stops all further output immediately)\n"
             "  -E: don't interpret backslash escapes (the default)"},
    {"env", "env [-i] [NAME=VALUE ...] [command]\n"
            "  -i start with empty environment"},
    {"expr", "expr EXPRESSION\n"
             "  Evaluate an expression: arithmetic (+ - * / %), string\n"
             "  comparison (= != < <= > >=), logical (& |), and string\n"
             "  operators (STR : REGEXP, match, substr, index, length)\n"
             "  Exit status: 0 if result is non-empty and non-zero, 1\n"
             "  if null/zero, 2 on error"},
    {"false", "false\n"
              "  Exit with status 1"},
    {"file", "file FILE...\n"
             "  Identify file types"},
    {"find", "find PATH [expression]\n"
             "  Common: -name PATTERN -type f|d|l\n"
             "  -mtime [+-]N: modified N days ago (+older, -newer)\n"
             "  -newer FILE: modified more recently than FILE\n"
             "  -size [+-]N[c|k|M|G|w]: size comparison (default unit: 512B blocks)\n"
             "  -print0: NUL-separated output (pairs with xargs -0)\n"
             "  -maxdepth/-mindepth N (global traversal options)\n"
             "  Boolean logic: -a/-and (implicit between adjacent terms),\n"
             "  -o/-or, !/-not, and \\( \\) grouping"},
    {"gzip", "gzip [-c] [-k] [-f] [-d] FILE...\n"
             "  -c stdout  -k keep original  -f force overwrite  -d decompress"},
    {"gunzip", "gunzip [-c] [-k] [-f] FILE...\n"
               "  -c stdout  -k keep original  -f force overwrite"},
    {"zcat", "zcat FILE...\n"
             "  Decompress to standard output"},
    {"grep", "grep [-i] [-n] [-v] [-r|-R] [-E] [-c] [-o] [-w] [-x] PATTERN [FILE...]\n"
             "  -i ignore case\n"
             "  -n line numbers\n"
             "  -v invert match\n"
             "  -r/-R recursive directory search\n"
             "  -E extended regex (default: POSIX basic regex)\n"
             "  -c print only a count of matching lines per file\n"
             "  -o print only the matched portion, one match per line\n"
             "  -w match whole words only\n"
             "  -x match whole lines only"},
    {"git", "git [-C PATH] [--no-pager] [-c key=value] <subcommand> [args]\n"
            "  Supported in this build:\n"
            "  init,\n"
            "  clone (supports --depth N for a shallow clone),\n"
            "  submodule (status, update/init [--recursive] [path...]),\n"
            "  remote,\n"
            "  ls-remote,\n"
            "  fetch,\n"
            "  pull,\n"
            "  merge,\n"
            "  cherry,\n"
            "  cherry-pick,\n"
            "  revert,\n"
            "  rebase,\n"
            "  push,\n"
            "  add,\n"
            "  rm,\n"
            "  mv,\n"
            "  clean,\n"
            "  stash,\n"
            "  commit,\n"
            "  reset,\n"
            "  restore,\n"
            "  checkout,\n"
            "  switch,\n"
            "  config --get,\n"
            "  symbolic-ref,\n"
            "  rev-list,\n"
            "  merge-base,\n"
            "  show-ref,\n"
            "  ls-files,\n"
            "  ls-tree,\n"
            "  cat-file,\n"
            "  rev-parse,\n"
            "  status,\n"
            "  branch,\n"
            "  tag,\n"
            "  diff,\n"
            "  log,\n"
            "  show,\n"
            "  reflog,\n"
            "  blame,\n"
            "  describe"},
    {"halt", "halt [-f]\n"
             "  Halt the system"},
    {"head", "head [-n N|-n -N] [FILE...]\n"
             "  Default N=10\n"
             "  -n -N: print all but the last N lines instead of the first N"},
    {"history", "history\n"
                "  Show command history"},
    {"id", "id\n"
           "  Show uid/gid info"},
    {"init", "init [--service-mode|-S|--allow-non-pid1]\n"
             "  System initialization (PID 1 by default)\n"
             "  --service-mode allows compatibility startup when PID != 1"},
#if SMALLCLUE_HAS_IFADDRS
    {"ipaddr", "ipaddr [-4|-6] [-a]\n"
               "  Show interface IP addresses\n"
               "  ipaddr add|del ADDR/PREFIXLEN dev IFACE\n"
               "  ipaddr flush dev IFACE\n"
               "  ipaddr link set IFACE up|down\n"
               "  ipaddr route add|del DEST/PREFIXLEN|default [via GW] [dev IFACE]\n"
               "  (Linux only, needs CAP_NET_ADMIN; IPv4 only)"},
#endif
    {"kill", "kill [-SIGNAL] PID...\n"
             "  Signals: HUP INT TERM KILL etc."},
    {"less", "less [FILE...]\n"
             "  Pager; navigation: j/k, /, n, g/G, q"},
    {"ln", "ln [-s] [-f] TARGET LINK\n"
           "       ln [-s] [-f] TARGET... DIRECTORY\n"
           "  -s symbolic link  -f force overwrite\n"
           "  When the last operand is a directory, each target's basename\n"
           "  is created inside it"},
    {"ls", "ls [-a] [-A] [-l] [-n] [-1] [-C] [-t] [-S] [-X] [-v] [-r] [-R] [-h] [-d] [-i]\n"
           "     [--color[=auto|always|never]] [path ...]\n"
           "  -a show entries starting with '.' (including . and ..)\n"
           "  -A show entries starting with '.' (excluding . and ..)\n"
           "  -l long format with permissions, ownership, size, time\n"
           "  -n numeric uid/gid (implies -l)\n"
           "  -1 list one file per line\n"
           "  -C list entries by columns\n"
           "  -t sort by modification time  -S sort by size  -X sort by extension\n"
           "  -v natural/version sort (e.g. file2 before file10)\n"
           "  -r reverse sort order  -R recurse into subdirectories\n"
           "  -h human-readable sizes (with -l)\n"
           "  -d list directories themselves, not their contents\n"
           "  -i show each entry's inode number as a leading column"},
    {"md", "md [-i] [-c] [FILE|URL]\n"
           "  View Markdown/HTML document; press 'o' to open links in-page\n"
           "  -i interactive mode.  Makes ~/Docs browsable\n"
           "  -c output raw markdown (convert if HTML)"},
    {"mdev", "mdev [-s]\n"
             "  Device manager (scan only)"},
    {"mkdir", "mkdir [-p] [-v] DIR...\n"
              "  -p create parents as needed\n"
              "  -v verbose"},
    {"mknod", "mknod [-m mode] NAME TYPE [MAJOR MINOR]\n"
              "  Create special files (b=block, c/u=char, p=fifo)"},
    {"mount", "mount [-p] [-t type] [-o options] [source] dir\n"
              "  Mount filesystems (iOS: omit source to open folder picker; -p persists to /etc/fstab)"},
    {"umount", "umount [-p] [-l] [-f] dir\n"
               "  Unmount filesystems (iOS: -p also removes matching /etc/fstab entry)\n"
               "  Linux: -l lazy unmount (MNT_DETACH), -f force (MNT_FORCE)"},
    {"micro", "micro [FILE]\n"
              "  Micro editor"},
    {"more", "more [FILE...]\n"
             "  Pager (alias of less)"},
    {"mv", "mv SRC... DEST\n"
           "  Move or rename files"},
    {"install", "install [-m MODE] [-D] SRC... DEST\n"
                "       install -d [-m MODE] DIRECTORY...\n"
                "  Copy SRC to DEST (or each SRC into DEST/ if it's a\n"
                "  directory) and chmod to MODE (default 0755)\n"
                "  -D create DEST's parent directories first\n"
                "  -d create directories instead of copying files\n"
                "  -v verbose"},
    {"base64", "base64 [-d] [-i] [-w COLS] [FILE]\n"
               "  Encode FILE/stdin to base64 (default), or decode with -d\n"
               "  -i/--ignore-garbage: skip invalid characters when decoding\n"
               "  -w COLS: wrap encoded output at COLS columns (default 76, 0 disables)"},
    {"md5sum", "md5sum [-c] [FILE...]\n"
               "  -c verify against a checksums file (\"HEXDIGEST  path\" per line)"},
    {"sha1sum", "sha1sum [-c] [FILE...]\n"
                "  -c verify against a checksums file"},
    {"sha256sum", "sha256sum [-c] [FILE...]\n"
                  "  -c verify against a checksums file"},
    {"nohup", "nohup COMMAND [ARG...]\n"
              "  Run COMMAND immune to SIGHUP, so it survives the controlling\n"
              "  terminal hanging up. If stdout is a terminal, output is appended\n"
              "  to nohup.out (or $HOME/nohup.out); if stderr is also a terminal,\n"
              "  it goes to the same place."},
    {"nslookup", "nslookup [-v] host [server]\n"
                 "  DNS lookup utility; queries SERVER directly (port 53) if\n"
                 "  given, else uses the system resolver. IP-shaped queries\n"
                 "  auto-detect as PTR/reverse lookups.\n"
                 "  -v prints hosts lookup debugging."},
    {"od", "od [-A d|o|x|n] [-t TYPE] [-c] [-v] [FILE]\n"
           "  Dump FILE/stdin in the given format (default: 2-byte octal words)\n"
           "  -A: address radix (d/o/x) or n for no address column\n"
           "  -t TYPE: x1/x2/x4 (hex), o1/o2/o4 (octal), d1/d2/d4 (signed decimal),\n"
           "           u1/u2/u4 (unsigned decimal), c (character)\n"
           "  -c: shorthand for -t c\n"
           "  -v: accepted for compatibility (repeated lines are never collapsed)"},
    {"seq", "seq [-w] [-s SEP] [FIRST [INCREMENT]] LAST\n"
            "  Print a sequence of numbers; -w zero-pads to equal width,\n"
            "  -s SEP sets the separator (default newline)"},
    {"nl", "nl [-b a|t] [-w WIDTH] [-s SEP] [FILE]\n"
           "  Number lines of FILE/stdin; -b t (default) numbers non-blank\n"
           "  lines only, -b a numbers every line"},
    {"tac", "tac [FILE...]\n"
            "  Concatenate and print FILE/stdin with lines in reverse order"},
    {"rev", "rev [FILE...]\n"
            "  Reverse the characters of each line of FILE/stdin"},
    {"fold", "fold [-w WIDTH] [-s] [FILE...]\n"
             "  Wrap each line to WIDTH characters (default 80);\n"
             "  -s breaks at the last whitespace before the width"},
    {"paste", "paste [-d LIST] [-s] [FILE...]\n"
              "  Merge corresponding lines of FILE/stdin side by side\n"
              "  (default delimiter: tab, cycles through -d LIST's chars);\n"
              "  -s: join each file's own lines serially instead"},
    {"split", "split [-l LINES | -b BYTES] [FILE [PREFIX]]\n"
              "  Split FILE/stdin into PREFIXaa, PREFIXab, ... (default\n"
              "  PREFIX: x); -l 1000 lines/chunk by default, or -b BYTES"},
    {"fmt", "fmt [-w WIDTH] [FILE...]\n"
            "  Reflow text into filled paragraphs (default width 75);\n"
            "  blank lines are paragraph breaks"},
    {"comm", "comm [-1] [-2] [-3] FILE1 FILE2\n"
             "  Compare two SORTED files; 3 columns by default (unique to\n"
             "  FILE1, unique to FILE2, common); -N suppresses column N"},
    {"awk", "awk [-F sep] [-v var=val] [-f progfile | -e prog | 'prog'] [file ...]\n"
            "  Pattern scanning/processing: BEGIN/END, patterns+actions,\n"
            "  fields/arrays/functions/getline/printf (BusyBox awk feature set)"},
    {"nextvi", "nextvi [FILE]\n"
               "  Full-screen text editor"},
    {"passwd", "passwd [username]\n"
               "  Change user password"},
    {"patch", "patch [-p N] [-i PATCHFILE] [FILE]\n"
              "  Apply a unified diff (from stdin, or -i PATCHFILE)\n"
              "  -p N strip N leading path components (default 1)\n"
              "  FILE overrides the target path for a single-file patch\n"
              "  Context-diff/plain-diff formats are not supported, only unified"},
    {"printf", "printf FORMAT [ARGUMENT...]\n"
               "  Format and print ARGUMENTs per FORMAT (like the shell builtin)\n"
               "  Conversions: %d %i %o %u %x %X %e %f %g %c %s %b %%\n"
               "  FORMAT escapes: \\n \\t \\r \\a \\b \\f \\v \\\\\n"
               "  If more ARGUMENTs remain than FORMAT consumes, FORMAT is reused"},
    {"host", "host [-4|-6] [-v] [-t TYPE] host [server]\n"
             "  -4 IPv4 only\n"
             "  -6 IPv6 only\n"
             "  -t A|AAAA select record type\n"
             "  -v verbose (hosts debug)\n"
             "  IP-shaped queries auto-detect as PTR/reverse lookups\n"
             "Server override is ignored."},
    {"hostname", "hostname\n"
                 "  Show system hostname"},
    {"pbcopy", "pbcopy\n"
               "  Copy stdin to system clipboard"},
    {"pbpaste", "pbpaste\n"
                "  Paste system clipboard to stdout"},
    {"ping", "ping [-4|-6] [-c count] [-t timeout_ms] HOST\n"
             "  ICMP echo ping (IPv4 and IPv6)"},
    {"poweroff", "poweroff [-f]\n"
             "  Power off the system"},
    {"ps", "ps [-e|-A|-a] [-f] [-p PID[,PID...]] [-u USER[,USER...]]\n"
           "  Show process list (all processes are always shown; -e/-A/-a\n"
           "  are accepted for compatibility). Also accepts bundled BSD-style\n"
           "  flags without a leading dash, e.g. `ps aux`, `ps ef`.\n"
           "  -f: full format, adds a STAT (state) column\n"
           "  -p PID[,PID...]: only show the given PID(s)\n"
           "  -u USER[,USER...]: only show processes owned by the given user(s)"},
    {"pwd", "pwd\n"
            "  Print working directory"},
    {"reboot", "reboot [-f]\n"
             "  Reboot the system"},
    {"resize", "resize [COLUMNS ROWS]\n"
               "  Report or set terminal size"},
    {"readlink", "readlink [-f|-e|-m] [-n] PATH...\n"
                 "  No flag: print the immediate symlink target\n"
                 "  -f canonicalize (resolve all symlinks + ./..); -e requires\n"
                 "  every component to exist; -m allows a missing final component\n"
                 "  -n suppress trailing newline"},
    {"realpath", "realpath [-e|-m] PATH...\n"
                 "  Print the canonicalized absolute path\n"
                 "  -e require full existence  -m allow a missing final component (default)"},
    {"rm", "rm [-r|-R] [-f] [-i] [--no-preserve-root] FILE...\n"
           "  -r/-R recursive\n"
           "  -f force\n"
           "  -i interactive\n"
           "  --preserve-root (default): refuse recursive removal of '/'\n"
           "  --no-preserve-root: disable that failsafe"},
    {"rmdir", "rmdir [-p] [-v] DIR...\n"
              "  Remove empty directories\n"
              "  -p remove parents\n"
              "  -v verbose"},
    {"rsync", "rsync [options] <source>... <destination>\n"
              "  Synchronize files and directories (OpenRsync-compatible applet)\n"
              "  Common: -a -v -z -r --delete --exclude PATTERN --include PATTERN\n"
              "  Remote paths use host:path syntax over SSH"},
    {"runit", "runit\n"
             "  Service supervisor"},
    {"sed", "sed [-n] [-E|-r] [-i[SUFFIX]] [-e SCRIPT]... [-f SCRIPTFILE]... [SCRIPT] [FILE...]\n"
            "  Commands: s/PAT/REP/[gi], y/SET1/SET2/, d, p\n"
            "  Address prefixes (any command): N, $, /regex/, N,M, N,$,\n"
            "  /regex1/,/regex2/, /regex1/,N -- restrict the command to matching lines\n"
            "  -n: suppress automatic printing (use with p)\n"
            "  Multiple -e/-f accumulate; commands within one script are\n"
            "  ';'-or-newline-separated. -E/-r: extended regex (default: basic)\n"
            "  -i[SUFFIX]: edit files in place, optionally backing up to FILE+SUFFIX"},
    {"sleep", "sleep SECONDS\n"
              "  Pause execution"},
    {"sort", "sort [-r] [-n] [-u] [-k N] [-t SEP] [-c|-C] [-m] [FILE...]\n"
             "  -r reverse\n"
             "  -n numeric\n"
             "  -u unique (after sorting)\n"
             "  -k N sort by field N through end of line (1-based)\n"
             "  -t SEP field separator for -k (default: runs of whitespace)\n"
             "  -c/--check: verify input is already sorted; no output, exits 1\n"
             "     and reports the first out-of-order line if not\n"
             "  -C/--check=quiet: like -c but no diagnostic message\n"
             "  -m/--merge: accepted for compatibility (sorts fully rather\n"
             "     than doing a true presorted-runs merge; same output)\n"
             "  Stable: equal-key lines keep their original relative order"},
    {"stat", "stat [-L] [-c FORMAT|--format=FORMAT] FILE...\n"
             "  -L follow symlinks\n"
             "  -c/--format FORMAT: %n name %s size %F type %a/%A perms\n"
             "    %u/%g uid/gid %U/%G user/group %i inode %h links\n"
             "    %d device %b blocks %B block-size %f raw mode(hex)\n"
             "    %X/%Y/%Z atime/mtime/ctime (epoch seconds), %% literal %"},
    {"stty", "stty [reset] [sane]\n"
             "  Report terminal settings; apply reset/sane"},
#if defined(SMALLCLUE_WITH_EXSH)
    {"exsh", "exsh\n"
             "  Launch PSCAL shell front end"},
    {"sh", "sh\n"
           "  Launch PSCAL shell front end"},
#elif defined(SMALLCLUE_WITH_SH)
    {"sh", "sh [-eiuxvnfCam] [-c command | script | -s] [args]\n"
           "  POSIX shell (BusyBox-ash compatible): pipelines, functions,\n"
           "  expansions, job control, interactive line editing"},
    {"ash", "ash [-eiuxvnfCam] [-c command | script | -s] [args]\n"
            "  Alias for sh"},
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
    {"su", "su [-] [username] [-c command]\n"
           "  Change user ID or become superuser"},
    {"sudo", "sudo command [args...]\n"
             "  Execute a command as another user"},
    {"tail", "tail [-n N|-n +N] [-f] [FILE...]\n"
             "  Default N=10\n"
             "  -n +N: start output at line N (relative to the start) instead\n"
             "  of printing the last N lines. Not combinable with -f."},
    {"tar", "tar -c|-x|-t -f archive [-v] [-z] [-C dir] [file...]\n"
            "  -c create  -x extract  -t list\n"
            "  -f archive path (or - for stdin/stdout)\n"
            "  -v verbose  -z gzip (also auto-detected on read)\n"
            "  -C dir  chdir before create, or extract-destination dir\n"
            "  Bundled form also accepted: tar xzf archive.tar.gz"},
    {"tee", "tee [-a] FILE...\n"
            "  -a append"},
    {"telnet", "telnet [-p PORT] HOST\n"
               "  Connect to HOST over TCP (default port 23) and relay stdin/stdout;\n"
               "  handles IAC option negotiation (declines every DO/WILL request)\n"
               "  and subnegotiation blocks -- no actual options are supported"},
    {"traceroute", "traceroute HOST [PORT]\n"
                   "  Trace network path using the system traceroute command"},
    {"test", "test EXPRESSION\n"
             "  File: -f -d -e -r -w -x -s -L/-h\n"
             "  File compare: -nt -ot -ef\n"
             "  String: = != -z -n; Int: -eq -ne -lt -le -gt -ge\n"
             "  Combine: ! (not), -a (and), -o (or) -- -a binds tighter than -o"},
    {"time", "time command [args...]\n"
             "  Run a smallclue applet and print real/user/sys timing"},
    {"tset", "tset [-IQqs] [-e CH] [-i CH] [-k CH] [-r] [TERM]\n"
             "  Set TERM and initialize terminal\n"
             "  -s emit shell commands\n"
             "  -r report terminal type\n"
             "  -Q quiet, -I skip init\n"
             "  -e/-i/-k set erase/intr/kill chars"},
    {"touch", "touch [-c] [-a] [-m] [-r REFFILE|-t STAMP|-d STRING] FILE...\n"
              "  Update timestamps or create empty file\n"
              "  -c no-create  -a access-time-only  -m mtime-only\n"
              "  -r REFFILE: copy REFFILE's timestamps\n"
              "  -t [[CC]YY]MMDDhhmm[.ss]\n"
              "  -d STRING: ISO-ish date (\"YYYY-MM-DD[ HH:MM[:SS]]\")"},
    {"timeout", "timeout [-s SIGNAL] [-k DURATION] [--preserve-status] DURATION COMMAND [ARG...]\n"
                "  Run COMMAND, terminating it if it's still running after DURATION\n"
                "  DURATION accepts an optional s/m/h/d suffix (default seconds)\n"
                "  -s SIGNAL: signal to send on timeout (default TERM)\n"
                "  -k DURATION: send KILL after this additional time if still alive\n"
                "  --preserve-status: exit with COMMAND's own status instead of 124\n"
                "  Exit 124 on timeout (unless --preserve-status), 125 on usage/setup\n"
                "  error, 126/127 if COMMAND can't be invoked, else COMMAND's status"},
    {"sum", "sum [-r|-s] [FILE...]\n"
            "  BSD (-r, default): rotate-right checksum, 1K blocks.\n"
            "  SysV (-s, --sysv): simple sum, 512-byte blocks.\n"
            "  With no FILE or FILE '-', read standard input.\n"
            "  Prints: <checksum> <blocks> [filename]\n"},
    {"tty", "tty [-s]\n"
            "  Print terminal name"},
    {"tr", "tr [-d] [-s] [-c] SET1 [SET2]\n"
           "  -d delete characters in SET1\n"
           "  -s squeeze repeats (of SET2 chars in translate mode,\n"
           "     SET1 chars if used alone or with -d)\n"
           "  -c/-C complement SET1\n"
           "  Sets support a-z ranges, [:alpha:]-style POSIX classes,\n"
           "  [c*n]/[c*] repeats, and \\n/\\t/\\\\ escapes"},
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
    {"uniq", "uniq [-c] [-d] [-u] [-i] [-f N] [-s N] [-w N] [FILE]\n"
             "  -c count\n"
             "  -d duplicates only\n"
             "  -u unique only\n"
             "  -i ignore case when comparing\n"
             "  -f N: skip the first N whitespace-separated fields\n"
             "  -s N: additionally skip the first N characters\n"
             "  -w N: compare at most N characters (default: rest of line)"},
    {"uptime", "uptime [-s]\n"
               "  Show app uptime since launch\n"
               "  -s show system uptime"},
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
    {"wc", "wc [-l] [-w] [-c] [-m] [-L] [FILE...]\n"
           "  Count lines/words/bytes; -m chars (locale-aware),\n"
           "  -L max line length (tabs expand to 8-col stops)"},
    {"wget", "wget [options] URL...\n"
             "  Common: -O FILE\n"
             "  --method=METHOD\n"
             "  --header=HEADER (repeatable)\n"
             "  --post-data=DATA\n"
             "  --user=USER --password=PASS\n"
             "  --no-check-certificate\n"
             "  -q\n"
             "  -nv"},
    {"which", "which [-a] program ...\n"
              "  Locate a command"},
    {"whoami", "whoami\n"
               "  Print effective user name"},
    {"yes", "yes [STRING...]\n"
            "  Repeatedly print STRING (default: y)"},
    {"no", "no [STRING...]\n"
           "  Repeatedly print STRING (default: n) and exit 1 on stop"},
    {"xargs", "xargs [-n N] [-0] [-I REPLACE] [-t] COMMAND [initial-args]\n"
              "  Build and run command lines from stdin (builtin applets\n"
              "  or arbitrary external binaries via execvp)\n"
              "  -n N max args per invocation (default: one invocation, all args)\n"
              "  -0 NUL-delimited input (pairs with find -print0)\n"
              "  -I REPLACE: one invocation per input line, substituting\n"
              "    REPLACE wherever it appears in COMMAND's arguments\n"
              "  -t print each command line before running it\n"
              "  Without -0: single/double quotes group whitespace into one\n"
              "    token (quotes stripped); backslash escapes the next char"},
    {"df", "df [-h] [path ...]\n"
           "  With no path, lists every mounted filesystem (like real df)\n"
           "  -h human-readable sizes"},
    {"dmesg", "dmesg [-T]\n"
              "  Print or control the kernel ring buffer\n"
              "  -T  show human-readable timestamps (iOS only)"},
    {"nslookup", "nslookup [-v] host [server]\n"
                 "  DNS lookup utility; queries SERVER directly (port 53) if given,\n"
                 "  else uses the system resolver. IP-shaped queries auto-detect as\n"
                 "  PTR/reverse lookups. -v prints hosts lookup debugging."},
#if defined(PSCAL_TARGET_IOS)
    {"addt", "addt\n"
             "  Open an additional shell tab"},
    {"tabadd", "tabadd\n"
               "  Alias for addt"},
    {"tadd", "tadd\n"
             "  Alias for addt"},
    {"smallclue-help", "smallclue-help [command]\n"
                       "  Without arguments: list all applets\n"
                       "  With a command: show usage if available"},
    {"licenses", "licenses\n"
                 "  Browse PSCAL and third-party licenses; use arrows/enter to view"},
    {"top", "top\n"
            "  Show PSCAL virtual processes and CPU ticks"},
#else
    {"top", "top [-d SECONDS] [-n COUNT] [-b]\n"
            "  Show real system processes from /proc, sorted by %CPU\n"
            "  -d SECONDS refresh delay (default 3)\n"
            "  -n COUNT   exit after COUNT frames (default: run until interrupted)\n"
            "  -b         batch mode: never clear the screen, print every frame"},
#endif
    {NULL, NULL}
};

static size_t kSmallclueAppletCount = sizeof(kSmallclueApplets) / sizeof(kSmallclueApplets[0]);

const char *smallclueLookupAppletUsage(const char *name) {
    if (!name) {
        return NULL;
    }
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
static void smallclueMenuStartFrameTo(FILE *out, bool *first_frame);

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

#if defined(PSCAL_TARGET_IOS)
    if (stream == stdin) {
        return smallclueReadStdin(buf, count, out_errno);
    }
#endif
    size_t read_bytes = fread(buf, 1, count, stream);
    if (read_bytes < count && ferror(stream)) {
        if (out_errno) {
            *out_errno = errno ? errno : EIO;
        }
    }
    return (ssize_t)read_bytes;
}

static bool smallclueWriteFullyStream(FILE *stream, const void *buf, size_t count, int *out_errno) {
    if (out_errno) {
        *out_errno = 0;
    }
    if (!stream || (!buf && count > 0)) {
        if (out_errno) {
            *out_errno = EINVAL;
        }
        return false;
    }
    size_t off = 0;
    while (off < count) {
        errno = 0;
        size_t nw = fwrite((const char *)buf + off, 1, count - off, stream);
        if (nw > 0) {
            off += nw;
            continue;
        }
        if (ferror(stream)) {
            int err = errno ? errno : EIO;
            if (err == EINTR || err == EAGAIN) {
                clearerr(stream);
                continue;
            }
            if (out_errno) {
                *out_errno = err;
            }
            return false;
        }
        if (out_errno) {
            *out_errno = EIO;
        }
        return false;
    }
    return true;
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

#if defined(PSCAL_TARGET_IOS)
    if (stream == stdin) {
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
#endif

    int ch = fgetc(stream);
    if (ch == EOF && ferror(stream)) {
        if (out_errno) {
            *out_errno = errno ? errno : EIO;
        }
    }
    return ch;
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

#if defined(PSCAL_TARGET_IOS)
    if (stream == stdin) {
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
#endif

    ssize_t len = getline(line, cap, stream);
    if (len < 0 && ferror(stream)) {
        if (out_errno) {
            *out_errno = errno ? errno : EIO;
        }
    }
    return len;
}

/* Real xargs (without -0) gives single/double quotes and a backslash real
 * meaning: a quoted span groups whitespace into one token (the quote chars
 * themselves are stripped, no escape processing inside), and outside
 * quotes a backslash escapes the very next character literally -- most
 * commonly used to keep an embedded space from splitting a token. An
 * unmatched quote is a hard error, matching real xargs (verified against
 * GNU findutils xargs in Docker: `'hello world' foo` -> two tokens
 * "hello world" and "foo"; `a\ b c` -> "a b" and "c"; an unterminated
 * quote errors and exits 1 rather than silently absorbing the rest of
 * the input). */
static bool smallclueReadTokensFromStdin(SmallclueLineVector *vec) {
    char *token = NULL;
    size_t tokcap = 0;
    size_t toklen = 0;
    char buf[16384];
    int read_err = 0;
    ssize_t n;
    char quoteChar = '\0'; /* '\'' or '"' while inside a quoted span, else '\0' */
    bool sawBackslash = false;
    bool haveContent = false; /* true once any char (even from an empty "" pair) started this token */

    while ((n = smallclueReadStream(stdin, buf, sizeof(buf), &read_err)) > 0) {
        for (ssize_t i = 0; i < n; ++i) {
            int ch = (unsigned char)buf[i];
            if (sawBackslash) {
                sawBackslash = false;
            } else if (quoteChar == '\0' && ch == '\\') {
                sawBackslash = true;
                haveContent = true;
                continue;
            } else if (quoteChar == '\0' && (ch == '\'' || ch == '"')) {
                quoteChar = (char)ch;
                haveContent = true;
                continue;
            } else if (quoteChar != '\0' && ch == quoteChar) {
                quoteChar = '\0';
                continue;
            } else if (quoteChar == '\0' && ((ch == ' ') || (ch >= '\t' && ch <= '\r'))) {
                if (haveContent) {
                    if (!smallclueLineVectorAppend(vec, token, toklen)) {
                        free(token);
                        return false;
                    }
                    toklen = 0;
                    haveContent = false;
                }
                continue;
            }
            haveContent = true;
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
    }
    if (read_err) {
        free(token);
        return false;
    }
    if (quoteChar != '\0') {
        fprintf(stderr, "xargs: unmatched %s quote; by default quotes are special to xargs "
                        "unless you use the -0 option\n",
                quoteChar == '\'' ? "single" : "double");
        free(token);
        errno = 0; /* signals to the caller that this message is already complete */
        return false;
    }
    if (haveContent) {
        bool ok = smallclueLineVectorAppend(vec, token, toklen);
        free(token);
        return ok;
    }
    free(token);
    return true;
}

/* xargs -0: tokens are separated by a literal NUL byte instead of
 * whitespace -- pairs safely with `find -print0`, since it makes no
 * assumption about filenames not containing spaces/newlines. */
static bool smallclueReadNulTokensFromStdin(SmallclueLineVector *vec) {
    char *token = NULL;
    size_t tokcap = 0;
    size_t toklen = 0;
    char buf[16384];
    int read_err = 0;
    ssize_t n;

    while ((n = smallclueReadStream(stdin, buf, sizeof(buf), &read_err)) > 0) {
        for (ssize_t i = 0; i < n; ++i) {
            char ch = buf[i];
            if (ch == '\0') {
                if (!smallclueLineVectorAppend(vec, token, toklen)) {
                    free(token);
                    return false;
                }
                toklen = 0;
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
            token[toklen++] = ch;
        }
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

/* xargs -I: each line of input (whole line, not whitespace-split) becomes
 * one invocation of the command. */
static bool smallclueReadLinesFromStdin(SmallclueLineVector *vec, bool nulDelimited) {
    if (nulDelimited) {
        return smallclueReadNulTokensFromStdin(vec);
    }
    char *line = NULL;
    size_t cap = 0;
    for (;;) {
        int read_err = 0;
        ssize_t len = smallclueGetlineStream(&line, &cap, stdin, &read_err);
        if (len < 0) {
            free(line);
            return read_err == 0;
        }
        if (len > 0 && line[len - 1] == '\n') {
            len--;
        }
        if (!smallclueLineVectorAppend(vec, line, (size_t)len)) {
            free(line);
            return false;
        }
    }
}

/* Runs one xargs invocation of `cmdArgv` (NULL-terminated, cmdArgv[0] is
 * the command name). Prefers the in-process builtin-applet dispatch when
 * the name matches one (fast, no fork), but falls back to fork+execvp for
 * anything else -- xargs previously could ONLY invoke other smallclue
 * applets, so `find . | xargs some-external-tool` failed outright even
 * though external binaries are exactly what a real Linux guest's xargs
 * needs to be able to run (including other smallclue-multicall symlinks
 * like ls/rm/grep, which execvp resolves to this same binary anyway). */
static int smallclueXargsRunOne(char **cmdArgv, int cmdArgc, bool verbose) {
    if (verbose) {
        for (int i = 0; i < cmdArgc; ++i) {
            fprintf(stderr, "%s%s", i > 0 ? " " : "", cmdArgv[i]);
        }
        fprintf(stderr, "\n");
    }
    const SmallclueApplet *target = smallclueFindApplet(cmdArgv[0]);
    if (target) {
        return smallclueDispatchApplet(target, cmdArgc, cmdArgv);
    }
    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "xargs: fork: %s\n", strerror(errno));
        return 1;
    }
    if (pid == 0) {
        execvp(cmdArgv[0], cmdArgv);
        fprintf(stderr, "xargs: %s: %s\n", cmdArgv[0], strerror(errno));
        _exit(127);
    }
    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        fprintf(stderr, "xargs: waitpid: %s\n", strerror(errno));
        return 1;
    }
    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    return 1;
}

typedef struct {
    int pid;
    int ppid;
    uid_t uid;
    char state;
    char *command;
} SmallcluePsEntry;

#if !defined(PSCAL_TARGET_IOS)
static int smallcluePsCompare(const void *a, const void *b) {
    const SmallcluePsEntry *pa = (const SmallcluePsEntry *)a;
    const SmallcluePsEntry *pb = (const SmallcluePsEntry *)b;
    return pa->pid - pb->pid;
}

static bool smallcluePsParsePidList(const char *s, int **out, size_t *out_count) {
    size_t cap = 8, count = 0;
    int *arr = (int *)malloc(cap * sizeof(int));
    if (!arr) return false;
    const char *p = s;
    while (*p) {
        char *end = NULL;
        long v = strtol(p, &end, 10);
        if (end == p) {
            free(arr);
            return false;
        }
        if (count == cap) {
            cap *= 2;
            int *resized = (int *)realloc(arr, cap * sizeof(int));
            if (!resized) {
                free(arr);
                return false;
            }
            arr = resized;
        }
        arr[count++] = (int)v;
        p = end;
        if (*p == ',') {
            p++;
        } else if (*p != '\0') {
            free(arr);
            return false;
        }
    }
    if (count == 0) {
        free(arr);
        return false;
    }
    *out = arr;
    *out_count = count;
    return true;
}

static bool smallcluePsParseUserList(const char *s, uid_t **out, size_t *out_count) {
    char *copy = strdup(s);
    if (!copy) return false;
    size_t cap = 8, count = 0;
    uid_t *arr = (uid_t *)malloc(cap * sizeof(uid_t));
    if (!arr) {
        free(copy);
        return false;
    }
    char *saveptr = NULL;
    for (char *tok = strtok_r(copy, ",", &saveptr); tok; tok = strtok_r(NULL, ",", &saveptr)) {
        uid_t uid;
        bool resolved = false;
        if (*tok && strspn(tok, "0123456789") == strlen(tok)) {
            uid = (uid_t)strtoul(tok, NULL, 10);
            resolved = true;
        } else {
            struct passwd *pw = getpwnam(tok);
            if (pw) {
                uid = pw->pw_uid;
                resolved = true;
            }
        }
        if (!resolved) continue;
        if (count == cap) {
            cap *= 2;
            uid_t *resized = (uid_t *)realloc(arr, cap * sizeof(uid_t));
            if (!resized) {
                free(arr);
                free(copy);
                return false;
            }
            arr = resized;
        }
        arr[count++] = uid;
    }
    free(copy);
    if (count == 0) {
        free(arr);
        return false;
    }
    *out = arr;
    *out_count = count;
    return true;
}

static bool smallcluePsPidMatches(const int *pids, size_t count, int pid) {
    for (size_t i = 0; i < count; ++i) {
        if (pids[i] == pid) return true;
    }
    return false;
}

static bool smallcluePsUidMatches(const uid_t *uids, size_t count, uid_t uid) {
    for (size_t i = 0; i < count; ++i) {
        if (uids[i] == uid) return true;
    }
    return false;
}
#endif

static int smallcluePsCommand(int argc, char **argv) {
#if defined(PSCAL_TARGET_IOS)
    (void)argc;
    (void)argv;
    size_t cap = vprocSnapshot(NULL, 0);
    VProcSnapshot *snaps = (cap > 0) ? (VProcSnapshot *)calloc(cap, sizeof(VProcSnapshot)) : NULL;
    size_t count = snaps ? vprocSnapshot(snaps, cap) : 0;
    if (!snaps || count == 0) {
        free(snaps);
        if (isatty(STDOUT_FILENO)) {
            printf("\033[1m  PID   PPID   PGID    SID STATE      COMMAND\033[0m\n");
        } else {
            puts("  PID   PPID   PGID    SID STATE      COMMAND");
        }
        puts(" <no virtual tasks>");
        return 0;
    }

    if (isatty(STDOUT_FILENO)) {
        printf("\033[1m  PID   PPID   PGID    SID STATE      COMMAND\033[0m\n");
    } else {
        puts("  PID   PPID   PGID    SID STATE      COMMAND");
    }
    for (size_t i = 0; i < count; ++i) {
        const VProcSnapshot *s = &snaps[i];
        const char *state = "running";
        if (s->zombie) {
            state = "zombie";
        } else if (s->stopped) {
            state = "stopped";
        } else if (s->continued) {
            state = "continued";
        } else if (s->exited) {
            state = "exited";
        } else if (s->sigchld_pending) {
            state = "sigchld";
        }
        const char *cmd = (s->command[0] != '\0')
            ? s->command
            : ((s->comm[0] != '\0') ? s->comm : "?");
        printf("%5d %6d %6d %6d %-10s %s\n",
               s->pid,
               s->parent_pid,
               s->pgid,
               s->sid,
               state,
               cmd);
    }
    free(snaps);
    return 0;
#else
    bool fullFormat = false;
    int *filterPids = NULL;
    size_t filterPidCount = 0;
    uid_t *filterUids = NULL;
    size_t filterUidCount = 0;

    for (int i = 1; i < argc; ++i) {
        const char *arg = argv[i];
        if (!arg || !*arg) continue;
        if (strcmp(arg, "-p") == 0 || strcmp(arg, "--pid") == 0) {
            if (i + 1 >= argc || !smallcluePsParsePidList(argv[i + 1], &filterPids, &filterPidCount)) {
                fprintf(stderr, "ps: invalid or missing argument to -p\n");
                free(filterPids);
                free(filterUids);
                return 1;
            }
            i++;
            continue;
        }
        if (strncmp(arg, "-p", 2) == 0 && isdigit((unsigned char)arg[2])) {
            if (!smallcluePsParsePidList(arg + 2, &filterPids, &filterPidCount)) {
                fprintf(stderr, "ps: invalid argument to -p\n");
                free(filterPids);
                free(filterUids);
                return 1;
            }
            continue;
        }
        if (strcmp(arg, "-u") == 0 || strcmp(arg, "--user") == 0) {
            if (i + 1 >= argc || !smallcluePsParseUserList(argv[i + 1], &filterUids, &filterUidCount)) {
                fprintf(stderr, "ps: invalid or missing argument to -u\n");
                free(filterPids);
                free(filterUids);
                return 1;
            }
            i++;
            continue;
        }
        if (strncmp(arg, "-u", 2) == 0 && arg[2] != '\0') {
            if (!smallcluePsParseUserList(arg + 2, &filterUids, &filterUidCount)) {
                fprintf(stderr, "ps: invalid argument to -u\n");
                free(filterPids);
                free(filterUids);
                return 1;
            }
            continue;
        }
        /* Bundled single-char flags, with or without a leading '-' -- real
         * ps accepts both `ps -ef` and the BSD-legacy `ps aux` spelling,
         * and the latter is arguably the single most common invocation
         * in the wild. */
        const char *flags = (arg[0] == '-') ? arg + 1 : arg;
        bool recognized = (*flags != '\0');
        for (const char *fc = flags; recognized && *fc; ++fc) {
            switch (*fc) {
                case 'e': case 'E':
                case 'A': case 'a':
                case 'x': case 'w': case 'W':
                    break; /* show-all / no-controlling-tty / wide -- already the default here */
                case 'f':
                    fullFormat = true;
                    break;
                case 'u': case 'U':
                    break; /* user-oriented format -- USER column is always shown */
                default:
                    recognized = false;
                    break;
            }
        }
        if (!recognized) {
            fprintf(stderr, "ps: unsupported option '%s'\n", arg);
            free(filterPids);
            free(filterUids);
            return 1;
        }
    }

    DIR *dir = opendir("/proc");
    if (dir) {
        SmallcluePsEntry *entries = NULL;
        size_t count = 0;
        size_t capacity = 0;
        struct dirent *ent;

        while ((ent = readdir(dir)) != NULL) {
            if (!isdigit(ent->d_name[0])) continue;

            int pid = atoi(ent->d_name);
            if (filterPidCount > 0 && !smallcluePsPidMatches(filterPids, filterPidCount, pid)) {
                continue;
            }
            char path[PATH_MAX];

            snprintf(path, sizeof(path), "/proc/%s/stat", ent->d_name);
            FILE *fp = fopen(path, "r");
            if (!fp) continue;

            char buf[1024];
            if (!fgets(buf, sizeof(buf), fp)) {
                fclose(fp);
                continue;
            }
            fclose(fp);

            char *open_paren = strchr(buf, '(');
            char *close_paren = strrchr(buf, ')');
            if (!open_paren || !close_paren || close_paren <= open_paren) {
                continue;
            }

            *close_paren = '\0';
            char *comm_short = open_paren + 1;
            char *rest = close_paren + 1;

            int ppid = 0;
            char state_char = '?';
            if (sscanf(rest, " %c %d", &state_char, &ppid) != 2) {
                ppid = 0;
            }

            struct stat st;
            uid_t uid = 0;
            snprintf(path, sizeof(path), "/proc/%s", ent->d_name);
            if (stat(path, &st) == 0) {
                uid = st.st_uid;
            }
            if (filterUidCount > 0 && filterPidCount == 0 &&
                !smallcluePsUidMatches(filterUids, filterUidCount, uid)) {
                continue;
            }

            char *command = NULL;
            snprintf(path, sizeof(path), "/proc/%s/cmdline", ent->d_name);
            fp = fopen(path, "r");
            if (fp) {
                char cmdline[1024];
                size_t len = fread(cmdline, 1, sizeof(cmdline) - 1, fp);
                fclose(fp);
                if (len > 0) {
                    cmdline[len] = '\0';
                    for (size_t i = 0; i < len; ++i) {
                        if (cmdline[i] == '\0') cmdline[i] = ' ';
                    }
                    if (len > 0 && cmdline[len - 1] == ' ') {
                        cmdline[len - 1] = '\0';
                    }
                    if (cmdline[0] != '\0') {
                        command = strdup(cmdline);
                    }
                }
            }

            if (!command) {
                command = strdup(comm_short);
            }

            if (command) {
                if (count == capacity) {
                    size_t new_cap = capacity ? capacity * 2 : 16;
                    SmallcluePsEntry *new_entries = (SmallcluePsEntry *)realloc(entries, new_cap * sizeof(SmallcluePsEntry));
                    if (!new_entries) {
                        free(command);
                        break;
                    }
                    entries = new_entries;
                    capacity = new_cap;
                }
                entries[count].pid = pid;
                entries[count].ppid = ppid;
                entries[count].uid = uid;
                entries[count].state = state_char;
                entries[count].command = command;
                count++;
            }
        }
        closedir(dir);

        if (entries && count > 1) {
            qsort(entries, count, sizeof(SmallcluePsEntry), smallcluePsCompare);
        }

        const char *header = fullFormat ? "  PID   PPID USER     S COMMAND" : "  PID   PPID USER     COMMAND";
        if (isatty(STDOUT_FILENO)) {
            printf("\033[1m%s\033[0m\n", header);
        } else {
            printf("%s\n", header);
        }
        for (size_t i = 0; i < count; ++i) {
            struct passwd *pw = getpwuid(entries[i].uid);
            char user_buf[32];
            if (pw) {
                snprintf(user_buf, sizeof(user_buf), "%s", pw->pw_name);
            } else {
                snprintf(user_buf, sizeof(user_buf), "%d", (int)entries[i].uid);
            }
            if (fullFormat) {
                printf("%5d %6d %-8s %c %s\n", entries[i].pid, entries[i].ppid, user_buf,
                       entries[i].state, entries[i].command);
            } else {
                printf("%5d %6d %-8s %s\n", entries[i].pid, entries[i].ppid, user_buf, entries[i].command);
            }
            free(entries[i].command);
        }
        free(entries);
    } else {
        pid_t pid = getpid();
        pid_t ppid = getppid();
        uid_t uid = getuid();
        const char *cmd = argv && argv[0] ? argv[0] : "ps";
        if (isatty(STDOUT_FILENO)) {
            printf("\033[1m  PID   PPID USER     COMMAND\033[0m\n");
        } else {
            printf("  PID   PPID USER     COMMAND\n");
        }
        struct passwd *pw = getpwuid(uid);
        char user_buf[32];
        if (pw) {
            snprintf(user_buf, sizeof(user_buf), "%s", pw->pw_name);
        } else {
            snprintf(user_buf, sizeof(user_buf), "%d", (int)uid);
        }
        printf("%5d %6d %-8s %s\n", (int)pid, (int)ppid, user_buf, cmd);
    }
    free(filterPids);
    free(filterUids);
    return 0;
#endif
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

static const char *smallclueTopPtyLabel(const VProcSnapshot *snap, char *buf, size_t buf_size) {
    if (!buf || buf_size == 0) {
        return "-";
    }
    if (!snap || snap->tty_pty_num < 0) {
        snprintf(buf, buf_size, "-");
        return buf;
    }
    snprintf(buf, buf_size, "pts/%d", snap->tty_pty_num);
    return buf;
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
            int mn;
            if (isatty(STDOUT_FILENO)) {
                mn = snprintf(mem_line, sizeof(mem_line),
                              "\033[7mMem: %zuK used, %zuK free\033[0m\n",
                              mem_used_kb, mem_free_kb);
            } else {
                mn = snprintf(mem_line, sizeof(mem_line),
                              "Mem: %zuK used, %zuK free\n",
                              mem_used_kb, mem_free_kb);
            }
            if (mn > 0) {
                (void)smallclueWriteAll(STDOUT_FILENO, mem_line, (size_t)mn);
            }
        }
        double cpu_usr = 0, cpu_sys = 0, cpu_nice = 0, cpu_idle = 0;
        if (smallclueReadCpuStats(&cpu_usr, &cpu_sys, &cpu_nice, &cpu_idle)) {
            char cpu_line[160];
            int cn;
            if (isatty(STDOUT_FILENO)) {
                cn = snprintf(cpu_line, sizeof(cpu_line),
                              "\033[7mCPU: %3.0f%% usr %3.0f%% sys %3.0f%% nic %3.0f%% idle\033[0m\n\n",
                              cpu_usr, cpu_sys, cpu_nice, cpu_idle);
            } else {
                cn = snprintf(cpu_line, sizeof(cpu_line),
                              "CPU: %3.0f%% usr %3.0f%% sys %3.0f%% nic %3.0f%% idle\n\n",
                              cpu_usr, cpu_sys, cpu_nice, cpu_idle);
            }
            if (cn > 0) {
                (void)smallclueWriteAll(STDOUT_FILENO, cpu_line, (size_t)cn);
            }
        }
#endif

        char header[160];
        int hn;
        if (isatty(STDOUT_FILENO)) {
            hn = snprintf(header, sizeof(header),
                          "\033[7m%6s %6s %6s %6s %-3s %-8s %-10s %6s %6s %s\033[0m\n",
                          "PID", "PPID", "PGID", "SID", "FG", "PTY", "STATE", "UTIME", "STIME", "CMD");
        } else {
            hn = snprintf(header, sizeof(header),
                          "%6s %6s %6s %6s %-3s %-8s %-10s %6s %6s %s\n",
                          "PID", "PPID", "PGID", "SID", "FG", "PTY", "STATE", "UTIME", "STIME", "CMD");
        }
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
                    char pty_label[16];
                    (void)smallclueTopPtyLabel(snap, pty_label, sizeof(pty_label));

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
                                     "%6d %6d %6d %6d %-3s %-8s %-10s %6.1f %6.1f %s%s\n",
                                     snap->pid, snap->parent_pid, snap->pgid, snap->sid,
                                     fg ? "fg" : "", pty_label, state, ut_s, st_s, indent, cmd);
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
                char pty_label[16];
                (void)smallclueTopPtyLabel(snap, pty_label, sizeof(pty_label));
                double ut_s = 0.0, st_s = 0.0;
                vprocFormatCpuTimes(snap->rusage_utime, snap->rusage_stime, &ut_s, &st_s);
                char line[320];
                int n = snprintf(line, sizeof(line),
                                 "%6d %6d %6d %6d %-3s %-8s %-10s %6.1f %6.1f %s\n",
                                 snap->pid, snap->parent_pid, snap->pgid, snap->sid,
                                 fg ? "fg" : "", pty_label, state, ut_s, st_s, cmd);
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
#else
/* Real /proc-based top for the Linux/aarch64 guest target (and any other
 * non-iOS build with a /proc filesystem). Reuses the same /proc/[pid]/stat
 * parsing approach as smallcluePsCommand's non-iOS branch, extended to
 * also pull utime/stime/rss so per-process %CPU/%MEM can be computed. */
typedef struct {
    int pid;
    int ppid;
    uid_t uid;
    char state;
    unsigned long long cpu_ticks;
    long rss_kb;
    char *command;
    double cpu_percent;
    double mem_percent;
} SmallclueTopEntry;

typedef struct {
    int pid;
    unsigned long long cpu_ticks;
} SmallclueTopPrevTicks;

static bool smallclueTopReadProcStatTotal(unsigned long long *total_out, unsigned long long *idle_out) {
    FILE *fp = fopen("/proc/stat", "r");
    if (!fp) return false;
    char line[512];
    bool ok = false;
    if (fgets(line, sizeof(line), fp)) {
        unsigned long long user = 0, nice_ = 0, system_ = 0, idle = 0;
        unsigned long long iowait = 0, irq = 0, softirq = 0, steal = 0;
        int n = sscanf(line, "cpu %llu %llu %llu %llu %llu %llu %llu %llu",
                        &user, &nice_, &system_, &idle, &iowait, &irq, &softirq, &steal);
        if (n >= 4) {
            if (total_out) {
                *total_out = user + nice_ + system_ + idle + iowait + irq + softirq + steal;
            }
            if (idle_out) *idle_out = idle + iowait;
            ok = true;
        }
    }
    fclose(fp);
    return ok;
}

static bool smallclueTopReadMemInfo(size_t *total_kb, size_t *used_kb) {
    FILE *fp = fopen("/proc/meminfo", "r");
    if (!fp) return false;
    char line[256];
    unsigned long long total = 0, avail = 0, free_ = 0, buffers = 0, cached = 0;
    bool haveAvail = false;
    while (fgets(line, sizeof(line), fp)) {
        unsigned long long val = 0;
        if (sscanf(line, "MemTotal: %llu kB", &val) == 1) total = val;
        else if (sscanf(line, "MemAvailable: %llu kB", &val) == 1) { avail = val; haveAvail = true; }
        else if (sscanf(line, "MemFree: %llu kB", &val) == 1) free_ = val;
        else if (sscanf(line, "Buffers: %llu kB", &val) == 1) buffers = val;
        else if (sscanf(line, "Cached: %llu kB", &val) == 1) cached = val;
    }
    fclose(fp);
    if (total == 0) return false;
    unsigned long long availTotal = haveAvail ? avail : (free_ + buffers + cached);
    if (total_kb) *total_kb = (size_t)total;
    if (used_kb) *used_kb = (size_t)(total > availTotal ? total - availTotal : 0);
    return true;
}

static bool smallclueTopReadLoadAvg(double load[3]) {
    FILE *fp = fopen("/proc/loadavg", "r");
    if (!fp) return false;
    bool ok = (fscanf(fp, "%lf %lf %lf", &load[0], &load[1], &load[2]) == 3);
    fclose(fp);
    return ok;
}

static int smallclueTopCompareEntries(const void *a, const void *b) {
    const SmallclueTopEntry *ea = (const SmallclueTopEntry *)a;
    const SmallclueTopEntry *eb = (const SmallclueTopEntry *)b;
    if (ea->cpu_percent != eb->cpu_percent) {
        return (ea->cpu_percent > eb->cpu_percent) ? -1 : 1;
    }
    return ea->pid - eb->pid;
}

static size_t smallclueTopCollect(SmallclueTopEntry **out_entries) {
    *out_entries = NULL;
    DIR *dir = opendir("/proc");
    if (!dir) return 0;

    SmallclueTopEntry *entries = NULL;
    size_t count = 0, capacity = 0;
    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL) {
        if (!isdigit((unsigned char)ent->d_name[0])) continue;
        int pid = atoi(ent->d_name);
        char path[PATH_MAX];

        snprintf(path, sizeof(path), "/proc/%s/stat", ent->d_name);
        FILE *fp = fopen(path, "r");
        if (!fp) continue;
        char buf[1024];
        if (!fgets(buf, sizeof(buf), fp)) {
            fclose(fp);
            continue;
        }
        fclose(fp);

        char *open_paren = strchr(buf, '(');
        char *close_paren = strrchr(buf, ')');
        if (!open_paren || !close_paren || close_paren <= open_paren) continue;
        *close_paren = '\0';
        char *comm_short = open_paren + 1;
        char *rest = close_paren + 1;

        char state = '?';
        int ppid = 0;
        unsigned long utime = 0, stime = 0;
        long rss_pages = 0;
        int n = sscanf(rest,
                       " %c %d %*d %*d %*d %*d %*u %*lu %*lu %*lu %*lu"
                       " %lu %lu %*ld %*ld %*ld %*ld %*ld %*ld %*llu %*lu %ld",
                       &state, &ppid, &utime, &stime, &rss_pages);
        if (n < 5) continue;

        struct stat st;
        uid_t uid = 0;
        snprintf(path, sizeof(path), "/proc/%s", ent->d_name);
        if (stat(path, &st) == 0) uid = st.st_uid;

        char *command = NULL;
        snprintf(path, sizeof(path), "/proc/%s/cmdline", ent->d_name);
        fp = fopen(path, "r");
        if (fp) {
            char cmdline[1024];
            size_t len = fread(cmdline, 1, sizeof(cmdline) - 1, fp);
            fclose(fp);
            if (len > 0) {
                cmdline[len] = '\0';
                for (size_t i = 0; i < len; ++i) {
                    if (cmdline[i] == '\0') cmdline[i] = ' ';
                }
                if (cmdline[len - 1] == ' ') cmdline[len - 1] = '\0';
                if (cmdline[0] != '\0') command = strdup(cmdline);
            }
        }
        if (!command) command = strdup(comm_short);
        if (!command) continue;

        if (count == capacity) {
            size_t new_cap = capacity ? capacity * 2 : 32;
            SmallclueTopEntry *resized = (SmallclueTopEntry *)realloc(entries, new_cap * sizeof(SmallclueTopEntry));
            if (!resized) {
                free(command);
                break;
            }
            entries = resized;
            capacity = new_cap;
        }
        entries[count].pid = pid;
        entries[count].ppid = ppid;
        entries[count].uid = uid;
        entries[count].state = state;
        entries[count].cpu_ticks = (unsigned long long)utime + (unsigned long long)stime;
        long page_kb = sysconf(_SC_PAGESIZE) / 1024;
        if (page_kb <= 0) page_kb = 4;
        entries[count].rss_kb = rss_pages * page_kb;
        entries[count].command = command;
        entries[count].cpu_percent = 0.0;
        entries[count].mem_percent = 0.0;
        count++;
    }
    closedir(dir);
    *out_entries = entries;
    return count;
}

static unsigned long long smallclueTopPrevTicksFor(const SmallclueTopPrevTicks *prev, size_t prev_count, int pid) {
    for (size_t i = 0; i < prev_count; ++i) {
        if (prev[i].pid == pid) return prev[i].cpu_ticks;
    }
    return 0;
}

static int smallclueTopCommand(int argc, char **argv) {
    smallclueResetGetopt();
    smallclueClearPendingSignals();
    double delay = 3.0;
    int max_iterations = -1;
    bool batch = !isatty(STDOUT_FILENO);

    for (int i = 1; i < argc; ++i) {
        const char *arg = argv[i];
        if (strcmp(arg, "-d") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "top: option requires an argument -- 'd'\n");
                return 1;
            }
            char *end = NULL;
            delay = strtod(argv[++i], &end);
            if (!end || *end != '\0' || delay <= 0.0) {
                fprintf(stderr, "top: invalid delay '%s'\n", argv[i]);
                return 1;
            }
        } else if (strcmp(arg, "-n") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "top: option requires an argument -- 'n'\n");
                return 1;
            }
            char *end = NULL;
            long count = strtol(argv[++i], &end, 10);
            if (!end || *end != '\0' || count <= 0 || count > INT_MAX) {
                fprintf(stderr, "top: invalid count '%s'\n", argv[i]);
                return 1;
            }
            max_iterations = (int)count;
        } else if (strcmp(arg, "-b") == 0) {
            batch = true;
        } else if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
            fputs("top [-d SECONDS] [-n COUNT] [-b]\n"
                  "  Show real system processes, sorted by %CPU.\n"
                  "  -d SECONDS refresh delay (default 3)\n"
                  "  -n COUNT   exit after COUNT frames (default: run until interrupted)\n"
                  "  -b         batch mode: never clear the screen, print every frame\n",
                  stdout);
            return 0;
        } else {
            fprintf(stderr, "top: unsupported option '%s'\n", arg);
            return 1;
        }
    }

    long ticks_per_sec = sysconf(_SC_CLK_TCK);
    if (ticks_per_sec <= 0) ticks_per_sec = 100;

    /* Take a throwaway baseline sample so the first displayed frame has a
     * meaningful (non-zero) %CPU instead of always reading 0.0 -- matters
     * for the common single-shot `top -b -n 1` scripted invocation, which
     * would otherwise never get a second sample to diff against. */
    SmallclueTopPrevTicks *prev = NULL;
    size_t prev_count = 0;
    unsigned long long prev_total_ticks = 0, prev_idle_ticks = 0;
    struct timespec prev_wall = {0, 0};
    {
        SmallclueTopEntry *baseline = NULL;
        size_t baseline_count = smallclueTopCollect(&baseline);
        prev = (SmallclueTopPrevTicks *)calloc(baseline_count ? baseline_count : 1, sizeof(SmallclueTopPrevTicks));
        if (prev) {
            for (size_t i = 0; i < baseline_count; ++i) {
                prev[i].pid = baseline[i].pid;
                prev[i].cpu_ticks = baseline[i].cpu_ticks;
            }
            prev_count = baseline_count;
        }
        for (size_t i = 0; i < baseline_count; ++i) free(baseline[i].command);
        free(baseline);
        smallclueTopReadProcStatTotal(&prev_total_ticks, &prev_idle_ticks);
        clock_gettime(CLOCK_MONOTONIC, &prev_wall);
        struct timespec primeSleep = {0, 200 * 1000 * 1000};
        nanosleep(&primeSleep, NULL);
    }

    int status = 0;
    int iterations = 0;
    while (1) {
        int abort_status = 0;
        if (smallclueShouldAbort(&abort_status)) {
            status = abort_status;
            break;
        }

        SmallclueTopEntry *entries = NULL;
        size_t count = smallclueTopCollect(&entries);

        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        double wall_delta = (double)(now.tv_sec - prev_wall.tv_sec) +
                             (double)(now.tv_nsec - prev_wall.tv_nsec) / 1e9;
        if (wall_delta <= 0.0) wall_delta = 0.001;

        unsigned long long total_ticks = 0, idle_ticks = 0;
        smallclueTopReadProcStatTotal(&total_ticks, &idle_ticks);
        unsigned long long total_delta = (total_ticks > prev_total_ticks) ? (total_ticks - prev_total_ticks) : 0;
        unsigned long long idle_delta = (idle_ticks > prev_idle_ticks) ? (idle_ticks - prev_idle_ticks) : 0;
        double aggregate_cpu_pct = (total_delta > 0)
            ? 100.0 * (double)(total_delta - idle_delta) / (double)total_delta
            : 0.0;

        size_t mem_total_kb = 0, mem_used_kb = 0;
        bool haveMem = smallclueTopReadMemInfo(&mem_total_kb, &mem_used_kb);

        for (size_t i = 0; i < count; ++i) {
            unsigned long long prevTicks = smallclueTopPrevTicksFor(prev, prev_count, entries[i].pid);
            unsigned long long deltaTicks = (entries[i].cpu_ticks > prevTicks) ? (entries[i].cpu_ticks - prevTicks) : 0;
            /* %CPU relative to a single core over the elapsed wall-clock
             * interval -- a fully busy single-threaded process reads
             * ~100%, matching real top/ps convention (can exceed 100% for
             * multi-threaded processes spanning multiple cores). */
            entries[i].cpu_percent = 100.0 * (double)deltaTicks / ((double)ticks_per_sec * wall_delta);
            if (haveMem && mem_total_kb > 0) {
                entries[i].mem_percent = 100.0 * (double)entries[i].rss_kb / (double)mem_total_kb;
            }
        }

        qsort(entries, count, sizeof(SmallclueTopEntry), smallclueTopCompareEntries);

        if (!batch && isatty(STDOUT_FILENO)) {
            fputs("\x1b[3J\x1b[H\x1b[2J", stdout);
        }

        double load[3] = {0, 0, 0};
        bool haveLoad = smallclueTopReadLoadAvg(load);
        if (haveLoad) {
            printf("Tasks: %zu total   load average: %.2f, %.2f, %.2f\n", count, load[0], load[1], load[2]);
        } else {
            printf("Tasks: %zu total\n", count);
        }
        printf("Cpu(s): %.1f%% used, %.1f%% idle\n", aggregate_cpu_pct, 100.0 - aggregate_cpu_pct);
        if (haveMem) {
            printf("Mem: %zuK total, %zuK used, %zuK free\n", mem_total_kb,
                   mem_used_kb, mem_total_kb > mem_used_kb ? mem_total_kb - mem_used_kb : 0);
        }
        printf("\n  %5s %5s %-8s %s %7s %6s %s\n", "PID", "PPID", "USER", "S", "%CPU", "%MEM", "COMMAND");

        int rows = -1, cols = -1;
        if (!batch && isatty(STDOUT_FILENO)) {
            smallclueGetTerminalSize(&rows, &cols);
        }
        size_t visible = count;
        if (rows > 6) {
            size_t cap = (size_t)(rows - 6);
            if (cap < visible) visible = cap;
        }
        for (size_t i = 0; i < visible; ++i) {
            struct passwd *pw = getpwuid(entries[i].uid);
            char user_buf[32];
            if (pw) {
                snprintf(user_buf, sizeof(user_buf), "%s", pw->pw_name);
            } else {
                snprintf(user_buf, sizeof(user_buf), "%d", (int)entries[i].uid);
            }
            printf("  %5d %5d %-8s %c %7.1f %6.1f %s\n",
                   entries[i].pid, entries[i].ppid, user_buf, entries[i].state,
                   entries[i].cpu_percent, entries[i].mem_percent, entries[i].command);
        }
        fflush(stdout);

        /* Build next iteration's prev-ticks table directly from the
         * entries we already have in hand -- no need to re-walk /proc. */
        free(prev);
        prev = (SmallclueTopPrevTicks *)calloc(count ? count : 1, sizeof(SmallclueTopPrevTicks));
        if (prev) {
            for (size_t i = 0; i < count; ++i) {
                prev[i].pid = entries[i].pid;
                prev[i].cpu_ticks = entries[i].cpu_ticks;
            }
            prev_count = count;
        } else {
            prev_count = 0;
        }
        prev_total_ticks = total_ticks;
        prev_idle_ticks = idle_ticks;
        prev_wall = now;

        for (size_t i = 0; i < count; ++i) free(entries[i].command);
        free(entries);

        if (max_iterations > 0) {
            iterations++;
            if (iterations >= max_iterations) break;
        }

        struct timespec ts;
        ts.tv_sec = (time_t)delay;
        ts.tv_nsec = (long)((delay - (double)ts.tv_sec) * 1e9);
        if (ts.tv_nsec < 0) ts.tv_nsec = 0;
        while (nanosleep(&ts, &ts) == -1 && errno == EINTR) {
            if (smallclueShouldAbort(&abort_status)) {
                status = abort_status;
                free(prev);
                return status;
            }
        }
    }

    free(prev);
    return status;
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

/* Parses a duration like "5", "2.5", "3s", "1m", "2h", "1d" into seconds. */
static bool smallclueTimeoutParseDuration(const char *s, double *out) {
    if (!s || !*s) return false;
    char *end = NULL;
    errno = 0;
    double v = strtod(s, &end);
    if (errno != 0 || end == s || v < 0) return false;
    double mult = 1.0;
    if (*end != '\0') {
        if (end[1] != '\0') return false;
        switch (*end) {
            case 's': mult = 1.0; break;
            case 'm': mult = 60.0; break;
            case 'h': mult = 3600.0; break;
            case 'd': mult = 86400.0; break;
            default: return false;
        }
    }
    *out = v * mult;
    return true;
}

/* Runs COMMAND in its own process group with a wall-clock time limit,
 * sending it a signal (default TERM) if it hasn't exited by then, and
 * escalating to KILL after --kill-after if it's still alive. Polls with
 * waitpid(WNOHANG) rather than relying on SIGALRM/itimers, matching the
 * simple portable style used elsewhere in this file (e.g. init's reap
 * loop) instead of adding signal-handler state. */
static int smallclueTimeoutCommand(int argc, char **argv) {
    int signalToSend = SIGTERM;
    double killAfter = 0.0;
    bool preserveStatus = false;

    int argi = 1;
    for (; argi < argc; ++argi) {
        const char *arg = argv[argi];
        if (strcmp(arg, "--") == 0) {
            argi++;
            break;
        }
        if (strcmp(arg, "-s") == 0 || strcmp(arg, "--signal") == 0) {
            if (argi + 1 >= argc || !smallclueParseSignal(argv[argi + 1], &signalToSend)) {
                fprintf(stderr, "timeout: invalid signal\n");
                return 125;
            }
            argi++;
        } else if (strncmp(arg, "--signal=", 9) == 0) {
            if (!smallclueParseSignal(arg + 9, &signalToSend)) {
                fprintf(stderr, "timeout: invalid signal '%s'\n", arg + 9);
                return 125;
            }
        } else if (strncmp(arg, "-s", 2) == 0 && arg[2] != '\0') {
            if (!smallclueParseSignal(arg + 2, &signalToSend)) {
                fprintf(stderr, "timeout: invalid signal '%s'\n", arg + 2);
                return 125;
            }
        } else if (strcmp(arg, "-k") == 0 || strcmp(arg, "--kill-after") == 0) {
            if (argi + 1 >= argc || !smallclueTimeoutParseDuration(argv[argi + 1], &killAfter)) {
                fprintf(stderr, "timeout: invalid duration\n");
                return 125;
            }
            argi++;
        } else if (strncmp(arg, "--kill-after=", 13) == 0) {
            if (!smallclueTimeoutParseDuration(arg + 13, &killAfter)) {
                fprintf(stderr, "timeout: invalid duration '%s'\n", arg + 13);
                return 125;
            }
        } else if (strcmp(arg, "--preserve-status") == 0) {
            preserveStatus = true;
        } else if (arg[0] == '-' && arg[1] != '\0') {
            fprintf(stderr, "timeout: unknown option '%s'\n", arg);
            return 125;
        } else {
            break;
        }
    }

    if (argi >= argc) {
        fprintf(stderr, "timeout: missing duration\n");
        return 125;
    }
    double duration;
    if (!smallclueTimeoutParseDuration(argv[argi], &duration)) {
        fprintf(stderr, "timeout: invalid duration '%s'\n", argv[argi]);
        return 125;
    }
    argi++;
    if (argi >= argc) {
        fprintf(stderr, "timeout: missing command\n");
        return 125;
    }
    char **cmdArgv = &argv[argi];

    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "timeout: fork: %s\n", strerror(errno));
        return 125;
    }
    if (pid == 0) {
        setpgid(0, 0);
        execvp(cmdArgv[0], cmdArgv);
        fprintf(stderr, "timeout: %s: %s\n", cmdArgv[0], strerror(errno));
        _exit(127);
    }
    setpgid(pid, pid);

    struct timespec start;
    clock_gettime(CLOCK_MONOTONIC, &start);
    bool timedOut = false;
    bool killSent = false;
    struct timespec signalSentAt = {0, 0};
    int status = 0;
    for (;;) {
        pid_t r = waitpid(pid, &status, WNOHANG);
        if (r == pid) break;
        if (r < 0 && errno != EINTR) {
            fprintf(stderr, "timeout: waitpid: %s\n", strerror(errno));
            return 125;
        }
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        double elapsed = (double)(now.tv_sec - start.tv_sec) +
                          (double)(now.tv_nsec - start.tv_nsec) / 1e9;
        if (!timedOut && elapsed >= duration) {
            kill(-pid, signalToSend);
            timedOut = true;
            signalSentAt = now;
        } else if (timedOut && killAfter > 0.0 && !killSent) {
            double sinceSignal = (double)(now.tv_sec - signalSentAt.tv_sec) +
                                   (double)(now.tv_nsec - signalSentAt.tv_nsec) / 1e9;
            if (sinceSignal >= killAfter) {
                kill(-pid, SIGKILL);
                killSent = true;
            }
        }
        struct timespec pollInterval = {0, 20 * 1000 * 1000};
        nanosleep(&pollInterval, NULL);
    }

    if (timedOut) {
        if (preserveStatus) {
            if (WIFEXITED(status)) return WEXITSTATUS(status);
            if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
            return 1;
        }
        return 124;
    }
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
    return 1;
}

/* xargs -I REPLACE mode: builds one invocation's argv by substituting
 * every base-arg token that equals `replaceStr` with `value`. Returns a
 * NULL-terminated argv the caller must free (each element + the array). */
/* Replaces every occurrence of `needle` in `haystack` with `value`
 * (matching GNU xargs -I, which substitutes the placeholder wherever it
 * appears WITHIN an argument -- e.g. `echo "file: {}"` -- not only when
 * the entire argument equals the placeholder). Returns a newly allocated
 * string the caller must free. */
static char *smallclueXargsSubstitute(const char *haystack, const char *needle, const char *value) {
    size_t needleLen = strlen(needle);
    size_t valueLen = strlen(value);
    size_t count = 0;
    for (const char *p = haystack; (p = strstr(p, needle)) != NULL; p += needleLen) {
        count++;
    }
    size_t resultLen = strlen(haystack) + count * (valueLen > needleLen ? valueLen - needleLen : 0) + 1;
    if (valueLen < needleLen) {
        resultLen = strlen(haystack) + 1;
    }
    char *result = (char *)malloc(resultLen);
    if (!result) return NULL;
    char *out = result;
    const char *cursor = haystack;
    const char *match;
    while ((match = strstr(cursor, needle)) != NULL) {
        size_t prefixLen = (size_t)(match - cursor);
        memcpy(out, cursor, prefixLen);
        out += prefixLen;
        memcpy(out, value, valueLen);
        out += valueLen;
        cursor = match + needleLen;
    }
    strcpy(out, cursor);
    return result;
}

static char **smallclueXargsBuildIArgv(char **baseArgs, int baseCount, const char *replaceStr, const char *value) {
    char **cmdArgv = (char **)calloc((size_t)baseCount + 1, sizeof(char *));
    if (!cmdArgv) return NULL;
    for (int i = 0; i < baseCount; ++i) {
        cmdArgv[i] = smallclueXargsSubstitute(baseArgs[i], replaceStr, value);
        if (!cmdArgv[i]) {
            for (int k = 0; k < i; ++k) free(cmdArgv[k]);
            free(cmdArgv);
            return NULL;
        }
    }
    return cmdArgv;
}

static void smallclueXargsFreeArgv(char **cmdArgv, int count) {
    if (!cmdArgv) return;
    for (int i = 0; i < count; ++i) {
        free(cmdArgv[i]);
    }
    free(cmdArgv);
}

static int smallclueXargsCommand(int argc, char **argv) {
    bool nulDelimited = false;
    bool verbose = false;
    const char *replaceStr = NULL;
    int maxArgsPerInvocation = 0; /* 0 = unlimited (one invocation, all args) */

    int argi = 1;
    for (; argi < argc; ++argi) {
        const char *arg = argv[argi];
        if (strcmp(arg, "--") == 0) {
            argi++;
            break;
        }
        if (strcmp(arg, "-0") == 0) {
            nulDelimited = true;
        } else if (strcmp(arg, "-t") == 0) {
            verbose = true;
        } else if (strncmp(arg, "-I", 2) == 0 && arg[2] != '\0') {
            /* Attached form, e.g. `-I{}` -- the common real-world spelling
             * (`find . | xargs -I{} cmd {}`), not just `-I {}` separately. */
            replaceStr = arg + 2;
        } else if (strcmp(arg, "-I") == 0) {
            if (argi + 1 >= argc) {
                fprintf(stderr, "xargs: -I requires a replacement string\n");
                return 1;
            }
            replaceStr = argv[++argi];
        } else if (strcmp(arg, "-n") == 0) {
            if (argi + 1 >= argc) {
                fprintf(stderr, "xargs: -n requires a count\n");
                return 1;
            }
            maxArgsPerInvocation = atoi(argv[++argi]);
        } else if (arg[0] == '-' && arg[1] != '\0') {
            fprintf(stderr, "xargs: unsupported option '%s'\n", arg);
            return 1;
        } else {
            break;
        }
    }
    if (argi >= argc) {
        fprintf(stderr, "xargs: missing command name\n");
        return 1;
    }
    int baseCount = argc - argi;
    char **baseArgs = &argv[argi];

    int status = 0;

    if (replaceStr) {
        /* -I mode: one invocation per input LINE (not per whitespace
         * token), substituting `replaceStr` wherever it appears in the
         * base command's own args. */
        SmallclueLineVector lines = {0};
        if (!smallclueReadLinesFromStdin(&lines, nulDelimited)) {
            perror("xargs");
            smallclueLineVectorFree(&lines);
            return 1;
        }
        for (size_t i = 0; i < lines.count; ++i) {
            if (lines.items[i][0] == '\0') continue;
            char **cmdArgv = smallclueXargsBuildIArgv(baseArgs, baseCount, replaceStr, lines.items[i]);
            if (!cmdArgv) {
                perror("xargs");
                status = 1;
                continue;
            }
            int rc = smallclueXargsRunOne(cmdArgv, baseCount, verbose);
            if (rc != 0) status = 1;
            smallclueXargsFreeArgv(cmdArgv, baseCount);
        }
        smallclueLineVectorFree(&lines);
        return status;
    }

    SmallclueLineVector extra = {0};
    bool ok = nulDelimited ? smallclueReadNulTokensFromStdin(&extra) : smallclueReadTokensFromStdin(&extra);
    if (!ok) {
        /* smallclueReadTokensFromStdin already reports unmatched-quote
         * errors itself; only an out-of-memory condition reaches here
         * without having printed anything, so perror() still applies. */
        if (!nulDelimited && errno == 0) {
            /* message already printed */
        } else {
            perror("xargs");
        }
        smallclueLineVectorFree(&extra);
        return 1;
    }

    size_t batchSize = maxArgsPerInvocation > 0 ? (size_t)maxArgsPerInvocation : extra.count;
    if (batchSize == 0) {
        /* No input tokens at all: still run once with just the base
         * command (matches traditional xargs, which runs the command
         * with no extra args rather than skipping it, unless --no-run-
         * if-empty is requested -- not implemented here). */
        char **cmdArgv = (char **)calloc((size_t)baseCount + 1, sizeof(char *));
        if (!cmdArgv) {
            perror("xargs");
            smallclueLineVectorFree(&extra);
            return 1;
        }
        for (int i = 0; i < baseCount; ++i) {
            cmdArgv[i] = strdup(baseArgs[i]);
        }
        status = smallclueXargsRunOne(cmdArgv, baseCount, verbose);
        smallclueXargsFreeArgv(cmdArgv, baseCount);
        smallclueLineVectorFree(&extra);
        return status;
    }

    for (size_t start = 0; start < extra.count; start += batchSize) {
        size_t end = start + batchSize;
        if (end > extra.count) end = extra.count;
        size_t batchCount = end - start;
        size_t total = (size_t)baseCount + batchCount;
        char **cmdArgv = (char **)calloc(total + 1, sizeof(char *));
        if (!cmdArgv) {
            perror("xargs");
            status = 1;
            break;
        }
        size_t index = 0;
        for (int i = 0; i < baseCount; ++i) {
            cmdArgv[index++] = strdup(baseArgs[i]);
        }
        for (size_t i = start; i < end; ++i) {
            cmdArgv[index++] = strdup(extra.items[i]);
        }
        int rc = smallclueXargsRunOne(cmdArgv, (int)total, verbose);
        if (rc != 0) status = 1;
        smallclueXargsFreeArgv(cmdArgv, (int)total);
    }
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

/* qsort's comparator signature has no room for a context pointer, so sort's
 * extra options (numeric/key-field/separator) live in this file-scope
 * struct, set immediately before the one qsort() call that uses it. */
typedef struct {
    bool numeric;
    bool haveKey;
    int keyField; /* 1-based; the key runs from here to end-of-line, matching
                    * GNU sort's own semantics for a bare "-k N" (no ",M" end
                    * field) */
    char keySep;  /* 0 = split on runs of whitespace (GNU sort's default) */
} SmallclueSortOptions;

static SmallclueSortOptions gSmallclueSortOpts;

/* Returns a pointer into `line` (no copy) at the start of the requested
 * sort key -- either the whole line, or from the Nth field onward. */
static const char *smallclueSortKeyOf(const char *line) {
    if (!gSmallclueSortOpts.haveKey) {
        return line;
    }
    const char *p = line;
    int field = 1;
    while (field < gSmallclueSortOpts.keyField && *p) {
        if (gSmallclueSortOpts.keySep) {
            while (*p && *p != gSmallclueSortOpts.keySep) p++;
            if (*p) p++;
        } else {
            while (*p && isspace((unsigned char)*p)) p++;
            while (*p && !isspace((unsigned char)*p)) p++;
            while (*p && isspace((unsigned char)*p)) p++;
        }
        field++;
    }
    return p;
}

static int smallclueSortCompare(const void *a, const void *b) {
    const char *lhs = *(const char *const *)a;
    const char *rhs = *(const char *const *)b;
    const char *lkey = smallclueSortKeyOf(lhs);
    const char *rkey = smallclueSortKeyOf(rhs);
    if (gSmallclueSortOpts.numeric) {
        double lv = strtod(lkey, NULL);
        double rv = strtod(rkey, NULL);
        if (lv < rv) return -1;
        if (lv > rv) return 1;
        return 0;
    }
    return strcmp(lkey, rkey);
}

/* qsort() isn't guaranteed stable, but GNU sort documents itself as
 * stable (equal-key lines keep their original relative order). A simple
 * bottom-up-recursive merge sort gives that for free (merge always
 * takes the left/earlier run on a tie) without needing to smuggle an
 * original-index tiebreaker through qsort's context-free comparator. */
static void smallclueSortStableMerge(char **arr, char **temp, size_t lo, size_t mid, size_t hi) {
    size_t i = lo, j = mid, k = lo;
    while (i < mid && j < hi) {
        if (smallclueSortCompare(&arr[i], &arr[j]) <= 0) {
            temp[k++] = arr[i++];
        } else {
            temp[k++] = arr[j++];
        }
    }
    while (i < mid) temp[k++] = arr[i++];
    while (j < hi) temp[k++] = arr[j++];
    for (size_t x = lo; x < hi; ++x) arr[x] = temp[x];
}

static void smallclueSortStableRec(char **arr, char **temp, size_t lo, size_t hi) {
    if (hi - lo <= 1) return;
    size_t mid = lo + (hi - lo) / 2;
    smallclueSortStableRec(arr, temp, lo, mid);
    smallclueSortStableRec(arr, temp, mid, hi);
    smallclueSortStableMerge(arr, temp, lo, mid, hi);
}

static void smallclueSortStable(char **arr, size_t count) {
    if (count < 2) return;
    char **temp = (char **)malloc(count * sizeof(char *));
    if (!temp) {
        qsort(arr, count, sizeof(char *), smallclueSortCompare);
        return;
    }
    smallclueSortStableRec(arr, temp, 0, count);
    free(temp);
}

/* -c/--check: verifies the input is already ordered per the current
 * comparator/reverse settings, printing GNU sort's "disorder" diagnostic
 * (unless quiet) and returning 1 on the first out-of-order pair. */
static int smallclueSortCheckOrder(const SmallclueLineVector *vec, bool reverse, bool quiet, const char *label) {
    for (size_t i = 1; i < vec->count; ++i) {
        int cmp = smallclueSortCompare(&vec->items[i - 1], &vec->items[i]);
        bool outOfOrder = reverse ? (cmp < 0) : (cmp > 0);
        if (outOfOrder) {
            if (!quiet) {
                char *lineCopy = strdup(vec->items[i]);
                if (lineCopy) {
                    size_t len = strlen(lineCopy);
                    if (len > 0 && lineCopy[len - 1] == '\n') lineCopy[len - 1] = '\0';
                    fprintf(stderr, "sort: %s:%zu: disorder: %s\n", label ? label : "-", i + 1, lineCopy);
                    free(lineCopy);
                }
            }
            return 1;
        }
    }
    return 0;
}

static FILE *smallclueOpenTempFile(const char *tag) {
#if defined(PSCAL_TARGET_IOS)
    const char *tmp_root = getenv("TMPDIR");
    if (!tmp_root || !*tmp_root) {
        tmp_root = "/tmp";
    }
    const char *name = (tag && *tag) ? tag : "tmp";
    char tmpl[PATH_MAX];
    snprintf(tmpl, sizeof(tmpl), "%s/smallclue-%s-XXXXXX", tmp_root, name);
    int fd = mkstemp(tmpl);
    if (fd < 0) {
        return NULL;
    }
    int tracked_fd = vprocHostDup(fd);
    if (tracked_fd >= 0) {
        close(fd);
        fd = tracked_fd;
    }
    FILE *fp = fdopen(fd, "w+b");
    if (!fp) {
        close(fd);
        unlink(tmpl);
        return NULL;
    }
    unlink(tmpl);
    return fp;
#else
    (void)tag;
    return tmpfile();
#endif
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
#if defined(PSCAL_TARGET_IOS)
    /*
     * mkstemp() may bypass vproc's open tracking on iOS. Move the descriptor
     * to a vproc-tracked duplicate so stdio writes are permitted by shim
     * fallback hardening.
     */
    int tracked_fd = vprocHostDup(fd);
    if (tracked_fd >= 0) {
        close(fd);
        fd = tracked_fd;
    }
#endif
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
            int write_err = 0;
            if (!smallclueWriteFullyStream(fp, buf, (size_t)read_bytes, &write_err)) {
                fprintf(stderr, "%s: failed to buffer pager input: %s\n",
                        pager_command_name(cmd_name),
                        strerror(write_err ? write_err : EIO));
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

static void smallclueSanitizeAndPrint(const char *data, size_t len, FILE *out) {
    if (!data) return;
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = (unsigned char)data[i];
        if (c == '\0') break;
        if (c == 0x7F) {
            fputc('^', out);
            fputc('?', out);
        } else if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') {
            fputc('^', out);
            fputc(c + 0x40, out);
        } else {
            fputc(c, out);
        }
    }
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
                if (buffer->raw_mode) {
                    fwrite(line, 1, prefix_len, stdout);
                } else {
                    smallclueSanitizeAndPrint(line, prefix_len, stdout);
                }
                fputs("\x1b[7m", stdout);
                if (buffer->raw_mode) {
                    fwrite(hit, 1, strlen(highlight_target), stdout);
                } else {
                    smallclueSanitizeAndPrint(hit, strlen(highlight_target), stdout);
                }
                fputs("\x1b[0m", stdout);
                if (buffer->raw_mode) {
                    fputs(hit + strlen(highlight_target), stdout);
                } else {
                    smallclueSanitizeAndPrint(hit + strlen(highlight_target), SIZE_MAX, stdout);
                }
            } else {
                if (buffer->raw_mode) {
                    fputs(line, stdout);
                } else {
                    smallclueSanitizeAndPrint(line, SIZE_MAX, stdout);
                }
            }
        } else {
            if (buffer->raw_mode) {
                fputs(line, stdout);
            } else {
                smallclueSanitizeAndPrint(line, SIZE_MAX, stdout);
            }
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

static int pagerPromptAndRead(const char *cmd_name, const char *detail) {
    const char *label = pager_command_name(cmd_name);
    bool md_mode = (label && strcmp(label, "md") == 0);
    bool color = isatty(STDOUT_FILENO);
    const char *inv = color ? "\033[7m" : "";
    const char *rst = color ? "\033[0m" : "";
    if (detail && *detail) {
        if (md_mode) {
            fprintf(stdout, "\r%s--%s %s-- (Space=advance, b=prev, arrows=scroll, [ ]=pick link, Enter=open, o=links, q=back, Q=quit)%s ",
                    inv, label, detail, rst);
        } else {
            fprintf(stdout, "\r%s--%s %s-- (Space=advance, b=prev, arrows=scroll, q=next file, Q=exit)%s ",
                    inv, label, detail, rst);
        }
    } else if (md_mode) {
        fprintf(stdout, "\r%s--%s-- (Space=advance, b=prev, arrows=scroll, [ ]=pick link, Enter=open, o=links, q=back, Q=quit)%s ", inv, label, rst);
    } else {
        fprintf(stdout, "\r%s--%s-- (Space=advance, b=prev, arrows=scroll, q=quit)%s ", inv, label, rst);
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
static int pager_terminal_cols(void);

static int pagerInteractiveSession(const char *cmd_name,
                                   const char *detail,
                                   PagerBuffer *buffer,
                                   int page_rows) {
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
        int key = pagerPromptAndRead(cmd_name, detail);
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
                } else if (key == ' ') {
                    pager_last_exit_key = ' ';
                    pager_last_md_link_index = -1;
                    goto done;
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
    char buffer[65536];
    bool dbg = getenv("PSCALI_PIPE_DEBUG") != NULL;
    /* Bolt optimization: Use direct write calls for 'cat' to bypass stdio overhead */
    fflush(stdout); /* flush any previously buffered stdout data to prevent interleaving */
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
        size_t total_written = 0;
        while (total_written < (size_t)n) {
            ssize_t nw = write(STDOUT_FILENO, buffer + total_written, (size_t)n - total_written);
            if (nw < 0) {
                if (errno == EINTR) continue;
                perror("cat: write error");
                return 1;
            }
            total_written += (size_t)nw;
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
static _Thread_local int pager_observed_rows = 0;
static _Thread_local int pager_observed_cols = 0;

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
    if (pager_control_fd_value > STDERR_FILENO) {
        close(pager_control_fd_value);
    }
    pager_control_fd_value = -2;
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
    int fd_is_tty = (fd >= 0 && pscalRuntimeFdIsInteractive(fd)) ? 1 : 0;
#if defined(PSCAL_TARGET_IOS)
    bool have_session_queue = pagerUseSessionInputQueue();
    bool use_session_queue = have_session_queue &&
                             (pager_session_queue_enabled || fd < 0 || !fd_is_tty);
#else
    bool use_session_queue = false;
#endif
    if (fd < 0) {
        if (!use_session_queue) {
            return 'q';
        }
    }
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
    const int resize_poll_ms = 100;
    if (pager_observed_rows <= 0 || pager_observed_cols <= 0) {
        int initial_rows = pager_terminal_rows();
        int initial_cols = pager_terminal_cols();
        if (initial_rows > 0) {
            pager_observed_rows = initial_rows;
        }
        if (initial_cols > 0) {
            pager_observed_cols = initial_cols;
        }
    }
    for (;;) {
        unsigned char ch = 0;
        ssize_t n = pagerReadByteWithTimeout(fd, use_session_queue, &ch, false, resize_poll_ms);
        if (n == -2) {
            int rows_now = pager_terminal_rows();
            int cols_now = pager_terminal_cols();
            if (rows_now > 0) {
                pager_observed_rows = rows_now;
            }
            if (cols_now > 0) {
                pager_observed_cols = cols_now;
            }
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
            int rows_now = pager_terminal_rows();
            int cols_now = pager_terminal_cols();
            if (rows_now > 0 && cols_now > 0) {
                if (pager_observed_rows <= 0 || pager_observed_cols <= 0) {
                    pager_observed_rows = rows_now;
                    pager_observed_cols = cols_now;
                } else if (rows_now != pager_observed_rows || cols_now != pager_observed_cols) {
                    pager_observed_rows = rows_now;
                    pager_observed_cols = cols_now;
                    result = PAGER_KEY_RESIZE;
                    break;
                }
            }
            if (n == 0) {
                continue;
            }
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

static int pager_file(const char *cmd_name,
                      const char *path,
                      const char *detail,
                      FILE *stream,
                      bool raw_mode) {
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
    buffer.raw_mode = raw_mode;
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
    status = pagerInteractiveSession(cmd_name, detail, &buffer, page_rows);
    pager_session_queue_enabled = prev_session_queue;
#else
    status = pagerInteractiveSession(cmd_name, detail, &buffer, page_rows);
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

static int markdownPreferredWrapWidth(void) {
    int width = markdownTermWidth();
    if (width <= 20) {
        return MARKDOWN_WRAP_WIDTH;
    }
    if (width > 2) {
        width -= 2;
    }
    if (width < 20) {
        return MARKDOWN_WRAP_WIDTH;
    }
    return width;
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

static void markdownWriteHeading(FILE *out, const char *text, int level, int wrap_width) {
    if (!text || !*text) return;
    char *formatted = markdownSimplifyInline(text);
    if (!formatted) return;
    fprintf(out, "%s\n", formatted);
    char underline = (level == 1) ? '=' : '-';
    size_t len = strlen(formatted);
    size_t underline_len = len > (size_t)wrap_width ? (size_t)wrap_width : len;
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

static void markdownFlushParagraph(FILE *out, char **paragraph, size_t *length, int wrap_width) {
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
            markdownWrapAndWrite(out, formatted, "", "", wrap_width);
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
        !strstr(probe, ". ") &&
        (strchr(probe, '.') || strchr(probe, '[') || strchr(probe, ':'))) {
        return true;
    }
    if (len > 1 && len <= 6 && probe[len - 1] == ',' &&
        (probe[0] == '.' || probe[0] == '#' || probe[0] == '[' || probe[0] == ':' || probe[0] == '@') &&
        !strstr(probe, "://")) {
        bool tiny_selector = true;
        for (size_t i = 0; i + 1 < len; ++i) {
            unsigned char ch = (unsigned char)probe[i];
            if (!(isalnum(ch) || ch == '-' || ch == '_' ||
                  ch == '.' || ch == '#' || ch == '[' || ch == ']' || ch == ':')) {
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
        !strstr(probe, ". ") &&
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
    int render_width = markdownPreferredWrapWidth();

    if (label && *label) {
        fprintf(output, "%s\n", label);
        size_t underline_len = strlen(label);
        if (underline_len > (size_t)render_width) {
            underline_len = (size_t)render_width;
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
                            markdownFlushParagraph(output, &paragraph, &paragraph_len, render_width);
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
                markdownFlushParagraph(output, &paragraph, &paragraph_len, render_width);
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
                markdownFlushParagraph(output, &paragraph, &paragraph_len, render_width);
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
                markdownFlushParagraph(output, &paragraph, &paragraph_len, render_width);
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
                markdownFlushParagraph(output, &paragraph, &paragraph_len, render_width);
                has_blank_separator = true;
                paragraph_link_only_chain = false;
            }
            continue;
        }
        }

        char fence = markdownFenceMarker(trimmed);
        if (fence != '\0') {
            bool had_paragraph = paragraph_len > 0;
            markdownFlushParagraph(output, &paragraph, &paragraph_len, render_width);
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
                markdownFlushParagraph(output, &paragraph, &paragraph_len, render_width);
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
                markdownWriteHeading(output, heading_text, setext_heading, render_width);
                has_blank_separator = true;
            }
            paragraph_len = 0;
            paragraph[0] = '\0';
            paragraph_link_only_chain = false;
            continue;
        }

        if (markdownIsHorizontalRule(trimmed)) {
            bool had_paragraph = paragraph_len > 0;
            markdownFlushParagraph(output, &paragraph, &paragraph_len, render_width);
            if (had_paragraph) {
                has_blank_separator = true;
                paragraph_link_only_chain = false;
            }
            for (int i = 0; i < render_width; ++i) {
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
            markdownFlushParagraph(output, &paragraph, &paragraph_len, render_width);
            if (had_paragraph) {
                has_blank_separator = true;
                paragraph_link_only_chain = false;
            }
            const char *heading_text = trimmed + heading;
            while (*heading_text == ' ' || *heading_text == '\t') heading_text++;
            markdownWriteHeading(output, heading_text, heading, render_width);
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
            markdownFlushParagraph(output, &paragraph, &paragraph_len, render_width);
            if (had_paragraph) {
                has_blank_separator = true;
                paragraph_link_only_chain = false;
            }
            char *quote = trimmed + 1;
            while (*quote == ' ' || *quote == '\t') quote++;
            char *formatted = markdownSimplifyInline(quote);
            if (formatted) {
                markdownWrapAndWrite(output, formatted, "> ", "> ", render_width);
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
                markdownFlushParagraph(output, &paragraph, &paragraph_len, render_width);
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
            markdownFlushParagraph(output, &paragraph, &paragraph_len, render_width);
            if (had_paragraph) {
                has_blank_separator = true;
                paragraph_link_only_chain = false;
            }
            char *formatted = markdownSimplifyInline(list_text);
            if (formatted) {
                markdownWrapAndWrite(output, formatted, prefix_first, prefix_sub, render_width);
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
    markdownFlushParagraph(output, &paragraph, &paragraph_len, render_width);
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
                                          int *selected_link_index_out,
                                          bool output_raw) {
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

    if (output_raw) {
        if (*render_source) {
            fputs(render_source, stdout);
        }
        free(converted_html);
        if (exit_key_out) {
            *exit_key_out = 'q';
        }
        return 0;
    }

    FILE *source = smallclueOpenTempFile("md-source");
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

    FILE *buffer = smallclueOpenTempFile("md-buffer");
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
    int status = pager_file("md", label ? label : "(stdin)", NULL, buffer, false);
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
                                            int *selected_link_index_out,
                                            bool output_raw) {
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
                                                selected_link_index_out,
                                                output_raw);
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
    if (smallclueHttpFetchToMemory("md", url, data_out, len_out, NULL) != 0) {
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
    bool first_frame = true;
#if defined(PSCAL_TARGET_IOS)
    bool prev_session_queue = pager_session_queue_enabled;
    pager_session_queue_enabled = true;
#endif

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

        char *frame = NULL;
        size_t frame_len = 0;
        FILE *out = open_memstream(&frame, &frame_len);
        if (!out) {
            out = stdout;
        }
        smallclueMenuStartFrameTo(out, &first_frame);
        char header[256];
        if (source_label && *source_label) {
            snprintf(header, sizeof(header), "Links in %s (%zu/%zu)  [Arrows=move Enter=open q=cancel]",
                   source_label, cursor + 1, links->count);
        } else {
            snprintf(header, sizeof(header), "Links (%zu/%zu)  [Arrows=move Enter=open q=cancel]",
                   cursor + 1, links->count);
        }
        fputs("\x1b[7m", out);
        if (cols > 0 && (int)strlen(header) > cols) {
            if (cols <= 3) { fwrite(header, 1, (size_t)cols, out); }
            else { fwrite(header, 1, (size_t)(cols - 3), out); fputs("...", out); }
        } else {
            fprintf(out, "%s", header);
        }
        fputs("\x1b[0m\n", out);

        size_t end = top + window;
        if (end > links->count) end = links->count;
        for (size_t i = top; i < end; ++i) {
            bool active = (i == cursor);
            const char *text = links->items[i].text ? links->items[i].text : "(link)";
            const char *target = links->items[i].target ? links->items[i].target : "";
            char line[PATH_MAX * 3];
            snprintf(line, sizeof(line), "%3zu. %s (%s)", i + 1, text, target);
            if (active) fputs("\x1b[7m", out);
            if (cols > 0 && (int)strlen(line) > cols) {
                if (cols > 3) {
                    fwrite(line, 1, (size_t)(cols - 3), out);
                    fputs("...", out);
                } else {
                    fwrite(line, 1, (size_t)cols, out);
                }
                fputc('\n', out);
            } else {
                fprintf(out, "%s\n", line);
            }
            if (active) fputs("\x1b[0m", out);
        }
        if (out != stdout) {
            fflush(out);
            fclose(out);
            if (frame && frame_len > 0) {
                fwrite(frame, 1, frame_len, stdout);
            }
            free(frame);
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
#if defined(PSCAL_TARGET_IOS)
                pager_session_queue_enabled = prev_session_queue;
#endif
                return (int)cursor;
            case 'q':
            case 'Q':
            case 3:
                printf("\x1b[2J\x1b[H");
                fflush(stdout);
#if defined(PSCAL_TARGET_IOS)
                pager_session_queue_enabled = prev_session_queue;
#endif
                return -1;
            default:
                break;
        }
    }
#if defined(PSCAL_TARGET_IOS)
    pager_session_queue_enabled = prev_session_queue;
#endif
    return -1;
}

static int smallclueMarkdownBrowseTarget(const char *initial_target, bool output_raw) {
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
                                                        &selected_link_index,
                                                        output_raw);
                free(remote_data);
            }
        } else if (strcmp(current, "-") == 0) {
            status = smallclueMarkdownDisplayStreamEx("(stdin)",
                                                      stdin,
                                                      MARKDOWN_INPUT_MODE_MARKDOWN,
                                                      &links,
                                                      &exit_key,
                                                      &selected_link_index,
                                                      output_raw);
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
                                                              &selected_link_index,
                                                              output_raw);
                    fclose(fp);
                }
            }
        }

        if (status != 0) {
            markdownLinkListFree(&links);
            overall_status = 1;
            break;
        }

        if (output_raw) {
            markdownLinkListFree(&links);
            overall_status = 0;
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
    return smallclueMarkdownBrowseTarget(path, false);
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

    bool use_color = isatty(STDOUT_FILENO);
    if (use_color) {
        printf("Markdown documents in \033[1;34m%s\033[0m:\n\n", visible_docs_dir);
    } else {
        printf("Markdown documents in %s:\n\n", visible_docs_dir);
    }

    for (size_t i = 0; i < count; ++i) {
        const char *title = entries[i].title ? entries[i].title : "";
        const char *name = entries[i].name ? entries[i].name : "(unknown)";
        if (use_color) {
            printf("  \033[1m%-24s\033[0m %s\n", name, title);
        } else {
            printf("  %-24s %s\n", name, title);
        }
        markdownDocEntryFree(&entries[i]);
    }
    free(entries);
    return 0;
}

static void smallclueMenuStartFrameTo(FILE *out, bool *first_frame) {
    if (!out) {
        out = stdout;
    }
    if (first_frame && *first_frame) {
        fputs("\x1b[2J\x1b[H", out);
        *first_frame = false;
        return;
    }
    fputs("\x1b[H\x1b[J", out);
}

static void markdownInteractiveRenderList(MarkdownDocEntry *entries,
                                          size_t count,
                                          size_t top,
                                          size_t cursor,
                                          size_t window,
                                          const char *docs_dir,
                                          int term_cols,
                                          bool show_docs_dir,
                                          bool *first_frame) {
    char *frame = NULL;
    size_t frame_len = 0;
    FILE *out = open_memstream(&frame, &frame_len);
    if (!out) {
        out = stdout;
    }
    smallclueMenuStartFrameTo(out, first_frame);
    char header[256];
    snprintf(header, sizeof(header),
             "Markdown docs (Arrows=move, Enter=open, q=quit) [%zu/%zu]",
             cursor + 1, count);
    fputs("\x1b[7m", out);
    if (term_cols > 0 && (int)strlen(header) > term_cols) {
        if (term_cols <= 3) {
            fwrite(header, 1, (size_t)term_cols, out);
        } else {
            fwrite(header, 1, (size_t)(term_cols - 3), out);
            fputs("...", out);
        }
    } else {
        fprintf(out, "%s", header);
    }
    fputs("\x1b[0m\n", out);
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
            fputs("\x1b[7m", out);
        }
        if (term_cols > 0 && (int)strlen(line) > term_cols) {
            if (term_cols <= 3) {
                fwrite(line, 1, (size_t)term_cols, out);
            } else {
                fwrite(line, 1, (size_t)(term_cols - 3), out);
                fputs("...", out);
            }
            fputc('\n', out);
        } else {
            fprintf(out, "%s\n", line);
        }
        if (highlight) {
            fputs("\x1b[0m", out);
        }
    }
    if (show_docs_dir) {
        char docs_dir_display[PATH_MAX];
        const char *visible_docs_dir = smallclueDisplayPath(docs_dir, docs_dir_display, sizeof(docs_dir_display));
        char footer[PATH_MAX + 32];
        snprintf(footer, sizeof(footer), "Docs: %s", visible_docs_dir);
        if (term_cols > 0 && (int)strlen(footer) > term_cols) {
            if (term_cols <= 3) {
                fwrite(footer, 1, (size_t)term_cols, out);
            } else {
                fwrite(footer, 1, (size_t)(term_cols - 3), out);
                fputs("...", out);
            }
            fputc('\n', out);
        } else {
            fprintf(out, "%s\n", footer);
        }
    }
    if (out != stdout) {
        fflush(out);
        fclose(out);
        if (frame && frame_len > 0) {
            fwrite(frame, 1, frame_len, stdout);
        }
        free(frame);
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

    pager_control_fd_reset();

    size_t cursor = 0;
    size_t top = 0;
    char selected[PATH_MAX];
    bool running = true;
    bool has_selection = false;
    bool first_frame = true;
#if defined(PSCAL_TARGET_IOS)
    bool prev_session_queue = pager_session_queue_enabled;
    pager_session_queue_enabled = true;
#endif

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

        markdownInteractiveRenderList(entries, count, top, cursor, window, docs_dir, cols, show_docs_dir, &first_frame);

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
    pager_control_fd_reset();
#if defined(PSCAL_TARGET_IOS)
    pager_session_queue_enabled = prev_session_queue;
#endif

    for (size_t i = 0; i < count; ++i) {
        markdownDocEntryFree(&entries[i]);
    }
    free(entries);

    if (!has_selection) {
        return 0;
    }
    int status = smallclueMarkdownBrowseTarget(selected, false);
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
    /* Restrict protocols to HTTP/HTTPS to prevent SSRF via redirects to file:// etc. */
#if LIBCURL_VERSION_NUM >= 0x075500
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS_STR, "http,https");
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS_STR, "http,https");
#else
    curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
    curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP | CURLPROTO_HTTPS);
#endif
}

/* Applies -X/-H/-d (method override, custom headers, POST body) onto a
 * CURL handle. Returns the built curl_slist (or NULL if no headers were
 * given) -- caller must curl_slist_free_all() it after curl_easy_perform. */
static struct curl_slist *smallclueCurlApplyRequestOptions(CURL *curl, const SmallclueHttpRequestOptions *reqOpts) {
    if (!curl || !reqOpts) return NULL;
    struct curl_slist *headerList = NULL;
    for (int i = 0; i < reqOpts->headerCount; ++i) {
        headerList = curl_slist_append(headerList, reqOpts->headers[i]);
    }
    if (headerList) {
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headerList);
    }
    if (reqOpts->postData) {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, reqOpts->postData);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, (long)strlen(reqOpts->postData));
    }
    if (reqOpts->method && *reqOpts->method) {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, reqOpts->method);
    }
    if (reqOpts->userpwd && *reqOpts->userpwd) {
        /* Real curl's default (without --anyauth/--digest/etc.) is
         * preemptive Basic auth, sent on the first request without
         * waiting for a 401 challenge -- CURLAUTH_ANY would instead defer
         * until challenged, which is wrong for the common case and was
         * caught by comparing against real curl's actual wire behavior. */
        curl_easy_setopt(curl, CURLOPT_HTTPAUTH, (long)CURLAUTH_BASIC);
        curl_easy_setopt(curl, CURLOPT_USERPWD, reqOpts->userpwd);
    }
    if (reqOpts->insecureTls) {
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
    }
    return headerList;
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

static int smallclueHttpFetch(const char *cmd_name, const char *url, const char *destinationPath,
                              const SmallclueHttpRequestOptions *reqOpts) {
#if !defined(PSCAL_HAS_LIBCURL)
    (void)reqOpts;
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
    struct curl_slist *headerList = smallclueCurlApplyRequestOptions(curl, reqOpts);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, smallclueCurlWriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, dest);
    CURLcode res = curl_easy_perform(curl);
    if (close_dest) {
        fclose(dest);
    } else {
        fflush(dest);
    }
    if (headerList) curl_slist_free_all(headerList);
    if (res != CURLE_OK) {
        fprintf(stderr, "%s: %s: %s\n", cmd_name ? cmd_name : "curl", url, curl_easy_strerror(res));
        curl_easy_cleanup(curl);
        return 1;
    }
    curl_easy_cleanup(curl);
    return 0;
#endif
}

static int smallclueHttpFetchToMemory(const char *cmd_name, const char *url, char **data_out, size_t *len_out,
                                      const SmallclueHttpRequestOptions *reqOpts) {
#if !defined(PSCAL_HAS_LIBCURL)
    (void)data_out;
    (void)len_out;
    (void)reqOpts;
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
    struct curl_slist *headerList = smallclueCurlApplyRequestOptions(curl, reqOpts);
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
    if (headerList) curl_slist_free_all(headerList);
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

typedef struct {
    bool numberAll;      /* -n */
    bool numberNonBlank;  /* -b (takes priority over -n if both given) */
    bool showEnds;        /* -E: '$' at end of line */
    bool showTabs;        /* -T: tabs as ^I */
    bool squeezeBlank;    /* -s: collapse runs of blank lines to one */
} SmallclueCatOptions;

/* Line-based formatting path, used only when any of -n/-b/-A/-E/-T/-s is
 * given -- the flag-less case keeps using the existing raw-byte-stream
 * print_file()/cat_file() fast path unchanged. */
static int smallclueCatFileFormatted(const char *path, const SmallclueCatOptions *opts, long *lineNo, bool *prevBlank) {
    FILE *fp;
    const char *label = path ? path : "(stdin)";
    if (!path || strcmp(path, "-") == 0) {
        fp = stdin;
    } else {
        char resolved[PATH_MAX];
        const char *open_path = smallclueResolvePath(path, resolved, sizeof(resolved));
        if (!open_path || *open_path == '\0') open_path = path;
        fp = fopen(open_path, "rb");
        if (!fp) {
            fprintf(stderr, "cat: %s: %s\n", path, strerror(errno));
            return 1;
        }
    }
    char *line = NULL;
    size_t cap = 0;
    int status = 0;
    for (;;) {
        int read_err = 0;
        ssize_t len = smallclueGetlineStream(&line, &cap, fp, &read_err);
        if (len < 0) {
            if (read_err) {
                fprintf(stderr, "cat: %s: %s\n", label, strerror(read_err));
                status = 1;
            }
            break;
        }
        bool hadNewline = (len > 0 && line[len - 1] == '\n');
        if (hadNewline) {
            line[len - 1] = '\0';
            len--;
        }
        bool isBlank = (len == 0);
        if (opts->squeezeBlank && isBlank && *prevBlank) {
            continue;
        }
        *prevBlank = isBlank;

        if (opts->numberAll || opts->numberNonBlank) {
            if (!opts->numberNonBlank || !isBlank) {
                printf("%6ld\t", ++(*lineNo));
            }
        }
        if (opts->showTabs) {
            for (ssize_t i = 0; i < len; ++i) {
                if (line[i] == '\t') fputs("^I", stdout);
                else putchar(line[i]);
            }
        } else {
            fwrite(line, 1, (size_t)len, stdout);
        }
        if (opts->showEnds) putchar('$');
        if (hadNewline) putchar('\n');
    }
    free(line);
    if (fp != stdin) fclose(fp);
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

static void print_long_listing(const char *filename, const struct stat *s, bool human, bool numeric_ids, bool show_inode, const char *color) {
    if (show_inode) {
        printf("%8llu ", (unsigned long long)s->st_ino);
    }
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
    printf(" %s ", time_buf);
    if (color) printf("\033[%sm", color);
    printf("%s", filename);
    if (color) printf("\033[0m");

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

static const char *smallclueLsGetColor(mode_t mode) {
    if (S_ISDIR(mode)) return "1;34";       /* bold blue */
    if (S_ISLNK(mode)) return "1;36";       /* bold cyan */
    if (S_ISCHR(mode) || S_ISBLK(mode)) return "1;33"; /* bold yellow */
    if (S_ISSOCK(mode)) return "35";        /* magenta */
    if (S_ISFIFO(mode)) return "33";        /* yellow */
    if (mode & S_IXUSR) return "1;32";      /* bold green */
    return NULL;
}

static int print_path_entry_with_stat(const char *path,
                                      const char *label,
                                      bool long_format,
                                      bool human,
                                      bool numeric_ids,
                                      const struct stat *stat_buf,
                                      int color_mode,
                                      int classify,
                                      bool show_inode) {
    struct stat local_stat;
    const struct stat *st = stat_buf;
    if (!st) {
        if (lstat(path, &local_stat) == -1) {
            fprintf(stderr, "ls: %s: %s\n", path, strerror(errno));
            return 1;
        }
        st = &local_stat;
    }

    const char *color = NULL;
    if (color_mode > 0 && st) {
        color = smallclueLsGetColor(st->st_mode);
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
        print_long_listing(out, st, human, numeric_ids, show_inode, color);
    } else {
        if (show_inode) {
            printf("%8llu ", (unsigned long long)st->st_ino);
        }
        if (color)
            printf("\033[%sm%s\033[0m\n", color, out);
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
    return print_path_entry_with_stat(path, label, long_format, human, false, NULL, color_mode, classify, false);
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

static int compare_ls_entries_by_name(const void *lhs, const void *rhs) {
    const SmallclueLsEntry *a = (const SmallclueLsEntry *)lhs;
    const SmallclueLsEntry *b = (const SmallclueLsEntry *)rhs;
    return strcmp(a->name, b->name);
}

static int compare_ls_entries_group_dirs_name(const void *lhs, const void *rhs) {
    const SmallclueLsEntry *a = (const SmallclueLsEntry *)lhs;
    const SmallclueLsEntry *b = (const SmallclueLsEntry *)rhs;
    bool a_is_dir = S_ISDIR(a->stat_buf.st_mode);
    bool b_is_dir = S_ISDIR(b->stat_buf.st_mode);
    if (a_is_dir != b_is_dir) {
        return a_is_dir ? -1 : 1;
    }
    return strcmp(a->name, b->name);
}

static int compare_ls_entries_group_dirs_mtime(const void *lhs, const void *rhs) {
    const SmallclueLsEntry *a = (const SmallclueLsEntry *)lhs;
    const SmallclueLsEntry *b = (const SmallclueLsEntry *)rhs;
    bool a_is_dir = S_ISDIR(a->stat_buf.st_mode);
    bool b_is_dir = S_ISDIR(b->stat_buf.st_mode);
    if (a_is_dir != b_is_dir) {
        return a_is_dir ? -1 : 1;
    }
    if (a->stat_buf.st_mtime > b->stat_buf.st_mtime) {
        return -1;
    }
    if (a->stat_buf.st_mtime < b->stat_buf.st_mtime) {
        return 1;
    }
    return strcmp(a->name, b->name);
}

static int compare_ls_entries_by_size(const void *lhs, const void *rhs) {
    const SmallclueLsEntry *a = (const SmallclueLsEntry *)lhs;
    const SmallclueLsEntry *b = (const SmallclueLsEntry *)rhs;
    if (a->stat_buf.st_size > b->stat_buf.st_size) return -1;
    if (a->stat_buf.st_size < b->stat_buf.st_size) return 1;
    return strcmp(a->name, b->name);
}

static const char *smallclueLsExtensionOf(const char *name) {
    const char *dot = strrchr(name, '.');
    return (dot && dot != name) ? dot + 1 : "";
}

static int compare_ls_entries_by_extension(const void *lhs, const void *rhs) {
    const SmallclueLsEntry *a = (const SmallclueLsEntry *)lhs;
    const SmallclueLsEntry *b = (const SmallclueLsEntry *)rhs;
    int cmp = strcmp(smallclueLsExtensionOf(a->name), smallclueLsExtensionOf(b->name));
    if (cmp != 0) return cmp;
    return strcmp(a->name, b->name);
}

/* Natural/version sort (GNU ls -v): compares runs of digits numerically
 * so "file2" sorts before "file10", falling back to plain lexical
 * comparison for non-digit runs. Implemented by hand rather than via
 * glibc's strverscmp(3) since that's not available on macOS (this
 * project builds here for dev even though the deploy target is Linux). */
static int smallclueNaturalCompare(const char *a, const char *b) {
    while (*a && *b) {
        if (isdigit((unsigned char)*a) && isdigit((unsigned char)*b)) {
            const char *a_start = a, *b_start = b;
            while (*a == '0') a++;
            while (*b == '0') b++;
            const char *a_digits = a, *b_digits = b;
            while (isdigit((unsigned char)*a)) a++;
            while (isdigit((unsigned char)*b)) b++;
            size_t a_len = (size_t)(a - a_digits);
            size_t b_len = (size_t)(b - b_digits);
            if (a_len != b_len) return (a_len < b_len) ? -1 : 1;
            int cmp = strncmp(a_digits, b_digits, a_len);
            if (cmp != 0) return cmp;
            /* Equal numeric value: fewer leading zeros sorts first
             * (matches GNU strverscmp's own tie-break convention). */
            size_t a_zeros = (size_t)(a_digits - a_start);
            size_t b_zeros = (size_t)(b_digits - b_start);
            if (a_zeros != b_zeros) return (a_zeros < b_zeros) ? -1 : 1;
            continue;
        }
        if (*a != *b) return (unsigned char)*a - (unsigned char)*b;
        a++;
        b++;
    }
    return (unsigned char)*a - (unsigned char)*b;
}

static int compare_ls_entries_by_version(const void *lhs, const void *rhs) {
    const SmallclueLsEntry *a = (const SmallclueLsEntry *)lhs;
    const SmallclueLsEntry *b = (const SmallclueLsEntry *)rhs;
    return smallclueNaturalCompare(a->name, b->name);
}

#define LS_FORMAT_AUTO 0
#define LS_FORMAT_LONG 1
#define LS_FORMAT_COLUMNS 2
#define LS_FORMAT_SINGLE 3

static void print_ls_columns(const SmallclueLsEntry *entries, size_t count, int color_mode, int classify, bool show_inode) {
    if (count == 0) {
        return;
    }

    int term_cols = pscalRuntimeDetectWindowCols();
    if (term_cols <= 0) {
        term_cols = 80;
    }

    size_t inode_width = 0;
    if (show_inode) {
        for (size_t i = 0; i < count; ++i) {
            char inobuf[32];
            int w = snprintf(inobuf, sizeof(inobuf), "%llu", (unsigned long long)entries[i].stat_buf.st_ino);
            if (w > 0 && (size_t)w > inode_width) {
                inode_width = (size_t)w;
            }
        }
    }

    size_t max_len = 0;
    for (size_t i = 0; i < count; ++i) {
        size_t len = strlen(entries[i].name);
        if (show_inode) {
            len += inode_width + 1; /* inode digits + one separating space */
        }
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
            char withInode[PATH_MAX];
            const char *base = name;
            if (show_inode) {
                snprintf(withInode, sizeof(withInode), "%*llu %s",
                         (int)inode_width, (unsigned long long)st->st_ino, name);
                base = withInode;
            }
            char decorated[PATH_MAX];
            const char *out = base;
            if (classify) {
                char suffix = '\0';
                if (S_ISDIR(st->st_mode)) suffix = '/';
                else if (S_ISLNK(st->st_mode)) suffix = '@';
                else if (S_ISSOCK(st->st_mode)) suffix = '=';
                else if (S_ISFIFO(st->st_mode)) suffix = '|';
                else if (st->st_mode & S_IXUSR) suffix = '*';
                if (suffix != '\0') {
                    snprintf(decorated, sizeof(decorated), "%s%c", base, suffix);
                    decorated[sizeof(decorated) - 1] = '\0';
                    out = decorated;
                }
            }
            const char *color = NULL;
            if (color_mode > 0) {
                color = smallclueLsGetColor(st->st_mode);
            }
            if (c == cols - 1 || (size_t)((c + 1) * rows + r) >= count) {
                if (color) printf("\033[%sm%s\033[0m", color, out); else printf("%s", out);
            } else {
                if (color) printf("\033[%sm%-*s\033[0m", color, (int)col_width, out);
                else printf("%-*s", (int)col_width, out);
            }
        }
        putchar('\n');
    }
}

static int list_directory(const char *path,
                          bool show_all,
                          bool show_almost_all,
                          int format_mode,
                          bool sort_by_time,
                          bool group_directories_first,
                          bool human,
                          bool numeric_ids,
                          int color_mode,
                          int classify,
                          bool sort_by_size,
                          bool sort_by_extension,
                          bool reverse_sort,
                          bool recursive,
                          bool show_inode,
                          bool sort_by_version) {
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

    if (count > 1) {
        int (*comparator)(const void *, const void *) = compare_ls_entries_by_name;
        if (group_directories_first) {
            if (sort_by_time) {
                comparator = compare_ls_entries_group_dirs_mtime;
            } else {
                comparator = compare_ls_entries_group_dirs_name;
            }
        } else if (sort_by_time) {
            comparator = compare_ls_entries_by_mtime;
        } else if (sort_by_size) {
            comparator = compare_ls_entries_by_size;
        } else if (sort_by_extension) {
            comparator = compare_ls_entries_by_extension;
        } else if (sort_by_version) {
            comparator = compare_ls_entries_by_version;
        }
        qsort(entries, count, sizeof(entries[0]), comparator);
        if (reverse_sort) {
            for (size_t i = 0; i < count / 2; ++i) {
                SmallclueLsEntry tmp = entries[i];
                entries[i] = entries[count - 1 - i];
                entries[count - 1 - i] = tmp;
            }
        }
    }

    if (format_mode == LS_FORMAT_LONG) {
        for (size_t i = 0; i < count; ++i) {
            status |= print_path_entry_with_stat(entries[i].full_path,
                                                 entries[i].name,
                                                 true,
                                                 human,
                                                 numeric_ids,
                                                 &entries[i].stat_buf,
                                                 color_mode,
                                                 classify,
                                                 show_inode);
        }
    } else if (format_mode == LS_FORMAT_SINGLE) {
        for (size_t i = 0; i < count; ++i) {
            status |= print_path_entry_with_stat(entries[i].full_path,
                                                 entries[i].name,
                                                 false,
                                                 human,
                                                 numeric_ids,
                                                 &entries[i].stat_buf,
                                                 color_mode,
                                                 classify,
                                                 show_inode);
        }
    } else {
        print_ls_columns(entries, count, color_mode, classify, show_inode);
    }

    if (recursive) {
        for (size_t i = 0; i < count; ++i) {
            if (!S_ISDIR(entries[i].stat_buf.st_mode)) continue;
            if (strcmp(entries[i].name, ".") == 0 || strcmp(entries[i].name, "..") == 0) continue;
            printf("\n%s:\n", entries[i].full_path);
            status |= list_directory(entries[i].full_path, show_all, show_almost_all, format_mode,
                                     sort_by_time, group_directories_first, human, numeric_ids,
                                     color_mode, classify, sort_by_size, sort_by_extension,
                                     reverse_sort, recursive, show_inode, sort_by_version);
        }
    }

    free_ls_entries(entries, count);
    return status ? 1 : 0;
}

static void smallcluePrintAppletList(FILE *out, const char *heading, bool color) {
    if (!out) {
        return;
    }
    if (heading && *heading) {
        if (color) {
            fprintf(out, "\033[1m%s\033[0m\n", heading);
        } else {
            fprintf(out, "%s\n", heading);
        }
    }
    for (size_t i = 0; i < kSmallclueAppletCount; ++i) {
        const SmallclueApplet *applet = &kSmallclueApplets[i];
        if (color) {
            fprintf(out, "  \033[36m%-16s\033[0m %s\n", applet->name, applet->description ? applet->description : "");
        } else {
            fprintf(out, "  %-16s %s\n", applet->name, applet->description ? applet->description : "");
        }
    }
}


static void print_usage(void) {
    fprintf(stderr, "This is smallclue. Usage:\n");
    fprintf(stderr, "  smallclue <applet> [arguments...]\n\n");
    fprintf(stderr, "Available applets:\n");
    smallcluePrintAppletList(stderr, NULL, isatty(STDERR_FILENO));
    fprintf(stderr, "\nYou can symlink applets to 'smallclue' or invoke them directly.\n");
}

/* Expands bash-echo-style backslash escapes (\a \b \e \f \n \r \t \v \\,
 * plus \0NNN octal and \xHH hex) while printing directly to stdout.
 * Returns true if \c was encountered, meaning the caller should stop all
 * further output immediately (no trailing space/newline, no more args). */
static bool smallclueEchoPrintExpanded(const char *s) {
    for (const char *p = s; *p; ++p) {
        if (*p == '\\' && p[1]) {
            switch (p[1]) {
                case 'a': putchar('\a'); p++; continue;
                case 'b': putchar('\b'); p++; continue;
                case 'c': return true;
                case 'e': putchar('\033'); p++; continue;
                case 'f': putchar('\f'); p++; continue;
                case 'n': putchar('\n'); p++; continue;
                case 'r': putchar('\r'); p++; continue;
                case 't': putchar('\t'); p++; continue;
                case 'v': putchar('\v'); p++; continue;
                case '\\': putchar('\\'); p++; continue;
                case '0': {
                    int val = 0, digits = 0;
                    const char *q = p + 2;
                    while (digits < 3 && *q >= '0' && *q <= '7') {
                        val = val * 8 + (*q - '0');
                        q++;
                        digits++;
                    }
                    putchar(val);
                    p = q - 1;
                    continue;
                }
                case 'x': {
                    int val = 0, digits = 0;
                    const char *q = p + 2;
                    while (digits < 2 && isxdigit((unsigned char)*q)) {
                        char hc = *q;
                        int hv = (hc >= '0' && hc <= '9') ? hc - '0' : (tolower((unsigned char)hc) - 'a' + 10);
                        val = val * 16 + hv;
                        q++;
                        digits++;
                    }
                    if (digits > 0) {
                        putchar(val);
                        p = q - 1;
                        continue;
                    }
                    break;
                }
                default:
                    break;
            }
        }
        putchar(*p);
    }
    return false;
}

static int smallclueEchoCommand(int argc, char **argv) {
    int print_newline = 1;
    bool interpret_escapes = false;
    int start_index = 1;

    /* Matches bash's builtin echo option scanning: a leading arg is only
     * an option cluster if EVERY character after the '-' is one of
     * n/e/E; anything else (including a bare "-") stops option scanning
     * and is treated as the first operand. */
    for (; start_index < argc; ++start_index) {
        const char *arg = argv[start_index];
        if (!arg || arg[0] != '-' || arg[1] == '\0') break;
        bool all_flags = true;
        for (const char *c = arg + 1; *c; ++c) {
            if (*c != 'n' && *c != 'e' && *c != 'E') {
                all_flags = false;
                break;
            }
        }
        if (!all_flags) break;
        for (const char *c = arg + 1; *c; ++c) {
            if (*c == 'n') print_newline = 0;
            else if (*c == 'e') interpret_escapes = true;
            else if (*c == 'E') interpret_escapes = false;
        }
    }

    bool stop = false;
    for (int i = start_index; i < argc && !stop; i++) {
        if (interpret_escapes) {
            stop = smallclueEchoPrintExpanded(argv[i]);
        } else {
            fputs(argv[i], stdout);
        }
        if (!stop && i < argc - 1) {
            putchar(' ');
        }
    }
    if (print_newline && !stop) {
        putchar('\n');
    }
    return 0;
}

static bool smallclueLsValidateShortOptions(const char *arg,
                                            int *show_all,
                                            int *show_almost_all,
                                            int *format,
                                            int *sort_by_time,
                                            int *list_dirs_only,
                                            int *human_sizes,
                                            int *classify,
                                            int *numeric_ids,
                                            int *sort_by_size,
                                            int *sort_by_extension,
                                            int *reverse_sort,
                                            int *recursive,
                                            int *show_inode,
                                            int *sort_by_version) {
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
                *format = LS_FORMAT_LONG;
                break;
            case '1':
                *format = LS_FORMAT_SINGLE;
                break;
            case 'C':
                *format = LS_FORMAT_COLUMNS;
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
                *format = LS_FORMAT_LONG;
                break;
            case 'S':
                *sort_by_size = 1;
                break;
            case 'X':
                *sort_by_extension = 1;
                break;
            case 'r':
                *reverse_sort = 1;
                break;
            case 'R':
                *recursive = 1;
                break;
            case 'i':
                *show_inode = 1;
                break;
            case 'v':
                *sort_by_version = 1;
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
    if (strcmp(arg, "--group-directories-first") == 0) {
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
    int format = LS_FORMAT_AUTO;
    int sort_by_time = 0;
    int group_directories_first = 0;
    int list_dirs_only = 0;
    int human_sizes = 0;
    int classify = 0;
    int numeric_ids = 0;
    int color_mode = 0; /* 0=auto, 1=always, -1=never */
    int sort_by_size = 0;
    int sort_by_extension = 0;
    int reverse_sort = 0;
    int recursive = 0;
    int show_inode = 0;
    int sort_by_version = 0;
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
            if (strcmp(arg, "--group-directories-first") == 0) {
                group_directories_first = 1;
            } else if (strcmp(arg, "--color") == 0 || strcmp(arg, "--colour") == 0) {
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
                                             &format,
                                             &sort_by_time,
                                             &list_dirs_only,
                                             &human_sizes,
                                             &classify,
                                             &numeric_ids,
                                             &sort_by_size,
                                             &sort_by_extension,
                                             &reverse_sort,
                                             &recursive,
                                             &show_inode,
                                             &sort_by_version)) {
            return 1;
        }
        idx++;
    }

    if (color_mode == 0) {
        color_mode = pscalRuntimeStdoutIsInteractive() ? 1 : -1;
    }

    if (format == LS_FORMAT_AUTO) {
        if (pscalRuntimeStdoutIsInteractive()) {
            format = LS_FORMAT_COLUMNS;
        } else {
            format = LS_FORMAT_SINGLE;
        }
    }

    int status = 0;
    int paths_start = idx;
    if (paths_start >= argc) {
        if (list_dirs_only) {
            return print_path_entry_with_stat(".", ".", format == LS_FORMAT_LONG, human_sizes, numeric_ids, NULL, color_mode, classify, show_inode) ? 1 : 0;
        }
        return list_directory(".", show_all, show_almost_all, format,
                              sort_by_time, group_directories_first, human_sizes, numeric_ids, color_mode, classify,
                              sort_by_size, sort_by_extension, reverse_sort, recursive, show_inode, sort_by_version);
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
            status |= list_directory(path, show_all, show_almost_all, format,
                                     sort_by_time, group_directories_first, human_sizes, numeric_ids, color_mode, classify,
                                     sort_by_size, sort_by_extension, reverse_sort, recursive, show_inode, sort_by_version);
        } else {
            status |= print_path_entry_with_stat(path, path, format == LS_FORMAT_LONG, human_sizes, numeric_ids, &stat_buf, color_mode, classify, show_inode);
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

static int smallclueChmodApplyOne(const char *path, bool useOctal, mode_t octalMode,
                                  const SmallclueChmodSpec *symbolicSpec) {
    if (useOctal) {
        if (chmod(path, octalMode) != 0) {
            fprintf(stderr, "chmod: %s: %s\n", path, strerror(errno));
            return 1;
        }
        return 0;
    }
    return smallclueChmodApplySymbolic(symbolicSpec, path);
}

static int smallclueChmodApplyRecursive(const char *path, bool useOctal, mode_t octalMode,
                                        const SmallclueChmodSpec *symbolicSpec) {
    int status = smallclueChmodApplyOne(path, useOctal, octalMode, symbolicSpec);
    struct stat st;
    if (lstat(path, &st) != 0 || !S_ISDIR(st.st_mode)) {
        return status;
    }
    DIR *dir = opendir(path);
    if (!dir) {
        fprintf(stderr, "chmod: %s: %s\n", path, strerror(errno));
        return 1;
    }
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        char child[PATH_MAX];
        if (smallclueBuildPath(child, sizeof(child), path, entry->d_name) != 0) {
            fprintf(stderr, "chmod: %s/%s: %s\n", path, entry->d_name, strerror(errno));
            status = 1;
            continue;
        }
        if (smallclueChmodApplyRecursive(child, useOctal, octalMode, symbolicSpec) != 0) {
            status = 1;
        }
    }
    closedir(dir);
    return status;
}

static int smallclueChmodCommand(int argc, char **argv) {
    bool recursive = false;
    int argi = 1;
    for (; argi < argc; ++argi) {
        if (strcmp(argv[argi], "-R") == 0 || strcmp(argv[argi], "-r") == 0 ||
            strcmp(argv[argi], "--recursive") == 0) {
            recursive = true;
        } else {
            break;
        }
    }
    if (argc - argi < 2) {
        fprintf(stderr, "usage: chmod [-R] mode file...\n");
        return 1;
    }
    mode_t octalMode = 0;
    SmallclueChmodSpec symbolicSpec;
    bool useOctal = smallclueChmodParseOctal(argv[argi], &octalMode);
    bool useSymbolic = false;
    if (!useOctal) {
        useSymbolic = smallclueChmodParseSymbolic(argv[argi], &symbolicSpec);
    }
    if (!useOctal && !useSymbolic) {
        fprintf(stderr, "chmod: invalid mode: %s\n", argv[argi]);
        return 1;
    }
    argi++;
    int status = 0;
    for (int i = argi; i < argc; ++i) {
        int rc = recursive
                     ? smallclueChmodApplyRecursive(argv[i], useOctal, octalMode, &symbolicSpec)
                     : smallclueChmodApplyOne(argv[i], useOctal, octalMode, &symbolicSpec);
        if (rc != 0) {
            status = 1;
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
    size_t buf_size = 64 * 1024;
    char *buffer = (char *)malloc(buf_size);
    if (!buffer) {
        return 1;
    }

    size_t filled = 0;
    while (filled + len + 1 <= buf_size) {
        memcpy(buffer + filled, text, len);
        buffer[filled + len] = '\n';
        filled += len + 1;
    }

    if (filled == 0) {
        /* Pattern too large for buffer, fall back to single line. */
        free(buffer);
        size_t line_len = len + 1;
        char *line = (char *)malloc(line_len + 1);
        if (!line) return 1;
        memcpy(line, text, len);
        line[len] = '\n';
        line[len + 1] = '\0';
        int status = initial_status;
        while (true) {
            if (smallclueShouldAbort(&status)) break;
            if (fwrite(line, 1, line_len, stdout) != line_len) {
                status = errno ? errno : status;
                break;
            }
        }
        free(line);
        return status;
    }

    int status = initial_status;
    size_t iteration = 0;
    while (true) {
        if ((iteration++ & 127) == 0) {
            if (smallclueShouldAbort(&status)) {
                break;
            }
        }
        size_t total_written = 0;
        while (total_written < filled) {
            ssize_t n = write(STDOUT_FILENO, buffer + total_written, filled - total_written);
            if (n < 0) {
                if (errno == EINTR) continue;
                status = errno ? errno : status;
                free(buffer);
                return status;
            }
            total_written += (size_t)n;
        }
    }
    free(buffer);
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
    char buf[16384];
    int read_err = 0;
    ssize_t n;

    while ((n = smallclueReadStream(f, buf, sizeof(buf), &read_err)) > 0) {
        ssize_t i = 0;
        /* Bolt optimization: Loop unrolling for BSD sum to reduce branching overhead */
        #define PROCESS_BSD_CHAR(idx) do { \
            unsigned char c = (unsigned char)buf[idx]; \
            sum = (uint16_t)((sum >> 1) | ((sum & 1) << 15)); \
            sum = (uint16_t)((sum + (uint16_t)c) & 0xFFFF); \
        } while (0)

        for (; i + 15 < n; i += 16) {
            PROCESS_BSD_CHAR(i);
            PROCESS_BSD_CHAR(i+1);
            PROCESS_BSD_CHAR(i+2);
            PROCESS_BSD_CHAR(i+3);
            PROCESS_BSD_CHAR(i+4);
            PROCESS_BSD_CHAR(i+5);
            PROCESS_BSD_CHAR(i+6);
            PROCESS_BSD_CHAR(i+7);
            PROCESS_BSD_CHAR(i+8);
            PROCESS_BSD_CHAR(i+9);
            PROCESS_BSD_CHAR(i+10);
            PROCESS_BSD_CHAR(i+11);
            PROCESS_BSD_CHAR(i+12);
            PROCESS_BSD_CHAR(i+13);
            PROCESS_BSD_CHAR(i+14);
            PROCESS_BSD_CHAR(i+15);
        }
        #undef PROCESS_BSD_CHAR

        for (; i < n; ++i) {
            unsigned char c = (unsigned char)buf[i];
            sum = (uint16_t)((sum >> 1) | ((sum & 1) << 15));
            sum = (uint16_t)((sum + (uint16_t)c) & 0xFFFF);
        }
        total += (unsigned long long)n;
    }
    if (out_blocks) {
        *out_blocks = (total + 1023ULL) / 1024ULL; /* 1K blocks */
    }
    return sum;
}

static uint16_t smallclueSysvSum(FILE *f, unsigned long long *out_blocks) {
    uint32_t sum = 0;
    unsigned long long total = 0;
    char buf[16384];
    int read_err = 0;
    ssize_t n;

    while ((n = smallclueReadStream(f, buf, sizeof(buf), &read_err)) > 0) {
        ssize_t i = 0;
        /* Bolt optimization: Loop unrolling for SysV sum to reduce branching overhead */
        for (; i + 15 < n; i += 16) {
            sum += (uint8_t)buf[i] + (uint8_t)buf[i+1] + (uint8_t)buf[i+2] + (uint8_t)buf[i+3] +
                   (uint8_t)buf[i+4] + (uint8_t)buf[i+5] + (uint8_t)buf[i+6] + (uint8_t)buf[i+7] +
                   (uint8_t)buf[i+8] + (uint8_t)buf[i+9] + (uint8_t)buf[i+10] + (uint8_t)buf[i+11] +
                   (uint8_t)buf[i+12] + (uint8_t)buf[i+13] + (uint8_t)buf[i+14] + (uint8_t)buf[i+15];
        }
        for (; i < n; ++i) {
            sum += (uint8_t)buf[i];
        }
        total += (unsigned long long)n;
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
#if defined(PSCAL_HAS_LIBGIT2)
    int lg2_major = 0;
    int lg2_minor = 0;
    int lg2_rev = 0;
    git_libgit2_version(&lg2_major, &lg2_minor, &lg2_rev);
    printf("libgit2: %d.%d.%d\n", lg2_major, lg2_minor, lg2_rev);
#endif
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
    {"libgit2", "libgit2_LICENSE.txt"},
    {"OpenSSH", "openssh_LICENSE.txt"},
    {"curl", "curl_LICENSE.txt"},
    {"OpenSSL", "openssl_LICENSE.txt"},
    {"SDL2", "sdl_LICENSE.txt"},
    {"Micro editor", "micro_LICENSE.txt"},
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

static void smallclueLicensesRenderMenu(size_t selected, bool *first_frame) {
    smallclueMenuStartFrameTo(stdout, first_frame);
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
    bool first_frame = true;
#if defined(PSCAL_TARGET_IOS)
    bool prev_session_queue = pager_session_queue_enabled;
    pager_session_queue_enabled = true;
#endif
    while (running) {
        smallclueLicensesRenderMenu(selected, &first_frame);
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
                    smallclueLicensesRenderMenu(selected, &first_frame);
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
#if defined(PSCAL_TARGET_IOS)
    pager_session_queue_enabled = prev_session_queue;
#endif
    smallclueEmitTerminalSane();
    return 0;
}

static int smallclueHelpCommand(int argc, char **argv) {
    int status = 0;
    char *buffer = NULL;
    size_t buflen = 0;
    bool interactive_out = pscalRuntimeStdoutIsInteractive();

    FILE *mem = open_memstream(&buffer, &buflen);
    if (!mem) {
        fprintf(stderr, "smallclue-help: unable to allocate buffer\n");
        return 1;
    }

    if (argc <= 1) {
        smallcluePrintAppletList(mem, "Available smallclue applets:", interactive_out);
    } else {
        for (int i = 1; i < argc; ++i) {
            const char *target = argv[i];
            const SmallclueApplet *applet = smallclueFindApplet(target);
            if (!applet) {
                fprintf(mem, "smallclue-help: '%s' not found\n", target);
                status = 1;
                continue;
            }
            const char *usage = smallclueLookupAppletUsage(applet->name);
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
                pager_file("smallclue-help", "(internal)", NULL, r, false);
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
#elif defined(SMALLCLUE_WITH_SH)
/* smallclue's native POSIX shell (src/shell/). */
extern int shMain(int argc, char **argv);
static int smallclueNativeShCommand(int argc, char **argv) {
    return shMain(argc, argv);
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

static int64_t smallclueSystemUptimeSeconds(void) {
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
    uint64_t now_ns = smallclueNowMonoNs();
    if (now_ns > 0) {
        return (int64_t)(now_ns / 1000000000ull);
    }
    return -1;
}

static int64_t smallclueAppUptimeSeconds(void) {
    uint64_t start_ns = gSmallclueProcessStartMonoNs;
    if (start_ns == 0) {
        start_ns = smallclueNowMonoNs();
        gSmallclueProcessStartMonoNs = start_ns;
    }
    uint64_t now_ns = smallclueNowMonoNs();
    if (now_ns < start_ns) {
        return 0;
    }
    return (int64_t)((now_ns - start_ns) / 1000000000ull);
}

static int smallclueUptimeCommand(int argc, char **argv) {
    bool show_system = false;
    int opt;
    optind = 1;
    while ((opt = getopt(argc, argv, "s")) != -1) {
        switch (opt) {
            case 's':
                show_system = true;
                break;
            default:
                fprintf(stderr, "usage: uptime [-s]\n");
                return 1;
        }
    }
    if (optind < argc) {
        fprintf(stderr, "usage: uptime [-s]\n");
        return 1;
    }

    int64_t seconds = show_system ? smallclueSystemUptimeSeconds() : smallclueAppUptimeSeconds();
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

static int smallclueTimeRunCommand(int argc, char **argv) {
    if (argc <= 0 || !argv || !argv[0] || argv[0][0] == '\0') {
        return 127;
    }

    const SmallclueApplet *applet = smallclueFindApplet(argv[0]);
    if (applet) {
        return smallclueDispatchApplet(applet, argc, argv);
    }

#if defined(PSCAL_TARGET_IOS)
    char exec_path[PATH_MAX];
    char shell_cwd[PATH_MAX];
    const char *resolve_cwd = NULL;
    if (vprocShellGetcwdShim(shell_cwd, sizeof(shell_cwd)) != NULL && shell_cwd[0] == '/') {
        resolve_cwd = shell_cwd;
    }
    if (smallclueResolveExecutableFromBaseCwd(resolve_cwd,
                                              argv[0],
                                              exec_path,
                                              sizeof(exec_path)) &&
        smallcluePathHasShebang(exec_path)) {
        int status = smallclueRunShebangTool(exec_path, argv);
        if (status >= 0) {
            return status;
        }
    }

    fprintf(stderr, "time: %s: command not found\n", argv[0]);
    return 127;
#else
    /* Not a built-in applet -- fork+execvp it like a real shell would,
     * instead of just reporting "command not found". The iOS build has
     * its own shebang-aware resolver above; on Linux/generic Unix,
     * execvp already handles PATH search and the kernel handles
     * shebangs directly, so a plain fork+execvp is sufficient (same
     * pattern already used by xargs's external-binary fallback and by
     * timeout's child). */
    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "time: fork: %s\n", strerror(errno));
        return 126;
    }
    if (pid == 0) {
        execvp(argv[0], argv);
        int err = errno;
        fprintf(stderr, "time: %s: %s\n", argv[0], strerror(err));
        _exit((err == ENOENT) ? 127 : 126);
    }
    int wait_status = 0;
    while (waitpid(pid, &wait_status, 0) < 0) {
        if (errno == EINTR) continue;
        fprintf(stderr, "time: waitpid: %s\n", strerror(errno));
        return 126;
    }
    if (WIFEXITED(wait_status)) {
        return WEXITSTATUS(wait_status);
    }
    if (WIFSIGNALED(wait_status)) {
        return 128 + WTERMSIG(wait_status);
    }
    return 1;
#endif
}

static int smallclueTimeCommand(int argc, char **argv) {
    if (argc < 2 || !argv[1] || argv[1][0] == '\0') {
        fprintf(stderr, "usage: time command [args...]\n");
        return 1;
    }

    struct timespec start_real = {0};
    struct timespec end_real = {0};
    struct rusage start_usage = {0};
    struct rusage end_usage = {0};
    bool have_real = (clock_gettime(CLOCK_MONOTONIC, &start_real) == 0);
    bool have_usage = (getrusage(RUSAGE_SELF, &start_usage) == 0);

    int status = smallclueTimeRunCommand(argc - 1, &argv[1]);

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

#if defined(PSCAL_TARGET_IOS)
static int smallclueWatchRunExternalCommand(int argc, char **argv, const char *base_cwd) {
    if (argc <= 0 || !argv || !argv[0] || argv[0][0] == '\0') {
        return 127;
    }
    pid_t pid = -1;
    char exec_path[PATH_MAX];
    if (!smallclueResolveExecutableFromBaseCwd(base_cwd, argv[0], exec_path, sizeof(exec_path))) {
        if (!strchr(argv[0], '/')) {
            char local_candidate[PATH_MAX];
            int written = 0;
            if (base_cwd && base_cwd[0] == '/') {
                written = snprintf(local_candidate, sizeof(local_candidate), "%s/%s", base_cwd, argv[0]);
            } else {
                written = snprintf(local_candidate, sizeof(local_candidate), "./%s", argv[0]);
            }
            if (written > 0 && (size_t)written < sizeof(local_candidate) &&
                smallclueResolveExecutableCandidate(local_candidate, exec_path, sizeof(exec_path))) {
                goto watch_exec_ready;
            }
        }
        fprintf(stderr, "watch: %s: command not found\n", argv[0]);
        return 127;
    }
watch_exec_ready:
    pid = fork();
    if (pid < 0) {
        fprintf(stderr, "watch: %s: %s\n", argv[0], strerror(errno));
        return 126;
    }
    if (pid == 0) {
        execv(exec_path, argv);
        int err = errno;
        if ((err == EPERM || err == ENOEXEC || err == EACCES) &&
            smallcluePathHasShebang(exec_path)) {
            (void)smallclueWatchExecViaShebang(exec_path, argc, argv);
            err = errno;
        }
        execvp(argv[0], argv);
        err = errno;
        fprintf(stderr, "watch: %s: %s\n", argv[0], strerror(err));
        _exit((err == ENOENT) ? 127 : 126);
    }
    int wait_status = 0;
    while (waitpid(pid, &wait_status, 0) < 0) {
        if (errno == EINTR) {
            continue;
        }
        fprintf(stderr, "watch: %s: %s\n", argv[0], strerror(errno));
        return 126;
    }
    if (WIFEXITED(wait_status)) {
        return WEXITSTATUS(wait_status);
    }
    if (WIFSIGNALED(wait_status)) {
        return 128 + WTERMSIG(wait_status);
    }
    return 1;
}

static int smallclueWatchRunCommand(int argc, char **argv) {
    if (argc <= 0 || !argv || !argv[0] || argv[0][0] == '\0') {
        return 127;
    }
    const SmallclueApplet *applet = smallclueFindApplet(argv[0]);
    const char *dbg = getenv("SMALLCLUE_DEBUG");
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

    char shell_cwd[PATH_MAX];
    const char *resolve_cwd = NULL;
    if (vprocShellGetcwdShim(shell_cwd, sizeof(shell_cwd)) != NULL && shell_cwd[0] == '/') {
        resolve_cwd = shell_cwd;
    }

    VProc *active_vp = vprocCurrent();
    int shell_pid = vprocGetShellSelfPid();
    bool force_new_vproc = !(active_vp && vprocPid(active_vp) > 0 && vprocPid(active_vp) != shell_pid);
    VProcCommandScope scope;
    bool scoped = vprocCommandScopeBegin(&scope,
                                         label[0] ? label : argv[0],
                                         force_new_vproc,
                                         false);
    int status = applet ? smallclueDispatchApplet(applet, argc, argv)
                        : smallclueWatchRunExternalCommand(argc, argv, resolve_cwd);
    if (scoped) {
        vprocCommandScopeEnd(&scope, status);
        if (dbg && *dbg) {
            fprintf(stderr, "[smallclue] vproc end pid=%d status=%d\n", scope.pid, status);
        }
    }
    return status;
}
#endif

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
        if (isatty(STDOUT_FILENO)) {
            fputs("\x1b[3J\x1b[H\x1b[2J", stdout);
            printf("\033[7mEvery %.2fs: %s\033[0m\n\n", interval, cmdline ? cmdline : argv[idx]);
        } else {
            printf("\nEvery %.2fs: %s\n\n", interval, cmdline ? cmdline : argv[idx]);
        }
        fflush(stdout);
#if defined(PSCAL_TARGET_IOS)
        status = smallclueWatchRunCommand(cmd_argc, &argv[idx]);
#else
        int sys_rc = system(cmdline ? cmdline : argv[idx]);
        if (sys_rc == -1) {
            status = 127;
        } else if (WIFEXITED(sys_rc)) {
            status = WEXITSTATUS(sys_rc);
        } else if (WIFSIGNALED(sys_rc)) {
            status = 128 + WTERMSIG(sys_rc);
        } else {
            status = 1;
        }
#endif
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

static char *smallclueBasenameOne(const char *input, const char *suffix) {
    char *path = strdup(input);
    if (!path) return NULL;
    char *base = basename(path);
    char *result = strdup(base ? base : "");
    free(path);
    if (!result) return NULL;
    if (suffix && *suffix) {
        size_t blen = strlen(result);
        size_t slen = strlen(suffix);
        /* GNU basename: only strip if it wouldn't leave an empty result. */
        if (blen > slen && strcmp(result + blen - slen, suffix) == 0) {
            result[blen - slen] = '\0';
        }
    }
    return result;
}

static int smallclueBasenameCommand(int argc, char **argv) {
    bool multiple = false;
    const char *suffix = NULL;
    bool nul_terminate = false;
    int argi = 1;
    for (; argi < argc; ++argi) {
        const char *arg = argv[argi];
        if (strcmp(arg, "--") == 0) {
            argi++;
            break;
        }
        if (strcmp(arg, "-a") == 0 || strcmp(arg, "--multiple") == 0) {
            multiple = true;
        } else if (strcmp(arg, "-s") == 0 || strcmp(arg, "--suffix") == 0) {
            if (argi + 1 >= argc) {
                fprintf(stderr, "basename: option '%s' requires an argument\n", arg);
                return 1;
            }
            suffix = argv[++argi];
            multiple = true;
        } else if (strncmp(arg, "--suffix=", 9) == 0) {
            suffix = arg + 9;
            multiple = true;
        } else if (strcmp(arg, "-z") == 0 || strcmp(arg, "--zero") == 0) {
            nul_terminate = true;
        } else if (arg[0] == '-' && arg[1] != '\0') {
            fprintf(stderr, "basename: unsupported option '%s'\n", arg);
            return 1;
        } else {
            break;
        }
    }
    if (argi >= argc) {
        fprintf(stderr, "basename: missing operand\n");
        return 1;
    }

    if (!multiple) {
        const char *name = argv[argi++];
        const char *singleSuffix = suffix;
        if (argi < argc) {
            singleSuffix = argv[argi++];
        }
        if (argi < argc) {
            fprintf(stderr, "basename: extra operand '%s'\n", argv[argi]);
            return 1;
        }
        char *result = smallclueBasenameOne(name, singleSuffix);
        if (!result) {
            perror("basename");
            return 1;
        }
        fputs(result, stdout);
        putchar(nul_terminate ? '\0' : '\n');
        free(result);
        return 0;
    }

    for (; argi < argc; ++argi) {
        char *result = smallclueBasenameOne(argv[argi], suffix);
        if (!result) {
            perror("basename");
            return 1;
        }
        fputs(result, stdout);
        putchar(nul_terminate ? '\0' : '\n');
        free(result);
    }
    return 0;
}

static int smallclueDirnameCommand(int argc, char **argv) {
    bool nul_terminate = false;
    int argi = 1;
    for (; argi < argc; ++argi) {
        const char *arg = argv[argi];
        if (strcmp(arg, "--") == 0) {
            argi++;
            break;
        }
        if (strcmp(arg, "-z") == 0 || strcmp(arg, "--zero") == 0) {
            nul_terminate = true;
        } else if (arg[0] == '-' && arg[1] != '\0') {
            fprintf(stderr, "dirname: unsupported option '%s'\n", arg);
            return 1;
        } else {
            break;
        }
    }
    if (argi >= argc) {
        fprintf(stderr, "dirname: missing operand\n");
        return 1;
    }
    for (; argi < argc; ++argi) {
        char *path = strdup(argv[argi]);
        if (!path) {
            perror("dirname");
            return 1;
        }
        char *dir = dirname(path);
        if (dir) {
            fputs(dir, stdout);
            putchar(nul_terminate ? '\0' : '\n');
        }
        free(path);
    }
    return 0;
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
    int *files = NULL;
    if (file_count > 0) {
        files = (int *)calloc((size_t)file_count, sizeof(int));
        if (!files) {
            perror("tee");
            return 1;
        }
        for (int i = 0; i < file_count; ++i) {
            int flags = O_WRONLY | O_CREAT | (append ? O_APPEND : O_TRUNC);
            files[i] = open(argv[optind + i], flags, 0666);
            if (files[i] < 0) {
                fprintf(stderr, "tee: %s: %s\n", argv[optind + i], strerror(errno));
            }
        }
    }
    int status = 0;
    char buffer[65536];
    bool stdout_failed = false;
    fflush(stdout); /* flush before transitioning to direct fd writes */
    while (true) {
        ssize_t nread = read(STDIN_FILENO, buffer, sizeof(buffer));
        if (nread < 0) {
            if (errno == EINTR) continue;
            perror("tee");
            status = 1;
            break;
        }
        if (nread == 0) {
            break;
        }
        ssize_t total_written = 0;
        while (!stdout_failed && total_written < nread) {
            ssize_t nw = write(STDOUT_FILENO, buffer + total_written, (size_t)(nread - total_written));
            if (nw < 0) {
                if (errno == EINTR) continue;
                perror("tee: write error");
                status = 1;
                stdout_failed = true;
                break;
            }
            total_written += nw;
        }
        for (int i = 0; i < file_count; ++i) {
            if (files[i] < 0) {
                continue;
            }
            ssize_t file_written = 0;
            while (file_written < nread) {
                ssize_t nw = write(files[i], buffer + file_written, (size_t)(nread - file_written));
                if (nw < 0) {
                    if (errno == EINTR) continue;
                    fprintf(stderr, "tee: %s: %s\n", argv[optind + i], strerror(errno));
                    close(files[i]);
                    files[i] = -1;
                    status = 1;
                    break;
                }
                file_written += nw;
            }
        }
    }
    if (files) {
        for (int i = 0; i < file_count; ++i) {
            if (files[i] >= 0) {
                close(files[i]);
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
static int smallclueMicroCommand(int argc, char **argv) {
    return smallclueRunMicro(argc, argv);
}
#if defined(SMALLCLUE_WITH_DVTM)
static int smallclueDvtmCommand(int argc, char **argv) {
    return smallclueRunDvtm(argc, argv);
}
#endif
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
    fputs("usage: ipaddr [-4|-6] [-a]\n"
          "       ipaddr add|del ADDR/PREFIXLEN dev IFACE\n"
          "       ipaddr flush dev IFACE\n"
          "       ipaddr link set IFACE up|down\n"
          "       ipaddr route add|del DEST/PREFIXLEN|default [via GATEWAY] [dev IFACE]\n",
          stderr);
}

#if defined(__linux__) || defined(linux) || defined(__linux)
/* IPv4-only netlink RTM_NEWADDR/RTM_DELADDR sender for `ipaddr add/del`.
 * Uses a real NETLINK_ROUTE socket (not ioctl SIOCSIFADDR) specifically
 * because ioctl's single-primary-address model can't add a SECOND
 * address to an interface that already has one without clobbering it --
 * netlink supports proper multi-address semantics matching real `ip addr
 * add/del`. IPv6 and CIDR-notation validation beyond a plain prefix
 * length are out of scope. Requires CAP_NET_ADMIN. */
struct smallclueNlAddAddrReq {
    struct nlmsghdr nh;
    struct ifaddrmsg ifa;
    struct rtattr rta_local;
    uint32_t addr_local;
    struct rtattr rta_address;
    uint32_t addr_address;
};

static int smallclueIpAddrModify(const char *ifaceName, const char *addrSpec, bool isAdd) {
    char addrPart[64];
    const char *slash = strchr(addrSpec, '/');
    if (!slash) {
        fprintf(stderr, "ipaddr: %s: expected ADDR/PREFIXLEN\n", addrSpec);
        return 1;
    }
    size_t addrLen = (size_t)(slash - addrSpec);
    if (addrLen == 0 || addrLen >= sizeof(addrPart)) {
        fprintf(stderr, "ipaddr: %s: invalid address\n", addrSpec);
        return 1;
    }
    memcpy(addrPart, addrSpec, addrLen);
    addrPart[addrLen] = '\0';
    int prefixLen = atoi(slash + 1);
    if (prefixLen < 0 || prefixLen > 32) {
        fprintf(stderr, "ipaddr: %s: invalid prefix length\n", addrSpec);
        return 1;
    }
    struct in_addr addr4;
    if (inet_pton(AF_INET, addrPart, &addr4) != 1) {
        fprintf(stderr, "ipaddr: %s: not a valid IPv4 address\n", addrPart);
        return 1;
    }
    unsigned int ifindex = if_nametoindex(ifaceName);
    if (ifindex == 0) {
        fprintf(stderr, "ipaddr: %s: %s\n", ifaceName, strerror(errno));
        return 1;
    }

    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) {
        fprintf(stderr, "ipaddr: netlink socket: %s\n", strerror(errno));
        return 1;
    }

    struct smallclueNlAddAddrReq req;
    memset(&req, 0, sizeof(req));
    req.nh.nlmsg_len = sizeof(req);
    req.nh.nlmsg_type = isAdd ? RTM_NEWADDR : RTM_DELADDR;
    req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    if (isAdd) {
        req.nh.nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;
    }
    req.nh.nlmsg_seq = 1;
    req.ifa.ifa_family = AF_INET;
    req.ifa.ifa_prefixlen = (unsigned char)prefixLen;
    req.ifa.ifa_scope = 0;
    req.ifa.ifa_index = ifindex;
    req.rta_local.rta_len = RTA_LENGTH(sizeof(req.addr_local));
    req.rta_local.rta_type = IFA_LOCAL;
    req.addr_local = addr4.s_addr;
    req.rta_address.rta_len = RTA_LENGTH(sizeof(req.addr_address));
    req.rta_address.rta_type = IFA_ADDRESS;
    req.addr_address = addr4.s_addr;

    struct sockaddr_nl dst;
    memset(&dst, 0, sizeof(dst));
    dst.nl_family = AF_NETLINK;

    if (sendto(sock, &req, req.nh.nlmsg_len, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
        fprintf(stderr, "ipaddr: netlink send: %s\n", strerror(errno));
        close(sock);
        return 1;
    }

    char replyBuf[4096];
    ssize_t n = recv(sock, replyBuf, sizeof(replyBuf), 0);
    close(sock);
    if (n < 0) {
        fprintf(stderr, "ipaddr: netlink recv: %s\n", strerror(errno));
        return 1;
    }
    for (struct nlmsghdr *nh = (struct nlmsghdr *)replyBuf; NLMSG_OK(nh, (size_t)n); nh = NLMSG_NEXT(nh, n)) {
        if (nh->nlmsg_type == NLMSG_ERROR) {
            const struct nlmsgerr *err = (const struct nlmsgerr *)NLMSG_DATA(nh);
            if (err->error != 0) {
                fprintf(stderr, "ipaddr: %s %s/%d on %s: %s\n",
                        isAdd ? "add" : "del", addrPart, prefixLen, ifaceName, strerror(-err->error));
                return 1;
            }
            return 0;
        }
    }
    fprintf(stderr, "ipaddr: no netlink ACK received\n");
    return 1;
}

/* Counts set bits in a netmask -- correct regardless of host/network
 * byte order, since only the bit *count* matters for a prefix length,
 * not which byte holds which bits. */
static int smallclueNetmaskToPrefixLen(uint32_t mask) {
    int count = 0;
    while (mask) {
        count += (int)(mask & 1);
        mask >>= 1;
    }
    return count;
}

/* `ipaddr flush dev IFACE`: enumerates every IPv4 address currently on
 * IFACE (via getifaddrs, matching the "show" path's enumeration) and
 * RTM_DELADDRs each one via the existing smallclueIpAddrModify(), the
 * same real netlink delete `ipaddr del` already uses. IPv6 is out of
 * scope, matching add/del's existing IPv4-only scope. Interfaces with
 * no addresses are a silent no-op success, matching real `ip addr
 * flush`. */
static int smallclueIpAddrFlush(const char *ifaceName) {
    struct ifaddrs *ifaddr = NULL;
    if (getifaddrs(&ifaddr) != 0) {
        fprintf(stderr, "ipaddr: getifaddrs failed: %s\n", strerror(errno));
        return 1;
    }
    int removed = 0;
    int failures = 0;
    for (struct ifaddrs *ifa = ifaddr; ifa; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr || !ifa->ifa_name || !ifa->ifa_netmask) continue;
        if (ifa->ifa_addr->sa_family != AF_INET) continue;
        if (strcmp(ifa->ifa_name, ifaceName) != 0) continue;

        char addrStr[INET_ADDRSTRLEN];
        struct in_addr addr4 = ((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
        if (!inet_ntop(AF_INET, &addr4, addrStr, sizeof(addrStr))) continue;
        uint32_t mask = ((struct sockaddr_in *)ifa->ifa_netmask)->sin_addr.s_addr;
        int prefixLen = smallclueNetmaskToPrefixLen(mask);

        char addrSpec[80];
        snprintf(addrSpec, sizeof(addrSpec), "%s/%d", addrStr, prefixLen);
        if (smallclueIpAddrModify(ifaceName, addrSpec, false) == 0) {
            removed++;
        } else {
            failures++;
        }
    }
    freeifaddrs(ifaddr);
    if (failures > 0) return 1;
    (void)removed;
    return 0;
}

/* Reads one netlink ACK/error reply and reports it; shared by the link
 * and route senders below (smallclueIpAddrModify above has its own
 * inline copy, predating this helper). */
static int smallclueNlReadAck(int sock, const char *context) {
    char replyBuf[4096];
    ssize_t n = recv(sock, replyBuf, sizeof(replyBuf), 0);
    if (n < 0) {
        fprintf(stderr, "ipaddr: netlink recv: %s\n", strerror(errno));
        return 1;
    }
    for (struct nlmsghdr *nh = (struct nlmsghdr *)replyBuf; NLMSG_OK(nh, (size_t)n); nh = NLMSG_NEXT(nh, n)) {
        if (nh->nlmsg_type == NLMSG_ERROR) {
            const struct nlmsgerr *err = (const struct nlmsgerr *)NLMSG_DATA(nh);
            if (err->error != 0) {
                fprintf(stderr, "ipaddr: %s: %s\n", context, strerror(-err->error));
                return 1;
            }
            return 0;
        }
    }
    fprintf(stderr, "ipaddr: no netlink ACK received\n");
    return 1;
}

struct smallclueNlLinkReq {
    struct nlmsghdr nh;
    struct ifinfomsg ifi;
};

static int smallclueIpLinkSetUpDown(const char *ifaceName, bool up) {
    unsigned int ifindex = if_nametoindex(ifaceName);
    if (ifindex == 0) {
        fprintf(stderr, "ipaddr: %s: %s\n", ifaceName, strerror(errno));
        return 1;
    }
    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) {
        fprintf(stderr, "ipaddr: netlink socket: %s\n", strerror(errno));
        return 1;
    }
    struct smallclueNlLinkReq req;
    memset(&req, 0, sizeof(req));
    req.nh.nlmsg_len = sizeof(req);
    req.nh.nlmsg_type = RTM_NEWLINK;
    req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.nh.nlmsg_seq = 1;
    req.ifi.ifi_family = AF_UNSPEC;
    req.ifi.ifi_index = (int)ifindex;
    req.ifi.ifi_flags = up ? IFF_UP : 0;
    req.ifi.ifi_change = IFF_UP; /* only the UP bit is being changed */

    struct sockaddr_nl dst;
    memset(&dst, 0, sizeof(dst));
    dst.nl_family = AF_NETLINK;
    if (sendto(sock, &req, req.nh.nlmsg_len, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
        fprintf(stderr, "ipaddr: netlink send: %s\n", strerror(errno));
        close(sock);
        return 1;
    }
    char ctx[256];
    snprintf(ctx, sizeof(ctx), "link set %s %s", ifaceName, up ? "up" : "down");
    int rc = smallclueNlReadAck(sock, ctx);
    close(sock);
    return rc;
}

/* IPv4-only netlink RTM_NEWROUTE/RTM_DELROUTE sender for `ipaddr route
 * add/del`. Supports the common forms: a plain destination network
 * (DEST/PREFIXLEN or the "default" shorthand for 0.0.0.0/0), an
 * optional gateway (`via ADDR`), and/or an optional outgoing interface
 * (`dev IFACE`) -- at least one of the two must be given, matching real
 * `ip route`. */
struct smallclueNlRouteReq {
    struct nlmsghdr nh;
    struct rtmsg rt;
    struct rtattr rta_dst;
    uint32_t addr_dst;
    /* RTA_GATEWAY and RTA_OIF appended dynamically after this fixed part,
     * sized generously in the buffer below. */
};

static int smallclueIpRouteModify(const char *destSpec, const char *gateway, const char *iface, bool isAdd) {
    struct in_addr dstAddr;
    int prefixLen;
    if (strcmp(destSpec, "default") == 0) {
        dstAddr.s_addr = 0;
        prefixLen = 0;
    } else {
        char addrPart[64];
        const char *slash = strchr(destSpec, '/');
        if (!slash) {
            fprintf(stderr, "ipaddr: %s: expected DEST/PREFIXLEN or 'default'\n", destSpec);
            return 1;
        }
        size_t addrLen = (size_t)(slash - destSpec);
        if (addrLen == 0 || addrLen >= sizeof(addrPart)) {
            fprintf(stderr, "ipaddr: %s: invalid destination\n", destSpec);
            return 1;
        }
        memcpy(addrPart, destSpec, addrLen);
        addrPart[addrLen] = '\0';
        prefixLen = atoi(slash + 1);
        if (prefixLen < 0 || prefixLen > 32) {
            fprintf(stderr, "ipaddr: %s: invalid prefix length\n", destSpec);
            return 1;
        }
        if (inet_pton(AF_INET, addrPart, &dstAddr) != 1) {
            fprintf(stderr, "ipaddr: %s: not a valid IPv4 address\n", addrPart);
            return 1;
        }
    }
    struct in_addr gwAddr;
    bool haveGw = false;
    if (gateway) {
        if (inet_pton(AF_INET, gateway, &gwAddr) != 1) {
            fprintf(stderr, "ipaddr: %s: not a valid IPv4 gateway address\n", gateway);
            return 1;
        }
        haveGw = true;
    }
    unsigned int ifindex = 0;
    if (iface) {
        ifindex = if_nametoindex(iface);
        if (ifindex == 0) {
            fprintf(stderr, "ipaddr: %s: %s\n", iface, strerror(errno));
            return 1;
        }
    }
    if (!haveGw && ifindex == 0) {
        fprintf(stderr, "ipaddr: route needs at least 'via GATEWAY' or 'dev IFACE'\n");
        return 1;
    }

    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) {
        fprintf(stderr, "ipaddr: netlink socket: %s\n", strerror(errno));
        return 1;
    }

    unsigned char buf[512];
    memset(buf, 0, sizeof(buf));
    struct nlmsghdr *nh = (struct nlmsghdr *)buf;
    struct rtmsg *rt = (struct rtmsg *)NLMSG_DATA(nh);
    nh->nlmsg_type = isAdd ? RTM_NEWROUTE : RTM_DELROUTE;
    nh->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    if (isAdd) nh->nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;
    nh->nlmsg_seq = 1;
    nh->nlmsg_len = NLMSG_LENGTH(sizeof(*rt));

    rt->rtm_family = AF_INET;
    rt->rtm_dst_len = (unsigned char)prefixLen;
    rt->rtm_src_len = 0;
    rt->rtm_tos = 0;
    rt->rtm_table = RT_TABLE_MAIN;
    rt->rtm_protocol = RTPROT_STATIC;
    rt->rtm_scope = haveGw ? RT_SCOPE_UNIVERSE : RT_SCOPE_LINK;
    rt->rtm_type = RTN_UNICAST;
    rt->rtm_flags = 0;

    if (prefixLen > 0 || strcmp(destSpec, "default") != 0) {
        struct rtattr *rta = (struct rtattr *)((char *)nh + NLMSG_ALIGN(nh->nlmsg_len));
        rta->rta_type = RTA_DST;
        rta->rta_len = RTA_LENGTH(sizeof(uint32_t));
        memcpy(RTA_DATA(rta), &dstAddr.s_addr, sizeof(uint32_t));
        nh->nlmsg_len = NLMSG_ALIGN(nh->nlmsg_len) + RTA_LENGTH(sizeof(uint32_t));
    }
    if (haveGw) {
        struct rtattr *rta = (struct rtattr *)((char *)nh + NLMSG_ALIGN(nh->nlmsg_len));
        rta->rta_type = RTA_GATEWAY;
        rta->rta_len = RTA_LENGTH(sizeof(uint32_t));
        memcpy(RTA_DATA(rta), &gwAddr.s_addr, sizeof(uint32_t));
        nh->nlmsg_len = NLMSG_ALIGN(nh->nlmsg_len) + RTA_LENGTH(sizeof(uint32_t));
    }
    if (ifindex != 0) {
        struct rtattr *rta = (struct rtattr *)((char *)nh + NLMSG_ALIGN(nh->nlmsg_len));
        rta->rta_type = RTA_OIF;
        uint32_t idx = ifindex;
        rta->rta_len = RTA_LENGTH(sizeof(uint32_t));
        memcpy(RTA_DATA(rta), &idx, sizeof(uint32_t));
        nh->nlmsg_len = NLMSG_ALIGN(nh->nlmsg_len) + RTA_LENGTH(sizeof(uint32_t));
    }

    struct sockaddr_nl dst;
    memset(&dst, 0, sizeof(dst));
    dst.nl_family = AF_NETLINK;
    if (sendto(sock, buf, nh->nlmsg_len, 0, (struct sockaddr *)&dst, sizeof(dst)) < 0) {
        fprintf(stderr, "ipaddr: netlink send: %s\n", strerror(errno));
        close(sock);
        return 1;
    }
    char ctx[256];
    snprintf(ctx, sizeof(ctx), "route %s %s", isAdd ? "add" : "del", destSpec);
    int rc = smallclueNlReadAck(sock, ctx);
    close(sock);
    return rc;
}
#endif

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
    if (argc >= 2 && (strcmp(argv[1], "add") == 0 || strcmp(argv[1], "del") == 0)) {
#if defined(__linux__) || defined(linux) || defined(__linux)
        bool isAdd = strcmp(argv[1], "add") == 0;
        /* ADDR/PREFIXLEN dev IFACE */
        if (argc != 5 || strcmp(argv[3], "dev") != 0) {
            smallclueIpAddrUsage();
            return 1;
        }
        return smallclueIpAddrModify(argv[4], argv[2], isAdd);
#else
        fprintf(stderr, "ipaddr: add/del is only supported on Linux (needs netlink)\n");
        return 1;
#endif
    }
    if (argc >= 2 && strcmp(argv[1], "flush") == 0) {
#if defined(__linux__) || defined(linux) || defined(__linux)
        /* flush dev IFACE */
        if (argc != 4 || strcmp(argv[2], "dev") != 0) {
            smallclueIpAddrUsage();
            return 1;
        }
        return smallclueIpAddrFlush(argv[3]);
#else
        fprintf(stderr, "ipaddr: flush is only supported on Linux (needs netlink)\n");
        return 1;
#endif
    }
    if (argc >= 2 && strcmp(argv[1], "link") == 0) {
#if defined(__linux__) || defined(linux) || defined(__linux)
        /* link set IFACE up|down */
        if (argc != 5 || strcmp(argv[2], "set") != 0 ||
            (strcmp(argv[4], "up") != 0 && strcmp(argv[4], "down") != 0)) {
            smallclueIpAddrUsage();
            return 1;
        }
        return smallclueIpLinkSetUpDown(argv[3], strcmp(argv[4], "up") == 0);
#else
        fprintf(stderr, "ipaddr: link set is only supported on Linux (needs netlink)\n");
        return 1;
#endif
    }
    if (argc >= 2 && strcmp(argv[1], "route") == 0) {
#if defined(__linux__) || defined(linux) || defined(__linux)
        /* route add|del DEST[/PREFIXLEN]|default [via GATEWAY] [dev IFACE] */
        if (argc < 4 || (strcmp(argv[2], "add") != 0 && strcmp(argv[2], "del") != 0)) {
            smallclueIpAddrUsage();
            return 1;
        }
        bool isAdd = strcmp(argv[2], "add") == 0;
        const char *dest = argv[3];
        const char *gateway = NULL;
        const char *iface = NULL;
        int i = 4;
        while (i < argc) {
            if (strcmp(argv[i], "via") == 0 && i + 1 < argc) {
                gateway = argv[i + 1];
                i += 2;
            } else if (strcmp(argv[i], "dev") == 0 && i + 1 < argc) {
                iface = argv[i + 1];
                i += 2;
            } else {
                smallclueIpAddrUsage();
                return 1;
            }
        }
        return smallclueIpRouteModify(dest, gateway, iface, isAdd);
#else
        fprintf(stderr, "ipaddr: route add/del is only supported on Linux (needs netlink)\n");
        return 1;
#endif
    }
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
    const char *query_path = path;
#if defined(PSCAL_TARGET_IOS)
    char resolved_path[PATH_MAX];
    const char *resolved = smallclueResolvePath(path, resolved_path, sizeof(resolved_path));
    if (resolved && resolved[0] != '\0') {
        query_path = resolved;
    }
#endif
#if defined(SMALLCLUE_HAVE_STATVFS)
    struct statvfs st;
    if (statvfs(query_path, &st) != 0) {
        return false;
    }
    unsigned long long block_size = st.f_frsize ? st.f_frsize : st.f_bsize;
#elif defined(SMALLCLUE_HAVE_STATFS)
    struct statfs st;
    if (statfs(query_path, &st) != 0) {
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
        if (realpath(query_path, resolved)) {
            label = resolved;
        }
        strncpy(out->mount_point, label, sizeof(out->mount_point) - 1);
        out->mount_point[sizeof(out->mount_point) - 1] = '\0';
    }
    return true;
}

/* Enumerates every mounted filesystem so bare `df` (no path arguments)
 * lists all mounts like the real tool, instead of only reporting the
 * current directory's filesystem. Returns a malloc'd array of malloc'd
 * mount-point strings; caller frees each element and the array. */
#if defined(__linux__) || defined(linux) || defined(__linux)
static char **smallclueDfEnumerateMounts(size_t *outCount) {
    FILE *fp = fopen("/proc/mounts", "r");
    if (!fp) fp = fopen("/etc/mtab", "r");
    if (!fp) {
        *outCount = 0;
        return NULL;
    }
    char **list = NULL;
    size_t count = 0, capacity = 0;
    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        char device[256], mountpoint[512], fstype[64];
        if (sscanf(line, "%255s %511s %63s", device, mountpoint, fstype) != 3) continue;
        /* Skip pseudo/virtual filesystems with no meaningful disk usage,
         * matching real df's own dummy-filesystem exclusion. */
        static const char *skipTypes[] = {
            "proc", "sysfs", "devtmpfs", "cgroup", "cgroup2", "devpts",
            "securityfs", "debugfs", "tracefs", "pstore", "mqueue",
            "hugetlbfs", "configfs", "bpf", "autofs", "fusectl", "tmpfs",
            "overlay", "squashfs", "binfmt_misc", "efivarfs", "rpc_pipefs",
        };
        bool skip = false;
        for (size_t s = 0; s < sizeof(skipTypes) / sizeof(skipTypes[0]); ++s) {
            if (strcmp(fstype, skipTypes[s]) == 0) {
                skip = true;
                break;
            }
        }
        if (skip) continue;
        if (count == capacity) {
            capacity = capacity ? capacity * 2 : 16;
            char **resized = (char **)realloc(list, capacity * sizeof(char *));
            if (!resized) break;
            list = resized;
        }
        list[count] = strdup(mountpoint);
        if (list[count]) count++;
    }
    fclose(fp);
    *outCount = count;
    return list;
}
#elif defined(SMALLCLUE_HAVE_STATFS)
static char **smallclueDfEnumerateMounts(size_t *outCount) {
    struct statfs *mounts = NULL;
    int n = getmntinfo(&mounts, MNT_NOWAIT);
    if (n <= 0) {
        *outCount = 0;
        return NULL;
    }
    char **list = (char **)calloc((size_t)n, sizeof(char *));
    if (!list) {
        *outCount = 0;
        return NULL;
    }
    size_t count = 0;
    for (int i = 0; i < n; ++i) {
        list[count] = strdup(mounts[i].f_mntonname);
        if (list[count]) count++;
    }
    *outCount = count;
    return list;
}
#else
static char **smallclueDfEnumerateMounts(size_t *outCount) {
    *outCount = 0;
    return NULL;
}
#endif

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
    if (isatty(STDOUT_FILENO)) {
        printf("\033[1m%-24s %12s %12s %12s %6s %s\033[0m\n",
               "Filesystem",
               human ? "Size" : "1K-blocks",
               human ? "Used" : "Used",
               human ? "Avail" : "Avail",
               "Use%",
               "Mounted on");
    } else {
        printf("%-24s %12s %12s %12s %6s %s\n",
               "Filesystem",
               human ? "Size" : "1K-blocks",
               human ? "Used" : "Used",
               human ? "Avail" : "Avail",
               "Use%",
               "Mounted on");
    }
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

    char **allMounts = NULL;
    size_t allMountsCount = 0;
    if (path_count == 0) {
        allMounts = smallclueDfEnumerateMounts(&allMountsCount);
    }
    size_t iterCount = (path_count > 0) ? (size_t)path_count
                        : (allMountsCount > 0) ? allMountsCount
                        : 1;

    for (size_t i = 0; i < iterCount; ++i) {
        const char *path;
        if (path_count > 0) {
            path = argv[path_start + i];
        } else if (allMountsCount > 0) {
            path = allMounts[i];
        } else {
            path = ".";
        }
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

    if (allMounts) {
        for (size_t i = 0; i < allMountsCount; ++i) free(allMounts[i]);
        free(allMounts);
    }
    return status;
}
enum {
    SMALLCLUE_PING_PAYLOAD_SIZE = 56
};

static uint16_t smallclueInternetChecksum(const void *data, size_t len) {
    const uint8_t *bytes = (const uint8_t *)data;
    uint32_t sum = 0;
    while (len > 1) {
        sum += (uint32_t)((bytes[0] << 8) | bytes[1]);
        bytes += 2;
        len -= 2;
    }
    if (len > 0) {
        sum += (uint32_t)(bytes[0] << 8);
    }
    while ((sum >> 16) != 0) {
        sum = (sum & 0xffffu) + (sum >> 16);
    }
    return (uint16_t)~sum;
}

/* Note on the `ident` parameter: Linux's unprivileged ICMP "ping socket"
 * (SOCK_DGRAM + IPPROTO_ICMP/IPPROTO_ICMPV6) rewrites the packet's id
 * field to the socket's kernel-assigned local port on send -- confirmed
 * against a real Linux kernel in Docker, where the reply's id never
 * matched the id we set. Validating the reply's id against our original
 * value is therefore unreliable and was a real (if previously untriggered
 * on this dev machine's non-Linux ping stack) bug. Each attempt already
 * uses a freshly connected, exclusive socket for exactly one request/
 * reply, so the OS itself guarantees this reply belongs to us; only the
 * sequence number (which the kernel does NOT rewrite) is checked here. */
static bool smallcluePingDecodeReply(const unsigned char *buf, size_t len,
        uint16_t seq, size_t *out_reply_len) {
    const struct icmp *icmp_hdr = NULL;
    size_t reply_len = len;

    if (len >= sizeof(struct ip)) {
        const struct ip *ip_hdr = (const struct ip *)buf;
        if (ip_hdr->ip_v == 4) {
            size_t ip_len = (size_t)ip_hdr->ip_hl << 2;
            if (ip_len >= sizeof(struct ip) && len >= ip_len + ICMP_MINLEN) {
                icmp_hdr = (const struct icmp *)(buf + ip_len);
                reply_len = len - ip_len;
            }
        }
    }
    if (!icmp_hdr && len >= ICMP_MINLEN) {
        icmp_hdr = (const struct icmp *)buf;
        reply_len = len;
    }
    if (!icmp_hdr) {
        errno = EPROTO;
        return false;
    }
    if (icmp_hdr->icmp_type != ICMP_ECHOREPLY) {
        errno = EPROTO;
        return false;
    }
    if (ntohs((uint16_t)icmp_hdr->icmp_seq) != seq) {
        errno = EPROTO;
        return false;
    }
    if (out_reply_len) {
        *out_reply_len = reply_len;
    }
    return true;
}

/* ICMPv6 "ping socket" (SOCK_DGRAM, IPPROTO_ICMPV6) replies deliver just
 * the ICMPv6 payload with no IPv6 header prepended (unlike the IPv4 path
 * above, which defensively handles both cases) -- verified against a real
 * Linux kernel in Docker. See smallcluePingDecodeReply's comment on why
 * the id field isn't checked. */
static bool smallcluePing6DecodeReply(const unsigned char *buf, size_t len,
        uint16_t seq, size_t *out_reply_len) {
    if (len < sizeof(struct icmp6_hdr)) {
        errno = EPROTO;
        return false;
    }
    const struct icmp6_hdr *icmp6 = (const struct icmp6_hdr *)buf;
    if (icmp6->icmp6_type != ICMP6_ECHO_REPLY) {
        errno = EPROTO;
        return false;
    }
    if (ntohs(icmp6->icmp6_seq) != seq) {
        errno = EPROTO;
        return false;
    }
    if (out_reply_len) {
        *out_reply_len = len;
    }
    return true;
}

static int smallcluePingAttempt(int family, const struct sockaddr *target_addr, socklen_t target_len,
        int timeout_ms, uint16_t ident, uint16_t seq, double *out_ms, size_t *out_reply_len) {
    if (!target_addr) {
        errno = EINVAL;
        return -1;
    }

    int sock = socket(family, SOCK_DGRAM, family == AF_INET6 ? IPPROTO_ICMPV6 : IPPROTO_ICMP);
    if (sock < 0) {
        return -1;
    }

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        close(sock);
        return -1;
    }

    if (connect(sock, target_addr, target_len) < 0) {
        close(sock);
        return -1;
    }

    unsigned char packet[sizeof(struct icmp6_hdr) + SMALLCLUE_PING_PAYLOAD_SIZE];
    size_t hdrLen = (family == AF_INET6) ? sizeof(struct icmp6_hdr) : ICMP_MINLEN;
    size_t packetLen = hdrLen + SMALLCLUE_PING_PAYLOAD_SIZE;
    memset(packet, 0, sizeof(packet));
    for (size_t i = hdrLen; i < packetLen; ++i) {
        packet[i] = (unsigned char)(i & 0xffu);
    }
    if (family == AF_INET6) {
        struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)packet;
        icmp6->icmp6_type = ICMP6_ECHO_REQUEST;
        icmp6->icmp6_code = 0;
        icmp6->icmp6_id = htons(ident);
        icmp6->icmp6_seq = htons(seq);
        /* icmp6_cksum is left at 0: the kernel computes it for ICMPv6
         * ping sockets since only the kernel knows the real source
         * address needed for the IPv6 pseudo-header. */
    } else {
        struct icmp *icmp_hdr = (struct icmp *)packet;
        icmp_hdr->icmp_type = ICMP_ECHO;
        icmp_hdr->icmp_code = 0;
        icmp_hdr->icmp_id = htons(ident);
        icmp_hdr->icmp_seq = htons(seq);
        icmp_hdr->icmp_cksum = 0;
        icmp_hdr->icmp_cksum = smallclueInternetChecksum(packet, packetLen);
    }

    struct timespec start;
    if (clock_gettime(CLOCK_MONOTONIC, &start) != 0) {
        close(sock);
        return -1;
    }

    ssize_t sent = send(sock, packet, packetLen, 0);
    if (sent != (ssize_t)packetLen) {
        if (sent >= 0) {
            errno = EIO;
        }
        close(sock);
        return -1;
    }

    unsigned char reply[1500];
    for (;;) {
        ssize_t received = recv(sock, reply, sizeof(reply), 0);
        if (received < 0) {
            close(sock);
            return -1;
        }

        struct timespec end;
        if (clock_gettime(CLOCK_MONOTONIC, &end) != 0) {
            close(sock);
            return -1;
        }

        size_t reply_len = 0;
        bool ok = (family == AF_INET6)
            ? smallcluePing6DecodeReply(reply, (size_t)received, seq, &reply_len)
            : smallcluePingDecodeReply(reply, (size_t)received, seq, &reply_len);
        if (!ok) {
            continue;
        }

        if (out_ms) {
            double start_ms = (double)start.tv_sec * 1000.0 + (double)start.tv_nsec / 1e6;
            double end_ms = (double)end.tv_sec * 1000.0 + (double)end.tv_nsec / 1e6;
            *out_ms = end_ms - start_ms;
        }
        if (out_reply_len) {
            *out_reply_len = reply_len;
        }
        close(sock);
        return 0;
    }
}

static int smallcluePingCommand(int argc, char **argv) {
    const char *usage = "usage: ping [-4|-6] [-c count] [-t timeout_ms] host\n";
    if (argc <= 1) {
        fputs(usage, stderr);
        return 1;
    }

    smallclueResetGetopt();
    int count = 4;
    int timeout_ms = 3000;
    int forceFamily = AF_UNSPEC;
    int opt;
    while ((opt = getopt(argc, argv, "46c:t:")) != -1) {
        switch (opt) {
            case '4':
                forceFamily = AF_INET;
                break;
            case '6':
                forceFamily = AF_INET6;
                break;
            case 'c':
                count = atoi(optarg);
                if (count <= 0) {
                    count = 4;
                }
                break;
            case 't':
                timeout_ms = atoi(optarg);
                if (timeout_ms <= 0) {
                    timeout_ms = 3000;
                }
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
#if defined(PSCAL_TARGET_IOS)
    if (PSCALRuntimePingHost) {
        char *output = NULL;
        int status = PSCALRuntimePingHost(host, count, timeout_ms, &output);
        if (output) {
            fputs(output, stdout);
            free(output);
        }
        return status;
    }
#endif

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;

    struct addrinfo *res = NULL;
    int gai = pscalHostsGetAddrInfo(host, NULL, &hints, &res);
    if (gai != 0) {
        fprintf(stderr, "ping: %s: %s\n", host, gai_strerror(gai));
        return 1;
    }

    struct addrinfo *selected = NULL;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        if (forceFamily != AF_UNSPEC && ai->ai_family != forceFamily) continue;
        if ((ai->ai_family == AF_INET && ai->ai_addrlen >= sizeof(struct sockaddr_in)) ||
            (ai->ai_family == AF_INET6 && ai->ai_addrlen >= sizeof(struct sockaddr_in6))) {
            selected = ai;
            break;
        }
    }
    if (!selected) {
        fprintf(stderr, "ping: %s: no ICMP-capable address resolved\n", host);
        pscalHostsFreeAddrInfo(res);
        return 1;
    }

    struct sockaddr_storage target_addr;
    socklen_t target_len = (socklen_t)selected->ai_addrlen;
    memcpy(&target_addr, selected->ai_addr, target_len);
    int family = selected->ai_family;

    char addrbuf[NI_MAXHOST];
    if (getnameinfo((struct sockaddr *)&target_addr, target_len,
            addrbuf, sizeof(addrbuf), NULL, 0, NI_NUMERICHOST) != 0) {
        strncpy(addrbuf, "unknown", sizeof(addrbuf));
        addrbuf[sizeof(addrbuf) - 1] = '\0';
    }

    printf("PING %s (%s): %d data bytes\n", host, addrbuf, SMALLCLUE_PING_PAYLOAD_SIZE);

    int successes = 0;
    double min_ms = 0.0;
    double max_ms = 0.0;
    double total_ms = 0.0;
    uint16_t ident = (uint16_t)(getpid() & 0xffff);

    for (int i = 0; i < count; ++i) {
        double elapsed_ms = 0.0;
        size_t reply_len = 0;
        int rc = smallcluePingAttempt(family, (struct sockaddr *)&target_addr, target_len,
            timeout_ms, ident, (uint16_t)(i + 1), &elapsed_ms, &reply_len);
        if (rc == 0) {
            successes++;
            if (successes == 1 || elapsed_ms < min_ms) {
                min_ms = elapsed_ms;
            }
            if (elapsed_ms > max_ms) {
                max_ms = elapsed_ms;
            }
            total_ms += elapsed_ms;
            printf("%zu bytes from %s: icmp_seq=%d time=%.3f ms\n",
                reply_len, addrbuf, i + 1, elapsed_ms);
        } else {
            printf("Request timeout for icmp_seq %d (%s)\n", i + 1, strerror(errno));
        }
        fflush(stdout);
        if (i + 1 < count) {
            usleep(1000000);
        }
    }

    printf("--- %s ping statistics ---\n", host);
    printf("%d packets transmitted, %d packets received, %.1f%% packet loss\n",
        count, successes, count > 0 ? ((double)(count - successes) * 100.0 / (double)count) : 0.0);
    if (successes > 0) {
        printf("round-trip min/avg/max = %.3f/%.3f/%.3f ms\n",
            min_ms, total_ms / (double)successes, max_ms);
    }

    pscalHostsFreeAddrInfo(res);
    return (successes > 0) ? 0 : 1;
}

#define TELNET_DEFAULT_PORT 23
#define TELNET_BUF_SIZE 4096

/* Telnet protocol constants (RFC 854) -- defined locally rather than
 * pulled from <arpa/telnet.h> since that header isn't guaranteed to
 * exist on every target libc (e.g. musl, used on the actual deployment
 * target). Only the handful this minimal client actually needs. */
#define TELNET_IAC  255
#define TELNET_DONT 254
#define TELNET_DO   253
#define TELNET_WONT 252
#define TELNET_WILL 251
#define TELNET_SB   250
#define TELNET_SE   240

typedef enum {
    TELNET_PARSE_DATA,
    TELNET_PARSE_IAC,
    TELNET_PARSE_CMD,   /* saw IAC DO/DONT/WILL/WONT, waiting for the option byte */
    TELNET_PARSE_SB,     /* inside IAC SB ... waiting for IAC SE to close it */
    TELNET_PARSE_SB_IAC, /* inside SB, saw an IAC, check if next is SE */
} SmallclueTelnetParseState;

typedef struct {
    SmallclueTelnetParseState state;
    unsigned char pendingCmd; /* the DO/DONT/WILL/WONT byte, valid in TELNET_PARSE_CMD */
} SmallclueTelnetParser;

/* Feeds one byte of server output through the telnet negotiation state
 * machine. Plain data bytes are appended to `out`; IAC-prefixed option
 * negotiation (DO/DONT/WILL/WONT <option>) is intercepted and answered
 * immediately on `sock` (this client declines every option: WONT in
 * reply to DO, DONT in reply to WILL -- the standard minimal-client
 * response when there's nothing to actually negotiate), and IAC SB ...
 * IAC SE subnegotiation blocks are consumed without being echoed. A
 * doubled IAC IAC in the data stream is the escape for a literal 0xFF
 * byte and is unescaped back to a single 0xFF. */
static void smallclueTelnetFeedByte(SmallclueTelnetParser *p, unsigned char c, int sock,
                                    unsigned char *out, size_t *outLen) {
    switch (p->state) {
        case TELNET_PARSE_DATA:
            if (c == TELNET_IAC) {
                p->state = TELNET_PARSE_IAC;
            } else {
                out[(*outLen)++] = c;
            }
            break;
        case TELNET_PARSE_IAC:
            if (c == TELNET_IAC) {
                out[(*outLen)++] = TELNET_IAC;
                p->state = TELNET_PARSE_DATA;
            } else if (c == TELNET_DO || c == TELNET_DONT || c == TELNET_WILL || c == TELNET_WONT) {
                p->pendingCmd = c;
                p->state = TELNET_PARSE_CMD;
            } else if (c == TELNET_SB) {
                p->state = TELNET_PARSE_SB;
            } else {
                /* Single-byte commands (NOP, AYT, etc.) and anything else
                 * unrecognized: consume and return to plain data. */
                p->state = TELNET_PARSE_DATA;
            }
            break;
        case TELNET_PARSE_CMD: {
            unsigned char reply[3] = { TELNET_IAC, 0, c };
            if (p->pendingCmd == TELNET_DO) {
                reply[1] = TELNET_WONT;
                (void)write(sock, reply, sizeof(reply));
            } else if (p->pendingCmd == TELNET_WILL) {
                reply[1] = TELNET_DONT;
                (void)write(sock, reply, sizeof(reply));
            }
            /* DONT/WONT from the server need no reply -- we already
             * aren't doing whatever it is. */
            p->state = TELNET_PARSE_DATA;
            break;
        }
        case TELNET_PARSE_SB:
            if (c == TELNET_IAC) {
                p->state = TELNET_PARSE_SB_IAC;
            }
            break;
        case TELNET_PARSE_SB_IAC:
            if (c == TELNET_SE) {
                p->state = TELNET_PARSE_DATA;
            } else {
                /* Not actually the closing IAC SE -- back into the
                 * subnegotiation body. */
                p->state = TELNET_PARSE_SB;
            }
            break;
    }
}

static int smallclueTelnetCommand(int argc, char **argv) {
    signal(SIGPIPE, SIG_IGN);
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
    SmallclueTelnetParser parser;
    memset(&parser, 0, sizeof(parser));
    parser.state = TELNET_PARSE_DATA;
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
            unsigned char buf[TELNET_BUF_SIZE];
            ssize_t n = read(sock, buf, sizeof(buf));
            if (n <= 0) {
                running = false;
            } else {
                unsigned char plain[TELNET_BUF_SIZE];
                size_t plainLen = 0;
                for (ssize_t i = 0; i < n; ++i) {
                    smallclueTelnetFeedByte(&parser, buf[i], sock, plain, &plainLen);
                }
                ssize_t off = 0;
                while (off < (ssize_t)plainLen) {
                    ssize_t w = write(STDOUT_FILENO, plain + off, plainLen - (size_t)off);
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
#if defined(PSCAL_TARGET_IOS)
    pthread_t bypass_tid = pthread_self();
    vprocRegisterInterposeBypassThread(bypass_tid);
#endif

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
#if defined(PSCAL_TARGET_IOS)
        vprocUnregisterInterposeBypassThread(bypass_tid);
#endif
        return 1;
    }

    int recv_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
    if (recv_sock < 0) {
        fprintf(stderr, "traceroute: unable to open ICMP socket: %s\n", strerror(errno));
        pscalHostsFreeAddrInfo(res);
#if defined(PSCAL_TARGET_IOS)
        vprocUnregisterInterposeBypassThread(bypass_tid);
#endif
        return 1;
    }

    int send_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (send_sock < 0) {
        fprintf(stderr, "traceroute: unable to open UDP socket: %s\n", strerror(errno));
        close(recv_sock);
        pscalHostsFreeAddrInfo(res);
#if defined(PSCAL_TARGET_IOS)
        vprocUnregisterInterposeBypassThread(bypass_tid);
#endif
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
    pscalHostsFreeAddrInfo(res);
#if defined(PSCAL_TARGET_IOS)
    vprocUnregisterInterposeBypassThread(bypass_tid);
#endif
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
#endif

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

#if defined(PSCAL_TARGET_IOS)
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
#elif defined(__linux__) || defined(linux) || defined(__linux)
    int len = klogctl(10, NULL, 0); // SYSLOG_ACTION_SIZE_BUFFER
    if (len < 0) {
        perror("dmesg: klogctl size");
        return 1;
    }
    char *buf = (char *)malloc((size_t)len + 1);
    if (!buf) {
        fprintf(stderr, "dmesg: out of memory\n");
        return 1;
    }
    int n = klogctl(3, buf, len); // SYSLOG_ACTION_READ_ALL
    if (n < 0) {
        perror("dmesg: klogctl read");
        free(buf);
        return 1;
    }
    buf[n] = 0;
    fputs(buf, stdout);
    if (n > 0 && buf[n-1] != '\n') {
        putchar('\n');
    }
    free(buf);
    return 0;
#else
    fprintf(stderr, "dmesg: not supported on this platform\n");
    return 1;
#endif
}

static int smallclueCatCommand(int argc, char **argv) {
    SmallclueCatOptions opts;
    memset(&opts, 0, sizeof(opts));
    int argi = 1;
    for (; argi < argc; ++argi) {
        const char *arg = argv[argi];
        if (!arg || arg[0] != '-' || strcmp(arg, "-") == 0) break;
        if (strcmp(arg, "--") == 0) { argi++; break; }
        for (const char *p = arg + 1; *p; ++p) {
            switch (*p) {
                case 'n': opts.numberAll = true; break;
                case 'b': opts.numberNonBlank = true; break;
                case 'E': opts.showEnds = true; break;
                case 'T': opts.showTabs = true; break;
                case 's': opts.squeezeBlank = true; break;
                case 'A': opts.showEnds = true; opts.showTabs = true; break;
                default:
                    fprintf(stderr, "cat: unsupported option -%c\n", *p);
                    return 1;
            }
        }
    }

    bool anyFlag = opts.numberAll || opts.numberNonBlank || opts.showEnds ||
                  opts.showTabs || opts.squeezeBlank;
    int status = 0;
    if (!anyFlag) {
        if (argi >= argc) {
            return cat_file(NULL);
        }
        for (int i = argi; i < argc; ++i) {
            status |= cat_file(argv[i]);
        }
        return status ? 1 : 0;
    }

    long lineNo = 0;
    bool prevBlank = false;
    if (argi >= argc) {
        return smallclueCatFileFormatted(NULL, &opts, &lineNo, &prevBlank);
    }
    for (int i = argi; i < argc; ++i) {
        status |= smallclueCatFileFormatted(argv[i], &opts, &lineNo, &prevBlank);
    }
    return status ? 1 : 0;
}

static const char *smallcluePagerDisplayName(const char *path) {
    if (!path || !*path || strcmp(path, "(stdin)") == 0) {
        return "(stdin)";
    }
    const char *slash = strrchr(path, '/');
    if (slash && slash[1] != '\0') {
        return slash + 1;
    }
    return path;
}

static int smallcluePagerCommand(int argc, char **argv) {
    const char *cmd_name = pager_command_name(argv && argc > 0 ? argv[0] : NULL);
    smallclueResetGetopt();
    int opt;
    bool raw_mode = false;
    while ((opt = getopt(argc, argv, "rR")) != -1) {
        switch (opt) {
            case 'r':
            case 'R':
                raw_mode = true;
                break;
            default:
                /* Ignore unknown options or treat as error? */
                break;
        }
    }

    int status = 0;
    int file_count = argc - optind;
    if (optind >= argc) {
        if (pscalRuntimeStdinIsInteractive()) {
            fprintf(stderr, "%s: missing filename\n", cmd_name);
            return 1;
        }
        return pager_file(cmd_name, "(stdin)", NULL, stdin, raw_mode);
    }
    for (int i = optind; i < argc; ++i) {
        const char *path = argv[i];
        char detail[PATH_MAX + 32];
        const char *detail_ptr = NULL;
        if (file_count > 1) {
            snprintf(detail, sizeof(detail), "%s (%d/%d)",
                     smallcluePagerDisplayName(path && strcmp(path, "-") != 0 ? path : "(stdin)"),
                     (i - optind) + 1,
                     file_count);
            detail_ptr = detail;
        }
        if (!path || strcmp(path, "-") == 0) {
            status |= pager_file(cmd_name, "(stdin)", detail_ptr, stdin, raw_mode);
            int exit_key = pagerLastExitKey();
            if (exit_key == 'Q' || exit_key == 3 || exit_key == 4) {
                break;
            }
            continue;
        }
        FILE *fp = fopen(path, "r");
        if (!fp) {
            fprintf(stderr, "%s: %s: %s\n", cmd_name, path, strerror(errno));
            status = 1;
            continue;
        }
        status |= pager_file(cmd_name, path, detail_ptr, fp, raw_mode);
        fclose(fp);
        {
            int exit_key = pagerLastExitKey();
            if (exit_key == 'Q' || exit_key == 3 || exit_key == 4) {
                break;
            }
        }
    }
    return status ? 1 : 0;
}

static int smallclueMarkdownCommand(int argc, char **argv) {
    smallclueResetGetopt();
    int list_only = 0;
    int interactive = 0;
    bool output_raw = false;
    int opt;
    while ((opt = getopt(argc, argv, "ilc")) != -1) {
        switch (opt) {
            case 'i':
                interactive = 1;
                break;
            case 'l':
                list_only = 1;
                break;
            case 'c':
                output_raw = true;
                break;
            default:
                fprintf(stderr, "usage: md [-i | -l | -c] [file|url ...]\n");
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
    if (list_only) {
        return smallclueMarkdownListDocuments();
    }
    if (optind >= argc) {
        if (!isatty(STDIN_FILENO)) {
            return smallclueMarkdownBrowseTarget("-", output_raw);
        }
        return smallclueMarkdownListDocuments();
    }
    int status = 0;
    int file_count = argc - optind;
    for (int i = optind; i < argc; ++i) {
        if (file_count > 1) {
            if (i > optind) {
                putchar('\n');
            }
            printf("==> %s <==\n", argv[i]);
        }
        status |= smallclueMarkdownBrowseTarget(argv[i], output_raw);
    }
    return status ? 1 : 0;
}

static int smallclueCurlCommand(int argc, char **argv) {
    smallclueResetGetopt();
    const char *output_path = NULL;
    int use_remote_name = 0;
    const char *method = NULL;
    char **headers = NULL;
    int headerCount = 0, headerCap = 0;
    char *postData = NULL;
    size_t postDataLen = 0;
    const char *userpwd = NULL;
    bool insecureTls = false;
    int opt;
    while ((opt = getopt(argc, argv, "o:OX:H:d:u:k")) != -1) {
        switch (opt) {
            case 'o':
                output_path = optarg;
                break;
            case 'O':
                use_remote_name = 1;
                break;
            case 'X':
                method = optarg;
                break;
            case 'u':
                userpwd = optarg;
                break;
            case 'k':
                insecureTls = true;
                break;
            case 'H': {
                if (headerCount == headerCap) {
                    headerCap = headerCap ? headerCap * 2 : 8;
                    char **resized = (char **)realloc(headers, (size_t)headerCap * sizeof(char *));
                    if (!resized) {
                        fprintf(stderr, "curl: out of memory\n");
                        free(headers);
                        free(postData);
                        return 1;
                    }
                    headers = resized;
                }
                headers[headerCount++] = optarg;
                break;
            }
            case 'd': {
                /* Real curl joins repeated -d values with '&', like
                 * concatenating form fields. */
                size_t addLen = strlen(optarg);
                size_t sepLen = (postDataLen > 0) ? 1 : 0;
                char *resized = (char *)realloc(postData, postDataLen + sepLen + addLen + 1);
                if (!resized) {
                    fprintf(stderr, "curl: out of memory\n");
                    free(headers);
                    free(postData);
                    return 1;
                }
                postData = resized;
                if (sepLen) postData[postDataLen++] = '&';
                memcpy(postData + postDataLen, optarg, addLen);
                postDataLen += addLen;
                postData[postDataLen] = '\0';
                break;
            }
            default:
                fprintf(stderr, "usage: curl [-o file | -O] [-X METHOD] [-H HEADER]... [-d DATA]... [-u USER:PASS] [-k] url...\n");
                free(headers);
                free(postData);
                return 1;
        }
    }
    if (output_path && use_remote_name) {
        fprintf(stderr, "curl: -o and -O may not be used together\n");
        free(headers);
        free(postData);
        return 1;
    }
    if (optind >= argc) {
        fprintf(stderr, "curl: missing URL\n");
        free(headers);
        free(postData);
        return 1;
    }
    if (output_path && (argc - optind) != 1) {
        fprintf(stderr, "curl: -o is only supported with a single URL\n");
        free(headers);
        free(postData);
        return 1;
    }
    SmallclueHttpRequestOptions reqOpts;
    memset(&reqOpts, 0, sizeof(reqOpts));
    reqOpts.method = method;
    reqOpts.headers = headers;
    reqOpts.headerCount = headerCount;
    reqOpts.postData = postData;
    reqOpts.userpwd = userpwd;
    reqOpts.insecureTls = insecureTls;

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
        status |= smallclueHttpFetch("curl", url, destination, &reqOpts);
    }
    free(headers);
    free(postData);
    return status ? 1 : 0;
}

static int smallclueWgetCommand(int argc, char **argv) {
    const char *method = NULL;
    char **headers = NULL;
    int headerCount = 0, headerCap = 0;
    char *postData = NULL;
    const char *wgetUser = NULL;
    const char *wgetPassword = NULL;
    bool insecureTls = false;
    char userpwdBuf[512];
    userpwdBuf[0] = '\0';

    /* Real wget has no short forms for these, only --header=/--post-data=/
     * --method=/--user=/--password=/--no-check-certificate (repeated GNU
     * long options with no getopt()-friendly short equivalent) -- strip
     * them out before calling getopt(), matching the convention used
     * elsewhere in this file (e.g. stat's --format=). */
    for (int i = 1; i < argc; ) {
        if (strncmp(argv[i], "--header=", 9) == 0) {
            if (headerCount == headerCap) {
                headerCap = headerCap ? headerCap * 2 : 8;
                char **resized = (char **)realloc(headers, (size_t)headerCap * sizeof(char *));
                if (!resized) {
                    fprintf(stderr, "wget: out of memory\n");
                    free(headers);
                    free(postData);
                    return 1;
                }
                headers = resized;
            }
            headers[headerCount++] = argv[i] + 9;
            for (int j = i; j + 1 < argc; ++j) argv[j] = argv[j + 1];
            argc--;
            continue;
        }
        if (strncmp(argv[i], "--post-data=", 12) == 0) {
            free(postData);
            postData = strdup(argv[i] + 12);
            for (int j = i; j + 1 < argc; ++j) argv[j] = argv[j + 1];
            argc--;
            continue;
        }
        if (strncmp(argv[i], "--method=", 9) == 0) {
            method = argv[i] + 9;
            for (int j = i; j + 1 < argc; ++j) argv[j] = argv[j + 1];
            argc--;
            continue;
        }
        if (strncmp(argv[i], "--user=", 7) == 0) {
            wgetUser = argv[i] + 7;
            for (int j = i; j + 1 < argc; ++j) argv[j] = argv[j + 1];
            argc--;
            continue;
        }
        if (strncmp(argv[i], "--password=", 11) == 0) {
            wgetPassword = argv[i] + 11;
            for (int j = i; j + 1 < argc; ++j) argv[j] = argv[j + 1];
            argc--;
            continue;
        }
        if (strcmp(argv[i], "--no-check-certificate") == 0) {
            insecureTls = true;
            for (int j = i; j + 1 < argc; ++j) argv[j] = argv[j + 1];
            argc--;
            continue;
        }
        i++;
    }
    if (wgetUser) {
        snprintf(userpwdBuf, sizeof(userpwdBuf), "%s:%s", wgetUser, wgetPassword ? wgetPassword : "");
    }

    smallclueResetGetopt();
    const char *output_path = NULL;
    int opt;
    while ((opt = getopt(argc, argv, "O:")) != -1) {
        switch (opt) {
            case 'O':
                output_path = optarg;
                break;
            default:
                fprintf(stderr, "usage: wget [-O file] [--method=METHOD] [--header=HEADER]... [--post-data=DATA]\n"
                                "            [--user=USER] [--password=PASS] [--no-check-certificate] url...\n");
                free(headers);
                free(postData);
                return 1;
        }
    }
    if (optind >= argc) {
        fprintf(stderr, "wget: missing URL\n");
        free(headers);
        free(postData);
        return 1;
    }
    if (output_path && (argc - optind) != 1) {
        fprintf(stderr, "wget: -O is only supported with a single URL\n");
        free(headers);
        free(postData);
        return 1;
    }

    SmallclueHttpRequestOptions reqOpts;
    memset(&reqOpts, 0, sizeof(reqOpts));
    reqOpts.method = method;
    reqOpts.headers = headers;
    reqOpts.headerCount = headerCount;
    reqOpts.postData = postData;
    reqOpts.userpwd = wgetUser ? userpwdBuf : NULL;
    reqOpts.insecureTls = insecureTls;

    int status = 0;
    for (int i = optind; i < argc; ++i) {
        const char *url = argv[i];
        const char *destination = output_path;
        char derived[PATH_MAX];
        if (!destination) {
            smallclueUrlSuggestFilename(url, derived, sizeof(derived));
            destination = derived;
        }
        int rc = smallclueHttpFetch("wget", url, destination, &reqOpts);
        if (rc == 0) {
            printf("Saved %s -> %s\n", url, destination ? destination : "(stdout)");
        }
        status |= rc;
    }
    free(headers);
    free(postData);
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

/* Forward declaration: the ISO-8601-ish string parser was originally
 * written for `touch -d`, but the same shapes are exactly what `date -d`
 * / `date -s` need too -- defined later in this file (touch's section),
 * reused here rather than duplicated. */
static bool smallclueTouchParseDashD(const char *spec, struct tm *out);

static int smallclueDateCommand(int argc, char **argv) {
    int arg_index = 1;
    int use_utc = 0;
    const char *format = "%a %b %e %T %Z %Y";
    const char *date_spec = NULL;
    const char *set_spec = NULL;

    while (arg_index < argc && argv[arg_index] && argv[arg_index][0] == '-') {
        const char *opt = argv[arg_index];
        if (strcmp(opt, "-u") == 0 || strcmp(opt, "--utc") == 0 || strcmp(opt, "--universal") == 0) {
            use_utc = 1;
            arg_index++;
            continue;
        }
        if (strcmp(opt, "-d") == 0 || strcmp(opt, "--date") == 0) {
            if (arg_index + 1 >= argc) {
                fprintf(stderr, "date: option '%s' requires an argument\n", opt);
                return 1;
            }
            date_spec = argv[arg_index + 1];
            arg_index += 2;
            continue;
        }
        if (strncmp(opt, "--date=", 7) == 0) {
            date_spec = opt + 7;
            arg_index++;
            continue;
        }
        if (strcmp(opt, "-s") == 0 || strcmp(opt, "--set") == 0) {
            if (arg_index + 1 >= argc) {
                fprintf(stderr, "date: option '%s' requires an argument\n", opt);
                return 1;
            }
            set_spec = argv[arg_index + 1];
            arg_index += 2;
            continue;
        }
        if (strncmp(opt, "--set=", 6) == 0) {
            set_spec = opt + 6;
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

    struct tm tm_buf;
    memset(&tm_buf, 0, sizeof(tm_buf));
    time_t now;

    const char *parse_spec = set_spec ? set_spec : date_spec;
    if (parse_spec) {
        if (!smallclueTouchParseDashD(parse_spec, &tm_buf)) {
            fprintf(stderr, "date: invalid date '%s'\n", parse_spec);
            return 1;
        }
        now = use_utc ? timegm(&tm_buf) : mktime(&tm_buf);
        if (now == (time_t)-1) {
            fprintf(stderr, "date: invalid date '%s'\n", parse_spec);
            return 1;
        }
        if (set_spec) {
            struct timespec ts = {.tv_sec = now, .tv_nsec = 0};
            if (clock_settime(CLOCK_REALTIME, &ts) != 0) {
                fprintf(stderr, "date: cannot set date: %s\n", strerror(errno));
                return 1;
            }
        }
    } else {
        now = time(NULL);
        if (now == (time_t)-1) {
            perror("date");
            return 1;
        }
    }

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

/* Sakamoto's algorithm to determine the day of the week.
 * Returns 0 = Sunday, 1 = Monday, etc.
 * Replaces mktime() to avoid libc overhead and time zone dependencies.
 * Assumes m is 1-12. */
static int smallclueDayOfWeek(int d, int m, int y) {
    static const int t[] = {0, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4};
    y -= m < 3;
    return (y + y/4 - y/100 + y/400 + t[m-1] + d) % 7;
}

static int smallclueFirstWeekdayOfMonth(int month, int year) {
    return smallclueDayOfWeek(1, month, year);
}

typedef struct {
    char lines[8][128]; /* Enough for text + ANSI codes */
} SmallclueCalMonthBlock;

static void smallclueCalRenderMonth(int month, int year, int highlight_day, SmallclueCalMonthBlock *out) {
    if (!out) return;
    memset(out, 0, sizeof(*out));

    struct tm tm_buf;
    memset(&tm_buf, 0, sizeof(tm_buf));
    tm_buf.tm_year = year - 1900;
    tm_buf.tm_mon = month - 1;
    tm_buf.tm_mday = 1;

    /* Line 0: Header (Month Year), centered in 20 chars */
    char header_text[64];
    if (strftime(header_text, sizeof(header_text), "%B %Y", &tm_buf) == 0) {
        snprintf(header_text, sizeof(header_text), "%d %d", month, year);
    }
    int len = (int)strlen(header_text);
    if (len > 20) len = 20;
    int pad_left = (20 - len) / 2;
    snprintf(out->lines[0], sizeof(out->lines[0]), "%*s%s", pad_left, "", header_text);

    /* Line 1: Day names */
    snprintf(out->lines[1], sizeof(out->lines[1]), "Su Mo Tu We Th Fr Sa");

    int first_wday = smallclueFirstWeekdayOfMonth(month, year);
    int days = smallclueDaysInMonth(month, year);

    int current_wday = 0;
    int line_idx = 2;
    char *ptr = out->lines[line_idx];
    size_t rem = sizeof(out->lines[line_idx]);

    /* Initial padding */
    for (current_wday = 0; current_wday < first_wday; ++current_wday) {
        int w = snprintf(ptr, rem, "   ");
        if (w > 0 && (size_t)w < rem) { ptr += w; rem -= w; }
    }

    int use_color = (highlight_day > 0 && isatty(STDOUT_FILENO));
    for (int day = 1; day <= days; ++day) {
        char day_str[32];
        if (use_color && day == highlight_day) {
            snprintf(day_str, sizeof(day_str), "\x1b[7m%2d\x1b[0m", day);
        } else {
            snprintf(day_str, sizeof(day_str), "%2d", day);
        }

        int w = snprintf(ptr, rem, "%s", day_str);
        if (w > 0 && (size_t)w < rem) { ptr += w; rem -= w; }

        current_wday++;
        if (current_wday % 7 == 0) {
            /* End of week, move to next line */
            line_idx++;
            if (line_idx < 8) {
                ptr = out->lines[line_idx];
                rem = sizeof(out->lines[line_idx]);
            } else {
                break;
            }
        } else {
            /* Space between days */
            if (day < days) {
                int s = snprintf(ptr, rem, " ");
                if (s > 0 && (size_t)s < rem) { ptr += s; rem -= s; }
            }
        }
    }
}

static int smallclueVisibleLength(const char *s) {
    int len = 0;
    int in_esc = 0;
    if (!s) return 0;
    for (; *s; ++s) {
        if (*s == '\x1b') {
            in_esc = 1;
        } else if (in_esc) {
            if (*s == 'm') in_esc = 0;
        } else {
            len++;
        }
    }
    return len;
}

static void smallclueCalPrintYear(int year, int current_day, int current_month, int current_year) {
    /* Print year header centered.
       3 months side by side = 20*3 + 2*2 (padding) = 64 chars.
       Centered year: (64 - 4) / 2 = 30 spaces padding (approx)
    */
    if (year < 1 || year > 9999) return;

    /* 35 spaces seems about right to center 4 digits in 64 columns?
       64 - 4 = 60. 30 spaces.
    */
    printf("                              %d\n\n", year);

    for (int row = 0; row < 4; ++row) {
        int m_start = row * 3 + 1;
        SmallclueCalMonthBlock blocks[3];

        for (int i = 0; i < 3; ++i) {
            int m = m_start + i;
            int hl = (year == current_year && m == current_month) ? current_day : 0;
            smallclueCalRenderMonth(m, year, hl, &blocks[i]);
        }

        for (int line = 0; line < 8; ++line) {
            for (int i = 0; i < 3; ++i) {
                const char *text = blocks[i].lines[line];
                int vis_len = smallclueVisibleLength(text);
                fputs(text, stdout);
                if (i < 2) {
                    /* Pad to 20 chars, plus 2 spaces gap */
                    int pad = 20 - vis_len;
                    if (pad < 0) pad = 0;
                    for (int p = 0; p < pad + 2; ++p) putchar(' ');
                }
            }
            putchar('\n');
        }
        /* Extra newline between rows of months, if not last row */
        /* Standard cal doesn't seem to put extra lines, just the 8 lines of month grid?
           Wait, months have variable weeks (4-6).
           SmallclueCalRenderMonth puts lines into fixed 8 slots.
           If a month has 5 weeks, line 7 (index 6) might be empty.
           If a month has 6 weeks, line 8 (index 7) might be empty.
           We print all 8 lines to keep alignment.
        */
        /* Actually standard cal output separates rows of months by one empty line usually? */
        /* Let's see: reproduce_cal.sh output shows one empty line after the month. */
        /* I'll verify logic by running it. */
        /* A bit of vertical separation is good. */
        /* Note: standard cal output for year fits in terminal. */
    }
}

static int smallclueCalCommand(int argc, char **argv) {
    time_t now = time(NULL);
    struct tm tm_now_buf;
    struct tm *tm_now = localtime_r(&now, &tm_now_buf);

    int current_day = tm_now ? tm_now->tm_mday : 0;
    int current_month = tm_now ? tm_now->tm_mon + 1 : 0;
    int current_year_val = tm_now ? tm_now->tm_year + 1900 : 0;

    if (argc == 1) {
        /* cal: print current month */
        SmallclueCalMonthBlock block;
        smallclueCalRenderMonth(current_month, current_year_val, current_day, &block);
        for (int i = 0; i < 8; ++i) {
            /* Trim trailing whitespace for single month view? */
            /* Or just print. Standard cal trims trailing spaces. */
            printf("%s\n", block.lines[i]);
        }
        return 0;
    }

    if (argc == 2) {
        /* cal [year] */
        int year = 0;
        if (smallclueParseInt(argv[1], 1, 9999, &year)) {
            smallclueCalPrintYear(year, current_day, current_month, current_year_val);
            return 0;
        } else {
             fprintf(stderr, "cal: usage: cal [year] or cal [month] [year]\n");
             return 1;
        }
    }

    if (argc == 3) {
        /* cal [month] [year] */
        int month = 0;
        int year = 0;
        if (!smallclueParseInt(argv[1], 1, 12, &month) || !smallclueParseInt(argv[2], 1, 9999, &year)) {
            fprintf(stderr, "cal: usage: cal [month] [year]\n");
            return 1;
        }
        int hl = (year == current_year_val && month == current_month) ? current_day : 0;
        SmallclueCalMonthBlock block;
        smallclueCalRenderMonth(month, year, hl, &block);
        for (int i = 0; i < 8; ++i) {
            printf("%s\n", block.lines[i]);
        }
        return 0;
    }

    fprintf(stderr, "cal: usage: cal [year] or cal [month] [year]\n");
    return 1;
}

static const char *smallclueStrCaseStr(const char *haystack, const char *needle, int ignore_case) {
    if (!haystack || !needle || !*needle) {
        return haystack;
    }
    /* Optimization: Use optimized libc strstr for case-sensitive search */
    if (!ignore_case) {
        return strstr(haystack, needle);
    }
#if defined(_GNU_SOURCE) || defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__DragonFly__)
    /* Optimization: Use optimized libc strcasestr for case-insensitive search */
    return strcasestr(haystack, needle);
#else
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
#endif
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

/* Parses the value passed to `-n` when it may carry a leading sign with
 * tool-specific meaning: BSD/GNU tail's "-n +NUM" starts output at line
 * NUM (relative to the beginning), and GNU head's "-n -NUM" prints all
 * but the last NUM lines. A bare "+NUM" for head has no special GNU
 * meaning and is treated as an ordinary positive count. */
static bool smallclueParseSignedLineCount(const char *text, char *signOut, long *valueOut) {
    if (!text || !*text) return false;
    char sign = '\0';
    const char *p = text;
    if (*p == '+' || *p == '-') {
        sign = *p;
        p++;
    }
    if (!*p) return false;
    char *endptr = NULL;
    long v = strtol(p, &endptr, 10);
    if (!endptr || *endptr != '\0' || v < 0) return false;
    if (signOut) *signOut = sign;
    if (valueOut) *valueOut = v;
    return true;
}

static int smallclueHeadStream(FILE *fp, const char *label, long lines) {
    if (lines <= 0) {
        return 0;
    }
    char buf[16384];
    long remaining = lines;
    int read_err = 0;
    ssize_t n;
    int status = 0;

    while (remaining > 0 && (n = smallclueReadStream(fp, buf, sizeof(buf), &read_err)) > 0) {
        ssize_t i = 0;
        ssize_t end_idx = -1;

        /* Bolt optimization: unrolled loop for head line scanning */
        #define CHECK_NL(idx) do { \
            if (buf[i + (idx)] == '\n') { \
                remaining--; \
                if (remaining == 0) { \
                    end_idx = i + (idx); \
                    goto found; \
                } \
            } \
        } while(0)

        for (; i + 15 < n; i += 16) {
            CHECK_NL(0); CHECK_NL(1); CHECK_NL(2); CHECK_NL(3);
            CHECK_NL(4); CHECK_NL(5); CHECK_NL(6); CHECK_NL(7);
            CHECK_NL(8); CHECK_NL(9); CHECK_NL(10); CHECK_NL(11);
            CHECK_NL(12); CHECK_NL(13); CHECK_NL(14); CHECK_NL(15);
        }
        #undef CHECK_NL

        for (; i < n; ++i) {
            if (buf[i] == '\n') {
                remaining--;
                if (remaining == 0) {
                    end_idx = i;
                    goto found;
                }
            }
        }
found:
        if (end_idx >= 0) {
            fwrite(buf, 1, (size_t)(end_idx + 1), stdout);
            break;
        } else {
            fwrite(buf, 1, (size_t)n, stdout);
        }
    }

    if (read_err) {
        fprintf(stderr, "head: %s: %s\n",
                label ? label : "(stdin)",
                strerror(read_err));
        status = 1;
    }
    return status;
}

/* GNU head's "-n -NUM": print all but the last NUM lines. Since head
 * doesn't know where the end is until EOF, this streams via a NUM-sized
 * ring buffer of line contents -- a line is only printed once NUM more
 * lines have arrived after it (proving it isn't among the final NUM),
 * and whatever remains buffered at EOF (exactly the excluded trailing
 * lines) is discarded rather than printed. */
static int smallclueHeadStreamAllButLast(FILE *fp, const char *label, long excludeCount) {
    if (excludeCount <= 0) {
        char *line = NULL;
        size_t cap = 0;
        int status = 0;
        while (1) {
            int read_err = 0;
            ssize_t len = smallclueGetlineStream(&line, &cap, fp, &read_err);
            if (len < 0) {
                if (read_err) {
                    fprintf(stderr, "head: %s: %s\n", label ? label : "(stdin)", strerror(read_err));
                    status = 1;
                }
                break;
            }
            fwrite(line, 1, (size_t)len, stdout);
        }
        free(line);
        return status;
    }

    char **ring = (char **)calloc((size_t)excludeCount, sizeof(char *));
    if (!ring) {
        fprintf(stderr, "head: %s: out of memory\n", label ? label : "(stdin)");
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
                fprintf(stderr, "head: %s: %s\n", label ? label : "(stdin)", strerror(read_err));
                status = 1;
            }
            break;
        }
        long slot = count % excludeCount;
        if (count >= excludeCount && ring[slot]) {
            fputs(ring[slot], stdout);
            free(ring[slot]);
            ring[slot] = NULL;
        }
        char *copy = (char *)malloc((size_t)len + 1);
        if (!copy) {
            fprintf(stderr, "head: %s: out of memory\n", label ? label : "(stdin)");
            status = 1;
            break;
        }
        memcpy(copy, line, (size_t)len);
        copy[len] = '\0';
        ring[slot] = copy;
        count++;
    }
    free(line);
    for (long i = 0; i < excludeCount; ++i) {
        free(ring[i]);
    }
    free(ring);
    return status;
}

static int smallclueHeadCommand(int argc, char **argv) {
    long lines = 10;
    bool allButLast = false;
    long excludeCount = 0;
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
            char sign = '\0';
            long value = 0;
            if (!smallclueParseSignedLineCount(argv[index + 1], &sign, &value)) {
                fprintf(stderr, "head: invalid line count '%s'\n", argv[index + 1]);
                return 1;
            }
            if (sign == '-') {
                allButLast = true;
                excludeCount = value;
            } else {
                allButLast = false;
                lines = value;
            }
            index += 2;
            continue;
        }
        if (strncmp(arg, "-n", 2) == 0 && arg[2] != '\0') {
            char sign = '\0';
            long value = 0;
            if (!smallclueParseSignedLineCount(arg + 2, &sign, &value)) {
                fprintf(stderr, "head: invalid line count '%s'\n", arg + 2);
                return 1;
            }
            if (sign == '-') {
                allButLast = true;
                excludeCount = value;
            } else {
                allButLast = false;
                lines = value;
            }
            index += 1;
            continue;
        }
        long dashLines = 0;
        if (smallclueParseDashLineCount(arg, &dashLines)) {
            lines = dashLines;
            allButLast = false;
            index += 1;
            continue;
        }
        fprintf(stderr, "head: unsupported option '%s'\n", arg);
        return 1;
    }

    int status = 0;
    int file_count = argc - index;
    if (file_count <= 0) {
        status = allButLast ? smallclueHeadStreamAllButLast(stdin, "(stdin)", excludeCount)
                             : smallclueHeadStream(stdin, "(stdin)", lines);
    } else {
        for (int i = index; i < argc; ++i) {
            const char *path = argv[i];
            FILE *fp = fopen(path, "r");
            if (!fp) {
                fprintf(stderr, "head: %s: %s\n", path, strerror(errno));
                status = 1;
                continue;
            }
            if (file_count > 1) {
                if (i > index) {
                    putchar('\n');
                }
                printf("==> %s <==\n", path);
            }
            status |= allButLast ? smallclueHeadStreamAllButLast(fp, path, excludeCount)
                                  : smallclueHeadStream(fp, path, lines);
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

/* BSD/GNU tail's "-n +NUM": start output at line NUM (1-based, relative
 * to the start of input) rather than counting back from the end. Unlike
 * the last-N-lines mode, this needs no buffering at all -- just count
 * lines as they stream by and start printing once the target is hit. */
static int smallclueTailStreamFromLine(FILE *fp, const char *label, long startLine) {
    if (startLine < 1) {
        startLine = 1;
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
                fprintf(stderr, "tail: %s: %s\n", label ? label : "(stdin)", strerror(read_err));
                status = 1;
            }
            break;
        }
        count++;
        if (count >= startLine) {
            fwrite(line, 1, (size_t)len, stdout);
        }
    }
    free(line);
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
    bool fromLineStart = false;
    long startLine = 1;
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
            char sign = '\0';
            long value = 0;
            if (!smallclueParseSignedLineCount(argv[index + 1], &sign, &value)) {
                fprintf(stderr, "tail: invalid line count '%s'\n", argv[index + 1]);
                return 1;
            }
            if (sign == '+') {
                fromLineStart = true;
                startLine = value;
            } else {
                fromLineStart = false;
                lines = value;
            }
            index += 2;
            continue;
        }
        if (strncmp(arg, "-n", 2) == 0 && arg[2] != '\0') {
            char sign = '\0';
            long value = 0;
            if (!smallclueParseSignedLineCount(arg + 2, &sign, &value)) {
                fprintf(stderr, "tail: invalid line count '%s'\n", arg + 2);
                return 1;
            }
            if (sign == '+') {
                fromLineStart = true;
                startLine = value;
            } else {
                fromLineStart = false;
                lines = value;
            }
            index += 1;
            continue;
        }
        long dashLines = 0;
        if (smallclueParseDashLineCount(arg, &dashLines)) {
            lines = dashLines;
            fromLineStart = false;
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
    if (follow && fromLineStart) {
        fprintf(stderr, "tail: -f cannot be combined with -n +NUM\n");
        return 1;
    }
    int status = 0;
    int file_count = argc - index;
    if (file_count <= 0) {
        status = follow ? smallclueTailFollow(stdin, "(stdin)", lines)
                : fromLineStart ? smallclueTailStreamFromLine(stdin, "(stdin)", startLine)
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
            if (file_count > 1) {
                if (i > index) {
                    putchar('\n');
                }
                printf("==> %s <==\n", path);
            }
            if (follow) {
                status |= smallclueTailFollow(fp, path, lines);
                fclose(fp);
                break;
            } else if (fromLineStart) {
                status |= smallclueTailStreamFromLine(fp, path, startLine);
                fclose(fp);
            } else {
                status |= smallclueTailStream(fp, path, lines);
                fclose(fp);
            }
        }
    }
    return status ? 1 : 0;
}

/* Parses touch -t's [[CC]YY]MMDDhhmm[.ss] compact timestamp form. The
 * digit count before an optional ".ss" suffix tells us which of the three
 * year-width variants we're looking at. */
static bool smallclueTouchParseDashT(const char *spec, struct tm *out) {
    memset(out, 0, sizeof(*out));
    out->tm_isdst = -1;
    char digits[13];
    int seconds = 0;
    const char *dot = strchr(spec, '.');
    size_t digitLen = dot ? (size_t)(dot - spec) : strlen(spec);
    if (dot) {
        if (strlen(dot + 1) != 2 || !isdigit((unsigned char)dot[1]) || !isdigit((unsigned char)dot[2])) {
            return false;
        }
        seconds = (dot[1] - '0') * 10 + (dot[2] - '0');
    }
    if (digitLen != 8 && digitLen != 10 && digitLen != 12) {
        return false;
    }
    if (digitLen >= sizeof(digits)) {
        return false;
    }
    for (size_t i = 0; i < digitLen; ++i) {
        if (!isdigit((unsigned char)spec[i])) {
            return false;
        }
        digits[i] = spec[i];
    }
    digits[digitLen] = '\0';

    int year = -1;
    const char *rest = digits;
    if (digitLen == 12) {
        char century[3] = {digits[0], digits[1], '\0'};
        char yy[3] = {digits[2], digits[3], '\0'};
        year = atoi(century) * 100 + atoi(yy);
        rest = digits + 4;
    } else if (digitLen == 10) {
        char yy[3] = {digits[0], digits[1], '\0'};
        int yyVal = atoi(yy);
        year = (yyVal < 69) ? 2000 + yyVal : 1900 + yyVal; /* POSIX pivot */
        rest = digits + 2;
    } else {
        time_t now = time(NULL);
        struct tm nowTm;
        localtime_r(&now, &nowTm);
        year = nowTm.tm_year + 1900;
    }
    char mm[3] = {rest[0], rest[1], '\0'};
    char dd[3] = {rest[2], rest[3], '\0'};
    char hh[3] = {rest[4], rest[5], '\0'};
    char min[3] = {rest[6], rest[7], '\0'};
    out->tm_year = year - 1900;
    out->tm_mon = atoi(mm) - 1;
    out->tm_mday = atoi(dd);
    out->tm_hour = atoi(hh);
    out->tm_min = atoi(min);
    out->tm_sec = seconds;
    return true;
}

/* Supports the common, unambiguous date-string shapes real scripts use.
 * Full natural-language parsing (GNU coreutils' "getdate" grammar --
 * "yesterday", "next monday", "+1 day") is a much larger feature and out
 * of scope here; this covers explicit ISO-8601-ish timestamps. */
static bool smallclueTouchParseDashD(const char *spec, struct tm *out) {
    static const char *formats[] = {
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M",
        "%Y-%m-%d",
        "%Y/%m/%d %H:%M:%S",
        "%Y/%m/%d",
    };
    for (size_t i = 0; i < sizeof(formats) / sizeof(formats[0]); ++i) {
        memset(out, 0, sizeof(*out));
        out->tm_isdst = -1;
        char *end = strptime(spec, formats[i], out);
        if (end && *end == '\0') {
            return true;
        }
    }
    return false;
}

static int smallclueTouchCommand(int argc, char **argv) {
    bool noCreate = false;
    bool accessOnly = false;
    bool modifyOnly = false;
    const char *refFile = NULL;
    const char *tSpec = NULL;
    const char *dSpec = NULL;

    int argi = 1;
    for (; argi < argc; ++argi) {
        const char *arg = argv[argi];
        if (strcmp(arg, "--") == 0) {
            argi++;
            break;
        }
        if (strcmp(arg, "-c") == 0 || strcmp(arg, "--no-create") == 0) {
            noCreate = true;
        } else if (strcmp(arg, "-a") == 0) {
            accessOnly = true;
        } else if (strcmp(arg, "-m") == 0) {
            modifyOnly = true;
        } else if (strcmp(arg, "-r") == 0) {
            if (argi + 1 >= argc) {
                fprintf(stderr, "touch: -r requires a reference file\n");
                return 1;
            }
            refFile = argv[++argi];
        } else if (strncmp(arg, "-r", 2) == 0 && arg[2] != '\0') {
            refFile = arg + 2;
        } else if (strcmp(arg, "-t") == 0) {
            if (argi + 1 >= argc) {
                fprintf(stderr, "touch: -t requires a timestamp argument\n");
                return 1;
            }
            tSpec = argv[++argi];
        } else if (strcmp(arg, "-d") == 0) {
            if (argi + 1 >= argc) {
                fprintf(stderr, "touch: -d requires a date string\n");
                return 1;
            }
            dSpec = argv[++argi];
        } else if (arg[0] == '-' && arg[1] != '\0') {
            fprintf(stderr, "touch: unsupported option '%s'\n", arg);
            return 1;
        } else {
            break;
        }
    }
    if (argi >= argc) {
        fprintf(stderr, "touch: missing file operand\n");
        return 1;
    }

    struct timeval times[2];
    if (refFile) {
        struct stat refStat;
        if (stat(refFile, &refStat) != 0) {
            fprintf(stderr, "touch: %s: %s\n", refFile, strerror(errno));
            return 1;
        }
        times[0].tv_sec = refStat.st_atime;
        times[0].tv_usec = 0;
        times[1].tv_sec = refStat.st_mtime;
        times[1].tv_usec = 0;
    } else if (tSpec) {
        struct tm tmVal;
        if (!smallclueTouchParseDashT(tSpec, &tmVal)) {
            fprintf(stderr, "touch: invalid -t timestamp '%s'\n", tSpec);
            return 1;
        }
        time_t t = mktime(&tmVal);
        if (t == (time_t)-1) {
            fprintf(stderr, "touch: invalid -t timestamp '%s'\n", tSpec);
            return 1;
        }
        times[0].tv_sec = times[1].tv_sec = t;
        times[0].tv_usec = times[1].tv_usec = 0;
    } else if (dSpec) {
        struct tm tmVal;
        if (!smallclueTouchParseDashD(dSpec, &tmVal)) {
            fprintf(stderr, "touch: unrecognized -d date string '%s'\n", dSpec);
            return 1;
        }
        time_t t = mktime(&tmVal);
        if (t == (time_t)-1) {
            fprintf(stderr, "touch: invalid -d date string '%s'\n", dSpec);
            return 1;
        }
        times[0].tv_sec = times[1].tv_sec = t;
        times[0].tv_usec = times[1].tv_usec = 0;
    } else {
        if (gettimeofday(&times[0], NULL) != 0) {
            times[0].tv_sec = time(NULL);
            times[0].tv_usec = 0;
        }
        times[1] = times[0];
    }

    int status = 0;
    for (int i = argi; i < argc; ++i) {
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
        struct timeval useTimes[2] = {times[0], times[1]};
        if (accessOnly || modifyOnly) {
            struct stat existing;
            if (stat(target, &existing) == 0) {
                if (accessOnly && !modifyOnly) {
                    useTimes[1].tv_sec = existing.st_mtime;
                    useTimes[1].tv_usec = 0;
                } else if (modifyOnly && !accessOnly) {
                    useTimes[0].tv_sec = existing.st_atime;
                    useTimes[0].tv_usec = 0;
                }
            }
        }

        if (noCreate && access(target, F_OK) != 0) {
            continue;
        }
        int fd = openat(AT_FDCWD, target, O_WRONLY | O_CREAT, 0666);
        if (fd < 0) {
            fprintf(stderr, "touch: %s: %s\n", target, strerror(errno));
#if defined(PSCAL_TARGET_IOS)
            smallclueLogPathExpansion("touch-open-failed", target);
#endif
            status = 1;
            continue;
        }
        if (futimes(fd, useTimes) != 0) {
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
    bool uniqueOnly = false;
    bool checkOnly = false;
    bool checkQuiet = false;
    memset(&gSmallclueSortOpts, 0, sizeof(gSmallclueSortOpts));
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
        if (strcmp(arg, "-n") == 0) {
            gSmallclueSortOpts.numeric = true;
            index++;
            continue;
        }
        if (strcmp(arg, "-u") == 0) {
            uniqueOnly = true;
            index++;
            continue;
        }
        if (strcmp(arg, "-c") == 0 || strcmp(arg, "--check") == 0 || strcmp(arg, "--check=diagnose-first") == 0) {
            checkOnly = true;
            index++;
            continue;
        }
        if (strcmp(arg, "-C") == 0 || strcmp(arg, "--check=quiet") == 0 || strcmp(arg, "--check=silent") == 0) {
            checkOnly = true;
            checkQuiet = true;
            index++;
            continue;
        }
        if (strcmp(arg, "-m") == 0 || strcmp(arg, "--merge") == 0) {
            /* Accepted for compatibility: treated as a full re-sort of
             * the (assumed-sorted) inputs rather than a true multiway
             * merge. Output is identical either way -- this just skips
             * the presorted-runs optimization, matching this codebase's
             * established scope trade-offs (e.g. diff's O(n*m) DP
             * instead of full Myers). Nothing else to do here: the
             * existing full-sort path below already produces the
             * correct result. */
            index++;
            continue;
        }
        if (strncmp(arg, "-t", 2) == 0) {
            if (arg[2] != '\0') {
                gSmallclueSortOpts.keySep = arg[2];
                index++;
            } else {
                if (index + 1 >= argc || !argv[index + 1][0]) {
                    fprintf(stderr, "sort: missing separator for -t\n");
                    return 1;
                }
                gSmallclueSortOpts.keySep = argv[index + 1][0];
                index += 2;
            }
            continue;
        }
        if (strncmp(arg, "-k", 2) == 0) {
            const char *valStr = NULL;
            if (arg[2] != '\0') {
                valStr = arg + 2;
                index++;
            } else {
                if (index + 1 >= argc) {
                    fprintf(stderr, "sort: missing field for -k\n");
                    return 1;
                }
                valStr = argv[index + 1];
                index += 2;
            }
            int field = (int)strtol(valStr, NULL, 10);
            if (field <= 0) {
                fprintf(stderr, "sort: invalid -k field '%s'\n", valStr);
                return 1;
            }
            gSmallclueSortOpts.haveKey = true;
            gSmallclueSortOpts.keyField = field;
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
    if (status == 0 && checkOnly) {
        /* GNU sort's -c reports FILE:LINE; with a single input source
         * that's unambiguous, so use the real name. With stdin or
         * multiple concatenated files there's no one file the global
         * line number maps to, so fall back to "-". */
        const char *label = (index < argc && index == argc - 1) ? argv[index] : "-";
        int rc = smallclueSortCheckOrder(&vec, reverse != 0, checkQuiet, label);
        smallclueLineVectorFree(&vec);
        return rc;
    }
    if (status == 0 && vec.count > 1) {
        smallclueSortStable(vec.items, vec.count);
    }
    if (status == 0) {
        char *lastPrinted = NULL;
        for (size_t k = 0; k < vec.count; ++k) {
            size_t i = reverse ? (vec.count - 1 - k) : k;
            if (uniqueOnly && lastPrinted && smallclueSortCompare(&lastPrinted, &vec.items[i]) == 0) {
                continue;
            }
            fputs(vec.items[i], stdout);
            lastPrinted = vec.items[i];
        }
    }
    smallclueLineVectorFree(&vec);
    return status;
}

typedef struct {
    bool printCounts;
    bool duplicatesOnly; /* -d: only print lines that had at least one repeat */
    bool uniquesOnly;    /* -u: only print lines that had NO repeats */
    bool ignoreCase;     /* -i */
    int skipFields;      /* -f N: skip N leading whitespace-separated fields */
    int skipChars;       /* -s N: additionally skip N leading characters */
    int maxChars;         /* -w N: compare at most N characters (0 = rest of line) */
} SmallclueUniqOptions;

/* Skips `fields` leading whitespace-separated fields (blanks before each
 * field, then the field's non-blank run), matching GNU uniq -f: blanks
 * strictly between the skipped fields and the next one are NOT skipped
 * further, they just become part of the comparison key. */
static const char *smallclueUniqSkipFields(const char *line, int fields) {
    const char *p = line;
    for (int i = 0; i < fields; ++i) {
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        while (*p && *p != ' ' && *p != '\t') p++;
    }
    return p;
}

static const char *smallclueUniqComparisonKey(const SmallclueUniqOptions *opts, const char *line) {
    const char *key = line;
    if (opts->skipFields > 0) {
        key = smallclueUniqSkipFields(key, opts->skipFields);
    }
    if (opts->skipChars > 0) {
        size_t len = strlen(key);
        size_t skip = (size_t)opts->skipChars;
        key += (skip < len) ? skip : len;
    }
    return key;
}

static int smallclueUniqCompareLines(const SmallclueUniqOptions *opts, const char *a, const char *b) {
    const char *ka = smallclueUniqComparisonKey(opts, a);
    const char *kb = smallclueUniqComparisonKey(opts, b);
    if (opts->maxChars > 0) {
        return opts->ignoreCase ? strncasecmp(ka, kb, (size_t)opts->maxChars)
                                 : strncmp(ka, kb, (size_t)opts->maxChars);
    }
    return opts->ignoreCase ? strcasecmp(ka, kb) : strcmp(ka, kb);
}

static void smallclueUniqEmit(const SmallclueUniqOptions *opts, const char *line, long count) {
    if (opts->duplicatesOnly && count < 2) return;
    if (opts->uniquesOnly && count > 1) return;
    if (opts->printCounts) {
        printf("%7ld %s", count, line);
    } else {
        fputs(line, stdout);
    }
}

static int smallclueUniqStream(FILE *fp, const char *path, const SmallclueUniqOptions *opts) {
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
        if (!prev || smallclueUniqCompareLines(opts, prev, line) != 0) {
            if (prev) {
                smallclueUniqEmit(opts, prev, count);
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
        smallclueUniqEmit(opts, prev, count);
    }
    free(prev);
    free(line);
    return status;
}

static int smallclueUniqCommand(int argc, char **argv) {
    SmallclueUniqOptions opts;
    memset(&opts, 0, sizeof(opts));
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
            opts.printCounts = true;
            index++;
            continue;
        }
        if (strcmp(arg, "-d") == 0) {
            opts.duplicatesOnly = true;
            index++;
            continue;
        }
        if (strcmp(arg, "-u") == 0) {
            opts.uniquesOnly = true;
            index++;
            continue;
        }
        if (strcmp(arg, "-i") == 0) {
            opts.ignoreCase = true;
            index++;
            continue;
        }
        if (strcmp(arg, "-f") == 0 || strcmp(arg, "--skip-fields") == 0) {
            if (index + 1 >= argc) {
                fprintf(stderr, "uniq: option '%s' requires an argument\n", arg);
                return 1;
            }
            opts.skipFields = atoi(argv[++index]);
            index++;
            continue;
        }
        if (strncmp(arg, "-f", 2) == 0 && isdigit((unsigned char)arg[2])) {
            opts.skipFields = atoi(arg + 2);
            index++;
            continue;
        }
        if (strncmp(arg, "--skip-fields=", 14) == 0) {
            opts.skipFields = atoi(arg + 14);
            index++;
            continue;
        }
        if (strcmp(arg, "-s") == 0 || strcmp(arg, "--skip-chars") == 0) {
            if (index + 1 >= argc) {
                fprintf(stderr, "uniq: option '%s' requires an argument\n", arg);
                return 1;
            }
            opts.skipChars = atoi(argv[++index]);
            index++;
            continue;
        }
        if (strncmp(arg, "-s", 2) == 0 && isdigit((unsigned char)arg[2])) {
            opts.skipChars = atoi(arg + 2);
            index++;
            continue;
        }
        if (strncmp(arg, "--skip-chars=", 13) == 0) {
            opts.skipChars = atoi(arg + 13);
            index++;
            continue;
        }
        if (strcmp(arg, "-w") == 0 || strcmp(arg, "--check-chars") == 0) {
            if (index + 1 >= argc) {
                fprintf(stderr, "uniq: option '%s' requires an argument\n", arg);
                return 1;
            }
            opts.maxChars = atoi(argv[++index]);
            index++;
            continue;
        }
        if (strncmp(arg, "-w", 2) == 0 && isdigit((unsigned char)arg[2])) {
            opts.maxChars = atoi(arg + 2);
            index++;
            continue;
        }
        if (strncmp(arg, "--check-chars=", 14) == 0) {
            opts.maxChars = atoi(arg + 14);
            index++;
            continue;
        }
        fprintf(stderr, "uniq: unsupported option '%s'\n", arg);
        return 1;
    }
    if (index >= argc) {
        return smallclueUniqStream(stdin, "(stdin)", &opts);
    }
    int status = 0;
    for (int i = index; i < argc; ++i) {
        FILE *fp = fopen(argv[i], "r");
        if (!fp) {
            fprintf(stderr, "uniq: %s: %s\n", argv[i], strerror(errno));
            status = 1;
            continue;
        }
        status |= smallclueUniqStream(fp, argv[i], &opts);
        fclose(fp);
    }
    return status;
}

typedef enum {
    SED_ADDR_NONE,        /* applies to every line */
    SED_ADDR_LINE,        /* line == line1 */
    SED_ADDR_LAST,        /* line == last line ($) */
    SED_ADDR_REGEX,       /* single line matching regex1 */
    SED_ADDR_LINE_RANGE,  /* line1 <= line <= line2 (line2 == -1: "to end") */
    SED_ADDR_REGEX_RANGE, /* from first line matching regex1 to the next
                           * line matching regex2 (or reaching line2, or
                           * "to end" if neither given) */
} SmallclueSedAddrType;

typedef struct {
    SmallclueSedAddrType type;
    long line1;
    long line2; /* -1 = unbounded ("to end") for the *_RANGE types */
    regex_t regex1;
    regex_t regex2;
    bool haveRegex1;
    bool haveRegex2;
    bool rangeActive; /* mutable run-time state for the *_RANGE types */
} SmallclueSedAddr;

typedef struct SmallclueSedExpr {
    SmallclueSedAddr addr;
    char cmdChar; /* 's', 'y', 'd', or 'p' */
    regex_t re;
    bool reValid;
    char *replacement;
    bool global;
    bool caseInsensitive;
    unsigned char yFrom[256];
    unsigned char yTo[256];
    bool yUsed[256];
} SmallclueSedExpr;

static const char *smallclueSedSkipWs(const char *p) {
    while (*p == ' ' || *p == '\t') p++;
    return p;
}

/* Parses one address TERM (a line number, '$', or a /regex/) at *pp,
 * advancing *pp past it. Returns false only on a malformed /regex/; a
 * term simply not being present is reported via the return value too,
 * so callers must check whether *pp actually advanced. */
static bool smallclueSedParseAddrTerm(const char **pp, bool extendedRegex, SmallclueSedAddr *out, bool *found) {
    const char *p = *pp;
    *found = false;
    if (*p == '$') {
        out->type = SED_ADDR_LAST;
        *pp = p + 1;
        *found = true;
        return true;
    }
    if (isdigit((unsigned char)*p)) {
        char *end = NULL;
        long v = strtol(p, &end, 10);
        out->type = SED_ADDR_LINE;
        out->line1 = v;
        *pp = end;
        *found = true;
        return true;
    }
    if (*p == '/') {
        const char *start = p + 1;
        const char *end = strchr(start, '/');
        if (!end) {
            fprintf(stderr, "sed: unterminated address regex\n");
            return false;
        }
        size_t len = (size_t)(end - start);
        char *pat = (char *)malloc(len + 1);
        if (!pat) return false;
        memcpy(pat, start, len);
        pat[len] = '\0';
        int flags = extendedRegex ? REG_EXTENDED : 0;
        int rc = regcomp(&out->regex1, pat, flags);
        free(pat);
        if (rc != 0) {
            fprintf(stderr, "sed: invalid address regex\n");
            return false;
        }
        out->type = SED_ADDR_REGEX;
        out->haveRegex1 = true;
        *pp = end + 1;
        *found = true;
        return true;
    }
    return true; /* no term present -- not an error, just nothing to parse */
}

/* Parses an optional address prefix (N, $, /re/, N,M, N,$, /re1/,/re2/,
 * /re1/,N, /re1/,$) at *pp. Absence of any address is not an error (it
 * means "every line") -- only a malformed address is. */
static bool smallclueSedParseAddress(const char **pp, bool extendedRegex, SmallclueSedAddr *out) {
    memset(out, 0, sizeof(*out));
    out->type = SED_ADDR_NONE;
    out->line2 = -1;
    const char *p = smallclueSedSkipWs(*pp);
    SmallclueSedAddr first;
    memset(&first, 0, sizeof(first));
    first.line2 = -1;
    bool found = false;
    if (!smallclueSedParseAddrTerm(&p, extendedRegex, &first, &found)) {
        return false;
    }
    if (!found) {
        *pp = p;
        return true;
    }
    p = smallclueSedSkipWs(p);
    if (*p != ',') {
        *out = first;
        *pp = p;
        return true;
    }
    p++;
    p = smallclueSedSkipWs(p);
    SmallclueSedAddr second;
    memset(&second, 0, sizeof(second));
    second.line2 = -1;
    bool foundSecond = false;
    if (!smallclueSedParseAddrTerm(&p, extendedRegex, &second, &foundSecond) || !foundSecond) {
        fprintf(stderr, "sed: expected address after ','\n");
        return false;
    }
    if (first.type == SED_ADDR_LINE) {
        out->type = SED_ADDR_LINE_RANGE;
        out->line1 = first.line1;
        out->line2 = (second.type == SED_ADDR_LINE) ? second.line1 : -1;
    } else if (first.type == SED_ADDR_REGEX) {
        out->type = SED_ADDR_REGEX_RANGE;
        out->regex1 = first.regex1;
        out->haveRegex1 = true;
        if (second.type == SED_ADDR_REGEX) {
            out->regex2 = second.regex1;
            out->haveRegex2 = true;
        } else if (second.type == SED_ADDR_LINE) {
            out->line2 = second.line1;
        } else {
            out->line2 = -1;
        }
    } else {
        fprintf(stderr, "sed: unsupported address range combination\n");
        return false;
    }
    *pp = p;
    return true;
}

static bool smallclueSedAddrMatches(SmallclueSedAddr *addr, long lineNo, bool isLastLine, const char *line) {
    switch (addr->type) {
        case SED_ADDR_NONE:
            return true;
        case SED_ADDR_LINE:
            return lineNo == addr->line1;
        case SED_ADDR_LAST:
            return isLastLine;
        case SED_ADDR_REGEX: {
            regmatch_t m;
            return regexec(&addr->regex1, line, 1, &m, 0) == 0;
        }
        case SED_ADDR_LINE_RANGE: {
            if (!addr->rangeActive) {
                if (lineNo != addr->line1) return false;
                addr->rangeActive = true;
            }
            if (addr->line2 >= 0 && lineNo >= addr->line2) {
                addr->rangeActive = false;
            }
            return true;
        }
        case SED_ADDR_REGEX_RANGE: {
            if (!addr->rangeActive) {
                regmatch_t m;
                if (addr->haveRegex1 && regexec(&addr->regex1, line, 1, &m, 0) == 0) {
                    addr->rangeActive = true;
                    return true; /* the opening line itself; don't also
                                  * check the closing condition on it */
                }
                return false;
            }
            if (addr->haveRegex2) {
                regmatch_t m;
                if (regexec(&addr->regex2, line, 1, &m, 0) == 0) {
                    addr->rangeActive = false;
                }
            } else if (addr->line2 >= 0 && lineNo >= addr->line2) {
                addr->rangeActive = false;
            }
            return true;
        }
    }
    return false;
}

/* s<delim>PATTERN<delim>REPLACEMENT<delim>[flags] -- delim is whatever
 * character immediately follows 's'. Flags after the closing delimiter are
 * scanned one character at a time (fixing a real bug in the previous
 * literal-substring implementation, which treated ANY 'g' appearing
 * anywhere in the flags tail as enabling global mode): 'g' = global, 'i'/
 * 'I' = case-insensitive. Compiles PATTERN as a POSIX regex (basic by
 * default, extended when extendedRegex is set, i.e. -E/-r) instead of the
 * previous literal-substring-only match. Fills in the s-command fields of
 * an already-allocated SmallclueSedExpr (its address/cmdChar are set by
 * the caller separately). */
static bool smallclueSedParseExpr(const char *expr, bool extendedRegex, SmallclueSedExpr *out) {
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

    for (const char *f = rep_end + 1; *f; ++f) {
        if (*f == 'g') {
            out->global = true;
        } else if (*f == 'i' || *f == 'I') {
            out->caseInsensitive = true;
        } else {
            fprintf(stderr, "sed: unsupported flag '%c'\n", *f);
            return false;
        }
    }

    char *pattern = (char *)malloc(pat_len + 1);
    out->replacement = (char *)malloc(rep_len + 1);
    if (!pattern || !out->replacement) {
        free(pattern);
        free(out->replacement);
        out->replacement = NULL;
        return false;
    }
    memcpy(pattern, pat_start, pat_len);
    pattern[pat_len] = '\0';
    memcpy(out->replacement, rep_start, rep_len);
    out->replacement[rep_len] = '\0';

    int flags = (extendedRegex ? REG_EXTENDED : 0) | (out->caseInsensitive ? REG_ICASE : 0);
    int rc = regcomp(&out->re, pattern, flags);
    if (rc != 0) {
        char errbuf[256];
        regerror(rc, &out->re, errbuf, sizeof(errbuf));
        fprintf(stderr, "sed: invalid pattern '%s': %s\n", pattern, errbuf);
        free(pattern);
        free(out->replacement);
        out->replacement = NULL;
        return false;
    }
    free(pattern);
    out->reValid = true;
    return true;
}

/* y<delim>SET1<delim>SET2<delim> -- transliterates characters like tr.
 * SET1 and SET2 must be the same length (real sed requires this too). */
static bool smallclueSedParseYExpr(const char *expr, SmallclueSedExpr *out) {
    if (!expr || expr[0] != 'y' || expr[1] == '\0') return false;
    char delim = expr[1];
    const char *set1Start = expr + 2;
    const char *set1End = strchr(set1Start, delim);
    if (!set1End) return false;
    const char *set2Start = set1End + 1;
    const char *set2End = strchr(set2Start, delim);
    if (!set2End) return false;
    size_t len1 = (size_t)(set1End - set1Start);
    size_t len2 = (size_t)(set2End - set2Start);
    if (len1 != len2) {
        fprintf(stderr, "sed: y command's two sets must be the same length\n");
        return false;
    }
    for (size_t i = 0; i < len1; ++i) {
        unsigned char from = (unsigned char)set1Start[i];
        out->yFrom[i] = from;
        out->yTo[i] = (unsigned char)set2Start[i];
        out->yUsed[i] = true;
    }
    return true;
}

static char *smallclueSedApplyY(const char *line, const SmallclueSedExpr *expr) {
    size_t len = strlen(line);
    char *out = (char *)malloc(len + 1);
    if (!out) return NULL;
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = (unsigned char)line[i];
        char replaced = (char)c;
        for (size_t j = 0; j < sizeof(expr->yUsed) && expr->yUsed[j]; ++j) {
            if (expr->yFrom[j] == c) {
                replaced = (char)expr->yTo[j];
                break;
            }
        }
        out[i] = replaced;
    }
    out[len] = '\0';
    return out;
}

static void smallclueSedExprFree(SmallclueSedExpr *e) {
    if (e->reValid) {
        regfree(&e->re);
        e->reValid = false;
    }
    free(e->replacement);
    e->replacement = NULL;
    if (e->addr.haveRegex1) {
        regfree(&e->addr.regex1);
        e->addr.haveRegex1 = false;
    }
    if (e->addr.haveRegex2) {
        regfree(&e->addr.regex2);
        e->addr.haveRegex2 = false;
    }
}

static bool smallclueSedAppend(char **out, size_t *outLen, size_t *cap, const char *data, size_t len) {
    if (*outLen + len + 1 > *cap) {
        size_t newCap = (*outLen + len + 1) * 2;
        char *resized = (char *)realloc(*out, newCap);
        if (!resized) return false;
        *out = resized;
        *cap = newCap;
    }
    memcpy(*out + *outLen, data, len);
    *outLen += len;
    return true;
}

/* Expands & (whole match) and \1-\9 (submatch) backreferences in the
 * replacement text against the current regexec match. */
static bool smallclueSedAppendReplacement(char **out, size_t *outLen, size_t *cap,
                                          const char *line, const char *replacement,
                                          const regmatch_t *pmatch, size_t nmatch) {
    for (const char *r = replacement; *r; ++r) {
        if (*r == '\\' && r[1] >= '1' && r[1] <= '9') {
            size_t idx = (size_t)(r[1] - '0');
            r++;
            if (idx < nmatch && pmatch[idx].rm_so >= 0) {
                if (!smallclueSedAppend(out, outLen, cap, line + pmatch[idx].rm_so,
                                       (size_t)(pmatch[idx].rm_eo - pmatch[idx].rm_so))) {
                    return false;
                }
            }
        } else if (*r == '\\' && r[1] == '&') {
            if (!smallclueSedAppend(out, outLen, cap, "&", 1)) return false;
            r++;
        } else if (*r == '&') {
            if (!smallclueSedAppend(out, outLen, cap, line + pmatch[0].rm_so,
                                   (size_t)(pmatch[0].rm_eo - pmatch[0].rm_so))) {
                return false;
            }
        } else {
            if (!smallclueSedAppend(out, outLen, cap, r, 1)) return false;
        }
    }
    return true;
}

static char *smallclueSedApply(const char *line, const SmallclueSedExpr *expr) {
    size_t lineLen = strlen(line);
    size_t cap = lineLen + 32;
    size_t outLen = 0;
    char *out = (char *)malloc(cap);
    if (!out) return NULL;
    out[0] = '\0';

    const char *cursor = line;
    bool replacedAny = false;
    bool firstMatch = true;
    while (*cursor || firstMatch) {
        regmatch_t pmatch[10];
        int eflags = (cursor == line) ? 0 : REG_NOTBOL;
        int rc = regexec(&expr->re, cursor, 10, pmatch, eflags);
        if (rc != 0) {
            break;
        }
        firstMatch = false;
        if (!smallclueSedAppend(&out, &outLen, &cap, cursor, (size_t)pmatch[0].rm_so)) {
            free(out);
            return NULL;
        }
        if (!smallclueSedAppendReplacement(&out, &outLen, &cap, cursor, expr->replacement, pmatch, 10)) {
            free(out);
            return NULL;
        }
        replacedAny = true;
        if (pmatch[0].rm_eo == pmatch[0].rm_so) {
            /* Zero-length match (e.g. pattern "x*" on non-x text): copy one
             * char forward to guarantee progress, matching sed's own
             * empty-match handling. */
            if (cursor[pmatch[0].rm_eo] == '\0') {
                cursor += pmatch[0].rm_eo;
                break;
            }
            if (!smallclueSedAppend(&out, &outLen, &cap, cursor + pmatch[0].rm_eo, 1)) {
                free(out);
                return NULL;
            }
            cursor += pmatch[0].rm_eo + 1;
        } else {
            cursor += pmatch[0].rm_eo;
        }
        if (!expr->global) {
            break;
        }
    }
    if (!smallclueSedAppend(&out, &outLen, &cap, cursor, strlen(cursor))) {
        free(out);
        return NULL;
    }
    out[outLen] = '\0';
    if (!replacedAny) {
        free(out);
        return strdup(line);
    }
    return out;
}

/* Runs every command in `cmds` (in order) against one line, honoring
 * each command's address. Returns the transformed line (caller frees);
 * sets *deleted if a 'd' command fired (auto-print should be skipped).
 * `line` is consumed/freed internally as commands chain. */
static char *smallclueSedRunCommandsOnLine(char *line, SmallclueSedExpr *cmds, size_t cmdCount,
                                           long lineNo, bool isLastLine, FILE *out,
                                           bool suppressAutoPrint, bool *deleted) {
    *deleted = false;
    for (size_t i = 0; i < cmdCount; ++i) {
        SmallclueSedExpr *cmd = &cmds[i];
        if (!smallclueSedAddrMatches(&cmd->addr, lineNo, isLastLine, line)) {
            continue;
        }
        switch (cmd->cmdChar) {
            case 's': {
                char *transformed = smallclueSedApply(line, cmd);
                free(line);
                line = transformed;
                break;
            }
            case 'y': {
                char *transformed = smallclueSedApplyY(line, cmd);
                free(line);
                line = transformed;
                break;
            }
            case 'd': {
                *deleted = true;
                return line; /* real sed stops processing this cycle immediately */
            }
            case 'p': {
                fputs(line, out);
                fputc('\n', out);
                break;
            }
            default:
                break;
        }
    }
    (void)suppressAutoPrint;
    return line;
}

static int smallclueSedProcessStream(FILE *in, FILE *out, SmallclueSedExpr *cmds, size_t cmdCount,
                                     bool suppressAutoPrint, const char *label, int *status) {
    char *curLine = NULL;
    size_t curCap = 0;
    char *nextLine = NULL;
    size_t nextCap = 0;
    int read_err = 0;
    ssize_t curLen = smallclueGetlineStream(&curLine, &curCap, in, &read_err);
    if (curLen < 0) {
        if (read_err) {
            fprintf(stderr, "sed: %s: %s\n", label, strerror(read_err));
            *status = 1;
        }
        free(curLine);
        free(nextLine);
        return *status;
    }

    long lineNo = 0;
    for (;;) {
        lineNo++;
        /* smallclueGetlineStream keeps the trailing '\n' in the buffer.
         * Matching against that embedded newline is wrong for both `$`
         * (which should anchor to the logical end of line, not after an
         * embedded newline) and `.` (a POSIX regex `.` matches '\n' too
         * without REG_NEWLINE, so a greedy `.*` would swallow it) -- strip
         * it before applying the substitution and re-add it after,
         * preserving a final line with no trailing newline as-is. */
        bool hadNewline = (curLen > 0 && curLine[(size_t)curLen - 1] == '\n');
        if (hadNewline) {
            curLine[(size_t)curLen - 1] = '\0';
        }

        /* One-line lookahead so `$` (last line) is known before this
         * line is processed -- otherwise a streaming pass has no way to
         * tell whether the current line is the last one. */
        int nextReadErr = 0;
        ssize_t nextLen = smallclueGetlineStream(&nextLine, &nextCap, in, &nextReadErr);
        bool isLast = (nextLen < 0);

        char *lineBuf = strdup(curLine);
        if (!lineBuf) {
            fprintf(stderr, "sed: out of memory\n");
            *status = 1;
            break;
        }
        bool deleted = false;
        lineBuf = smallclueSedRunCommandsOnLine(lineBuf, cmds, cmdCount, lineNo, isLast, out,
                                                suppressAutoPrint, &deleted);
        if (!lineBuf) {
            fprintf(stderr, "sed: out of memory\n");
            *status = 1;
            break;
        }
        if (!deleted && !suppressAutoPrint) {
            fputs(lineBuf, out);
            if (hadNewline) {
                fputc('\n', out);
            }
        }
        free(lineBuf);

        if (isLast) {
            if (nextReadErr) {
                fprintf(stderr, "sed: %s: %s\n", label, strerror(nextReadErr));
                *status = 1;
            }
            break;
        }
        /* Shift the lookahead line into position for the next pass. */
        char *tmpLine = curLine;
        curLine = nextLine;
        nextLine = tmpLine;
        size_t tmpCap = curCap;
        curCap = nextCap;
        nextCap = tmpCap;
        curLen = nextLen;
    }
    free(curLine);
    free(nextLine);
    return *status;
}

/* Parses a combined script buffer (all -e SCRIPTs and -f FILE contents
 * concatenated, newline-separated) into a list of commands. Commands
 * are separated by ';' or newline; '#'-led lines are comments. Only 's',
 * 'y', 'd', and 'p' command letters are recognized. */
static bool smallclueSedParseScript(const char *script, bool extendedRegex,
                                    SmallclueSedExpr **outCmds, size_t *outCount) {
    size_t cap = 8, count = 0;
    SmallclueSedExpr *cmds = (SmallclueSedExpr *)calloc(cap, sizeof(SmallclueSedExpr));
    if (!cmds) return false;
    const char *p = script;
    while (*p) {
        while (*p == ' ' || *p == '\t' || *p == '\n' || *p == ';') p++;
        if (!*p) break;
        if (*p == '#') {
            while (*p && *p != '\n') p++;
            continue;
        }
        SmallclueSedExpr cmd;
        memset(&cmd, 0, sizeof(cmd));
        cmd.addr.line2 = -1;
        if (!smallclueSedParseAddress(&p, extendedRegex, &cmd.addr)) {
            free(cmds);
            return false;
        }
        p = smallclueSedSkipWs(p);
        if (!*p || *p == '\n' || *p == ';') {
            fprintf(stderr, "sed: missing command\n");
            free(cmds);
            return false;
        }
        cmd.cmdChar = *p;
        if (*p == 's') {
            const char *flagsEnd = p;
            char delim = p[1];
            if (!delim) {
                fprintf(stderr, "sed: malformed s command\n");
                free(cmds);
                return false;
            }
            const char *patStart = p + 2;
            const char *patEnd = strchr(patStart, delim);
            if (!patEnd) {
                fprintf(stderr, "sed: unterminated s command\n");
                free(cmds);
                return false;
            }
            const char *repStart = patEnd + 1;
            const char *repEnd = strchr(repStart, delim);
            if (!repEnd) {
                fprintf(stderr, "sed: unterminated s command\n");
                free(cmds);
                return false;
            }
            flagsEnd = repEnd + 1;
            while (*flagsEnd && *flagsEnd != ';' && *flagsEnd != '\n' &&
                   *flagsEnd != ' ' && *flagsEnd != '\t') {
                flagsEnd++;
            }
            size_t exprLen = (size_t)(flagsEnd - p);
            char *exprCopy = (char *)malloc(exprLen + 1);
            if (!exprCopy) {
                free(cmds);
                return false;
            }
            memcpy(exprCopy, p, exprLen);
            exprCopy[exprLen] = '\0';
            bool ok = smallclueSedParseExpr(exprCopy, extendedRegex, &cmd);
            free(exprCopy);
            if (!ok) {
                fprintf(stderr, "sed: invalid expression\n");
                free(cmds);
                return false;
            }
            p = flagsEnd;
        } else if (*p == 'y') {
            const char *flagsEnd = p;
            char delim = p[1];
            if (!delim) {
                fprintf(stderr, "sed: malformed y command\n");
                free(cmds);
                return false;
            }
            const char *set1Start = p + 2;
            const char *set1End = strchr(set1Start, delim);
            if (!set1End) {
                fprintf(stderr, "sed: unterminated y command\n");
                free(cmds);
                return false;
            }
            const char *set2Start = set1End + 1;
            const char *set2End = strchr(set2Start, delim);
            if (!set2End) {
                fprintf(stderr, "sed: unterminated y command\n");
                free(cmds);
                return false;
            }
            flagsEnd = set2End + 1;
            size_t exprLen = (size_t)(flagsEnd - p);
            char *exprCopy = (char *)malloc(exprLen + 1);
            if (!exprCopy) {
                free(cmds);
                return false;
            }
            memcpy(exprCopy, p, exprLen);
            exprCopy[exprLen] = '\0';
            bool ok = smallclueSedParseYExpr(exprCopy, &cmd);
            free(exprCopy);
            if (!ok) {
                free(cmds);
                return false;
            }
            p = flagsEnd;
        } else if (*p == 'd' || *p == 'p') {
            p++;
        } else {
            fprintf(stderr, "sed: unsupported command '%c'\n", *p);
            free(cmds);
            return false;
        }
        if (count == cap) {
            cap *= 2;
            SmallclueSedExpr *resized = (SmallclueSedExpr *)realloc(cmds, cap * sizeof(SmallclueSedExpr));
            if (!resized) {
                free(cmds);
                return false;
            }
            cmds = resized;
        }
        cmds[count++] = cmd;
    }
    *outCmds = cmds;
    *outCount = count;
    return true;
}

static char *smallclueSedReadFileContents(const char *path) {
    FILE *fp = fopen(path, "r");
    if (!fp) return NULL;
    size_t cap = 4096, len = 0;
    char *buf = (char *)malloc(cap);
    if (!buf) {
        fclose(fp);
        return NULL;
    }
    size_t n;
    while ((n = fread(buf + len, 1, cap - len, fp)) > 0) {
        len += n;
        if (len == cap) {
            cap *= 2;
            char *resized = (char *)realloc(buf, cap);
            if (!resized) {
                free(buf);
                fclose(fp);
                return NULL;
            }
            buf = resized;
        }
    }
    fclose(fp);
    buf[len] = '\0';
    return buf;
}

static int smallclueSedCommand(int argc, char **argv) {
    bool extendedRegex = false;
    bool inPlace = false;
    bool suppressAutoPrint = false;
    const char *inPlaceSuffix = NULL;
    char *scriptBuf = NULL;
    size_t scriptLen = 0;
    bool haveExplicitScript = false;
    int argi = 1;

    for (; argi < argc; ++argi) {
        const char *arg = argv[argi];
        if (strcmp(arg, "--") == 0) {
            argi++;
            break;
        }
        if (strcmp(arg, "-E") == 0 || strcmp(arg, "-r") == 0) {
            extendedRegex = true;
        } else if (strcmp(arg, "-n") == 0) {
            suppressAutoPrint = true;
        } else if (strcmp(arg, "-i") == 0) {
            inPlace = true;
        } else if (strncmp(arg, "-i", 2) == 0 && arg[2] != '\0') {
            inPlace = true;
            inPlaceSuffix = arg + 2;
        } else if (strcmp(arg, "-e") == 0) {
            if (argi + 1 >= argc) {
                fprintf(stderr, "sed: option requires an argument -- 'e'\n");
                free(scriptBuf);
                return 1;
            }
            const char *piece = argv[++argi];
            size_t pieceLen = strlen(piece);
            char *resized = (char *)realloc(scriptBuf, scriptLen + pieceLen + 2);
            if (!resized) {
                free(scriptBuf);
                return 1;
            }
            scriptBuf = resized;
            memcpy(scriptBuf + scriptLen, piece, pieceLen);
            scriptLen += pieceLen;
            scriptBuf[scriptLen++] = '\n';
            scriptBuf[scriptLen] = '\0';
            haveExplicitScript = true;
        } else if (strncmp(arg, "-e", 2) == 0 && arg[2] != '\0') {
            const char *piece = arg + 2;
            size_t pieceLen = strlen(piece);
            char *resized = (char *)realloc(scriptBuf, scriptLen + pieceLen + 2);
            if (!resized) {
                free(scriptBuf);
                return 1;
            }
            scriptBuf = resized;
            memcpy(scriptBuf + scriptLen, piece, pieceLen);
            scriptLen += pieceLen;
            scriptBuf[scriptLen++] = '\n';
            scriptBuf[scriptLen] = '\0';
            haveExplicitScript = true;
        } else if (strcmp(arg, "-f") == 0) {
            if (argi + 1 >= argc) {
                fprintf(stderr, "sed: option requires an argument -- 'f'\n");
                free(scriptBuf);
                return 1;
            }
            const char *scriptFile = argv[++argi];
            char *fileContents = smallclueSedReadFileContents(scriptFile);
            if (!fileContents) {
                fprintf(stderr, "sed: %s: %s\n", scriptFile, strerror(errno));
                free(scriptBuf);
                return 1;
            }
            size_t pieceLen = strlen(fileContents);
            char *resized = (char *)realloc(scriptBuf, scriptLen + pieceLen + 2);
            if (!resized) {
                free(fileContents);
                free(scriptBuf);
                return 1;
            }
            scriptBuf = resized;
            memcpy(scriptBuf + scriptLen, fileContents, pieceLen);
            scriptLen += pieceLen;
            scriptBuf[scriptLen++] = '\n';
            scriptBuf[scriptLen] = '\0';
            free(fileContents);
            haveExplicitScript = true;
        } else if (arg[0] == '-' && arg[1] != '\0') {
            fprintf(stderr, "sed: unsupported option '%s'\n", arg);
            free(scriptBuf);
            return 1;
        } else {
            break;
        }
    }

    if (!haveExplicitScript) {
        if (argi >= argc) {
            fprintf(stderr, "sed: missing expression\n");
            free(scriptBuf);
            return 1;
        }
        scriptBuf = strdup(argv[argi]);
        argi++;
    }

    SmallclueSedExpr *cmds = NULL;
    size_t cmdCount = 0;
    if (!smallclueSedParseScript(scriptBuf, extendedRegex, &cmds, &cmdCount)) {
        fprintf(stderr, "sed: invalid script\n");
        free(scriptBuf);
        return 1;
    }
    free(scriptBuf);

    int status = 0;
    if (argi >= argc) {
        if (inPlace) {
            fprintf(stderr, "sed: -i requires a file argument (cannot edit stdin in place)\n");
            for (size_t i = 0; i < cmdCount; ++i) smallclueSedExprFree(&cmds[i]);
            free(cmds);
            return 1;
        }
        smallclueSedProcessStream(stdin, stdout, cmds, cmdCount, suppressAutoPrint, "(stdin)", &status);
    } else {
        for (int i = argi; i < argc && status == 0; ++i) {
            FILE *fp = fopen(argv[i], "r");
            if (!fp) {
                fprintf(stderr, "sed: %s: %s\n", argv[i], strerror(errno));
                status = 1;
                break;
            }
            if (!inPlace) {
                smallclueSedProcessStream(fp, stdout, cmds, cmdCount, suppressAutoPrint, argv[i], &status);
                fclose(fp);
                continue;
            }
            char tmpPath[PATH_MAX];
            snprintf(tmpPath, sizeof(tmpPath), "%s.sedtmp.XXXXXX", argv[i]);
            int tmpFd = mkstemp(tmpPath);
            if (tmpFd < 0) {
                fprintf(stderr, "sed: %s: %s\n", argv[i], strerror(errno));
                status = 1;
                fclose(fp);
                continue;
            }
            FILE *tmpFp = fdopen(tmpFd, "w");
            if (!tmpFp) {
                fprintf(stderr, "sed: %s: %s\n", tmpPath, strerror(errno));
                close(tmpFd);
                unlink(tmpPath);
                status = 1;
                fclose(fp);
                continue;
            }
            smallclueSedProcessStream(fp, tmpFp, cmds, cmdCount, suppressAutoPrint, argv[i], &status);
            fclose(fp);
            fclose(tmpFp);
            if (status != 0) {
                unlink(tmpPath);
                continue;
            }
            if (inPlaceSuffix && *inPlaceSuffix) {
                char backupPath[PATH_MAX];
                snprintf(backupPath, sizeof(backupPath), "%s%s", argv[i], inPlaceSuffix);
                if (rename(argv[i], backupPath) != 0) {
                    fprintf(stderr, "sed: %s: %s\n", backupPath, strerror(errno));
                    status = 1;
                    unlink(tmpPath);
                    continue;
                }
            }
            if (rename(tmpPath, argv[i]) != 0) {
                fprintf(stderr, "sed: %s: %s\n", argv[i], strerror(errno));
                status = 1;
                unlink(tmpPath);
            }
        }
    }
    for (size_t i = 0; i < cmdCount; ++i) smallclueSedExprFree(&cmds[i]);
    free(cmds);
    return status;
}

#define SMALLCLUE_CUT_MAX_RANGES 64

typedef struct {
    int start; /* 1-based, inclusive */
    int end;   /* 1-based, inclusive; -1 = unbounded ("N-") */
} SmallclueCutRange;

/* Parses a cut -f/-c LIST: comma-separated N, N-M, N-, or -M (meaning 1-M). */
static bool smallclueCutParseList(const char *spec, SmallclueCutRange *ranges, size_t *count, size_t maxRanges) {
    *count = 0;
    const char *p = spec;
    while (*p) {
        while (*p == ',') p++;
        if (!*p) break;
        if (*count >= maxRanges) return false;
        int start, end;
        if (*p == '-') {
            start = 1;
            p++;
            char *endp;
            end = (int)strtol(p, &endp, 10);
            if (endp == p) return false;
            p = endp;
        } else {
            char *endp;
            start = (int)strtol(p, &endp, 10);
            if (endp == p || start <= 0) return false;
            p = endp;
            if (*p == '-') {
                p++;
                if (*p == '\0' || *p == ',') {
                    end = -1; /* "N-" unbounded */
                } else {
                    char *endp2;
                    end = (int)strtol(p, &endp2, 10);
                    if (endp2 == p) return false;
                    p = endp2;
                }
            } else {
                end = start;
            }
        }
        ranges[*count].start = start;
        ranges[*count].end = end;
        (*count)++;
    }
    return *count > 0;
}

static bool smallclueCutRangesContain(const SmallclueCutRange *ranges, size_t count, int pos) {
    for (size_t i = 0; i < count; ++i) {
        if (pos >= ranges[i].start && (ranges[i].end == -1 || pos <= ranges[i].end)) {
            return true;
        }
    }
    return false;
}

static void smallclueCutPrintFields(const char *line, char delim, const SmallclueCutRange *ranges,
                                    size_t rangeCount, bool suppressNoDelim) {
    if (!strchr(line, delim)) {
        if (!suppressNoDelim) {
            printf("%s\n", line);
        }
        return;
    }
    int fieldNo = 1;
    const char *start = line;
    bool printedAny = false;
    for (const char *p = line;; ++p) {
        if (*p == delim || *p == '\0') {
            if (smallclueCutRangesContain(ranges, rangeCount, fieldNo)) {
                if (printedAny) putchar(delim);
                fwrite(start, 1, (size_t)(p - start), stdout);
                printedAny = true;
            }
            if (*p == '\0') break;
            fieldNo++;
            start = p + 1;
        }
    }
    putchar('\n');
}

static void smallclueCutPrintChars(const char *line, const SmallclueCutRange *ranges, size_t rangeCount) {
    size_t len = strlen(line);
    for (size_t i = 0; i < len; ++i) {
        if (smallclueCutRangesContain(ranges, rangeCount, (int)(i + 1))) {
            putchar(line[i]);
        }
    }
    putchar('\n');
}

static int smallclueCutCommand(int argc, char **argv) {
    char delimiter = '\t';
    bool haveFieldList = false, haveCharList = false, suppressNoDelim = false;
    SmallclueCutRange ranges[SMALLCLUE_CUT_MAX_RANGES];
    size_t rangeCount = 0;

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
        if (strcmp(arg, "-s") == 0) {
            suppressNoDelim = true;
            index++;
            continue;
        }
        if (strncmp(arg, "-d", 2) == 0) {
            if (arg[2] != '\0') {
                delimiter = arg[2];
                index++;
                continue;
            }
            if (index + 1 >= argc || !argv[index + 1][0]) {
                fprintf(stderr, "cut: missing delimiter\n");
                return 1;
            }
            delimiter = argv[index + 1][0];
            index += 2;
            continue;
        }
        if (strncmp(arg, "-f", 2) == 0 || strncmp(arg, "-c", 2) == 0) {
            bool isChar = (arg[1] == 'c');
            const char *listStr = NULL;
            if (arg[2] != '\0') {
                listStr = arg + 2;
                index++;
            } else {
                if (index + 1 >= argc) {
                    fprintf(stderr, "cut: missing %s list\n", isChar ? "-c" : "-f");
                    return 1;
                }
                listStr = argv[index + 1];
                index += 2;
            }
            if (!smallclueCutParseList(listStr, ranges, &rangeCount, SMALLCLUE_CUT_MAX_RANGES)) {
                fprintf(stderr, "cut: invalid %s list '%s'\n", isChar ? "-c" : "-f", listStr);
                return 1;
            }
            if (isChar) haveCharList = true; else haveFieldList = true;
            continue;
        }
        fprintf(stderr, "cut: unsupported option '%s'\n", arg);
        return 1;
    }
    if (!haveFieldList && !haveCharList) {
        fprintf(stderr, "cut: you must specify a list of -f fields or -c characters\n");
        return 1;
    }
    if (haveFieldList && haveCharList) {
        fprintf(stderr, "cut: only one of -f or -c may be given\n");
        return 1;
    }

    char *line = NULL;
    size_t cap = 0;
    int status = 0;
    int fileCount = argc - index;
    for (int fi = 0; fi < (fileCount > 0 ? fileCount : 1); ++fi) {
        FILE *fp = stdin;
        const char *label = "-";
        if (fileCount > 0) {
            label = argv[index + fi];
            fp = fopen(label, "r");
            if (!fp) {
                fprintf(stderr, "cut: %s: %s\n", label, strerror(errno));
                status = 1;
                continue;
            }
        }
        while (true) {
            int read_err = 0;
            ssize_t len = smallclueGetlineStream(&line, &cap, fp, &read_err);
            if (len < 0) {
                if (read_err) {
                    fprintf(stderr, "cut: %s: %s\n", label, strerror(read_err));
                    status = 1;
                }
                break;
            }
            if (len > 0 && line[len - 1] == '\n') {
                line[len - 1] = '\0';
            }
            if (haveCharList) {
                smallclueCutPrintChars(line, ranges, rangeCount);
            } else {
                smallclueCutPrintFields(line, delimiter, ranges, rangeCount, suppressNoDelim);
            }
        }
        if (fp != stdin) fclose(fp);
    }
    free(line);
    return status;
}

/* Expands a tr SET specification into a flat, ORDER-PRESERVING array of
 * bytes: character ranges (a-z), POSIX classes ([:alpha:] etc), [c*n]/
 * [c*] repeats, and \n/\t/\\ backslash escapes. Order matters for
 * translate mode (SET1[i] -> SET2[i]), so classes/ranges expand in
 * ascending byte order, matching the conventional interpretation. */
static bool smallclueTrExpandSet(const char *spec, unsigned char *outBuf, size_t outCap, size_t *outLen) {
    *outLen = 0;
    size_t i = 0;
    size_t specLen = strlen(spec);
    while (i < specLen && *outLen < outCap) {
        if (spec[i] == '[' && i + 1 < specLen && spec[i + 1] == ':') {
            const char *end = strstr(spec + i + 2, ":]");
            if (end) {
                size_t nameLen = (size_t)(end - (spec + i + 2));
                const char *name = spec + i + 2;
                int (*pred)(int) = NULL;
                if (nameLen == 5 && strncmp(name, "alpha", 5) == 0) pred = isalpha;
                else if (nameLen == 5 && strncmp(name, "digit", 5) == 0) pred = isdigit;
                else if (nameLen == 5 && strncmp(name, "upper", 5) == 0) pred = isupper;
                else if (nameLen == 5 && strncmp(name, "lower", 5) == 0) pred = islower;
                else if (nameLen == 5 && strncmp(name, "space", 5) == 0) pred = isspace;
                else if (nameLen == 5 && strncmp(name, "punct", 5) == 0) pred = ispunct;
                else if (nameLen == 5 && strncmp(name, "alnum", 5) == 0) pred = isalnum;
                else if (nameLen == 5 && strncmp(name, "blank", 5) == 0) pred = isblank;
                else if (nameLen == 5 && strncmp(name, "cntrl", 5) == 0) pred = iscntrl;
                else if (nameLen == 5 && strncmp(name, "print", 5) == 0) pred = isprint;
                else if (nameLen == 5 && strncmp(name, "graph", 5) == 0) pred = isgraph;
                else if (nameLen == 6 && strncmp(name, "xdigit", 6) == 0) pred = isxdigit;
                if (pred) {
                    for (int c = 0; c < 256 && *outLen < outCap; ++c) {
                        if (pred(c)) outBuf[(*outLen)++] = (unsigned char)c;
                    }
                    i = (size_t)((end + 2) - spec);
                    continue;
                }
            }
        }
        if (spec[i] == '[' && i + 2 < specLen && spec[i + 2] == '*') {
            unsigned char repChar = (unsigned char)spec[i + 1];
            size_t j = i + 3;
            long count = 0;
            bool hasCount = false;
            while (j < specLen && isdigit((unsigned char)spec[j])) {
                count = count * 10 + (spec[j] - '0');
                hasCount = true;
                j++;
            }
            if (j < specLen && spec[j] == ']') {
                if (!hasCount) count = 1; /* "[c*]" (fill-to-length) -- caller pads with the last char anyway */
                for (long k = 0; k < count && *outLen < outCap; ++k) {
                    outBuf[(*outLen)++] = repChar;
                }
                i = j + 1;
                continue;
            }
        }
        if (i + 2 < specLen && spec[i + 1] == '-' && spec[i] != '\\') {
            unsigned char from = (unsigned char)spec[i];
            unsigned char to = (unsigned char)spec[i + 2];
            if (from <= to) {
                for (unsigned int c = from; c <= to && *outLen < outCap; ++c) {
                    outBuf[(*outLen)++] = (unsigned char)c;
                }
                i += 3;
                continue;
            }
        }
        if (spec[i] == '\\' && i + 1 < specLen) {
            unsigned char actual;
            switch (spec[i + 1]) {
                case 'n': actual = '\n'; break;
                case 't': actual = '\t'; break;
                case 'r': actual = '\r'; break;
                case '\\': actual = '\\'; break;
                case '0': actual = '\0'; break;
                default: actual = (unsigned char)spec[i + 1]; break;
            }
            outBuf[(*outLen)++] = actual;
            i += 2;
            continue;
        }
        outBuf[(*outLen)++] = (unsigned char)spec[i];
        i++;
    }
    return true;
}

static int smallclueTrCommand(int argc, char **argv) {
    bool deleteMode = false, squeezeMode = false, complementMode = false;
    int argi = 1;
    for (; argi < argc; ++argi) {
        const char *arg = argv[argi];
        if (strcmp(arg, "--") == 0) { argi++; break; }
        if (arg[0] != '-' || arg[1] == '\0') break;
        for (const char *p = arg + 1; *p; ++p) {
            if (*p == 'd') deleteMode = true;
            else if (*p == 's') squeezeMode = true;
            else if (*p == 'c' || *p == 'C') complementMode = true;
            else {
                fprintf(stderr, "tr: unsupported option '%c'\n", *p);
                return 1;
            }
        }
    }
    int operandCount = argc - argi;
    if (operandCount < 1) {
        fprintf(stderr, "tr: missing operand\n");
        return 1;
    }

    unsigned char expanded1[512], expanded2[512];
    size_t len1 = 0, len2 = 0;
    smallclueTrExpandSet(argv[argi], expanded1, sizeof(expanded1), &len1);
    bool haveSet2 = (operandCount >= 2);
    if (haveSet2) {
        smallclueTrExpandSet(argv[argi + 1], expanded2, sizeof(expanded2), &len2);
    }

    if (complementMode) {
        bool inSet[256] = {false};
        for (size_t i = 0; i < len1; ++i) inSet[expanded1[i]] = true;
        size_t newLen = 0;
        for (int c = 0; c < 256; ++c) {
            if (!inSet[c]) expanded1[newLen++] = (unsigned char)c;
        }
        len1 = newLen;
    }

    bool set1Member[256] = {false};
    for (size_t i = 0; i < len1; ++i) set1Member[expanded1[i]] = true;
    bool set2Member[256] = {false};
    for (size_t i = 0; i < len2; ++i) set2Member[expanded2[i]] = true;

    unsigned char map[256];
    for (int i = 0; i < 256; ++i) map[i] = (unsigned char)i;
    if (!deleteMode && haveSet2 && len2 > 0) {
        for (size_t i = 0; i < len1; ++i) {
            unsigned char to = (unsigned char)(i < len2 ? expanded2[i] : expanded2[len2 - 1]);
            map[expanded1[i]] = to;
        }
    } else if (!deleteMode && !haveSet2 && !squeezeMode) {
        fprintf(stderr, "tr: missing operand after '%s'\n", argv[argi]);
        return 1;
    }

    int lastOutput = -1;
    char buf[16384];
    char outBuf[16384];
    ssize_t n;
    int read_err = 0;

    while ((n = smallclueReadStream(stdin, buf, sizeof(buf), &read_err)) > 0) {
        size_t outIdx = 0;
        for (ssize_t i = 0; i < n; ++i) {
            unsigned char c = (unsigned char)buf[i];
            bool squeezeCandidate;
            if (deleteMode) {
                if (set1Member[c]) continue;
                squeezeCandidate = squeezeMode && haveSet2 && set2Member[c];
            } else if (haveSet2) {
                c = map[c];
                squeezeCandidate = squeezeMode && set2Member[c];
            } else {
                /* squeeze-only, no translation */
                squeezeCandidate = squeezeMode && set1Member[c];
            }
            if (squeezeCandidate && lastOutput == (int)c) {
                continue;
            }
            outBuf[outIdx++] = (char)c;
            lastOutput = squeezeCandidate ? (int)c : -1;
        }
        if (outIdx > 0) {
            fwrite(outBuf, 1, outIdx, stdout);
        }
    }

    if (read_err) {
        fprintf(stderr, "tr: read error: %s\n", strerror(read_err));
        return 1;
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

static int smallclueWhoamiCommand(int argc, char **argv) {
    (void)argc;
    (void)argv;
    uid_t uid = geteuid();
    struct passwd *pw = getpwuid(uid);
    if (pw && pw->pw_name) {
        puts(pw->pw_name);
    } else {
        printf("%u\n", (unsigned)uid);
    }
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
    char resolved_exec[PATH_MAX];
    const char *exec_path = argv[index];
    if (smallclueResolveCommandPathForExec(argv[index], resolved_exec, sizeof(resolved_exec))) {
        exec_path = resolved_exec;
    }
    execv(exec_path, &argv[index]);
    execvp(argv[index], &argv[index]);
    fprintf(stderr, "env: %s: %s\n", argv[index], strerror(errno));
    if (errno == ENOENT) {
        return 127;
    }
    return 126;
}

/* Highlights every non-overlapping regex match in [line, line+len) using
 * the already-compiled pattern. `len` is the byte length actually being
 * searched (the caller has already excluded any trailing '\n' so `$`/`.`
 * behave as end-of-line, not end-of-buffer -- see smallclueGrepMatches). */
static void smallclueGrepHighlightMatches(const char *line, size_t len, const regex_t *re) {
    const char *cursor = line;
    const char *end = line + len;
    while (cursor <= end) {
        regmatch_t pmatch[1];
        /* regexec needs a NUL-terminated string; searching from `cursor`
         * within the original NUL-terminated line buffer is safe as long
         * as we never search past `end`. */
        int eflags = (cursor == line) ? 0 : REG_NOTBOL;
        int rc = regexec(re, cursor, 1, pmatch, eflags);
        if (rc != 0 || cursor + pmatch[0].rm_so >= end) {
            fwrite(cursor, 1, (size_t)(end - cursor), stdout);
            return;
        }
        if (pmatch[0].rm_so > 0) {
            fwrite(cursor, 1, (size_t)pmatch[0].rm_so, stdout);
        }
        const char *matchStart = cursor + pmatch[0].rm_so;
        size_t matchLen = (size_t)(pmatch[0].rm_eo - pmatch[0].rm_so);
        if (matchStart + matchLen > end) {
            matchLen = (size_t)(end - matchStart);
        }
        fputs("\033[1;31m", stdout);
        fwrite(matchStart, 1, matchLen, stdout);
        fputs("\033[0m", stdout);
        if (matchLen == 0) {
            /* Zero-length match: emit one char verbatim to guarantee
             * forward progress. */
            if (matchStart >= end) return;
            fwrite(matchStart, 1, 1, stdout);
            cursor = matchStart + 1;
        } else {
            cursor = matchStart + matchLen;
        }
    }
}

static void smallclueGrepPrintMatch(const char *line, size_t len, const regex_t *re, int color_enabled,
                                    const char *prefix_path, long line_number) {
    if (prefix_path) {
        if (color_enabled) fputs("\033[35m", stdout);
        printf("%s", prefix_path);
        if (color_enabled) fputs("\033[36m:\033[0m", stdout);
        else putchar(':');
    }
    if (line_number > 0) {
        if (color_enabled) fputs("\033[32m", stdout);
        printf("%ld", line_number);
        if (color_enabled) fputs("\033[36m:\033[0m", stdout);
        else putchar(':');
    }

    if (!color_enabled) {
        fwrite(line, 1, len, stdout);
        return;
    }
    smallclueGrepHighlightMatches(line, len, re);
}

static bool smallclueGrepIsWordChar(char c) {
    return isalnum((unsigned char)c) || c == '_';
}

/* Finds the first match satisfying -w's word-boundary constraint: the
 * match must not be immediately preceded or followed by a word
 * character. Retries at subsequent positions if the first regexec hit
 * isn't word-bounded, since the "real" word match may occur later in
 * the line. Portable (checks boundaries manually rather than relying on
 * \< \> regex extensions, which aren't guaranteed across regex(3)
 * implementations). */
static bool smallclueGrepFindWordMatch(const char *line, size_t lineLen, const regex_t *re, regmatch_t *outMatch) {
    size_t offset = 0;
    while (offset <= lineLen) {
        regmatch_t m;
        int eflags = (offset > 0) ? REG_NOTBOL : 0;
        if (regexec(re, line + offset, 1, &m, eflags) != 0) return false;
        size_t start = offset + (size_t)m.rm_so;
        size_t end = offset + (size_t)m.rm_eo;
        bool leftOk = (start == 0) || !smallclueGrepIsWordChar(line[start - 1]);
        bool rightOk = (end == lineLen) || !smallclueGrepIsWordChar(line[end]);
        if (leftOk && rightOk) {
            outMatch->rm_so = (regoff_t)start;
            outMatch->rm_eo = (regoff_t)end;
            return true;
        }
        size_t advance = (end > offset) ? (end - offset) : 1;
        offset += advance;
    }
    return false;
}

/* Matches `line` (length lineLen, WITHOUT any trailing '\n' -- callers
 * must strip it first) against the compiled pattern, honoring -w
 * (whole word) / -x (whole line) if requested. Returns the match bounds
 * (relative to `line`) via outMatch when non-NULL. */
static bool smallclueGrepMatchesEx(const char *line, size_t lineLen, const regex_t *re,
                                   bool wordMode, bool lineMode, regmatch_t *outMatch) {
    regmatch_t m;
    if (lineMode) {
        if (regexec(re, line, 1, &m, 0) != 0) return false;
        if ((size_t)m.rm_so != 0 || (size_t)m.rm_eo != lineLen) return false;
    } else if (wordMode) {
        if (!smallclueGrepFindWordMatch(line, lineLen, re, &m)) return false;
    } else {
        if (regexec(re, line, 1, &m, 0) != 0) return false;
    }
    if (outMatch) *outMatch = m;
    return true;
}

static bool smallclueGrepMatches(const char *line, size_t lineLen, const regex_t *re) {
    return smallclueGrepMatchesEx(line, lineLen, re, false, false, NULL);
}

/* -o: prints every non-overlapping match on the line (honoring -w/-x),
 * one per output line, instead of the whole line. */
static void smallclueGrepPrintAllMatches(const char *line, size_t lineLen, const regex_t *re,
                                         bool wordMode, bool lineMode,
                                         const char *prefixPath, long lineNo, bool numberLines) {
    size_t offset = 0;
    while (offset <= lineLen) {
        regmatch_t m;
        int eflags = (offset > 0) ? REG_NOTBOL : 0;
        if (regexec(re, line + offset, 1, &m, eflags) != 0) break;
        size_t start = offset + (size_t)m.rm_so;
        size_t end = offset + (size_t)m.rm_eo;
        bool ok = true;
        if (lineMode) {
            ok = (start == 0 && end == lineLen);
        } else if (wordMode) {
            bool leftOk = (start == 0) || !smallclueGrepIsWordChar(line[start - 1]);
            bool rightOk = (end == lineLen) || !smallclueGrepIsWordChar(line[end]);
            ok = leftOk && rightOk;
        }
        if (ok && end > start) {
            if (prefixPath) printf("%s:", prefixPath);
            if (numberLines) printf("%ld:", lineNo);
            fwrite(line + start, 1, end - start, stdout);
            putchar('\n');
        }
        size_t advance = (end > offset) ? (end - offset) : 1;
        offset += advance;
    }
}

typedef struct SmallclueGrepOptions {
    bool numberLines;
    bool invertMatch;
    bool useColor;
    bool recursive;
    bool multiplePaths; /* prefix matched lines with the file path */
    bool countOnly;      /* -c */
    bool matchOnly;      /* -o */
    bool wordMatch;      /* -w */
    bool lineMatch;      /* -x */
} SmallclueGrepOptions;

static int smallclueGrepScanStream(FILE *fp, const char *label, const regex_t *re,
                                   const SmallclueGrepOptions *opts) {
    int status = 1;
    char *line = NULL;
    size_t cap = 0;
    long lineNo = 0;
    long matchCount = 0;
    for (;;) {
        int read_err = 0;
        ssize_t len = smallclueGetlineStream(&line, &cap, fp, &read_err);
        if (len < 0) {
            if (read_err) {
                fprintf(stderr, "grep: %s: %s\n", label, strerror(read_err));
            }
            break;
        }
        lineNo++;
        /* Strip any trailing '\n' before matching so `$`/`.` behave against
         * the logical end of line, not an embedded newline (the same bug
         * class fixed in sed) -- but still print with the original length
         * so output formatting is unaffected. */
        size_t matchLen = (size_t)len;
        if (matchLen > 0 && line[matchLen - 1] == '\n') {
            line[matchLen - 1] = '\0';
            matchLen--;
        }
        bool found = smallclueGrepMatchesEx(line, matchLen, re, opts->wordMatch, opts->lineMatch, NULL);
        if (opts->invertMatch ? !found : found) {
            status = 0;
            if (opts->countOnly) {
                matchCount++;
            } else if (opts->matchOnly && !opts->invertMatch) {
                smallclueGrepPrintAllMatches(line, matchLen, re, opts->wordMatch, opts->lineMatch,
                                             opts->multiplePaths ? label : NULL,
                                             opts->numberLines ? lineNo : 0, opts->numberLines);
            } else {
                /* Print only up to matchLen (line[] now has a NUL where the
                 * original '\n' was), then re-add the newline explicitly --
                 * printing the original `len` bytes here would emit that
                 * stray NUL byte in place of the newline. */
                smallclueGrepPrintMatch(line, matchLen, re, opts->useColor && !opts->invertMatch,
                                        opts->multiplePaths ? label : NULL,
                                        opts->numberLines ? lineNo : 0);
                if (matchLen < (size_t)len) {
                    fputc('\n', stdout);
                }
            }
        }
    }
    if (opts->countOnly) {
        if (opts->multiplePaths) printf("%s:", label);
        printf("%ld\n", matchCount);
    }
    free(line);
    return status;
}

static void smallclueGrepWalkPath(const char *path, const regex_t *re, const SmallclueGrepOptions *opts, int *status) {
    struct stat st;
    if (lstat(path, &st) != 0) {
        fprintf(stderr, "grep: %s: %s\n", path, strerror(errno));
        *status = *status == 0 ? 0 : 2;
        return;
    }
    if (S_ISDIR(st.st_mode)) {
        if (!opts->recursive) {
            fprintf(stderr, "grep: %s: is a directory\n", path);
            *status = *status == 0 ? 0 : 2;
            return;
        }
        DIR *dir = opendir(path);
        if (!dir) {
            fprintf(stderr, "grep: %s: %s\n", path, strerror(errno));
            *status = *status == 0 ? 0 : 2;
            return;
        }
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
                continue;
            }
            char child[PATH_MAX];
            if (smallclueBuildPath(child, sizeof(child), path, entry->d_name) != 0) {
                fprintf(stderr, "grep: %s/%s: %s\n", path, entry->d_name, strerror(errno));
                *status = *status == 0 ? 0 : 2;
                continue;
            }
            smallclueGrepWalkPath(child, re, opts, status);
        }
        closedir(dir);
        return;
    }
    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "grep: %s: %s\n", path, strerror(errno));
        *status = *status == 0 ? 0 : 2;
        return;
    }
    int rc = smallclueGrepScanStream(fp, path, re, opts);
    fclose(fp);
    if (rc == 0) {
        *status = 0;
    } else if (*status != 0) {
        *status = 1;
    }
}

static int smallclueGrepCommand(int argc, char **argv) {
    int index = 1;
    SmallclueGrepOptions opts;
    memset(&opts, 0, sizeof(opts));
    bool extendedRegex = false;
    bool ignoreCase = false;
    int color_mode = 0; /* 0=auto, 1=always, -1=never */

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
                ignoreCase = true;
                index++;
                continue;
            }
            if (strcmp(arg, "--invert-match") == 0 || strcmp(arg, "--invert") == 0) {
                opts.invertMatch = true;
                index++;
                continue;
            }
            if (strcmp(arg, "--line-number") == 0 || strcmp(arg, "--number") == 0) {
                opts.numberLines = true;
                index++;
                continue;
            }
            if (strcmp(arg, "--recursive") == 0) {
                opts.recursive = true;
                index++;
                continue;
            }
            if (strcmp(arg, "--extended-regexp") == 0) {
                extendedRegex = true;
                index++;
                continue;
            }
            if (strcmp(arg, "--count") == 0) {
                opts.countOnly = true;
                index++;
                continue;
            }
            if (strcmp(arg, "--only-matching") == 0) {
                opts.matchOnly = true;
                index++;
                continue;
            }
            if (strcmp(arg, "--word-regexp") == 0) {
                opts.wordMatch = true;
                index++;
                continue;
            }
            if (strcmp(arg, "--line-regexp") == 0) {
                opts.lineMatch = true;
                index++;
                continue;
            }
            if (strncmp(arg, "--color", 7) == 0 || strncmp(arg, "--colour", 8) == 0) {
                const char *val = NULL;
                if (strncmp(arg, "--color=", 8) == 0) val = arg + 8;
                else if (strncmp(arg, "--colour=", 9) == 0) val = arg + 9;
                else val = "auto"; /* implicit argument for --color */

                if (strcasecmp(val, "always") == 0) color_mode = 1;
                else if (strcasecmp(val, "never") == 0 || strcasecmp(val, "none") == 0) color_mode = -1;
                else color_mode = 0;

                index++;
                continue;
            }
            /* Unrecognized long option: treat as start of pattern/paths. */
            break;
        }
        for (const char *opt = arg + 1; *opt; ++opt) {
            if (*opt == 'n') {
                opts.numberLines = true;
            } else if (*opt == 'i') {
                ignoreCase = true;
            } else if (*opt == 'v') {
                opts.invertMatch = true;
            } else if (*opt == 'r' || *opt == 'R') {
                opts.recursive = true;
            } else if (*opt == 'E') {
                extendedRegex = true;
            } else if (*opt == 'c') {
                opts.countOnly = true;
            } else if (*opt == 'o') {
                opts.matchOnly = true;
            } else if (*opt == 'w') {
                opts.wordMatch = true;
            } else if (*opt == 'x') {
                opts.lineMatch = true;
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

    regex_t re;
    int reFlags = (extendedRegex ? REG_EXTENDED : 0) | (ignoreCase ? REG_ICASE : 0);
    int rc = regcomp(&re, pattern, reFlags);
    if (rc != 0) {
        char errbuf[256];
        regerror(rc, &re, errbuf, sizeof(errbuf));
        fprintf(stderr, "grep: invalid pattern '%s': %s\n", pattern, errbuf);
        return 2;
    }

    if (color_mode == 0) {
        color_mode = pscalRuntimeStdoutIsInteractive() ? 1 : -1;
    }
    opts.useColor = (color_mode == 1);

    int paths = argc - index;
    int status;
    if (paths <= 0) {
        status = smallclueGrepScanStream(stdin, "(standard input)", &re, &opts);
    } else {
        opts.multiplePaths = (paths > 1) || opts.recursive;
        status = 1;
        for (int i = index; i < argc; ++i) {
            smallclueGrepWalkPath(argv[i], &re, &opts, &status);
        }
    }
    regfree(&re);
    return status;
}

typedef struct {
    uint64_t lines;
    uint64_t words;
    uint64_t bytes;
    uint64_t chars;
    uint64_t max_line_length;
} SmallclueWcCounts;

static int smallclueWcProcessFileFast(const char *path, FILE *fp, SmallclueWcCounts *counts) {
    uint64_t lines = 0;
    uint64_t words = 0;
    uint64_t bytes = 0;
    int in_word = 0;
    int read_err = 0;
    char buf[16384];
    ssize_t n;

    while ((n = smallclueReadStream(fp, buf, sizeof(buf), &read_err)) > 0) {
        bytes += (uint64_t)n;
        ssize_t i = 0;
        /* Bolt optimization: loop unrolling for wc */
        #define PROCESS_CHAR(idx) do { \
            unsigned char c = (unsigned char)buf[idx]; \
            lines += (c == '\n'); \
            if ((c == ' ') || (c >= '\t' && c <= '\r')) { \
                in_word = 0; \
            } else if (!in_word) { \
                words++; \
                in_word = 1; \
            } \
        } while (0)

        for (; i + 15 < n; i += 16) {
            PROCESS_CHAR(i);
            PROCESS_CHAR(i+1);
            PROCESS_CHAR(i+2);
            PROCESS_CHAR(i+3);
            PROCESS_CHAR(i+4);
            PROCESS_CHAR(i+5);
            PROCESS_CHAR(i+6);
            PROCESS_CHAR(i+7);
            PROCESS_CHAR(i+8);
            PROCESS_CHAR(i+9);
            PROCESS_CHAR(i+10);
            PROCESS_CHAR(i+11);
            PROCESS_CHAR(i+12);
            PROCESS_CHAR(i+13);
            PROCESS_CHAR(i+14);
            PROCESS_CHAR(i+15);
        }
        #undef PROCESS_CHAR
        for (; i < n; ++i) {
            unsigned char c = (unsigned char)buf[i];
            if (c == '\n') {
                lines++;
            }

            /* Bolt optimization: inline space check instead of isspace() to avoid function call overhead */
            int is_sp = (c == ' ') || (c >= '\t' && c <= '\r');
            if (is_sp) {
                in_word = 0;
            } else if (!in_word) {
                words++;
                in_word = 1;
            }
        }
    }

    counts->lines = lines;
    counts->words = words;
    counts->bytes = bytes;
    counts->chars = bytes;
    counts->max_line_length = 0;
    return read_err ? 1 : 0;
}

/* Slower path used only when -m/-L are requested: decodes multibyte
 * characters via mbrtowc (honoring the process locale) so -m's character
 * count and -L's column-based max-line-length match GNU wc under a UTF-8
 * locale, instead of just approximating them as raw byte counts. -L expands
 * tabs to the next multiple of 8 columns, matching GNU coreutils' actual
 * behavior (verified against Linux wc). */
static int smallclueWcProcessFileWide(const char *path, FILE *fp, SmallclueWcCounts *counts) {
    uint64_t lines = 0;
    uint64_t words = 0;
    uint64_t bytes = 0;
    uint64_t chars = 0;
    uint64_t max_line_length = 0;
    uint64_t cur_line_length = 0;
    int in_word = 0;
    int read_err = 0;
    char buf[16384];
    ssize_t n;
    mbstate_t mbs;
    memset(&mbs, 0, sizeof(mbs));
    unsigned char carry[16];
    size_t carryLen = 0;

    while ((n = smallclueReadStream(fp, buf, sizeof(buf), &read_err)) > 0) {
        bytes += (uint64_t)n;

        for (int i = 0; i < n; ++i) {
            unsigned char c = (unsigned char)buf[i];
            if (c == '\n') {
                lines++;
            }
            int is_sp = (c == ' ') || (c >= '\t' && c <= '\r');
            if (is_sp) {
                in_word = 0;
            } else if (!in_word) {
                words++;
                in_word = 1;
            }
        }

        /* Character decode: work off a carry buffer so a multibyte
         * sequence split across two reads still decodes correctly. */
        size_t avail = carryLen + (size_t)n;
        unsigned char *scratch = (unsigned char *)malloc(avail > 0 ? avail : 1);
        if (!scratch) {
            fprintf(stderr, "wc: out of memory\n");
            return 1;
        }
        if (carryLen) memcpy(scratch, carry, carryLen);
        memcpy(scratch + carryLen, buf, (size_t)n);

        size_t pos = 0;
        while (pos < avail) {
            wchar_t wc;
            size_t rc = mbrtowc(&wc, (const char *)scratch + pos, avail - pos, &mbs);
            if (rc == (size_t)-2) {
                /* Incomplete sequence at the end of the buffer -- carry the
                 * remaining bytes over to the next read. */
                size_t remain = avail - pos;
                if (remain > sizeof(carry)) remain = sizeof(carry);
                memcpy(carry, scratch + pos, remain);
                carryLen = remain;
                pos = avail;
                break;
            }
            if (rc == (size_t)-1) {
                /* Invalid sequence -- count the single byte as one
                 * character and resync, matching GNU wc's behavior. */
                memset(&mbs, 0, sizeof(mbs));
                chars++;
                cur_line_length++;
                pos++;
                carryLen = 0;
                continue;
            }
            if (rc == 0) rc = 1; /* embedded NUL still counts as a character */
            chars++;
            if (wc == L'\n') {
                if (cur_line_length > max_line_length) max_line_length = cur_line_length;
                cur_line_length = 0;
            } else if (wc == L'\t') {
                cur_line_length = (cur_line_length / 8 + 1) * 8;
            } else {
                cur_line_length++;
            }
            pos += rc;
            carryLen = 0;
        }
        free(scratch);
    }

    if (cur_line_length > max_line_length) max_line_length = cur_line_length;

    counts->lines = lines;
    counts->words = words;
    counts->bytes = bytes;
    counts->chars = chars;
    counts->max_line_length = max_line_length;
    return read_err ? 1 : 0;
}

static int smallclueWcProcessFile(const char *path, SmallclueWcCounts *counts, bool needWide) {
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

    int rc = needWide ? smallclueWcProcessFileWide(path, fp, counts)
                       : smallclueWcProcessFileFast(path, fp, counts);

    if (fp != stdin) {
        fclose(fp);
    }
    if (rc != 0) {
        fprintf(stderr, "wc: %s: read error\n", path ? path : "(stdin)");
        return 1;
    }
    return 0;
}

static void smallclueWcPrint(const SmallclueWcCounts *counts, int show_lines, int show_words,
                              int show_chars, int show_bytes, int show_maxline, const char *label) {
    if (show_lines) {
        printf("%12" PRIu64, counts->lines);
    }
    if (show_words) {
        printf("%12" PRIu64, counts->words);
    }
    if (show_chars) {
        printf("%12" PRIu64, counts->chars);
    }
    if (show_bytes) {
        printf("%12" PRIu64, counts->bytes);
    }
    if (show_maxline) {
        printf("%12" PRIu64, counts->max_line_length);
    }
    if (label) {
        printf(" %s", label);
    }
    putchar('\n');
}

static int smallclueWcCommand(int argc, char **argv) {
    int show_lines = 0, show_words = 0, show_bytes = 0, show_chars = 0, show_maxline = 0;
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
            else if (*opt == 'm') show_chars = 1;
            else if (*opt == 'L') show_maxline = 1;
            else {
                fprintf(stderr, "wc: invalid option -- %c\n", *opt);
                return 1;
            }
        }
        index++;
    }
    if (!show_lines && !show_words && !show_bytes && !show_chars && !show_maxline) {
        show_lines = show_words = show_bytes = 1;
    }
    bool needWide = show_chars || show_maxline;
    if (needWide) {
        setlocale(LC_CTYPE, "");
    }
    int paths = argc - index;
    int status = 0;
    SmallclueWcCounts counts;
    SmallclueWcCounts total = {0, 0, 0, 0, 0};
    if (paths <= 0) {
        if (smallclueWcProcessFile(NULL, &counts, needWide) != 0) {
            return 1;
        }
        smallclueWcPrint(&counts, show_lines, show_words, show_chars, show_bytes, show_maxline, NULL);
    } else {
        for (int i = index; i < argc; ++i) {
            if (smallclueWcProcessFile(argv[i], &counts, needWide) != 0) {
                status = 1;
                continue;
            }
            smallclueWcPrint(&counts, show_lines, show_words, show_chars, show_bytes, show_maxline, argv[i]);
            total.lines += counts.lines;
            total.words += counts.words;
            total.bytes += counts.bytes;
            total.chars += counts.chars;
            if (counts.max_line_length > total.max_line_length) {
                total.max_line_length = counts.max_line_length;
            }
        }
        if (paths > 1) {
            smallclueWcPrint(&total, show_lines, show_words, show_chars, show_bytes, show_maxline, "total");
        }
    }
    return status;
}

typedef struct {
    int summarize_only;
    int use_kilobytes;
    int human_readable;
    int max_depth;      /* -1 = unlimited */
    int grand_total;    /* -c */
    int one_filesystem; /* -x */
    dev_t root_dev;     /* set per top-level argument when -x is active */
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
    } else {
        /* POSIX/real du's actual default unit is 512-byte blocks, not
         * raw bytes (matches `ls -s`'s own block-count column). */
        if (value >= 0) {
            value = (value + 511) / 512;
        } else {
            value = -(((-value) + 511) / 512);
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
    /* Real du measures actual disk usage (allocated 512-byte blocks),
     * not apparent file size -- st_size would badly undercount small
     * files on filesystems with block sizes larger than the file. */
    long long total = (long long)st.st_blocks * 512;
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
            if (opts && opts->one_filesystem) {
                struct stat childSt;
                if (lstat(child, &childSt) == 0 && childSt.st_dev != opts->root_dev) {
                    continue; /* -x: don't cross onto a different filesystem */
                }
            }
            total += smallclueDuVisit(child, status, opts, depth + 1);
        }
        closedir(dir);
    }

    bool isDir = S_ISDIR(st.st_mode);
    if (opts && opts->summarize_only) {
        if (depth == 0) {
            smallclueDuPrintSize(total, path, opts);
        }
    } else {
        /* GNU du's real default: print a subtotal for every DIRECTORY at
         * every depth, but never an individual file -- the top-level
         * operand itself is always printed even if it's a plain file
         * (matching `du somefile` still reporting that file's size). */
        bool withinDepth = !opts || opts->max_depth < 0 || depth <= opts->max_depth;
        if ((isDir || depth == 0) && withinDepth) {
            smallclueDuPrintSize(total, path, opts);
        }
    }
    return total;
}

static int smallclueDuCommand(int argc, char **argv) {
    SmallclueDuOptions opts;
    memset(&opts, 0, sizeof(opts));
    opts.max_depth = -1;

    /* --max-depth=N is a GNU long option with no getopt()-friendly
     * short form other than -d N (which getopt handles fine); strip the
     * "=N" long form out first, matching the convention used elsewhere
     * in this file (e.g. stat's --format=). */
    for (int i = 1; i < argc; ) {
        if (strncmp(argv[i], "--max-depth=", 12) == 0) {
            opts.max_depth = atoi(argv[i] + 12);
            for (int j = i; j + 1 < argc; ++j) argv[j] = argv[j + 1];
            argc--;
            continue;
        }
        i++;
    }

    int opt;
    smallclueResetGetopt();
    while ((opt = getopt(argc, argv, "skhcxd:")) != -1) {
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
            case 'c':
                opts.grand_total = 1;
                break;
            case 'x':
                opts.one_filesystem = 1;
                break;
            case 'd':
                opts.max_depth = atoi(optarg);
                break;
            default:
                return 1;
        }
    }

    int status = 0;
    long long grandTotal = 0;
    int pathCount = (optind < argc) ? (argc - optind) : 1;
    for (int i = 0; i < pathCount; ++i) {
        const char *path = (optind < argc) ? argv[optind + i] : ".";
        if (opts.one_filesystem) {
            struct stat rootSt;
            if (lstat(path, &rootSt) == 0) {
                opts.root_dev = rootSt.st_dev;
            }
        }
        grandTotal += smallclueDuVisit(path, &status, &opts, 0);
    }
    if (opts.grand_total) {
        smallclueDuPrintSize(grandTotal, "total", &opts);
    }
    return status ? 1 : 0;
}

/* Boolean expression tree for find's predicate language: -a/-and (implicit
 * between adjacent terms too), -o/-or, !/-not, and parenthesized grouping.
 * Precedence (loosest to tightest, matching real find): OR, AND, NOT.
 * Actions (-print/-print0/-delete/-exec) are themselves expression terms
 * that perform a side effect and evaluate true -- this is what makes
 * `find . -name '*.c' -o -name '*.h'` and `find . -name '*.o' -delete`
 * both fall out of the same evaluator instead of needing special cases. */
typedef enum {
    FIND_NODE_TEST,
    FIND_NODE_AND,
    FIND_NODE_OR,
    FIND_NODE_NOT,
    FIND_NODE_PRINT,
    FIND_NODE_PRINT0,
    FIND_NODE_DELETE,
    FIND_NODE_EXEC,
} SmallclueFindNodeType;

typedef enum {
    FIND_TEST_NAME,
    FIND_TEST_INAME,
    FIND_TEST_TYPE,
    FIND_TEST_MTIME,
    FIND_TEST_NEWER,
    FIND_TEST_SIZE,
} SmallclueFindTestKind;

typedef struct SmallclueFindNode {
    SmallclueFindNodeType type;
    SmallclueFindTestKind testKind;
    const char *strArg;   /* -name/-iname pattern */
    char typeFilter;      /* -type: 'f', 'd', 'l' */
    char sign;            /* -mtime/-size: '+', '-', or '\0' for exact */
    long long value;      /* -mtime days or -size threshold */
    bool isBlockUnit;     /* -size: bare/b vs c/k/M/G/w */
    time_t newerMtime;    /* -newer: reference mtime */
    char **execArgv;      /* -exec: argv slice up to (not including) ';' */
    int execArgc;
    struct SmallclueFindNode *left;
    struct SmallclueFindNode *right; /* AND/OR right operand, NOT's child */
} SmallclueFindNode;

typedef struct SmallclueFindOptions {
    int maxDepth; /* -1 = unlimited */
    int minDepth; /* 0 = no minimum */
    SmallclueFindNode *root;
} SmallclueFindOptions;

/* Parses find's -size [+-]N[ckMGwb] spec. Confirmed against the real
 * system find with /usr/bin/find explicitly (this shell has a `find`
 * function that redirects to an unrelated bfs-based tool -- an earlier
 * pass through that shadowed `find` produced self-contradictory
 * results and had to be discarded and redone): only the bare/`b` form
 * rounds the file's size UP to whole 512-byte blocks and compares that
 * block COUNT to N. `c` compares the exact byte count to N. `k`/`M`/`G`/`w`
 * compare the exact byte count to N scaled by the suffix -- NOT
 * rounded to a block boundary (e.g. -size -1k matches a 1000-byte file
 * directly against the 1024-byte threshold, no rounding involved). */
static bool smallclueFindParseSize(const char *s, char *signOut, long long *valueOut, bool *isBlockUnit) {
    if (!s || !*s) return false;
    char sign = '\0';
    const char *p = s;
    if (*p == '+' || *p == '-') {
        sign = *p;
        p++;
    }
    char *end = NULL;
    long long v = strtoll(p, &end, 10);
    if (end == p) return false;
    long long multiplier = 1; /* bare: block count itself, not bytes */
    bool blockUnit = true;
    if (*end != '\0') {
        switch (*end) {
            case 'c': multiplier = 1; blockUnit = false; break;
            case 'k': multiplier = 1024; blockUnit = false; break;
            case 'M': multiplier = 1024LL * 1024; blockUnit = false; break;
            case 'G': multiplier = 1024LL * 1024 * 1024; blockUnit = false; break;
            case 'w': multiplier = 2; blockUnit = false; break;
            case 'b': multiplier = 1; blockUnit = true; break;
            default: return false;
        }
        if (end[1] != '\0') return false;
    }
    *signOut = sign;
    *valueOut = v * multiplier;
    *isBlockUnit = blockUnit;
    return true;
}

static bool smallclueFindParseSignedInt(const char *s, char *signOut, long long *valueOut) {
    if (!s || !*s) return false;
    char sign = '\0';
    const char *p = s;
    if (*p == '+' || *p == '-') {
        sign = *p;
        p++;
    }
    char *end = NULL;
    long long v = strtoll(p, &end, 10);
    if (!end || end == p || *end != '\0') return false;
    *signOut = sign;
    *valueOut = v;
    return true;
}

static bool smallclueFindCompareSigned(char sign, long long actual, long long spec) {
    if (sign == '+') return actual > spec;
    if (sign == '-') return actual < spec;
    return actual == spec;
}

static bool smallclueFindTestMatches(const SmallclueFindNode *node, const char *path, const struct stat *st) {
    switch (node->testKind) {
        case FIND_TEST_NAME:
        case FIND_TEST_INAME: {
            const char *leaf = smallclueLeafName(path);
            int flags = (node->testKind == FIND_TEST_INAME) ? FNM_CASEFOLD : 0;
            return fnmatch(node->strArg, leaf, flags) == 0;
        }
        case FIND_TEST_TYPE:
            switch (node->typeFilter) {
                case 'f': return S_ISREG(st->st_mode);
                case 'd': return S_ISDIR(st->st_mode);
                case 'l': return S_ISLNK(st->st_mode);
                default: return true;
            }
        case FIND_TEST_MTIME: {
            long long ageSeconds = (long long)time(NULL) - (long long)st->st_mtime;
            long long daysAgo = ageSeconds / 86400;
            return smallclueFindCompareSigned(node->sign, daysAgo, node->value);
        }
        case FIND_TEST_NEWER:
            return st->st_mtime > node->newerMtime;
        case FIND_TEST_SIZE: {
            long long measure = node->isBlockUnit
                ? (((long long)st->st_size + 511) / 512)
                : (long long)st->st_size;
            return smallclueFindCompareSigned(node->sign, measure, node->value);
        }
    }
    return false;
}

static int smallclueFindRunExec(const char *path, char **execArgv, int execArgc);

/* Evaluates the expression tree for one visited path. AND/OR short-circuit
 * via C's &&/|| exactly like real find: a term after a false -a (or after a
 * true -o) is never evaluated, so its side effects (an -exec or -delete
 * later in the expression) don't run -- matching real find's actual
 * behavior for e.g. `find . -name '*.tmp' -delete` only deleting matches,
 * or `find . -name a -o -name b` only ever testing the first name. */
static bool smallclueFindEval(const SmallclueFindNode *node, const char *path, const struct stat *st, int *status) {
    switch (node->type) {
        case FIND_NODE_TEST:
            return smallclueFindTestMatches(node, path, st);
        case FIND_NODE_AND:
            return smallclueFindEval(node->left, path, st, status) &&
                   smallclueFindEval(node->right, path, st, status);
        case FIND_NODE_OR:
            return smallclueFindEval(node->left, path, st, status) ||
                   smallclueFindEval(node->right, path, st, status);
        case FIND_NODE_NOT:
            return !smallclueFindEval(node->right, path, st, status);
        case FIND_NODE_PRINT:
            fputs(path, stdout);
            putchar('\n');
            return true;
        case FIND_NODE_PRINT0:
            fputs(path, stdout);
            putchar('\0');
            return true;
        case FIND_NODE_DELETE: {
            int rc = S_ISDIR(st->st_mode) ? rmdir(path) : unlink(path);
            if (rc != 0) {
                fprintf(stderr, "find: %s: %s\n", path, strerror(errno));
                if (status) *status = 1;
                return false;
            }
            return true;
        }
        case FIND_NODE_EXEC:
            return smallclueFindRunExec(path, node->execArgv, node->execArgc) == 0;
    }
    return false;
}

/* Recursive-descent parser for find's expression grammar, precedence
 * loosest-to-tightest: OR ("-o"/"-or"), AND ("-a"/"-and", or nothing at all
 * between two adjacent terms -- find's implicit AND), NOT ("!"/"-not"),
 * primary (a test/action, or a parenthesized sub-expression). Returns NULL
 * on a parse error (after printing a message to stderr) -- *hadAction is
 * set true if any -print/-print0/-delete/-exec term is found anywhere in
 * the expression, so the caller knows whether to add an implicit -print. */
static SmallclueFindNode *smallclueFindParseOr(char **argv, int argc, int *idx, bool *hadAction);

static SmallclueFindNode *smallclueFindParsePrimary(char **argv, int argc, int *idx, bool *hadAction) {
    if (*idx >= argc) {
        fprintf(stderr, "find: unexpected end of expression\n");
        return NULL;
    }
    const char *arg = argv[*idx];
    if (strcmp(arg, "(") == 0) {
        (*idx)++;
        SmallclueFindNode *inner = smallclueFindParseOr(argv, argc, idx, hadAction);
        if (!inner) return NULL;
        if (*idx >= argc || strcmp(argv[*idx], ")") != 0) {
            fprintf(stderr, "find: missing closing ')'\n");
            return NULL;
        }
        (*idx)++;
        return inner;
    }
    if (strcmp(arg, "-name") == 0 || strcmp(arg, "-iname") == 0) {
        bool isIname = (arg[1] == 'i');
        (*idx)++;
        if (*idx >= argc) {
            fprintf(stderr, "find: missing argument to %s\n", arg);
            return NULL;
        }
        SmallclueFindNode *node = (SmallclueFindNode *)calloc(1, sizeof(*node));
        node->type = FIND_NODE_TEST;
        node->testKind = isIname ? FIND_TEST_INAME : FIND_TEST_NAME;
        node->strArg = argv[(*idx)++];
        return node;
    }
    if (strcmp(arg, "-type") == 0) {
        (*idx)++;
        if (*idx >= argc) {
            fprintf(stderr, "find: missing argument to -type\n");
            return NULL;
        }
        const char *typeArg = argv[(*idx)++];
        if (strcmp(typeArg, "f") != 0 && strcmp(typeArg, "d") != 0 && strcmp(typeArg, "l") != 0) {
            fprintf(stderr, "find: unsupported -type '%s' (only f/d/l)\n", typeArg);
            return NULL;
        }
        SmallclueFindNode *node = (SmallclueFindNode *)calloc(1, sizeof(*node));
        node->type = FIND_NODE_TEST;
        node->testKind = FIND_TEST_TYPE;
        node->typeFilter = typeArg[0];
        return node;
    }
    if (strcmp(arg, "-mtime") == 0) {
        (*idx)++;
        if (*idx >= argc) {
            fprintf(stderr, "find: missing argument to -mtime\n");
            return NULL;
        }
        char sign;
        long long value;
        if (!smallclueFindParseSignedInt(argv[(*idx)++], &sign, &value)) {
            fprintf(stderr, "find: invalid -mtime argument\n");
            return NULL;
        }
        SmallclueFindNode *node = (SmallclueFindNode *)calloc(1, sizeof(*node));
        node->type = FIND_NODE_TEST;
        node->testKind = FIND_TEST_MTIME;
        node->sign = sign;
        node->value = value;
        return node;
    }
    if (strcmp(arg, "-newer") == 0) {
        (*idx)++;
        if (*idx >= argc) {
            fprintf(stderr, "find: missing argument to -newer\n");
            return NULL;
        }
        const char *refPath = argv[(*idx)++];
        struct stat refSt;
        if (stat(refPath, &refSt) != 0) {
            fprintf(stderr, "find: %s: %s\n", refPath, strerror(errno));
            return NULL;
        }
        SmallclueFindNode *node = (SmallclueFindNode *)calloc(1, sizeof(*node));
        node->type = FIND_NODE_TEST;
        node->testKind = FIND_TEST_NEWER;
        node->newerMtime = refSt.st_mtime;
        return node;
    }
    if (strcmp(arg, "-size") == 0) {
        (*idx)++;
        if (*idx >= argc) {
            fprintf(stderr, "find: missing argument to -size\n");
            return NULL;
        }
        char sign;
        long long value;
        bool isBlockUnit;
        if (!smallclueFindParseSize(argv[(*idx)++], &sign, &value, &isBlockUnit)) {
            fprintf(stderr, "find: invalid -size argument\n");
            return NULL;
        }
        SmallclueFindNode *node = (SmallclueFindNode *)calloc(1, sizeof(*node));
        node->type = FIND_NODE_TEST;
        node->testKind = FIND_TEST_SIZE;
        node->sign = sign;
        node->value = value;
        node->isBlockUnit = isBlockUnit;
        return node;
    }
    if (strcmp(arg, "-print") == 0) {
        (*idx)++;
        *hadAction = true;
        SmallclueFindNode *node = (SmallclueFindNode *)calloc(1, sizeof(*node));
        node->type = FIND_NODE_PRINT;
        return node;
    }
    if (strcmp(arg, "-print0") == 0) {
        (*idx)++;
        *hadAction = true;
        SmallclueFindNode *node = (SmallclueFindNode *)calloc(1, sizeof(*node));
        node->type = FIND_NODE_PRINT0;
        return node;
    }
    if (strcmp(arg, "-delete") == 0) {
        (*idx)++;
        *hadAction = true;
        SmallclueFindNode *node = (SmallclueFindNode *)calloc(1, sizeof(*node));
        node->type = FIND_NODE_DELETE;
        return node;
    }
    if (strcmp(arg, "-exec") == 0) {
        (*idx)++;
        int execStart = *idx;
        while (*idx < argc && strcmp(argv[*idx], ";") != 0) {
            (*idx)++;
        }
        if (*idx >= argc) {
            fprintf(stderr, "find: -exec requires a terminating ';'\n");
            return NULL;
        }
        int execArgc = *idx - execStart;
        if (execArgc == 0) {
            fprintf(stderr, "find: -exec requires a command\n");
            return NULL;
        }
        SmallclueFindNode *node = (SmallclueFindNode *)calloc(1, sizeof(*node));
        node->type = FIND_NODE_EXEC;
        node->execArgv = &argv[execStart];
        node->execArgc = execArgc;
        (*idx)++; /* consume the ';' */
        *hadAction = true;
        return node;
    }
    fprintf(stderr, "find: unsupported predicate '%s'\n", arg);
    return NULL;
}

static SmallclueFindNode *smallclueFindParseNot(char **argv, int argc, int *idx, bool *hadAction) {
    if (*idx < argc && (strcmp(argv[*idx], "!") == 0 || strcmp(argv[*idx], "-not") == 0)) {
        (*idx)++;
        SmallclueFindNode *child = smallclueFindParseNot(argv, argc, idx, hadAction);
        if (!child) return NULL;
        SmallclueFindNode *node = (SmallclueFindNode *)calloc(1, sizeof(*node));
        node->type = FIND_NODE_NOT;
        node->right = child;
        return node;
    }
    return smallclueFindParsePrimary(argv, argc, idx, hadAction);
}

static bool smallclueFindAtExprBoundary(char **argv, int argc, int idx) {
    if (idx >= argc) return true;
    const char *tok = argv[idx];
    return strcmp(tok, "-o") == 0 || strcmp(tok, "-or") == 0 || strcmp(tok, ")") == 0;
}

static SmallclueFindNode *smallclueFindParseAnd(char **argv, int argc, int *idx, bool *hadAction) {
    SmallclueFindNode *left = smallclueFindParseNot(argv, argc, idx, hadAction);
    if (!left) return NULL;
    while (!smallclueFindAtExprBoundary(argv, argc, *idx)) {
        if (strcmp(argv[*idx], "-a") == 0 || strcmp(argv[*idx], "-and") == 0) {
            (*idx)++;
        }
        /* else: implicit AND -- another term follows directly, no operator token */
        SmallclueFindNode *right = smallclueFindParseNot(argv, argc, idx, hadAction);
        if (!right) return NULL;
        SmallclueFindNode *node = (SmallclueFindNode *)calloc(1, sizeof(*node));
        node->type = FIND_NODE_AND;
        node->left = left;
        node->right = right;
        left = node;
    }
    return left;
}

static SmallclueFindNode *smallclueFindParseOr(char **argv, int argc, int *idx, bool *hadAction) {
    SmallclueFindNode *left = smallclueFindParseAnd(argv, argc, idx, hadAction);
    if (!left) return NULL;
    while (*idx < argc && (strcmp(argv[*idx], "-o") == 0 || strcmp(argv[*idx], "-or") == 0)) {
        (*idx)++;
        SmallclueFindNode *right = smallclueFindParseAnd(argv, argc, idx, hadAction);
        if (!right) return NULL;
        SmallclueFindNode *node = (SmallclueFindNode *)calloc(1, sizeof(*node));
        node->type = FIND_NODE_OR;
        node->left = left;
        node->right = right;
        left = node;
    }
    return left;
}

static int smallclueFindRunExec(const char *path, char **execArgv, int execArgc) {
    char **argvCopy = calloc((size_t)execArgc + 1, sizeof(char *));
    if (!argvCopy) {
        fprintf(stderr, "find: out of memory\n");
        return 1;
    }
    for (int i = 0; i < execArgc; ++i) {
        if (strcmp(execArgv[i], "{}") == 0) {
            argvCopy[i] = (char *)path;
        } else {
            argvCopy[i] = execArgv[i];
        }
    }
    argvCopy[execArgc] = NULL;

    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "find: fork: %s\n", strerror(errno));
        free(argvCopy);
        return 1;
    }
    if (pid == 0) {
        execvp(argvCopy[0], argvCopy);
        fprintf(stderr, "find: %s: %s\n", argvCopy[0], strerror(errno));
        _exit(127);
    }
    free(argvCopy);
    int childStatus = 0;
    if (waitpid(pid, &childStatus, 0) < 0) {
        fprintf(stderr, "find: waitpid: %s\n", strerror(errno));
        return 1;
    }
    if (!WIFEXITED(childStatus) || WEXITSTATUS(childStatus) != 0) {
        return 1;
    }
    return 0;
}

static int smallclueFindVisit(const char *path, const SmallclueFindOptions *opts,
                              int *status, int depth) {
    struct stat st;
    if (lstat(path, &st) != 0) {
        fprintf(stderr, "find: %s: %s\n", path, strerror(errno));
        if (status) *status = 1;
        return 1;
    }

    bool isDir = S_ISDIR(st.st_mode);
    bool descendFirst = isDir && (opts->maxDepth < 0 || depth < opts->maxDepth);
    /* -delete requires an empty directory, so recurse (and delete children)
     * before acting on this entry -- matches GNU find's depth-first order
     * for -delete. */
    if (descendFirst) {
        DIR *dir = opendir(path);
        if (!dir) {
            fprintf(stderr, "find: %s: %s\n", path, strerror(errno));
            if (status) *status = 1;
        } else {
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
                smallclueFindVisit(child, opts, status, depth + 1);
            }
            closedir(dir);
        }
    }

    if (depth >= opts->minDepth) {
        smallclueFindEval(opts->root, path, &st, status);
    }
    return 0;
}

static int smallclueFindCommand(int argc, char **argv) {
    const char *start = ".";
    SmallclueFindOptions opts;
    memset(&opts, 0, sizeof(opts));
    opts.maxDepth = -1;

    int index = 1;
    if (index < argc && argv[index] && argv[index][0] != '-') {
        start = argv[index++];
    }

    /* -maxdepth/-mindepth are global traversal options in real find, not
     * expression terms -- pull them out of argv wherever they appear
     * (compacting the array in place) before handing the rest to the
     * boolean-expression parser. */
    for (int i = index; i < argc; ) {
        if (strcmp(argv[i], "-maxdepth") == 0 || strcmp(argv[i], "-mindepth") == 0) {
            bool isMax = (argv[i][2] == 'a');
            if (i + 1 >= argc) {
                fprintf(stderr, "find: missing argument to %s\n", argv[i]);
                return 1;
            }
            int value = atoi(argv[i + 1]);
            if (isMax) opts.maxDepth = value; else opts.minDepth = value;
            for (int j = i; j + 2 < argc; ++j) argv[j] = argv[j + 2];
            argc -= 2;
            continue;
        }
        i++;
    }

    bool hadAction = false;
    int parseIdx = index;
    SmallclueFindNode *root = NULL;
    if (parseIdx < argc) {
        root = smallclueFindParseOr(argv, argc, &parseIdx, &hadAction);
        if (!root) {
            return 1;
        }
        if (parseIdx != argc) {
            fprintf(stderr, "find: unexpected token '%s'\n", argv[parseIdx]);
            return 1;
        }
    }
    if (!hadAction) {
        SmallclueFindNode *printNode = (SmallclueFindNode *)calloc(1, sizeof(*printNode));
        printNode->type = FIND_NODE_PRINT;
        if (root) {
            SmallclueFindNode *andNode = (SmallclueFindNode *)calloc(1, sizeof(*andNode));
            andNode->type = FIND_NODE_AND;
            andNode->left = root;
            andNode->right = printNode;
            root = andNode;
        } else {
            root = printNode;
        }
    }
    opts.root = root;

    int status = 0;
    smallclueFindVisit(start, &opts, &status, 0);
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
    if (isatty(STDERR_FILENO)) {
        fprintf(stderr, "%s: remove '\033[1;31m%s\033[0m'? [y/N] ", label, path);
    } else {
        fprintf(stderr, "%s: remove '%s'? [y/N] ", label, path);
    }
    fflush(stderr);
    int c = getchar();
    /* consume the rest of the line */
    int d;
    while ((d = getchar()) != '\n' && d != EOF) { }
    return c == 'y' || c == 'Y';
}

static int smallclueRemovePathWithLabel(const char *label, const char *path, bool recursive, bool force, bool interactive) {
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

    /* Interactive mode check: prompt for all files */
    if (interactive && !force) {
        if (!smallclueConfirmDelete(label, target)) {
            return 0;
        }
    }

    if (S_ISDIR(st.st_mode)) {
        if (!recursive) {
            fprintf(stderr, "%s: %s: is a directory\n", label, target);
            return -1;
        }
        /* When interactive, the "prompt for all files" check above already
         * confirmed this exact same path -- asking again here would prompt
         * the user twice for one directory. Only prompt here for the bare
         * `rm -r DIR` case (neither -i nor -f given), which is intended as
         * a lightweight safety net before recursing. */
        if (!interactive && !force && !smallclueConfirmDelete(label, target)) {
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
            if (smallclueRemovePathWithLabel(label, child_path, true, force, interactive) != 0) {
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
    /* No separate confirm here: the "prompt for all files" check at the
     * top of this function already asked about this exact path and
     * would have returned early if declined -- re-asking here was a
     * second, redundant prompt for the same plain-file removal. */
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

static void smallclueCopyPreserveTimes(const char *src, const char *dst, const struct stat *srcStat) {
    struct timeval times[2];
    times[0].tv_sec = srcStat->st_atime;
    times[0].tv_usec = 0;
    times[1].tv_sec = srcStat->st_mtime;
    times[1].tv_usec = 0;
    if (utimes(dst, times) != 0) {
        fprintf(stderr, "cp: %s: failed to preserve timestamps from %s: %s\n", dst, src, strerror(errno));
    }
}

/* Recursive copy for `cp -r`/`-a`/`-R`: files copy via smallclueCopyFile,
 * symlinks are recreated pointing at the same target (not followed and
 * copied as file content), directories are made then walked. preserveTimes
 * corresponds to -p/-a (mode is always preserved by smallclueCopyFile). */
static int smallclueCopyRecursive(const char *label, const char *src, const char *dst, bool preserveTimes) {
    struct stat srcStat;
    if (lstat(src, &srcStat) != 0) {
        fprintf(stderr, "%s: %s: %s\n", label, src, strerror(errno));
        return -1;
    }

    if (S_ISLNK(srcStat.st_mode)) {
        char linkTarget[PATH_MAX];
        ssize_t n = readlink(src, linkTarget, sizeof(linkTarget) - 1);
        if (n < 0) {
            fprintf(stderr, "%s: %s: %s\n", label, src, strerror(errno));
            return -1;
        }
        linkTarget[n] = '\0';
        unlink(dst);
        if (symlink(linkTarget, dst) != 0) {
            fprintf(stderr, "%s: %s: %s\n", label, dst, strerror(errno));
            return -1;
        }
        return 0;
    }

    if (S_ISDIR(srcStat.st_mode)) {
        if (mkdir(dst, srcStat.st_mode & 07777) != 0 && errno != EEXIST) {
            fprintf(stderr, "%s: %s: %s\n", label, dst, strerror(errno));
            return -1;
        }
        DIR *dir = opendir(src);
        if (!dir) {
            fprintf(stderr, "%s: %s: %s\n", label, src, strerror(errno));
            return -1;
        }
        struct dirent *entry;
        int status = 0;
        while ((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
                continue;
            }
            char childSrc[PATH_MAX];
            char childDst[PATH_MAX];
            if (smallclueBuildPath(childSrc, sizeof(childSrc), src, entry->d_name) != 0 ||
                smallclueBuildPath(childDst, sizeof(childDst), dst, entry->d_name) != 0) {
                fprintf(stderr, "%s: %s/%s: %s\n", label, src, entry->d_name, strerror(errno));
                status = -1;
                continue;
            }
            if (smallclueCopyRecursive(label, childSrc, childDst, preserveTimes) != 0) {
                status = -1;
            }
        }
        closedir(dir);
        if (preserveTimes) {
            smallclueCopyPreserveTimes(src, dst, &srcStat);
        }
        return status;
    }

    if (S_ISREG(srcStat.st_mode)) {
        int rc = smallclueCopyFile(label, src, dst);
        if (rc == 0 && preserveTimes) {
            smallclueCopyPreserveTimes(src, dst, &srcStat);
        }
        return rc;
    }

    fprintf(stderr, "%s: %s: unsupported file type, skipping\n", label, src);
    return 0;
}

static int smallclueMkdirParents(const char *path, mode_t mode, bool verbose) {
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
                if (mkdir(mutable_path, mode) == 0) {
                    if (verbose) {
                        printf("mkdir: created directory '%s'\n", mutable_path);
                    }
                } else if (errno != EEXIST) {
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
    } else if (verbose) {
        printf("mkdir: created directory '%s'\n", path);
    }
    free(mutable_path);
    return 0;
}

/* GNU rm's failsafe against `rm -rf /`-class disasters: recursive removal
 * of a path that resolves to exactly "/" is refused unless the caller
 * explicitly opts out via --no-preserve-root. On by default, matching GNU
 * coreutils (not an opt-in flag). */
static bool smallclueRmIsPreservedRoot(const char *path) {
    if (!path) return false;
    char resolved[PATH_MAX];
    const char *target = realpath(path, resolved) ? resolved : path;
    return strcmp(target, "/") == 0;
}

static int smallclueRmCommand(int argc, char **argv) {
    int recursive = 0;
    int force = 0;
    int interactive = 0;
    bool preserve_root = true;

    /* --preserve-root/--no-preserve-root are GNU long options with no
     * short-flag equivalent -- getopt() doesn't understand "--"-prefixed
     * long options and hard-errors on them, so strip them out first
     * (same convention used by stat's --format=). */
    for (int i = 1; i < argc; ) {
        if (strcmp(argv[i], "--preserve-root") == 0) {
            preserve_root = true;
            for (int j = i; j + 1 < argc; ++j) argv[j] = argv[j + 1];
            argc--;
            continue;
        }
        if (strcmp(argv[i], "--no-preserve-root") == 0) {
            preserve_root = false;
            for (int j = i; j + 1 < argc; ++j) argv[j] = argv[j + 1];
            argc--;
            continue;
        }
        i++;
    }

    int opt;
    smallclueResetGetopt();
    while ((opt = getopt(argc, argv, "rRfi")) != -1) {
        switch (opt) {
            case 'r':
            case 'R':
                recursive = 1;
                break;
            case 'f':
                force = 1;
                interactive = 0;
                break;
            case 'i':
                interactive = 1;
                force = 0;
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
        if (recursive && preserve_root && smallclueRmIsPreservedRoot(expanded)) {
            fprintf(stderr, "rm: it is dangerous to operate recursively on '%s'\n", expanded);
            fprintf(stderr, "rm: use --no-preserve-root to override this failsafe\n");
            status = 1;
            continue;
        }
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
                if (recursive && preserve_root && smallclueRmIsPreservedRoot(matches.gl_pathv[m])) {
                    fprintf(stderr, "rm: it is dangerous to operate recursively on '%s'\n", matches.gl_pathv[m]);
                    fprintf(stderr, "rm: use --no-preserve-root to override this failsafe\n");
                    status = 1;
                    continue;
                }
                if (smallclueRemovePathWithLabel("rm", matches.gl_pathv[m], recursive != 0, force != 0, interactive != 0) != 0) {
                    if (!force) {
                        status = 1;
                    }
                }
            }
            globfree(&matches);
        } else {
            if (smallclueRemovePathWithLabel("rm", expanded, recursive != 0, force != 0, interactive != 0) != 0) {
                if (!force) {
                    status = 1;
                }
            }
        }
    }
    return status;
}

static int smallclueRmdirPath(const char *path, bool parents, bool verbose) {
    if (rmdir(path) != 0) {
        fprintf(stderr, "rmdir: %s: %s\n", path, strerror(errno));
        return -1;
    }
    if (verbose) {
        printf("rmdir: removing directory, '%s'\n", path);
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
        if (verbose) {
            printf("rmdir: removing directory, '%s'\n", mutable_path);
        }
    }
    free(mutable_path);
    return 0;
}

static int smallclueRmdirCommand(int argc, char **argv) {
    int parents = 0;
    int verbose = 0;
    int opt;
    smallclueResetGetopt();
    while ((opt = getopt(argc, argv, "pv")) != -1) {
        switch (opt) {
            case 'p':
                parents = 1;
                break;
            case 'v':
                verbose = 1;
                break;
            default:
                fprintf(stderr, "usage: rmdir [-p] [-v] dir...\n");
                return 1;
        }
    }
    if (optind >= argc) {
        fprintf(stderr, "rmdir: missing operand\n");
        return 1;
    }
    int status = 0;
    for (int i = optind; i < argc; ++i) {
        if (smallclueRmdirPath(argv[i], parents != 0, verbose != 0) != 0) {
            status = 1;
        }
    }
    return status;
}

static int smallclueMkdirCommand(int argc, char **argv) {
    int parents = 0;
    int verbose = 0;
    int opt;
    smallclueResetGetopt();
    while ((opt = getopt(argc, argv, "pv")) != -1) {
        switch (opt) {
            case 'p':
                parents = 1;
                break;
            case 'v':
                verbose = 1;
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
            if (smallclueMkdirParents(target, 0777, verbose) != 0) {
                fprintf(stderr, "mkdir: %s: %s\n", target, strerror(errno));
                status = 1;
            }
        } else {
            if (mkdir(target, 0777) != 0) {
                fprintf(stderr, "mkdir: %s: %s\n", target, strerror(errno));
                status = 1;
            } else if (verbose) {
                printf("mkdir: created directory '%s'\n", target);
            }
        }
    }
    return status;
}

static int smallclueMknodCommand(int argc, char **argv) {
    mode_t mode = 0666;
    smallclueResetGetopt();
    int opt;
    while ((opt = getopt(argc, argv, "m:")) != -1) {
        switch (opt) {
            case 'm':
                {
                    char *endptr = NULL;
                    long val = strtol(optarg, &endptr, 8);
                    if (endptr && *endptr == '\0' && val >= 0 && val <= 07777) {
                        mode = (mode_t)val;
                    } else {
                        fprintf(stderr, "mknod: invalid mode '%s'\n", optarg);
                        return 1;
                    }
                }
                break;
            default:
                fprintf(stderr, "usage: mknod [-m mode] NAME TYPE [MAJOR MINOR]\n");
                return 1;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "mknod: missing operand\n");
        return 1;
    }

    const char *name = argv[optind];
    if (optind + 1 >= argc) {
        fprintf(stderr, "mknod: missing type operand\n");
        return 1;
    }
    const char *type_str = argv[optind + 1];
    char type = type_str[0];

    dev_t dev = 0;

    if (type == 'b' || type == 'c' || type == 'u') {
        if (optind + 3 >= argc) {
            fprintf(stderr, "mknod: missing major/minor operands\n");
            return 1;
        }
        int major = atoi(argv[optind + 2]);
        int minor = atoi(argv[optind + 3]);
        dev = makedev(major, minor);
    }

    if (type == 'b') {
        mode |= S_IFBLK;
    } else if (type == 'c' || type == 'u') {
        mode |= S_IFCHR;
    } else if (type == 'p') {
        mode |= S_IFIFO;
    } else {
        fprintf(stderr, "mknod: invalid type '%c'\n", type);
        return 1;
    }

    if (mknod(name, mode, dev) != 0) {
        perror("mknod");
        return 1;
    }

    return 0;
}

#if defined(PSCAL_TARGET_IOS)
static bool smallclueFstabEncodeField(const char *input, char *out, size_t out_size) {
    if (!input || !out || out_size == 0) {
        errno = EINVAL;
        return false;
    }
    size_t out_len = 0;
    for (size_t i = 0; input[i] != '\0'; ++i) {
        unsigned char ch = (unsigned char)input[i];
        if (ch == '\\' || isspace(ch) || ch == '#') {
            if (out_len + 4 >= out_size) {
                errno = ENAMETOOLONG;
                return false;
            }
            out[out_len++] = '\\';
            out[out_len++] = (char)('0' + ((ch >> 6) & 0x07));
            out[out_len++] = (char)('0' + ((ch >> 3) & 0x07));
            out[out_len++] = (char)('0' + (ch & 0x07));
            continue;
        }
        if (out_len + 1 >= out_size) {
            errno = ENAMETOOLONG;
            return false;
        }
        out[out_len++] = (char)ch;
    }
    out[out_len] = '\0';
    return true;
}

static bool smallclueFstabBufferAppend(char **buffer,
                                       size_t *length,
                                       size_t *capacity,
                                       const char *data,
                                       size_t data_len) {
    if (!buffer || !length || !capacity) {
        errno = EINVAL;
        return false;
    }
    if (data_len == 0) {
        return true;
    }
    if (!data) {
        errno = EINVAL;
        return false;
    }
    if (*length > SIZE_MAX - data_len) {
        errno = EOVERFLOW;
        return false;
    }
    size_t needed = *length + data_len + 1;
    if (needed > *capacity) {
        size_t new_capacity = (*capacity > 0) ? *capacity : 1024;
        while (new_capacity < needed) {
            if (new_capacity > SIZE_MAX / 2) {
                new_capacity = needed;
                break;
            }
            new_capacity *= 2;
        }
        char *resized = (char *)realloc(*buffer, new_capacity);
        if (!resized) {
            errno = ENOMEM;
            return false;
        }
        *buffer = resized;
        *capacity = new_capacity;
    }
    memcpy(*buffer + *length, data, data_len);
    *length += data_len;
    (*buffer)[*length] = '\0';
    return true;
}

static bool smallclueFstabReadWholeFile(int fd, char **out_data, size_t *out_len) {
    if (fd < 0 || !out_data || !out_len) {
        errno = EINVAL;
        return false;
    }
    if (vprocHostLseek(fd, 0, SEEK_SET) < 0) {
        return false;
    }

    char *buffer = NULL;
    size_t length = 0;
    size_t capacity = 0;
    char chunk[2048];
    while (true) {
        ssize_t read_bytes = vprocHostRead(fd, chunk, sizeof(chunk));
        if (read_bytes < 0) {
            int saved_errno = errno;
            free(buffer);
            errno = saved_errno;
            return false;
        }
        if (read_bytes == 0) {
            break;
        }
        if (!smallclueFstabBufferAppend(&buffer,
                                        &length,
                                        &capacity,
                                        chunk,
                                        (size_t)read_bytes)) {
            int saved_errno = errno;
            free(buffer);
            errno = saved_errno;
            return false;
        }
    }

    if (!buffer) {
        buffer = (char *)calloc(1, 1);
        if (!buffer) {
            errno = ENOMEM;
            return false;
        }
    }
    buffer[length] = '\0';
    *out_data = buffer;
    *out_len = length;
    return true;
}

static bool smallclueFstabRewriteWholeFile(int fd, const char *data, size_t data_len) {
    if (fd < 0 || (!data && data_len > 0)) {
        errno = EINVAL;
        return false;
    }
    if (vprocHostLseek(fd, 0, SEEK_SET) < 0) {
        return false;
    }
    if (ftruncate(fd, 0) != 0) {
        return false;
    }
    if (vprocHostLseek(fd, 0, SEEK_SET) < 0) {
        return false;
    }
    size_t written = 0;
    while (written < data_len) {
        ssize_t rc = vprocHostWrite(fd, data + written, data_len - written);
        if (rc <= 0) {
            if (rc == 0) {
                errno = EIO;
            }
            return false;
        }
        written += (size_t)rc;
    }
    (void)vprocHostFsync(fd);
    return true;
}

static bool smallclueFstabLineEquals(const char *line, size_t line_len, const char *value) {
    if (!line || !value) {
        return false;
    }
    while (line_len > 0 && (line[line_len - 1] == '\n' || line[line_len - 1] == '\r')) {
        line_len--;
    }
    size_t value_len = strlen(value);
    return line_len == value_len && memcmp(line, value, value_len) == 0;
}

static bool smallclueFstabLineMatchesTarget(const char *line,
                                            size_t line_len,
                                            const char *target_encoded) {
    if (!line || !target_encoded) {
        return false;
    }
    while (line_len > 0 && (line[line_len - 1] == '\n' || line[line_len - 1] == '\r')) {
        line_len--;
    }
    char *scratch = (char *)malloc(line_len + 1);
    if (!scratch) {
        return false;
    }
    memcpy(scratch, line, line_len);
    scratch[line_len] = '\0';

    char *cursor = scratch;
    while (*cursor && isspace((unsigned char)*cursor)) {
        cursor++;
    }
    if (*cursor == '\0' || *cursor == '#') {
        free(scratch);
        return false;
    }

    char *saveptr = NULL;
    char *source_field = strtok_r(cursor, " \t", &saveptr);
    char *target_field = strtok_r(NULL, " \t", &saveptr);
    (void)source_field;
    bool match = (target_field && strcmp(target_field, target_encoded) == 0);
    free(scratch);
    return match;
}

static bool smallclueMountPersistFstabEntry(const char *source,
                                            const char *target,
                                            const char *type,
                                            const char *options) {
    if (!source || source[0] != '/' ||
        !target || target[0] != '/' ||
        !type || type[0] == '\0' ||
        !options || options[0] == '\0') {
        errno = EINVAL;
        return false;
    }

    char source_encoded[PATH_MAX * 4];
    char target_encoded[PATH_MAX * 4];
    char type_encoded[sizeof(((PathTruncateMountEntry *)0)->type) * 4];
    char options_encoded[sizeof(((PathTruncateMountEntry *)0)->options) * 4];
    if (!smallclueFstabEncodeField(source, source_encoded, sizeof(source_encoded)) ||
        !smallclueFstabEncodeField(target, target_encoded, sizeof(target_encoded)) ||
        !smallclueFstabEncodeField(type, type_encoded, sizeof(type_encoded)) ||
        !smallclueFstabEncodeField(options, options_encoded, sizeof(options_encoded))) {
        return false;
    }

    char entry_line[(PATH_MAX * 8) + 128];
    int written = snprintf(entry_line,
                           sizeof(entry_line),
                           "%s %s %s %s 0 0",
                           source_encoded,
                           target_encoded,
                           type_encoded,
                           options_encoded);
    if (written < 0 || (size_t)written >= sizeof(entry_line)) {
        errno = ENAMETOOLONG;
        return false;
    }

    int fd = vprocHostOpen("/etc/fstab", O_RDWR | O_CREAT, 0666);
    if (fd < 0) {
        return false;
    }

    char *existing = NULL;
    size_t existing_len = 0;
    if (!smallclueFstabReadWholeFile(fd, &existing, &existing_len)) {
        int saved_errno = errno;
        vprocHostClose(fd);
        errno = saved_errno;
        return false;
    }

    bool exists = false;
    const char *cursor = existing;
    const char *end = existing + existing_len;
    while (cursor < end) {
        const char *newline = memchr(cursor, '\n', (size_t)(end - cursor));
        size_t raw_len = newline ? (size_t)(newline - cursor + 1) : (size_t)(end - cursor);
        size_t line_len = newline ? raw_len - 1 : raw_len;
        if (smallclueFstabLineEquals(cursor, line_len, entry_line)) {
            exists = true;
            break;
        }
        cursor += raw_len;
    }

    if (!exists) {
        char *updated = NULL;
        size_t updated_len = 0;
        size_t updated_capacity = 0;
        if (!smallclueFstabBufferAppend(&updated,
                                        &updated_len,
                                        &updated_capacity,
                                        existing,
                                        existing_len)) {
            int saved_errno = errno;
            free(existing);
            vprocHostClose(fd);
            errno = saved_errno;
            return false;
        }
        if (updated_len > 0 && updated[updated_len - 1] != '\n') {
            if (!smallclueFstabBufferAppend(&updated,
                                            &updated_len,
                                            &updated_capacity,
                                            "\n",
                                            1)) {
                int saved_errno = errno;
                free(updated);
                free(existing);
                vprocHostClose(fd);
                errno = saved_errno;
                return false;
            }
        }
        if (!smallclueFstabBufferAppend(&updated,
                                        &updated_len,
                                        &updated_capacity,
                                        entry_line,
                                        strlen(entry_line)) ||
            !smallclueFstabBufferAppend(&updated,
                                        &updated_len,
                                        &updated_capacity,
                                        "\n",
                                        1)) {
            int saved_errno = errno;
            free(updated);
            free(existing);
            vprocHostClose(fd);
            errno = saved_errno;
            return false;
        }
        if (!smallclueFstabRewriteWholeFile(fd, updated, updated_len)) {
            int saved_errno = errno;
            free(updated);
            free(existing);
            vprocHostClose(fd);
            errno = saved_errno;
            return false;
        }
        free(updated);
    }

    free(existing);
    vprocHostClose(fd);
    return true;
}

static bool smallclueMountRemoveFstabEntry(const char *target) {
    if (!target || target[0] != '/') {
        errno = EINVAL;
        return false;
    }

    char target_encoded[PATH_MAX * 4];
    if (!smallclueFstabEncodeField(target, target_encoded, sizeof(target_encoded))) {
        return false;
    }

    int fd = vprocHostOpen("/etc/fstab", O_RDWR | O_CREAT, 0666);
    if (fd < 0) {
        return false;
    }

    char *existing = NULL;
    size_t existing_len = 0;
    if (!smallclueFstabReadWholeFile(fd, &existing, &existing_len)) {
        int saved_errno = errno;
        vprocHostClose(fd);
        errno = saved_errno;
        return false;
    }

    bool removed = false;
    char *updated = NULL;
    size_t updated_len = 0;
    size_t updated_capacity = 0;
    const char *cursor = existing;
    const char *end = existing + existing_len;
    while (cursor < end) {
        const char *newline = memchr(cursor, '\n', (size_t)(end - cursor));
        size_t raw_len = newline ? (size_t)(newline - cursor + 1) : (size_t)(end - cursor);
        size_t line_len = newline ? raw_len - 1 : raw_len;
        if (!smallclueFstabLineMatchesTarget(cursor, line_len, target_encoded)) {
            if (!smallclueFstabBufferAppend(&updated,
                                            &updated_len,
                                            &updated_capacity,
                                            cursor,
                                            raw_len)) {
                int saved_errno = errno;
                free(updated);
                free(existing);
                vprocHostClose(fd);
                errno = saved_errno;
                return false;
            }
        } else {
            removed = true;
        }
        cursor += raw_len;
    }

    if (!removed) {
        free(updated);
        free(existing);
        vprocHostClose(fd);
        errno = ENOENT;
        return false;
    }

    if (!smallclueFstabRewriteWholeFile(fd, updated ? updated : "", updated_len)) {
        int saved_errno = errno;
        free(updated);
        free(existing);
        vprocHostClose(fd);
        errno = saved_errno;
        return false;
    }

    free(updated);
    free(existing);
    vprocHostClose(fd);
    return true;
}
#endif

static int smallclueMountCommand(int argc, char **argv) {
#if defined(__linux__) || defined(linux) || defined(__linux)
    const char *usage = "usage: mount [-t type] [-o options] device dir\n";
    const char *type = NULL;
    char *options = NULL;
    unsigned long flags = 0;

    smallclueResetGetopt();
    int opt;
    while ((opt = getopt(argc, argv, "t:o:")) != -1) {
        switch (opt) {
            case 't':
                type = optarg;
                break;
            case 'o':
                if (options) {
                    size_t old_len = strlen(options);
                    size_t new_len = old_len + 1 + strlen(optarg) + 1;
                    char *new_opts = (char *)realloc(options, new_len);
                    if (new_opts) {
                        options = new_opts;
                        strcat(options, ",");
                        strcat(options, optarg);
                    }
                } else {
                    options = strdup(optarg);
                }
                break;
            default:
                if (options) free(options);
                fputs(usage, stderr);
                return 1;
        }
    }

    if (optind >= argc) {
        if (options) free(options);
        FILE *fp = fopen("/proc/mounts", "r");
        if (!fp) fp = fopen("/etc/mtab", "r");
        if (!fp) {
             perror("mount: cannot read mounts");
             return 1;
        }
        char buf[1024];
        while (fgets(buf, sizeof(buf), fp)) {
            fputs(buf, stdout);
        }
        fclose(fp);
        return 0;
    }

    if (optind + 1 >= argc) {
        if (options) free(options);
        fputs(usage, stderr);
        return 1;
    }

    const char *source = argv[optind];
    const char *target = argv[optind + 1];

    char *data = NULL;
    if (options) {
        char *opts = strdup(options);
        char *token = strtok(opts, ",");
        while (token) {
            bool is_flag = true;
            if (strcmp(token, "ro") == 0) flags |= MS_RDONLY;
            else if (strcmp(token, "rw") == 0) flags &= ~MS_RDONLY;
            else if (strcmp(token, "nosuid") == 0) flags |= MS_NOSUID;
            else if (strcmp(token, "suid") == 0) flags &= ~MS_NOSUID;
            else if (strcmp(token, "nodev") == 0) flags |= MS_NODEV;
            else if (strcmp(token, "dev") == 0) flags &= ~MS_NODEV;
            else if (strcmp(token, "noexec") == 0) flags |= MS_NOEXEC;
            else if (strcmp(token, "exec") == 0) flags &= ~MS_NOEXEC;
#ifdef MS_REMOUNT
            else if (strcmp(token, "remount") == 0) flags |= MS_REMOUNT;
#endif
#ifdef MS_BIND
            else if (strcmp(token, "bind") == 0) flags |= MS_BIND;
#endif
            else is_flag = false;

            if (!is_flag) {
                 if (!data) {
                     data = strdup(token);
                 } else {
                     size_t old_len = strlen(data);
                     size_t new_len = old_len + 1 + strlen(token) + 1;
                     char *new_data = (char *)realloc(data, new_len);
                     if (new_data) {
                         data = new_data;
                         strcat(data, ",");
                         strcat(data, token);
                     }
                 }
            }
            token = strtok(NULL, ",");
        }
        free(opts);
        free(options);
    }

    int rc = mount(source, target, type ? type : "auto", flags, data);
    if (data) free(data);

    if (rc != 0) {
        perror("mount");
        return 1;
    }
    return 0;
#elif defined(PSCAL_TARGET_IOS)
    const char *usage = "usage: mount [-p] [-t type] [-o options] [source] dir\n";
    const char *type = NULL;
    char *options = NULL;
    char *picked_source = NULL;
    bool persist_to_fstab = false;
    unsigned long flags = 0;
    enum {
        SMALLCLUE_MOUNT_RDONLY = 1ul << 0,
        SMALLCLUE_MOUNT_NOSUID = 1ul << 1,
        SMALLCLUE_MOUNT_NODEV = 1ul << 2,
        SMALLCLUE_MOUNT_NOEXEC = 1ul << 3,
        SMALLCLUE_MOUNT_REMOUNT = 1ul << 4,
        SMALLCLUE_MOUNT_BIND = 1ul << 5
    };

    smallclueResetGetopt();
    int opt;
    while ((opt = getopt(argc, argv, "pt:o:")) != -1) {
        switch (opt) {
            case 'p':
                persist_to_fstab = true;
                break;
            case 't':
                type = optarg;
                break;
            case 'o':
                if (options) {
                    size_t old_len = strlen(options);
                    size_t new_len = old_len + 1 + strlen(optarg) + 1;
                    char *new_opts = (char *)realloc(options, new_len);
                    if (new_opts) {
                        options = new_opts;
                        strcat(options, ",");
                        strcat(options, optarg);
                    }
                } else {
                    options = strdup(optarg);
                }
                break;
            default:
                free(options);
                fputs(usage, stderr);
                return 1;
        }
    }

    if (options) {
        char *opts = strdup(options);
        if (opts) {
            char *token = strtok(opts, ",");
            while (token) {
                if (strcmp(token, "ro") == 0) flags |= SMALLCLUE_MOUNT_RDONLY;
                else if (strcmp(token, "rw") == 0) flags &= ~SMALLCLUE_MOUNT_RDONLY;
                else if (strcmp(token, "nosuid") == 0) flags |= SMALLCLUE_MOUNT_NOSUID;
                else if (strcmp(token, "suid") == 0) flags &= ~SMALLCLUE_MOUNT_NOSUID;
                else if (strcmp(token, "nodev") == 0) flags |= SMALLCLUE_MOUNT_NODEV;
                else if (strcmp(token, "dev") == 0) flags &= ~SMALLCLUE_MOUNT_NODEV;
                else if (strcmp(token, "noexec") == 0) flags |= SMALLCLUE_MOUNT_NOEXEC;
                else if (strcmp(token, "exec") == 0) flags &= ~SMALLCLUE_MOUNT_NOEXEC;
                else if (strcmp(token, "remount") == 0) flags |= SMALLCLUE_MOUNT_REMOUNT;
                else if (strcmp(token, "bind") == 0) flags |= SMALLCLUE_MOUNT_BIND;
                token = strtok(NULL, ",");
            }
            free(opts);
        }
    }

    if (optind >= argc) {
        const char *root_source = "rootfs";
        const char *root_type = "ext4";
        struct statfs sfs;
        if (statfs("/", &sfs) == 0) {
            if (sfs.f_mntfromname[0]) {
                root_source = sfs.f_mntfromname;
            }
            if (sfs.f_fstypename[0]) {
                root_type = sfs.f_fstypename;
            }
        }
        printf("%s / %s rw 0 0\n", root_source, root_type);

        size_t mount_count = pathTruncateMountSnapshot(NULL, 0);
        PathTruncateMountEntry *entries = NULL;
        if (mount_count > 0) {
            entries = (PathTruncateMountEntry *)calloc(mount_count, sizeof(PathTruncateMountEntry));
            if (!entries) {
                free(options);
                fprintf(stderr, "mount: out of memory\n");
                return 1;
            }
            mount_count = pathTruncateMountSnapshot(entries, mount_count);
            for (size_t i = 0; i < mount_count; ++i) {
                const char *entry_type = entries[i].type[0] ? entries[i].type : "auto";
                const char *entry_opts = entries[i].options[0] ? entries[i].options : "rw";
                printf("%s %s %s %s 0 0\n",
                       entries[i].source,
                       entries[i].target,
                       entry_type,
                       entry_opts);
            }
        }
        free(entries);
        free(options);
        return 0;
    }

    if (optind + 2 < argc) {
        free(options);
        free(picked_source);
        fputs(usage, stderr);
        return 1;
    }

    const char *source = NULL;
    const char *target = NULL;
    if (optind + 1 < argc) {
        source = argv[optind];
        target = argv[optind + 1];
    } else {
        target = argv[optind];
        if (!pscalRuntimePickMountSourceDirectory) {
            free(options);
            fputs("mount: interactive picker unavailable on this runtime\n", stderr);
            return 1;
        }
        picked_source = pscalRuntimePickMountSourceDirectory();
        if (!picked_source || picked_source[0] == '\0') {
            int pick_errno = errno ? errno : ECANCELED;
            free(options);
            free(picked_source);
            fprintf(stderr, "mount: source picker: %s\n", strerror(pick_errno));
            return 1;
        }
        source = picked_source;
    }

    char source_real[PATH_MAX];
    bool source_resolved_ok = false;
    char source_resolved[PATH_MAX];
    const char *source_path = smallclueResolvePath(source, source_resolved, sizeof(source_resolved));
    if (source_path && source_path[0] != '\0' &&
        smallclueHostRealpathPath(source_path, source_real, sizeof(source_real))) {
        source_resolved_ok = true;
    } else if (source[0] == '/' &&
               smallclueHostRealpathPath(source, source_real, sizeof(source_real))) {
        source_resolved_ok = true;
    }
    if (!source_resolved_ok) {
        fprintf(stderr, "mount: %s: %s\n", source, strerror(errno));
        free(options);
        free(picked_source);
        return 1;
    }
    struct stat source_st;
    if (smallclueHostStatPath(source_real, &source_st) != 0) {
        fprintf(stderr, "mount: %s: %s\n", source, strerror(errno));
        free(options);
        free(picked_source);
        return 1;
    }
    if (!S_ISDIR(source_st.st_mode)) {
        fprintf(stderr, "mount: %s: not a directory\n", source);
        free(options);
        free(picked_source);
        return 1;
    }

    char target_virtual[PATH_MAX];
    if (!realpath(target, target_virtual)) {
        fprintf(stderr, "mount: %s: %s\n", target, strerror(errno));
        free(options);
        free(picked_source);
        return 1;
    }

    char target_host[PATH_MAX];
    if (!pathTruncateExpand(target_virtual, target_host, sizeof(target_host))) {
        fprintf(stderr, "mount: %s: %s\n", target, strerror(errno));
        free(options);
        free(picked_source);
        return 1;
    }

    char target_real[PATH_MAX];
    if (!smallclueHostRealpathPath(target_host, target_real, sizeof(target_real))) {
        fprintf(stderr, "mount: %s: %s\n", target, strerror(errno));
        free(options);
        free(picked_source);
        return 1;
    }
    struct stat target_st;
    if (smallclueHostStatPath(target_real, &target_st) != 0) {
        fprintf(stderr, "mount: %s: %s\n", target, strerror(errno));
        free(options);
        free(picked_source);
        return 1;
    }
    if (!S_ISDIR(target_st.st_mode)) {
        fprintf(stderr, "mount: %s: not a directory\n", target);
        free(options);
        free(picked_source);
        return 1;
    }

    if (!pathTruncateMountAdd(source_real,
                              target_virtual,
                              type ? type : "bind",
                              options,
                              flags)) {
        perror("mount");
        free(options);
        free(picked_source);
        return 1;
    }

    if (persist_to_fstab) {
        const char *entry_type = (type && type[0] != '\0') ? type : "bind";
        const char *entry_options = (options && options[0] != '\0') ? options : "rw";
        if (!smallclueMountPersistFstabEntry(source_real, target_virtual, entry_type, entry_options)) {
            int saved_errno = errno;
            fprintf(stderr,
                    "mount: mounted but failed to persist in /etc/fstab: %s\n",
                    strerror(saved_errno ? saved_errno : EIO));
            free(options);
            free(picked_source);
            return 1;
        }
    }

    free(options);
    free(picked_source);
    return 0;
#else
    (void)argc;
    (void)argv;
    fprintf(stderr, "mount: not supported on this platform\n");
    return 1;
#endif
}

static int smallclueUmountCommand(int argc, char **argv) {
#if defined(__linux__) || defined(linux) || defined(__linux)
    const char *usage = "usage: umount [-l] [-f] dir\n";
    bool lazy = false;
    bool force = false;
    smallclueResetGetopt();
    int opt;
    while ((opt = getopt(argc, argv, "lf")) != -1) {
        switch (opt) {
            case 'l':
                lazy = true;
                break;
            case 'f':
                force = true;
                break;
            default:
                fputs(usage, stderr);
                return 1;
        }
    }
    if (optind + 1 != argc) {
        fputs(usage, stderr);
        return 1;
    }
    const char *target = argv[optind];
    int flags = 0;
    if (lazy) flags |= MNT_DETACH;
    if (force) flags |= MNT_FORCE;
    int rc = flags ? umount2(target, flags) : umount(target);
    if (rc != 0) {
        perror("umount");
        return 1;
    }
    return 0;
#elif defined(PSCAL_TARGET_IOS)
    const char *usage = "usage: umount [-p] dir\n";
    bool persist_to_fstab = false;

    smallclueResetGetopt();
    int opt;
    while ((opt = getopt(argc, argv, "p")) != -1) {
        switch (opt) {
            case 'p':
                persist_to_fstab = true;
                break;
            default:
                fputs(usage, stderr);
                return 1;
        }
    }
    if (optind + 1 != argc) {
        fputs(usage, stderr);
        return 1;
    }

    const char *target = argv[optind];
    char target_virtual[PATH_MAX];
    bool have_target_virtual = false;
    if (realpath(target, target_virtual)) {
        have_target_virtual = true;
    } else {
        if (target[0] == '/') {
            int n = snprintf(target_virtual, sizeof(target_virtual), "%s", target);
            if (n > 0 && (size_t)n < sizeof(target_virtual)) {
                have_target_virtual = true;
            }
        } else {
            char cwd[PATH_MAX];
            if (getcwd(cwd, sizeof(cwd))) {
                int n = snprintf(target_virtual, sizeof(target_virtual), "%s/%s", cwd, target);
                if (n > 0 && (size_t)n < sizeof(target_virtual)) {
                    have_target_virtual = true;
                }
            }
        }
    }
    if (!have_target_virtual) {
        fprintf(stderr, "umount: %s: %s\n", target, strerror(errno));
        return 1;
    }

    if (!pathTruncateMountRemove(target_virtual)) {
        int saved_errno = errno;
        fprintf(stderr,
                "umount: %s: %s\n",
                target,
                strerror(saved_errno ? saved_errno : EINVAL));
        return 1;
    }

    if (persist_to_fstab) {
        if (!smallclueMountRemoveFstabEntry(target_virtual)) {
            int saved_errno = errno;
            fprintf(stderr,
                    "umount: unmounted but failed to update /etc/fstab: %s\n",
                    strerror(saved_errno ? saved_errno : EIO));
            return 1;
        }
    }
    return 0;
#else
    (void)argc;
    (void)argv;
    fprintf(stderr, "umount: not supported on this platform\n");
    return 1;
#endif
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

/* GNU-stat-style custom format string (-c/--format), e.g. '%s' / '%Y' /
 * '%n (%a)'. Directives: n=name s=size(bytes) b=blocks(512B units)
 * B=block size(bytes) f=raw mode(hex) F=type description a=perms(octal)
 * A=perms(rwx string) u/g=uid/gid U/G=user/group name i=inode h=hardlink
 * count d=device X/Y/Z=atime/mtime/ctime(epoch seconds). %% is a literal
 * '%'; \n and \t are recognized as escapes in the format string itself
 * (matching GNU stat, which supports both since the format is usually
 * passed already-interpreted by the shell, but a smallclue script/rc
 * invocation may pass it raw). */
static void smallclueStatPrintFormatted(const char *path, const struct stat *st, const char *format) {
    for (const char *p = format; *p; ++p) {
        if (*p == '\\' && p[1] == 'n') {
            putchar('\n');
            p++;
        } else if (*p == '\\' && p[1] == 't') {
            putchar('\t');
            p++;
        } else if (*p == '%' && p[1]) {
            char directive = *++p;
            switch (directive) {
                case '%': putchar('%'); break;
                case 'n': fputs(path, stdout); break;
                case 's': printf("%lld", (long long)st->st_size); break;
                case 'b': printf("%lld", (long long)st->st_blocks); break;
                case 'B': printf("%ld", (long)st->st_blksize); break;
                case 'f': printf("%x", (unsigned)st->st_mode); break;
                case 'F': fputs(smallclueStatTypeLabel(st), stdout); break;
                case 'a': printf("%03o", (unsigned)(st->st_mode & 07777)); break;
                case 'A': {
                    char perms[11];
                    smallclueStatFormatPerms(perms, sizeof(perms), st->st_mode);
                    fputs(perms, stdout);
                    break;
                }
                case 'u': printf("%u", (unsigned)st->st_uid); break;
                case 'g': printf("%u", (unsigned)st->st_gid); break;
                case 'U': {
                    struct passwd *pw = getpwuid(st->st_uid);
                    fputs(pw ? pw->pw_name : "?", stdout);
                    break;
                }
                case 'G': {
                    struct group *gr = getgrgid(st->st_gid);
                    fputs(gr ? gr->gr_name : "?", stdout);
                    break;
                }
                case 'i': printf("%llu", (unsigned long long)st->st_ino); break;
                case 'h': printf("%llu", (unsigned long long)st->st_nlink); break;
                case 'd': printf("%llu", (unsigned long long)st->st_dev); break;
                case 'X': printf("%lld", (long long)st->st_atime); break;
                case 'Y': printf("%lld", (long long)st->st_mtime); break;
                case 'Z': printf("%lld", (long long)st->st_ctime); break;
                default:
                    putchar('%');
                    putchar(directive);
                    break;
            }
        } else {
            putchar(*p);
        }
    }
    putchar('\n');
}

static int smallclueStatCommand(int argc, char **argv) {
    int follow = 0;
    const char *format = NULL;

    /* Strip out the GNU long form --format=FORMAT before getopt() ever
     * sees it -- getopt() doesn't understand "--"-prefixed long options
     * with an "=" value and hard-errors on it ("illegal option"), so this
     * has to happen first, not as a post-getopt scan. */
    for (int i = 1; i < argc; ) {
        if (strncmp(argv[i], "--format=", 9) == 0) {
            format = argv[i] + 9;
            for (int j = i; j + 1 < argc; ++j) {
                argv[j] = argv[j + 1];
            }
            argc--;
            continue;
        }
        i++;
    }

    smallclueResetGetopt();
    int opt;
    while ((opt = getopt(argc, argv, "Lc:")) != -1) {
        switch (opt) {
            case 'L':
                follow = 1;
                break;
            case 'c':
                format = optarg;
                break;
            default:
                fprintf(stderr, "stat: usage: stat [-L] [-c FORMAT] FILE...\n");
                return 1;
        }
    }
    if (optind >= argc) {
        fprintf(stderr, "stat: missing operand\n");
        return 1;
    }
    int status = 0;
    for (int i = optind; i < argc; ++i) {
        char resolved[PATH_MAX];
        const char *target = smallclueResolvePath(argv[i], resolved, sizeof(resolved));
        if (!target || *target == '\0') {
            target = argv[i];
        }
        if (format) {
            struct stat st;
            if ((follow ? stat(target, &st) : lstat(target, &st)) != 0) {
                fprintf(stderr, "stat: %s: %s\n", argv[i], strerror(errno));
                status = 1;
                continue;
            }
            smallclueStatPrintFormatted(argv[i], &st, format);
            continue;
        }
        if (smallclueStatPath(argv[i], follow) != 0) {
            status = 1;
        } else if (i + 1 < argc) {
            putchar('\n');
        }
    }
    return status;
}

static int smallclueLnCreateOne(const char *target, const char *linkname, bool symbolic, bool force) {
    if (force) {
        unlink(linkname);
    }
    if (symbolic) {
        if (symlink(target, linkname) != 0) {
            fprintf(stderr, "ln: cannot create symbolic link '%s': %s\n", linkname, strerror(errno));
            return 1;
        }
    } else {
        if (link(target, linkname) != 0) {
            fprintf(stderr, "ln: cannot create link '%s': %s\n", linkname, strerror(errno));
            return 1;
        }
    }
    return 0;
}

static int smallclueLnCommand(int argc, char **argv) {
    int symbolic = 0;
    int force = 0;
    int opt;
    smallclueResetGetopt();
    while ((opt = getopt(argc, argv, "sf")) != -1) {
        switch (opt) {
            case 's':
                symbolic = 1;
                break;
            case 'f':
                force = 1;
                break;
            default:
                fprintf(stderr, "ln: invalid option -- %c\n", optopt);
                return 1;
        }
    }
    int nOperands = argc - optind;
    if (nOperands < 2) {
        fprintf(stderr, "ln: missing file operand\n");
        return 1;
    }

    const char *lastArg = argv[argc - 1];
    struct stat destStat;
    bool destIsDir = (nOperands > 2) || (stat(lastArg, &destStat) == 0 && S_ISDIR(destStat.st_mode));

    if (!destIsDir) {
        /* Classic two-operand form: `ln [-s] TARGET LINKNAME`. */
        return smallclueLnCreateOne(argv[optind], argv[optind + 1], symbolic, force);
    }

    /* `ln [-s] TARGET... DIRECTORY` -- matches GNU ln's auto-append of each
     * target's basename inside the destination directory instead of
     * requiring the caller to spell out the link path (e.g.
     * `ln -s /usr/bin/foo /usr/local/bin/` now creates
     * /usr/local/bin/foo, rather than failing with EEXIST against the
     * directory itself). */
    int status = 0;
    for (int i = optind; i < argc - 1; ++i) {
        const char *target = argv[i];
        const char *base = smallclueLeafName(target);
        char linkname[PATH_MAX];
        if (smallclueBuildPath(linkname, sizeof(linkname), lastArg, base) != 0) {
            fprintf(stderr, "ln: %s/%s: %s\n", lastArg, base, strerror(errno));
            status = 1;
            continue;
        }
        if (smallclueLnCreateOne(target, linkname, symbolic, force) != 0) {
            status = 1;
        }
    }
    return status;
}

static char *smallclueSearchPath(const char *name) {
    if (!name || !*name) {
        return NULL;
    }
    char resolved[PATH_MAX];
    if (!smallclueResolveCommandPathForExec(name, resolved, sizeof(resolved))) {
        return NULL;
    }
#if defined(PSCAL_TARGET_IOS)
    char display[PATH_MAX];
    if (pathTruncateStrip(resolved, display, sizeof(display)) &&
        strcmp(display, resolved) != 0) {
        return strdup(display);
    }
#endif
    return strdup(resolved);
}

static int smallclueWhichCommand(int argc, char **argv) {
    bool all = false;
    smallclueResetGetopt();
    int opt;
    while ((opt = getopt(argc, argv, "a")) != -1) {
        switch (opt) {
            case 'a':
                all = true;
                break;
            default:
                fprintf(stderr, "usage: which [-a] program ...\n");
                return 1;
        }
    }

    if (optind >= argc) {
        return 1;
    }

    int status = 0;
    const char *env = getenv("PATH");

    for (int i = optind; i < argc; ++i) {
        const char *name = argv[i];
        if (strchr(name, '/')) {
            char *path = smallclueSearchPath(name);
            if (path) {
                puts(path);
                free(path);
            } else {
                status = 1;
            }
            continue;
        }

        bool found = false;
        if (env && *env) {
            char *path_copy = strdup(env);
            if (path_copy) {
                char *token = strtok(path_copy, ":");
                while (token) {
                    char candidate[PATH_MAX];
                    int w = snprintf(candidate, sizeof(candidate), "%s/%s", token, name);
                    char resolved_candidate[PATH_MAX];
                    if (w > 0 && (size_t)w < sizeof(candidate) &&
                        smallclueResolveExecutableCandidate(candidate,
                                                            resolved_candidate,
                                                            sizeof(resolved_candidate))) {
#if defined(PSCAL_TARGET_IOS)
                        char display[PATH_MAX];
                        if (pathTruncateStrip(resolved_candidate, display, sizeof(display)) &&
                            strcmp(display, resolved_candidate) != 0) {
                            puts(display);
                        } else {
                            puts(resolved_candidate);
                        }
#else
                        puts(resolved_candidate);
#endif
                        found = true;
                        if (!all) {
                            break;
                        }
                    }
                    token = strtok(NULL, ":");
                }
                free(path_copy);
            }
        }

        if (!found) {
            status = 1;
        }
    }

    return status;
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
    bool recursive = false;
    bool preserveTimes = false;
    int argi = 1;
    for (; argi < argc; ++argi) {
        const char *arg = argv[argi];
        if (arg[0] != '-' || strcmp(arg, "-") == 0) {
            break;
        }
        if (strcmp(arg, "--") == 0) {
            argi++;
            break;
        }
        for (const char *p = arg + 1; *p; ++p) {
            switch (*p) {
                case 'r':
                case 'R':
                    recursive = true;
                    break;
                case 'a':
                    recursive = true;
                    preserveTimes = true;
                    break;
                case 'p':
                    preserveTimes = true;
                    break;
                default:
                    fprintf(stderr, "cp: unsupported option '%c'\n", *p);
                    return 1;
            }
        }
    }

    if (argc - argi < 2) {
        fprintf(stderr, "cp: missing file operand\n");
        return 1;
    }
    const char *dest = argv[argc - 1];
    char resolved_dest_root[PATH_MAX];
    const char *dest_real = smallclueResolvePath(dest, resolved_dest_root, sizeof(resolved_dest_root));
    struct stat dest_stat;
    int dest_exists = (stat(dest_real, &dest_stat) == 0);
    bool dest_is_dir = dest_exists && S_ISDIR(dest_stat.st_mode);
    int source_count = (argc - 1) - argi;
    if (source_count > 1 && !dest_is_dir) {
        fprintf(stderr, "cp: target '%s' is not a directory\n", dest);
        return 1;
    }
    int status = 0;
    for (int i = argi; i < argi + source_count; ++i) {
        char resolved_src[PATH_MAX];
        const char *src = smallclueResolvePath(argv[i], resolved_src, sizeof(resolved_src));
        struct stat src_stat;
        if (lstat(src, &src_stat) != 0) {
            fprintf(stderr, "cp: %s: %s\n", src, strerror(errno));
            status = 1;
            continue;
        }
        if (S_ISDIR(src_stat.st_mode) && !recursive) {
            fprintf(stderr, "cp: -r not specified; omitting directory '%s'\n", src);
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
        if (S_ISDIR(src_stat.st_mode)) {
            if (smallclueCopyRecursive("cp", src, target, preserveTimes) != 0) {
                status = 1;
            }
        } else if (smallclueCopyFile("cp", src, target) != 0) {
            status = 1;
        } else if (preserveTimes) {
            smallclueCopyPreserveTimes(src, target, &src_stat);
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
            struct stat src_stat;
            bool src_is_dir = (lstat(src, &src_stat) == 0) && S_ISDIR(src_stat.st_mode);
            if (src_is_dir) {
                if (smallclueCopyRecursive("mv", src, target, true) != 0) {
                    status = 1;
                    continue;
                }
            } else if (smallclueCopyFile("mv", src, target) != 0) {
                status = 1;
                continue;
            }
            if (smallclueRemovePathWithLabel("mv", src, src_is_dir, true, false) != 0) {
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

/* install(1): `make install` targets very commonly invoke this directly
 * rather than cp+chmod+mkdir -p, so its absence is a real gap for a
 * self-hosted build environment. Supports the common subset: copying
 * (optionally into a directory, or with -D creating the destination's
 * parent directories first) with a settable mode, and -d for creating
 * directories outright instead of copying files. -o/-g (owner/group) are
 * not implemented -- they require root in the common case and add scope
 * without being load-bearing for a single-user guest. */
static int smallclueInstallCommand(int argc, char **argv) {
    mode_t mode = 0755;
    bool makeDirs = false;      /* -d: create directories, don't copy files */
    bool makeParentDirs = false; /* -D: create DEST's parent dirs first */
    bool verbose = false;

    int argi = 1;
    for (; argi < argc; ++argi) {
        const char *arg = argv[argi];
        if (strcmp(arg, "--") == 0) {
            argi++;
            break;
        }
        if (strcmp(arg, "-m") == 0) {
            if (argi + 1 >= argc) {
                fprintf(stderr, "install: -m requires a mode argument\n");
                return 1;
            }
            mode_t parsed;
            if (!smallclueChmodParseOctal(argv[++argi], &parsed)) {
                fprintf(stderr, "install: invalid mode '%s'\n", argv[argi]);
                return 1;
            }
            mode = parsed;
        } else if (strcmp(arg, "-d") == 0) {
            makeDirs = true;
        } else if (strcmp(arg, "-D") == 0) {
            makeParentDirs = true;
        } else if (strcmp(arg, "-v") == 0) {
            verbose = true;
        } else if (arg[0] == '-' && arg[1] != '\0') {
            fprintf(stderr, "install: unsupported option '%s'\n", arg);
            return 1;
        } else {
            break;
        }
    }

    if (makeDirs) {
        if (argi >= argc) {
            fprintf(stderr, "install: -d requires at least one directory\n");
            return 1;
        }
        int status = 0;
        for (int i = argi; i < argc; ++i) {
            if (verbose) {
                printf("install: creating directory %s\n", argv[i]);
            }
            if (smallclueMkdirParents(argv[i], mode, verbose) != 0) {
                fprintf(stderr, "install: %s: %s\n", argv[i], strerror(errno));
                status = 1;
            }
        }
        return status;
    }

    if (argc - argi < 2) {
        fprintf(stderr, "install: missing file operand\n");
        return 1;
    }
    const char *dest = argv[argc - 1];
    int sourceCount = (argc - 1) - argi;
    struct stat destStat;
    bool destIsDir = stat(dest, &destStat) == 0 && S_ISDIR(destStat.st_mode);
    if (sourceCount > 1 && !destIsDir) {
        fprintf(stderr, "install: target '%s' is not a directory\n", dest);
        return 1;
    }

    int status = 0;
    for (int i = argi; i < argi + sourceCount; ++i) {
        const char *src = argv[i];
        char targetPath[PATH_MAX];
        const char *target = dest;
        if (destIsDir) {
            if (smallclueBuildPath(targetPath, sizeof(targetPath), dest, smallclueLeafName(src)) != 0) {
                fprintf(stderr, "install: %s/%s: %s\n", dest, smallclueLeafName(src), strerror(errno));
                status = 1;
                continue;
            }
            target = targetPath;
        } else if (makeParentDirs) {
            char parentBuf[PATH_MAX];
            snprintf(parentBuf, sizeof(parentBuf), "%s", dest);
            char *slash = strrchr(parentBuf, '/');
            if (slash && slash != parentBuf) {
                *slash = '\0';
                if (smallclueMkdirParents(parentBuf, 0777, verbose) != 0) {
                    fprintf(stderr, "install: %s: %s\n", parentBuf, strerror(errno));
                    status = 1;
                    continue;
                }
            }
        }
        if (verbose) {
            printf("install: %s -> %s\n", src, target);
        }
        if (smallclueCopyFile("install", src, target) != 0) {
            status = 1;
            continue;
        }
        if (chmod(target, mode) != 0) {
            fprintf(stderr, "install: %s: %s\n", target, strerror(errno));
            status = 1;
        }
    }
    return status;
}

typedef struct {
    bool recursive;
    bool verbose;
    bool compress;
    bool preserve_mode;
    bool preserve_times;
    bool dry_run;
    bool delete_extra;
    bool update_only;
    bool checksum;
    char **include_patterns;
    size_t include_count;
    size_t include_capacity;
    char **exclude_patterns;
    size_t exclude_count;
    size_t exclude_capacity;
    const char *filter_root;
    const char *filter_dest_root;
} SmallclueRsyncOptions;

static bool smallclueRsyncLegacyFallbackEnabled(void) {
    int parsed = pagerParseEnvBool(getenv("PSCALI_RSYNC_LEGACY"));
    return parsed == 1;
}

static int smallclueRunNativeRsyncCommand(int argc, char **argv) {
    if (argc <= 0 || !argv || !argv[0]) {
        return 1;
    }

    char exec_path[PATH_MAX];
    if (!smallclueResolveCommandPathForExec("rsync", exec_path, sizeof(exec_path))) {
        fprintf(stderr,
                "rsync: no native rsync backend found in PATH; "
                "install/provide a real rsync binary or set PSCALI_RSYNC_LEGACY=1\n");
        return 127;
    }

    setenv("PSCALI_RSYNC_EXTERNAL_DELEGATE_ACTIVE", "1", 1);
    execv(exec_path, argv);
    int err = errno;
    fprintf(stderr, "rsync: %s: %s\n", exec_path, strerror(err));
    return (err == ENOENT) ? 127 : 126;
}

static void smallclueRsyncUsage(FILE *out) {
    if (!out) {
        out = stderr;
    }
    fprintf(out,
            "usage: rsync [options] <source>... <destination>\n"
            "  -a, --archive          archive mode (implies -rpt)\n"
            "  -r, --recursive        recurse into directories\n"
            "  -p, --perms            preserve permissions\n"
            "  -t, --times            preserve modification times\n"
            "  -u, --update           skip files newer on receiver\n"
            "  -c, --checksum         use checksum to detect changes\n"
            "  -v, --verbose          verbose output\n"
            "  -z, --compress         enable compression for remote transfer (scp -C)\n"
            "  -n, --dry-run          show what would change without writing\n"
            "      --delete           delete destination entries not present in source\n"
            "      --include=PATTERN  include files matching pattern\n"
            "      --exclude=PATTERN  exclude files matching pattern\n");
}

static int smallclueRsyncAddPattern(char ***patterns,
                                    size_t *count,
                                    size_t *capacity,
                                    const char *value) {
    if (!patterns || !count || !capacity || !value || value[0] == '\0') {
        return -1;
    }
    if (*count == *capacity) {
        size_t next_capacity = *capacity ? (*capacity * 2) : 8;
        char **resized = (char **)realloc(*patterns, next_capacity * sizeof(char *));
        if (!resized) {
            return -1;
        }
        *patterns = resized;
        *capacity = next_capacity;
    }
    (*patterns)[*count] = strdup(value);
    if (!(*patterns)[*count]) {
        return -1;
    }
    (*count)++;
    return 0;
}

static void smallclueRsyncFreePatterns(char **patterns, size_t count) {
    if (!patterns) {
        return;
    }
    for (size_t i = 0; i < count; ++i) {
        free(patterns[i]);
    }
    free(patterns);
}

static bool smallclueRsyncHasTrailingSlash(const char *path) {
    if (!path) {
        return false;
    }
    size_t len = strlen(path);
    return len > 1 && path[len - 1] == '/';
}

static bool smallclueRsyncLooksRemote(const char *path) {
    if (!path || !*path) {
        return false;
    }
    if (strncmp(path, "rsync://", 8) == 0) {
        return true;
    }
    if (strstr(path, "://") != NULL) {
        return false;
    }
    const char *colon = strchr(path, ':');
    if (!colon || colon == path) {
        return false;
    }
    const char *slash = strchr(path, '/');
    if (slash && slash < colon) {
        return false;
    }
    if (path[0] == '/' || path[0] == '.') {
        return false;
    }
    return true;
}

static void smallclueRsyncStatTimes(const struct stat *st, struct timeval tv[2]) {
    if (!st || !tv) {
        return;
    }
#if defined(__APPLE__)
    tv[0].tv_sec = st->st_atimespec.tv_sec;
    tv[0].tv_usec = (suseconds_t)(st->st_atimespec.tv_nsec / 1000);
    tv[1].tv_sec = st->st_mtimespec.tv_sec;
    tv[1].tv_usec = (suseconds_t)(st->st_mtimespec.tv_nsec / 1000);
#else
    tv[0].tv_sec = st->st_atim.tv_sec;
    tv[0].tv_usec = (suseconds_t)(st->st_atim.tv_nsec / 1000);
    tv[1].tv_sec = st->st_mtim.tv_sec;
    tv[1].tv_usec = (suseconds_t)(st->st_mtim.tv_nsec / 1000);
#endif
}

static int smallclueRsyncCompareMtime(const struct stat *lhs, const struct stat *rhs) {
#if defined(__APPLE__)
    if (lhs->st_mtimespec.tv_sec != rhs->st_mtimespec.tv_sec) {
        return (lhs->st_mtimespec.tv_sec < rhs->st_mtimespec.tv_sec) ? -1 : 1;
    }
    if (lhs->st_mtimespec.tv_nsec != rhs->st_mtimespec.tv_nsec) {
        return (lhs->st_mtimespec.tv_nsec < rhs->st_mtimespec.tv_nsec) ? -1 : 1;
    }
#else
    if (lhs->st_mtim.tv_sec != rhs->st_mtim.tv_sec) {
        return (lhs->st_mtim.tv_sec < rhs->st_mtim.tv_sec) ? -1 : 1;
    }
    if (lhs->st_mtim.tv_nsec != rhs->st_mtim.tv_nsec) {
        return (lhs->st_mtim.tv_nsec < rhs->st_mtim.tv_nsec) ? -1 : 1;
    }
#endif
    return 0;
}

static bool smallclueRsyncSameMtime(const struct stat *a, const struct stat *b) {
    return smallclueRsyncCompareMtime(a, b) == 0;
}

static int smallclueRsyncFileChecksum(const char *path, uint64_t *out_hash) {
    if (!path || !out_hash) {
        errno = EINVAL;
        return -1;
    }
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        return -1;
    }
    uint64_t hash = 1469598103934665603ULL;
    unsigned char buffer[16384];
    for (;;) {
        ssize_t nread = read(fd, buffer, sizeof(buffer));
        if (nread == 0) {
            break;
        }
        if (nread < 0) {
            int saved = errno;
            close(fd);
            errno = saved;
            return -1;
        }
        for (ssize_t i = 0; i < nread; ++i) {
            hash ^= (uint64_t)buffer[i];
            hash *= 1099511628211ULL;
        }
    }
    close(fd);
    *out_hash = hash;
    return 0;
}

static bool smallclueRsyncParentPath(const char *path, char *out, size_t out_size) {
    if (!path || !out || out_size == 0) {
        return false;
    }
    if (!smallclueCopyPath(out, out_size, path)) {
        return false;
    }
    smallclueTrimTrailingSlashes(out);
    char *slash = strrchr(out, '/');
    if (!slash) {
        if (out_size < 2) {
            return false;
        }
        out[0] = '.';
        out[1] = '\0';
        return true;
    }
    if (slash == out) {
        out[1] = '\0';
        return true;
    }
    *slash = '\0';
    return true;
}

static const char *smallclueRsyncLeafName(const char *path, char *scratch, size_t scratch_size) {
    if (!path || !scratch || scratch_size == 0 || !smallclueCopyPath(scratch, scratch_size, path)) {
        return path;
    }
    smallclueTrimTrailingSlashes(scratch);
    return smallclueLeafName(scratch);
}

static const char *smallclueRsyncRelativePath(const char *root,
                                              const char *path,
                                              char *out,
                                              size_t out_size) {
    if (!path || !out || out_size == 0) {
        return "";
    }
    out[0] = '\0';
    if (!root || root[0] == '\0') {
        const char *leaf = smallclueLeafName(path);
        smallclueCopyPath(out, out_size, leaf ? leaf : path);
        return out;
    }
    char root_buf[PATH_MAX];
    if (!smallclueCopyPath(root_buf, sizeof(root_buf), root)) {
        const char *leaf = smallclueLeafName(path);
        smallclueCopyPath(out, out_size, leaf ? leaf : path);
        return out;
    }
    smallclueTrimTrailingSlashes(root_buf);
    size_t root_len = strlen(root_buf);
    if (strncmp(path, root_buf, root_len) == 0 &&
        (path[root_len] == '\0' || path[root_len] == '/')) {
        const char *suffix = path + root_len;
        if (*suffix == '/') {
            suffix++;
        }
        if (*suffix == '\0') {
            smallclueCopyPath(out, out_size, ".");
        } else {
            smallclueCopyPath(out, out_size, suffix);
        }
        return out;
    }
    const char *leaf = smallclueLeafName(path);
    smallclueCopyPath(out, out_size, leaf ? leaf : path);
    return out;
}

static bool smallclueRsyncPatternMatch(const char *pattern,
                                       const char *relative_path,
                                       const char *leaf_name,
                                       bool is_dir) {
    if (!pattern || !*pattern) {
        return false;
    }
    if (relative_path && fnmatch(pattern, relative_path, FNM_PATHNAME) == 0) {
        return true;
    }
    if (leaf_name && fnmatch(pattern, leaf_name, 0) == 0) {
        return true;
    }
    if (is_dir && relative_path) {
        char rel_dir[PATH_MAX];
        int written = snprintf(rel_dir, sizeof(rel_dir), "%s/", relative_path);
        if (written > 0 && (size_t)written < sizeof(rel_dir) &&
            fnmatch(pattern, rel_dir, FNM_PATHNAME) == 0) {
            return true;
        }
    }
    return false;
}

static bool smallclueRsyncMatchesAny(const char *relative_path,
                                     const char *leaf_name,
                                     bool is_dir,
                                     char **patterns,
                                     size_t pattern_count) {
    for (size_t i = 0; i < pattern_count; ++i) {
        if (smallclueRsyncPatternMatch(patterns[i], relative_path, leaf_name, is_dir)) {
            return true;
        }
    }
    return false;
}

static bool smallclueRsyncPathSelected(const SmallclueRsyncOptions *opts,
                                       const char *path,
                                       bool is_dir,
                                       bool use_dest_root) {
    if (!opts) {
        return true;
    }
    if (opts->include_count == 0 && opts->exclude_count == 0) {
        return true;
    }
    char relbuf[PATH_MAX];
    char leafbuf[PATH_MAX];
    const char *relative = smallclueRsyncRelativePath(use_dest_root ? opts->filter_dest_root : opts->filter_root,
                                                      path,
                                                      relbuf,
                                                      sizeof(relbuf));
    const char *leaf = smallclueRsyncLeafName(path, leafbuf, sizeof(leafbuf));
    bool excluded = smallclueRsyncMatchesAny(relative, leaf, is_dir, opts->exclude_patterns, opts->exclude_count);
    if (excluded) {
        return false;
    }
    if (opts->include_count == 0) {
        return true;
    }
    if (is_dir) {
        return true;
    }
    return smallclueRsyncMatchesAny(relative, leaf, false, opts->include_patterns, opts->include_count);
}

static int smallclueRsyncApplyMetadata(const char *dst,
                                       const struct stat *src_stat,
                                       const SmallclueRsyncOptions *opts,
                                       bool allow_chmod) {
    if (!dst || !src_stat || !opts || opts->dry_run) {
        return 0;
    }
    int status = 0;
    if (opts->preserve_mode && allow_chmod) {
        mode_t mode = src_stat->st_mode & 07777;
        if (chmod(dst, mode) != 0) {
            fprintf(stderr, "rsync: chmod %s: %s\n", dst, strerror(errno));
            status = -1;
        }
    }
    if (opts->preserve_times) {
        struct timeval tv[2];
        smallclueRsyncStatTimes(src_stat, tv);
        if (utimes(dst, tv) != 0) {
            fprintf(stderr, "rsync: utimes %s: %s\n", dst, strerror(errno));
            status = -1;
        }
    }
    return status;
}

static int smallclueRsyncEnsureDir(const char *path, mode_t mode, const SmallclueRsyncOptions *opts) {
    struct stat st;
    if (lstat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            return 0;
        }
        if (opts->dry_run) {
            if (opts->verbose) {
                printf("delete %s\n", path);
                printf("mkdir %s\n", path);
            }
            return 0;
        }
        if (smallclueRemovePathWithLabel("rsync", path, true, true, false) != 0) {
            return -1;
        }
    } else if (errno != ENOENT) {
        fprintf(stderr, "rsync: %s: %s\n", path, strerror(errno));
        return -1;
    }
    if (opts->dry_run) {
        if (opts->verbose) {
            printf("mkdir %s\n", path);
        }
        return 0;
    }
    if (smallclueMkdirParents(path, mode, false) != 0) {
        fprintf(stderr, "rsync: mkdir %s: %s\n", path, strerror(errno));
        return -1;
    }
    return 0;
}

static int smallclueRsyncEnsureParentDir(const char *path, const SmallclueRsyncOptions *opts) {
    char parent[PATH_MAX];
    if (!smallclueCopyPath(parent, sizeof(parent), path)) {
        errno = ENAMETOOLONG;
        fprintf(stderr, "rsync: %s: %s\n", path, strerror(errno));
        return -1;
    }
    if (!smallclueChopParentDirectory(parent)) {
        return 0;
    }
    return smallclueRsyncEnsureDir(parent, 0777, opts);
}

static int smallclueRsyncRemovePath(const char *path, const SmallclueRsyncOptions *opts) {
    if (opts->dry_run) {
        if (opts->verbose) {
            printf("delete %s\n", path);
        }
        return 0;
    }
    return smallclueRemovePathWithLabel("rsync", path, true, true, false);
}

static int smallclueRsyncSyncEntry(const char *src, const char *dst, const SmallclueRsyncOptions *opts);

static int smallclueRsyncDeleteExtraneous(const char *src_dir,
                                          const char *dst_dir,
                                          const SmallclueRsyncOptions *opts) {
    DIR *dir = opendir(dst_dir);
    if (!dir) {
        fprintf(stderr, "rsync: %s: %s\n", dst_dir, strerror(errno));
        return -1;
    }
    int status = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        char src_child[PATH_MAX];
        char dst_child[PATH_MAX];
        if (smallclueBuildPath(src_child, sizeof(src_child), src_dir, entry->d_name) != 0 ||
            smallclueBuildPath(dst_child, sizeof(dst_child), dst_dir, entry->d_name) != 0) {
            fprintf(stderr, "rsync: path too long while deleting '%s'\n", entry->d_name);
            status = -1;
            continue;
        }
        struct stat dst_st;
        if (lstat(dst_child, &dst_st) != 0) {
            continue;
        }
        if (!smallclueRsyncPathSelected(opts, dst_child, S_ISDIR(dst_st.st_mode), true)) {
            continue;
        }
        struct stat src_st;
        if (lstat(src_child, &src_st) == 0) {
            continue;
        }
        if (errno != ENOENT) {
            fprintf(stderr, "rsync: %s: %s\n", src_child, strerror(errno));
            status = -1;
            continue;
        }
        if (smallclueRsyncRemovePath(dst_child, opts) != 0) {
            status = -1;
        }
    }
    closedir(dir);
    return status;
}

static int smallclueRsyncSyncDirectoryContents(const char *src_dir,
                                               const char *dst_dir,
                                               const SmallclueRsyncOptions *opts,
                                               bool delete_extra) {
    struct stat src_st;
    if (lstat(src_dir, &src_st) != 0) {
        fprintf(stderr, "rsync: %s: %s\n", src_dir, strerror(errno));
        return -1;
    }
    if (smallclueRsyncEnsureDir(dst_dir, src_st.st_mode & 0777, opts) != 0) {
        return -1;
    }

    DIR *dir = opendir(src_dir);
    if (!dir) {
        fprintf(stderr, "rsync: %s: %s\n", src_dir, strerror(errno));
        return -1;
    }

    int status = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        char src_child[PATH_MAX];
        char dst_child[PATH_MAX];
        if (smallclueBuildPath(src_child, sizeof(src_child), src_dir, entry->d_name) != 0 ||
            smallclueBuildPath(dst_child, sizeof(dst_child), dst_dir, entry->d_name) != 0) {
            fprintf(stderr, "rsync: path too long while syncing '%s'\n", entry->d_name);
            status = -1;
            continue;
        }
        if (smallclueRsyncSyncEntry(src_child, dst_child, opts) != 0) {
            status = -1;
        }
    }
    closedir(dir);

    if (delete_extra && opts->delete_extra) {
        if (smallclueRsyncDeleteExtraneous(src_dir, dst_dir, opts) != 0) {
            status = -1;
        }
    }
    return status;
}

static int smallclueRsyncSyncEntry(const char *src, const char *dst, const SmallclueRsyncOptions *opts) {
    struct stat src_st;
    if (lstat(src, &src_st) != 0) {
        fprintf(stderr, "rsync: %s: %s\n", src, strerror(errno));
        return -1;
    }
    bool src_is_dir = S_ISDIR(src_st.st_mode);
    if (!smallclueRsyncPathSelected(opts, src, src_is_dir, false)) {
        if (opts->verbose) {
            printf("exclude %s\n", src);
        }
        return 0;
    }

    if (src_is_dir) {
        if (!opts->recursive) {
            fprintf(stderr, "rsync: skipping directory '%s' (use -r)\n", src);
            return -1;
        }
        int status = smallclueRsyncSyncDirectoryContents(src, dst, opts, true);
        if (status == 0 && smallclueRsyncApplyMetadata(dst, &src_st, opts, true) != 0) {
            status = -1;
        }
        return status;
    }

    if (S_ISLNK(src_st.st_mode)) {
        char link_target[PATH_MAX];
        ssize_t link_len = readlink(src, link_target, sizeof(link_target) - 1);
        if (link_len < 0) {
            fprintf(stderr, "rsync: readlink %s: %s\n", src, strerror(errno));
            return -1;
        }
        link_target[link_len] = '\0';

        bool needs_update = true;
        struct stat dst_st;
        if (lstat(dst, &dst_st) == 0 && S_ISLNK(dst_st.st_mode)) {
            char existing_target[PATH_MAX];
            ssize_t existing_len = readlink(dst, existing_target, sizeof(existing_target) - 1);
            if (existing_len >= 0) {
                existing_target[existing_len] = '\0';
                if (strcmp(existing_target, link_target) == 0) {
                    needs_update = false;
                }
            }
        }

        if (!needs_update) {
            if (opts->verbose) {
                printf("skip %s\n", dst);
            }
            return 0;
        }

        if (smallclueRsyncEnsureParentDir(dst, opts) != 0) {
            return -1;
        }

        if (opts->verbose) {
            printf("link %s -> %s\n", src, dst);
        }
        if (opts->dry_run) {
            return 0;
        }

        if (lstat(dst, &dst_st) == 0) {
            if (smallclueRemovePathWithLabel("rsync", dst, true, true, false) != 0) {
                return -1;
            }
        } else if (errno != ENOENT) {
            fprintf(stderr, "rsync: %s: %s\n", dst, strerror(errno));
            return -1;
        }

        if (symlink(link_target, dst) != 0) {
            fprintf(stderr, "rsync: symlink %s -> %s: %s\n", dst, link_target, strerror(errno));
            return -1;
        }
        return 0;
    }

    if (!S_ISREG(src_st.st_mode)) {
        if (opts->verbose) {
            printf("skip %s (unsupported file type)\n", src);
        }
        return 0;
    }

    struct stat dst_st;
    bool dst_exists = (lstat(dst, &dst_st) == 0);
    bool needs_copy = true;
    if (dst_exists && S_ISREG(dst_st.st_mode)) {
        if (opts->update_only && smallclueRsyncCompareMtime(&dst_st, &src_st) > 0) {
            needs_copy = false;
        } else if (opts->checksum) {
            if (src_st.st_size == dst_st.st_size) {
                uint64_t src_hash = 0;
                uint64_t dst_hash = 0;
                if (smallclueRsyncFileChecksum(src, &src_hash) != 0 ||
                    smallclueRsyncFileChecksum(dst, &dst_hash) != 0) {
                    fprintf(stderr, "rsync: checksum failed for '%s' or '%s': %s\n", src, dst, strerror(errno));
                    return -1;
                }
                if (src_hash == dst_hash) {
                    needs_copy = false;
                }
            }
        } else {
            bool same_size = src_st.st_size == dst_st.st_size;
            bool same_mtime = smallclueRsyncSameMtime(&src_st, &dst_st);
            bool same_mode = ((src_st.st_mode & 07777) == (dst_st.st_mode & 07777));
            if (same_size && same_mtime && (!opts->preserve_mode || same_mode)) {
                needs_copy = false;
            }
        }
    }

    if (!needs_copy) {
        if (opts->verbose) {
            printf("skip %s\n", dst);
        }
        if (smallclueRsyncApplyMetadata(dst, &src_st, opts, true) != 0) {
            return -1;
        }
        return 0;
    }

    if (smallclueRsyncEnsureParentDir(dst, opts) != 0) {
        return -1;
    }
    if (opts->verbose) {
        printf("copy %s -> %s\n", src, dst);
    }
    if (opts->dry_run) {
        return 0;
    }

    if (dst_exists && !S_ISREG(dst_st.st_mode)) {
        if (smallclueRemovePathWithLabel("rsync", dst, true, true, false) != 0) {
            return -1;
        }
    }
    if (smallclueCopyFile("rsync", src, dst) != 0) {
        return -1;
    }
    return smallclueRsyncApplyMetadata(dst, &src_st, opts, true);
}

static char *smallclueRsyncBuildRemoteSourceArg(const char *arg, bool recursive) {
    if (!arg) {
        return NULL;
    }
    if (!recursive || !smallclueRsyncHasTrailingSlash(arg)) {
        return strdup(arg);
    }

    size_t len = strlen(arg);
    while (len > 1 && arg[len - 1] == '/') {
        len--;
    }

    bool already_dot = false;
    if (len >= 2 && arg[len - 2] == '/' && arg[len - 1] == '.') {
        already_dot = true;
    }
    if (already_dot) {
        return strdup(arg);
    }

    size_t out_len = len + 2; /* "/." */
    char *out = (char *)malloc(out_len + 1);
    if (!out) {
        return NULL;
    }
    memcpy(out, arg, len);
    out[len] = '/';
    out[len + 1] = '.';
    out[len + 2] = '\0';
    return out;
}

static int smallclueRsyncRemoteDryRun(int argc, char **argv, int operand_index) {
    if (!argv || operand_index >= argc) {
        return 1;
    }
    const char *dest = argv[argc - 1];
    for (int i = operand_index; i < argc - 1; ++i) {
        if (!argv[i]) {
            continue;
        }
        printf("copy %s -> %s\n", argv[i], dest ? dest : "");
    }
    return 0;
}

static int smallclueRsyncRunRemoteScp(int argc,
                                      char **argv,
                                      int operand_index,
                                      int remote_count,
                                      const SmallclueRsyncOptions *opts) {
    if (remote_count > 1) {
        fprintf(stderr, "rsync: remote-to-remote copy is not supported\n");
        return 1;
    }
    if (opts->delete_extra) {
        fprintf(stderr, "rsync: --delete is only supported for local paths\n");
        return 1;
    }
    if (opts->update_only || opts->checksum || opts->include_count > 0 || opts->exclude_count > 0) {
        fprintf(stderr, "rsync: -u/-c/--include/--exclude are not supported for remote transfers yet\n");
        return 1;
    }
    if (opts->dry_run) {
        return smallclueRsyncRemoteDryRun(argc, argv, operand_index);
    }

    size_t max_args = (size_t)(argc - operand_index) + 8;
    char **scp_argv = (char **)calloc(max_args + 1, sizeof(char *));
    if (!scp_argv) {
        fprintf(stderr, "rsync: out of memory\n");
        return 1;
    }

    int scp_argc = 0;
    scp_argv[scp_argc++] = strdup("scp");
    if (opts->recursive) {
        scp_argv[scp_argc++] = strdup("-r");
    }
    if (opts->preserve_mode || opts->preserve_times) {
        scp_argv[scp_argc++] = strdup("-p");
    }
    if (opts->compress) {
        scp_argv[scp_argc++] = strdup("-C");
    }
    for (int i = operand_index; i < argc; ++i) {
        if (i < argc - 1) {
            scp_argv[scp_argc++] = smallclueRsyncBuildRemoteSourceArg(argv[i], opts->recursive);
        } else {
            scp_argv[scp_argc++] = strdup(argv[i]);
        }
    }

    int rc = 0;
    for (int i = 0; i < scp_argc; ++i) {
        if (!scp_argv[i]) {
            fprintf(stderr, "rsync: out of memory\n");
            rc = 1;
            goto rsync_remote_cleanup;
        }
    }

    if (opts->verbose) {
        const char *dest = argv[argc - 1];
        for (int i = operand_index; i < argc - 1; ++i) {
            if (!argv[i]) {
                continue;
            }
            printf("copy %s -> %s\n", argv[i], dest ? dest : "");
        }
    }

    setenv("PSCALI_SCP_NO_FOLLOW_SYMLINK_DIRS", "1", 1);
    rc = smallclueRunScp(scp_argc, scp_argv);
    unsetenv("PSCALI_SCP_NO_FOLLOW_SYMLINK_DIRS");

rsync_remote_cleanup:
    for (int i = 0; i < scp_argc; ++i) {
        free(scp_argv[i]);
    }
    free(scp_argv);
    return rc;
}

static int smallclueRsyncCommand(int argc, char **argv) {
    if (!smallclueRsyncLegacyFallbackEnabled()) {
        return smallclueRunRsync(argc, argv);
    }

    SmallclueRsyncOptions opts;
    memset(&opts, 0, sizeof(opts));

    int argi = 1;
    while (argi < argc) {
        const char *arg = argv[argi];
        if (!arg || arg[0] != '-' || strcmp(arg, "-") == 0) {
            break;
        }
        if (strcmp(arg, "--") == 0) {
            argi++;
            break;
        }
        if (strcmp(arg, "--help") == 0) {
            smallclueRsyncUsage(stdout);
            smallclueRsyncFreePatterns(opts.include_patterns, opts.include_count);
            smallclueRsyncFreePatterns(opts.exclude_patterns, opts.exclude_count);
            return 0;
        }
        if (strcmp(arg, "--delete") == 0) {
            opts.delete_extra = true;
            argi++;
            continue;
        }
        if (strcmp(arg, "--dry-run") == 0) {
            opts.dry_run = true;
            argi++;
            continue;
        }
        if (strcmp(arg, "--archive") == 0) {
            opts.recursive = true;
            opts.preserve_mode = true;
            opts.preserve_times = true;
            argi++;
            continue;
        }
        if (strcmp(arg, "--recursive") == 0) {
            opts.recursive = true;
            argi++;
            continue;
        }
        if (strcmp(arg, "--verbose") == 0) {
            opts.verbose = true;
            argi++;
            continue;
        }
        if (strcmp(arg, "--compress") == 0) {
            opts.compress = true;
            argi++;
            continue;
        }
        if (strcmp(arg, "--perms") == 0) {
            opts.preserve_mode = true;
            argi++;
            continue;
        }
        if (strcmp(arg, "--times") == 0) {
            opts.preserve_times = true;
            argi++;
            continue;
        }
        if (strcmp(arg, "--update") == 0) {
            opts.update_only = true;
            argi++;
            continue;
        }
        if (strcmp(arg, "--checksum") == 0) {
            opts.checksum = true;
            argi++;
            continue;
        }
        if (strncmp(arg, "--include=", 10) == 0) {
            if (smallclueRsyncAddPattern(&opts.include_patterns,
                                         &opts.include_count,
                                         &opts.include_capacity,
                                         arg + 10) != 0) {
                fprintf(stderr, "rsync: unable to add include pattern\n");
                goto rsync_parse_fail;
            }
            argi++;
            continue;
        }
        if (strcmp(arg, "--include") == 0) {
            if (argi + 1 >= argc) {
                fprintf(stderr, "rsync: --include requires a pattern\n");
                goto rsync_parse_fail;
            }
            if (smallclueRsyncAddPattern(&opts.include_patterns,
                                         &opts.include_count,
                                         &opts.include_capacity,
                                         argv[argi + 1]) != 0) {
                fprintf(stderr, "rsync: unable to add include pattern\n");
                goto rsync_parse_fail;
            }
            argi += 2;
            continue;
        }
        if (strncmp(arg, "--exclude=", 10) == 0) {
            if (smallclueRsyncAddPattern(&opts.exclude_patterns,
                                         &opts.exclude_count,
                                         &opts.exclude_capacity,
                                         arg + 10) != 0) {
                fprintf(stderr, "rsync: unable to add exclude pattern\n");
                goto rsync_parse_fail;
            }
            argi++;
            continue;
        }
        if (strcmp(arg, "--exclude") == 0) {
            if (argi + 1 >= argc) {
                fprintf(stderr, "rsync: --exclude requires a pattern\n");
                goto rsync_parse_fail;
            }
            if (smallclueRsyncAddPattern(&opts.exclude_patterns,
                                         &opts.exclude_count,
                                         &opts.exclude_capacity,
                                         argv[argi + 1]) != 0) {
                fprintf(stderr, "rsync: unable to add exclude pattern\n");
                goto rsync_parse_fail;
            }
            argi += 2;
            continue;
        }
        if (arg[1] == '-') {
            fprintf(stderr, "rsync: unknown option '%s'\n", arg);
            goto rsync_parse_fail;
        }
        for (const char *cursor = arg + 1; *cursor; ++cursor) {
            switch (*cursor) {
                case 'a':
                    opts.recursive = true;
                    opts.preserve_mode = true;
                    opts.preserve_times = true;
                    break;
                case 'r':
                    opts.recursive = true;
                    break;
                case 'v':
                    opts.verbose = true;
                    break;
                case 'z':
                    opts.compress = true;
                    break;
                case 'p':
                    opts.preserve_mode = true;
                    break;
                case 't':
                    opts.preserve_times = true;
                    break;
                case 'n':
                    opts.dry_run = true;
                    break;
                case 'u':
                    opts.update_only = true;
                    break;
                case 'c':
                    opts.checksum = true;
                    break;
                default:
                    fprintf(stderr, "rsync: invalid option -- %c\n", *cursor);
                    goto rsync_parse_fail;
            }
        }
        argi++;
    }

    {
        int operand_count = argc - argi;
        if (operand_count < 2) {
            smallclueRsyncUsage(stderr);
            goto rsync_parse_fail;
        }

        int source_count = operand_count - 1;
        bool has_remote = false;
        int remote_count = 0;
        for (int i = argi; i < argc; ++i) {
            if (strncmp(argv[i], "rsync://", 8) == 0) {
                fprintf(stderr, "rsync: rsync:// URLs are not supported; use host:path syntax\n");
                goto rsync_parse_fail;
            }
            if (smallclueRsyncLooksRemote(argv[i])) {
                has_remote = true;
                remote_count++;
            }
        }
        if (has_remote) {
            int rc = smallclueRsyncRunRemoteScp(argc, argv, argi, remote_count, &opts);
            smallclueRsyncFreePatterns(opts.include_patterns, opts.include_count);
            smallclueRsyncFreePatterns(opts.exclude_patterns, opts.exclude_count);
            return rc;
        }

        if (opts.delete_extra && source_count != 1) {
            fprintf(stderr, "rsync: --delete currently requires exactly one source\n");
            goto rsync_parse_fail;
        }

        const char *dest_arg = argv[argc - 1];
        char resolved_dest[PATH_MAX];
        const char *dest = smallclueResolvePath(dest_arg, resolved_dest, sizeof(resolved_dest));
        struct stat dest_st;
        bool dest_exists = lstat(dest, &dest_st) == 0;
        bool dest_is_dir = dest_exists && S_ISDIR(dest_st.st_mode);

        if (source_count > 1) {
            if (dest_exists && !dest_is_dir) {
                fprintf(stderr, "rsync: destination '%s' is not a directory\n", dest_arg);
                goto rsync_parse_fail;
            }
            if (!dest_exists) {
                if (smallclueRsyncEnsureDir(dest, 0777, &opts) != 0) {
                    goto rsync_parse_fail;
                }
                dest_exists = true;
                dest_is_dir = true;
            }
        }

        int status = 0;
        for (int i = 0; i < source_count; ++i) {
            const char *src_arg = argv[argi + i];
            bool src_trailing_slash = smallclueRsyncHasTrailingSlash(src_arg);

            char resolved_src[PATH_MAX];
            const char *src = smallclueResolvePath(src_arg, resolved_src, sizeof(resolved_src));

            struct stat src_st;
            if (lstat(src, &src_st) != 0) {
                fprintf(stderr, "rsync: %s: %s\n", src_arg, strerror(errno));
                status = 1;
                continue;
            }

            const char *target = dest;
            char target_path[PATH_MAX];
            bool copy_dir_contents = false;

            if (source_count > 1 || dest_is_dir) {
                if (S_ISDIR(src_st.st_mode) && src_trailing_slash) {
                    copy_dir_contents = true;
                    target = dest;
                } else {
                    char leaf_scratch[PATH_MAX];
                    const char *leaf = smallclueRsyncLeafName(src_arg, leaf_scratch, sizeof(leaf_scratch));
                    if (smallclueBuildPath(target_path, sizeof(target_path), dest, leaf) != 0) {
                        fprintf(stderr, "rsync: %s/%s: %s\n", dest, leaf, strerror(errno));
                        status = 1;
                        continue;
                    }
                    target = target_path;
                }
            } else if (S_ISDIR(src_st.st_mode) && src_trailing_slash) {
                copy_dir_contents = true;
                target = dest;
            }

            char src_root_buf[PATH_MAX];
            char dst_root_buf[PATH_MAX];
            if (copy_dir_contents) {
                opts.filter_root = src;
                opts.filter_dest_root = target;
            } else {
                if (!smallclueRsyncParentPath(src, src_root_buf, sizeof(src_root_buf)) ||
                    !smallclueRsyncParentPath(target, dst_root_buf, sizeof(dst_root_buf))) {
                    fprintf(stderr, "rsync: unable to derive filter roots for '%s'\n", src_arg);
                    status = 1;
                    continue;
                }
                opts.filter_root = src_root_buf;
                opts.filter_dest_root = dst_root_buf;
            }

            int rc;
            if (copy_dir_contents) {
                rc = smallclueRsyncSyncDirectoryContents(src, target, &opts, opts.delete_extra);
            } else {
                rc = smallclueRsyncSyncEntry(src, target, &opts);
            }
            if (rc != 0) {
                status = 1;
            }
        }

        smallclueRsyncFreePatterns(opts.include_patterns, opts.include_count);
        smallclueRsyncFreePatterns(opts.exclude_patterns, opts.exclude_count);
        return status;
    }

rsync_parse_fail:
    smallclueRsyncFreePatterns(opts.include_patterns, opts.include_count);
    smallclueRsyncFreePatterns(opts.exclude_patterns, opts.exclude_count);
    return 1;
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

static int levenshtein_distance(const char *s1, const char *s2) {
    size_t len1 = strlen(s1);
    size_t len2 = strlen(s2);
    if (len1 == 0) return (int)len2;
    if (len2 == 0) return (int)len1;

    int *matrix = (int *)malloc((len1 + 1) * (len2 + 1) * sizeof(int));
    if (!matrix) return -1;

    for (size_t i = 0; i <= len1; i++) matrix[i * (len2 + 1)] = (int)i;
    for (size_t j = 0; j <= len2; j++) matrix[j] = (int)j;

    for (size_t i = 1; i <= len1; i++) {
        for (size_t j = 1; j <= len2; j++) {
            int cost = (s1[i - 1] == s2[j - 1]) ? 0 : 1;
            int delete_op = matrix[(i - 1) * (len2 + 1) + j] + 1;
            int insert_op = matrix[i * (len2 + 1) + (j - 1)] + 1;
            int substitute_op = matrix[(i - 1) * (len2 + 1) + (j - 1)] + cost;
            int min = delete_op;
            if (insert_op < min) min = insert_op;
            if (substitute_op < min) min = substitute_op;
            matrix[i * (len2 + 1) + j] = min;
        }
    }

    int result = matrix[len1 * (len2 + 1) + len2];
    free(matrix);
    return result;
}

static const char *smallclueSuggestCommand(const char *typo) {
    if (!typo || !*typo) return NULL;

    const char *best_match = NULL;
    int best_dist = -1;
    size_t typo_len = strlen(typo);

    for (size_t i = 0; i < kSmallclueAppletCount; ++i) {
        const char *name = kSmallclueApplets[i].name;
        if (!name) continue;

        int dist = levenshtein_distance(typo, name);
        if (dist < 0) continue;

        if (best_dist == -1 || dist < best_dist) {
            best_dist = dist;
            best_match = name;
        }
    }

    if (best_match && best_dist != -1) {
        if (best_dist <= 2 && best_dist < (int)typo_len) {
            return best_match;
        }
    }
    return NULL;
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
        fprintf(stderr, "smallclue: '%s' applet not found.\n", call_name);
        const char *suggestion = smallclueSuggestCommand(call_name);
        if (suggestion) {
            fprintf(stderr, "Did you mean '%s'?\n", suggestion);
        }
        fprintf(stderr, "\n");
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

/* Evaluates a single atomic expression: no -a/-o splitting (that's handled
 * one level up, by smallclueTestEvaluateOr/And below), just !expr, a bare
 * string, a unary op + operand, or a binary op between two operands. */
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
        if (strcmp(op, "-x") == 0) {
            return access(arg, X_OK) == 0;
        }
        if (strcmp(op, "-s") == 0) {
            struct stat st;
            return stat(arg, &st) == 0 && st.st_size > 0;
        }
        if (strcmp(op, "-L") == 0 || strcmp(op, "-h") == 0) {
            struct stat st;
            return lstat(arg, &st) == 0 && S_ISLNK(st.st_mode);
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
        if (strcmp(op, "-nt") == 0 || strcmp(op, "-ot") == 0) {
            struct stat lst, rst;
            bool haveLeft = stat(left, &lst) == 0;
            bool haveRight = stat(right, &rst) == 0;
            if (!haveLeft || !haveRight) {
                /* POSIX: -nt is true if left exists and right doesn't. */
                return strcmp(op, "-nt") == 0 && haveLeft && !haveRight;
            }
            if (strcmp(op, "-nt") == 0) return lst.st_mtime > rst.st_mtime;
            return lst.st_mtime < rst.st_mtime;
        }
        if (strcmp(op, "-ef") == 0) {
            struct stat lst, rst;
            return stat(left, &lst) == 0 && stat(right, &rst) == 0 &&
                   lst.st_dev == rst.st_dev && lst.st_ino == rst.st_ino;
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

/* -a/-o support: scans for the first top-level "-a"/"-o" token and splits
 * there, recursing on each side. -o has lower precedence than -a (matches
 * POSIX: "expr1 -a expr2 -o expr3" groups as "(expr1 -a expr2) -o expr3"),
 * so the OR-split happens first/outermost and the AND-split is tried only
 * within an OR-free segment. Neither operator is looked for as the very
 * first or very last token (that position can only be a genuine operand,
 * e.g. `test -a foo` bare-unary-checks "foo" being non-empty via the
 * single-arg fallback in smallclueTestEvaluate, not an empty left-hand AND
 * side) -- this matches how real test(1) resolves the ambiguity. */
static bool smallclueTestEvaluateAnd(int argc, char **argv) {
    for (int i = 1; i < argc - 1; ++i) {
        if (strcmp(argv[i], "-a") == 0) {
            return smallclueTestEvaluateAnd(i, argv) && smallclueTestEvaluateAnd(argc - i - 1, argv + i + 1);
        }
    }
    return smallclueTestEvaluate(argc, argv);
}

static bool smallclueTestEvaluateOr(int argc, char **argv) {
    for (int i = 1; i < argc - 1; ++i) {
        if (strcmp(argv[i], "-o") == 0) {
            return smallclueTestEvaluateOr(i, argv) || smallclueTestEvaluateOr(argc - i - 1, argv + i + 1);
        }
    }
    return smallclueTestEvaluateAnd(argc, argv);
}

static int smallclueTestWithArgs(int argc, char **argv) {
    if (argc <= 0) {
        return 1;
    }
    bool result = smallclueTestEvaluateOr(argc, argv);
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

static int smallclueInitCommand(int argc, char **argv) {
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
    pid_t selfPid = getpid();
    if (selfPid != 1 && !allowNonPid1) {
        fprintf(stderr, "init: must be run as PID 1\n");
        fprintf(stderr, "init: use --service-mode to run in compatibility mode on iOS/iPadOS\n");
        return 1;
    }
    if (selfPid != 1) {
        printf("init: compatibility mode enabled (pid=%d)\n", (int)selfPid);
    }

    /* Basic init implementation:
     * 1. Block signals
     * 2. Run /etc/rc if present
     * 3. Reap zombies loop
     */

    printf("smallclue init: starting...\n");

    char rcPath[PATH_MAX];
    if (smallclueResolveEtcEntry("rc", F_OK, rcPath, sizeof(rcPath))) {
        printf("smallclue init: running %s\n", rcPath);
        pid_t pid = fork();
        if (pid == 0) {
            execl(rcPath, rcPath, NULL);
            int execErr = errno;
            char exshPath[PATH_MAX];
            if ((execErr == EACCES || execErr == ENOEXEC || execErr == ENOTSUP || execErr == EPERM) &&
                smallclueResolveExshPath(exshPath, sizeof(exshPath))) {
                execl(exshPath, exshPath, rcPath, NULL);
                execErr = errno;
            }
            fprintf(stderr, "init: failed to exec '%s': %s\n", rcPath, strerror(execErr));
            _exit(127);
        } else if (pid > 0) {
            /* A single waitpid(pid, ...) here only ever reaps rc itself --
             * for the entire time rc is running (which for an interactive
             * session can be the whole guest lifetime), any orphaned or
             * double-forked background process reparented to us as PID 1
             * would accumulate as an unreaped zombie, since nothing else
             * in this init calls wait() until final shutdown.
             *
             * waitpid(-1, ...) blocks until ANY child changes state and
             * reaps it, whichever child that is -- looping on that instead
             * of targeting `pid` directly means every orphan that exits
             * while rc runs gets reaped as it happens, with no signal
             * handler needed. We keep looping past any non-rc child until
             * we see rc's own pid, at which point we've both reaped rc and
             * captured its exit status for the log message below. */
            int rcStatus = 0;
            bool haveRcStatus = false;
            for (;;) {
                int status = 0;
                pid_t reaped = waitpid(-1, &status, 0);
                if (reaped < 0) {
                    if (errno == EINTR) {
                        continue;
                    }
                    fprintf(stderr, "init: waitpid(%s) failed: %s\n", rcPath, strerror(errno));
                    break;
                }
                if (reaped == pid) {
                    rcStatus = status;
                    haveRcStatus = true;
                    break;
                }
                /* Some other reparented child exited -- reaped and
                 * discarded; keep waiting for rc specifically. */
            }
            if (haveRcStatus && (!WIFEXITED(rcStatus) || WEXITSTATUS(rcStatus) != 0)) {
                if (WIFEXITED(rcStatus)) {
                    fprintf(stderr, "init: %s exited with status %d\n",
                            rcPath, WEXITSTATUS(rcStatus));
                } else if (WIFSIGNALED(rcStatus)) {
                    fprintf(stderr, "init: %s terminated by signal %d\n",
                            rcPath, WTERMSIG(rcStatus));
                }
            }
        } else {
            fprintf(stderr, "init: fork failed for %s: %s\n", rcPath, strerror(errno));
        }
    } else {
        const char *etcRoot = getenv("PSCALI_ETC_ROOT");
        if (etcRoot && etcRoot[0] == '/') {
            printf("smallclue init: rc not found (checked %s/rc and /etc/rc)\n",
                   etcRoot);
        } else {
            printf("smallclue init: /etc/rc not found\n");
        }
    }

    /* Ignore signals that might terminate us */
    signal(SIGTERM, SIG_IGN);
    signal(SIGINT, SIG_IGN);
    signal(SIGTSTP, SIG_IGN);
    signal(SIGQUIT, SIG_IGN);

    if (getpid() == 1) {
        printf("smallclue init: rc exited, shutting down...\n");
        kill(-1, SIGTERM);
        sleep(1);
        kill(-1, SIGKILL);
    }
    return 0;
}


static int smallclueMdevCommand(int argc, char **argv) {
    int scan = 0;
    smallclueResetGetopt();
    int opt;
    while ((opt = getopt(argc, argv, "s")) != -1) {
        if (opt == 's') {
            scan = 1;
        } else {
            fprintf(stderr, "usage: mdev [-s]\n");
            return 1;
        }
    }

    if (scan) {
        printf("mdev: scanning /sys...\n");
        // In a real implementation, we would traverse /sys and populate /dev.
        // For SmallClue/iOS, devices are typically static or virtualized.
        return 0;
    }

    // mdev hotplug mode (called by kernel)
    // Needs environment variables like ACTION, DEVPATH, SUBSYSTEM.
    const char *action = getenv("ACTION");
    const char *devpath = getenv("DEVPATH");
    if (action && devpath) {
        printf("mdev: action=%s devpath=%s\n", action, devpath);
    } else {
        fprintf(stderr, "mdev: missing ACTION or DEVPATH env\n");
        return 1;
    }


    return 0;
}

static int smallclueRunitCommand(int argc, char **argv) {
    (void)argc;
    (void)argv;

    // Minimal runit implementation:
    // Scans /etc/service (or arg) and spawns 'run' scripts.
    // Does not implement full supervision (restart, control).

    char default_service_dir[PATH_MAX];
    const char *service_dir = "/etc/service";
    if (argc > 1) {
        service_dir = argv[1];
    } else if (smallclueResolveEtcEntry("service", R_OK,
                                        default_service_dir,
                                        sizeof(default_service_dir))) {
        service_dir = default_service_dir;
    }

    DIR *dir = opendir(service_dir);
    if (!dir) {
        fprintf(stderr, "runit: cannot open service directory '%s': %s\n", service_dir, strerror(errno));
        return 1;
    }

    printf("runit: starting services in %s\n", service_dir);

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_name[0] == '.') continue;

        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s/run", service_dir, entry->d_name);

        if (access(path, X_OK) == 0) {
            printf("runit: starting %s\n", entry->d_name);
            pid_t pid = fork();
            if (pid == 0) {
                execl(path, path, NULL);
                fprintf(stderr, "runit: failed to exec %s: %s\n", path, strerror(errno));
                exit(127);
            }
        }
    }
    closedir(dir);

    // Reap children
    while (1) {
        int status;
        pid_t pid = wait(&status);
        if (pid < 0) {
            if (errno == ECHILD) {
                // No children left, sleep to avoid busy loop
                sleep(1);
            }
            continue;
        }
    }
    return 0;
}

static int smallclueHaltCommand(int argc, char **argv) {
    int force = 0;
    smallclueResetGetopt();
    int opt;
    while ((opt = getopt(argc, argv, "f")) != -1) {
        if (opt == 'f') force = 1;
    }

    const char *cmd = "halt";
    if (argc > 0) cmd = argv[0];

    printf("System %s requested%s...\n", cmd, force ? " (forced)" : "");

    // On a real system, we would signal init (PID 1).
    // kill(1, SIGTERM);

#if defined(PSCAL_TARGET_IOS)
    // On iOS/PSCAL, we can just exit the shell runtime.
    exit(0);
#else
    // On Linux, invoke reboot() syscall if we are root/init?
    // For now, just exit.
    exit(0);
#endif

    return 0;
}
