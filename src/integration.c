#include "smallclue.h"

#include "backend_ast/builtin.h"
#include "core/utils.h"
#include "vm/vm.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <setjmp.h>

#if defined(PSCAL_TARGET_IOS)
#include "ios/vproc.h"
#endif

#if defined(PSCAL_TARGET_IOS)
#if defined(__APPLE__)
extern jmp_buf *PSCALRuntimeSwapExitJumpBuffer(jmp_buf *buffer) __attribute__((weak_import));
extern int PSCALRuntimePushExitOverride(jmp_buf *buffer) __attribute__((weak_import));
extern void PSCALRuntimePopExitOverride(void) __attribute__((weak_import));
extern int PSCALRuntimePushExitOverrideWithStatus(jmp_buf *buffer, volatile int *status_out) __attribute__((weak_import));
extern void PSCALRuntimePopExitOverrideWithStatus(void) __attribute__((weak_import));
#else
extern jmp_buf *PSCALRuntimeSwapExitJumpBuffer(jmp_buf *buffer) __attribute__((weak));
extern int PSCALRuntimePushExitOverride(jmp_buf *buffer) __attribute__((weak));
extern void PSCALRuntimePopExitOverride(void) __attribute__((weak));
extern int PSCALRuntimePushExitOverrideWithStatus(jmp_buf *buffer, volatile int *status_out) __attribute__((weak));
extern void PSCALRuntimePopExitOverrideWithStatus(void) __attribute__((weak));
#endif
/* Provide weak fallbacks so standalone smallclue builds without the runtime
 * bridge still link cleanly on iOS. The real runtime implementation overrides
 * these when available. */
__attribute__((weak))
jmp_buf *PSCALRuntimeSwapExitJumpBuffer(jmp_buf *buffer) {
    (void)buffer;
    return NULL;
}
__attribute__((weak))
int PSCALRuntimePushExitOverride(jmp_buf *buffer) {
    (void)buffer;
    return -1;
}
__attribute__((weak))
void PSCALRuntimePopExitOverride(void) {
}
__attribute__((weak))
int PSCALRuntimePushExitOverrideWithStatus(jmp_buf *buffer, volatile int *status_out) {
    (void)buffer;
    (void)status_out;
    return -1;
}
__attribute__((weak))
void PSCALRuntimePopExitOverrideWithStatus(void) {
}
#endif

#if defined(__APPLE__)
extern void shellRuntimeSetLastStatus(int status) __attribute__((weak_import));
#elif defined(__GNUC__)
extern void shellRuntimeSetLastStatus(int status) __attribute__((weak));
#else
void shellRuntimeSetLastStatus(int status);
#endif

static char *smallclueDuplicateArg(const Value *value) {
    if (!value) {
        return strdup("");
    }
    if (value->type == TYPE_STRING && value->s_val) {
        return strdup(value->s_val);
    }
    if (IS_INTLIKE(*value)) {
        char buf[32];
        snprintf(buf, sizeof(buf), "%lld", (long long)AS_INTEGER(*value));
        return strdup(buf);
    }
    if (isRealType(value->type)) {
        char buf[64];
        long double real = AS_REAL(*value);
        snprintf(buf, sizeof(buf), "%.17Lg", real);
        return strdup(buf);
    }
    return strdup("");
}

static void smallclueFormatLabel(int argc, char **argv, char *out, size_t out_sz) {
    if (!out || out_sz == 0) {
        return;
    }
    out[0] = '\0';
    if (!argv || argc <= 0) {
        return;
    }
    size_t used = 0;
    for (int i = 0; i < argc && used + 1 < out_sz; ++i) {
        const char *part = argv[i] ? argv[i] : "";
        size_t len = strlen(part);
        if (used + len + 1 >= out_sz) {
            len = out_sz - used - 1;
        }
        memcpy(out + used, part, len);
        used += len;
        if (used + 1 < out_sz && i + 1 < argc) {
            out[used++] = ' ';
        }
    }
    out[used] = '\0';
}

static Value smallclueInvokeBuiltin(VM *vm, int arg_count, Value *args, const char *name) {
    const SmallclueApplet *applet = smallclueFindApplet(name);
    if (!applet) {
        if (shellRuntimeSetLastStatus) {
            shellRuntimeSetLastStatus(127);
        }
        return makeVoid();
    }

    int arg_start = 0;
    if (arg_count > 0 && args[0].type == TYPE_STRING && args[0].s_val) {
        if (strcasecmp(args[0].s_val, applet->name) == 0) {
            arg_start = 1;
        }
    }
    int argc = (arg_count - arg_start) + 1;
    if (argc < 1) {
        argc = 1;
    }
    char **argv = (char **)calloc((size_t)(argc + 1), sizeof(char *));
    if (!argv) {
        if (shellRuntimeSetLastStatus) {
            shellRuntimeSetLastStatus(1);
        }
        return makeVoid();
    }

    bool ok = true;
    argv[0] = strdup(applet->name);
    if (!argv[0]) {
        ok = false;
    }
    for (int i = arg_start; ok && i < arg_count; ++i) {
        argv[(i - arg_start) + 1] = smallclueDuplicateArg(&args[i]);
        if (!argv[i + 1]) {
            ok = false;
        }
    }

    const char *debug_env = getenv("SMALLCLUE_DEBUG_ARGS");
    if (debug_env && *debug_env) {
        fprintf(stderr, "[smallclue] %s argc=%d\n", applet->name, argc);
        for (int i = 0; i < argc; ++i) {
            fprintf(stderr, "  argv[%d]=%s\n", i, argv[i] ? argv[i] : "(null)");
        }
    }

    int status = 1;
    if (ok) {
#if defined(PSCAL_TARGET_IOS)
        VProcCommandScope vproc_scope;
        bool vproc_scope_active = false;
        char label[96];
        smallclueFormatLabel(argc, argv, label, sizeof(label));
        if (label[0]) {
            vproc_scope_active = vprocCommandScopeBegin(&vproc_scope, label, false, false);
        } else {
            vproc_scope_active = vprocCommandScopeBegin(&vproc_scope, applet->name, false, false);
        }

        jmp_buf exit_env;
        volatile int exit_status_sink = 0;
        bool override_active = false;
        if (PSCALRuntimePushExitOverrideWithStatus &&
            PSCALRuntimePushExitOverrideWithStatus(&exit_env, &exit_status_sink) == 0) {
            override_active = true;
            int jump_code = setjmp(exit_env);
            if (jump_code != 0) {
                status = (jump_code == 1) ? exit_status_sink : jump_code;
                goto smallclue_dispatch_done;
            }
        } else if (PSCALRuntimePushExitOverride && PSCALRuntimePushExitOverride(&exit_env) == 0) {
            override_active = true;
            int jump_code = setjmp(exit_env);
            if (jump_code != 0) {
                status = (jump_code == 1) ? 0 : jump_code;
                goto smallclue_dispatch_done;
            }
        }
#endif
        status = smallclueDispatchApplet(applet, argc, argv);
#if defined(PSCAL_TARGET_IOS)
smallclue_dispatch_done:
        if (vproc_scope_active) {
            vprocCommandScopeEnd(&vproc_scope, status);
            vproc_scope_active = false;
        }
        if (override_active) {
            if (PSCALRuntimePopExitOverrideWithStatus) {
                PSCALRuntimePopExitOverrideWithStatus();
            } else if (PSCALRuntimePopExitOverride) {
                PSCALRuntimePopExitOverride();
            }
        }
#endif
    }
    if (shellRuntimeSetLastStatus) {
        shellRuntimeSetLastStatus(status);
    }

    for (int i = 0; i < argc; ++i) {
        free(argv[i]);
    }
    free(argv);

    (void)vm;
    return makeVoid();
}

#define DEFINE_SMALLCLUE_WRAPPER(name_literal, ident)                                        \
    static Value vmBuiltinSmallclue_##ident(VM *vm, int arg_count, Value *args) {            \
        return smallclueInvokeBuiltin(vm, arg_count, args, name_literal);                    \
    }

DEFINE_SMALLCLUE_WRAPPER("cat", cat)
DEFINE_SMALLCLUE_WRAPPER("clear", clear)
DEFINE_SMALLCLUE_WRAPPER("cls", cls)
DEFINE_SMALLCLUE_WRAPPER("date", date)
DEFINE_SMALLCLUE_WRAPPER("cal", cal)
DEFINE_SMALLCLUE_WRAPPER("head", head)
DEFINE_SMALLCLUE_WRAPPER("tail", tail)
DEFINE_SMALLCLUE_WRAPPER("touch", touch)
DEFINE_SMALLCLUE_WRAPPER("grep", grep)
DEFINE_SMALLCLUE_WRAPPER("wc", wc)
DEFINE_SMALLCLUE_WRAPPER("du", du)
DEFINE_SMALLCLUE_WRAPPER("find", find)
DEFINE_SMALLCLUE_WRAPPER("stty", stty)
DEFINE_SMALLCLUE_WRAPPER("resize", resize)
DEFINE_SMALLCLUE_WRAPPER("sort", sort)
DEFINE_SMALLCLUE_WRAPPER("uniq", uniq)
DEFINE_SMALLCLUE_WRAPPER("sed", sed)
DEFINE_SMALLCLUE_WRAPPER("cut", cut)
DEFINE_SMALLCLUE_WRAPPER("curl", curl)
DEFINE_SMALLCLUE_WRAPPER("tr", tr)
DEFINE_SMALLCLUE_WRAPPER("id", id)
DEFINE_SMALLCLUE_WRAPPER("pbcopy", pbcopy)
DEFINE_SMALLCLUE_WRAPPER("pbpaste", pbpaste)
#if SMALLCLUE_HAS_IFADDRS
DEFINE_SMALLCLUE_WRAPPER("ipaddr", ipaddr)
#endif
DEFINE_SMALLCLUE_WRAPPER("df", df)
DEFINE_SMALLCLUE_WRAPPER("pwd", pwd)
DEFINE_SMALLCLUE_WRAPPER("chmod", chmod)
DEFINE_SMALLCLUE_WRAPPER("true", truecmd)
DEFINE_SMALLCLUE_WRAPPER("false", falsecmd)
DEFINE_SMALLCLUE_WRAPPER("yes", yes)
DEFINE_SMALLCLUE_WRAPPER("no", no)
DEFINE_SMALLCLUE_WRAPPER("version", version)
DEFINE_SMALLCLUE_WRAPPER("sleep", sleepcmd)
DEFINE_SMALLCLUE_WRAPPER("basename", basename)
DEFINE_SMALLCLUE_WRAPPER("dirname", dirname)
DEFINE_SMALLCLUE_WRAPPER("tee", tee)
DEFINE_SMALLCLUE_WRAPPER("test", testcmd)
DEFINE_SMALLCLUE_WRAPPER("[", bracket)
DEFINE_SMALLCLUE_WRAPPER("xargs", xargs)
DEFINE_SMALLCLUE_WRAPPER("ps", ps)
DEFINE_SMALLCLUE_WRAPPER("kill", kill)
#if defined(SMALLCLUE_WITH_EXSH)
DEFINE_SMALLCLUE_WRAPPER("sh", sh)
#endif
DEFINE_SMALLCLUE_WRAPPER("uptime", uptime)
DEFINE_SMALLCLUE_WRAPPER("file", file)
DEFINE_SMALLCLUE_WRAPPER("scp", scp)
DEFINE_SMALLCLUE_WRAPPER("sftp", sftp)
DEFINE_SMALLCLUE_WRAPPER("script", script)
DEFINE_SMALLCLUE_WRAPPER("ssh", ssh)
DEFINE_SMALLCLUE_WRAPPER("ssh-keygen", sshkeygen)
#if defined(PSCAL_TARGET_IOS)
DEFINE_SMALLCLUE_WRAPPER("mkdir", mkdir)
DEFINE_SMALLCLUE_WRAPPER("cp", cp)
DEFINE_SMALLCLUE_WRAPPER("mv", mv)
DEFINE_SMALLCLUE_WRAPPER("rm", rm)
DEFINE_SMALLCLUE_WRAPPER("rmdir", rmdir)
DEFINE_SMALLCLUE_WRAPPER("ln", ln)
DEFINE_SMALLCLUE_WRAPPER("ping", ping)
DEFINE_SMALLCLUE_WRAPPER("env", env)
DEFINE_SMALLCLUE_WRAPPER("telnet", telnet)
DEFINE_SMALLCLUE_WRAPPER("traceroute", traceroute)
DEFINE_SMALLCLUE_WRAPPER("nslookup", nslookup)
DEFINE_SMALLCLUE_WRAPPER("host", host)
DEFINE_SMALLCLUE_WRAPPER("dmesg", dmesg)
DEFINE_SMALLCLUE_WRAPPER("licenses", licenses)
#endif
#if defined(PSCAL_TARGET_IOS)
DEFINE_SMALLCLUE_WRAPPER("nextvi", nextvi)
#endif
DEFINE_SMALLCLUE_WRAPPER("less", less)
DEFINE_SMALLCLUE_WRAPPER("ls", ls)
DEFINE_SMALLCLUE_WRAPPER("md", md)
DEFINE_SMALLCLUE_WRAPPER("wget", wget)
DEFINE_SMALLCLUE_WRAPPER("watch", watch)
DEFINE_SMALLCLUE_WRAPPER("more", more)
#if defined(PSCAL_TARGET_IOS)
DEFINE_SMALLCLUE_WRAPPER("smallclue-help", smallclue_help)
#endif

#undef DEFINE_SMALLCLUE_WRAPPER

static pthread_once_t g_smallclue_builtin_once = PTHREAD_ONCE_INIT;

static void registerSmallclueBuiltin(const char *name,
                                     VmBuiltinFn handler,
                                     const char *display_name) {
    VmBuiltinFn existing = getVmBuiltinHandler(name);
    if (existing != NULL) {
        /* Preserve any existing handler (e.g., shell builtins); only register when missing. */
        return;
    }
    registerVmBuiltin(name, handler, BUILTIN_TYPE_PROCEDURE, display_name);
}

static void smallclueRegisterBuiltinsOnce(void) {
    registerSmallclueBuiltin("cat", vmBuiltinSmallclue_cat, "cat");
    registerSmallclueBuiltin("ls", vmBuiltinSmallclue_ls, "ls");
    registerSmallclueBuiltin("md", vmBuiltinSmallclue_md, "md");
    registerSmallclueBuiltin("less", vmBuiltinSmallclue_less, "less");
    registerSmallclueBuiltin("more", vmBuiltinSmallclue_more, "more");
    registerSmallclueBuiltin("clear", vmBuiltinSmallclue_clear, "clear");
    registerSmallclueBuiltin("cls", vmBuiltinSmallclue_cls, "cls");
    registerSmallclueBuiltin("date", vmBuiltinSmallclue_date, "date");
    registerSmallclueBuiltin("cal", vmBuiltinSmallclue_cal, "cal");
    registerSmallclueBuiltin("head", vmBuiltinSmallclue_head, "head");
    registerSmallclueBuiltin("tail", vmBuiltinSmallclue_tail, "tail");
    registerSmallclueBuiltin("touch", vmBuiltinSmallclue_touch, "touch");
    registerSmallclueBuiltin("grep", vmBuiltinSmallclue_grep, "grep");
    registerSmallclueBuiltin("wc", vmBuiltinSmallclue_wc, "wc");
    registerSmallclueBuiltin("du", vmBuiltinSmallclue_du, "du");
    registerSmallclueBuiltin("find", vmBuiltinSmallclue_find, "find");
    registerSmallclueBuiltin("stty", vmBuiltinSmallclue_stty, "stty");
    registerSmallclueBuiltin("resize", vmBuiltinSmallclue_resize, "resize");
    registerSmallclueBuiltin("sort", vmBuiltinSmallclue_sort, "sort");
    registerSmallclueBuiltin("uniq", vmBuiltinSmallclue_uniq, "uniq");
    registerSmallclueBuiltin("sed", vmBuiltinSmallclue_sed, "sed");
    registerSmallclueBuiltin("cut", vmBuiltinSmallclue_cut, "cut");
    registerSmallclueBuiltin("curl", vmBuiltinSmallclue_curl, "curl");
    registerSmallclueBuiltin("tr", vmBuiltinSmallclue_tr, "tr");
    registerSmallclueBuiltin("id", vmBuiltinSmallclue_id, "id");
    registerSmallclueBuiltin("pbcopy", vmBuiltinSmallclue_pbcopy, "pbcopy");
    registerSmallclueBuiltin("pbpaste", vmBuiltinSmallclue_pbpaste, "pbpaste");
#if SMALLCLUE_HAS_IFADDRS
    registerSmallclueBuiltin("ipaddr", vmBuiltinSmallclue_ipaddr, "ipaddr");
#endif
    registerSmallclueBuiltin("df", vmBuiltinSmallclue_df, "df");
    registerSmallclueBuiltin("file", vmBuiltinSmallclue_file, "file");
    registerSmallclueBuiltin("pwd", vmBuiltinSmallclue_pwd, "pwd");
    registerSmallclueBuiltin("chmod", vmBuiltinSmallclue_chmod, "chmod");
    registerSmallclueBuiltin("true", vmBuiltinSmallclue_truecmd, "true");
    registerSmallclueBuiltin("false", vmBuiltinSmallclue_falsecmd, "false");
    registerSmallclueBuiltin("yes", vmBuiltinSmallclue_yes, "yes");
    registerSmallclueBuiltin("no", vmBuiltinSmallclue_no, "no");
    registerSmallclueBuiltin("sleep", vmBuiltinSmallclue_sleepcmd, "sleep");
    registerSmallclueBuiltin("basename", vmBuiltinSmallclue_basename, "basename");
    registerSmallclueBuiltin("dirname", vmBuiltinSmallclue_dirname, "dirname");
    registerSmallclueBuiltin("tee", vmBuiltinSmallclue_tee, "tee");
    registerSmallclueBuiltin("test", vmBuiltinSmallclue_testcmd, "test");
    registerSmallclueBuiltin("[", vmBuiltinSmallclue_bracket, "[");
    registerSmallclueBuiltin("xargs", vmBuiltinSmallclue_xargs, "xargs");
    registerSmallclueBuiltin("ps", vmBuiltinSmallclue_ps, "ps");
    registerSmallclueBuiltin("kill", vmBuiltinSmallclue_kill, "kill");
#if defined(SMALLCLUE_WITH_EXSH)
    registerSmallclueBuiltin("sh", vmBuiltinSmallclue_sh, "sh");
#endif
    registerSmallclueBuiltin("uptime", vmBuiltinSmallclue_uptime, "uptime");
    registerSmallclueBuiltin("scp", vmBuiltinSmallclue_scp, "scp");
    registerSmallclueBuiltin("sftp", vmBuiltinSmallclue_sftp, "sftp");
    registerSmallclueBuiltin("ssh", vmBuiltinSmallclue_ssh, "ssh");
    registerSmallclueBuiltin("ssh-keygen", vmBuiltinSmallclue_sshkeygen, "ssh-keygen");
#if defined(PSCAL_TARGET_IOS)
    registerSmallclueBuiltin("mkdir", vmBuiltinSmallclue_mkdir, "mkdir");
    registerSmallclueBuiltin("cp", vmBuiltinSmallclue_cp, "cp");
    registerSmallclueBuiltin("mv", vmBuiltinSmallclue_mv, "mv");
    registerSmallclueBuiltin("rm", vmBuiltinSmallclue_rm, "rm");
    registerSmallclueBuiltin("rmdir", vmBuiltinSmallclue_rmdir, "rmdir");
    registerSmallclueBuiltin("ln", vmBuiltinSmallclue_ln, "ln");
    registerSmallclueBuiltin("ls", vmBuiltinSmallclue_ls, "ls"); /* critical: keep smallclue ls available on iOS */
    registerSmallclueBuiltin("ping", vmBuiltinSmallclue_ping, "ping");
    registerSmallclueBuiltin("env", vmBuiltinSmallclue_env, "env");
    registerSmallclueBuiltin("telnet", vmBuiltinSmallclue_telnet, "telnet");
    registerSmallclueBuiltin("traceroute", vmBuiltinSmallclue_traceroute, "traceroute");
    registerSmallclueBuiltin("nslookup", vmBuiltinSmallclue_nslookup, "nslookup");
    registerSmallclueBuiltin("host", vmBuiltinSmallclue_host, "host");
    registerSmallclueBuiltin("script", vmBuiltinSmallclue_script, "script");
    registerSmallclueBuiltin("nextvi", vmBuiltinSmallclue_nextvi, "nextvi");
    registerSmallclueBuiltin("vi", vmBuiltinSmallclue_nextvi, "vi");
    registerSmallclueBuiltin("dmesg", vmBuiltinSmallclue_dmesg, "dmesg");
    registerSmallclueBuiltin("licenses", vmBuiltinSmallclue_licenses, "licenses");
#endif
    registerSmallclueBuiltin("wget", vmBuiltinSmallclue_wget, "wget");
    registerSmallclueBuiltin("watch", vmBuiltinSmallclue_watch, "watch");
    registerSmallclueBuiltin("version", vmBuiltinSmallclue_version, "version");
#if defined(PSCAL_TARGET_IOS)
    registerSmallclueBuiltin("smallclue-help", vmBuiltinSmallclue_smallclue_help, "smallclue-help");
#endif
}

void smallclueRegisterBuiltins(void) {
    pthread_once(&g_smallclue_builtin_once, smallclueRegisterBuiltinsOnce);
}
