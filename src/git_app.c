#include "smallclue.h"
#include "common/path_truncate.h"

#include <ctype.h>
#include <errno.h>
#include <fnmatch.h>
#include <limits.h>
#include <regex.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

#if defined(PSCAL_HAS_LIBGIT2)
#include <git2.h>
#endif

typedef enum SmallclueGitDiffMode {
    SMALLCLUE_GIT_DIFF_PATCH = 0,
    SMALLCLUE_GIT_DIFF_NAME_ONLY,
    SMALLCLUE_GIT_DIFF_NAME_STATUS,
    SMALLCLUE_GIT_DIFF_STAT,
} SmallclueGitDiffMode;

typedef struct SmallclueGitGlobalOptions {
    const char *start_path;
} SmallclueGitGlobalOptions;

static int smallclueGitPrintUsage(void) {
    fputs("usage: git [-C path] [--no-pager] [-c key=value] <subcommand> [args...]\n", stderr);
    return 2;
}

static void smallclueGitPrintError(const char *message) {
    if (!message) {
        message = "error";
    }
    fprintf(stderr, "git: %s\n", message);
}

#if !defined(PSCAL_HAS_LIBGIT2)
int smallclueGitCommand(int argc, char **argv) {
    (void)argc;
    (void)argv;
    smallclueGitPrintError("libgit2 support is not enabled in this build");
    return 1;
}
#else

static void smallclueGitPrintLibgitError(const char *prefix) {
    const git_error *err = git_error_last();
    if (err && err->message && *err->message) {
        if (prefix && *prefix) {
            fprintf(stderr, "git: %s: %s\n", prefix, err->message);
        } else {
            fprintf(stderr, "git: %s\n", err->message);
        }
        return;
    }
    if (prefix && *prefix) {
        fprintf(stderr, "git: %s\n", prefix);
    } else {
        fprintf(stderr, "git: unknown libgit2 error\n");
    }
}

static int smallclueGitOidShort(const git_oid *oid, size_t width, char *out, size_t out_sz) {
    if (!oid || !out || out_sz == 0) {
        return -1;
    }
    if (width == 0) {
        width = 7;
    }
    if (width >= out_sz) {
        width = out_sz - 1;
    }
    if (width > GIT_OID_HEXSZ) {
        width = GIT_OID_HEXSZ;
    }
    char full[GIT_OID_HEXSZ + 1];
    if (!git_oid_tostr(full, sizeof(full), oid)) {
        return -1;
    }
    memcpy(out, full, width);
    out[width] = '\0';
    return 0;
}

static const char *smallclueGitCommitSubject(const git_commit *commit) {
    if (!commit) {
        return "";
    }
    const char *msg = git_commit_message(commit);
    if (!msg) {
        return "";
    }
    while (*msg == '\n' || *msg == '\r') {
        msg++;
    }
    return msg;
}

static size_t smallclueGitCopySubjectLine(const char *message, char *out, size_t out_sz) {
    if (!out || out_sz == 0) {
        return 0;
    }
    out[0] = '\0';
    if (!message) {
        return 0;
    }
    size_t i = 0;
    while (message[i] && message[i] != '\n' && message[i] != '\r' && i + 1 < out_sz) {
        out[i] = message[i];
        i++;
    }
    out[i] = '\0';
    return i;
}

static int smallclueGitOpenRepository(const char *start_path, git_repository **out_repo) {
    if (!out_repo) {
        return -1;
    }
    *out_repo = NULL;
    const char *path = (start_path && *start_path) ? start_path : ".";
    if (git_repository_open_ext(out_repo, path, GIT_REPOSITORY_OPEN_CROSS_FS, NULL) != 0) {
        return -1;
    }
    return 0;
}

static int smallclueGitCopyPath(const char *src, char *out, size_t out_sz) {
    if (!src || !out || out_sz == 0) {
        return -1;
    }
    int n = snprintf(out, out_sz, "%s", src);
    return (n >= 0 && (size_t)n < out_sz) ? 0 : -1;
}

static int smallclueGitDisplayPath(const char *path, char *out, size_t out_sz) {
    if (!path || !out || out_sz == 0) {
        return -1;
    }
#if defined(PSCAL_TARGET_IOS)
    char stripped[PATH_MAX];
    if (pathTruncateStrip(path, stripped, sizeof(stripped))) {
        return smallclueGitCopyPath(stripped, out, out_sz);
    }
#endif
    return smallclueGitCopyPath(path, out, out_sz);
}

static int smallclueGitResolvePathFromBase(const char *base_path,
                                           const char *input_path,
                                           char *out,
                                           size_t out_sz) {
    if (!base_path || !*base_path || !out || out_sz == 0) {
        return -1;
    }

    char candidate[PATH_MAX];
    if (!input_path || !*input_path) {
        if (smallclueGitCopyPath(base_path, candidate, sizeof(candidate)) != 0) {
            return -1;
        }
    } else if (input_path[0] == '/') {
        if (smallclueGitCopyPath(input_path, candidate, sizeof(candidate)) != 0) {
            return -1;
        }
    } else {
        int n = snprintf(candidate, sizeof(candidate), "%s/%s", base_path, input_path);
        if (n < 0 || (size_t)n >= sizeof(candidate)) {
            return -1;
        }
    }

#if defined(PSCAL_TARGET_IOS)
    char expanded[PATH_MAX];
    if (!pathTruncateExpand(candidate, expanded, sizeof(expanded))) {
        return -1;
    }
    return smallclueGitCopyPath(expanded, out, out_sz);
#else
    return smallclueGitCopyPath(candidate, out, out_sz);
#endif
}

static int smallclueGitResolveStartPath(const SmallclueGitGlobalOptions *opts,
                                        char *out,
                                        size_t out_sz) {
    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof(cwd))) {
        return -1;
    }
    const char *start = (opts && opts->start_path && *opts->start_path) ? opts->start_path : NULL;
    return smallclueGitResolvePathFromBase(cwd, start, out, out_sz);
}

static int smallclueGitParseGlobalOptions(int argc,
                                          char **argv,
                                          SmallclueGitGlobalOptions *opts,
                                          int *out_subcmd_index) {
    if (!opts || !out_subcmd_index) {
        return -1;
    }
    opts->start_path = NULL;

    int i = 1;
    while (i < argc) {
        const char *arg = argv[i];
        if (!arg || *arg == '\0') {
            i++;
            continue;
        }
        if (strcmp(arg, "--") == 0) {
            i++;
            break;
        }
        if (strcmp(arg, "-C") == 0) {
            if (i + 1 >= argc) {
                smallclueGitPrintError("option '-C' requires a path argument");
                return -1;
            }
            opts->start_path = argv[i + 1];
            i += 2;
            continue;
        }
        if (strncmp(arg, "-C", 2) == 0 && arg[2] != '\0') {
            opts->start_path = arg + 2;
            i++;
            continue;
        }
        if (strcmp(arg, "--no-pager") == 0) {
            i++;
            continue;
        }
        if (strcmp(arg, "-c") == 0) {
            if (i + 1 >= argc) {
                smallclueGitPrintError("option '-c' requires a key=value argument");
                return -1;
            }
            i += 2;
            continue;
        }
        if (strncmp(arg, "-c", 2) == 0 && arg[2] != '\0') {
            i++;
            continue;
        }
        break;
    }

    *out_subcmd_index = i;
    return 0;
}

static const char *smallclueGitStatusPath(const git_status_entry *entry);
static int smallclueGitResolveCommit(git_repository *repo, const char *spec, git_commit **out_commit);

typedef struct SmallclueGitConfigValueList {
    char **items;
    size_t count;
    size_t cap;
} SmallclueGitConfigValueList;

typedef struct SmallclueGitConfigFilterContext {
    const char *match_pattern;
    bool use_regex;
    regex_t regex;
    bool regex_ready;
    SmallclueGitConfigValueList kept;
    bool removed_any;
    bool oom;
} SmallclueGitConfigFilterContext;

static void smallclueGitConfigValueListFree(SmallclueGitConfigValueList *list) {
    if (!list) {
        return;
    }
    for (size_t i = 0; i < list->count; ++i) {
        free(list->items[i]);
    }
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->cap = 0;
}

static int smallclueGitConfigValueListAppend(SmallclueGitConfigValueList *list, const char *value) {
    if (!list || !value) {
        return -1;
    }
    if (list->count == list->cap) {
        size_t next_cap = (list->cap == 0) ? 8 : (list->cap * 2);
        char **next_items = (char **)realloc(list->items, next_cap * sizeof(char *));
        if (!next_items) {
            return -1;
        }
        list->items = next_items;
        list->cap = next_cap;
    }
    char *dup = strdup(value);
    if (!dup) {
        return -1;
    }
    list->items[list->count++] = dup;
    return 0;
}

static int smallclueGitConfigFilterCollect(const git_config_entry *entry, void *payload) {
    SmallclueGitConfigFilterContext *ctx = (SmallclueGitConfigFilterContext *)payload;
    if (!ctx || !entry || !entry->value) {
        return 0;
    }
    bool matched = false;
    if (ctx->match_pattern && *ctx->match_pattern) {
        if (ctx->use_regex && ctx->regex_ready) {
            matched = (regexec(&ctx->regex, entry->value, 0, NULL, 0) == 0);
        } else {
            matched = (strcmp(entry->value, ctx->match_pattern) == 0);
        }
    }
    if (matched) {
        ctx->removed_any = true;
        return 0;
    }
    if (smallclueGitConfigValueListAppend(&ctx->kept, entry->value) != 0) {
        ctx->oom = true;
        return -1;
    }
    return 0;
}

static int smallclueGitConfigAppendValue(git_config *cfg, const char *key, const char *value) {
    if (!cfg || !key || !*key || !value) {
        return -1;
    }
    return git_config_set_multivar(cfg, key, "$^", value);
}

static int smallclueGitConfigCollectValue(const git_config_entry *entry, void *payload) {
    SmallclueGitConfigValueList *list = (SmallclueGitConfigValueList *)payload;
    if (!list || !entry) {
        return 0;
    }
    const char *value = entry->value ? entry->value : "";
    if (smallclueGitConfigValueListAppend(list, value) != 0) {
        return -1;
    }
    return 0;
}

/*
 * Reads all values for a config key.
 * Returns:
 *   0 on success with one or more values in list,
 *   1 when key is missing,
 *  -1 on hard failure.
 */
static int smallclueGitConfigReadValues(git_config *cfg,
                                        const char *key,
                                        SmallclueGitConfigValueList *list) {
    if (!cfg || !key || !*key || !list) {
        return -1;
    }
    memset(list, 0, sizeof(*list));
    int rc = git_config_get_multivar_foreach(cfg, key, NULL, smallclueGitConfigCollectValue, list);
    if (rc == GIT_ENOTFOUND) {
        return 1;
    }
    if (rc != 0) {
        smallclueGitConfigValueListFree(list);
        return -1;
    }
    return 0;
}

/*
 * Removes exactly one matching value for a key.
 * - with regex=true, match_expr is treated as POSIX extended regex.
 * - with regex=false and match_expr non-null, requires exact string match.
 * - with regex=false and match_expr null/empty, matches any value.
 * Returns:
 *   0 on success (one value removed),
 *   1 when no value matched / key missing,
 *   2 when multiple values match (ambiguous),
 *  -1 on hard failure.
 */
static int smallclueGitConfigDeleteSingleMatchingValue(git_config *cfg,
                                                       const char *key,
                                                       const char *match_expr,
                                                       bool regex) {
    if (!cfg || !key || !*key) {
        return -1;
    }

    SmallclueGitConfigValueList values;
    int read_rc = smallclueGitConfigReadValues(cfg, key, &values);
    if (read_rc != 0) {
        return read_rc;
    }

    int match_count = 0;
    size_t match_index = 0;
    regex_t reg;
    bool reg_ready = false;
    if (regex && match_expr && *match_expr) {
        if (regcomp(&reg, match_expr, REG_EXTENDED) != 0) {
            smallclueGitConfigValueListFree(&values);
            return -1;
        }
        reg_ready = true;
    }

    for (size_t i = 0; i < values.count; ++i) {
        const char *candidate = values.items[i] ? values.items[i] : "";
        bool matched = false;
        if (!match_expr || !*match_expr) {
            matched = true;
        } else if (regex) {
            matched = reg_ready && (regexec(&reg, candidate, 0, NULL, 0) == 0);
        } else {
            matched = (strcmp(candidate, match_expr) == 0);
        }
        if (matched) {
            match_index = i;
            match_count++;
        }
    }

    if (reg_ready) {
        regfree(&reg);
    }

    if (match_count == 0) {
        smallclueGitConfigValueListFree(&values);
        return 1;
    }
    if (match_count > 1) {
        smallclueGitConfigValueListFree(&values);
        return 2;
    }

    int rc = git_config_delete_multivar(cfg, key, ".*");
    if (rc != 0 && rc != GIT_ENOTFOUND) {
        smallclueGitConfigValueListFree(&values);
        return -1;
    }
    for (size_t i = 0; i < values.count; ++i) {
        if (i == match_index) {
            continue;
        }
        if (smallclueGitConfigAppendValue(cfg, key, values.items[i] ? values.items[i] : "") != 0) {
            smallclueGitConfigValueListFree(&values);
            return -1;
        }
    }

    smallclueGitConfigValueListFree(&values);
    return 0;
}

/*
 * Removes all matching values for a multivar key while preserving other values.
 * The match expression is treated as a POSIX extended regex when use_regex=true.
 * Returns:
 *   0 on success (at least one value removed),
 *   1 when no matching value exists,
 *  -1 on hard failure.
 */
static int smallclueGitConfigDeleteMatchingValue(git_config *cfg,
                                                 const char *key,
                                                 const char *match_expr,
                                                 bool use_regex) {
    if (!cfg || !key || !*key || !match_expr || !*match_expr) {
        return -1;
    }

    SmallclueGitConfigFilterContext ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.match_pattern = match_expr;
    ctx.use_regex = use_regex;
    if (ctx.use_regex) {
        if (regcomp(&ctx.regex, match_expr, REG_EXTENDED) != 0) {
            return -1;
        }
        ctx.regex_ready = true;
    }

    int rc = git_config_get_multivar_foreach(cfg, key, NULL, smallclueGitConfigFilterCollect, &ctx);
    if (rc == GIT_ENOTFOUND) {
        if (ctx.regex_ready) {
            regfree(&ctx.regex);
        }
        smallclueGitConfigValueListFree(&ctx.kept);
        return 1;
    }
    if (rc != 0 || ctx.oom) {
        if (ctx.regex_ready) {
            regfree(&ctx.regex);
        }
        smallclueGitConfigValueListFree(&ctx.kept);
        return -1;
    }
    if (!ctx.removed_any) {
        if (ctx.regex_ready) {
            regfree(&ctx.regex);
        }
        smallclueGitConfigValueListFree(&ctx.kept);
        return 1;
    }

    rc = git_config_delete_multivar(cfg, key, ".*");
    if (rc != 0 && rc != GIT_ENOTFOUND) {
        if (ctx.regex_ready) {
            regfree(&ctx.regex);
        }
        smallclueGitConfigValueListFree(&ctx.kept);
        return -1;
    }

    for (size_t i = 0; i < ctx.kept.count; ++i) {
        if (smallclueGitConfigAppendValue(cfg, key, ctx.kept.items[i]) != 0) {
            if (ctx.regex_ready) {
                regfree(&ctx.regex);
            }
            smallclueGitConfigValueListFree(&ctx.kept);
            return -1;
        }
    }

    if (ctx.regex_ready) {
        regfree(&ctx.regex);
    }
    smallclueGitConfigValueListFree(&ctx.kept);
    return 0;
}

static int smallclueGitEnsureDirPath(const char *path) {
    if (!path || !*path) {
        return -1;
    }
    char buf[PATH_MAX];
    size_t len = strlen(path);
    if (len >= sizeof(buf)) {
        return -1;
    }
    memcpy(buf, path, len + 1);
    while (len > 1 && buf[len - 1] == '/') {
        buf[len - 1] = '\0';
        len--;
    }
    for (char *p = buf + 1; *p; ++p) {
        if (*p != '/') {
            continue;
        }
        *p = '\0';
        if (mkdir(buf, 0777) != 0 && errno != EEXIST) {
            return -1;
        }
        *p = '/';
    }
    if (mkdir(buf, 0777) != 0 && errno != EEXIST) {
        return -1;
    }
    return 0;
}

static int smallclueGitCommandInit(const SmallclueGitGlobalOptions *opts,
                                   const char *start_path,
                                   int argc,
                                   char **argv) {
    (void)opts;
    const char *path_arg = NULL;
    const char *initial_branch = NULL;
    bool quiet = false;
    bool bare = false;

    for (int i = 0; i < argc; ++i) {
        const char *arg = argv[i];
        if (!arg) {
            continue;
        }
        if (strcmp(arg, "-q") == 0 || strcmp(arg, "--quiet") == 0) {
            quiet = true;
            continue;
        }
        if (strcmp(arg, "--bare") == 0) {
            bare = true;
            continue;
        }
        if ((strcmp(arg, "-b") == 0 || strcmp(arg, "--initial-branch") == 0) && i + 1 < argc) {
            initial_branch = argv[++i];
            continue;
        }
        if (strncmp(arg, "--initial-branch=", 17) == 0) {
            initial_branch = arg + 17;
            continue;
        }
        if (arg[0] == '-') {
            smallclueGitPrintError("unsupported init option");
            return 2;
        }
        if (!path_arg) {
            path_arg = arg;
            continue;
        }
        smallclueGitPrintError("too many init path arguments");
        return 2;
    }

    char target_path[PATH_MAX];
    const char *target = (start_path && *start_path) ? start_path : ".";
    if (path_arg && *path_arg) {
        if (smallclueGitResolvePathFromBase(target, path_arg, target_path, sizeof(target_path)) != 0) {
            smallclueGitPrintError("init path too long");
            return 2;
        }
        if (smallclueGitEnsureDirPath(target_path) != 0) {
            fprintf(stderr, "git: init path create failed: %s\n", strerror(errno));
            return 1;
        }
        target = target_path;
    }

    git_repository *repo = NULL;
    if (git_repository_init(&repo, target, bare ? 1 : 0) != 0 || !repo) {
        smallclueGitPrintLibgitError("init failed");
        return 1;
    }

    if (initial_branch && *initial_branch) {
        char head_path[PATH_MAX];
        const char *repo_path = git_repository_path(repo);
        if (!repo_path || !*repo_path ||
            snprintf(head_path, sizeof(head_path), "%sHEAD", repo_path) >= (int)sizeof(head_path)) {
            git_repository_free(repo);
            smallclueGitPrintError("failed to locate HEAD path");
            return 1;
        }
        FILE *fp = fopen(head_path, "w");
        if (!fp) {
            git_repository_free(repo);
            fprintf(stderr, "git: failed to update HEAD: %s\n", strerror(errno));
            return 1;
        }
        fprintf(fp, "ref: refs/heads/%s\n", initial_branch);
        fclose(fp);
    }

    if (!quiet) {
        const char *repo_path = git_repository_path(repo);
        if (!repo_path || !*repo_path) {
            repo_path = target;
        }
        char display_path[PATH_MAX];
        if (smallclueGitDisplayPath(repo_path, display_path, sizeof(display_path)) == 0) {
            repo_path = display_path;
        }
        printf("Initialized empty Git repository in %s\n", repo_path);
    }

    git_repository_free(repo);
    return 0;
}

static int smallclueGitCommandRevParse(git_repository *repo, int argc, char **argv) {
    bool verify = false;
    bool is_inside = false;
    bool show_toplevel = false;
    bool show_git_dir = false;
    bool abbrev_ref = false;
    size_t short_width = 0;
    const char *revision = NULL;

    for (int i = 0; i < argc; ++i) {
        const char *arg = argv[i];
        if (!arg) {
            continue;
        }
        if (strcmp(arg, "--verify") == 0) {
            verify = true;
            continue;
        }
        if (strcmp(arg, "--is-inside-work-tree") == 0) {
            is_inside = true;
            continue;
        }
        if (strcmp(arg, "--show-toplevel") == 0) {
            show_toplevel = true;
            continue;
        }
        if (strcmp(arg, "--git-dir") == 0) {
            show_git_dir = true;
            continue;
        }
        if (strcmp(arg, "--abbrev-ref") == 0) {
            abbrev_ref = true;
            continue;
        }
        if (strcmp(arg, "--short") == 0) {
            short_width = 7;
            continue;
        }
        if (strncmp(arg, "--short=", 8) == 0) {
            const char *n = arg + 8;
            if (*n == '\0') {
                short_width = 7;
            } else {
                char *end = NULL;
                long v = strtol(n, &end, 10);
                if (!end || *end != '\0' || v <= 0) {
                    smallclueGitPrintError("invalid value for --short");
                    return 2;
                }
                short_width = (size_t)v;
            }
            continue;
        }
        revision = arg;
    }

    if (is_inside) {
        puts("true");
        return 0;
    }
    if (show_toplevel) {
        const char *wd = git_repository_workdir(repo);
        if (!wd) {
            smallclueGitPrintError("not a working tree repository");
            return 1;
        }
        char buf[PATH_MAX];
        size_t len = strlen(wd);
        while (len > 0 && wd[len - 1] == '/') {
            len--;
        }
        if (len == 0) {
            len = strlen(wd);
        }
        if (len >= sizeof(buf)) {
            smallclueGitPrintError("worktree path too long");
            return 1;
        }
        memcpy(buf, wd, len);
        buf[len] = '\0';
        char display[PATH_MAX];
        if (smallclueGitDisplayPath(buf, display, sizeof(display)) == 0) {
            puts(display);
        } else {
            puts(buf);
        }
        return 0;
    }
    if (show_git_dir) {
        const char *git_dir = git_repository_path(repo);
        if (!git_dir) {
            smallclueGitPrintError("unable to resolve .git directory");
            return 1;
        }
        const char *wd = git_repository_workdir(repo);
        if (wd) {
            size_t wlen = strlen(wd);
            if (strncmp(git_dir, wd, wlen) == 0) {
                const char *tail = git_dir + wlen;
                if (strcmp(tail, ".git/") == 0 || strcmp(tail, ".git") == 0) {
                    puts(".git");
                    return 0;
                }
            }
        }
        char pathbuf[PATH_MAX];
        size_t glen = strlen(git_dir);
        while (glen > 1 && git_dir[glen - 1] == '/') {
            glen--;
        }
        if (glen >= sizeof(pathbuf)) {
            smallclueGitPrintError("git-dir path too long");
            return 1;
        }
        memcpy(pathbuf, git_dir, glen);
        pathbuf[glen] = '\0';
        char display[PATH_MAX];
        if (smallclueGitDisplayPath(pathbuf, display, sizeof(display)) == 0) {
            puts(display);
        } else {
            puts(pathbuf);
        }
        return 0;
    }
    if (abbrev_ref) {
        git_reference *head = NULL;
        if (git_repository_head(&head, repo) != 0) {
            if (git_repository_head_detached(repo)) {
                puts("HEAD");
                return 0;
            }
            smallclueGitPrintLibgitError("unable to resolve HEAD");
            return 128;
        }
        const char *name = git_reference_shorthand(head);
        if (!name || !*name) {
            name = "HEAD";
        }
        puts(name);
        git_reference_free(head);
        return 0;
    }

    if (!revision) {
        revision = "HEAD";
    }

    git_object *obj = NULL;
    if (git_revparse_single(&obj, repo, revision) != 0) {
        if (verify) {
            fputs("fatal: Needed a single revision\n", stderr);
            return 128;
        }
        smallclueGitPrintLibgitError("unable to resolve revision");
        return 128;
    }

    const git_oid *oid = git_object_id(obj);
    if (!oid) {
        git_object_free(obj);
        smallclueGitPrintError("resolved object has no oid");
        return 128;
    }

    char oid_buf[GIT_OID_HEXSZ + 1];
    if (short_width > 0) {
        if (smallclueGitOidShort(oid, short_width, oid_buf, sizeof(oid_buf)) != 0) {
            git_object_free(obj);
            smallclueGitPrintError("failed to format short oid");
            return 128;
        }
    } else {
        if (!git_oid_tostr(oid_buf, sizeof(oid_buf), oid)) {
            git_object_free(obj);
            smallclueGitPrintError("failed to format oid");
            return 128;
        }
    }
    puts(oid_buf);

    git_object_free(obj);
    return 0;
}

static bool smallclueGitStartsWith(const char *s, const char *prefix) {
    if (!s || !prefix) {
        return false;
    }
    size_t p = strlen(prefix);
    return strncmp(s, prefix, p) == 0;
}

static bool smallclueGitLooksLikeUrl(const char *value) {
    if (!value || !*value) {
        return false;
    }
    if (strstr(value, "://")) {
        return true;
    }
    if (smallclueGitStartsWith(value, "git@")) {
        return true;
    }
    if (smallclueGitStartsWith(value, "ssh://") ||
        smallclueGitStartsWith(value, "http://") ||
        smallclueGitStartsWith(value, "https://") ||
        smallclueGitStartsWith(value, "file://")) {
        return true;
    }
    return false;
}

static bool smallclueGitLooksLikeFilesystemPath(const char *value) {
    if (!value || !*value) {
        return false;
    }
    if (smallclueGitLooksLikeUrl(value)) {
        return false;
    }
    if (value[0] == '/' || value[0] == '.') {
        return true;
    }
    if (strchr(value, '/')) {
        return true;
    }
    return false;
}

static int smallclueGitResolveMaybePathFromBase(const char *base_path,
                                                const char *value,
                                                char *out,
                                                size_t out_sz) {
    if (!value || !*value || !out || out_sz == 0) {
        return -1;
    }
    if (!smallclueGitLooksLikeFilesystemPath(value)) {
        return smallclueGitCopyPath(value, out, out_sz);
    }
    return smallclueGitResolvePathFromBase(base_path, value, out, out_sz);
}

static int smallclueGitResolveMaybePathFromCwd(const char *value,
                                               char *out,
                                               size_t out_sz) {
    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof(cwd))) {
        return -1;
    }
    return smallclueGitResolveMaybePathFromBase(cwd, value, out, out_sz);
}

static const char *smallclueGitDisplayMaybePath(const char *value,
                                                char *buf,
                                                size_t buf_sz) {
    if (!value || !*value || !buf || buf_sz == 0) {
        return value;
    }
    if (smallclueGitLooksLikeFilesystemPath(value)) {
        if (smallclueGitDisplayPath(value, buf, buf_sz) == 0) {
            return buf;
        }
    }
    return value;
}

static bool smallclueGitRefNameMatchesPattern(const char *name, const char *pattern) {
    if (!name || !pattern || !*pattern) {
        return false;
    }
    if (strcmp(name, pattern) == 0) {
        return true;
    }
    size_t nlen = strlen(name);
    size_t plen = strlen(pattern);
    if (plen > nlen) {
        return false;
    }
    if (strcmp(name + (nlen - plen), pattern) == 0) {
        if (nlen == plen) {
            return true;
        }
        if (name[nlen - plen - 1] == '/') {
            return true;
        }
    }
    return false;
}

static int smallclueGitCompareCStringPtr(const void *a, const void *b) {
    const char *const *sa = (const char *const *)a;
    const char *const *sb = (const char *const *)b;
    const char *lhs = (sa && *sa) ? *sa : "";
    const char *rhs = (sb && *sb) ? *sb : "";
    return strcmp(lhs, rhs);
}

static int smallclueGitConfigPrintValueCallback(const git_config_entry *entry, void *payload) {
    (void)payload;
    if (!entry) {
        return 0;
    }
    if (entry->value) {
        fputs(entry->value, stdout);
    }
    fputc('\n', stdout);
    return 0;
}

static int smallclueGitCommandConfig(git_repository *repo, int argc, char **argv) {
    typedef enum SmallclueGitConfigOp {
        SMALLCLUE_GIT_CONFIG_OP_NONE = 0,
        SMALLCLUE_GIT_CONFIG_OP_GET,
        SMALLCLUE_GIT_CONFIG_OP_GET_ALL,
        SMALLCLUE_GIT_CONFIG_OP_LIST,
        SMALLCLUE_GIT_CONFIG_OP_SET,
        SMALLCLUE_GIT_CONFIG_OP_ADD,
        SMALLCLUE_GIT_CONFIG_OP_REPLACE_ALL,
        SMALLCLUE_GIT_CONFIG_OP_UNSET,
        SMALLCLUE_GIT_CONFIG_OP_UNSET_ALL,
    } SmallclueGitConfigOp;

    SmallclueGitConfigOp op = SMALLCLUE_GIT_CONFIG_OP_NONE;
    const char *positionals[4];
    int positional_count = 0;

    for (int i = 0; i < argc; ++i) {
        const char *arg = argv[i];
        if (!arg) {
            continue;
        }
        if (strcmp(arg, "--local") == 0) {
            continue;
        }
        if (strcmp(arg, "--global") == 0 || strcmp(arg, "--system") == 0 ||
            strcmp(arg, "--worktree") == 0 || strcmp(arg, "--file") == 0) {
            smallclueGitPrintError("unsupported config scope option");
            return 2;
        }
        if (strcmp(arg, "--get") == 0) {
            if (op != SMALLCLUE_GIT_CONFIG_OP_NONE && op != SMALLCLUE_GIT_CONFIG_OP_GET) {
                smallclueGitPrintError("config supports one action at a time");
                return 2;
            }
            op = SMALLCLUE_GIT_CONFIG_OP_GET;
            continue;
        }
        if (strncmp(arg, "--get=", 6) == 0) {
            if (op != SMALLCLUE_GIT_CONFIG_OP_NONE && op != SMALLCLUE_GIT_CONFIG_OP_GET) {
                smallclueGitPrintError("config supports one action at a time");
                return 2;
            }
            op = SMALLCLUE_GIT_CONFIG_OP_GET;
            if (positional_count >= (int)(sizeof(positionals) / sizeof(positionals[0]))) {
                smallclueGitPrintError("too many config arguments");
                return 2;
            }
            positionals[positional_count++] = arg + 6;
            continue;
        }
        if (strcmp(arg, "--get-all") == 0) {
            if (op != SMALLCLUE_GIT_CONFIG_OP_NONE && op != SMALLCLUE_GIT_CONFIG_OP_GET_ALL) {
                smallclueGitPrintError("config supports one action at a time");
                return 2;
            }
            op = SMALLCLUE_GIT_CONFIG_OP_GET_ALL;
            continue;
        }
        if (strcmp(arg, "--list") == 0 || strcmp(arg, "-l") == 0) {
            if (op != SMALLCLUE_GIT_CONFIG_OP_NONE && op != SMALLCLUE_GIT_CONFIG_OP_LIST) {
                smallclueGitPrintError("config supports one action at a time");
                return 2;
            }
            op = SMALLCLUE_GIT_CONFIG_OP_LIST;
            continue;
        }
        if (strcmp(arg, "--add") == 0) {
            if (op != SMALLCLUE_GIT_CONFIG_OP_NONE && op != SMALLCLUE_GIT_CONFIG_OP_ADD) {
                smallclueGitPrintError("config supports one action at a time");
                return 2;
            }
            op = SMALLCLUE_GIT_CONFIG_OP_ADD;
            continue;
        }
        if (strcmp(arg, "--replace-all") == 0) {
            if (op != SMALLCLUE_GIT_CONFIG_OP_NONE && op != SMALLCLUE_GIT_CONFIG_OP_REPLACE_ALL) {
                smallclueGitPrintError("config supports one action at a time");
                return 2;
            }
            op = SMALLCLUE_GIT_CONFIG_OP_REPLACE_ALL;
            continue;
        }
        if (strcmp(arg, "--unset") == 0) {
            if (op != SMALLCLUE_GIT_CONFIG_OP_NONE && op != SMALLCLUE_GIT_CONFIG_OP_UNSET) {
                smallclueGitPrintError("config supports one action at a time");
                return 2;
            }
            op = SMALLCLUE_GIT_CONFIG_OP_UNSET;
            continue;
        }
        if (strcmp(arg, "--unset-all") == 0) {
            if (op != SMALLCLUE_GIT_CONFIG_OP_NONE && op != SMALLCLUE_GIT_CONFIG_OP_UNSET_ALL) {
                smallclueGitPrintError("config supports one action at a time");
                return 2;
            }
            op = SMALLCLUE_GIT_CONFIG_OP_UNSET_ALL;
            continue;
        }
        if (arg[0] == '-') {
            smallclueGitPrintError("unsupported config option");
            return 2;
        }
        if (positional_count >= (int)(sizeof(positionals) / sizeof(positionals[0]))) {
            smallclueGitPrintError("too many config arguments");
            return 2;
        }
        positionals[positional_count++] = arg;
    }

    if (op == SMALLCLUE_GIT_CONFIG_OP_NONE) {
        op = SMALLCLUE_GIT_CONFIG_OP_SET;
    }

    const char *key = NULL;
    const char *value = NULL;
    const char *pattern = NULL;
    switch (op) {
    case SMALLCLUE_GIT_CONFIG_OP_GET:
    case SMALLCLUE_GIT_CONFIG_OP_GET_ALL:
        if (positional_count != 1) {
            smallclueGitPrintError("config requires exactly one key");
            return 2;
        }
        key = positionals[0];
        break;
    case SMALLCLUE_GIT_CONFIG_OP_LIST:
        if (positional_count != 0) {
            smallclueGitPrintError("config --list does not take positional arguments");
            return 2;
        }
        break;
    case SMALLCLUE_GIT_CONFIG_OP_SET:
    case SMALLCLUE_GIT_CONFIG_OP_ADD:
        if (positional_count != 2) {
            smallclueGitPrintError("config set/add require <key> <value>");
            return 2;
        }
        key = positionals[0];
        value = positionals[1];
        break;
    case SMALLCLUE_GIT_CONFIG_OP_REPLACE_ALL:
        if (positional_count != 2 && positional_count != 3) {
            smallclueGitPrintError("config --replace-all requires <key> <value> [<value-pattern>]");
            return 2;
        }
        key = positionals[0];
        value = positionals[1];
        pattern = (positional_count == 3) ? positionals[2] : NULL;
        break;
    case SMALLCLUE_GIT_CONFIG_OP_UNSET:
    case SMALLCLUE_GIT_CONFIG_OP_UNSET_ALL:
        if (positional_count != 1 && positional_count != 2) {
            smallclueGitPrintError("config unset requires <key> [<value-pattern>]");
            return 2;
        }
        key = positionals[0];
        pattern = (positional_count == 2) ? positionals[1] : NULL;
        break;
    default:
        smallclueGitPrintError("unsupported config action");
        return 2;
    }

    if (key && !*key) {
        smallclueGitPrintError("config key must not be empty");
        return 2;
    }

    git_config *cfg = NULL;
    if (git_repository_config(&cfg, repo) != 0 || !cfg) {
        smallclueGitPrintLibgitError("config lookup failed");
        return 1;
    }

    int rc = 0;
    if (op == SMALLCLUE_GIT_CONFIG_OP_GET) {
        git_buf value_buf = GIT_BUF_INIT;
        rc = git_config_get_string_buf(&value_buf, cfg, key);
        if (rc != 0) {
            git_buf_dispose(&value_buf);
            git_config_free(cfg);
            if (rc == GIT_ENOTFOUND) {
                return 1;
            }
            smallclueGitPrintLibgitError("config get failed");
            return 1;
        }
        if (value_buf.ptr && value_buf.size > 0) {
            fputs(value_buf.ptr, stdout);
            if (value_buf.ptr[value_buf.size - 1] != '\n') {
                fputc('\n', stdout);
            }
        } else {
            fputc('\n', stdout);
        }
        git_buf_dispose(&value_buf);
        git_config_free(cfg);
        return 0;
    }

    if (op == SMALLCLUE_GIT_CONFIG_OP_GET_ALL) {
        rc = git_config_get_multivar_foreach(cfg, key, NULL, smallclueGitConfigPrintValueCallback, NULL);
        git_config_free(cfg);
        if (rc == GIT_ENOTFOUND) {
            return 1;
        }
        if (rc != 0) {
            smallclueGitPrintLibgitError("config --get-all failed");
            return 1;
        }
        return 0;
    }

    if (op == SMALLCLUE_GIT_CONFIG_OP_LIST) {
        git_config_iterator *iter = NULL;
        git_config_entry *entry = NULL;
        rc = git_config_iterator_new(&iter, cfg);
        if (rc != 0 || !iter) {
            git_config_free(cfg);
            smallclueGitPrintLibgitError("config --list failed");
            return 1;
        }
        for (;;) {
            rc = git_config_next(&entry, iter);
            if (rc != 0) {
                break;
            }
            if (entry && entry->name) {
                fputs(entry->name, stdout);
                if (entry->value) {
                    fputc('=', stdout);
                    fputs(entry->value, stdout);
                }
                fputc('\n', stdout);
            }
        }
        git_config_iterator_free(iter);
        git_config_free(cfg);
        if (rc != GIT_ITEROVER) {
            smallclueGitPrintLibgitError("config --list failed");
            return 1;
        }
        return 0;
    }

    if (op == SMALLCLUE_GIT_CONFIG_OP_SET) {
        SmallclueGitConfigValueList values;
        int read_rc = smallclueGitConfigReadValues(cfg, key, &values);
        if (read_rc == -1) {
            git_config_free(cfg);
            smallclueGitPrintLibgitError("config set failed");
            return 1;
        }
        if (read_rc == 0 && values.count > 1) {
            fprintf(stderr, "warning: %s has multiple values\n", key);
            fprintf(stderr, "error: cannot overwrite multiple values with a single value\n");
            fprintf(stderr, "       Use a regexp, --add or --replace-all to change %s.\n", key);
            smallclueGitConfigValueListFree(&values);
            git_config_free(cfg);
            return 5;
        }
        smallclueGitConfigValueListFree(&values);
        rc = git_config_set_string(cfg, key, value);
        git_config_free(cfg);
        if (rc != 0) {
            smallclueGitPrintLibgitError("config set failed");
            return 1;
        }
        return 0;
    }

    if (op == SMALLCLUE_GIT_CONFIG_OP_ADD) {
        rc = smallclueGitConfigAppendValue(cfg, key, value);
        git_config_free(cfg);
        if (rc != 0) {
            smallclueGitPrintLibgitError("config --add failed");
            return 1;
        }
        return 0;
    }

    if (op == SMALLCLUE_GIT_CONFIG_OP_REPLACE_ALL) {
        const char *replace_pattern = (pattern && *pattern) ? pattern : ".*";
        rc = git_config_set_multivar(cfg, key, replace_pattern, value);
        git_config_free(cfg);
        if (rc != 0) {
            smallclueGitPrintLibgitError("config --replace-all failed");
            return 1;
        }
        return 0;
    }

    if (op == SMALLCLUE_GIT_CONFIG_OP_UNSET) {
        int drc = smallclueGitConfigDeleteSingleMatchingValue(cfg, key, pattern, (pattern && *pattern));
        git_config_free(cfg);
        if (drc == 1) {
            return 5;
        }
        if (drc == 2) {
            fprintf(stderr, "warning: %s has multiple values\n", key);
            return 5;
        }
        if (drc != 0) {
            smallclueGitPrintLibgitError("config --unset failed");
            return 1;
        }
        return 0;
    }

    if (op == SMALLCLUE_GIT_CONFIG_OP_UNSET_ALL) {
        if (pattern && *pattern) {
            int drc = smallclueGitConfigDeleteMatchingValue(cfg, key, pattern, true);
            git_config_free(cfg);
            if (drc == 1) {
                return 5;
            }
            if (drc != 0) {
                smallclueGitPrintLibgitError("config --unset-all failed");
                return 1;
            }
            return 0;
        }
        rc = git_config_delete_multivar(cfg, key, ".*");
        git_config_free(cfg);
        if (rc == GIT_ENOTFOUND) {
            return 5;
        }
        if (rc != 0) {
            smallclueGitPrintLibgitError("config --unset-all failed");
            return 1;
        }
        return 0;
    }

    git_config_free(cfg);
    smallclueGitPrintError("unsupported config action");
    return 2;
}

static int smallclueGitCommandSymbolicRef(git_repository *repo, int argc, char **argv) {
    bool short_name = false;
    const char *refname = NULL;

    for (int i = 0; i < argc; ++i) {
        const char *arg = argv[i];
        if (!arg) {
            continue;
        }
        if (strcmp(arg, "--short") == 0) {
            short_name = true;
            continue;
        }
        if (arg[0] == '-') {
            smallclueGitPrintError("unsupported symbolic-ref option");
            return 2;
        }
        if (!refname) {
            refname = arg;
            continue;
        }
        smallclueGitPrintError("too many symbolic-ref arguments");
        return 2;
    }

    if (!refname) {
        refname = "HEAD";
    }

    git_reference *ref = NULL;
    if (git_reference_lookup(&ref, repo, refname) != 0 || !ref) {
        smallclueGitPrintLibgitError("symbolic-ref lookup failed");
        return 1;
    }
    if (git_reference_type(ref) != GIT_REFERENCE_SYMBOLIC) {
        git_reference_free(ref);
        return 1;
    }

    const char *target = git_reference_symbolic_target(ref);
    if (!target || !*target) {
        git_reference_free(ref);
        return 1;
    }

    if (short_name) {
        const char *slash = strrchr(target, '/');
        puts((slash && slash[1]) ? slash + 1 : target);
    } else {
        puts(target);
    }

    git_reference_free(ref);
    return 0;
}

static int smallclueGitCommandRevList(git_repository *repo, int argc, char **argv) {
    bool reverse = false;
    int max_count = -1;
    const char *revs[32];
    int rev_count = 0;

    for (int i = 0; i < argc; ++i) {
        const char *arg = argv[i];
        if (!arg) {
            continue;
        }
        if (strcmp(arg, "--reverse") == 0) {
            reverse = true;
            continue;
        }
        if ((strcmp(arg, "-n") == 0 || strcmp(arg, "--max-count") == 0) && i + 1 < argc) {
            max_count = atoi(argv[++i]);
            continue;
        }
        if (strncmp(arg, "--max-count=", 12) == 0) {
            max_count = atoi(arg + 12);
            continue;
        }
        if (arg[0] == '-') {
            smallclueGitPrintError("unsupported rev-list option");
            return 2;
        }
        if (rev_count >= (int)(sizeof(revs) / sizeof(revs[0]))) {
            smallclueGitPrintError("too many rev-list revisions");
            return 2;
        }
        revs[rev_count++] = arg;
    }

    if (rev_count == 0) {
        smallclueGitPrintError("rev-list requires at least one revision");
        return 2;
    }
    if (max_count == 0) {
        return 0;
    }

    git_revwalk *walk = NULL;
    if (git_revwalk_new(&walk, repo) != 0 || !walk) {
        smallclueGitPrintLibgitError("rev-list walk init failed");
        return 1;
    }
    git_revwalk_sorting(walk, GIT_SORT_TOPOLOGICAL | GIT_SORT_TIME);

    for (int i = 0; i < rev_count; ++i) {
        git_object *obj = NULL;
        if (git_revparse_single(&obj, repo, revs[i]) != 0 || !obj) {
            git_revwalk_free(walk);
            smallclueGitPrintLibgitError("rev-list revision parse failed");
            return 128;
        }
        const git_oid *oid = git_object_id(obj);
        if (!oid || git_revwalk_push(walk, oid) != 0) {
            git_object_free(obj);
            git_revwalk_free(walk);
            smallclueGitPrintLibgitError("rev-list push failed");
            return 128;
        }
        git_object_free(obj);
    }

    int printed = 0;
    char **reverse_lines = NULL;
    size_t reverse_count = 0;
    size_t reverse_capacity = 0;
    git_oid oid;
    while (git_revwalk_next(&oid, walk) == 0) {
        char oid_buf[GIT_OID_HEXSZ + 1];
        if (git_oid_tostr(oid_buf, sizeof(oid_buf), &oid)) {
            if (reverse) {
                if (reverse_count == reverse_capacity) {
                    size_t new_capacity = reverse_capacity ? reverse_capacity * 2 : 16;
                    char **grown = (char **)realloc(reverse_lines, new_capacity * sizeof(char *));
                    if (!grown) {
                        for (size_t j = 0; j < reverse_count; ++j) {
                            free(reverse_lines[j]);
                        }
                        free(reverse_lines);
                        git_revwalk_free(walk);
                        smallclueGitPrintError("out of memory");
                        return 1;
                    }
                    reverse_lines = grown;
                    reverse_capacity = new_capacity;
                }
                reverse_lines[reverse_count] = strdup(oid_buf);
                if (!reverse_lines[reverse_count]) {
                    for (size_t j = 0; j < reverse_count; ++j) {
                        free(reverse_lines[j]);
                    }
                    free(reverse_lines);
                    git_revwalk_free(walk);
                    smallclueGitPrintError("out of memory");
                    return 1;
                }
                reverse_count++;
            } else {
                puts(oid_buf);
            }
        }
        printed++;
        if (max_count > 0 && printed >= max_count) {
            break;
        }
    }

    if (reverse && reverse_lines) {
        for (size_t i = reverse_count; i > 0; --i) {
            puts(reverse_lines[i - 1]);
            free(reverse_lines[i - 1]);
        }
        free(reverse_lines);
    }

    git_revwalk_free(walk);
    return 0;
}

static int smallclueGitCommandShowRef(git_repository *repo, int argc, char **argv) {
    bool heads_only = false;
    bool tags_only = false;
    bool verify = false;
    bool hash_only = false;
    size_t hash_width = 0;
    const char *patterns[32];
    int pattern_count = 0;

    for (int i = 0; i < argc; ++i) {
        const char *arg = argv[i];
        if (!arg) {
            continue;
        }
        if (strcmp(arg, "--heads") == 0) {
            heads_only = true;
            continue;
        }
        if (strcmp(arg, "--tags") == 0) {
            tags_only = true;
            continue;
        }
        if (strcmp(arg, "--verify") == 0) {
            verify = true;
            continue;
        }
        if (strcmp(arg, "--hash") == 0) {
            hash_only = true;
            hash_width = GIT_OID_HEXSZ;
            continue;
        }
        if (strncmp(arg, "--hash=", 7) == 0) {
            hash_only = true;
            hash_width = (size_t)atoi(arg + 7);
            if (hash_width == 0) {
                hash_width = GIT_OID_HEXSZ;
            }
            continue;
        }
        if (arg[0] == '-') {
            smallclueGitPrintError("unsupported show-ref option");
            return 2;
        }
        if (pattern_count >= (int)(sizeof(patterns) / sizeof(patterns[0]))) {
            smallclueGitPrintError("too many show-ref patterns");
            return 2;
        }
        patterns[pattern_count++] = arg;
    }

    git_reference_iterator *it = NULL;
    if (git_reference_iterator_new(&it, repo) != 0 || !it) {
        smallclueGitPrintLibgitError("show-ref iterator failed");
        return 1;
    }

    int matched = 0;
    git_reference *ref = NULL;
    while (git_reference_next(&ref, it) == 0) {
        const char *name = git_reference_name(ref);
        if (!name || !*name) {
            git_reference_free(ref);
            ref = NULL;
            continue;
        }
        if (heads_only && !smallclueGitStartsWith(name, "refs/heads/")) {
            git_reference_free(ref);
            ref = NULL;
            continue;
        }
        if (tags_only && !smallclueGitStartsWith(name, "refs/tags/")) {
            git_reference_free(ref);
            ref = NULL;
            continue;
        }

        bool selected = true;
        if (pattern_count > 0) {
            selected = false;
            for (int i = 0; i < pattern_count; ++i) {
                if (verify) {
                    if (strcmp(name, patterns[i]) == 0) {
                        selected = true;
                        break;
                    }
                } else if (smallclueGitRefNameMatchesPattern(name, patterns[i])) {
                    selected = true;
                    break;
                }
            }
        }
        if (!selected) {
            git_reference_free(ref);
            ref = NULL;
            continue;
        }

        const git_oid *oid = git_reference_target(ref);
        git_reference *resolved = NULL;
        if (!oid && git_reference_resolve(&resolved, ref) == 0 && resolved) {
            oid = git_reference_target(resolved);
        }
        if (oid) {
            char oid_buf[GIT_OID_HEXSZ + 1];
            if (hash_only && hash_width < GIT_OID_HEXSZ) {
                if (smallclueGitOidShort(oid, hash_width, oid_buf, sizeof(oid_buf)) != 0) {
                    git_reference_free(resolved);
                    git_reference_free(ref);
                    git_reference_iterator_free(it);
                    smallclueGitPrintError("failed to format oid");
                    return 1;
                }
            } else if (!git_oid_tostr(oid_buf, sizeof(oid_buf), oid)) {
                git_reference_free(resolved);
                git_reference_free(ref);
                git_reference_iterator_free(it);
                smallclueGitPrintError("failed to format oid");
                return 1;
            }

            if (hash_only) {
                puts(oid_buf);
            } else {
                printf("%s %s\n", oid_buf, name);
            }
            matched++;
        }

        git_reference_free(resolved);
        git_reference_free(ref);
        ref = NULL;
    }

    git_reference_iterator_free(it);

    if (pattern_count > 0 && matched == 0) {
        return 1;
    }
    return 0;
}

static int smallclueGitCommandLsFiles(git_repository *repo, int argc, char **argv) {
    bool want_cached = false;
    bool want_others = false;

    for (int i = 0; i < argc; ++i) {
        const char *arg = argv[i];
        if (!arg) {
            continue;
        }
        if (strcmp(arg, "--cached") == 0) {
            want_cached = true;
            continue;
        }
        if (strcmp(arg, "--others") == 0) {
            want_others = true;
            continue;
        }
        if (strcmp(arg, "--exclude-standard") == 0) {
            continue;
        }
        smallclueGitPrintError("unsupported ls-files option");
        return 2;
    }

    if (!want_cached && !want_others) {
        want_cached = true;
    }

    if (want_cached) {
        git_index *index = NULL;
        if (git_repository_index(&index, repo) != 0 || !index) {
            smallclueGitPrintLibgitError("ls-files index lookup failed");
            return 1;
        }
        size_t count = git_index_entrycount(index);
        char **paths = NULL;
        if (count > 0) {
            paths = (char **)calloc(count, sizeof(char *));
            if (!paths) {
                git_index_free(index);
                smallclueGitPrintError("out of memory");
                return 1;
            }
        }
        size_t path_count = 0;
        for (size_t i = 0; i < count; ++i) {
            const git_index_entry *entry = git_index_get_byindex(index, i);
            if (!entry || !entry->path) {
                continue;
            }
            char *copy = strdup(entry->path);
            if (!copy) {
                for (size_t j = 0; j < path_count; ++j) {
                    free(paths[j]);
                }
                free(paths);
                git_index_free(index);
                smallclueGitPrintError("out of memory");
                return 1;
            }
            paths[path_count++] = copy;
        }
        qsort(paths, path_count, sizeof(char *), smallclueGitCompareCStringPtr);
        for (size_t i = 0; i < path_count; ++i) {
            puts(paths[i]);
            free(paths[i]);
        }
        free(paths);
        git_index_free(index);
    }

    if (want_others) {
        git_status_options opts = GIT_STATUS_OPTIONS_INIT;
        opts.show = GIT_STATUS_SHOW_WORKDIR_ONLY;
        opts.flags = GIT_STATUS_OPT_INCLUDE_UNTRACKED |
                     GIT_STATUS_OPT_RECURSE_UNTRACKED_DIRS |
                     GIT_STATUS_OPT_DISABLE_PATHSPEC_MATCH;
        git_status_list *status_list = NULL;
        if (git_status_list_new(&status_list, repo, &opts) != 0 || !status_list) {
            smallclueGitPrintLibgitError("ls-files status listing failed");
            return 1;
        }
        size_t count = git_status_list_entrycount(status_list);
        for (size_t i = 0; i < count; ++i) {
            const git_status_entry *entry = git_status_byindex(status_list, i);
            if (!entry || !(entry->status & GIT_STATUS_WT_NEW)) {
                continue;
            }
            const char *path = smallclueGitStatusPath(entry);
            if (path && *path) {
                puts(path);
            }
        }
        git_status_list_free(status_list);
    }

    return 0;
}

static int smallclueGitCommandAdd(git_repository *repo, int argc, char **argv) {
    bool add_all = false;
    bool force = false;
    bool saw_paths = false;
    bool after_double_dash = false;

    git_index *index = NULL;
    if (git_repository_index(&index, repo) != 0 || !index) {
        smallclueGitPrintLibgitError("add: index lookup failed");
        return 1;
    }

    for (int i = 0; i < argc; ++i) {
        const char *arg = argv[i];
        if (!arg) {
            continue;
        }
        if (!after_double_dash && strcmp(arg, "--") == 0) {
            after_double_dash = true;
            continue;
        }
        if (!after_double_dash && (strcmp(arg, "-A") == 0 || strcmp(arg, "--all") == 0)) {
            add_all = true;
            continue;
        }
        if (!after_double_dash && strcmp(arg, "-f") == 0) {
            force = true;
            continue;
        }
        if (!after_double_dash && arg[0] == '-') {
            git_index_free(index);
            smallclueGitPrintError("unsupported add option");
            return 2;
        }
        if (git_index_add_bypath(index, arg) != 0) {
            git_index_free(index);
            smallclueGitPrintLibgitError("add failed");
            return 128;
        }
        saw_paths = true;
    }

    if (!saw_paths && add_all) {
        uint32_t flags = GIT_INDEX_ADD_DEFAULT;
        if (force) {
            flags |= GIT_INDEX_ADD_FORCE;
        }
        if (git_index_add_all(index, NULL, flags, NULL, NULL) != 0) {
            git_index_free(index);
            smallclueGitPrintLibgitError("add --all failed");
            return 128;
        }
    } else if (!saw_paths) {
        git_index_free(index);
        smallclueGitPrintError("add requires at least one path");
        return 2;
    }

    if (git_index_write(index) != 0) {
        git_index_free(index);
        smallclueGitPrintLibgitError("add: index write failed");
        return 1;
    }

    git_index_free(index);
    return 0;
}

static int smallclueGitStageTrackedWorktreeChanges(git_repository *repo, git_index *index) {
    if (!repo || !index) {
        return -1;
    }
    git_status_options opts = GIT_STATUS_OPTIONS_INIT;
    opts.show = GIT_STATUS_SHOW_WORKDIR_ONLY;
    opts.flags = GIT_STATUS_OPT_INCLUDE_UNTRACKED |
                 GIT_STATUS_OPT_RECURSE_UNTRACKED_DIRS |
                 GIT_STATUS_OPT_RENAMES_INDEX_TO_WORKDIR |
                 GIT_STATUS_OPT_SORT_CASE_SENSITIVELY;

    git_status_list *status_list = NULL;
    if (git_status_list_new(&status_list, repo, &opts) != 0 || !status_list) {
        return -1;
    }

    size_t count = git_status_list_entrycount(status_list);
    for (size_t i = 0; i < count; ++i) {
        const git_status_entry *entry = git_status_byindex(status_list, i);
        if (!entry) {
            continue;
        }
        unsigned int st = entry->status;
        if (st & GIT_STATUS_WT_NEW) {
            continue;
        }
        const char *path = smallclueGitStatusPath(entry);
        if (!path || !*path) {
            continue;
        }
        if (st & GIT_STATUS_WT_DELETED) {
            if (git_index_remove_bypath(index, path) != 0) {
                git_status_list_free(status_list);
                return -1;
            }
            continue;
        }
        if (st & (GIT_STATUS_WT_MODIFIED | GIT_STATUS_WT_RENAMED | GIT_STATUS_WT_TYPECHANGE)) {
            if (git_index_add_bypath(index, path) != 0) {
                git_status_list_free(status_list);
                return -1;
            }
        }
    }

    git_status_list_free(status_list);
    return 0;
}

/*
 * Returns:
 *   0 -> clean (for tracked changes),
 *   1 -> dirty,
 *  -1 -> error.
 */
static int smallclueGitHasTrackedChanges(git_repository *repo) {
    if (!repo) {
        return -1;
    }

    git_status_options opts = GIT_STATUS_OPTIONS_INIT;
    opts.show = GIT_STATUS_SHOW_INDEX_AND_WORKDIR;
    opts.flags = GIT_STATUS_OPT_INCLUDE_UNMODIFIED | GIT_STATUS_OPT_RECURSE_UNTRACKED_DIRS;

    git_status_list *status_list = NULL;
    if (git_status_list_new(&status_list, repo, &opts) != 0 || !status_list) {
        return -1;
    }

    size_t count = git_status_list_entrycount(status_list);
    for (size_t i = 0; i < count; ++i) {
        const git_status_entry *entry = git_status_byindex(status_list, i);
        if (!entry) {
            continue;
        }
        unsigned int st = entry->status;
        if (st == GIT_STATUS_CURRENT || st == GIT_STATUS_WT_NEW || st == GIT_STATUS_IGNORED) {
            continue;
        }
        git_status_list_free(status_list);
        return 1;
    }

    git_status_list_free(status_list);
    return 0;
}

static int smallclueGitCreateDefaultSignatures(git_repository *repo,
                                               git_signature **out_author,
                                               git_signature **out_committer) {
    if (!out_author || !out_committer) {
        return -1;
    }
    *out_author = NULL;
    *out_committer = NULL;

    git_signature *author = NULL;
    if (git_signature_default(&author, repo) != 0 || !author) {
        const char *name = getenv("GIT_AUTHOR_NAME");
        const char *email = getenv("GIT_AUTHOR_EMAIL");
        if (!name || !*name) {
            name = "PSCAL User";
        }
        if (!email || !*email) {
            email = "pscal@example.com";
        }
        if (git_signature_now(&author, name, email) != 0 || !author) {
            return -1;
        }
    }

    git_signature *committer = NULL;
    if (git_signature_dup(&committer, author) != 0 || !committer) {
        git_signature_free(author);
        return -1;
    }

    *out_author = author;
    *out_committer = committer;
    return 0;
}

static int smallclueGitCommandCommit(git_repository *repo, int argc, char **argv) {
    const char *message = NULL;
    bool allow_empty = false;
    bool quiet = false;
    bool stage_all = false;

    for (int i = 0; i < argc; ++i) {
        const char *arg = argv[i];
        if (!arg) {
            continue;
        }
        if ((strcmp(arg, "-m") == 0 || strcmp(arg, "--message") == 0) && i + 1 < argc) {
            message = argv[++i];
            continue;
        }
        if (strncmp(arg, "--message=", 10) == 0) {
            message = arg + 10;
            continue;
        }
        if (strcmp(arg, "--allow-empty") == 0) {
            allow_empty = true;
            continue;
        }
        if (strcmp(arg, "-q") == 0 || strcmp(arg, "--quiet") == 0) {
            quiet = true;
            continue;
        }
        if (strcmp(arg, "-a") == 0 || strcmp(arg, "--all") == 0) {
            stage_all = true;
            continue;
        }
        smallclueGitPrintError("unsupported commit option");
        return 2;
    }

    if (!message || !*message) {
        smallclueGitPrintError("commit requires -m/--message");
        return 2;
    }

    git_index *index = NULL;
    if (git_repository_index(&index, repo) != 0 || !index) {
        smallclueGitPrintLibgitError("commit: index lookup failed");
        return 1;
    }

    if (stage_all) {
        if (smallclueGitStageTrackedWorktreeChanges(repo, index) != 0) {
            git_index_free(index);
            smallclueGitPrintLibgitError("commit -a: staging tracked changes failed");
            return 1;
        }
    }

    git_oid tree_oid;
    if (git_index_write_tree(&tree_oid, index) != 0) {
        git_index_free(index);
        smallclueGitPrintLibgitError("commit: write tree failed");
        return 1;
    }
    if (git_index_write(index) != 0) {
        git_index_free(index);
        smallclueGitPrintLibgitError("commit: index write failed");
        return 1;
    }
    git_index_free(index);

    git_tree *tree = NULL;
    if (git_tree_lookup(&tree, repo, &tree_oid) != 0 || !tree) {
        smallclueGitPrintLibgitError("commit: tree lookup failed");
        return 1;
    }

    git_commit *parent = NULL;
    git_reference *head_ref = NULL;
    if (git_repository_head(&head_ref, repo) == 0 && head_ref) {
        git_object *head_obj = NULL;
        if (git_reference_peel(&head_obj, head_ref, GIT_OBJECT_COMMIT) == 0 && head_obj) {
            parent = (git_commit *)head_obj;
        }
    }

    if (!allow_empty && parent) {
        git_tree *parent_tree = NULL;
        if (git_commit_tree(&parent_tree, parent) == 0 && parent_tree) {
            if (git_oid_equal(git_tree_id(parent_tree), &tree_oid)) {
                git_tree_free(parent_tree);
                git_reference_free(head_ref);
                git_commit_free(parent);
                git_tree_free(tree);
                fputs("nothing to commit\n", stderr);
                return 1;
            }
            git_tree_free(parent_tree);
        }
    }

    git_signature *author = NULL;
    git_signature *committer = NULL;
    if (smallclueGitCreateDefaultSignatures(repo, &author, &committer) != 0) {
        git_reference_free(head_ref);
        git_commit_free(parent);
        git_tree_free(tree);
        smallclueGitPrintLibgitError("commit: signature creation failed");
        return 1;
    }

    const git_commit *parents[1];
    size_t parent_count = 0;
    if (parent) {
        parents[parent_count++] = parent;
    }

    git_oid commit_oid;
    if (git_commit_create(&commit_oid,
                          repo,
                          "HEAD",
                          author,
                          committer,
                          NULL,
                          message,
                          tree,
                          parent_count,
                          parents) != 0) {
        git_signature_free(author);
        git_signature_free(committer);
        git_reference_free(head_ref);
        git_commit_free(parent);
        git_tree_free(tree);
        smallclueGitPrintLibgitError("commit failed");
        return 1;
    }

    if (!quiet) {
        char short_oid[16];
        if (smallclueGitOidShort(&commit_oid, 7, short_oid, sizeof(short_oid)) == 0) {
            printf("[%s] %s\n", short_oid, message);
        }
    }

    git_signature_free(author);
    git_signature_free(committer);
    git_reference_free(head_ref);
    git_commit_free(parent);
    git_tree_free(tree);
    return 0;
}

static int smallclueGitCommandReset(git_repository *repo, int argc, char **argv) {
    git_reset_t mode = GIT_RESET_MIXED;
    const char *revision = "HEAD";
    bool revision_set = false;

    for (int i = 0; i < argc; ++i) {
        const char *arg = argv[i];
        if (!arg) {
            continue;
        }
        if (strcmp(arg, "--soft") == 0) {
            mode = GIT_RESET_SOFT;
            continue;
        }
        if (strcmp(arg, "--mixed") == 0) {
            mode = GIT_RESET_MIXED;
            continue;
        }
        if (strcmp(arg, "--hard") == 0) {
            mode = GIT_RESET_HARD;
            continue;
        }
        if (strcmp(arg, "-q") == 0 || strcmp(arg, "--quiet") == 0) {
            continue;
        }
        if (arg[0] == '-') {
            smallclueGitPrintError("unsupported reset option");
            return 2;
        }
        if (!revision_set) {
            revision = arg;
            revision_set = true;
            continue;
        }
        smallclueGitPrintError("pathspec reset is not supported in this phase");
        return 2;
    }

    git_object *target = NULL;
    if (git_revparse_single(&target, repo, revision) != 0 || !target) {
        smallclueGitPrintLibgitError("reset revision lookup failed");
        return 128;
    }

    if (git_reset(repo, target, mode, NULL) != 0) {
        git_object_free(target);
        smallclueGitPrintLibgitError("reset failed");
        return 1;
    }

    git_object_free(target);
    return 0;
}

static int smallclueGitCommandRestore(git_repository *repo, int argc, char **argv) {
    bool restore_staged = false;
    bool restore_worktree = false;
    const char *source = NULL;
    char *paths[128];
    size_t path_count = 0;
    bool after_double_dash = false;

    for (int i = 0; i < argc; ++i) {
        const char *arg = argv[i];
        if (!arg) {
            continue;
        }
        if (!after_double_dash && strcmp(arg, "--") == 0) {
            after_double_dash = true;
            continue;
        }
        if (!after_double_dash && strcmp(arg, "--staged") == 0) {
            restore_staged = true;
            continue;
        }
        if (!after_double_dash && strcmp(arg, "--worktree") == 0) {
            restore_worktree = true;
            continue;
        }
        if (!after_double_dash && strcmp(arg, "--source") == 0 && i + 1 < argc) {
            source = argv[++i];
            continue;
        }
        if (!after_double_dash && strncmp(arg, "--source=", 9) == 0) {
            source = arg + 9;
            continue;
        }
        if (!after_double_dash && arg[0] == '-') {
            smallclueGitPrintError("unsupported restore option");
            return 2;
        }
        if (path_count >= (sizeof(paths) / sizeof(paths[0]))) {
            smallclueGitPrintError("too many restore paths");
            return 2;
        }
        paths[path_count++] = (char *)arg;
    }

    if (!restore_staged && !restore_worktree) {
        restore_worktree = true;
    }
    if (path_count == 0) {
        smallclueGitPrintError("restore requires at least one path");
        return 2;
    }

    git_strarray pathspec;
    pathspec.strings = paths;
    pathspec.count = path_count;

    git_object *source_obj = NULL;
    if ((restore_staged || source) && source && *source) {
        if (git_revparse_single(&source_obj, repo, source) != 0 || !source_obj) {
            smallclueGitPrintLibgitError("restore source lookup failed");
            return 128;
        }
    } else if (restore_staged) {
        if (git_revparse_single(&source_obj, repo, "HEAD") != 0 || !source_obj) {
            smallclueGitPrintLibgitError("restore HEAD lookup failed");
            return 128;
        }
    }

    if (restore_staged) {
        if (!source_obj) {
            smallclueGitPrintError("restore --staged requires a source");
            return 2;
        }
        if (git_reset_default(repo, source_obj, &pathspec) != 0) {
            git_object_free(source_obj);
            smallclueGitPrintLibgitError("restore staged failed");
            return 1;
        }
    }

    if (restore_worktree) {
        git_checkout_options checkout_opts = GIT_CHECKOUT_OPTIONS_INIT;
        checkout_opts.checkout_strategy = GIT_CHECKOUT_FORCE | GIT_CHECKOUT_RECREATE_MISSING;
        checkout_opts.paths = pathspec;
        int rc = 0;
        if (source_obj) {
            rc = git_checkout_tree(repo, source_obj, &checkout_opts);
        } else {
            rc = git_checkout_index(repo, NULL, &checkout_opts);
        }
        if (rc != 0) {
            git_object_free(source_obj);
            smallclueGitPrintLibgitError("restore worktree failed");
            return 1;
        }
    }

    git_object_free(source_obj);
    return 0;
}

static int smallclueGitCheckoutRef(git_repository *repo,
                                   const char *ref_name,
                                   git_checkout_options *checkout_opts) {
    if (!repo || !ref_name || !checkout_opts) {
        return -1;
    }
    if (git_repository_set_head(repo, ref_name) != 0) {
        smallclueGitPrintLibgitError("checkout: failed to update HEAD");
        return 1;
    }
    if (git_checkout_head(repo, checkout_opts) != 0) {
        smallclueGitPrintLibgitError("checkout failed");
        return 1;
    }
    return 0;
}

static int smallclueGitCheckoutDetached(git_repository *repo,
                                        git_object *target_obj,
                                        git_checkout_options *checkout_opts) {
    if (!repo || !target_obj || !checkout_opts) {
        return -1;
    }
    if (git_checkout_tree(repo, target_obj, checkout_opts) != 0) {
        smallclueGitPrintLibgitError("checkout failed");
        return 1;
    }
    if (git_repository_set_head_detached(repo, git_object_id(target_obj)) != 0) {
        smallclueGitPrintLibgitError("checkout: failed to detach HEAD");
        return 1;
    }
    return 0;
}

static int smallclueGitCommandCheckoutCommon(git_repository *repo,
                                             int argc,
                                             char **argv,
                                             bool switch_style) {
    bool force = false;
    bool detach = false;
    bool quiet = false;
    bool create_force = false;
    const char *create_branch = NULL;
    const char *target_spec = NULL;

    for (int i = 0; i < argc; ++i) {
        const char *arg = argv[i];
        if (!arg) {
            continue;
        }
        if (strcmp(arg, "-q") == 0 || strcmp(arg, "--quiet") == 0) {
            quiet = true;
            continue;
        }
        if (strcmp(arg, "-f") == 0 || strcmp(arg, "--force") == 0) {
            force = true;
            continue;
        }
        if (strcmp(arg, "--detach") == 0) {
            detach = true;
            continue;
        }
        if ((!switch_style && (strcmp(arg, "-b") == 0 || strcmp(arg, "-B") == 0)) ||
            (switch_style && (strcmp(arg, "-c") == 0 || strcmp(arg, "-C") == 0))) {
            if (i + 1 >= argc) {
                smallclueGitPrintError("branch creation option requires a branch name");
                return 2;
            }
            create_branch = argv[++i];
            create_force = (strcmp(arg, "-B") == 0 || strcmp(arg, "-C") == 0);
            continue;
        }
        if (strcmp(arg, "--") == 0) {
            smallclueGitPrintError("path checkout is not supported in this phase (use restore)");
            return 2;
        }
        if (arg[0] == '-') {
            smallclueGitPrintError("unsupported checkout option");
            return 2;
        }
        if (!target_spec) {
            target_spec = arg;
            continue;
        }
        smallclueGitPrintError("too many checkout operands");
        return 2;
    }

    if (create_branch && !target_spec) {
        target_spec = "HEAD";
    }
    if (!create_branch && !target_spec) {
        smallclueGitPrintError(switch_style ? "switch requires a branch or --detach target"
                                            : "checkout requires a branch or revision");
        return 2;
    }

    git_checkout_options checkout_opts = GIT_CHECKOUT_OPTIONS_INIT;
    checkout_opts.checkout_strategy = (force ? GIT_CHECKOUT_FORCE : GIT_CHECKOUT_SAFE) | GIT_CHECKOUT_RECREATE_MISSING;
    (void)quiet;

    char created_ref_name[PATH_MAX] = {0};
    if (create_branch) {
        git_commit *start_commit = NULL;
        if (smallclueGitResolveCommit(repo, target_spec, &start_commit) != 0 || !start_commit) {
            smallclueGitPrintLibgitError("checkout: invalid start point");
            return 128;
        }
        git_reference *created = NULL;
        if (git_branch_create(&created, repo, create_branch, start_commit, create_force ? 1 : 0) != 0 || !created) {
            git_commit_free(start_commit);
            smallclueGitPrintLibgitError("checkout: failed to create branch");
            return 1;
        }
        const char *ref_name = git_reference_name(created);
        if (!ref_name || snprintf(created_ref_name, sizeof(created_ref_name), "%s", ref_name) >= (int)sizeof(created_ref_name)) {
            git_reference_free(created);
            git_commit_free(start_commit);
            smallclueGitPrintError("checkout: branch reference name too long");
            return 1;
        }
        git_reference_free(created);
        git_commit_free(start_commit);
    }

    if (created_ref_name[0]) {
        return smallclueGitCheckoutRef(repo, created_ref_name, &checkout_opts);
    }

    if (detach) {
        git_object *obj = NULL;
        if (git_revparse_single(&obj, repo, target_spec) != 0 || !obj) {
            smallclueGitPrintLibgitError("checkout: revision lookup failed");
            return 128;
        }
        int rc = smallclueGitCheckoutDetached(repo, obj, &checkout_opts);
        git_object_free(obj);
        return rc;
    }

    git_reference *branch = NULL;
    int branch_lookup = git_branch_lookup(&branch, repo, target_spec, GIT_BRANCH_LOCAL);
    if (branch_lookup == 0 && branch) {
        const char *ref_name = git_reference_name(branch);
        char ref_buf[PATH_MAX];
        if (!ref_name || snprintf(ref_buf, sizeof(ref_buf), "%s", ref_name) >= (int)sizeof(ref_buf)) {
            git_reference_free(branch);
            smallclueGitPrintError("checkout: branch reference name too long");
            return 1;
        }
        git_reference_free(branch);
        return smallclueGitCheckoutRef(repo, ref_buf, &checkout_opts);
    }

    if (switch_style) {
        fprintf(stderr, "fatal: invalid reference: %s\n", target_spec);
        return 1;
    }

    git_object *obj = NULL;
    if (git_revparse_single(&obj, repo, target_spec) != 0 || !obj) {
        smallclueGitPrintLibgitError("checkout: revision lookup failed");
        return 128;
    }
    int rc = smallclueGitCheckoutDetached(repo, obj, &checkout_opts);
    git_object_free(obj);
    return rc;
}

static int smallclueGitCommandCheckout(git_repository *repo, int argc, char **argv) {
    return smallclueGitCommandCheckoutCommon(repo, argc, argv, false);
}

static int smallclueGitCommandSwitch(git_repository *repo, int argc, char **argv) {
    return smallclueGitCommandCheckoutCommon(repo, argc, argv, true);
}

static char smallclueGitStatusCodeIndex(unsigned int status) {
    if (status & GIT_STATUS_INDEX_NEW) return 'A';
    if (status & GIT_STATUS_INDEX_MODIFIED) return 'M';
    if (status & GIT_STATUS_INDEX_DELETED) return 'D';
    if (status & GIT_STATUS_INDEX_RENAMED) return 'R';
    if (status & GIT_STATUS_INDEX_TYPECHANGE) return 'T';
    return ' ';
}

static char smallclueGitStatusCodeWorktree(unsigned int status) {
    if (status & GIT_STATUS_WT_MODIFIED) return 'M';
    if (status & GIT_STATUS_WT_DELETED) return 'D';
    if (status & GIT_STATUS_WT_RENAMED) return 'R';
    if (status & GIT_STATUS_WT_TYPECHANGE) return 'T';
    return ' ';
}

static const char *smallclueGitStatusPath(const git_status_entry *entry) {
    if (!entry) {
        return NULL;
    }
    if (entry->index_to_workdir && entry->index_to_workdir->new_file.path) {
        return entry->index_to_workdir->new_file.path;
    }
    if (entry->head_to_index && entry->head_to_index->new_file.path) {
        return entry->head_to_index->new_file.path;
    }
    if (entry->head_to_index && entry->head_to_index->old_file.path) {
        return entry->head_to_index->old_file.path;
    }
    return NULL;
}

static int smallclueGitCommandStatus(git_repository *repo, int argc, char **argv) {
    bool short_output = false;
    bool show_branch = false;
    unsigned int untracked_mode = GIT_STATUS_OPT_INCLUDE_UNTRACKED | GIT_STATUS_OPT_RECURSE_UNTRACKED_DIRS;

    for (int i = 0; i < argc; ++i) {
        const char *arg = argv[i];
        if (!arg) {
            continue;
        }
        if (strcmp(arg, "-s") == 0 || strcmp(arg, "--short") == 0) {
            short_output = true;
            continue;
        }
        if (strcmp(arg, "-b") == 0 || strcmp(arg, "--branch") == 0) {
            show_branch = true;
            continue;
        }
        if (strcmp(arg, "--porcelain") == 0 || strcmp(arg, "--porcelain=v1") == 0) {
            short_output = true;
            continue;
        }
        if (strncmp(arg, "--untracked-files=", 18) == 0) {
            const char *mode = arg + 18;
            if (strcmp(mode, "no") == 0) {
                untracked_mode = 0;
            } else if (strcmp(mode, "normal") == 0) {
                untracked_mode = GIT_STATUS_OPT_INCLUDE_UNTRACKED;
            } else if (strcmp(mode, "all") == 0) {
                untracked_mode = GIT_STATUS_OPT_INCLUDE_UNTRACKED | GIT_STATUS_OPT_RECURSE_UNTRACKED_DIRS;
            } else {
                smallclueGitPrintError("unsupported value for --untracked-files");
                return 2;
            }
            continue;
        }
        smallclueGitPrintError("unsupported status option");
        return 2;
    }

    if (show_branch) {
        git_reference *head = NULL;
        if (git_repository_head(&head, repo) == 0) {
            const char *name = git_reference_shorthand(head);
            if (!name || !*name) {
                name = "HEAD";
            }
            printf("## %s\n", name);
            git_reference_free(head);
        } else if (git_repository_head_detached(repo)) {
            puts("## HEAD (detached)");
        } else {
            puts("## HEAD");
        }
    }

    git_status_options options = GIT_STATUS_OPTIONS_INIT;
    options.show = GIT_STATUS_SHOW_INDEX_AND_WORKDIR;
    options.flags = GIT_STATUS_OPT_INCLUDE_UNMODIFIED |
                    GIT_STATUS_OPT_EXCLUDE_SUBMODULES |
                    GIT_STATUS_OPT_RENAMES_HEAD_TO_INDEX |
                    GIT_STATUS_OPT_RENAMES_INDEX_TO_WORKDIR |
                    GIT_STATUS_OPT_SORT_CASE_SENSITIVELY |
                    untracked_mode;

    git_status_list *status_list = NULL;
    if (git_status_list_new(&status_list, repo, &options) != 0) {
        smallclueGitPrintLibgitError("status failed");
        return 1;
    }

    size_t count = git_status_list_entrycount(status_list);
    for (size_t i = 0; i < count; ++i) {
        const git_status_entry *entry = git_status_byindex(status_list, i);
        if (!entry) {
            continue;
        }
        unsigned int st = entry->status;
        if (st == GIT_STATUS_CURRENT) {
            continue;
        }

        const char *path = smallclueGitStatusPath(entry);
        if (!path) {
            continue;
        }

        if (st & GIT_STATUS_WT_NEW) {
            printf("?? %s\n", path);
            continue;
        }

        char x = smallclueGitStatusCodeIndex(st);
        char y = smallclueGitStatusCodeWorktree(st);
        if (!short_output && !show_branch) {
            short_output = true;
        }
        printf("%c%c %s\n", x, y, path);
    }

    git_status_list_free(status_list);
    return 0;
}

typedef struct SmallclueGitBranchEntry {
    char *name;
    bool current;
    char short_oid[16];
    char *subject;
} SmallclueGitBranchEntry;

static int smallclueGitBranchEntryCompare(const void *a, const void *b) {
    const SmallclueGitBranchEntry *lhs = (const SmallclueGitBranchEntry *)a;
    const SmallclueGitBranchEntry *rhs = (const SmallclueGitBranchEntry *)b;
    if (!lhs->name && !rhs->name) return 0;
    if (!lhs->name) return -1;
    if (!rhs->name) return 1;
    return strcmp(lhs->name, rhs->name);
}

static int smallclueGitPatternMatchAny(const char *name, int pattern_count, char **patterns) {
    if (pattern_count <= 0) {
        return 1;
    }
    for (int i = 0; i < pattern_count; ++i) {
        if (fnmatch(patterns[i], name, 0) == 0) {
            return 1;
        }
    }
    return 0;
}

static int smallclueGitCommandBranchList(git_repository *repo,
                                         bool all,
                                         bool verbose,
                                         int pattern_count,
                                         char **patterns) {
    git_reference *head = NULL;
    const char *head_name = NULL;
    if (git_repository_head(&head, repo) == 0) {
        head_name = git_reference_shorthand(head);
    }

    git_branch_t branch_flags = all ? GIT_BRANCH_ALL : GIT_BRANCH_LOCAL;
    git_branch_iterator *it = NULL;
    if (git_branch_iterator_new(&it, repo, branch_flags) != 0) {
        if (head) git_reference_free(head);
        smallclueGitPrintLibgitError("branch listing failed");
        return 1;
    }

    SmallclueGitBranchEntry *entries = NULL;
    size_t count = 0;
    size_t cap = 0;

    git_reference *ref = NULL;
    git_branch_t type = GIT_BRANCH_LOCAL;
    while (git_branch_next(&ref, &type, it) == 0) {
        const char *name = NULL;
        if (git_branch_name(&name, ref) != 0 || !name) {
            git_reference_free(ref);
            ref = NULL;
            continue;
        }
        if (!smallclueGitPatternMatchAny(name, pattern_count, patterns)) {
            git_reference_free(ref);
            ref = NULL;
            continue;
        }

        if (count == cap) {
            size_t new_cap = cap == 0 ? 8 : cap * 2;
            SmallclueGitBranchEntry *resized = (SmallclueGitBranchEntry *)realloc(entries, new_cap * sizeof(*entries));
            if (!resized) {
                git_reference_free(ref);
                ref = NULL;
                break;
            }
            entries = resized;
            cap = new_cap;
        }

        SmallclueGitBranchEntry *e = &entries[count++];
        memset(e, 0, sizeof(*e));
        e->name = strdup(name);
        e->current = (head_name && strcmp(name, head_name) == 0);

        const git_oid *oid = git_reference_target(ref);
        if (!oid) {
            git_reference *peeled = NULL;
            if (git_reference_peel((git_object **)&peeled, ref, GIT_OBJECT_COMMIT) == 0 && peeled) {
                oid = git_reference_target(peeled);
                git_reference_free(peeled);
            }
        }

        if (oid) {
            (void)smallclueGitOidShort(oid, 7, e->short_oid, sizeof(e->short_oid));
            git_commit *commit = NULL;
            if (git_commit_lookup(&commit, repo, oid) == 0) {
                const char *subject = smallclueGitCommitSubject(commit);
                char line[256];
                smallclueGitCopySubjectLine(subject, line, sizeof(line));
                e->subject = strdup(line);
                git_commit_free(commit);
            }
        }

        git_reference_free(ref);
        ref = NULL;
    }

    if (ref) {
        git_reference_free(ref);
    }
    git_branch_iterator_free(it);
    if (head) {
        git_reference_free(head);
    }

    qsort(entries, count, sizeof(*entries), smallclueGitBranchEntryCompare);

    for (size_t i = 0; i < count; ++i) {
        const SmallclueGitBranchEntry *e = &entries[i];
        if (!e->name) {
            continue;
        }
        char marker = e->current ? '*' : ' ';
        if (verbose) {
            const char *subject = (e->subject && *e->subject) ? e->subject : "";
            printf("%c %-7s %s %s\n", marker, e->name, e->short_oid[0] ? e->short_oid : "0000000", subject);
        } else {
            printf("%c %s\n", marker, e->name);
        }
    }

    for (size_t i = 0; i < count; ++i) {
        free(entries[i].name);
        free(entries[i].subject);
    }
    free(entries);
    return 0;
}

static int smallclueGitCommandBranchCreate(git_repository *repo,
                                           const char *name,
                                           const char *start_point) {
    if (!name || !*name) {
        smallclueGitPrintError("branch name is required");
        return 2;
    }
    const char *base = (start_point && *start_point) ? start_point : "HEAD";
    git_commit *target = NULL;
    if (smallclueGitResolveCommit(repo, base, &target) != 0 || !target) {
        smallclueGitPrintLibgitError("branch: invalid start point");
        return 128;
    }

    git_reference *created = NULL;
    if (git_branch_create(&created, repo, name, target, 0) != 0) {
        git_commit_free(target);
        smallclueGitPrintLibgitError("branch create failed");
        return 1;
    }

    git_reference_free(created);
    git_commit_free(target);
    return 0;
}

static int smallclueGitCommandBranchDelete(git_repository *repo,
                                           int name_count,
                                           char **names,
                                           bool force) {
    git_reference *head = NULL;
    const char *head_name = NULL;
    if (git_repository_head(&head, repo) == 0 && head) {
        head_name = git_reference_shorthand(head);
    }

    for (int i = 0; i < name_count; ++i) {
        const char *name = names[i];
        if (!name || !*name) {
            continue;
        }
        if (head_name && strcmp(head_name, name) == 0) {
            const char *workdir = git_repository_workdir(repo);
            if (!workdir || !*workdir) {
                workdir = "<bare-repo>";
            } else {
                char display_workdir[PATH_MAX];
                if (smallclueGitDisplayPath(workdir, display_workdir, sizeof(display_workdir)) == 0) {
                    workdir = display_workdir;
                }
            }
            if (head) git_reference_free(head);
            fprintf(stderr, "error: Cannot delete branch '%s' checked out at '%s'\n", name, workdir);
            return 1;
        }

        git_reference *branch = NULL;
        if (git_branch_lookup(&branch, repo, name, GIT_BRANCH_LOCAL) != 0 || !branch) {
            if (head) git_reference_free(head);
            fprintf(stderr, "error: branch '%s' not found\n", name);
            return 1;
        }

        char short_oid[16] = "0000000";
        const git_oid *oid = git_reference_target(branch);
        if (oid) {
            (void)smallclueGitOidShort(oid, 7, short_oid, sizeof(short_oid));
        }

        int rc = 0;
        if (force) {
            rc = git_reference_delete(branch);
        } else {
            rc = git_branch_delete(branch);
        }
        if (rc != 0) {
            git_reference_free(branch);
            if (head) git_reference_free(head);
            if (!force && git_error_last() && git_error_last()->klass == GIT_ERROR_REFERENCE) {
                fprintf(stderr, "error: The branch '%s' is not fully merged.\n", name);
            } else {
                smallclueGitPrintLibgitError("branch delete failed");
            }
            return 1;
        }

        printf("Deleted branch %s (was %s).\n", name, short_oid);
        git_reference_free(branch);
    }

    if (head) git_reference_free(head);
    return 0;
}

static int smallclueGitCommandBranchRename(git_repository *repo,
                                           int operand_count,
                                           char **operands,
                                           bool force) {
    const char *old_name = NULL;
    const char *new_name = NULL;

    if (operand_count == 1) {
        new_name = operands[0];
        git_reference *head = NULL;
        if (git_repository_head(&head, repo) != 0 || !head) {
            fprintf(stderr, "fatal: No branch to rename\n");
            return 128;
        }
        old_name = git_reference_shorthand(head);
        git_reference_free(head);
    } else if (operand_count == 2) {
        old_name = operands[0];
        new_name = operands[1];
    } else {
        smallclueGitPrintError("branch rename expects one or two branch names");
        return 2;
    }

    if (!old_name || !*old_name || !new_name || !*new_name) {
        smallclueGitPrintError("branch rename expects valid branch names");
        return 2;
    }

    git_reference *branch = NULL;
    if (git_branch_lookup(&branch, repo, old_name, GIT_BRANCH_LOCAL) != 0 || !branch) {
        fprintf(stderr, "error: branch '%s' not found\n", old_name);
        return 1;
    }

    git_reference *moved = NULL;
    if (git_branch_move(&moved, branch, new_name, force ? 1 : 0) != 0) {
        git_reference_free(branch);
        smallclueGitPrintLibgitError("branch rename failed");
        return 1;
    }

    git_reference_free(moved);
    git_reference_free(branch);
    return 0;
}

static int smallclueGitCommandBranch(git_repository *repo, int argc, char **argv) {
    enum {
        SMALLCLUE_BRANCH_LIST = 0,
        SMALLCLUE_BRANCH_CREATE,
        SMALLCLUE_BRANCH_DELETE,
        SMALLCLUE_BRANCH_RENAME,
    } action = SMALLCLUE_BRANCH_LIST;

    bool all = false;
    bool verbose = false;
    bool explicit_list = false;
    bool force = false;
    int operand_start = argc;

    for (int i = 0; i < argc; ++i) {
        const char *arg = argv[i];
        if (!arg) {
            continue;
        }
        if (strcmp(arg, "--list") == 0 || strcmp(arg, "-l") == 0) {
            action = SMALLCLUE_BRANCH_LIST;
            explicit_list = true;
            continue;
        }
        if (strcmp(arg, "-a") == 0) {
            all = true;
            action = SMALLCLUE_BRANCH_LIST;
            explicit_list = true;
            continue;
        }
        if (strcmp(arg, "-v") == 0 || strcmp(arg, "-vv") == 0) {
            verbose = true;
            action = SMALLCLUE_BRANCH_LIST;
            explicit_list = true;
            continue;
        }
        if (strcmp(arg, "-d") == 0) {
            action = SMALLCLUE_BRANCH_DELETE;
            force = false;
            operand_start = i + 1;
            break;
        }
        if (strcmp(arg, "-D") == 0) {
            action = SMALLCLUE_BRANCH_DELETE;
            force = true;
            operand_start = i + 1;
            break;
        }
        if (strcmp(arg, "-m") == 0) {
            action = SMALLCLUE_BRANCH_RENAME;
            force = false;
            operand_start = i + 1;
            break;
        }
        if (strcmp(arg, "-M") == 0) {
            action = SMALLCLUE_BRANCH_RENAME;
            force = true;
            operand_start = i + 1;
            break;
        }
        if (arg[0] == '-') {
            smallclueGitPrintError("unsupported branch option");
            return 2;
        }

        operand_start = i;
        action = explicit_list ? SMALLCLUE_BRANCH_LIST : SMALLCLUE_BRANCH_CREATE;
        break;
    }

    if (action == SMALLCLUE_BRANCH_LIST) {
        int pattern_count = 0;
        char **patterns = NULL;
        if (operand_start < argc) {
            pattern_count = argc - operand_start;
            patterns = &argv[operand_start];
        }
        return smallclueGitCommandBranchList(repo, all, verbose, pattern_count, patterns);
    }

    if (action == SMALLCLUE_BRANCH_CREATE) {
        int count = (operand_start < argc) ? (argc - operand_start) : 0;
        if (count < 1 || count > 2) {
            smallclueGitPrintError("branch create expects: git branch <name> [start-point]");
            return 2;
        }
        const char *name = argv[operand_start];
        const char *start_point = (count > 1) ? argv[operand_start + 1] : NULL;
        return smallclueGitCommandBranchCreate(repo, name, start_point);
    }

    if (action == SMALLCLUE_BRANCH_DELETE) {
        int count = (operand_start < argc) ? (argc - operand_start) : 0;
        if (count <= 0) {
            smallclueGitPrintError("branch delete expects at least one branch name");
            return 2;
        }
        return smallclueGitCommandBranchDelete(repo, count, &argv[operand_start], force);
    }

    if (action == SMALLCLUE_BRANCH_RENAME) {
        int count = (operand_start < argc) ? (argc - operand_start) : 0;
        return smallclueGitCommandBranchRename(repo, count, &argv[operand_start], force);
    }

    smallclueGitPrintError("unsupported branch mode");
    return 2;
}

static char smallclueGitDeltaStatusLetter(git_delta_t status) {
    switch (status) {
        case GIT_DELTA_ADDED:
            return 'A';
        case GIT_DELTA_DELETED:
            return 'D';
        case GIT_DELTA_RENAMED:
            return 'R';
        case GIT_DELTA_TYPECHANGE:
            return 'T';
        case GIT_DELTA_COPIED:
            return 'C';
        case GIT_DELTA_MODIFIED:
        default:
            return 'M';
    }
}

static int smallclueGitPrintDiffNameOnly(git_diff *diff) {
    size_t n = git_diff_num_deltas(diff);
    for (size_t i = 0; i < n; ++i) {
        const git_diff_delta *delta = git_diff_get_delta(diff, i);
        if (!delta || !delta->new_file.path) {
            continue;
        }
        puts(delta->new_file.path);
    }
    return 0;
}

static int smallclueGitPrintDiffNameStatus(git_diff *diff) {
    size_t n = git_diff_num_deltas(diff);
    for (size_t i = 0; i < n; ++i) {
        const git_diff_delta *delta = git_diff_get_delta(diff, i);
        if (!delta || !delta->new_file.path) {
            continue;
        }
        printf("%c\t%s\n", smallclueGitDeltaStatusLetter(delta->status), delta->new_file.path);
    }
    return 0;
}

static int smallclueGitPrintDiffStat(git_diff *diff) {
    git_diff_stats *stats = NULL;
    git_buf buf = GIT_BUF_INIT;
    if (git_diff_get_stats(&stats, diff) != 0) {
        smallclueGitPrintLibgitError("diff stat failed");
        return 1;
    }
    if (git_diff_stats_to_buf(&buf, stats, GIT_DIFF_STATS_FULL, 80) != 0) {
        git_diff_stats_free(stats);
        smallclueGitPrintLibgitError("diff stat formatting failed");
        return 1;
    }
    if (buf.ptr && buf.size > 0) {
        fputs(buf.ptr, stdout);
    }
    git_buf_dispose(&buf);
    git_diff_stats_free(stats);
    return 0;
}

static int smallclueGitDiffPrintCallback(const git_diff_delta *delta,
                                         const git_diff_hunk *hunk,
                                         const git_diff_line *line,
                                         void *payload) {
    (void)delta;
    (void)hunk;
    (void)payload;
    if (!line || !line->content || line->content_len == 0) {
        return 0;
    }
    switch (line->origin) {
        case GIT_DIFF_LINE_CONTEXT:
        case GIT_DIFF_LINE_ADDITION:
        case GIT_DIFF_LINE_DELETION:
            fputc((int)line->origin, stdout);
            break;
        default:
            break;
    }
    fwrite(line->content, 1, line->content_len, stdout);
    return 0;
}

static int smallclueGitPrintDiff(git_diff *diff, SmallclueGitDiffMode mode) {
    switch (mode) {
        case SMALLCLUE_GIT_DIFF_NAME_ONLY:
            return smallclueGitPrintDiffNameOnly(diff);
        case SMALLCLUE_GIT_DIFF_NAME_STATUS:
            return smallclueGitPrintDiffNameStatus(diff);
        case SMALLCLUE_GIT_DIFF_STAT:
            return smallclueGitPrintDiffStat(diff);
        case SMALLCLUE_GIT_DIFF_PATCH:
        default:
            if (git_diff_print(diff, GIT_DIFF_FORMAT_PATCH, smallclueGitDiffPrintCallback, NULL) != 0) {
                smallclueGitPrintLibgitError("diff print failed");
                return 1;
            }
            return 0;
    }
}

static int smallclueGitResolveCommit(git_repository *repo, const char *spec, git_commit **out_commit) {
    *out_commit = NULL;
    git_object *obj = NULL;
    if (git_revparse_single(&obj, repo, spec) != 0) {
        return -1;
    }
    git_commit *commit = NULL;
    if (git_object_peel((git_object **)&commit, obj, GIT_OBJECT_COMMIT) != 0) {
        git_object_free(obj);
        return -1;
    }
    git_object_free(obj);
    *out_commit = commit;
    return 0;
}

static int smallclueGitBuildDiff(git_repository *repo,
                                 bool cached,
                                 int rev_count,
                                 char **revs,
                                 uint32_t context_lines,
                                 git_diff **out_diff) {
    *out_diff = NULL;

    git_diff_options opts = GIT_DIFF_OPTIONS_INIT;
    opts.context_lines = context_lines;

    if (rev_count == 0 && !cached) {
        git_index *index = NULL;
        if (git_repository_index(&index, repo) != 0) {
            return -1;
        }
        int rc = git_diff_index_to_workdir(out_diff, repo, index, &opts);
        git_index_free(index);
        return rc;
    }

    if (rev_count == 0 && cached) {
        git_commit *head_commit = NULL;
        git_tree *head_tree = NULL;
        git_index *index = NULL;

        if (smallclueGitResolveCommit(repo, "HEAD", &head_commit) != 0) {
            return -1;
        }
        if (git_commit_tree(&head_tree, head_commit) != 0) {
            git_commit_free(head_commit);
            return -1;
        }
        if (git_repository_index(&index, repo) != 0) {
            git_tree_free(head_tree);
            git_commit_free(head_commit);
            return -1;
        }

        int rc = git_diff_tree_to_index(out_diff, repo, head_tree, index, &opts);

        git_index_free(index);
        git_tree_free(head_tree);
        git_commit_free(head_commit);
        return rc;
    }

    if (rev_count == 2) {
        git_commit *left_commit = NULL;
        git_commit *right_commit = NULL;
        git_tree *left_tree = NULL;
        git_tree *right_tree = NULL;

        if (smallclueGitResolveCommit(repo, revs[0], &left_commit) != 0) {
            return -1;
        }
        if (smallclueGitResolveCommit(repo, revs[1], &right_commit) != 0) {
            git_commit_free(left_commit);
            return -1;
        }
        if (git_commit_tree(&left_tree, left_commit) != 0 ||
            git_commit_tree(&right_tree, right_commit) != 0) {
            git_tree_free(left_tree);
            git_tree_free(right_tree);
            git_commit_free(left_commit);
            git_commit_free(right_commit);
            return -1;
        }

        int rc = git_diff_tree_to_tree(out_diff, repo, left_tree, right_tree, &opts);

        git_tree_free(left_tree);
        git_tree_free(right_tree);
        git_commit_free(left_commit);
        git_commit_free(right_commit);
        return rc;
    }

    return -1;
}

static int smallclueGitCommandDiff(git_repository *repo, int argc, char **argv) {
    bool cached = false;
    SmallclueGitDiffMode mode = SMALLCLUE_GIT_DIFF_PATCH;
    uint32_t context_lines = 3;
    char *revs[2] = {0};
    int rev_count = 0;

    for (int i = 0; i < argc; ++i) {
        const char *arg = argv[i];
        if (!arg) {
            continue;
        }
        if (strcmp(arg, "--cached") == 0) {
            cached = true;
            continue;
        }
        if (strcmp(arg, "--name-only") == 0) {
            mode = SMALLCLUE_GIT_DIFF_NAME_ONLY;
            continue;
        }
        if (strcmp(arg, "--name-status") == 0) {
            mode = SMALLCLUE_GIT_DIFF_NAME_STATUS;
            continue;
        }
        if (strcmp(arg, "--stat") == 0) {
            mode = SMALLCLUE_GIT_DIFF_STAT;
            continue;
        }
        if (strcmp(arg, "--no-color") == 0) {
            continue;
        }
        if (strncmp(arg, "-U", 2) == 0) {
            const char *n = arg + 2;
            if (*n == '\0') {
                smallclueGitPrintError("-U requires a value");
                return 2;
            }
            char *end = NULL;
            long v = strtol(n, &end, 10);
            if (!end || *end != '\0' || v < 0) {
                smallclueGitPrintError("invalid -U value");
                return 2;
            }
            context_lines = (uint32_t)v;
            continue;
        }
        if (arg[0] == '-') {
            smallclueGitPrintError("unsupported diff option");
            return 2;
        }
        if (rev_count < 2) {
            revs[rev_count++] = (char *)arg;
            continue;
        }
        smallclueGitPrintError("too many revisions for diff");
        return 2;
    }

    git_diff *diff = NULL;
    if (smallclueGitBuildDiff(repo, cached, rev_count, revs, context_lines, &diff) != 0 || !diff) {
        smallclueGitPrintLibgitError("failed to build diff");
        return 128;
    }

    int rc = smallclueGitPrintDiff(diff, mode);
    git_diff_free(diff);
    return rc;
}

static int smallclueGitTagExtractMessage(git_repository *repo, const char *tag_name, char *out, size_t out_sz) {
    out[0] = '\0';
    git_object *obj = NULL;
    if (git_revparse_single(&obj, repo, tag_name) != 0 || !obj) {
        return -1;
    }

    int rc = -1;
    if (git_object_type(obj) == GIT_OBJECT_TAG) {
        git_tag *tag = (git_tag *)obj;
        const char *msg = git_tag_message(tag);
        if (msg) {
            smallclueGitCopySubjectLine(msg, out, out_sz);
            rc = 0;
        }
    } else if (git_object_type(obj) == GIT_OBJECT_COMMIT) {
        git_commit *commit = (git_commit *)obj;
        const char *msg = git_commit_message(commit);
        if (msg) {
            smallclueGitCopySubjectLine(msg, out, out_sz);
            rc = 0;
        }
    }

    git_object_free(obj);
    return rc;
}

static int smallclueGitCommandTagList(git_repository *repo,
                                      int annotation_width,
                                      int pattern_count,
                                      char **patterns) {
    git_strarray names = {0};
    if (git_tag_list(&names, repo) != 0) {
        smallclueGitPrintLibgitError("tag list failed");
        return 1;
    }

    for (size_t i = 0; i < names.count; ++i) {
        const char *name = names.strings[i];
        if (!name) {
            continue;
        }
        if (!smallclueGitPatternMatchAny(name, pattern_count, patterns)) {
            continue;
        }
        if (annotation_width > 0) {
            char msg[256];
            if (smallclueGitTagExtractMessage(repo, name, msg, sizeof(msg)) != 0) {
                msg[0] = '\0';
            }
            printf("%-15s %s\n", name, msg);
        } else {
            puts(name);
        }
    }

    git_strarray_dispose(&names);
    return 0;
}

static int smallclueGitCommandTagCreate(git_repository *repo,
                                        const char *name,
                                        const char *target_spec,
                                        bool annotated,
                                        const char *message,
                                        bool force) {
    if (!name || !*name) {
        smallclueGitPrintError("tag name is required");
        return 2;
    }
    if (annotated && (!message || !*message)) {
        smallclueGitPrintError("annotated tag creation requires -m <message>");
        return 2;
    }

    const char *target_expr = (target_spec && *target_spec) ? target_spec : "HEAD";
    git_object *target_obj = NULL;
    if (git_revparse_single(&target_obj, repo, target_expr) != 0 || !target_obj) {
        smallclueGitPrintLibgitError("tag: invalid target");
        return 128;
    }

    git_oid out_oid = {{0}};
    int rc = 0;
    if (annotated) {
        git_signature *author = NULL;
        git_signature *committer = NULL;
        if (smallclueGitCreateDefaultSignatures(repo, &author, &committer) != 0) {
            git_object_free(target_obj);
            smallclueGitPrintError("unable to resolve git user identity for tag");
            return 1;
        }
        rc = git_tag_create(&out_oid, repo, name, target_obj, author, message, force ? 1 : 0);
        git_signature_free(author);
        git_signature_free(committer);
    } else {
        rc = git_tag_create_lightweight(&out_oid, repo, name, target_obj, force ? 1 : 0);
    }

    git_object_free(target_obj);

    if (rc != 0) {
        smallclueGitPrintLibgitError("tag create failed");
        return 1;
    }
    return 0;
}

static int smallclueGitCommandTagDelete(git_repository *repo, int count, char **names) {
    for (int i = 0; i < count; ++i) {
        const char *name = names[i];
        if (!name || !*name) {
            continue;
        }

        char spec[PATH_MAX];
        if (snprintf(spec, sizeof(spec), "refs/tags/%s", name) >= (int)sizeof(spec)) {
            smallclueGitPrintError("tag name too long");
            return 1;
        }

        char short_oid[16] = "0000000";
        git_object *obj = NULL;
        if (git_revparse_single(&obj, repo, spec) == 0 && obj) {
            (void)smallclueGitOidShort(git_object_id(obj), 7, short_oid, sizeof(short_oid));
            git_object_free(obj);
        }

        if (git_tag_delete(repo, name) != 0) {
            fprintf(stderr, "error: tag '%s' not found\n", name);
            return 1;
        }
        printf("Deleted tag '%s' (was %s)\n", name, short_oid);
    }
    return 0;
}

static int smallclueGitCommandTag(git_repository *repo, int argc, char **argv) {
    enum {
        SMALLCLUE_TAG_LIST = 0,
        SMALLCLUE_TAG_CREATE,
        SMALLCLUE_TAG_DELETE,
    } action = SMALLCLUE_TAG_LIST;

    bool explicit_list = false;
    bool annotated = false;
    bool force = false;
    int annotation_width = 0;
    const char *message = NULL;
    int operand_start = argc;

    for (int i = 0; i < argc; ++i) {
        const char *arg = argv[i];
        if (!arg) {
            continue;
        }
        if (strcmp(arg, "--list") == 0 || strcmp(arg, "-l") == 0) {
            action = SMALLCLUE_TAG_LIST;
            explicit_list = true;
            continue;
        }
        if (strcmp(arg, "-d") == 0) {
            action = SMALLCLUE_TAG_DELETE;
            operand_start = i + 1;
            break;
        }
        if (strcmp(arg, "-a") == 0) {
            annotated = true;
            continue;
        }
        if (strcmp(arg, "-f") == 0) {
            force = true;
            continue;
        }
        if (strcmp(arg, "-m") == 0) {
            if (i + 1 >= argc) {
                smallclueGitPrintError("tag -m requires a message");
                return 2;
            }
            message = argv[++i];
            continue;
        }
        if (strcmp(arg, "-n") == 0) {
            annotation_width = 1;
            action = SMALLCLUE_TAG_LIST;
            explicit_list = true;
            continue;
        }
        if (strncmp(arg, "-n", 2) == 0 && arg[2] != '\0') {
            char *end = NULL;
            long v = strtol(arg + 2, &end, 10);
            if (!end || *end != '\0' || v < 0) {
                smallclueGitPrintError("invalid -n value for tag");
                return 2;
            }
            annotation_width = (int)v;
            action = SMALLCLUE_TAG_LIST;
            explicit_list = true;
            continue;
        }
        if (arg[0] == '-') {
            smallclueGitPrintError("unsupported tag option");
            return 2;
        }

        operand_start = i;
        if (explicit_list) {
            action = SMALLCLUE_TAG_LIST;
        } else if (action != SMALLCLUE_TAG_DELETE) {
            action = SMALLCLUE_TAG_CREATE;
        }
        break;
    }

    if (action == SMALLCLUE_TAG_LIST) {
        int pattern_count = 0;
        char **patterns = NULL;
        if (operand_start < argc) {
            pattern_count = argc - operand_start;
            patterns = &argv[operand_start];
        }
        return smallclueGitCommandTagList(repo, annotation_width, pattern_count, patterns);
    }

    if (action == SMALLCLUE_TAG_DELETE) {
        int count = (operand_start < argc) ? (argc - operand_start) : 0;
        if (count <= 0) {
            smallclueGitPrintError("tag delete expects at least one tag name");
            return 2;
        }
        return smallclueGitCommandTagDelete(repo, count, &argv[operand_start]);
    }

    if (action == SMALLCLUE_TAG_CREATE) {
        int count = (operand_start < argc) ? (argc - operand_start) : 0;
        if (count < 1 || count > 2) {
            smallclueGitPrintError("tag create expects: git tag [-a] [-m msg] <name> [target]");
            return 2;
        }
        return smallclueGitCommandTagCreate(repo,
                                            argv[operand_start],
                                            count > 1 ? argv[operand_start + 1] : NULL,
                                            annotated,
                                            message,
                                            force);
    }

    smallclueGitPrintError("unsupported tag mode");
    return 2;
}

static int smallclueGitDecorateCommit(git_repository *repo,
                                      const git_oid *commit_oid,
                                      const char *head_name,
                                      const git_oid *head_target,
                                      char *out,
                                      size_t out_sz) {
    if (!out || out_sz == 0) {
        return -1;
    }
    out[0] = '\0';
    bool first = true;

    if (head_name && head_target && git_oid_equal(commit_oid, head_target)) {
        snprintf(out, out_sz, "HEAD -> %s", head_name);
        first = false;
    }

    git_branch_iterator *bit = NULL;
    if (git_branch_iterator_new(&bit, repo, GIT_BRANCH_LOCAL) == 0) {
        git_reference *ref = NULL;
        git_branch_t type;
        while (git_branch_next(&ref, &type, bit) == 0) {
            const char *name = NULL;
            if (git_branch_name(&name, ref) == 0 && name && *name) {
                const git_oid *oid = git_reference_target(ref);
                if (oid && git_oid_equal(commit_oid, oid)) {
                    if (!(head_name && strcmp(head_name, name) == 0)) {
                        size_t used = strlen(out);
                        int n = snprintf(out + used,
                                         out_sz > used ? out_sz - used : 0,
                                         "%s%s",
                                         first ? "" : ", ",
                                         name);
                        if (n > 0) {
                            first = false;
                        }
                    }
                }
            }
            git_reference_free(ref);
            ref = NULL;
        }
        git_branch_iterator_free(bit);
    }

    git_strarray tags = {0};
    if (git_tag_list(&tags, repo) == 0) {
        for (size_t i = 0; i < tags.count; ++i) {
            const char *name = tags.strings[i];
            if (!name) {
                continue;
            }
            git_object *obj = NULL;
            if (git_revparse_single(&obj, repo, name) != 0 || !obj) {
                continue;
            }
            git_object *peeled = NULL;
            if (git_object_peel(&peeled, obj, GIT_OBJECT_COMMIT) == 0 && peeled) {
                const git_oid *oid = git_object_id(peeled);
                if (oid && git_oid_equal(commit_oid, oid)) {
                    size_t used = strlen(out);
                    (void)snprintf(out + used,
                                   out_sz > used ? out_sz - used : 0,
                                   "%s%s%s",
                                   first ? "" : ", ",
                                   "tag: ",
                                   name);
                    first = false;
                }
                git_object_free(peeled);
            }
            git_object_free(obj);
        }
        git_strarray_dispose(&tags);
    }

    return 0;
}

static int smallclueGitCommandLog(git_repository *repo, int argc, char **argv) {
    bool oneline = false;
    bool decorate = false;
    bool reverse = false;
    int max_count = -1;
    const char *author_filter = NULL;
    const char *grep_filter = NULL;

    for (int i = 0; i < argc; ++i) {
        const char *arg = argv[i];
        if (!arg) continue;
        if (strcmp(arg, "--oneline") == 0) {
            oneline = true;
            continue;
        }
        if (strcmp(arg, "--decorate") == 0) {
            decorate = true;
            continue;
        }
        if (strcmp(arg, "--reverse") == 0) {
            reverse = true;
            continue;
        }
        if ((strcmp(arg, "-n") == 0 || strcmp(arg, "--max-count") == 0) && i + 1 < argc) {
            i++;
            max_count = atoi(argv[i]);
            if (max_count < 0) max_count = -1;
            continue;
        }
        if (strncmp(arg, "--max-count=", 12) == 0) {
            max_count = atoi(arg + 12);
            if (max_count < 0) max_count = -1;
            continue;
        }
        if (strcmp(arg, "--author") == 0 && i + 1 < argc) {
            i++;
            author_filter = argv[i];
            continue;
        }
        if (strncmp(arg, "--author=", 9) == 0) {
            author_filter = arg + 9;
            continue;
        }
        if (strcmp(arg, "--grep") == 0 && i + 1 < argc) {
            i++;
            grep_filter = argv[i];
            continue;
        }
        if (strncmp(arg, "--grep=", 7) == 0) {
            grep_filter = arg + 7;
            continue;
        }
        if (arg[0] == '-') {
            smallclueGitPrintError("unsupported log option");
            return 2;
        }
    }

    git_revwalk *walk = NULL;
    if (git_revwalk_new(&walk, repo) != 0) {
        smallclueGitPrintLibgitError("log walk failed");
        return 1;
    }
    git_revwalk_sorting(walk, GIT_SORT_TOPOLOGICAL | GIT_SORT_TIME);
    if (git_revwalk_push_head(walk) != 0) {
        git_revwalk_free(walk);
        smallclueGitPrintLibgitError("log push HEAD failed");
        return 1;
    }

    git_reference *head = NULL;
    const char *head_name = NULL;
    git_oid head_target;
    memset(&head_target, 0, sizeof(head_target));
    bool have_head_target = false;
    if (git_repository_head(&head, repo) == 0) {
        head_name = git_reference_shorthand(head);
        const git_oid *target = git_reference_target(head);
        if (target) {
            git_oid_cpy(&head_target, target);
            have_head_target = true;
        }
    }

    int printed = 0;
    char **reverse_lines = NULL;
    size_t reverse_count = 0;
    size_t reverse_capacity = 0;
    if (max_count == 0) {
        if (head) git_reference_free(head);
        git_revwalk_free(walk);
        return 0;
    }
    git_oid oid;
    while (git_revwalk_next(&oid, walk) == 0) {
        git_commit *commit = NULL;
        if (git_commit_lookup(&commit, repo, &oid) != 0) {
            continue;
        }

        if (author_filter && *author_filter) {
            const git_signature *sig = git_commit_author(commit);
            const char *name = sig ? sig->name : "";
            if (!name || !strstr(name, author_filter)) {
                git_commit_free(commit);
                continue;
            }
        }

        if (grep_filter && *grep_filter) {
            const char *msg = git_commit_message(commit);
            if (!msg || !strstr(msg, grep_filter)) {
                git_commit_free(commit);
                continue;
            }
        }

        char short_oid[16];
        (void)smallclueGitOidShort(&oid, 7, short_oid, sizeof(short_oid));
        char subject[512];
        smallclueGitCopySubjectLine(smallclueGitCommitSubject(commit), subject, sizeof(subject));

        char line[2048];
        line[0] = '\0';
        if (oneline || !oneline) {
            if (decorate) {
                char deco[512];
                smallclueGitDecorateCommit(repo,
                                           &oid,
                                           head_name,
                                           have_head_target ? &head_target : NULL,
                                           deco,
                                           sizeof(deco));
                if (deco[0]) {
                    (void)snprintf(line, sizeof(line), "%s (%s) %s\n", short_oid, deco, subject);
                } else {
                    (void)snprintf(line, sizeof(line), "%s %s\n", short_oid, subject);
                }
            } else {
                (void)snprintf(line, sizeof(line), "%s %s\n", short_oid, subject);
            }
            if (reverse) {
                if (reverse_count == reverse_capacity) {
                    size_t new_capacity = reverse_capacity ? reverse_capacity * 2 : 16;
                    char **grown = (char **)realloc(reverse_lines, new_capacity * sizeof(char *));
                    if (!grown) {
                        git_commit_free(commit);
                        for (size_t j = 0; j < reverse_count; ++j) {
                            free(reverse_lines[j]);
                        }
                        free(reverse_lines);
                        if (head) git_reference_free(head);
                        git_revwalk_free(walk);
                        smallclueGitPrintError("out of memory");
                        return 1;
                    }
                    reverse_lines = grown;
                    reverse_capacity = new_capacity;
                }
                reverse_lines[reverse_count] = strdup(line);
                if (!reverse_lines[reverse_count]) {
                    git_commit_free(commit);
                    for (size_t j = 0; j < reverse_count; ++j) {
                        free(reverse_lines[j]);
                    }
                    free(reverse_lines);
                    if (head) git_reference_free(head);
                    git_revwalk_free(walk);
                    smallclueGitPrintError("out of memory");
                    return 1;
                }
                reverse_count++;
            } else {
                fputs(line, stdout);
            }
        }

        printed++;
        git_commit_free(commit);
        if (max_count >= 0 && printed >= max_count) {
            break;
        }
    }

    if (reverse && reverse_lines) {
        for (size_t i = reverse_count; i > 0; --i) {
            fputs(reverse_lines[i - 1], stdout);
            free(reverse_lines[i - 1]);
        }
        free(reverse_lines);
    }

    if (head) git_reference_free(head);
    git_revwalk_free(walk);
    return 0;
}

static int smallclueGitCommandShow(git_repository *repo, int argc, char **argv) {
    bool name_only = false;
    bool name_status = false;
    bool stat_mode = false;
    bool no_patch = false;
    bool explicit_patch = false;
    const char *pretty = NULL;
    const char *revision = "HEAD";

    for (int i = 0; i < argc; ++i) {
        const char *arg = argv[i];
        if (!arg) continue;
        if (strcmp(arg, "--name-only") == 0) {
            name_only = true;
            continue;
        }
        if (strcmp(arg, "--name-status") == 0) {
            name_status = true;
            continue;
        }
        if (strcmp(arg, "--stat") == 0) {
            stat_mode = true;
            continue;
        }
        if (strcmp(arg, "--no-patch") == 0) {
            no_patch = true;
            continue;
        }
        if (strcmp(arg, "--patch") == 0) {
            explicit_patch = true;
            continue;
        }
        if (strncmp(arg, "--pretty=", 9) == 0) {
            pretty = arg + 9;
            continue;
        }
        if (arg[0] == '-') {
            smallclueGitPrintError("unsupported show option");
            return 2;
        }
        revision = arg;
    }

    git_commit *commit = NULL;
    if (smallclueGitResolveCommit(repo, revision, &commit) != 0 || !commit) {
        smallclueGitPrintLibgitError("show: unable to resolve revision");
        return 128;
    }

    const git_oid *oid = git_commit_id(commit);
    char oid_buf[GIT_OID_HEXSZ + 1];
    (void)git_oid_tostr(oid_buf, sizeof(oid_buf), oid);

    char subject[512];
    smallclueGitCopySubjectLine(smallclueGitCommitSubject(commit), subject, sizeof(subject));

    if (pretty) {
        if (strcmp(pretty, "oneline") == 0) {
            printf("%s %s\n", oid_buf, subject);
        } else if (strcmp(pretty, "format:%s") == 0) {
            printf("%s\n", subject);
        }
    }

    if (no_patch) {
        git_commit_free(commit);
        return 0;
    }

    git_tree *new_tree = NULL;
    if (git_commit_tree(&new_tree, commit) != 0) {
        git_commit_free(commit);
        smallclueGitPrintLibgitError("show: commit tree lookup failed");
        return 128;
    }

    git_tree *old_tree = NULL;
    if (git_commit_parentcount(commit) > 0) {
        git_commit *parent = NULL;
        if (git_commit_parent(&parent, commit, 0) == 0) {
            (void)git_commit_tree(&old_tree, parent);
            git_commit_free(parent);
        }
    }

    git_diff_options diff_opts = GIT_DIFF_OPTIONS_INIT;
    git_diff *diff = NULL;
    if (git_diff_tree_to_tree(&diff, repo, old_tree, new_tree, &diff_opts) != 0 || !diff) {
        git_tree_free(old_tree);
        git_tree_free(new_tree);
        git_commit_free(commit);
        smallclueGitPrintLibgitError("show: diff generation failed");
        return 128;
    }

    SmallclueGitDiffMode mode = SMALLCLUE_GIT_DIFF_PATCH;
    if (name_only) mode = SMALLCLUE_GIT_DIFF_NAME_ONLY;
    if (name_status) mode = SMALLCLUE_GIT_DIFF_NAME_STATUS;
    if (stat_mode) mode = SMALLCLUE_GIT_DIFF_STAT;
    if (explicit_patch) mode = SMALLCLUE_GIT_DIFF_PATCH;

    int rc = smallclueGitPrintDiff(diff, mode);

    git_diff_free(diff);
    git_tree_free(old_tree);
    git_tree_free(new_tree);
    git_commit_free(commit);
    return rc;
}

static int smallclueGitCurrentBranchName(git_repository *repo, char *out, size_t out_sz) {
    if (!repo || !out || out_sz == 0) {
        return -1;
    }
    out[0] = '\0';
    git_reference *head = NULL;
    if (git_repository_head(&head, repo) != 0 || !head) {
        return -1;
    }
    if (git_repository_head_detached(repo)) {
        git_reference_free(head);
        return -1;
    }
    const char *name = git_reference_shorthand(head);
    int rc = (name && *name && snprintf(out, out_sz, "%s", name) < (int)out_sz) ? 0 : -1;
    git_reference_free(head);
    return rc;
}

static int smallclueGitCommandClone(const char *start_path, int argc, char **argv) {
    bool bare = false;
    bool quiet = false;
    const char *branch = NULL;
    const char *source = NULL;
    const char *dest_arg = NULL;

    for (int i = 0; i < argc; ++i) {
        const char *arg = argv[i];
        if (!arg) {
            continue;
        }
        if (strcmp(arg, "--bare") == 0) {
            bare = true;
            continue;
        }
        if (strcmp(arg, "-q") == 0 || strcmp(arg, "--quiet") == 0) {
            quiet = true;
            continue;
        }
        if ((strcmp(arg, "-b") == 0 || strcmp(arg, "--branch") == 0) && i + 1 < argc) {
            branch = argv[++i];
            continue;
        }
        if (strncmp(arg, "--branch=", 9) == 0) {
            branch = arg + 9;
            continue;
        }
        if (arg[0] == '-') {
            smallclueGitPrintError("unsupported clone option");
            return 2;
        }
        if (!source) {
            source = arg;
            continue;
        }
        if (!dest_arg) {
            dest_arg = arg;
            continue;
        }
        smallclueGitPrintError("too many clone arguments");
        return 2;
    }

    if (!source || !*source) {
        smallclueGitPrintError("clone requires a repository source");
        return 2;
    }

    char source_buf[PATH_MAX];
    const char *clone_source = source;
    if (smallclueGitResolveMaybePathFromBase(start_path, source, source_buf, sizeof(source_buf)) == 0) {
        clone_source = source_buf;
    }

    char dest_buf[PATH_MAX];
    const char *clone_dest = NULL;
    if (dest_arg && *dest_arg) {
        if (smallclueGitResolvePathFromBase(start_path, dest_arg, dest_buf, sizeof(dest_buf)) != 0) {
            smallclueGitPrintError("clone destination path too long");
            return 2;
        }
        clone_dest = dest_buf;
    } else {
        const char *tail = strrchr(source, '/');
        tail = tail ? tail + 1 : source;
        if (!tail || !*tail) {
            smallclueGitPrintError("unable to derive destination directory from source");
            return 2;
        }
        char base_name[PATH_MAX];
        if (snprintf(base_name, sizeof(base_name), "%s", tail) >= (int)sizeof(base_name)) {
            smallclueGitPrintError("source basename too long");
            return 2;
        }
        size_t blen = strlen(base_name);
        if (blen > 4 && strcmp(base_name + blen - 4, ".git") == 0) {
            base_name[blen - 4] = '\0';
        }
        if (smallclueGitResolvePathFromBase(start_path, base_name, dest_buf, sizeof(dest_buf)) != 0) {
            smallclueGitPrintError("clone destination path too long");
            return 2;
        }
        clone_dest = dest_buf;
    }

    if (!quiet) {
        char display_dest[PATH_MAX];
        const char *shown = smallclueGitDisplayMaybePath(clone_dest, display_dest, sizeof(display_dest));
        fprintf(stderr, "Cloning into '%s'...\n", shown ? shown : clone_dest);
    }

    git_clone_options clone_opts = GIT_CLONE_OPTIONS_INIT;
    clone_opts.bare = bare ? 1 : 0;
    if (branch && *branch) {
        clone_opts.checkout_branch = branch;
    }

    git_repository *cloned = NULL;
    if (git_clone(&cloned, clone_source, clone_dest, &clone_opts) != 0 || !cloned) {
        smallclueGitPrintLibgitError("clone failed");
        return 1;
    }
    git_repository_free(cloned);
    return 0;
}

static int smallclueGitCommandRemote(git_repository *repo, int argc, char **argv) {
    bool verbose = false;
    const char *action = NULL;
    int action_index = 0;

    if (argc > 0 && (strcmp(argv[0], "-v") == 0 || strcmp(argv[0], "--verbose") == 0)) {
        verbose = true;
        action_index = 1;
    }
    if (action_index < argc) {
        action = argv[action_index];
    }

    if (!action) {
        git_strarray names = {0};
        if (git_remote_list(&names, repo) != 0) {
            smallclueGitPrintLibgitError("remote list failed");
            return 1;
        }
        if (names.count > 1) {
            qsort(names.strings, names.count, sizeof(char *), smallclueGitCompareCStringPtr);
        }
        for (size_t i = 0; i < names.count; ++i) {
            const char *name = names.strings[i];
            if (!name) continue;
            if (!verbose) {
                puts(name);
                continue;
            }
            git_remote *remote = NULL;
            if (git_remote_lookup(&remote, repo, name) != 0 || !remote) {
                continue;
            }
            const char *fetch_url = git_remote_url(remote);
            const char *push_url = git_remote_pushurl(remote);
            if (!push_url || !*push_url) {
                push_url = fetch_url;
            }
            char display_fetch[PATH_MAX];
            char display_push[PATH_MAX];
            const char *shown_fetch = smallclueGitDisplayMaybePath(fetch_url, display_fetch, sizeof(display_fetch));
            const char *shown_push = smallclueGitDisplayMaybePath(push_url, display_push, sizeof(display_push));
            printf("%s\t%s (fetch)\n", name, shown_fetch ? shown_fetch : "");
            printf("%s\t%s (push)\n", name, shown_push ? shown_push : "");
            git_remote_free(remote);
        }
        git_strarray_dispose(&names);
        return 0;
    }

    const char *sub = action;
    int subargc = argc - (action_index + 1);
    char **subargv = &argv[action_index + 1];

    if (strcmp(sub, "add") == 0) {
        if (subargc != 2) {
            smallclueGitPrintError("usage: git remote add <name> <url>");
            return 2;
        }
        char url_buf[PATH_MAX];
        const char *url = subargv[1];
        if (smallclueGitResolveMaybePathFromCwd(url, url_buf, sizeof(url_buf)) == 0) {
            url = url_buf;
        }
        git_remote *remote = NULL;
        if (git_remote_create(&remote, repo, subargv[0], url) != 0) {
            smallclueGitPrintLibgitError("remote add failed");
            return 1;
        }
        git_remote_free(remote);
        return 0;
    }

    if (strcmp(sub, "remove") == 0 || strcmp(sub, "rm") == 0) {
        if (subargc != 1) {
            smallclueGitPrintError("usage: git remote remove <name>");
            return 2;
        }
        if (git_remote_delete(repo, subargv[0]) != 0) {
            smallclueGitPrintLibgitError("remote remove failed");
            return 1;
        }
        return 0;
    }

    if (strcmp(sub, "rename") == 0) {
        if (subargc != 2) {
            smallclueGitPrintError("usage: git remote rename <old> <new>");
            return 2;
        }
        git_strarray problems = {0};
        if (git_remote_rename(&problems, repo, subargv[0], subargv[1]) != 0) {
            smallclueGitPrintLibgitError("remote rename failed");
            git_strarray_dispose(&problems);
            return 1;
        }
        git_strarray_dispose(&problems);
        return 0;
    }

    if (strcmp(sub, "get-url") == 0) {
        bool push = false;
        const char *name = NULL;
        for (int i = 0; i < subargc; ++i) {
            const char *arg = subargv[i];
            if (strcmp(arg, "--push") == 0) {
                push = true;
                continue;
            }
            if (arg[0] == '-') {
                smallclueGitPrintError("unsupported remote get-url option");
                return 2;
            }
            name = arg;
        }
        if (!name) {
            smallclueGitPrintError("usage: git remote get-url [--push] <name>");
            return 2;
        }
        git_remote *remote = NULL;
        if (git_remote_lookup(&remote, repo, name) != 0 || !remote) {
            smallclueGitPrintLibgitError("remote get-url lookup failed");
            return 1;
        }
        const char *url = push ? git_remote_pushurl(remote) : git_remote_url(remote);
        if ((!url || !*url) && push) {
            url = git_remote_url(remote);
        }
        if (!url || !*url) {
            git_remote_free(remote);
            return 1;
        }
        char display[PATH_MAX];
        const char *shown = smallclueGitDisplayMaybePath(url, display, sizeof(display));
        puts(shown ? shown : url);
        git_remote_free(remote);
        return 0;
    }

    if (strcmp(sub, "set-url") == 0) {
        bool push = false;
        bool add_mode = false;
        bool delete_mode = false;
        const char *name = NULL;
        const char *url = NULL;
        const char *old_url = NULL;
        for (int i = 0; i < subargc; ++i) {
            const char *arg = subargv[i];
            if (strcmp(arg, "--push") == 0) {
                push = true;
                continue;
            }
            if (strcmp(arg, "--add") == 0) {
                add_mode = true;
                continue;
            }
            if (strcmp(arg, "--delete") == 0) {
                delete_mode = true;
                continue;
            }
            if (arg[0] == '-') {
                smallclueGitPrintError("unsupported remote set-url option");
                return 2;
            }
            if (!name) {
                name = arg;
                continue;
            }
            if (!url) {
                url = arg;
                continue;
            }
            if (!old_url) {
                old_url = arg;
                continue;
            }
            smallclueGitPrintError("usage: git remote set-url [--push] [--add|--delete] <name> <url> [<oldurl>]");
            return 2;
        }
        if (!name || !url) {
            smallclueGitPrintError("usage: git remote set-url [--push] [--add|--delete] <name> <url> [<oldurl>]");
            return 2;
        }
        if (add_mode && delete_mode) {
            smallclueGitPrintError("remote set-url: --add and --delete are mutually exclusive");
            return 2;
        }
        if ((add_mode || delete_mode) && old_url) {
            smallclueGitPrintError("usage: git remote set-url [--push] [--add|--delete] <name> <url> [<oldurl>]");
            return 2;
        }

        git_remote *remote = NULL;
        if (git_remote_lookup(&remote, repo, name) != 0 || !remote) {
            smallclueGitPrintLibgitError("remote set-url lookup failed");
            return 1;
        }
        git_remote_free(remote);

        char key[512];
        if (snprintf(key, sizeof(key), "remote.%s.%s", name, push ? "pushurl" : "url") >= (int)sizeof(key)) {
            smallclueGitPrintError("remote set-url key too long");
            return 2;
        }

        char url_buf[PATH_MAX];
        if (smallclueGitResolveMaybePathFromCwd(url, url_buf, sizeof(url_buf)) == 0) {
            url = url_buf;
        }

        git_config *cfg = NULL;
        if (git_repository_config(&cfg, repo) != 0 || !cfg) {
            smallclueGitPrintLibgitError("remote set-url config open failed");
            return 1;
        }

        int rc = 0;
        if (delete_mode) {
            rc = smallclueGitConfigDeleteMatchingValue(cfg, key, url, true);
            if (rc == 1) {
                char display[PATH_MAX];
                const char *shown = smallclueGitDisplayMaybePath(url, display, sizeof(display));
                fprintf(stderr, "error: No such URL found: %s\n", shown ? shown : url);
                git_config_free(cfg);
                return 2;
            }
            if (rc != 0) {
                git_config_free(cfg);
                smallclueGitPrintLibgitError("remote set-url --delete failed");
                return 1;
            }
            git_config_free(cfg);
            return 0;
        }

        if (add_mode) {
            rc = smallclueGitConfigAppendValue(cfg, key, url);
            if (rc != 0) {
                git_config_free(cfg);
                smallclueGitPrintLibgitError("remote set-url --add failed");
                return 1;
            }
            git_config_free(cfg);
            return 0;
        }

        if (old_url && *old_url) {
            char old_url_buf[PATH_MAX];
            if (smallclueGitResolveMaybePathFromCwd(old_url, old_url_buf, sizeof(old_url_buf)) == 0) {
                old_url = old_url_buf;
            }
            rc = smallclueGitConfigDeleteMatchingValue(cfg, key, old_url, true);
            if (rc == 1) {
                char display[PATH_MAX];
                const char *shown = smallclueGitDisplayMaybePath(old_url, display, sizeof(display));
                fprintf(stderr, "error: No such URL found: %s\n", shown ? shown : old_url);
                git_config_free(cfg);
                return 2;
            }
            if (rc != 0 || smallclueGitConfigAppendValue(cfg, key, url) != 0) {
                git_config_free(cfg);
                smallclueGitPrintLibgitError("remote set-url replacement failed");
                return 1;
            }
            git_config_free(cfg);
            return 0;
        }

        git_config_free(cfg);
        rc = push ? git_remote_set_pushurl(repo, name, url) : git_remote_set_url(repo, name, url);
        if (rc != 0) {
            smallclueGitPrintLibgitError("remote set-url failed");
            return 1;
        }
        return 0;
    }

    smallclueGitPrintError("unsupported remote subcommand");
    return 2;
}

static int smallclueGitCommandFetch(git_repository *repo, int argc, char **argv) {
    const char *remote_name = "origin";
    bool fetch_all = false;
    bool prune = false;
    bool quiet = false;
    char *refspecs[64];
    size_t refspec_count = 0;
    bool remote_set = false;

    for (int i = 0; i < argc; ++i) {
        const char *arg = argv[i];
        if (!arg) continue;
        if (strcmp(arg, "--prune") == 0) {
            prune = true;
            continue;
        }
        if (strcmp(arg, "--all") == 0) {
            fetch_all = true;
            continue;
        }
        if (strcmp(arg, "-q") == 0 || strcmp(arg, "--quiet") == 0) {
            quiet = true;
            continue;
        }
        if (arg[0] == '-') {
            smallclueGitPrintError("unsupported fetch option");
            return 2;
        }
        if (!remote_set) {
            remote_name = arg;
            remote_set = true;
            continue;
        }
        if (refspec_count >= (sizeof(refspecs) / sizeof(refspecs[0]))) {
            smallclueGitPrintError("too many fetch refspecs");
            return 2;
        }
        refspecs[refspec_count++] = (char *)arg;
    }

    if (fetch_all && (remote_set || refspec_count > 0)) {
        smallclueGitPrintError("fetch: --all does not take a remote or refspecs");
        return 2;
    }

    git_fetch_options opts = GIT_FETCH_OPTIONS_INIT;
    opts.prune = prune ? GIT_FETCH_PRUNE : GIT_FETCH_NO_PRUNE;

    if (fetch_all) {
        git_strarray names = {0};
        if (git_remote_list(&names, repo) != 0) {
            smallclueGitPrintLibgitError("fetch --all: remote list failed");
            return 1;
        }
        int rc = 0;
        for (size_t i = 0; i < names.count; ++i) {
            const char *name = names.strings[i];
            if (!name || !*name) {
                continue;
            }
            git_remote *remote = NULL;
            if (git_remote_lookup(&remote, repo, name) != 0 || !remote) {
                rc = -1;
                break;
            }
            if (git_remote_fetch(remote, NULL, &opts, NULL) != 0) {
                git_remote_free(remote);
                rc = -1;
                break;
            }
            git_remote_free(remote);
        }
        git_strarray_dispose(&names);
        (void)quiet;
        if (rc != 0) {
            smallclueGitPrintLibgitError("fetch --all failed");
            return 1;
        }
        return 0;
    }

    git_remote *remote = NULL;
    if (git_remote_lookup(&remote, repo, remote_name) != 0 || !remote) {
        smallclueGitPrintLibgitError("fetch: remote lookup failed");
        return 1;
    }
    git_strarray arr = {0};
    if (refspec_count > 0) {
        arr.strings = refspecs;
        arr.count = refspec_count;
    }
    int rc = git_remote_fetch(remote, refspec_count > 0 ? &arr : NULL, &opts, NULL);
    git_remote_free(remote);
    (void)quiet;
    if (rc != 0) {
        smallclueGitPrintLibgitError("fetch failed");
        return 1;
    }
    return 0;
}

static int smallclueGitCommandPull(git_repository *repo, int argc, char **argv) {
    const char *remote_name = "origin";
    const char *branch_name = NULL;
    char upstream_remote[256];
    char upstream_branch[256];
    bool ff_only = false;
    bool no_ff = false;
    bool quiet = false;
    bool remote_set = false;
    upstream_remote[0] = '\0';
    upstream_branch[0] = '\0';

    for (int i = 0; i < argc; ++i) {
        const char *arg = argv[i];
        if (!arg) continue;
        if (strcmp(arg, "--ff-only") == 0) {
            ff_only = true;
            no_ff = false;
            continue;
        }
        if (strcmp(arg, "--no-ff") == 0) {
            no_ff = true;
            continue;
        }
        if (strcmp(arg, "--ff") == 0) {
            no_ff = false;
            continue;
        }
        if (strcmp(arg, "-q") == 0 || strcmp(arg, "--quiet") == 0) {
            quiet = true;
            continue;
        }
        if (arg[0] == '-') {
            smallclueGitPrintError("unsupported pull option");
            return 2;
        }
        if (!remote_set) {
            remote_name = arg;
            remote_set = true;
            continue;
        }
        if (!branch_name) {
            branch_name = arg;
            continue;
        }
        smallclueGitPrintError("too many pull arguments");
        return 2;
    }

    char current_branch[256];
    if (smallclueGitCurrentBranchName(repo, current_branch, sizeof(current_branch)) != 0) {
        smallclueGitPrintError("pull requires current branch (detached HEAD unsupported)");
        return 1;
    }
    if (!remote_set && !branch_name) {
        char local_ref_name[512];
        if (snprintf(local_ref_name, sizeof(local_ref_name), "refs/heads/%s", current_branch) < (int)sizeof(local_ref_name)) {
            git_reference *local_ref = NULL;
            if (git_reference_lookup(&local_ref, repo, local_ref_name) == 0 && local_ref) {
                git_reference *upstream_ref = NULL;
                if (git_branch_upstream(&upstream_ref, local_ref) == 0 && upstream_ref) {
                    const char *up_name = git_reference_name(upstream_ref);
                    if (up_name && smallclueGitStartsWith(up_name, "refs/remotes/")) {
                        const char *rem = up_name + strlen("refs/remotes/");
                        const char *slash = strchr(rem, '/');
                        if (slash && slash[1] != '\0') {
                            size_t remote_len = (size_t)(slash - rem);
                            if (remote_len < sizeof(upstream_remote) &&
                                snprintf(upstream_remote, sizeof(upstream_remote), "%.*s", (int)remote_len, rem) < (int)sizeof(upstream_remote) &&
                                snprintf(upstream_branch, sizeof(upstream_branch), "%s", slash + 1) < (int)sizeof(upstream_branch)) {
                                remote_name = upstream_remote;
                                branch_name = upstream_branch;
                            }
                        }
                    }
                    git_reference_free(upstream_ref);
                }
                git_reference_free(local_ref);
            }
        }
    }
    if (!branch_name) {
        branch_name = current_branch;
    }

    if (ff_only && no_ff) {
        smallclueGitPrintError("pull: --ff-only and --no-ff are mutually exclusive");
        return 2;
    }

    char refspec_storage[512];
    if (snprintf(refspec_storage,
                 sizeof(refspec_storage),
                 "refs/heads/%s:refs/remotes/%s/%s",
                 branch_name, remote_name, branch_name) >= (int)sizeof(refspec_storage)) {
        smallclueGitPrintError("pull refspec too long");
        return 2;
    }
    char *refspecs[1];
    refspecs[0] = refspec_storage;
    git_strarray arr = { refspecs, 1 };

    git_remote *remote = NULL;
    if (git_remote_lookup(&remote, repo, remote_name) != 0 || !remote) {
        smallclueGitPrintLibgitError("pull: remote lookup failed");
        return 1;
    }
    git_fetch_options fetch_opts = GIT_FETCH_OPTIONS_INIT;
    if (git_remote_fetch(remote, &arr, &fetch_opts, NULL) != 0) {
        git_remote_free(remote);
        smallclueGitPrintLibgitError("pull fetch failed");
        return 1;
    }
    git_remote_free(remote);

    char remote_ref_name[512];
    if (snprintf(remote_ref_name, sizeof(remote_ref_name), "refs/remotes/%s/%s", remote_name, branch_name) >= (int)sizeof(remote_ref_name)) {
        smallclueGitPrintError("pull remote ref name too long");
        return 1;
    }
    git_reference *remote_ref = NULL;
    if (git_reference_lookup(&remote_ref, repo, remote_ref_name) != 0 || !remote_ref) {
        smallclueGitPrintLibgitError("pull: fetched branch not found");
        return 1;
    }

    git_annotated_commit *their_head = NULL;
    if (git_annotated_commit_from_ref(&their_head, repo, remote_ref) != 0 || !their_head) {
        git_reference_free(remote_ref);
        smallclueGitPrintLibgitError("pull: unable to build annotated commit");
        return 1;
    }

    int rc = 1;
    git_reference *local_ref = NULL;
    git_commit *local_head = NULL;
    git_commit *remote_head = NULL;
    git_tree *result_tree = NULL;
    bool used_merge_state = false;

    char local_ref_name[512];
    if (snprintf(local_ref_name, sizeof(local_ref_name), "refs/heads/%s", current_branch) >= (int)sizeof(local_ref_name)) {
        git_annotated_commit_free(their_head);
        git_reference_free(remote_ref);
        smallclueGitPrintError("pull: local ref name too long");
        return 1;
    }
    if (git_reference_lookup(&local_ref, repo, local_ref_name) != 0 || !local_ref) {
        git_annotated_commit_free(their_head);
        git_reference_free(remote_ref);
        smallclueGitPrintLibgitError("pull: local branch lookup failed");
        return 1;
    }
    {
        git_object *head_obj = NULL;
        if (git_reference_peel(&head_obj, local_ref, GIT_OBJECT_COMMIT) != 0 || !head_obj) {
            git_reference_free(local_ref);
            git_annotated_commit_free(their_head);
            git_reference_free(remote_ref);
            smallclueGitPrintLibgitError("pull: local commit lookup failed");
            return 1;
        }
        local_head = (git_commit *)head_obj;
    }

    const git_annotated_commit *heads[1] = { their_head };
    git_merge_analysis_t analysis = GIT_MERGE_ANALYSIS_NONE;
    git_merge_preference_t pref = GIT_MERGE_PREFERENCE_NONE;
    if (git_merge_analysis(&analysis, &pref, repo, heads, 1) != 0) {
        git_commit_free(local_head);
        git_reference_free(local_ref);
        git_annotated_commit_free(their_head);
        git_reference_free(remote_ref);
        smallclueGitPrintLibgitError("pull: merge analysis failed");
        return 1;
    }

    if (analysis & GIT_MERGE_ANALYSIS_UP_TO_DATE) {
        git_commit_free(local_head);
        git_reference_free(local_ref);
        git_annotated_commit_free(their_head);
        git_reference_free(remote_ref);
        return 0;
    }

    const git_oid *target_oid = git_reference_target(remote_ref);
    if (!target_oid) {
        git_commit_free(local_head);
        git_reference_free(local_ref);
        git_annotated_commit_free(their_head);
        git_reference_free(remote_ref);
        smallclueGitPrintError("pull: missing target oid");
        return 1;
    }
    if (git_commit_lookup(&remote_head, repo, target_oid) != 0 || !remote_head) {
        git_commit_free(local_head);
        git_reference_free(local_ref);
        git_annotated_commit_free(their_head);
        git_reference_free(remote_ref);
        smallclueGitPrintLibgitError("pull: remote commit lookup failed");
        return 1;
    }

    bool can_ff = (analysis & GIT_MERGE_ANALYSIS_FASTFORWARD) != 0;
    bool can_merge = (analysis & GIT_MERGE_ANALYSIS_NORMAL) != 0;

    if (ff_only && !can_ff) {
        fputs("fatal: Not possible to fast-forward, aborting.\n", stderr);
        goto cleanup;
    }

    if (can_ff && !no_ff) {
        git_reference *updated = NULL;
        if (git_reference_set_target(&updated, local_ref, target_oid, "pull: fast-forward") != 0 || !updated) {
            smallclueGitPrintLibgitError("pull: fast-forward update failed");
            goto cleanup;
        }
        git_reference_free(updated);
        if (git_repository_set_head(repo, local_ref_name) != 0) {
            smallclueGitPrintLibgitError("pull: set HEAD failed");
            goto cleanup;
        }
        git_checkout_options checkout_opts = GIT_CHECKOUT_OPTIONS_INIT;
        checkout_opts.checkout_strategy = GIT_CHECKOUT_SAFE | GIT_CHECKOUT_RECREATE_MISSING;
        if (git_checkout_head(repo, &checkout_opts) != 0) {
            smallclueGitPrintLibgitError("pull: checkout failed");
            goto cleanup;
        }
        rc = 0;
        goto cleanup;
    }

    if (!can_merge && !(can_ff && no_ff)) {
        smallclueGitPrintError("pull: merge analysis does not allow integration");
        goto cleanup;
    }

    if (git_repository_state(repo) != GIT_REPOSITORY_STATE_NONE) {
        smallclueGitPrintError("pull: repository has unfinished operation");
        goto cleanup;
    }
    {
        int dirty = smallclueGitHasTrackedChanges(repo);
        if (dirty < 0) {
            smallclueGitPrintLibgitError("pull: unable to inspect working tree state");
            goto cleanup;
        }
        if (dirty > 0) {
            fputs("error: Your local changes would be overwritten by merge.\n", stderr);
            goto cleanup;
        }
    }

    if (can_ff && no_ff) {
        if (git_commit_tree(&result_tree, remote_head) != 0 || !result_tree) {
            smallclueGitPrintLibgitError("pull: remote tree lookup failed");
            goto cleanup;
        }
    } else {
        git_merge_options merge_opts = GIT_MERGE_OPTIONS_INIT;
        git_checkout_options merge_checkout_opts = GIT_CHECKOUT_OPTIONS_INIT;
        merge_checkout_opts.checkout_strategy = GIT_CHECKOUT_SAFE | GIT_CHECKOUT_RECREATE_MISSING;
        if (git_merge(repo, heads, 1, &merge_opts, &merge_checkout_opts) != 0) {
            smallclueGitPrintLibgitError("pull: merge failed");
            goto cleanup;
        }
        used_merge_state = true;

        git_index *index = NULL;
        if (git_repository_index(&index, repo) != 0 || !index) {
            smallclueGitPrintLibgitError("pull: merge index lookup failed");
            goto cleanup;
        }
        if (git_index_has_conflicts(index)) {
            git_index_free(index);
            fputs("Automatic merge failed; fix conflicts and then commit the result.\n", stderr);
            goto cleanup;
        }

        git_oid tree_oid;
        if (git_index_write_tree_to(&tree_oid, index, repo) != 0 || git_index_write(index) != 0) {
            git_index_free(index);
            smallclueGitPrintLibgitError("pull: merge tree write failed");
            goto cleanup;
        }
        git_index_free(index);

        if (git_tree_lookup(&result_tree, repo, &tree_oid) != 0 || !result_tree) {
            smallclueGitPrintLibgitError("pull: merge tree lookup failed");
            goto cleanup;
        }
    }

    git_signature *author = NULL;
    git_signature *committer = NULL;
    if (smallclueGitCreateDefaultSignatures(repo, &author, &committer) != 0) {
        smallclueGitPrintLibgitError("pull: signature creation failed");
        goto cleanup;
    }

    char merge_message[768];
    const char *merge_remote = remote_name ? remote_name : "remote";
    if (snprintf(merge_message,
                 sizeof(merge_message),
                 "Merge branch '%s' of %s",
                 branch_name ? branch_name : current_branch,
                 merge_remote) >= (int)sizeof(merge_message)) {
        git_signature_free(author);
        git_signature_free(committer);
        smallclueGitPrintError("pull: merge message too long");
        goto cleanup;
    }

    const git_commit *parents[2];
    parents[0] = local_head;
    parents[1] = remote_head;
    git_oid merge_oid;
    if (git_commit_create(&merge_oid,
                          repo,
                          "HEAD",
                          author,
                          committer,
                          NULL,
                          merge_message,
                          result_tree,
                          2,
                          parents) != 0) {
        git_signature_free(author);
        git_signature_free(committer);
        smallclueGitPrintLibgitError("pull: merge commit failed");
        goto cleanup;
    }
    git_signature_free(author);
    git_signature_free(committer);

    if (used_merge_state && git_repository_state_cleanup(repo) != 0) {
        smallclueGitPrintLibgitError("pull: merge state cleanup failed");
        goto cleanup;
    }
    used_merge_state = false;

    {
        git_checkout_options checkout_opts = GIT_CHECKOUT_OPTIONS_INIT;
        checkout_opts.checkout_strategy = GIT_CHECKOUT_SAFE | GIT_CHECKOUT_RECREATE_MISSING;
        if (git_checkout_head(repo, &checkout_opts) != 0) {
            smallclueGitPrintLibgitError("pull: checkout failed");
            goto cleanup;
        }
    }

    (void)quiet;
    rc = 0;

cleanup:
    if (used_merge_state) {
        (void)git_repository_state_cleanup(repo);
    }
    git_tree_free(result_tree);
    git_commit_free(remote_head);
    git_commit_free(local_head);
    git_reference_free(local_ref);
    git_annotated_commit_free(their_head);
    git_reference_free(remote_ref);
    return rc;
}

static bool smallclueGitIsSimpleBranchName(const char *name) {
    if (!name || !*name) {
        return false;
    }
    if (strcmp(name, "HEAD") == 0) {
        return false;
    }
    if (strchr(name, '/')) {
        return false;
    }
    if (smallclueGitStartsWith(name, "refs/")) {
        return false;
    }
    return true;
}

static int smallclueGitNormalizePushRefspec(const char *spec, char *out, size_t out_sz) {
    if (!spec || !*spec || !out || out_sz == 0) {
        return -1;
    }

    const char *cursor = spec;
    bool had_plus = false;
    if (cursor[0] == '+') {
        had_plus = true;
        cursor++;
    }

    const char *colon = strchr(cursor, ':');
    if (colon) {
        char lhs[256];
        char rhs[256];
        size_t lhs_len = (size_t)(colon - cursor);
        if (lhs_len == 0 || lhs_len >= sizeof(lhs) ||
            snprintf(lhs, sizeof(lhs), "%.*s", (int)lhs_len, cursor) >= (int)sizeof(lhs) ||
            snprintf(rhs, sizeof(rhs), "%s", colon + 1) >= (int)sizeof(rhs)) {
            return -1;
        }
        const char *left = lhs;
        const char *right = rhs;
        char left_expanded[300];
        char right_expanded[300];
        if (smallclueGitIsSimpleBranchName(left)) {
            if (snprintf(left_expanded, sizeof(left_expanded), "refs/heads/%s", left) >= (int)sizeof(left_expanded)) {
                return -1;
            }
            left = left_expanded;
        }
        if (smallclueGitIsSimpleBranchName(right)) {
            if (snprintf(right_expanded, sizeof(right_expanded), "refs/heads/%s", right) >= (int)sizeof(right_expanded)) {
                return -1;
            }
            right = right_expanded;
        }
        if (snprintf(out, out_sz, "%s%s:%s", had_plus ? "+" : "", left, right) >= (int)out_sz) {
            return -1;
        }
        return 0;
    }

    if (smallclueGitIsSimpleBranchName(cursor)) {
        if (snprintf(out,
                     out_sz,
                     "%srefs/heads/%s:refs/heads/%s",
                     had_plus ? "+" : "",
                     cursor,
                     cursor) >= (int)out_sz) {
            return -1;
        }
        return 0;
    }

    if (snprintf(out, out_sz, "%s%s", had_plus ? "+" : "", cursor) >= (int)out_sz) {
        return -1;
    }
    return 0;
}

static bool smallclueGitPushRefspecExists(char **refspecs, size_t count, const char *candidate) {
    if (!candidate || !*candidate) {
        return false;
    }
    for (size_t i = 0; i < count; ++i) {
        if (refspecs[i] && strcmp(refspecs[i], candidate) == 0) {
            return true;
        }
    }
    return false;
}

static int smallclueGitAppendFollowTags(git_repository *repo,
                                        bool force,
                                        char **refspecs,
                                        char refspec_buf[][512],
                                        size_t *refspec_count,
                                        size_t refspec_cap) {
    if (!repo || !refspecs || !refspec_count) {
        return -1;
    }

    git_oid tip_oids[64];
    size_t tip_count = 0;

    for (size_t i = 0; i < *refspec_count; ++i) {
        const char *spec = refspecs[i];
        if (!spec || !*spec) {
            continue;
        }
        const char *cursor = (spec[0] == '+') ? (spec + 1) : spec;
        if (cursor[0] == ':') {
            continue;
        }
        const char *colon = strchr(cursor, ':');
        if (!colon || colon == cursor) {
            continue;
        }
        char source_ref[300];
        size_t source_len = (size_t)(colon - cursor);
        if (source_len >= sizeof(source_ref) ||
            snprintf(source_ref, sizeof(source_ref), "%.*s", (int)source_len, cursor) >= (int)sizeof(source_ref)) {
            continue;
        }

        git_object *src_obj = NULL;
        if (git_revparse_single(&src_obj, repo, source_ref) != 0 || !src_obj) {
            continue;
        }
        git_object *src_commit_obj = NULL;
        if (git_object_peel(&src_commit_obj, src_obj, GIT_OBJECT_COMMIT) != 0 || !src_commit_obj) {
            git_object_free(src_obj);
            continue;
        }
        const git_oid *tip_oid = git_object_id(src_commit_obj);
        if (tip_oid && tip_count < (sizeof(tip_oids) / sizeof(tip_oids[0]))) {
            bool seen = false;
            for (size_t j = 0; j < tip_count; ++j) {
                if (git_oid_equal(&tip_oids[j], tip_oid)) {
                    seen = true;
                    break;
                }
            }
            if (!seen) {
                git_oid_cpy(&tip_oids[tip_count++], tip_oid);
            }
        }
        git_object_free(src_commit_obj);
        git_object_free(src_obj);
    }

    if (tip_count == 0) {
        return 0;
    }

    git_strarray tag_names = {0};
    if (git_tag_list(&tag_names, repo) != 0) {
        return -1;
    }

    for (size_t i = 0; i < tag_names.count; ++i) {
        const char *tag = tag_names.strings[i];
        if (!tag || !*tag) {
            continue;
        }

        char tag_ref_name[512];
        if (snprintf(tag_ref_name, sizeof(tag_ref_name), "refs/tags/%s", tag) >= (int)sizeof(tag_ref_name)) {
            continue;
        }

        git_object *tag_obj = NULL;
        if (git_revparse_single(&tag_obj, repo, tag_ref_name) != 0 || !tag_obj) {
            continue;
        }
        if (git_object_type(tag_obj) != GIT_OBJECT_TAG) {
            git_object_free(tag_obj);
            continue;
        }

        git_object *tag_target_commit = NULL;
        if (git_object_peel(&tag_target_commit, tag_obj, GIT_OBJECT_COMMIT) != 0 || !tag_target_commit) {
            git_object_free(tag_obj);
            continue;
        }

        const git_oid *tag_target_oid = git_object_id(tag_target_commit);
        bool reachable = false;
        for (size_t t = 0; t < tip_count; ++t) {
            if (tag_target_oid &&
                (git_oid_equal(&tip_oids[t], tag_target_oid) ||
                 git_graph_descendant_of(repo, &tip_oids[t], tag_target_oid) == 1)) {
                reachable = true;
                break;
            }
        }
        git_object_free(tag_target_commit);
        git_object_free(tag_obj);
        if (!reachable) {
            continue;
        }

        if (*refspec_count >= refspec_cap) {
            git_strarray_dispose(&tag_names);
            return -2;
        }

        const char *fmt = force ? "+refs/tags/%s:refs/tags/%s" : "refs/tags/%s:refs/tags/%s";
        if (snprintf(refspec_buf[*refspec_count], sizeof(refspec_buf[*refspec_count]), fmt, tag, tag) >= (int)sizeof(refspec_buf[*refspec_count])) {
            git_strarray_dispose(&tag_names);
            return -2;
        }
        if (!smallclueGitPushRefspecExists(refspecs, *refspec_count, refspec_buf[*refspec_count])) {
            refspecs[*refspec_count] = refspec_buf[*refspec_count];
            (*refspec_count)++;
        }
    }

    git_strarray_dispose(&tag_names);
    return 0;
}

static int smallclueGitCommandPush(git_repository *repo, int argc, char **argv) {
    const char *remote_name = "origin";
    bool set_upstream = false;
    bool force = false;
    bool quiet = false;
    bool push_all = false;
    bool push_tags = false;
    bool follow_tags = false;
    bool delete_mode = false;
    bool remote_set = false;
    char *user_refspecs[64];
    size_t user_refspec_count = 0;

    for (int i = 0; i < argc; ++i) {
        const char *arg = argv[i];
        if (!arg) continue;
        if (strcmp(arg, "-u") == 0 || strcmp(arg, "--set-upstream") == 0) {
            set_upstream = true;
            continue;
        }
        if (strcmp(arg, "-f") == 0 || strcmp(arg, "--force") == 0) {
            force = true;
            continue;
        }
        if (strcmp(arg, "-q") == 0 || strcmp(arg, "--quiet") == 0) {
            quiet = true;
            continue;
        }
        if (strcmp(arg, "--all") == 0) {
            push_all = true;
            continue;
        }
        if (strcmp(arg, "--tags") == 0) {
            push_tags = true;
            continue;
        }
        if (strcmp(arg, "--follow-tags") == 0) {
            follow_tags = true;
            continue;
        }
        if (strcmp(arg, "--delete") == 0) {
            delete_mode = true;
            continue;
        }
        if (arg[0] == '-') {
            smallclueGitPrintError("unsupported push option");
            return 2;
        }
        if (!remote_set) {
            remote_name = arg;
            remote_set = true;
            continue;
        }
        if (user_refspec_count >= (sizeof(user_refspecs) / sizeof(user_refspecs[0]))) {
            smallclueGitPrintError("too many push refspecs");
            return 2;
        }
        user_refspecs[user_refspec_count++] = (char *)arg;
    }

    if (push_all && delete_mode) {
        smallclueGitPrintError("push: --all and --delete are mutually exclusive");
        return 2;
    }
    if (push_all && user_refspec_count > 0) {
        smallclueGitPrintError("push: --all does not take refspecs");
        return 2;
    }
    if (delete_mode && user_refspec_count == 0) {
        smallclueGitPrintError("push: --delete requires at least one refname");
        return 2;
    }
    if (delete_mode && (push_tags || follow_tags)) {
        smallclueGitPrintError("push: --delete cannot be combined with tag-push options");
        return 2;
    }

    char current_branch[256];
    bool has_current_branch = (smallclueGitCurrentBranchName(repo, current_branch, sizeof(current_branch)) == 0);

    char generated_refspec[512];
    char pushed_refspecs_buf[64][512];
    char *pushed_refspecs[64];
    size_t pushed_count = 0;

    if (push_all) {
        git_branch_iterator *it = NULL;
        if (git_branch_iterator_new(&it, repo, GIT_BRANCH_LOCAL) != 0 || !it) {
            smallclueGitPrintLibgitError("push: unable to enumerate local branches");
            return 1;
        }
        git_reference *ref = NULL;
        git_branch_t bt = GIT_BRANCH_LOCAL;
        while (git_branch_next(&ref, &bt, it) == 0) {
            const char *name = NULL;
            if (git_branch_name(&name, ref) == 0 && name && *name) {
                if (pushed_count >= (sizeof(pushed_refspecs) / sizeof(pushed_refspecs[0]))) {
                    git_reference_free(ref);
                    git_branch_iterator_free(it);
                    smallclueGitPrintError("too many branches for push --all");
                    return 2;
                }
                const char *fmt = force ? "+refs/heads/%s:refs/heads/%s" : "refs/heads/%s:refs/heads/%s";
                if (snprintf(pushed_refspecs_buf[pushed_count],
                             sizeof(pushed_refspecs_buf[pushed_count]),
                             fmt,
                             name,
                             name) >= (int)sizeof(pushed_refspecs_buf[pushed_count])) {
                    git_reference_free(ref);
                    git_branch_iterator_free(it);
                    smallclueGitPrintError("push refspec too long");
                    return 2;
                }
                pushed_refspecs[pushed_count] = pushed_refspecs_buf[pushed_count];
                pushed_count++;
            }
            git_reference_free(ref);
            ref = NULL;
        }
        git_branch_iterator_free(it);
    } else if (delete_mode) {
        for (size_t i = 0; i < user_refspec_count; ++i) {
            const char *raw = user_refspecs[i];
            if (!raw || !*raw) {
                continue;
            }
            const char *remote_ref = raw;
            const char *colon = strchr(raw, ':');
            if (colon && colon[1] != '\0') {
                remote_ref = colon + 1;
            }
            char expanded_ref[300];
            if (smallclueGitIsSimpleBranchName(remote_ref)) {
                if (snprintf(expanded_ref, sizeof(expanded_ref), "refs/heads/%s", remote_ref) >= (int)sizeof(expanded_ref)) {
                    smallclueGitPrintError("push delete ref too long");
                    return 2;
                }
                remote_ref = expanded_ref;
            }
            if (snprintf(pushed_refspecs_buf[i], sizeof(pushed_refspecs_buf[i]), ":%s", remote_ref) >= (int)sizeof(pushed_refspecs_buf[i])) {
                smallclueGitPrintError("push delete refspec too long");
                return 2;
            }
            pushed_refspecs[pushed_count++] = pushed_refspecs_buf[i];
        }
    } else if (user_refspec_count == 0) {
        if (!has_current_branch) {
            smallclueGitPrintError("push requires a refspec in detached HEAD");
            return 1;
        }
        const char *fmt = force ? "+refs/heads/%s:refs/heads/%s" : "refs/heads/%s:refs/heads/%s";
        if (snprintf(generated_refspec, sizeof(generated_refspec), fmt, current_branch, current_branch) >= (int)sizeof(generated_refspec)) {
            smallclueGitPrintError("push refspec too long");
            return 2;
        }
        pushed_refspecs[pushed_count++] = generated_refspec;
    } else {
        char normalized_refspecs_buf[64][512];
        for (size_t i = 0; i < user_refspec_count; ++i) {
            const char *raw_spec = user_refspecs[i];
            const char *spec = raw_spec;
            if (raw_spec && smallclueGitNormalizePushRefspec(raw_spec, normalized_refspecs_buf[i], sizeof(normalized_refspecs_buf[i])) == 0) {
                spec = normalized_refspecs_buf[i];
            }
            if (!force || !spec || spec[0] == '+') {
                pushed_refspecs[pushed_count++] = (char *)spec;
                continue;
            }
            if (snprintf(pushed_refspecs_buf[i], sizeof(pushed_refspecs_buf[i]), "+%s", spec) >= (int)sizeof(pushed_refspecs_buf[i])) {
                smallclueGitPrintError("push refspec too long");
                return 2;
            }
            pushed_refspecs[pushed_count++] = pushed_refspecs_buf[i];
        }
    }

    if (push_tags) {
        git_strarray tag_names = {0};
        if (git_tag_list(&tag_names, repo) != 0) {
            smallclueGitPrintLibgitError("push: unable to enumerate tags");
            return 1;
        }
        for (size_t i = 0; i < tag_names.count; ++i) {
            const char *tag = tag_names.strings[i];
            if (!tag || !*tag) {
                continue;
            }
            if (pushed_count >= (sizeof(pushed_refspecs) / sizeof(pushed_refspecs[0]))) {
                git_strarray_dispose(&tag_names);
                smallclueGitPrintError("too many tags for push --tags");
                return 2;
            }
            const char *fmt = force ? "+refs/tags/%s:refs/tags/%s" : "refs/tags/%s:refs/tags/%s";
            if (snprintf(pushed_refspecs_buf[pushed_count],
                         sizeof(pushed_refspecs_buf[pushed_count]),
                         fmt,
                         tag,
                         tag) >= (int)sizeof(pushed_refspecs_buf[pushed_count])) {
                git_strarray_dispose(&tag_names);
                smallclueGitPrintError("push tag refspec too long");
                return 2;
            }
            pushed_refspecs[pushed_count] = pushed_refspecs_buf[pushed_count];
            pushed_count++;
        }
        git_strarray_dispose(&tag_names);
    }

    if (follow_tags) {
        int frc = smallclueGitAppendFollowTags(repo,
                                               force,
                                               pushed_refspecs,
                                               pushed_refspecs_buf,
                                               &pushed_count,
                                               sizeof(pushed_refspecs) / sizeof(pushed_refspecs[0]));
        if (frc == -2) {
            smallclueGitPrintError("too many follow-tags refspecs");
            return 2;
        }
        if (frc != 0) {
            smallclueGitPrintLibgitError("push: follow-tags processing failed");
            return 1;
        }
    }

    if (pushed_count == 0) {
        (void)quiet;
        return 0;
    }

    git_remote *remote = NULL;
    if (git_remote_lookup(&remote, repo, remote_name) != 0 || !remote) {
        smallclueGitPrintLibgitError("push: remote lookup failed");
        return 1;
    }
    git_push_options push_opts = GIT_PUSH_OPTIONS_INIT;
    git_strarray arr = { pushed_refspecs, pushed_count };
    if (git_remote_push(remote, &arr, &push_opts) != 0) {
        git_remote_free(remote);
        smallclueGitPrintLibgitError("push failed");
        return 1;
    }
    git_remote_free(remote);

    if (set_upstream && has_current_branch &&
        user_refspec_count == 0 &&
        !push_all && !push_tags && !delete_mode) {
        char local_ref_name[512];
        if (snprintf(local_ref_name, sizeof(local_ref_name), "refs/heads/%s", current_branch) < (int)sizeof(local_ref_name)) {
            git_reference *local_ref = NULL;
            if (git_reference_lookup(&local_ref, repo, local_ref_name) == 0 && local_ref) {
                char upstream_name[512];
                if (snprintf(upstream_name, sizeof(upstream_name), "%s/%s", remote_name, current_branch) < (int)sizeof(upstream_name)) {
                    (void)git_branch_set_upstream(local_ref, upstream_name);
                }
                git_reference_free(local_ref);
            }
        }
    } else if (set_upstream && has_current_branch &&
               user_refspec_count == 1 &&
               !push_all && !push_tags && !delete_mode) {
        const char *spec = pushed_refspecs[0];
        if (spec && *spec) {
            const char *cursor = (spec[0] == '+') ? (spec + 1) : spec;
            char left_buf[256];
            char right_buf[256];
            const char *colon = strchr(cursor, ':');
            if (colon) {
                size_t left_len = (size_t)(colon - cursor);
                if (left_len < sizeof(left_buf) &&
                    snprintf(left_buf, sizeof(left_buf), "%.*s", (int)left_len, cursor) < (int)sizeof(left_buf) &&
                    snprintf(right_buf, sizeof(right_buf), "%s", colon + 1) < (int)sizeof(right_buf)) {
                    const char *left = left_buf;
                    const char *right = right_buf;
                    if (strncmp(left, "refs/heads/", 11) == 0) {
                        left += 11;
                    }
                    if (strncmp(right, "refs/heads/", 11) == 0) {
                        right += 11;
                    }
                    if (strcmp(left, current_branch) == 0 && right[0] != '\0') {
                        char local_ref_name[512];
                        if (snprintf(local_ref_name, sizeof(local_ref_name), "refs/heads/%s", current_branch) < (int)sizeof(local_ref_name)) {
                            git_reference *local_ref = NULL;
                            if (git_reference_lookup(&local_ref, repo, local_ref_name) == 0 && local_ref) {
                                char upstream_name[512];
                                if (snprintf(upstream_name, sizeof(upstream_name), "%s/%s", remote_name, right) < (int)sizeof(upstream_name)) {
                                    (void)git_branch_set_upstream(local_ref, upstream_name);
                                }
                                git_reference_free(local_ref);
                            }
                        }
                    }
                }
            }
        }
    }

    (void)quiet;
    return 0;
}

static int smallclueGitCommandMain(git_repository *repo, const char *subcmd, int subargc, char **subargv) {
    if (strcmp(subcmd, "add") == 0) {
        return smallclueGitCommandAdd(repo, subargc, subargv);
    }
    if (strcmp(subcmd, "commit") == 0) {
        return smallclueGitCommandCommit(repo, subargc, subargv);
    }
    if (strcmp(subcmd, "reset") == 0) {
        return smallclueGitCommandReset(repo, subargc, subargv);
    }
    if (strcmp(subcmd, "restore") == 0) {
        return smallclueGitCommandRestore(repo, subargc, subargv);
    }
    if (strcmp(subcmd, "checkout") == 0) {
        return smallclueGitCommandCheckout(repo, subargc, subargv);
    }
    if (strcmp(subcmd, "switch") == 0) {
        return smallclueGitCommandSwitch(repo, subargc, subargv);
    }
    if (strcmp(subcmd, "remote") == 0) {
        return smallclueGitCommandRemote(repo, subargc, subargv);
    }
    if (strcmp(subcmd, "fetch") == 0) {
        return smallclueGitCommandFetch(repo, subargc, subargv);
    }
    if (strcmp(subcmd, "pull") == 0) {
        return smallclueGitCommandPull(repo, subargc, subargv);
    }
    if (strcmp(subcmd, "push") == 0) {
        return smallclueGitCommandPush(repo, subargc, subargv);
    }
    if (strcmp(subcmd, "config") == 0) {
        return smallclueGitCommandConfig(repo, subargc, subargv);
    }
    if (strcmp(subcmd, "symbolic-ref") == 0) {
        return smallclueGitCommandSymbolicRef(repo, subargc, subargv);
    }
    if (strcmp(subcmd, "rev-list") == 0) {
        return smallclueGitCommandRevList(repo, subargc, subargv);
    }
    if (strcmp(subcmd, "show-ref") == 0) {
        return smallclueGitCommandShowRef(repo, subargc, subargv);
    }
    if (strcmp(subcmd, "ls-files") == 0) {
        return smallclueGitCommandLsFiles(repo, subargc, subargv);
    }
    if (strcmp(subcmd, "rev-parse") == 0) {
        return smallclueGitCommandRevParse(repo, subargc, subargv);
    }
    if (strcmp(subcmd, "status") == 0) {
        return smallclueGitCommandStatus(repo, subargc, subargv);
    }
    if (strcmp(subcmd, "branch") == 0) {
        return smallclueGitCommandBranch(repo, subargc, subargv);
    }
    if (strcmp(subcmd, "tag") == 0) {
        return smallclueGitCommandTag(repo, subargc, subargv);
    }
    if (strcmp(subcmd, "diff") == 0) {
        return smallclueGitCommandDiff(repo, subargc, subargv);
    }
    if (strcmp(subcmd, "log") == 0) {
        return smallclueGitCommandLog(repo, subargc, subargv);
    }
    if (strcmp(subcmd, "show") == 0) {
        return smallclueGitCommandShow(repo, subargc, subargv);
    }

    smallclueGitPrintError("unsupported git subcommand");
    return 2;
}

int smallclueGitCommand(int argc, char **argv) {
    if (argc < 2) {
        return smallclueGitPrintUsage();
    }

    SmallclueGitGlobalOptions opts;
    int subcmd_index = 1;
    if (smallclueGitParseGlobalOptions(argc, argv, &opts, &subcmd_index) != 0) {
        return 2;
    }
    if (subcmd_index >= argc) {
        return smallclueGitPrintUsage();
    }

    const char *subcmd = argv[subcmd_index];
    char repo_start_path[PATH_MAX];
    if (smallclueGitResolveStartPath(&opts, repo_start_path, sizeof(repo_start_path)) != 0) {
        fprintf(stderr, "git: unable to resolve working directory: %s\n", strerror(errno));
        return 1;
    }

    int git_init_rc = git_libgit2_init();
    if (git_init_rc < 0) {
        smallclueGitPrintLibgitError("libgit2 init failed");
        return 1;
    }

    int rc = 1;
    git_repository *repo = NULL;
    if (strcmp(subcmd, "init") == 0) {
        rc = smallclueGitCommandInit(&opts,
                                     repo_start_path,
                                     argc - (subcmd_index + 1),
                                     &argv[subcmd_index + 1]);
        goto done;
    }
    if (strcmp(subcmd, "clone") == 0) {
        rc = smallclueGitCommandClone(repo_start_path,
                                      argc - (subcmd_index + 1),
                                      &argv[subcmd_index + 1]);
        goto done;
    }

    if (smallclueGitOpenRepository(repo_start_path, &repo) != 0 || !repo) {
        smallclueGitPrintLibgitError("not a git repository");
        rc = 1;
        goto done;
    }

    rc = smallclueGitCommandMain(repo, subcmd, argc - (subcmd_index + 1), &argv[subcmd_index + 1]);

done:
    if (repo) {
        git_repository_free(repo);
    }
    git_libgit2_shutdown();
    return rc;
}

#endif
