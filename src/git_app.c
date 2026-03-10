#include "smallclue.h"
#include "common/path_truncate.h"

#include <ctype.h>
#include <dirent.h>
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
#include <time.h>
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

static int smallclueGitParseAuthorIdentity(const char *spec,
                                           char *name_out,
                                           size_t name_out_sz,
                                           char *email_out,
                                           size_t email_out_sz) {
    if (!spec || !name_out || name_out_sz == 0 || !email_out || email_out_sz == 0) {
        return -1;
    }
    name_out[0] = '\0';
    email_out[0] = '\0';

    const char *lt = strrchr(spec, '<');
    const char *gt = strrchr(spec, '>');
    if (!lt || !gt || lt >= gt) {
        return -1;
    }

    const char *name_start = spec;
    while (*name_start && isspace((unsigned char)*name_start)) {
        name_start++;
    }
    const char *name_end = lt;
    while (name_end > name_start && isspace((unsigned char)name_end[-1])) {
        name_end--;
    }
    if (name_end <= name_start) {
        return -1;
    }

    const char *email_start = lt + 1;
    while (email_start < gt && isspace((unsigned char)*email_start)) {
        email_start++;
    }
    const char *email_end = gt;
    while (email_end > email_start && isspace((unsigned char)email_end[-1])) {
        email_end--;
    }
    if (email_end <= email_start) {
        return -1;
    }

    size_t name_len = (size_t)(name_end - name_start);
    size_t email_len = (size_t)(email_end - email_start);
    if (name_len + 1 > name_out_sz || email_len + 1 > email_out_sz) {
        return -1;
    }

    memcpy(name_out, name_start, name_len);
    name_out[name_len] = '\0';
    memcpy(email_out, email_start, email_len);
    email_out[email_len] = '\0';
    return 0;
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
static int smallclueGitCurrentBranchName(git_repository *repo, char *out, size_t out_sz);
static int smallclueGitCreateDefaultSignatures(git_repository *repo,
                                               git_signature **out_author,
                                               git_signature **out_committer);
static int smallclueGitHardResetToHead(git_repository *repo, const char *context);

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

static int smallclueGitBuildWorkdirPath(git_repository *repo,
                                        const char *repo_rel_path,
                                        char *out,
                                        size_t out_sz) {
    if (!repo || !repo_rel_path || !*repo_rel_path || !out || out_sz == 0) {
        return -1;
    }
    const char *workdir = git_repository_workdir(repo);
    if (!workdir || !*workdir) {
        return -1;
    }
    int n = snprintf(out, out_sz, "%s%s", workdir, repo_rel_path);
    return (n >= 0 && (size_t)n < out_sz) ? 0 : -1;
}

static int smallclueGitNormalizeRepoPath(const char *input, char *out, size_t out_sz) {
    if (!input || !*input || !out || out_sz == 0) {
        return -1;
    }
    const char *src = input;
    while (src[0] == '.' && src[1] == '/') {
        src += 2;
    }
    size_t len = strlen(src);
    while (len > 1 && src[len - 1] == '/') {
        len--;
    }
    if (len == 0 || len >= out_sz) {
        return -1;
    }
    memcpy(out, src, len);
    out[len] = '\0';
    return 0;
}

static bool smallclueGitPathEqualsOrInside(const char *candidate, const char *prefix) {
    if (!candidate || !prefix) {
        return false;
    }
    if (strcmp(candidate, prefix) == 0) {
        return true;
    }
    size_t plen = strlen(prefix);
    return (strncmp(candidate, prefix, plen) == 0 && candidate[plen] == '/');
}

static void smallclueGitFreeStringList(char **items, size_t count) {
    if (!items) {
        return;
    }
    for (size_t i = 0; i < count; ++i) {
        free(items[i]);
    }
    free(items);
}

static int smallclueGitCollectIndexPaths(git_index *index,
                                         const char *path,
                                         bool recursive,
                                         char ***out_paths,
                                         size_t *out_count) {
    if (!index || !path || !*path || !out_paths || !out_count) {
        return -1;
    }
    *out_paths = NULL;
    *out_count = 0;

    size_t capacity = 0;
    size_t count = 0;
    char **items = NULL;
    size_t entry_count = git_index_entrycount(index);
    for (size_t i = 0; i < entry_count; ++i) {
        const git_index_entry *entry = git_index_get_byindex(index, i);
        if (!entry || !entry->path) {
            continue;
        }

        bool match = false;
        if (recursive) {
            match = smallclueGitPathEqualsOrInside(entry->path, path);
        } else {
            match = (strcmp(entry->path, path) == 0);
        }
        if (!match) {
            continue;
        }

        if (count == capacity) {
            size_t next = (capacity == 0) ? 8 : (capacity * 2);
            char **next_items = (char **)realloc(items, next * sizeof(char *));
            if (!next_items) {
                smallclueGitFreeStringList(items, count);
                return -1;
            }
            items = next_items;
            capacity = next;
        }
        items[count] = strdup(entry->path);
        if (!items[count]) {
            smallclueGitFreeStringList(items, count);
            return -1;
        }
        count++;
    }

    *out_paths = items;
    *out_count = count;
    return 0;
}

static int smallclueGitPathIsDirectory(const char *path) {
    struct stat st;
    if (lstat(path, &st) != 0) {
        return -1;
    }
    return S_ISDIR(st.st_mode) ? 1 : 0;
}

/*
 * Returns:
 *   0 success
 *   1 path missing
 *   2 path is directory but recursive removal not enabled
 *  -1 hard failure (errno preserved)
 */
static int smallclueGitRemoveFilesystemPath(const char *path, bool recursive) {
    if (!path || !*path) {
        errno = EINVAL;
        return -1;
    }

    struct stat st;
    if (lstat(path, &st) != 0) {
        if (errno == ENOENT || errno == ENOTDIR) {
            return 1;
        }
        return -1;
    }

    if (S_ISDIR(st.st_mode)) {
        if (!recursive) {
            return 2;
        }
        DIR *dir = opendir(path);
        if (!dir) {
            return -1;
        }
        struct dirent *entry = NULL;
        while ((entry = readdir(dir)) != NULL) {
            const char *name = entry->d_name;
            if (!name || strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
                continue;
            }
            char child[PATH_MAX];
            int n = snprintf(child, sizeof(child), "%s/%s", path, name);
            if (n < 0 || (size_t)n >= sizeof(child)) {
                closedir(dir);
                errno = ENAMETOOLONG;
                return -1;
            }
            int rc = smallclueGitRemoveFilesystemPath(child, true);
            if (rc < 0) {
                closedir(dir);
                return -1;
            }
        }
        closedir(dir);
        if (rmdir(path) != 0) {
            return -1;
        }
        return 0;
    }

    if (unlink(path) != 0) {
        if (errno == ENOENT || errno == ENOTDIR) {
            return 1;
        }
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
    bool symbolic_full_name = false;
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
        if (strcmp(arg, "--symbolic-full-name") == 0) {
            symbolic_full_name = true;
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
    if (!revision) {
        revision = "HEAD";
    }

    if (abbrev_ref || symbolic_full_name) {
        git_object *obj = NULL;
        git_reference *ref = NULL;
        if (git_revparse_ext(&obj, &ref, repo, revision) != 0) {
            if (obj) {
                git_object_free(obj);
            }
            if (ref) {
                git_reference_free(ref);
            }
            if (verify) {
                fputs("fatal: Needed a single revision\n", stderr);
                return 128;
            }
            smallclueGitPrintLibgitError("unable to resolve revision");
            return 128;
        }

        if (abbrev_ref) {
            if (ref) {
                const char *name = git_reference_shorthand(ref);
                if (!name || !*name) {
                    name = "HEAD";
                }
                puts(name);
            } else if (strcmp(revision, "HEAD") == 0 || strcmp(revision, "@") == 0) {
                puts("HEAD");
            }
        } else if (symbolic_full_name) {
            if (ref) {
                const char *name = git_reference_name(ref);
                if (name && *name) {
                    puts(name);
                }
            } else if (strcmp(revision, "HEAD") == 0 || strcmp(revision, "@") == 0) {
                puts("HEAD");
            }
        }

        git_object_free(obj);
        git_reference_free(ref);
        return 0;
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

static int smallclueGitFormatTzOffsetMinutes(int minutes, char *out, size_t out_sz) {
    if (!out || out_sz < 6) {
        return -1;
    }
    char sign = '+';
    if (minutes < 0) {
        sign = '-';
        minutes = -minutes;
    }
    int hh = minutes / 60;
    int mm = minutes % 60;
    int n = snprintf(out, out_sz, "%c%02d%02d", sign, hh, mm);
    if (n < 0 || (size_t)n >= out_sz) {
        return -1;
    }
    return 0;
}

static int smallclueGitFormatReflogDate(const git_signature *sig,
                                        bool date_raw,
                                        bool date_iso,
                                        size_t fallback_index,
                                        char *out,
                                        size_t out_sz) {
    if (!out || out_sz == 0) {
        return -1;
    }
    out[0] = '\0';
    if (!date_raw && !date_iso) {
        int n = snprintf(out, out_sz, "%zu", fallback_index);
        return (n >= 0 && (size_t)n < out_sz) ? 0 : -1;
    }
    if (!sig) {
        int n = snprintf(out, out_sz, "%zu", fallback_index);
        return (n >= 0 && (size_t)n < out_sz) ? 0 : -1;
    }
    char tz_buf[8];
    if (smallclueGitFormatTzOffsetMinutes(sig->when.offset, tz_buf, sizeof(tz_buf)) != 0) {
        return -1;
    }
    if (date_raw) {
        int n = snprintf(out, out_sz, "%lld %s", (long long)sig->when.time, tz_buf);
        return (n >= 0 && (size_t)n < out_sz) ? 0 : -1;
    }

    time_t raw = (time_t)sig->when.time;
    struct tm tm_utc;
    if (!gmtime_r(&raw, &tm_utc)) {
        return -1;
    }
    raw += (time_t)(sig->when.offset * 60);
    struct tm tm_local;
    if (!gmtime_r(&raw, &tm_local)) {
        return -1;
    }
    int n = snprintf(out,
                     out_sz,
                     "%04d-%02d-%02d %02d:%02d:%02d %s",
                     tm_local.tm_year + 1900,
                     tm_local.tm_mon + 1,
                     tm_local.tm_mday,
                     tm_local.tm_hour,
                     tm_local.tm_min,
                     tm_local.tm_sec,
                     tz_buf);
    return (n >= 0 && (size_t)n < out_sz) ? 0 : -1;
}

static int smallclueGitCommandReflog(git_repository *repo, int argc, char **argv) {
    bool date_raw = false;
    bool date_iso = false;
    int max_count = -1;
    const char *ref_input = "HEAD";
    bool ref_set = false;

    for (int i = 0; i < argc; ++i) {
        const char *arg = argv[i];
        if (!arg || !*arg) {
            continue;
        }
        if ((strcmp(arg, "show") == 0 || strcmp(arg, "list") == 0) && !ref_set && i == 0) {
            continue;
        }
        if ((strcmp(arg, "-n") == 0 || strcmp(arg, "--max-count") == 0) && i + 1 < argc) {
            const char *n = argv[++i];
            char *end = NULL;
            long v = strtol(n, &end, 10);
            if (!end || *end != '\0' || v < 0) {
                smallclueGitPrintError("invalid reflog max-count");
                return 2;
            }
            max_count = (int)v;
            continue;
        }
        if (strncmp(arg, "--max-count=", 12) == 0) {
            const char *n = arg + 12;
            char *end = NULL;
            long v = strtol(n, &end, 10);
            if (!end || *end != '\0' || v < 0) {
                smallclueGitPrintError("invalid reflog max-count");
                return 2;
            }
            max_count = (int)v;
            continue;
        }
        if (strncmp(arg, "--date=", 7) == 0) {
            const char *mode = arg + 7;
            if (strcmp(mode, "raw") == 0) {
                date_raw = true;
                date_iso = false;
                continue;
            }
            if (strcmp(mode, "iso") == 0 || strcmp(mode, "iso-strict") == 0) {
                date_raw = false;
                date_iso = true;
                continue;
            }
            smallclueGitPrintError("unsupported reflog date mode");
            return 2;
        }
        if (strcmp(arg, "--") == 0) {
            continue;
        }
        if (arg[0] == '-') {
            smallclueGitPrintError("unsupported reflog option");
            return 2;
        }
        if (ref_set) {
            smallclueGitPrintError("too many reflog arguments");
            return 2;
        }
        ref_input = arg;
        ref_set = true;
    }

    if (max_count == 0) {
        return 0;
    }

    git_reflog *log = NULL;
    const char *ref_name = ref_input;
    git_reference *dwim = NULL;
    if (strcmp(ref_input, "HEAD") != 0 && !smallclueGitStartsWith(ref_input, "refs/")) {
        if (git_reference_dwim(&dwim, repo, ref_input) == 0 && dwim) {
            const char *resolved = git_reference_name(dwim);
            if (resolved && *resolved) {
                ref_name = resolved;
            }
        }
    }
    if (git_reflog_read(&log, repo, ref_name) != 0 || !log) {
        if (ref_name != ref_input) {
            log = NULL;
            (void)git_reflog_read(&log, repo, ref_input);
        }
    }
    git_reference_free(dwim);
    if (!log) {
        smallclueGitPrintLibgitError("reflog read failed");
        return 1;
    }

    size_t count = git_reflog_entrycount(log);
    if (count == 0 && strcmp(ref_input, "HEAD") != 0) {
        git_reflog_free(log);
        log = NULL;
        if (git_reflog_read(&log, repo, "HEAD") == 0 && log) {
            count = git_reflog_entrycount(log);
        }
    }
    size_t shown = 0;
    for (size_t idx = 0; idx < count; ++idx) {
        const git_reflog_entry *entry = git_reflog_entry_byindex(log, idx);
        if (!entry) {
            continue;
        }
        const git_oid *oid = git_reflog_entry_id_new(entry);
        if (!oid) {
            continue;
        }
        char short_oid[16];
        if (smallclueGitOidShort(oid, 7, short_oid, sizeof(short_oid)) != 0) {
            git_reflog_free(log);
            smallclueGitPrintError("failed to format reflog oid");
            return 1;
        }
        char date_buf[128];
        const git_signature *sig = git_reflog_entry_committer(entry);
        if (smallclueGitFormatReflogDate(sig, date_raw, date_iso, shown, date_buf, sizeof(date_buf)) != 0) {
            git_reflog_free(log);
            smallclueGitPrintError("failed to format reflog date");
            return 1;
        }
        const char *msg = git_reflog_entry_message(entry);
        if (!msg) {
            msg = "";
        }
        printf("%s %s@{%s}: %s\n", short_oid, ref_input, date_buf, msg);
        shown++;
        if (max_count > 0 && shown >= (size_t)max_count) {
            break;
        }
    }

    git_reflog_free(log);
    return 0;
}

static int smallclueGitCommandMergeBase(git_repository *repo, int argc, char **argv) {
    bool show_all = false;
    bool is_ancestor = false;
    const char *revs[8];
    int rev_count = 0;

    for (int i = 0; i < argc; ++i) {
        const char *arg = argv[i];
        if (!arg || !*arg) {
            continue;
        }
        if (strcmp(arg, "--all") == 0) {
            show_all = true;
            continue;
        }
        if (strcmp(arg, "--is-ancestor") == 0) {
            is_ancestor = true;
            continue;
        }
        if (strcmp(arg, "--") == 0) {
            continue;
        }
        if (arg[0] == '-') {
            smallclueGitPrintError("unsupported merge-base option");
            return 2;
        }
        if (rev_count >= (int)(sizeof(revs) / sizeof(revs[0]))) {
            smallclueGitPrintError("too many merge-base revisions");
            return 2;
        }
        revs[rev_count++] = arg;
    }

    if (is_ancestor) {
        if (show_all || rev_count != 2) {
            smallclueGitPrintError("usage: git merge-base --is-ancestor <commit> <commit>");
            return 2;
        }
        git_commit *a = NULL;
        git_commit *b = NULL;
        if (smallclueGitResolveCommit(repo, revs[0], &a) != 0 || !a) {
            smallclueGitPrintLibgitError("merge-base: unable to resolve commit");
            return 128;
        }
        if (smallclueGitResolveCommit(repo, revs[1], &b) != 0 || !b) {
            git_commit_free(a);
            smallclueGitPrintLibgitError("merge-base: unable to resolve commit");
            return 128;
        }
        const git_oid *a_oid = git_commit_id(a);
        const git_oid *b_oid = git_commit_id(b);
        int rc = git_graph_descendant_of(repo, b_oid, a_oid);
        git_commit_free(a);
        git_commit_free(b);
        if (rc < 0) {
            smallclueGitPrintLibgitError("merge-base: ancestry check failed");
            return 1;
        }
        return rc ? 0 : 1;
    }

    if (rev_count != 2) {
        smallclueGitPrintError("usage: git merge-base [--all] <commit> <commit>");
        return 2;
    }

    git_commit *a = NULL;
    git_commit *b = NULL;
    if (smallclueGitResolveCommit(repo, revs[0], &a) != 0 || !a) {
        smallclueGitPrintLibgitError("merge-base: unable to resolve commit");
        return 128;
    }
    if (smallclueGitResolveCommit(repo, revs[1], &b) != 0 || !b) {
        git_commit_free(a);
        smallclueGitPrintLibgitError("merge-base: unable to resolve commit");
        return 128;
    }

    int rc = 0;
    if (show_all) {
        git_oidarray bases = {0};
        rc = git_merge_bases(&bases, repo, git_commit_id(a), git_commit_id(b));
        if (rc == GIT_ENOTFOUND || bases.count == 0) {
            git_commit_free(a);
            git_commit_free(b);
            git_oidarray_dispose(&bases);
            return 1;
        }
        if (rc != 0) {
            git_commit_free(a);
            git_commit_free(b);
            git_oidarray_dispose(&bases);
            smallclueGitPrintLibgitError("merge-base failed");
            return 1;
        }
        for (size_t i = 0; i < bases.count; ++i) {
            char oid_buf[GIT_OID_HEXSZ + 1];
            if (!git_oid_tostr(oid_buf, sizeof(oid_buf), &bases.ids[i])) {
                git_commit_free(a);
                git_commit_free(b);
                git_oidarray_dispose(&bases);
                smallclueGitPrintError("failed to format oid");
                return 1;
            }
            puts(oid_buf);
        }
        git_oidarray_dispose(&bases);
    } else {
        git_oid base_oid;
        rc = git_merge_base(&base_oid, repo, git_commit_id(a), git_commit_id(b));
        if (rc == GIT_ENOTFOUND) {
            git_commit_free(a);
            git_commit_free(b);
            return 1;
        }
        if (rc != 0) {
            git_commit_free(a);
            git_commit_free(b);
            smallclueGitPrintLibgitError("merge-base failed");
            return 1;
        }
        char oid_buf[GIT_OID_HEXSZ + 1];
        if (!git_oid_tostr(oid_buf, sizeof(oid_buf), &base_oid)) {
            git_commit_free(a);
            git_commit_free(b);
            smallclueGitPrintError("failed to format oid");
            return 1;
        }
        puts(oid_buf);
    }

    git_commit_free(a);
    git_commit_free(b);
    return 0;
}

typedef struct SmallclueGitOidList {
    git_oid *items;
    size_t count;
    size_t cap;
} SmallclueGitOidList;

static void smallclueGitOidListFree(SmallclueGitOidList *list) {
    if (!list) {
        return;
    }
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->cap = 0;
}

static int smallclueGitOidListAppend(SmallclueGitOidList *list, const git_oid *oid) {
    if (!list || !oid) {
        return -1;
    }
    if (list->count == list->cap) {
        size_t next_cap = (list->cap == 0) ? 64 : (list->cap * 2);
        git_oid *next_items = (git_oid *)realloc(list->items, next_cap * sizeof(git_oid));
        if (!next_items) {
            return -1;
        }
        list->items = next_items;
        list->cap = next_cap;
    }
    git_oid_cpy(&list->items[list->count], oid);
    list->count++;
    return 0;
}

static int smallclueGitOidCompare(const void *a, const void *b) {
    return git_oid_cmp((const git_oid *)a, (const git_oid *)b);
}

static void smallclueGitOidListSortUnique(SmallclueGitOidList *list) {
    if (!list || list->count == 0 || !list->items) {
        return;
    }
    qsort(list->items, list->count, sizeof(git_oid), smallclueGitOidCompare);
    size_t out = 1;
    for (size_t i = 1; i < list->count; ++i) {
        if (git_oid_cmp(&list->items[i], &list->items[out - 1]) != 0) {
            if (out != i) {
                list->items[out] = list->items[i];
            }
            out++;
        }
    }
    list->count = out;
}

static bool smallclueGitOidListContains(const SmallclueGitOidList *list, const git_oid *oid) {
    if (!list || !oid || list->count == 0 || !list->items) {
        return false;
    }
    const git_oid *found = (const git_oid *)bsearch(oid,
                                                    list->items,
                                                    list->count,
                                                    sizeof(git_oid),
                                                    smallclueGitOidCompare);
    return found != NULL;
}

static int smallclueGitComputeCommitPatchId(git_repository *repo,
                                            const git_oid *commit_oid,
                                            git_oid *out_patch_id,
                                            bool *out_has_patch) {
    if (!repo || !commit_oid || !out_patch_id || !out_has_patch) {
        return -1;
    }
    *out_has_patch = false;

    git_commit *commit = NULL;
    git_commit *parent = NULL;
    git_tree *tree = NULL;
    git_tree *parent_tree = NULL;
    git_diff *diff = NULL;
    int rc = -1;

    if (git_commit_lookup(&commit, repo, commit_oid) != 0 || !commit) {
        goto done;
    }

    size_t parent_count = git_commit_parentcount(commit);
    if (parent_count > 1) {
        rc = 0;
        goto done;
    }

    if (git_commit_tree(&tree, commit) != 0 || !tree) {
        goto done;
    }
    if (parent_count == 1) {
        if (git_commit_parent(&parent, commit, 0) != 0 || !parent) {
            goto done;
        }
        if (git_commit_tree(&parent_tree, parent) != 0 || !parent_tree) {
            goto done;
        }
    }

    if (git_diff_tree_to_tree(&diff, repo, parent_tree, tree, NULL) != 0 || !diff) {
        goto done;
    }

    git_diff_patchid_options patch_opts = GIT_DIFF_PATCHID_OPTIONS_INIT;
    int prc = git_diff_patchid(out_patch_id, diff, &patch_opts);
    if (prc == GIT_ENOTFOUND) {
        rc = 0;
        goto done;
    }
    if (prc != 0) {
        goto done;
    }

    *out_has_patch = true;
    rc = 0;

done:
    git_diff_free(diff);
    git_tree_free(parent_tree);
    git_tree_free(tree);
    git_commit_free(parent);
    git_commit_free(commit);
    return rc;
}

static int smallclueGitCollectPatchIds(git_repository *repo,
                                       const git_oid *tip_oid,
                                       const git_oid *hide_oid,
                                       SmallclueGitOidList *out_list) {
    if (!repo || !tip_oid || !out_list) {
        return -1;
    }
    git_revwalk *walk = NULL;
    if (git_revwalk_new(&walk, repo) != 0 || !walk) {
        return -1;
    }

    git_revwalk_sorting(walk, GIT_SORT_TOPOLOGICAL | GIT_SORT_TIME);
    if (git_revwalk_push(walk, tip_oid) != 0) {
        git_revwalk_free(walk);
        return -1;
    }
    if (hide_oid && git_revwalk_hide(walk, hide_oid) != 0) {
        git_revwalk_free(walk);
        return -1;
    }

    git_oid oid;
    while (git_revwalk_next(&oid, walk) == 0) {
        git_oid patch_id;
        bool has_patch = false;
        if (smallclueGitComputeCommitPatchId(repo, &oid, &patch_id, &has_patch) != 0) {
            git_revwalk_free(walk);
            return -1;
        }
        if (!has_patch) {
            continue;
        }
        if (smallclueGitOidListAppend(out_list, &patch_id) != 0) {
            git_revwalk_free(walk);
            return -1;
        }
    }

    git_revwalk_free(walk);
    smallclueGitOidListSortUnique(out_list);
    return 0;
}

static int smallclueGitResolveDefaultUpstream(git_repository *repo, char *out, size_t out_sz) {
    if (!repo || !out || out_sz == 0) {
        return -1;
    }
    out[0] = '\0';

    char current_branch[256];
    if (smallclueGitCurrentBranchName(repo, current_branch, sizeof(current_branch)) != 0) {
        return -1;
    }

    char local_ref_name[512];
    if (snprintf(local_ref_name, sizeof(local_ref_name), "refs/heads/%s", current_branch) >= (int)sizeof(local_ref_name)) {
        return -1;
    }

    git_reference *local_ref = NULL;
    git_reference *upstream_ref = NULL;
    int rc = -1;

    if (git_reference_lookup(&local_ref, repo, local_ref_name) != 0 || !local_ref) {
        goto done;
    }
    if (git_branch_upstream(&upstream_ref, local_ref) != 0 || !upstream_ref) {
        goto done;
    }
    const char *name = git_reference_name(upstream_ref);
    if (!name || !*name) {
        goto done;
    }
    if (snprintf(out, out_sz, "%s", name) >= (int)out_sz) {
        goto done;
    }

    rc = 0;
done:
    git_reference_free(upstream_ref);
    git_reference_free(local_ref);
    return rc;
}

static int smallclueGitCommandCherry(git_repository *repo, int argc, char **argv) {
    bool verbose = false;
    bool use_abbrev = false;
    size_t abbrev_width = 7;
    const char *args[3];
    int arg_count = 0;

    for (int i = 0; i < argc; ++i) {
        const char *arg = argv[i];
        if (!arg || !*arg) {
            continue;
        }
        if (strcmp(arg, "-v") == 0 || strcmp(arg, "--verbose") == 0) {
            verbose = true;
            continue;
        }
        if (strcmp(arg, "--no-verbose") == 0) {
            verbose = false;
            continue;
        }
        if (strcmp(arg, "--abbrev") == 0) {
            use_abbrev = true;
            abbrev_width = 7;
            continue;
        }
        if (strncmp(arg, "--abbrev=", 9) == 0) {
            const char *n = arg + 9;
            char *end = NULL;
            long value = strtol(n, &end, 10);
            if (!end || *end != '\0' || value <= 0) {
                smallclueGitPrintError("invalid value for --abbrev");
                return 2;
            }
            use_abbrev = true;
            abbrev_width = (size_t)value;
            continue;
        }
        if (strcmp(arg, "--no-abbrev") == 0) {
            use_abbrev = false;
            continue;
        }
        if (strcmp(arg, "--") == 0) {
            continue;
        }
        if (arg[0] == '-') {
            smallclueGitPrintError("unsupported cherry option");
            return 2;
        }
        if (arg_count >= (int)(sizeof(args) / sizeof(args[0]))) {
            smallclueGitPrintError("usage: git cherry [-v] [<upstream> [<head> [<limit>]]]");
            return 2;
        }
        args[arg_count++] = arg;
    }

    char upstream_buf[512];
    const char *upstream_spec = NULL;
    const char *head_spec = "HEAD";
    const char *limit_spec = NULL;

    if (arg_count == 0) {
        if (smallclueGitResolveDefaultUpstream(repo, upstream_buf, sizeof(upstream_buf)) != 0) {
            fputs("Could not find a tracked remote branch, please specify <upstream> manually.\n", stderr);
            fputs("usage: git cherry [-v] [<upstream> [<head> [<limit>]]]\n", stderr);
            return 129;
        }
        upstream_spec = upstream_buf;
    } else {
        upstream_spec = args[0];
        if (arg_count >= 2) {
            head_spec = args[1];
        }
        if (arg_count >= 3) {
            limit_spec = args[2];
        }
    }

    git_commit *upstream_commit = NULL;
    git_commit *head_commit = NULL;
    git_commit *limit_commit = NULL;

    if (smallclueGitResolveCommit(repo, upstream_spec, &upstream_commit) != 0 || !upstream_commit) {
        smallclueGitPrintLibgitError("cherry: unable to resolve upstream");
        return 128;
    }
    if (smallclueGitResolveCommit(repo, head_spec, &head_commit) != 0 || !head_commit) {
        git_commit_free(upstream_commit);
        smallclueGitPrintLibgitError("cherry: unable to resolve head");
        return 128;
    }
    if (limit_spec) {
        if (smallclueGitResolveCommit(repo, limit_spec, &limit_commit) != 0 || !limit_commit) {
            git_commit_free(head_commit);
            git_commit_free(upstream_commit);
            smallclueGitPrintLibgitError("cherry: unable to resolve limit");
            return 128;
        }
    }

    SmallclueGitOidList upstream_patch_ids = {0};
    if (smallclueGitCollectPatchIds(repo,
                                    git_commit_id(upstream_commit),
                                    git_commit_id(head_commit),
                                    &upstream_patch_ids) != 0) {
        smallclueGitOidListFree(&upstream_patch_ids);
        git_commit_free(limit_commit);
        git_commit_free(head_commit);
        git_commit_free(upstream_commit);
        smallclueGitPrintLibgitError("cherry: failed to collect upstream patch ids");
        return 1;
    }

    git_revwalk *walk = NULL;
    if (git_revwalk_new(&walk, repo) != 0 || !walk) {
        smallclueGitOidListFree(&upstream_patch_ids);
        git_commit_free(limit_commit);
        git_commit_free(head_commit);
        git_commit_free(upstream_commit);
        smallclueGitPrintLibgitError("cherry: revwalk init failed");
        return 1;
    }

    git_revwalk_sorting(walk, GIT_SORT_TOPOLOGICAL | GIT_SORT_REVERSE);
    if (git_revwalk_push(walk, git_commit_id(head_commit)) != 0 ||
        git_revwalk_hide(walk, git_commit_id(upstream_commit)) != 0 ||
        (limit_commit && git_revwalk_hide(walk, git_commit_id(limit_commit)) != 0)) {
        git_revwalk_free(walk);
        smallclueGitOidListFree(&upstream_patch_ids);
        git_commit_free(limit_commit);
        git_commit_free(head_commit);
        git_commit_free(upstream_commit);
        smallclueGitPrintLibgitError("cherry: revwalk setup failed");
        return 1;
    }

    git_oid oid;
    while (git_revwalk_next(&oid, walk) == 0) {
        git_oid patch_id;
        bool has_patch = false;
        if (smallclueGitComputeCommitPatchId(repo, &oid, &patch_id, &has_patch) != 0) {
            git_revwalk_free(walk);
            smallclueGitOidListFree(&upstream_patch_ids);
            git_commit_free(limit_commit);
            git_commit_free(head_commit);
            git_commit_free(upstream_commit);
            smallclueGitPrintLibgitError("cherry: failed to compute patch-id");
            return 1;
        }

        char oid_buf[GIT_OID_HEXSZ + 1];
        if (use_abbrev) {
            if (smallclueGitOidShort(&oid, abbrev_width, oid_buf, sizeof(oid_buf)) != 0) {
                git_revwalk_free(walk);
                smallclueGitOidListFree(&upstream_patch_ids);
                git_commit_free(limit_commit);
                git_commit_free(head_commit);
                git_commit_free(upstream_commit);
                smallclueGitPrintError("failed to format oid");
                return 1;
            }
        } else if (!git_oid_tostr(oid_buf, sizeof(oid_buf), &oid)) {
            git_revwalk_free(walk);
            smallclueGitOidListFree(&upstream_patch_ids);
            git_commit_free(limit_commit);
            git_commit_free(head_commit);
            git_commit_free(upstream_commit);
            smallclueGitPrintError("failed to format oid");
            return 1;
        }

        char mark = '+';
        if (has_patch && smallclueGitOidListContains(&upstream_patch_ids, &patch_id)) {
            mark = '-';
        }

        if (verbose) {
            git_commit *commit = NULL;
            const char *subject = "";
            char subject_line[256];
            if (git_commit_lookup(&commit, repo, &oid) == 0 && commit) {
                subject = smallclueGitCommitSubject(commit);
            }
            subject_line[0] = '\0';
            if (subject && *subject) {
                (void)smallclueGitCopySubjectLine(subject, subject_line, sizeof(subject_line));
            }
            if (subject_line[0] != '\0') {
                printf("%c %s %s\n", mark, oid_buf, subject_line);
            } else {
                printf("%c %s\n", mark, oid_buf);
            }
            git_commit_free(commit);
        } else {
            printf("%c %s\n", mark, oid_buf);
        }
    }

    git_revwalk_free(walk);
    smallclueGitOidListFree(&upstream_patch_ids);
    git_commit_free(limit_commit);
    git_commit_free(head_commit);
    git_commit_free(upstream_commit);
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

typedef struct SmallclueGitLsTreeOptions {
    bool recurse;
    bool only_trees;
    bool show_trees;
    bool name_only;
    bool object_only;
    char terminator;
} SmallclueGitLsTreeOptions;

static const char *smallclueGitLsTreeTypeName(git_object_t type) {
    switch (type) {
        case GIT_OBJECT_TREE:
            return "tree";
        case GIT_OBJECT_BLOB:
            return "blob";
        case GIT_OBJECT_COMMIT:
            return "commit";
        default:
            return "unknown";
    }
}

static int smallclueGitLsTreeJoinPath(const char *prefix,
                                      const char *name,
                                      char *out,
                                      size_t out_sz) {
    if (!name || !*name || !out || out_sz == 0) {
        return -1;
    }
    if (!prefix || !*prefix) {
        return smallclueGitCopyPath(name, out, out_sz);
    }
    int n = snprintf(out, out_sz, "%s%s", prefix, name);
    return (n >= 0 && (size_t)n < out_sz) ? 0 : -1;
}

static int smallclueGitLsTreePrintEntry(const git_tree_entry *entry,
                                        const char *path,
                                        const SmallclueGitLsTreeOptions *opts) {
    if (!entry || !path || !opts) {
        return -1;
    }

    char oid_buf[GIT_OID_HEXSZ + 1];
    if (!git_oid_tostr(oid_buf, sizeof(oid_buf), git_tree_entry_id(entry))) {
        return -1;
    }

    if (opts->name_only) {
        fputs(path, stdout);
        fputc((int)opts->terminator, stdout);
        return 0;
    }

    if (opts->object_only) {
        fputs(oid_buf, stdout);
        fputc((int)opts->terminator, stdout);
        return 0;
    }

    unsigned int mode = (unsigned int)git_tree_entry_filemode(entry);
    const char *type_name = smallclueGitLsTreeTypeName(git_tree_entry_type(entry));
    printf("%06o %s %s\t%s%c", mode, type_name, oid_buf, path, opts->terminator);
    return 0;
}

static int smallclueGitLsTreeWalk(git_repository *repo,
                                  const git_tree *tree,
                                  const char *prefix,
                                  const SmallclueGitLsTreeOptions *opts) {
    if (!repo || !tree || !opts) {
        return -1;
    }

    size_t count = git_tree_entrycount(tree);
    for (size_t i = 0; i < count; ++i) {
        const git_tree_entry *entry = git_tree_entry_byindex(tree, i);
        if (!entry) {
            continue;
        }
        const char *name = git_tree_entry_name(entry);
        if (!name || !*name) {
            continue;
        }

        char path[PATH_MAX];
        if (smallclueGitLsTreeJoinPath(prefix, name, path, sizeof(path)) != 0) {
            return -1;
        }

        git_object_t type = git_tree_entry_type(entry);
        bool is_tree = (type == GIT_OBJECT_TREE);
        if (is_tree) {
            bool print_tree = opts->only_trees || !opts->recurse || opts->show_trees;
            if (print_tree && smallclueGitLsTreePrintEntry(entry, path, opts) != 0) {
                return -1;
            }
            if (opts->recurse) {
                git_tree *subtree = NULL;
                if (git_tree_lookup(&subtree, repo, git_tree_entry_id(entry)) != 0 || !subtree) {
                    return -1;
                }
                char child_prefix[PATH_MAX];
                int n = snprintf(child_prefix, sizeof(child_prefix), "%s/", path);
                if (n < 0 || (size_t)n >= sizeof(child_prefix)) {
                    git_tree_free(subtree);
                    return -1;
                }
                int rc = smallclueGitLsTreeWalk(repo, subtree, child_prefix, opts);
                git_tree_free(subtree);
                if (rc != 0) {
                    return rc;
                }
            }
        } else if (!opts->only_trees) {
            if (smallclueGitLsTreePrintEntry(entry, path, opts) != 0) {
                return -1;
            }
        }
    }

    return 0;
}

static int smallclueGitLsTreeNormalizePathspec(const char *in,
                                               char *out,
                                               size_t out_sz,
                                               bool *out_trailing_slash) {
    if (!in || !out || out_sz == 0) {
        return -1;
    }

    const char *src = in;
    while (src[0] == '.' && src[1] == '/') {
        src += 2;
    }

    size_t len = strlen(src);
    bool had_trailing_slash = false;
    while (len > 0 && src[len - 1] == '/') {
        had_trailing_slash = true;
        len--;
    }

    if (out_trailing_slash) {
        *out_trailing_slash = had_trailing_slash;
    }

    if (len == 0) {
        out[0] = '\0';
        return 0;
    }
    if (len >= out_sz) {
        return -1;
    }
    memcpy(out, src, len);
    out[len] = '\0';
    return 0;
}

static int smallclueGitCommandLsTree(git_repository *repo, int argc, char **argv) {
    SmallclueGitLsTreeOptions opts;
    memset(&opts, 0, sizeof(opts));
    opts.terminator = '\n';

    bool after_double_dash = false;
    const char *operands[128];
    int operand_count = 0;

    for (int i = 0; i < argc; ++i) {
        const char *arg = argv[i];
        if (!arg || !*arg) {
            continue;
        }
        if (!after_double_dash && strcmp(arg, "--") == 0) {
            after_double_dash = true;
            continue;
        }
        if (!after_double_dash && strcmp(arg, "-r") == 0) {
            opts.recurse = true;
            continue;
        }
        if (!after_double_dash && strcmp(arg, "-d") == 0) {
            opts.only_trees = true;
            continue;
        }
        if (!after_double_dash && strcmp(arg, "-t") == 0) {
            opts.show_trees = true;
            continue;
        }
        if (!after_double_dash && strcmp(arg, "-z") == 0) {
            opts.terminator = '\0';
            continue;
        }
        if (!after_double_dash && (strcmp(arg, "--name-only") == 0 || strcmp(arg, "--name-status") == 0)) {
            opts.name_only = true;
            continue;
        }
        if (!after_double_dash && strcmp(arg, "--object-only") == 0) {
            opts.object_only = true;
            continue;
        }
        if (!after_double_dash && arg[0] == '-') {
            smallclueGitPrintError("unsupported ls-tree option");
            return 2;
        }
        if (operand_count >= (int)(sizeof(operands) / sizeof(operands[0]))) {
            smallclueGitPrintError("too many ls-tree operands");
            return 2;
        }
        operands[operand_count++] = arg;
    }

    if (opts.name_only && opts.object_only) {
        smallclueGitPrintError("ls-tree: --name-only and --object-only are mutually exclusive");
        return 2;
    }
    if (operand_count == 0) {
        smallclueGitPrintError("ls-tree requires a tree-ish");
        return 2;
    }

    const char *treeish = operands[0];
    git_object *obj = NULL;
    if (git_revparse_single(&obj, repo, treeish) != 0 || !obj) {
        smallclueGitPrintLibgitError("ls-tree: unable to resolve tree-ish");
        return 128;
    }
    git_tree *root_tree = NULL;
    if (git_object_peel((git_object **)&root_tree, obj, GIT_OBJECT_TREE) != 0 || !root_tree) {
        git_object_free(obj);
        smallclueGitPrintLibgitError("ls-tree: object is not a tree");
        return 128;
    }
    git_object_free(obj);

    int rc = 0;
    int path_count = operand_count - 1;
    if (path_count <= 0) {
        rc = smallclueGitLsTreeWalk(repo, root_tree, "", &opts);
        git_tree_free(root_tree);
        if (rc != 0) {
            smallclueGitPrintLibgitError("ls-tree walk failed");
            return 1;
        }
        return 0;
    }

    for (int i = 0; i < path_count; ++i) {
        const char *raw_spec = operands[i + 1];
        bool trailing_slash = false;
        char spec[PATH_MAX];
        if (smallclueGitLsTreeNormalizePathspec(raw_spec, spec, sizeof(spec), &trailing_slash) != 0) {
            rc = 1;
            break;
        }
        if (!*spec) {
            rc = smallclueGitLsTreeWalk(repo, root_tree, "", &opts);
            if (rc != 0) {
                break;
            }
            continue;
        }

        git_tree_entry *entry = NULL;
        if (git_tree_entry_bypath(&entry, root_tree, spec) != 0 || !entry) {
            continue;
        }

        git_object_t type = git_tree_entry_type(entry);
        bool is_tree = (type == GIT_OBJECT_TREE);
        if (!is_tree) {
            if (!opts.only_trees && smallclueGitLsTreePrintEntry(entry, spec, &opts) != 0) {
                rc = 1;
                git_tree_entry_free(entry);
                break;
            }
            git_tree_entry_free(entry);
            continue;
        }

        if (!trailing_slash) {
            bool print_tree = opts.only_trees || !opts.recurse || opts.show_trees;
            if (print_tree && smallclueGitLsTreePrintEntry(entry, spec, &opts) != 0) {
                rc = 1;
                git_tree_entry_free(entry);
                break;
            }
            if (opts.recurse) {
                git_tree *subtree = NULL;
                if (git_tree_lookup(&subtree, repo, git_tree_entry_id(entry)) != 0 || !subtree) {
                    rc = 1;
                    git_tree_entry_free(entry);
                    break;
                }
                char child_prefix[PATH_MAX];
                int n = snprintf(child_prefix, sizeof(child_prefix), "%s/", spec);
                if (n < 0 || (size_t)n >= sizeof(child_prefix)) {
                    git_tree_free(subtree);
                    rc = 1;
                    git_tree_entry_free(entry);
                    break;
                }
                rc = smallclueGitLsTreeWalk(repo, subtree, child_prefix, &opts);
                git_tree_free(subtree);
                if (rc != 0) {
                    git_tree_entry_free(entry);
                    break;
                }
            }
            git_tree_entry_free(entry);
            continue;
        }

        if ((opts.show_trees || (opts.recurse && opts.only_trees)) &&
            smallclueGitLsTreePrintEntry(entry, spec, &opts) != 0) {
            rc = 1;
            git_tree_entry_free(entry);
            break;
        }

        git_tree *subtree = NULL;
        if (git_tree_lookup(&subtree, repo, git_tree_entry_id(entry)) != 0 || !subtree) {
            rc = 1;
            git_tree_entry_free(entry);
            break;
        }
        SmallclueGitLsTreeOptions child_opts = opts;
        if (!opts.recurse) {
            child_opts.recurse = false;
        }
        char child_prefix[PATH_MAX];
        int n = snprintf(child_prefix, sizeof(child_prefix), "%s/", spec);
        if (n < 0 || (size_t)n >= sizeof(child_prefix)) {
            git_tree_free(subtree);
            git_tree_entry_free(entry);
            rc = 1;
            break;
        }
        rc = smallclueGitLsTreeWalk(repo, subtree, child_prefix, &child_opts);
        git_tree_free(subtree);
        git_tree_entry_free(entry);
        if (rc != 0) {
            break;
        }
    }

    git_tree_free(root_tree);
    if (rc != 0) {
        smallclueGitPrintLibgitError("ls-tree failed");
        return 1;
    }
    return 0;
}

static int smallclueGitCatFileUsage(void) {
    smallclueGitPrintError("usage: git cat-file (-e|-p|-t|-s) <object> | git cat-file <type> <object>");
    return 2;
}

static git_object_t smallclueGitObjectTypeFromName(const char *name) {
    if (!name || !*name) {
        return GIT_OBJECT_INVALID;
    }
    if (strcmp(name, "blob") == 0) {
        return GIT_OBJECT_BLOB;
    }
    if (strcmp(name, "tree") == 0) {
        return GIT_OBJECT_TREE;
    }
    if (strcmp(name, "commit") == 0) {
        return GIT_OBJECT_COMMIT;
    }
    if (strcmp(name, "tag") == 0) {
        return GIT_OBJECT_TAG;
    }
    return GIT_OBJECT_INVALID;
}

static int smallclueGitCatFilePrintRawObject(git_repository *repo, const git_oid *oid) {
    if (!repo || !oid) {
        return -1;
    }
    git_odb *odb = NULL;
    git_odb_object *odb_obj = NULL;
    if (git_repository_odb(&odb, repo) != 0 || !odb) {
        return -1;
    }
    if (git_odb_read(&odb_obj, odb, oid) != 0 || !odb_obj) {
        git_odb_free(odb);
        return -1;
    }
    const void *data = git_odb_object_data(odb_obj);
    size_t len = git_odb_object_size(odb_obj);
    if (data && len > 0) {
        (void)fwrite(data, 1, len, stdout);
    }
    git_odb_object_free(odb_obj);
    git_odb_free(odb);
    return 0;
}

static int smallclueGitCatFilePrintSize(git_repository *repo, const git_oid *oid) {
    if (!repo || !oid) {
        return -1;
    }
    git_odb *odb = NULL;
    git_odb_object *odb_obj = NULL;
    if (git_repository_odb(&odb, repo) != 0 || !odb) {
        return -1;
    }
    if (git_odb_read(&odb_obj, odb, oid) != 0 || !odb_obj) {
        git_odb_free(odb);
        return -1;
    }
    printf("%llu\n", (unsigned long long)git_odb_object_size(odb_obj));
    git_odb_object_free(odb_obj);
    git_odb_free(odb);
    return 0;
}

static int smallclueGitCatFilePrintPrettyTree(const git_tree *tree) {
    if (!tree) {
        return -1;
    }
    size_t count = git_tree_entrycount(tree);
    for (size_t i = 0; i < count; ++i) {
        const git_tree_entry *entry = git_tree_entry_byindex(tree, i);
        if (!entry) {
            continue;
        }
        const char *name = git_tree_entry_name(entry);
        if (!name || !*name) {
            continue;
        }
        char oid_buf[GIT_OID_HEXSZ + 1];
        if (!git_oid_tostr(oid_buf, sizeof(oid_buf), git_tree_entry_id(entry))) {
            return -1;
        }
        unsigned int mode = (unsigned int)git_tree_entry_filemode(entry);
        const char *type_name = smallclueGitLsTreeTypeName(git_tree_entry_type(entry));
        printf("%06o %s %s\t%s\n", mode, type_name, oid_buf, name);
    }
    return 0;
}

static int smallclueGitCommandCatFile(git_repository *repo, int argc, char **argv) {
    enum {
        SMALLCLUE_CAT_MODE_NONE = 0,
        SMALLCLUE_CAT_MODE_EXISTS,
        SMALLCLUE_CAT_MODE_PRETTY,
        SMALLCLUE_CAT_MODE_TYPE,
        SMALLCLUE_CAT_MODE_SIZE,
    } mode = SMALLCLUE_CAT_MODE_NONE;

    const char *operands[4];
    int operand_count = 0;

    for (int i = 0; i < argc; ++i) {
        const char *arg = argv[i];
        if (!arg || !*arg) {
            continue;
        }
        if (strcmp(arg, "-e") == 0) {
            if (mode != SMALLCLUE_CAT_MODE_NONE) {
                return smallclueGitCatFileUsage();
            }
            mode = SMALLCLUE_CAT_MODE_EXISTS;
            continue;
        }
        if (strcmp(arg, "-p") == 0) {
            if (mode != SMALLCLUE_CAT_MODE_NONE) {
                return smallclueGitCatFileUsage();
            }
            mode = SMALLCLUE_CAT_MODE_PRETTY;
            continue;
        }
        if (strcmp(arg, "-t") == 0) {
            if (mode != SMALLCLUE_CAT_MODE_NONE) {
                return smallclueGitCatFileUsage();
            }
            mode = SMALLCLUE_CAT_MODE_TYPE;
            continue;
        }
        if (strcmp(arg, "-s") == 0) {
            if (mode != SMALLCLUE_CAT_MODE_NONE) {
                return smallclueGitCatFileUsage();
            }
            mode = SMALLCLUE_CAT_MODE_SIZE;
            continue;
        }
        if (arg[0] == '-') {
            smallclueGitPrintError("unsupported cat-file option");
            return 2;
        }
        if (operand_count >= (int)(sizeof(operands) / sizeof(operands[0]))) {
            return smallclueGitCatFileUsage();
        }
        operands[operand_count++] = arg;
    }

    const char *object_spec = NULL;
    git_object_t expected_type = GIT_OBJECT_INVALID;
    bool legacy_type_mode = false;
    if (mode == SMALLCLUE_CAT_MODE_NONE) {
        if (operand_count != 2) {
            return smallclueGitCatFileUsage();
        }
        expected_type = smallclueGitObjectTypeFromName(operands[0]);
        if (expected_type == GIT_OBJECT_INVALID) {
            smallclueGitPrintError("cat-file: invalid object type");
            return 128;
        }
        object_spec = operands[1];
        legacy_type_mode = true;
    } else {
        if (operand_count != 1) {
            return smallclueGitCatFileUsage();
        }
        object_spec = operands[0];
    }

    git_object *obj = NULL;
    if (git_revparse_single(&obj, repo, object_spec) != 0 || !obj) {
        smallclueGitPrintLibgitError("cat-file: unable to resolve object");
        return 128;
    }

    int rc = 0;
    if (legacy_type_mode) {
        git_object *typed = NULL;
        if (git_object_peel(&typed, obj, expected_type) != 0 || !typed) {
            git_object_free(obj);
            smallclueGitPrintLibgitError("cat-file: object does not match requested type");
            return 128;
        }
        rc = smallclueGitCatFilePrintRawObject(repo, git_object_id(typed));
        git_object_free(typed);
        git_object_free(obj);
        if (rc != 0) {
            smallclueGitPrintLibgitError("cat-file: failed to read object");
            return 1;
        }
        return 0;
    }

    if (mode == SMALLCLUE_CAT_MODE_EXISTS) {
        git_object_free(obj);
        return 0;
    }

    if (mode == SMALLCLUE_CAT_MODE_TYPE) {
        const char *type_name = smallclueGitLsTreeTypeName(git_object_type(obj));
        puts(type_name);
        git_object_free(obj);
        return 0;
    }

    if (mode == SMALLCLUE_CAT_MODE_SIZE) {
        rc = smallclueGitCatFilePrintSize(repo, git_object_id(obj));
        git_object_free(obj);
        if (rc != 0) {
            smallclueGitPrintLibgitError("cat-file: failed to read object size");
            return 1;
        }
        return 0;
    }

    if (mode == SMALLCLUE_CAT_MODE_PRETTY) {
        git_object_t type = git_object_type(obj);
        if (type == GIT_OBJECT_TREE) {
            git_tree *tree = NULL;
            if (git_object_peel((git_object **)&tree, obj, GIT_OBJECT_TREE) != 0 || !tree) {
                git_object_free(obj);
                smallclueGitPrintLibgitError("cat-file: tree lookup failed");
                return 1;
            }
            rc = smallclueGitCatFilePrintPrettyTree(tree);
            git_tree_free(tree);
            git_object_free(obj);
            if (rc != 0) {
                smallclueGitPrintLibgitError("cat-file: tree formatting failed");
                return 1;
            }
            return 0;
        }
        rc = smallclueGitCatFilePrintRawObject(repo, git_object_id(obj));
        git_object_free(obj);
        if (rc != 0) {
            smallclueGitPrintLibgitError("cat-file: failed to read object");
            return 1;
        }
        return 0;
    }

    git_object_free(obj);
    return smallclueGitCatFileUsage();
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

static int smallclueGitCommandRm(git_repository *repo, int argc, char **argv) {
    bool cached_only = false;
    bool recursive = false;
    bool quiet = false;
    bool after_double_dash = false;
    char *paths[256];
    size_t path_count = 0;

    for (int i = 0; i < argc; ++i) {
        const char *arg = argv[i];
        if (!arg) {
            continue;
        }
        if (!after_double_dash && strcmp(arg, "--") == 0) {
            after_double_dash = true;
            continue;
        }
        if (!after_double_dash && (strcmp(arg, "--cached") == 0)) {
            cached_only = true;
            continue;
        }
        if (!after_double_dash &&
            (strcmp(arg, "-r") == 0 || strcmp(arg, "-R") == 0 || strcmp(arg, "--recursive") == 0)) {
            recursive = true;
            continue;
        }
        if (!after_double_dash &&
            (strcmp(arg, "-q") == 0 || strcmp(arg, "--quiet") == 0)) {
            quiet = true;
            continue;
        }
        if (!after_double_dash &&
            (strcmp(arg, "-f") == 0 || strcmp(arg, "--force") == 0)) {
            /* Current implementation always applies removals when pathspecs resolve. */
            continue;
        }
        if (!after_double_dash && arg[0] == '-') {
            smallclueGitPrintError("unsupported rm option");
            return 2;
        }
        if (path_count >= (sizeof(paths) / sizeof(paths[0]))) {
            smallclueGitPrintError("too many rm paths");
            return 2;
        }
        paths[path_count++] = (char *)arg;
    }

    if (path_count == 0) {
        smallclueGitPrintError("rm requires at least one path");
        return 2;
    }

    git_index *index = NULL;
    if (git_repository_index(&index, repo) != 0 || !index) {
        smallclueGitPrintLibgitError("rm: index lookup failed");
        return 1;
    }

    for (size_t p = 0; p < path_count; ++p) {
        char normalized[PATH_MAX];
        if (smallclueGitNormalizeRepoPath(paths[p], normalized, sizeof(normalized)) != 0) {
            git_index_free(index);
            smallclueGitPrintError("rm path is too long");
            return 2;
        }

        char **matches = NULL;
        size_t match_count = 0;
        if (smallclueGitCollectIndexPaths(index, normalized, recursive, &matches, &match_count) != 0) {
            git_index_free(index);
            smallclueGitPrintError("out of memory");
            return 1;
        }

        if (match_count == 0) {
            smallclueGitFreeStringList(matches, match_count);
            if (!recursive) {
                if (smallclueGitCollectIndexPaths(index, normalized, true, &matches, &match_count) != 0) {
                    git_index_free(index);
                    smallclueGitPrintError("out of memory");
                    return 1;
                }
                if (match_count > 0) {
                    smallclueGitFreeStringList(matches, match_count);
                    git_index_free(index);
                    smallclueGitPrintError("not removing recursively without -r");
                    return 1;
                }
            }
            smallclueGitFreeStringList(matches, match_count);
            git_index_free(index);
            fprintf(stderr, "git: pathspec '%s' did not match any files\n", normalized);
            return 128;
        }

        for (size_t i = 0; i < match_count; ++i) {
            const char *entry_path = matches[i];
            if (!entry_path || !*entry_path) {
                continue;
            }
            if (git_index_remove_bypath(index, entry_path) != 0) {
                smallclueGitFreeStringList(matches, match_count);
                git_index_free(index);
                smallclueGitPrintLibgitError("rm: failed to update index");
                return 1;
            }

            if (!cached_only) {
                char host_path[PATH_MAX];
                if (smallclueGitBuildWorkdirPath(repo, entry_path, host_path, sizeof(host_path)) != 0) {
                    smallclueGitFreeStringList(matches, match_count);
                    git_index_free(index);
                    smallclueGitPrintError("rm: repository has no working tree");
                    return 1;
                }
                int rm_rc = smallclueGitRemoveFilesystemPath(host_path, recursive);
                if (rm_rc == 2) {
                    smallclueGitFreeStringList(matches, match_count);
                    git_index_free(index);
                    smallclueGitPrintError("not removing directory without -r");
                    return 1;
                }
                if (rm_rc < 0) {
                    int saved_errno = errno;
                    smallclueGitFreeStringList(matches, match_count);
                    git_index_free(index);
                    fprintf(stderr, "git: rm failed for '%s': %s\n", entry_path, strerror(saved_errno));
                    return 1;
                }
            }

            if (!quiet) {
                printf("rm '%s'\n", entry_path);
            }
        }

        smallclueGitFreeStringList(matches, match_count);
    }

    if (git_index_write(index) != 0) {
        git_index_free(index);
        smallclueGitPrintLibgitError("rm: index write failed");
        return 1;
    }

    git_index_free(index);
    return 0;
}

static int smallclueGitCommandMv(git_repository *repo, int argc, char **argv) {
    bool force = false;
    bool after_double_dash = false;
    char *operands[256];
    size_t operand_count = 0;

    for (int i = 0; i < argc; ++i) {
        const char *arg = argv[i];
        if (!arg) {
            continue;
        }
        if (!after_double_dash && strcmp(arg, "--") == 0) {
            after_double_dash = true;
            continue;
        }
        if (!after_double_dash && (strcmp(arg, "-f") == 0 || strcmp(arg, "--force") == 0)) {
            force = true;
            continue;
        }
        if (!after_double_dash && arg[0] == '-') {
            smallclueGitPrintError("unsupported mv option");
            return 2;
        }
        if (operand_count >= (sizeof(operands) / sizeof(operands[0]))) {
            smallclueGitPrintError("too many mv operands");
            return 2;
        }
        operands[operand_count++] = (char *)arg;
    }

    if (operand_count < 2) {
        smallclueGitPrintError("mv expects at least two paths");
        return 2;
    }

    git_index *index = NULL;
    if (git_repository_index(&index, repo) != 0 || !index) {
        smallclueGitPrintLibgitError("mv: index lookup failed");
        return 1;
    }

    char dest_norm[PATH_MAX];
    if (smallclueGitNormalizeRepoPath(operands[operand_count - 1], dest_norm, sizeof(dest_norm)) != 0) {
        git_index_free(index);
        smallclueGitPrintError("mv destination path is too long");
        return 2;
    }

    char dest_host[PATH_MAX];
    if (smallclueGitBuildWorkdirPath(repo, dest_norm, dest_host, sizeof(dest_host)) != 0) {
        git_index_free(index);
        smallclueGitPrintError("mv: repository has no working tree");
        return 1;
    }

    bool dest_is_dir = false;
    if (operand_count > 2) {
        int dir_state = smallclueGitPathIsDirectory(dest_host);
        if (dir_state != 1) {
            git_index_free(index);
            fprintf(stderr, "git: destination '%s' is not a directory\n", dest_norm);
            return 1;
        }
        dest_is_dir = true;
    } else {
        int dir_state = smallclueGitPathIsDirectory(dest_host);
        dest_is_dir = (dir_state == 1);
    }

    for (size_t i = 0; i + 1 < operand_count; ++i) {
        char src_norm[PATH_MAX];
        if (smallclueGitNormalizeRepoPath(operands[i], src_norm, sizeof(src_norm)) != 0) {
            git_index_free(index);
            smallclueGitPrintError("mv source path is too long");
            return 2;
        }

        char dst_norm[PATH_MAX];
        if (dest_is_dir) {
            const char *base = strrchr(src_norm, '/');
            base = base ? (base + 1) : src_norm;
            int n = snprintf(dst_norm, sizeof(dst_norm), "%s/%s", dest_norm, base);
            if (n < 0 || (size_t)n >= sizeof(dst_norm)) {
                git_index_free(index);
                smallclueGitPrintError("mv destination path is too long");
                return 2;
            }
        } else {
            if (smallclueGitCopyPath(dest_norm, dst_norm, sizeof(dst_norm)) != 0) {
                git_index_free(index);
                smallclueGitPrintError("mv destination path is too long");
                return 2;
            }
        }

        char **matches = NULL;
        size_t match_count = 0;
        if (smallclueGitCollectIndexPaths(index, src_norm, true, &matches, &match_count) != 0) {
            git_index_free(index);
            smallclueGitPrintError("out of memory");
            return 1;
        }
        if (match_count == 0) {
            smallclueGitFreeStringList(matches, match_count);
            git_index_free(index);
            fprintf(stderr, "git: not under version control: %s\n", src_norm);
            return 1;
        }

        char src_host[PATH_MAX];
        char dst_host[PATH_MAX];
        if (smallclueGitBuildWorkdirPath(repo, src_norm, src_host, sizeof(src_host)) != 0 ||
            smallclueGitBuildWorkdirPath(repo, dst_norm, dst_host, sizeof(dst_host)) != 0) {
            smallclueGitFreeStringList(matches, match_count);
            git_index_free(index);
            smallclueGitPrintError("mv: repository has no working tree");
            return 1;
        }

        if (!force) {
            struct stat st;
            if (lstat(dst_host, &st) == 0) {
                smallclueGitFreeStringList(matches, match_count);
                git_index_free(index);
                fprintf(stderr, "git: destination exists: %s\n", dst_norm);
                return 1;
            }
        }

        if (rename(src_host, dst_host) != 0) {
            int saved_errno = errno;
            smallclueGitFreeStringList(matches, match_count);
            git_index_free(index);
            fprintf(stderr, "git: mv failed: %s\n", strerror(saved_errno));
            return 1;
        }

        size_t src_len = strlen(src_norm);
        for (size_t m = 0; m < match_count; ++m) {
            const char *old_path = matches[m];
            if (!old_path || !*old_path) {
                continue;
            }
            char new_path[PATH_MAX];
            if (strcmp(old_path, src_norm) == 0) {
                if (smallclueGitCopyPath(dst_norm, new_path, sizeof(new_path)) != 0) {
                    smallclueGitFreeStringList(matches, match_count);
                    git_index_free(index);
                    smallclueGitPrintError("mv target path is too long");
                    return 1;
                }
            } else if (smallclueGitPathEqualsOrInside(old_path, src_norm)) {
                int n = snprintf(new_path, sizeof(new_path), "%s/%s", dst_norm, old_path + src_len + 1);
                if (n < 0 || (size_t)n >= sizeof(new_path)) {
                    smallclueGitFreeStringList(matches, match_count);
                    git_index_free(index);
                    smallclueGitPrintError("mv target path is too long");
                    return 1;
                }
            } else {
                continue;
            }

            if (git_index_remove_bypath(index, old_path) != 0) {
                smallclueGitFreeStringList(matches, match_count);
                git_index_free(index);
                smallclueGitPrintLibgitError("mv: index remove failed");
                return 1;
            }
            if (git_index_add_bypath(index, new_path) != 0) {
                smallclueGitFreeStringList(matches, match_count);
                git_index_free(index);
                smallclueGitPrintLibgitError("mv: index add failed");
                return 1;
            }
        }

        smallclueGitFreeStringList(matches, match_count);
    }

    if (git_index_write(index) != 0) {
        git_index_free(index);
        smallclueGitPrintLibgitError("mv: index write failed");
        return 1;
    }

    git_index_free(index);
    return 0;
}

typedef struct SmallclueGitCleanPathList {
    char **items;
    size_t count;
    size_t cap;
} SmallclueGitCleanPathList;

static void smallclueGitCleanPathListFree(SmallclueGitCleanPathList *list) {
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

static int smallclueGitCleanPathListAdd(SmallclueGitCleanPathList *list, const char *path) {
    if (!list || !path || !*path) {
        return -1;
    }
    for (size_t i = 0; i < list->count; ++i) {
        if (strcmp(list->items[i], path) == 0) {
            return 0;
        }
    }
    if (list->count == list->cap) {
        size_t next = (list->cap == 0) ? 8 : (list->cap * 2);
        char **resized = (char **)realloc(list->items, next * sizeof(char *));
        if (!resized) {
            return -1;
        }
        list->items = resized;
        list->cap = next;
    }
    list->items[list->count] = strdup(path);
    if (!list->items[list->count]) {
        return -1;
    }
    list->count++;
    return 0;
}

static bool smallclueGitPathspecLooksLikeGlob(const char *spec) {
    if (!spec) {
        return false;
    }
    for (const unsigned char *p = (const unsigned char *)spec; *p; ++p) {
        if (*p == '*' || *p == '?' || *p == '[') {
            return true;
        }
    }
    return false;
}

static bool smallclueGitCleanPathMatchesSpec(const char *path, const char *spec) {
    if (!path || !*path || !spec || !*spec) {
        return false;
    }
    if (smallclueGitPathspecLooksLikeGlob(spec)) {
        return fnmatch(spec, path, 0) == 0;
    }
    return smallclueGitPathEqualsOrInside(path, spec);
}

static int smallclueGitCommandClean(git_repository *repo, int argc, char **argv) {
    bool force = false;
    bool dry_run = false;
    bool remove_dirs = false;
    bool quiet = false;
    bool include_ignored = false;
    bool only_ignored = false;
    bool after_double_dash = false;
    SmallclueGitCleanPathList pathspecs;
    memset(&pathspecs, 0, sizeof(pathspecs));

    for (int i = 0; i < argc; ++i) {
        const char *arg = argv[i];
        if (!arg) {
            continue;
        }
        if (!after_double_dash && strcmp(arg, "--") == 0) {
            after_double_dash = true;
            continue;
        }
        if (!after_double_dash && (strcmp(arg, "-f") == 0 || strcmp(arg, "--force") == 0)) {
            force = true;
            continue;
        }
        if (!after_double_dash && (strcmp(arg, "-n") == 0 || strcmp(arg, "--dry-run") == 0)) {
            dry_run = true;
            continue;
        }
        if (!after_double_dash && strcmp(arg, "-d") == 0) {
            remove_dirs = true;
            continue;
        }
        if (!after_double_dash && (strcmp(arg, "-q") == 0 || strcmp(arg, "--quiet") == 0)) {
            quiet = true;
            continue;
        }
        if (!after_double_dash && strcmp(arg, "-x") == 0) {
            include_ignored = true;
            only_ignored = false;
            continue;
        }
        if (!after_double_dash && strcmp(arg, "-X") == 0) {
            include_ignored = true;
            only_ignored = true;
            continue;
        }
        if (!after_double_dash && arg[0] == '-') {
            smallclueGitPrintError("unsupported clean option");
            smallclueGitCleanPathListFree(&pathspecs);
            return 2;
        }
        char normalized[PATH_MAX];
        if (smallclueGitNormalizeRepoPath(arg, normalized, sizeof(normalized)) != 0) {
            smallclueGitPrintError("clean path is too long");
            smallclueGitCleanPathListFree(&pathspecs);
            return 2;
        }
        if (smallclueGitCleanPathListAdd(&pathspecs, normalized) != 0) {
            smallclueGitPrintError("out of memory");
            smallclueGitCleanPathListFree(&pathspecs);
            return 1;
        }
    }

    if (!force && !dry_run) {
        smallclueGitPrintError("clean requires -f or -n");
        smallclueGitCleanPathListFree(&pathspecs);
        return 1;
    }

    git_status_options opts = GIT_STATUS_OPTIONS_INIT;
    opts.show = GIT_STATUS_SHOW_WORKDIR_ONLY;
    opts.flags = GIT_STATUS_OPT_INCLUDE_UNTRACKED |
                 GIT_STATUS_OPT_DISABLE_PATHSPEC_MATCH;
    if (include_ignored) {
        opts.flags |= GIT_STATUS_OPT_INCLUDE_IGNORED;
    }
    if (pathspecs.count > 0) {
        opts.flags |= GIT_STATUS_OPT_RECURSE_UNTRACKED_DIRS;
        if (include_ignored) {
            opts.flags |= GIT_STATUS_OPT_RECURSE_IGNORED_DIRS;
        }
    }

    git_status_list *status_list = NULL;
    if (git_status_list_new(&status_list, repo, &opts) != 0 || !status_list) {
        smallclueGitPrintLibgitError("clean: status listing failed");
        smallclueGitCleanPathListFree(&pathspecs);
        return 1;
    }

    SmallclueGitCleanPathList candidates;
    memset(&candidates, 0, sizeof(candidates));

    size_t count = git_status_list_entrycount(status_list);
    for (size_t i = 0; i < count; ++i) {
        const git_status_entry *entry = git_status_byindex(status_list, i);
        if (!entry) {
            continue;
        }
        bool is_untracked = (entry->status & GIT_STATUS_WT_NEW) != 0;
        bool is_ignored = (entry->status & GIT_STATUS_IGNORED) != 0;
        if (only_ignored) {
            if (!is_ignored) {
                continue;
            }
        } else if (include_ignored) {
            if (!is_untracked && !is_ignored) {
                continue;
            }
        } else {
            if (!is_untracked) {
                continue;
            }
        }

        const char *path = smallclueGitStatusPath(entry);
        if (!path || !*path) {
            continue;
        }
        if (smallclueGitCleanPathListAdd(&candidates, path) != 0) {
            git_status_list_free(status_list);
            smallclueGitCleanPathListFree(&candidates);
            smallclueGitCleanPathListFree(&pathspecs);
            smallclueGitPrintError("out of memory");
            return 1;
        }
    }
    git_status_list_free(status_list);

    if (candidates.count == 0) {
        smallclueGitCleanPathListFree(&candidates);
        smallclueGitCleanPathListFree(&pathspecs);
        return 0;
    }
    qsort(candidates.items, candidates.count, sizeof(char *), smallclueGitCompareCStringPtr);

    int rc = 0;
    for (size_t i = 0; i < candidates.count; ++i) {
        const char *raw = candidates.items[i];
        if (!raw || !*raw) {
            continue;
        }

        char normalized[PATH_MAX];
        if (smallclueGitNormalizeRepoPath(raw, normalized, sizeof(normalized)) != 0) {
            rc = 1;
            break;
        }
        if (pathspecs.count > 0) {
            bool matched = false;
            for (size_t s = 0; s < pathspecs.count; ++s) {
                if (smallclueGitCleanPathMatchesSpec(normalized, pathspecs.items[s])) {
                    matched = true;
                    break;
                }
            }
            if (!matched) {
                continue;
            }
        }
        char host_path[PATH_MAX];
        if (smallclueGitBuildWorkdirPath(repo, normalized, host_path, sizeof(host_path)) != 0) {
            rc = 1;
            break;
        }

        int dir_state = smallclueGitPathIsDirectory(host_path);
        bool is_dir = (dir_state == 1);
        if (is_dir && !remove_dirs) {
            continue;
        }

        if (dry_run) {
            if (!quiet) {
                printf("Would remove %s\n", raw);
            }
            continue;
        }

        int rm_rc = smallclueGitRemoveFilesystemPath(host_path, is_dir);
        if (rm_rc == 1) {
            continue;
        }
        if (rm_rc < 0) {
            rc = 1;
            break;
        }
        if (!quiet) {
            printf("Removing %s\n", raw);
        }
    }

    smallclueGitCleanPathListFree(&candidates);
    smallclueGitCleanPathListFree(&pathspecs);
    return rc;
}

static int smallclueGitParseStashIndex(const char *spec, size_t *out_index) {
    if (!out_index) {
        return -1;
    }
    *out_index = 0;
    if (!spec || !*spec) {
        return 0;
    }

    const char *cursor = spec;
    size_t len = strlen(spec);
    if (len > 8 && strncmp(spec, "stash@{", 7) == 0 && spec[len - 1] == '}') {
        cursor = spec + 7;
        len -= 8;
    }

    if (len == 0 || !isdigit((unsigned char)cursor[0])) {
        return -1;
    }
    size_t value = 0;
    for (size_t i = 0; i < len; ++i) {
        if (!isdigit((unsigned char)cursor[i])) {
            return -1;
        }
        value = (value * 10) + (size_t)(cursor[i] - '0');
    }
    *out_index = value;
    return 0;
}

static int smallclueGitStashListCallback(size_t index, const char *message, const git_oid *stash_id, void *payload) {
    (void)stash_id;
    (void)payload;
    if (!message) {
        message = "";
    }
    printf("stash@{%zu}: %s\n", index, message);
    return 0;
}

typedef struct SmallclueGitStashLookupContext {
    size_t target_index;
    bool found;
    git_oid oid;
} SmallclueGitStashLookupContext;

static int smallclueGitStashLookupCallback(size_t index,
                                           const char *message,
                                           const git_oid *stash_id,
                                           void *payload) {
    (void)message;
    SmallclueGitStashLookupContext *ctx = (SmallclueGitStashLookupContext *)payload;
    if (!ctx || !stash_id) {
        return 0;
    }
    if (index == ctx->target_index) {
        git_oid_cpy(&ctx->oid, stash_id);
        ctx->found = true;
        return 1;
    }
    return 0;
}

static int smallclueGitCommandStash(git_repository *repo, int argc, char **argv) {
    const char *subcmd = "push";
    int subargc = argc;
    char **subargv = argv;
    if (argc > 0 && argv[0] && argv[0][0] != '-') {
        if (strcmp(argv[0], "push") == 0 ||
            strcmp(argv[0], "save") == 0 ||
            strcmp(argv[0], "list") == 0 ||
            strcmp(argv[0], "apply") == 0 ||
            strcmp(argv[0], "pop") == 0 ||
            strcmp(argv[0], "drop") == 0 ||
            strcmp(argv[0], "clear") == 0) {
            subcmd = argv[0];
            subargc = argc - 1;
            subargv = &argv[1];
        }
    }

    if (strcmp(subcmd, "list") == 0) {
        if (subargc != 0) {
            smallclueGitPrintError("stash list takes no arguments");
            return 2;
        }
        if (git_stash_foreach(repo, smallclueGitStashListCallback, NULL) != 0) {
            smallclueGitPrintLibgitError("stash list failed");
            return 1;
        }
        return 0;
    }

    if (strcmp(subcmd, "clear") == 0) {
        if (subargc != 0) {
            smallclueGitPrintError("stash clear takes no arguments");
            return 2;
        }
        for (;;) {
            int rc = git_stash_drop(repo, 0);
            if (rc == 0) {
                continue;
            }
            if (rc == GIT_ENOTFOUND) {
                break;
            }
            smallclueGitPrintLibgitError("stash clear failed");
            return 1;
        }
        return 0;
    }

    if (strcmp(subcmd, "drop") == 0) {
        size_t index = 0;
        bool quiet = false;
        const char *stash_spec = NULL;
        for (int i = 0; i < subargc; ++i) {
            const char *arg = subargv[i];
            if (!arg) {
                continue;
            }
            if (strcmp(arg, "-q") == 0 || strcmp(arg, "--quiet") == 0) {
                quiet = true;
                continue;
            }
            if (arg[0] == '-') {
                smallclueGitPrintError("unsupported stash option");
                return 2;
            }
            if (stash_spec) {
                smallclueGitPrintError("stash drop accepts at most one stash reference");
                return 2;
            }
            stash_spec = arg;
        }
        if (stash_spec && smallclueGitParseStashIndex(stash_spec, &index) != 0) {
            smallclueGitPrintError("invalid stash reference");
            return 2;
        }
        SmallclueGitStashLookupContext lookup;
        memset(&lookup, 0, sizeof(lookup));
        lookup.target_index = index;
        (void)git_stash_foreach(repo, smallclueGitStashLookupCallback, &lookup);
        if (git_stash_drop(repo, index) != 0) {
            smallclueGitPrintLibgitError("stash drop failed");
            return 1;
        }
        if (!quiet && lookup.found) {
            char oid_buf[GIT_OID_HEXSZ + 1];
            if (git_oid_tostr(oid_buf, sizeof(oid_buf), &lookup.oid)) {
                printf("Dropped stash@{%zu} (%s)\n", index, oid_buf);
            }
        }
        return 0;
    }

    if (strcmp(subcmd, "apply") == 0 || strcmp(subcmd, "pop") == 0) {
        bool quiet = false;
        bool reinstate_index = false;
        const char *stash_spec = NULL;
        for (int i = 0; i < subargc; ++i) {
            const char *arg = subargv[i];
            if (!arg) {
                continue;
            }
            if (strcmp(arg, "-q") == 0 || strcmp(arg, "--quiet") == 0) {
                quiet = true;
                continue;
            }
            if (strcmp(arg, "--index") == 0) {
                reinstate_index = true;
                continue;
            }
            if (arg[0] == '-') {
                smallclueGitPrintError("unsupported stash option");
                return 2;
            }
            if (stash_spec) {
                smallclueGitPrintError("too many stash references");
                return 2;
            }
            stash_spec = arg;
        }
        size_t index = 0;
        if (smallclueGitParseStashIndex(stash_spec, &index) != 0) {
            smallclueGitPrintError("invalid stash reference");
            return 2;
        }
        git_stash_apply_options opts = GIT_STASH_APPLY_OPTIONS_INIT;
        if (reinstate_index) {
            opts.flags |= GIT_STASH_APPLY_REINSTATE_INDEX;
        }
        int rc = (strcmp(subcmd, "pop") == 0)
                     ? git_stash_pop(repo, index, &opts)
                     : git_stash_apply(repo, index, &opts);
        if (rc != 0) {
            if (rc == GIT_ENOTFOUND) {
                smallclueGitPrintError("No stash entries found.");
                return 1;
            }
            smallclueGitPrintLibgitError(strcmp(subcmd, "pop") == 0 ? "stash pop failed" : "stash apply failed");
            return 1;
        }
        (void)quiet;
        return 0;
    }

    if (strcmp(subcmd, "push") == 0 || strcmp(subcmd, "save") == 0) {
        bool quiet = false;
        bool include_untracked = false;
        bool include_ignored = false;
        bool keep_index = false;
        const char *message = NULL;
        bool after_double_dash = false;

        for (int i = 0; i < subargc; ++i) {
            const char *arg = subargv[i];
            if (!arg) {
                continue;
            }
            if (!after_double_dash && strcmp(arg, "--") == 0) {
                after_double_dash = true;
                continue;
            }
            if (!after_double_dash && (strcmp(arg, "-q") == 0 || strcmp(arg, "--quiet") == 0)) {
                quiet = true;
                continue;
            }
            if (!after_double_dash && (strcmp(arg, "-u") == 0 || strcmp(arg, "--include-untracked") == 0)) {
                include_untracked = true;
                continue;
            }
            if (!after_double_dash && (strcmp(arg, "-a") == 0 || strcmp(arg, "--all") == 0)) {
                include_untracked = true;
                include_ignored = true;
                continue;
            }
            if (!after_double_dash && (strcmp(arg, "-k") == 0 || strcmp(arg, "--keep-index") == 0)) {
                keep_index = true;
                continue;
            }
            if (!after_double_dash &&
                (strcmp(arg, "-m") == 0 || strcmp(arg, "--message") == 0) &&
                i + 1 < subargc) {
                message = subargv[++i];
                continue;
            }
            if (!after_double_dash && strncmp(arg, "--message=", 10) == 0) {
                message = arg + 10;
                continue;
            }
            if (!after_double_dash && arg[0] == '-') {
                smallclueGitPrintError("unsupported stash option");
                return 2;
            }
            if (!message) {
                message = arg;
                continue;
            }
            smallclueGitPrintError("stash push/save accepts at most one message");
            return 2;
        }

        git_signature *stash_sig = NULL;
        if (git_signature_default(&stash_sig, repo) != 0 || !stash_sig) {
            git_signature *author = NULL;
            git_signature *committer = NULL;
            if (smallclueGitCreateDefaultSignatures(repo, &author, &committer) != 0) {
                smallclueGitPrintLibgitError("stash: signature creation failed");
                return 1;
            }
            stash_sig = author;
            git_signature_free(committer);
        }

        git_stash_flags flags = GIT_STASH_DEFAULT;
        if (include_untracked) {
            flags |= GIT_STASH_INCLUDE_UNTRACKED;
        }
        if (include_ignored) {
            flags |= GIT_STASH_INCLUDE_IGNORED;
        }
        if (keep_index) {
            flags |= GIT_STASH_KEEP_INDEX;
        }

        git_oid stash_oid;
        int rc = git_stash_save(&stash_oid, repo, stash_sig, message, flags);
        git_signature_free(stash_sig);
        if (rc != 0) {
            if (rc == GIT_ENOTFOUND) {
                if (!quiet) {
                    puts("No local changes to save");
                }
                return 0;
            }
            smallclueGitPrintLibgitError("stash save failed");
            return 1;
        }

        if (!quiet) {
            char short_oid[16];
            if (smallclueGitOidShort(&stash_oid, 7, short_oid, sizeof(short_oid)) == 0) {
                printf("Saved working directory and index state %s\n", short_oid);
            } else {
                puts("Saved working directory and index state");
            }
        }
        return 0;
    }

    smallclueGitPrintError("unsupported stash subcommand");
    return 2;
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

static int smallclueGitHardResetToHead(git_repository *repo, const char *context) {
    if (!repo) {
        return -1;
    }
    git_object *head_obj = NULL;
    if (git_revparse_single(&head_obj, repo, "HEAD") != 0 || !head_obj) {
        if (context && *context) {
            smallclueGitPrintLibgitError(context);
        }
        return -1;
    }
    int rc = git_reset(repo, head_obj, GIT_RESET_HARD, NULL);
    git_object_free(head_obj);
    if (rc != 0) {
        if (context && *context) {
            smallclueGitPrintLibgitError(context);
        }
        return -1;
    }
    return 0;
}

static int smallclueGitCommandCommit(git_repository *repo, int argc, char **argv) {
    const char *message = NULL;
    const char *author_override_spec = NULL;
    bool allow_empty = false;
    bool quiet = false;
    bool signoff = false;
    bool stage_all = false;
    bool amend = false;
    bool no_edit = false;
    bool reset_author = false;

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
        if (strcmp(arg, "--author") == 0 && i + 1 < argc) {
            author_override_spec = argv[++i];
            continue;
        }
        if (strncmp(arg, "--author=", 9) == 0) {
            author_override_spec = arg + 9;
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
        if (strcmp(arg, "-s") == 0 || strcmp(arg, "--signoff") == 0) {
            signoff = true;
            continue;
        }
        if (strcmp(arg, "-a") == 0 || strcmp(arg, "--all") == 0) {
            stage_all = true;
            continue;
        }
        if (strcmp(arg, "--amend") == 0) {
            amend = true;
            continue;
        }
        if (strcmp(arg, "--no-edit") == 0) {
            no_edit = true;
            continue;
        }
        if (strcmp(arg, "--reset-author") == 0) {
            reset_author = true;
            continue;
        }
        smallclueGitPrintError("unsupported commit option");
        return 2;
    }

    if (no_edit && !amend) {
        smallclueGitPrintError("commit --no-edit requires --amend");
        return 2;
    }
    if (reset_author && !amend) {
        smallclueGitPrintError("commit --reset-author requires --amend");
        return 2;
    }

    if (!amend && (!message || !*message)) {
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

    git_commit *head_commit = NULL;
    git_reference *head_ref = NULL;
    if (git_repository_head(&head_ref, repo) == 0 && head_ref) {
        git_object *head_obj = NULL;
        if (git_reference_peel(&head_obj, head_ref, GIT_OBJECT_COMMIT) == 0 && head_obj) {
            head_commit = (git_commit *)head_obj;
        }
    }
    if (amend && !head_commit) {
        git_reference_free(head_ref);
        git_tree_free(tree);
        smallclueGitPrintError("commit --amend requires an existing commit");
        return 1;
    }

    if (!allow_empty && !amend && head_commit) {
        git_tree *parent_tree = NULL;
        if (git_commit_tree(&parent_tree, head_commit) == 0 && parent_tree) {
            if (git_oid_equal(git_tree_id(parent_tree), &tree_oid)) {
                git_tree_free(parent_tree);
                git_reference_free(head_ref);
                git_commit_free(head_commit);
                git_tree_free(tree);
                fputs("nothing to commit\n", stderr);
                return 1;
            }
            git_tree_free(parent_tree);
        }
    }

    const char *final_message = message;
    if (amend && (!final_message || !*final_message)) {
        final_message = git_commit_message(head_commit);
        if (!final_message || !*final_message) {
            git_reference_free(head_ref);
            git_commit_free(head_commit);
            git_tree_free(tree);
            smallclueGitPrintError("commit --amend requires -m/--message when HEAD has no message");
            return 2;
        }
    }

    git_signature *author = NULL;
    git_signature *committer = NULL;
    if (smallclueGitCreateDefaultSignatures(repo, &author, &committer) != 0) {
        git_reference_free(head_ref);
        git_commit_free(head_commit);
        git_tree_free(tree);
        smallclueGitPrintLibgitError("commit: signature creation failed");
        return 1;
    }
    if (amend && head_commit && !reset_author) {
        const git_signature *existing_author = git_commit_author(head_commit);
        if (existing_author && existing_author->name && existing_author->email) {
            git_signature *amend_author = NULL;
            if (git_signature_dup(&amend_author, existing_author) == 0 && amend_author) {
                git_signature_free(author);
                author = amend_author;
            }
        }
    }
    if (author_override_spec && *author_override_spec) {
        char author_name[256];
        char author_email[256];
        if (smallclueGitParseAuthorIdentity(author_override_spec,
                                            author_name,
                                            sizeof(author_name),
                                            author_email,
                                            sizeof(author_email)) != 0) {
            git_signature_free(author);
            git_signature_free(committer);
            git_reference_free(head_ref);
            git_commit_free(head_commit);
            git_tree_free(tree);
            smallclueGitPrintError("commit --author expects 'Name <email>'");
            return 2;
        }
        git_signature *override_author = NULL;
        if (git_signature_now(&override_author, author_name, author_email) != 0 || !override_author) {
            git_signature_free(author);
            git_signature_free(committer);
            git_reference_free(head_ref);
            git_commit_free(head_commit);
            git_tree_free(tree);
            smallclueGitPrintLibgitError("commit: failed to create author signature");
            return 1;
        }
        git_signature_free(author);
        author = override_author;
    }

    char *owned_final_message = NULL;
    if (signoff) {
        const char *co_name = (committer && committer->name) ? committer->name : "PSCAL User";
        const char *co_email = (committer && committer->email) ? committer->email : "pscal@example.com";
        char trailer[512];
        int tn = snprintf(trailer, sizeof(trailer), "Signed-off-by: %s <%s>", co_name, co_email);
        if (tn < 0 || (size_t)tn >= sizeof(trailer)) {
            git_signature_free(author);
            git_signature_free(committer);
            git_reference_free(head_ref);
            git_commit_free(head_commit);
            git_tree_free(tree);
            smallclueGitPrintError("commit signoff trailer too long");
            return 2;
        }

        size_t base_len = final_message ? strlen(final_message) : 0;
        bool has_trailing_nl = (base_len > 0 && final_message[base_len - 1] == '\n');
        const char *joiner = has_trailing_nl ? "\n" : "\n\n";
        size_t joiner_len = strlen(joiner);
        size_t trailer_len = (size_t)tn;
        size_t total_len = base_len + joiner_len + trailer_len;
        owned_final_message = (char *)malloc(total_len + 1);
        if (!owned_final_message) {
            git_signature_free(author);
            git_signature_free(committer);
            git_reference_free(head_ref);
            git_commit_free(head_commit);
            git_tree_free(tree);
            smallclueGitPrintError("out of memory");
            return 1;
        }
        if (base_len > 0) {
            memcpy(owned_final_message, final_message, base_len);
        }
        memcpy(owned_final_message + base_len, joiner, joiner_len);
        memcpy(owned_final_message + base_len + joiner_len, trailer, trailer_len);
        owned_final_message[total_len] = '\0';
        final_message = owned_final_message;
    }

    git_oid commit_oid;
    if (amend) {
        if (git_commit_amend(&commit_oid,
                             head_commit,
                             "HEAD",
                             author,
                             committer,
                             NULL,
                             final_message,
                             tree) != 0) {
            free(owned_final_message);
            git_signature_free(author);
            git_signature_free(committer);
            git_reference_free(head_ref);
            git_commit_free(head_commit);
            git_tree_free(tree);
            smallclueGitPrintLibgitError("commit --amend failed");
            return 1;
        }
    } else {
        const git_commit *parents[1];
        size_t parent_count = 0;
        if (head_commit) {
            parents[parent_count++] = head_commit;
        }
        if (git_commit_create(&commit_oid,
                              repo,
                              "HEAD",
                              author,
                              committer,
                              NULL,
                              final_message,
                              tree,
                              parent_count,
                              parent_count > 0 ? parents : NULL) != 0) {
            free(owned_final_message);
            git_signature_free(author);
            git_signature_free(committer);
            git_reference_free(head_ref);
            git_commit_free(head_commit);
            git_tree_free(tree);
            smallclueGitPrintLibgitError("commit failed");
            return 1;
        }
    }

    if (!quiet) {
        char short_oid[16];
        if (smallclueGitOidShort(&commit_oid, 7, short_oid, sizeof(short_oid)) == 0) {
            char subject_line[256];
            subject_line[0] = '\0';
            (void)smallclueGitCopySubjectLine(final_message, subject_line, sizeof(subject_line));
            if (subject_line[0] != '\0') {
                printf("[%s] %s\n", short_oid, subject_line);
            } else {
                printf("[%s] %s\n", short_oid, final_message ? final_message : "");
            }
        }
    }

    free(owned_final_message);
    git_signature_free(author);
    git_signature_free(committer);
    git_reference_free(head_ref);
    git_commit_free(head_commit);
    git_tree_free(tree);
    return 0;
}

static int smallclueGitCommandReset(git_repository *repo, int argc, char **argv) {
    git_reset_t mode = GIT_RESET_MIXED;
    const char *revision = "HEAD";
    bool revision_set = false;
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
        if (!after_double_dash && !revision_set) {
            revision = arg;
            revision_set = true;
            continue;
        }
        if (path_count >= (sizeof(paths) / sizeof(paths[0]))) {
            smallclueGitPrintError("too many reset pathspecs");
            return 2;
        }
        paths[path_count++] = (char *)arg;
    }

    git_object *target = NULL;
    if (git_revparse_single(&target, repo, revision) != 0 || !target) {
        smallclueGitPrintLibgitError("reset revision lookup failed");
        return 128;
    }

    if (path_count > 0) {
        if (mode != GIT_RESET_MIXED) {
            git_object_free(target);
            smallclueGitPrintError("pathspec reset only supports --mixed mode");
            return 2;
        }
        git_strarray pathspec = { paths, path_count };
        if (git_reset_default(repo, target, &pathspec) != 0) {
            git_object_free(target);
            smallclueGitPrintLibgitError("reset pathspec failed");
            return 1;
        }
    } else if (git_reset(repo, target, mode, NULL) != 0) {
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
    bool path_mode = false;
    char *paths[128];
    size_t path_count = 0;

    for (int i = 0; i < argc; ++i) {
        const char *arg = argv[i];
        if (!arg) {
            continue;
        }
        if (path_mode) {
            if (path_count >= (sizeof(paths) / sizeof(paths[0]))) {
                smallclueGitPrintError("too many checkout paths");
                return 2;
            }
            paths[path_count++] = (char *)arg;
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
            path_mode = true;
            continue;
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

    if (path_mode) {
        if (switch_style) {
            smallclueGitPrintError("switch does not support path checkout");
            return 2;
        }
        if (detach || create_branch) {
            smallclueGitPrintError("path checkout does not support branch/detach options");
            return 2;
        }
        if (path_count == 0) {
            smallclueGitPrintError("checkout -- requires at least one path");
            return 2;
        }

        git_strarray pathspec = { paths, path_count };
        git_object *source_obj = NULL;
        if (target_spec && *target_spec) {
            if (git_revparse_single(&source_obj, repo, target_spec) != 0 || !source_obj) {
                smallclueGitPrintLibgitError("checkout: invalid source revision");
                return 128;
            }
            if (git_reset_default(repo, source_obj, &pathspec) != 0) {
                git_object_free(source_obj);
                smallclueGitPrintLibgitError("checkout: failed to update index");
                return 1;
            }
        }

        git_checkout_options checkout_opts = GIT_CHECKOUT_OPTIONS_INIT;
        checkout_opts.checkout_strategy = GIT_CHECKOUT_FORCE | GIT_CHECKOUT_RECREATE_MISSING;
        checkout_opts.paths = pathspec;
        int rc = 0;
        if (source_obj) {
            rc = git_checkout_tree(repo, source_obj, &checkout_opts);
        } else {
            rc = git_checkout_index(repo, NULL, &checkout_opts);
        }
        git_object_free(source_obj);
        if (rc != 0) {
            smallclueGitPrintLibgitError("checkout path update failed");
            return 1;
        }
        (void)quiet;
        return 0;
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
    char short_oid[GIT_OID_HEXSZ + 1];
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
                                         char **patterns,
                                         bool filter_merged,
                                         bool filter_no_merged,
                                         const char *filter_target_spec,
                                         bool filter_contains,
                                         bool filter_no_contains,
                                         const char *contains_target_spec,
                                         bool filter_points_at,
                                         const char *points_at_spec) {
    git_reference *head = NULL;
    const char *head_name = NULL;
    git_commit *filter_target = NULL;
    const git_oid *filter_target_oid = NULL;
    git_commit *contains_target = NULL;
    const git_oid *contains_target_oid = NULL;
    git_commit *points_at_target = NULL;
    const git_oid *points_at_oid = NULL;
    int rc_out = 0;

    if (filter_merged && filter_no_merged) {
        smallclueGitPrintError("branch: --merged and --no-merged are mutually exclusive");
        return 2;
    }
    if (filter_contains && filter_no_contains) {
        smallclueGitPrintError("branch: --contains and --no-contains are mutually exclusive");
        return 2;
    }

    if (filter_merged || filter_no_merged) {
        const char *target_spec = (filter_target_spec && *filter_target_spec) ? filter_target_spec : "HEAD";
        if (smallclueGitResolveCommit(repo, target_spec, &filter_target) != 0 || !filter_target) {
            smallclueGitPrintLibgitError("branch: unable to resolve filter commit");
            return 128;
        }
        filter_target_oid = git_commit_id(filter_target);
    }
    if (filter_contains || filter_no_contains) {
        const char *target_spec = (contains_target_spec && *contains_target_spec) ? contains_target_spec : "HEAD";
        if (smallclueGitResolveCommit(repo, target_spec, &contains_target) != 0 || !contains_target) {
            if (filter_target) {
                git_commit_free(filter_target);
            }
            smallclueGitPrintLibgitError("branch: unable to resolve contains commit");
            return 128;
        }
        contains_target_oid = git_commit_id(contains_target);
    }
    if (filter_points_at) {
        const char *target_spec = (points_at_spec && *points_at_spec) ? points_at_spec : "HEAD";
        if (smallclueGitResolveCommit(repo, target_spec, &points_at_target) != 0 || !points_at_target) {
            if (filter_target) {
                git_commit_free(filter_target);
            }
            if (contains_target) {
                git_commit_free(contains_target);
            }
            smallclueGitPrintLibgitError("branch: unable to resolve points-at commit");
            return 128;
        }
        points_at_oid = git_commit_id(points_at_target);
    }

    if (git_repository_head(&head, repo) == 0) {
        head_name = git_reference_shorthand(head);
    }

    git_branch_t branch_flags = all ? GIT_BRANCH_ALL : GIT_BRANCH_LOCAL;
    git_branch_iterator *it = NULL;
    if (git_branch_iterator_new(&it, repo, branch_flags) != 0) {
        if (head) git_reference_free(head);
        if (filter_target) git_commit_free(filter_target);
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
        git_object *peeled_obj = NULL;
        if (!oid) {
            if (git_reference_peel(&peeled_obj, ref, GIT_OBJECT_COMMIT) == 0 && peeled_obj) {
                oid = git_object_id(peeled_obj);
            }
        }

        if ((filter_merged || filter_no_merged) && oid && filter_target_oid) {
            bool merged = false;
            if (git_oid_equal(oid, filter_target_oid)) {
                merged = true;
            } else {
                int grc = git_graph_descendant_of(repo, filter_target_oid, oid);
                if (grc < 0) {
                    if (peeled_obj) {
                        git_object_free(peeled_obj);
                    }
                    git_reference_free(ref);
                    ref = NULL;
                    rc_out = 1;
                    smallclueGitPrintLibgitError("branch: merged-filter ancestry check failed");
                    goto cleanup;
                }
                merged = (grc != 0);
            }

            if ((filter_merged && !merged) || (filter_no_merged && merged)) {
                if (peeled_obj) {
                    git_object_free(peeled_obj);
                }
                git_reference_free(ref);
                ref = NULL;
                count--;
                free(e->name);
                e->name = NULL;
                continue;
            }
        } else if ((filter_merged || filter_no_merged) && !oid) {
            if (peeled_obj) {
                git_object_free(peeled_obj);
            }
            git_reference_free(ref);
            ref = NULL;
            count--;
            free(e->name);
            e->name = NULL;
            continue;
        }

        if ((filter_contains || filter_no_contains) && oid && contains_target_oid) {
            bool contains = false;
            if (git_oid_equal(oid, contains_target_oid)) {
                contains = true;
            } else {
                int grc = git_graph_descendant_of(repo, oid, contains_target_oid);
                if (grc < 0) {
                    if (peeled_obj) {
                        git_object_free(peeled_obj);
                    }
                    git_reference_free(ref);
                    ref = NULL;
                    rc_out = 1;
                    smallclueGitPrintLibgitError("branch: contains-filter ancestry check failed");
                    goto cleanup;
                }
                contains = (grc != 0);
            }

            if ((filter_contains && !contains) || (filter_no_contains && contains)) {
                if (peeled_obj) {
                    git_object_free(peeled_obj);
                }
                git_reference_free(ref);
                ref = NULL;
                count--;
                free(e->name);
                e->name = NULL;
                continue;
            }
        } else if ((filter_contains || filter_no_contains) && !oid) {
            if (peeled_obj) {
                git_object_free(peeled_obj);
            }
            git_reference_free(ref);
            ref = NULL;
            count--;
            free(e->name);
            e->name = NULL;
            continue;
        }

        if (filter_points_at && points_at_oid) {
            if (!oid || !git_oid_equal(oid, points_at_oid)) {
                if (peeled_obj) {
                    git_object_free(peeled_obj);
                }
                git_reference_free(ref);
                ref = NULL;
                count--;
                free(e->name);
                e->name = NULL;
                continue;
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

        if (peeled_obj) {
            git_object_free(peeled_obj);
        }
        git_reference_free(ref);
        ref = NULL;
    }

cleanup:
    if (ref) {
        git_reference_free(ref);
    }
    git_branch_iterator_free(it);
    if (head) {
        git_reference_free(head);
    }
    if (filter_target) {
        git_commit_free(filter_target);
    }
    if (contains_target) {
        git_commit_free(contains_target);
    }
    if (points_at_target) {
        git_commit_free(points_at_target);
    }

    if (rc_out != 0) {
        for (size_t i = 0; i < count; ++i) {
            free(entries[i].name);
            free(entries[i].subject);
        }
        free(entries);
        return rc_out;
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
                                           const char *start_point,
                                           bool force) {
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
    if (git_branch_create(&created, repo, name, target, force ? 1 : 0) != 0) {
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

static int smallclueGitCommandBranchCopy(git_repository *repo,
                                         int operand_count,
                                         char **operands,
                                         bool force) {
    const char *old_name = NULL;
    const char *new_name = NULL;

    if (operand_count == 1) {
        new_name = operands[0];
        git_reference *head = NULL;
        if (git_repository_head(&head, repo) != 0 || !head) {
            fprintf(stderr, "fatal: No branch to copy\n");
            return 128;
        }
        old_name = git_reference_shorthand(head);
        git_reference_free(head);
    } else if (operand_count == 2) {
        old_name = operands[0];
        new_name = operands[1];
    } else {
        smallclueGitPrintError("branch copy expects one or two branch names");
        return 2;
    }

    if (!old_name || !*old_name || !new_name || !*new_name) {
        smallclueGitPrintError("branch copy expects valid branch names");
        return 2;
    }

    git_reference *source = NULL;
    if (git_branch_lookup(&source, repo, old_name, GIT_BRANCH_LOCAL) != 0 || !source) {
        fprintf(stderr, "error: branch '%s' not found\n", old_name);
        return 1;
    }

    git_object *obj = NULL;
    if (git_reference_peel(&obj, source, GIT_OBJECT_COMMIT) != 0 || !obj) {
        git_reference_free(source);
        smallclueGitPrintLibgitError("branch copy failed");
        return 1;
    }
    git_commit *target = (git_commit *)obj;

    git_reference *created = NULL;
    if (git_branch_create(&created, repo, new_name, target, force ? 1 : 0) != 0 || !created) {
        git_commit_free(target);
        git_reference_free(source);
        smallclueGitPrintLibgitError("branch copy failed");
        return 1;
    }

    git_buf upstream_name = GIT_BUF_INIT;
    const char *source_ref_name = git_reference_name(source);
    if (source_ref_name &&
        git_branch_upstream_name(&upstream_name, repo, source_ref_name) == 0 &&
        upstream_name.ptr &&
        upstream_name.ptr[0] != '\0') {
        const char *up_name = upstream_name.ptr;
        if (strncmp(up_name, "refs/remotes/", 13) == 0 && up_name[13] != '\0') {
            up_name += 13;
        }
        (void)git_branch_set_upstream(created, up_name);
    }

    git_buf_dispose(&upstream_name);
    git_reference_free(created);
    git_commit_free(target);
    git_reference_free(source);
    return 0;
}

static int smallclueGitCommandBranchSetUpstream(git_repository *repo,
                                                const char *upstream_spec,
                                                int operand_count,
                                                char **operands) {
    if (!upstream_spec || !*upstream_spec) {
        smallclueGitPrintError("branch --set-upstream-to requires an upstream");
        return 2;
    }
    if (operand_count > 1) {
        smallclueGitPrintError("branch --set-upstream-to accepts at most one branch name");
        return 2;
    }

    char current_branch[256];
    const char *target_branch = NULL;
    if (operand_count == 1) {
        target_branch = operands[0];
    } else if (smallclueGitCurrentBranchName(repo, current_branch, sizeof(current_branch)) == 0) {
        target_branch = current_branch;
    } else {
        smallclueGitPrintError("could not set upstream: HEAD does not point to a branch");
        return 1;
    }

    if (!target_branch || !*target_branch) {
        smallclueGitPrintError("branch --set-upstream-to requires a valid branch name");
        return 2;
    }

    git_reference *branch = NULL;
    if (git_branch_lookup(&branch, repo, target_branch, GIT_BRANCH_LOCAL) != 0 || !branch) {
        fprintf(stderr, "error: branch '%s' not found\n", target_branch);
        return 1;
    }

    if (git_branch_set_upstream(branch, upstream_spec) != 0) {
        git_reference_free(branch);
        smallclueGitPrintLibgitError("branch set-upstream failed");
        return 1;
    }

    char upstream_display[512];
    const char *display = upstream_spec;
    git_reference *upstream_ref = NULL;
    if (git_branch_upstream(&upstream_ref, branch) == 0 && upstream_ref) {
        const char *full = git_reference_name(upstream_ref);
        if (full && strncmp(full, "refs/remotes/", 13) == 0 && full[13] != '\0') {
            display = full + 13;
        } else if (full && *full) {
            display = full;
        }
    }
    if (snprintf(upstream_display, sizeof(upstream_display), "%s", display ? display : upstream_spec) >= (int)sizeof(upstream_display)) {
        if (upstream_ref) {
            git_reference_free(upstream_ref);
        }
        git_reference_free(branch);
        smallclueGitPrintError("upstream name too long");
        return 2;
    }

    printf("branch '%s' set up to track '%s'.\n", target_branch, upstream_display);

    if (upstream_ref) {
        git_reference_free(upstream_ref);
    }
    git_reference_free(branch);
    return 0;
}

static int smallclueGitCommandBranchUnsetUpstream(git_repository *repo,
                                                  int operand_count,
                                                  char **operands) {
    if (operand_count > 1) {
        smallclueGitPrintError("branch --unset-upstream accepts at most one branch name");
        return 2;
    }

    char current_branch[256];
    const char *target_branch = NULL;
    if (operand_count == 1) {
        target_branch = operands[0];
    } else if (smallclueGitCurrentBranchName(repo, current_branch, sizeof(current_branch)) == 0) {
        target_branch = current_branch;
    } else {
        smallclueGitPrintError("could not unset upstream: HEAD does not point to a branch");
        return 1;
    }

    if (!target_branch || !*target_branch) {
        smallclueGitPrintError("branch --unset-upstream requires a valid branch name");
        return 2;
    }

    git_reference *branch = NULL;
    if (git_branch_lookup(&branch, repo, target_branch, GIT_BRANCH_LOCAL) != 0 || !branch) {
        fprintf(stderr, "error: branch '%s' not found\n", target_branch);
        return 1;
    }

    if (git_branch_set_upstream(branch, NULL) != 0) {
        git_reference_free(branch);
        smallclueGitPrintLibgitError("branch unset-upstream failed");
        return 1;
    }

    git_reference_free(branch);
    return 0;
}

static int smallclueGitCommandBranch(git_repository *repo, int argc, char **argv) {
    enum {
        SMALLCLUE_BRANCH_LIST = 0,
        SMALLCLUE_BRANCH_CREATE,
        SMALLCLUE_BRANCH_DELETE,
        SMALLCLUE_BRANCH_RENAME,
        SMALLCLUE_BRANCH_COPY,
        SMALLCLUE_BRANCH_SHOW_CURRENT,
        SMALLCLUE_BRANCH_SET_UPSTREAM,
        SMALLCLUE_BRANCH_UNSET_UPSTREAM,
    } action = SMALLCLUE_BRANCH_LIST;

    bool all = false;
    bool verbose = false;
    bool explicit_list = false;
    bool force = false;
    bool create_force = false;
    bool filter_merged = false;
    bool filter_no_merged = false;
    const char *filter_target_spec = NULL;
    bool filter_contains = false;
    bool filter_no_contains = false;
    const char *contains_target_spec = NULL;
    bool filter_points_at = false;
    const char *points_at_spec = NULL;
    int operand_start = argc;
    const char *set_upstream_to = NULL;

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
        if (strcmp(arg, "--show-current") == 0) {
            action = SMALLCLUE_BRANCH_SHOW_CURRENT;
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
        if (strcmp(arg, "--merged") == 0) {
            filter_merged = true;
            action = SMALLCLUE_BRANCH_LIST;
            explicit_list = true;
            if (i + 1 < argc && argv[i + 1] && argv[i + 1][0] != '-') {
                filter_target_spec = argv[++i];
            }
            continue;
        }
        if (strncmp(arg, "--merged=", 9) == 0) {
            filter_merged = true;
            action = SMALLCLUE_BRANCH_LIST;
            explicit_list = true;
            filter_target_spec = arg + 9;
            continue;
        }
        if (strcmp(arg, "--no-merged") == 0) {
            filter_no_merged = true;
            action = SMALLCLUE_BRANCH_LIST;
            explicit_list = true;
            if (i + 1 < argc && argv[i + 1] && argv[i + 1][0] != '-') {
                filter_target_spec = argv[++i];
            }
            continue;
        }
        if (strncmp(arg, "--no-merged=", 12) == 0) {
            filter_no_merged = true;
            action = SMALLCLUE_BRANCH_LIST;
            explicit_list = true;
            filter_target_spec = arg + 12;
            continue;
        }
        if (strcmp(arg, "--contains") == 0) {
            filter_contains = true;
            action = SMALLCLUE_BRANCH_LIST;
            explicit_list = true;
            if (i + 1 < argc && argv[i + 1] && argv[i + 1][0] != '-') {
                contains_target_spec = argv[++i];
            }
            continue;
        }
        if (strncmp(arg, "--contains=", 11) == 0) {
            filter_contains = true;
            action = SMALLCLUE_BRANCH_LIST;
            explicit_list = true;
            contains_target_spec = arg + 11;
            continue;
        }
        if (strcmp(arg, "--no-contains") == 0) {
            filter_no_contains = true;
            action = SMALLCLUE_BRANCH_LIST;
            explicit_list = true;
            if (i + 1 < argc && argv[i + 1] && argv[i + 1][0] != '-') {
                contains_target_spec = argv[++i];
            }
            continue;
        }
        if (strncmp(arg, "--no-contains=", 14) == 0) {
            filter_no_contains = true;
            action = SMALLCLUE_BRANCH_LIST;
            explicit_list = true;
            contains_target_spec = arg + 14;
            continue;
        }
        if (strcmp(arg, "--points-at") == 0) {
            filter_points_at = true;
            action = SMALLCLUE_BRANCH_LIST;
            explicit_list = true;
            if (i + 1 < argc && argv[i + 1] && argv[i + 1][0] != '-') {
                points_at_spec = argv[++i];
            }
            continue;
        }
        if (strncmp(arg, "--points-at=", 12) == 0) {
            filter_points_at = true;
            action = SMALLCLUE_BRANCH_LIST;
            explicit_list = true;
            points_at_spec = arg + 12;
            continue;
        }
        if (strcmp(arg, "-f") == 0 || strcmp(arg, "--force") == 0) {
            create_force = true;
            force = true;
            continue;
        }
        if (strcmp(arg, "-u") == 0 || strcmp(arg, "--set-upstream-to") == 0 || strcmp(arg, "--set-upstream") == 0) {
            if (i + 1 >= argc) {
                smallclueGitPrintError("branch --set-upstream-to requires an upstream");
                return 2;
            }
            set_upstream_to = argv[++i];
            action = SMALLCLUE_BRANCH_SET_UPSTREAM;
            operand_start = i + 1;
            continue;
        }
        if (strncmp(arg, "--set-upstream-to=", 18) == 0) {
            set_upstream_to = arg + 18;
            action = SMALLCLUE_BRANCH_SET_UPSTREAM;
            operand_start = i + 1;
            continue;
        }
        if (strcmp(arg, "--unset-upstream") == 0) {
            action = SMALLCLUE_BRANCH_UNSET_UPSTREAM;
            operand_start = i + 1;
            continue;
        }
        if (strcmp(arg, "-d") == 0 || strcmp(arg, "--delete") == 0) {
            action = SMALLCLUE_BRANCH_DELETE;
            continue;
        }
        if (strcmp(arg, "-D") == 0) {
            action = SMALLCLUE_BRANCH_DELETE;
            force = true;
            continue;
        }
        if (strcmp(arg, "-m") == 0 || strcmp(arg, "--move") == 0) {
            action = SMALLCLUE_BRANCH_RENAME;
            continue;
        }
        if (strcmp(arg, "-M") == 0) {
            action = SMALLCLUE_BRANCH_RENAME;
            force = true;
            continue;
        }
        if (strcmp(arg, "-c") == 0 || strcmp(arg, "--copy") == 0) {
            action = SMALLCLUE_BRANCH_COPY;
            continue;
        }
        if (strcmp(arg, "-C") == 0) {
            action = SMALLCLUE_BRANCH_COPY;
            force = true;
            continue;
        }
        if (arg[0] == '-') {
            smallclueGitPrintError("unsupported branch option");
            return 2;
        }

        if (action == SMALLCLUE_BRANCH_SET_UPSTREAM ||
            action == SMALLCLUE_BRANCH_UNSET_UPSTREAM ||
            action == SMALLCLUE_BRANCH_DELETE ||
            action == SMALLCLUE_BRANCH_RENAME ||
            action == SMALLCLUE_BRANCH_COPY) {
            operand_start = i;
            break;
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
        return smallclueGitCommandBranchList(repo,
                                             all,
                                             verbose,
                                             pattern_count,
                                             patterns,
                                             filter_merged,
                                             filter_no_merged,
                                             filter_target_spec,
                                             filter_contains,
                                             filter_no_contains,
                                             contains_target_spec,
                                             filter_points_at,
                                             points_at_spec);
    }

    if (action == SMALLCLUE_BRANCH_CREATE) {
        int count = (operand_start < argc) ? (argc - operand_start) : 0;
        if (count < 1 || count > 2) {
            smallclueGitPrintError("branch create expects: git branch <name> [start-point]");
            return 2;
        }
        const char *name = argv[operand_start];
        const char *start_point = (count > 1) ? argv[operand_start + 1] : NULL;
        return smallclueGitCommandBranchCreate(repo, name, start_point, create_force);
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

    if (action == SMALLCLUE_BRANCH_COPY) {
        int count = (operand_start < argc) ? (argc - operand_start) : 0;
        return smallclueGitCommandBranchCopy(repo, count, &argv[operand_start], force);
    }

    if (action == SMALLCLUE_BRANCH_SHOW_CURRENT) {
        if (operand_start < argc) {
            smallclueGitPrintError("branch --show-current expects no branch patterns or operands");
            return 2;
        }
        git_reference *head = NULL;
        if (git_repository_head(&head, repo) == 0 && head) {
            const char *name = git_reference_shorthand(head);
            if (name && *name && strcmp(name, "HEAD") != 0) {
                puts(name);
            }
            git_reference_free(head);
            return 0;
        }
        if (head) {
            git_reference_free(head);
        }
        if (git_repository_head_detached(repo)) {
            return 0;
        }
        smallclueGitPrintLibgitError("branch --show-current failed");
        return 1;
    }

    if (action == SMALLCLUE_BRANCH_SET_UPSTREAM) {
        int count = (operand_start < argc) ? (argc - operand_start) : 0;
        return smallclueGitCommandBranchSetUpstream(repo, set_upstream_to, count, &argv[operand_start]);
    }

    if (action == SMALLCLUE_BRANCH_UNSET_UPSTREAM) {
        int count = (operand_start < argc) ? (argc - operand_start) : 0;
        return smallclueGitCommandBranchUnsetUpstream(repo, count, &argv[operand_start]);
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

static int smallclueGitAppendLiteral(char *out, size_t out_sz, size_t *used, const char *value) {
    if (!out || !used || !value) {
        return -1;
    }
    size_t remain = (*used < out_sz) ? (out_sz - *used) : 0;
    int n = snprintf(out + *used, remain, "%s", value);
    if (n < 0 || (size_t)n >= remain) {
        return -1;
    }
    *used += (size_t)n;
    return 0;
}

static int smallclueGitAppendChar(char *out, size_t out_sz, size_t *used, char c) {
    if (!out || !used || *used + 1 >= out_sz) {
        return -1;
    }
    out[*used] = c;
    (*used)++;
    out[*used] = '\0';
    return 0;
}

static const char *smallclueGitCommitBody(const git_commit *commit) {
    const char *msg = git_commit_message(commit);
    if (!msg) {
        return "";
    }
    const char *nl = strchr(msg, '\n');
    if (!nl) {
        return "";
    }
    const char *body = nl + 1;
    if (*body == '\n') {
        body++;
    }
    return body;
}

static int smallclueGitFormatPrettyCommit(const git_commit *commit,
                                          const git_oid *oid,
                                          size_t abbrev_width,
                                          const char *format_spec,
                                          char *out,
                                          size_t out_sz) {
    if (!commit || !oid || !format_spec || !out || out_sz == 0) {
        return -1;
    }
    out[0] = '\0';

    char full_oid[GIT_OID_HEXSZ + 1];
    if (!git_oid_tostr(full_oid, sizeof(full_oid), oid)) {
        return -1;
    }
    char short_oid[16];
    if (smallclueGitOidShort(oid, abbrev_width, short_oid, sizeof(short_oid)) != 0) {
        return -1;
    }
    char subject[512];
    smallclueGitCopySubjectLine(smallclueGitCommitSubject(commit), subject, sizeof(subject));
    const git_signature *author = git_commit_author(commit);
    const git_signature *committer = git_commit_committer(commit);
    const char *body = smallclueGitCommitBody(commit);
    const char *full_msg = git_commit_message(commit);
    if (!full_msg) {
        full_msg = "";
    }

    size_t used = 0;
    for (size_t i = 0; format_spec[i] != '\0'; ++i) {
        if (format_spec[i] != '%') {
            if (smallclueGitAppendChar(out, out_sz, &used, format_spec[i]) != 0) {
                return -1;
            }
            continue;
        }
        char next = format_spec[i + 1];
        if (next == '\0') {
            if (smallclueGitAppendChar(out, out_sz, &used, '%') != 0) {
                return -1;
            }
            break;
        }
        if (next == '%') {
            if (smallclueGitAppendChar(out, out_sz, &used, '%') != 0) {
                return -1;
            }
            i++;
            continue;
        }
        if (next == 'H') {
            if (smallclueGitAppendLiteral(out, out_sz, &used, full_oid) != 0) {
                return -1;
            }
            i++;
            continue;
        }
        if (next == 'h') {
            if (smallclueGitAppendLiteral(out, out_sz, &used, short_oid) != 0) {
                return -1;
            }
            i++;
            continue;
        }
        if (next == 's') {
            if (smallclueGitAppendLiteral(out, out_sz, &used, subject) != 0) {
                return -1;
            }
            i++;
            continue;
        }
        if (next == 'b') {
            if (smallclueGitAppendLiteral(out, out_sz, &used, body) != 0) {
                return -1;
            }
            i++;
            continue;
        }
        if (next == 'B') {
            if (smallclueGitAppendLiteral(out, out_sz, &used, full_msg) != 0) {
                return -1;
            }
            i++;
            continue;
        }
        if ((next == 'a' || next == 'c') && format_spec[i + 2] != '\0') {
            char suffix = format_spec[i + 2];
            if (next == 'a' && suffix == 'n') {
                const char *v = (author && author->name) ? author->name : "";
                if (smallclueGitAppendLiteral(out, out_sz, &used, v) != 0) {
                    return -1;
                }
                i += 2;
                continue;
            }
            if (next == 'a' && suffix == 'e') {
                const char *v = (author && author->email) ? author->email : "";
                if (smallclueGitAppendLiteral(out, out_sz, &used, v) != 0) {
                    return -1;
                }
                i += 2;
                continue;
            }
            if (next == 'c' && suffix == 'n') {
                const char *v = (committer && committer->name) ? committer->name : "";
                if (smallclueGitAppendLiteral(out, out_sz, &used, v) != 0) {
                    return -1;
                }
                i += 2;
                continue;
            }
            if (next == 'c' && suffix == 'e') {
                const char *v = (committer && committer->email) ? committer->email : "";
                if (smallclueGitAppendLiteral(out, out_sz, &used, v) != 0) {
                    return -1;
                }
                i += 2;
                continue;
            }
        }

        if (smallclueGitAppendChar(out, out_sz, &used, '%') != 0 ||
            smallclueGitAppendChar(out, out_sz, &used, next) != 0) {
            return -1;
        }
        i++;
    }

    return 0;
}

static int smallclueGitCommandLog(git_repository *repo, int argc, char **argv) {
    bool oneline = false;
    bool decorate = false;
    bool reverse = false;
    bool log_all = false;
    int max_count = -1;
    const char *author_filter = NULL;
    const char *grep_filter = NULL;
    char *rev_specs[64];
    int rev_spec_count = 0;
    bool parse_options = true;
    const char *pretty_spec = NULL;
    const char *format_spec = NULL;
    bool format_with_terminator = false;
    bool no_abbrev_commit = false;
    size_t abbrev_width = 7;

    for (int i = 0; i < argc; ++i) {
        const char *arg = argv[i];
        if (!arg) continue;
        if (parse_options && strcmp(arg, "--") == 0) {
            parse_options = false;
            continue;
        }
        if (!parse_options) {
            if (rev_spec_count >= (int)(sizeof(rev_specs) / sizeof(rev_specs[0]))) {
                smallclueGitPrintError("too many log revision arguments");
                return 2;
            }
            rev_specs[rev_spec_count++] = argv[i];
            continue;
        }
        if (strcmp(arg, "--oneline") == 0) {
            oneline = true;
            continue;
        }
        if (strcmp(arg, "--abbrev-commit") == 0) {
            no_abbrev_commit = false;
            continue;
        }
        if (strcmp(arg, "--no-abbrev-commit") == 0) {
            no_abbrev_commit = true;
            continue;
        }
        if (strncmp(arg, "--abbrev=", 9) == 0) {
            int n = atoi(arg + 9);
            if (n <= 0) {
                smallclueGitPrintError("invalid --abbrev value");
                return 2;
            }
            abbrev_width = (size_t)n;
            continue;
        }
        if (strcmp(arg, "--all") == 0) {
            log_all = true;
            continue;
        }
        if (strcmp(arg, "--no-decorate") == 0) {
            decorate = false;
            continue;
        }
        if (strncmp(arg, "--decorate=", 11) == 0) {
            const char *mode = arg + 11;
            if (strcmp(mode, "no") == 0 || strcmp(mode, "false") == 0) {
                decorate = false;
            } else if (strcmp(mode, "short") == 0 ||
                       strcmp(mode, "full") == 0 ||
                       strcmp(mode, "auto") == 0 ||
                       strcmp(mode, "true") == 0 ||
                       mode[0] == '\0') {
                decorate = true;
            } else {
                smallclueGitPrintError("unsupported log --decorate mode");
                return 2;
            }
            continue;
        }
        if (strcmp(arg, "--pretty") == 0 && i + 1 < argc) {
            pretty_spec = argv[++i];
            continue;
        }
        if (strncmp(arg, "--pretty=", 9) == 0) {
            pretty_spec = arg + 9;
            continue;
        }
        if (strcmp(arg, "--format") == 0 && i + 1 < argc) {
            format_spec = argv[++i];
            format_with_terminator = true;
            continue;
        }
        if (strncmp(arg, "--format=", 9) == 0) {
            format_spec = arg + 9;
            format_with_terminator = true;
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
        if (rev_spec_count >= (int)(sizeof(rev_specs) / sizeof(rev_specs[0]))) {
            smallclueGitPrintError("too many log revision arguments");
            return 2;
        }
        rev_specs[rev_spec_count++] = argv[i];
    }

    if (pretty_spec && *pretty_spec) {
        if (strcmp(pretty_spec, "oneline") == 0) {
            oneline = true;
        } else if (strncmp(pretty_spec, "format:", 7) == 0) {
            format_spec = pretty_spec + 7;
            format_with_terminator = false;
        } else {
            smallclueGitPrintError("unsupported log --pretty mode");
            return 2;
        }
    }

    git_revwalk *walk = NULL;
    if (git_revwalk_new(&walk, repo) != 0) {
        smallclueGitPrintLibgitError("log walk failed");
        return 1;
    }
    git_revwalk_sorting(walk, GIT_SORT_TOPOLOGICAL | GIT_SORT_TIME);

    if (log_all) {
        int all_rc = git_revwalk_push_glob(walk, "refs/*");
        if (all_rc != 0 && all_rc != GIT_ENOTFOUND) {
            git_revwalk_free(walk);
            smallclueGitPrintLibgitError("log --all failed");
            return 1;
        }
    }

    if (!log_all && rev_spec_count == 0) {
        if (git_revwalk_push_head(walk) != 0) {
            git_revwalk_free(walk);
            smallclueGitPrintLibgitError("log push HEAD failed");
            return 1;
        }
    }

    for (int i = 0; i < rev_spec_count; ++i) {
        const char *spec = rev_specs[i];
        if (!spec || !*spec) {
            continue;
        }
        if (strstr(spec, "..")) {
            if (git_revwalk_push_range(walk, spec) != 0) {
                git_revwalk_free(walk);
                smallclueGitPrintLibgitError("log: unable to resolve revision range");
                return 128;
            }
            continue;
        }
        if (spec[0] == '^' && spec[1] != '\0') {
            git_commit *hide_commit = NULL;
            if (smallclueGitResolveCommit(repo, spec + 1, &hide_commit) != 0 || !hide_commit) {
                git_revwalk_free(walk);
                smallclueGitPrintLibgitError("log: unable to resolve revision");
                return 128;
            }
            const git_oid *hide_oid = git_commit_id(hide_commit);
            int hrc = hide_oid ? git_revwalk_hide(walk, hide_oid) : -1;
            git_commit_free(hide_commit);
            if (hrc != 0) {
                git_revwalk_free(walk);
                smallclueGitPrintLibgitError("log: unable to hide revision");
                return 128;
            }
            continue;
        }
        git_commit *push_commit = NULL;
        if (smallclueGitResolveCommit(repo, spec, &push_commit) != 0 || !push_commit) {
            git_revwalk_free(walk);
            smallclueGitPrintLibgitError("log: unable to resolve revision");
            return 128;
        }
        const git_oid *push_oid = git_commit_id(push_commit);
        int prc = push_oid ? git_revwalk_push(walk, push_oid) : -1;
        git_commit_free(push_commit);
        if (prc != 0) {
            git_revwalk_free(walk);
            smallclueGitPrintLibgitError("log: unable to push revision");
            return 128;
        }
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

        char short_oid[GIT_OID_HEXSZ + 1];
        size_t oid_width = no_abbrev_commit ? GIT_OID_HEXSZ : abbrev_width;
        (void)smallclueGitOidShort(&oid, oid_width, short_oid, sizeof(short_oid));
        char subject[512];
        smallclueGitCopySubjectLine(smallclueGitCommitSubject(commit), subject, sizeof(subject));

        char line[2048];
        line[0] = '\0';
        if (format_spec && *format_spec) {
            if (smallclueGitFormatPrettyCommit(commit, &oid, abbrev_width, format_spec, line, sizeof(line)) != 0) {
                git_commit_free(commit);
                if (reverse_lines) {
                    for (size_t j = 0; j < reverse_count; ++j) {
                        free(reverse_lines[j]);
                    }
                    free(reverse_lines);
                }
                if (head) git_reference_free(head);
                git_revwalk_free(walk);
                smallclueGitPrintError("log format output too long");
                return 1;
            }
        } else {
            if (oneline) {
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
            } else {
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
            }
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
            if (format_spec && *format_spec) {
                if (!format_with_terminator && printed > 0) {
                    /* pretty=format uses separators between commits, no trailing newline. */
                    fputc('\n', stdout);
                }
                fputs(line, stdout);
                if (format_with_terminator) {
                    fputc('\n', stdout);
                }
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
        bool first_output = true;
        for (size_t i = reverse_count; i > 0; --i) {
            if (format_spec && *format_spec && !format_with_terminator && !first_output) {
                fputc('\n', stdout);
            }
            fputs(reverse_lines[i - 1], stdout);
            if (format_spec && *format_spec && format_with_terminator) {
                fputc('\n', stdout);
            }
            free(reverse_lines[i - 1]);
            first_output = false;
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

static int smallclueGitResolveRepoPathFromInput(git_repository *repo,
                                                const char *input,
                                                char *out,
                                                size_t out_sz) {
    if (!repo || !input || !*input || !out || out_sz == 0) {
        return -1;
    }

    char normalized[PATH_MAX];
    if (smallclueGitNormalizeRepoPath(input, normalized, sizeof(normalized)) != 0) {
        return -1;
    }

    const char *workdir = git_repository_workdir(repo);
    if (!workdir || !*workdir) {
        return smallclueGitCopyPath(normalized, out, out_sz);
    }

    char cwd[PATH_MAX];
    if (!getcwd(cwd, sizeof(cwd))) {
        return smallclueGitCopyPath(normalized, out, out_sz);
    }

    char abs_path[PATH_MAX];
    if (smallclueGitResolvePathFromBase(cwd, input, abs_path, sizeof(abs_path)) != 0) {
        return smallclueGitCopyPath(normalized, out, out_sz);
    }

    size_t workdir_len = strlen(workdir);
    if (strncmp(abs_path, workdir, workdir_len) != 0) {
        return smallclueGitCopyPath(normalized, out, out_sz);
    }
    if (smallclueGitNormalizeRepoPath(abs_path + workdir_len, out, out_sz) != 0) {
        return -1;
    }
    return 0;
}

static void smallclueGitFormatOffsetTz(int minutes, char *out, size_t out_sz) {
    if (!out || out_sz == 0) {
        return;
    }
    char sign = '+';
    if (minutes < 0) {
        sign = '-';
        minutes = -minutes;
    }
    int hours = minutes / 60;
    int mins = minutes % 60;
    if (snprintf(out, out_sz, "%c%02d%02d", sign, hours, mins) >= (int)out_sz) {
        out[0] = '\0';
    }
}

static void smallclueGitFormatBlameTimestamp(const git_signature *sig, char *out, size_t out_sz) {
    if (!out || out_sz == 0) {
        return;
    }
    out[0] = '\0';
    if (!sig) {
        return;
    }

    time_t shifted = (time_t)(sig->when.time + ((git_time_t)sig->when.offset * 60));
    struct tm tm_utc;
    if (!gmtime_r(&shifted, &tm_utc)) {
        return;
    }
    char base[48];
    if (strftime(base, sizeof(base), "%Y-%m-%d %H:%M:%S", &tm_utc) == 0) {
        return;
    }
    char tz[8];
    smallclueGitFormatOffsetTz(sig->when.offset, tz, sizeof(tz));
    (void)snprintf(out, out_sz, "%s %s", base, tz);
}

static int smallclueGitPrintBlameLinePorcelain(git_repository *repo,
                                               const git_blame_hunk *hunk,
                                               const git_blame_line *line,
                                               size_t final_line_no,
                                               const char *path) {
    if (!repo || !hunk || !line || !path) {
        return -1;
    }

    char final_oid[GIT_OID_HEXSZ + 1];
    if (!git_oid_tostr(final_oid, sizeof(final_oid), &hunk->final_commit_id)) {
        return -1;
    }

    size_t offset = 0;
    if (final_line_no >= hunk->final_start_line_number) {
        offset = final_line_no - hunk->final_start_line_number;
    }
    size_t orig_line_no = hunk->orig_start_line_number + offset;

    printf("%s %zu %zu 1\n", final_oid, orig_line_no, final_line_no);

    const git_signature *author = hunk->final_signature;
    const git_signature *committer = hunk->final_committer ? hunk->final_committer : author;
    const char *author_name = (author && author->name) ? author->name : "Not Committed Yet";
    const char *author_mail = (author && author->email) ? author->email : "not.committed.yet";
    const char *committer_name = (committer && committer->name) ? committer->name : author_name;
    const char *committer_mail = (committer && committer->email) ? committer->email : author_mail;
    char author_tz[8];
    char committer_tz[8];
    smallclueGitFormatOffsetTz(author ? author->when.offset : 0, author_tz, sizeof(author_tz));
    smallclueGitFormatOffsetTz(committer ? committer->when.offset : 0, committer_tz, sizeof(committer_tz));

    printf("author %s\n", author_name);
    printf("author-mail <%s>\n", author_mail);
    printf("author-time %lld\n", (long long)(author ? author->when.time : 0));
    printf("author-tz %s\n", author_tz);
    printf("committer %s\n", committer_name);
    printf("committer-mail <%s>\n", committer_mail);
    printf("committer-time %lld\n", (long long)(committer ? committer->when.time : 0));
    printf("committer-tz %s\n", committer_tz);
    printf("summary %s\n", (hunk->summary && *hunk->summary) ? hunk->summary : "");

    if (hunk->boundary) {
        puts("boundary");
    }

    bool printed_previous = false;
    if (!git_oid_is_zero(&hunk->orig_commit_id) &&
        !git_oid_equal(&hunk->orig_commit_id, &hunk->final_commit_id)) {
        char orig_oid[GIT_OID_HEXSZ + 1];
        if (!git_oid_tostr(orig_oid, sizeof(orig_oid), &hunk->orig_commit_id)) {
            return -1;
        }
        printf("previous %s %s\n", orig_oid, (hunk->orig_path && *hunk->orig_path) ? hunk->orig_path : path);
        printed_previous = true;
    }
    if (!printed_previous && !hunk->boundary) {
        git_commit *final_commit = NULL;
        if (git_commit_lookup(&final_commit, repo, &hunk->final_commit_id) == 0 && final_commit) {
            if (git_commit_parentcount(final_commit) > 0) {
                git_commit *parent = NULL;
                if (git_commit_parent(&parent, final_commit, 0) == 0 && parent) {
                    char parent_oid[GIT_OID_HEXSZ + 1];
                    if (!git_oid_tostr(parent_oid, sizeof(parent_oid), git_commit_id(parent))) {
                        git_commit_free(parent);
                        git_commit_free(final_commit);
                        return -1;
                    }
                    printf("previous %s %s\n",
                           parent_oid,
                           (hunk->orig_path && *hunk->orig_path) ? hunk->orig_path : path);
                    git_commit_free(parent);
                }
            }
            git_commit_free(final_commit);
        }
    }

    printf("filename %s\n", path);
    fputc('\t', stdout);
    if (line->ptr && line->len > 0) {
        fwrite(line->ptr, 1, line->len, stdout);
        if (line->ptr[line->len - 1] != '\n') {
            fputc('\n', stdout);
        }
    } else {
        fputc('\n', stdout);
    }
    return 0;
}

static int smallclueGitPrintBlameLineDefault(const git_blame_hunk *hunk,
                                             const git_blame_line *line,
                                             size_t final_line_no) {
    if (!hunk || !line) {
        return -1;
    }

    size_t oid_width = hunk->boundary ? 7 : 8;
    char short_oid[16];
    if (smallclueGitOidShort(&hunk->final_commit_id, oid_width, short_oid, sizeof(short_oid)) != 0) {
        return -1;
    }

    const git_signature *author = hunk->final_signature;
    const char *author_name = (author && author->name) ? author->name : "Not Committed Yet";
    char when[64];
    smallclueGitFormatBlameTimestamp(author, when, sizeof(when));
    if (!when[0]) {
        (void)snprintf(when, sizeof(when), "1970-01-01 00:00:00 +0000");
    }

    char content[2048];
    size_t n = 0;
    if (line->ptr && line->len > 0) {
        n = line->len;
        if (n >= sizeof(content)) {
            n = sizeof(content) - 1;
        }
        memcpy(content, line->ptr, n);
    }
    while (n > 0 && (content[n - 1] == '\n' || content[n - 1] == '\r')) {
        n--;
    }
    content[n] = '\0';

    if (hunk->boundary) {
        printf("^%s (%s %s %zu) %s\n", short_oid, author_name, when, final_line_no, content);
    } else {
        printf("%s (%s %s %zu) %s\n", short_oid, author_name, when, final_line_no, content);
    }
    return 0;
}

static int smallclueGitCommandBlame(git_repository *repo, int argc, char **argv) {
    bool line_porcelain = false;
    bool after_double_dash = false;
    const char *pre_pos[2] = {0};
    int pre_count = 0;
    const char *post_pos[2] = {0};
    int post_count = 0;

    for (int i = 0; i < argc; ++i) {
        const char *arg = argv[i];
        if (!arg || !*arg) {
            continue;
        }
        if (!after_double_dash && strcmp(arg, "--line-porcelain") == 0) {
            line_porcelain = true;
            continue;
        }
        if (!after_double_dash && strcmp(arg, "--") == 0) {
            after_double_dash = true;
            continue;
        }
        if (!after_double_dash && arg[0] == '-') {
            smallclueGitPrintError("unsupported blame option");
            return 2;
        }
        if (after_double_dash) {
            if (post_count >= 2) {
                smallclueGitPrintError("too many blame operands");
                return 2;
            }
            post_pos[post_count++] = arg;
        } else {
            if (pre_count >= 2) {
                smallclueGitPrintError("too many blame operands");
                return 2;
            }
            pre_pos[pre_count++] = arg;
        }
    }

    const char *rev_spec = "HEAD";
    const char *path_spec = NULL;
    if (after_double_dash) {
        if (post_count != 1) {
            smallclueGitPrintError("blame requires exactly one file path");
            return 2;
        }
        path_spec = post_pos[0];
        if (pre_count > 1) {
            smallclueGitPrintError("blame accepts at most one revision before '--'");
            return 2;
        }
        if (pre_count == 1) {
            rev_spec = pre_pos[0];
        }
    } else {
        if (pre_count == 1) {
            path_spec = pre_pos[0];
        } else if (pre_count == 2) {
            rev_spec = pre_pos[0];
            path_spec = pre_pos[1];
        } else {
            smallclueGitPrintError("usage: git blame [--line-porcelain] [<rev>] [--] <path>");
            return 2;
        }
    }

    char repo_path[PATH_MAX];
    if (smallclueGitResolveRepoPathFromInput(repo, path_spec, repo_path, sizeof(repo_path)) != 0) {
        smallclueGitPrintError("blame: invalid path");
        return 2;
    }

    git_blame_options opts = GIT_BLAME_OPTIONS_INIT;
    git_commit *target = NULL;
    if (smallclueGitResolveCommit(repo, rev_spec, &target) != 0 || !target) {
        smallclueGitPrintLibgitError("blame: unable to resolve revision");
        return 128;
    }
    git_oid_cpy(&opts.newest_commit, git_commit_id(target));
    git_commit_free(target);

    git_blame *blame = NULL;
    if (git_blame_file(&blame, repo, repo_path, &opts) != 0 || !blame) {
        smallclueGitPrintLibgitError("blame failed");
        return 1;
    }

    size_t max_final_line = 0;
    size_t hunk_count = git_blame_hunkcount(blame);
    for (size_t i = 0; i < hunk_count; ++i) {
        const git_blame_hunk *h = git_blame_hunk_byindex(blame, i);
        if (!h || h->lines_in_hunk == 0) {
            continue;
        }
        size_t end = h->final_start_line_number + h->lines_in_hunk - 1;
        if (end > max_final_line) {
            max_final_line = end;
        }
    }

    for (size_t line_no = 1; line_no <= max_final_line; ++line_no) {
        const git_blame_hunk *hunk = git_blame_hunk_byline(blame, line_no);
        const git_blame_line *line = git_blame_line_byindex(blame, line_no);
        if (!hunk) {
            git_blame_free(blame);
            smallclueGitPrintError("blame: failed to read hunk data");
            return 1;
        }

        git_blame_line synthetic = { "", 0 };
        if (!line) {
            line = &synthetic;
        }

        int rc = 0;
        if (line_porcelain) {
            rc = smallclueGitPrintBlameLinePorcelain(repo, hunk, line, line_no, repo_path);
        } else {
            rc = smallclueGitPrintBlameLineDefault(hunk, line, line_no);
        }
        if (rc != 0) {
            git_blame_free(blame);
            smallclueGitPrintError("blame: output formatting failed");
            return 1;
        }
    }

    git_blame_free(blame);
    return 0;
}

static int smallclueGitCommandDescribe(git_repository *repo, int argc, char **argv) {
    git_describe_options opts = GIT_DESCRIBE_OPTIONS_INIT;
    git_describe_format_options fmt = GIT_DESCRIBE_FORMAT_OPTIONS_INIT;
    const char *revision = "HEAD";
    bool revision_set = false;
    bool use_workdir = false;

    for (int i = 0; i < argc; ++i) {
        const char *arg = argv[i];
        if (!arg || !*arg) {
            continue;
        }
        if (strcmp(arg, "--tags") == 0) {
            opts.describe_strategy = GIT_DESCRIBE_TAGS;
            continue;
        }
        if (strcmp(arg, "--all") == 0) {
            opts.describe_strategy = GIT_DESCRIBE_ALL;
            continue;
        }
        if (strcmp(arg, "--always") == 0) {
            opts.show_commit_oid_as_fallback = 1;
            continue;
        }
        if (strcmp(arg, "--long") == 0) {
            fmt.always_use_long_format = 1;
            continue;
        }
        if (strcmp(arg, "--dirty") == 0) {
            fmt.dirty_suffix = "-dirty";
            use_workdir = true;
            continue;
        }
        if (strncmp(arg, "--dirty=", 8) == 0) {
            fmt.dirty_suffix = arg + 8;
            use_workdir = true;
            continue;
        }
        if (strcmp(arg, "--abbrev") == 0 && i + 1 < argc) {
            long n = strtol(argv[++i], NULL, 10);
            if (n < 0) {
                smallclueGitPrintError("invalid --abbrev value");
                return 2;
            }
            fmt.abbreviated_size = (unsigned int)n;
            continue;
        }
        if (strncmp(arg, "--abbrev=", 9) == 0) {
            long n = strtol(arg + 9, NULL, 10);
            if (n < 0) {
                smallclueGitPrintError("invalid --abbrev value");
                return 2;
            }
            fmt.abbreviated_size = (unsigned int)n;
            continue;
        }
        if (arg[0] == '-') {
            smallclueGitPrintError("unsupported describe option");
            return 2;
        }
        if (revision_set) {
            smallclueGitPrintError("describe accepts at most one revision");
            return 2;
        }
        revision = arg;
        revision_set = true;
    }

    git_describe_result *result = NULL;
    if (use_workdir && strcmp(revision, "HEAD") == 0) {
        if (git_describe_workdir(&result, repo, &opts) != 0 || !result) {
            smallclueGitPrintLibgitError("describe failed");
            return 128;
        }
    } else {
        git_object *target = NULL;
        if (git_revparse_single(&target, repo, revision) != 0 || !target) {
            smallclueGitPrintLibgitError("describe: unable to resolve revision");
            return 128;
        }
        if (git_describe_commit(&result, target, &opts) != 0 || !result) {
            git_object_free(target);
            smallclueGitPrintLibgitError("describe failed");
            return 128;
        }
        git_object_free(target);
    }

    git_buf out = GIT_BUF_INIT;
    if (git_describe_format(&out, result, &fmt) != 0 || !out.ptr) {
        git_buf_dispose(&out);
        git_describe_result_free(result);
        smallclueGitPrintLibgitError("describe formatting failed");
        return 1;
    }

    fputs(out.ptr, stdout);
    fputc('\n', stdout);
    git_buf_dispose(&out);
    git_describe_result_free(result);
    return 0;
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

static bool smallclueGitLsRemoteRefMatches(const char *refname, int pattern_count, const char **patterns) {
    if (!refname || !*refname) {
        return false;
    }
    if (pattern_count <= 0 || !patterns) {
        return true;
    }
    const char *tail = strrchr(refname, '/');
    tail = tail ? tail + 1 : refname;
    for (int i = 0; i < pattern_count; ++i) {
        const char *pattern = patterns[i];
        if (!pattern || !*pattern) {
            continue;
        }
        if (fnmatch(pattern, refname, 0) == 0) {
            return true;
        }
        if (fnmatch(pattern, tail, 0) == 0) {
            return true;
        }
        if (smallclueGitRefNameMatchesPattern(refname, pattern)) {
            return true;
        }
    }
    return false;
}

static int smallclueGitCommandLsRemote(git_repository *repo, int argc, char **argv) {
    bool heads_only = false;
    bool tags_only = false;
    bool refs_only = false;
    bool show_symref = false;
    bool quiet = false;
    bool exit_code_on_no_match = false;
    bool after_double_dash = false;
    const char *repository = NULL;
    const char *patterns[64];
    int pattern_count = 0;

    for (int i = 0; i < argc; ++i) {
        const char *arg = argv[i];
        if (!arg || !*arg) {
            continue;
        }
        if (!after_double_dash && strcmp(arg, "--") == 0) {
            after_double_dash = true;
            continue;
        }
        if (!after_double_dash && arg[0] == '-') {
            if (strcmp(arg, "-h") == 0 || strcmp(arg, "--heads") == 0 || strcmp(arg, "--branches") == 0) {
                heads_only = true;
                continue;
            }
            if (strcmp(arg, "-t") == 0 || strcmp(arg, "--tags") == 0) {
                tags_only = true;
                continue;
            }
            if (strcmp(arg, "--refs") == 0) {
                refs_only = true;
                continue;
            }
            if (strcmp(arg, "--symref") == 0) {
                show_symref = true;
                continue;
            }
            if (strcmp(arg, "-q") == 0 || strcmp(arg, "--quiet") == 0) {
                quiet = true;
                continue;
            }
            if (strcmp(arg, "--exit-code") == 0) {
                exit_code_on_no_match = true;
                continue;
            }
            smallclueGitPrintError("unsupported ls-remote option");
            return 2;
        }

        if (!repository) {
            repository = arg;
            continue;
        }
        if (pattern_count >= (int)(sizeof(patterns) / sizeof(patterns[0]))) {
            smallclueGitPrintError("too many ls-remote patterns");
            return 2;
        }
        patterns[pattern_count++] = arg;
    }

    if (!repository || !*repository) {
        if (!repo) {
            smallclueGitPrintError("usage: git ls-remote [--heads] [--tags] [--refs] [--symref] [--exit-code] <repository> [patterns...]");
            return 2;
        }
        repository = "origin";
    }

    git_remote *remote = NULL;
    if (repo && git_remote_lookup(&remote, repo, repository) == 0 && remote) {
        /* configured remote */
    } else {
        char repo_buf[PATH_MAX];
        const char *resolved_repo = repository;
        if (smallclueGitResolveMaybePathFromCwd(repository, repo_buf, sizeof(repo_buf)) == 0) {
            resolved_repo = repo_buf;
        }
        int create_rc = repo
            ? git_remote_create_anonymous(&remote, repo, resolved_repo)
            : 0;
        if (!repo) {
            const char *detached_url = resolved_repo;
            char file_url[PATH_MAX + 16];
            if (smallclueGitLooksLikeFilesystemPath(resolved_repo) && !smallclueGitLooksLikeUrl(resolved_repo)) {
                if (snprintf(file_url, sizeof(file_url), "file://%s", resolved_repo) >= (int)sizeof(file_url)) {
                    smallclueGitPrintError("ls-remote repository path too long");
                    return 2;
                }
                detached_url = file_url;
            }
            create_rc = git_remote_create_detached(&remote, detached_url);
        }
        if (create_rc != 0 || !remote) {
            smallclueGitPrintLibgitError("ls-remote: remote lookup failed");
            return 1;
        }
    }

    git_remote_connect_options connect_opts = GIT_REMOTE_CONNECT_OPTIONS_INIT;
    int rc = git_remote_connect(remote, GIT_DIRECTION_FETCH, &connect_opts.callbacks, NULL, NULL);
    if (rc != 0) {
        git_remote_free(remote);
        smallclueGitPrintLibgitError("ls-remote: connect failed");
        return 1;
    }

    const git_remote_head **remote_heads = NULL;
    size_t remote_head_count = 0;
    rc = git_remote_ls(&remote_heads, &remote_head_count, remote);
    if (rc != 0) {
        git_remote_disconnect(remote);
        git_remote_free(remote);
        smallclueGitPrintLibgitError("ls-remote: listing refs failed");
        return 1;
    }

    size_t matched = 0;
    if (!quiet) {
        for (size_t i = 0; i < remote_head_count; ++i) {
            const git_remote_head *head = remote_heads[i];
            if (!head || !head->name || !head->name[0]) {
                continue;
            }

            const char *name = head->name;
            bool is_head_ref = smallclueGitStartsWith(name, "refs/heads/");
            bool is_tag_ref = smallclueGitStartsWith(name, "refs/tags/");
            bool is_ref = smallclueGitStartsWith(name, "refs/");
            if (heads_only || tags_only) {
                bool include = (heads_only && is_head_ref) || (tags_only && is_tag_ref);
                if (!include) {
                    continue;
                }
            }
            if (refs_only && !is_ref) {
                continue;
            }
            if (!smallclueGitLsRemoteRefMatches(name, pattern_count, patterns)) {
                continue;
            }

            if (show_symref && head->symref_target && head->symref_target[0]) {
                printf("ref: %s\t%s\n", head->symref_target, name);
            }

            char oid_buf[GIT_OID_HEXSZ + 1];
            if (!git_oid_tostr(oid_buf, sizeof(oid_buf), &head->oid)) {
                git_remote_disconnect(remote);
                git_remote_free(remote);
                smallclueGitPrintError("ls-remote: failed to format oid");
                return 1;
            }
            printf("%s\t%s\n", oid_buf, name);
            matched++;
        }
    } else {
        for (size_t i = 0; i < remote_head_count; ++i) {
            const git_remote_head *head = remote_heads[i];
            if (!head || !head->name || !head->name[0]) {
                continue;
            }
            const char *name = head->name;
            bool is_head_ref = smallclueGitStartsWith(name, "refs/heads/");
            bool is_tag_ref = smallclueGitStartsWith(name, "refs/tags/");
            bool is_ref = smallclueGitStartsWith(name, "refs/");
            if (heads_only || tags_only) {
                bool include = (heads_only && is_head_ref) || (tags_only && is_tag_ref);
                if (!include) {
                    continue;
                }
            }
            if (refs_only && !is_ref) {
                continue;
            }
            if (!smallclueGitLsRemoteRefMatches(name, pattern_count, patterns)) {
                continue;
            }
            matched++;
        }
    }

    git_remote_disconnect(remote);
    git_remote_free(remote);

    if (exit_code_on_no_match && matched == 0) {
        return 2;
    }
    return 0;
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

static int smallclueGitCommandMerge(git_repository *repo, int argc, char **argv) {
    bool ff_only = false;
    bool no_ff = false;
    bool quiet = false;
    const char *target_spec = NULL;

    for (int i = 0; i < argc; ++i) {
        const char *arg = argv[i];
        if (!arg) {
            continue;
        }
        if (strcmp(arg, "--ff-only") == 0) {
            ff_only = true;
            continue;
        }
        if (strcmp(arg, "--no-ff") == 0) {
            no_ff = true;
            continue;
        }
        if (strcmp(arg, "--ff") == 0) {
            no_ff = false;
            ff_only = false;
            continue;
        }
        if (strcmp(arg, "-q") == 0 || strcmp(arg, "--quiet") == 0) {
            quiet = true;
            continue;
        }
        if (arg[0] == '-') {
            smallclueGitPrintError("unsupported merge option");
            return 2;
        }
        if (!target_spec) {
            target_spec = arg;
            continue;
        }
        smallclueGitPrintError("merge currently supports exactly one target");
        return 2;
    }

    if (!target_spec || !*target_spec) {
        smallclueGitPrintError("merge requires a target revision");
        return 2;
    }
    if (ff_only && no_ff) {
        smallclueGitPrintError("merge: --ff-only and --no-ff are mutually exclusive");
        return 2;
    }
    if (git_repository_state(repo) != GIT_REPOSITORY_STATE_NONE) {
        smallclueGitPrintError("merge: repository has unfinished operation");
        return 1;
    }

    int dirty = smallclueGitHasTrackedChanges(repo);
    if (dirty < 0) {
        smallclueGitPrintLibgitError("merge: unable to inspect working tree state");
        return 1;
    }
    if (dirty > 0) {
        fputs("error: Your local changes would be overwritten by merge.\n", stderr);
        return 1;
    }

    git_reference *head_ref = NULL;
    if (git_repository_head(&head_ref, repo) != 0 || !head_ref) {
        smallclueGitPrintError("merge: detached HEAD is not supported");
        return 1;
    }
    const char *current_branch = git_reference_shorthand(head_ref);
    if (!current_branch || !*current_branch) {
        git_reference_free(head_ref);
        smallclueGitPrintError("merge: unable to determine current branch");
        return 1;
    }

    char local_ref_name[512];
    if (snprintf(local_ref_name, sizeof(local_ref_name), "refs/heads/%s", current_branch) >= (int)sizeof(local_ref_name)) {
        git_reference_free(head_ref);
        smallclueGitPrintError("merge: local ref name too long");
        return 1;
    }

    git_annotated_commit *their_head = NULL;
    if (git_annotated_commit_from_revspec(&their_head, repo, target_spec) != 0 || !their_head) {
        git_reference_free(head_ref);
        smallclueGitPrintLibgitError("merge: unable to resolve target");
        return 128;
    }

    int rc = 1;
    git_commit *local_head = NULL;
    git_commit *remote_head = NULL;
    git_tree *result_tree = NULL;
    bool used_merge_state = false;

    {
        git_object *head_obj = NULL;
        if (git_reference_peel(&head_obj, head_ref, GIT_OBJECT_COMMIT) != 0 || !head_obj) {
            smallclueGitPrintLibgitError("merge: local commit lookup failed");
            goto cleanup;
        }
        local_head = (git_commit *)head_obj;
    }

    if (git_commit_lookup(&remote_head, repo, git_annotated_commit_id(their_head)) != 0 || !remote_head) {
        smallclueGitPrintLibgitError("merge: target commit lookup failed");
        goto cleanup;
    }

    const git_annotated_commit *heads[1] = { their_head };
    git_merge_analysis_t analysis = GIT_MERGE_ANALYSIS_NONE;
    git_merge_preference_t pref = GIT_MERGE_PREFERENCE_NONE;
    if (git_merge_analysis(&analysis, &pref, repo, heads, 1) != 0) {
        smallclueGitPrintLibgitError("merge: analysis failed");
        goto cleanup;
    }
    (void)pref;

    if (analysis & GIT_MERGE_ANALYSIS_UP_TO_DATE) {
        rc = 0;
        goto cleanup;
    }

    bool can_ff = (analysis & GIT_MERGE_ANALYSIS_FASTFORWARD) != 0;
    bool can_merge = (analysis & GIT_MERGE_ANALYSIS_NORMAL) != 0;

    if (ff_only && !can_ff) {
        fputs("fatal: Not possible to fast-forward, aborting.\n", stderr);
        goto cleanup;
    }

    const git_oid *target_oid = git_commit_id(remote_head);
    if (!target_oid) {
        smallclueGitPrintError("merge: target oid is unavailable");
        goto cleanup;
    }

    if (can_ff && !no_ff) {
        git_reference *local_ref = NULL;
        if (git_reference_lookup(&local_ref, repo, local_ref_name) != 0 || !local_ref) {
            smallclueGitPrintLibgitError("merge: local branch lookup failed");
            goto cleanup;
        }
        git_reference *updated = NULL;
        if (git_reference_set_target(&updated, local_ref, target_oid, "merge: fast-forward") != 0 || !updated) {
            git_reference_free(local_ref);
            smallclueGitPrintLibgitError("merge: fast-forward update failed");
            goto cleanup;
        }
        git_reference_free(local_ref);
        git_reference_free(updated);
        if (git_repository_set_head(repo, local_ref_name) != 0) {
            smallclueGitPrintLibgitError("merge: set HEAD failed");
            goto cleanup;
        }
        git_object *target_obj = NULL;
        if (git_revparse_single(&target_obj, repo, "HEAD") != 0 || !target_obj) {
            smallclueGitPrintLibgitError("merge: fast-forward target lookup failed");
            goto cleanup;
        }
        if (git_reset(repo, target_obj, GIT_RESET_HARD, NULL) != 0) {
            git_object_free(target_obj);
            smallclueGitPrintLibgitError("merge: fast-forward worktree update failed");
            goto cleanup;
        }
        git_object_free(target_obj);
        rc = 0;
        goto cleanup;
    }

    if (!can_merge && !(can_ff && no_ff)) {
        smallclueGitPrintError("merge: merge analysis does not allow integration");
        goto cleanup;
    }

    if (can_ff && no_ff) {
        if (git_commit_tree(&result_tree, remote_head) != 0 || !result_tree) {
            smallclueGitPrintLibgitError("merge: target tree lookup failed");
            goto cleanup;
        }
    } else {
        git_merge_options merge_opts = GIT_MERGE_OPTIONS_INIT;
        git_checkout_options merge_checkout_opts = GIT_CHECKOUT_OPTIONS_INIT;
        merge_checkout_opts.checkout_strategy = GIT_CHECKOUT_SAFE | GIT_CHECKOUT_RECREATE_MISSING;
        if (git_merge(repo, heads, 1, &merge_opts, &merge_checkout_opts) != 0) {
            smallclueGitPrintLibgitError("merge failed");
            goto cleanup;
        }
        used_merge_state = true;

        git_index *index = NULL;
        if (git_repository_index(&index, repo) != 0 || !index) {
            smallclueGitPrintLibgitError("merge: index lookup failed");
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
            smallclueGitPrintLibgitError("merge: tree write failed");
            goto cleanup;
        }
        git_index_free(index);

        if (git_tree_lookup(&result_tree, repo, &tree_oid) != 0 || !result_tree) {
            smallclueGitPrintLibgitError("merge: tree lookup failed");
            goto cleanup;
        }
    }

    git_signature *author = NULL;
    git_signature *committer = NULL;
    if (smallclueGitCreateDefaultSignatures(repo, &author, &committer) != 0) {
        smallclueGitPrintLibgitError("merge: signature creation failed");
        goto cleanup;
    }

    char merge_message[768];
    if (snprintf(merge_message, sizeof(merge_message), "Merge %s", target_spec) >= (int)sizeof(merge_message)) {
        git_signature_free(author);
        git_signature_free(committer);
        smallclueGitPrintError("merge: message too long");
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
        smallclueGitPrintLibgitError("merge commit failed");
        goto cleanup;
    }
    git_signature_free(author);
    git_signature_free(committer);

    if (used_merge_state && git_repository_state_cleanup(repo) != 0) {
        smallclueGitPrintLibgitError("merge: state cleanup failed");
        goto cleanup;
    }
    used_merge_state = false;

    {
        git_object *new_head = NULL;
        if (git_revparse_single(&new_head, repo, "HEAD") != 0 || !new_head) {
            smallclueGitPrintLibgitError("merge: post-merge HEAD lookup failed");
            goto cleanup;
        }
        if (git_reset(repo, new_head, GIT_RESET_HARD, NULL) != 0) {
            git_object_free(new_head);
            smallclueGitPrintLibgitError("merge: post-merge worktree update failed");
            goto cleanup;
        }
        git_object_free(new_head);
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
    git_reference_free(head_ref);
    git_annotated_commit_free(their_head);
    return rc;
}

static int smallclueGitCommandCherryPick(git_repository *repo, int argc, char **argv) {
    bool quiet = false;
    bool no_commit = false;
    bool add_trailer = false;
    bool abort_op = false;
    int mainline = 0;
    const char *target_spec = NULL;

    for (int i = 0; i < argc; ++i) {
        const char *arg = argv[i];
        if (!arg) {
            continue;
        }
        if (strcmp(arg, "--abort") == 0) {
            abort_op = true;
            continue;
        }
        if (strcmp(arg, "-q") == 0 || strcmp(arg, "--quiet") == 0) {
            quiet = true;
            continue;
        }
        if (strcmp(arg, "-n") == 0 || strcmp(arg, "--no-commit") == 0) {
            no_commit = true;
            continue;
        }
        if (strcmp(arg, "-x") == 0) {
            add_trailer = true;
            continue;
        }
        if ((strcmp(arg, "-m") == 0 || strcmp(arg, "--mainline") == 0) && i + 1 < argc) {
            char *end = NULL;
            long v = strtol(argv[++i], &end, 10);
            if (!end || *end != '\0' || v <= 0) {
                smallclueGitPrintError("invalid value for cherry-pick --mainline");
                return 2;
            }
            mainline = (int)v;
            continue;
        }
        if (arg[0] == '-') {
            smallclueGitPrintError("unsupported cherry-pick option");
            return 2;
        }
        if (!target_spec) {
            target_spec = arg;
            continue;
        }
        smallclueGitPrintError("cherry-pick currently supports exactly one commit");
        return 2;
    }

    if (abort_op) {
        git_repository_state_t st = git_repository_state(repo);
        if (st != GIT_REPOSITORY_STATE_CHERRYPICK &&
            st != GIT_REPOSITORY_STATE_CHERRYPICK_SEQUENCE) {
            smallclueGitPrintError("cherry-pick --abort: no cherry-pick in progress");
            return 1;
        }
        if (git_repository_state_cleanup(repo) != 0) {
            smallclueGitPrintLibgitError("cherry-pick --abort failed");
            return 1;
        }
        if (smallclueGitHardResetToHead(repo, "cherry-pick --abort reset failed") != 0) {
            return 1;
        }
        return 0;
    }

    if (!target_spec || !*target_spec) {
        smallclueGitPrintError("cherry-pick requires a target commit");
        return 2;
    }
    if (git_repository_state(repo) != GIT_REPOSITORY_STATE_NONE) {
        smallclueGitPrintError("cherry-pick: repository has unfinished operation");
        return 1;
    }

    int dirty = smallclueGitHasTrackedChanges(repo);
    if (dirty < 0) {
        smallclueGitPrintLibgitError("cherry-pick: unable to inspect working tree state");
        return 1;
    }
    if (dirty > 0) {
        fputs("error: Your local changes would be overwritten by cherry-pick.\n", stderr);
        return 1;
    }

    git_commit *picked = NULL;
    if (smallclueGitResolveCommit(repo, target_spec, &picked) != 0 || !picked) {
        smallclueGitPrintLibgitError("cherry-pick: unable to resolve commit");
        return 128;
    }

    git_cherrypick_options opts = GIT_CHERRYPICK_OPTIONS_INIT;
    opts.mainline = mainline;
    opts.checkout_opts.checkout_strategy = GIT_CHECKOUT_SAFE | GIT_CHECKOUT_RECREATE_MISSING;

    if (git_cherrypick(repo, picked, &opts) != 0) {
        git_commit_free(picked);
        smallclueGitPrintLibgitError("cherry-pick failed");
        return 1;
    }

    git_index *index = NULL;
    if (git_repository_index(&index, repo) != 0 || !index) {
        git_commit_free(picked);
        smallclueGitPrintLibgitError("cherry-pick: index lookup failed");
        return 1;
    }
    if (git_index_has_conflicts(index)) {
        git_index_free(index);
        git_commit_free(picked);
        fputs("error: could not apply commit due to conflicts.\n", stderr);
        return 1;
    }

    if (no_commit) {
        if (git_index_write(index) != 0) {
            git_index_free(index);
            git_commit_free(picked);
            smallclueGitPrintLibgitError("cherry-pick: index write failed");
            return 1;
        }
        git_index_free(index);
        if (git_repository_state_cleanup(repo) != 0) {
            git_commit_free(picked);
            smallclueGitPrintLibgitError("cherry-pick: state cleanup failed");
            return 1;
        }
        git_commit_free(picked);
        return 0;
    }

    git_oid tree_oid;
    if (git_index_write_tree_to(&tree_oid, index, repo) != 0 || git_index_write(index) != 0) {
        git_index_free(index);
        git_commit_free(picked);
        smallclueGitPrintLibgitError("cherry-pick: tree write failed");
        return 1;
    }
    git_index_free(index);

    git_tree *tree = NULL;
    if (git_tree_lookup(&tree, repo, &tree_oid) != 0 || !tree) {
        git_commit_free(picked);
        smallclueGitPrintLibgitError("cherry-pick: tree lookup failed");
        return 1;
    }

    git_reference *head_ref = NULL;
    git_commit *head_commit = NULL;
    if (git_repository_head(&head_ref, repo) != 0 || !head_ref) {
        git_tree_free(tree);
        git_commit_free(picked);
        smallclueGitPrintError("cherry-pick: detached HEAD is not supported");
        return 1;
    }
    {
        git_object *head_obj = NULL;
        if (git_reference_peel(&head_obj, head_ref, GIT_OBJECT_COMMIT) != 0 || !head_obj) {
            git_reference_free(head_ref);
            git_tree_free(tree);
            git_commit_free(picked);
            smallclueGitPrintLibgitError("cherry-pick: HEAD commit lookup failed");
            return 1;
        }
        head_commit = (git_commit *)head_obj;
    }

    const char *base_message = git_commit_message(picked);
    if (!base_message || !*base_message) {
        base_message = "cherry-pick";
    }

    char *final_message = NULL;
    if (add_trailer) {
        char oid_buf[GIT_OID_HEXSZ + 1];
        if (!git_oid_tostr(oid_buf, sizeof(oid_buf), git_commit_id(picked))) {
            git_commit_free(head_commit);
            git_reference_free(head_ref);
            git_tree_free(tree);
            git_commit_free(picked);
            smallclueGitPrintError("cherry-pick: failed to format commit id");
            return 1;
        }
        size_t need = strlen(base_message) + strlen("\n(cherry picked from commit )\n") + strlen(oid_buf) + 1;
        final_message = (char *)malloc(need);
        if (!final_message) {
            git_commit_free(head_commit);
            git_reference_free(head_ref);
            git_tree_free(tree);
            git_commit_free(picked);
            smallclueGitPrintError("out of memory");
            return 1;
        }
        snprintf(final_message, need, "%s\n(cherry picked from commit %s)\n", base_message, oid_buf);
    } else {
        final_message = strdup(base_message);
        if (!final_message) {
            git_commit_free(head_commit);
            git_reference_free(head_ref);
            git_tree_free(tree);
            git_commit_free(picked);
            smallclueGitPrintError("out of memory");
            return 1;
        }
    }

    git_signature *author = NULL;
    git_signature *committer = NULL;
    if (smallclueGitCreateDefaultSignatures(repo, &author, &committer) != 0) {
        free(final_message);
        git_commit_free(head_commit);
        git_reference_free(head_ref);
        git_tree_free(tree);
        git_commit_free(picked);
        smallclueGitPrintLibgitError("cherry-pick: signature creation failed");
        return 1;
    }

    const git_commit *parents[1];
    parents[0] = head_commit;
    git_oid new_oid;
    if (git_commit_create(&new_oid,
                          repo,
                          "HEAD",
                          author,
                          committer,
                          NULL,
                          final_message,
                          tree,
                          1,
                          parents) != 0) {
        git_signature_free(author);
        git_signature_free(committer);
        free(final_message);
        git_commit_free(head_commit);
        git_reference_free(head_ref);
        git_tree_free(tree);
        git_commit_free(picked);
        smallclueGitPrintLibgitError("cherry-pick commit failed");
        return 1;
    }

    git_signature_free(author);
    git_signature_free(committer);
    free(final_message);
    git_commit_free(head_commit);
    git_reference_free(head_ref);
    git_tree_free(tree);
    git_commit_free(picked);

    if (git_repository_state_cleanup(repo) != 0) {
        smallclueGitPrintLibgitError("cherry-pick: state cleanup failed");
        return 1;
    }
    if (smallclueGitHardResetToHead(repo, "cherry-pick: post-commit reset failed") != 0) {
        return 1;
    }
    (void)quiet;
    return 0;
}

static int smallclueGitCommandRevert(git_repository *repo, int argc, char **argv) {
    bool quiet = false;
    bool no_commit = false;
    bool abort_op = false;
    int mainline = 0;
    const char *target_spec = NULL;

    for (int i = 0; i < argc; ++i) {
        const char *arg = argv[i];
        if (!arg) {
            continue;
        }
        if (strcmp(arg, "--abort") == 0) {
            abort_op = true;
            continue;
        }
        if (strcmp(arg, "-q") == 0 || strcmp(arg, "--quiet") == 0) {
            quiet = true;
            continue;
        }
        if (strcmp(arg, "-n") == 0 || strcmp(arg, "--no-commit") == 0) {
            no_commit = true;
            continue;
        }
        if ((strcmp(arg, "-m") == 0 || strcmp(arg, "--mainline") == 0) && i + 1 < argc) {
            char *end = NULL;
            long v = strtol(argv[++i], &end, 10);
            if (!end || *end != '\0' || v <= 0) {
                smallclueGitPrintError("invalid value for revert --mainline");
                return 2;
            }
            mainline = (int)v;
            continue;
        }
        if (arg[0] == '-') {
            smallclueGitPrintError("unsupported revert option");
            return 2;
        }
        if (!target_spec) {
            target_spec = arg;
            continue;
        }
        smallclueGitPrintError("revert currently supports exactly one commit");
        return 2;
    }

    if (abort_op) {
        git_repository_state_t st = git_repository_state(repo);
        if (st != GIT_REPOSITORY_STATE_REVERT &&
            st != GIT_REPOSITORY_STATE_REVERT_SEQUENCE) {
            smallclueGitPrintError("revert --abort: no revert in progress");
            return 1;
        }
        if (git_repository_state_cleanup(repo) != 0) {
            smallclueGitPrintLibgitError("revert --abort failed");
            return 1;
        }
        if (smallclueGitHardResetToHead(repo, "revert --abort reset failed") != 0) {
            return 1;
        }
        return 0;
    }

    if (!target_spec || !*target_spec) {
        smallclueGitPrintError("revert requires a target commit");
        return 2;
    }
    if (git_repository_state(repo) != GIT_REPOSITORY_STATE_NONE) {
        smallclueGitPrintError("revert: repository has unfinished operation");
        return 1;
    }

    int dirty = smallclueGitHasTrackedChanges(repo);
    if (dirty < 0) {
        smallclueGitPrintLibgitError("revert: unable to inspect working tree state");
        return 1;
    }
    if (dirty > 0) {
        fputs("error: Your local changes would be overwritten by revert.\n", stderr);
        return 1;
    }

    git_commit *reverted = NULL;
    if (smallclueGitResolveCommit(repo, target_spec, &reverted) != 0 || !reverted) {
        smallclueGitPrintLibgitError("revert: unable to resolve commit");
        return 128;
    }

    git_revert_options opts = GIT_REVERT_OPTIONS_INIT;
    opts.mainline = mainline;
    opts.checkout_opts.checkout_strategy = GIT_CHECKOUT_SAFE | GIT_CHECKOUT_RECREATE_MISSING;

    if (git_revert(repo, reverted, &opts) != 0) {
        git_commit_free(reverted);
        smallclueGitPrintLibgitError("revert failed");
        return 1;
    }

    git_index *index = NULL;
    if (git_repository_index(&index, repo) != 0 || !index) {
        git_commit_free(reverted);
        smallclueGitPrintLibgitError("revert: index lookup failed");
        return 1;
    }
    if (git_index_has_conflicts(index)) {
        git_index_free(index);
        git_commit_free(reverted);
        fputs("error: Revert resulted in conflicts.\n", stderr);
        return 1;
    }

    if (no_commit) {
        if (git_index_write(index) != 0) {
            git_index_free(index);
            git_commit_free(reverted);
            smallclueGitPrintLibgitError("revert: index write failed");
            return 1;
        }
        git_index_free(index);
        if (git_repository_state_cleanup(repo) != 0) {
            git_commit_free(reverted);
            smallclueGitPrintLibgitError("revert: state cleanup failed");
            return 1;
        }
        git_commit_free(reverted);
        return 0;
    }

    git_oid tree_oid;
    if (git_index_write_tree_to(&tree_oid, index, repo) != 0 || git_index_write(index) != 0) {
        git_index_free(index);
        git_commit_free(reverted);
        smallclueGitPrintLibgitError("revert: tree write failed");
        return 1;
    }
    git_index_free(index);

    git_tree *tree = NULL;
    if (git_tree_lookup(&tree, repo, &tree_oid) != 0 || !tree) {
        git_commit_free(reverted);
        smallclueGitPrintLibgitError("revert: tree lookup failed");
        return 1;
    }

    git_reference *head_ref = NULL;
    git_commit *head_commit = NULL;
    if (git_repository_head(&head_ref, repo) != 0 || !head_ref) {
        git_tree_free(tree);
        git_commit_free(reverted);
        smallclueGitPrintError("revert: detached HEAD is not supported");
        return 1;
    }
    {
        git_object *head_obj = NULL;
        if (git_reference_peel(&head_obj, head_ref, GIT_OBJECT_COMMIT) != 0 || !head_obj) {
            git_reference_free(head_ref);
            git_tree_free(tree);
            git_commit_free(reverted);
            smallclueGitPrintLibgitError("revert: HEAD commit lookup failed");
            return 1;
        }
        head_commit = (git_commit *)head_obj;
    }

    char reverted_oid[GIT_OID_HEXSZ + 1];
    if (!git_oid_tostr(reverted_oid, sizeof(reverted_oid), git_commit_id(reverted))) {
        git_commit_free(head_commit);
        git_reference_free(head_ref);
        git_tree_free(tree);
        git_commit_free(reverted);
        smallclueGitPrintError("revert: failed to format commit id");
        return 1;
    }
    char subject[256];
    smallclueGitCopySubjectLine(smallclueGitCommitSubject(reverted), subject, sizeof(subject));
    char message[1024];
    if (snprintf(message,
                 sizeof(message),
                 "Revert \"%s\"\n\nThis reverts commit %s.\n",
                 subject,
                 reverted_oid) >= (int)sizeof(message)) {
        git_commit_free(head_commit);
        git_reference_free(head_ref);
        git_tree_free(tree);
        git_commit_free(reverted);
        smallclueGitPrintError("revert: message too long");
        return 1;
    }

    git_signature *author = NULL;
    git_signature *committer = NULL;
    if (smallclueGitCreateDefaultSignatures(repo, &author, &committer) != 0) {
        git_commit_free(head_commit);
        git_reference_free(head_ref);
        git_tree_free(tree);
        git_commit_free(reverted);
        smallclueGitPrintLibgitError("revert: signature creation failed");
        return 1;
    }

    const git_commit *parents[1];
    parents[0] = head_commit;
    git_oid new_oid;
    if (git_commit_create(&new_oid,
                          repo,
                          "HEAD",
                          author,
                          committer,
                          NULL,
                          message,
                          tree,
                          1,
                          parents) != 0) {
        git_signature_free(author);
        git_signature_free(committer);
        git_commit_free(head_commit);
        git_reference_free(head_ref);
        git_tree_free(tree);
        git_commit_free(reverted);
        smallclueGitPrintLibgitError("revert commit failed");
        return 1;
    }

    git_signature_free(author);
    git_signature_free(committer);
    git_commit_free(head_commit);
    git_reference_free(head_ref);
    git_tree_free(tree);
    git_commit_free(reverted);

    if (git_repository_state_cleanup(repo) != 0) {
        smallclueGitPrintLibgitError("revert: state cleanup failed");
        return 1;
    }
    if (smallclueGitHardResetToHead(repo, "revert: post-commit reset failed") != 0) {
        return 1;
    }
    (void)quiet;
    return 0;
}

typedef enum SmallclueGitRebaseCommitResult {
    SMALLCLUE_GIT_REBASE_COMMIT_OK = 0,
    SMALLCLUE_GIT_REBASE_COMMIT_APPLIED = 1,
    SMALLCLUE_GIT_REBASE_COMMIT_UNMERGED = 2,
    SMALLCLUE_GIT_REBASE_COMMIT_ERROR = -1,
} SmallclueGitRebaseCommitResult;

static SmallclueGitRebaseCommitResult smallclueGitRebaseCommitCurrent(git_repository *repo,
                                                                      git_rebase *rebase,
                                                                      const git_signature *committer,
                                                                      bool quiet) {
    if (!repo || !rebase || !committer) {
        return SMALLCLUE_GIT_REBASE_COMMIT_ERROR;
    }

    const size_t current = git_rebase_operation_current(rebase);
    if (current == GIT_REBASE_NO_OPERATION) {
        return SMALLCLUE_GIT_REBASE_COMMIT_OK;
    }

    git_rebase_operation *operation = git_rebase_operation_byindex(rebase, current);
    if (!operation) {
        smallclueGitPrintError("rebase: invalid current operation");
        return SMALLCLUE_GIT_REBASE_COMMIT_ERROR;
    }

    git_commit *orig_commit = NULL;
    const git_signature *author = NULL;
    if (git_commit_lookup(&orig_commit, repo, &operation->id) == 0 && orig_commit) {
        author = git_commit_author(orig_commit);
    }

    git_oid new_oid;
    int rc = git_rebase_commit(&new_oid, rebase, author, committer, NULL, NULL);
    git_commit_free(orig_commit);

    if (rc == GIT_EAPPLIED) {
        return SMALLCLUE_GIT_REBASE_COMMIT_APPLIED;
    }
    if (rc == GIT_EUNMERGED) {
        return SMALLCLUE_GIT_REBASE_COMMIT_UNMERGED;
    }
    if (rc != 0) {
        smallclueGitPrintLibgitError("rebase commit failed");
        return SMALLCLUE_GIT_REBASE_COMMIT_ERROR;
    }

    (void)quiet;
    (void)new_oid;
    return SMALLCLUE_GIT_REBASE_COMMIT_OK;
}

static int smallclueGitRebaseIndexHasConflicts(git_repository *repo, bool *out_has_conflicts) {
    if (!repo || !out_has_conflicts) {
        return -1;
    }
    *out_has_conflicts = false;
    git_index *index = NULL;
    if (git_repository_index(&index, repo) != 0 || !index) {
        return -1;
    }
    *out_has_conflicts = git_index_has_conflicts(index);
    git_index_free(index);
    return 0;
}

static int smallclueGitRebaseRun(git_repository *repo, git_rebase *rebase, bool continue_mode, bool quiet) {
    if (!repo || !rebase) {
        return -1;
    }

    git_signature *author = NULL;
    git_signature *committer = NULL;
    if (smallclueGitCreateDefaultSignatures(repo, &author, &committer) != 0) {
        smallclueGitPrintLibgitError("rebase: signature creation failed");
        return 1;
    }
    git_signature_free(author);

    if (continue_mode) {
        bool conflicts = false;
        if (smallclueGitRebaseIndexHasConflicts(repo, &conflicts) != 0) {
            git_signature_free(committer);
            smallclueGitPrintLibgitError("rebase --continue: index lookup failed");
            return 1;
        }
        if (conflicts) {
            git_signature_free(committer);
            fputs("error: cannot continue rebase with unresolved conflicts.\n", stderr);
            return 1;
        }
        SmallclueGitRebaseCommitResult c = smallclueGitRebaseCommitCurrent(repo, rebase, committer, quiet);
        if (c == SMALLCLUE_GIT_REBASE_COMMIT_UNMERGED) {
            git_signature_free(committer);
            fputs("error: cannot continue rebase with unresolved conflicts.\n", stderr);
            return 1;
        }
        if (c == SMALLCLUE_GIT_REBASE_COMMIT_ERROR) {
            git_signature_free(committer);
            return 1;
        }
    }

    const size_t total_ops = git_rebase_operation_entrycount(rebase);
    for (;;) {
        git_rebase_operation *operation = NULL;
        int next_rc = git_rebase_next(&operation, rebase);
        if (next_rc == GIT_ITEROVER) {
            break;
        }
        if (next_rc != 0) {
            bool conflicts = false;
            if (smallclueGitRebaseIndexHasConflicts(repo, &conflicts) == 0 && conflicts) {
                git_signature_free(committer);
                fputs("error: rebase stopped due to conflicts; resolve them and run 'git rebase --continue'.\n", stderr);
                return 1;
            }
            git_signature_free(committer);
            smallclueGitPrintLibgitError("rebase: next failed");
            return 1;
        }
        (void)operation;
        if (!quiet && total_ops > 0) {
            const size_t current = git_rebase_operation_current(rebase);
            if (current != GIT_REBASE_NO_OPERATION) {
                fprintf(stderr, "Rebasing (%zu/%zu)\n", current + 1, total_ops);
            }
        }

        SmallclueGitRebaseCommitResult c = smallclueGitRebaseCommitCurrent(repo, rebase, committer, quiet);
        if (c == SMALLCLUE_GIT_REBASE_COMMIT_UNMERGED) {
            git_signature_free(committer);
            fputs("error: rebase stopped due to conflicts; resolve them and run 'git rebase --continue'.\n", stderr);
            return 1;
        }
        if (c == SMALLCLUE_GIT_REBASE_COMMIT_ERROR) {
            git_signature_free(committer);
            return 1;
        }
    }

    if (git_rebase_finish(rebase, committer) != 0) {
        git_signature_free(committer);
        smallclueGitPrintLibgitError("rebase finish failed");
        return 1;
    }
    if (!quiet) {
        const char *head_name = git_rebase_orig_head_name(rebase);
        char head_buf[512];
        if (!head_name || !*head_name) {
            git_reference *head_ref = NULL;
            if (git_repository_head(&head_ref, repo) == 0 && head_ref) {
                const char *name = git_reference_name(head_ref);
                if (name && *name &&
                    snprintf(head_buf, sizeof(head_buf), "%s", name) < (int)sizeof(head_buf)) {
                    head_name = head_buf;
                }
                git_reference_free(head_ref);
            }
        }
        if (!head_name || !*head_name) {
            head_name = "HEAD";
        }
        fprintf(stderr, "Successfully rebased and updated %s.\n", head_name);
    }
    git_signature_free(committer);

    if (smallclueGitHardResetToHead(repo, "rebase: post-finish reset failed") != 0) {
        return 1;
    }
    return 0;
}

static int smallclueGitCommandRebase(git_repository *repo, int argc, char **argv) {
    bool quiet = false;
    bool abort_op = false;
    bool continue_op = false;
    const char *upstream_spec = NULL;

    for (int i = 0; i < argc; ++i) {
        const char *arg = argv[i];
        if (!arg) {
            continue;
        }
        if (strcmp(arg, "-q") == 0 || strcmp(arg, "--quiet") == 0) {
            quiet = true;
            continue;
        }
        if (strcmp(arg, "--abort") == 0) {
            abort_op = true;
            continue;
        }
        if (strcmp(arg, "--continue") == 0) {
            continue_op = true;
            continue;
        }
        if (arg[0] == '-') {
            smallclueGitPrintError("unsupported rebase option");
            return 2;
        }
        if (!upstream_spec) {
            upstream_spec = arg;
            continue;
        }
        smallclueGitPrintError("rebase currently supports a single upstream argument");
        return 2;
    }

    if (abort_op && continue_op) {
        smallclueGitPrintError("rebase: --abort and --continue are mutually exclusive");
        return 2;
    }

    if (abort_op) {
        if (upstream_spec) {
            smallclueGitPrintError("rebase --abort does not accept an upstream");
            return 2;
        }
        git_rebase *rebase = NULL;
        git_rebase_options opts = GIT_REBASE_OPTIONS_INIT;
        if (git_rebase_open(&rebase, repo, &opts) != 0 || !rebase) {
            smallclueGitPrintError("rebase --abort: no rebase in progress");
            return 1;
        }
        int rc = git_rebase_abort(rebase);
        git_rebase_free(rebase);
        if (rc != 0) {
            smallclueGitPrintLibgitError("rebase --abort failed");
            return 1;
        }
        return 0;
    }

    if (continue_op) {
        if (upstream_spec) {
            smallclueGitPrintError("rebase --continue does not accept an upstream");
            return 2;
        }
        git_rebase *rebase = NULL;
        git_rebase_options opts = GIT_REBASE_OPTIONS_INIT;
        opts.checkout_options.checkout_strategy = GIT_CHECKOUT_SAFE | GIT_CHECKOUT_RECREATE_MISSING;
        if (git_rebase_open(&rebase, repo, &opts) != 0 || !rebase) {
            smallclueGitPrintError("rebase --continue: no rebase in progress");
            return 1;
        }
        int rc = smallclueGitRebaseRun(repo, rebase, true, quiet);
        git_rebase_free(rebase);
        return rc;
    }

    if (!upstream_spec || !*upstream_spec) {
        smallclueGitPrintError("rebase requires an upstream");
        return 2;
    }
    if (git_repository_state(repo) != GIT_REPOSITORY_STATE_NONE) {
        smallclueGitPrintError("rebase: repository has unfinished operation");
        return 1;
    }

    int dirty = smallclueGitHasTrackedChanges(repo);
    if (dirty < 0) {
        smallclueGitPrintLibgitError("rebase: unable to inspect working tree state");
        return 1;
    }
    if (dirty > 0) {
        fputs("error: cannot rebase with local changes.\n", stderr);
        return 1;
    }

    git_reference *head_ref = NULL;
    if (git_repository_head(&head_ref, repo) != 0 || !head_ref) {
        smallclueGitPrintError("rebase: detached HEAD is not supported");
        return 1;
    }
    git_reference_free(head_ref);

    git_annotated_commit *upstream = NULL;
    if (git_annotated_commit_from_revspec(&upstream, repo, upstream_spec) != 0 || !upstream) {
        smallclueGitPrintLibgitError("rebase: unable to resolve upstream");
        return 128;
    }

    git_rebase *rebase = NULL;
    git_rebase_options opts = GIT_REBASE_OPTIONS_INIT;
    opts.checkout_options.checkout_strategy = GIT_CHECKOUT_SAFE | GIT_CHECKOUT_RECREATE_MISSING;
    if (git_rebase_init(&rebase, repo, NULL, upstream, NULL, &opts) != 0 || !rebase) {
        git_annotated_commit_free(upstream);
        smallclueGitPrintLibgitError("rebase init failed");
        return 1;
    }
    git_annotated_commit_free(upstream);

    int rc = smallclueGitRebaseRun(repo, rebase, false, quiet);
    git_rebase_free(rebase);
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
    if (strcmp(subcmd, "rm") == 0) {
        return smallclueGitCommandRm(repo, subargc, subargv);
    }
    if (strcmp(subcmd, "mv") == 0) {
        return smallclueGitCommandMv(repo, subargc, subargv);
    }
    if (strcmp(subcmd, "clean") == 0) {
        return smallclueGitCommandClean(repo, subargc, subargv);
    }
    if (strcmp(subcmd, "stash") == 0) {
        return smallclueGitCommandStash(repo, subargc, subargv);
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
    if (strcmp(subcmd, "ls-remote") == 0) {
        return smallclueGitCommandLsRemote(repo, subargc, subargv);
    }
    if (strcmp(subcmd, "fetch") == 0) {
        return smallclueGitCommandFetch(repo, subargc, subargv);
    }
    if (strcmp(subcmd, "pull") == 0) {
        return smallclueGitCommandPull(repo, subargc, subargv);
    }
    if (strcmp(subcmd, "merge") == 0) {
        return smallclueGitCommandMerge(repo, subargc, subargv);
    }
    if (strcmp(subcmd, "cherry") == 0) {
        return smallclueGitCommandCherry(repo, subargc, subargv);
    }
    if (strcmp(subcmd, "cherry-pick") == 0) {
        return smallclueGitCommandCherryPick(repo, subargc, subargv);
    }
    if (strcmp(subcmd, "revert") == 0) {
        return smallclueGitCommandRevert(repo, subargc, subargv);
    }
    if (strcmp(subcmd, "rebase") == 0) {
        return smallclueGitCommandRebase(repo, subargc, subargv);
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
    if (strcmp(subcmd, "ls-tree") == 0) {
        return smallclueGitCommandLsTree(repo, subargc, subargv);
    }
    if (strcmp(subcmd, "cat-file") == 0) {
        return smallclueGitCommandCatFile(repo, subargc, subargv);
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
    if (strcmp(subcmd, "reflog") == 0) {
        return smallclueGitCommandReflog(repo, subargc, subargv);
    }
    if (strcmp(subcmd, "merge-base") == 0) {
        return smallclueGitCommandMergeBase(repo, subargc, subargv);
    }
    if (strcmp(subcmd, "blame") == 0) {
        return smallclueGitCommandBlame(repo, subargc, subargv);
    }
    if (strcmp(subcmd, "describe") == 0) {
        return smallclueGitCommandDescribe(repo, subargc, subargv);
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
        if (strcmp(subcmd, "ls-remote") == 0) {
            rc = smallclueGitCommandLsRemote(NULL, argc - (subcmd_index + 1), &argv[subcmd_index + 1]);
            goto done;
        }
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
