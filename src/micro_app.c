#include "micro_app.h"

#include "nextvi_app.h"

#include <errno.h>
#include <limits.h>
#include <spawn.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

extern char **environ;

static atomic_bool s_micro_warned_compat = ATOMIC_VAR_INIT(false);

static bool smallclueMicroCompatEnabled(void) {
    const char *value = getenv("PSCALI_MICRO_COMPAT_NEXTVI");
    if (!value || value[0] == '\0') {
        return false;
    }
    if (strcmp(value, "0") == 0 || strcasecmp(value, "off") == 0 || strcasecmp(value, "false") == 0) {
        return false;
    }
    return true;
}

static void smallclueWarnMicroCompat(void) {
    bool expected = false;
    if (atomic_compare_exchange_strong(&s_micro_warned_compat, &expected, true)) {
        fprintf(stderr, "micro: using nextvi compatibility mode (PSCALI_MICRO_COMPAT_NEXTVI=1)\n");
    }
}

static bool smallclueMicroIsExshSymlink(const char *path) {
    if (!path || path[0] == '\0') {
        return false;
    }
    struct stat st;
    if (lstat(path, &st) != 0 || !S_ISLNK(st.st_mode)) {
        return false;
    }
    char target[PATH_MAX];
    ssize_t nread = readlink(path, target, sizeof(target) - 1);
    if (nread <= 0) {
        return false;
    }
    target[nread] = '\0';
    return strcmp(target, "/bin/exsh") == 0 || strcmp(target, "exsh") == 0;
}

static bool smallclueMicroIsExecutableFile(const char *path) {
    if (!path || path[0] == '\0') {
        return false;
    }
    if (smallclueMicroIsExshSymlink(path)) {
        return false;
    }
    struct stat st;
    if (stat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
        return false;
    }
    return access(path, X_OK) == 0;
}

static bool smallclueMicroSetCandidate(char *out_path, size_t out_sz, const char *candidate) {
    if (!out_path || out_sz == 0 || !candidate || candidate[0] == '\0') {
        return false;
    }
    if (!smallclueMicroIsExecutableFile(candidate)) {
        return false;
    }
    int written = snprintf(out_path, out_sz, "%s", candidate);
    return written > 0 && (size_t)written < out_sz;
}

static bool smallclueMicroBuildCandidate(char *out_path,
                                         size_t out_sz,
                                         const char *prefix,
                                         const char *leaf) {
    if (!out_path || out_sz == 0 || !prefix || prefix[0] == '\0' || !leaf || leaf[0] == '\0') {
        return false;
    }
    char candidate[PATH_MAX];
    int written = snprintf(candidate, sizeof(candidate), "%s/%s", prefix, leaf);
    if (written <= 0 || (size_t)written >= sizeof(candidate)) {
        return false;
    }
    return smallclueMicroSetCandidate(out_path, out_sz, candidate);
}

static bool smallclueLocateMicroExecutable(char *out_path, size_t out_sz) {
    if (!out_path || out_sz == 0) {
        return false;
    }
    out_path[0] = '\0';

    const char *env_path = getenv("PSCALI_MICRO_PATH");
    if (smallclueMicroSetCandidate(out_path, out_sz, env_path)) {
        return true;
    }

    const char *workspace = getenv("PSCALI_WORKSPACE_ROOT");
    if (smallclueMicroBuildCandidate(out_path, out_sz, workspace, "bin/micro.bin") ||
        smallclueMicroBuildCandidate(out_path, out_sz, workspace, "bin/micro")) {
        return true;
    }

    const char *container_root = getenv("PSCALI_CONTAINER_ROOT");
    if (smallclueMicroBuildCandidate(out_path, out_sz, container_root, "Documents/bin/micro.bin") ||
        smallclueMicroBuildCandidate(out_path, out_sz, container_root, "Documents/bin/micro") ||
        smallclueMicroBuildCandidate(out_path, out_sz, container_root, "Documents/micro")) {
        return true;
    }

    const char *home = getenv("HOME");
    if (smallclueMicroBuildCandidate(out_path, out_sz, home, "../micro") ||
        smallclueMicroBuildCandidate(out_path, out_sz, home, "../bin/micro.bin") ||
        smallclueMicroBuildCandidate(out_path, out_sz, home, "../bin/micro")) {
        return true;
    }

    if (smallclueMicroSetCandidate(out_path, out_sz, "/bin/micro.bin")) {
        return true;
    }
    if (smallclueMicroSetCandidate(out_path, out_sz, "/bin/micro")) {
        return true;
    }
    return false;
}

static int smallclueRunMicroExecutable(const char *exe_path, int argc, char **argv) {
    if (!exe_path || exe_path[0] == '\0') {
        return -1;
    }
    size_t child_argc = (argc > 0 && argv) ? (size_t)argc : 1u;
    char **child_argv = (char **)calloc(child_argc + 1u, sizeof(char *));
    if (!child_argv) {
        perror("micro");
        return 127;
    }
    if (argc > 0 && argv) {
        for (size_t i = 0; i < child_argc; ++i) {
            child_argv[i] = argv[i];
        }
    } else {
        child_argv[0] = "micro";
    }
    child_argv[child_argc] = NULL;

    pid_t pid = 0;
    int spawn_rc = posix_spawn(&pid, exe_path, NULL, NULL, child_argv, environ);
    free(child_argv);
    if (spawn_rc != 0) {
        errno = spawn_rc;
        perror("micro");
        return 127;
    }

    int status = 0;
    for (;;) {
        pid_t waited = waitpid(pid, &status, 0);
        if (waited < 0 && errno == EINTR) {
            continue;
        }
        if (waited < 0) {
            perror("micro");
            return 127;
        }
        break;
    }

    if (WIFEXITED(status)) {
        return WEXITSTATUS(status);
    }
    if (WIFSIGNALED(status)) {
        return 128 + WTERMSIG(status);
    }
    return 1;
}

__attribute__((weak))
int pscal_micro_main_entry(int argc, char **argv) {
    char exe_path[PATH_MAX];
    if (!smallclueLocateMicroExecutable(exe_path, sizeof(exe_path))) {
        return -1;
    }
    return smallclueRunMicroExecutable(exe_path, argc, argv);
}

int smallclueRunMicro(int argc, char **argv) {
    int micro_status = pscal_micro_main_entry(argc, argv);
    if (micro_status >= 0) {
        return micro_status;
    }
    if (smallclueMicroCompatEnabled()) {
        smallclueWarnMicroCompat();
        return smallclueRunEditor(argc, argv);
    }
    fprintf(stderr, "micro: unavailable (no executable payload found)\n");
    fprintf(stderr, "micro: set PSCALI_MICRO_PATH or bundle micro.deflate/micro for iOS builds\n");
    return 127;
}
