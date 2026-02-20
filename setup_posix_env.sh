#!/bin/bash
set -e

# 1. Create dummy headers
echo "Creating dummy headers..."
mkdir -p src/core
cat > src/core/build_info.h <<EOF
#ifndef BUILD_INFO_H
#define BUILD_INFO_H
#define BUILD_VERSION "1.0.0-test"
#include <stdbool.h>
#include <stddef.h>
bool pscalRuntimeStderrIsInteractive(void);
const char *pscal_program_version_string(void);
bool pathTruncateEnabled(void);
bool pathTruncateStrip(const char *path, char *buffer, size_t buflen);
#endif
EOF

mkdir -p third-party/openssh
if [ ! -f third-party/openssh/pscal_runtime_hooks.h ]; then
cat > third-party/openssh/pscal_runtime_hooks.h <<EOF
#ifndef PSCAL_RUNTIME_HOOKS_H
#define PSCAL_RUNTIME_HOOKS_H
#include <setjmp.h>
#include <signal.h>
typedef struct {
    int exit_code;
    jmp_buf env;
} pscal_openssh_exit_context;

void pscal_openssh_reset_progress_state(void);
void pscal_openssh_push_exit_context(pscal_openssh_exit_context *ctx);
void pscal_openssh_pop_exit_context(pscal_openssh_exit_context *ctx);
void pscal_openssh_set_global_exit_handler(sigjmp_buf *env, volatile sig_atomic_t *code_out);
void pscal_openssh_request_exit(int code);
#endif
EOF
fi

mkdir -p third-party/ios_system/ssh_keygen
cat > third-party/ios_system/ssh_keygen/sshkey.h <<EOF
#ifndef SSHKEY_H
#define SSHKEY_H
struct sshkey {
    int dummy;
};
#endif
EOF

# 2. Create extra stubs
cat > src/runtime_stubs_extra.c <<EOF
#include "smallclue.h"
#include <stdbool.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

bool pscalRuntimeStderrIsInteractive(void) {
    return isatty(STDERR_FILENO);
}

const char *pscal_program_version_string(void) {
    return "1.0.0-test";
}

bool pathTruncateEnabled(void) {
    return false;
}

bool pathTruncateStrip(const char *path, char *buffer, size_t buflen) {
    if (!path || !buffer || buflen == 0) return false;
    strncpy(buffer, path, buflen - 1);
    buffer[buflen - 1] = '\0';
    return false; /* Did not modify */
}

int exsh_main(int argc, char **argv) {
    printf("SmallClue Shell (minimal)\n");
    char line[1024];
    while (1) {
        char cwd[1024];
        if (getcwd(cwd, sizeof(cwd))) {
            printf("%s %% ", cwd);
        } else {
            printf("? %% ");
        }
        fflush(stdout);

        if (!fgets(line, sizeof(line), stdin)) {
            break;
        }

        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') {
            line[len-1] = '\0';
            len--;
        }
        if (len == 0) continue;

        char *args[64];
        int nargs = 0;
        char *token = strtok(line, " \t");
        while (token && nargs < 63) {
            args[nargs++] = token;
            token = strtok(NULL, " \t");
        }
        args[nargs] = NULL;

        if (nargs == 0) continue;

        if (strcmp(args[0], "exit") == 0) {
            break;
        }
        if (strcmp(args[0], "cd") == 0) {
            const char *target = (nargs > 1) ? args[1] : getenv("HOME");
            if (!target) target = "/";
            if (chdir(target) != 0) {
                perror("cd");
            }
            continue;
        }

        const SmallclueApplet *applet = smallclueFindApplet(args[0]);
        if (applet) {
            smallclueDispatchApplet(applet, nargs, args);
        } else {
            printf("%s: command not found\n", args[0]);
        }
    }
    return 0;
}
EOF

# 3. Compile smallclue
echo "Compiling smallclue..."
EXTRA_C_DEFS=""
EXTRA_LD_FLAGS=""
if [ "$(uname -s)" = "Darwin" ]; then
    # Keep BSD typedefs (u_int/u_char/u_short) visible in macOS SDK networking headers.
    EXTRA_C_DEFS="-D_DARWIN_C_SOURCE"
fi
if [ "$(uname -s)" = "Linux" ]; then
    EXTRA_LD_FLAGS="-static"
fi

NEXTVI_SRC="src/nextvi_stubs.c"
if [ -f third-party/nextvi/vi.c ]; then
    echo "Using Nextvi from third-party/nextvi..."
    NEXTVI_SRC="third-party/nextvi/vi.c"
fi

OPENSSH_SRC="src/openssh_stubs.c"
# To build with real OpenSSH, you must manually compile the libraries and link them.
# For now, we default to stubs unless explicitly overridden.

gcc -std=c99 -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700 -D_GNU_SOURCE -DSMALLCLUE_WITH_EXSH ${EXTRA_C_DEFS} \
    -I. -Isrc ${EXTRA_LD_FLAGS} -lpthread \
    src/main.c \
    src/core.c \
    src/runtime_support.c \
    src/nextvi_app.c \
    ${NEXTVI_SRC} \
    ${OPENSSH_SRC} \
    src/openssh_app.c \
    src/vproc_test_app.c \
    src/openssh_shim.c \
    src/runtime_stubs_extra.c \
    -o smallclue

if [ ! -f smallclue ]; then
    echo "Compilation failed."
    exit 1
fi

if [ "$(uname -s)" = "Darwin" ] && [ -n "${SMALLCLUE_CODESIGN_IDENTITY:-}" ]; then
    echo "Signing smallclue with identity: ${SMALLCLUE_CODESIGN_IDENTITY}"
    codesign --force --timestamp=none --sign "${SMALLCLUE_CODESIGN_IDENTITY}" smallclue
fi

# 4. Setup rootfs
ROOTFS="rootfs"
echo "Setting up $ROOTFS..."
rm -rf "$ROOTFS"
mkdir -p "$ROOTFS"/{bin,usr/bin,etc,tmp,var,home,dev,proc,sys}

# 5. Install smallclue
cp smallclue "$ROOTFS/bin/"
if [ "$(uname -s)" = "Darwin" ] && [ -n "${SMALLCLUE_CODESIGN_IDENTITY:-}" ]; then
    codesign --force --timestamp=none --sign "${SMALLCLUE_CODESIGN_IDENTITY}" "$ROOTFS/bin/smallclue"
fi

# 6. Create symlinks
echo "Creating symlinks..."
# Extract applet names from ./smallclue output
# The output format has 2 spaces indentation for applet names.
APPLETS=$(./smallclue 2>&1 | grep "^  " | awk '{print $1}' | grep -v "smallclue")

for applet in $APPLETS; do
    # Skip if it is smallclue itself (already handled)
    if [ "$applet" == "smallclue" ]; then
        continue
    fi
    ln -sf smallclue "$ROOTFS/bin/$applet"
done

# 7. Create dummy files
echo "Creating dummy /etc files..."
echo "root:x:0:0:root:/home:/bin/sh" > "$ROOTFS/etc/passwd"
echo "root:x:0:" > "$ROOTFS/etc/group"

echo "Creating /etc/rc..."
cat > "$ROOTFS/etc/rc" <<EOF
#!/bin/sh
echo "Welcome to SmallClue POSIX Environment!"
echo "Mounting filesystems..."
# mount -t proc proc /proc
# mount -t sysfs sys /sys
# mount -t devtmpfs dev /dev
echo "Starting services..."
echo "Done."
EOF
chmod +x "$ROOTFS/etc/rc"

echo "Creating enter_chroot.sh..."
cat > enter_chroot.sh <<EOF
#!/bin/sh
# Check for root privileges and auto-elevate
if [ "\$(id -u)" -ne 0 ]; then
    echo "Entering chroot as root..."
    exec sudo "\$0" "\$@"
fi
# Execute chroot with explicit shell to override user's SHELL env var
exec chroot $ROOTFS /bin/sh -l
EOF
chmod +x enter_chroot.sh

echo "Setup complete."
echo ""
if [ "$(uname -s)" = "Darwin" ]; then
    echo "macOS note:"
    echo "  chroot may SIGKILL unsigned binaries (AMFI/AppleSystemPolicy)."
    echo "  If chroot is killed, sign with a real cert and rerun:"
    echo "    SMALLCLUE_CODESIGN_IDENTITY=\"Apple Development: Your Name (TEAMID)\" ./setup_posix_env.sh"
    echo "  Otherwise run applets directly without chroot:"
    echo "    ./smallclue ls -la"
    echo "  For a true chroot-style environment, use Linux."
else
    echo "To enter the environment:"
    echo "  ./enter_chroot.sh"
    echo ""
    echo "Or run specific commands:"
    echo "  sudo chroot $ROOTFS /bin/ls -la"
fi
