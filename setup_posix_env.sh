#!/bin/bash
set -e

# Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
    echo "This script requires root privileges to set up the rootfs correctly."
    echo "Please run with sudo: sudo $0"
    exit 1
fi

# 0. Check for dependencies
MISSING_DEPS=0
if [ ! -d "third-party/nextvi/.git" ]; then
    echo "Nextvi repository missing or incomplete."
    MISSING_DEPS=1
fi
if [ ! -d "third-party/openssh/.git" ]; then
    echo "OpenSSH repository missing or incomplete."
    MISSING_DEPS=1
fi

if [ "$MISSING_DEPS" -eq 1 ]; then
    echo "Fetching dependencies..."
    chmod +x fetch_dependencies.sh
    ./fetch_dependencies.sh
else
    echo "Dependencies verified."
fi

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
cat > src/openssh_globals.c <<EOF
#include <signal.h>
volatile sig_atomic_t pscal_openssh_interrupted = 0;
int pscal_openssh_showprogress = 1;
EOF

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
OPENSSH_OBJS=""
OPENSSH_LIBS=""
OPENSSH_SHIM="src/openssh_shim.c"

OPENSSH_DIR="third-party/openssh"
if [ -d "$OPENSSH_DIR" ]; then
    echo "Configuring OpenSSH..."
    if [ ! -f "$OPENSSH_DIR/Makefile" ]; then
        if [ ! -f "$OPENSSH_DIR/configure" ]; then
            echo "configure script missing. Attempting to generate with autoreconf (this may take a moment)..."
            if command -v autoreconf >/dev/null 2>&1; then
                if ! (cd "$OPENSSH_DIR" && autoreconf -i > autoreconf.log 2>&1); then
                    echo "Error: autoreconf failed."
                    echo "--- autoreconf output ---"
                    cat "$OPENSSH_DIR/autoreconf.log"
                    echo "-------------------------"
                    echo "Please ensure you have autoconf and automake installed."
                    exit 1
                fi
            else
                echo "Error: autoreconf not found. Please install autoconf to build OpenSSH."
                if [ "$(uname -s)" = "Darwin" ]; then
                    echo "On macOS: brew install autoconf automake"
                else
                    echo "On Linux: sudo apt-get install autoconf automake"
                fi
                exit 1
            fi
        fi

        if [ -f "$OPENSSH_DIR/configure" ]; then
            (cd "$OPENSSH_DIR" && ./configure)
        else
            echo "Error: configure script not found and could not be generated."
            exit 1
        fi
    fi

    echo "Patching OpenSSH..."
    # Rename usage first
    # scp.c
    if grep -q "cleanup_exit" "$OPENSSH_DIR/scp.c"; then
        sed -i.bak 's/\bcleanup_exit\b/scp_cleanup_exit/g' "$OPENSSH_DIR/scp.c"
        # Add prototype to avoid implicit declaration warning
        if ! grep -q "void scp_cleanup_exit(int);" "$OPENSSH_DIR/scp.c"; then
             sed -i.bak '/#include "includes.h"/a void scp_cleanup_exit(int);' "$OPENSSH_DIR/scp.c"
        fi
        rm -f "$OPENSSH_DIR/scp.c.bak"
    fi
    if grep -q "volatile sig_atomic_t interrupted" "$OPENSSH_DIR/scp.c"; then
        sed -i.bak 's/\binterrupted\b/pscal_openssh_interrupted/g' "$OPENSSH_DIR/scp.c"
        # Now change definitions to extern
        sed -i.bak 's/volatile sig_atomic_t pscal_openssh_interrupted = 0;/extern volatile sig_atomic_t pscal_openssh_interrupted;/g' "$OPENSSH_DIR/scp.c"
        rm -f "$OPENSSH_DIR/scp.c.bak"
    fi
    if grep -q "int showprogress" "$OPENSSH_DIR/scp.c"; then
        sed -i.bak 's/\bshowprogress\b/pscal_openssh_showprogress/g' "$OPENSSH_DIR/scp.c"
        sed -i.bak 's/int pscal_openssh_showprogress = 1;/extern int pscal_openssh_showprogress;/g' "$OPENSSH_DIR/scp.c"
        rm -f "$OPENSSH_DIR/scp.c.bak"
    fi

    # sftp.c
    if grep -q "volatile sig_atomic_t interrupted" "$OPENSSH_DIR/sftp.c"; then
        sed -i.bak 's/\binterrupted\b/pscal_openssh_interrupted/g' "$OPENSSH_DIR/sftp.c"
        sed -i.bak 's/volatile sig_atomic_t pscal_openssh_interrupted = 0;/extern volatile sig_atomic_t pscal_openssh_interrupted;/g' "$OPENSSH_DIR/sftp.c"
        rm -f "$OPENSSH_DIR/sftp.c.bak"
    fi
    if grep -q "int showprogress" "$OPENSSH_DIR/sftp.c"; then
        sed -i.bak 's/\bshowprogress\b/pscal_openssh_showprogress/g' "$OPENSSH_DIR/sftp.c"
        sed -i.bak 's/int pscal_openssh_showprogress = 1;/extern int pscal_openssh_showprogress;/g' "$OPENSSH_DIR/sftp.c"
        rm -f "$OPENSSH_DIR/sftp.c.bak"
    fi

    # sftp-client.c
    if grep -q "volatile sig_atomic_t interrupted" "$OPENSSH_DIR/sftp-client.c"; then
        sed -i.bak 's/\binterrupted\b/pscal_openssh_interrupted/g' "$OPENSSH_DIR/sftp-client.c"
        rm -f "$OPENSSH_DIR/sftp-client.c.bak"
    fi
    if grep -q "extern int showprogress" "$OPENSSH_DIR/sftp-client.c"; then
        sed -i.bak 's/\bshowprogress\b/pscal_openssh_showprogress/g' "$OPENSSH_DIR/sftp-client.c"
        sed -i.bak 's/extern int showprogress;/extern int pscal_openssh_showprogress;/g' "$OPENSSH_DIR/sftp-client.c"
        rm -f "$OPENSSH_DIR/sftp-client.c.bak"
    fi

    # Force rebuild of patched files
    rm -f "$OPENSSH_DIR/scp.o" "$OPENSSH_DIR/sftp.o" "$OPENSSH_DIR/sftp-client.o"

    echo "Building OpenSSH objects..."
    (cd "$OPENSSH_DIR" && make -j4 libssh.a openbsd-compat/libopenbsd-compat.a \
        ssh.o readconf.o clientloop.o sshtty.o sshconnect.o sshconnect2.o mux.o ssh-sk-client.o \
        scp.o progressmeter.o sftp-common.o sftp-client.o sftp-glob.o \
        sftp.o sftp-usergroup.o \
        ssh-keygen.o sshsig.o)

    OPENSSH_OBJS="$OPENSSH_DIR/ssh.o $OPENSSH_DIR/readconf.o $OPENSSH_DIR/clientloop.o $OPENSSH_DIR/sshtty.o \
$OPENSSH_DIR/sshconnect.o $OPENSSH_DIR/sshconnect2.o $OPENSSH_DIR/mux.o $OPENSSH_DIR/ssh-sk-client.o \
$OPENSSH_DIR/scp.o $OPENSSH_DIR/progressmeter.o $OPENSSH_DIR/sftp-common.o $OPENSSH_DIR/sftp-client.o $OPENSSH_DIR/sftp-glob.o \
$OPENSSH_DIR/sftp.o $OPENSSH_DIR/sftp-usergroup.o \
$OPENSSH_DIR/ssh-keygen.o $OPENSSH_DIR/sshsig.o"

    # Link against built static libs and system libs (zlib, crypto)
    # On Linux with -static, -lcrypto -lz will use static versions if available.
    OPENSSH_LIBS="$OPENSSH_DIR/libssh.a $OPENSSH_DIR/openbsd-compat/libopenbsd-compat.a -lcrypto -lz"

    # Include globals and stubs
    OPENSSH_SRC="src/openssh_stubs.c src/openssh_globals.c"

    # Do not link shim if using real openssh (avoid dns symbol conflict)
    OPENSSH_SHIM=""
fi

gcc -std=c99 -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700 -D_GNU_SOURCE -DSMALLCLUE_WITH_EXSH ${EXTRA_C_DEFS} \
    -I. -Isrc ${EXTRA_LD_FLAGS} -lpthread \
    src/main.c \
    src/core.c \
    src/runtime_support.c \
    src/nextvi_app.c \
    ${NEXTVI_SRC} \
    ${OPENSSH_SRC} \
    ${OPENSSH_OBJS} \
    src/openssh_app.c \
    src/vproc_test_app.c \
    ${OPENSSH_SHIM} \
    src/runtime_stubs_extra.c \
    ${OPENSSH_LIBS} \
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

if [ "$(uname -s)" = "Linux" ] && [ -d "$ROOTFS" ]; then
    # Cleanup previous mounts if any (reverse order for nested mounts)
    # Use readlink -f to get absolute path for reliable matching
    ABS_ROOTFS=$(readlink -f "$ROOTFS")
    mount | awk -v root="$ABS_ROOTFS" '$3 == root || $3 ~ "^" root "/" {print $3}' | sort -r | while read -r mountpoint; do
        echo "Unmounting $mountpoint..."
        umount "$mountpoint" || true
    done
fi

rm -rf "$ROOTFS"
mkdir -p "$ROOTFS"/{bin,usr/bin,etc,tmp,var,home/username,dev,proc,sys,root}
chown -R 1000:1000 "$ROOTFS/home/username"
chmod 1777 "$ROOTFS/tmp"

# 4.5 Populate /dev
echo "Populating /dev..."
if [ "$(uname -s)" = "Linux" ]; then
    # Standard Linux device nodes
    # Try mknod first (some containers restrict this)
    if mknod -m 666 "$ROOTFS/dev/test_null" c 1 3 2>/dev/null; then
        rm -f "$ROOTFS/dev/test_null"
        # mknod works, proceed
        echo "Creating devices using mknod..."
        mknod -m 666 "$ROOTFS/dev/null" c 1 3
        mknod -m 666 "$ROOTFS/dev/zero" c 1 5
        mknod -m 666 "$ROOTFS/dev/random" c 1 8
        mknod -m 666 "$ROOTFS/dev/urandom" c 1 9
        mknod -m 666 "$ROOTFS/dev/tty" c 5 0
        mknod -m 622 "$ROOTFS/dev/console" c 5 1
        mknod -m 666 "$ROOTFS/dev/ptmx" c 5 2
    else
        echo "Notice: mknod failed or not permitted. Attempting fallback to bind mounts..."
        # Fallback: bind mount devices
        # Note: These bind mounts persist until unmounted. The cleanup step at start of script handles them on re-run.
        for dev in null zero random urandom tty console ptmx; do
            if [ -e "/dev/$dev" ]; then
                touch "$ROOTFS/dev/$dev"
                mount --bind "/dev/$dev" "$ROOTFS/dev/$dev"
            else
                echo "Warning: Host device /dev/$dev not found, skipping."
            fi
        done
    fi
    mkdir -p "$ROOTFS/dev/shm"
    mkdir -p "$ROOTFS/dev/pts"
elif [ "$(uname -s)" = "Darwin" ]; then
    # macOS device nodes (Major/Minor may vary by OS version, these are common for recent macOS)
    # /dev/null
    mknod -m 666 "$ROOTFS/dev/null" c 3 2 || echo "Failed to create /dev/null"
    # /dev/zero
    mknod -m 666 "$ROOTFS/dev/zero" c 3 3 || echo "Failed to create /dev/zero"
    # /dev/tty
    mknod -m 666 "$ROOTFS/dev/tty" c 2 0 || echo "Failed to create /dev/tty"
    # /dev/random
    mknod -m 666 "$ROOTFS/dev/random" c 14 0 || echo "Failed to create /dev/random"
    # /dev/urandom
    mknod -m 666 "$ROOTFS/dev/urandom" c 14 1 || echo "Failed to create /dev/urandom"
fi

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
cat > "$ROOTFS/etc/passwd" <<EOF
root:x:0:0:root:/root:/bin/sh
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
sshd:x:104:65534::/run/sshd:/usr/sbin/nologin
username:x:1000:1000:User Name,,,:/home/username:/bin/sh
EOF

cat > "$ROOTFS/etc/group" <<EOF
root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
adm:x:4:syslog,username
tty:x:5:
disk:x:6:
lp:x:7:
proxy:x:13:
www-data:x:33:
backup:x:34:
list:x:38:
gnats:x:41:
shadow:x:42:
utmp:x:43:
video:x:44:
sasl:x:45:
plugdev:x:46:
staff:x:50:
games:x:60:
users:x:100:
nogroup:x:65534:
input:x:104:
crontab:x:105:
syslog:x:106:
messagebus:x:107:
ssh:x:108:
sudo:x:27:username
username:x:1000:
EOF

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
