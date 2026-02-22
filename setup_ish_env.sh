#!/bin/bash
set -e

# Check for root privileges (needed for chown/mknod in rootfs)
if [ "$(id -u)" -ne 0 ]; then
    echo "This script requires root privileges to set up the rootfs correctly."
    echo "Please run with sudo: sudo $0"
    exit 1
fi

# 0. Determine 32-bit i686 toolchain support
TARGET_HOST="i686-linux-gnu"
TARGET_DESC=""
declare -a CC_CMD
declare -a TARGET_CFLAGS
declare -a TARGET_LDFLAGS
declare -a SMALLCLUE_RUNNER_CMD

if command -v gcc >/dev/null 2>&1 && gcc -m32 -static -o /dev/null -x c - <<< "int main(){return 0;}" 2>/dev/null; then
    CC_CMD=(gcc -m32)
    TARGET_CFLAGS=(-m32)
    TARGET_LDFLAGS=(-m32)
    TARGET_DESC="native gcc -m32"
elif command -v i686-linux-gnu-gcc >/dev/null 2>&1 && i686-linux-gnu-gcc -static -o /dev/null -x c - <<< "int main(){return 0;}" 2>/dev/null; then
    CC_CMD=(i686-linux-gnu-gcc)
    TARGET_DESC="cross i686-linux-gnu-gcc"
else
    HOST_ARCH="$(uname -m)"
    echo "Error: no usable 32-bit i686 compiler found."
    if [ "$HOST_ARCH" = "aarch64" ] || [ "$HOST_ARCH" = "arm64" ] || [ "$HOST_ARCH" = "armv7l" ]; then
        echo "On ARM hosts (Raspberry Pi), install the i686 cross toolchain:"
        echo "  sudo apt-get update"
        echo "  sudo apt-get install gcc-i686-linux-gnu libc6-dev-i386-cross binutils-i686-linux-gnu qemu-user-static"
    else
        echo "Install multilib support:"
        echo "  sudo apt-get update"
        echo "  sudo apt-get install gcc-multilib libc6-dev-i386"
    fi
    exit 1
fi

CC_PRINT="${CC_CMD[*]}"
BUILD_CC="cc"
if command -v gcc >/dev/null 2>&1; then
    BUILD_CC="gcc"
elif command -v cc >/dev/null 2>&1; then
    BUILD_CC="cc"
fi

BUILD_TRIPLET="$($BUILD_CC -dumpmachine 2>/dev/null || true)"
if [ -z "$BUILD_TRIPLET" ]; then
    BUILD_TRIPLET="$(uname -m)-unknown-linux-gnu"
fi
echo "Setting up iSH (32-bit x86) build environment using ${TARGET_DESC}..."

# 1. Fetch dependencies
echo "Fetching dependencies..."
chmod +x fetch_dependencies.sh
./fetch_dependencies.sh

# 2. Create dummy headers (Same as setup_posix_env.sh)
echo "Creating dummy headers..."
mkdir -p src/core
cat > src/core/build_info.h <<EOF
#ifndef BUILD_INFO_H
#define BUILD_INFO_H
#define BUILD_VERSION "1.0.0-ish"
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
    return "1.0.0-ish";
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
EOF

# 3. Configure and Build Dependencies
OPENSSH_DIR="third-party/openssh"
OPENSSH_SRC="src/openssh_stubs.c"
OPENSSH_OBJS=""
OPENSSH_LIBS=""
OPENSSH_SHIM="src/openssh_shim.c"
TARGET_IS_CROSS=0
if [ "${CC_CMD[0]}" = "i686-linux-gnu-gcc" ]; then
    TARGET_IS_CROSS=1
fi
OPENSSH_CPPFLAGS=""
OPENSSH_LDFLAGS=""
if [ "$TARGET_IS_CROSS" -eq 1 ]; then
    if [ -d /usr/include/i386-linux-gnu ]; then
        OPENSSH_CPPFLAGS="$OPENSSH_CPPFLAGS -I/usr/include/i386-linux-gnu"
    fi
    if [ -d /usr/lib/i386-linux-gnu ]; then
        OPENSSH_LDFLAGS="$OPENSSH_LDFLAGS -L/usr/lib/i386-linux-gnu"
    fi
fi

if [ -d "$OPENSSH_DIR" ]; then
    echo "Checking i686 zlib/crypto for OpenSSH..."
    HAVE_TARGET_ZLIB=1
    HAVE_TARGET_CRYPTO=1

    if ! "${CC_CMD[@]}" "${TARGET_CFLAGS[@]}" "${TARGET_LDFLAGS[@]}" ${OPENSSH_CPPFLAGS} ${OPENSSH_LDFLAGS} \
        -static -x c - -o /dev/null -lz >/dev/null 2>&1 <<'EOF'
#include <zlib.h>
int main(void) { return zlibVersion() ? 0 : 1; }
EOF
    then
        HAVE_TARGET_ZLIB=0
    fi

    if ! "${CC_CMD[@]}" "${TARGET_CFLAGS[@]}" "${TARGET_LDFLAGS[@]}" ${OPENSSH_CPPFLAGS} ${OPENSSH_LDFLAGS} \
        -static -x c - -o /dev/null -lcrypto >/dev/null 2>&1 <<'EOF'
#include <openssl/crypto.h>
int main(void) { return OpenSSL_version_num() ? 0 : 1; }
EOF
    then
        HAVE_TARGET_CRYPTO=0
    fi

    if [ "$HAVE_TARGET_ZLIB" -ne 1 ] || [ "$HAVE_TARGET_CRYPTO" -ne 1 ]; then
        echo "Warning: missing i686 OpenSSH deps; building with OpenSSH stubs only."
        if [ "$HAVE_TARGET_ZLIB" -ne 1 ]; then
            echo "  Missing target zlib (-lz)."
        fi
        if [ "$HAVE_TARGET_CRYPTO" -ne 1 ]; then
            echo "  Missing target OpenSSL crypto (-lcrypto)."
        fi
        if [ "$TARGET_IS_CROSS" -eq 1 ]; then
            echo "Install i386 target libs on Debian:"
            echo "  sudo dpkg --add-architecture i386"
            echo "  sudo apt-get update"
            echo "  sudo apt-get install zlib1g-dev:i386 libssl-dev:i386"
        else
            echo "Install 32-bit target libs on Debian:"
            echo "  sudo dpkg --add-architecture i386"
            echo "  sudo apt-get update"
            echo "  sudo apt-get install zlib1g-dev:i386 libssl-dev:i386"
        fi
    else
    echo "Configuring OpenSSH for i686..."
    
    # Check if we need to reconfigure (simplistic check: if Makefile exists but we want to be safe)
    # We always force reconfigure to ensure -m32 is picked up
    if [ -f "$OPENSSH_DIR/Makefile" ]; then
        echo "Cleaning OpenSSH..."
        (cd "$OPENSSH_DIR" && make distclean >/dev/null 2>&1 || true)
    fi

    if [ ! -f "$OPENSSH_DIR/configure" ]; then
        echo "Generating configure..."
        (cd "$OPENSSH_DIR" && autoreconf -i)
    fi

    echo "Running configure for OpenSSH..."
    (cd "$OPENSSH_DIR" && CPPFLAGS="$OPENSSH_CPPFLAGS" LDFLAGS="$OPENSSH_LDFLAGS ${TARGET_LDFLAGS[*]}" ./configure --host="$TARGET_HOST" --without-openssl-header-check CC="$CC_PRINT")

    echo "Patching OpenSSH (setup_posix_env.sh logic)..."
    # setup_posix_env.sh patching logic
    # scp.c
    if grep -q "cleanup_exit" "$OPENSSH_DIR/scp.c"; then
        sed -i.bak 's/\bcleanup_exit\b/scp_cleanup_exit/g' "$OPENSSH_DIR/scp.c"
        if ! grep -q "void scp_cleanup_exit(int);" "$OPENSSH_DIR/scp.c"; then
             sed -i.bak '/#include "includes.h"/a void scp_cleanup_exit(int);' "$OPENSSH_DIR/scp.c"
        fi
        rm -f "$OPENSSH_DIR/scp.c.bak"
    fi
    if grep -q "volatile sig_atomic_t interrupted" "$OPENSSH_DIR/scp.c"; then
        sed -i.bak 's/\binterrupted\b/pscal_openssh_interrupted/g' "$OPENSSH_DIR/scp.c"
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

    OPENSSH_LIBS="$OPENSSH_DIR/libssh.a $OPENSSH_DIR/openbsd-compat/libopenbsd-compat.a -lcrypto -lz"
    OPENSSH_SRC="src/openssh_stubs.c src/openssh_globals.c"
    OPENSSH_SHIM=""
    fi
fi

# Dash
DASH_DIR="third-party/dash"
if [ -d "$DASH_DIR" ]; then
    echo "Configuring Dash for i686..."
    DASH_AR="ar"
    DASH_RANLIB="ranlib"
    if [ "$TARGET_IS_CROSS" -eq 1 ]; then
        if command -v i686-linux-gnu-ar >/dev/null 2>&1; then
            DASH_AR="i686-linux-gnu-ar"
        fi
        if command -v i686-linux-gnu-ranlib >/dev/null 2>&1; then
            DASH_RANLIB="i686-linux-gnu-ranlib"
        fi
    fi
    if [ -f "$DASH_DIR/Makefile" ]; then
        (cd "$DASH_DIR" && make distclean >/dev/null 2>&1 || true)
    fi
    if [ ! -f "$DASH_DIR/configure" ]; then
        (cd "$DASH_DIR" && ./autogen.sh)
    fi
    DASH_CC_FOR_BUILD="$BUILD_CC"
    (cd "$DASH_DIR" && AR="$DASH_AR" RANLIB="$DASH_RANLIB" CC_FOR_BUILD="$DASH_CC_FOR_BUILD" ./configure --build="$BUILD_TRIPLET" --host="$TARGET_HOST" --enable-static CC="$CC_PRINT" CFLAGS="${TARGET_CFLAGS[*]}" LDFLAGS="${TARGET_LDFLAGS[*]} -static")
    echo "Building Dash..."
    (cd "$DASH_DIR" && make -j4 CC="$CC_PRINT" CC_FOR_BUILD="$DASH_CC_FOR_BUILD" AR="$DASH_AR" RANLIB="$DASH_RANLIB" CFLAGS="${TARGET_CFLAGS[*]}" LDFLAGS="${TARGET_LDFLAGS[*]} -static")

    if [ ! -f "$DASH_DIR/src/dash" ]; then
        echo "Error: dash build did not produce $DASH_DIR/src/dash"
        exit 1
    fi
    DASH_BUILD_FILE_INFO="$(file "$DASH_DIR/src/dash" || true)"
    echo "$DASH_BUILD_FILE_INFO" | grep -Eq "ELF 32-bit|Intel 80386|i386" || {
        echo "Error: dash is not an i686 binary."
        echo "  file: $DASH_BUILD_FILE_INFO"
        exit 1
    }
    echo "$DASH_BUILD_FILE_INFO" | grep -q "statically linked" || {
        echo "Error: dash is not statically linked."
        echo "  file: $DASH_BUILD_FILE_INFO"
        exit 1
    }
fi

NEXTVI_SRC="src/nextvi_stubs.c"
if [ -f third-party/nextvi/vi.c ]; then
    echo "Verifying nextvi can be compiled for i686 target..."
    NEXTVI_CHECK_OBJ="third-party/nextvi/.nextvi_target_check.o"
    "${CC_CMD[@]}" "${TARGET_CFLAGS[@]}" -std=c99 -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700 -D_GNU_SOURCE -I. -Isrc -c third-party/nextvi/vi.c -o "$NEXTVI_CHECK_OBJ"
    rm -f "$NEXTVI_CHECK_OBJ"
    echo "Using target-compiled nextvi source."
    NEXTVI_SRC="third-party/nextvi/vi.c"
else
    echo "nextvi source not found; using stubs."
fi

# 4. Compile smallclue
echo "Compiling smallclue (iSH/32-bit static)..."
"${CC_CMD[@]}" "${TARGET_CFLAGS[@]}" "${TARGET_LDFLAGS[@]}" -static -std=c99 -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700 -D_GNU_SOURCE \
    -I. -Isrc -lpthread \
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

echo "Verifying 32-bit binary..."
file smallclue | grep -E "ELF 32-bit|Intel 80386|i386" || { echo "Error: smallclue is not a 32-bit i686 binary"; exit 1; }

# 5. Setup rootfs
ROOTFS="rootfs_ish"
echo "Setting up $ROOTFS..."

rm -rf "$ROOTFS"
mkdir -p "$ROOTFS"/{bin,sbin,usr/bin,usr/sbin,etc,tmp,var,home/username,dev,proc,sys,root}
chown -R 1000:1000 "$ROOTFS/home/username"
chmod 1777 "$ROOTFS/tmp"

# Populate /dev (Minimal for iSH, it usually populates its own or uses devtmpfs)
# We'll create standard nodes just in case, if allowed
if mknod -m 666 "$ROOTFS/dev/test_null" c 1 3 2>/dev/null; then
    rm -f "$ROOTFS/dev/test_null"
    echo "Creating static device nodes..."
    mknod -m 666 "$ROOTFS/dev/null" c 1 3
    mknod -m 666 "$ROOTFS/dev/zero" c 1 5
    mknod -m 666 "$ROOTFS/dev/random" c 1 8
    mknod -m 666 "$ROOTFS/dev/urandom" c 1 9
    mknod -m 666 "$ROOTFS/dev/tty" c 5 0
    mknod -m 622 "$ROOTFS/dev/console" c 5 1
    mknod -m 666 "$ROOTFS/dev/ptmx" c 5 2
else
    echo "Warning: mknod not permitted. Skipping static device creation."
    echo "iSH should populate /dev automatically at runtime."
fi
mkdir -p "$ROOTFS/dev/shm"
mkdir -p "$ROOTFS/dev/pts"

# Install binaries
cp smallclue "$ROOTFS/bin/"

DASH_USABLE=0
if [ -f "third-party/dash/src/dash" ]; then
    DASH_FILE_INFO="$(file "third-party/dash/src/dash" || true)"
    if echo "$DASH_FILE_INFO" | grep -Eq "ELF 32-bit|Intel 80386|i386" && echo "$DASH_FILE_INFO" | grep -q "statically linked"; then
        echo "Installing dash..."
        cp "third-party/dash/src/dash" "$ROOTFS/bin/dash"
        ln -sf dash "$ROOTFS/bin/sh"
        DASH_USABLE=1
    else
        echo "Warning: dash exists but is not a static i686 binary; skipping /bin/sh -> dash."
    fi
fi

# Create symlinks
if ./smallclue >/dev/null 2>&1; then
    SMALLCLUE_RUNNER_CMD=(./smallclue)
elif command -v qemu-i386-static >/dev/null 2>&1; then
    SMALLCLUE_RUNNER_CMD=(qemu-i386-static ./smallclue)
elif command -v qemu-i386 >/dev/null 2>&1; then
    SMALLCLUE_RUNNER_CMD=(qemu-i386 ./smallclue)
else
    SMALLCLUE_RUNNER_CMD=()
fi

if [ "${#SMALLCLUE_RUNNER_CMD[@]}" -gt 0 ]; then
    APPLETS=$("${SMALLCLUE_RUNNER_CMD[@]}" 2>&1 | grep "^  " | awk '{print $1}' | grep -v "^smallclue$" || true)
else
    echo "Warning: unable to execute i686 smallclue binary on this host."
    echo "Falling back to parsing applet names from src/core.c."
    APPLETS=$(awk '
        /static const SmallclueApplet kSmallclueApplets\[] = {/ { in_table = 1; next }
        in_table && /^\};/ { exit }
        in_table && match($0, /^[[:space:]]*\{"[^"]+"/) {
            line = $0
            sub(/^[[:space:]]*\{"/, "", line)
            sub(/".*$/, "", line)
            if (line != "smallclue") {
                print line
            }
        }
    ' src/core.c | sort -u)
fi

for applet in $APPLETS; do
    if [ "$applet" == "smallclue" ]; then continue; fi
    if [ "$applet" == "sh" ] && [ -f "$ROOTFS/bin/dash" ]; then continue; fi
    ln -sf smallclue "$ROOTFS/bin/$applet"
done

if [ "$DASH_USABLE" -eq 0 ]; then
    if printf '%s\n' "$APPLETS" | grep -qx "sh"; then
        ln -sf smallclue "$ROOTFS/bin/sh"
    else
        echo "Error: no runnable /bin/sh candidate found."
        echo "Need either:"
        echo "  1) static i686 dash at third-party/dash/src/dash, or"
        echo "  2) smallclue built with 'sh' applet."
        exit 1
    fi
fi

# iSH default launch command is /bin/login -f root; provide a simple wrapper.
cat > "$ROOTFS/bin/login" <<EOF
#!/bin/sh
if [ "\$1" = "-f" ] && [ -n "\$2" ]; then
    export USER="\$2"
    export LOGNAME="\$2"
fi
exec /bin/sh -l
EOF
chmod +x "$ROOTFS/bin/login"
ln -sf /bin/login "$ROOTFS/usr/bin/login"

if [ ! -x "$ROOTFS/bin/login" ]; then
    echo "Error: /bin/login is not executable in rootfs."
    exit 1
fi
if [ ! -e "$ROOTFS/bin/sh" ]; then
    echo "Error: /bin/sh is missing in rootfs."
    exit 1
fi

# Init symlink for iSH
ln -sf /bin/smallclue "$ROOTFS/sbin/init"
ln -sf /bin/smallclue "$ROOTFS/init" # Just in case

# Dummy files
cat > "$ROOTFS/etc/passwd" <<EOF
root:x:0:0:root:/root:/bin/sh
username:x:1000:1000:User Name,,,:/home/username:/bin/sh
EOF

cat > "$ROOTFS/etc/group" <<EOF
root:x:0:
username:x:1000:
EOF

echo "Creating /etc/hosts..."
cat > "$ROOTFS/etc/hosts" <<EOF
127.0.0.1   localhost
127.0.1.1   smallclue
::1         localhost ip6-localhost ip6-loopback
EOF

cat > "$ROOTFS/etc/profile" <<EOF
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
EOF

echo "Creating /etc/rc..."
cat > "$ROOTFS/etc/rc" <<EOF
#!/bin/sh
echo "Welcome to SmallClue (iSH Edition)!"
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
echo "Mounting filesystems..."
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devpts devpts /dev/pts
echo "Starting shell..."
# exec /bin/sh
EOF
chmod +x "$ROOTFS/etc/rc"

# Package
echo "Packaging to ish-rootfs.tar.gz..."
tar -czf ish-rootfs.tar.gz -C "$ROOTFS" .

echo "Done. ish-rootfs.tar.gz is ready for iSH."
echo "You can import this using iSH's import feature or extract it into the iSH filesystem."
