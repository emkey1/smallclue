#!/bin/bash
set -e

# Check for root privileges (needed for chown/mknod in rootfs)
if [ "$(id -u)" -ne 0 ]; then
    echo "This script requires root privileges to set up the rootfs correctly."
    echo "Please run with sudo: sudo $0"
    exit 1
fi

AUTO_INSTALL_DEPS="${AUTO_INSTALL_DEPS:-1}"
OPENSSH_VENDOR_FALLBACK="${OPENSSH_VENDOR_FALLBACK:-1}"
IS_DEBIAN_APT=0
if [ -f /etc/debian_version ] && command -v apt-get >/dev/null 2>&1 && command -v dpkg >/dev/null 2>&1; then
    IS_DEBIAN_APT=1
fi
HOST_DEB_ARCH=""
DPKG_HAS_BROKEN=0
if [ "$IS_DEBIAN_APT" -eq 1 ]; then
    HOST_DEB_ARCH="$(dpkg --print-architecture 2>/dev/null || true)"
    if dpkg --audit 2>/dev/null | grep -q .; then
        DPKG_HAS_BROKEN=1
    fi
fi
APT_UPDATED=0

aptMaybeUpdate() {
    if [ "$APT_UPDATED" -eq 0 ]; then
        apt-get update
        APT_UPDATED=1
    fi
}

debianPkgInstalled() {
    local pkg="$1"
    dpkg-query -W -f='${Status}\n' "$pkg" 2>/dev/null | grep -q "install ok installed"
}

ensureDebianPackages() {
    if [ "$IS_DEBIAN_APT" -ne 1 ]; then
        return 1
    fi
    local missing=()
    local pkg=""
    for pkg in "$@"; do
        if ! debianPkgInstalled "$pkg"; then
            missing+=("$pkg")
        fi
    done
    if [ "${#missing[@]}" -gt 0 ]; then
        aptMaybeUpdate
        apt-get install -y --no-install-recommends "${missing[@]}"
    fi
    return 0
}

aptInstallNoRecommends() {
    aptMaybeUpdate
    apt-get install -y --no-install-recommends "$@"
}

ensureI386ArchDebian() {
    if [ "$IS_DEBIAN_APT" -ne 1 ]; then
        return 1
    fi
    if ! dpkg --print-foreign-architectures | grep -qx "i386"; then
        dpkg --add-architecture i386
        APT_UPDATED=0
    fi
    return 0
}

ensureDebianI386OpenSshDeps() {
    if [ "$IS_DEBIAN_APT" -ne 1 ]; then
        return 1
    fi
    ensureI386ArchDebian

    # Try straightforward i386 installs only; do not force host package changes.
    if ! aptInstallNoRecommends libc6:i386 libc6-dev:i386 zlib1g:i386 zlib1g-dev:i386 libssl3:i386 libssl-dev:i386; then
        return 1
    fi
    return 0
}

downloadTarball() {
    local out="$1"
    shift
    local url=""
    for url in "$@"; do
        [ -z "$url" ] && continue
        echo "Trying download: $url"
        if command -v curl >/dev/null 2>&1; then
            if curl -L --fail -o "$out" "$url"; then
                return 0
            fi
        elif command -v wget >/dev/null 2>&1; then
            if wget -O "$out" "$url"; then
                return 0
            fi
        else
            echo "Error: need curl or wget to download sources."
            return 1
        fi
    done
    return 1
}

buildVendoredOpenSshDeps() {
    local vendor_root="third-party/ish-i686-deps"
    local src_root="$vendor_root/src"
    local stage_root="$vendor_root/stage"
    local stage_abs=""
    local zlib_ver="1.3.1"
    local zlib_src="$src_root/zlib-$zlib_ver"
    local zlib_tar="$src_root/zlib-$zlib_ver.tar.gz"
    local zlib_url_1="https://zlib.net/zlib-$zlib_ver.tar.gz"
    local zlib_url_2="https://zlib.net/fossils/zlib-$zlib_ver.tar.gz"
    local zlib_url_3="https://www.zlib.net/fossils/zlib-$zlib_ver.tar.gz"
    local openssl_ver="3.6.0"
    local openssl_src="$src_root/openssl-$openssl_ver"
    local openssl_tar="$src_root/openssl-$openssl_ver.tar.gz"
    local openssl_url_1="https://www.openssl.org/source/openssl-$openssl_ver.tar.gz"
    local openssl_url_2="https://www.openssl.org/source/old/3.6/openssl-$openssl_ver.tar.gz"
    local target_ar="ar"
    local target_ranlib="ranlib"
    local cc_prefix=""
    local zlib_header=""
    local zlib_lib=""
    local openssl_header=""
    local openssl_lib=""

    mkdir -p "$src_root" "$stage_root"
    rm -rf "$stage_root"
    mkdir -p "$stage_root"
    stage_abs="$(cd "$stage_root" && pwd)"

    if [ "$TARGET_IS_CROSS" -eq 1 ]; then
        cc_prefix="i686-linux-gnu-"
        if command -v i686-linux-gnu-ar >/dev/null 2>&1; then
            target_ar="i686-linux-gnu-ar"
        fi
        if command -v i686-linux-gnu-ranlib >/dev/null 2>&1; then
            target_ranlib="i686-linux-gnu-ranlib"
        fi
    fi

    if [ ! -d "$zlib_src" ]; then
        echo "Fetching zlib $zlib_ver..."
        if [ ! -f "$zlib_tar" ]; then
            downloadTarball "$zlib_tar" "$zlib_url_1" "$zlib_url_2" "$zlib_url_3" || {
                echo "Error: unable to download zlib source tarball."
                return 1
            }
        fi
        tar -xf "$zlib_tar" -C "$src_root" || {
            echo "Error: unable to extract $zlib_tar"
            return 1
        }
        if [ ! -d "$zlib_src" ]; then
            echo "Error: expected zlib source dir not found after extract: $zlib_src"
            return 1
        fi
    fi

    echo "Building vendored zlib for i686..."
    (cd "$zlib_src" && \
        make distclean >/dev/null 2>&1 || true && \
        CC="$CC_PRINT" AR="$target_ar" RANLIB="$target_ranlib" \
        ./configure --static --prefix=/usr && \
        make -j4 && make install DESTDIR="$stage_abs")

    if [ ! -d "$openssl_src" ]; then
        if [ -d ../../third-party/openssl-3.6.0 ]; then
            echo "Using bundled OpenSSL source from ../../third-party/openssl-3.6.0"
            cp -a ../../third-party/openssl-3.6.0 "$openssl_src"
        elif [ -d ../third-party/openssl-3.6.0 ]; then
            echo "Using bundled OpenSSL source from ../third-party/openssl-3.6.0"
            cp -a ../third-party/openssl-3.6.0 "$openssl_src"
        else
            echo "Fetching OpenSSL $openssl_ver..."
            if [ ! -f "$openssl_tar" ]; then
                downloadTarball "$openssl_tar" "$openssl_url_1" "$openssl_url_2" || {
                    echo "Error: unable to download OpenSSL source tarball."
                    return 1
                }
            fi
            tar -xf "$openssl_tar" -C "$src_root" || {
                echo "Error: unable to extract $openssl_tar"
                return 1
            }
        fi
        if [ ! -d "$openssl_src" ]; then
            echo "Error: expected OpenSSL source dir not found after extract: $openssl_src"
            return 1
        fi
    fi

    echo "Building vendored OpenSSL for i686..."
    if [ -n "$cc_prefix" ]; then
        (cd "$openssl_src" && \
            make clean >/dev/null 2>&1 || true && \
            perl Configure linux-generic32 no-shared no-tests no-module \
                --prefix=/usr \
                --openssldir=/etc/ssl \
                --cross-compile-prefix="$cc_prefix" && \
            make -j4 CC="$CC_PRINT" AR="$target_ar" RANLIB="$target_ranlib" && \
            make install_sw DESTDIR="$stage_abs")
    else
        (cd "$openssl_src" && \
            make clean >/dev/null 2>&1 || true && \
            perl Configure linux-generic32 no-shared no-tests no-module \
                --prefix=/usr \
                --openssldir=/etc/ssl && \
            make -j4 CC="$CC_PRINT" AR="$target_ar" RANLIB="$target_ranlib" && \
            make install_sw DESTDIR="$stage_abs")
    fi

    zlib_header="$(find "$stage_abs" -type f -path '*/include/zlib.h' | head -n 1 || true)"
    zlib_lib="$(find "$stage_abs" -type f -name 'libz.a' | head -n 1 || true)"
    openssl_header="$(find "$stage_abs" -type f -path '*/include/openssl/ssl.h' | head -n 1 || true)"
    openssl_lib="$(find "$stage_abs" -type f -name 'libcrypto.a' | head -n 1 || true)"

    if [ -z "$zlib_header" ] || [ -z "$zlib_lib" ] || [ -z "$openssl_header" ] || [ -z "$openssl_lib" ]; then
        echo "Error: vendored OpenSSH deps were built but required artifacts were not found."
        echo "  zlib header:    ${zlib_header:-missing}"
        echo "  zlib lib:       ${zlib_lib:-missing}"
        echo "  openssl header: ${openssl_header:-missing}"
        echo "  openssl lib:    ${openssl_lib:-missing}"
        return 1
    fi

    OPENSSH_CPPFLAGS="$OPENSSH_CPPFLAGS -I$(dirname "$zlib_header") -I$(dirname "$(dirname "$openssl_header")")"
    OPENSSH_LDFLAGS="$OPENSSH_LDFLAGS -L$(dirname "$zlib_lib") -L$(dirname "$openssl_lib")"
}

selectI686Toolchain() {
    if command -v gcc >/dev/null 2>&1 && gcc -m32 -static -o /dev/null -x c - <<< "int main(){return 0;}" 2>/dev/null; then
        CC_CMD=(gcc -m32)
        TARGET_CFLAGS=(-m32)
        TARGET_LDFLAGS=(-m32)
        TARGET_DESC="native gcc -m32"
        return 0
    fi
    if command -v i686-linux-gnu-gcc >/dev/null 2>&1 && i686-linux-gnu-gcc -static -o /dev/null -x c - <<< "int main(){return 0;}" 2>/dev/null; then
        CC_CMD=(i686-linux-gnu-gcc)
        TARGET_CFLAGS=()
        TARGET_LDFLAGS=()
        TARGET_DESC="cross i686-linux-gnu-gcc"
        return 0
    fi
    return 1
}

# 0. Determine 32-bit i686 toolchain support
TARGET_HOST="i686-linux-gnu"
TARGET_DESC=""
declare -a CC_CMD
declare -a TARGET_CFLAGS
declare -a TARGET_LDFLAGS
declare -a SMALLCLUE_RUNNER_CMD

if ! selectI686Toolchain; then
    HOST_ARCH="$(uname -m)"
    if [ "$AUTO_INSTALL_DEPS" = "1" ] && [ "$IS_DEBIAN_APT" -eq 1 ] && [ "$DPKG_HAS_BROKEN" -eq 0 ]; then
        echo "Installing missing toolchain/build dependencies..."
        ensureDebianPackages make file autoconf automake libtool pkg-config
        if [ "$HOST_ARCH" = "aarch64" ] || [ "$HOST_ARCH" = "arm64" ] || [ "$HOST_ARCH" = "armv7l" ]; then
            ensureDebianPackages gcc-i686-linux-gnu libc6-dev-i386-cross binutils-i686-linux-gnu qemu-user-static
        else
            ensureI386ArchDebian
            ensureDebianPackages gcc-multilib libc6-dev-i386
        fi
        selectI686Toolchain || true
    elif [ "$AUTO_INSTALL_DEPS" = "1" ] && [ "$IS_DEBIAN_APT" -eq 1 ] && [ "$DPKG_HAS_BROKEN" -eq 1 ]; then
        echo "Warning: dpkg has unconfigured/broken packages; skipping apt auto-install."
        echo "  (Script will continue and use non-apt fallback paths when possible.)"
    fi
fi

if ! selectI686Toolchain; then
    HOST_ARCH="$(uname -m)"
    echo "Error: no usable 32-bit i686 compiler found."
    if [ "$HOST_ARCH" = "aarch64" ] || [ "$HOST_ARCH" = "arm64" ] || [ "$HOST_ARCH" = "armv7l" ]; then
        echo "On ARM hosts (Raspberry Pi), install the i686 cross toolchain:"
        echo "  sudo apt-get update"
        echo "  sudo apt-get install gcc-i686-linux-gnu libc6-dev-i386-cross binutils-i686-linux-gnu qemu-user-static"
    else
        echo "Install multilib support:"
        echo "  sudo dpkg --add-architecture i386"
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
OPENSSH_ENABLED=0
ALLOW_OPENSSH_STUBS="${ALLOW_OPENSSH_STUBS:-0}"
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

probeOpenSshTargetLibs() {
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
        -static -x c - -o /dev/null -lcrypto -lz -ldl -pthread >/dev/null 2>&1 <<'EOF'
#include <openssl/crypto.h>
int main(void) { return OpenSSL_version_num() ? 0 : 1; }
EOF
    then
        HAVE_TARGET_CRYPTO=0
    fi
}

if [ -d "$OPENSSH_DIR" ]; then
    echo "Checking i686 zlib/crypto for OpenSSH..."
    probeOpenSshTargetLibs

    if ([ "$HAVE_TARGET_ZLIB" -ne 1 ] || [ "$HAVE_TARGET_CRYPTO" -ne 1 ]) && \
       [ "$AUTO_INSTALL_DEPS" = "1" ] && [ "$IS_DEBIAN_APT" -eq 1 ] && [ "$DPKG_HAS_BROKEN" -eq 0 ]; then
        echo "Installing missing i386 OpenSSH dependency packages..."
        ensureDebianI386OpenSshDeps || true
        probeOpenSshTargetLibs
    elif ([ "$HAVE_TARGET_ZLIB" -ne 1 ] || [ "$HAVE_TARGET_CRYPTO" -ne 1 ]) && \
         [ "$AUTO_INSTALL_DEPS" = "1" ] && [ "$IS_DEBIAN_APT" -eq 1 ] && [ "$DPKG_HAS_BROKEN" -eq 1 ]; then
        echo "Warning: dpkg currently broken; skipping apt OpenSSH dependency install."
    fi

    if ([ "$HAVE_TARGET_ZLIB" -ne 1 ] || [ "$HAVE_TARGET_CRYPTO" -ne 1 ]) && \
       [ "$OPENSSH_VENDOR_FALLBACK" = "1" ]; then
        echo "System i386 OpenSSH deps unavailable; trying vendored OpenSSL+zlib build..."
        if ! buildVendoredOpenSshDeps; then
            echo "Warning: vendored OpenSSH dependency build failed."
            if [ "$ALLOW_OPENSSH_STUBS" != "1" ]; then
                echo "Error: cannot continue without OpenSSH deps (or ALLOW_OPENSSH_STUBS=1)."
                exit 1
            fi
        fi
        probeOpenSshTargetLibs
    fi

    if [ "$HAVE_TARGET_ZLIB" -ne 1 ] || [ "$HAVE_TARGET_CRYPTO" -ne 1 ]; then
        echo "Warning: missing i686 OpenSSH deps."
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
            echo "  sudo apt-get install libc6:i386 libc6-dev:i386 zlib1g:i386 zlib1g-dev:i386 libssl3:i386 libssl-dev:i386"
            echo "If Raspberry Pi repo version suffixes prevent multiarch installs:"
            echo "  rerun with OPENSSH_VENDOR_FALLBACK=1 (default) to build vendored OpenSSL+zlib"
        else
            echo "Install 32-bit target libs on Debian:"
            echo "  sudo dpkg --add-architecture i386"
            echo "  sudo apt-get update"
            echo "  sudo apt-get install libc6:i386 libc6-dev:i386 zlib1g:i386 zlib1g-dev:i386 libssl3:i386 libssl-dev:i386"
            echo "If multiarch versioning blocks this, rerun with OPENSSH_VENDOR_FALLBACK=1."
        fi
        if [ "$ALLOW_OPENSSH_STUBS" != "1" ]; then
            echo "Error: refusing to continue with OpenSSH stubs."
            echo "Set ALLOW_OPENSSH_STUBS=1 to build without real ssh/scp/sftp support."
            exit 1
        fi
        echo "Continuing with OpenSSH stubs because ALLOW_OPENSSH_STUBS=1."
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
    # Force-disable syscalls known to be missing/stubbed on iSH kernels so
    # OpenSSH prefers portable fallbacks instead of ENOSYS paths at runtime.
    (cd "$OPENSSH_DIR" && \
        ac_cv_func_accept4=no \
        ac_cv_func_inotify_init=no \
        ac_cv_func_inotify_init1=no \
        ac_cv_func_faccessat2=no \
        ac_cv_func_sched_getattr=no \
        ac_cv_func_membarrier=no \
        CPPFLAGS="$OPENSSH_CPPFLAGS" \
        LDFLAGS="$OPENSSH_LDFLAGS ${TARGET_LDFLAGS[*]}" \
        ./configure --host="$TARGET_HOST" --without-openssl-header-check CC="$CC_PRINT")

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

    OPENSSH_LIBS="$OPENSSH_DIR/libssh.a $OPENSSH_DIR/openbsd-compat/libopenbsd-compat.a -lcrypto -lz -ldl"
    OPENSSH_SRC="src/openssh_stubs.c src/openssh_globals.c"
    OPENSSH_SHIM=""
    OPENSSH_ENABLED=1
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

DISABLE_NEXTVI="${DISABLE_NEXTVI:-0}"
NEXTVI_DIRECT_MODE="${NEXTVI_DIRECT_MODE:-1}"
NEXTVI_SRC="src/nextvi_stubs.c"
if [ "$DISABLE_NEXTVI" = "1" ]; then
    echo "nextvi disabled via DISABLE_NEXTVI=1; using stubs."
elif [ -f third-party/nextvi/vi.c ]; then
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
NEXTVI_DEFS=""
if [ "$NEXTVI_DIRECT_MODE" = "1" ]; then
    NEXTVI_DEFS="-DSMALLCLUE_NEXTVI_DIRECT=1"
    echo "nextvi direct mode enabled (no pthread editor worker thread)."
fi

echo "Compiling smallclue (iSH/32-bit static)..."
"${CC_CMD[@]}" "${TARGET_CFLAGS[@]}" "${TARGET_LDFLAGS[@]}" -static -std=c99 -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700 -D_GNU_SOURCE ${NEXTVI_DEFS} \
    -I. -Isrc ${OPENSSH_LDFLAGS} -lpthread \
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

if [ "$OPENSSH_ENABLED" -eq 1 ]; then
    echo "OpenSSH integration: enabled (ssh/scp/sftp/ssh-keygen available)."
else
    echo "OpenSSH integration: stubs only."
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

# Run /etc/rc if present and not already run
if [ -x /etc/rc ] && [ ! -f /tmp/rc_ran ]; then
    /etc/rc
    touch /tmp/rc_ran
fi
EOF
chmod 644 "$ROOTFS/etc/profile"

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
