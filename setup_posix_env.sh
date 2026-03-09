#!/bin/bash
set -e

SMALLCLUE_SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DVTM_RUNTIME_HOOKS_HEADER="${SMALLCLUE_SCRIPT_DIR}/src/dvtm_runtime_hooks.h"

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
if [ ! -d "third-party/openssh" ] || [ ! -f "third-party/openssh/ssh.c" ] || [ ! -f "third-party/openssh/scp.c" ] || [ ! -f "third-party/openssh/sftp.c" ] || [ ! -f "third-party/openssh/configure.ac" ]; then
    echo "OpenSSH repository missing or incomplete."
    MISSING_DEPS=1
fi
if [ ! -d "third-party/dash" ]; then
    echo "Dash missing."
    MISSING_DEPS=1
fi
if [ ! -d "third-party/dvtm/.git" ] || [ ! -f "third-party/dvtm/dvtm.c" ] || [ ! -f "third-party/dvtm/vt.c" ] || [ ! -f "third-party/dvtm/config.def.h" ]; then
    echo "dvtm repository missing or incomplete."
    MISSING_DEPS=1
fi
if [ ! -d "third-party/libgit2" ] || [ ! -f "third-party/libgit2/CMakeLists.txt" ] || [ ! -f "third-party/libgit2/include/git2.h" ]; then
    echo "libgit2 repository missing or incomplete."
    MISSING_DEPS=1
fi

if [ "$MISSING_DEPS" -eq 1 ]; then
    echo "Fetching dependencies..."
else
    echo "Dependencies present, checking for updates/patches..."
fi
chmod +x fetch_dependencies.sh
./fetch_dependencies.sh

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
#include <stdint.h>
volatile sig_atomic_t pscal_openssh_interrupted = 0;
int pscal_openssh_showprogress = 1;

/*
 * Some OpenSSH object files (e.g. ML-KEM code paths) may reference htole64/le64toh
 * as external symbols depending on libc feature exposure. Provide weak fallbacks so
 * static smallclue links remain portable across Linux build environments.
 */
#if defined(__linux__)
# ifdef htole64
#  undef htole64
# endif
# ifdef le64toh
#  undef le64toh
# endif
__attribute__((weak)) uint64_t htole64(uint64_t v) {
# if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return v;
# else
    return __builtin_bswap64(v);
# endif
}
__attribute__((weak)) uint64_t le64toh(uint64_t v) {
# if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    return v;
# else
    return __builtin_bswap64(v);
# endif
}
#endif
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

/* exsh stubs removed as dash is used for sh */
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

SMALLCLUE_WITH_DVTM="${SMALLCLUE_WITH_DVTM:-1}"
DVTM_OBJS=""
DVTM_LIBS=""
DVTM_EXTRA_DEFS=""
SMALLCLUE_WITH_LIBGIT2="${SMALLCLUE_WITH_LIBGIT2:-1}"
LIBGIT2_EXTRA_DEFS=""
LIBGIT2_EXTRA_CFLAGS=""
LIBGIT2_LIBS=""

OPENSSH_SRC="src/openssh_stubs.c"
OPENSSH_OBJS=""
OPENSSH_LIBS=""
OPENSSH_SHIM="src/openssh_shim.c"

OPENSSH_DIR="third-party/openssh"
if [ -d "$OPENSSH_DIR" ]; then
    # Revert sshd.c patching if present (from previous failed runs)
    if [ -d "$OPENSSH_DIR/.git" ] && [ -f "$OPENSSH_DIR/sshd.c" ] && grep -q "pscal_openssh_sshd_main" "$OPENSSH_DIR/sshd.c"; then
        echo "Reverting sshd.c changes..."
        (cd "$OPENSSH_DIR" && git checkout sshd.c)
    fi

    echo "Configuring OpenSSH..."
    if [ -f "$OPENSSH_DIR/Makefile" ]; then
        NEED_RECONF=0
        if [ "$(uname -s)" = "Linux" ] && ! grep -q "\-static" "$OPENSSH_DIR/Makefile"; then
             echo "Reconfiguring OpenSSH for static build..."
             NEED_RECONF=1
        fi
        if ! grep -q "sysconfdir = /etc/ssh" "$OPENSSH_DIR/Makefile"; then
             echo "Reconfiguring OpenSSH for sysconfdir..."
             NEED_RECONF=1
        fi

        if [ "$NEED_RECONF" -eq 1 ]; then
            echo "Cleaning OpenSSH build to reconfigure..."
            MAKEFILE_SHELL_PATH="$(awk -F= '/^SHELL[[:space:]]*=/{gsub(/[[:space:]]/, "", $2); print $2; exit}' "$OPENSSH_DIR/Makefile")"
            if [ -n "$MAKEFILE_SHELL_PATH" ] && [ ! -x "$MAKEFILE_SHELL_PATH" ]; then
                echo "OpenSSH Makefile references missing shell: $MAKEFILE_SHELL_PATH"
                echo "Purging generated OpenSSH build files instead of make distclean..."
                (cd "$OPENSSH_DIR" && rm -f Makefile config.status config.log config.h && rm -rf autom4te.cache)
            elif ! (cd "$OPENSSH_DIR" && make distclean); then
                echo "Warning: make distclean failed; purging generated OpenSSH build files..."
                (cd "$OPENSSH_DIR" && rm -f Makefile config.status config.log config.h && rm -rf autom4te.cache)
            fi
        fi
    fi

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
            OPENSSH_CONFIG_ENV=()
            OPENSSH_CONFIG_ARGS=(--sysconfdir=/etc/ssh)

            if [ "$(uname -s)" = "Linux" ]; then
                OPENSSH_CONFIG_ENV+=("LDFLAGS=-static")
            fi

            if [ "$(uname -s)" = "Darwin" ]; then
                CLEAN_PATH=""
                IFS=':' read -r -a PATH_PARTS <<< "$PATH"
                for p in "${PATH_PARTS[@]}"; do
                    case "$p" in
                        *miniconda*|*anaconda*|*/conda/*) continue ;;
                    esac
                    if [ -z "$CLEAN_PATH" ]; then
                        CLEAN_PATH="$p"
                    else
                        CLEAN_PATH="$CLEAN_PATH:$p"
                    fi
                done
                if [ -z "$CLEAN_PATH" ]; then
                    CLEAN_PATH="/usr/bin:/bin:/usr/sbin:/sbin"
                fi
                OPENSSH_CONFIG_ENV+=("PATH=$CLEAN_PATH")

                BREW_OPENSSL_PREFIX=""
                if command -v brew >/dev/null 2>&1; then
                    BREW_OPENSSL_PREFIX="$(brew --prefix openssl@3 2>/dev/null || true)"
                    if [ -z "$BREW_OPENSSL_PREFIX" ]; then
                        BREW_OPENSSL_PREFIX="$(brew --prefix openssl@1.1 2>/dev/null || true)"
                    fi
                fi

                if [ -n "$BREW_OPENSSL_PREFIX" ] && [ -d "$BREW_OPENSSL_PREFIX/include" ] && [ -d "$BREW_OPENSSL_PREFIX/lib" ]; then
                    echo "Configuring OpenSSH with Homebrew OpenSSL at $BREW_OPENSSL_PREFIX"
                    OPENSSH_CONFIG_ENV+=("CPPFLAGS=-I$BREW_OPENSSL_PREFIX/include")
                    OPENSSH_CONFIG_ENV+=("LDFLAGS=-L$BREW_OPENSSL_PREFIX/lib")
                    OPENSSH_CONFIG_ENV+=("PKG_CONFIG_PATH=$BREW_OPENSSL_PREFIX/lib/pkgconfig${PKG_CONFIG_PATH:+:$PKG_CONFIG_PATH}")
                    if [ -x "$BREW_OPENSSL_PREFIX/bin/openssl" ]; then
                        OPENSSH_CONFIG_ENV+=("OPENSSL_BIN=$BREW_OPENSSL_PREFIX/bin/openssl")
                    fi
                else
                    CLEAN_OPENSSL_BIN="$(PATH="$CLEAN_PATH" command -v openssl || true)"
                    if [ -n "$CLEAN_OPENSSL_BIN" ]; then
                        echo "Configuring OpenSSH with OpenSSL binary: $CLEAN_OPENSSL_BIN"
                        OPENSSH_CONFIG_ENV+=("OPENSSL_BIN=$CLEAN_OPENSSL_BIN")
                    fi
                fi
            fi

            if ! (cd "$OPENSSH_DIR" && env "${OPENSSH_CONFIG_ENV[@]}" ./configure "${OPENSSH_CONFIG_ARGS[@]}"); then
                echo "Error: OpenSSH configure failed."
                if [ -f "$OPENSSH_DIR/config.log" ]; then
                    echo "See: $OPENSSH_DIR/config.log"
                fi
                exit 1
            fi
        else
            echo "Error: configure script not found and could not be generated."
            echo "Try re-running: ./fetch_dependencies.sh"
            exit 1
        fi
    fi

    echo "Patching OpenSSH..."
    # Rename usage first
    # scp.c
    if grep -q "cleanup_exit" "$OPENSSH_DIR/scp.c"; then
        sed -i.bak 's/cleanup_exit/scp_cleanup_exit/g' "$OPENSSH_DIR/scp.c"
        # Add prototype to avoid implicit declaration warning
        if ! grep -q "void scp_cleanup_exit(int);" "$OPENSSH_DIR/scp.c"; then
            awk '
                { print }
                /#include "includes.h"/ { print "void scp_cleanup_exit(int);" }
            ' "$OPENSSH_DIR/scp.c" > "$OPENSSH_DIR/scp.c.tmp" && mv "$OPENSSH_DIR/scp.c.tmp" "$OPENSSH_DIR/scp.c"
        fi
        rm -f "$OPENSSH_DIR/scp.c.bak"
    fi
    if grep -q "volatile sig_atomic_t interrupted" "$OPENSSH_DIR/scp.c"; then
        sed -i.bak 's/interrupted/pscal_openssh_interrupted/g' "$OPENSSH_DIR/scp.c"
        # Now change definitions to extern
        sed -i.bak 's/volatile sig_atomic_t pscal_openssh_interrupted = 0;/extern volatile sig_atomic_t pscal_openssh_interrupted;/g' "$OPENSSH_DIR/scp.c"
        rm -f "$OPENSSH_DIR/scp.c.bak"
    fi
    if grep -q "int showprogress" "$OPENSSH_DIR/scp.c"; then
        sed -i.bak 's/showprogress/pscal_openssh_showprogress/g' "$OPENSSH_DIR/scp.c"
        sed -i.bak 's/int pscal_openssh_showprogress = 1;/extern int pscal_openssh_showprogress;/g' "$OPENSSH_DIR/scp.c"
        rm -f "$OPENSSH_DIR/scp.c.bak"
    fi

    # sftp.c
    if grep -q "volatile sig_atomic_t interrupted" "$OPENSSH_DIR/sftp.c"; then
        sed -i.bak 's/interrupted/pscal_openssh_interrupted/g' "$OPENSSH_DIR/sftp.c"
        sed -i.bak 's/volatile sig_atomic_t pscal_openssh_interrupted = 0;/extern volatile sig_atomic_t pscal_openssh_interrupted;/g' "$OPENSSH_DIR/sftp.c"
        rm -f "$OPENSSH_DIR/sftp.c.bak"
    fi
    if grep -q "int showprogress" "$OPENSSH_DIR/sftp.c"; then
        sed -i.bak 's/showprogress/pscal_openssh_showprogress/g' "$OPENSSH_DIR/sftp.c"
        sed -i.bak 's/int pscal_openssh_showprogress = 1;/extern int pscal_openssh_showprogress;/g' "$OPENSSH_DIR/sftp.c"
        rm -f "$OPENSSH_DIR/sftp.c.bak"
    fi

    # sftp-client.c
    if grep -q "interrupted" "$OPENSSH_DIR/sftp-client.c"; then
        sed -i.bak 's/interrupted/pscal_openssh_interrupted/g' "$OPENSSH_DIR/sftp-client.c"
        rm -f "$OPENSSH_DIR/sftp-client.c.bak"
    fi
    if grep -q "showprogress" "$OPENSSH_DIR/sftp-client.c"; then
        sed -i.bak 's/showprogress/pscal_openssh_showprogress/g' "$OPENSSH_DIR/sftp-client.c"
        if ! grep -q "extern int pscal_openssh_showprogress;" "$OPENSSH_DIR/sftp-client.c"; then
            awk '
                { print }
                /extern volatile sig_atomic_t pscal_openssh_interrupted;/ {
                    print "extern int pscal_openssh_showprogress;"
                }
            ' "$OPENSSH_DIR/sftp-client.c" > "$OPENSSH_DIR/sftp-client.c.tmp" && mv "$OPENSSH_DIR/sftp-client.c.tmp" "$OPENSSH_DIR/sftp-client.c"
        fi
        rm -f "$OPENSSH_DIR/sftp-client.c.bak"
    fi

    # Force rebuild of patched files
    rm -f "$OPENSSH_DIR/scp.o" "$OPENSSH_DIR/sftp.o" "$OPENSSH_DIR/sftp-client.o"

    echo "Building OpenSSH objects..."
    (cd "$OPENSSH_DIR" && make -j4 libssh.a openbsd-compat/libopenbsd-compat.a \
        ssh.o readconf.o clientloop.o sshtty.o sshconnect.o sshconnect2.o mux.o ssh-sk-client.o \
        scp.o progressmeter.o sftp-common.o sftp-client.o sftp-glob.o \
        sftp.o sftp-usergroup.o \
        ssh-keygen.o sshsig.o ssh-pkcs11.o)

    echo "Building OpenSSH sshd..."
    (cd "$OPENSSH_DIR" && make -j4 sshd)

    OPENSSH_OBJS="$OPENSSH_DIR/ssh.o $OPENSSH_DIR/readconf.o $OPENSSH_DIR/clientloop.o $OPENSSH_DIR/sshtty.o \
$OPENSSH_DIR/sshconnect.o $OPENSSH_DIR/sshconnect2.o $OPENSSH_DIR/mux.o $OPENSSH_DIR/ssh-sk-client.o \
$OPENSSH_DIR/scp.o $OPENSSH_DIR/progressmeter.o $OPENSSH_DIR/sftp-common.o $OPENSSH_DIR/sftp-client.o $OPENSSH_DIR/sftp-glob.o \
$OPENSSH_DIR/sftp.o $OPENSSH_DIR/sftp-usergroup.o \
$OPENSSH_DIR/ssh-keygen.o $OPENSSH_DIR/sshsig.o $OPENSSH_DIR/ssh-pkcs11.o"

    # Link against built static libs and system libs (zlib, crypto)
    # On Linux with -static, -lcrypto -lz will use static versions if available.
    OPENSSH_LIBS="$OPENSSH_DIR/libssh.a $OPENSSH_DIR/openbsd-compat/libopenbsd-compat.a -lcrypto -lz"
    if [ "$(uname -s)" = "Linux" ]; then
        OPENSSH_LIBS="$OPENSSH_LIBS -lcrypt"
    fi

    # Include globals and stubs
    OPENSSH_SRC="src/openssh_stubs.c src/openssh_globals.c"

    # Do not link shim if using real openssh (avoid dns symbol conflict)
    OPENSSH_SHIM=""
fi

# Build dash if present
DASH_DIR="third-party/dash"
if [ -d "$DASH_DIR" ] && [ ! -f "$DASH_DIR/src/dash" ]; then
    echo "Building dash..."
    # Git checkout needs autogen
    if [ ! -f "$DASH_DIR/configure" ]; then
        echo "Generating dash configure script..."
        (cd "$DASH_DIR" && ./autogen.sh)
    fi
    (cd "$DASH_DIR" && ./configure --enable-static && make -j4)
fi

if [ "$SMALLCLUE_WITH_DVTM" = "1" ]; then
    DVTM_DIR="third-party/dvtm"
    DVTM_BUILD_DIR="${DVTM_DIR}/.pscal-build"
    if [ ! -d "$DVTM_DIR" ] || [ ! -f "$DVTM_DIR/dvtm.c" ] || [ ! -f "$DVTM_DIR/vt.c" ] || [ ! -f "$DVTM_DIR/config.def.h" ]; then
        echo "Error: dvtm source tree is missing required files."
        echo "Run ./fetch_dependencies.sh and retry."
        exit 1
    fi

    mkdir -p "$DVTM_BUILD_DIR"
    cp "$DVTM_DIR/config.def.h" "$DVTM_BUILD_DIR/config.h"

    DVTM_PROBE_SRC="$DVTM_BUILD_DIR/curses_probe.c"
    cat > "$DVTM_PROBE_SRC" <<EOF
#include <curses.h>
#include <stdlib.h>
int main(void) { initscr(); endwin(); return 0; }
EOF

    for try_libs in "-lncursesw -lutil" "-lncursesw" "-lncurses -lutil" "-lncurses" "-lcurses -lutil" "-lcurses"; do
        if gcc -std=c99 -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700 -D_GNU_SOURCE ${EXTRA_C_DEFS} ${EXTRA_LD_FLAGS} \
            "$DVTM_PROBE_SRC" ${try_libs} -o "$DVTM_BUILD_DIR/curses_probe.bin" >/dev/null 2>&1; then
            DVTM_LIBS="$try_libs"
            break
        fi
    done

    if [ -z "$DVTM_LIBS" ]; then
        echo "Error: failed to locate a curses+util link combination for dvtm."
        echo "Tried: -lncursesw/-lncurses/-lcurses with and without -lutil."
        exit 1
    fi

    echo "Building dvtm applet support (${DVTM_LIBS})..."
    DVTM_COMMON_DEFS="-D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700 -D_XOPEN_SOURCE_EXTENDED -D_GNU_SOURCE ${EXTRA_C_DEFS} -DVERSION=\\\"0.16-pscal\\\" -Dexit=pscalDvtmRequestExit"
    gcc -std=c99 ${DVTM_COMMON_DEFS} -include "$DVTM_RUNTIME_HOOKS_HEADER" -I"$DVTM_BUILD_DIR" -I"$DVTM_DIR" -Isrc \
        -Dmain=dvtm_main_entry -c "$DVTM_DIR/dvtm.c" -o "$DVTM_BUILD_DIR/dvtm.o"
    gcc -std=c99 ${DVTM_COMMON_DEFS} -include "$DVTM_RUNTIME_HOOKS_HEADER" -I"$DVTM_BUILD_DIR" -I"$DVTM_DIR" -Isrc \
        -c "$DVTM_DIR/vt.c" -o "$DVTM_BUILD_DIR/vt.o"

    DVTM_OBJS="$DVTM_BUILD_DIR/dvtm.o $DVTM_BUILD_DIR/vt.o"
    DVTM_EXTRA_DEFS="-DSMALLCLUE_WITH_DVTM"
fi

if [ "$SMALLCLUE_WITH_LIBGIT2" = "1" ]; then
    LIBGIT2_DIR="third-party/libgit2"
    LIBGIT2_BUILD_DIR="${LIBGIT2_DIR}/.pscal-build"
    LIBGIT2_ARCHIVE=""
    if [ ! -d "$LIBGIT2_DIR" ] || [ ! -f "$LIBGIT2_DIR/CMakeLists.txt" ] || [ ! -f "$LIBGIT2_DIR/include/git2.h" ]; then
        echo "Error: libgit2 source tree is missing required files."
        echo "Run ./fetch_dependencies.sh and retry."
        exit 1
    fi
    if ! command -v cmake >/dev/null 2>&1; then
        echo "Error: cmake is required to build libgit2."
        exit 1
    fi
    CMAKE_GENERATOR_ARGS=""
    if command -v ninja >/dev/null 2>&1; then
        CMAKE_GENERATOR_ARGS="-G Ninja"
    fi
    echo "Building libgit2 applet support..."
    cmake -S "$LIBGIT2_DIR" -B "$LIBGIT2_BUILD_DIR" $CMAKE_GENERATOR_ARGS \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_SHARED_LIBS=OFF \
        -DBUILD_TESTS=OFF \
        -DBUILD_BENCHMARKS=OFF \
        -DBUILD_CLI=OFF \
        -DBUILD_EXAMPLES=OFF \
        -DBUILD_FUZZERS=OFF \
        -DUSE_SSH=OFF \
        -DUSE_HTTPS=ON \
        -DUSE_SHA1=builtin \
        -DUSE_SHA256=builtin \
        -DUSE_HTTP_PARSER=builtin \
        -DUSE_AUTH_NTLM=OFF \
        -DUSE_AUTH_NEGOTIATE=OFF \
        -DUSE_REGEX=builtin \
        -DUSE_COMPRESSION=builtin \
        -DUSE_I18N=OFF \
        -DENABLE_WERROR=OFF
    cmake --build "$LIBGIT2_BUILD_DIR" --target libgit2package -j4
    if [ -f "$LIBGIT2_BUILD_DIR/libgit2.a" ]; then
        LIBGIT2_ARCHIVE="$LIBGIT2_BUILD_DIR/libgit2.a"
    else
        LIBGIT2_ARCHIVE=$(find "$LIBGIT2_BUILD_DIR" -name "libgit2.a" -print | head -n 1 || true)
    fi
    if [ -z "$LIBGIT2_ARCHIVE" ] || [ ! -f "$LIBGIT2_ARCHIVE" ]; then
        echo "Error: libgit2 static archive not produced."
        exit 1
    fi
    LIBGIT2_EXTRA_DEFS="-DPSCAL_HAS_LIBGIT2"
    LIBGIT2_EXTRA_CFLAGS="-I${LIBGIT2_DIR}/include"
    LIBGIT2_LIBS="$LIBGIT2_ARCHIVE"
fi

gcc -std=c99 -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700 -D_GNU_SOURCE ${EXTRA_C_DEFS} ${DVTM_EXTRA_DEFS} ${LIBGIT2_EXTRA_DEFS} \
    ${LIBGIT2_EXTRA_CFLAGS} \
    -I. -Isrc ${EXTRA_LD_FLAGS} -lpthread \
    src/main.c \
    src/core.c \
    src/runtime_support.c \
    src/micro_app.c \
    src/dvtm_app.c \
    src/nextvi_app.c \
    ${NEXTVI_SRC} \
    ${OPENSSH_SRC} \
    ${OPENSSH_OBJS} \
    ${DVTM_OBJS} \
    src/openssh_app.c \
    src/vproc_test_app.c \
    src/micro_app.c \
    ${OPENSSH_SHIM} \
    src/runtime_stubs_extra.c \
    ${OPENSSH_LIBS} \
    ${DVTM_LIBS} \
    ${LIBGIT2_LIBS} \
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
mkdir -p "$ROOTFS"/{bin,sbin,usr/bin,usr/sbin,etc,tmp,var,home/username,dev,proc,sys,root}
chown -R 1000:1000 "$ROOTFS/home/username"
chmod 1777 "$ROOTFS/tmp"

# 4.5 Populate /dev
echo "Populating /dev..."
if [ "$(uname -s)" = "Linux" ]; then
    # Standard Linux device nodes
    # Try mknod first (some containers restrict this)
    USE_MKNOD=0
    if mknod -m 666 "$ROOTFS/dev/test_null" c 1 3 2>/dev/null; then
        rm -f "$ROOTFS/dev/test_null"
        USE_MKNOD=1
    fi

    if [ "$USE_MKNOD" -eq 1 ]; then
        echo "Creating devices using mknod..."
        mknod -m 666 "$ROOTFS/dev/null" c 1 3
        mknod -m 666 "$ROOTFS/dev/zero" c 1 5
        mknod -m 666 "$ROOTFS/dev/random" c 1 8
        mknod -m 666 "$ROOTFS/dev/urandom" c 1 9
        mknod -m 666 "$ROOTFS/dev/tty" c 5 0
        mknod -m 622 "$ROOTFS/dev/console" c 5 1
        mknod -m 666 "$ROOTFS/dev/ptmx" c 5 2

        # Verify that devices were actually created.
        # In some environments (e.g. certain container configurations), mknod might return
        # success but fail to create the node, or create it in a way that is not visible.
        if [ ! -c "$ROOTFS/dev/null" ]; then
            echo "Warning: mknod appeared to succeed but /dev/null is missing or not a char device."
            echo "Falling back to bind mounts..."
            USE_MKNOD=0
        fi
    fi

    if [ "$USE_MKNOD" -eq 0 ]; then
        echo "Notice: Using bind mounts for /dev..."
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

# 5. Install smallclue and dash
cp smallclue "$ROOTFS/bin/"
if [ -x "third-party/micro-bin/micro" ]; then
    echo "Installing micro..."
    cp "third-party/micro-bin/micro" "$ROOTFS/usr/bin/micro-real"
    chmod 755 "$ROOTFS/usr/bin/micro-real"
fi
if [ -f "third-party/openssh/sshd" ]; then
    echo "Installing sshd..."
    cp "third-party/openssh/sshd" "$ROOTFS/bin/sshd"
fi
if [ "$(uname -s)" = "Darwin" ] && [ -n "${SMALLCLUE_CODESIGN_IDENTITY:-}" ]; then
    codesign --force --timestamp=none --sign "${SMALLCLUE_CODESIGN_IDENTITY}" "$ROOTFS/bin/smallclue"
fi

if [ -f "third-party/dash/src/dash" ]; then
    echo "Installing dash..."
    cp "third-party/dash/src/dash" "$ROOTFS/bin/dash"
    mkdir -p "$ROOTFS/usr/share/doc/dash"
    cp "third-party/dash/COPYING" "$ROOTFS/usr/share/doc/dash/"
    # Symlink /bin/sh to dash
    ln -sf dash "$ROOTFS/bin/sh"
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
    # If dash is present, do not overwrite sh
    if [ "$applet" == "sh" ] && [ -f "$ROOTFS/bin/dash" ]; then
        continue
    fi
    ln -sf smallclue "$ROOTFS/bin/$applet"
done

# Init symlink
ln -sf /bin/smallclue "$ROOTFS/sbin/init"

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

echo "Creating /etc/shadow..."
cat > "$ROOTFS/etc/shadow" <<EOF
root:*:19700:0:99999:7:::
daemon:*:19700:0:99999:7:::
bin:*:19700:0:99999:7:::
sys:*:19700:0:99999:7:::
sync:*:19700:0:99999:7:::
games:*:19700:0:99999:7:::
man:*:19700:0:99999:7:::
lp:*:19700:0:99999:7:::
proxy:*:19700:0:99999:7:::
www-data:*:19700:0:99999:7:::
backup:*:19700:0:99999:7:::
list:*:19700:0:99999:7:::
nobody:*:19700:0:99999:7:::
sshd:*:19700:0:99999:7:::
username::19700:0:99999:7:::
EOF
chmod 600 "$ROOTFS/etc/shadow"

echo "Creating /etc/profile..."
cat > "$ROOTFS/etc/profile" <<EOF
# System-wide profile
export PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin

# Run /etc/rc if present and not already run
if [ -x /etc/rc ] && [ ! -f /tmp/rc_ran ]; then
    /etc/rc
fi
EOF
chmod 644 "$ROOTFS/etc/profile"

echo "Creating .exshrc..."
cat > "$ROOTFS/home/username/.exshrc" <<EOF
# Minimal .exshrc
echo "Loading .exshrc..."
EOF
chown 1000:1000 "$ROOTFS/home/username/.exshrc"

echo "Creating .profile..."
cat > "$ROOTFS/home/username/.profile" <<EOF
export ENV=\$HOME/.dashrc
export PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin
EOF
chown 1000:1000 "$ROOTFS/home/username/.profile"

echo "Creating .dashrc..."
cat > "$ROOTFS/home/username/.dashrc" <<EOF
# Basic dash configuration

# Get username if not set
if [ -z "\$USER" ]; then
    USER=\$(id | cut -d \( -f2 | cut -d \) -f1)
fi

# Get hostname
if [ -f /etc/hostname ]; then
    HOSTNAME=\$(cat /etc/hostname)
else
    HOSTNAME=\$(uname -n)
fi

# Check for root
MY_UID=\$(id | cut -d = -f2 | cut -d \( -f1)
if [ "\$MY_UID" = "0" ]; then
    PS1='\${USER}@\${HOSTNAME}:\${PWD}# '
else
    PS1='\${USER}@\${HOSTNAME}:\${PWD}\$ '
fi

# Aliases
alias ll='ls -al'
alias la='ls -A'
alias l='ls -CF'
alias ls='ls --color=auto'
EOF
chown 1000:1000 "$ROOTFS/home/username/.dashrc"

echo "Creating root .profile..."
cat > "$ROOTFS/root/.profile" <<EOF
export ENV=\$HOME/.dashrc
export PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin
EOF

echo "Creating root .dashrc..."
cat > "$ROOTFS/root/.dashrc" <<EOF
# Basic dash configuration

# Get username if not set
if [ -z "\$USER" ]; then
    USER=\$(id | cut -d \( -f2 | cut -d \) -f1)
fi

# Get hostname
if [ -f /etc/hostname ]; then
    HOSTNAME=\$(cat /etc/hostname)
else
    HOSTNAME=\$(uname -n)
fi

# Check for root
MY_UID=\$(id | cut -d = -f2 | cut -d \( -f1)
if [ "\$MY_UID" = "0" ]; then
    PS1='\${USER}@\${HOSTNAME}:\${PWD}# '
else
    PS1='\${USER}@\${HOSTNAME}:\${PWD}\$ '
fi

# Aliases
alias ll='ls -al'
alias la='ls -A'
alias l='ls -CF'
alias ls='ls --color=auto'
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

echo "Creating /etc/hosts..."
cat > "$ROOTFS/etc/hosts" <<EOF
127.0.0.1   localhost
127.0.1.1   smallclue

::1         localhost ip6-localhost ip6-loopback
ff02::1     ip6-allnodes
ff02::2     ip6-allrouters
EOF

echo "Creating /etc/hostname..."
echo "smallclue" > "$ROOTFS/etc/hostname"

echo "Setting up SSH..."
mkdir -p "$ROOTFS/var/empty"
mkdir -p "$ROOTFS/run/sshd"
mkdir -p "$ROOTFS/etc/ssh"

if [ ! -f "$ROOTFS/etc/ssh/ssh_host_rsa_key" ]; then
    echo "Generating SSH host keys..."
    ssh-keygen -t rsa -f "$ROOTFS/etc/ssh/ssh_host_rsa_key" -N "" -q
    ssh-keygen -t ecdsa -f "$ROOTFS/etc/ssh/ssh_host_ecdsa_key" -N "" -q
    ssh-keygen -t ed25519 -f "$ROOTFS/etc/ssh/ssh_host_ed25519_key" -N "" -q
fi

cat > "$ROOTFS/etc/ssh/sshd_config" <<EOF
Port 22
PermitRootLogin yes
PasswordAuthentication yes
PermitEmptyPasswords yes
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
AuthorizedKeysFile .ssh/authorized_keys
Subsystem sftp internal-sftp
EOF

echo "Creating /etc/rc..."
cat > "$ROOTFS/etc/rc" <<EOF
#!/bin/sh
touch /tmp/rc_ran
echo "Welcome to SmallClue POSIX Environment!"
echo "Mounting filesystems..."
# mount -t proc proc /proc
# mount -t sysfs sys /sys
# mount -t devtmpfs dev /dev
echo "Starting services..."
/bin/sshd -f /etc/ssh/sshd_config
echo "Done."
exec /bin/sh -l
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
