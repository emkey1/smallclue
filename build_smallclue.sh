#!/bin/bash
set -e

# Builds ./smallclue in the current directory: fetches/patches third-party
# deps if needed, generates the small static stub sources (build_info.h,
# openssh_globals.c, runtime_stubs_extra.c, pscal_runtime_hooks.h --
# CMake standalone builds do this too, see CMakeLists.txt), configures and
# builds OpenSSH, dvtm, and libgit2, then compiles and links smallclue.
#
# None of this needs root -- only setup_posix_env.sh's rootfs/chroot
# assembly (steps past this script) does. setup_posix_env.sh calls this
# script as its first step; run it directly if you just want the binary.

SMALLCLUE_SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
DVTM_RUNTIME_HOOKS_HEADER="${SMALLCLUE_SCRIPT_DIR}/src/dvtm_runtime_hooks.h"

# 0. Check for dependencies
MISSING_DEPS=0
if [ ! -e "third-party/nextvi/.git" ]; then
    echo "Nextvi repository missing or incomplete."
    MISSING_DEPS=1
fi
if [ ! -d "third-party/openssh" ] || [ ! -f "third-party/openssh/ssh.c" ] || [ ! -f "third-party/openssh/scp.c" ] || [ ! -f "third-party/openssh/sftp.c" ] || [ ! -f "third-party/openssh/configure.ac" ]; then
    echo "OpenSSH repository missing or incomplete."
    MISSING_DEPS=1
fi
if [ ! -e "third-party/dvtm/.git" ] || [ ! -f "third-party/dvtm/dvtm.c" ] || [ ! -f "third-party/dvtm/vt.c" ] || [ ! -f "third-party/dvtm/config.def.h" ]; then
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

/* exsh stubs removed: standalone builds use smallclue's built-in sh */

/* core.c's applet table references these unconditionally (git/rsync entries
 * aren't ifdef-guarded), but their real implementations (src/git_app.c,
 * src/openrsync_app.c) need libgit2/the vendored openrsync tree, which this
 * script only builds when SMALLCLUE_WITH_LIBGIT2=1 / openrsync is fetched.
 * Weak so the real, strong definition (when those sources are compiled in
 * below) silently wins the link over this fallback. */
__attribute__((weak)) int smallclueGitCommand(int argc, char **argv) {
    (void)argc;
    (void)argv;
    fprintf(stderr, "git: not built in this configuration (libgit2 unavailable)\n");
    return 127;
}

__attribute__((weak)) int smallclueRunRsync(int argc, char **argv) {
    (void)argc;
    (void)argv;
    fprintf(stderr, "rsync: real-protocol client not built in this configuration (openrsync unavailable)\n");
    return 127;
}
EOF

# 3. Compile smallclue
echo "Compiling smallclue..."
EXTRA_C_DEFS=""
EXTRA_C_INCLUDES=""
EXTRA_LD_FLAGS=""
# _POSIX_C_SOURCE/_XOPEN_SOURCE/_GNU_SOURCE are only safe to force on
# non-Darwin: combined with _DARWIN_C_SOURCE on macOS they still hide BSD
# extensions like chroot(2) from unistd.h ("call to undeclared function
# 'chroot'"), matching CMakeLists.txt's own Apple-vs-not branch, which never
# sets _POSIX_C_SOURCE at all on Apple.
PORTABILITY_DEFS="-D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700 -D_GNU_SOURCE"
if [ "$(uname -s)" = "Darwin" ]; then
    PORTABILITY_DEFS=""
    # Keep BSD typedefs (u_int/u_char/u_short) visible in macOS SDK networking headers.
    EXTRA_C_DEFS="-D_DARWIN_C_SOURCE"
    # macOS ships no libcrypto/libssl headers or libs in the SDK; point the
    # compile and final link at the same OpenSSL the OpenSSH configure step
    # found (homebrew, typically).
    for ssl_prefix in "$(brew --prefix openssl@3 2>/dev/null)" /opt/homebrew/opt/openssl@3 /usr/local/opt/openssl@3; do
        if [ -n "$ssl_prefix" ] && [ -d "$ssl_prefix/include" ] && [ -d "$ssl_prefix/lib" ]; then
            EXTRA_C_INCLUDES="-I$ssl_prefix/include"
            EXTRA_LD_FLAGS="-L$ssl_prefix/lib"
            break
        fi
    done
fi
EXTRA_TAIL_LIBS=""
if [ "$(uname -s)" = "Linux" ]; then
    EXTRA_LD_FLAGS="-static"
    # awk_interp.c's math builtins (sin/cos/exp/log/sqrt/atan2/fmod/pow/...)
    # and crypt() (su, OpenSSH) are in libm/libcrypt on glibc, unlike Darwin
    # where both are folded into libSystem. With -static, library order
    # matters -- these must come after every object that references them,
    # so they're appended at the very end of the link line, not here.
    #
    # -lssl -lcrypto here too: libgit2.a's openssl.c.o (built with
    # USE_HTTPS=ON) needs SSL_*/SSL_CTX_* symbols. OPENSSH_LIBS already
    # carries its own -lcrypto earlier in the link line (for OpenSSH's own
    # crypto use), but that's BEFORE ${LIBGIT2_LIBS} -- static linking is a
    # single left-to-right pass, so by the time ld reaches libgit2.a's
    # unresolved SSL_* refs it's already past that -lcrypto and never looks
    # back ("undefined reference to SSL_connect" etc). Re-listing both here,
    # after LIBGIT2_LIBS, resolves it the same way CMakeLists.txt's own
    # libgit2 target_link_libraries ordering already does.
    EXTRA_TAIL_LIBS="-lm -lcrypt -lssl -lcrypto"
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
                # Retry relaxing the OpenSSL header/library version cross-check:
                # some systems (e.g. a locally-built OpenSSL alongside an older
                # system libcrypto) have headers and library reporting different
                # versions even though they're ABI-compatible for our purposes.
                echo "OpenSSH configure failed; retrying with --without-openssl-header-check..."
                if ! (cd "$OPENSSH_DIR" && env "${OPENSSH_CONFIG_ENV[@]}" ./configure "${OPENSSH_CONFIG_ARGS[@]}" --without-openssl-header-check); then
                    echo "Error: OpenSSH configure failed."
                    if [ -f "$OPENSSH_DIR/config.log" ]; then
                        echo "See: $OPENSSH_DIR/config.log"
                    fi
                    exit 1
                fi
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

    # sftp-client.c. The pscal_openssh_ checks make these idempotent: the
    # plain substring guards used to match their own output, stacking the
    # prefix on every rebuild (pscal_openssh_pscal_openssh_...).
    if grep -q "interrupted" "$OPENSSH_DIR/sftp-client.c" && \
       ! grep -q "pscal_openssh_interrupted" "$OPENSSH_DIR/sftp-client.c"; then
        sed -i.bak 's/interrupted/pscal_openssh_interrupted/g' "$OPENSSH_DIR/sftp-client.c"
        rm -f "$OPENSSH_DIR/sftp-client.c.bak"
    fi
    if grep -q "showprogress" "$OPENSSH_DIR/sftp-client.c" && \
       ! grep -q "pscal_openssh_showprogress" "$OPENSSH_DIR/sftp-client.c"; then
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
    if [ "$(uname -s)" = "Darwin" ]; then
        # openbsd-compat's getrrsetbyname uses the BIND resolver state.
        OPENSSH_LIBS="$OPENSSH_LIBS -lresolv"
    fi

    # Include globals and stubs
    OPENSSH_SRC="src/openssh_stubs.c src/openssh_globals.c"

    # Do not link shim if using real openssh (avoid dns symbol conflict)
    OPENSSH_SHIM=""
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

    # Debian/glibc splits terminfo out of libncurses*.a for STATIC linking
    # (dynamic linking doesn't need this -- libncurses.so already pulls
    # tinfo symbols in via its own NEEDED entry). A static-only build (our
    # EXTRA_LD_FLAGS=-static path) sees undefined references to `SP`/
    # `_nc_screen_of`/etc without an explicit -ltinfo, even though
    # libncursesw.a/libncurses.a themselves link fine dynamically. Every
    # existing combo gets a -ltinfo-augmented counterpart so this doesn't
    # regress platforms where tinfo is already folded into libncurses*.a.
    for try_libs in "-lncursesw -lutil" "-lncursesw" \
                     "-lncursesw -lutil -ltinfo" "-lncursesw -ltinfo" \
                     "-lncurses -lutil" "-lncurses" \
                     "-lncurses -lutil -ltinfo" "-lncurses -ltinfo" \
                     "-lcurses -lutil" "-lcurses"; do
        if gcc -std=c99 -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700 -D_GNU_SOURCE ${EXTRA_C_DEFS} ${EXTRA_LD_FLAGS} \
            "$DVTM_PROBE_SRC" ${try_libs} -o "$DVTM_BUILD_DIR/curses_probe.bin" >/dev/null 2>&1; then
            DVTM_LIBS="$try_libs"
            break
        fi
    done

    if [ -z "$DVTM_LIBS" ]; then
        echo "Error: failed to locate a curses+util link combination for dvtm."
        echo "Tried: -lncursesw/-lncurses/-lcurses with and without -lutil/-ltinfo."
        exit 1
    fi

    echo "Building dvtm applet support (${DVTM_LIBS})..."
    # DVTM_COMMON_DEFS is expanded unquoted below (plain word-splitting, no
    # eval/second shell parse) so it must hold the RAW argv text gcc expects
    # -- one literal backslash-quote per side, not a double-escaped pair.
    DVTM_COMMON_DEFS="-D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700 -D_XOPEN_SOURCE_EXTENDED -D_GNU_SOURCE ${EXTRA_C_DEFS} -DVERSION=\"0.16-pscal\" -Dexit=pscalDvtmRequestExit"
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
        -DUSE_SHA1=OpenSSL \
        -DUSE_SHA256=OpenSSL \
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
    if [ "$(uname -s)" = "Darwin" ]; then
        # libgit2's HTTPS/keychain backends use SecureTransport on macOS.
        LIBGIT2_LIBS="$LIBGIT2_LIBS -framework Security -framework CoreFoundation -liconv"
    fi
fi

gcc -std=c99 ${PORTABILITY_DEFS} -DSMALLCLUE_WITH_SH ${EXTRA_C_DEFS} ${DVTM_EXTRA_DEFS} ${LIBGIT2_EXTRA_DEFS} \
    ${LIBGIT2_EXTRA_CFLAGS} \
    -I. -Isrc ${EXTRA_C_INCLUDES} ${EXTRA_LD_FLAGS} -lpthread \
    src/main.c \
    src/core.c \
    src/runtime_support.c \
    src/micro_app.c \
    src/micro_main_stub.c \
    src/dvtm_app.c \
    src/nextvi_app.c \
    ${NEXTVI_SRC} \
    ${OPENSSH_SRC} \
    ${OPENSSH_OBJS} \
    ${DVTM_OBJS} \
    src/openssh_app.c \
    src/vproc_test_app.c \
    src/shell/lexer.c \
    src/shell/parser.c \
    src/shell/ast.c \
    src/shell/sh_utils.c \
    src/shell/sh_var.c \
    src/shell/sh_astcopy.c \
    src/shell/sh_expand.c \
    src/shell/sh_arith.c \
    src/shell/sh_exec.c \
    src/shell/sh_builtins.c \
    src/shell/sh_lineedit.c \
    src/shell/sh_main.c \
    ${OPENSSH_SHIM} \
    src/runtime_stubs_extra.c \
    src/awk_lexer.c \
    src/awk_parser.c \
    src/awk_value.c \
    src/awk_interp.c \
    src/awk_app.c \
    src/base64_app.c \
    src/checksum_app.c \
    src/chown_app.c \
    src/chroot_app.c \
    src/cmp_app.c \
    src/comm_app.c \
    src/dd_app.c \
    src/diff_app.c \
    src/expr_app.c \
    src/fmt_app.c \
    src/fold_app.c \
    src/gzip_app.c \
    src/nl_app.c \
    src/nohup_app.c \
    src/od_app.c \
    src/paste_app.c \
    src/patch_app.c \
    src/printf_app.c \
    src/readlink_app.c \
    src/rev_app.c \
    src/seq_app.c \
    src/split_app.c \
    src/tac_app.c \
    src/tar_app.c \
    ${OPENSSH_LIBS} \
    ${DVTM_LIBS} \
    ${LIBGIT2_LIBS} \
    ${EXTRA_TAIL_LIBS} \
    -o smallclue

if [ ! -f smallclue ]; then
    echo "Compilation failed."
    exit 1
fi

if [ "$(uname -s)" = "Darwin" ] && [ -n "${SMALLCLUE_CODESIGN_IDENTITY:-}" ]; then
    echo "Signing smallclue with identity: ${SMALLCLUE_CODESIGN_IDENTITY}"
    codesign --force --timestamp=none --sign "${SMALLCLUE_CODESIGN_IDENTITY}" smallclue
fi
