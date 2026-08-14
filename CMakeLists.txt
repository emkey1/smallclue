cmake_minimum_required(VERSION 3.10)

# Project Definition
project(smallclue C)

# Set C Standard (C99 or C11 recommended)
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS ON) # Enable compiler-specific extensions (useful for POSIX/BSD functions)

# Options for build configuration
option(ENABLE_CURL "Enable curl support (requires libcurl)" ON)
option(ENABLE_IOS_TARGET "Enable iOS specific build flags (PSCAL_TARGET_IOS)" OFF)
option(WITH_EXSH "Include exsh shell integration" OFF)

# Add preprocessor definitions based on system
if(APPLE)
    add_definitions(-D__APPLE__)
    # For compatibility with Apple's availability macros if needed
    add_definitions(-D_DARWIN_C_SOURCE)
elseif(UNIX AND NOT APPLE)
    add_definitions(-D_POSIX_C_SOURCE=200809L)
    add_definitions(-D_XOPEN_SOURCE=700)
    add_definitions(-D_GNU_SOURCE) # For older glibc
endif()

if(ENABLE_IOS_TARGET)
    add_definitions(-DPSCAL_TARGET_IOS)
endif()

# Find dependencies
find_package(Threads REQUIRED)

if(ENABLE_CURL)
    # Same static-vs-shared story as the FTS_LIBRARY/BSD_LIBRARY/ZLIB/OpenSSL
    # lookups further down this file: this build links fully static on
    # UNIX-and-not-Apple (see the target_link_options(-static) block below),
    # and find_package(CURL) defaults to preferring libcurl.so, which a
    # static link can't use ("attempted static link of dynamic object").
    # Prefer the .a explicitly; libcurl4-openssl-dev/libcurl-dev ship both.
    if(UNIX AND NOT APPLE)
        set(_smallclue_saved_lib_suffixes ${CMAKE_FIND_LIBRARY_SUFFIXES})
        set(CMAKE_FIND_LIBRARY_SUFFIXES .a ${CMAKE_FIND_LIBRARY_SUFFIXES})
    endif()
    find_package(CURL)
    if(UNIX AND NOT APPLE)
        set(CMAKE_FIND_LIBRARY_SUFFIXES ${_smallclue_saved_lib_suffixes})
    endif()

    if(CURL_FOUND AND UNIX AND NOT APPLE)
        # A .a on disk doesn't mean it can actually finish a *static* link:
        # curl packages commonly need gssapi/nghttp2/zstd/brotli/... too,
        # and which of those apply depends on how this system's curl was
        # built. Rather than hand-enumerate that transitive set (fragile,
        # distro-specific, and some of it is unfixable from here at all --
        # Debian/Ubuntu never ships a static libgssapi_krb5.a, because MIT
        # krb5's mechanism-glue plugins are designed around dlopen, not
        # static linking), actually attempt the static link and see.
        include(CheckCSourceCompiles)
        set(_smallclue_saved_req_flags "${CMAKE_REQUIRED_FLAGS}")
        set(_smallclue_saved_req_libs "${CMAKE_REQUIRED_LIBRARIES}")
        set(_smallclue_saved_req_incs "${CMAKE_REQUIRED_INCLUDES}")
        set(CMAKE_REQUIRED_FLAGS "-static")
        set(CMAKE_REQUIRED_LIBRARIES ${CURL_LIBRARIES})
        set(CMAKE_REQUIRED_INCLUDES ${CURL_INCLUDE_DIRS})
        check_c_source_compiles("
#include <curl/curl.h>
int main(void) {
    curl_global_init(CURL_GLOBAL_DEFAULT);
    CURL *h = curl_easy_init();
    curl_easy_cleanup(h);
    curl_global_cleanup();
    return 0;
}
" SMALLCLUE_CURL_STATIC_LINKS)
        set(CMAKE_REQUIRED_FLAGS "${_smallclue_saved_req_flags}")
        set(CMAKE_REQUIRED_LIBRARIES "${_smallclue_saved_req_libs}")
        set(CMAKE_REQUIRED_INCLUDES "${_smallclue_saved_req_incs}")
        if(NOT SMALLCLUE_CURL_STATIC_LINKS)
            message(WARNING "libcurl was found but a real static test-link against it failed in this environment (commonly: this system's curl needs gssapi, and Debian/Ubuntu never ships a static libgssapi_krb5.a at all). Falling back to a vendored static curl build instead of this system package.")
            set(CURL_FOUND FALSE)
        endif()
    endif()

    # The system package is missing, or its static link just failed above --
    # build our own static libcurl from vendored source instead of the
    # system one. The Debian/Ubuntu failure this exists to work around is
    # specifically that their libcurl4-openssl-dev is built with GSS-
    # Negotiate (gssapi) support baked in, and gssapi/nghttp2/libidn2 are all
    # auto-probed by curl's own ./configure whenever the matching dev
    # package happens to be present on the *build* system -- rather than
    # hand-enumerate and strip each one back out of a moving-target system
    # curl (fragile, distro-specific, and the gssapi case is flatly
    # unfixable there at all -- see above), vendor upstream curl's own
    # release source (fetched by fetch_dependencies.sh, same tarball-fetch
    # pattern as OpenSSH below) and build it ourselves with those features
    # explicitly turned off from the start, so the collision this whole
    # block exists to catch can't recur no matter what else happens to be
    # installed on the build machine.
    if(NOT CURL_FOUND AND UNIX AND NOT APPLE)
        if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/third-party/curl/configure)
            find_program(SMALLCLUE_MAKE NAMES make gmake)
            if(NOT SMALLCLUE_MAKE)
                message(WARNING "make not found; can't build the vendored static curl. Building without curl support.")
            else()
                # curl ships its own autotools ./configure (pre-generated in
                # the release tarball fetch_dependencies.sh downloads, no
                # autoreconf needed) -- ExternalProject_Add's CMAKE_ARGS form
                # doesn't apply here since curl isn't a CMake project;
                # CONFIGURE_COMMAND/BUILD_COMMAND/INSTALL_COMMAND drive its
                # configure/make/make-install directly instead. Deliberately
                # not ${CMAKE_MAKE_PROGRAM} for BUILD_COMMAND/INSTALL_COMMAND:
                # that's whatever the *outer* project's generator uses (e.g.
                # ninja, which can't read curl's autotools-generated
                # Makefile), not necessarily plain make.
                include(ExternalProject)
                set(CURL_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third-party/curl)
                set(CURL_PREFIX ${CMAKE_CURRENT_BINARY_DIR}/curl-build)
                set(CURL_INSTALL_DIR ${CURL_PREFIX}/install)
                set(SMALLCLUE_CURL_STATIC_LIBRARY ${CURL_INSTALL_DIR}/lib/libcurl.a)
                ExternalProject_Add(curl_external
                    SOURCE_DIR ${CURL_SOURCE_DIR}
                    PREFIX ${CURL_PREFIX}
                    CONFIGURE_COMMAND ${CURL_SOURCE_DIR}/configure
                        --prefix=${CURL_INSTALL_DIR}
                        CC=${CMAKE_C_COMPILER}
                        --disable-shared
                        --enable-static
                        --with-openssl
                        --without-nghttp2
                        --without-libssh2
                        --without-libpsl
                        --without-brotli
                        --without-zstd
                        --without-libidn2
                        --disable-ldap
                        --disable-ldaps
                        --without-gssapi
                        --disable-manual
                    BUILD_COMMAND ${SMALLCLUE_MAKE}
                    INSTALL_COMMAND ${SMALLCLUE_MAKE} install
                    BUILD_BYPRODUCTS ${SMALLCLUE_CURL_STATIC_LIBRARY}
                    BUILD_IN_SOURCE 0
                )
                set(CURL_FOUND TRUE)
                set(SMALLCLUE_CURL_VENDORED TRUE)
                set(CURL_INCLUDE_DIRS ${CURL_INSTALL_DIR}/include)
                set(CURL_LIBRARIES ${SMALLCLUE_CURL_STATIC_LIBRARY})
            endif()
        else()
            message(WARNING "third-party/curl missing; run ./fetch_dependencies.sh to vendor a static-link-safe curl build. Building without curl support.")
        endif()
    endif()

    if(CURL_FOUND)
        add_definitions(-DPSCAL_HAS_LIBCURL)
        include_directories(${CURL_INCLUDE_DIRS})
    else()
        message(WARNING "CURL not found or not usable. Building without curl support.")
        set(ENABLE_CURL OFF)
    endif()
endif()

# Include directories
# Assuming directory structure:
#   CMakeLists.txt
#   src/
#   common/ (required by core.c includes)
#   third-party/ (required by openssh_app.c)
include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/common
    ${CMAKE_CURRENT_SOURCE_DIR}/third-party/nextvi
    ${CMAKE_CURRENT_SOURCE_DIR}/third-party/openssh
    ${CMAKE_CURRENT_SOURCE_DIR}/third-party/openssh/openbsd-compat
)

# openrsync lives in PSCAL's third-party tree when smallclue is the
# src/smallclue submodule; standalone checkouts can put it in their own
# third-party/ instead.
set(OPENRSYNC_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../../third-party/openrsync)
if(NOT EXISTS ${OPENRSYNC_ROOT}/config_pscal.h AND
   EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/third-party/openrsync/config_pscal.h)
    set(OPENRSYNC_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/third-party/openrsync)
endif()
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/generated/openrsync)
configure_file(${OPENRSYNC_ROOT}/config_pscal.h
    ${CMAKE_CURRENT_BINARY_DIR}/generated/openrsync/config.h COPYONLY)

# --- Standalone-build stub generation -------------------------------------
# setup_posix_env.sh/setup_ish_env.sh (rootfs-oriented, require sudo) also
# write these files as a side effect, with identical static content. For a
# plain standalone `cmake .. && cmake --build .` (no rootfs needed), generate
# them here instead so the build doesn't require root just to get source
# files that have no system-specific content. Never overwrites an existing
# file, so PSCAL/rootfs builds that already generated these are untouched.
if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/src/core/build_info.h)
    file(WRITE ${CMAKE_CURRENT_SOURCE_DIR}/src/core/build_info.h
"#ifndef BUILD_INFO_H
#define BUILD_INFO_H
#define BUILD_VERSION \"1.0.0-test\"
#include <stdbool.h>
#include <stddef.h>
bool pscalRuntimeStderrIsInteractive(void);
const char *pscal_program_version_string(void);
bool pathTruncateEnabled(void);
bool pathTruncateStrip(const char *path, char *buffer, size_t buflen);
#endif
")
endif()

if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/third-party/openssh AND
   NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/third-party/openssh/pscal_runtime_hooks.h)
    file(WRITE ${CMAKE_CURRENT_SOURCE_DIR}/third-party/openssh/pscal_runtime_hooks.h
"#ifndef PSCAL_RUNTIME_HOOKS_H
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
")
endif()

if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/third-party/ios_system/ssh_keygen/sshkey.h)
    file(MAKE_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/third-party/ios_system/ssh_keygen)
    file(WRITE ${CMAKE_CURRENT_SOURCE_DIR}/third-party/ios_system/ssh_keygen/sshkey.h
"#ifndef SSHKEY_H
#define SSHKEY_H
struct sshkey {
    int dummy;
};
#endif
")
endif()

if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/src/openssh_globals.c)
    file(WRITE ${CMAKE_CURRENT_SOURCE_DIR}/src/openssh_globals.c
"#include <signal.h>
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
")
endif()

if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime_stubs_extra.c)
    file(WRITE ${CMAKE_CURRENT_SOURCE_DIR}/src/runtime_stubs_extra.c
"#include \"smallclue.h\"
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
    return \"1.0.0-test\";
}

bool pathTruncateEnabled(void) {
    return false;
}

bool pathTruncateStrip(const char *path, char *buffer, size_t buflen) {
    if (!path || !buffer || buflen == 0) return false;
    strncpy(buffer, path, buflen - 1);
    buffer[buflen - 1] = '\\0';
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
    fprintf(stderr, \"git: not built in this configuration (libgit2 unavailable)\\n\");
    return 127;
}

__attribute__((weak)) int smallclueRunRsync(int argc, char **argv) {
    (void)argc;
    (void)argv;
    fprintf(stderr, \"rsync: real-protocol client not built in this configuration (openrsync unavailable)\\n\");
    return 127;
}
")
endif()

if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/third-party/openssh AND
   NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/third-party/openssh/config.h)
    message(FATAL_ERROR
        "third-party/openssh/config.h is missing -- OpenSSH hasn't been "
        "configured yet. From third-party/openssh, run:\n"
        "    ./configure --sysconfdir=/etc/ssh\n"
        "(on macOS, point CPPFLAGS/LDFLAGS/PKG_CONFIG_PATH at your OpenSSL "
        "install first, e.g. via `brew --prefix openssl@3`). "
        "See setup_posix_env.sh's OpenSSH configure step for the exact flags "
        "used on Linux/macOS if `./configure` fails outright.")
endif()

# Source files
set(NEXTVI_SOURCES third-party/nextvi/vi.c)

file(GLOB_RECURSE OPENSSH_SOURCES CONFIGURE_DEPENDS
    third-party/openssh/*.c
)
list(FILTER OPENSSH_SOURCES EXCLUDE REGEX "openbsd-compat/regress/")
list(FILTER OPENSSH_SOURCES EXCLUDE REGEX "/ssh-agent\\.c$")
list(FILTER OPENSSH_SOURCES EXCLUDE REGEX "/ssh-add\\.c$")
list(FILTER OPENSSH_SOURCES EXCLUDE REGEX "/auth2-gss\\.c$")
list(FILTER OPENSSH_SOURCES EXCLUDE REGEX "/gss-genr\\.c$")
# Drop server/auth-only sources; keep client pieces like authfd/authfile.
list(FILTER OPENSSH_SOURCES EXCLUDE REGEX "/auth2-.*\\.c$")
list(FILTER OPENSSH_SOURCES EXCLUDE REGEX "/auth-(passwd|rhosts|shadow).*\\.c$")
list(FILTER OPENSSH_SOURCES EXCLUDE REGEX "/monitor.*\\.c$")
list(FILTER OPENSSH_SOURCES EXCLUDE REGEX "/sshd.*\\.c$")
list(FILTER OPENSSH_SOURCES EXCLUDE REGEX "/servconf\\.c$")
list(FILTER OPENSSH_SOURCES EXCLUDE REGEX "/session\\.c$")
list(FILTER OPENSSH_SOURCES EXCLUDE REGEX "/sandbox-.*\\.c$")
list(FILTER OPENSSH_SOURCES EXCLUDE REGEX "/ssh-keysign\\.c$")
list(FILTER OPENSSH_SOURCES EXCLUDE REGEX "/ssh-pkcs11-helper\\.c$")
# ssh-pkcs11.c is the direct (dlopen-based) PKCS11 provider implementation,
# meant to be compiled only inside the ssh-pkcs11-helper subprocess (just
# excluded above). The actual client-side entry point sshconnect2.c/
# ssh-keygen.c call into is ssh-pkcs11-client.c, which talks to that helper
# over IPC -- keeping both in the same binary is a straight duplicate-symbol
# collision (both define pkcs11_add_provider/_terminate/_key_free/etc).
# cleanup.c's cleanup_exit() is explicitly commented "default implementation"
# (just _exit(i)) -- clientloop.c defines a fuller client-specific override
# (restores terminal raw mode, kills any ssh mux proxy command) that's a
# strict superset and safely no-ops those extra steps when not actually
# running the interactive ssh client (leave_raw_mode/ssh_kill_proxy_command
# check their own state and do nothing if ssh never initialized it). With
# every openssh client program now in one binary, only one cleanup_exit can
# exist; drop the trivial one and let clientloop.c's serve everyone.
list(FILTER OPENSSH_SOURCES EXCLUDE REGEX "/cleanup\\.c$")
list(FILTER OPENSSH_SOURCES EXCLUDE REGEX "/ssh-pkcs11\\.c$")
list(FILTER OPENSSH_SOURCES EXCLUDE REGEX "/sftp-server\\.c$")
list(FILTER OPENSSH_SOURCES EXCLUDE REGEX "/sftp-server-main\\.c$")
# sftp-realpath.c provides a local-filesystem-path sftp_realpath(path,
# resolved) (its own comment: "XXX rewrite sftp-server to use POSIX
# realpath") used only by the just-excluded sftp-server.c. It collides with
# the unrelated client-protocol sftp_realpath(conn, path) in sftp-client.c
# (sends an SFTP REALPATH request to the remote), which is what the actual
# sftp client (sftp.c) calls.
list(FILTER OPENSSH_SOURCES EXCLUDE REGEX "/sftp-realpath\\.c$")
list(FILTER OPENSSH_SOURCES EXCLUDE REGEX "/sshsig\\.c$")
# These four have generic-sounding names but are exclusively sshd (server)
# infrastructure -- auth.c/auth2.c back the privsep monitor's authentication
# state machine, sshlogin.c/serverloop.c back utmp/lastlog accounting and the
# server's own select loop. None of ssh.c/sshconnect*.c/scp.c/sftp.c/
# sftp-client.c call into them; they were missed by the patterns above and,
# once their own server-only callees (auth2-*.c, monitor*.c, session.c,
# servconf.c, loginrec.c) are filtered out, they fail to link.
list(FILTER OPENSSH_SOURCES EXCLUDE REGEX "/auth\\.c$")
list(FILTER OPENSSH_SOURCES EXCLUDE REGEX "/auth2\\.c$")
list(FILTER OPENSSH_SOURCES EXCLUDE REGEX "/sshlogin\\.c$")
list(FILTER OPENSSH_SOURCES EXCLUDE REGEX "/serverloop\\.c$")
list(FILTER OPENSSH_SOURCES EXCLUDE REGEX "/platform-pledge\\.c$")
list(FILTER OPENSSH_SOURCES EXCLUDE REGEX "/platform-tracing\\.c$")
# dns.c backs VerifyHostKeyDNS (looking up SSHFP records to confirm a host
# key), but src/openssh_shim.c already provides a deliberate stub
# verify_host_key_dns() ("DNS SSHFP lookups disabled in this build") --
# dns.c was missed by the exclusion patterns above, so it was being
# compiled in as dead weight, colliding with that stub (duplicate symbol)
# once its own missing getrrsetbyname()/freerrset() dependency is resolved
# by *not* excluding it. Exclude dns.c itself instead of re-adding
# getrrsetbyname.c/-ldns.c; DNS SSHFP support stays off, matching intent.
list(FILTER OPENSSH_SOURCES EXCLUDE REGEX "/dns\\.c$")
list(FILTER OPENSSH_SOURCES EXCLUDE REGEX "/getrrsetbyname.*\\.c$")
# ssh-sk-helper (FIDO2 security-key subprocess) and ssh-keyscan (standalone
# host-key scanner) are separate mini-programs with their own main(), never
# wired up as smallclue applets (no ssh-sk-helper/ssh-keyscan entries in the
# applet table) -- same category as the already-excluded ssh-agent.c/
# ssh-add.c. Left in, they collide with src/main.c's real main() at link
# time since only ssh.c/scp.c/sftp.c/ssh-keygen.c get the main->pscal_*
# rename treatment from fetch_dependencies.sh.
list(FILTER OPENSSH_SOURCES EXCLUDE REGEX "/ssh-sk-helper\\.c$")
list(FILTER OPENSSH_SOURCES EXCLUDE REGEX "/ssh-keyscan\\.c$")
list(FILTER OPENSSH_SOURCES EXCLUDE REGEX "/ssh-sk-client\\.c$")
# contrib/ ships standalone GUI askpass helpers (GNOME/X11/KDE) with their own
# main() and dependencies this build doesn't have and doesn't need -- not part
# of the ssh/scp/sftp/ssh-keygen client. regress/ is test-only.
list(FILTER OPENSSH_SOURCES EXCLUDE REGEX "/contrib/")
list(FILTER OPENSSH_SOURCES EXCLUDE REGEX "/regress/")
# utmp/wtmp/lastlog login accounting is sshd (server) territory, not needed by
# the ssh/scp/sftp client, and pulls in BSD-only <util.h> that musl lacks.
list(FILTER OPENSSH_SOURCES EXCLUDE REGEX "/loginrec\\.c$")
list(FILTER OPENSSH_SOURCES EXCLUDE REGEX "/logintest\\.c$")

# Re-add client helpers that were filtered out by broad patterns.
list(APPEND OPENSSH_SOURCES
    third-party/openssh/monitor_fdpass.c
    third-party/openssh/sshsig.c
    third-party/openssh/platform-pledge.c
)

set(SOURCES
    src/main.c
    src/core.c
    src/openrsync_app.c
    src/micro_app.c
    src/micro_main_stub.c
    src/nextvi_app.c
    src/openssh_app.c
    src/openssh_globals.c
    src/vproc_test_app.c
    src/runtime_support.c
    src/runtime_stubs_extra.c
    src/openssh_stubs.c
    src/openssh_shim.c
    src/tar_app.c
    src/gzip_app.c
    src/readlink_app.c
    src/checksum_app.c
    src/diff_app.c
    src/patch_app.c
    src/printf_app.c
    src/expr_app.c
    src/chown_app.c
    src/chroot_app.c
    src/base64_app.c
    src/nohup_app.c
    src/cmp_app.c
    src/dd_app.c
    src/od_app.c
    src/seq_app.c
    src/nl_app.c
    src/tac_app.c
    src/rev_app.c
    src/fold_app.c
    src/paste_app.c
    src/split_app.c
    src/fmt_app.c
    src/comm_app.c
    src/awk_lexer.c
    src/awk_parser.c
    src/awk_value.c
    src/awk_interp.c
    src/awk_app.c
    ${NEXTVI_SOURCES}
    ${OPENSSH_SOURCES}
    ${OPENRSYNC_ROOT}/blocks.c
    ${OPENRSYNC_ROOT}/client.c
    ${OPENRSYNC_ROOT}/compats.c
    ${OPENRSYNC_ROOT}/copy.c
    ${OPENRSYNC_ROOT}/downloader.c
    ${OPENRSYNC_ROOT}/fargs.c
    ${OPENRSYNC_ROOT}/flist.c
    ${OPENRSYNC_ROOT}/hash.c
    ${OPENRSYNC_ROOT}/ids.c
    ${OPENRSYNC_ROOT}/io.c
    ${OPENRSYNC_ROOT}/log.c
    ${OPENRSYNC_ROOT}/main.c
    ${OPENRSYNC_ROOT}/md4.c
    ${OPENRSYNC_ROOT}/misc.c
    ${OPENRSYNC_ROOT}/mkpath.c
    ${OPENRSYNC_ROOT}/mktemp.c
    ${OPENRSYNC_ROOT}/receiver.c
    ${OPENRSYNC_ROOT}/rmatch.c
    ${OPENRSYNC_ROOT}/rules.c
    ${OPENRSYNC_ROOT}/sender.c
    ${OPENRSYNC_ROOT}/server.c
    ${OPENRSYNC_ROOT}/session.c
    ${OPENRSYNC_ROOT}/socket.c
    ${OPENRSYNC_ROOT}/symlinks.c
    ${OPENRSYNC_ROOT}/uploader.c
    ${OPENRSYNC_ROOT}/zcompress.c
)

set_source_files_properties(${NEXTVI_SOURCES} PROPERTIES COMPILE_DEFINITIONS "main=nextvi_main_entry")
# scp.c defines its own cleanup_exit() (closes remin/remout/remin2/remout2
# fds) distinct from clientloop.c's client-specific one -- rename it so it
# doesn't collide, scoped to scp.c only so its own internal call sites (the
# only callers) pick up the renamed symbol consistently.
set_source_files_properties(third-party/openssh/scp.c PROPERTIES COMPILE_DEFINITIONS "cleanup_exit=pscal_openssh_scp_cleanup_exit")
# NOTE: ssh/scp/sftp/ssh-keygen's main() -> pscal_openssh_*_main() renames are
# done by fetch_dependencies.sh via sed directly on third-party/openssh/*.c
# (matching src/openssh_app.c's extern declarations), not via COMPILE_DEFINITIONS
# here. The old ssh_main=/scp_main=/etc. defines assumed an ios_system-style
# pre-renamed source tree that this repo no longer vendors; removed as dead.
# NOTE: main.c is also listed in the shared set_source_files_properties()
# call below (it needs the same err/warn/exit renames as every other
# openrsync source), and a *second* set_source_files_properties() call on a
# file that's already had COMPILE_DEFINITIONS set REPLACES the property
# rather than merging with it -- so the "main=pscal_openrsync_main" rename
# has to live inside that shared call's COMPILE_DEFINITIONS string, not in
# a standalone call like this one used to be (it silently never took effect).
set_source_files_properties(
    ${OPENRSYNC_ROOT}/blocks.c
    ${OPENRSYNC_ROOT}/client.c
    ${OPENRSYNC_ROOT}/compats.c
    ${OPENRSYNC_ROOT}/copy.c
    ${OPENRSYNC_ROOT}/downloader.c
    ${OPENRSYNC_ROOT}/fargs.c
    ${OPENRSYNC_ROOT}/flist.c
    ${OPENRSYNC_ROOT}/hash.c
    ${OPENRSYNC_ROOT}/ids.c
    ${OPENRSYNC_ROOT}/io.c
    ${OPENRSYNC_ROOT}/log.c
    ${OPENRSYNC_ROOT}/main.c
    ${OPENRSYNC_ROOT}/md4.c
    ${OPENRSYNC_ROOT}/misc.c
    ${OPENRSYNC_ROOT}/mkpath.c
    ${OPENRSYNC_ROOT}/mktemp.c
    ${OPENRSYNC_ROOT}/receiver.c
    ${OPENRSYNC_ROOT}/rmatch.c
    ${OPENRSYNC_ROOT}/rules.c
    ${OPENRSYNC_ROOT}/sender.c
    ${OPENRSYNC_ROOT}/server.c
    ${OPENRSYNC_ROOT}/session.c
    ${OPENRSYNC_ROOT}/socket.c
    ${OPENRSYNC_ROOT}/symlinks.c
    ${OPENRSYNC_ROOT}/uploader.c
    ${OPENRSYNC_ROOT}/zcompress.c
    PROPERTIES
    COMPILE_DEFINITIONS
        "err=pscal_openrsync_err;errc=pscal_openrsync_errc;errx=pscal_openrsync_errx;warn=pscal_openrsync_warn;warnc=pscal_openrsync_warnc;warnx=pscal_openrsync_warnx;exit=pscal_openrsync_request_exit;getprogname=pscal_openrsync_getprogname;main=pscal_openrsync_main;freeargs=pscal_openrsync_freeargs;scan_scaled=pscal_openrsync_scan_scaled;addargs=pscal_openrsync_addargs;fmt_scaled=pscal_openrsync_fmt_scaled"
    COMPILE_OPTIONS
        "-include${CMAKE_CURRENT_BINARY_DIR}/generated/openrsync/config.h;-include${CMAKE_CURRENT_SOURCE_DIR}/src/openrsync_hooks.h"
    INCLUDE_DIRECTORIES
        "${CMAKE_CURRENT_BINARY_DIR}/generated/openrsync;${OPENRSYNC_ROOT};${CMAKE_CURRENT_SOURCE_DIR}/compat"
)

add_compile_definitions(HAVE_CONFIG_H)

# Optional Integration source
# src/integration.c depends on vm/vm.h and backend_ast/builtin.h
# Only include if building with the full shell environment
if(WITH_EXSH)
    add_definitions(-DSMALLCLUE_WITH_EXSH)
    list(APPEND SOURCES src/integration.c)
    # You might need to add include paths for vm/ and backend_ast/ here
    # include_directories(${CMAKE_CURRENT_SOURCE_DIR}/vm)
else()
    # Standalone builds ship smallclue's own POSIX shell (BusyBox-ash-class):
    # the exsh lexer/parser vendored in src/shell/ plus a native AST-walking
    # interpreter with no PSCAL VM dependency.
    add_definitions(-DSMALLCLUE_WITH_SH)
    list(APPEND SOURCES
        src/shell/lexer.c
        src/shell/parser.c
        src/shell/ast.c
        src/shell/sh_utils.c
        src/shell/sh_var.c
        src/shell/sh_astcopy.c
        src/shell/sh_expand.c
        src/shell/sh_arith.c
        src/shell/sh_exec.c
        src/shell/sh_builtins.c
        src/shell/sh_lineedit.c
        src/shell/sh_main.c
    )
endif()

# The built-in `git` applet (src/git_app.c) is libgit2-backed. This mirrors
# setup_posix_env.sh/setup_ish_env.sh's own libgit2 build (same flags, same
# static-archive-via-ExternalProject approach), which this top-level
# CMakeLists.txt previously didn't wire up at all -- git_app.c wasn't even
# in SOURCES, so `git` was a registered-but-undefined applet in any plain
# `cmake .` build. USE_SSH is ON here (unlike the setup scripts, which
# default it off) because libssh2 is available in this environment and SSH
# remotes are a core git workflow.
option(SMALLCLUE_WITH_LIBGIT2 "Build the libgit2-backed git applet" ON)
if(SMALLCLUE_WITH_LIBGIT2)
    if(NOT EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/third-party/libgit2/CMakeLists.txt)
        message(WARNING "third-party/libgit2 missing or incomplete; disabling the git applet. Run ./fetch_dependencies.sh.")
        set(SMALLCLUE_WITH_LIBGIT2 OFF)
    endif()
endif()

if(SMALLCLUE_WITH_LIBGIT2)
    find_package(PkgConfig)
    set(SMALLCLUE_LIBGIT2_USE_SSH OFF)
    if(PkgConfig_FOUND)
        # IMPORTED_TARGET gives a proper PkgConfig::LIBSSH2 target with both
        # the library and its directory attached -- pkg_check_modules' bare
        # LIBSSH2_LIBRARIES variable is just "ssh2" with no -L, which fails
        # to link unless libssh2 happens to already be on the linker's
        # default search path.
        #
        # Same static-vs-shared story as the FTS_LIBRARY/CURL/ZLIB/OpenSSL
        # lookups elsewhere in this file: IMPORTED_TARGET resolves the
        # library to an absolute path via find_library() under the hood, so
        # it needs the same .a preference on this fully-static
        # (UNIX-and-not-Apple) build, or the linker fails with "attempted
        # static link of dynamic object" against libssh2.so.
        if(UNIX AND NOT APPLE)
            set(_smallclue_saved_lib_suffixes ${CMAKE_FIND_LIBRARY_SUFFIXES})
            set(CMAKE_FIND_LIBRARY_SUFFIXES .a ${CMAKE_FIND_LIBRARY_SUFFIXES})
        endif()
        pkg_check_modules(LIBSSH2 QUIET IMPORTED_TARGET libssh2)
        if(UNIX AND NOT APPLE)
            set(CMAKE_FIND_LIBRARY_SUFFIXES ${_smallclue_saved_lib_suffixes})
        endif()

        if(LIBSSH2_FOUND AND UNIX AND NOT APPLE)
            # libssh2 vendors its own chacha20-poly1305 cipher
            # (cipher-chachapoly.o: chachapoly_crypt/chachapoly_get_length).
            # third-party/openssh/cipher-chachapoly-libcrypto.c defines the
            # exact same two symbol names for smallclue's own ssh/scp/sftp
            # applets. Dynamically linked, ELF symbol interposition papers
            # over this; both statically archived into the same binary is a
            # real "multiple definition" link error. Test-link against
            # libssh2 with stand-in definitions of the same two symbols to
            # catch this before it breaks the real (much slower) build.
            # A plain test link isn't enough: static archives only pull in
            # the specific .o members needed to resolve some other
            # outstanding reference, and a trivial test program that never
            # calls libssh2's real API won't happen to need cipher-
            # chachapoly.o at all, so the two same-named stand-in symbols
            # below would just never collide -- proven empirically (an
            # earlier version of this check, without --whole-archive,
            # passed here despite the real build failing, and a manual gcc
            # -static stub.c -Wl,--whole-archive -lssh2 -Wl,--no-whole-archive
            # reproducing the real "multiple definition" error). Force the
            # *entire* archive to be linked in instead, so this reflects the
            # true worst case rather than depending on which specific
            # libssh2 entry points a minimal test program happens to touch.
            #
            # Passed as CMAKE_REQUIRED_FLAGS (a literal flags string), not
            # CMAKE_REQUIRED_LIBRARIES: the latter goes through CMake's own
            # target_link_libraries library-graph handling, which is free to
            # reorder/deduplicate entries and silently breaks the exact
            # --whole-archive/--no-whole-archive bracketing this needs --
            # confirmed empirically (that form also reported a false
            # "Success" here despite the real collision).
            include(CheckCSourceCompiles)
            string(REPLACE ";" " " _smallclue_libssh2_ldflags "${LIBSSH2_LDFLAGS}")
            set(_smallclue_saved_req_flags "${CMAKE_REQUIRED_FLAGS}")
            set(CMAKE_REQUIRED_FLAGS "-static -Wl,--whole-archive ${_smallclue_libssh2_ldflags} -Wl,--no-whole-archive")
            check_c_source_compiles("
int chachapoly_crypt(void) { return 0; }
int chachapoly_get_length(void) { return 0; }
int main(void) { return chachapoly_crypt() + chachapoly_get_length(); }
" SMALLCLUE_LIBSSH2_STATIC_LINKS)
            set(CMAKE_REQUIRED_FLAGS "${_smallclue_saved_req_flags}")
            if(NOT SMALLCLUE_LIBSSH2_STATIC_LINKS)
                # Real fix, instead of just disabling: rename libssh2's two
                # colliding symbols in a private copy of its static archive,
                # so its chachapoly.o and OpenSSH's own cipher-chachapoly-
                # libcrypto.o can both be statically archived into the same
                # binary without a duplicate-symbol error. Neither `ar` nor
                # `objcopy` can rewrite symbols inside a .a in place in one
                # shot portably, so: extract every member out with `ar x`,
                # run `objcopy --redefine-sym` on each .o (a harmless no-op
                # on members that don't define either symbol), then
                # re-archive the renamed members with `ar rcs`.
                find_program(SMALLCLUE_AR NAMES ar)
                find_program(SMALLCLUE_OBJCOPY NAMES objcopy)
                set(_smallclue_saved_lib_suffixes ${CMAKE_FIND_LIBRARY_SUFFIXES})
                set(CMAKE_FIND_LIBRARY_SUFFIXES .a)
                find_library(SMALLCLUE_LIBSSH2_STATIC_PATH NAMES ssh2 HINTS ${LIBSSH2_LIBRARY_DIRS})
                set(CMAKE_FIND_LIBRARY_SUFFIXES ${_smallclue_saved_lib_suffixes})

                set(SMALLCLUE_LIBSSH2_RENAMED FALSE)
                if(SMALLCLUE_AR AND SMALLCLUE_OBJCOPY AND SMALLCLUE_LIBSSH2_STATIC_PATH)
                    set(_smallclue_libssh2_extract_dir ${CMAKE_CURRENT_BINARY_DIR}/libssh2-renamed/extract)
                    set(SMALLCLUE_LIBSSH2_RENAMED_ARCHIVE ${CMAKE_CURRENT_BINARY_DIR}/libssh2-renamed/libssh2.a)
                    file(REMOVE_RECURSE ${_smallclue_libssh2_extract_dir})
                    file(MAKE_DIRECTORY ${_smallclue_libssh2_extract_dir})
                    execute_process(
                        COMMAND ${SMALLCLUE_AR} x ${SMALLCLUE_LIBSSH2_STATIC_PATH}
                        WORKING_DIRECTORY ${_smallclue_libssh2_extract_dir}
                        RESULT_VARIABLE _smallclue_libssh2_ar_x_result
                    )
                    file(GLOB _smallclue_libssh2_objs ${_smallclue_libssh2_extract_dir}/*.o)
                    set(_smallclue_libssh2_objcopy_ok TRUE)
                    foreach(_smallclue_obj ${_smallclue_libssh2_objs})
                        execute_process(
                            COMMAND ${SMALLCLUE_OBJCOPY}
                                --redefine-sym chachapoly_crypt=smallclue_libssh2_chachapoly_crypt
                                --redefine-sym chachapoly_get_length=smallclue_libssh2_chachapoly_get_length
                                ${_smallclue_obj}
                            RESULT_VARIABLE _smallclue_libssh2_objcopy_result
                        )
                        if(NOT _smallclue_libssh2_objcopy_result EQUAL 0)
                            set(_smallclue_libssh2_objcopy_ok FALSE)
                        endif()
                    endforeach()
                    if(_smallclue_libssh2_objs AND _smallclue_libssh2_ar_x_result EQUAL 0 AND _smallclue_libssh2_objcopy_ok)
                        file(REMOVE ${SMALLCLUE_LIBSSH2_RENAMED_ARCHIVE})
                        execute_process(
                            COMMAND ${SMALLCLUE_AR} rcs ${SMALLCLUE_LIBSSH2_RENAMED_ARCHIVE} ${_smallclue_libssh2_objs}
                            RESULT_VARIABLE _smallclue_libssh2_ar_rcs_result
                        )
                        if(_smallclue_libssh2_ar_rcs_result EQUAL 0)
                            # Retest, this time against the renamed archive --
                            # confirms the rename actually resolved the
                            # collision instead of just assuming it did (same
                            # rationale as the original whole-archive test
                            # above: a plain link that never touches the
                            # renamed chachapoly members wouldn't prove
                            # anything either way).
                            #
                            # libssh2.a's own crypto backend (crypto.o) and
                            # optional zlib compression (comp.o) need real
                            # OpenSSL/zlib symbols to resolve at all -- find_
                            # package(OpenSSL)/find_package(ZLIB) haven't run
                            # yet this far up the file (they're below, after
                            # this whole SMALLCLUE_WITH_LIBGIT2 block), so a
                            # bare whole-archive link against just libssh2.a
                            # would fail on unrelated undefined EVP_*/BN_*
                            # references and misreport this as the rename
                            # not having worked. Look them up locally instead
                            # (same .a-preference dance as everywhere else in
                            # this file) purely to make this probe link
                            # complete; the real final link further down
                            # still does its own find_package(OpenSSL)/
                            # find_package(ZLIB) and target_link_libraries()
                            # independently of this.
                            set(_smallclue_saved_lib_suffixes ${CMAKE_FIND_LIBRARY_SUFFIXES})
                            set(CMAKE_FIND_LIBRARY_SUFFIXES .a)
                            find_library(SMALLCLUE_LIBSSH2_RETEST_CRYPTO NAMES crypto)
                            find_library(SMALLCLUE_LIBSSH2_RETEST_Z NAMES z)
                            find_library(SMALLCLUE_LIBSSH2_RETEST_ZSTD NAMES zstd)
                            set(CMAKE_FIND_LIBRARY_SUFFIXES ${_smallclue_saved_lib_suffixes})

                            set(_smallclue_saved_req_flags "${CMAKE_REQUIRED_FLAGS}")
                            set(_smallclue_saved_req_libs "${CMAKE_REQUIRED_LIBRARIES}")
                            set(CMAKE_REQUIRED_FLAGS "-static -Wl,--whole-archive ${SMALLCLUE_LIBSSH2_RENAMED_ARCHIVE} -Wl,--no-whole-archive")
                            set(CMAKE_REQUIRED_LIBRARIES ${SMALLCLUE_LIBSSH2_RETEST_CRYPTO} ${SMALLCLUE_LIBSSH2_RETEST_Z} ${SMALLCLUE_LIBSSH2_RETEST_ZSTD})
                            check_c_source_compiles("
int chachapoly_crypt(void) { return 0; }
int chachapoly_get_length(void) { return 0; }
int main(void) { return chachapoly_crypt() + chachapoly_get_length(); }
" SMALLCLUE_LIBSSH2_RENAMED_STATIC_LINKS)
                            set(CMAKE_REQUIRED_FLAGS "${_smallclue_saved_req_flags}")
                            set(CMAKE_REQUIRED_LIBRARIES "${_smallclue_saved_req_libs}")
                            if(SMALLCLUE_LIBSSH2_RENAMED_STATIC_LINKS)
                                set(SMALLCLUE_LIBSSH2_RENAMED TRUE)
                            endif()
                        endif()
                    endif()
                endif()

                if(SMALLCLUE_LIBSSH2_RENAMED)
                    message(STATUS "libssh2's chachapoly symbols collided with OpenSSH's; renamed them in a private copy of libssh2's static archive instead of disabling libgit2's SSH transport (${SMALLCLUE_LIBSSH2_RENAMED_ARCHIVE}).")
                else()
                    message(WARNING "libssh2 found, but its bundled chachapoly cipher collides (duplicate symbol) with OpenSSH's own once both are statically archived into the same binary, and renaming its symbols via objcopy didn't resolve it either (ar/objcopy missing, or the rename+retest itself failed -- see any errors above). Disabling libgit2's SSH transport for this static build -- git/ssh/scp/sftp over SSH still work via the separately-linked OpenSSH applets, just not libgit2's own git+ssh:// remote support.")
                    set(LIBSSH2_FOUND FALSE)
                endif()
            endif()
        endif()

        if(LIBSSH2_FOUND)
            set(SMALLCLUE_LIBGIT2_USE_SSH ON)
        endif()
    endif()

    include(ExternalProject)
    set(LIBGIT2_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third-party/libgit2)
    set(LIBGIT2_PREFIX ${CMAKE_CURRENT_BINARY_DIR}/libgit2-build)
    set(LIBGIT2_INSTALL_DIR ${LIBGIT2_PREFIX}/install)
    set(LIBGIT2_LIBRARY ${LIBGIT2_INSTALL_DIR}/lib/libgit2.a)

    ExternalProject_Add(libgit2_external
        SOURCE_DIR ${LIBGIT2_SOURCE_DIR}
        PREFIX ${LIBGIT2_PREFIX}
        INSTALL_DIR ${LIBGIT2_INSTALL_DIR}
        CMAKE_ARGS
            -DCMAKE_BUILD_TYPE=Release
            -DCMAKE_INSTALL_PREFIX=${LIBGIT2_INSTALL_DIR}
            -DCMAKE_INSTALL_LIBDIR=lib
            -DBUILD_SHARED_LIBS=OFF
            -DBUILD_TESTS=OFF
            -DBUILD_BENCHMARKS=OFF
            -DBUILD_CLI=OFF
            -DBUILD_EXAMPLES=OFF
            -DBUILD_FUZZERS=OFF
            -DUSE_SSH=$<IF:$<BOOL:${SMALLCLUE_LIBGIT2_USE_SSH}>,ON,OFF>
            -DUSE_HTTPS=ON
            # builtin (libgit2's vendored RFC6234 SHA implementation) declares
            # SHA1/SHA224/SHA256/SHA384/SHA512 as an enum; OpenSSL's own
            # <openssl/sha.h> (pulled in transitively via the openssl streams
            # backend USE_HTTPS=ON selects) declares the same identifiers as
            # functions. Both land in the same TU (libgit2.c) and collide.
            # Since USE_HTTPS is already OpenSSL, use OpenSSL for the hash
            # backend too so there's only one declaration of each symbol.
            -DUSE_SHA1=OpenSSL
            -DUSE_SHA256=OpenSSL
            -DUSE_HTTP_PARSER=builtin
            -DUSE_AUTH_NTLM=OFF
            -DUSE_AUTH_NEGOTIATE=OFF
            -DUSE_REGEX=builtin
            -DUSE_COMPRESSION=builtin
            -DUSE_I18N=OFF
            -DENABLE_WERROR=OFF
        BUILD_BYPRODUCTS ${LIBGIT2_LIBRARY}
        INSTALL_COMMAND ${CMAKE_COMMAND} --build <BINARY_DIR> --target install
    )

    add_definitions(-DPSCAL_HAS_LIBGIT2)
    include_directories(${LIBGIT2_INSTALL_DIR}/include)
    list(APPEND SOURCES src/git_app.c)
endif()

# External Dependency Placeholders
# smallclue references symbols from OpenSSH (pscal_openssh_*) and Nextvi (nextvi_main_entry).
# These sources are NOT in the files you uploaded.
# You must add the source files for these libraries to the target, or link against them.
# Example:
# list(APPEND SOURCES third-party/nextvi/nextvi.c)
# list(APPEND SOURCES third-party/openssh/ssh.c ...)

# Define the Executable
add_executable(smallclue ${SOURCES})

# Link Libraries
target_link_libraries(smallclue PRIVATE Threads::Threads)

if(ENABLE_CURL)
    target_link_libraries(smallclue PRIVATE ${CURL_LIBRARIES})
    if(SMALLCLUE_CURL_VENDORED)
        add_dependencies(smallclue curl_external)
    endif()
endif()

if(APPLE)
    target_link_libraries(smallclue PRIVATE resolv)
endif()

if(UNIX AND NOT APPLE)
    # awk_interp.c's builtins (sin/cos/exp/log/sqrt/atan2/fmod/pow) and
    # OpenSSH/su's crypt() calls are in libm/libcrypt on glibc; both are
    # part of libSystem on Darwin, hence the UNIX-and-not-APPLE guard.
    target_link_libraries(smallclue PRIVATE m crypt)

    # Every consumer that has relied on this build (AetherOS's initramfs
    # stage-1 /bin/sh chief among them) needs a fully static binary, and the
    # rest of this file already assumes one -- the FTS_LIBRARY/BSD_LIBRARY
    # and ZLIB/OpenSSL .a-preference blocks below only make sense against a
    # static final link. Nothing actually forced -static, though, so a plain
    # `cmake --build` silently produced a dynamically-linked binary: no
    # build-time warning, just a binary that needs libc/libm/libcrypt.so at
    # runtime instead of none, surfacing (for the initramfs case) as an
    # opaque kernel panic at boot, stages removed from the build. Apple
    # platforms (including the PSCAL/iOS embedded target, which links into a
    # host app rather than running standalone) are excluded on purpose:
    # Darwin ships no static libc to link against.
    target_link_options(smallclue PRIVATE -static)
endif()

# musl libc (Alpine, aarch64-linux-musl) has no <fts.h>/libfts -- glibc and
# Darwin both ship it in libc itself, so this is a no-op there. On musl,
# install musl-fts-dev (ships both the header at the normal system include
# path and libfts.a/.so) -- same package Alpine's own openssh/rsync use.
# find_library() defaults to preferring .so on Linux; this build links fully
# static (-static), so ask for the .a explicitly or the linker fails with
# "attempted static link of dynamic object".
set(_smallclue_saved_lib_suffixes ${CMAKE_FIND_LIBRARY_SUFFIXES})
set(CMAKE_FIND_LIBRARY_SUFFIXES .a ${CMAKE_FIND_LIBRARY_SUFFIXES})
find_library(FTS_LIBRARY fts)
set(CMAKE_FIND_LIBRARY_SUFFIXES ${_smallclue_saved_lib_suffixes})
if(FTS_LIBRARY)
    target_link_libraries(smallclue PRIVATE ${FTS_LIBRARY})
endif()

# openrsync (vendored OpenBSD source) calls strlcpy/strlcat/recallocarray/
# strtonum/major/minor -- present in BSD libc and in Darwin's, but glibc only
# gained strlcpy/strlcat in 2.38 and never shipped the rest. Same story as
# FTS_LIBRARY above: link the distro's libbsd (apt/dnf package libbsd-dev)
# when present.
if(UNIX AND NOT APPLE)
    set(_smallclue_saved_lib_suffixes ${CMAKE_FIND_LIBRARY_SUFFIXES})
    set(CMAKE_FIND_LIBRARY_SUFFIXES .a ${CMAKE_FIND_LIBRARY_SUFFIXES})
    find_library(BSD_LIBRARY bsd)
    set(CMAKE_FIND_LIBRARY_SUFFIXES ${_smallclue_saved_lib_suffixes})
    if(BSD_LIBRARY)
        target_link_libraries(smallclue PRIVATE ${BSD_LIBRARY})
    else()
        message(WARNING "libbsd not found; openrsync needs strlcpy/strlcat/recallocarray/strtonum/major/minor. Install libbsd-dev (Debian/Ubuntu) or equivalent.")
    endif()
endif()

# Link OpenSSH dependencies
# Same static-vs-shared story as the FTS_LIBRARY lookup above: FindZLIB/
# FindOpenSSL also default to preferring .so on Linux, which this fully
# static (-static) build can't link against ("attempted static link of a
# dynamic object"). zlib-static/openssl-libs-static (Alpine package names)
# ship the matching .a files; just need CMake to prefer them.
set(_smallclue_saved_lib_suffixes ${CMAKE_FIND_LIBRARY_SUFFIXES})
set(CMAKE_FIND_LIBRARY_SUFFIXES .a ${CMAKE_FIND_LIBRARY_SUFFIXES})
find_package(ZLIB REQUIRED)
find_package(OpenSSL REQUIRED)
# This system's libcrypto.a was built with its optional zlib/zstd BIO
# compression filters compiled in (c_zlib.o/c_zstd.o) -- those object files
# get pulled into any static link that needs libcrypto.a at all (regardless
# of whether smallclue itself calls BIO_f_zlib()/BIO_f_zstd()), and they
# reference zlib's compress()/uncompress() and libzstd's ZSTD_* API in turn.
# Optional (not REQUIRED): older/leaner OpenSSL builds (e.g. Alpine's,
# musl) don't compile zstd support in at all, so libzstd may legitimately
# not be needed there.
find_library(ZSTD_LIBRARY zstd)
set(CMAKE_FIND_LIBRARY_SUFFIXES ${_smallclue_saved_lib_suffixes})
target_link_libraries(smallclue PRIVATE ZLIB::ZLIB)
target_link_libraries(smallclue PRIVATE OpenSSL::SSL OpenSSL::Crypto)
# Static linking on Linux is a single left-to-right pass -- ZLIB::ZLIB was
# already listed *before* OpenSSL::SSL/Crypto above, so by the time the
# linker reaches libcrypto.a's own internal reference to zlib's
# compress()/uncompress(), it has already passed libz.a in the link line and
# won't look back. Re-list ZLIB::ZLIB (and libzstd, if present) after
# OpenSSL so they're available on this later pass too -- same fix as the
# libgit2.a re-list of OpenSSL::SSL/Crypto below.
target_link_libraries(smallclue PRIVATE ZLIB::ZLIB)
if(ZSTD_LIBRARY)
    target_link_libraries(smallclue PRIVATE ${ZSTD_LIBRARY})
else()
    message(WARNING "libzstd not found; if this OpenSSL build has zstd BIO support compiled in, the static link will fail with undefined ZSTD_* references. Install libzstd-dev (Debian/Ubuntu) or equivalent.")
endif()

if(SMALLCLUE_WITH_LIBGIT2)
    add_dependencies(smallclue libgit2_external)
    target_link_libraries(smallclue PRIVATE ${LIBGIT2_LIBRARY})
    if(SMALLCLUE_LIBGIT2_USE_SSH)
        if(SMALLCLUE_LIBSSH2_RENAMED)
            target_link_libraries(smallclue PRIVATE ${SMALLCLUE_LIBSSH2_RENAMED_ARCHIVE})
        else()
            target_link_libraries(smallclue PRIVATE PkgConfig::LIBSSH2)
        endif()
    endif()
    # libgit2.a's openssl.c needs SSL_*/OPENSSL_* symbols, but static linking
    # on Linux is a single left-to-right pass -- since OpenSSL::SSL/Crypto
    # were already listed earlier (line ~399, before libgit2.a lands in the
    # link line), the linker never looks back at them once it hits libgit2's
    # unresolved references. Re-list them after libgit2.a so they're
    # available on this later pass too.
    target_link_libraries(smallclue PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    if(ZSTD_LIBRARY)
        target_link_libraries(smallclue PRIVATE ${ZSTD_LIBRARY})
    endif()
endif()

if(APPLE)
    # Link against CoreFoundation or specific frameworks if iOS target functions require them
    # target_link_libraries(smallclue PRIVATE "-framework Foundation")
    if(SMALLCLUE_WITH_LIBGIT2)
        # libgit2's default macOS TLS backend is SecureTransport (stransport.c),
        # which needs Security.framework and CoreFoundation.
        target_link_libraries(smallclue PRIVATE "-framework Security" "-framework CoreFoundation")
    endif()
endif()

# Fail the build loudly if the -static request above didn't actually take
# (e.g. a future change to this file drops it, or a toolchain silently
# ignores it). Checking readelf's dynamic-section NEEDED entries rather than
# `ldd`'s exit status: it only parses ELF headers instead of ever executing
# the freshly-built binary, and its behavior doesn't vary between glibc and
# musl targets the way `ldd` invocations can. Deferring this to boot time (a
# static-only consumer like AetherOS's initramfs stage-1 /bin/sh gets an
# opaque "cannot open shared object file" -> kernel panic three build stages
# later) is exactly the failure mode this exists to catch at build time
# instead.
if(UNIX AND NOT APPLE)
    find_program(SMALLCLUE_READELF readelf)
    if(SMALLCLUE_READELF)
        add_custom_command(TARGET smallclue POST_BUILD
            COMMAND sh -c "if \"${SMALLCLUE_READELF}\" -d \"$<TARGET_FILE:smallclue>\" 2>/dev/null | grep -q NEEDED; then echo 'FATAL: smallclue linked dynamically (found NEEDED entries) -- expected a fully static binary on UNIX-and-not-Apple builds. See CMakeLists.txt UNIX-AND-NOT-APPLE target_link_options(-static) block.' >&2; \"${SMALLCLUE_READELF}\" -d \"$<TARGET_FILE:smallclue>\" >&2; exit 1; fi"
            COMMENT "Verifying smallclue linked fully static"
            VERBATIM
        )
    else()
        message(WARNING "readelf not found; skipping the post-build static-link check for smallclue. Verify manually (e.g. `ldd`/`readelf -d`) before relying on this binary as a static bootstrap/initramfs userland.")
    endif()
endif()

# Install instructions (optional)
install(TARGETS smallclue DESTINATION bin)
