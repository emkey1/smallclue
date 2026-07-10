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
    find_package(CURL)
    if(CURL_FOUND)
        add_definitions(-DPSCAL_HAS_LIBCURL)
        include_directories(${CURL_INCLUDE_DIRS})
    else()
        message(WARNING "CURL not found. Building without curl support.")
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

set(OPENRSYNC_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../../third-party/openrsync)
file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/generated/openrsync)
configure_file(${OPENRSYNC_ROOT}/config_pscal.h
    ${CMAKE_CURRENT_BINARY_DIR}/generated/openrsync/config.h COPYONLY)

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
        pkg_check_modules(LIBSSH2 QUIET IMPORTED_TARGET libssh2)
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
endif()

if(APPLE)
    target_link_libraries(smallclue PRIVATE resolv)
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
set(CMAKE_FIND_LIBRARY_SUFFIXES ${_smallclue_saved_lib_suffixes})
target_link_libraries(smallclue PRIVATE ZLIB::ZLIB)
target_link_libraries(smallclue PRIVATE OpenSSL::SSL OpenSSL::Crypto)

if(SMALLCLUE_WITH_LIBGIT2)
    add_dependencies(smallclue libgit2_external)
    target_link_libraries(smallclue PRIVATE ${LIBGIT2_LIBRARY})
    if(SMALLCLUE_LIBGIT2_USE_SSH)
        target_link_libraries(smallclue PRIVATE PkgConfig::LIBSSH2)
    endif()
    # libgit2.a's openssl.c needs SSL_*/OPENSSL_* symbols, but static linking
    # on Linux is a single left-to-right pass -- since OpenSSL::SSL/Crypto
    # were already listed earlier (line ~399, before libgit2.a lands in the
    # link line), the linker never looks back at them once it hits libgit2's
    # unresolved references. Re-list them after libgit2.a so they're
    # available on this later pass too.
    target_link_libraries(smallclue PRIVATE OpenSSL::SSL OpenSSL::Crypto)
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

# Install instructions (optional)
install(TARGETS smallclue DESTINATION bin)
