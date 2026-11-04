#!/bin/bash
set -e

THIRD_PARTY_DIR="third-party"

mkdir -p "$THIRD_PARTY_DIR"

reset_incomplete_repo() {
    local dir="$1"
    local require_git="$2"
    shift 2
    local required=("$@")

    if [ ! -d "$dir" ]; then
        return 0
    fi

    if [ "$require_git" = "1" ] && [ ! -e "$dir/.git" ]; then
        echo "Removing incomplete dependency at $dir (missing .git)..."
        rm -rf "$dir"
        return 0
    fi

    local missing=0
    local f
    for f in "${required[@]}"; do
        if [ ! -e "$dir/$f" ]; then
            missing=1
            break
        fi
    done

    if [ "$missing" -eq 1 ]; then
        echo "Removing incomplete dependency at $dir (missing required files)..."
        rm -rf "$dir"
    fi
}

# --- Nextvi ---
# Tracked as a git submodule pinned to the `smallclue` branch of
# emkey1/nextvi (a fork of kyx0r/nextvi with the main()-rename,
# CR-handling, and ICRNL patches below baked in as commits, instead of
# reapplying them via sed on every fetch). Falls back to a plain
# clone+patch for non-git (tarball) checkouts.
if [ -f .gitmodules ] && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "Initializing nextvi submodule..."
    git submodule update --init --recursive -- "$THIRD_PARTY_DIR/nextvi"
fi
reset_incomplete_repo "$THIRD_PARTY_DIR/nextvi" "1" "vi.c" "term.c"
if [ ! -d "$THIRD_PARTY_DIR/nextvi" ]; then
    echo "Cloning nextvi (submodule unavailable)..."
    git clone -b smallclue https://github.com/emkey1/nextvi "$THIRD_PARTY_DIR/nextvi"
fi

# Sanity-check the patches are present (they should already be baked into
# the fork above; this only fires for the plain-clone fallback pointed at
# unpatched upstream nextvi).
NEXTVI_MAIN=$(grep -l "int main" "$THIRD_PARTY_DIR/nextvi"/*.c 2>/dev/null | head -n 1)
if [ -n "$NEXTVI_MAIN" ]; then
    echo "Patching nextvi main in $NEXTVI_MAIN..."
    sed -i.bak 's/int main(/int nextvi_main_entry(/g' "$NEXTVI_MAIN"
    rm -f "${NEXTVI_MAIN}.bak"
    if ! grep -q "void nextvi_reset_state" "$NEXTVI_MAIN"; then
        echo "" >> "$NEXTVI_MAIN"
        echo "void nextvi_reset_state(void) {}" >> "$NEXTVI_MAIN"
    fi
fi

VI_C="$THIRD_PARTY_DIR/nextvi/vi.c"
if [ -f "$VI_C" ] && ! grep -q "case '\\\r':" "$VI_C"; then
    echo "Patching nextvi CR handling in vi.c..."
    sed -i.bak 's/case '\''\\n'\'':/case '\''\\n'\'': case '\''\\r'\'':/g' "$VI_C"
    rm -f "${VI_C}.bak"
fi

LED_C="$THIRD_PARTY_DIR/nextvi/led.c"
if [ -f "$LED_C" ] && ! grep -q "return c == '\\\r' ? '\\\n' : c;" "$LED_C"; then
    echo "Patching nextvi CR handling in led.c..."
    sed -i.bak '/if (c == '\''\\n'\'' || TK_INT(c))/{
        N
        s/return c;/return c == '\''\\r'\'' ? '\''\\n'\'' : c;/
        s/if (c == '\''\\n'\'' || TK_INT(c))/if (c == '\''\\n'\'' || c == '\''\\r'\'' || TK_INT(c))/
    }' "$LED_C"
    rm -f "${LED_C}.bak"
fi

TERM_C="$THIRD_PARTY_DIR/nextvi/term.c"
if [ -f "$TERM_C" ] && ! grep -q "ICRNL" "$TERM_C"; then
    echo "Patching nextvi term.c to enable ICRNL..."
    sed -i.bak '/newtermios.c_lflag &= ~(ICANON | ISIG | ECHO);/a \
	newtermios.c_iflag |= ICRNL;' "$TERM_C"
    rm -f "${TERM_C}.bak"
fi

# --- dvtm ---
# Tracked as a git submodule pinned to emkey1/dvtm (a fork of
# martanne/dvtm with a small Darwin build fix), the same fork/commit
# PSCAL's third-party tree uses. No source patching needed here.
if [ -f .gitmodules ] && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "Initializing dvtm submodule..."
    git submodule update --init --recursive -- "$THIRD_PARTY_DIR/dvtm"
fi
reset_incomplete_repo "$THIRD_PARTY_DIR/dvtm" "1" "dvtm.c" "vt.c" "config.def.h"
if [ ! -d "$THIRD_PARTY_DIR/dvtm" ]; then
    if [ -d "../../third-party/dvtm/.git" ]; then
        echo "Copying dvtm from ../../third-party/dvtm..."
        cp -a "../../third-party/dvtm" "$THIRD_PARTY_DIR/dvtm"
    elif [ -d "../third-party/dvtm/.git" ]; then
        echo "Copying dvtm from ../third-party/dvtm..."
        cp -a "../third-party/dvtm" "$THIRD_PARTY_DIR/dvtm"
    else
        echo "Cloning dvtm (submodule unavailable)..."
        git clone https://github.com/emkey1/dvtm "$THIRD_PARTY_DIR/dvtm"
    fi
fi

# --- libgit2 ---
# Tracked as a git submodule (see .gitmodules) pinned to upstream libgit2,
# unmodified, as PSCAL's third-party tree is. `git submodule update --init` is
# the normal way to populate it; fall back to a plain clone for tarball
# checkouts (no .git) or PSCAL's own nested tree.
if [ -f .gitmodules ] && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "Initializing libgit2 submodule..."
    git submodule update --init --recursive -- "$THIRD_PARTY_DIR/libgit2"
fi
reset_incomplete_repo "$THIRD_PARTY_DIR/libgit2" "1" "CMakeLists.txt" "include/git2.h"
if [ ! -d "$THIRD_PARTY_DIR/libgit2" ]; then
    if [ -d "../../third-party/libgit2/.git" ]; then
        echo "Copying libgit2 from ../../third-party/libgit2..."
        cp -a "../../third-party/libgit2" "$THIRD_PARTY_DIR/libgit2"
    elif [ -d "../third-party/libgit2/.git" ]; then
        echo "Copying libgit2 from ../third-party/libgit2..."
        cp -a "../third-party/libgit2" "$THIRD_PARTY_DIR/libgit2"
    else
        echo "Cloning libgit2 (submodule unavailable)..."
        git clone https://github.com/libgit2/libgit2 "$THIRD_PARTY_DIR/libgit2"
        git -C "$THIRD_PARTY_DIR/libgit2" checkout -q 86c7738ca
    fi
fi

# --- openrsync ---
# Tracked as a git submodule pinned to emkey1/openrsync (the same fork PSCAL
# uses, with config_pscal.h already vendored in). Standalone checkouts that
# aren't nested in PSCAL's third-party/openrsync tree need this.
if [ -f .gitmodules ] && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "Initializing openrsync submodule..."
    git submodule update --init --recursive -- "$THIRD_PARTY_DIR/openrsync"
fi
reset_incomplete_repo "$THIRD_PARTY_DIR/openrsync" "1" "config_pscal.h"
if [ ! -d "$THIRD_PARTY_DIR/openrsync" ]; then
    echo "Cloning openrsync (submodule unavailable)..."
    git clone https://github.com/emkey1/openrsync "$THIRD_PARTY_DIR/openrsync"
fi

# --- OpenSSH ---
# Tracked as a git submodule pinned to the `ish-aok-10.5` branch of
# emkey1/openssh (see .gitmodules). This used to be a release tarball fetched
# from cdn.openbsd.org and then rewritten in place by a dozen-plus sed/python
# edits applied right here: the pscal_openssh_*_main renames, the musl
# <nlist.h>/<util.h>/<endian.h> include guards, the openbsd-compat fnmatch/
# readpassphrase/getopt #include_next forwarding, and the shared
# showprogress/interrupted aliasing. The fork carries all of those as commits
# now, except the include guards, which OpenSSH 10.5 made unnecessary: it
# includes those headers bare and has configure write empty stand-ins into
# openbsd-compat/include for any the host lacks. So re-fetching and
# re-patching a vanilla tarball over the top would at best redo work already
# done and at worst silently discard the fork's own changes -- including the
# posix_spawn conversion and the per-task __progname handling, which no sed
# edit here ever knew about. So treat it exactly like the four submodules
# above: init it, and clone the fork if a submodule isn't available.
if [ -f .gitmodules ] && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "Initializing openssh submodule..."
    git submodule update --init --recursive -- "$THIRD_PARTY_DIR/openssh"
fi
reset_incomplete_repo "$THIRD_PARTY_DIR/openssh" "1" "configure.ac" "ssh.c" "scp.c" "sftp.c"
if [ ! -d "$THIRD_PARTY_DIR/openssh" ]; then
    echo "Cloning openssh (submodule unavailable)..."
    git clone -b ish-aok-10.5 https://github.com/emkey1/openssh "$THIRD_PARTY_DIR/openssh"
fi

# The fork commits a hand-maintained config.h, which Apple builds use as is.
# Other hosts need their own, and CMakeLists.txt runs openssh's ./configure
# for them (see its "Configure third-party/openssh" block).

# --- curl (vendored static build) ---
# Not a submodule/fork like libgit2/openrsync/nextvi/dvtm above -- curl needs
# no smallclue-specific patching, just a source tree CMakeLists.txt can build
# itself with its own flags (see the ENABLE_CURL block there for why: the
# *system* libcurl4-openssl-dev on Debian/Ubuntu bakes in gssapi support that
# has no static libgssapi_krb5.a to link against at all, so this build vendors
# and configures its own curl instead of ever relying on that system package).
# Fetched as a plain release tarball, same pattern as OpenSSH above (release
# tarballs ship a pre-generated ./configure, no autoreconf needed here either).
CURL_VERSION="8.21.0"
if [ -d "$THIRD_PARTY_DIR/curl" ] && [ ! -f "$THIRD_PARTY_DIR/curl/configure" ]; then
    echo "Removing incomplete curl source at $THIRD_PARTY_DIR/curl..."
    rm -rf "$THIRD_PARTY_DIR/curl"
fi
if [ -d "$THIRD_PARTY_DIR/curl" ] && [ -f "$THIRD_PARTY_DIR/curl/include/curl/curlver.h" ]; then
    if ! grep -q "LIBCURL_VERSION \"$CURL_VERSION\"" "$THIRD_PARTY_DIR/curl/include/curl/curlver.h"; then
        echo "Removing outdated curl source (need $CURL_VERSION)..."
        rm -rf "$THIRD_PARTY_DIR/curl"
    fi
fi
if [ ! -d "$THIRD_PARTY_DIR/curl" ]; then
    echo "Fetching curl $CURL_VERSION release source..."
    CURL_TARBALL="$THIRD_PARTY_DIR/curl-${CURL_VERSION}.tar.gz"
    CURL_URL="https://curl.se/download/curl-${CURL_VERSION}.tar.gz"
    curl -fL --retry 3 --retry-delay 2 -o "$CURL_TARBALL" "$CURL_URL"
    mkdir -p "$THIRD_PARTY_DIR/curl"
    tar -xzf "$CURL_TARBALL" --strip-components=1 -C "$THIRD_PARTY_DIR/curl"
    rm -f "$CURL_TARBALL"
fi

echo "Dependencies fetched and patched."
