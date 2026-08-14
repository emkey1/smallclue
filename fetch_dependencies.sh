#!/bin/bash
set -e

THIRD_PARTY_DIR="third-party"
OPENSSH_PORTABLE_VERSION="10.2p1"
OPENSSH_EXPECTED_VERSION_PREFIX="OpenSSH_10."

mkdir -p "$THIRD_PARTY_DIR"

reset_incomplete_repo() {
    local dir="$1"
    local require_git="$2"
    shift 2
    local required=("$@")

    if [ ! -d "$dir" ]; then
        return 0
    fi

    if [ "$require_git" = "1" ] && [ ! -d "$dir/.git" ]; then
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
reset_incomplete_repo "$THIRD_PARTY_DIR/nextvi" "1" "vi.c" "term.c"
if [ ! -d "$THIRD_PARTY_DIR/nextvi" ]; then
    echo "Cloning nextvi..."
    git clone https://github.com/kyx0r/nextvi "$THIRD_PARTY_DIR/nextvi"
    # Pin to a known working commit/tag if possible. Using HEAD for now as it is stable.
    # (cd "$THIRD_PARTY_DIR/nextvi" && git checkout <hash>)

    # Find main file for nextvi
    NEXTVI_MAIN=$(grep -l "int main" "$THIRD_PARTY_DIR/nextvi"/*.c | head -n 1)
    if [ -f "$NEXTVI_MAIN" ]; then
        echo "Patching nextvi main in $NEXTVI_MAIN..."
        # Match "int main(" and replace with "int nextvi_main_entry("
        sed -i.bak 's/int main(/int nextvi_main_entry(/g' "$NEXTVI_MAIN"
        rm -f "${NEXTVI_MAIN}.bak"

        # Add nextvi_reset_state stub if not present
        if ! grep -q "void nextvi_reset_state" "$NEXTVI_MAIN"; then
            echo "" >> "$NEXTVI_MAIN"
            echo "void nextvi_reset_state(void) {}" >> "$NEXTVI_MAIN"
        fi

    else
        echo "Could not find nextvi main file."
    fi
fi

# Patch CR handling for nextvi (idempotent)
VI_C="$THIRD_PARTY_DIR/nextvi/vi.c"
if [ -f "$VI_C" ]; then
    # Check if patch is already applied
    if ! grep -q "case '\\\r':" "$VI_C"; then
        echo "Patching nextvi CR handling in vi.c..."
        # Handle CR in command mode
        # Use single quotes for sed command to handle backslashes correctly
        sed -i.bak 's/case '\''\\n'\'':/case '\''\\n'\'': case '\''\\r'\'':/g' "$VI_C"
        rm -f "${VI_C}.bak"
    else
        echo "nextvi vi.c already patched for CR handling."
    fi
fi

LED_C="$THIRD_PARTY_DIR/nextvi/led.c"
if [ -f "$LED_C" ]; then
    # Check if patch is already applied (checking one of the changes)
    if ! grep -q "return c == '\\\r' ? '\\\n' : c;" "$LED_C"; then
        echo "Patching nextvi CR handling in led.c..."
        # Handle CR in insert mode (treat as newline)
        sed -i.bak '/if (c == '\''\\n'\'' || TK_INT(c))/{
            N
            s/return c;/return c == '\''\\r'\'' ? '\''\\n'\'' : c;/
            s/if (c == '\''\\n'\'' || TK_INT(c))/if (c == '\''\\n'\'' || c == '\''\\r'\'' || TK_INT(c))/
        }' "$LED_C"
        rm -f "${LED_C}.bak"
    else
        echo "nextvi led.c already patched for CR handling."
    fi
fi

# Patch term.c to enable ICRNL (map CR to NL on input)
TERM_C="$THIRD_PARTY_DIR/nextvi/term.c"
if [ -f "$TERM_C" ]; then
    if ! grep -q "ICRNL" "$TERM_C"; then
        echo "Patching nextvi term.c to enable ICRNL..."
        # Find the line disabling ICANON | ISIG | ECHO and add ICRNL to c_iflag
        sed -i.bak '/newtermios.c_lflag &= ~(ICANON | ISIG | ECHO);/a \
	newtermios.c_iflag |= ICRNL;' "$TERM_C"
        rm -f "${TERM_C}.bak"
    else
        echo "nextvi term.c already patched for ICRNL."
    fi
fi

# --- dvtm ---
reset_incomplete_repo "$THIRD_PARTY_DIR/dvtm" "1" "dvtm.c" "vt.c" "config.def.h"
if [ ! -d "$THIRD_PARTY_DIR/dvtm" ]; then
    if [ -d "../../third-party/dvtm/.git" ]; then
        echo "Copying dvtm from ../../third-party/dvtm..."
        cp -a "../../third-party/dvtm" "$THIRD_PARTY_DIR/dvtm"
    elif [ -d "../third-party/dvtm/.git" ]; then
        echo "Copying dvtm from ../third-party/dvtm..."
        cp -a "../third-party/dvtm" "$THIRD_PARTY_DIR/dvtm"
    else
        echo "Cloning dvtm..."
        git clone https://github.com/martanne/dvtm "$THIRD_PARTY_DIR/dvtm"
    fi
fi

# --- libgit2 ---
reset_incomplete_repo "$THIRD_PARTY_DIR/libgit2" "1" "CMakeLists.txt" "include/git2.h"
if [ ! -d "$THIRD_PARTY_DIR/libgit2" ]; then
    if [ -d "../../third-party/libgit2/.git" ]; then
        echo "Copying libgit2 from ../../third-party/libgit2..."
        cp -a "../../third-party/libgit2" "$THIRD_PARTY_DIR/libgit2"
    elif [ -d "../third-party/libgit2/.git" ]; then
        echo "Copying libgit2 from ../third-party/libgit2..."
        cp -a "../third-party/libgit2" "$THIRD_PARTY_DIR/libgit2"
    else
        echo "Cloning libgit2..."
        git clone https://github.com/libgit2/libgit2 "$THIRD_PARTY_DIR/libgit2"
    fi
fi

# --- OpenSSH ---
reset_incomplete_repo "$THIRD_PARTY_DIR/openssh" "0" "configure" "configure.ac" "ssh.c" "scp.c" "sftp.c"
if [ -d "$THIRD_PARTY_DIR/openssh" ] && [ -f "$THIRD_PARTY_DIR/openssh/version.h" ]; then
    if ! grep -q "$OPENSSH_EXPECTED_VERSION_PREFIX" "$THIRD_PARTY_DIR/openssh/version.h"; then
        echo "Removing outdated OpenSSH source (need $OPENSSH_EXPECTED_VERSION_PREFIX*)..."
        rm -rf "$THIRD_PARTY_DIR/openssh"
    fi
fi
if [ ! -d "$THIRD_PARTY_DIR/openssh" ]; then
    echo "Fetching OpenSSH Portable release source..."
    OPENSSH_TARBALL="$THIRD_PARTY_DIR/openssh-${OPENSSH_PORTABLE_VERSION}.tar.gz"
    OPENSSH_URL="https://cdn.openbsd.org/pub/OpenBSD/OpenSSH/portable/openssh-${OPENSSH_PORTABLE_VERSION}.tar.gz"
    curl -fL --retry 3 --retry-delay 2 -o "$OPENSSH_TARBALL" "$OPENSSH_URL"
    mkdir -p "$THIRD_PARTY_DIR/openssh"
    tar -xzf "$OPENSSH_TARBALL" --strip-components=1 -C "$THIRD_PARTY_DIR/openssh"
    rm -f "$OPENSSH_TARBALL"

    # Patch OpenSSH clients
    OPENSSH_DIR="$THIRD_PARTY_DIR/openssh"
    if [ -d "$OPENSSH_DIR" ]; then
        for tool in ssh scp sftp ssh-keygen; do
            SRC_FILE="$OPENSSH_DIR/$tool.c"
            if [ -f "$SRC_FILE" ]; then
                FUNC_NAME="pscal_openssh_$(echo $tool | tr '-' '_')_main"
                echo "Patching $tool in $SRC_FILE..."
                # Replace "main(" at start of line (return type on prev line)
                sed -i.bak "s/^main(/$FUNC_NAME(/g" "$SRC_FILE"
                # Replace "int main(" at start of line
                sed -i.bak "s/^int main(/int $FUNC_NAME(/g" "$SRC_FILE"
                rm -f "$SRC_FILE.bak"
            fi
        done
    fi
fi

OPENSSH_DIR="$THIRD_PARTY_DIR/openssh"
if [ -d "$OPENSSH_DIR" ] && [ ! -f "$OPENSSH_DIR/configure" ]; then
    echo "Warning: OpenSSH configure script is missing."
    echo "setup_posix_env.sh will try autoreconf during the build stage."
fi

# musl libc (e.g. Alpine, aarch64-linux-musl cross builds) is missing a few
# BSD/glibc-only headers that several openssh files include unconditionally
# even though their actual use is already properly #ifdef-guarded (or, for
# <util.h>, declares the same openpty/forkpty/login_tty musl already gets via
# the HAVE_PTY_H-guarded <pty.h> a few lines below in every file that needs
# them for real). Guard the bare #include lines so musl targets build.
# Idempotent: only patches an unguarded include, safe to re-run.
for pair in "nlist.h:HAVE_NLIST_H" "util.h:HAVE_UTIL_H" "endian.h:HAVE_ENDIAN_H"; do
    HDR="${pair%%:*}"
    GUARD="${pair##*:}"
    for f in $(find "$OPENSSH_DIR" -name "*.c" -not -path "*/regress/*" -not -path "*/contrib/*" -exec grep -l "^#include <$HDR>$" {} + 2>/dev/null); do
        # Already guarded if the line immediately before the bare #include is
        # our #ifdef -- check this, not just "does the include exist", or a
        # second run would nest another #ifdef/#endif around an already-fixed
        # include every time.
        if grep -B1 "^#include <$HDR>\$" "$f" | grep -q "^#ifdef $GUARD\$"; then
            continue
        fi
        echo "Guarding <$HDR> include in $f for musl targets..."
        sed -i.bak "/^#include <$HDR>\$/{
            i\\
#ifdef $GUARD
            a\\
#endif
        }" "$f"
        rm -f "$f.bak"
    done
done

# openbsd-compat/{fnmatch,readpassphrase,getopt}.h are OpenBSD-compat shims
# that are each supposed to no-op themselves (via their own HAVE_* guard)
# when the platform already provides a real header of the same name -- but
# this project's include path puts openbsd-compat/ ahead of the system
# include dirs, so a bare #include <fnmatch.h>/<readpassphrase.h>/<getopt.h>
# anywhere in the tree resolves to these (now-empty) shims instead of the
# real system header, even when HAVE_* correctly reports the platform has
# one. Rewrite each to forward to the next header of the same name on the
# search path (the system one) via #include_next when available. Idempotent:
# skipped once the file already contains "#include_next".
if [ -d "$OPENSSH_DIR/openbsd-compat" ]; then
    FNMATCH_H="$OPENSSH_DIR/openbsd-compat/fnmatch.h"
    if [ -f "$FNMATCH_H" ] && ! grep -q "include_next" "$FNMATCH_H"; then
        echo "Patching openbsd-compat/fnmatch.h to forward to the system header when available..."
        python3 - "$FNMATCH_H" <<'PYEOF'
import sys
path = sys.argv[1]
with open(path) as f:
    text = f.read()
old = "#ifndef HAVE_FNMATCH_H\n/* Ensure we define FNM_CASEFOLD */\n#define __BSD_VISIBLE 1"
new = ("#ifdef HAVE_FNMATCH_H\n"
       "/* This directory is on the include search path ahead of the system's own\n"
       " * fnmatch.h, so a bare #include <fnmatch.h> anywhere in the tree would\n"
       " * otherwise resolve to this compat shim instead of the real header even\n"
       " * when the platform provides one. Forward to the next fnmatch.h on the\n"
       " * search path (the system one) so its declarations are actually visible. */\n"
       "#include_next <fnmatch.h>\n"
       "#else\n"
       "/* Ensure we define FNM_CASEFOLD */\n"
       "#define __BSD_VISIBLE 1")
assert old in text, "fnmatch.h shape changed upstream, patch needs review"
text = text.replace(old, new, 1)
text = text.replace("#endif /* !_FNMATCH_H_ */\n#endif /* ! HAVE_FNMATCH_H */",
                     "#endif /* !_FNMATCH_H_ */\n#endif /* HAVE_FNMATCH_H */", 1)
with open(path, "w") as f:
    f.write(text)
PYEOF
    fi

    READPASSPHRASE_H="$OPENSSH_DIR/openbsd-compat/readpassphrase.h"
    if [ -f "$READPASSPHRASE_H" ] && ! grep -q "include_next" "$READPASSPHRASE_H"; then
        echo "Patching openbsd-compat/readpassphrase.h to forward to the system header when available..."
        python3 - "$READPASSPHRASE_H" <<'PYEOF'
import sys
path = sys.argv[1]
with open(path) as f:
    text = f.read()
old = """#ifndef _READPASSPHRASE_H_
#define _READPASSPHRASE_H_

#include "includes.h"

#ifndef HAVE_READPASSPHRASE

#define RPP_ECHO_OFF    0x00\t\t/* Turn off echo (default). */
#define RPP_ECHO_ON     0x01\t\t/* Leave echo on. */
#define RPP_REQUIRE_TTY 0x02\t\t/* Fail if there is no tty. */
#define RPP_FORCELOWER  0x04\t\t/* Force input to lower case. */
#define RPP_FORCEUPPER  0x08\t\t/* Force input to upper case. */
#define RPP_SEVENBIT    0x10\t\t/* Strip the high bit from input. */
#define RPP_STDIN       0x20\t\t/* Read from stdin, not /dev/tty */

char * readpassphrase(const char *, char *, size_t, int);

#endif /* HAVE_READPASSPHRASE */

#endif /* !_READPASSPHRASE_H_ */"""
new = """#include "includes.h"

#ifdef HAVE_READPASSPHRASE
/* This directory is on the include search path ahead of the system's own
 * readpassphrase.h, so a bare #include <readpassphrase.h> anywhere in the
 * tree would otherwise resolve to this compat shim instead of the real
 * header even when the platform provides one. Forward to the next
 * readpassphrase.h on the search path (the system one). Deliberately no
 * _READPASSPHRASE_H_ guard around this branch: the system header has its
 * own guard, and defining the same macro name here would make its content
 * get skipped as "already included" without ever having been seen. */
#include_next <readpassphrase.h>
#elif !defined(_READPASSPHRASE_H_)
#define _READPASSPHRASE_H_

#define RPP_ECHO_OFF    0x00\t\t/* Turn off echo (default). */
#define RPP_ECHO_ON     0x01\t\t/* Leave echo on. */
#define RPP_REQUIRE_TTY 0x02\t\t/* Fail if there is no tty. */
#define RPP_FORCELOWER  0x04\t\t/* Force input to lower case. */
#define RPP_FORCEUPPER  0x08\t\t/* Force input to upper case. */
#define RPP_SEVENBIT    0x10\t\t/* Strip the high bit from input. */
#define RPP_STDIN       0x20\t\t/* Read from stdin, not /dev/tty */

char * readpassphrase(const char *, char *, size_t, int);

#endif /* HAVE_READPASSPHRASE */"""
assert old in text, "readpassphrase.h shape changed upstream, patch needs review"
text = text.replace(old, new, 1)
with open(path, "w") as f:
    f.write(text)
PYEOF
    fi

    GETOPT_H="$OPENSSH_DIR/openbsd-compat/getopt.h"
    if [ -f "$GETOPT_H" ] && ! grep -q "include_next" "$GETOPT_H"; then
        echo "Patching openbsd-compat/getopt.h to forward to the system header when available..."
        python3 - "$GETOPT_H" <<'PYEOF'
import sys
path = sys.argv[1]
with open(path) as f:
    text = f.read()
old_head = "#ifndef _GETOPT_H_\n#define _GETOPT_H_\n\n#ifndef __THROW"
new_head = """#if defined(HAVE_GETOPT_H) && defined(HAVE_GETOPT_OPTRESET)
/* This directory is on the include search path ahead of the system's own
 * getopt.h, so a bare #include <getopt.h> anywhere in the tree would
 * otherwise resolve to this compat shim instead of the real header even
 * when the platform provides one (its struct option/getopt_long/
 * getopt_long_only declarations below are `#if 0`'d out precisely because
 * they assume the system header will be the one actually seen). Forward to
 * the next getopt.h on the search path (the system one) -- but ONLY when
 * the system also has BSD's optreset (HAVE_GETOPT_OPTRESET): openbsd-
 * compat/getopt_long.c's own struct option/getopt_long stay compiled in
 * (its guard is `!HAVE_GETOPT || !HAVE_GETOPT_OPTRESET`) on any libc that
 * has getopt_long but lacks optreset -- glibc among them. Forwarding
 * unconditionally on HAVE_GETOPT_H alone pulls the system's conflicting
 * struct option into the same translation unit as getopt_long.c's own,
 * which is a redefinition error, not a redundant-but-harmless one.
 * Deliberately no _GETOPT_H_ guard around this branch: the system header
 * has its own guard, and defining the same macro name here would make its
 * content get skipped as "already included" without ever having been seen. */
#include_next <getopt.h>
#elif !defined(_GETOPT_H_)
#define _GETOPT_H_

#ifndef __THROW"""
assert old_head in text, "getopt.h shape changed upstream, patch needs review"
text = text.replace(old_head, new_head, 1)

old_struct = "#if 0\nstruct option {"
new_struct = ("/* Not every translation unit that reaches this fallback branch (i.e. that\n"
              " * doesn't take the include_next path above) defines HAVE_GETOPT_H in its\n"
              " * own config.h -- notably the vendored third-party/openrsync tree, which\n"
              " * has an entirely separate config.h that never mentions getopt at all. The\n"
              " * GNU-style struct option/getopt_long/getopt_long_only ABI below is stable\n"
              " * across every platform this project targets (Linux glibc, macOS, *BSD),\n"
              " * so it's safe to always provide it here rather than gating it further --\n"
              " * EXCEPT for openbsd-compat/getopt_long.c itself, which reaches this same\n"
              " * fallback branch (via includes.h) on any libc with getopt but no BSD\n"
              " * optreset (glibc among them) and ALSO defines this exact struct/functions\n"
              " * a few lines further down in that same file -- a real double-definition,\n"
              " * not a redundant-but-harmless one. It defines the sentinel below before\n"
              " * including anything, specifically to skip this copy. */\n"
              "#ifndef SMALLCLUE_GETOPT_LONG_C_OWN_STRUCT_OPTION\n"
              "struct option {")
assert old_struct in text, "getopt.h struct option shape changed upstream, patch needs review"
text = text.replace(old_struct, new_struct, 1)

old_tail = """int\t getopt_long(int, char * const *, const char *,
\t    const struct option *, int *);
int\t getopt_long_only(int, char * const *, const char *,
\t    const struct option *, int *);
#endif

#ifndef _GETOPT_DEFINED_"""
new_tail = """int\t getopt_long(int, char * const *, const char *,
\t    const struct option *, int *);
int\t getopt_long_only(int, char * const *, const char *,
\t    const struct option *, int *);
#endif /* !SMALLCLUE_GETOPT_LONG_C_OWN_STRUCT_OPTION */

#ifndef _GETOPT_DEFINED_"""
assert old_tail in text, "getopt.h tail shape changed upstream, patch needs review"
text = text.replace(old_tail, new_tail, 1)
with open(path, "w") as f:
    f.write(text)
PYEOF
    fi

    GETOPT_LONG_C="$OPENSSH_DIR/openbsd-compat/getopt_long.c"
    if [ -f "$GETOPT_LONG_C" ] && ! grep -q "SMALLCLUE_GETOPT_LONG_C_OWN_STRUCT_OPTION" "$GETOPT_LONG_C"; then
        echo "Patching openbsd-compat/getopt_long.c to skip getopt.h's own struct option copy..."
        python3 - "$GETOPT_LONG_C" <<'PYEOF'
import sys
path = sys.argv[1]
with open(path) as f:
    text = f.read()
old = '/* OPENBSD ORIGINAL: lib/libc/stdlib/getopt_long.c */\n#include "includes.h"'
new = ('/* OPENBSD ORIGINAL: lib/libc/stdlib/getopt_long.c */\n'
       '/* This file defines its own struct option/getopt_long/getopt_long_only\n'
       ' * (guarded below by !HAVE_GETOPT || !HAVE_GETOPT_OPTRESET) whenever the\n'
       ' * platform lacks BSD optreset -- true on glibc. includes.h pulls in this\n'
       ' * same directory\'s own getopt.h too (via openbsd-compat.h), which in its\n'
       ' * fallback branch also defines that struct for OTHER consumers (notably\n'
       ' * openrsync) that never define it themselves. Without this sentinel both\n'
       ' * copies land in this one translation unit -- a real redefinition, not a\n'
       ' * redundant-but-harmless one. */\n'
       '#define SMALLCLUE_GETOPT_LONG_C_OWN_STRUCT_OPTION 1\n'
       '#include "includes.h"')
assert old in text, "getopt_long.c shape changed upstream, patch needs review"
text = text.replace(old, new, 1)
with open(path, "w") as f:
    f.write(text)
PYEOF
    fi
fi

# scp.c/sftp.c both define their own file-scope `showprogress`/`interrupted`
# globals; sftp-client.c externs a would-be-shared `interrupted` too. Linked
# into one smallclue binary (rather than three separate scp/sftp/sftp
# executables as upstream expects), these collide. src/openssh_globals.c
# already provides the single shared pscal_openssh_showprogress/
# pscal_openssh_interrupted definitions -- alias each file's own name to
# them instead of defining/declaring its own copy. Idempotent: skipped once
# a file already references pscal_openssh_interrupted.
if [ -f "$OPENSSH_DIR/scp.c" ] && ! grep -q "pscal_openssh_interrupted" "$OPENSSH_DIR/scp.c"; then
    echo "Aliasing scp.c's showprogress/interrupted globals to the shared openssh_globals.c ones..."
    python3 - "$OPENSSH_DIR/scp.c" <<'PYEOF'
import sys
path = sys.argv[1]
with open(path) as f:
    text = f.read()
text = text.replace(
    "/* This is set to zero if the progressmeter is not desired. */\nint showprogress = 1;",
    "/* This is set to zero if the progressmeter is not desired. scp.c and sftp.c\n"
    " * are both linked into the same smallclue binary, so this can't be a\n"
    " * plain file-scope global in each -- it has to be the single shared\n"
    " * definition in src/openssh_globals.c, aliased here by macro. */\n"
    "extern int pscal_openssh_showprogress;\n"
    "#define showprogress pscal_openssh_showprogress", 1)
text = text.replace(
    "/* Needed for sftp */\nvolatile sig_atomic_t interrupted = 0;",
    "/* Needed for sftp. Shared with sftp.c/sftp-client.c for the same reason as\n"
    " * showprogress above -- single definition in src/openssh_globals.c. */\n"
    "extern volatile sig_atomic_t pscal_openssh_interrupted;\n"
    "#define interrupted pscal_openssh_interrupted", 1)
with open(path, "w") as f:
    f.write(text)
PYEOF
fi

if [ -f "$OPENSSH_DIR/sftp.c" ] && ! grep -q "pscal_openssh_interrupted" "$OPENSSH_DIR/sftp.c"; then
    echo "Aliasing sftp.c's showprogress/interrupted globals to the shared openssh_globals.c ones..."
    python3 - "$OPENSSH_DIR/sftp.c" <<'PYEOF'
import sys
path = sys.argv[1]
with open(path) as f:
    text = f.read()
text = text.replace(
    "/* This is set to 0 if the progressmeter is not desired. */\nint showprogress = 1;",
    "/* This is set to 0 if the progressmeter is not desired. Shared with scp.c/\n"
    " * sftp-client.c -- single definition in src/openssh_globals.c. */\n"
    "extern int pscal_openssh_showprogress;\n"
    "#define showprogress pscal_openssh_showprogress", 1)
text = text.replace(
    "/* SIGINT received during command processing */\nvolatile sig_atomic_t interrupted = 0;",
    "/* SIGINT received during command processing. Shared with scp.c/\n"
    " * sftp-client.c -- single definition in src/openssh_globals.c. */\n"
    "extern volatile sig_atomic_t pscal_openssh_interrupted;\n"
    "#define interrupted pscal_openssh_interrupted", 1)
with open(path, "w") as f:
    f.write(text)
PYEOF
fi

if [ -f "$OPENSSH_DIR/sftp-client.c" ] && grep -q "^extern volatile sig_atomic_t interrupted;$" "$OPENSSH_DIR/sftp-client.c"; then
    echo "Aliasing sftp-client.c's interrupted extern to the shared openssh_globals.c one..."
    python3 - "$OPENSSH_DIR/sftp-client.c" <<'PYEOF'
import sys
path = sys.argv[1]
with open(path) as f:
    text = f.read()
text = text.replace(
    "extern volatile sig_atomic_t interrupted;\n",
    "extern volatile sig_atomic_t pscal_openssh_interrupted;\n"
    "#define interrupted pscal_openssh_interrupted\n", 1)
with open(path, "w") as f:
    f.write(text)
PYEOF
fi

echo "Dependencies fetched and patched."
