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

# --- Linenoise ---
if [ ! -d "$THIRD_PARTY_DIR/linenoise" ]; then
    echo "Cloning linenoise..."
    git clone https://github.com/antirez/linenoise "$THIRD_PARTY_DIR/linenoise"
fi

# --- Dash ---
if [ ! -d "$THIRD_PARTY_DIR/dash" ]; then
    echo "Cloning dash..."
    git clone https://git.kernel.org/pub/scm/utils/dash/dash.git "$THIRD_PARTY_DIR/dash"
    # Pin to a stable release (v0.5.13.1)
    (cd "$THIRD_PARTY_DIR/dash" && git checkout v0.5.13.1)
fi

# --- Dash Integration (Linenoise) ---
DASH_SRC="$THIRD_PARTY_DIR/dash/src"
if [ -d "$DASH_SRC" ]; then
    echo "Integrating linenoise into dash..."
    cp "$THIRD_PARTY_DIR/linenoise/linenoise.c" "$DASH_SRC/"
    cp "$THIRD_PARTY_DIR/linenoise/linenoise.h" "$DASH_SRC/"

    # Patch Makefile.am to include linenoise.c
    if ! grep -q "linenoise.c" "$DASH_SRC/Makefile.am"; then
        echo "Patching dash Makefile.am..."
        sed -i.bak 's/input.c/input.c linenoise.c/g' "$DASH_SRC/Makefile.am"
        rm -f "$DASH_SRC/Makefile.am.bak"
    fi

    # Patch input.c
    INPUT_C="$DASH_SRC/input.c"
    if [ -f "$INPUT_C" ]; then
        if ! grep -q 'linenoise.h' "$INPUT_C"; then
            echo "Patching dash input.c includes..."
            awk '
                { print }
                /#include "trap.h"/ {
                    print "#include \"linenoise.h\""
                }
            ' "$INPUT_C" > "$INPUT_C.tmp" && mv "$INPUT_C.tmp" "$INPUT_C"
        fi

        if ! grep -q '^#include <ctype.h>' "$INPUT_C"; then
            awk '
                BEGIN { done = 0 }
                {
                    print
                    if (!done && $0 ~ /^#include <stdio.h>/) {
                        print "#include <ctype.h>"
                        print "#include <dirent.h>"
                        print "#include <limits.h>"
                        print "#include <sys/stat.h>"
                        done = 1
                    }
                }
            ' "$INPUT_C" > "$INPUT_C.tmp" && mv "$INPUT_C.tmp" "$INPUT_C"
        fi

        if ! grep -q 'PSCAL_LINENOISE_COMPLETION_BEGIN' "$INPUT_C"; then
            echo "Patching dash input.c completion helpers..."
            cat > "$DASH_SRC/linenoise_completion_helpers.c" <<'EOF'
/* PSCAL_LINENOISE_COMPLETION_BEGIN */
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static void
smallclueLinenoiseAddMergedCompletion(const char *buf, size_t token_start,
				      const char *replacement,
				      linenoiseCompletions *lc)
{
	size_t prefix_len = token_start;
	size_t repl_len = strlen(replacement);
	char merged[PATH_MAX * 2];

	if (prefix_len + repl_len + 1 >= sizeof(merged))
		return;
	memcpy(merged, buf, prefix_len);
	memcpy(merged + prefix_len, replacement, repl_len);
	merged[prefix_len + repl_len] = '\0';
	linenoiseAddCompletion(lc, merged);
}

static int
smallcluePrefixMatch(const char *text, const char *prefix)
{
	size_t prefix_len = strlen(prefix);
	return strncmp(text, prefix, prefix_len) == 0;
}

static void
smallclueLinenoiseCompletePath(const char *buf, size_t token_start,
			       const char *token, linenoiseCompletions *lc)
{
	const char *slash = strrchr(token, '/');
	const char *name_prefix = token;
	char dir_open[PATH_MAX];
	char dir_emit[PATH_MAX];
	DIR *dir;
	struct dirent *entry;

	if (slash) {
		size_t emit_len = (size_t)(slash - token + 1);
		if (emit_len >= sizeof(dir_emit))
			return;
		memcpy(dir_emit, token, emit_len);
		dir_emit[emit_len] = '\0';
		name_prefix = slash + 1;
		if (strcmp(dir_emit, "/") == 0) {
			snprintf(dir_open, sizeof(dir_open), "/");
		} else {
			size_t open_len = emit_len - 1;
			if (open_len >= sizeof(dir_open))
				return;
			memcpy(dir_open, token, open_len);
			dir_open[open_len] = '\0';
			if (open_len == 0)
				snprintf(dir_open, sizeof(dir_open), ".");
		}
	} else {
		dir_emit[0] = '\0';
		snprintf(dir_open, sizeof(dir_open), ".");
	}

	dir = opendir(dir_open);
	if (!dir)
		return;

	while ((entry = readdir(dir)) != NULL) {
		char candidate[PATH_MAX];
		char fullpath[PATH_MAX];
		size_t candidate_len;
		struct stat st;

		if (name_prefix[0] != '.' && entry->d_name[0] == '.')
			continue;
		if (!smallcluePrefixMatch(entry->d_name, name_prefix))
			continue;

		snprintf(candidate, sizeof(candidate), "%s%s", dir_emit, entry->d_name);
		if (slash) {
			if (strcmp(dir_open, "/") == 0)
				snprintf(fullpath, sizeof(fullpath), "/%s", entry->d_name);
			else
				snprintf(fullpath, sizeof(fullpath), "%s/%s", dir_open, entry->d_name);
		} else {
			snprintf(fullpath, sizeof(fullpath), "%s", entry->d_name);
		}

		candidate_len = strlen(candidate);
		if (candidate_len + 1 < sizeof(candidate) &&
		    stat(fullpath, &st) == 0 &&
		    S_ISDIR(st.st_mode) &&
		    (candidate_len == 0 || candidate[candidate_len - 1] != '/')) {
			candidate[candidate_len++] = '/';
			candidate[candidate_len] = '\0';
		}

		smallclueLinenoiseAddMergedCompletion(buf, token_start, candidate, lc);
	}

	closedir(dir);
}

static void
smallclueLinenoiseCompleteCommands(const char *buf, size_t token_start,
				   const char *token, linenoiseCompletions *lc)
{
	char *path_copy;
	char *saveptr = NULL;
	char *segment;
	const char *path_env = getenv("PATH");

	if (!path_env || !*path_env)
		return;

	path_copy = strdup(path_env);
	if (!path_copy)
		return;

	for (segment = strtok_r(path_copy, ":", &saveptr);
	     segment;
	     segment = strtok_r(NULL, ":", &saveptr)) {
		DIR *dir;
		struct dirent *entry;
		const char *dir_path = (*segment == '\0') ? "." : segment;

		dir = opendir(dir_path);
		if (!dir)
			continue;

		while ((entry = readdir(dir)) != NULL) {
			char fullpath[PATH_MAX];
			struct stat st;

			if (entry->d_name[0] == '.')
				continue;
			if (!smallcluePrefixMatch(entry->d_name, token))
				continue;

			snprintf(fullpath, sizeof(fullpath), "%s/%s", dir_path, entry->d_name);
			if (stat(fullpath, &st) != 0 || !S_ISREG(st.st_mode))
				continue;
			if (access(fullpath, X_OK) != 0)
				continue;

			smallclueLinenoiseAddMergedCompletion(buf, token_start, entry->d_name, lc);
		}
		closedir(dir);
	}

	free(path_copy);
}

static void
smallclueLinenoiseCompletion(const char *buf, linenoiseCompletions *lc)
{
	size_t len;
	size_t token_start;
	const char *token;

	if (!buf)
		return;

	len = strlen(buf);
	if (len == 0)
		return;

	token_start = len;
	while (token_start > 0 &&
	       !isspace((unsigned char)buf[token_start - 1]))
		token_start--;

	token = buf + token_start;
	if (*token == '\0')
		return;

	if (token_start == 0 && strchr(token, '/') == NULL)
		smallclueLinenoiseCompleteCommands(buf, token_start, token, lc);
	smallclueLinenoiseCompletePath(buf, token_start, token, lc);
}
/* PSCAL_LINENOISE_COMPLETION_END */
EOF
            HELPER_LINE=$(grep -n '^#define IBUFSIZ' "$INPUT_C" | head -n 1 | cut -d: -f1)
            if [ -n "$HELPER_LINE" ]; then
                head -n $((HELPER_LINE - 1)) "$INPUT_C" > "$INPUT_C.tmp"
                cat "$DASH_SRC/linenoise_completion_helpers.c" >> "$INPUT_C.tmp"
                tail -n +"$HELPER_LINE" "$INPUT_C" >> "$INPUT_C.tmp"
                mv "$INPUT_C.tmp" "$INPUT_C"
            fi
            rm -f "$DASH_SRC/linenoise_completion_helpers.c"
        fi

        # Replace the linenoise read block with completion-aware version.
        if ! grep -q 'linenoiseSetCompletionCallback' "$INPUT_C"; then
            echo "Patching dash input.c linenoise read loop..."
            cat > "$DASH_SRC/linenoise_patch.c" <<'EOF'
	if (fd == 0 && isatty(0)) {
		static char *ln_buf = NULL;
		static int ln_len = 0;
		static int ln_pos = 0;
		static int history_loaded = 0;
		static int completion_loaded = 0;

		if (!history_loaded) {
			const char *home = getenv("HOME");
			if (home) {
				char path[1024];
				snprintf(path, sizeof(path), "%s/.sh_history", home);
				linenoiseHistoryLoad(path);
			}
			history_loaded = 1;
		}
		if (!completion_loaded) {
			linenoiseSetCompletionCallback(smallclueLinenoiseCompletion);
			completion_loaded = 1;
		}

		if (ln_buf == NULL) {
			char *line = linenoise(getprompt(NULL));
			if (line) {
				if (*line) {
					linenoiseHistoryAdd(line);
					const char *home = getenv("HOME");
					if (home) {
						char path[1024];
						snprintf(path, sizeof(path), "%s/.sh_history", home);
						linenoiseHistorySave(path);
					}
				}
				int len = strlen(line);
				ln_buf = malloc(len + 2);
				if (ln_buf) {
					strcpy(ln_buf, line);
					ln_buf[len] = '\n';
					ln_buf[len + 1] = '\0';
					ln_len = len + 1;
					ln_pos = 0;
				}
				free(line);
			} else {
				return 0;
			}
		}

		if (ln_buf) {
			int to_copy = ln_len - ln_pos;
			if (to_copy > nr)
				to_copy = nr;
			memcpy(buf, ln_buf + ln_pos, to_copy);
			ln_pos += to_copy;
			if (ln_pos >= ln_len) {
				free(ln_buf);
				ln_buf = NULL;
				ln_len = 0;
				ln_pos = 0;
			}
			return to_copy;
		}
	}
EOF
            START_LINE=$(grep -n 'if (fd == 0 && isatty(0)) {' "$INPUT_C" | head -n 1 | cut -d: -f1)
            END_LINE=$(awk -v start="$START_LINE" 'NR > start && /#ifndef SMALL/ { print NR; exit }' "$INPUT_C")
            if [ -n "$START_LINE" ] && [ -n "$END_LINE" ]; then
                head -n $((START_LINE - 1)) "$INPUT_C" > "$INPUT_C.tmp"
                cat "$DASH_SRC/linenoise_patch.c" >> "$INPUT_C.tmp"
                tail -n +"$END_LINE" "$INPUT_C" >> "$INPUT_C.tmp"
                mv "$INPUT_C.tmp" "$INPUT_C"
            fi
            rm -f "$DASH_SRC/linenoise_patch.c"
        fi

        # Keep the old libedit branch compiled out when linenoise is active.
        if ! grep -q "if (0) { /\* replaced by linenoise \*/" "$INPUT_C"; then
            sed -i.bak 's/if (fd == 0 && el) {/if (0) { \/* replaced by linenoise *\//' "$INPUT_C"
            rm -f "$INPUT_C.bak"
        fi
    fi

    # Patch parser.c to suppress prompt when using linenoise (which handles prompt itself)
    PARSER_C="$DASH_SRC/parser.c"
    if [ -f "$PARSER_C" ]; then
        if grep -q "show = 1;" "$PARSER_C"; then
            echo "Patching dash parser.c..."
            sed -i.bak 's/show = 1;/show = !stdin_istty;/g' "$PARSER_C"
            sed -i.bak 's/show = !el;/show = !el \&\& !stdin_istty;/g' "$PARSER_C"
            rm -f "$PARSER_C.bak"
        fi
    fi
fi

echo "Dependencies fetched and patched."
