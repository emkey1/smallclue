#!/bin/bash
set -e

THIRD_PARTY_DIR="third-party"

mkdir -p "$THIRD_PARTY_DIR"

# --- Nextvi ---
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
if [ ! -d "$THIRD_PARTY_DIR/openssh" ]; then
    echo "Cloning OpenSSH Portable..."
    git clone https://github.com/openssh/openssh-portable "$THIRD_PARTY_DIR/openssh"
    # Pin to a stable release
    (cd "$THIRD_PARTY_DIR/openssh" && git checkout V_9_7_P1)

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
if [ -d "$OPENSSH_DIR" ] && [ ! -f "$OPENSSH_DIR/Makefile" ]; then
    # Try configure if autoreconf is available or if configure exists
    if [ -f "$OPENSSH_DIR/configure" ]; then
        echo "Configuring OpenSSH..."
        (cd "$OPENSSH_DIR" && ./configure)
    elif command -v autoreconf >/dev/null 2>&1; then
        echo "Generating configure for OpenSSH (this may take a moment)..."
        if ! (cd "$OPENSSH_DIR" && autoreconf -i > autoreconf.log 2>&1); then
            echo "Error: autoreconf failed."
            echo "--- autoreconf output ---"
            cat "$OPENSSH_DIR/autoreconf.log"
            echo "-------------------------"
            echo "Please ensure you have autoconf and automake installed."
            exit 1
        fi
        (cd "$OPENSSH_DIR" && ./configure)
    else
        echo "Error: autoreconf not found. Cannot configure OpenSSH."
        echo "Please install autoconf (and automake)."
        if [ "$(uname -s)" = "Darwin" ]; then
            echo "On macOS: brew install autoconf automake"
        else
            echo "On Linux: sudo apt-get install autoconf automake"
        fi
        exit 1
    fi
fi

# --- Linenoise ---
if [ ! -d "$THIRD_PARTY_DIR/linenoise" ]; then
    echo "Cloning linenoise..."
    git clone https://github.com/antirez/linenoise "$THIRD_PARTY_DIR/linenoise"
fi

# --- Dash ---
if [ ! -d "$THIRD_PARTY_DIR/dash" ]; then
    echo "Cloning dash..."
    git clone git://git.kernel.org/pub/scm/utils/dash/dash.git "$THIRD_PARTY_DIR/dash"
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
    if ! grep -q "linenoise.h" "$INPUT_C"; then
        echo "Patching dash input.c..."
        sed -i.bak '/#include "trap.h"/a #include "linenoise.h"' "$INPUT_C"

        # Create patch content for linenoise integration
        cat > "$DASH_SRC/linenoise_patch.c" <<'EOF'
	if (fd == 0 && isatty(0)) {
		static char *ln_buf = NULL;
		static int ln_len = 0;
		static int ln_pos = 0;

		if (ln_buf == NULL) {
			char *line = linenoise(getprompt(NULL));
			if (line) {
				linenoiseHistoryAdd(line);
				int len = strlen(line);
				ln_buf = malloc(len + 2);
				if (ln_buf) {
					strcpy(ln_buf, line);
					ln_buf[len] = '\n';
					ln_buf[len+1] = '\0';
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
			if (to_copy > nr) to_copy = nr;
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
        # Replace the libedit block with a marker
        sed -i.bak 's/if (fd == 0 && el) {/if (0) { \/* replaced by linenoise *\//' "$INPUT_C"

        # Insert new block before the marker
        LINE_NUM=$(grep -n "if (0) { /\* replaced by linenoise \*/" "$INPUT_C" | cut -d: -f1)
        if [ ! -z "$LINE_NUM" ]; then
             head -n $(($LINE_NUM - 2)) "$INPUT_C" > "$INPUT_C.tmp"
             cat "$DASH_SRC/linenoise_patch.c" >> "$INPUT_C.tmp"
             tail -n +$(($LINE_NUM - 1)) "$INPUT_C" >> "$INPUT_C.tmp"
             mv "$INPUT_C.tmp" "$INPUT_C"
        fi

        rm -f "$INPUT_C.bak" "$DASH_SRC/linenoise_patch.c"
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
