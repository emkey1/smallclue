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

# --- Dash ---
if [ ! -d "$THIRD_PARTY_DIR/dash" ]; then
    echo "Cloning dash..."
    git clone git://git.kernel.org/pub/scm/utils/dash/dash.git "$THIRD_PARTY_DIR/dash"
fi

echo "Dependencies fetched and patched."
