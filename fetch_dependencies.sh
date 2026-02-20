#!/bin/bash
set -e

THIRD_PARTY_DIR="third-party"

# Clean up previous attempts to ensure correct patching
if [ -d "$THIRD_PARTY_DIR" ]; then
    echo "Cleaning up $THIRD_PARTY_DIR..."
    rm -rf "$THIRD_PARTY_DIR"
fi

mkdir -p "$THIRD_PARTY_DIR"

# --- Nextvi ---
echo "Cloning nextvi..."
git clone https://github.com/kyx0r/nextvi "$THIRD_PARTY_DIR/nextvi"
# Pin to a known working commit/tag if possible. Using HEAD for now as it is stable.
# (cd "$THIRD_PARTY_DIR/nextvi" && git checkout <hash>)

# Find main file for nextvi
NEXTVI_MAIN=$(grep -l "int main" "$THIRD_PARTY_DIR/nextvi"/*.c | head -n 1)
if [ -f "$NEXTVI_MAIN" ]; then
    echo "Patching nextvi main in $NEXTVI_MAIN..."
    # Match "int main(" and replace with "int nextvi_main_entry("
    sed -i 's/int main(/int nextvi_main_entry(/g' "$NEXTVI_MAIN"

    # Add nextvi_reset_state stub if not present
    if ! grep -q "void nextvi_reset_state" "$NEXTVI_MAIN"; then
        echo "" >> "$NEXTVI_MAIN"
        echo "void nextvi_reset_state(void) {}" >> "$NEXTVI_MAIN"
    fi
else
    echo "Could not find nextvi main file."
fi

# --- OpenSSH ---
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
            sed -i "s/^main(/$FUNC_NAME(/g" "$SRC_FILE"
            # Replace "int main(" at start of line
            sed -i "s/^int main(/int $FUNC_NAME(/g" "$SRC_FILE"
        fi
    done

    # Try configure if autoreconf is available or if configure exists
    if [ -f "$OPENSSH_DIR/configure" ]; then
        echo "Configuring OpenSSH..."
        (cd "$OPENSSH_DIR" && ./configure)
    elif command -v autoreconf >/dev/null 2>&1; then
        echo "Generating configure for OpenSSH..."
        (cd "$OPENSSH_DIR" && autoreconf -i && ./configure)
    else
        echo "Error: autoreconf not found. Cannot configure OpenSSH."
        echo "Please install autoconf."
        exit 1
    fi
fi

echo "Dependencies fetched and patched."
