#!/bin/bash
set -e

SMALLCLUE_SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Check for root privileges
if [ "$(id -u)" -ne 0 ]; then
    echo "This script requires root privileges to set up the rootfs correctly."
    echo "Please run with sudo: sudo $0"
    exit 1
fi

# 0-3. Build ./smallclue (fetch deps, generate stubs, compile OpenSSH/
#      dvtm/libgit2/smallclue). None of that needs root; split out so
#      it can be run standalone via ./build_smallclue.sh (no sudo) --
#      only the rootfs assembly below actually needs it.
"$SMALLCLUE_SCRIPT_DIR/build_smallclue.sh"

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

# 5. Install smallclue
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
    ln -sf smallclue "$ROOTFS/bin/$applet"
done

# Sanity check: if smallclue advertises an "rsync" applet, the symlink it
# depends on for local-to-local transfers (openrsync's execvp("rsync", ...)
# re-exec) must actually be there and resolve back to smallclue. A silent
# miss here means every "rsync -a src/ dst/" invocation fails with ENOENT
# inside the rootfs, with no other build-time signal.
if echo "$APPLETS" | grep -qx "rsync"; then
    RSYNC_LINK_TARGET=$(readlink "$ROOTFS/bin/rsync" 2>/dev/null || true)
    if [ "$RSYNC_LINK_TARGET" != "smallclue" ]; then
        echo "ERROR: 'rsync' applet is advertised by smallclue but $ROOTFS/bin/rsync" >&2
        echo "       is not a 'smallclue' symlink (got: '${RSYNC_LINK_TARGET:-<missing>}')." >&2
        echo "       openrsync's local-to-local transfer path execvp()s literal 'rsync'" >&2
        echo "       and will fail with ENOENT without this symlink." >&2
        exit 1
    fi
fi

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
export ENV=\$HOME/.shrc
export PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin
EOF
chown 1000:1000 "$ROOTFS/home/username/.profile"

echo "Creating .shrc..."
cat > "$ROOTFS/home/username/.shrc" <<EOF
# Basic sh configuration

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
chown 1000:1000 "$ROOTFS/home/username/.shrc"

echo "Creating root .profile..."
cat > "$ROOTFS/root/.profile" <<EOF
export ENV=\$HOME/.shrc
export PATH=/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin
EOF

echo "Creating root .shrc..."
cat > "$ROOTFS/root/.shrc" <<EOF
# Basic sh configuration

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
