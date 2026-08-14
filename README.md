# SmallCLUE (Small Command Line Unix Environment)

**SmallCLUE** is a lightweight, multicall binary that provides a suite of standard Unix-like utilities. It is designed specifically for constrained or sandboxed environments where standard GNU/BSD core utilities are unavailable, such as custom terminal emulators on iOS and iPadOS (e.g., PSCAL).

Functionally similar to BusyBox, `SmallCLUE` combines many common tools (like `ls`, `cp`, `grep`, `ssh`) into a single executable to reduce overhead and simplify integration.

## Overview

* **Multicall Architecture:** Invoking the binary as `smallclue ls` or symlinking `ls` to `smallclue` runs the `ls` applet.
* **Zero-Dependency Implementations:** Most core utilities are implemented directly in C within `src/core.c` to minimize external dependencies.
* **Third-Party Integration:** Includes wrappers for complex tools like **OpenSSH** and **Nextvi**.
* **iOS Specifics:** Features applets designed for iOS quirks, such as `pbcopy`/`pbpaste` for system clipboard access and specialized path virtualization hooks.

## Available Applets

`SmallCLUE` currently implements the following commands:

### File Management
* **ls**: List directory contents (supports colors, `-l`, `-h`, `-a`, `-t`, `-R` recursive, `-i` inode, `-S`/`-X`/`-v`/`-r` sort order).
* **cp**: Copy files and directories (`-r`/`-R` recursive, `-a` archive, `-p` preserve timestamps).
* **rsync**: By default, dispatches to the vendored upstream **openrsync** (`third-party/openrsync/`), a real rsync-protocol client -- not the hand-rolled local-sync-plus-scp engine described below. Supports `-u`/`--update` (skip files whose destination copy is newer than the source), `--compare-dest`/`--copy-dest`/`--link-dest` (skip/copy/hardlink unchanged files from a reference directory instead of re-transferring them), pushing to a remote rsync daemon (`rsync://host/module/path` or `host::module/path` as the destination, not just as a source), `--progress` (live per-file transfer percentage), and real `-z`/`--compress` rsync-protocol payload compression (not just SSH transport compression), and real `-c`/`--checksum` (never trust size/mtime alone; force a real content comparison via block-transfer checksums). Notes: `-z`'s wire format is openrsync/smallclue's own (not byte-compatible with GNU rsync's compression scheme) -- it works for any transfer where smallclue is on both ends (local sync, ssh between two smallclue instances, daemon between two smallclue instances), but fails loudly and immediately (not silently) if used against an unmodified real rsync peer. `-c` has the *same* "smallclue on both ends" assumption but a worse failure mode against a foreign peer: rather than failing loudly, it can hang indefinitely (both sides blocked in poll() waiting on each other) -- pass `--timeout=N` explicitly if combining `-c` with a peer that might not be openrsync/smallclue. Set `PSCALI_RSYNC_LEGACY=1` to use the legacy hand-rolled engine instead, which synchronizes files/directories locally or over SSH (`-a`, `-r`, `-p`, `-t`, `-u`, `-c`, `-v`, `-z`, `-n`, `--delete`, `--include`, `--exclude`) and routes remote `host:path` transfers through the OpenSSH `scp` backend (supports `-a/-r/-p/-t/-v/-z`, plus `-n` preview; remote `-u/-c/--include/--exclude/--delete` are not yet implemented in that legacy path).
* **mv**: Move or rename files.
* **rm**: Remove files and directories (`-r`/`-R`, `-f`, `-i`, `--preserve-root`).
* **mkdir** / **rmdir**: Create or remove directories.
* **touch**: Update file timestamps or create empty files (`-c`, `-d`, `-t`, `-r`).
* **ln**: Create links (symbolic and hard; `-f` force, `-s` symbolic, directory-target auto-append).
* **mount** / **umount**: Add or remove filesystem mounts (real `mount(2)`/`umount(2)` syscall wrappers on Linux; `umount` supports `-l`/`-f` lazy/force unmount).
* **pwd**: Print working directory.
* **chmod**: Change file modes/permissions (supports octal and symbolic `u+x`, `-R` recursive).
* **du**: Estimate file space usage (GNU-default directory-subtotal behavior, `--max-depth`, `-c` grand total, `-x` one-filesystem, `-h`).
* **df**: Report file system disk space usage (enumerates all mounts from `/proc/mounts` when no path is given).
* **chown** / **chgrp**: Change file ownership/group.
* **chroot**: Run a command (or shell) with a new root directory, optionally dropping to another user/group.
* **file**: Determine file type.
* **stat**: Display file status.
* **basename** / **dirname**: Parse path components (multi-operand support; `basename` supports a `SUFFIX` operand).
* **find**: Search for files and directories (`-name`, `-type`, `-exec`, `-delete`, `-maxdepth`/`-mindepth`, `-mtime`/`-newer`, `-size`, `-print0`, and full boolean logic: `-a`/`-and` (implicit between adjacent terms), `-o`/`-or`, `!`/`-not`, `\( \)` grouping).
* **readlink** / **realpath**: Print resolved symbolic links or canonicalized absolute paths.
* **install**: Copy files and set attributes (or create directories), like `make install`'s underlying tool.
* **diff**: Compare files line by line (`-u` unified, `-q`).
* **patch**: Apply a unified diff to files.
* **cmp**: Compare two files byte by byte.
* **dd**: Convert and copy a file block by block (`if=`/`of=`/`bs=`/`count=`/`skip=`/`seek=`/`conv=notrunc`).
* **od**: Dump files in octal/hex/decimal/character format.

### Archives & Compression
* **tar**: Create, extract, or list tar archives (`-c`/`-x`/`-t`, `-z` for `.tar.gz`).
* **gzip** / **gunzip**: Compress/decompress files (via the already-linked zlib dependency).

### Text Processing & Filtering
* **cat**: Concatenate and print files.
* **echo**: Print arguments to standard output.
* **grep**: File pattern searcher with real POSIX regex support (supports `-i`, `-v`, `-n`, `-r`/`-R` recursive, `-c`, `-o`, `-w`, `-x`, `--color`).
* **head** / **tail**: Output the first/last part of files (tail supports `-f` follow).
* **more** / **less**: File paging filters.
* **wc**: Word, line, character, and byte count (`-l`, `-w`, `-c`, `-m` locale-aware character count, `-L` max line length).
* **sort**: Sort lines of text files.
* **uniq**: Report or omit repeated lines.
* **cut**: Remove sections from each line of files.
* **sed**: Stream editor with real POSIX regex support (`s///` substitution, `y///` transliteration, `d`/`p` commands, `-i` in-place edit, `-e`/`-f` multiple scripts, line/regex address ranges).
* **tr**: Translate or delete characters.
* **tee**: Read from standard input and write to standard output and files.
* **sum**: BSD/SysV checksum utility.
* **seq**: Print a sequence of numbers (`-w` zero-pad, `-s` separator, floating-point).
* **nl**: Number lines of files (`-b a`/`t`, `-w`, `-s`).
* **tac**: Concatenate and print files with lines in reverse order.
* **rev**: Reverse the characters of each line.
* **fold**: Wrap each line to a given width (`-w`, `-s` break at whitespace).
* **paste**: Merge corresponding lines of files side by side (`-d`, `-s`).
* **split**: Split a file into pieces by line count or byte count (`-l`, `-b`).
* **fmt**: Reflow text into filled paragraphs (`-w` width, default 75).
* **awk**: Pattern scanning and processing language targeting the BusyBox awk feature set -- patterns/actions, `BEGIN`/`END`, range patterns, user-defined functions (arrays passed by reference, scalars by value), associative arrays (`for...in`, `delete`, multi-dimensional via `SUBSEP`), full expression grammar, `getline` (plain/`var`/`< file`/`cmd |`), `print`/`printf` with `>`/`>>`/`|` redirection, string functions (`length`, `substr`, `index`, `split`, `sub`, `gsub`, `match`, `sprintf`, `tolower`/`toupper`), math functions, `-F`/`-v`/`-f`/`-e` CLI options. Not implemented: gawk extensions (`asort`, `gensub`, `strftime`, bitwise functions, `switch`, coprocesses).
* **comm**: Compare two sorted files line by line (`-1`/`-2`/`-3` to suppress columns).
* **md5sum** / **sha1sum** / **sha256sum**: Compute or check cryptographic digests (`-c`).
* **base64**: Base64 encode or decode (`-d`, `-i`, `-w`).
* **expr**: Evaluate expressions (shell arithmetic/string idiom).
* **printf**: Format and print data (standalone applet, not just a shell builtin).

### Editors & Viewers
* **vi** / **nextvi**: A small, efficient vi-like text editor.
* **md**: A terminal-based Markdown viewer (renders tables, headers, and lists interactively).

### Networking
* **ssh**: OpenSSH client wrapper.
* **scp**: Secure copy (OpenSSH).
* **sftp**: Secure file transfer (OpenSSH).
* **ssh-keygen**: Generate authentication keys.
* **ssh-copy-id**: Install SSH public keys on a remote host.
* **ping**: ICMP echo request/reply utility, IPv4 and IPv6 (`-4`/`-6` to force a family).
* **curl** / **wget**: libcurl-backed HTTP(S) client wrappers (`-o`/`-O`, `-X`/`--method`, `-H`/`--header`, `-d`/`--post-data`, `-u`/`--user`+`--password` basic auth, `-k`/`--no-check-certificate` insecure TLS).
* **telnet**: Telnet client with real IAC option negotiation (declines every DO/WILL request, handles subnegotiation blocks and escaped IAC bytes) -- no actual options are supported, but it interoperates cleanly with real telnetd servers instead of showing negotiation bytes as garbage.
* **nslookup** / **host**: DNS lookup utilities; IP-shaped queries auto-detect as PTR/reverse lookups. An optional trailing `server` argument queries that DNS server directly over UDP/53 (falling back to TCP for truncated replies, per RFC 1035) via a from-scratch DNS client (raw wire-format encode/decode, name compression, A/AAAA/PTR/CNAME/NS/MX/TXT/SRV), instead of going through the system resolver. `host -t TYPE` and `nslookup -type=TYPE`/`-q=TYPE` select NS/MX/TXT/SRV lookups (in addition to A/AAAA); since `getaddrinfo()` has no equivalent for these, they always use the raw client, defaulting to `/etc/resolv.conf`'s nameserver when no explicit server is given.
* **traceroute**: Trace the route packets take to a network host.
* **ipaddr**: Display network interface addresses; on Linux (real netlink, IPv4 only, needs `CAP_NET_ADMIN`): `ipaddr add|del ADDR/PREFIXLEN dev IFACE`, `ipaddr flush dev IFACE`, `ipaddr link set IFACE up|down`, `ipaddr route add|del DEST/PREFIXLEN|default [via GW] [dev IFACE]`.

### Shell & System
* **sh** / **ash**: In standalone builds, smallclue's own POSIX shell (BusyBox-ash-class): pipelines, functions, full word expansion (`${var...}`, `$(...)`, `$((...))`, globbing, IFS splitting), heredocs, traps, job control (`jobs`/`fg`/`bg`/`wait`), `set -e/-u/-x/-o pipefail`, and interactive line editing with history and tab completion. Implemented in `src/shell/`: the lexer/parser are vendored from exsh, executed by a native AST-walking interpreter with no PSCAL VM dependency. In embedded PSCAL builds (`WITH_EXSH`), `sh` launches the PSCAL shell frontend (`exsh`) instead.
* **dvtm**: Launch the dvtm terminal multiplexer applet (enabled in iOS/iPadOS chroot and Docker setup builds).
* **env**: Run a program in a modified environment.
* **ps**: Report a snapshot of current processes (real `/proc` parsing on Linux, with `STAT` column; supports `-e`/`-f`/`aux`-style argument forms and `-p PID`).
* **top**: Show running processes sorted by %CPU (real `/proc`-based on Linux; shows PSCAL virtual processes on iOS/iPadOS).
* **kill**: Send signals to processes.
* **uptime**: Show app uptime since launch (use `-s` for system uptime).
* **uname**: Print system information.
* **id**: Print user identity information.
* **date**: Print or set the system date and time.
* **cal**: Display a calendar.
* **clear** / **cls**: Clear the terminal screen.
* **sleep**: Delay for a specified amount of time.
* **tset**: Modify terminal settings.
* **stty**: Inspect or modify terminal settings.
* **tty**: Report tty.
* **resize**: Synchronize terminal row/column settings with the host.
* **script**: Record terminal output to a file.
* **watch**: Execute a program periodically, showing output fullscreen.
* **time**: Measure command runtime (times external binaries, not just built-in applets, on Linux).
* **timeout**: Run a command with a time limit (`-s SIGNAL`, `-k DURATION`, `--preserve-status`).
* **nohup**: Run a command immune to hangups.
* **git**: Built-in libgit2-backed git applet (currently supports: `init`, `clone` (including `--depth` shallow clones and `--recurse-submodules`), `submodule` (`init`/`update`/`status`/`sync`/`foreach`), `remote`, `fetch`, `ls-remote`, `pull`, `push`, `add`, `rm`, `mv`, `clean`, `commit`, `reset`, `restore`, `checkout`, `switch`, `config` (`--get`, `--get-all`, `--list`, set, `--add`, `--replace-all`, `--unset`, `--unset-all`), `symbolic-ref`, `rev-parse`, `rev-list`, `reflog`, `show-ref`, `ls-files`, `ls-tree`, `cat-file`, `status`, `branch` (list/create/delete/rename/copy/set-upstream/unset-upstream), `tag` (list/create/delete), `diff`, `log` (including `--graph` and `-p`/`--patch`), `show`, `merge`, `merge-base`, `rebase`, `stash`, `cherry-pick`, `cherry`, `revert`, `blame`, and `describe`). Credentialed transports (HTTPS token / SSH key auth) are supported via a credentials callback.
* **type**: Describe command names.
* **xargs**: Build and execute command lines from standard input (`-n`, `-0`, `-I`, `-t`; quote/backslash-aware tokenization).
* **pbcopy** / **pbpaste**: Clipboard helpers (on iOS/iPadOS these integrate with the system clipboard).
* **test** / **[**: Evaluate conditional expressions.
* **true** / **false**: Return success or failure status.
* **yes** / **no**: Repeatedly print strings (with success/failure exit semantics).
* **version**: Print smallclue/PSCAL version info.
* **vproc-test**: Run vproc/terminal diagnostics.

### iOS / iPadOS Only Applets
These applets are only registered on `PSCAL_TARGET_IOS` builds.

* **addt**: Open an additional shell tab.
* **tabadd** / **tadd**: Aliases for `addt`.
* **smallclue-help**: List available smallclue applets and command help.
* **dmesg**: Prints the PSCAL runtime session log.
* **licenses**: View open source licenses included in the distribution.

## Build Notes (iOS/iPadOS chroot + Docker)

* `setup_posix_env.sh` and `setup_ish_env.sh` now build SmallCLUE with `dvtm` enabled by default.
* Set `SMALLCLUE_WITH_DVTM=0` to explicitly disable `dvtm` during these setup builds.
* `setup_posix_env.sh` and `setup_ish_env.sh` now build and link bundled `libgit2` by default when `third-party/libgit2` is present.
* Set `SMALLCLUE_WITH_LIBGIT2=0` to skip libgit2 integration in these setup builds.
* Docker builds require curses development headers/libraries (`libncurses-dev`); the Dockerfile dependency check/install path now includes this.
* The `version` applet prints the linked `libgit2` version when libgit2 support is enabled.

## Usage

Can be run directly via the main entry point if built as a standalone executable:

```bash
./smallclue <command> [arguments...]
