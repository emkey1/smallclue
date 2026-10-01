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
* **rsync**: By default, dispatches to the vendored upstream **openrsync** (`third-party/openrsync/`), a real rsync-protocol client -- not the hand-rolled local-sync-plus-scp engine described below. Supports `-u`/`--update` (skip files whose destination copy is newer than the source), `--compare-dest`/`--copy-dest`/`--link-dest` (skip/copy/hardlink unchanged files from a reference directory instead of re-transferring them), pushing to a remote rsync daemon (`rsync://host/module/path` or `host::module/path` as the destination, not just as a source), `--progress` (live per-file transfer percentage), and real `-z`/`--compress` rsync-protocol payload compression (not just SSH transport compression), and real `-c`/`--checksum` (never trust size/mtime alone; force a real content comparison via block-transfer checksums). Notes: `-z`'s wire format is openrsync/smallclue's own (not byte-compatible with GNU rsync's compression scheme) -- it works for any transfer where smallclue is on both ends (local sync, ssh between two smallclue instances, daemon between two smallclue instances), but fails loudly and immediately (not silently) if used against an unmodified real rsync peer. `-c`/`--checksum` currently has a real bug in its whole-file-checksum wire exchange: a same-size/same-mtime/differing-content sync (the case `-c` exists to catch) can hang or fail with "unexpected end of file", and not just against a foreign peer -- it reproduces smallclue-to-smallclue too. As a safety net (not a fix for the underlying bug), `-c` without an explicit `--timeout` now gets a bounded 60s default poll timeout, so a hang fails cleanly instead of blocking forever; pass `--timeout=N` yourself to change that, or `--timeout=0` to force no timeout at all. Set `PSCALI_RSYNC_LEGACY=1` to use the legacy hand-rolled engine instead, which synchronizes files/directories locally or over SSH (`-a`, `-r`, `-p`, `-t`, `-u`, `-c`, `-v`, `-z`, `-n`, `--delete`, `--include`, `--exclude`) and routes remote `host:path` transfers through the OpenSSH `scp` backend (supports `-a/-r/-p/-t/-v/-z`, plus `-n` preview; remote `-u/-c/--include/--exclude/--delete` are not yet implemented in that legacy path).
* **mv**: Move or rename files.
* **rm**: Remove files and directories (`-r`/`-R`, `-f`, `-i`, `--preserve-root`).
* **mkdir** / **rmdir**: Create or remove directories.
* **touch**: Change file timestamps; GNU coreutils compatible (`-a -m --time -c -h -d DATE -r FILE -t STAMP`).
* **ln**: Make links, compatible with GNU coreutils 9 (`src/ln_app.c`): all four forms (`TARGET LINK`, `TARGET`, `TARGET... DIR`, `-t DIR TARGET...`) and `-s -f -n -T -t -v -i -r -L -P -d/-F -b --backup[=CONTROL] -S`; `-f` replaces atomically. Matches GNU ln 9.4 on 95 cases (resulting tree, output, status).
* **mount** / **umount**: Add or remove filesystem mounts (real `mount(2)`/`umount(2)` syscall wrappers on Linux; `umount` supports `-l`/`-f` lazy/force unmount).
* **pwd**: Print working directory.
* **chmod**: Change file modes/permissions (supports octal and symbolic `u+x`, `-R` recursive).
* **du**: Summarize disk usage; GNU coreutils compatible (`-a -s -d -c -S -l -x -L -b -h --si -k -m -B -t --exclude --inodes --time`).
* **df**: Report file system disk space usage (enumerates all mounts from `/proc/mounts` when no path is given).
* **chown** / **chgrp**: Change file ownership/group.
* **chroot**: Run a command (or shell) with a new root directory, optionally dropping to another user/group.
* **file**: Determine file type.
* **stat**: Display file or file-system status; GNU coreutils compatible (every `-c`/`--printf` directive with widths and precision, `-L -f -t`).
* **basename** / **dirname**: Parse path components (multi-operand support; `basename` supports a `SUFFIX` operand).
* **find**: Search for files and directories (`-name`, `-type`, `-exec`, `-delete`, `-maxdepth`/`-mindepth`, `-mtime`/`-newer`, `-size`, `-print0`, and full boolean logic: `-a`/`-and` (implicit between adjacent terms), `-o`/`-or`, `!`/`-not`, `\( \)` grouping).
* **readlink** / **realpath**: Print symlink values or canonical names; GNU coreutils compatible (`-f -e -m`, realpath `-L -P -s -q -z --relative-to --relative-base`).
* **install**: Copy files and set attributes (or create directories), like `make install`'s underlying tool.
* **diff**: Compare files line by line; GNU diffutils compatible (normal, `-c`, `-u`, `-e`, `-n`, `-y`, `-r`, `-N`, `-x`, whitespace and case options).
* **patch**: Apply a unified diff to files.
* **cmp**: Compare two files byte by byte; GNU diffutils compatible (`-b` `-l` `-s` `-i SKIP1[:SKIP2]` `-n` and SKIP operands with GNU number suffixes).
* **dd**: Convert and copy a file; GNU coreutils compatible (every operand, conv, iflag/oflag and status value; GNU's report).
* **od**: Dump files; GNU coreutils compatible (`-t a c d o u x f` with sizes and `z`, old options, `-A -j -N -w -v -S --endian`, traditional offsets).

### Archives & Compression
* **tar**: GNU tar 1.35 compatible (reads ustar/GNU/pax, writes GNU format byte-for-byte as GNU does; `c x t r u`, old bundled syntax, `-C -v -z -j -J -a -I -O -k -p -m -h -P --strip-components --exclude -X -T --owner --group --mode --mtime --remove-files`).
* **gzip / gunzip / zcat**: GNU gzip 1.13 compatible (GNU's header, in-place with attributes kept, `-c -d -t -l -v -f -k -r -q -n -N -S -1..-9`, its warnings and exit statuses, concatenated members, trailing data).

### Text Processing & Filtering
* **cat**: Concatenate files; GNU coreutils compatible (`-A -b -e -E -n -s -t -T -u -v`, state carried across files).
* **echo**: Print arguments to standard output.
* **grep**: File pattern searcher with real POSIX regex support (supports `-i`, `-v`, `-n`, `-r`/`-R` recursive, `-c`, `-o`, `-w`, `-x`, `--color`).
* **head** / **tail**: Output the first/last part of files (tail supports `-f` follow).
* **more** / **less**: File paging filters.
* **wc**: Word, line, character, and byte count (`-l`, `-w`, `-c`, `-m` locale-aware character count, `-L` max line length).
* **sort**: Sort lines of text files.
* **uniq**: Report or omit repeated lines; GNU coreutils compatible (`-c` `-d` `-D` `--all-repeated` `--group` `-u` `-i` `-f` `-s` `-w` `-z`, obsolete `-N`/`+N`, INPUT and OUTPUT).
* **cut**: Remove sections from each line of files.
* **sed**: POSIX stream editor with the GNU extensions Linux scripts use (`src/sed_app.c`): every command (`{}` `=` `a` `b` `c` `d` `D` `F` `g` `G` `h` `H` `i` `l` `n` `N` `p` `P` `q` `Q` `r` `R` `s` `t` `T` `w` `W` `x` `y` `z` `:`), addresses including `first~step`, `addr,+N`, `0,/re/` and `!`, `e` (run a shell command), `s` flags `g` `p` N `w` `e` `i` `m` with `\U`/`\L` case conversion, `-n` `-E` `-i[SUFFIX]` (mode and owner kept) `-s` `-z` `-u`. Output matches GNU sed 4.9 on 159 cases.
* **tr**: Translate, squeeze or delete characters; GNU coreutils compatible (escapes, ranges, `[:class:]`, `[=c=]`, `[c*n]`, `-c -d -s -t`, GNU's validation messages).
* **tee**: Read from standard input and write to standard output and files.
* **sum**: BSD and System V checksums; GNU coreutils compatible.
* **seq**: Print number sequences; GNU coreutils compatible (`-f -s -w`, decimal/exponent/hex operands, exact decimal stepping).
* **nl**: Number lines; GNU coreutils compatible (`-b/-h/-f a|t|n|pBRE`, `-v -i -l -n -w -s -p -d`, logical page sections).
* **tac**: Print files last record first; GNU coreutils compatible (`-b -r -s`, GNU's backward search and regex syntax).
* **rev**: Reverse the characters of each line.
* **fold**: Wrap lines; GNU coreutils compatible (`-b -s -w`, the obsolete `-NUM`).
* **paste**: Merge corresponding lines of files side by side (`-d`, `-s`).
* **split**: Split a file into pieces; GNU coreutils compatible (`-l -b -C -n` in all forms, suffix widening, `-d -x -a -e -t --filter --verbose`).
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
* **env**: Run a command in a modified environment; GNU coreutils compatible (`-i -u -0 -C -S -v`, the signal options, exit statuses 125/126/127).
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
* **stty**: Print or change terminal settings, compatible with GNU coreutils 9 (`src/stty_app.c`): every mode and its `-` form, `raw`/`cooked`/`sane`/`cbreak` and the other combinations, control characters (`^X`, `^?`, `^-`, `undef`, numbers), `min`/`time`, speeds, `rows`/`cols`/`size`, `-F DEVICE`, and `-a`/`-g` with `-g` strings interchangeable with GNU's on Linux. Kept in Linux's termios terms on every host; where the host fronts a Linux tty (iSH-AOK) it uses the kernel's TCGETS/TCSETSW, so Linux-only settings (xcase, iuclc, olcuc, cmspar) work too.
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
