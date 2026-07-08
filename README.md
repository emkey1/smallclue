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
* **rsync**: By default, dispatches to the vendored upstream **openrsync** (`third-party/openrsync/`), a real rsync-protocol client -- not the hand-rolled local-sync-plus-scp engine described below. openrsync gaps vs GNU rsync: no `-u`/`--update` or `-c`/`--checksum`, `--link-dest`/`--copy-dest` compiled out, `-z`/`--compress` only requests SSH transport compression (not real rsync-protocol payload compression), no `--progress`, and daemon-push (uploading to a remote `rsync://`/`::` target) is not supported. Set `PSCALI_RSYNC_LEGACY=1` to use the legacy hand-rolled engine instead, which synchronizes files/directories locally or over SSH (`-a`, `-r`, `-p`, `-t`, `-u`, `-c`, `-v`, `-z`, `-n`, `--delete`, `--include`, `--exclude`) and routes remote `host:path` transfers through the OpenSSH `scp` backend (supports `-a/-r/-p/-t/-v/-z`, plus `-n` preview; remote `-u/-c/--include/--exclude/--delete` are not yet implemented in that legacy path).
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
* **ping**: ICMP echo request/reply utility (real `IPPROTO_ICMP` socket with a checksummed ICMP header; IPv4 only, no IPv6 path yet).
* **curl** / **wget**: libcurl-backed HTTP(S) client wrappers (`-o`/`-O`, `-X`/`--method`, `-H`/`--header`, `-d`/`--post-data`, `-u`/`--user`+`--password` basic auth, `-k`/`--no-check-certificate` insecure TLS).
* **telnet**: Simple Telnet client.
* **nslookup** / **host**: DNS lookup utilities.
* **traceroute**: Trace the route packets take to a network host.
* **ipaddr**: Display network interface addresses.

### Shell & System
* **sh**: Launches the PSCAL shell frontend (`exsh`).
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
* **xargs**: Build and execute command lines from standard input.
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
