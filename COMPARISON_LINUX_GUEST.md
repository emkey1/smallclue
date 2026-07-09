# SmallCLUE as a standalone Linux guest userland: gap analysis

## Framing

The original [COMPARISON.md](COMPARISON.md) evaluated SmallCLUE as an iOS-terminal
helper that runs *alongside* a full Alpine/Devuan rootfs — anything SmallCLUE didn't
cover, real BusyBox (or GNU coreutils) was still one `$PATH` lookup away. That
framing no longer applies.

In the iSH-AOK-based architecture, SmallCLUE (MIT) is being evaluated as the
**entire non-language-runtime userland** of a minimal aarch64 Linux guest: the
`pascal`/`aether`/`rea`/`clike`/`exsh` frontends plus SmallCLUE plus nothing else —
specifically no BusyBox, no GNU coreutils/findutils/sed/gawk, no Alpine `apk-tools`.
If SmallCLUE can't do something, **nothing in the guest can**. This document
re-does the comparison under that assumption: every gap below is "the guest cannot
do X at all," not "the guest has to shell out to something else for X."

Per the task brief, SmallCLUE's iOS-specific design choices (vproc integration,
pbcopy/pbpaste, the `PSCAL_TARGET_IOS`-gated applet section, `sh` launching `exsh`
rather than a bespoke shell) are **intentional and out of scope** — they are not
treated as deficits here, and `exsh` remains the shell in the new architecture.

Findings below come from reading the actual argument-parsing code in
`src/core.c` (18,692 lines), `src/git_app.c` (12,829 lines), `src/openrsync_app.c`,
and `third-party/openrsync/main.c` — not from the README, which turns out to be
stale in several important ways (noted inline). All line numbers refer to the
current `HEAD` of the `smallclue` submodule as audited on 2026-07-08.

One correction to the task's own framing: **an `init` applet already exists**
(`smallclueInitCommand`, `core.c:18476-18568`) with real PID-1 semantics
(refuses to run unless `getpid()==1` or `--service-mode`/`-S` is passed) and execs
`/etc/rc`. It is not zero — see the "Process management" gap below for what's
actually missing from it.

---

## 1. Applet inventory reality check

The README's applet list is itself stale — a straight scan of the applet dispatch
table in `core.c` turns up applets the README doesn't mention at all: `su`, `sudo`,
`passwd`, `mdev`, `runit`, `halt`, `poweroff`, `reboot`, `hostname`, `history`,
`hterm`, `mknod`, `exsh` (as a dispatch target). None of these change the gap
analysis below, but a doc-accuracy pass on the README is a cheap side fix.

---

## 2. Category (a): capabilities entirely absent

Verified by direct grep across all of `src/*.c` (case-insensitive) — zero matches
for every name below unless otherwise noted:

| Missing | Why it matters for a self-hosted guest | Notes |
|---|---|---|
| **tar** | No way to unpack a `.tar`/`.tar.gz` *inside* the guest at all — source tarballs, release archives, and container-style rootfs images all ship as tar. This is the single most-cited gap in the task brief. | No vendored tar/libarchive anywhere under `third-party/`. |
| **gzip / gunzip / zcat** | Pairs with tar; also the ubiquitous single-file compression format for logs, patches, etc. | **zlib is already linked into the binary** — `CMakeLists.txt:222-223`, `find_package(ZLIB REQUIRED)` + `target_link_libraries(smallclue PRIVATE ZLIB::ZLIB)` — currently used only internally by vendored libgit2. A gzip/gunzip applet is "wire up an existing dependency," not "add a new one." |
| **awk** | Extremely common in build scripts and config generation (`./configure`-style scripts, Makefiles, install scripts). | No implementation of any kind, not even a subset. Confirmed via `grep -in awk src/core.c` → zero matches. |
| **diff / cmp** | Needed to inspect changes, verify build outputs, and as a prerequisite for `patch`. | Zero matches for a standalone diff applet; the only "diff" string in `core.c` is the `git diff` subcommand name inside git's help text (`core.c:2194`), and an unrelated `smallclueTimevalDiffSeconds` helper (`core.c:10844`) used by the `time` builtin. |
| **patch** | Build systems routinely apply source patches (`.patch`/`.diff` files) before compiling — without it, any patched build recipe breaks. | Not present; no dependency on diff/patch format parsing anywhere. |
| **expr** | Shell arithmetic/string idiom used in POSIX-sh scripts (`i=$(expr $i + 1)`); `exsh` may have its own arithmetic, but scripts written against POSIX sh assume `expr` exists standalone. | Not present. |
| **dd** | Low-level block copy — image manipulation, zeroing, `/dev/zero`/`/dev/urandom` sourced writes. | Not present. |
| **od / hexdump / xxd** | Binary inspection during debugging (build failures, corrupted downloads, verifying ELF headers). | Not present. |
| **printf (standalone)** | POSIX sh scripts frequently call `/usr/bin/printf` rather than relying on a builtin. | Not present as an applet (only used internally as a C function). |
| **readlink / realpath** | Path canonicalization is a very common shell-script idiom (`cd "$(dirname "$(readlink -f "$0")")"`). | Not present, though `realpath(3)` is used internally via `dlsym` lookups (`core.c:194-196`) — the libc function is present, just not exposed as an applet. |
| **chown / chgrp** | Ownership changes are routine in build/install scripts, even in a single-user guest (e.g. fixing ownership after extracting a tarball as a different UID). | Not present. |
| **install** | `make install` targets very commonly invoke `install` directly rather than `cp`+`chmod`. | Not present. |
| **timeout / nohup / nice / setsid** | Process-control idioms for backgrounding/bounding builds and services. | Not present. |
| **base64 / md5sum / sha1sum / sha256sum** | Checksum verification of downloaded artifacts is standard practice; `sum` (BSD/SysV checksum) exists but is not a substitute — nothing produces an MD5/SHA digest. | Only `sum` (BSD/SysV, `core.c:10263`) exists; no cryptographic-hash applet at all. |
| **seq / nl / fmt / fold / split / comm / paste / tac / rev** | Assorted text-pipeline utilities scripts commonly assume are present. | Not present; lower priority than the items above. |
| **A real `top`** | `smallclueTopCommand` (`core.c:3100-3310`) is compiled only under `#if defined(PSCAL_TARGET_IOS)`, and its applet-table registration is *also* inside that same `#ifdef` (`core.c:2102-2108`). **On the target Linux/aarch64 build, `top` does not exist as a recognized applet at all** — despite `ps` having a working real-`/proc` backend (`core.c:2846-2980`) that a Linux `top` could reuse. | Confirmed by reading both the `#if` guard around the function body and the applet-table entry. |

---

## 3. Category (b): applets that exist but are materially incomplete

### Text processing & filtering

- **`sed`** (`smallclueSedCommand`, `core.c:14314-14384`) — matches the README's own "basic substitution support" caveat, and it undersells how basic: exactly **one** `s<delim>PATTERN<delim>REPLACEMENT<delim>[g]` script per invocation, via `smallclueSedParseExpr`/`smallclueSedApply` (`core.c:14229-14312`). Pattern matching is **plain `strncmp` literal substring matching — no regex engine at all** (no `.`, `*`, `[...]`, anchors, backreferences). Missing entirely: `-i` (in-place edit), `-e`/`-f` (multiple scripts / script file), address/line-range selection (`1,5s/…/…/`, `/pat/,/pat/`), `y///` transliteration, `a`/`i`/`c`/`d`/`p`/`q` commands, multiple `;`-separated commands. Minor bug: the `g` flag detector (`strchr(rep_end+1,'g')`, `core.c:14257`) matches `g` anywhere in the trailing flags region, not just as a lone flag character.
- **`grep`** (`smallclueGrepCommand`, `core.c:14792-14920`) — same story: matching goes through `smallclueStrCaseStr` (`core.c:12969-13004`), a `strstr`/`strcasestr` wrapper — **no regex at all**, so every "pattern" is a literal substring. Flags supported: `-n`, `-i`, `-v`, `--color`/`--colour` (`core.c:14804-14852`). Missing: `-r`/`-R` (recursive), `-c`/`-l`/`-L`/`-o`, `-A`/`-B`/`-C` (context), `-w`/`-x`, `-e`/`-f` (multiple patterns).
- **`tr`** (`smallclueTrCommand`, `core.c:14514-14624`) — **no flag parsing whatsoever**; `set1`/`set2` are taken positionally from `argv[1]`/`argv[2]`. Delete-mode is only reachable by omitting the second operand (`core.c:14525`), which means the idiomatic invocation `tr -d 'set'` is **silently misparsed** (`-d` becomes `set1`, `'set'` becomes `set2`) rather than working or erroring cleanly — a real compatibility trap. No `-s` (squeeze), no `-c` (complement), and critically **no character-range expansion** (`a-z` is treated as three literal characters `a`, `-`, `z`) and no POSIX classes (`[:alpha:]` etc.) — both extremely common in real usage (`tr a-z A-Z`).
- **`cut`** (`smallclueCutCommand`, `core.c:14417-14512`) — supports exactly **one** field number via `-f` (no ranges/lists like `-f1,3` or `-f1-3`), and has **no `-c` byte/character-range mode at all** — cut can only ever operate in single-field, delimiter-based mode. `-d`/`-f` are otherwise correctly parsed (`core.c:14430-14462`). Confirmed bug: on a line that contains no delimiter at all, `smallclueCutPrintField` (`core.c:14386-14416`) falls through to printing a **bare newline**, discarding the line's content — real `cut` prints the whole original line unchanged in that case (only suppressible with `-s`, which also doesn't exist here).
- **`cat`** (`smallclueCatCommand`, `core.c:12437-12446`) — **zero option parsing of any kind**; any `-n`/`-A`/etc. flag is silently treated as a (nonexistent) filename and fails with "No such file or directory" rather than being rejected as an unsupported flag (worse than the other applets' behavior). `-`/stdin handling is correct (`cat_file`, `core.c:9176-9179`).
- **`echo`** (`smallclueEchoCommand`, `core.c:9628-9645`) — only recognizes `-n` as the literal first argument; **no `-e`/backslash-escape processing at all**, so scripts expecting `\n`/`\t` interpretation get literal backslash-n text.
- **`sort`** (`core.c:14087-14140`) — only `-r`; no `-n` (numeric), `-k` (key), `-t` (separator), `-u`, `-c`, `-m`; uses `qsort` which is not guaranteed stable, a real behavioral divergence for tie-break ordering.
- **`uniq`** (`core.c:14192-14227`) — only `-c`; no `-d`/`-u`/`-i`/`-f`/`-s`/`-w`.
- **`head`/`tail`** (`core.c:13089-13415`) — the shared `-N` legacy-shorthand parser (`smallclueParseDashLineCount`, `core.c:13006-13027`) only accepts pure `-<digits>`, so **`head -n +N`/`tail -n +N` ("start at line N") is unsupported**, and there's no `-c` byte-count mode. `tail -f` **explicitly refuses more than one input file** (`core.c:13379-13382`), unlike real tail which interleaves multi-file follow output.
- **`wc`** — reasonably complete (`-l`/`-w`/`-c`, multi-file totals); missing only `-m` (character vs byte count) and `-L`.

### File management

- **`find`** (`smallclueFindCommand`, `core.c:15224-15247`) — **by far the largest single gap in this category**. It supports exactly one predicate: an optional leading path plus `-name PATTERN` (`fnmatch`-based). Anything else — **`-exec`, `-type`, `-delete`, `-maxdepth`/`-mindepth`, `-mtime`/`-newer`, `-size`, `-print0`, `-prune`, and all boolean logic (`-a`/`-o`/`!`/parentheses)** — is entirely absent; any other token is a hard parse error. This alone blocks the overwhelming majority of real `find` invocations used in build/install scripts (`find . -name '*.o' -delete`, `find /tmp -mtime +7 -exec rm {} \;`, etc.).
- **`cp`** (`core.c:16960-17015`) — **no flags at all, and directories are hard-rejected** ("is a directory" error, `core.c:16986-16990`) — `cp` cannot copy a directory under any invocation. No `-r`/`-R`/`-a`/`-p`/`-f`/`-i`/`-n`. This blocks essentially every install/extract/backup workflow that isn't single-file.
- **`mv`** (`core.c:17017-17071`) — no flags; correct same-filesystem `rename()` and cross-device fallback to copy+unlink, but since the copy fallback is `smallclueCopyFile` (the same one `cp` uses), **cross-filesystem moves of directories fail** for the same reason `cp` can't handle directories.
- **`touch`** (`core.c:13417-13462`) — **zero flags**; every invocation force-creates the target and stamps "now" on both atime and mtime. No `-c` (no-create), `-t`/`-d` (explicit timestamp), `-r` (reference file), `-a`/`-m` (single-timestamp). This breaks the common Makefile idiom of `touch -r`/`touch -d` to bump mtimes without content changes.
- **`stat`** (`core.c:16775-16802`) — only `-L` (follow symlinks); **no `-c`/`--format`/`--printf` custom format strings at all** (fixed hardcoded output format) and no `-f` (filesystem-info mode). Scripts that parse `stat -c '%s'`/`stat -c '%Y'` output — extremely common — will break outright.
- **`chmod`** (`core.c:10014-10044`) — supports both octal and symbolic (`u+x` etc.) modes correctly, but **no `-R` (recursive)** — one of the most common chmod invocations (`chmod -R 755 dir`) is unsupported. Symbolic mode also lacks `X`/`s`/`t` (setuid/setgid/sticky, conditional-exec).
- **`ln`** (`core.c:16804-16837`) — only `-s`; no `-f` (force-overwrite existing target — currently just fails with EEXIST), and critically **no directory-target auto-append of the source basename**, so the extremely common idiom `ln -s /usr/bin/foo /usr/local/bin/` fails outright instead of creating `/usr/local/bin/foo`.
- **`rm`** (`core.c:15534-15602`) — `-r`/`-f`/`-i` supported, but **no `--preserve-root` guard at all** (no special-casing of `/` found anywhere in `smallclueRemovePathWithLabel`), only lowercase `-r` (not `-R`), and a real double-confirmation-prompt bug: with plain `-i` on a directory, the user is asked to confirm the same path twice (once at the top of the removal helper, once again before recursing, `core.c:15354-15365`).
- **`mount`/`umount`** — the **Linux code path is a genuine, generic `mount(2)`/`umount(2)` syscall wrapper**, not iOS-bind-mount-only (confirmed: zero special-casing, positive or negative, for `proc`/`tmpfs`/`sysfs`/`devtmpfs` anywhere — unrecognized `-o` tokens are passed straight through as filesystem-specific mount data exactly like real `mount(8)` does). `mount -t proc proc /proc`, `-t tmpfs`, and `-t sysfs` are now **verified working in Docker**. `umount` also has **`-l`/`-f`** (lazy/force unmount via `umount2()` flags) as of a prior fix. No remaining gap here.
- **`df`** (`core.c:11697-11745`) — with no path arguments, only reports the current directory's filesystem rather than enumerating all mounts from `/proc/mounts` like real `df`.
- **`du`** (`core.c:15157-15186`) — plain `du` (no flags) prints every visited file rather than only directory subtotals (GNU's default); no `--max-depth`, `-c` (grand total), `-x`.
- **`ls`** (`core.c:9744-9849`) — no `-R` (recursive listing — cannot inspect a tree in one invocation), no `-S`/`-X`/`-v`/`-r` sort-order flags (all hard-error as "invalid option" rather than being ignored), no `-i` (inode).
- **`basename`/`dirname`** (`core.c:11263-11297`) — single positional arg only; no `SUFFIX` operand for `basename`, no multi-operand support for either (extra args silently ignored rather than erroring).

### Networking

- **`git` (libgit2 wrapper) — no credential support for authenticated remotes, at all.** This is the single largest gap in the networking/git category. Exhaustive grep across all 12,829 lines of `src/git_app.c` for `git_credential`, `GIT_CREDTYPE`, `credentials_cb`, SSH key paths, or any `USERNAME`/`PASSWORD`/`TOKEN` handling returns **zero matches**. Every clone/fetch/pull/push call site (`git_clone_options` at `git_app.c:8781`, five separate `git_fetch_options` sites including `9156`/`9668`/`9707`/`10434`/`10642`, `git_push_options` at `12579`) uses the bare default-init macro with no `.callbacks.credentials` ever populated. **Net effect: only fully anonymous transports work — any HTTPS remote requiring a token/password, or any SSH remote requiring key auth, fails outright.** Given that GitHub requires token auth for HTTPS and key auth for SSH, this blocks the single most common real-world git operation (push/pull against an actual hosted remote).
- **`git submodule` — no standalone subcommand exists.** Submodule logic (`git_app.c:8382-8803`) only runs inside `clone --recurse-submodules`; there is no `git submodule init/update/status/sync/foreach` for a repo that's already checked out — exactly PBuild's own workflow of bumping submodule pins on an existing tree.
- **`git clone --depth`** (shallow clone) — absent; no `--depth`/`--shallow-since`/`--shallow-exclude` handling in the clone option parser. Matters for minimal-footprint guest use with large-history repos.
- **`git log --graph` and `git log -p`** — both absent (confirmed via grep of the log-formatting function); both are extremely common day-to-day incantations. (`merge`, `rebase`, `stash`, `cherry-pick`, `revert`, and `blame` are, encouragingly, **already implemented with real libgit2-backed logic** — the README is simply stale in not mentioning them; this is a documentation fix, not an implementation gap.)
- **`rsync` — the README describes the wrong default engine** (now corrected). By default (unless `PSCALI_RSYNC_LEGACY=1` is set), `smallclueRsyncCommand` (`core.c:17866-17869`) dispatches to the **vendored upstream `openrsync`** (`third-party/openrsync/`, built unconditionally per `CMakeLists.txt:60-181`) — a real rsync-protocol client, not the hand-rolled local-sync-plus-scp engine the README documents. `--compare-dest`/`--copy-dest`/`--link-dest` are now implemented (previously `--copy-dest`/`--link-dest` were compiled out behind `#if 0`; fixed by re-enabling the option table/switch case and adding a `linkat()`-based hardlink helper, `copy.c`'s `link_file()`). **Important verification gotcha found while fixing this:** openrsync's local-to-local transfer path forks a child that `execvp()`s a program literally named `"rsync"` (`fargs.c`'s `RSYNC_PATH`) to act as the protocol's server side — on a dev machine with a real system rsync in `$PATH`, this silently masks any local code changes, since the real rsync satisfies the exec and runs instead. Verifying against smallclue's actual deployment topology (a `rsync -> smallclue` self-symlink, matching `setup_posix_env.sh`'s per-applet symlink generation) is required to actually exercise this code. Daemon-push is also now implemented: `fargs_parse()`'s blanket rejection of sender mode against a remote daemon target was replaced with a real validation branch, and `socket.c`'s `rsync_socket()` now branches to `rsync_sender()` instead of asserting receiver-only (mirroring the pattern `client.c` already used for SSH pushes) -- verified against a real `rsync --daemon` in Docker, both `rsync://host:port/module/path` and `host::module/path` forms, with the existing pull path confirmed unaffected. `--progress` is also now implemented (live per-file percentage during transfer, not just a post-hoc summary): hooked into both `downloader.c` (pull direction) and `sender.c` (push direction), since openrsync's local-fork/execvp-self design means only ONE of the two roles has a real stdout to print to depending on the transfer direction -- instrumenting both sides was necessary for local syncs, ssh pushes/pulls, and daemon pushes/pulls to all show progress correctly. `-z`/`--compress` is also now real: `zcompress.c` adds a session-persistent raw-deflate/inflate stream (Z_SYNC_FLUSH per chunk, so each wire unit decodes independently), wired into `sender.c`'s literal-data path and `downloader.c`'s receive path, plus a `fargs.c` fix to actually forward `--compress` to the peer invocation (previously only ssh's own transport-compression flag was forwarded, never ours, so the two sides would silently disagree about whether payload data was compressed). This is openrsync/smallclue's own wire format, not GNU rsync's -- confirmed via testing that pushing with `-z` to a real, unmodified `rsync --daemon` fails loudly and immediately ("Invalid block index ... error from remote host"), not silently, which is an acceptable boundary since smallclue is always on both ends of any transfer it initiates with `-z`. Verified a 4.29 MB highly-compressible file dropped to 16.4 KB actually read over the wire (via the existing wire-byte counters), incompressible random data transfers without corruption, and no interaction issues combined with `--progress` or `--copy-dest`. `-c`/`--checksum` is also now implemented: `check_file()` (`uploader.c`) is gated to never trust size/mtime alone when `sess->opts->checksum` is set, instead reporting "possible match" so the real block-transfer engine's rolling+strong checksums decide -- verified this already-existing code path is genuinely correct and fast (a same-size file with only its mtime touched round-trips through block-matching correctly, sending zero literal bytes, well under a second), then confirmed `-c` catches the specific case it exists for: same size AND same mtime but genuinely differing content, correctly detected and re-synced, no hang, no delay. A prior attempt at this flag had been reverted (documented in a since-removed `uploader.c` comment) after producing a wrong skip of genuinely-differing content plus an unexplained delay; that symptom is consistent with accidentally returning "up to date" instead of "needs a real comparison" in the same-size branch, which this version deliberately never does. `fargs.c` also needed the same peer-forwarding fix `-u`/`--update` needed (checksum's skip-decision runs on the receiving side, which for a push is the peer, not us). **Caveat found while stress-testing this against a real, unmodified `rsync` daemon (3.2.7):** unlike `-z` (fails loudly and immediately against a foreign peer), forwarding `-c` to one can cause a silent, indefinite hang in the exact same-size/same-mtime/differing-content case -- both sides end up blocked in `poll()` waiting on each other, apparently because the foreign daemon's own (much newer protocol) `--checksum` implementation expects a whole-file-checksum wire exchange this fork doesn't produce. Confirmed via `sample`-based stack traces (stuck in `rsync_sender()`'s `poll()`) and the daemon's own log (received a partial file list, then silence) that this is specifically a foreign-peer protocol mismatch, not a bug in the smallclue-to-smallclue case: the identical same-size/same-mtime/differing-content scenario against smallclue's own local self-exec re-transfer path (a genuinely separate two-process IPC round-trip, not a same-process shortcut) works correctly and fast. Same scope boundary as `-z`: openrsync/smallclue is assumed to be on both ends of any transfer it initiates; pass `--timeout=N` explicitly when combining `-c` with a peer that might not be. The legacy hand-rolled engine (only reachable via the undocumented `PSCALI_RSYNC_LEGACY=1` escape hatch) is the one that actually matches the README's non-default description.
- **`curl`/`wget`** — genuinely libcurl-backed (`smallclueHttpFetch`, `core.c:9074-9116`), so **HTTP(S) download inside the guest does work** by default — but GET-only: no `-X` (method), `-H` (headers), `-d`/POST body, `-u` (basic auth), or `-k` (insecure TLS toggle) anywhere (confirmed zero occurrences of `CURLOPT_CUSTOMREQUEST`/`CURLOPT_POST`/`CURLOPT_HTTPHEADER`). Blocks any API-driven bootstrap flow that isn't a plain GET.
- **`ping`** — the README's claim ("TCP-based ping utility") is **factually wrong for the current code**: it's genuine ICMP (`IPPROTO_ICMP` DGRAM socket with a real checksummed ICMP header, `core.c:11815-11844`), not a TCP-connect probe. No IPv6 path at all (always filters to the first `AF_INET` result, hard-errors if only AAAA records exist).
- **`telnet`** — a raw TCP byte-pump (effectively `nc host port`), no IAC/DO/WILL/WONT telnet protocol negotiation at all.
- **`nslookup`/`host`** — reverse/PTR lookup and a real custom-DNS-server override are now implemented: a from-scratch raw UDP DNS client (wire-format name encode/decode with compression-pointer support, A/AAAA/PTR/CNAME parsing, RCODE handling) is used whenever a trailing `server` argument is given, verified against real external resolvers (8.8.8.8) for forward/reverse/`-4`/`-6` lookups. Still no MX/TXT/NS/SRV record queries (only A/AAAA/PTR are queryable).
- **`ip addr`** — `add`/`del` (address), `link set up/down`, and `route add/del` are now implemented via real `AF_NETLINK`/`NETLINK_ROUTE` sockets (RTM_NEWADDR/DELADDR/NEWLINK/NEWROUTE/DELROUTE), verified against a real kernel's netlink subsystem in Docker including edge cases (on-link routes, duplicate-add rejection, nonexistent-route deletion). No `flush` yet.

### Process / shell / system

- **`init` has no persistent zombie-reaping loop.** `smallclueInitCommand` (`core.c:18476-18568`) does exactly one blocking `waitpid()` on the `/etc/rc` child's PID, then — only once, at shutdown after rc exits — does a single `kill(-1, SIGTERM)`/sleep/`kill(-1, SIGKILL)` sweep. There is no `SIGCHLD` handler anywhere in the file and no `waitpid(-1, WNOHANG)` reaping loop for the entire session. Any orphaned/double-forked daemon (the classic detach-from-terminal pattern) reparented to PID 1 will accumulate as a zombie for the whole session, only getting cleaned up in that one final shutdown sweep.
- **`ps` takes no arguments at all** (`argc`/`argv` explicitly cast to `(void)` and ignored, `core.c:2797-2798`) — `ps -ef`, `ps aux`, `ps -p PID` all behave identically to bare `ps`. The underlying data collection is solid real `/proc` parsing (PID/PPID/UID/cmdline), and a `STAT` state character is even parsed (`core.c:2882`) but never displayed — pure waste.
- **`xargs` cannot invoke external binaries at all** — the command name is resolved only via `smallclueFindApplet` (`core.c:3518`), so `find . | xargs some-external-tool` fails outright; only SmallCLUE's own built-in applets can be targets. Also takes **zero options** (`getopt(argc,argv,"")`, `core.c:3508`): no `-n`, `-I{}`, `-0`, `-P`, `-t`. Tokenization is whitespace-only with no quote/backslash handling.
- **`test`/`[` lacks `-a`/`-o`** (logical AND/OR, `core.c:18393`) and several unary operators (`-x`, `-s`, `-L`, `-nt`/`-ot`/`-ef`) — compound expressions of any kind hard-error as "unsupported expression." This is likely to break real shell scripts (`/etc/rc`, build `configure`-style scripts) that use multi-clause tests.
- **`date` has no `-d`/`--date=STRING` or `-s`/`--set`** — cannot parse an arbitrary date string or set the system clock at all; any non-`+FORMAT`, non-`-u` argument is a hard error. This is a real gap for provisioning/boot scripts that need to set the clock from some other source.
- **`time` cannot time external (non-applet) binaries on non-iOS builds** — the shebang-exec fallback is `#if defined(PSCAL_TARGET_IOS)`-only (`core.c:10881-10898`); on Linux, `time somebinary` where `somebinary` isn't a built-in applet just prints "command not found."

---

## 4. Top 10 fixes, ranked for the self-sufficient-Linux-guest use case

Ranked by what would actually block a real user extracting an archive, building/
compiling, editing files, filtering text, managing processes, or using git —
weighted above cosmetic BusyBox parity.

### 1. `tar` — new applet from scratch
**What:** No tar implementation exists anywhere.
**Why it matters:** Without it, there is no way to unpack a source tarball or release
archive *inside* the guest — this is the most literal blocker to "get code onto this
machine and build it."
**Effort:** New applet from scratch. A ustar-format reader (extract + list) is a few
hundred lines; a writer (`tar c`) is more work but less urgent initially. Should be
built to pipe through the same decompression path as gzip below for `.tar.gz`.

### 2. `gzip`/`gunzip` — wire up an already-vendored dependency
**What:** No gzip/gunzip applet exists.
**Why it matters:** The overwhelmingly common archive format in the wild is
`.tar.gz`; without decompression, even a working tar is only half useful.
**Effort:** Low-moderate — **zlib is already `find_package`'d and linked into the
binary** (`CMakeLists.txt:222-223`), currently used only internally by libgit2. This
is "add a thin applet around an existing dependency," not "vendor something new."

### 3. `find`: add `-exec`, `-type`, `-delete`, `-maxdepth`/`-mindepth`
**What:** Current `find` supports only `-name`; every other predicate and all
boolean logic is a hard parse error.
**Why it matters:** Virtually every real-world `find` invocation in build/install
scripts uses at least one of these (`find . -name '*.o' -delete`,
`find /tmp -mtime +7 -exec rm {} \;`). The single flattest predicate list blocks the
majority of practical find usage.
**Effort:** Flag/feature additions to an existing applet, moderate-to-high (a real
predicate evaluator with `-a`/`-o`/`!` would be the complete fix, but `-exec` and
`-type` alone cover most real usage and are individually tractable).

### 4. `cp -r`/`-a` (recursive directory copy)
**What:** `cp` currently hard-rejects any directory source.
**Why it matters:** Blocks essentially any install, extraction (of a plain
directory rather than a tarball), or backup workflow that isn't strictly
single-file.
**Effort:** Flag addition, moderate — needs a recursive directory walk plus
mode/time preservation logic that doesn't currently exist at all.

### 5. `git`: add a credentials callback for authenticated remotes
**What:** No `git_credential`/callback wiring exists anywhere in the 12.8k-line
libgit2 wrapper — clone/fetch/pull/push only work against fully anonymous
transports.
**Why it matters:** This doesn't just limit git — it makes git **non-functional**
for the single most common real-world case (pushing/pulling a real hosted repo,
which today requires HTTPS token or SSH key auth). "Use git" as a guest workflow is
currently broken for anything but read-only public clones.
**Effort:** Moderate — libgit2 ships default-credential-acquisition helpers
(SSH-agent, default key-file probing, `git_credential_userpass_plaintext_new` for
env-var-sourced HTTPS tokens) that can be wired into a single shared
`credentials_cb` reused across all five call sites, rather than building auth from
scratch.

### 6. `sed`: real regex support via libc `<regex.h>`, plus `-i`
**What:** `sed` only does literal-substring `s///` (no regex at all), with no
in-place editing.
**Why it matters:** Config-file patching and build-script text substitution
routinely rely on anchors, character classes, and wildcards — literal-substring-only
`sed` will silently fail to match intended patterns rather than erroring.
**Effort:** Moderate — the musl/glibc target already provides POSIX
`regcomp`/`regexec`; this is "swap `strncmp` for `regexec`" plus add `-i`, not "write
a regex engine."

### 7. `grep`: real regex support (shares the `<regex.h>` work with sed) + `-r`
**What:** Same substring-only limitation as sed.
**Why it matters:** Anchors/wildcards/character-classes in `grep` patterns are
ubiquitous in scripts; `-r` (recursive) is one of the most commonly used grep flags
for searching a source tree.
**Effort:** Moderate, and can share the regex plumbing built for item 6.

### 8. `init`: add a persistent `SIGCHLD` reaper
**What:** `init` only waits on the `/etc/rc` child directly; there is no ongoing
zombie-reaping for the session.
**Why it matters:** Any real Linux guest running background services or
double-forked daemons needs PID 1 to continuously reap orphans — without this,
zombies accumulate for the entire session lifetime, only cleared by one final
shutdown sweep.
**Effort:** Small, targeted fix — a `SIGCHLD` handler plus a
`waitpid(-1, &status, WNOHANG)` loop, added alongside the existing rc-wait logic.

### 9. `test`/`[`: add `-a`/`-o` and remaining unary operators
**What:** No compound-expression support (`-a`/`-o`), missing `-x`/`-s`/`-L`/
`-nt`/`-ot`/`-ef`.
**Why it matters:** Shell scripts (including the guest's own `/etc/rc` and any
`configure`-style build scripts) commonly use compound test expressions; the
current hard-error on anything beyond a single clause will break real scripts, not
just edge cases.
**Effort:** Small-to-moderate — extending the existing `argc`-shape-driven parser to
handle chained clauses.

### 10. `stat -c`/`--format` custom format strings
**What:** `stat` only prints a fixed, hardcoded output format.
**Why it matters:** `stat -c '%s'`/`stat -c '%Y'`-style invocations are a standard
idiom in build/install scripts for getting a file's size or mtime programmatically;
without format-string support, any script relying on parsed `stat` output breaks
outright.
**Effort:** Small — add a format-directive parser (`%s`/`%Y`/`%n`/`%a` etc.) on top
of the metadata this applet already collects.

---

### Honorable mentions (just outside the top 10)

- **`xargs`: allow invoking arbitrary external binaries**, not just built-in
  applets — currently `find . | xargs anything-not-a-smallclue-applet` fails
  outright. Also missing `-0`/`-I{}`/`-n`.
- **`chmod -R`** (recursive) — extremely common, currently absent.
- **`touch`**: no flags at all (`-c`/`-d`/`-t`/`-r`) — breaks Makefile-style
  timestamp idioms.
- **`awk`** — enormously useful but a full implementation is a much larger project
  than anything above; worth a minimal-subset version (field splitting + simple
  patterns) rather than a full language if time is constrained.
- **`diff`/`patch`** — needed for source patching in build recipes; moderate new
  applets (a Myers-diff-based `diff`, a simpler unified-diff-applying `patch`).
- **`git submodule`** as a standalone subcommand (today only exists inside
  `clone --recurse-submodules`) — directly relevant to PBuild's own submodule-pin-
  bump workflow, and **`git clone --depth`** (shallow clone) for footprint-conscious
  guest images.
- **`ln -s` directory-target auto-append** — `ln -s /usr/bin/foo /usr/local/bin/`
  currently fails instead of creating `/usr/local/bin/foo`, breaking a very common
  idiom.
