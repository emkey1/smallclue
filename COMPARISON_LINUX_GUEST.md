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
`src/core.c` (25,211 lines), `src/git_app.c` (13,191 lines), `src/openrsync_app.c`,
and `third-party/openrsync/main.c` — not from the README, which turns out to be
stale in several important ways (noted inline). All line numbers refer to the
current `HEAD` of the `smallclue` submodule as re-audited on 2026-07-09.

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

**This entire category is now stale — every item below has been closed** by a
dedicated new applet/source file since this table was written (confirmed by
re-grepping current `src/*.c`, ~89 completed tasks visible in `git log
--oneline`). Two narrow sub-gaps remain (hexdump/xxd, and nice/setsid), noted
inline. Kept in table form for continuity, with "Notes" now describing current
reality rather than absence.

| Applet | Current status | Notes |
|---|---|---|
| **tar** | **Implemented.** `src/tar_app.c`, `smallclueTarCommand`. | Real ustar-format create/extract/list (`-c`/`-x`/`-t`/`-v`/`-f`/`-z`/`-C`), with gzip auto-detected on read via magic bytes regardless of `-z`, and zlib-backed on write when `-z` is given. GNU longname/PAX extensions explicitly out of scope (documented in-file). |
| **gzip / gunzip / zcat** | **Implemented.** `src/gzip_app.c`, `smallclueGzipCommand`/`smallclueGunzipCommand`/`smallclueZcatCommand`. | Wraps the already-linked zlib (`gzopen`/`gzread`/`gzwrite`) rather than reimplementing DEFLATE, exactly as previously proposed. Supports `-c`/`-d`/`-k`/`-f`. |
| **awk** | **Implemented.** `src/awk_app.c` + `awk_lexer.c`/`awk_parser.c`/`awk_interp.c`/`awk_value.c` (a from-scratch interpreter, ~2000 lines in the interpreter alone). | Targets the BusyBox awk feature set: field splitting/NF/NR, BEGIN/END/pattern-range, user-defined functions, hash-table associative arrays with SUBSEP joining, and builtins (`length`/`substr`/`index`/`split`/`sub`/`gsub`/`match`/`sprintf`/`tolower`/`toupper`/`system`/`close`, etc). CLI: `-F`, `-v`, `-f` (repeatable), `-e`. |
| **diff / cmp** | **Implemented.** `src/diff_app.c` (`smallclueDiffCommand`) and `src/cmp_app.c` (`smallclueCmpCommand`), both new standalone applets. | `diff`: O(n·m) DP LCS (documented as a deliberate simplicity tradeoff over Myers), real unified-diff output (`---`/`+++`/`@@` hunks with context); supports `-u`, `-q`/`--brief`; no `-c` context-diff, no `-r` recursive directory comparison. `cmp`: byte-by-byte compare, `-s`/`--silent`, `-l`/`--verbose` (lists all differing offsets). |
| **patch** | **Implemented.** `src/patch_app.c`, `smallcluePatchCommand`. | Applies unified-diff hunks (`-p N` path-strip, `-i FILE`, `-v`). Context lines verified strictly; a mismatched hunk is reported and skipped rather than fuzzy-matched (documented scope limit, no reverse-patch). |
| **expr** | **Implemented.** `src/expr_app.c`, `smallclueExprCommand`. | Full POSIX precedence-climbing grammar (`or`/`and`/`cmp`/`add`/`mul`/`colon`/`primary`): arithmetic, comparisons, `&`/`|` logical, `length`/`index`/`substr`/`match`, `:` BRE matching via `regcomp`/`regexec`. |
| **dd** | **Implemented.** `src/dd_app.c`, `smallclueDdCommand`. | `if=`/`of=`/`bs=`/`count=`/`skip=`/`seek=`/`conv=notrunc` (no `sync`/`noerror`/`ucase`/`lcase`), size suffixes `k`/`M`/`G`/`b`/`w`, GNU-style `N+M records in/out` summary. |
| **od / hexdump / xxd** | **`od` implemented; `hexdump`/`xxd` still absent.** `src/od_app.c`, `smallclueOdCommand`. | `od` supports `-A d\|o\|x\|n`, `-t x1/x2/x4/o1/o2/o4/d.../u.../c`, `-c`, `-v`. `hexdump`/`xxd` remain genuinely unimplemented — confirmed no code or aliasing anywhere in `src/*.c`. |
| **printf (standalone)** | **Implemented.** `src/printf_app.c`, `smallcluePrintfCommand`, registered as the `printf` applet. | Supports `%s/%d/%i/%o/%u/%x/%X/%c/%e/%E/%f/%F/%g/%G/%b`, flags/width/precision, backslash escapes, octal/hex escapes for `%b`, and POSIX repeat-format-until-args-exhausted looping. |
| **readlink / realpath** | **Implemented.** `src/readlink_app.c`, `smallclueReadlinkCommand`/`smallclueRealpathCommand`, registered as separate applets. | `readlink -f` supported, plus `-e` (must exist), `-m` (allow missing components), `-n` (no trailing newline); `realpath` defaults to GNU-matching allow-missing-final-component behavior. |
| **chown / chgrp** | **Implemented.** `src/chown_app.c`, `smallclueChownCommand`/`smallclueChgrpCommand`, registered separately. | `user:group`/`user:`/`:group` syntax (numeric or named), `-R` recursive, `-h`/`--no-dereference` (uses `lchown`). |
| **install** | **Implemented.** `core.c`, `smallclueInstallCommand`. | `-m MODE`, `-d` (create directories), `-D` (create dest's parent dirs), `-v`; copies into a directory or renames to an explicit dest, then chmods. `-o`/`-g` (owner/group) explicitly out of scope (documented — requires root). |
| **timeout / nohup / nice / setsid** | **`timeout`/`nohup` implemented; `nice`/`setsid` still absent.** `src/nohup_app.c` (`smallclueNohupCommand`) and `core.c` (`smallclueTimeoutCommand`). | `nohup` ignores SIGHUP, redirects to `nohup.out` when attached to a tty. `timeout` supports `-s`/`--signal`, `-k`/`--kill-after` (SIGKILL escalation), `--preserve-status`, own process group, exit 124 on timeout. `setsid`/`nice` are not applets — `setsid()` only appears internally (pty/ssh-shim plumbing), and "nice" only appears as a `/proc/stat` field name. |
| **base64 / md5sum / sha1sum / sha256sum** | **Implemented.** `src/base64_app.c` (`smallclueBase64Command`) and `src/checksum_app.c` (`smallclueMd5sumCommand`/`smallclueSha1sumCommand`/`smallclueSha256sumCommand`). | `base64`: `-d`/`--decode`, `-w`/`--wrap COLS`, `-i`/`--ignore-garbage`. Checksums share one driver, support `-c`/`--check`, and use real OpenSSL (`EVP_md5`/`sha1`/`sha256`) as the crypto backend, not vendored/in-tree code. |
| **seq / nl / fmt / fold / split / comm / paste / tac / rev** | **Implemented.** `src/seq_app.c`, `nl_app.c`, `fmt_app.c`, `fold_app.c`, `split_app.c`, `comm_app.c`, `paste_app.c`, `tac_app.c`, `rev_app.c` — nine dedicated new applet files. | `seq` (`-s`/`-w`), `nl` (`-b`/`-s`/`-w`), `fmt` (`-w`, default 75), `fold` (`-w`/`-s`), `split` (`-b`/`-l`), `comm` (3-column sorted diff, no `-1`/`-2`/`-3` suppress flags), `paste` (`-d`/`-s`), `tac`, `rev` — all real functional implementations, not stubs. |
| **A real `top`** | **Implemented for Linux.** Two `smallclueTopCommand` definitions in `core.c` under `#if defined(PSCAL_TARGET_IOS) ... #else ... #endif`; both registered under `"top"`. | The non-iOS/Linux branch is a genuine `/proc` reader (`/proc/<pid>/stat`, `/proc/stat`, `/proc/meminfo`, `/proc/loadavg`, `/proc/<pid>/cmdline`), computing %CPU by diffing utime/stime ticks across samples and %MEM from RSS; supports `-d SECONDS`, `-n COUNT`, `-b` batch mode. |

---

## 3. Category (b): applets that exist but are materially incomplete

### Text processing & filtering

- **`sed`** (`smallclueSedCommand`, `core.c:19130`) — code now supports real regex: `smallclueSedParseExpr` (`core.c:18618`) uses `regcomp`/`regexec` (`REG_EXTENDED`/`REG_ICASE`), not literal `strncmp` matching. `-i` (with optional backup suffix), `-e`/`-f` (multiple scripts, concatenated), and `-E`/`-r` are all supported. Address/line-range selection (line number, `$`, regex, `N,M`) is implemented via `smallclueSedAddrMatches`/`smallclueSedParseAddress` (`core.c:18506-18574`). `y///` transliteration is implemented (`smallclueSedParseYExpr`/`smallclueSedApplyY`, `core.c:18675`/`18702`). Multiple `;`-separated commands are parsed by `smallclueSedParseScript` (`core.c:18971`). The old `g`-flag substring-match bug is fixed — flags are now scanned char-by-char (`core.c:18636-18644`), rejecting unrecognized flag characters. Remaining gap: only `s`/`y`/`d`/`p` command letters are recognized (`core.c:19079-19086`) — `a`/`i`/`c`/`q` are still unsupported.
- **`grep`** (`smallclueGrepCommand`, `core.c:20085`) — code now supports real regex via `regcomp`/`regexec`, with no literal-substring fallback path. Flags supported: `-n`, `-i`, `-v`, `-r`/`-R` (recursive), `-E`, `-c`, `-o`, `-w`, `-x`, `--color`/`--colour`. Remaining gap: `-l`/`-L` (files-with-matches) and `-A`/`-B`/`-C` (context) and `-e`/`-f` (multiple patterns/pattern file) are still missing.
- **`tr`** (`smallclueTrCommand`, `core.c:19602`) — code now has real per-character flag parsing: `-d`, `-s`, `-c`/`-C` are all independently parsed and combinable (`core.c:19609`), so `tr -d 'set'` works correctly (no more `-d`/`'set'` positional misparse). `smallclueTrExpandSet` (`core.c:19520`) expands `a-z`-style ranges, all 12 POSIX classes (`[:alpha:]` etc., `core.c:19525-19546`), `[c*n]` repeat syntax, and backslash escapes — this exceeds what the old audit even asked for. No remaining gap of substance here.
- **`cut`** (`smallclueCutCommand`, `core.c:19320` area) — code now supports field ranges/lists via `smallclueCutParseList` (`core.c:19320`: comma lists and `N`/`N-M`/`N-`/`-M` forms), plus a separate `-c` byte/character-range mode (`smallclueCutPrintChars`). `-s` (suppress no-delimiter lines) is implemented, and the old bare-newline bug is fixed: `smallclueCutPrintFields` (`core.c:19370-19377`) now prints the whole original line unless `-s` is given. No remaining gap of substance here.
- **`cat`** (`smallclueCatCommand`, `core.c:15785`) — code now parses `-n`, `-b`, `-E`, `-T`, `-s`, `-A` (combined E+T) via a real per-character option switch, rather than treating flags as filenames.
- **`echo`** (`smallclueEchoCommand`, `core.c:12054`) — code now parses `-n`/`-e`/`-E` with bash-compatible option-cluster detection; `smallclueEchoPrintExpanded` (`core.c:12002`) handles `\a \b \c \e \f \n \r \t \v \\`, octal `\0NNN`, and hex `\xHH` escapes.
- **`sort`** (`smallclueSortCommand`, `core.c:18066`) — code now supports `-r`, `-n`, `-u`, `-c`, `-C`, `-m`, `-t`, `-k`. Sorting uses a genuine bottom-up merge sort (`smallclueSortStableRec`/`smallclueSortStableMerge`, `core.c:5673-5695`) in place of `qsort`, explicitly for real stability rather than incidental tie-break behavior (per the code comment at `core.c:5668`). No remaining gap of substance here.
- **`uniq`** (`smallclueUniqCommand`, `core.c:18303`) — code now supports `-c`, `-d`, `-u`, `-i`, `-f`/`--skip-fields`, `-s`/`--skip-chars`, and `-w` (max-chars), all wired into a shared comparison-key helper. No remaining gap of substance here.
- **`head`/`tail`** — code now supports signed forms via `smallclueParseSignedLineCount` (`core.c:16630`): `head -n +N` prints from line N to end, `head -n -N` prints all but the last N; `tail -n +N` starts at line N (`core.c:17118-17130`). Remaining gaps: neither `head` nor `tail` has a `-c` byte-count mode, and `tail -f` still explicitly refuses more than one input file (`"tail: -f currently supports a single input"`, `core.c:17161-17164`) — unchanged from the original claim.
- **`wc`** (`smallclueWcCommand`, `core.c:20451`) — code now supports `-m` (character count, triggers `setlocale(LC_CTYPE, "")` for multibyte correctness) and `-L` (max line length) alongside `-l`/`-w`/`-c`; multi-file totals correctly take the max, not the sum, for `-L`'s aggregate row. No remaining gap.

### File management

- **`find`** (`smallclueFindCommand`, `core.c`) — code now supports far more than the old single-predicate parser: a real recursive-descent predicate-tree parser (`smallclueFindParseOr` → `ParseAnd` → `ParseNot` → `ParsePrimary`) builds an AST evaluated with proper C-style short-circuit `&&`/`||` semantics. Confirmed implemented: `-name`/`-iname` (fnmatch, case-fold), `-type f/d/l`, `-maxdepth`/`-mindepth`, `-delete` (children-before-parent, matches GNU), `-exec ... ;` with `{}` substitution via fork/execvp, `-mtime`/`-newer`/`-size` (with correct unit handling), `-print`/`-print0`, and full boolean logic `-a`/`-and`/implicit-AND, `-o`/`-or`, `!`/`-not`, `( )` grouping with correct AND-tighter-than-OR precedence. Two residual gaps: **no `-prune`** at all, and `-exec` supports only `;` termination, not the `+` batch form.
- **`cp`** (`smallclueCpCommand`, `core.c`) — code now supports `-r`/`-R`/`-a`/`-p`, correctly combined (`-a` implies recursive+preserve-times); directories now dispatch to a real recursive-copy path instead of hard-erroring. Remaining gap: no `-f`/`-i`/`-n`, and any other unrecognized flag still hard-errors.
- **`mv`** (`smallclueMvCommand`, `core.c`) — fixed: the `EXDEV` fallback now stats the source and, for directories, dispatches to `smallclueCopyRecursive` (the same recursive-copy path `cp -r`/`-a` uses, with timestamp preservation) followed by a recursive `smallclueRemovePathWithLabel` of the source tree; single files still use `smallclueCopyFile` as before. Verified with a real cross-filesystem move (separate APFS volume) of a nested directory tree including a symlink: destination landed intact, source fully removed.
- **`touch`** (`core.c`) — code now supports `-c`/`--no-create`, `-a`, `-m`, `-r FILE`/`-rFILE`, `-t TIMESPEC`, and `-d DATESTRING`, closing the old Makefile-idiom gap.
- **`stat`** (`core.c`) — code now supports `-c`/`--format=` with a rich directive set (`%n %s %b %B %f %F %a %A %u %g %U %G %i %h %d %X %Y %Z`, plus `\n`/`\t` escapes), alongside the existing `-L`. Remaining gap: no `-f` (filesystem-info/statfs mode) — `getopt` string is still just `"Lc:"`.
- **`chmod`** (`core.c`) — `-R`/`-r`/`--recursive` now implemented and correctly recurses. Remaining gap: the symbolic-mode parser still only accepts `r`/`w`/`x` — `X`/`s`/`t` (conditional-exec, setuid/setgid, sticky) are still unsupported in symbolic mode.
- **`ln`** (`core.c`) — code now supports `-f` (unlinks the target before linking, avoiding EEXIST) and directory-target auto-append (computes each source's basename when the target is a directory, for both single- and multi-operand forms) — the `ln -s /usr/bin/foo /usr/local/bin/` idiom now works.
- **`rm`** (`core.c`) — code now supports `--preserve-root` (default on) / `--no-preserve-root` with a real root-path guard, and both cases of `-r`/`-R` via `getopt`. The double-confirmation-prompt bug is fixed: the directory-recursion branch's second prompt is now gated so it only fires for non-interactive/non-forced recursion, not for `rm -ri DIR` (which now asks once, as expected).
- **`mount`/`umount`** — the **Linux code path is a genuine, generic `mount(2)`/`umount(2)` syscall wrapper**, not iOS-bind-mount-only (confirmed: zero special-casing, positive or negative, for `proc`/`tmpfs`/`sysfs`/`devtmpfs` anywhere — unrecognized `-o` tokens are passed straight through as filesystem-specific mount data exactly like real `mount(8)` does). `mount -t proc proc /proc`, `-t tmpfs`, and `-t sysfs` are now **verified working in Docker**. `umount` also has **`-l`/`-f`** (lazy/force unmount via `umount2()` flags) as of a prior fix. No remaining gap here.
- **`df`** (`core.c`) — code now enumerates all mounts when no path is given: `smallclueDfEnumerateMounts` parses `/proc/mounts` (falling back to `/etc/mtab`) on Linux, skipping pseudo-filesystems (tmpfs, proc, sysfs, overlay, etc.), or uses `getmntinfo` on BSD/macOS.
- **`du`** (`core.c`) — code now uses actual disk usage (`st_blocks * 512`, not `st_size`) and, by default (no flags), prints a subtotal per directory at every depth, only printing a non-directory entry when it's the top-level operand — matching GNU `du`'s default. `-c` (grand total), `-x` (one-filesystem via `st_dev`), and `-d N`/`--max-depth=N` are all now implemented.
- **`ls`** (`core.c`) — code now supports `-R` (recursive, with `"name:\n"` headers), `-S`/`-X`/`-v`/`-r` (real `qsort` comparators for size/extension/version, real array-reversal), and `-i` (inode plumbed through to the print functions) — none of these are stubs.
- **`basename`/`dirname`** (`core.c`) — code now matches GNU semantics: `basename` accepts a SUFFIX as a second positional arg in single-operand form, and `-a`/`--multiple` or `-s SUFFIX`/`--suffix=` enables multi-operand mode (one name per line), plus `-z`/`--zero`; `dirname` loops over all operands printing one per line (correctly has no suffix option, matching real GNU `dirname`).

### Networking

- **`git` credential support — code now supports authenticated remotes.** `smallclueGitCredentialsCallback` (`git_app.c:85`), with helpers `smallclueGitTryAgentKey` (`:49`) and `smallclueGitTryDefaultKeyFile` (`:53`), is wired via `smallclueGitApplyCredentials` (`:114`) into all 7 options-struct call sites: the 1 clone (`:9131`), all 5 fetch (`:9510`, `:10023`, `:10063`, `:10791`, `:11000`), and the 1 push (`:12938`) — a single shared callback reused everywhere, exactly as previously proposed. It tries, in libgit2 `allowed_types` order: SSH-agent key (`git_credential_ssh_key_from_agent`), then unencrypted default key files under `~/.ssh` (id_ed25519/id_ecdsa/id_rsa, requiring both private+public present) for SSH; `GIT_USERNAME`+`GIT_PASSWORD` env vars or a bare `GIT_TOKEN` (as password, with `usernameFromUrl` or `x-access-token` as user) for HTTPS; falling back to `git_credential_default_new` (NTLM/Negotiate), then `GIT_PASSTHROUGH` if nothing applies (preserving anonymous-transport behavior). Code now supports token/SSH-key auth for the common hosted-remote push/pull case; not verified against a real authenticated remote in this pass.
- **`git submodule` — now a standalone subcommand, but not fully.** `smallclueGitCommandSubmodule` (`git_app.c:8940`) dispatches from `"submodule"` (`:13093`) independent of `clone`. `status` (walks via `git_submodule_foreach`, printing git's ` <sha> path`/`-<sha> path`/`+<sha> path` convention, missing only the branch-name annotation) and `update`/`init` (folded into one path reusing the recursive clone-update-submodules helper, with pathspec filtering or "all") now work standalone — covering exactly PBuild's own submodule-pin-bump workflow. `sync`, `foreach`, and `deinit` are recognized names but explicitly stubbed out (`"submodule: this subcommand is not implemented"`, `git_app.c:8998`) — still a real gap for those three.
- **`git clone --depth`** (shallow clone) — now implemented: `--depth N`/`--depth=N` is parsed in `smallclueGitCommandClone` and sets `clone_opts.fetch_opts.depth` (a real libgit2 field). `--shallow-since`/`--shallow-exclude` remain absent (zero matches) — still a gap for those two.
- **`git log --graph` and `git log -p`** — both now implemented, plus a real bug fix. `-p`/`--patch`/`-u` (with `-s`/`--no-patch` to disable) reuses the same tree-diff/print path as `git show`. `--graph` prefixes each entry's first line with `"* "` (documented in-code as not reproducing full per-commit graph-column continuation on multi-line entries — an accepted scope trade-off). Separately, non-oneline `log` previously fell back to the same one-line summary as `--oneline`; it now has a distinct full-format branch (`commit <full-hash>` / `Author:` / `Date:` / 4-space-indented message, correct inter-entry blank-line spacing) plus a date-formatting fix avoiding `%e`'s space-padding to match real git's single-space single-digit-day rendering. (`merge`, `rebase`, `stash`, `cherry-pick`, `revert`, and `blame` remain **already implemented with real libgit2-backed logic** — the README is simply stale in not mentioning them; this is a documentation fix, not an implementation gap.)
- **`rsync` — the README describes the wrong default engine** (now corrected). By default (unless `PSCALI_RSYNC_LEGACY=1` is set), `smallclueRsyncCommand` (`core.c:17866-17869`) dispatches to the **vendored upstream `openrsync`** (`third-party/openrsync/`, built unconditionally per `CMakeLists.txt:60-181`) — a real rsync-protocol client, not the hand-rolled local-sync-plus-scp engine the README documents. `--compare-dest`/`--copy-dest`/`--link-dest` are now implemented (previously `--copy-dest`/`--link-dest` were compiled out behind `#if 0`; fixed by re-enabling the option table/switch case and adding a `linkat()`-based hardlink helper, `copy.c`'s `link_file()`). **Important verification gotcha found while fixing this:** openrsync's local-to-local transfer path forks a child that `execvp()`s a program literally named `"rsync"` (`fargs.c`'s `RSYNC_PATH`) to act as the protocol's server side — on a dev machine with a real system rsync in `$PATH`, this silently masks any local code changes, since the real rsync satisfies the exec and runs instead. Verifying against smallclue's actual deployment topology (a `rsync -> smallclue` self-symlink, matching `setup_posix_env.sh`'s per-applet symlink generation) is required to actually exercise this code. Daemon-push is also now implemented: `fargs_parse()`'s blanket rejection of sender mode against a remote daemon target was replaced with a real validation branch, and `socket.c`'s `rsync_socket()` now branches to `rsync_sender()` instead of asserting receiver-only (mirroring the pattern `client.c` already used for SSH pushes) -- verified against a real `rsync --daemon` in Docker, both `rsync://host:port/module/path` and `host::module/path` forms, with the existing pull path confirmed unaffected. `--progress` is also now implemented (live per-file percentage during transfer, not just a post-hoc summary): hooked into both `downloader.c` (pull direction) and `sender.c` (push direction), since openrsync's local-fork/execvp-self design means only ONE of the two roles has a real stdout to print to depending on the transfer direction -- instrumenting both sides was necessary for local syncs, ssh pushes/pulls, and daemon pushes/pulls to all show progress correctly. `-z`/`--compress` is also now real: `zcompress.c` adds a session-persistent raw-deflate/inflate stream (Z_SYNC_FLUSH per chunk, so each wire unit decodes independently), wired into `sender.c`'s literal-data path and `downloader.c`'s receive path, plus a `fargs.c` fix to actually forward `--compress` to the peer invocation (previously only ssh's own transport-compression flag was forwarded, never ours, so the two sides would silently disagree about whether payload data was compressed). This is openrsync/smallclue's own wire format, not GNU rsync's -- confirmed via testing that pushing with `-z` to a real, unmodified `rsync --daemon` fails loudly and immediately ("Invalid block index ... error from remote host"), not silently, which is an acceptable boundary since smallclue is always on both ends of any transfer it initiates with `-z`. Verified a 4.29 MB highly-compressible file dropped to 16.4 KB actually read over the wire (via the existing wire-byte counters), incompressible random data transfers without corruption, and no interaction issues combined with `--progress` or `--copy-dest`. `-c`/`--checksum` is also now implemented: `check_file()` (`uploader.c`) is gated to never trust size/mtime alone when `sess->opts->checksum` is set, instead reporting "possible match" so the real block-transfer engine's rolling+strong checksums decide -- verified this already-existing code path is genuinely correct and fast (a same-size file with only its mtime touched round-trips through block-matching correctly, sending zero literal bytes, well under a second), then confirmed `-c` catches the specific case it exists for: same size AND same mtime but genuinely differing content, correctly detected and re-synced, no hang, no delay. A prior attempt at this flag had been reverted (documented in a since-removed `uploader.c` comment) after producing a wrong skip of genuinely-differing content plus an unexplained delay; that symptom is consistent with accidentally returning "up to date" instead of "needs a real comparison" in the same-size branch, which this version deliberately never does. `fargs.c` also needed the same peer-forwarding fix `-u`/`--update` needed (checksum's skip-decision runs on the receiving side, which for a push is the peer, not us). **Caveat found while stress-testing this against a real, unmodified `rsync` daemon (3.2.7):** unlike `-z` (fails loudly and immediately against a foreign peer), forwarding `-c` to one can cause a silent, indefinite hang in the exact same-size/same-mtime/differing-content case -- both sides end up blocked in `poll()` waiting on each other, apparently because the foreign daemon's own (much newer protocol) `--checksum` implementation expects a whole-file-checksum wire exchange this fork doesn't produce. Confirmed via `sample`-based stack traces (stuck in `rsync_sender()`'s `poll()`) and the daemon's own log (received a partial file list, then silence) that this is specifically a foreign-peer protocol mismatch, not a bug in the smallclue-to-smallclue case: the identical same-size/same-mtime/differing-content scenario against smallclue's own local self-exec re-transfer path (a genuinely separate two-process IPC round-trip, not a same-process shortcut) works correctly and fast. Same scope boundary as `-z`: openrsync/smallclue is assumed to be on both ends of any transfer it initiates; pass `--timeout=N` explicitly when combining `-c` with a peer that might not be. The legacy hand-rolled engine (only reachable via the undocumented `PSCALI_RSYNC_LEGACY=1` escape hatch) is the one that actually matches the README's non-default description.
- **`curl`/`wget`** — genuinely libcurl-backed (`smallclueHttpFetch`), so **HTTP(S) download inside the guest does work** by default. Code now also supports `-X` (method override), `-H` (repeatable headers), `-d` (POST body, joined with `&` across repeats), `-u` (basic auth), and `-k`/`--no-check-certificate` (insecure TLS) — wired to `CURLOPT_CUSTOMREQUEST`, `CURLOPT_HTTPHEADER`, `CURLOPT_POSTFIELDS`/`CURLOPT_POSTFIELDSIZE`, `CURLOPT_HTTPAUTH`+`CURLOPT_USERPWD`, and `CURLOPT_SSL_VERIFYPEER`/`CURLOPT_SSL_VERIFYHOST` respectively (`smallclueCurlApplyRequestOptions`). `wget` has equivalent long-form flags (`--method=`, `--header=`, `--post-data=`). No remaining gap of substance here.
- **`ping`** — the README's claim ("TCP-based ping utility") was already factually wrong for the code even before this pass: it's genuine ICMP (`IPPROTO_ICMP` DGRAM socket with a real checksummed ICMP header). Code now also supports IPv6: `-4`/`-6` force a family, defaulting to `AF_UNSPEC` (tries both) rather than hard-filtering to the first `AF_INET` result; a dedicated ICMPv6 path builds/validates `ICMP6_ECHO_REQUEST`/`ICMP6_ECHO_REPLY`. No remaining gap of substance here.
- **`telnet`** — code now implements a real IAC state machine (`TELNET_IAC/DO/DONT/WILL/WONT/SB/SE` constants, a dedicated parse-state enum): intercepts `IAC DO/WILL <opt>` and replies `IAC WONT <opt>`/`IAC DONT <opt>` (declining every option), consumes `IAC SB ... IAC SE` subnegotiation without echoing it, and unescapes doubled `IAC IAC` as a literal data byte. No longer a raw byte-pump.
- **`nslookup`/`host`** — reverse/PTR lookup, a real custom-DNS-server override, and MX/TXT/NS/SRV record queries are now implemented: a from-scratch raw UDP/TCP DNS client (wire-format name encode/decode with compression-pointer support, A/AAAA/PTR/CNAME/NS/MX/TXT/SRV parsing, RCODE handling, and a DNS-over-TCP fallback for truncated UDP replies per RFC 1035) is used whenever a trailing `server` argument is given (or, for the new record types, always -- they have no `getaddrinfo()` equivalent, so a raw query is issued against `/etc/resolv.conf`'s default nameserver when no explicit server is given). `host -t TYPE` and `nslookup -type=TYPE`/`-q=TYPE` both select MX/TXT/NS/SRV. Verified against real external resolvers (8.8.8.8) for forward/reverse/`-4`/`-6` address lookups and all four new record types (including a real bug the TXT verification caught: a well-populated domain's TXT answer exceeded 512 bytes with no EDNS0 advertised, so the server truncated it and set the TC bit, which the client didn't check at all before -- fixed with the TCP fallback).
- **`ip addr`** — `add`/`del` (address), `link set up/down`, `route add/del`, and `flush` are now implemented via real `AF_NETLINK`/`NETLINK_ROUTE` sockets (RTM_NEWADDR/DELADDR/NEWLINK/NEWROUTE/DELROUTE), verified against a real kernel's netlink subsystem in Docker including edge cases (on-link routes, duplicate-add rejection, nonexistent-route deletion, flushing an interface with multiple addresses down to zero, and a second flush against an already-empty interface as a clean no-op).

### Process / shell / system

- **`init` now reaps children continuously, not just at shutdown.** `smallclueInitCommand` (`core.c`) now loops `waitpid(-1, &status, 0)` continuously while `/etc/rc` runs, reaping any child that exits (not just rc's own PID), only stopping the loop once rc's own PID is reaped; the original shutdown sweep (`kill(-1, SIGTERM)`/sleep/`kill(-1, SIGKILL)`) is unchanged and still runs afterward. No dedicated `SIGCHLD` handler was added, but the blocking reap-loop achieves the same "continuously reap during the session" effect the old gap described as missing.
- **`ps` now takes real arguments.** Code now parses `-p`/`--pid` (with comma lists), `-u`/`--user` (name or uid lists), `-f` (full format), and accepts bundled/BSD-style invocations (`ps aux`, `ps -ef`). The `STAT` state character, previously parsed but unused, is now actually displayed (an `S` column) when `-f` is given.
- **`xargs` can now invoke external binaries.** The runner now falls back to `fork()`+`execvp()` when `smallclueFindApplet` finds no built-in match, so `find . | xargs some-external-tool` now works. Code also now supports `-0` (NUL-delimited), `-t` (verbose/echo), `-I`/`-I{}` (attached and separate forms, per-line substitution), and `-n` (batch size) — no `-P` (parallel) support exists. Tokenization is now quote/backslash-aware (tracks quote state for `'`/`"`, honors backslash escapes outside quotes, reports "unmatched quote" errors) rather than whitespace-only.
- **`test`/`[` now supports `-a`/`-o` and the previously-missing unary/binary operators.** Code now implements unary `-x`, `-s`, `-L`/`-h`, and binary `-nt`, `-ot`, `-ef` (via stat device/inode comparison), plus `-a`/`-o` with correct POSIX precedence (OR splits outermost, AND binds tighter, both recursing per side) — compound expressions no longer hard-error.
- **`date` now supports `-d`/`--date=STRING` and `-s`/`--set=STRING`.** `-d`/`--date` parses an arbitrary date string and converts it; `-s`/`--set` additionally calls `clock_settime(CLOCK_REALTIME, ...)` to actually set the system clock. No remaining gap of substance here.
- **`time` can now time external binaries on non-iOS builds.** The non-iOS path now does `fork()`+`execvp(argv[0], argv)` for any non-applet binary and translates exit/signal status to a return code — the iOS-only shebang gate is no longer the only path; Linux `time somebinary` no longer just prints "command not found."

---

## 4. Top 10 fixes, ranked for the self-sufficient-Linux-guest use case

**Status update: all 10 items below are now closed** (confirmed against current
source in section 2/3 above) — this list is kept as a historical record of what
was prioritized and why, not as an open punch list. Each entry's "What"
describes the state at the time this ranking was written; see the
corresponding bullet in sections 2-3 for current behavior and any residual
sub-gaps (e.g. `find -prune` and `-exec ... +`, `chmod` symbolic `X`/`s`/`t`,
`stat -f`).

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

**Status update: all items below are now closed**, including `mv`'s
cross-filesystem directory fallback (see the `mv` bullet in section 3 —
now repointed at `cp`'s recursive-copy path).

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
