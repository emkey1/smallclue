# smallclue TODO

## Build & dependency infrastructure

- [x] **Fork + submodule the remaining third-party deps.** libgit2, openrsync,
      nextvi, and dvtm are done (pinned submodules of emkey1 forks, matching
      PSCAL's tree; nextvi's 4 sed patches were baked into commits on a
      dedicated `smallclue` branch of the fork rather than `master`, which
      carries an unrelated PSCAL snapshot).
  - [ ] `openssh` — the one deliberately left out. Fetched as a release
        tarball (not git) and patched by a dozen-plus sed/python edits (main
        renames, musl include guards, showprogress/interrupted aliasing). A
        fork means owning rebases onto upstream releases, including security
        updates — decide if that upkeep is worth it before starting.
- [x] **Make the standalone (non-PSCAL-nested) build less fragile.** CMake now
      self-generates the 4 static stub files that `setup_posix_env.sh` used to
      (only if absent, so root-built/PSCAL trees are untouched) and fails with
      a clear, actionable `FATAL_ERROR` naming the exact `./configure` command
      if `third-party/openssh/config.h` is missing, instead of a bare compiler
      "file not found". The openrsync `config_pscal.h` gap is separately fixed
      by the submodule conversion above.
- [x] **Split `setup_posix_env.sh` into non-root and root halves.** Steps 0-3
      (fetch deps, generate stubs, configure/build OpenSSH+dvtm+libgit2,
      compile+link `smallclue`) moved to a new standalone `build_smallclue.sh`
      (no sudo needed); `setup_posix_env.sh` now just root-checks, calls it,
      then does the actual root-only work (rootfs assembly, `/dev`, install,
      symlinks, `/etc` files). Also fixed two real bugs the root gate had been
      hiding on macOS, uncovered by finally being able to run steps 0-3
      standalone here: (1) two `[ -d ".../.git" ]` dependency checks that
      always failed now that nextvi/dvtm are submodules (`.git` is a file,
      not a dir, for a submodule) — changed to `-e`; (2) the final `gcc`
      invocation forced `_POSIX_C_SOURCE`/`_XOPEN_SOURCE`/`_GNU_SOURCE`
      unconditionally, which on Darwin (even combined with
      `_DARWIN_C_SOURCE`) hides `chroot(2)`'s prototype and has no OpenSSL
      `-I` path for `checksum_app.c`'s `<openssl/evp.h>` — both fixed to
      match CMakeLists.txt's own Apple-vs-not branching.
  - [ ] **Newly discovered, NOT fixed:** this raw-`gcc` build path (used by
        `build_smallclue.sh`/`setup_posix_env.sh`, distinct from the CMake
        path) never actually compiles `src/git_app.c` or
        `src/openrsync_app.c` into the final binary, despite building
        libgit2 and fetching openrsync — `git`/`rsync` silently fall back to
        the "not built in this configuration" stub in binaries built this
        way. Replicating openrsync's CMake integration (a dozen+ source
        files needing the same symbol-rename macros CMakeLists.txt applies)
        in bash is a real chunk of work, deliberately not attempted here.
        Confirmed present before this session's changes too (not a
        regression from the split). If this build path is actually used to
        ship binaries (vs. CMake), this is a real functional gap worth
        prioritizing.
- [x] **Add CI.** `.github/workflows/build.yml` runs `fetch_dependencies.sh`
      + openssh `./configure` + cmake configure/build/smoke-test on macOS and
      Linux, on every push/PR to main. Both jobs green on the first real run
      (github.com/emkey1/smallclue/actions).

## Known bugs / behavior gaps

- [ ] **rsync `-c`/`--checksum` can hang against a non-openrsync/smallclue
      peer** (both ends block in poll(); README documents `--timeout=N` as the
      workaround). Fix would be detecting/failing loudly like `-z` does.
- [ ] Legacy rsync engine (`PSCALI_RSYNC_LEGACY=1`): remote
      `-u/-c/--include/--exclude/--delete` are not implemented in the scp
      bridge path.

## Documentation

- [x] **COMPARISON.md was stale on the shell:** fixed to say standalone builds
      use smallclue's own native POSIX shell (`src/shell/`), with `exsh` only
      for embedded-PSCAL (`WITH_EXSH`) builds, matching README.
- [x] `fetch_dependencies.sh` pinned nothing for nextvi/dvtm (HEAD of
      upstream) — fixed by the submodule conversion above.
