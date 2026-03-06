## 2024-05-19 - Optimization of smallclueStrCaseStr for grep -i
**Learning:** `grep -i` operations in this codebase suffer significantly from a manual character-by-character check for case-insensitive matching in the `smallclueStrCaseStr` helper when `ignore_case` is set.
**Action:** Use `#if defined(_GNU_SOURCE) || defined(__APPLE__)` (and other BSDs) to utilize the `strcasestr` standard library function. This relies on the fact that `_GNU_SOURCE` is defined in the `setup_posix_env.sh` compilation script. The manual fallback mechanism is preserved to ensure compatibility on systems without `strcasestr`.
## 2024-05-19 - Optimization of sum applet block read
**Learning:** The `sum` applet processes inputs byte-by-byte using `fgetc`. For an algorithm like BSD or SysV checksums which calculate quickly, IO reading is a significant bottleneck. Reading in blocks (like `smallclueReadStream(f, buf, sizeof(buf), &read_err)`) can improve throughput significantly and eliminates function call overhead for every byte.
**Action:** Replace `fgetc` with `smallclueReadStream` block reading in `sum` implementations (`smallclueBsdSum` and `smallclueSysvSum`) and similarly when scanning files.
