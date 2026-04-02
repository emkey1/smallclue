## 2024-05-19 - Optimization of smallclueStrCaseStr for grep -i
**Learning:** `grep -i` operations in this codebase suffer significantly from a manual character-by-character check for case-insensitive matching in the `smallclueStrCaseStr` helper when `ignore_case` is set.
**Action:** Use `#if defined(_GNU_SOURCE) || defined(__APPLE__)` (and other BSDs) to utilize the `strcasestr` standard library function. This relies on the fact that `_GNU_SOURCE` is defined in the `setup_posix_env.sh` compilation script. The manual fallback mechanism is preserved to ensure compatibility on systems without `strcasestr`.
## 2024-05-19 - Optimization of sum applet block read
**Learning:** The `sum` applet processes inputs byte-by-byte using `fgetc`. For an algorithm like BSD or SysV checksums which calculate quickly, IO reading is a significant bottleneck. Reading in blocks (like `smallclueReadStream(f, buf, sizeof(buf), &read_err)`) can improve throughput significantly and eliminates function call overhead for every byte.
**Action:** Replace `fgetc` with `smallclueReadStream` block reading in `sum` implementations (`smallclueBsdSum` and `smallclueSysvSum`) and similarly when scanning files.

## 2025-05-15 - Unrolling loops for SysV Checksums
**Learning:** By analyzing performance hotspots in sequence processing, unrolling a tightly bounded loop manually when summing large arrays significantly reduces branching and condition evaluation overhead in compiler environments with default or basic optimization layers (`gcc`).
**Action:** Unroll hot loops manually or ensure compilers can auto-vectorize performance-critical iterative functions for faster sequential checksums, block parsing, or text streaming operations, aiming to do 16 or 32 elements simultaneously.
## 2025-05-19 - Optimization of wc block read
**Learning:** When counting lines and words, processing bytes individually with branch checks adds large overhead. Unrolling the loop, similarly done in SysV and BSD checksum loops, improves wc execution speeds.
**Action:** Unroll loops that iterate character by character over loaded smallclueReadStream buffers. Used 16-unroll factor for wc and sum routines in smallclueWcProcessFile and smallclueBsdSum.
## 2025-05-19 - Optimization of tr block read
**Learning:** Similar to `wc` and `sum`, character-by-character operations in `tr` have a large overhead from branch evaluation and iteration.
**Action:** Unroll loops that iterate character by character over loaded `smallclueReadStream` buffers. Used a 16-unroll factor for `tr` routines in `smallclueTrCommand`.
## 2025-05-19 - Optimization of smallclueBsdSum block read
**Learning:** The `smallclueBsdSum` loop was processing inputs byte-by-byte which adds branching overhead.
**Action:** Unroll loops that iterate character by character over loaded `smallclueReadStream` buffers. Used 16-unroll factor for `smallclueBsdSum`.
## 2025-05-19 - Optimization of smallclueReadTokensFromStdin tokenizing
**Learning:** `smallclueReadTokensFromStdin` processes stream buffers character-by-character and uses a function call (`isspace`) in the inner loop. This creates significant overhead when applets like `xargs` are reading large amounts of input. Avoiding function calls and inlining the checks increases processing speed substantially.
**Action:** Use manual equivalent inline bounds checking (`(ch == ' ') || (ch >= '\t' && ch <= '\r')`) instead of external function calls like `isspace()` when tokenizing standard stream block processing to avoid overhead.
## 2025-05-19 - Optimization of head stream block read
**Learning:** The `head` applet (`smallclueHeadStream` in `src/core.c`) is optimized by replacing line-by-line dynamic allocations (`smallclueGetlineStream`) with 16KB block processing (`smallclueReadStream`) and a manually unrolled loop to scan for newlines, significantly reducing system call and heap allocation overhead.
**Action:** For sequential parsing, use 16KB block reads with `smallclueReadStream` rather than byte-by-byte or line-by-line dynamic allocations (`smallclueGetlineStream`), and unroll inner loops to eliminate branching overhead.

## $(date +%Y-%m-%d) - Optimize Cat throughput via syscall bypass
**Learning:** For file stream utilities like `cat`, wrapping the stream through stdio `fwrite()` imposes unneeded overhead due to buffering memory copies and lock acquisition compared to raw direct POSIX `write()` loops. By upgrading `cat_file`/`print_file` to use direct `write(STDOUT_FILENO)` with a large stack buffer (64K), we avoid stdio bottlenecking.
**Action:** When implementing tools meant to shovel bytes quickly (cat, yes, dd), use unbuffered direct system calls like `read` and `write` wrapped in retry loops for `EINTR`, and manually ensure `fflush()` is called on stdio streams beforehand if intermixing could occur.
## 2025-05-19 - Optimization of tee applet block write
**Learning:** For utilities like `tee` that stream high volumes of data to `stdout`, using buffered `fwrite(stdout)` imposes significant overhead due to memory copying and stdio lock acquisition.
**Action:** Replace `fwrite` with raw, direct POSIX `write(STDOUT_FILENO)` in a loop that explicitly handles `EINTR` and partial writes to maximize throughput, while retaining `fwrite` for standard file outputs. Always `fflush(stdout)` before jumping to raw writes to avoid interleaving output.
