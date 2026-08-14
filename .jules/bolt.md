## 2024-05-19 - Optimization of smallclueStrCaseStr for grep -i
**Learning:** `grep -i` operations in this codebase suffer significantly from a manual character-by-character check for case-insensitive matching in the `smallclueStrCaseStr` helper when `ignore_case` is set.
**Action:** Use `#if defined(_GNU_SOURCE) || defined(__APPLE__)` (and other BSDs) to utilize the `strcasestr` standard library function. This relies on the fact that `_GNU_SOURCE` is defined in the `setup_posix_env.sh` compilation script. The manual fallback mechanism is preserved to ensure compatibility on systems without `strcasestr`.
## 2025-05-19 - Optimization of tail stream ring buffer
**Learning:** The `tail` applet (`smallclueTailStream` in `src/core.c`) originally used an array of dynamically allocated strings (`char **ring`) and called `malloc` and `free` on every new line, adding significant overhead for continuous streams.
**Action:** Replace dynamically allocated string arrays with a struct-based ring buffer (`{ char *data; size_t cap; }`) that reuses capacities via `realloc`, significantly reducing `malloc` and `free` overhead for continuous streams.
