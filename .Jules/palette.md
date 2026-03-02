## 2024-05-23 - Grep Color highlighting
**Learning:** Even CLI tools benefit immensely from visual hierarchy. `grep` without color is hard to scan. Users expect standard tools to behave in standard ways (like supporting `--color`).
**Action:** Always check if CLI output can be enhanced with color or formatting to improve readability, but respect `auto`/`never` settings.

## 2024-05-24 - Formatting terminal tabular output
**Learning:** Formatting individual columns of a terminal table output with ANSI escape codes will break the column alignment calculation of `printf`.
**Action:** Always wrap the entire header string in `\033[1m` (bold) and `\033[0m` (reset) before printing using ANSI codes to preserve visual alignment and readability in CLI tools.
