## 2024-05-23 - Grep Color highlighting
**Learning:** Even CLI tools benefit immensely from visual hierarchy. `grep` without color is hard to scan. Users expect standard tools to behave in standard ways (like supporting `--color`).
**Action:** Always check if CLI output can be enhanced with color or formatting to improve readability, but respect `auto`/`never` settings.
## 2024-05-14 - Fix df command header alignment

**Learning:** When applying bold ANSI formatting (`\033[1m`) to individual columns in tabular output (`printf` format string), the invisible escape codes throw off the column width calculations. For `%-24s \033[1m%12s\033[0m`, `printf` pads based on the visible string plus escape characters resulting in misaligned visual columns compared to the data rows.

**Action:** Wrap the entire header line in bold format `\033[1m...\033[0m` instead of formatting individual column placeholders to maintain correct tabular alignment when printed to a TTY.
