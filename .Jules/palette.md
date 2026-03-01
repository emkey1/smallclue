## 2024-05-23 - Grep Color highlighting
**Learning:** Even CLI tools benefit immensely from visual hierarchy. `grep` without color is hard to scan. Users expect standard tools to behave in standard ways (like supporting `--color`).
**Action:** Always check if CLI output can be enhanced with color or formatting to improve readability, but respect `auto`/`never` settings.

## 2024-03-01 - Make `df` table headers bold in interactive terminals
**Learning:** Terminal tabular outputs (like `df`) are significantly easier to read when headers are bolded to visually separate them from the data rows.
**Action:** When implementing new tabular terminal outputs, wrap the header row `printf` in `isatty(STDOUT_FILENO)` checks to add `\033[1m` ANSI escape codes for interactive sessions, ensuring the codes are outside any width specifiers (e.g., `%-24s`) to prevent column misalignment.
