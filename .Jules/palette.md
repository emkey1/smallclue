## 2024-05-23 - Grep Color highlighting
**Learning:** Even CLI tools benefit immensely from visual hierarchy. `grep` without color is hard to scan. Users expect standard tools to behave in standard ways (like supporting `--color`).
**Action:** Always check if CLI output can be enhanced with color or formatting to improve readability, but respect `auto`/`never` settings.

## 2024-05-23 - Terminal Tabular Data Hierarchy
**Learning:** Terminal outputs displaying tabular data (like `df`, `top`, `ps`) are much easier to scan if the header row has a distinct visual hierarchy. Applying a bold font weight is a common and effective pattern. It's critical to only apply these ANSI formatting codes when the standard output is a TTY (`isatty(STDOUT_FILENO)`) to avoid corrupting data piped to other commands or log files.
**Action:** When implementing or modifying CLI commands that output tables, apply bold styling to the header row when rendering to a terminal, ensuring fallback to plain text for non-interactive outputs.
