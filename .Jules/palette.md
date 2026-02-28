## 2024-05-17 - Bold TTY headers

**Learning:** Tabular CLI applications (like `top` and `df`) greatly benefit from bold formatting (`\033[1m`) on their header rows to distinguish columns, but this must be conditionally gated by `isatty(STDOUT_FILENO)` to avoid breaking downstream text parsers.
**Action:** Always check `isatty()` before emitting ANSI escapes in CLI tool outputs.
