## 2026-04-05 - [isatty Guards for ANSI UI Escape Sequences]
**Learning:** ANSI escape codes printed to stdout for clearing the screen or managing interactive UI states (e.g. `\x1b[3J\x1b[H\x1b[2J` in `watch` or `\r\x1b[K` in the pager) can leak into redirected output, leading to log pollution.
**Action:** Always guard terminal-clearing escape sequences and line-erasing codes with `isatty(STDOUT_FILENO)` when outputting to `stdout`, just like we do for colors, to ensure clean output redirection.
