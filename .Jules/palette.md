## 2024-05-23 - Grep Color highlighting
**Learning:** Even CLI tools benefit immensely from visual hierarchy. `grep` without color is hard to scan. Users expect standard tools to behave in standard ways (like supporting `--color`).
**Action:** Always check if CLI output can be enhanced with color or formatting to improve readability, but respect `auto`/`never` settings.

## 2023-10-25 - Terminal Tabular Alignment with Colors
**Learning:** Applying ANSI bold formatting to individual column placeholders in `printf` when rendering tabular output throws off width calculations and breaks alignment.
**Action:** Always wrap the entire header format string in ANSI formatting tags (e.g. `\033[1m...\033[0m`) instead of wrapping individual column entries to ensure `printf` spacing works correctly.

## 2024-11-06 - Pager Status Line Visual Separation
**Learning:** Pager interfaces (like `less` or `more`) inherently mix UI elements (the status prompt) with arbitrary document text. Without visual styling, the prompt blends into the text, creating a confusing UX where users can't tell where the file ends and the tool begins.
**Action:** Always use inverse video (e.g., `\033[7m`) for terminal pager status lines or similar floating TUI elements to ensure clear visual separation from the content being viewed.

## 2024-11-20 - Fullscreen Applet Visual Hierarchy
**Learning:** Fullscreen applets like `watch` lack visual separation between their status/header lines and the arbitrary command output they continuously render, making them harder to scan or distinguish from normal shell output.
**Action:** Always wrap the header/status lines of fullscreen utilities in inverse video (`\033[7m`) to establish a clear visual hierarchy and separate the tool's UI from the command payload it displays.

## 2025-02-12 - Interactive Prompts ANSI Guarding
**Learning:** Interactive terminal prompts that print to `stderr` (like confirmation dialogs) often remember to check `isatty(STDIN_FILENO)` before prompting, but forget to independently check `isatty(STDERR_FILENO)` before emitting ANSI color codes. This results in log files filled with raw escape sequences when users redirect `stderr` but leave `stdin` interactive.
**Action:** Always guard ANSI escape sequences printed to `stderr` with an `isatty(STDERR_FILENO)` check, even if the prompt logic itself is already guarded by an `isatty(STDIN_FILENO)` check.

## 2025-05-12 - Sequential Multi-file Output Headers
**Learning:** Utilities that sequentially process and print the contents of multiple files (such as `head` and `tail`) lack clear visual separation without explicit headers. Users expect the standard `==> filename <==` delimiter to differentiate outputs from separate files.
**Action:** Always print clear separator headers (and pre-spacing for subsequent files) when sequentially concatenating or summarizing multiple distinct files to standard output.

## 2025-05-12 - Sequential Multi-file Output Headers
**Learning:** Utilities that sequentially process and print the contents of multiple files (such as `head` and `tail`) lack clear visual separation without explicit headers. Users expect the standard `==> filename <==` delimiter to differentiate outputs from separate files.
**Action:** Always print clear separator headers (and pre-spacing for subsequent files) when sequentially concatenating or summarizing multiple distinct files to standard output. Applied this to `md`.
