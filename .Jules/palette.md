## 2024-05-23 - Grep Color highlighting
**Learning:** Even CLI tools benefit immensely from visual hierarchy. `grep` without color is hard to scan. Users expect standard tools to behave in standard ways (like supporting `--color`).
**Action:** Always check if CLI output can be enhanced with color or formatting to improve readability, but respect `auto`/`never` settings.

## 2023-10-25 - Terminal Tabular Alignment with Colors
**Learning:** Applying ANSI bold formatting to individual column placeholders in `printf` when rendering tabular output throws off width calculations and breaks alignment.
**Action:** Always wrap the entire header format string in ANSI formatting tags (e.g. `\033[1m...\033[0m`) instead of wrapping individual column entries to ensure `printf` spacing works correctly.

## 2024-11-06 - Pager Status Line Visual Separation
**Learning:** Pager interfaces (like `less` or `more`) inherently mix UI elements (the status prompt) with arbitrary document text. Without visual styling, the prompt blends into the text, creating a confusing UX where users can't tell where the file ends and the tool begins.
**Action:** Always use inverse video (e.g., `\033[7m`) for terminal pager status lines or similar floating TUI elements to ensure clear visual separation from the content being viewed.
