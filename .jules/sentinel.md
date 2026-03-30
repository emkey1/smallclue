## 2024-05-23 - [SUID Privilege Escalation in sudo Applet]
**Vulnerability:** The 'sudo' applet in the multi-call binary allowed any user to execute commands as root without authentication if the binary was installed with SUID permissions (which is required for the 'passwd' applet).
**Learning:** When building multi-call binaries that may be installed SUID root, every applet must be audited for privilege escalation risks. 'sudo' without authentication is effectively a backdoor in such environments.
**Prevention:** Implement authentication checks (e.g., verifying root password via /etc/shadow) or restrict usage (e.g., allow only root) for privileged applets when running under SUID.

## 2024-05-24 - [Environment Injection in sudo Applet]
**Vulnerability:** The 'sudo' applet failed to sanitize the environment (LD_PRELOAD, PATH, etc.) before executing commands as root, allowing local privilege escalation via shared library injection or PATH manipulation.
**Learning:** Authentication alone is insufficient for SUID binaries; the execution environment must also be scrubbed to prevent the child process from inheriting attacker-controlled variables that influence execution.
**Prevention:** Always unset dangerous environment variables (LD_*, IFS) and reset PATH to a safe default before executing commands in a privileged context.
## 2024-05-24 - Secure Password Wiping in Authentication Utilities
**Vulnerability:** Passwords used in authentication (`sudo` and `passwd` applets) were left in memory indefinitely after use, allowing potential exposure via memory scraping or core dumps.
**Learning:** Even well-intentioned code that securely hashes passwords (using `crypt`) can leave plaintext secrets in dynamically allocated strings or static buffers. Dead store elimination by compilers often optimizes away standard `memset` calls intended to zero out these buffers before freeing them.
**Prevention:** Always use a secure memory zeroing function (like `smallclueSecureMemzero` utilizing `volatile` pointers) to guarantee that sensitive data is scrubbed from memory immediately after its lifecycle ends.

## 2024-05-24 - [Incomplete Password Wiping in Static Buffers]
**Vulnerability:** When wiping passwords in `sudo` and `passwd` applets, the caller only zeroed the buffer up to `strlen(pass)`. Because the `smallclueGetPass` function used a shared static buffer, shorter passwords entered subsequently did not overwrite the remnants of previous longer passwords in the buffer, leading to potential data leakage.
**Learning:** Zeroing a dynamically-sized subset (like `strlen`) of a fixed-size static buffer leaves the rest of the buffer intact, which may contain sensitive data from previous calls. Relying solely on the caller to manage static buffer clearing is error-prone.
**Prevention:** Always securely zero out the entire static buffer (`sizeof(buf)`) at the beginning of the function and on failure before returning, instead of relying on the caller to zero the buffer based on the string length.

## 2024-11-20 - Global Static Password Buffer Memory Disclosure
**Vulnerability:** The `smallclueGetPass` function in `src/core.c` returned a pointer directly to its internal `static char buf[128]` after reading a password. Callers (`sudo` and `passwd` applets) were clearing it by using `smallclueSecureMemzero(pass, strlen(pass))`. This left the unused portion of the 128-byte buffer uncleared. If a user entered a long password followed by a short password, the trailing characters of the long password remained in the static buffer and were accessible in memory.
**Learning:** Returning pointers to static buffers for sensitive data delegates the responsibility of clearing the buffer to the caller, who often does not know the true allocated size. `strlen` only zeroes the initialized characters and fails to overwrite residual sensitive data past the null terminator in fixed-size buffers.
**Prevention:** Sensitive input routines should either clear the full static buffer size directly before returning a heap-allocated copy (`strdup`) so the caller can safely zero and free the string length, or the API should require the caller to provide a sized buffer and explicitly document the clearing requirement.

## 2024-11-20 - [Password Stdin Buffer Leak in smallclueGetPass]
**Vulnerability:** The `smallclueGetPass` function read passwords using a fixed-size buffer (`fgets` up to 127 bytes). If a user entered a password longer than the buffer, the remaining characters were left in the standard input buffer. These residual characters would bleed into subsequent input reads (like a password confirmation prompt) or, worse, be executed as commands by the shell if the program terminated immediately.
**Learning:** Fixed-size buffers reading from standard input must handle overflows by consuming the rest of the stream up to the delimiter (newline) to prevent subsequent reads from consuming the truncated fragments as legitimate input.
**Prevention:** When using `fgets` or similar bounded-read functions for sensitive input, always verify if the delimiter (e.g., `\n`) is present in the buffer. If it is missing and the buffer is full, actively consume and discard the remaining characters from `stdin` until the delimiter or `EOF` is found.
## 2024-05-23 - [HIGH] Environment variable injection in su command
**Vulnerability:** The `su` command (`smallclueSuCommand` in `src/core.c`) did not sanitize environment variables (such as `LD_PRELOAD`, `LD_LIBRARY_PATH`, `LD_DEBUG`, `IFS`) before spawning the target shell, unlike the `sudo` command.
**Learning:** This oversight in a setuid-like applet could allow privilege escalation by enabling a malicious user to inject code into the target user's shell session via environment variables. The architecture missed applying the sanitization consistently across all privilege-boundary-crossing applets.
**Prevention:** Always sanitize the environment (`unsetenv`) for critical variables before calling `execl` or `execv` in applets that transition user context (e.g., `su`, `sudo`, `login`).

## 2024-05-18 - PATH injection in su applet
**Vulnerability:** The 'su' applet unsets dangerous environment variables but fails to reset 'PATH' to a safe default, allowing privilege escalation if the target user's shell relies on PATH resolution.
**Learning:** When transitioning user context, sanitizing LD_PRELOAD is insufficient if PATH is left intact, as executable resolution can still be hijacked to run malicious binaries as root.
**Prevention:** Always reset PATH to a safe, trusted default (e.g., /usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin) along with other environment sanitization when switching users.
