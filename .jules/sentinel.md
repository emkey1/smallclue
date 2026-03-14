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
