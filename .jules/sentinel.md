## 2024-05-23 - [SUID Privilege Escalation in sudo Applet]
**Vulnerability:** The 'sudo' applet in the multi-call binary allowed any user to execute commands as root without authentication if the binary was installed with SUID permissions (which is required for the 'passwd' applet).
**Learning:** When building multi-call binaries that may be installed SUID root, every applet must be audited for privilege escalation risks. 'sudo' without authentication is effectively a backdoor in such environments.
**Prevention:** Implement authentication checks (e.g., verifying root password via /etc/shadow) or restrict usage (e.g., allow only root) for privileged applets when running under SUID.

## 2024-05-24 - [Environment Injection in sudo Applet]
**Vulnerability:** The 'sudo' applet failed to sanitize the environment (LD_PRELOAD, PATH, etc.) before executing commands as root, allowing local privilege escalation via shared library injection or PATH manipulation.
**Learning:** Authentication alone is insufficient for SUID binaries; the execution environment must also be scrubbed to prevent the child process from inheriting attacker-controlled variables that influence execution.
**Prevention:** Always unset dangerous environment variables (LD_*, IFS) and reset PATH to a safe default before executing commands in a privileged context.
