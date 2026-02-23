## 2024-05-23 - [SUID Privilege Escalation in sudo Applet]
**Vulnerability:** The 'sudo' applet in the multi-call binary allowed any user to execute commands as root without authentication if the binary was installed with SUID permissions (which is required for the 'passwd' applet).
**Learning:** When building multi-call binaries that may be installed SUID root, every applet must be audited for privilege escalation risks. 'sudo' without authentication is effectively a backdoor in such environments.
**Prevention:** Implement authentication checks (e.g., verifying root password via /etc/shadow) or restrict usage (e.g., allow only root) for privileged applets when running under SUID.
