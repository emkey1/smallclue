# SmallCLUE (Small Command Line Unix Environment)

**SmallCLUE** is a lightweight, multicall binary that provides a suite of standard Unix-like utilities. It is designed specifically for constrained or sandboxed environments where standard GNU/BSD core utilities are unavailable, such as custom terminal emulators on iOS and iPadOS (e.g., PSCAL).

Functionally similar to BusyBox, `SmallCLUE` combines many common tools (like `ls`, `cp`, `grep`, `ssh`) into a single executable to reduce overhead and simplify integration.

## Overview

* **Multicall Architecture:** Invoking the binary as `smallclue ls` or symlinking `ls` to `smallclue` runs the `ls` applet.
* **Zero-Dependency Implementations:** Most core utilities are implemented directly in C within `src/core.c` to minimize external dependencies.
* **Third-Party Integration:** Includes wrappers for complex tools like **OpenSSH** and **Nextvi**.
* **iOS Specifics:** Features applets designed for iOS quirks, such as `pbcopy`/`pbpaste` for system clipboard access and specialized path virtualization hooks.

## Available Applets

`SmallCLUE` currently implements the following commands:

### File Management
* **ls**: List directory contents (supports colors, `-l`, `-h`, `-a`, `-t`).
* **cp**: Copy files and directories (recursive).
* **mv**: Move or rename files.
* **rm**: Remove files and directories.
* **mkdir** / **rmdir**: Create or remove directories.
* **touch**: Update file timestamps or create empty files.
* **ln**: Create links (symbolic and hard).
* **pwd**: Print working directory.
* **chmod**: Change file modes/permissions (supports octal and symbolic `u+x`).
* **du**: Estimate file space usage.
* **df**: Report file system disk space usage.
* **file**: Determine file type.
* **stat**: Display file status.
* **basename** / **dirname**: Parse path components.
* **find**: Search for files and directories.

### Text Processing & Filtering
* **cat**: Concatenate and print files.
* **echo**: Print arguments to standard output.
* **grep**: File pattern searcher (supports `-i`, `-v`, `-n`).
* **head** / **tail**: Output the first/last part of files (tail supports `-f` follow).
* **more** / **less**: File paging filters.
* **wc**: Word, line, character, and byte count.
* **sort**: Sort lines of text files.
* **uniq**: Report or omit repeated lines.
* **cut**: Remove sections from each line of files.
* **sed**: Stream editor (basic substitution support).
* **tr**: Translate or delete characters.
* **tee**: Read from standard input and write to standard output and files.
* **sum**: BSD/SysV checksum utility.

### Editors & Viewers
* **vi** / **nextvi**: A small, efficient vi-like text editor.
* **md**: A terminal-based Markdown viewer (renders tables, headers, and lists interactively).

### Networking
* **ssh**: OpenSSH client wrapper.
* **scp**: Secure copy (OpenSSH).
* **sftp**: Secure file transfer (OpenSSH).
* **ssh-keygen**: Generate authentication keys.
* **ssh-copy-id**: Install SSH public keys on a remote host.
* **ping**: TCP-based ping utility.
* **curl** / **wget**: Tools for transferring data with URL syntax (wrappers).
* **telnet**: Simple Telnet client.
* **nslookup** / **host**: DNS lookup utilities.
* **traceroute**: Trace the route packets take to a network host.
* **ipaddr**: Display network interface addresses.

### Shell & System
* **sh**: Launches the PSCAL shell frontend (`exsh`).
* **env**: Run a program in a modified environment.
* **ps**: Report a snapshot of current processes.
* **kill**: Send signals to processes.
* **uptime**: Tell how long the system has been running.
* **uname**: Print system information.
* **id**: Print user identity information.
* **date**: Print or set the system date and time.
* **cal**: Display a calendar.
* **clear** / **cls**: Clear the terminal screen.
* **sleep**: Delay for a specified amount of time.
* **tset**: Modify terminal settings.
* **stty**: Inspect or modify terminal settings.
* **tty**: Report tty.
* **resize**: Synchronize terminal row/column settings with the host.
* **script**: Record terminal output to a file.
* **watch**: Execute a program periodically, showing output fullscreen.
* **time**: Measure command runtime.
* **type**: Describe command names.
* **xargs**: Build and execute command lines from standard input.
* **pbcopy** / **pbpaste**: Clipboard helpers (on iOS/iPadOS these integrate with the system clipboard).
* **test** / **[**: Evaluate conditional expressions.
* **true** / **false**: Return success or failure status.
* **yes** / **no**: Repeatedly print strings (with success/failure exit semantics).
* **version**: Print smallclue/PSCAL version info.
* **vproc-test**: Run vproc/terminal diagnostics.

### iOS / iPadOS Only Applets
These applets are only registered on `PSCAL_TARGET_IOS` builds.

* **addt**: Open an additional shell tab.
* **tabadd** / **tadd**: Aliases for `addt`.
* **smallclue-help**: List available smallclue applets and command help.
* **dmesg**: Prints the PSCAL runtime session log.
* **top**: Show PSCAL virtual processes.
* **licenses**: View open source licenses included in the distribution.

## Usage

Can be run directly via the main entry point if built as a standalone executable:

```bash
./smallclue <command> [arguments...]
