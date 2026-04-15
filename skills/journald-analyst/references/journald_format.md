# Journald JSON Log Format Reference

## Format Overview
- **Line-based JSON (JSONL)**: Each line is a complete JSON object representing one systemd journal entry.
- **Common Fields**: `timestamp`, `message`, `PRIORITY`, `SYSLOG_IDENTIFIER`, `_TRANSPORT`, `_BOOT_ID`.

## Key Fields for Analysis
- `PRIORITY`: Log level as a string (e.g., "5"). 0=emerg, 1=alert, 2=crit, 3=err, 4=warning, 5=notice, 6=info, 7=debug.
- `SYSLOG_IDENTIFIER`: The name of the process or unit that generated the log (e.g., `kernel`, `sshd`, `systemd`).
- `message`: The actual log message content.
- `_TRANSPORT`: How the entry was received by journald (e.g., `kernel`, `stdout`, `syslog`, `journal`).
- `timestamp`: RFC3339 formatted timestamp (e.g., `2026-04-11T23:15:28.055638Z`).
- `__REALTIME_TIMESTAMP`: Microseconds since epoch.
- `_BOOT_ID`: Unique ID for the current boot session.
- `_MACHINE_ID`: Unique ID for the local machine.
- `host`: Hostname where the log was generated.

## High-Signal Identifiers for Security
- `sshd`: SSH login attempts, successes, and failures.
- `sudo`: Execution of commands with elevated privileges.
- `systemd-logind`: Session creation and deletion.
- `kernel`: Hardware events, OOM kills, and firewall (iptables/nftables) logs.
- `audit`: If `auditd` is not running, the kernel may send audit events (e.g., syscalls, file access) to journald.

## Filtering Noise
- **Exclude Debug/Info**: Filter `PRIORITY > 5` if looking for errors or critical events.
- **Service Filtering**: Use `SYSLOG_IDENTIFIER` to focus on specific services known for security relevance.
