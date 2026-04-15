# Journald Security Analysis Guide

## Threat Hunting Patterns

### 1. SSH Brute Force Detection
Focus on `SYSLOG_IDENTIFIER == "sshd"`. Look for high frequency of "Failed password" or "Connection closed by authenticating user".

```python
import polars as pl

df = pl.scan_ndjson("journal.json")
ssh_failures = (
    df.filter(pl.col("SYSLOG_IDENTIFIER") == "sshd")
    .filter(pl.col("message").str.contains("Failed password"))
    .select(["timestamp", "message", "host"])
    .collect()
)
```

### 2. Privilege Escalation (Sudo)
Monitor `SYSLOG_IDENTIFIER == "sudo"` for unusual commands or unauthorized attempts.

```python
sudo_usage = (
    df.filter(pl.col("SYSLOG_IDENTIFIER") == "sudo")
    .select(["timestamp", "message", "host"])
    .collect()
)
```

### 3. Kernel Anomalies
Analyze `SYSLOG_IDENTIFIER == "kernel"`. Look for Segfaults, OOM kills, or USB device insertions.

```python
kernel_events = (
    df.filter(pl.col("SYSLOG_IDENTIFIER") == "kernel")
    .filter(pl.col("message").str.contains("segfault|Out of memory|usb"))
    .collect()
)
```

### 4. Persistence Mechanisms
Look for `systemd` logs related to new service creation or modifications.

```python
systemd_changes = (
    df.filter(pl.col("SYSLOG_IDENTIFIER") == "systemd")
    .filter(pl.col("message").str.contains("Reloading|Starting|Started"))
    .collect()
)
```

## Useful Polars Snippets

### Aggregate by Service and Priority
```python
stats = (
    df.group_by(["SYSLOG_IDENTIFIER", "PRIORITY"])
    .count()
    .sort("count", descending=True)
    .collect()
)
```

### Time Series Analysis
Group by hour to find spikes in activity.
```python
timeline = (
    df.with_columns(pl.col("timestamp").str.to_datetime())
    .group_by_dynamic("timestamp", every="1h")
    .count()
    .collect()
)
```
