---
name: osqueryi-analyst
description: Runs live osqueryi queries to investigate endpoint state, hunt for threats, and enumerate persistence mechanisms. Use when a user wants to interactively query the local system using osquery SQL, investigate a running host, or triage a potential compromise in real time.
metadata:
  author: "Security Engineering Team"
  version: "1.0.0"
  tags: ["osquery", "osqueryi", "endpoint", "threat-hunting", "live-response"]
---

# osqueryi Live Query Analysis

## Instructions

### Step 1: Launch and Configure
1.  **Start osqueryi**: Launch the interactive shell, optionally with flags for output format and verbosity.
    ```bash
    osqueryi --json
    # or for a specific extensions socket
    osqueryi --socket /var/osquery/osquery.em
    ```
2.  **Set Output Mode**: Inside the shell, set a format appropriate for the task.
    ```sql
    .mode json
    -- or: .mode csv, .mode line, .mode pretty (default)
    ```
3.  **Save Output**: Redirect query results to a file for downstream analysis.
    ```sql
    .output findings-YYYY-MM-DD.json
    SELECT * FROM processes WHERE on_disk = 0;
    .output stdout
    ```
4.  **Consult References**: For table schemas and security hunting queries, refer to `references/osquery_tables.md` and `references/osqueryi_security_research.md`.

### Step 2: Live Investigation
1.  **Orient**: Start with high-value tables to establish baseline system state.
2.  **Follow Leads**: Chain queries across `processes`, `sockets`, `users`, and `file` tables using `pid`, `uid`, or `path` as join keys.
3.  **Capture Evidence**: Save all queries and output to a timestamped `analyst_log-YY-MM-DD-HH-MM.md`.

## Working Agreements
- **Script Retention**: Always create and retain scripts (e.g., `analyze_*.py`) in the **current project directory**. **DO NOT** place scripts in `/tmp` or other directories outside the project, as they must be preserved for future reference and reproducibility.
- **Non-Destructive**: osqueryi is read-only — queries cannot modify system state.
- **No Analogies**: Keep technical explanations direct and professional.
- **Timestamping**: Always suffix output files with the current date-time.
- **Python Style**: When post-processing results, use `orjson`, `polars`, and `duckdb`. Use `uv` for environment management.


## Generating Scripts in Python
- Use `uv pip install osquery` if you need to interact programtically 

## Examples

### Example 1: Find Processes Running from Unusual Paths
**User says**: "Look for processes not running from standard system directories."
**Action**:
```sql
SELECT pid, name, path, cmdline, uid, parent
FROM processes
WHERE path NOT LIKE '/usr/%'
  AND path NOT LIKE '/bin/%'
  AND path NOT LIKE '/sbin/%'
  AND path NOT LIKE '/opt/%'
  AND path != ''
ORDER BY start_time DESC;
```

### Example 2: Identify New Persistence Mechanisms
**User says**: "What persistence is on this host?"
**Action**:
```sql
-- cron jobs
SELECT command, path, username FROM crontab;

-- startup items (macOS)
SELECT name, path, source FROM startup_items;

-- systemd units (Linux)
SELECT id, description, fragment_path, active_state
FROM systemd_units WHERE active_state = 'active';

-- scheduled tasks (Windows)
SELECT name, action, path, enabled FROM scheduled_tasks;
```

### Example 3: Detect Suspicious Network Listeners
**User says**: "What is listening on the network?"
**Action**:
```sql
SELECT l.pid, p.name, p.path, l.port, l.address, l.protocol
FROM listening_ports l
JOIN processes p ON l.pid = p.pid
WHERE l.address != '127.0.0.1'
  AND l.address != '::1'
ORDER BY l.port;
```

### Example 4: Correlate Open Sockets to Processes
**User says**: "Is anything connecting out to unexpected IPs?"
**Action**:
```sql
SELECT s.pid, p.name, p.path, s.remote_address, s.remote_port, s.state
FROM process_open_sockets s
JOIN processes p ON s.pid = p.pid
WHERE s.remote_address != ''
  AND s.remote_address NOT LIKE '127.%'
  AND s.remote_address != '::1'
ORDER BY s.remote_port;
```

## Troubleshooting

### Error: "osqueryi: command not found"
**Cause**: osquery is not installed or not in PATH.
**Solution**: Install via the official osquery package for the platform, or locate the binary at `/usr/local/bin/osqueryi` or `C:\Program Files\osquery\osqueryi.exe`.

### Error: "no such table"
**Cause**: The queried table is platform-specific (e.g., `launchd` is macOS-only, `registry` is Windows-only).
**Solution**: Run `.tables` to list all available tables on the current platform, or check `references/osquery_tables.md` for platform coverage.

### Error: "permission denied" or empty results on sensitive tables
**Cause**: osqueryi must run as root/Administrator for tables like `process_memory_map`, `socket_events`, or `user_ssh_keys`.
**Solution**: Re-launch with `sudo osqueryi` (Linux/macOS) or as Administrator (Windows).

### Error: "extension socket not found"
**Cause**: osqueryd is not running, so the extension socket is unavailable.
**Solution**: Run osqueryi standalone (without `--socket`) for most tables, or start osqueryd first if custom extensions are required.
