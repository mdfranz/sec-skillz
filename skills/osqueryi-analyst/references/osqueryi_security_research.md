# osqueryi Security Research Reference

## Threat Hunting Query Patterns

### Process Anomalies

**Processes with no binary on disk (common in fileless malware / process hollowing)**
```sql
SELECT pid, name, path, cmdline, uid
FROM processes
WHERE on_disk = 0
  AND path != '';
```

**Processes spawned from writable directories**
```sql
SELECT pid, name, path, cmdline, parent, start_time
FROM processes
WHERE path LIKE '/tmp/%'
   OR path LIKE '/var/tmp/%'
   OR path LIKE '/dev/shm/%'
   OR path LIKE '%/.%';
```

**Short-lived or recently started processes**
```sql
SELECT pid, name, path, cmdline, start_time,
       (strftime('%s', 'now') - start_time) AS seconds_running
FROM processes
ORDER BY start_time DESC
LIMIT 50;
```

**Processes with suspicious parent relationships (e.g., bash spawned by a web server)**
```sql
SELECT c.pid, c.name AS child, c.path AS child_path, c.cmdline,
       p.name AS parent, p.path AS parent_path
FROM processes c
JOIN processes p ON c.parent = p.pid
WHERE p.name IN ('nginx', 'apache2', 'httpd', 'python', 'node', 'java')
  AND c.name IN ('bash', 'sh', 'zsh', 'dash', 'perl', 'python', 'ruby', 'nc', 'ncat', 'socat');
```

---

### Network Anomalies

**Unexpected outbound connections on unusual ports**
```sql
SELECT s.pid, p.name, p.path, s.remote_address, s.remote_port, s.state
FROM process_open_sockets s
JOIN processes p ON s.pid = p.pid
WHERE s.remote_port NOT IN (80, 443, 53, 22, 25, 587, 993)
  AND s.remote_address NOT LIKE '10.%'
  AND s.remote_address NOT LIKE '192.168.%'
  AND s.remote_address NOT LIKE '172.%'
  AND s.remote_address != '127.0.0.1'
  AND s.remote_address != ''
ORDER BY s.remote_port;
```

**Processes listening on all interfaces (0.0.0.0 or ::)**
```sql
SELECT l.pid, p.name, p.path, l.port, l.protocol
FROM listening_ports l
JOIN processes p ON l.pid = p.pid
WHERE l.address IN ('0.0.0.0', '::')
ORDER BY l.port;
```


### Persistence Mechanisms

**All cron jobs across all users**
```sql
SELECT username, command, path, minute, hour, day_of_month, month, day_of_week
FROM crontab
ORDER BY username;
```

**Systemd units that are enabled but not standard**
```sql
SELECT id, description, fragment_path, active_state, sub_state
FROM systemd_units
WHERE active_state = 'active'
  AND fragment_path NOT LIKE '/lib/systemd/%'
  AND fragment_path NOT LIKE '/usr/lib/systemd/%'
  AND fragment_path != '';
```

**macOS LaunchDaemons and LaunchAgents in user directories**
```sql
SELECT name, path, program_arguments, run_at_load, username
FROM launchd
WHERE path LIKE '/Users/%'
   OR path LIKE '/tmp/%';
```

**WMI persistence (Windows)**
```sql
SELECT name, query, query_language FROM wmi_event_filters;
SELECT name, script_text FROM wmi_script_event_consumers;
```

---

### 4. Credential and Key Hunting

**SSH authorized keys (potential backdoors)**
```sql
SELECT username, authorized_keys.uid, key, key_file
FROM authorized_keys
JOIN users ON authorized_keys.uid = users.uid;
```

**Identify SUID/SGID binaries not in standard paths**
```sql
SELECT path, username, groupname, permissions, size
FROM suid_bin
WHERE path NOT LIKE '/usr/%'
  AND path NOT LIKE '/bin/%'
  AND path NOT LIKE '/sbin/%';
```

**Sudoers rules granting broad access**
```sql
SELECT source, header, rule_details
FROM sudoers
WHERE rule_details LIKE '%NOPASSWD%'
   OR rule_details LIKE '%ALL%';
```

---

### 5. File System Indicators

**Hash a suspicious file**
```sql
SELECT path, md5, sha256
FROM hash
WHERE path = '/tmp/suspicious_binary';
```

**Find recently modified files in system directories**
```sql
SELECT path, mtime, size, uid, gid, mode
FROM file
WHERE directory = '/etc'
  AND mtime > (strftime('%s', 'now') - 86400)
ORDER BY mtime DESC;
```

**Find files matching a glob pattern**
```sql
SELECT path, size, mtime, md5
FROM file
JOIN hash USING (path)
WHERE path LIKE '/home/%/.ssh/%'
  AND type = 'regular';
```

---

### 6. User and Session Activity

**Currently logged-in users**
```sql
SELECT liu.user, liu.tty, liu.host, liu.time, u.uid, u.gid
FROM logged_in_users liu
JOIN users u ON liu.user = u.username;
```

**Recent logins (last/wtmp)**
```sql
SELECT username, tty, host, time, type
FROM last
ORDER BY time DESC
LIMIT 50;
```

**Users with no password (shadow, Linux, requires root)**
```sql
SELECT username, password_status
FROM shadow
WHERE password_status = 'empty';
```

---

## Joining Across Tables

osqueryi supports standard SQL JOINs across virtual tables. Common join patterns:

```sql
-- Enrich sockets with process info
SELECT p.name, p.path, p.cmdline, s.remote_address, s.remote_port
FROM process_open_sockets s
JOIN processes p ON s.pid = p.pid;

-- Find files owned by a specific user
SELECT f.path, f.size, u.username
FROM file f
JOIN users u ON f.uid = u.uid
WHERE directory = '/home'
  AND u.username = 'suspicious_user';
```

## Exporting Results for Offline Analysis

```bash
# Export all running processes to JSON
osqueryi --json "SELECT * FROM processes" > processes.json

# Export to CSV
osqueryi --csv "SELECT pid, name, path, cmdline FROM processes" > processes.csv
```

Then ingest into DuckDB:
```python
import duckdb
con = duckdb.connect('analysis.db')
con.execute("CREATE TABLE processes AS SELECT * FROM read_json_auto('processes.json')")
```
