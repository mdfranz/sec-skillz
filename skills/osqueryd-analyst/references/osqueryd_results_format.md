# osqueryd Results Log Format Reference

## Format Overview
- **Line-based JSON (NDJSON)**: Each line is a complete JSON object representing one differential event.
- **Differential mode**: Records track state changes — each query fires on a schedule and reports what was `"added"` or `"removed"` since the previous execution.
- **Snapshot mode**: Some queries may be configured to emit `"snapshot"` records that represent full point-in-time state rather than a delta. These require different handling.

## Envelope Fields (present on every record)

| Field | Type | Description |
|---|---|---|
| `name` | string | Scheduled query name (e.g., `all_processes`, `net_processes`) |
| `action` | string | `"added"`, `"removed"`, or `"snapshot"` |
| `hostIdentifier` | string | Hostname of the reporting host |
| `calendarTime` | string | Human-readable UTC timestamp (e.g., `"Mon Apr 13 12:00:00 2026 UTC"`) |
| `unixTime` | integer | Unix epoch seconds of the query execution |
| `epoch` | integer | Monotonic counter epoch — increments across osqueryd restarts |
| `counter` | integer | Per-query execution counter — increments each time the query fires |
| `numerics` | boolean | If `true`, all column values were coerced to strings representing numerics |
| `decorations` | object | Host metadata attached to every record (see below) |
| `columns` | object | The actual query result row — fields vary by `name` (see per-query schemas below) |

## Decorations Object
Applied uniformly by the osqueryd configuration. Common fields:

| Field | Description |
|---|---|
| `host_uuid` | Stable hardware UUID for the host |
| `username` | The OS user under which osqueryd is running |

## Per-Query `columns` Schemas

### `all_processes`
Full process table snapshot. High cardinality — expect tens of thousands of records per host.

| Field | Description |
|---|---|
| `pid` | Process ID |
| `name` | Short process name |
| `path` | Full path to the executable on disk |
| `cmdline` | Full command line including arguments |
| `uid` | Effective user ID |
| `gid` | Effective group ID |
| `parent` | Parent process ID |
| `resident_size` | Resident memory in bytes |
| `user_time` | CPU time in user space (ms) |
| `system_time` | CPU time in kernel space (ms) |
| `disk_bytes_read` | Bytes read from disk |
| `disk_bytes_written` | Bytes written to disk |

### `active_processes`
A focused subset — typically processes with network listeners or specific metadata. Includes the same core fields as `all_processes` plus:

| Field | Description |
|---|---|
| `address` | Bound or connected address |
| `port` | Associated network port |

### `net_processes`
Network connection state joined with process identity.

| Field | Description |
|---|---|
| `pid` | Process ID |
| `name` | Process name |
| `path` | Executable path |
| `local_address` | Local socket address |
| `remote_address` | Remote peer address |
| `local_port` | Local port number |
| `remote_port` | Remote port number |

### `shell_history`
Shell command history records.

| Field | Description |
|---|---|
| `uid` | User ID that ran the command |
| `command` | Full command string |
| `time` | Unix timestamp of the command (where available) |

### `installed_packages`
Software package inventory.

| Field | Description |
|---|---|
| `name` | Package name |
| `version` | Installed version string |

### `system_info`
Host hardware and identity. Very low cardinality — typically 1–2 records per collection window.

| Field | Description |
|---|---|
| `hostname` | System hostname |
| `cpu_brand` | CPU model string |
| `physical_memory` | Total physical RAM in bytes |

## Key Interpretation Notes

- **Differential balance**: A roughly equal count of `"added"` and `"removed"` records across the full log indicates continuous steady-state monitoring. A large excess of `"added"` over `"removed"` may indicate a fresh osqueryd start or a host with rapidly changing state.
- **`pid` reuse**: PIDs are recycled by the OS. In a long differential log, the same `pid` may appear as `"removed"` for one process and `"added"` for a different process. Join on `pid` + `unixTime` or `epoch`/`counter` to avoid false correlation.
- **`columns` values are always strings**: osqueryd serializes all column values as JSON strings, even numeric fields. Cast to integer or float explicitly in `polars` when needed for arithmetic.
