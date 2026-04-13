# Practical Analysis of osqueryd Results Logs with `orjson` and `polars`

## Executive Summary

osqueryd results logs are newline-delimited JSON records produced by scheduled queries running on a host. Each record is a differential event — either `"added"` (state appeared) or `"removed"` (state disappeared) — with the payload nested under a `columns` object.

The most reliable workflow for local investigations is:

1. Use `uv` to create a dedicated environment.
2. Use `orjson` to sample the envelope schema and understand which query names are present.
3. Use `polars` lazy scans to filter by `name`, flatten `columns`, and split by `action`.
4. Persist per-query Parquet files before iterative analysis.

## 1. Environment Setup

```bash
uv venv
source .venv/bin/activate
uv pip install polars orjson
```

Keep analysis code in reusable scripts in the working directory so the workflow can be rerun against later log drops.

## 2. Schema Discovery

### 2.1 Sample Raw Records

```python
import orjson

with open("osqueryd.results.log", "rb") as f:
    for line_number, line in enumerate(f, start=1):
        try:
            record = orjson.loads(line)
        except orjson.JSONDecodeError:
            print(f"bad json on line {line_number}")
            continue
        print(orjson.dumps(record, option=orjson.OPT_INDENT_2).decode())
        if line_number >= 3:
            break
```

### 2.2 Count Query Names and Actions

```python
import orjson
from collections import Counter

name_counts = Counter()
action_counts = Counter()

with open("osqueryd.results.log", "rb") as f:
    for line in f:
        record = orjson.loads(line)
        name_counts[record.get("name", "unknown")] += 1
        action_counts[record.get("action", "unknown")] += 1

print("--- Query names ---")
for name, count in name_counts.most_common():
    print(f"{count:7}  {name}")

print("\n--- Actions ---")
for action, count in action_counts.most_common():
    print(f"{count:7}  {action}")
```

## 3. Building Lazy `polars` Workflows: Parquet-First

Always check the current directory for `.parquet` files before scanning the results log.

```python
import polars as pl
from pathlib import Path

parquet_path = Path("all_processes.parquet")

if parquet_path.exists():
    proc_df = pl.scan_parquet(parquet_path)
else:
    proc_df = (
        pl.scan_ndjson("osqueryd.results.log")
        .filter(
            (pl.col("name") == "all_processes") &
            (pl.col("action") == "added")
        )
        .select(
            pl.col("unixTime").alias("ts"),
            pl.col("hostIdentifier").alias("host"),
            pl.col("columns").struct.field("pid").cast(pl.Int64).alias("pid"),
            pl.col("columns").struct.field("name").alias("proc_name"),
            pl.col("columns").struct.field("path").alias("path"),
            pl.col("columns").struct.field("cmdline").alias("cmdline"),
            pl.col("columns").struct.field("uid").cast(pl.Int64).alias("uid"),
            pl.col("columns").struct.field("parent").cast(pl.Int64).alias("parent_pid"),
        )
    )
    proc_df.sink_parquet(parquet_path)
```

## 4. Process Analysis

### 4.1 Processes Running from Non-Standard Paths

```python
import polars as pl

suspicious_procs = (
    pl.scan_parquet("all_processes.parquet")
    .filter(
        ~pl.col("path").str.starts_with("/usr/")
        & ~pl.col("path").str.starts_with("/bin/")
        & ~pl.col("path").str.starts_with("/sbin/")
        & ~pl.col("path").str.starts_with("/opt/")
        & ~pl.col("path").str.starts_with("/lib")
        & (pl.col("path") != "")
    )
    .select("pid", "proc_name", "path", "cmdline", "uid", "parent_pid")
    .sort("uid")
)

print(suspicious_procs.collect())
```

### 4.2 Processes Running as Root (uid == 0) with Suspicious Paths

```python
import polars as pl

root_procs = (
    pl.scan_parquet("all_processes.parquet")
    .filter(
        (pl.col("uid") == 0) &
        ~pl.col("path").str.starts_with("/usr/") &
        ~pl.col("path").str.starts_with("/bin/") &
        ~pl.col("path").str.starts_with("/sbin/") &
        ~pl.col("path").str.starts_with("/lib") &
        (pl.col("path") != "")
    )
    .select("pid", "proc_name", "path", "cmdline", "parent_pid")
)

print(root_procs.collect())
```

### 4.3 Detect Short-Lived Processes (appeared and then disappeared)

```python
import polars as pl

added = (
    pl.scan_ndjson("osqueryd.results.log")
    .filter(
        (pl.col("name") == "all_processes") &
        (pl.col("action") == "added")
    )
    .select(
        pl.col("columns").struct.field("pid").alias("pid"),
        pl.col("columns").struct.field("name").alias("proc_name"),
        pl.col("columns").struct.field("path").alias("path"),
        pl.col("columns").struct.field("cmdline").alias("cmdline"),
        pl.col("unixTime").alias("add_time"),
    )
    .collect()
)

removed = (
    pl.scan_ndjson("osqueryd.results.log")
    .filter(
        (pl.col("name") == "all_processes") &
        (pl.col("action") == "removed")
    )
    .select(
        pl.col("columns").struct.field("pid").alias("pid"),
        pl.col("unixTime").alias("remove_time"),
    )
    .collect()
)

# Join on pid to find processes that both appeared and disappeared
short_lived = (
    added.join(removed, on="pid", how="inner")
    .with_columns(
        (pl.col("remove_time") - pl.col("add_time")).alias("lifetime_s")
    )
    .filter(pl.col("lifetime_s") < 30)
    .sort("lifetime_s")
)

print(short_lived)
```

Short-lived processes warrant review — particularly those running from `/tmp`, home directories, or with `base64`, `curl`, `wget`, or interpreter invocations in the `cmdline`.

## 5. Network Connection Analysis

### 5.1 Build a Net-Processes Parquet

```python
import polars as pl
from pathlib import Path

parquet_path = Path("net_processes.parquet")

if not parquet_path.exists():
    net_df = (
        pl.scan_ndjson("osqueryd.results.log")
        .filter(
            (pl.col("name") == "net_processes") &
            (pl.col("action") == "added")
        )
        .select(
            pl.col("unixTime").alias("ts"),
            pl.col("hostIdentifier").alias("host"),
            pl.col("columns").struct.field("pid").cast(pl.Int64).alias("pid"),
            pl.col("columns").struct.field("name").alias("proc_name"),
            pl.col("columns").struct.field("path").alias("path"),
            pl.col("columns").struct.field("local_address").alias("local_address"),
            pl.col("columns").struct.field("remote_address").alias("remote_address"),
            pl.col("columns").struct.field("local_port").cast(pl.Int32).alias("local_port"),
            pl.col("columns").struct.field("remote_port").cast(pl.Int32).alias("remote_port"),
        )
    )
    net_df.sink_parquet(parquet_path)
```

### 5.2 External Connections by Process

```python
import polars as pl

external = (
    pl.scan_parquet("net_processes.parquet")
    .filter(
        ~pl.col("remote_address").str.starts_with("127.")
        & ~pl.col("remote_address").str.starts_with("10.")
        & ~pl.col("remote_address").str.starts_with("192.168.")
        & ~pl.col("remote_address").str.starts_with("172.")
        & (pl.col("remote_address") != "")
        & (pl.col("remote_address") != "::")
        & (pl.col("remote_address") != "::1")
    )
    .group_by(["proc_name", "path", "remote_address", "remote_port"])
    .agg(
        pl.col("pid").n_unique().alias("distinct_pids"),
        pl.len().alias("connection_events"),
    )
    .sort("connection_events", descending=True)
)

print(external.collect())
```

### 5.3 Correlate Network Connections with Full Process Metadata

```python
import polars as pl

net = pl.scan_parquet("net_processes.parquet")
procs = pl.scan_parquet("all_processes.parquet")

enriched = (
    net.join(
        procs.select("pid", "cmdline", "uid", "parent_pid"),
        on="pid",
        how="left",
    )
    .filter(
        ~pl.col("remote_address").str.starts_with("127.")
        & (pl.col("remote_address") != "")
    )
    .select(
        "proc_name", "pid", "cmdline", "uid",
        "remote_address", "remote_port",
        "local_address", "local_port",
    )
)

print(enriched.collect())
```

## 6. Shell History Analysis

### 6.1 Extract All Commands

```python
import polars as pl
from pathlib import Path

parquet_path = Path("shell_history.parquet")

if not parquet_path.exists():
    hist_df = (
        pl.scan_ndjson("osqueryd.results.log")
        .filter(
            (pl.col("name") == "shell_history") &
            (pl.col("action") == "added")
        )
        .select(
            pl.col("unixTime").alias("ts"),
            pl.col("hostIdentifier").alias("host"),
            pl.col("columns").struct.field("uid").cast(pl.Int64).alias("uid"),
            pl.col("columns").struct.field("command").alias("command"),
            pl.col("columns").struct.field("time").alias("cmd_time"),
        )
    )
    hist_df.sink_parquet(parquet_path)
```

### 6.2 Hunt for High-Risk Command Patterns

```python
import polars as pl

HIGH_RISK_PATTERNS = [
    r"(?i)(curl|wget).*(http)",
    r"(?i)chmod\s+\+x",
    r"(?i)base64\s+(-d|--decode)",
    r"(?i)/tmp/[^\s]+",
    r"(?i)(python|python3|perl|ruby|php)\s+-[ce]",
    r"(?i)(nc|ncat|netcat)\s+.*-[el]",
    r"(?i)(adduser|useradd|passwd)\s+",
    r"(?i)(crontab|at\s+-f)",
]

hist = pl.scan_parquet("shell_history.parquet")

for pattern in HIGH_RISK_PATTERNS:
    matches = (
        hist
        .filter(pl.col("command").str.contains(pattern))
        .select("uid", "cmd_time", "command")
        .collect()
    )
    if len(matches) > 0:
        print(f"\n=== Pattern: {pattern} ===")
        print(matches)
```

## 7. Package Change Tracking

### 7.1 Net-New Packages (Installed, Not Subsequently Removed)

```python
import polars as pl

added_pkgs = (
    pl.scan_ndjson("osqueryd.results.log")
    .filter(
        (pl.col("name") == "installed_packages") &
        (pl.col("action") == "added")
    )
    .select(
        pl.col("columns").struct.field("name").alias("pkg_name"),
        pl.col("columns").struct.field("version").alias("version"),
        pl.col("unixTime").alias("ts"),
    )
    .collect()
)

removed_pkgs = (
    pl.scan_ndjson("osqueryd.results.log")
    .filter(
        (pl.col("name") == "installed_packages") &
        (pl.col("action") == "removed")
    )
    .select(
        pl.col("columns").struct.field("name").alias("pkg_name"),
        pl.col("columns").struct.field("version").alias("version"),
    )
    .collect()
)

# Packages that were added but not in the removed set
net_new = added_pkgs.join(
    removed_pkgs.with_columns(pl.lit(True).alias("was_removed")),
    on=["pkg_name", "version"],
    how="left",
).filter(pl.col("was_removed").is_null())

print(net_new.sort("ts"))
```

## 8. Operational Guidance

- Filter by `name` before accessing `columns` subfields — different queries expose different struct shapes.
- Keep transformations lazy until the final `collect()`.
- Persist each query name as its own Parquet file as soon as the working schema is clear.
- Use Parquet outputs as the default source for repeated filtering, grouping, and joins.
- Never treat `pid` alone as a stable process identity across the full log — PIDs are recycled by the OS.
- Save each investigative script so later analysts can rerun the same logic.
- Record assumptions, thresholds, and false-positive notes in a timestamped analyst log.

## 9. Troubleshooting

### Invalid JSON lines
Use `orjson` with explicit error handling and line numbers to isolate malformed records.

### Missing nested fields under `columns`
Different query names expose different structs. Always filter to a single `name` value before selecting `columns` subfields.

### `columns` values are unexpected types
osqueryd serializes all column values as strings. Cast explicitly: `pl.col("columns").struct.field("pid").cast(pl.Int64)`.

### `"snapshot"` records mixed with differential records
Count distinct `action` values first. If `"snapshot"` is present for a given query name, treat those records as independent point-in-time state snapshots and exclude them from added/removed diff logic.

### Repeated scans of the raw log are slow
Persist each filtered query name to its own Parquet file and rerun iterative analysis against the Parquet files.
