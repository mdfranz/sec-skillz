---
name: journald-analyst
description: Analyzes journald JSON logs to identify system-level threats, suspicious process activity, and authentication anomalies. Use when a user provides journald logs in JSON format, asks for Linux system log analysis, or needs to hunt for privilege escalation and brute force attempts.
metadata:
  author: "Security Engineering Team"
  version: "1.0.0"
  tags: ["journald", "linux", "threat-hunting", "system-security"]
---

# Journald Analyst

## Instructions

### Step 1: Set Up the Environment First

Always initialize a local Python environment with `uv` before reading or transforming journald logs.

1. **Create the virtual environment**:
   ```bash
   uv venv
   source .venv/bin/activate
   ```
2. **Install the required libraries**:
   ```bash
   uv pip install polars orjson
   ```
3. **Create reusable scripts in the current working directory**. Do not rely on ad hoc shell one-liners for repeatable analysis.

### Step 2: Initial Discovery with `orjson`

Use `orjson` for fast line-by-line inspection and schema sampling before building larger `polars` workflows.

1. **Sample the data**: Create a script such as `sample_journal.py` to inspect a few records.
   ```python
   import orjson

   with open("journal.json", "rb") as f:
       for _ in range(5):
           line = f.readline()
           if not line:
               break
           print(orjson.dumps(orjson.loads(line), option=orjson.OPT_INDENT_2).decode())
   ```
2. **Count service identifiers**: Create a script such as `count_services.py` to see which services are logging.
   ```python
   import orjson
   from collections import Counter

   counts = Counter()
   with open("journal.json", "rb") as f:
       for line in f:
           event = orjson.loads(line)
           counts[event.get("SYSLOG_IDENTIFIER", "unknown")] += 1

   for service, count in counts.most_common():
       print(f"{count:7} {service}")
   ```
3. **Consult references**: Use `references/journald_format.md` for field definitions and `references/journald_security_research.md` for Polars-based hunting patterns.

### Step 3: Targeted Analysis with `polars`

1. **Check for existing Parquet files**: Before scanning `journal.json`, check for `.parquet` files. If they exist, use `polars.scan_parquet()`.
2. **Filter by Priority**: Prioritize critical logs by filtering `PRIORITY` values (e.g., "0" to "4").
3. **Use lazy scans for scale**: Prefer `polars.scan_ndjson()` for large log files.
4. **Persist JSON data as Parquet**: Materialize filtered datasets to Parquet early (e.g., `df.sink_parquet("auth_logs.parquet")`).
5. **Document findings**: Maintain an `analyst_log-YY-MM-DD_HH-MM.md` file for every session.

## Working Agreements
- **Python environment**: ALWAYS create a virtual environment with `uv venv` and install dependencies with `uv pip install polars orjson`.
- **Tool re-use**: ALWAYS search for and re-use existing scripts in the current directory.
- **Data-First retrieval**: ALWAYS check for and use existing `.parquet` files.
- **Script retention**: Always create and retain scripts such as `analyze_*.py` in the current project directory.
- **Python style**: Prefer `orjson` for streaming JSON parsing and `polars` for filtering and aggregations.

## Examples

### Example 1: Hunting for SSH Brute Force
**User says**: "Check for failed logins."
**Action**:
1. Filter to `SYSLOG_IDENTIFIER == "sshd"` and `message` containing "Failed password".
2. Group by `host` or IP (if extracted from message) and count.

### Example 2: Tracking Sudo Usage
**User says**: "Show me all sudo commands executed."
**Action**:
1. Filter to `SYSLOG_IDENTIFIER == "sudo"`.
2. Extract and display `timestamp`, `message`, and `host`.

## Troubleshooting

### Error: "Invalid JSON"
**Cause**: The log file might be truncated or contains non-JSON lines.
**Solution**: Use an `orjson` script with try-except blocks to skip malformed lines.

### Error: "Missing fields"
**Cause**: Not all journald entries contain the same fields (e.g., `SYSLOG_IDENTIFIER` might be missing).
**Solution**: Use `pl.col("field").fill_null("unknown")` or filter for existence.
