---
name: osqueryd-analyst
description: Analyzes osqueryd differential result logs to investigate endpoint state changes, hunt for persistence, and correlate process and network activity. Use when a user provides osqueryd.results.log files, asks for host-based threat hunting, or needs to reconstruct current system state from scheduled query output.
metadata:
  author: "Security Engineering Team"
  version: "1.0.0"
  tags: ["osquery", "osqueryd", "endpoint", "threat-hunting", "live-response", "differential"]
---

# osqueryd Results Log Analyst

## Instructions

### Step 1: Set Up the Environment First

Always initialize a local Python environment with `uv` before reading or transforming osqueryd results logs.

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

1. **Sample the data**: Create a script such as `sample_results.py` to inspect a few records and understand the schema.
   ```python
   import orjson

   with open("osqueryd.results.log", "rb") as f:
       for _ in range(5):
           line = f.readline()
           if not line:
               break
           print(orjson.dumps(orjson.loads(line), option=orjson.OPT_INDENT_2).decode())
   ```
2. **Count query names and actions**: Create a script such as `count_queries.py` to see which scheduled queries produced data and the ratio of added vs. removed records.
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
3. **Consult references**: Use `references/osqueryd_results_format.md` for the record schema and `references/osqueryd_security_research.md` for `polars`-based hunting patterns.

### Step 3: Targeted Analysis with `polars`

1. **Check for existing Parquet files**: Before scanning `osqueryd.results.log`, check the current directory for `.parquet` files (e.g., `all_processes.parquet`, `net_processes.parquet`). If they exist, use `polars.scan_parquet()` for significantly faster analysis.
2. **Filter by `name` early**: Each scheduled query produces records of a specific shape under `columns`. Filter to a single query name before attempting to flatten nested fields.
3. **Flatten the `columns` struct**: All payload fields are nested under the `columns` key. Use `pl.col("columns").struct.field("field_name")` to extract individual fields.
4. **Account for the differential format**: Records carry an `action` field of either `"added"` or `"removed"`. For point-in-time state reconstruction, filter to `action == "added"`. For change detection, diff the added and removed sets.
5. **Use lazy scans for scale**: Prefer `polars.scan_ndjson()` so large log files are processed lazily.
6. **Persist JSON data as Parquet**: Materialize filtered and flattened datasets to Parquet early (e.g., `df.sink_parquet("all_processes.parquet")`) so repeated analysis does not require rescanning raw JSON.
7. **Document findings**: Maintain an `analyst_log-YY-MM-DD_HH-MM.md` file for every session.

## Working Agreements
- **Python environment**: ALWAYS create a virtual environment with `uv venv` and install dependencies with `uv pip install polars orjson`. Do NOT use `uv run`.
- **Tool re-use**: ALWAYS search for and re-use existing tools and scripts in the current directory before creating new ones.
- **Data-first retrieval**: ALWAYS check for and use existing `.parquet` files in the current directory before rescanning `osqueryd.results.log`.
- **Script retention**: Always create and retain scripts such as `analyze_*.py` in the current project directory. Do not place analysis scripts in `/tmp`.
- **Data persistence**: Persist intermediate or normalized datasets to Parquet with `polars` (e.g., `sink_parquet`) when the analysis will require repeated filtering, grouping, or joins.
- **Differential awareness**: NEVER treat all records as current state. Always consider whether a record is `"added"` or `"removed"` before drawing conclusions about system state.
- **Timestamping**: Rename throwaway notes or scratch markdown files with a `-YY-MM-DD_HH-MM.md` suffix.
- **Python style**: Prefer `orjson` for streaming JSON parsing and `polars` for filtering, aggregations, joins, and exports.
- **No Analogies**: Keep technical explanations direct and professional.

## Examples

### Example 1: Reconstruct Running Process State
**User says**: "What processes were running on this host?"
**Action**:
1. Filter `osqueryd.results.log` to `name == "all_processes"` and `action == "added"`.
2. Flatten `columns` fields: `pid`, `name`, `path`, `cmdline`, `uid`, `parent`.
3. Persist to `all_processes.parquet`.
4. Review processes running from non-standard paths (not `/usr/`, `/bin/`, `/sbin/`).

### Example 2: Find Processes with Active Network Connections
**User says**: "Which processes were making network connections?"
**Action**:
1. Filter to `name == "net_processes"` and `action == "added"`.
2. Flatten `columns` fields: `pid`, `name`, `path`, `local_address`, `remote_address`, `local_port`, `remote_port`.
3. Filter out loopback (`remote_address` not `127.0.0.1` or `::1`).
4. Join against `all_processes.parquet` on `pid` to add `cmdline` and `uid` context.

### Example 3: Detect Package Installation Events
**User says**: "Were any new packages installed during the observation window?"
**Action**:
1. Filter to `name == "installed_packages"`.
2. Separate `action == "added"` (installations) from `action == "removed"` (removals).
3. Extract `columns.name` and `columns.version`.
4. Report net-new packages: present in added, absent in removed.

### Example 4: Review Shell History for Suspicious Commands
**User says**: "What commands did users run?"
**Action**:
1. Filter to `name == "shell_history"` and `action == "added"`.
2. Flatten `columns.command`, `columns.uid`, `columns.time`.
3. Search for commands referencing `curl`, `wget`, `chmod +x`, `base64`, `/tmp`, or other high-risk patterns.
4. Correlate `uid` against `columns.username` from the `decorations` field.

## Troubleshooting

### Error: "Invalid JSON" or "Line Truncated"
**Cause**: The results log may have been cut off during collection or rotation.
**Solution**: Use an `orjson` script that catches decode errors per line, reports the line number, and continues parsing valid records.

### Error: "Polars schema mismatch" or missing nested fields under `columns`
**Cause**: Different scheduled queries expose different field shapes under `columns`. Mixing query names in the same scan produces struct conflicts.
**Solution**: Always filter to a single `name` value before selecting `columns` subfields. Do not attempt cross-query struct access on a mixed frame.

### Error: "State reconstruction looks incomplete"
**Cause**: The differential log only captures changes. If osqueryd was started mid-session, the initial `"added"` baseline record for a long-running process may not be present.
**Solution**: Treat the reconstructed state as a lower bound. Cross-reference with `system_info` records to determine the observation window, and note that processes predating the first log entry will be absent.

### Error: "Repeated scans of osqueryd.results.log are too slow"
**Cause**: Large NDJSON inputs are being re-read for every aggregation.
**Solution**: Persist each query name as its own Parquet file after the first scan and rerun iterative analysis against the Parquet files.

### Error: "Unexpected `action` values"
**Cause**: osqueryd uses `"added"` and `"removed"` for differential results, but also `"snapshot"` when a query is configured for full-state snapshots instead of differential mode.
**Solution**: Count distinct `action` values with `orjson` first. If `"snapshot"` records are present, treat them as full point-in-time state and do not attempt differential reconstruction for that query.
