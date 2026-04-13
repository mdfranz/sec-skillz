---
name: suricata-analyst
description: Analyzes Suricata EVE JSON logs to identify network threats, suspicious egress, and protocol anomalies. Use when a user provides eve.json logs, asks for network traffic analysis, or needs to hunt for C2 beaconing and data exfiltration.
metadata:
  author: "Security Engineering Team"
  version: "1.2.0"
  tags: ["suricata", "nsm", "threat-hunting", "network-security"]
---

# Suricata (EVE) Analyst

## Instructions

### Step 1: Set Up the Environment First

Always initialize a local Python environment with `uv` before reading or transforming EVE logs.

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

1. **Sample the data**: Create a script such as `sample_eve.py` to inspect a few records without loading the full file.
   ```python
   import orjson

   with open("eve.json", "rb") as f:
       for _ in range(5):
           line = f.readline()
           if not line:
               break
           print(orjson.dumps(orjson.loads(line), option=orjson.OPT_INDENT_2).decode())
   ```
2. **Count event types**: Create a script such as `count_events.py` to see which protocol records are available.
   ```python
   import orjson
   from collections import Counter

   counts = Counter()
   with open("eve.json", "rb") as f:
       for line in f:
           event = orjson.loads(line)
           counts[event.get("event_type", "unknown")] += 1

   for event_type, count in counts.most_common():
       print(f"{count:7} {event_type}")
   ```
3. **Consult references**: Use `references/eve_format.md` for common fields and `references/suricata_eve_analysis.md` for Polars-based hunting patterns.

### Step 3: Targeted Analysis with `polars`

1. **Check for existing Parquet files**: Before scanning `eve.json`, check the current directory for `.parquet` files (e.g., `dns.parquet`, `flow.parquet`). If they exist, use `polars.scan_parquet()` for significantly faster analysis.
2. **Filter noise early**: If starting from `eve.json`, exclude `stats` events and prioritize `alert`, `dns`, `tls`, `http`, `flow`, and `quic`.
3. **Use lazy scans for scale**: Prefer `polars.scan_ndjson()` so large `eve.json` files are processed lazily instead of loaded eagerly.
4. **Persist JSON data as Parquet**: Materialize filtered or flattened datasets to Parquet early (e.g., `df.sink_parquet("dns.parquet")`) so repeated analysis does not require rescanning raw JSON.
5. **Flatten only what you need**: Select the few nested fields relevant to the hypothesis being tested, then collect just that subset.
6. **Document findings**: Maintain an `analyst_log-YY-MM-DD_HH-MM.md` file for every session.

## Working Agreements
- **Python environment**: ALWAYS create a virtual environment with `uv venv` and install dependencies with `uv pip install polars orjson`. Do NOT use `uv run`.
- **Tool re-use**: ALWAYS search for and re-use existing tools and scripts in the current directory before creating new ones.
- **Data-First retrieval**: ALWAYS check for and use existing `.parquet` files in the current directory before rescanning `eve.json`.
- **Script retention**: Always create and retain scripts such as `analyze_*.py` in the current project directory. Do not place analysis scripts in `/tmp`.
- **Data persistence**: Persist intermediate or normalized EVE datasets to Parquet with `polars` (e.g., `sink_parquet`) when the analysis will require repeated filtering, grouping, or joins.
- **Timestamping**: Rename throwaway notes or scratch markdown files with a `-YY-MM-DD_HH-MM.md` suffix.
- **Python style**: Prefer `orjson` for streaming JSON parsing and `polars` for filtering, aggregations, joins, and exports.

## Examples

### Example 1: Hunting for Rare SNIs
**User says**: "Check for suspicious TLS connections."
**Action**:
1. Filter to `event_type == "tls"` with `polars.scan_ndjson()`.
2. Extract `tls.sni` and count occurrences.
3. Highlight rare or unique SNIs and correlate them with `src_ip`, `dest_ip`, and JA3 values.

### Example 2: Volume-based Exfiltration
**User says**: "Find any hosts sending large amounts of data to the internet."
**Action**:
1. Filter to `event_type == "flow"`.
2. Persist the filtered flow dataset to Parquet for repeatable analysis.
3. Sum `flow.bytes_toserver` by `src_ip` for external destinations.
4. Calculate directional imbalance and flag hosts with high upload volume and repeated external connections.

## Troubleshooting

### Error: "Invalid JSON" or "Line Truncated"
**Cause**: The EVE log may have been cut off during collection or copy.
**Solution**: Use an `orjson` script that catches decode errors, reports the bad line number, and continues parsing valid records.

### Error: "Polars schema mismatch" or missing nested fields
**Cause**: EVE records are sparse and different `event_type` values expose different nested structures.
**Solution**: Filter by `event_type` first, then select nested fields with null-tolerant expressions instead of assuming every record shares the same schema.

### Error: "Repeated scans of eve.json are too slow"
**Cause**: Large NDJSON inputs are being re-read for every aggregation or join.
**Solution**: Persist the normalized subset to Parquet with `polars` and rerun iterative analysis against the Parquet file instead of the original JSON.

### Error: "No alerts found"
**Cause**: The log may only contain metadata, or Suricata signatures did not trigger.
**Solution**: Pivot to protocol-based hunting in DNS, TLS, HTTP, and flow records using `references/suricata_eve_analysis.md`.
