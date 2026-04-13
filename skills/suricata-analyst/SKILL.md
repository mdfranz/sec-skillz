---
name: suricata-analyst
description: Analyzes Suricata EVE JSON logs to identify network threats, suspicious egress, and protocol anomalies. Use when a user provides eve.json logs, asks for network traffic analysis, or needs to hunt for C2 beaconing and data exfiltration.
metadata:
  author: "Security Engineering Team"
  version: "1.1.0"
  tags: ["suricata", "nsm", "threat-hunting", "network-security"]
---

# Suricata (EVE) Analyst

## Instructions

### Step 1: Initial Discovery

Use Python for initial discovery and data sampling.

1.  **Sample the Data**: Always begin by sampling the logs to understand the schema and volume.
    ```bash
    python3 -c "import json; f=open('eve.json'); [print(json.dumps(json.loads(f.readline()), indent=2)) for _ in range(5)]"
    ```
2.  **Identify Event Types**: Determine which protocols are present.
    ```bash
    python3 -c "import json, collections; counts = collections.Counter(json.loads(line).get('event_type') for line in open('eve.json')); [print(f'{c:7} {t}') for t, c in counts.most_common()]"
    ```
3.  **Consult References**: For detailed field mapping, refer to `references/eve_format.md` and `references/suricata_eve_analysis.md`.

### Step 2: Targeted Analysis
1.  **Filter Noise**: Ignore `stats` events and focus on external traffic.
2.  **Create Persistence**: Use Python and DuckDB for complex queries. Refer to `original/ndr/suricata/` for existing script patterns.
3.  **Document Findings**: Maintain an `analyst_log-YY-MM-DD_HH-MM.md` file for every session.

## Working Agreements
- **Python use of UV**: ALWAYS create a virtual environment with `uv venv`. Install packages with `uv pip install`. Do NOT use `uv run`.
- **Tool Re-use**: ALWAYS search for and re-use existing tools and scripts in current directory before creating new ones.
- **Script Retention**: Always create and retain scripts (e.g., `analyze_*.py`) in the **current project directory**. **DO NOT** place scripts in `/tmp` or other directories outside the project, as they must be preserved for future reference and reproducibility.
- **Timestamping**: Rename throwaway files with a `-YY-MM-DD_HH-MM.md` suffix.
- **Python Style**: Use `orjson`, `polars`, and `duckdb`. Use `uv` for environment management.

## Examples

### Example 1: Hunting for Rare SNIs
**User says**: "Check for suspicious TLS connections."
**Action**:
1. Filter for `event_type: "tls"`.
2. Extract `tls.sni` and count occurrences.
3. Highlight SNIs that appear fewer than 3 times across the dataset.

### Example 2: Volume-based Exfiltration
**User says**: "Find any hosts sending large amounts of data to the internet."
**Action**:
1. Query `event_type: "flow"`.
2. Sum `bytes_toserver` by `src_ip` where `dest_ip` is external.
3. Calculate Producer-Consumer Ratio (PCR).

## Troubleshooting

### Error: "Invalid JSON" or "Line Truncated"
**Cause**: The EVE log might have been cut off during a copy or crash.
**Solution**: Use a Python script that handles `JSONDecodeError` gracefully by skipping or reporting malformed lines.

### Error: "DuckDB Out of Memory"
**Cause**: Ingesting extremely large JSON files without streaming.
**Solution**: Convert the JSON to Parquet using `polars.scan_ndjson()` first, then query the Parquet file with DuckDB.

### Error: "No alerts found"
**Cause**: The log might only contain metadata, or the signature engine wasn't triggered.
**Solution**: Pivot to protocol-based hunting (DNS/TLS) using `references/suricata_eve_analysis.md` for inspiration.
