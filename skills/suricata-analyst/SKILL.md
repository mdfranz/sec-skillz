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
1.  **Sample the Data**: Always begin by sampling the logs to understand the schema and volume.
    ```bash
    head -n 5 eve.json | jq .
    ```
2.  **Identify Event Types**: Determine which protocols are present.
    ```bash
    jq -r .event_type eve.json | sort | uniq -c | sort -nr
    ```
3.  **Consult References**: For detailed field mapping, refer to `references/eve_format.md` and `references/suricata_eve_analysis.md`.

### Step 2: Targeted Analysis
1.  **Filter Noise**: Ignore `stats` events and focus on external traffic.
2.  **Create Persistence**: Use Python and DuckDB for complex queries. Refer to `original/ndr/suricata/` for existing script patterns.
3.  **Document Findings**: Maintain an `analyst_log-YY-MM-DD_HH-MM.md` file for every session.

## Working Agreements
- **No Deletions**: Do not delete scripts or intermediate output files.
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
**Solution**: Use `jq` to validate the file or a script that handles `JSONDecodeError` gracefully by skipping malformed lines.

### Error: "DuckDB Out of Memory"
**Cause**: Ingesting extremely large JSON files without streaming.
**Solution**: Convert the JSON to Parquet using `polars.scan_ndjson()` first, then query the Parquet file with DuckDB.

### Error: "No alerts found"
**Cause**: The log might only contain metadata, or the signature engine wasn't triggered.
**Solution**: Pivot to protocol-based hunting (DNS/TLS) using `references/suricata_eve_analysis.md` for inspiration.
