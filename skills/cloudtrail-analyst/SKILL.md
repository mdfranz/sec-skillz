---
name: cloudtrail-analyst
description: Analyzes AWS CloudTrail logs to identify security anomalies, unauthorized API calls, and privilege escalation. Use when a user provides CloudTrail logs, asks for AWS security analysis, or needs to hunt for suspicious IAM activity and resource tampering.
metadata:
  author: "Security Engineering Team"
  version: "1.1.0"
  tags: ["aws", "cloudtrail", "forensics", "iam", "cloud-security"]
---

# CloudTrail Log Analysis

## Instructions

### Step 1: Ingestion and Flattening
1.  **Understand Source**: CloudTrail logs are nested JSON. Refer to `references/cloudtrail_format.md` for field mapping.
2.  **Flatten for Analysis**: Use `jq` to convert the `Records` array into JSONL format for easier processing.
    ```bash
    cat *.json | jq -c '.Records[]' > flattened.jsonl
    ```
3.  **DuckDB Setup**: Ingest the flattened data into DuckDB for high-performance SQL querying.
    ```python
    import duckdb
    con = duckdb.connect('analysis.db')
    con.execute("CREATE TABLE events AS SELECT * FROM read_json_auto('flattened.jsonl')")
    ```

### Step 2: Investigation
1.  **Identify Anomalies**: Search for `errorCode` spikes or unauthorized operations.
2.  **Trace Principals**: Follow the `userIdentity.arn` and `role_arn` to map the scope of an incident.
3.  **Document Actions**: Capture all commands and findings in `analyst_log-YY-MM-DD-HH-MM.md`.

## Working Agreements
- **Persistence**: Save confident data as a persistent `.db` file. Do not delete scripts (`analyze_[topic].py`).
- **Memory Safety**: Use `polars.scan_ndjson()` or DuckDB disk spilling for large datasets to prevent OOM.
- **Python Style**: Use `orjson`, `polars`, and `duckdb`. Use `uv` for environment management.
- **No Analogies**: Keep technical explanations direct and professional.

## Examples

### Example 1: Hunting for Unauthorized Discovery
**User says**: "Search for any 'Access Denied' errors in the last log batch."
**Action**:
1. Query for events where `errorCode` is `AccessDenied` or `Client.UnauthorizedOperation`.
2. Group by `eventName` and `userIdentity.arn` to find the most aggressive principal.

### Example 2: Detecting Log Tampering
**User says**: "Did anyone try to disable CloudTrail?"
**Action**:
1. Search for `StopLogging`, `DeleteTrail`, or `UpdateTrail` in the `eventName` field.
2. Identify the `sourceIPAddress` and `userAgent` of the requester.

## Troubleshooting

### Error: "DuckDB Out of Memory"
**Cause**: Loading massive raw JSON files into memory.
**Solution**: Set `PRAGMA memory_limit='2GB'` and use DuckDB's native JSON reader which supports disk spilling.

### Error: "Missing Records"
**Cause**: Searching in Management Events for Data Event activity (e.g., S3 `GetObject`).
**Solution**: Verify if Data Events were enabled in the trail configuration. Check `references/cloudtrail_security_research.md` for event categories.

### Error: "Invalid JSON format"
**Cause**: CloudTrail files are often gzipped or contain a single `Records` object rather than JSONL.
**Solution**: Use `zcat` for gzipped files and the `jq` flattening recipe in Step 1.
