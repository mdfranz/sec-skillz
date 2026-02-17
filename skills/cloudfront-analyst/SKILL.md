---
name: cloudfront-analyst
description: Analyzes Amazon CloudFront logs to identify network threats, suspicious egress, and protocol anomalies. Use when a user provides CloudFront access logs, asks for traffic analysis, or needs to hunt for WAF bypasses and DDoS patterns.
---

# CloudFront Log Analysis

## Instructions

### Step 1: Ingestion and Preparation
1.  **Understand Source**: CloudFront provides Standard Logs (S3) and Real-time Logs (Kinesis). Refer to `references/cloudfront_format.md` for field mapping.
2.  **Standard Log Format**: Standard logs are TSV-like (tab-separated) with a header. They are often gzipped.
3.  **DuckDB Setup**: Ingest the logs into DuckDB for high-performance SQL querying. DuckDB can handle the header lines and compression.
    ```python
    import duckdb
    con = duckdb.connect('analysis.db')
    # Skip the first 2 lines (Version and Fields)
    con.execute("""
        CREATE TABLE events AS 
        SELECT * FROM read_csv_auto('*.gz', 
                                    header=True, 
                                    skip=2, 
                                    delim='	')
    """)
    ```

### Step 2: Investigation
1.  **Identify Anomalies**: Search for 4xx/5xx error spikes, unusual `User-Agent` strings, or high request volume from single IPs.
2.  **WAF Analysis**: If `x-edge-result-type` is `Error` or `LimitExceeded`, it might indicate WAF blocking or rate limiting.
3.  **Geographic Spikes**: Analyze `x-edge-location` to find unexpected geographic traffic patterns.
4.  **Document Actions**: Capture all commands and findings in `analyst_log-YY-MM-DD-HH-MM.md`.

## Working Agreements
- **Persistence**: Save confident data as a persistent `.db` file. Do not delete scripts (`analyze_cf.py`).
- **Memory Safety**: Use DuckDB's native CSV reader which supports disk spilling for large datasets.
- **Python Style**: Use `orjson`, `polars`, and `duckdb`. Use `uv` for environment management.
- **No Analogies**: Keep technical explanations direct and professional.

## Examples

### Example 1: Hunting for Scrapers
**User says**: "Check for any IP addresses making an excessive number of requests."
**Action**:
1. Query for `c-ip` grouped by count.
2. Filter for high counts and inspect `cs-user-agent` and `cs-uri-stem`.

### Example 2: Detecting Cache-Busting Attacks
**User says**: "Are we seeing many cache misses on random-looking URLs?"
**Action**:
1. Search for events where `x-edge-result-type` is `Miss`.
2. Analyze the `cs-uri-query` for high-entropy or randomized strings.

## Troubleshooting

### Error: "Invalid CSV format"
**Cause**: CloudFront logs have two header lines before the actual CSV header.
**Solution**: Use `skip=2` in your ingestion tool to bypass the `#Version` and `#Fields` lines.

### Error: "Timestamp parsing failure"
**Cause**: `date` and `time` are separate fields in CloudFront logs.
**Solution**: Concatenate them: `strptime(date || ' ' || time, '%Y-%m-%d %H:%M:%S')`.

### Error: "DuckDB Out of Memory"
**Cause**: Ingesting extremely large log files without streaming or scanning.
**Solution**: Convert the logs to Parquet using `polars.scan_csv(..., separator='\t')` first, then query the Parquet file with DuckDB.
