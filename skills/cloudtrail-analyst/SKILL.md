---
name: cloudtrail-analyst
description: Analyzes AWS CloudTrail logs using Python, DuckDB, and jq, emphasizing performance, persistence, and structured logging.
---

# CloudTrail Log Analysis

## Overview

Amazon CloudTrail is a service that enables governance, compliance, operational auditing, and risk auditing of your AWS accounts. CloudTrail logs all AWS Management Console sign-in events, AWS SDKs and command-line tool calls, and calls made to the AWS APIs by using the AWS Management Console, AWS SDKs, command-line tools, and other software.

By using CloudTrail, you can detect unusual activity in your AWS environment, such as unexpected changes to security groups or IAM users, as well as identify potential security threats. For example, you can use CloudTrail to detect and respond to unauthorized access attempts, unauthorized changes to resources, or suspicious activity in your AWS accounts. Additionally, CloudTrail can be used to create audit trails of resource changes and to ensure compliance with internal policies and industry regulations.

When using AWS CloudTrail, it can be helpful to import certain types of logs in order to perform security analysis. 

When downloaded to a local filesystem CloudTrail can be very effective in hunting for threats. This skill provides guidance on how to do local analysis of compressed JSON log sources that have been retrieved from S3.

## General Instructions
- Perform web searches for AWS CloudTrail file format to help parse and understand the content of the cloud events.
- Review references for guidance on how to search for attack patterns
- Create a time-stamped markdown file for any work performed (`analyst_log-YY-MM-DD-HH-MM.md`) to capture analysis steps and sample data.
- Create persistent scripts for all but the most trivial tasks using the naming convention `analyze_[topic].py` or `parse_[topic].sh`. Do not remove any scripts after creation.
- Do not clean up temporary output from analyst scripts; rename them with a suffix of `YY-MM-DD-HH-MM.md`.
- **Prevent Out of Memory (OOM) errors**, particularly on low-resource systems:
    - **DuckDB**: Use DuckDB as the primary engine for large data; it handles disk spilling automatically. Set `PRAGMA memory_limit='2GB'` (adjust as needed) to constrain usage.
    - **Streaming & Chunking**: Use `polars.scan_ndjson()` for lazy loading or Python generators to process files record-by-record. Avoid `json.load()` on massive files.
    - **Pre-reduction**: Use `jq` to filter and flatten data *before* ingesting into Python/Pandas.
- Do NOT use analogies to explain concepts.
- Ensure all analysis files are in `.md` format.

## Quick Start
- Initialize environment: `uv venv && source .venv/bin/activate`
- Install dependencies: `uv pip install duckdb orjson polars pandas matplotlib`

## Common Recipes

### jq: Flatten CloudTrail Records
```bash
cat *.json | jq -c '.Records[]' > flattened.jsonl
```

### DuckDB: Direct Ingestion
```python
import duckdb
con = duckdb.connect('analysis.db')
con.execute("CREATE TABLE events AS SELECT * FROM read_json_auto('*.json', format='auto', records='true')")
```

## Python Coding Style
- Use Python or `jq` to parse and analyze log files.
- Use Python `duckdb` to ingest and analyze data. Save confident data as a persistent `.db` file in the current directory.
- Review existing Python code in the current directory before writing new code to solve problems.
- Use `uv` to create virtual environments and install libraries. Maintain a `requirements.txt` file.
- Use `orjson` instead of the built-in `json` library for better performance.
- Use Python `polars` to convert JSON to parquet if needed.
- Use Python `pandas` for statistical analysis if beneficial.
- Create visualizations as `.png` files with meaningful, space-free filenames.
- Use `sys.argv` for command-line arguments instead of `argparse` to keep syntax simple. Do not hardcode filenames.
