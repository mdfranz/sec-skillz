---
name: cloudtrail-analyst
description: Analyzes AWS CloudTrail logs using Python, DuckDB, and jq, emphasizing performance, persistence, and structured logging.
---

# CloudTrail Log Analysis

## General Instructions
- Perform web searches for AWS CloudTrail file format to help parse and understand the content of the cloud events.
- Create a time-stamped markdown file for any work performed (`analyst_log-YY-MM-DD-MM.md`) to capture analysis steps and sample data.
- Create persistent scripts for all but the most trivial tasks. Do not remove any scripts after creation.
- Do not clean up temporary output from analyst scripts; rename them with a suffix of `YY-MM-DD-HH-MM.md`.
- Prevent Out of Memory errors by managing data parsing and ingestion carefully.
- Do NOT use analogies to explain concepts.
- Ensure all analysis files are in `.md` format.

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
