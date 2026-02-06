# Project: Suricata EVE JSON Analysis

## General Instructions
- Do not read in the entire file unless instructed to and use `head` because the files are probably over the limit
- Search suricata file format so you will know which event_type to use
- Files will be in the logs directory and may be greater than the agent file limit
- Do not remove any scripts after they have been created
- Create a time-stamped markdown file for any work you do (use `analyst_log-YY-DD-HH-MM.md`) that captures how analysis was performed and sample data, but this is not comprehensive
- Do not clean up temporary output from analyst scripts but rename them to a a suffix of `YY-DD-HH-MM.md`
- When performing an analyst task review Python code in the current directory to see it can solve the problem

## Suricata (EVE) File Format
- Ignore `event_type` of `stats` as this has no security relevant data
- Focus on public destination IPs, not internal RFC 1918 Traffic
- The most important event_types are: dns, tls, quic, flow because they allow analysis of egress traffic

## Coding Style
- Use Python or `jq` to parse and analyze log files as necessary 
- Use `orjson` instead of the built-in `json` library
- Use Python `duckdb` to analyze parquet data 
- Use Python `polars` to convert JSON to parquet if needed
- Use `uv` instead of pip and to create a virtual environments and install libraries
- Do not hardcode file-names use sys.argv for  command-line argument and NOT argparse
