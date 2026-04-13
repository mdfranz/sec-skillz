# Practical Analysis of Suricata EVE JSON with `orjson` and `polars`

## Executive Summary

Suricata EVE logs are newline-delimited JSON records that capture protocol metadata, flow summaries, and alerts at high volume. The most reliable workflow for local investigations is:

1. Use `uv` to create a dedicated environment.
2. Use `orjson` to sample and validate raw records.
3. Use `polars` lazy scans to filter and flatten the data.
4. Persist reusable subsets of the JSON data to Parquet before iterative analysis.

This approach keeps analysis reproducible, fast on large files, and easy to adapt when event schemas vary across `dns`, `tls`, `http`, `flow`, `quic`, and `alert` records.

## 1. Environment Setup

Start every investigation by creating the environment first.

```bash
uv venv
source .venv/bin/activate
uv pip install polars orjson
```

Keep analysis code in reusable scripts in the working directory so the workflow can be rerun against later log drops.

Persist reusable intermediate datasets to Parquet once the relevant event type and nested fields have been identified.

## 2. EVE Data Model and Inspection Strategy

Every EVE record commonly includes:

- `timestamp`
- `flow_id`
- `event_type`
- `src_ip`
- `dest_ip`
- `src_port`
- `dest_port`
- `proto`

The nested payload depends on `event_type`. For example:

- `dns` records carry fields under `dns.*`
- `tls` records carry fields under `tls.*`
- `http` records carry fields under `http.*`
- `flow` records carry counters and duration fields under `flow.*`

Because EVE is sparse, inspect and validate before building larger transformations.

### 2.1 Sample Raw Records with `orjson`

```python
import orjson

with open("eve.json", "rb") as f:
    for line_number, line in enumerate(f, start=1):
        try:
            record = orjson.loads(line)
        except orjson.JSONDecodeError:
            print(f"bad json on line {line_number}")
            continue

        print(orjson.dumps(record, option=orjson.OPT_INDENT_2).decode())
        if line_number >= 5:
            break
```

### 2.2 Count Event Types Before Hunting

```python
import orjson
from collections import Counter

counts = Counter()

with open("eve.json", "rb") as f:
    for line in f:
        record = orjson.loads(line)
        counts[record.get("event_type", "unknown")] += 1

for event_type, count in counts.most_common():
    print(f"{count:7} {event_type}")
```

Use this count to decide whether the log is best treated as an alert triage set, a protocol metadata hunt, or a flow-focused egress review.

## 3. Building Lazy `polars` Workflows

Prefer `polars.scan_ndjson()` over eager reads for large files. Start by reducing the dataset to the event type and fields needed for the hypothesis.

```python
import polars as pl

base = (
    pl.scan_ndjson("eve.json")
    .filter(pl.col("event_type") != "stats")
    .select(
        "timestamp",
        "flow_id",
        "event_type",
        "src_ip",
        "dest_ip",
        "src_port",
        "dest_port",
        "proto",
    )
)
```

For deeper hunts, branch from `base` into event-specific frames and add nested columns only when they are present in the target event type.

### 3.1 Persist Filtered JSON to Parquet Early

When you know which event family matters, write that normalized subset to Parquet so subsequent pivots, joins, and exports do not keep rescanning the original NDJSON file.

```python
import polars as pl

flows = (
    pl.scan_ndjson("eve.json")
    .filter(pl.col("event_type") == "flow")
    .select(
        "timestamp",
        "src_ip",
        "dest_ip",
        "src_port",
        "dest_port",
        "proto",
        pl.col("flow").struct.field("age").alias("age"),
        pl.col("flow").struct.field("bytes_toserver").alias("bytes_toserver"),
        pl.col("flow").struct.field("bytes_toclient").alias("bytes_toclient"),
    )
)

flows.sink_parquet("flow-events.parquet")
```

Use the Parquet output as the default input for repeated analysis steps:

```python
import polars as pl

flow_df = pl.scan_parquet("flow-events.parquet")
print(flow_df.group_by("src_ip").len().collect())
```

## 4. Flow Analysis for Egress and Beaconing

Flow records are useful when you need to find top talkers, disproportionate upload volume, long-lived sessions, or repeated low-variance connections.

### 4.1 Directional Volume and Exfiltration Candidates

```python
import polars as pl

flows = (
    pl.scan_ndjson("eve.json")
    .filter(pl.col("event_type") == "flow")
    .select(
        "src_ip",
        "dest_ip",
        "dest_port",
        pl.col("flow").struct.field("bytes_toserver").alias("bytes_toserver"),
        pl.col("flow").struct.field("bytes_toclient").alias("bytes_toclient"),
    )
    .with_columns(
        (
            (pl.col("bytes_toserver") - pl.col("bytes_toclient"))
            / (pl.col("bytes_toserver") + pl.col("bytes_toclient")).replace(0, None)
        ).alias("pcr")
    )
    .group_by("src_ip")
    .agg(
        pl.col("bytes_toserver").sum().alias("upload"),
        pl.col("bytes_toclient").sum().alias("download"),
        pl.col("dest_ip").n_unique().alias("distinct_dests"),
        pl.col("pcr").mean().alias("avg_pcr"),
    )
    .filter(pl.col("upload") > 10_000_000)
    .sort(["avg_pcr", "upload"], descending=[True, True])
)

print(flows.collect())
```

Interpretation:

- `avg_pcr` near `1.0` suggests mostly outbound transfer.
- High `upload` plus many distinct destinations may indicate staging, exfiltration, or scanning.
- High `upload` to a single rare destination can indicate a focused transfer channel.

### 4.2 Long-Lived Low-Volume Sessions

```python
import polars as pl

long_flows = (
    pl.scan_ndjson("eve.json")
    .filter(pl.col("event_type") == "flow")
    .select(
        "timestamp",
        "src_ip",
        "dest_ip",
        "dest_port",
        pl.col("flow").struct.field("age").alias("age"),
        pl.col("flow").struct.field("bytes_toserver").alias("bytes_toserver"),
        pl.col("flow").struct.field("bytes_toclient").alias("bytes_toclient"),
    )
    .with_columns(
        (pl.col("bytes_toserver") + pl.col("bytes_toclient")).alias("total_bytes")
    )
    .filter((pl.col("age") > 1800) & (pl.col("total_bytes") < 50_000))
    .sort("age", descending=True)
)

print(long_flows.collect())
```

These sessions are useful when hunting for reverse shells, long-lived tunnels, or idle control channels.

### 4.3 Repeated Connection Timing

```python
import polars as pl

beacons = (
    pl.scan_ndjson("eve.json")
    .filter(pl.col("event_type") == "flow")
    .select("timestamp", "src_ip", "dest_ip", "dest_port")
    .with_columns(pl.col("timestamp").str.to_datetime(strict=False))
    .sort(["src_ip", "dest_ip", "dest_port", "timestamp"])
    .with_columns(
        pl.col("timestamp")
        .diff()
        .over(["src_ip", "dest_ip", "dest_port"])
        .dt.total_seconds()
        .alias("gap_s")
    )
    .group_by(["src_ip", "dest_ip", "dest_port"])
    .agg(
        pl.len().alias("connection_count"),
        pl.col("gap_s").drop_nulls().mean().alias("avg_gap_s"),
        pl.col("gap_s").drop_nulls().std().alias("gap_stddev_s"),
    )
    .filter((pl.col("connection_count") > 20) & (pl.col("gap_stddev_s") < 5))
    .sort("gap_stddev_s")
)

print(beacons.collect())
```

Low variance in the inter-arrival time is a useful starting point for beaconing review, especially when paired with rare destinations or suspicious protocols.

## 5. DNS Intelligence

DNS records are valuable for rare domain hunting, tunneling detection, and spotting high-NXDOMAIN behavior.

### 5.1 Rare and Long Query Names

```python
import polars as pl

rare_dns = (
    pl.scan_ndjson("eve.json")
    .filter(pl.col("event_type") == "dns")
    .select(
        "src_ip",
        pl.col("dns").struct.field("rrname").alias("rrname"),
        pl.col("dns").struct.field("rcode").alias("rcode"),
    )
    .with_columns(pl.col("rrname").str.len_chars().alias("rrname_len"))
    .group_by("rrname")
    .agg(
        pl.len().alias("query_count"),
        pl.col("src_ip").n_unique().alias("distinct_clients"),
        pl.col("rcode").drop_nulls().mode().first().alias("common_rcode"),
        pl.col("rrname_len").max().alias("max_len"),
    )
    .filter((pl.col("query_count") < 3) | (pl.col("max_len") > 50))
    .sort(["query_count", "max_len"], descending=[False, True])
)

print(rare_dns.collect())
```

Useful pivots:

- very long subdomains
- low-frequency domains seen from few clients
- names repeatedly returning `NXDOMAIN`

### 5.2 TXT Record Payload Review

```python
import polars as pl

txt_records = (
    pl.scan_ndjson("eve.json")
    .filter(pl.col("event_type") == "dns")
    .select(
        "timestamp",
        "src_ip",
        "dest_ip",
        pl.col("dns").struct.field("rrname").alias("rrname"),
        pl.col("dns").struct.field("rrtype").alias("rrtype"),
        pl.col("dns").struct.field("rdata").alias("rdata"),
    )
    .filter(pl.col("rrtype") == "TXT")
    .with_columns(
        pl.col("rdata").cast(pl.String, strict=False).str.len_chars().alias("rdata_len")
    )
    .filter(pl.col("rdata_len") > 200)
    .sort("rdata_len", descending=True)
)

print(txt_records.collect())
```

Large TXT responses are not automatically malicious, but they are good candidates for manual review when tunneling is suspected.

### 5.3 NXDOMAIN Concentration by Source

```python
import polars as pl

nxdomain = (
    pl.scan_ndjson("eve.json")
    .filter(pl.col("event_type") == "dns")
    .select(
        "src_ip",
        pl.col("dns").struct.field("rcode").alias("rcode"),
        pl.col("dns").struct.field("rrname").alias("rrname"),
    )
    .group_by("src_ip")
    .agg(
        pl.len().alias("dns_events"),
        pl.when(pl.col("rcode") == "NXDOMAIN").then(1).otherwise(0).sum().alias("nxdomain_count"),
        pl.col("rrname").n_unique().alias("unique_names"),
    )
    .with_columns(
        (pl.col("nxdomain_count") / pl.col("dns_events")).alias("nxdomain_ratio")
    )
    .sort("nxdomain_ratio", descending=True)
)

print(nxdomain.collect())
```

High ratios with many unique names can indicate DGAs, misconfigured software, or tunneling tools that randomize labels.

## 6. TLS Metadata Hunting

TLS records expose SNI, JA3, issuer, subject, and certificate validity data without decrypting the payload.

### 6.1 Rare JA3 and SNI Combinations

```python
import polars as pl

rare_tls = (
    pl.scan_ndjson("eve.json")
    .filter(pl.col("event_type") == "tls")
    .select(
        "src_ip",
        "dest_ip",
        pl.col("tls").struct.field("sni").alias("sni"),
        pl.col("tls").struct.field("ja3").struct.field("hash").alias("ja3_hash"),
    )
    .group_by(["ja3_hash", "sni"])
    .agg(
        pl.len().alias("occurrence_count"),
        pl.col("src_ip").n_unique().alias("distinct_sources"),
        pl.col("dest_ip").n_unique().alias("distinct_dests"),
    )
    .filter(pl.col("occurrence_count") < 10)
    .sort("occurrence_count")
)

print(rare_tls.collect())
```

Rare JA3 values are worth investigating when they pair with:

- unknown or newly observed SNIs
- a single internal host
- suspicious egress destinations

### 6.2 Expired or Self-Signed Certificates

```python
import polars as pl

cert_review = (
    pl.scan_ndjson("eve.json")
    .filter(pl.col("event_type") == "tls")
    .select(
        "timestamp",
        "src_ip",
        "dest_ip",
        pl.col("tls").struct.field("sni").alias("sni"),
        pl.col("tls").struct.field("subject").alias("subject"),
        pl.col("tls").struct.field("issuerdn").alias("issuerdn"),
        pl.col("tls").struct.field("notafter").alias("notafter"),
    )
    .with_columns(
        pl.col("timestamp").str.to_datetime(strict=False).alias("ts"),
        pl.col("notafter").str.to_datetime(strict=False).alias("notafter_ts"),
    )
    .with_columns(
        (pl.col("notafter_ts") < pl.col("ts")).alias("expired"),
        (pl.col("subject") == pl.col("issuerdn")).alias("self_signed"),
    )
    .filter(pl.col("expired") | pl.col("self_signed"))
    .sort("timestamp", descending=True)
)

print(cert_review.collect())
```

Field availability varies between Suricata versions and configurations, so inspect a sample first and adjust the selected nested fields accordingly.

## 7. Cross-Protocol Correlation

`flow_id` is useful inside the same connection, but many investigative pivots also need time-based correlation between protocol records.

### 7.1 DNS Followed by TLS from the Same Host

```python
import polars as pl

dns = (
    pl.scan_ndjson("eve.json")
    .filter(pl.col("event_type") == "dns")
    .select(
        pl.col("timestamp").str.to_datetime(strict=False).alias("dns_time"),
        "src_ip",
        pl.col("dns").struct.field("rrname").alias("rrname"),
        pl.col("dns").struct.field("grouped").struct.field("A").alias("answers_a"),
    )
    .explode("answers_a")
)

tls = (
    pl.scan_ndjson("eve.json")
    .filter(pl.col("event_type") == "tls")
    .select(
        pl.col("timestamp").str.to_datetime(strict=False).alias("tls_time"),
        "src_ip",
        "dest_ip",
        pl.col("tls").struct.field("sni").alias("sni"),
    )
)

correlated = (
    tls.join(
        dns,
        left_on=["src_ip", "dest_ip"],
        right_on=["src_ip", "answers_a"],
        how="inner",
    )
    .with_columns((pl.col("tls_time") - pl.col("dns_time")).dt.total_seconds().alias("delta_s"))
    .filter((pl.col("delta_s") >= 0) & (pl.col("delta_s") <= 5))
    .sort("tls_time", descending=True)
)

print(correlated.collect())
```

This helps answer whether an SNI, certificate, or destination IP was preceded by a matching DNS resolution from the same source host.

## 8. Operational Guidance

- Filter to one `event_type` before selecting nested fields.
- Keep transformations lazy until the final `collect()`.
- Persist normalized event subsets to Parquet as soon as the working schema is clear.
- Use Parquet outputs as the default source for repeated filtering, grouping, and joins.
- Save each investigative script so later analysts can rerun the same logic.
- Record assumptions, thresholds, and false-positive notes in a timestamped analyst log.

## 9. Troubleshooting

### Invalid JSON lines

Use `orjson` with explicit error handling and line numbers to isolate malformed records without discarding the full dataset.

### Missing nested fields in `polars`

Different `event_type` values expose different structs. Filter first, then select or unwrap nested fields only for that event type.

### Slow or memory-heavy collections

Reduce the selected columns, keep work lazy longer, and filter earlier before calling `collect()`.

### Repeated scans of raw NDJSON are slow

Persist the filtered dataset to Parquet with `sink_parquet()` or `collect().write_parquet()` and rerun iterative analysis against that Parquet file.

### No alerts present

Treat the dataset as a metadata hunt. Pivot into `dns`, `tls`, `http`, `flow`, and `quic` records rather than expecting signature hits.
