# Suricata (EVE) File Format Reference

## Format Overview
- **Line-based JSON (JSONL)**: Each line is a complete JSON object representing one event.
- **Common Fields**: `timestamp`, `flow_id`, `event_type`, `src_ip`, `dest_ip`, `src_port`, `dest_port`, `proto`.

## High-Signal Event Types for Threat Hunting
- `alert`: Signature-based detections (the most obvious starting point).
- `dns`: Domain queries and responses. Look for rare domains or high NXDOMAIN counts.
- `tls`: Encrypted handshake metadata. Check for SNI (Server Name Indication) and JA3 fingerprints.
- `http`: Cleartext web requests. Inspect `hostname`, `url`, and `user_agent`.
- `flow`: Summary of a connection. Use for volumetric analysis (bytes/packets sent).
- `quic`: Modern encrypted protocol metadata, similar to TLS.

## Noise Reduction
- **Exclude `stats`**: The `event_type: "stats"` records contain operational telemetry (packet counts, memory usage) and are generally not useful for threat hunting.
- **RFC1918**: When hunting for egress/C2, filter out internal-to-internal traffic (e.g., `dest_ip` not in `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`).
