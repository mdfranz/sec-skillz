# CloudFront Research: Security Detection and Analysis

This document outlines security threats detectable via CloudFront logs and strategies for hunting malicious activity at the edge.

## High-Signal Security Events

### 1. WAF Bypass Attempts
Attackers often try to find the "origin" IP address to bypass CloudFront and WAF.
- **Indicator**: Requests with an `x-host-header` that doesn't match the expected `cs-host`.
- **Action**: Monitor for discrepancies between the `Host` header and the distribution's configured CNAMEs.

### 2. DDoS & Application Layer Attacks
- **HTTP Flood**: Massive spike in requests from a distributed set of IPs or a single IP targeting a specific `cs-uri-stem`.
- **Indicator**: `sc-status` 429 (Too Many Requests) or 503 (Service Unavailable) if the origin is overwhelmed.
- **Analysis**: Group by `c-ip` and `cs-uri-stem` to identify the most frequent requesters and targets.

### 3. Cache-Busting
Attackers add random query parameters to URLs to force CloudFront to fetch from the origin, bypassing the cache and increasing origin load.
- **Indicator**: High volume of `x-edge-result-type` = `Miss` or `RefreshHit` with high-entropy `cs-uri-query`.
- **SQL Example**:
    ```sql
    SELECT cs-uri-stem, cs-uri-query, count(*)
    FROM events
    WHERE x-edge-result-type = 'Miss'
    GROUP BY 1, 2
    HAVING count(*) > 100;
    ```

### 4. Vulnerability Scanning
Scanners looking for common files (`.env`, `wp-login.php`, `.git/config`).
- **Indicator**: Series of 404/403 errors across many non-existent paths from a single `c-ip`.
- **Detection**:
    ```sql
    SELECT c-ip, count(DISTINCT cs-uri-stem) as unique_paths
    FROM events
    WHERE sc-status IN (404, 403)
    GROUP BY c-ip
    ORDER BY unique_paths DESC;
    ```

### 5. Suspicious Geographic Activity
Traffic from regions where your application does not operate.
- **Indicator**: `x-edge-location` codes belonging to unexpected countries.
- **Action**: Cross-reference edge location codes (e.g., `IAD` = Northern Virginia, `LHR` = London) with your expected user base.

## DuckDB Analysis Patterns

### Combining Date and Time
```sql
CREATE VIEW cf_logs AS
SELECT 
    strptime(date || ' ' || time, '%Y-%m-%d %H:%M:%S') as timestamp,
    *
FROM events;
```

### Identifying Top Attackers (by 4xx errors)
```sql
SELECT "c-ip", count(*) as error_count
FROM cf_logs
WHERE "sc-status" >= 400 AND "sc-status" < 500
GROUP BY "c-ip"
ORDER BY error_count DESC
LIMIT 10;
```

### Analyzing Time-Taken for Slow Post Attacks
```sql
SELECT "c-ip", "cs-uri-stem", avg("time-taken") as avg_time
FROM cf_logs
WHERE "cs-method" = 'POST'
GROUP BY 1, 2
ORDER BY avg_time DESC;
```

## Mitigation Strategies
- **AWS WAF**: Deploy managed rules (SQLi, XSS, Core Rule Set).
- **Origin Access Control (OAC)**: Ensure the S3 origin only accepts requests from CloudFront.
- **Custom Headers**: Add a secret header at CloudFront and verify it at the origin.
- **Field-Level Encryption**: Protect sensitive data (like POST body) before it reaches the origin.
