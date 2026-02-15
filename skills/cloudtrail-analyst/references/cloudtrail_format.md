# AWS CloudTrail File Format Reference

## Format Overview
- **Gzipped JSON**: CloudTrail logs are typically delivered as `.json.gz` files.
- **Root Element**: A single JSON object with a `Records` key containing an array of event objects.
- **Key Fields**: `eventTime`, `eventSource`, `eventName`, `awsRegion`, `sourceIPAddress`, `userIdentity`, `requestParameters`, `responseElements`.

## User Identity Types
- **IAMUser**: A standard IAM user.
- **AssumedRole**: A session created via `sts:AssumeRole`. Check `sessionContext.sessionIssuer.arn` to find the source role.
- **Root**: The account root user (should be rare).
- **AWSService**: Actions taken by AWS services (e.g., Auto Scaling).

## High-Signal Events for Hunting
- **IAM Persistence**: `CreateAccessKey`, `CreateLoginProfile`, `UpdateAssumeRolePolicy`.
- **Evasion**: `StopLogging`, `DeleteTrail`, `UpdateTrail`.
- **Exfiltration**: `ModifySnapshotAttribute`, `ModifyImageAttribute` (making resources public).
- **Privilege Escalation**: `AttachUserPolicy`, `PutRolePolicy`.

## Data Volume Strategies
- **Flat Files**: Convert the nested `Records` array into a flat JSONL (JSON Lines) format using `jq` for faster processing.
  ```bash
  cat *.json | jq -c '.Records[]' > flattened.jsonl
  ```
- **Partitioning**: When using DuckDB, use the `awsRegion` or `eventTime` to partition data if the volume is high.
