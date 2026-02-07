# AWS CloudTrail Research: Detection Methods and Event Search

This document outlines research findings on methods for writing detections in AWS CloudTrail, the format of CloudTrail events, and strategies for searching large volumes of security events.

## CloudTrail Event Format

CloudTrail log files are stored in Amazon S3 as gzipped JSON files. Each file contains a root `Records` array, where each object represents a single API call or event.

### Key Fields for Analysis
*   **`eventTime`**: Timestamp of the event (UTC).
*   **`eventName`**: The specific API action (e.g., `RunInstances`, `ConsoleLogin`).
*   **`eventSource`**: The service that generated the event (e.g., `iam.amazonaws.com`, `s3.amazonaws.com`).
*   **`awsRegion`**: Region where the event occurred.
*   **`sourceIPAddress`**: IP address of the requester.
*   **`userAgent`**: Application or agent used to make the request.
*   **`vpcEndpointId`**: The ID of the VPC endpoint used for the request (critical for private API security).
*   **`recipientAccountId`**: The account ID that received the request (useful for cross-account analysis).
*   **`userIdentity`**: Detailed object containing information about the caller:
    *   `type`: (e.g., `IAMUser`, `AssumedRole`, `Root`).
    *   `arn`: The Amazon Resource Name of the principal.
    *   `accountId`: AWS account ID.
    *   `sessionContext`: Contains session attributes, including `attributes.mfaAuthenticated` (was MFA used?) and `sessionIssuer` (who assumed the role).
*   **`requestParameters`**: Parameters sent with the API request (useful for deep inspection).
*   **`responseElements`**: Elements returned by the service (e.g., `instanceId` of a created EC2 instance).
*   **`errorCode` / `errorMessage`**: Present if the API call failed (crucial for detecting brute force or unauthorized attempts).

### Event Categories
1.  **Management Events:** Control plane operations (e.g., configuring security groups, creating users). Logged by default.
2.  **Data Events:** Data plane operations (e.g., S3 object `GetObject`, Lambda function invocation). High volume; must be explicitly enabled.
3.  **Network Activity Events:** (Newer) Records AWS API calls made to your VPC endpoints from a private VPC. Useful for detecting lateral movement or unauthorized VPC usage.
4.  **Insights Events:** Anomalies detected by CloudTrail Insights.


### Optimization Strategies for SQL Queries
*   **Partitioning & Partition Pruning:** Organize data by common predicates (e.g., `account`, `region`, `year/month/day`). Ensure queries filter on those fields so the engine can skip irrelevant partitions. (In Athena, this is often implemented via partition projection.)
*   **Columnar Formats (Parquet/ORC):** Convert raw JSON to Parquet/ORC for lower scan cost and faster queries; keep raw JSON as a source of truth if desired.
*   **Select Only Needed Columns:** Avoid `SELECT *` on wide schemas; projecting fewer columns can reduce IO significantly in many engines.
*   **Pre-Parse / Flatten Common Fields:** Materialize frequently-used fields (e.g., `eventName`, `eventSource`, `userIdentity.arn`, `sourceIPAddress`, `errorCode`) into columns to avoid repeated JSON extraction cost.
*   **Be Careful with Regex and Wildcards:** Prefer exact matches and anchored patterns; avoid leading wildcards (e.g., `LIKE '%foo'`) when possible.

##  SQL Query Examples for Security

Note: CloudTrail fields are often nested JSON. Adjust field access (`userIdentity.arn`) and timestamp parsing to match your SQL engine and table schema (struct vs JSON string vs flattened columns). If `eventTime` is stored as an ISO-8601 string, string comparison against an ISO-8601 literal is usually sufficient for time filtering.

### Unauthorized API Calls
**Purpose:** Detects failed attempts to perform actions due to lack of permissions.
**Why it matters:** A spike in these errors often indicates a compromised credential being used for "discovery" (an attacker trying to figure out what they can do) or an internal user attempting to escalate privileges.
*   `Client.UnauthorizedOperation`: Standard error when an IAM user lacks permission.
*   `AccessDenied`: Common S3 access error.
*   `Client.InvalidPermission.NotFound`: Often seen when a specified permission doesn't exist.

```sql
SELECT eventTime, eventName, eventSource, userIdentity.arn, sourceIPAddress, errorMessage
FROM cloudtrail_logs
WHERE errorCode IN ('Client.UnauthorizedOperation', 'Client.InvalidPermission.NotFound', 'AccessDenied')
  AND eventTime >= '2024-01-01T00:00:00Z'
ORDER BY eventTime DESC;
```

### Root Account Usage
**Purpose:** Identifies any activity performed by the AWS Root user.
**Why it matters:** The Root user has unrestricted access to the entire account and cannot be limited by IAM policies. Best practice dictates that the Root user should only be used for specific account management tasks (like billing). Any unexpected usage is a critical security incident.

```sql
SELECT eventTime, eventName, sourceIPAddress, userAgent
FROM cloudtrail_logs
WHERE userIdentity.type = 'Root'
  AND eventTime >= '2024-01-01T00:00:00Z'
ORDER BY eventTime DESC;
```

### Security Group Modifications
**Purpose:** Tracks changes to Security Groups (virtual firewalls).
**Why it matters:** Misconfigured security groups are a leading cause of cloud breaches. Attackers often attempt to open ports (like SSH 22 or RDP 3389) to the public internet (`0.0.0.0/0`) to gain backdoor access. Monitoring `AuthorizeSecurityGroupIngress` and `RevokeSecurityGroupIngress` is essential for network hygiene.

```sql
SELECT eventTime, eventName, userIdentity.arn, requestParameters
FROM cloudtrail_logs
WHERE eventName LIKE '%SecurityGroup%'
  AND (eventName LIKE 'Authorize%' OR eventName LIKE 'Revoke%' OR eventName LIKE 'Create%' OR eventName LIKE 'Delete%')
ORDER BY eventTime DESC;
```

### Failed Console Logins
**Purpose:** Identifies failed attempts to log in to the AWS Management Console.
**Why it matters:** Repeated failed login attempts (`ConsoleLogin` with a 'Failure' response) are a primary indicator of brute-force attacks, credential stuffing, or password spraying. correlating this with `sourceIPAddress` can help identify malicious actors.

```sql
SELECT eventTime, userIdentity.userName, sourceIPAddress, responseElements
FROM cloudtrail_logs
WHERE eventName = 'ConsoleLogin'
  AND responseElements LIKE '%Failure%'
ORDER BY eventTime DESC;
```

## Potential Detection Signatures (CloudTrail)

Below are additional high-signal event patterns (“signatures”) that are commonly useful for CloudTrail-based detections. Treat these as starting points: tune by account, principal, region, and expected automation.

### CloudTrail / Logging Tampering (High Priority)
*   **Stop/alter CloudTrail logging:**
    *   `cloudtrail.amazonaws.com`: `StopLogging`, `DeleteTrail`, `UpdateTrail`, `PutEventSelectors`, `PutInsightSelectors`, `RemoveTags`
*   **CloudTrail Lake tampering (if used):**
    *   `cloudtrail.amazonaws.com`: `DeleteEventDataStore`, `UpdateEventDataStore`, `StopQuery`, `CancelQuery`
*   **CloudWatch Logs tampering (if CloudTrail delivers there):**
    *   `logs.amazonaws.com`: `DeleteLogGroup`, `DeleteLogStream`, `PutRetentionPolicy` (sudden very-low retention), `DisassociateKmsKey`
*   **S3 log bucket tampering (CloudTrail S3 delivery):**
    *   `s3.amazonaws.com`: `PutBucketPolicy`, `DeleteBucketPolicy`, `PutBucketAcl`, `PutBucketPublicAccessBlock`, `DeleteBucketPublicAccessBlock`, `PutEncryptionConfiguration`

### IAM Privilege Escalation & Persistence
*   **Attach admin or powerful policies:**
    *   `iam.amazonaws.com`: `AttachUserPolicy`, `AttachRolePolicy`, `AttachGroupPolicy`
    *   **Signature idea:** policy ARN contains `AdministratorAccess` (or your “break-glass/admin” managed policies).
*   **Inline policy injection (often higher risk than managed):**
    *   `iam.amazonaws.com`: `PutUserPolicy`, `PutRolePolicy`, `PutGroupPolicy`
    *   **Signature idea:** policy document grants `Action:"*"` or sensitive actions (e.g., `iam:*`, `kms:Decrypt`, `sts:AssumeRole`).
*   **Policy version backdooring:**
    *   `iam.amazonaws.com`: `CreatePolicyVersion`, `SetDefaultPolicyVersion`
*   **Role trust modification (assume-role backdoor):**
    *   `iam.amazonaws.com`: `UpdateAssumeRolePolicy`
    *   **Signature idea:** new trusted principal is an unexpected AWS account, or a wildcard principal in the trust.
*   **Credential creation / persistence:**
    *   `iam.amazonaws.com`: `CreateAccessKey`, `UpdateAccessKey` (enable), `CreateLoginProfile`, `UpdateLoginProfile`
    *   **Signature idea:** keys created for rarely-used users, or outside normal change windows.
*   **PassRole (frequent escalation primitive):**
    *   `iam.amazonaws.com`: `PassRole`
    *   **Signature idea:** role passed to compute/deployment services (EC2/Lambda/ECS/Glue/CloudFormation) by an unexpected principal.

### Console Authentication & MFA Weakening
*   **Console login failures / unusual success:**
    *   `signin.amazonaws.com`: `ConsoleLogin`
    *   **Signature idea:** success from new geo/IP, or success immediately after repeated failures.
*   **MFA removal / deactivation:**
    *   `iam.amazonaws.com`: `DeactivateMFADevice`, `DeleteVirtualMFADevice`, `ResyncMFADevice`

### Reconnaissance (Low Fidelity Alone; Great for Correlation)
*   **Broad discovery activity:**
    *   `iam.amazonaws.com`: `ListUsers`, `ListRoles`, `GetAccountAuthorizationDetails`
    *   `organizations.amazonaws.com`: `ListAccounts`, `DescribeOrganization`
    *   `ec2.amazonaws.com`: `DescribeInstances`, `DescribeSecurityGroups`, `DescribeRegions`
    *   `s3.amazonaws.com`: `ListBuckets`, `GetBucketLocation`
*   **Correlation idea:** “Recon burst” → `AssumeRole` → `Put*Policy`/`PassRole`/`CreateAccessKey`

### Data Exposure / Public Access Changes
*   **S3 public exposure:**
    *   `s3.amazonaws.com`: `PutBucketAcl`, `PutBucketPolicy`, `PutBucketPublicAccessBlock`, `DeleteBucketPublicAccessBlock`, `PutBucketWebsite`
    *   **Signature idea:** bucket policy includes public principal (`"Principal":"*"`) or ACL grants to `AllUsers`/`AuthenticatedUsers`. `PutBucketWebsite` enables static hosting, potentially for phishing/malware.
*   **Snapshot / image sharing (exfil path):**
    *   `ec2.amazonaws.com`: `ModifySnapshotAttribute`, `ModifyImageAttribute`
    *   `rds.amazonaws.com`: `ModifyDBSnapshotAttribute`
    *   **Signature idea:** snapshot/image made public or shared to an unexpected account.

### S3 Ransomware & Data Destruction
*   **Lifecycle rule abuse (fast deletion):**
    *   `s3.amazonaws.com`: `PutLifecycleConfiguration`
    *   **Signature idea:** Rule created to expire objects in < 1 day or transition to inaccessible storage classes immediately.
*   **Versioning suspension (pre-deletion):**
    *   `s3.amazonaws.com`: `PutBucketVersioning`
    *   **Signature idea:** Status set to `Suspended` followed by mass `DeleteObject` calls (if Data Events enabled).
*   **Replication disabling (prevent backups):**
    *   `s3.amazonaws.com`: `DeleteBucketReplication`

### Key Management (Ransomware / Cover Tracks / Data Lockout)
*   **KMS key disruption:**
    *   `kms.amazonaws.com`: `DisableKey`, `ScheduleKeyDeletion`, `CancelKeyDeletion`
*   **KMS policy/grant changes:**
    *   `kms.amazonaws.com`: `PutKeyPolicy`, `CreateGrant`, `RevokeGrant`, `RetireGrant`
    *   **Signature idea:** grants enabling broad decrypt usage, or principals outside the expected set.

### Deployment / Execution Primitives (Often Used for Persistence)
*   **Lambda modifications:**
    *   `lambda.amazonaws.com`: `CreateFunction`, `UpdateFunctionCode`, `UpdateFunctionConfiguration`, `AddPermission`
*   **ECR image pushes / repo policy changes:**
    *   `ecr.amazonaws.com`: `PutImage`, `BatchDeleteImage`, `SetRepositoryPolicy`
*   **CloudFormation stack operations with IAM capabilities:**
    *   `cloudformation.amazonaws.com`: `CreateStack`, `UpdateStack`
    *   **Signature idea:** `requestParameters.capabilities` contains `CAPABILITY_IAM` / `CAPABILITY_NAMED_IAM`.

### Network & Edge Surface Changes
*   **Ingress opened broadly:**
    *   `ec2.amazonaws.com`: `AuthorizeSecurityGroupIngress`
    *   **Signature idea:** `0.0.0.0/0` or `::/0` on sensitive ports (22, 3389, 5432, 3306, 6379).
*   **Route changes / external exposure:**
    *   `ec2.amazonaws.com`: `CreateRoute`, `ReplaceRoute`, `AssociateRouteTable`, `CreateInternetGateway`, `AttachInternetGateway`
    *   `route53.amazonaws.com`: `ChangeResourceRecordSets` (domain hijack / redirect risk)

### Useful Metadata Fields for Signature Quality
*   **`readOnly`**: Helps separate recon (`true`) from change actions (`false`).
*   **`userIdentity.sessionContext.sessionIssuer.arn`**: The role/user issuing an assumed-role session (critical for STS analysis).
*   **`additionalEventData`**: Context-specific data. Examples:
    *   `MFAUsed`: "Yes"/"No" for console logins.
    *   `LoginTo`: URL of the console login destination.
    *   `MobileVersion`: If the mobile app was used.
*   **`tlsDetails`**:
    *   `tlsVersion`: e.g., "TLSv1.2", "TLSv1.3". Detect old/insecure clients.
    *   `cipherSuite`: The crypto suite used.
    *   `clientProvidedHostHeader`: Can help identify the true target of a request or potential spoofing.

## DuckDB Implementation Patterns

DuckDB is exceptionally fast for CloudTrail analysis because it can handle nested JSON and gzipped files natively.

### Efficient Ingestion (Gzipped JSON)
```sql
-- Create a table directly from gzipped CloudTrail files
CREATE TABLE cloudtrail_raw AS 
SELECT * FROM read_json_auto('data/*.json.gz', records=true);

-- Flatten common fields into a view for easier analysis
CREATE VIEW events AS
SELECT
    eventTime,
    eventName,
    eventSource,
    awsRegion,
    sourceIPAddress,
    userIdentity.type AS user_type,
    userIdentity.arn AS user_arn,
    userIdentity.sessionContext.sessionIssuer.arn AS role_arn,
    errorCode,
    errorMessage,
    requestParameters,
    responseElements
FROM cloudtrail_raw,
UNNEST(Records) AS t(Records); -- If the JSON isn't pre-flattened
```

### Hunting for Lateral Movement (AssumeRole Chains)
```sql
SELECT 
    eventTime, 
    user_arn, 
    requestParameters->>'roleArn' AS assumed_role,
    sourceIPAddress
FROM events 
WHERE eventName = 'AssumeRole'
ORDER BY eventTime;
```

### Finding Sensitive Data Exfiltration (S3)
```sql
SELECT 
    eventTime, 
    user_arn, 
    requestParameters->>'bucketName' AS bucket,
    requestParameters->>'key' AS object_key
FROM events 
WHERE eventSource = 's3.amazonaws.com' 
  AND eventName IN ('GetObject', 'PutBucketPolicy')
ORDER BY eventTime;
```

## Example SQL Queries (Additional)

#### CloudTrail Logging Tampering
```sql
SELECT eventTime, eventName, userIdentity.arn, sourceIPAddress, userAgent, requestParameters, errorCode
FROM cloudtrail_logs
WHERE eventSource = 'cloudtrail.amazonaws.com'
  AND eventName IN ('StopLogging','DeleteTrail','UpdateTrail','PutEventSelectors','PutInsightSelectors','DeleteEventDataStore','UpdateEventDataStore')
ORDER BY eventTime DESC;
```

#### New Access Keys or Console Password Set
```sql
SELECT eventTime, eventName, userIdentity.arn, requestParameters, sourceIPAddress, userAgent
FROM cloudtrail_logs
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName IN ('CreateAccessKey','CreateLoginProfile','UpdateLoginProfile')
ORDER BY eventTime DESC;
```

#### Role Trust Policy Changes
```sql
SELECT eventTime, userIdentity.arn, requestParameters, sourceIPAddress, userAgent
FROM cloudtrail_logs
WHERE eventSource = 'iam.amazonaws.com'
  AND eventName = 'UpdateAssumeRolePolicy'
ORDER BY eventTime DESC;
```

#### S3 Public Access Block Changes
```sql
SELECT eventTime, eventName, userIdentity.arn, requestParameters, sourceIPAddress, userAgent
FROM cloudtrail_logs
WHERE eventSource = 's3.amazonaws.com'
  AND eventName IN ('PutBucketPublicAccessBlock','DeleteBucketPublicAccessBlock')
ORDER BY eventTime DESC;
```
