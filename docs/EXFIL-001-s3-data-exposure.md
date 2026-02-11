# EXFIL-001: S3 Bucket Policy Allows Public Access

**Severity:** Critical
**MITRE ATT&CK:** T1537 — Transfer Data to Cloud Account
**Tactic:** Exfiltration
**Category:** Data Exfiltration

---

## Attack Scenario

An attacker with sufficient IAM permissions modifies an S3 bucket policy to allow public access — either to exfiltrate data to an external location or to expose data for later retrieval. This can happen through two primary paths:

**Path 1: Post-compromise exfiltration.** An attacker who has already escalated privileges (IAM-001) modifies a bucket policy to add `"Principal": "*"` with `s3:GetObject`, making all objects in the bucket publicly downloadable. They then retrieve the data from an external IP.

**Path 2: Misconfiguration exploitation.** An attacker discovers a bucket that is already public or semi-public (e.g., accessible to any authenticated AWS user) and modifies the policy to grant broader access for persistent exfiltration.

**Path 3: ACL-based exposure.** Instead of modifying the bucket policy, the attacker uses `PutBucketAcl` to grant public read access via S3 Access Control Lists — an older but still functional mechanism.

### Why This Matters

- S3 data exposure is the most common cloud data breach vector globally
- A single `PutBucketPolicy` call can expose terabytes of data to the internet
- S3 buckets frequently contain sensitive data: customer records, financial data, credentials, backups, database exports
- AWS S3 Block Public Access settings mitigate this, but many organizations have exceptions for specific buckets, and attackers target those exceptions
- Unlike privilege escalation, data exposure has immediate external impact — the data is accessible from anywhere in the world within seconds

---

## What the Attacker Does

### Method 1: Bucket Policy Modification

```
Step 1: Identify target buckets with sensitive data
        → aws s3 ls
        → aws s3 ls s3://customer-data-prod/

Step 2: Modify the bucket policy to allow public read
        → aws s3api put-bucket-policy \
            --bucket customer-data-prod \
            --policy '{
              "Version": "2012-10-17",
              "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::customer-data-prod/*"
              }]
            }'

Step 3: Download data from external network
        → curl https://customer-data-prod.s3.amazonaws.com/exports/customers.csv

Step 4: (Optional) Revert the policy to cover tracks
        → aws s3api put-bucket-policy --bucket customer-data-prod --policy file://original-policy.json
```

### Method 2: ACL-Based Exposure

```
Step 1: Grant public read via ACL
        → aws s3api put-bucket-acl \
            --bucket customer-data-prod \
            --acl public-read

Step 2: Access data publicly
        → curl https://customer-data-prod.s3.amazonaws.com/any-object
```

### Method 3: Cross-Account Sharing

```
Step 1: Add an external AWS account to the bucket policy
        → "Principal": {"AWS": "arn:aws:iam::999999999999:root"}
        → This shares data with an attacker-controlled AWS account
        → Harder to detect than public access because the bucket does not appear "public"
```

---

## CloudTrail Evidence

### PutBucketPolicy Event

```json
{
  "eventVersion": "1.08",
  "userIdentity": {
    "type": "IAMUser",
    "principalId": "AIDAEXAMPLEID",
    "arn": "arn:aws:iam::123456789012:user/compromised-admin",
    "accountId": "123456789012",
    "userName": "compromised-admin"
  },
  "eventTime": "2026-02-10T16:18:42Z",
  "eventSource": "s3.amazonaws.com",
  "eventName": "PutBucketPolicy",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.55",
  "userAgent": "aws-cli/2.15.0 Python/3.11.6",
  "requestParameters": {
    "bucketName": "customer-data-prod",
    "bucketPolicy": {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Principal": "*",
          "Action": "s3:GetObject",
          "Resource": "arn:aws:s3:::customer-data-prod/*"
        }
      ]
    }
  },
  "responseElements": null,
  "requestID": "example-request-id",
  "eventID": "example-event-id",
  "readOnly": false,
  "eventType": "AwsApiCall",
  "recipientAccountId": "123456789012"
}
```

### Key Fields to Examine

| Field | What to Look For |
|-------|-----------------|
| `eventName` | `PutBucketPolicy`, `PutBucketAcl`, `DeleteBucketPolicy` |
| `requestParameters.bucketName` | Which bucket was modified? Does it contain sensitive data? |
| `requestParameters.bucketPolicy` | Does the policy contain `"Principal": "*"`? |
| `requestParameters.bucketPolicy` | Does the policy grant `s3:GetObject` or `s3:*`? |
| `sourceIPAddress` | Does this match known admin IPs? |
| `userIdentity` | Is this user authorized to modify bucket policies? |

### Critical Signals

- **`"Principal": "*"`** — grants access to anyone on the internet
- **`"Principal": {"AWS": "*"}`** — grants access to any authenticated AWS user
- **`"Principal": {"AWS": "arn:aws:iam::EXTERNAL_ACCOUNT:root"}`** — grants access to an external account (cross-account exfiltration)
- **`"Action": "s3:*"`** — grants full S3 permissions including write and delete
- **`PutBucketAcl` with `public-read` or `public-read-write`** — ACL-based exposure

---

## Detection Logic

### CloudWatch Metric Filter

```
{ ($.eventSource = "s3.amazonaws.com") && (($.eventName = "PutBucketPolicy") || ($.eventName = "PutBucketAcl") || ($.eventName = "DeleteBucketPolicy")) }
```

### EventBridge Rule Pattern

```json
{
  "source": ["aws.s3"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["s3.amazonaws.com"],
    "eventName": ["PutBucketPolicy", "PutBucketAcl", "DeleteBucketPolicy"]
  }
}
```

### Enhanced Detection (Lambda Post-Processing)

```python
import json

def analyze_bucket_policy(event):
    """Analyzes S3 bucket policy changes for public access or cross-account sharing."""
    detail = event.get('detail', {})
    event_name = detail.get('eventName', '')
    actor = detail.get('userIdentity', {}).get('arn', 'unknown')
    source_ip = detail.get('sourceIPAddress', 'unknown')
    bucket = detail.get('requestParameters', {}).get('bucketName', 'unknown')
    account_id = detail.get('recipientAccountId', '')

    result = {
        'rule': 'EXFIL-001',
        'event_name': event_name,
        'actor': actor,
        'source_ip': source_ip,
        'bucket': bucket
    }

    if event_name == 'PutBucketPolicy':
        policy = detail.get('requestParameters', {}).get('bucketPolicy', {})
        if isinstance(policy, str):
            try:
                policy = json.loads(policy)
            except json.JSONDecodeError:
                result['alert'] = True
                result['severity'] = 'HIGH'
                result['message'] = f'Unparseable bucket policy applied to {bucket}'
                return result

        for statement in policy.get('Statement', []):
            if statement.get('Effect') != 'Allow':
                continue

            principal = statement.get('Principal', '')
            action = statement.get('Action', '')

            # Check for public access
            if principal == '*' or principal == {"AWS": "*"}:
                result['alert'] = True
                result['severity'] = 'CRITICAL'
                result['exposure_type'] = 'PUBLIC'
                result['message'] = f'CRITICAL: Bucket {bucket} policy grants public access — Principal: *'
                return result

            # Check for cross-account access
            if isinstance(principal, dict):
                aws_principals = principal.get('AWS', [])
                if isinstance(aws_principals, str):
                    aws_principals = [aws_principals]
                for p in aws_principals:
                    if account_id and account_id not in p:
                        result['alert'] = True
                        result['severity'] = 'HIGH'
                        result['exposure_type'] = 'CROSS_ACCOUNT'
                        result['external_principal'] = p
                        result['message'] = f'HIGH: Bucket {bucket} shared with external account: {p}'
                        return result

    if event_name == 'PutBucketAcl':
        # PutBucketAcl with public-read or public-read-write
        acl = detail.get('requestParameters', {}).get('AccessControlPolicy', {})
        x_amz_acl = detail.get('requestParameters', {}).get('x-amz-acl', '')
        if x_amz_acl in ['public-read', 'public-read-write']:
            result['alert'] = True
            result['severity'] = 'CRITICAL'
            result['exposure_type'] = 'PUBLIC_ACL'
            result['message'] = f'CRITICAL: Bucket {bucket} ACL set to {x_amz_acl}'
            return result

    if event_name == 'DeleteBucketPolicy':
        result['alert'] = True
        result['severity'] = 'MEDIUM'
        result['message'] = f'MEDIUM: Bucket policy deleted from {bucket} — verify this is authorized'
        return result

    result['alert'] = False
    return result

def handler(event, context):
    return analyze_bucket_policy(event)
```

---

## False Positives

| Source | Frequency | Mitigation |
|--------|-----------|------------|
| Static website hosting buckets (legitimately public) | High | Maintain an allowlist of known public buckets |
| Terraform/CloudFormation deploying bucket policies | Medium | Exclude automation roles; verify policy content |
| CDN origin buckets (CloudFront) | Medium | Exclude buckets with CloudFront OAI/OAC principals |
| Cross-account data sharing (authorized) | Medium | Maintain an allowlist of authorized external accounts |
| Public dataset or open data buckets | Low | Tag and exclude known open data buckets |

### Tuning Guidance

**Two-tier approach:**

1. **Tier 1 (always alert):** Any policy containing `"Principal": "*"` on a bucket not in the known-public allowlist. No exceptions.

2. **Tier 2 (alert with lower severity):** Cross-account sharing to accounts not in the authorized partners list. Policy changes by non-automation users. ACL modifications of any kind.

Maintain an allowlist of buckets that are intentionally public (static websites, public datasets). Review this allowlist quarterly.

```python
KNOWN_PUBLIC_BUCKETS = [
    'company-static-website',
    'company-public-assets',
    'open-data-exports'
]

AUTHORIZED_EXTERNAL_ACCOUNTS = [
    '111111111111',  # Partner Company A
    '222222222222',  # Audit firm
]
```

---

## Response Playbook

### Immediate (0–15 minutes)

1. **Check the bucket policy.** Is the bucket now publicly accessible?
   ```bash
   aws s3api get-bucket-policy --bucket customer-data-prod
   ```

2. **Check Block Public Access settings.**
   ```bash
   aws s3api get-public-access-block --bucket customer-data-prod
   ```

3. **If public and unauthorized: block access immediately.**
   ```bash
   aws s3api put-public-access-block --bucket customer-data-prod \
     --public-access-block-configuration \
       BlockPublicAcls=true,\
       IgnorePublicAcls=true,\
       BlockPublicPolicy=true,\
       RestrictPublicBuckets=true
   ```

4. **If cross-account sharing and unauthorized: revert the policy.**
   ```bash
   aws s3api put-bucket-policy --bucket customer-data-prod \
     --policy file://original-policy.json
   ```

### Investigation (15–60 minutes)

5. **Determine what data is in the bucket.** What is the classification? Customer PII? Financial records? Credentials? Backups?

6. **Check S3 server access logs** (if enabled) for the bucket. Were objects accessed from external IPs during the exposure window?
   ```bash
   aws s3 ls s3://access-logs-bucket/customer-data-prod/
   ```

7. **Estimate the exposure window.** Time between the `PutBucketPolicy` event and when access was blocked. Check if the attacker reverted the policy themselves (indicating targeted exfiltration rather than ongoing exposure).

8. **Check CloudTrail for S3 data events** (if enabled). Look for `GetObject` calls from unusual IPs or user agents.

9. **Identify how the attacker got `s3:PutBucketPolicy` permission.** Check for preceding privilege escalation events (IAM-001, IAM-003).

### Containment and Notification (1–24 hours)

10. **If customer data was exposed:** initiate your data breach notification process. In Canada, PIPEDA requires notification to the Privacy Commissioner and affected individuals if there is a "real risk of significant harm."

11. **If credentials or secrets were in the bucket:** rotate all potentially exposed credentials immediately.

12. **Implement preventive controls:**
    - Enable S3 Block Public Access at the account level (not just bucket level)
    - Add an SCP denying `s3:PutBucketPolicy` with `"Principal": "*"` except for authorized roles
    - Enable S3 data events in CloudTrail for sensitive buckets

13. **Document the incident** with: exposure window, data classification, access logs analysis, root cause, and preventive controls implemented.

---

## Compliance References

| Framework | Requirement | How This Rule Helps |
|-----------|-------------|-------------------|
| PCI DSS | 1.3 — Restrict inbound and outbound traffic | Detects removal of S3 access restrictions |
| PCI DSS | 3.4 — Render PAN unreadable | Alerts when encryption or access controls on cardholder data stores are weakened |
| SOC 2 | CC6.1 — Logical access security | Detects unauthorized access permission changes |
| SOC 2 | CC6.6 — Manage transmission boundaries | Monitors for data exposure to unauthorized networks |
| HIPAA | 164.312(e)(1) — Transmission security | Detects when ePHI storage access controls are modified |
| CIS AWS | 2.1.1 — S3 buckets are not publicly accessible | Directly monitors for public access enablement |
| CIS AWS | 2.1.5 — S3 bucket policy does not grant public access | Monitors bucket policy changes for public principal |

---

## Related Rules

- **EXFIL-002:** S3 Bucket ACL Grants Public Access — ACL-based exposure (complementary to policy-based detection)
- **EXFIL-003:** EBS Snapshot Shared Externally — similar exfiltration technique via compute snapshots
- **EXFIL-004:** AMI Shared Publicly — machine image exposure
- **EXFIL-005:** RDS Snapshot Shared — database snapshot sharing to external accounts
- **IAM-001:** Self-Escalation via Inline Policy — privilege escalation often precedes data exfiltration

---

## References

- [MITRE ATT&CK T1537 — Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537/)
- [AWS S3 Security Best Practices](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html)
- [AWS S3 Block Public Access](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
- [PIPEDA Breach Notification Requirements](https://www.priv.gc.ca/en/privacy-topics/business-privacy/safeguards-and-breaches/privacy-breaches/respond-to-a-privacy-breach-at-your-business/)
