# IAM-001: Self-Escalation via Inline Policy

**Severity:** Critical
**MITRE ATT&CK:** T1098.001 — Account Manipulation: Additional Cloud Credentials
**Tactic:** Privilege Escalation
**Category:** IAM Privilege Escalation

---

## Attack Scenario

An attacker gains access to an IAM user with limited permissions — typically through a compromised access key, a phished developer, or leaked credentials in a public repository. The user has restricted access (e.g., read-only S3, limited EC2 describe) but the account's IAM policies contain a common misconfiguration: the user has `iam:PutUserPolicy` permission on their own user resource.

The attacker discovers this permission through enumeration (using tools like Pacu, enumerate-iam, or manual CLI probing) and exploits it to attach an inline policy granting themselves `Action: *` on `Resource: *` — full administrative access. This single API call escalates a low-privilege foothold into complete account compromise.

**This is one of the most common privilege escalation paths in AWS**, documented extensively in ACRTP training, Rhino Security Labs research, and real-world breach reports.

### Why This Matters

- A single misconfigured IAM policy can turn a limited breach into total account compromise
- The escalation happens in one API call — there is no multi-step chain to detect incrementally
- Once escalated, the attacker has admin access to create persistence, exfiltrate data, and disable logging
- Without this detection, the escalation is invisible until the attacker takes a visible action (data theft, resource creation)

---

## What the Attacker Does

```
Step 1: Enumerate current permissions
        → iam:GetUser, iam:ListUserPolicies, iam:SimulatePrincipalPolicy
        → Attacker discovers they have iam:PutUserPolicy on themselves

Step 2: Craft a permissive inline policy
        → { "Effect": "Allow", "Action": "*", "Resource": "*" }

Step 3: Attach the policy to their own user
        → aws iam put-user-policy \
            --user-name compromised-developer \
            --policy-name admin-access \
            --policy-document file://admin-policy.json

Step 4: Verify escalation
        → aws sts get-caller-identity
        → aws iam list-attached-user-policies --user-name compromised-developer

Step 5: Use new permissions
        → Data exfiltration, persistence, lateral movement
```

### Tools That Automate This

- **Pacu** (Rhino Security Labs): `iam__privesc_scan` module identifies and exploits this path automatically
- **enumerate-iam**: Discovers available IAM permissions through brute-force API calls
- **CloudGoat** (Rhino Security Labs): Training scenario `iam_privesc_by_rollback` demonstrates this technique
- **ACRTP Labs**: Multiple labs cover this exact privilege escalation path

---

## CloudTrail Evidence

The attack generates the following CloudTrail event:

```json
{
  "eventVersion": "1.08",
  "userIdentity": {
    "type": "IAMUser",
    "principalId": "AIDAEXAMPLEID",
    "arn": "arn:aws:iam::123456789012:user/compromised-developer",
    "accountId": "123456789012",
    "accessKeyId": "AKIAEXAMPLEKEY",
    "userName": "compromised-developer"
  },
  "eventTime": "2026-02-10T14:32:18Z",
  "eventSource": "iam.amazonaws.com",
  "eventName": "PutUserPolicy",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "198.51.100.42",
  "userAgent": "aws-cli/2.15.0 Python/3.11.6",
  "requestParameters": {
    "userName": "compromised-developer",
    "policyName": "admin-access",
    "policyDocument": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"*\",\"Resource\":\"*\"}]}"
  },
  "responseElements": null,
  "requestID": "example-request-id",
  "eventID": "example-event-id",
  "eventType": "AwsApiCall",
  "recipientAccountId": "123456789012"
}
```

### Key Fields to Examine

| Field | What to Look For |
|-------|-----------------|
| `eventName` | `PutUserPolicy` or `PutRolePolicy` |
| `userIdentity.userName` | The actor performing the API call |
| `requestParameters.userName` | The target user receiving the policy |
| `requestParameters.policyDocument` | Look for `Action: *` or overly broad permissions |
| `sourceIPAddress` | Does this match known corporate IP ranges? |
| `userAgent` | `aws-cli` from a user who normally uses the console is suspicious |

### The Critical Signal

**`userIdentity.userName == requestParameters.userName`**

When the actor and the target are the same identity, and the policy grants broad permissions, this is almost always privilege escalation. Legitimate administrators typically modify other users' policies, not their own.

---

## Detection Logic

### CloudWatch Metric Filter

```
{ ($.eventSource = "iam.amazonaws.com") && (($.eventName = "PutUserPolicy") || ($.eventName = "PutRolePolicy")) }
```

### EventBridge Rule Pattern

```json
{
  "source": ["aws.iam"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["iam.amazonaws.com"],
    "eventName": ["PutUserPolicy", "PutRolePolicy"]
  }
}
```

### Enhanced Detection (Lambda Post-Processing)

For higher fidelity, a Lambda function can inspect the event and check:

1. **Self-escalation:** Does `userIdentity.userName` match `requestParameters.userName`?
2. **Broad permissions:** Does `policyDocument` contain `"Action": "*"` or `"Action": "iam:*"`?
3. **Known automation exclusion:** Is the actor a known Terraform or CI/CD role?

```python
import json

def is_self_escalation(event):
    """Returns True if user is attaching a broad policy to themselves."""
    detail = event.get('detail', {})
    actor = detail.get('userIdentity', {}).get('userName', '')
    target = detail.get('requestParameters', {}).get('userName', '')
    policy_doc = detail.get('requestParameters', {}).get('policyDocument', '{}')

    # Check self-targeting
    if actor != target:
        return False

    # Check for broad permissions
    try:
        doc = json.loads(policy_doc) if isinstance(policy_doc, str) else policy_doc
        for statement in doc.get('Statement', []):
            action = statement.get('Action', '')
            if action == '*' or (isinstance(action, list) and '*' in action):
                return True
    except (json.JSONDecodeError, AttributeError):
        pass

    return False

# Exclusion list for known automation
EXCLUDED_USERS = ['terraform-runner', 'github-actions-deployer', 'cloudformation-service']

def handler(event, context):
    detail = event.get('detail', {})
    actor = detail.get('userIdentity', {}).get('userName', '')

    if actor in EXCLUDED_USERS:
        return {'alert': False, 'reason': 'Known automation user'}

    if is_self_escalation(event):
        return {
            'alert': True,
            'severity': 'CRITICAL',
            'rule': 'IAM-001',
            'actor': actor,
            'source_ip': detail.get('sourceIPAddress'),
            'user_agent': detail.get('userAgent'),
            'message': f'CRITICAL: User {actor} attached broad inline policy to themselves'
        }

    return {'alert': False, 'reason': 'Not self-escalation or not broad permissions'}
```

---

## False Positives

| Source | Frequency | Mitigation |
|--------|-----------|------------|
| Terraform/CloudFormation automation | High | Exclude known automation role ARNs and usernames |
| Authorized admin updating own test policy | Low | Rare in production — investigate anyway |
| CI/CD pipeline provisioning IAM resources | Medium | Exclude CI/CD service role ARNs |
| AWS SSO/Identity Center role provisioning | Low | Exclude SSO service principal |

### Tuning Guidance

Add exclusions for known automation users in the CloudWatch filter:

```
{ ($.eventSource = "iam.amazonaws.com") && (($.eventName = "PutUserPolicy") || ($.eventName = "PutRolePolicy")) && ($.userIdentity.userName != "terraform-runner") && ($.userIdentity.userName != "github-actions-deployer") }
```

**Start with the base rule (no exclusions) for 7 days.** Review every alert to understand your environment's normal behavior before adding exclusions. Excluding too early hides real attacks.

---

## Response Playbook

### Immediate (0–15 minutes)

1. **Verify the alert is not a known automation user.** Check the `userIdentity` against your CMDB or IAM documentation.
2. **If unauthorized: immediately delete the inline policy.**
   ```bash
   aws iam delete-user-policy \
     --user-name compromised-developer \
     --policy-name admin-access
   ```
3. **Disable the user's access keys.**
   ```bash
   aws iam update-access-key \
     --user-name compromised-developer \
     --access-key-id AKIAEXAMPLEKEY \
     --status Inactive
   ```
4. **Disable console access** if the user has a login profile.
   ```bash
   aws iam delete-login-profile \
     --user-name compromised-developer
   ```

### Investigation (15–60 minutes)

5. **Pull all CloudTrail events for this user** in the past 24 hours.
   ```bash
   aws cloudtrail lookup-events \
     --lookup-attributes AttributeKey=Username,AttributeValue=compromised-developer \
     --start-time $(date -d '24 hours ago' -u +%Y-%m-%dT%H:%M:%SZ) \
     --max-results 50
   ```
6. **Identify the source IP and user agent.** Does the IP belong to your corporate network? Is the user agent consistent with the user's normal tools?
7. **Check what the user did after escalation.** Look for data access (S3 GetObject), resource creation (RunInstances), persistence (CreateUser, CreateAccessKey), or logging tampering (StopLogging).
8. **Determine initial access vector.** How did the attacker get the credentials? Check for:
   - Leaked keys in public repositories (GitHub, GitLab)
   - Phishing (check email logs if available)
   - Credential stuffing (check AUTH-004 brute force alerts)
   - Compromised CI/CD pipeline

### Containment (1–4 hours)

9. **If lateral movement occurred:** identify all resources accessed and all roles assumed. Revoke sessions for affected roles.
10. **Rotate all credentials** for the compromised user — access keys, console password, MFA device.
11. **Review IAM policies** to remove the `iam:PutUserPolicy` permission that enabled the escalation in the first place.
12. **Document the incident** with timeline, impact assessment, and remediation actions.

---

## Compliance References

| Framework | Requirement | How This Rule Helps |
|-----------|-------------|-------------------|
| PCI DSS | 7.1 — Limit access to system components | Detects unauthorized privilege expansion |
| PCI DSS | 7.2 — Access control systems | Alerts on IAM policy changes that bypass access controls |
| SOC 2 | CC6.1 — Logical and physical access controls | Monitors for access control circumvention |
| HIPAA | 164.312(a)(1) — Access control | Detects unauthorized access escalation to ePHI systems |
| CIS AWS | 1.16 — IAM policies attached only to groups/roles | Detects inline policy attachment to individual users |

---

## Related Rules

- **IAM-002:** Cross-Identity Access Key Creation — detects when one user creates access keys for another user
- **IAM-003:** Administrative Policy Attachment — detects attachment of AWS managed admin policies
- **IAM-004:** Policy Version Escalation — detects CreatePolicyVersion to restore permissive policy versions
- **LOG-001:** CloudTrail Logging Stopped — attackers often disable logging immediately after privilege escalation

---

## References

- [Rhino Security Labs — AWS IAM Privilege Escalation Methods](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/)
- [MITRE ATT&CK T1098.001](https://attack.mitre.org/techniques/T1098/001/)
- [AWS CloudTrail IAM API Reference](https://docs.aws.amazon.com/IAM/latest/APIReference/)
- [Pacu — AWS Exploitation Framework](https://github.com/RhinoSecurityLabs/pacu)
