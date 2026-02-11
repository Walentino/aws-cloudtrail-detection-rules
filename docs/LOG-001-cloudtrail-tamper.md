# LOG-001: CloudTrail Logging Stopped

**Severity:** Critical
**MITRE ATT&CK:** T1562.008 — Impair Defenses: Disable Cloud Logs
**Tactic:** Defense Evasion
**Category:** Logging Tampering

---

## Attack Scenario

An attacker who has already gained elevated access to an AWS account (often through privilege escalation like IAM-001) takes the next logical step: disabling the logging system that would record their subsequent actions. By calling `StopLogging` on a CloudTrail trail, the attacker creates a blind spot — all API activity after this point goes unrecorded.

This is not a theoretical risk. CloudTrail tampering is present in the majority of sophisticated AWS intrusions. The logic is simple: if defenders cannot see what happened, they cannot investigate, respond, or attribute the attack. Attackers treat logging disruption as a standard operating procedure, not an optional step.

### Why This Matters

- **Every second without logging is a second without evidence.** If StopLogging succeeds and is not detected immediately, the attacker operates in the dark for minutes, hours, or days.
- **This is a multiplier for every other attack technique.** Privilege escalation, data exfiltration, persistence — all become harder to detect and investigate if CloudTrail is offline.
- **It is the most important detection rule in this entire library.** If you deploy only one rule, deploy this one.

---

## What the Attacker Does

```
Step 1: Gain elevated access (via privilege escalation or compromised admin)

Step 2: Identify the CloudTrail configuration
        → aws cloudtrail describe-trails
        → Attacker identifies trail name, S3 bucket, log group

Step 3: Disable logging
        → aws cloudtrail stop-logging --name main-trail

Step 4: (Alternative) Delete the trail entirely
        → aws cloudtrail delete-trail --name main-trail

Step 5: (Alternative) Modify event selectors to exclude specific events
        → aws cloudtrail put-event-selectors \
            --trail-name main-trail \
            --event-selectors '[]'

Step 6: Operate freely
        → Data exfiltration, persistence, lateral movement
        → No CloudTrail events recorded for these actions
```

### The Three Variants

| Method | API Call | Stealth Level | Reversibility |
|--------|----------|--------------|---------------|
| Stop logging | `StopLogging` | Low — easily detected if monitored | High — `StartLogging` restores |
| Delete trail | `DeleteTrail` | Low — obvious destruction | Medium — must recreate trail |
| Modify event selectors | `PutEventSelectors` | **High** — trail appears active but stops recording specific events | High — selectors can be restored |

**PutEventSelectors is the most dangerous variant** because the trail still appears to be running. Dashboards show a healthy trail. But event selectors have been emptied, and no management events are being recorded. This is the technique sophisticated attackers prefer.

---

## CloudTrail Evidence

### StopLogging Event

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
  "eventTime": "2026-02-10T15:41:07Z",
  "eventSource": "cloudtrail.amazonaws.com",
  "eventName": "StopLogging",
  "awsRegion": "us-east-1",
  "sourceIPAddress": "203.0.113.55",
  "userAgent": "aws-cli/2.15.0 Python/3.11.6",
  "requestParameters": {
    "name": "arn:aws:cloudtrail:us-east-1:123456789012:trail/main-trail"
  },
  "responseElements": null,
  "requestID": "example-request-id",
  "eventID": "example-event-id",
  "readOnly": false,
  "eventType": "AwsApiCall",
  "managementEvent": true,
  "recipientAccountId": "123456789012"
}
```

### Key Fields to Examine

| Field | What to Look For |
|-------|-----------------|
| `eventName` | `StopLogging`, `DeleteTrail`, or `PutEventSelectors` |
| `userIdentity` | Who did this? Is this an authorized admin performing maintenance? |
| `sourceIPAddress` | Does this IP match known admin workstations? |
| `requestParameters.name` | Which trail was targeted? Is it the organization's primary trail? |
| `eventTime` | Did this happen during a maintenance window or at an unusual time? |

### The Irony

The `StopLogging` event itself is recorded in CloudTrail before logging stops. This creates a narrow window — if your detection rule fires on this event and alerts within seconds, you catch the attacker before they go dark. If your alerting has a 5-minute delay, the attacker has 5 minutes of unmonitored access.

**This is why EventBridge (near real-time) is preferred over CloudWatch (minutes of delay) for this specific rule.**

---

## Detection Logic

### CloudWatch Metric Filter

```
{ ($.eventSource = "cloudtrail.amazonaws.com") && (($.eventName = "StopLogging") || ($.eventName = "DeleteTrail") || ($.eventName = "UpdateTrail") || ($.eventName = "PutEventSelectors")) }
```

### EventBridge Rule Pattern (Recommended)

```json
{
  "source": ["aws.cloudtrail"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["cloudtrail.amazonaws.com"],
    "eventName": ["StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"]
  }
}
```

### Enhanced Detection (Lambda Post-Processing)

```python
import json

# These events should NEVER happen in normal operations
CRITICAL_EVENTS = ['StopLogging', 'DeleteTrail']

# These events need context — they might be legitimate configuration changes
SUSPICIOUS_EVENTS = ['UpdateTrail', 'PutEventSelectors']

# Known maintenance windows (UTC)
MAINTENANCE_WINDOWS = []  # Add your org's windows, e.g., [('Saturday', 2, 6)]

def handler(event, context):
    detail = event.get('detail', {})
    event_name = detail.get('eventName', '')
    actor = detail.get('userIdentity', {}).get('arn', 'unknown')
    source_ip = detail.get('sourceIPAddress', 'unknown')
    trail_name = detail.get('requestParameters', {}).get('name', 'unknown')

    if event_name in CRITICAL_EVENTS:
        return {
            'alert': True,
            'severity': 'CRITICAL',
            'rule': 'LOG-001',
            'message': f'CRITICAL: {event_name} called on {trail_name} by {actor} from {source_ip}',
            'event_name': event_name,
            'actor': actor,
            'source_ip': source_ip,
            'trail': trail_name,
            'action': 'IMMEDIATE_RESPONSE_REQUIRED'
        }

    if event_name == 'PutEventSelectors':
        # Check if event selectors were emptied
        selectors = detail.get('requestParameters', {}).get('eventSelectors', [])
        if not selectors or selectors == []:
            return {
                'alert': True,
                'severity': 'CRITICAL',
                'rule': 'LOG-001',
                'message': f'CRITICAL: Event selectors emptied on {trail_name} by {actor} — trail appears active but is blind',
                'event_name': event_name,
                'actor': actor,
                'source_ip': source_ip,
                'trail': trail_name
            }

    if event_name in SUSPICIOUS_EVENTS:
        return {
            'alert': True,
            'severity': 'HIGH',
            'rule': 'LOG-001',
            'message': f'HIGH: {event_name} called on {trail_name} by {actor} — verify this is authorized',
            'event_name': event_name,
            'actor': actor,
            'source_ip': source_ip,
            'trail': trail_name
        }

    return {'alert': False}
```

---

## False Positives

| Source | Frequency | Mitigation |
|--------|-----------|------------|
| CloudTrail trail reconfiguration during maintenance | Rare | Document maintenance windows; still investigate every occurrence |
| Terraform destroying and recreating trails | Low | Exclude Terraform service role; verify the trail is recreated |
| AWS Organizations trail management | Low | Exclude Organizations service principal |
| Testing in sandbox/dev accounts | Medium | Apply rule only to production account trails |

### Tuning Guidance

**Do not broadly exclude any users or roles from this rule.**

Unlike IAM rules where Terraform exclusions are reasonable, CloudTrail tampering should trigger an alert every single time regardless of who does it. Even if your Terraform pipeline legitimately recreates a trail, that event should be reviewed by a human.

The only safe tuning is restricting the rule to your organization's primary trails and excluding sandbox accounts where trails may be created and destroyed during testing.

---

## Response Playbook

### Immediate (0–5 minutes)

**This is the only rule in this library with a 5-minute response target.** Every minute of delay is a minute the attacker operates unmonitored.

1. **Verify CloudTrail status immediately.**
   ```bash
   aws cloudtrail get-trail-status --name main-trail
   ```
   Check `IsLogging` — if `false`, logging has been stopped.

2. **If logging was stopped: restart it immediately.**
   ```bash
   aws cloudtrail start-logging --name main-trail
   ```

3. **If the trail was deleted: recreate it** using your Terraform/CloudFormation template or the AWS CLI.

4. **If event selectors were modified: restore them.**
   ```bash
   aws cloudtrail put-event-selectors \
     --trail-name main-trail \
     --event-selectors '[{"ReadWriteType":"All","IncludeManagementEvents":true}]'
   ```

### Investigation (5–60 minutes)

5. **Identify the actor.** Pull the `userIdentity` from the CloudTrail event. Is this a known admin? A compromised user? An assumed role?

6. **Check what happened before the StopLogging call.** The attacker likely escalated privileges first. Look for IAM-001, IAM-002, IAM-003 alerts in the preceding hours.

7. **Estimate the blind spot.** Calculate the time between `StopLogging` and when logging was restored. All API activity during this window is unrecorded in CloudTrail.

8. **Check alternative log sources for the blind spot period:**
   - VPC Flow Logs (network activity)
   - S3 server access logs (bucket access)
   - CloudWatch Logs (application logs)
   - AWS Config (resource state changes)
   - GuardDuty findings (if not also disabled — check LOG-004)

9. **Look for concurrent GuardDuty disabling.** Sophisticated attackers disable both CloudTrail and GuardDuty. Check for `DeleteDetector` events (LOG-004).

### Containment (1–4 hours)

10. **Revoke the actor's access** — disable access keys, revoke sessions, delete login profile.

11. **Review SCP (Service Control Policies)** — add an SCP to your AWS Organization that denies `cloudtrail:StopLogging` and `cloudtrail:DeleteTrail` for all principals except a break-glass role.

12. **Implement preventive controls** to ensure this cannot happen again:
    ```json
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Sid": "DenyCloudTrailTampering",
          "Effect": "Deny",
          "Action": [
            "cloudtrail:StopLogging",
            "cloudtrail:DeleteTrail",
            "cloudtrail:PutEventSelectors"
          ],
          "Resource": "*",
          "Condition": {
            "StringNotEquals": {
              "aws:PrincipalArn": "arn:aws:iam::123456789012:role/break-glass-admin"
            }
          }
        }
      ]
    }
    ```

13. **Document the incident** with the blind spot duration, estimated impact, and preventive controls implemented.

---

## Compliance References

| Framework | Requirement | How This Rule Helps |
|-----------|-------------|-------------------|
| PCI DSS | 10.2 — Implement automated audit trails | Detects attempts to disable the audit trail itself |
| PCI DSS | 10.5 — Secure audit trails so they cannot be altered | Alerts on trail modification or deletion |
| PCI DSS | 10.7 — Retain audit trail history | Detects events that would cause loss of audit history |
| SOC 2 | CC7.2 — Monitor system components for anomalies | Monitors the monitoring system for tampering |
| HIPAA | 164.312(b) — Audit controls | Detects disabling of audit mechanisms protecting ePHI |
| CIS AWS | 3.1–3.3 — CloudTrail is enabled and configured | Detects any change to CloudTrail configuration |

---

## Related Rules

- **LOG-002:** CloudTrail Trail Deleted — detects `DeleteTrail` specifically
- **LOG-003:** CloudTrail Configuration Changed — detects `UpdateTrail` and `PutEventSelectors`
- **LOG-004:** GuardDuty Detector Deleted — attackers often disable both logging and detection simultaneously
- **IAM-001:** Self-Escalation via Inline Policy — privilege escalation typically precedes logging tampering

---

## References

- [MITRE ATT&CK T1562.008 — Impair Defenses: Disable Cloud Logs](https://attack.mitre.org/techniques/T1562/008/)
- [AWS CloudTrail API Reference](https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/)
- [AWS Security Blog — Detecting CloudTrail Disruption](https://aws.amazon.com/blogs/security/)
- [CIS AWS Foundations Benchmark — Section 3: Logging](https://www.cisecurity.org/benchmark/amazon_web_services)
