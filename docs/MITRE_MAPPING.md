# MITRE ATT&CK Mapping

This document maps all detection rules to the MITRE ATT&CK framework for Cloud.

## Coverage Summary

| Tactic | Techniques Covered | Rules |
|--------|-------------------|-------|
| Initial Access | T1078.004 | 3 |
| Persistence | T1098.001, T1136.003 | 3 |
| Privilege Escalation | T1098.001, T1078.004 | 5 |
| Defense Evasion | T1562.007, T1562.008 | 7 |
| Credential Access | T1110.001 | 1 |
| Discovery | T1580 | 1 |
| Exfiltration | T1537 | 5 |
| Impact | T1485, T1486 | 3 |

## Detailed Mapping

### Initial Access

#### T1078.004 - Valid Accounts: Cloud Accounts
Adversaries may obtain and abuse credentials of a cloud account as a means of gaining Initial Access.

| Rule ID | Rule Name | Detection |
|---------|-----------|-----------|
| ACCESS-001 | Root Account API Activity | Root account usage outside console login |
| ACCESS-002 | Console Login Without MFA | Successful login without second factor |
| ACCESS-003 | Root Console Login | Root account console access |

---

### Persistence

#### T1098.001 - Account Manipulation: Additional Cloud Credentials
Adversaries may add adversary-controlled credentials to gain persistence.

| Rule ID | Rule Name | Detection |
|---------|-----------|-----------|
| IAM-002 | Cross-Identity Access Key Creation | Creating keys for other users |
| IAM-005 | Console Access Created | Enabling console access for users |

#### T1136.003 - Create Account: Cloud Account
Adversaries may create a cloud account to maintain access.

| Rule ID | Rule Name | Detection |
|---------|-----------|-----------|
| IAM-005 | Console Access Created | New login profile creation |

---

### Privilege Escalation

#### T1098.001 - Account Manipulation: Additional Cloud Credentials
Adversaries may modify permissions to escalate privileges.

| Rule ID | Rule Name | Detection |
|---------|-----------|-----------|
| IAM-001 | Self-Escalation via Inline Policy | Self-attached wildcard policies |
| IAM-003 | Administrative Policy Attachment | Admin policy attachments |
| IAM-004 | Policy Version Escalation | Policy version manipulation |

#### T1078.004 - Valid Accounts: Cloud Accounts
Adversaries may use valid cloud accounts for privilege escalation.

| Rule ID | Rule Name | Detection |
|---------|-----------|-----------|
| ACCESS-001 | Root Account API Activity | Root account abuse |
| ACCESS-003 | Root Console Login | Root console access |

---

### Defense Evasion

#### T1562.007 - Impair Defenses: Disable or Modify Cloud Firewall
Adversaries may disable or modify cloud firewalls.

| Rule ID | Rule Name | Detection |
|---------|-----------|-----------|
| SG-001 | Security Group Open to Internet | Opening security groups |
| SG-002 | Security Group Allows All Traffic | Allowing all traffic |
| SG-003 | Security Group Deleted | Deleting security groups |

#### T1562.008 - Impair Defenses: Disable Cloud Logs
Adversaries may disable cloud logging to avoid detection.

| Rule ID | Rule Name | Detection |
|---------|-----------|-----------|
| LOG-001 | CloudTrail Logging Stopped | StopLogging API call |
| LOG-002 | CloudTrail Trail Deleted | DeleteTrail API call |
| LOG-003 | CloudTrail Configuration Changed | UpdateTrail API call |
| LOG-004 | GuardDuty Detector Deleted | DeleteDetector API call |

---

### Credential Access

#### T1110.001 - Brute Force: Password Guessing
Adversaries may attempt to guess passwords.

| Rule ID | Rule Name | Detection |
|---------|-----------|-----------|
| ACCESS-004 | Multiple Failed Login Attempts | Failed ConsoleLogin events |

---

### Discovery

#### T1580 - Cloud Infrastructure Discovery
Adversaries may attempt to discover cloud infrastructure.

| Rule ID | Rule Name | Detection |
|---------|-----------|-----------|
| ACCESS-005 | Unauthorized API Calls | Access denied errors |

---

### Exfiltration

#### T1537 - Transfer Data to Cloud Account
Adversaries may exfiltrate data to another cloud account.

| Rule ID | Rule Name | Detection |
|---------|-----------|-----------|
| EXFIL-001 | S3 Bucket Policy Allows Public Access | Public bucket policies |
| EXFIL-002 | S3 Bucket ACL Grants Public Access | Public bucket ACLs |
| EXFIL-003 | EBS Snapshot Shared Externally | Snapshot sharing |
| EXFIL-004 | AMI Shared Publicly | AMI sharing |
| EXFIL-005 | RDS Snapshot Shared | Database snapshot sharing |

---

### Impact

#### T1485 - Data Destruction
Adversaries may destroy data to disrupt availability.

| Rule ID | Rule Name | Detection |
|---------|-----------|-----------|
| ENCRYPT-001 | KMS Key Scheduled for Deletion | Key deletion scheduling |
| ENCRYPT-003 | S3 Bucket Encryption Removed | Encryption removal |

#### T1486 - Data Encrypted for Impact
Adversaries may encrypt data to impact availability (ransomware).

| Rule ID | Rule Name | Detection |
|---------|-----------|-----------|
| ENCRYPT-002 | KMS Key Disabled | Key disabling |

---

## References

- [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/)
- [MITRE ATT&CK for AWS](https://attack.mitre.org/matrices/enterprise/cloud/aws/)
- [AWS Security Reference Architecture](https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/)
