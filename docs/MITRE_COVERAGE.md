# MITRE ATT&CK for Cloud — Detection Coverage

This document maps every detection rule in this repository to the [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/), showing what is covered, what is partially covered, and where gaps remain.

Last updated: February 2026

---

## Coverage Summary

| Tactic | Techniques Covered | Total Known | Coverage | Status |
|--------|-------------------|-------------|----------|--------|
| Initial Access | 1 | 4 | 25% | Partial |
| Persistence | 2 | 5 | 40% | Partial |
| Privilege Escalation | 5 | 6 | 83% | Strong |
| Defense Evasion | 4 | 7 | 57% | Moderate |
| Credential Access | 2 | 4 | 50% | Moderate |
| Discovery | 0 | 5 | 0% | Roadmap |
| Lateral Movement | 0 | 3 | 0% | Roadmap |
| Collection | 0 | 2 | 0% | Roadmap |
| Exfiltration | 5 | 5 | 100% | Complete |
| Impact | 3 | 4 | 75% | Strong |

**Overall: 22 of 45 known cloud techniques covered (49%)**

---

## Detailed Coverage by Tactic

### Initial Access — 25% Coverage

| Technique | ID | Detected | Rule(s) | Notes |
|-----------|-----|----------|---------|-------|
| Valid Accounts: Cloud Accounts | T1078.004 | ✅ | AUTH-001, AUTH-002, AUTH-003 | Root login, console login without MFA |
| Trusted Relationship | T1199 | ⬚ | — | Roadmap: cross-account role trust abuse |
| Exploit Public-Facing Application | T1190 | ⬚ | — | Requires application-layer logging, out of CloudTrail scope |
| Phishing | T1566 | ⬚ | — | Requires email/identity provider logs, out of scope |

### Persistence — 40% Coverage

| Technique | ID | Detected | Rule(s) | Notes |
|-----------|-----|----------|---------|-------|
| Account Manipulation: Additional Cloud Credentials | T1098.001 | ✅ | IAM-002 | Cross-identity access key creation |
| Create Account: Cloud Account | T1136.003 | ✅ | IAM-005 | Console access creation for existing user |
| Account Manipulation: Additional Cloud Roles | T1098.003 | ⬚ | — | Roadmap: detect new role creation with trust to external accounts |
| Implant Internal Image | T1525 | ⬚ | — | Roadmap: detect modified AMI registration |
| Event Triggered Execution | T1546 | ⬚ | — | Roadmap: Lambda function creation as persistence mechanism |

### Privilege Escalation — 83% Coverage

| Technique | ID | Detected | Rule(s) | Notes |
|-----------|-----|----------|---------|-------|
| Account Manipulation: Additional Cloud Credentials | T1098.001 | ✅ | IAM-001, IAM-002, IAM-003, IAM-004 | Self-escalation, key creation, policy attachment, version escalation |
| Valid Accounts: Cloud Accounts | T1078.004 | ✅ | AUTH-001, AUTH-002, AUTH-003 | Compromised credential usage patterns |
| Abuse Elevation Control Mechanism | T1548 | ⬚ | — | Roadmap: detect STS token escalation via confused deputy |

**This is the strongest coverage area.** IAM privilege escalation is the #1 post-compromise technique in AWS breaches, and this library detects the specific API calls attackers use: PutUserPolicy, PutRolePolicy, CreateAccessKey, AttachUserPolicy, and CreatePolicyVersion.

### Defense Evasion — 57% Coverage

| Technique | ID | Detected | Rule(s) | Notes |
|-----------|-----|----------|---------|-------|
| Impair Defenses: Disable Cloud Logs | T1562.008 | ✅ | LOG-001, LOG-002, LOG-003 | StopLogging, DeleteTrail, PutEventSelectors |
| Impair Defenses: Disable Cloud Firewall | T1562.007 | ✅ | SG-001, SG-002, SG-003 | Security group modification and deletion |
| Impair Defenses: Disable or Modify Tools | T1562.001 | ✅ | LOG-004 | GuardDuty detector deletion |
| Modify Cloud Compute Infrastructure | T1578 | ⬚ | — | Roadmap: detect instance modification to evade monitoring |
| Unused/Unsupported Cloud Regions | T1535 | ⬚ | — | Roadmap: detect API activity in unusual regions |
| Modify Authentication Process | T1556 | ⬚ | — | Roadmap: detect SAML provider or identity pool modification |

### Credential Access — 50% Coverage

| Technique | ID | Detected | Rule(s) | Notes |
|-----------|-----|----------|---------|-------|
| Brute Force | T1110.001 | ✅ | AUTH-004 | Multiple failed console login attempts |
| Unsecured Credentials | T1552 | ✅ | AUTH-005 | Unauthorized API call patterns indicating credential testing |
| Steal Application Access Token | T1528 | ⬚ | — | Roadmap: detect unusual STS:AssumeRole frequency |
| Forge Web Credentials | T1606 | ⬚ | — | Requires identity provider logs, partially out of CloudTrail scope |

### Discovery — 0% Coverage (Roadmap)

| Technique | ID | Detected | Rule(s) | Notes |
|-----------|-----|----------|---------|-------|
| Cloud Infrastructure Discovery | T1580 | ⬚ | — | Planned: DescribeInstances, DescribeSecurityGroups enumeration |
| Cloud Service Discovery | T1526 | ⬚ | — | Planned: ListBuckets, ListFunctions, ListRoles enumeration |
| Account Discovery: Cloud Account | T1087.004 | ⬚ | — | Planned: ListUsers, GetAccountAuthorizationDetails |
| Cloud Service Dashboard | T1538 | ⬚ | — | Planned: Console access pattern analysis |
| Network Service Discovery | T1046 | ⬚ | — | Requires VPC Flow Logs, out of CloudTrail scope |

**Why this is zero:** Discovery events (DescribeInstances, ListBuckets) generate extremely high volumes in normal operations. Detection requires baselining and anomaly detection, not simple pattern matching. This is the most challenging tactic to detect via CloudTrail alone. Planned for a future release using frequency-based thresholds.

### Lateral Movement — 0% Coverage (Roadmap)

| Technique | ID | Detected | Rule(s) | Notes |
|-----------|-----|----------|---------|-------|
| Use Alternate Authentication Material | T1550 | ⬚ | — | Planned: cross-account AssumeRole chain detection |
| Internal Spearphishing | T1534 | ⬚ | — | Requires email/collaboration logs, out of scope |
| Taint Shared Content | T1080 | ⬚ | — | Planned: S3 object replacement in shared buckets |

**Why this is zero:** Lateral movement in AWS primarily occurs through cross-account role assumption chains. Detecting this requires correlating AssumeRole events across multiple accounts, which needs a centralized CloudTrail log aggregation strategy. Planned for a future release.

### Collection — 0% Coverage (Roadmap)

| Technique | ID | Detected | Rule(s) | Notes |
|-----------|-----|----------|---------|-------|
| Data from Cloud Storage | T1530 | ⬚ | — | Planned: anomalous S3 GetObject volume/patterns |
| Data Staged: Remote Data Staging | T1074.002 | ⬚ | — | Planned: detect data staging to attacker-controlled S3 |

### Exfiltration — 100% Coverage

| Technique | ID | Detected | Rule(s) | Notes |
|-----------|-----|----------|---------|-------|
| Transfer Data to Cloud Account | T1537 | ✅ | EXFIL-001, EXFIL-002, EXFIL-003, EXFIL-004, EXFIL-005 | S3 public access, EBS/AMI/RDS snapshot sharing |

**Complete coverage of the primary cloud exfiltration technique.** All five rules detect different methods attackers use to expose data: bucket policy changes, ACL modifications, EBS snapshot sharing to external accounts, AMI public sharing, and RDS snapshot sharing.

### Impact — 75% Coverage

| Technique | ID | Detected | Rule(s) | Notes |
|-----------|-----|----------|---------|-------|
| Data Destruction | T1485 | ✅ | ENC-001, ENC-002 | KMS key deletion and disabling |
| Data Encryption for Impact | T1486 | ✅ | ENC-003 | S3 bucket encryption removal (precursor to ransomware) |
| Resource Hijacking | T1496 | ⬚ | — | Roadmap: detect cryptomining via unusual EC2 instance launches |

---

## Coverage Gaps — Prioritized Roadmap

### High Priority (Next Release)

1. **Discovery: Cloud Infrastructure Enumeration** — DescribeInstances, DescribeSecurityGroups, ListBuckets frequency analysis. Most requested by practitioners.
2. **Lateral Movement: Cross-Account AssumeRole Chains** — Detect role assumption paths spanning 3+ accounts. Requires centralized logging.
3. **Impact: Resource Hijacking (Cryptomining)** — Detect RunInstances for GPU instance types from unusual principals.

### Medium Priority

4. **Defense Evasion: Unusual Region Activity** — API calls in regions not normally used by the organization.
5. **Persistence: Lambda as Backdoor** — CreateFunction or UpdateFunctionCode with external code sources.
6. **Credential Access: STS Token Abuse** — AssumeRole frequency analysis per principal.

### Lower Priority / Out of Scope

7. **Phishing / Internal Spearphishing** — Requires email and identity provider logs beyond CloudTrail.
8. **Network Service Discovery** — Requires VPC Flow Logs integration.
9. **Forge Web Credentials** — Requires SAML/OIDC provider logs.

---

## How to Read This Document

- **✅ Detected** — A detection rule exists in this repository for this technique.
- **⬚ Roadmap** — No detection exists yet. Notes explain why and when it is planned.
- **Rule IDs** reference the JSON files in the `rules/` directory.
- **Technique IDs** reference the [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/).
- Coverage percentages are based on CloudTrail-detectable techniques only. Some techniques require additional log sources (VPC Flow Logs, application logs, identity provider logs) and are noted as out of scope.

---

## References

- [MITRE ATT&CK Cloud Matrix](https://attack.mitre.org/matrices/enterprise/cloud/)
- [MITRE ATT&CK for AWS](https://attack.mitre.org/techniques/enterprise/)
- [AWS CloudTrail Event Reference](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference.html)
