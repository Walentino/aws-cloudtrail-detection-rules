# Compliance Mapping

This document maps detection rules to common compliance frameworks.

## Framework Coverage

| Framework | Requirements Covered |
|-----------|---------------------|
| PCI DSS 4.0 | 14 requirements |
| SOC 2 Type II | 8 criteria |
| HIPAA Security Rule | 6 standards |
| CIS AWS Foundations | 12 controls |

---

## PCI DSS 4.0

### Requirement 1: Network Security Controls

| Requirement | Description | Rules |
|-------------|-------------|-------|
| 1.2.1 | Restrict inbound/outbound traffic | SG-001, SG-002 |
| 1.3.1 | Restrict inbound traffic to CDE | SG-001, SG-002, SG-003 |

### Requirement 3: Protect Stored Account Data

| Requirement | Description | Rules |
|-------------|-------------|-------|
| 3.4.1 | Render PAN unreadable | ENCRYPT-001, ENCRYPT-002, ENCRYPT-003 |
| 3.5.1 | Protect cryptographic keys | ENCRYPT-001, ENCRYPT-002 |
| 3.6.1 | Key management procedures | ENCRYPT-001, ENCRYPT-002 |

### Requirement 7: Restrict Access

| Requirement | Description | Rules |
|-------------|-------------|-------|
| 7.1.1 | Access control policy | IAM-001, IAM-003 |
| 7.2.1 | Appropriate access based on need | IAM-001, IAM-002, IAM-003, IAM-004 |
| 7.2.2 | Assign access based on job function | EXFIL-001, EXFIL-002, EXFIL-003 |

### Requirement 8: Identify Users and Authenticate Access

| Requirement | Description | Rules |
|-------------|-------------|-------|
| 8.1.1 | User identification policy | IAM-002, IAM-005 |
| 8.2.1 | Unique user IDs | IAM-002 |
| 8.3.1 | Strong authentication | ACCESS-002, ACCESS-003 |
| 8.3.6 | MFA for all access | ACCESS-002 |

### Requirement 10: Log and Monitor All Access

| Requirement | Description | Rules |
|-------------|-------------|-------|
| 10.2.1 | Audit log implementation | LOG-001, LOG-002, LOG-003 |
| 10.3.1 | Protect audit trail | LOG-001, LOG-002, LOG-003 |
| 10.4.1 | Review logs daily | All rules enable this |
| 10.5.1 | Retain audit trail | LOG-001, LOG-002 |
| 10.6.1 | Review security events | All rules |

---

## SOC 2 Type II

### CC6 - Logical and Physical Access Controls

| Criteria | Description | Rules |
|----------|-------------|-------|
| CC6.1 | Logical access security | IAM-001, IAM-002, IAM-003, IAM-004, ACCESS-001, ACCESS-003, ENCRYPT-001 |
| CC6.2 | New access provisioning | IAM-002, IAM-005 |
| CC6.3 | Access removal | SG-003 |
| CC6.6 | Network security | SG-001, SG-002, SG-003 |
| CC6.8 | Unauthorized access prevention | ACCESS-004, ACCESS-005 |

### CC7 - System Operations

| Criteria | Description | Rules |
|----------|-------------|-------|
| CC7.2 | Security monitoring | LOG-001, LOG-002, LOG-003, LOG-004, All detection rules |
| CC7.3 | Evaluate security events | All detection rules |
| CC7.4 | Respond to security incidents | Response procedures in all rules |

### CC8 - Change Management

| Criteria | Description | Rules |
|----------|-------------|-------|
| CC8.1 | Infrastructure changes | All IAM rules, SG rules, LOG rules |

---

## HIPAA Security Rule

### § 164.312 Technical Safeguards

| Standard | Description | Rules |
|----------|-------------|-------|
| 164.312(a)(1) | Access Control | IAM-001, IAM-003, IAM-004, ACCESS-001, ACCESS-004 |
| 164.312(a)(2)(iv) | Encryption | ENCRYPT-001, ENCRYPT-002, ENCRYPT-003 |
| 164.312(b) | Audit Controls | LOG-001, LOG-002, LOG-003, LOG-004, ACCESS-005 |
| 164.312(d) | Person Authentication | ACCESS-002, IAM-002, IAM-005 |
| 164.312(e)(1) | Transmission Security | EXFIL-001, EXFIL-002, EXFIL-003, EXFIL-005, SG-001 |
| 164.312(e)(2)(ii) | Encryption | ENCRYPT-003 |

---

## CIS AWS Foundations Benchmark v2.0

### Section 1: Identity and Access Management

| Control | Description | Rules |
|---------|-------------|-------|
| 1.4 | Rotate access keys | IAM-002 |
| 1.7 | Eliminate root account use | ACCESS-001, ACCESS-003 |
| 1.10 | MFA for all users | ACCESS-002 |
| 1.16 | Attach policies to groups/roles | IAM-001, IAM-003, IAM-004 |

### Section 2: Storage

| Control | Description | Rules |
|---------|-------------|-------|
| 2.1.1 | S3 bucket encryption | ENCRYPT-003 |
| 2.1.5 | S3 bucket public access | EXFIL-001, EXFIL-002 |
| 2.2.1 | EBS encryption | EXFIL-003 |
| 2.3.1 | RDS encryption | EXFIL-005 |
| 2.8 | KMS key rotation | ENCRYPT-001, ENCRYPT-002 |

### Section 3: Logging

| Control | Description | Rules |
|---------|-------------|-------|
| 3.1 | CloudTrail enabled | LOG-001, LOG-002 |
| 3.2 | CloudTrail log validation | LOG-003 |
| 3.3 | S3 bucket logging | Related to EXFIL rules |

### Section 4: Monitoring

| Control | Description | Rules |
|---------|-------------|-------|
| 4.1-4.15 | CloudWatch alarms | All CloudWatch metric filters |
| 4.15 | GuardDuty enabled | LOG-004 |

### Section 5: Networking

| Control | Description | Rules |
|---------|-------------|-------|
| 5.1 | No 0.0.0.0/0 SSH | SG-001 |
| 5.2 | No 0.0.0.0/0 RDP | SG-001 |
| 5.4 | Default security group | SG-003 |

---

## Using This Mapping

### For Compliance Audits

When preparing for audits, use this mapping to demonstrate:

1. **Detection Coverage**: Show which controls have active detection
2. **Evidence of Monitoring**: Provide alert history and response records
3. **Control Effectiveness**: Demonstrate true positive/false positive ratios

### For Gap Analysis

Identify controls not yet covered by automated detection:

1. Review each framework section
2. Compare against deployed rules
3. Prioritize missing coverage based on risk

### For Security Programs

Use compliance requirements to prioritize:

1. Rules covering multiple frameworks = higher priority
2. Critical/High severity rules = implement first
3. Framework-specific requirements = tailor for your industry

---

## References

- [PCI DSS v4.0](https://www.pcisecuritystandards.org/)
- [SOC 2 Trust Services Criteria](https://www.aicpa.org/)
- [HIPAA Security Rule](https://www.hhs.gov/hipaa/)
- [CIS AWS Foundations Benchmark](https://www.cisecurity.org/benchmark/amazon_web_services)
