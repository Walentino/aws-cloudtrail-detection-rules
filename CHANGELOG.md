# Changelog

All notable changes to this project will be documented in this file.

## [1.1.0] — 2026-02-11

### Added
- Architecture diagram (Mermaid) in README showing both CloudWatch and EventBridge deployment paths
- "Why These Rules Exist" business impact section with audit-readiness and compliance value messaging
- MITRE ATT&CK coverage matrix (docs/MITRE_COVERAGE.md) — 22 of 45 cloud techniques covered, with gap analysis and prioritized roadmap
- Deep-dive documentation for three critical detection rules:
  - IAM-001: Self-Escalation via Inline Policy (docs/IAM-001-privilege-escalation.md)
  - LOG-001: CloudTrail Logging Stopped (docs/LOG-001-cloudtrail-tamper.md)
  - EXFIL-001: S3 Bucket Policy Allows Public Access (docs/EXFIL-001-s3-data-exposure.md)
- Each deep-dive includes: attack scenario, CloudTrail evidence, detection logic (CloudWatch + EventBridge + Lambda), false positive guidance, response playbook, and compliance references
- Roadmap section in README with planned work items
- Prerequisites section under Quick Start
- CHANGELOG.md

### Changed
- Restructured README section order: Architecture → Why → Coverage → Quick Start → Categories → Compliance → Tuning → Deployment → Roadmap
- Updated Author section: title changed from "Detection Engineer" to "Cloud Security Engineer"
- Added SignalRoot portfolio link to Author section
- Detection Coverage table now links to deep-dive docs for IAM, Logging, and Exfiltration categories

## [1.0.0] — 2025-02-11

### Added
- Initial release: 25 detection rules across 6 categories
- IAM Privilege Escalation (5 rules)
- Unusual Access Patterns (5 rules)
- Data Exfiltration (5 rules)
- Security Group Changes (3 rules)
- Encryption Changes (3 rules)
- Logging Tampering (4 rules)
- CloudWatch Metric Filter deployment via Terraform
- EventBridge Rules deployment via Terraform
- Compliance mapping: PCI DSS, SOC 2, HIPAA, CIS AWS Foundations
- Tuning guidance for all rule categories
- MIT License
