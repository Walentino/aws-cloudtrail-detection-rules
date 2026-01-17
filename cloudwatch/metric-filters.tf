# CloudWatch Metric Filters for AWS CloudTrail Detection Rules
# 
# This Terraform configuration deploys all 25 detection rules as CloudWatch
# Metric Filters with associated alarms and SNS notifications.
#
# Author: Adewale Odeja (https://linkedin.com/in/adewaleodeja)
# Repository: https://github.com/Walentino/aws-cloudtrail-detection-rules

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# -----------------------------------------------------------------------------
# VARIABLES
# -----------------------------------------------------------------------------

variable "cloudtrail_log_group_name" {
  description = "Name of the CloudWatch Log Group receiving CloudTrail events"
  type        = string
}

variable "sns_topic_arn" {
  description = "ARN of the SNS topic for security alerts"
  type        = string
}

variable "alarm_namespace" {
  description = "CloudWatch namespace for security metrics"
  type        = string
  default     = "SecurityDetections"
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}

# -----------------------------------------------------------------------------
# LOCAL VARIABLES - Detection Rule Definitions
# -----------------------------------------------------------------------------

locals {
  common_tags = merge(var.tags, {
    ManagedBy = "terraform"
    Purpose   = "security-detection"
  })

  # All 25 detection rules
  detection_rules = {
    # IAM Privilege Escalation (5 rules)
    iam_self_escalation = {
      name        = "IAM-001-Self-Escalation-Inline-Policy"
      description = "Detects self-attached inline policies with wildcard permissions"
      pattern     = "{ ($.eventSource = \"iam.amazonaws.com\") && (($.eventName = \"PutUserPolicy\") || ($.eventName = \"PutRolePolicy\")) }"
      severity    = "CRITICAL"
    }
    iam_cross_identity_key = {
      name        = "IAM-002-Cross-Identity-Access-Key"
      description = "Detects access key creation for different users"
      pattern     = "{ ($.eventSource = \"iam.amazonaws.com\") && ($.eventName = \"CreateAccessKey\") }"
      severity    = "HIGH"
    }
    iam_admin_policy_attach = {
      name        = "IAM-003-Admin-Policy-Attachment"
      description = "Detects administrative policy attachments"
      pattern     = "{ ($.eventSource = \"iam.amazonaws.com\") && (($.eventName = \"AttachUserPolicy\") || ($.eventName = \"AttachRolePolicy\") || ($.eventName = \"AttachGroupPolicy\")) }"
      severity    = "CRITICAL"
    }
    iam_policy_version = {
      name        = "IAM-004-Policy-Version-Escalation"
      description = "Detects new policy versions set as default"
      pattern     = "{ ($.eventSource = \"iam.amazonaws.com\") && ($.eventName = \"CreatePolicyVersion\") }"
      severity    = "HIGH"
    }
    iam_console_access = {
      name        = "IAM-005-Console-Access-Created"
      description = "Detects console access enabled for users"
      pattern     = "{ ($.eventSource = \"iam.amazonaws.com\") && ($.eventName = \"CreateLoginProfile\") }"
      severity    = "MEDIUM"
    }

    # Unusual Access Patterns (5 rules)
    access_root_api = {
      name        = "ACCESS-001-Root-Account-API-Activity"
      description = "Detects root account API calls"
      pattern     = "{ ($.userIdentity.type = \"Root\") && ($.eventName != \"ConsoleLogin\") }"
      severity    = "HIGH"
    }
    access_no_mfa = {
      name        = "ACCESS-002-Console-Login-Without-MFA"
      description = "Detects console logins without MFA"
      pattern     = "{ ($.eventSource = \"signin.amazonaws.com\") && ($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed = \"No\") && ($.responseElements.ConsoleLogin = \"Success\") }"
      severity    = "HIGH"
    }
    access_root_login = {
      name        = "ACCESS-003-Root-Console-Login"
      description = "Detects root account console logins"
      pattern     = "{ ($.eventSource = \"signin.amazonaws.com\") && ($.eventName = \"ConsoleLogin\") && ($.userIdentity.type = \"Root\") }"
      severity    = "HIGH"
    }
    access_failed_logins = {
      name        = "ACCESS-004-Multiple-Failed-Logins"
      description = "Detects failed console login attempts"
      pattern     = "{ ($.eventSource = \"signin.amazonaws.com\") && ($.eventName = \"ConsoleLogin\") && ($.responseElements.ConsoleLogin = \"Failure\") }"
      severity    = "HIGH"
    }
    access_denied = {
      name        = "ACCESS-005-Unauthorized-API-Calls"
      description = "Detects access denied errors"
      pattern     = "{ ($.errorCode = \"*UnauthorizedAccess*\") || ($.errorCode = \"AccessDenied*\") }"
      severity    = "MEDIUM"
    }

    # Data Exfiltration (5 rules)
    exfil_s3_public_policy = {
      name        = "EXFIL-001-S3-Public-Bucket-Policy"
      description = "Detects S3 bucket policies allowing public access"
      pattern     = "{ ($.eventSource = \"s3.amazonaws.com\") && ($.eventName = \"PutBucketPolicy\") }"
      severity    = "CRITICAL"
    }
    exfil_s3_public_acl = {
      name        = "EXFIL-002-S3-Public-Bucket-ACL"
      description = "Detects S3 bucket ACLs granting public access"
      pattern     = "{ ($.eventSource = \"s3.amazonaws.com\") && ($.eventName = \"PutBucketAcl\") }"
      severity    = "CRITICAL"
    }
    exfil_ebs_snapshot = {
      name        = "EXFIL-003-EBS-Snapshot-Shared"
      description = "Detects EBS snapshots shared externally"
      pattern     = "{ ($.eventSource = \"ec2.amazonaws.com\") && ($.eventName = \"ModifySnapshotAttribute\") }"
      severity    = "CRITICAL"
    }
    exfil_ami_shared = {
      name        = "EXFIL-004-AMI-Shared"
      description = "Detects AMIs shared publicly or externally"
      pattern     = "{ ($.eventSource = \"ec2.amazonaws.com\") && ($.eventName = \"ModifyImageAttribute\") }"
      severity    = "HIGH"
    }
    exfil_rds_snapshot = {
      name        = "EXFIL-005-RDS-Snapshot-Shared"
      description = "Detects RDS snapshots shared externally"
      pattern     = "{ ($.eventSource = \"rds.amazonaws.com\") && (($.eventName = \"ModifyDBSnapshotAttribute\") || ($.eventName = \"ModifyDBClusterSnapshotAttribute\")) }"
      severity    = "CRITICAL"
    }

    # Security Group Changes (3 rules)
    sg_open_sensitive = {
      name        = "SG-001-Security-Group-Open-Internet"
      description = "Detects security group ingress rules added"
      pattern     = "{ ($.eventSource = \"ec2.amazonaws.com\") && ($.eventName = \"AuthorizeSecurityGroupIngress\") }"
      severity    = "CRITICAL"
    }
    sg_all_traffic = {
      name        = "SG-002-Security-Group-All-Traffic"
      description = "Detects security group allowing all traffic"
      pattern     = "{ ($.eventSource = \"ec2.amazonaws.com\") && ($.eventName = \"AuthorizeSecurityGroupIngress\") }"
      severity    = "CRITICAL"
    }
    sg_deleted = {
      name        = "SG-003-Security-Group-Deleted"
      description = "Detects security group deletion"
      pattern     = "{ ($.eventSource = \"ec2.amazonaws.com\") && ($.eventName = \"DeleteSecurityGroup\") }"
      severity    = "MEDIUM"
    }

    # Encryption Changes (3 rules)
    encrypt_kms_deletion = {
      name        = "ENCRYPT-001-KMS-Key-Deletion-Scheduled"
      description = "Detects KMS key scheduled for deletion"
      pattern     = "{ ($.eventSource = \"kms.amazonaws.com\") && ($.eventName = \"ScheduleKeyDeletion\") }"
      severity    = "CRITICAL"
    }
    encrypt_kms_disabled = {
      name        = "ENCRYPT-002-KMS-Key-Disabled"
      description = "Detects KMS key disabled"
      pattern     = "{ ($.eventSource = \"kms.amazonaws.com\") && ($.eventName = \"DisableKey\") }"
      severity    = "HIGH"
    }
    encrypt_s3_removed = {
      name        = "ENCRYPT-003-S3-Encryption-Removed"
      description = "Detects S3 bucket encryption removed"
      pattern     = "{ ($.eventSource = \"s3.amazonaws.com\") && ($.eventName = \"DeleteBucketEncryption\") }"
      severity    = "HIGH"
    }

    # Logging Tampering (4 rules)
    log_cloudtrail_stopped = {
      name        = "LOG-001-CloudTrail-Logging-Stopped"
      description = "Detects CloudTrail logging stopped"
      pattern     = "{ ($.eventSource = \"cloudtrail.amazonaws.com\") && ($.eventName = \"StopLogging\") }"
      severity    = "CRITICAL"
    }
    log_cloudtrail_deleted = {
      name        = "LOG-002-CloudTrail-Trail-Deleted"
      description = "Detects CloudTrail trail deletion"
      pattern     = "{ ($.eventSource = \"cloudtrail.amazonaws.com\") && ($.eventName = \"DeleteTrail\") }"
      severity    = "CRITICAL"
    }
    log_cloudtrail_modified = {
      name        = "LOG-003-CloudTrail-Configuration-Changed"
      description = "Detects CloudTrail configuration changes"
      pattern     = "{ ($.eventSource = \"cloudtrail.amazonaws.com\") && ($.eventName = \"UpdateTrail\") }"
      severity    = "HIGH"
    }
    log_guardduty_deleted = {
      name        = "LOG-004-GuardDuty-Detector-Deleted"
      description = "Detects GuardDuty detector deletion"
      pattern     = "{ ($.eventSource = \"guardduty.amazonaws.com\") && ($.eventName = \"DeleteDetector\") }"
      severity    = "CRITICAL"
    }
  }
}

# -----------------------------------------------------------------------------
# METRIC FILTERS
# -----------------------------------------------------------------------------

resource "aws_cloudwatch_log_metric_filter" "detection_rules" {
  for_each = local.detection_rules

  name           = each.value.name
  log_group_name = var.cloudtrail_log_group_name
  pattern        = each.value.pattern

  metric_transformation {
    name          = replace(each.value.name, "-", "")
    namespace     = var.alarm_namespace
    value         = "1"
    default_value = "0"
  }
}

# -----------------------------------------------------------------------------
# CLOUDWATCH ALARMS
# -----------------------------------------------------------------------------

resource "aws_cloudwatch_metric_alarm" "detection_rules" {
  for_each = local.detection_rules

  alarm_name          = each.value.name
  alarm_description   = "${each.value.severity}: ${each.value.description}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = replace(each.value.name, "-", "")
  namespace           = var.alarm_namespace
  period              = 60
  statistic           = "Sum"
  threshold           = 0
  treat_missing_data  = "notBreaching"

  alarm_actions = [var.sns_topic_arn]
  ok_actions    = []

  tags = merge(local.common_tags, {
    Severity = each.value.severity
    RuleID   = each.key
  })
}

# -----------------------------------------------------------------------------
# OUTPUTS
# -----------------------------------------------------------------------------

output "metric_filter_names" {
  description = "Names of all created metric filters"
  value       = [for k, v in aws_cloudwatch_log_metric_filter.detection_rules : v.name]
}

output "alarm_arns" {
  description = "ARNs of all created alarms"
  value       = [for k, v in aws_cloudwatch_metric_alarm.detection_rules : v.arn]
}

output "rule_count" {
  description = "Total number of detection rules deployed"
  value       = length(local.detection_rules)
}

output "rules_by_severity" {
  description = "Count of rules by severity level"
  value = {
    CRITICAL = length([for k, v in local.detection_rules : k if v.severity == "CRITICAL"])
    HIGH     = length([for k, v in local.detection_rules : k if v.severity == "HIGH"])
    MEDIUM   = length([for k, v in local.detection_rules : k if v.severity == "MEDIUM"])
  }
}
