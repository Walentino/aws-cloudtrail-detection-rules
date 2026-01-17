# EventBridge Rules for AWS CloudTrail Detection
#
# Near real-time detection using EventBridge (seconds vs minutes with CloudWatch)
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

variable "sns_topic_arn" {
  description = "ARN of the SNS topic for security alerts"
  type        = string
}

variable "name_prefix" {
  description = "Prefix for EventBridge rule names"
  type        = string
  default     = "security-detection"
}

variable "tags" {
  description = "Tags to apply to all resources"
  type        = map(string)
  default     = {}
}

# -----------------------------------------------------------------------------
# LOCAL VARIABLES
# -----------------------------------------------------------------------------

locals {
  common_tags = merge(var.tags, {
    ManagedBy = "terraform"
    Purpose   = "security-detection"
  })
}

# -----------------------------------------------------------------------------
# EVENTBRIDGE RULES - Logging Tampering (Highest Priority)
# -----------------------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "cloudtrail_stopped" {
  name        = "${var.name_prefix}-cloudtrail-stopped"
  description = "CRITICAL: CloudTrail logging was stopped"

  event_pattern = jsonencode({
    source      = ["aws.cloudtrail"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["cloudtrail.amazonaws.com"]
      eventName   = ["StopLogging"]
    }
  })

  tags = local.common_tags
}

resource "aws_cloudwatch_event_rule" "cloudtrail_deleted" {
  name        = "${var.name_prefix}-cloudtrail-deleted"
  description = "CRITICAL: CloudTrail trail was deleted"

  event_pattern = jsonencode({
    source      = ["aws.cloudtrail"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["cloudtrail.amazonaws.com"]
      eventName   = ["DeleteTrail"]
    }
  })

  tags = local.common_tags
}

resource "aws_cloudwatch_event_rule" "guardduty_deleted" {
  name        = "${var.name_prefix}-guardduty-deleted"
  description = "CRITICAL: GuardDuty detector was deleted"

  event_pattern = jsonencode({
    source      = ["aws.cloudtrail"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["guardduty.amazonaws.com"]
      eventName   = ["DeleteDetector"]
    }
  })

  tags = local.common_tags
}

# -----------------------------------------------------------------------------
# EVENTBRIDGE RULES - IAM Privilege Escalation
# -----------------------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "iam_admin_policy" {
  name        = "${var.name_prefix}-iam-admin-policy"
  description = "CRITICAL: Administrative policy attached to principal"

  event_pattern = jsonencode({
    source      = ["aws.cloudtrail"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["iam.amazonaws.com"]
      eventName   = ["AttachUserPolicy", "AttachRolePolicy", "AttachGroupPolicy"]
    }
  })

  tags = local.common_tags
}

resource "aws_cloudwatch_event_rule" "iam_inline_policy" {
  name        = "${var.name_prefix}-iam-inline-policy"
  description = "HIGH: Inline policy created on principal"

  event_pattern = jsonencode({
    source      = ["aws.cloudtrail"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["iam.amazonaws.com"]
      eventName   = ["PutUserPolicy", "PutRolePolicy", "PutGroupPolicy"]
    }
  })

  tags = local.common_tags
}

resource "aws_cloudwatch_event_rule" "iam_access_key" {
  name        = "${var.name_prefix}-iam-access-key"
  description = "HIGH: IAM access key created"

  event_pattern = jsonencode({
    source      = ["aws.cloudtrail"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["iam.amazonaws.com"]
      eventName   = ["CreateAccessKey"]
    }
  })

  tags = local.common_tags
}

# -----------------------------------------------------------------------------
# EVENTBRIDGE RULES - Root Account
# -----------------------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "root_activity" {
  name        = "${var.name_prefix}-root-activity"
  description = "HIGH: Root account API activity detected"

  event_pattern = jsonencode({
    source      = ["aws.cloudtrail"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      userIdentity = {
        type = ["Root"]
      }
    }
  })

  tags = local.common_tags
}

resource "aws_cloudwatch_event_rule" "root_login" {
  name        = "${var.name_prefix}-root-login"
  description = "HIGH: Root account console login"

  event_pattern = jsonencode({
    source      = ["aws.signin"]
    detail-type = ["AWS Console Sign In via CloudTrail"]
    detail = {
      userIdentity = {
        type = ["Root"]
      }
    }
  })

  tags = local.common_tags
}

# -----------------------------------------------------------------------------
# EVENTBRIDGE RULES - Data Exfiltration
# -----------------------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "s3_public" {
  name        = "${var.name_prefix}-s3-public-access"
  description = "CRITICAL: S3 bucket policy or ACL modified"

  event_pattern = jsonencode({
    source      = ["aws.cloudtrail"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["s3.amazonaws.com"]
      eventName   = ["PutBucketPolicy", "PutBucketAcl", "DeleteBucketPolicy"]
    }
  })

  tags = local.common_tags
}

resource "aws_cloudwatch_event_rule" "snapshot_shared" {
  name        = "${var.name_prefix}-snapshot-shared"
  description = "CRITICAL: EBS or RDS snapshot sharing modified"

  event_pattern = jsonencode({
    source      = ["aws.cloudtrail"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventName = ["ModifySnapshotAttribute", "ModifyDBSnapshotAttribute", "ModifyDBClusterSnapshotAttribute", "ModifyImageAttribute"]
    }
  })

  tags = local.common_tags
}

# -----------------------------------------------------------------------------
# EVENTBRIDGE RULES - Encryption
# -----------------------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "kms_key_deletion" {
  name        = "${var.name_prefix}-kms-deletion"
  description = "CRITICAL: KMS key scheduled for deletion or disabled"

  event_pattern = jsonencode({
    source      = ["aws.cloudtrail"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["kms.amazonaws.com"]
      eventName   = ["ScheduleKeyDeletion", "DisableKey"]
    }
  })

  tags = local.common_tags
}

# -----------------------------------------------------------------------------
# EVENTBRIDGE RULES - Security Groups
# -----------------------------------------------------------------------------

resource "aws_cloudwatch_event_rule" "security_group_change" {
  name        = "${var.name_prefix}-security-group-change"
  description = "HIGH: Security group ingress rule modified"

  event_pattern = jsonencode({
    source      = ["aws.cloudtrail"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["ec2.amazonaws.com"]
      eventName   = ["AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress"]
    }
  })

  tags = local.common_tags
}

# -----------------------------------------------------------------------------
# SNS TARGETS
# -----------------------------------------------------------------------------

resource "aws_cloudwatch_event_target" "cloudtrail_stopped" {
  rule      = aws_cloudwatch_event_rule.cloudtrail_stopped.name
  target_id = "send-to-sns"
  arn       = var.sns_topic_arn

  input_transformer {
    input_paths = {
      account   = "$.detail.userIdentity.accountId"
      user      = "$.detail.userIdentity.userName"
      event     = "$.detail.eventName"
      source_ip = "$.detail.sourceIPAddress"
      time      = "$.detail.eventTime"
      trail     = "$.detail.requestParameters.name"
    }
    input_template = "\"🚨 CRITICAL: CloudTrail Logging Stopped\\n\\nAccount: <account>\\nUser: <user>\\nTrail: <trail>\\nSource IP: <source_ip>\\nTime: <time>\\n\\nImmediate investigation required. Attacker may be covering tracks.\""
  }
}

resource "aws_cloudwatch_event_target" "cloudtrail_deleted" {
  rule      = aws_cloudwatch_event_rule.cloudtrail_deleted.name
  target_id = "send-to-sns"
  arn       = var.sns_topic_arn

  input_transformer {
    input_paths = {
      account   = "$.detail.userIdentity.accountId"
      user      = "$.detail.userIdentity.userName"
      source_ip = "$.detail.sourceIPAddress"
      time      = "$.detail.eventTime"
    }
    input_template = "\"🚨 CRITICAL: CloudTrail Trail Deleted\\n\\nAccount: <account>\\nUser: <user>\\nSource IP: <source_ip>\\nTime: <time>\\n\\nImmediate investigation required.\""
  }
}

resource "aws_cloudwatch_event_target" "guardduty_deleted" {
  rule      = aws_cloudwatch_event_rule.guardduty_deleted.name
  target_id = "send-to-sns"
  arn       = var.sns_topic_arn

  input_transformer {
    input_paths = {
      account   = "$.detail.userIdentity.accountId"
      user      = "$.detail.userIdentity.userName"
      source_ip = "$.detail.sourceIPAddress"
      time      = "$.detail.eventTime"
    }
    input_template = "\"🚨 CRITICAL: GuardDuty Detector Deleted\\n\\nAccount: <account>\\nUser: <user>\\nSource IP: <source_ip>\\nTime: <time>\\n\\nThreat detection disabled. Immediate investigation required.\""
  }
}

resource "aws_cloudwatch_event_target" "iam_admin_policy" {
  rule      = aws_cloudwatch_event_rule.iam_admin_policy.name
  target_id = "send-to-sns"
  arn       = var.sns_topic_arn

  input_transformer {
    input_paths = {
      account    = "$.detail.userIdentity.accountId"
      user       = "$.detail.userIdentity.userName"
      event      = "$.detail.eventName"
      source_ip  = "$.detail.sourceIPAddress"
      time       = "$.detail.eventTime"
      policy_arn = "$.detail.requestParameters.policyArn"
    }
    input_template = "\"⚠️ HIGH: IAM Policy Attached\\n\\nAccount: <account>\\nActor: <user>\\nAction: <event>\\nPolicy: <policy_arn>\\nSource IP: <source_ip>\\nTime: <time>\""
  }
}

resource "aws_cloudwatch_event_target" "root_activity" {
  rule      = aws_cloudwatch_event_rule.root_activity.name
  target_id = "send-to-sns"
  arn       = var.sns_topic_arn

  input_transformer {
    input_paths = {
      account   = "$.detail.userIdentity.accountId"
      event     = "$.detail.eventName"
      source_ip = "$.detail.sourceIPAddress"
      time      = "$.detail.eventTime"
    }
    input_template = "\"⚠️ HIGH: Root Account Activity\\n\\nAccount: <account>\\nAction: <event>\\nSource IP: <source_ip>\\nTime: <time>\\n\\nRoot account usage should be extremely rare.\""
  }
}

resource "aws_cloudwatch_event_target" "s3_public" {
  rule      = aws_cloudwatch_event_rule.s3_public.name
  target_id = "send-to-sns"
  arn       = var.sns_topic_arn

  input_transformer {
    input_paths = {
      account   = "$.detail.userIdentity.accountId"
      user      = "$.detail.userIdentity.userName"
      event     = "$.detail.eventName"
      bucket    = "$.detail.requestParameters.bucketName"
      source_ip = "$.detail.sourceIPAddress"
      time      = "$.detail.eventTime"
    }
    input_template = "\"🚨 CRITICAL: S3 Bucket Access Modified\\n\\nAccount: <account>\\nActor: <user>\\nAction: <event>\\nBucket: <bucket>\\nSource IP: <source_ip>\\nTime: <time>\\n\\nCheck for public access configuration.\""
  }
}

resource "aws_cloudwatch_event_target" "kms_deletion" {
  rule      = aws_cloudwatch_event_rule.kms_key_deletion.name
  target_id = "send-to-sns"
  arn       = var.sns_topic_arn

  input_transformer {
    input_paths = {
      account   = "$.detail.userIdentity.accountId"
      user      = "$.detail.userIdentity.userName"
      event     = "$.detail.eventName"
      key_id    = "$.detail.requestParameters.keyId"
      source_ip = "$.detail.sourceIPAddress"
      time      = "$.detail.eventTime"
    }
    input_template = "\"🚨 CRITICAL: KMS Key Modified\\n\\nAccount: <account>\\nActor: <user>\\nAction: <event>\\nKey ID: <key_id>\\nSource IP: <source_ip>\\nTime: <time>\\n\\nData encrypted with this key may become inaccessible.\""
  }
}

# -----------------------------------------------------------------------------
# SNS TOPIC POLICY (Allow EventBridge to publish)
# -----------------------------------------------------------------------------

data "aws_iam_policy_document" "sns_topic_policy" {
  statement {
    sid    = "AllowEventBridgePublish"
    effect = "Allow"
    
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    
    actions   = ["sns:Publish"]
    resources = [var.sns_topic_arn]
  }
}

# -----------------------------------------------------------------------------
# OUTPUTS
# -----------------------------------------------------------------------------

output "eventbridge_rule_arns" {
  description = "ARNs of created EventBridge rules"
  value = [
    aws_cloudwatch_event_rule.cloudtrail_stopped.arn,
    aws_cloudwatch_event_rule.cloudtrail_deleted.arn,
    aws_cloudwatch_event_rule.guardduty_deleted.arn,
    aws_cloudwatch_event_rule.iam_admin_policy.arn,
    aws_cloudwatch_event_rule.iam_inline_policy.arn,
    aws_cloudwatch_event_rule.iam_access_key.arn,
    aws_cloudwatch_event_rule.root_activity.arn,
    aws_cloudwatch_event_rule.root_login.arn,
    aws_cloudwatch_event_rule.s3_public.arn,
    aws_cloudwatch_event_rule.snapshot_shared.arn,
    aws_cloudwatch_event_rule.kms_key_deletion.arn,
    aws_cloudwatch_event_rule.security_group_change.arn,
  ]
}

output "rule_count" {
  description = "Number of EventBridge rules created"
  value       = 12
}
