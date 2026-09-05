######################################################################
# KMS — customer-managed key for PHI at rest.
# Closes the "customer custody of keys" half of GAP-01 and GAP-02.
# Wired into the S3 bucket and DynamoDB table in hardening.tf.
######################################################################

data "aws_caller_identity" "current" {}

resource "aws_kms_key" "phi" {
  description             = "Customer-managed CMK for Acme Health PHI at rest (${local.name_prefix})"
  enable_key_rotation     = true
  deletion_window_in_days = 30

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnableIAMUserPermissions"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        # CloudWatch Logs needs its own key-policy grant to encrypt a log
        # group with this CMK - IAM permissions alone aren't enough for
        # this service, and it requires this specific EncryptionContext
        # condition. Added for the GAP-08 API Gateway access log group
        # (terraform/hardening.tf) to keep it on the same customer CMK as
        # the rest of the system rather than the AWS-managed default.
        Sid    = "AllowCloudWatchLogsEncryption"
        Effect = "Allow"
        Principal = {
          Service = "logs.${var.aws_region}.amazonaws.com"
        }
        Action = [
          "kms:Encrypt*",
          "kms:Decrypt*",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:Describe*"
        ]
        Resource = "*"
        Condition = {
          ArnLike = {
            "kms:EncryptionContext:aws:logs:arn" = "arn:aws:logs:${var.aws_region}:${data.aws_caller_identity.current.account_id}:log-group:*"
          }
        }
      }
    ]
  })
}

resource "aws_kms_alias" "phi" {
  name          = "alias/${local.name_prefix}-phi-${local.suffix}"
  target_key_id = aws_kms_key.phi.key_id
}
