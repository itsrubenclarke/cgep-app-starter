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
      }
    ]
  })
}

resource "aws_kms_alias" "phi" {
  name          = "alias/${local.name_prefix}-phi-${local.suffix}"
  target_key_id = aws_kms_key.phi.key_id
}
