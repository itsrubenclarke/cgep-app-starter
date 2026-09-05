######################################################################
# Gap-closing overrides on the starter's existing resources.
# Each block below is scoped to one GAPS.md entry — see WRITEUP.md's
# Control coverage table for the CMMC control it maps to.
######################################################################

# GAP-01: SSE-S3 -> SSE-KMS with the customer CMK from kms.tf.
resource "aws_s3_bucket_server_side_encryption_configuration" "uploads" {
  bucket = aws_s3_bucket.uploads.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.phi.arn
    }
    bucket_key_enabled = true
  }
}

# GAP-02: DynamoDB SSE has no standalone resource type in the AWS provider —
# it's a nested block on aws_dynamodb_table itself, so this gap is closed
# directly on that resource in main.tf, not here. See main.tf's
# aws_dynamodb_table.intake for the server_side_encryption block.
#
# Follow-on for GAP-01/GAP-02: the key policy in kms.tf only says "IAM
# controls access to this key" — it doesn't grant anyone that access. The
# Lambda's execution role needs its own explicit grant to actually use the
# CMK, or every read/write through the app breaks (confirmed via
# `make test` after applying GAP-02: kms:Decrypt AccessDeniedException).
resource "aws_iam_role_policy" "lambda_kms" {
  name = "intake-kms-access"
  role = aws_iam_role.lambda.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["kms:Decrypt", "kms:GenerateDataKey"]
        Resource = aws_kms_key.phi.arn
      }
    ]
  })
}

# GAP-03: deny any request to the uploads bucket that isn't over TLS.
resource "aws_s3_bucket_policy" "uploads_tls_only" {
  bucket = aws_s3_bucket.uploads.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.uploads.arn,
          "${aws_s3_bucket.uploads.arn}/*"
        ]
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false"
          }
        }
      }
    ]
  })
}

# GAP-04: enable versioning so PHI overwrites/deletes are recoverable.
resource "aws_s3_bucket_versioning" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  versioning_configuration {
    status = "Enabled"
  }
}
