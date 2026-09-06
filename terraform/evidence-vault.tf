######################################################################
# Evidence vault — Object Lock S3 bucket for signed pipeline artifacts.
# Adapted from Lab 2.5's evidence-vault primitive, repointed at this
# repo's naming convention (local.name_prefix / local.suffix) and this
# CMK instead of AES256.
#
# Lock mode: GOVERNANCE, not COMPLIANCE. COMPLIANCE means nobody, not
# even the account root, can delete evidence before retention expires -
# the strongest possible tamper-resistance claim, but it also means this
# bucket can never be cleaned up or torn down during the capstone.
# GOVERNANCE still blocks deletion for everyone except a caller explicitly
# granted s3:BypassGovernanceRetention, which keeps the tamper-resistance
# claim credible while leaving room to iterate over 30 days. Documented
# as the deliberate trade-off the brief asks for (tamper-resistance vs.
# operational flexibility), not a default left unexamined.
#
# Retention: 365 days. Evidence needs to outlive a typical audit cycle;
# a year is the defensible floor for that, not an arbitrary number.
#
# Encryption: this CMK (aws_kms_key.phi), not AES256 like the Lab 2.5
# primitive used - keeps the vault on the same customer-controlled-key
# footing as the rest of this system's PHI-adjacent data (GAP-01/02).
# Learned pattern from GAP-01/02/06/08: whatever writes to this vault
# later (the pipeline's signing/upload step) will need its own explicit
# kms:Decrypt / kms:GenerateDataKey grant on this key - IAM permissions
# alone won't get it there. Wire that up when oidc-trust.tf and the
# pipeline are built.
######################################################################

resource "aws_s3_bucket" "evidence_vault" {
  bucket              = "${local.name_prefix}-evidence-vault-${local.suffix}"
  object_lock_enabled = true
}

resource "aws_s3_bucket_versioning" "evidence_vault" {
  bucket = aws_s3_bucket.evidence_vault.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "evidence_vault" {
  bucket = aws_s3_bucket.evidence_vault.id

  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = 365
    }
  }

  depends_on = [aws_s3_bucket_versioning.evidence_vault]
}

resource "aws_s3_bucket_server_side_encryption_configuration" "evidence_vault" {
  bucket = aws_s3_bucket.evidence_vault.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.phi.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "evidence_vault" {
  bucket                  = aws_s3_bucket.evidence_vault.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Belt-and-braces on top of Object Lock: deny bucket deletion from anyone
# except the account root, regardless of lock mode.
resource "aws_s3_bucket_policy" "evidence_vault" {
  bucket = aws_s3_bucket.evidence_vault.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyBucketDeletion"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:DeleteBucket"
        Resource  = aws_s3_bucket.evidence_vault.arn
        Condition = {
          StringNotEquals = {
            "aws:PrincipalArn" = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
          }
        }
      }
    ]
  })
}
