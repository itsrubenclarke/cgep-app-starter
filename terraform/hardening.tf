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
