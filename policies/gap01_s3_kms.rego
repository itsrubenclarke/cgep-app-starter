# policies/gap01_s3_kms.rego
# METADATA
# title: SC.L2-3.13.11 - Cryptographic Protection (S3 uploads bucket, SSE-KMS)
# description: "The uploads bucket must be encrypted with aws:kms, not the AWS-managed SSE-S3 default (GAP-01)."
# custom:
#   control_id: SC.L2-3.13.11
#   framework: cmmc-l2
#   gap_id: GAP-01
#   severity: high
#   remediation: "Add an aws_s3_bucket_server_side_encryption_configuration for the bucket with sse_algorithm = \"aws:kms\" and a kms_master_key_id."
package compliance.gap01_s3_kms

import rego.v1

deny contains msg if {
	bucket := bucket_addresses[_]
	not has_kms_encryption(bucket)
	msg := sprintf(
		"[SC.L2-3.13.11 / GAP-01] %s: no aws_s3_bucket_server_side_encryption_configuration using aws:kms. Remediation: add one referencing this bucket with sse_algorithm = \"aws:kms\".",
		[bucket],
	)
}

bucket_addresses contains addr if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket"
	addr := sprintf("aws_s3_bucket.%s", [r.name])
}

has_kms_encryption(bucket_addr) if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket_server_side_encryption_configuration"
	some ref in r.expressions.bucket.references
	references_bucket(ref, bucket_addr)
	sse_addr := sprintf("aws_s3_bucket_server_side_encryption_configuration.%s", [r.name])
	algorithm := planned_algorithm(sse_addr)
	algorithm == "aws:kms"
}

references_bucket(ref, bucket_addr) if ref == bucket_addr
references_bucket(ref, bucket_addr) if ref == sprintf("%s.id", [bucket_addr])
references_bucket(ref, bucket_addr) if ref == sprintf("%s.bucket", [bucket_addr])

planned_algorithm(addr) := algo if {
	some r in input.planned_values.root_module.resources
	r.address == addr
	algo := r.values.rule[0].apply_server_side_encryption_by_default[0].sse_algorithm
}
