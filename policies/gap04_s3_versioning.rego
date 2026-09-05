# policies/gap04_s3_versioning.rego
# METADATA
# title: MP.L2-3.8.9 - Protection of Backup CUI (S3 uploads bucket versioning)
# description: "The uploads bucket must have versioning enabled so PHI overwrites/deletes are recoverable (GAP-04)."
# custom:
#   control_id: MP.L2-3.8.9
#   framework: cmmc-l2
#   gap_id: GAP-04
#   severity: medium
#   remediation: "Add an aws_s3_bucket_versioning resource for the bucket with status = \"Enabled\"."
package compliance.gap04_s3_versioning

import rego.v1

deny contains msg if {
	bucket := bucket_addresses[_]
	not has_versioning(bucket)
	msg := sprintf(
		"[MP.L2-3.8.9 / GAP-04] %s: no aws_s3_bucket_versioning with status Enabled. Remediation: add one referencing this bucket.",
		[bucket],
	)
}

bucket_addresses contains addr if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket"
	addr := sprintf("aws_s3_bucket.%s", [r.name])
}

has_versioning(bucket_addr) if {
	some r in input.configuration.root_module.resources
	r.type == "aws_s3_bucket_versioning"
	some ref in r.expressions.bucket.references
	references_bucket(ref, bucket_addr)
	v_addr := sprintf("aws_s3_bucket_versioning.%s", [r.name])
	planned_status(v_addr) == "Enabled"
}

references_bucket(ref, bucket_addr) if ref == bucket_addr
references_bucket(ref, bucket_addr) if ref == sprintf("%s.id", [bucket_addr])
references_bucket(ref, bucket_addr) if ref == sprintf("%s.bucket", [bucket_addr])

planned_status(addr) := status if {
	some r in input.planned_values.root_module.resources
	r.address == addr
	status := r.values.versioning_configuration[0].status
}
