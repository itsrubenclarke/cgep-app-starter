# policies/gap02_dynamodb_kms.rego
# METADATA
# title: SC.L2-3.13.11 - Cryptographic Protection (DynamoDB table CMK)
# description: "The submissions table must use a customer-managed KMS key, not the AWS-owned default (GAP-02)."
# custom:
#   control_id: SC.L2-3.13.11
#   framework: cmmc-l2
#   gap_id: GAP-02
#   severity: high
#   remediation: "Add a server_side_encryption { enabled = true, kms_key_arn = <your CMK arn> } block to the table."
package compliance.gap02_dynamodb_kms

import rego.v1

deny contains msg if {
	some r in input.planned_values.root_module.resources
	r.type == "aws_dynamodb_table"
	not has_cmk(r)
	msg := sprintf(
		"[SC.L2-3.13.11 / GAP-02] %s: no server_side_encryption block with a customer-managed kms_key_arn. Remediation: add server_side_encryption { enabled = true, kms_key_arn = ... }.",
		[r.address],
	)
}

has_cmk(r) if {
	sse := r.values.server_side_encryption
	count(sse) > 0
	sse[0].enabled == true
	sse[0].kms_key_arn != ""
	sse[0].kms_key_arn != null
}
