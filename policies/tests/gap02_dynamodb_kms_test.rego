# policies/tests/gap02_dynamodb_kms_test.rego
package compliance.gap02_test

import rego.v1
import data.compliance.gap02_dynamodb_kms

compliant_input := {"planned_values": {"root_module": {"resources": [{
	"address": "aws_dynamodb_table.intake",
	"type": "aws_dynamodb_table",
	"values": {"server_side_encryption": [{"enabled": true, "kms_key_arn": "arn:aws:kms:us-east-1:123:key/abc"}]},
}]}}}

noncompliant_input := {"planned_values": {"root_module": {"resources": [{
	"address": "aws_dynamodb_table.intake",
	"type": "aws_dynamodb_table",
	"values": {"server_side_encryption": []},
}]}}}

test_compliant_passes if { count(gap02_dynamodb_kms.deny) == 0 with input as compliant_input }

test_reverted_to_default_key_fails if {
	some msg in gap02_dynamodb_kms.deny with input as noncompliant_input
	contains(msg, "GAP-02")
}
