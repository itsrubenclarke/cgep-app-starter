# policies/tests/gap01_s3_kms_test.rego
package compliance.gap01_test

import rego.v1
import data.compliance.gap01_s3_kms

compliant_input := {
	"configuration": {"root_module": {"resources": [
		{"address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket", "name": "uploads", "expressions": {}},
		{
			"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
			"type": "aws_s3_bucket_server_side_encryption_configuration",
			"name": "uploads",
			"expressions": {"bucket": {"references": ["aws_s3_bucket.uploads.id"]}},
		},
	]}},
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
		"values": {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}]}]},
	}]}},
}

noncompliant_input := {
	"configuration": {"root_module": {"resources": [
		{"address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket", "name": "uploads", "expressions": {}},
		{
			"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
			"type": "aws_s3_bucket_server_side_encryption_configuration",
			"name": "uploads",
			"expressions": {"bucket": {"references": ["aws_s3_bucket.uploads.id"]}},
		},
	]}},
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_s3_bucket_server_side_encryption_configuration.uploads",
		"values": {"rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "AES256"}]}]},
	}]}},
}

missing_input := {"configuration": {"root_module": {"resources": [
	{"address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket", "name": "uploads", "expressions": {}},
]}}}

test_compliant_passes if { count(gap01_s3_kms.deny) == 0 with input as compliant_input }

test_reverted_to_aes256_fails if {
	some msg in gap01_s3_kms.deny with input as noncompliant_input
	contains(msg, "GAP-01")
}

test_missing_entirely_fails if {
	some msg in gap01_s3_kms.deny with input as missing_input
	contains(msg, "GAP-01")
}
