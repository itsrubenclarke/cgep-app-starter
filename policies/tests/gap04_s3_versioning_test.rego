# policies/tests/gap04_s3_versioning_test.rego
package compliance.gap04_test

import rego.v1
import data.compliance.gap04_s3_versioning

compliant_input := {
	"configuration": {"root_module": {"resources": [
		{"address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket", "name": "uploads", "expressions": {}},
		{
			"address": "aws_s3_bucket_versioning.uploads",
			"type": "aws_s3_bucket_versioning",
			"name": "uploads",
			"expressions": {"bucket": {"references": ["aws_s3_bucket.uploads.id"]}},
		},
	]}},
	"planned_values": {"root_module": {"resources": [{
		"address": "aws_s3_bucket_versioning.uploads",
		"values": {"versioning_configuration": [{"status": "Enabled"}]},
	}]}},
}

noncompliant_input := {"configuration": {"root_module": {"resources": [
	{"address": "aws_s3_bucket.uploads", "type": "aws_s3_bucket", "name": "uploads", "expressions": {}},
]}}}

test_compliant_passes if { count(gap04_s3_versioning.deny) == 0 with input as compliant_input }

test_removed_versioning_fails if {
	some msg in gap04_s3_versioning.deny with input as noncompliant_input
	contains(msg, "GAP-04")
}
