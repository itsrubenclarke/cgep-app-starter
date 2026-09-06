# policies/tests/gap07_lambda_least_priv_test.rego
package compliance.gap07_test

import rego.v1
import data.compliance.gap07_lambda_least_priv

compliant_input := {"planned_values": {"root_module": {"resources": [{
	"address": "aws_iam_role_policy.lambda_inline",
	"type": "aws_iam_role_policy",
	"values": {"policy": "{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"dynamodb:PutItem\",\"Resource\":\"arn:aws:dynamodb:x\"},{\"Effect\":\"Allow\",\"Action\":\"s3:PutObject\",\"Resource\":\"arn:aws:s3:::x/*\"}]}"},
}]}}}

noncompliant_input := {"planned_values": {"root_module": {"resources": [{
	"address": "aws_iam_role_policy.lambda_inline",
	"type": "aws_iam_role_policy",
	"values": {"policy": "{\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"dynamodb:*\",\"Resource\":\"arn:aws:dynamodb:x\"}]}"},
}]}}}

test_compliant_passes if { count(gap07_lambda_least_priv.deny) == 0 with input as compliant_input }

test_reverted_to_wildcard_fails if {
	some msg in gap07_lambda_least_priv.deny with input as noncompliant_input
	contains(msg, "GAP-07")
}
