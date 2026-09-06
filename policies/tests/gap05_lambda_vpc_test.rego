# policies/tests/gap05_lambda_vpc_test.rego
package compliance.gap05_test

import rego.v1
import data.compliance.gap05_lambda_vpc

compliant_input := {"configuration": {"root_module": {"resources": [{
	"address": "aws_lambda_function.intake",
	"type": "aws_lambda_function",
	"name": "intake",
	"expressions": {"vpc_config": [{"subnet_ids": {"references": ["aws_subnet.private"]}}]},
}]}}}

noncompliant_input := {"configuration": {"root_module": {"resources": [{
	"address": "aws_lambda_function.intake",
	"type": "aws_lambda_function",
	"name": "intake",
	"expressions": {},
}]}}}

test_compliant_passes if { count(gap05_lambda_vpc.deny) == 0 with input as compliant_input }

test_removed_vpc_config_fails if {
	some msg in gap05_lambda_vpc.deny with input as noncompliant_input
	contains(msg, "GAP-05")
}
