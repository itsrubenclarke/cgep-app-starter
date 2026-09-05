# policies/tests/gap08_apigw_logging_test.rego
package compliance.gap08_test

import rego.v1
import data.compliance.gap08_apigw_logging

compliant_input := {"configuration": {"root_module": {"resources": [{
	"address": "aws_apigatewayv2_stage.default",
	"type": "aws_apigatewayv2_stage",
	"name": "default",
	"expressions": {"access_log_settings": [{"destination_arn": {"references": ["aws_cloudwatch_log_group.apigw"]}}]},
}]}}}

noncompliant_input := {"configuration": {"root_module": {"resources": [{
	"address": "aws_apigatewayv2_stage.default",
	"type": "aws_apigatewayv2_stage",
	"name": "default",
	"expressions": {},
}]}}}

test_compliant_passes if { count(gap08_apigw_logging.deny) == 0 with input as compliant_input }

test_removed_access_logging_fails if {
	some msg in gap08_apigw_logging.deny with input as noncompliant_input
	contains(msg, "GAP-08")
}
