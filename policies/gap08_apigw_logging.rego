# policies/gap08_apigw_logging.rego
# METADATA
# title: AU.L2-3.3.1 - System Audit Logging (API Gateway access logs)
# description: "The default stage must have access_log_settings configured (GAP-08)."
# custom:
#   control_id: AU.L2-3.3.1
#   framework: cmmc-l2
#   gap_id: GAP-08
#   severity: medium
#   remediation: "Add an access_log_settings block pointing at a CloudWatch log group, scoped with a resource policy."
package compliance.gap08_apigw_logging

import rego.v1

deny contains msg if {
	some r in input.configuration.root_module.resources
	r.type == "aws_apigatewayv2_stage"
	not r.expressions.access_log_settings
	addr := sprintf("aws_apigatewayv2_stage.%s", [r.name])
	msg := sprintf(
		"[AU.L2-3.3.1 / GAP-08] %s: no access_log_settings block. Remediation: wire access logging to a CloudWatch log group.",
		[addr],
	)
}
