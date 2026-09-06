# policies/gap07_lambda_least_priv.rego
# METADATA
# title: AC.L2-3.1.5 - Least Privilege (Lambda inline IAM policy)
# description: "The Lambda's inline IAM policy must not grant wildcard actions like dynamodb:* or s3:* (GAP-07)."
# custom:
#   control_id: AC.L2-3.1.5
#   framework: cmmc-l2
#   gap_id: GAP-07
#   severity: high
#   remediation: "Scope each Statement's Action to the specific calls the handler makes (e.g. dynamodb:PutItem, s3:PutObject)."
package compliance.gap07_lambda_least_priv

import rego.v1

# Matches a JSON action string ending in a wildcard, e.g. "dynamodb:*" or
# "s3:*" - catches any service-level wildcard action, not just these two.
wildcard_action_pattern := `:\*"`

deny contains msg if {
	some r in input.planned_values.root_module.resources
	r.type == "aws_iam_role_policy"
	policy := r.values.policy
	regex.match(wildcard_action_pattern, policy)
	msg := sprintf(
		"[AC.L2-3.1.5 / GAP-07] %s: inline policy grants a wildcard action (matches %q). Remediation: scope to the exact actions the caller needs.",
		[r.address, wildcard_action_pattern],
	)
}
