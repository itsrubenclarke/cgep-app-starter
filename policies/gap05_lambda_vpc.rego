# policies/gap05_lambda_vpc.rego
# METADATA
# title: SC.L2-3.13.1 - Boundary Protection (Lambda in the private VPC)
# description: "The intake Lambda must declare a vpc_config, not run in the default Lambda network (GAP-05)."
# custom:
#   control_id: SC.L2-3.13.1
#   framework: cmmc-l2
#   gap_id: GAP-05
#   severity: high
#   remediation: "Add a vpc_config block referencing the private subnets and a scoped security group."
package compliance.gap05_lambda_vpc

import rego.v1

deny contains msg if {
	some r in input.configuration.root_module.resources
	r.type == "aws_lambda_function"
	not r.expressions.vpc_config
	addr := sprintf("aws_lambda_function.%s", [r.name])
	msg := sprintf(
		"[SC.L2-3.13.1 / GAP-05] %s: no vpc_config block. Remediation: place the function in the existing private subnets with a scoped security group.",
		[addr],
	)
}
