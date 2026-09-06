######################################################################
# GitHub OIDC trust — lets .github/workflows/grc-gate.yml assume a role
# in this account without long-lived AWS credentials.
# Adapted from Lab 4.3's oidc-trust primitive. The GitHub OIDC provider
# is a one-per-account resource (AWS rejects a duplicate for the same
# URL) and Lab 4.3 already created it - referenced here via a data
# source, not a second aws_iam_openid_connect_provider resource. This
# capstone gets its own role(s), scoped to this specific fork, distinct
# from Lab 4.3's own "cgep-grc-gate" role (which stays scoped to
# cgep-labs and untouched by this file).
#
# Two roles, not one - a security review caught the original single-role
# version trusting any ref (:*) in this repo with PowerUserAccess +
# IAMFullAccess. That's broader than the pipeline actually needs: plan
# and policy-check run on every PR (any branch) and only ever read state,
# while apply/sign/upload only run after a merge to main and are the only
# steps that need real write access. Splitting the trust condition by ref
# closes that gap without breaking PR-triggered plan runs.
######################################################################

data "aws_iam_openid_connect_provider" "github" {
  url = "https://token.actions.githubusercontent.com"
}

# Assumable from any ref in this repo (PRs included) - read-only, for the
# plan + policy-check steps that run on every PR.
resource "aws_iam_role" "grc_gate_plan" {
  name = "${local.name_prefix}-grc-gate-plan"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = data.aws_iam_openid_connect_provider.github.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = { "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com" }
        StringLike   = { "token.actions.githubusercontent.com:sub" = "repo:itsrubenclarke@*/cgep-app-starter@*:*" }
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "grc_gate_plan_readonly" {
  role       = aws_iam_role.grc_gate_plan.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# Assumable ONLY from a push to main - the only ref allowed to actually
# deploy, sign, and upload evidence. This is the role that matters most:
# never loosen this ref condition to a wildcard, or any branch/PR in this
# repo gains write access to the account.
resource "aws_iam_role" "grc_gate_apply" {
  name = "${local.name_prefix}-grc-gate-apply"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = data.aws_iam_openid_connect_provider.github.arn }
      Action    = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringEquals = { "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com" }
        # GitHub appends immutable owner/repo IDs to the sub claim by
        # default (repo:OWNER@OWNERID/REPO@REPOID:ref:refs/heads/main), so
        # the ID segments still need a wildcard - only the ref itself is
        # pinned exactly. That one exact match (no trailing :*) is what
        # stops any other branch or PR from assuming this role.
        StringLike = { "token.actions.githubusercontent.com:sub" = "repo:itsrubenclarke@*/cgep-app-starter@*:ref:refs/heads/main" }
      }
    }]
  })
}

# Mirrors mrc-grc's own broad access (PowerUserAccess + IAMFullAccess),
# now scoped down to only fire from main. Accepted trade-off for a
# single-account, 30-day project: a hand-scoped least-privilege deploy
# policy would be stronger for production, but risks the pipeline
# failing mid-apply on an action nobody anticipated needing, which costs
# more debugging time than this project has left. Documented here rather
# than left unexamined.
resource "aws_iam_role_policy_attachment" "grc_gate_apply_power_user" {
  role       = aws_iam_role.grc_gate_apply.name
  policy_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
}

resource "aws_iam_role_policy_attachment" "grc_gate_apply_iam" {
  role       = aws_iam_role.grc_gate_apply.name
  policy_arn = "arn:aws:iam::aws:policy/IAMFullAccess"
}

output "grc_gate_plan_role_arn" {
  value = aws_iam_role.grc_gate_plan.arn
}

output "grc_gate_apply_role_arn" {
  value = aws_iam_role.grc_gate_apply.arn
}
