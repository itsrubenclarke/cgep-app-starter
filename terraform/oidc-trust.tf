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
#
# This repo is public. A security review caught that the `sub` claim
# alone is NOT a safe trust boundary here: for a pull_request event,
# GitHub's sub claim only encodes the base repo (itsrubenclarke/
# cgep-app-starter), the same whether the PR comes from a branch on this
# repo or from a stranger's fork with a rewritten grc-gate.yml. Unlike
# secrets, repository `vars` (what role-to-assume reads) ARE exposed to
# fork-triggered pull_request runs, so the `sub`-only condition would let
# any fork holding its own modified workflow assume this role.
# job_workflow_ref doesn't have that gap: it always names wherever the
# workflow FILE ITSELF lives, so a fork's rewritten workflow shows the
# fork's own path, not this one. Both conditions must hold.
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
        StringLike = {
          "token.actions.githubusercontent.com:sub"              = "repo:itsrubenclarke@*/cgep-app-starter@*:*"
          "token.actions.githubusercontent.com:job_workflow_ref" = "itsrubenclarke/cgep-app-starter/.github/workflows/grc-gate.yml@*"
        }
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "grc_gate_plan_readonly" {
  role       = aws_iam_role.grc_gate_plan.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# Even a read-only `terraform plan` acquires and releases a DynamoDB lock
# on every run - ReadOnlyAccess covers reading the state object in S3, but
# not the PutItem/DeleteItem the lock itself needs. Without this, PR
# plans fail to acquire the lock at all. Scoped to just this lock table,
# not DynamoDB generally.
resource "aws_iam_role_policy" "grc_gate_plan_state_lock" {
  name = "tfstate-lock"
  role = aws_iam_role.grc_gate_plan.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:DeleteItem"]
        Resource = "arn:aws:dynamodb:us-east-1:${data.aws_caller_identity.current.account_id}:table/acme-health-intake-tfstate-lock"
      }
    ]
  })
}

# Every PR run signs and uploads evidence too, even one the policy gate
# blocks, so a red PR still leaves a signed, verifiable record that the
# gate actually caught it, not just a workflow status badge. That needs
# two grants ReadOnlyAccess doesn't include: s3:PutObject to the vault
# itself, and kms:GenerateDataKey on the CMK the vault is encrypted
# with - yet another instance of the "the key policy alone grants
# nothing" pattern already seen for CloudWatch Logs, CloudTrail, and the
# Lambda's own KMS access.
resource "aws_iam_role_policy" "grc_gate_plan_evidence_upload" {
  name = "evidence-vault-upload"
  role = aws_iam_role.grc_gate_plan.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "s3:PutObject"
        Resource = "${aws_s3_bucket.evidence_vault.arn}/runs/*"
      },
      {
        Effect   = "Allow"
        Action   = "kms:GenerateDataKey"
        Resource = aws_kms_key.phi.arn
      }
    ]
  })
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
