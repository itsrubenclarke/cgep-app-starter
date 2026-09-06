# Acme Health Patient Intake API: CGE-P Capstone

Ruben Clarke's Certified GRC Engineer (Practitioner) capstone. Wraps the
[`GRCEngClub/cgep-app-starter`](https://github.com/GRCEngClub/cgep-app-starter)
Patient Intake API in the four CGE-P layers so the workload is audit-defensible
against **CMMC Level 2** as the primary framework.

**Full reasoning:** [`WRITEUP.md`](./WRITEUP.md) covers framework choice, control
coverage, design decisions, the evidence trace, trade-offs, and a residual risk
register. [`DESIGN.md`](./DESIGN.md) holds the per-gap maps behind it.

**What to grade:** head of `main`. Every push to `main` produces a fresh signed
evidence bundle in the vault under `runs/<run_id>/`.

## What's here

| Layer | Where | What it does |
|---|---|---|
| 1. Terraform baseline | `terraform/` | Customer-managed KMS key, Object Lock evidence vault, multi-region CloudTrail, GitHub OIDC roles, and the overrides closing the 8 gaps in [`GAPS.md`](./GAPS.md) |
| 2. Policy suite | `policies/` | 6 Rego policies, 13 tests, each citing a CMMC L2 control and catching a real gap |
| 3. Pipeline | `.github/workflows/grc-gate.yml` | plan → policy check → apply on merge → sign → upload to vault |
| 4. OSCAL | `oscal/` | Component definition, profile, and authored catalog. See [`oscal/README.md`](./oscal/README.md) |

## For the grader: verifying this submission

### No AWS credentials needed

```bash
git clone https://github.com/itsrubenclarke/cgep-app-starter && cd cgep-app-starter

# Layer 2: the policy suite passes its own tests
opa test policies/
# → PASS: 13/13

# Layer 4: the OSCAL validates (see oscal/README.md for the full recipe)
cat oscal/trestle-validate.txt
```

**The gate has teeth.** Both graded PRs are in the history. The
[Actions tab](https://github.com/itsrubenclarke/cgep-app-starter/actions) labels
runs `grc-gate #1` through `#6`, while the scripts and `WRITEUP.md` refer to run
IDs, so here is the full mapping. Three of the six are red, and that is the point:

| Run | ID | What it was | Result |
|---|---|---|---|
| `#1` | [34023942632](https://github.com/itsrubenclarke/cgep-app-starter/actions/runs/34023942632) | PR #1, first CI run. CI had no access to Terraform state, so it planned to rebuild all 56 resources; the GAP-02 policy correctly failed against that plan | ❌ diagnosed, fixed with a remote backend |
| `#2` | [34024334524](https://github.com/itsrubenclarke/cgep-app-starter/actions/runs/34024334524) | PR #1, after the backend fix. Policy gate now **passed**; the run failed only because the plan role couldn't yet write evidence to the vault | ❌ permissions, then granted |
| `#3` | [34024761519](https://github.com/itsrubenclarke/cgep-app-starter/actions/runs/34024761519) | PR #1, green check. Gate passed and evidence was signed under the pull-request identity | ✅ |
| `#4` | [34024978457](https://github.com/itsrubenclarke/cgep-app-starter/actions/runs/34024978457) | **Merge of PR #1 to `main`.** All 14 steps passed, including the pipeline's first real `Terraform apply` | ✅ **the graded green run** |
| `#5` | [34025487183](https://github.com/itsrubenclarke/cgep-app-starter/actions/runs/34025487183) | **PR #2**, reintroducing GAP-07's wildcard IAM permission. Gate failed, `Terraform apply` was skipped, PR status came back `FAILURE`. Closed unmerged | ❌ **the graded red run, blocked by design** |
| `#6` | [34036921316](https://github.com/itsrubenclarke/cgep-app-starter/actions/runs/34036921316) | Layer 4 OSCAL push to `main`. A second full deployment | ✅ |

Runs `#1` and `#2` are development failures, kept rather than rewritten: `WRITEUP.md`
traces what each one exposed, including a fork-PR trust hole in the OIDC role that
surfaced while fixing them. Run `#5` is the deliberate one. Runs `#4` and `#6` are both real
deployments and both verify below. Any run numbered above `#6` is a later push to
`main`, each producing its own signed bundle in the vault under `runs/<run_id>/`.

**Per-run policy results** are attached to every run as the `grc-evidence-<run_id>`
artifact (Actions tab → the run → Artifacts). It contains `conftest-results.json`,
the per-policy pass/fail for that plan, and `receipt.json`, which records the
bundle's SHA-256, its S3 version ID, and the commit it came from. Note the signed
bundle itself lives in the vault rather than the artifact, so verifying the
signature needs the read access below.

### Needs read access to this AWS account

```bash
# Run #4, the graded green run (merge of PR #1)
./scripts/verify-evidence.sh 34024978457 \
  --vault acme-health-intake-evidence-vault-4f63d674 --profile default
# → Verified OK
# → CHAIN INTACT for run 34024978457

# Run #6, a second, later deployment from main
./scripts/verify-evidence.sh 34036921316 \
  --vault acme-health-intake-evidence-vault-4f63d674 --profile default
# → CHAIN INTACT for run 34036921316
```

`CHAIN INTACT` means all three checks passed: the bundle matches its recorded
SHA-256, its Cosign signature verifies against Sigstore's public transparency log
as having come from this repo's workflow on `main`, and the object is still under
Object Lock retention.

Run `34024761519` (`#3`) is the honest negative case. It's the pull-request check
rather than a deployment, so it's signed under `refs/pull/1/merge` and verification
of it *fails* by design: the identity pin distinguishes a check run from a real
deploy rather than trusting anything the pipeline signs.

For a signed snapshot of the vault's own configuration (Object Lock mode,
retention, versioning, which key encrypts it):

```bash
./scripts/capture-attestation.sh --run-id 34024978457 \
  --vault acme-health-intake-evidence-vault-4f63d674 --profile default
```

### Deploy it yourself (optional)

The starter's workload is unchanged and still runs. Nothing above requires this.

```bash
make deploy AWS_PROFILE=<your-sandbox-profile>
make test   AWS_PROFILE=<your-sandbox-profile>
# → {"submission_id": "...", "status": "received"}
```

> **AWS SSO note:** if your profile is SSO-based, Terraform's provider can fail to
> read it directly with `failed to find SSO session section`. The Makefile's
> `eval $(aws configure export-credentials)` pattern handles this; do the same
> export first if running `terraform` by hand.

## Cost and teardown

Pay-per-use for the workload itself. The always-on costs are the customer-managed
KMS key, CloudTrail, and the two VPC interface endpoints (KMS and X-Ray), the last
being the largest line item at roughly $7/month each.

`make destroy` removes the workload. It will **not** empty the evidence vault:
objects there are under Object Lock GOVERNANCE retention for 365 days, so deleting
them early requires a caller explicitly granted `s3:BypassGovernanceRetention`,
which nobody currently holds. That's the intended behaviour, not a bug.

## Attribution

Starter application, `GAPS.md`, `FRAMEWORKS.md`, and `WORKLOAD.md` come from
[`GRCEngClub/cgep-app-starter`](https://github.com/GRCEngClub/cgep-app-starter).
Everything in `terraform/` beyond the starter's own resources, plus all of
`policies/`, `scripts/`, `.github/`, and `oscal/`, was authored for this capstone.

License follows the starter: MIT.
