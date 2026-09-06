# Acme Health: GRC Engineering Capstone Write-up

## What this is

Acme Health's Patient Intake API is a small AWS system that accepts patient intake forms and stores them. It worked, but it couldn't survive an audit: it shipped with eight named weaknesses, listed in `GAPS.md`, ranging from data stored without proper encryption to an access policy that granted far more permission than the application needed. This project makes that system defensible against **CMMC Level 2**, the framework chosen and defended in the next section.

It does that in four layers: hardened infrastructure that closes the weaknesses, automated policy checks that block them from coming back, a pipeline that refuses to deploy any change failing those checks and cryptographically signs proof of every change that passes, and a machine-readable compliance document tying all of it back to that framework's controls. The rest of this write-up explains what I chose, why, and what I'd still fix.

## Primary framework

I've chosen CMMC Level 2 over HIPAA and SOC 2. CMMC is the US Department of Defense's certification for contractors handling sensitive information, built on the NIST 800-171 control set. It isn't the most obvious regulatory fit for a telehealth company, but its control families gave the cleanest one-to-one mapping onto the eight gaps, with almost no overlap between controls. I picked mapping clarity over natural fit as the deciding factor, and I'm naming that trade-off rather than pretending CMMC is the obvious HIPAA-style choice.

## Control coverage

Each gap maps to one CMMC Level 2 control. "Terraform" means the weakness is fixed in the infrastructure code itself; "policy" means an automated check blocks it from being reintroduced; "both" means it's fixed and guarded.

| ID | Where | CMMC L2 Control | Closed In (Terraform / Policy / Both) | Commit |
|---|---|---|---|---|
| GAP-01 | `aws_s3_bucket.uploads` | SC.L2-3.13.11: Cryptographic Protection | Both (`policies/gap01_s3_kms.rego`) | `5e20b28`, `808d48a` |
| GAP-02 | `aws_dynamodb_table.intake` | SC.L2-3.13.11: Cryptographic Protection | Both (`policies/gap02_dynamodb_kms.rego`) | `d2aacfa`, `808d48a` |
| GAP-03 | `aws_s3_bucket.uploads` | SC.L2-3.13.8: Transmission Confidentiality | Terraform only (see below) | `6919a6e` |
| GAP-04 | `aws_s3_bucket.uploads` | MP.L2-3.8.9: Protection of Backup CUI | Both (`policies/gap04_s3_versioning.rego`) | `33c00d2`, `808d48a` |
| GAP-05 | `aws_lambda_function.intake` | SC.L2-3.13.1: Boundary Protection | Both (`policies/gap05_lambda_vpc.rego`) | `2774c97`, `808d48a` |
| GAP-06 | `aws_lambda_function.intake` | SI.L2-3.14.6: System Monitoring | Terraform (partial, see Trade-offs) | `b60bd72` |
| GAP-07 | `aws_iam_role_policy.lambda_inline` | AC.L2-3.1.5: Least Privilege | Both (`policies/gap07_lambda_least_priv.rego`) | `c8c7d13`, `808d48a` |
| GAP-08 | `aws_apigatewayv2_stage.default` | AU.L2-3.3.1: System Audit Logging | Both (partial, see Trade-offs; `policies/gap08_apigw_logging.rego`) | `2c3fe52`, `7ed5d48`, `808d48a` |

GAP-01 and GAP-02 share a control (SC.L2-3.13.11) because they're the same requirement, encrypt stored data with a key we own rather than one AWS manages for us, applied to two different places. That's not a mapping error. They did close differently in code: the storage bucket takes its encryption setting as a separate add-on resource, while the database takes it as a setting inside the resource itself, so GAP-02 meant editing the starter's original file rather than layering cleanly on top of it.

GAP-03 stayed Terraform-only. Its rule, deny any connection that isn't encrypted in transit, lives inside a policy document that Terraform bundles into a single opaque string. An automated check can't read inside it to confirm the rule is still intact. A check for whether *a* policy exists at all would still pass if someone gutted the rule inside it, which is worse than no check, because it looks like coverage.

GAP-07's check works around that same limitation, but only by luck of timing: when the gap is reintroduced against infrastructure that already exists, the document resolves into readable text and a pattern match for wildcard permissions catches it. Run against a plan before anything is deployed, it would pass silently. That last point is reasoned from how Terraform assembles these documents, not something I ran and watched fail, and it's the one claim in this section not confirmed against live infrastructure.

GAP-06 and GAP-08 are both partial, for unrelated reasons detailed in Trade-offs. Neither has a policy check on its unclosed portion: GAP-06 is already a partial workaround, so guarding it would overstate how solid it is, and GAP-08's missing piece was never built, so there's nothing to guard.

## Design decisions

**Region: `us-east-1`.** A free choice under the brief, and I took it as one.
No data-residency rule applies to a sandbox workload, and CMMC doesn't impose
one the way a GDPR-driven scenario would. Everything lives in that single
region, the application, the encryption key, the evidence vault, and the audit
trail, so there's no cross-region data movement to justify. A real telehealth
deployment would pick its region based on where the patient population sits.

**Object Lock mode: GOVERNANCE, not COMPLIANCE** (`terraform/evidence-vault.tf`,
`bc8cad6`). Object Lock is the S3 feature that stops a file being deleted or
overwritten for a fixed period. COMPLIANCE mode means nobody can delete
evidence early, not even the account's root user, which is the strongest
chain-of-custody claim available. I chose GOVERNANCE: it blocks deletion for
everyone except a caller explicitly granted the bypass permission, which
nobody currently holds, so the tamper-resistance claim stays credible while I
keep room to clean up during an actively changing project. Retention is 365
days, so evidence outlives a typical audit cycle. I traded some theoretical
tamper-resistance for practical iteration speed, and would switch to
COMPLIANCE for production once the system stops being rebuilt week to week.

**One AWS account, not a separate evidence-vault account.** The stronger design
puts the vault in a different account from the system being audited, so that
compromising the audited account can't quietly rewrite its own evidence. I
stayed single-account: this is a short sandbox project, and a second account
would have added cross-account trust to every step of the pipeline to defend
against a threat this scope doesn't really face. The cost is real and named in
the risk register below: the deploy role can reach both the system and the
evidence, so a compromise of `main` reaches both. That separation is the first
thing I'd add for production.

**Apply on merge, not a manual approval gate** (`.github/workflows/grc-gate.yml`,
`54a3275`). I chose full auto-apply on a push to `main`: the policy gate
already blocks a merge if any of the 6 enforced controls regress, so a
human approval step on top would mostly re-check what the gate already
checked rather than add independent judgment. Instead of a manual gate, I
mitigated the "pipeline has real deploy power" risk two ways: (1) the
privileged `grc-gate-apply` IAM role can only be assumed from
`ref:refs/heads/main` specifically, not any branch or PR, and (2) the
apply step itself is conditioned on the policy-check step's outcome, so
even a direct push that bypasses branch protection can't apply over a
failing gate. I'd reconsider a manual gate for a system with a larger
blast radius than a single Lambda/API Gateway/DynamoDB stack, or once
more than one person is pushing to `main`.

**Sign and upload combined into one script/step, not two** (`scripts/capture-evidence.sh`).
The brief's guide names five steps (plan, policy-check, apply-on-merge,
sign, upload), but the receipt (`run_id`, `vault`, `bundle_key`,
`version_id`, `sha256`, `commit`) needs the S3 object's version ID, which
only exists *after* the upload happens. Splitting sign and upload into two
separate scripts or steps would mean either uploading twice or holding
partial state between steps for no real benefit, and the labs' own
`grc-gate.yml` reference (Lab 4.3/4.4) makes the same call, naming it one
step ("Bundle + sign + upload to vault"). I followed that precedent rather
than forcing an artificial split just to hit a literal step count.

**VPC endpoints over a NAT gateway** (`terraform/hardening.tf`, `2774c97`).
Moving the intake Lambda into the starter's existing VPC (GAP-05) left it
with no route to DynamoDB, S3, or KMS once it lost its public internet
path, since the private subnets have no NAT gateway. A NAT gateway would
have restored that path at a real per-hour cost and routed the traffic out
to the public internet and back. I chose Gateway endpoints for S3 and
DynamoDB (free, attached to the route table) and an Interface endpoint for
KMS instead: cheaper, and it keeps that traffic on the AWS backbone rather
than leaving the VPC at all, a better fit for SC.L2-3.13.1 (Boundary
Protection) than "open a path out and back in."

**Two IAM roles for CI, not one** (`terraform/oidc-trust.tf`). The first
version used a single role, trusted from any ref in this repo
(`repo:itsrubenclarke@*/cgep-app-starter@*:*`), with PowerUserAccess and
IAMFullAccess attached directly. A security review flagged that this let
any workflow run on any branch, not just a push to `main`, assume an
admin-equivalent role. The broad permissions themselves were an already-
defended trade-off (mirroring `mrc-grc`'s own access for a short,
single-account project); the missing ref restriction was not a trade-off
anyone had actually chosen, just an oversight. I split it into
`grc-gate-plan` (any ref, `ReadOnlyAccess` only, for PR-triggered plan and
policy-check) and `grc-gate-apply` (trusted only from
`ref:refs/heads/main`, keeping the broad deploy access for the post-merge
apply, sign, and upload steps), matching the pipeline's actual two trust
boundaries instead of collapsing them into one role.

## How the pipeline produces evidence

Every push to `main` runs the same chain: plan the change, check it against the policies, deploy it only if those checks pass, then sign and store proof of what was deployed. Here is one real run of that chain, start to finish.

PR #1 (`feature/terraform-hardening` into `main`) is the traceable example. It carried Layers 1 to 3: the eight gap fixes, the six policies, and the pipeline itself. Opening it triggered the first real run, `grc-gate #1` (34023942632), under the read-only `grc-gate-plan` role, which immediately surfaced two problems. (The Actions tab numbers runs `#1` to `#6`; `README.md` maps every number to its run ID and outcome.)

First, CI had no access to the Terraform state that had only ever lived on my laptop, so it planned to rebuild all 56 resources from scratch. Second, the GAP-02 policy failed against that from-scratch plan, because a database that doesn't exist yet has no encryption key to report. Both were fixed with a shared remote state backend. Fixing that then exposed something worse. A security review found the plan role would let anyone fork this public repository, rewrite the workflow, and assume the role, because the trust condition only checked which repository the run claimed to come from, and GitHub doesn't withhold repository variables from fork-triggered runs the way it withholds secrets. Fixed by additionally pinning the workflow file's own location.

The next run, `#2` (34024334524), got further: the policy gate passed this time, and the run failed only because the plan role had no permission yet to write into the evidence vault. Granting it that, scoped to the vault's `runs/` prefix, produced `#3` (34024761519), the first fully green run: plan, the six-policy check, and a signed evidence bundle uploaded under `runs/34024761519/`, signed under the pull-request identity and correctly distinct from a real deployment.

Merging the PR triggered a separate run, `#4` (34024978457), this time under the privileged `grc-gate-apply` role scoped only to `main`. All 14 steps passed, including `Terraform apply`, the first time this pipeline deployed anything by itself rather than by hand from my laptop. That run's bundle carries the `main`-branch identity that `scripts/verify-evidence.sh` is pinned to. Ran it for real:

```
$ ./scripts/verify-evidence.sh 34024978457 --vault acme-health-intake-evidence-vault-4f63d674 --profile default
Verified OK
CHAIN INTACT for run 34024978457
```

`CHAIN INTACT` means all three checks passed: the bundle's contents match its recorded fingerprint, the signature verifies against Sigstore's public log as having come from this repository's pipeline, and the file is still under its deletion lock. Run 34024978457 (`#4`) is the one to cite for the green PR, and `#6` (34036921316), the later Layer 4 deploy, verifies the same way. Run 34024761519 (`#3`), the pull-request check, is the honest negative case: verifying it fails, which is correct, because the identity pin distinguishes a check run from a real deployment rather than accepting anything the pipeline signs.

The red PR is #2 (`red/reintroduce-gap07`), a single-line revert of GAP-07 putting the wildcard database permission back. I confirmed the failure locally first, then pushed and watched `#5` (34025487183) fail the same way: the policy gate failed, `Terraform apply` was correctly skipped, and the PR's overall status came back `FAILURE`. No real infrastructure was ever at risk, since a pull request never applies. Closed without merging once the block was proven.

One feature branch carried the whole Terraform layer, one commit per gap, each recorded in the Control coverage table above. Only the green and red pair above is graded.

### How I know these checks actually work

A passing check only means something if it would have failed on a real problem. Each layer was tested against one.

The gate was run against the exact self-check the brief says graders perform. I commented out the versioning resource (GAP-04), ran a read-only plan, and the gate failed with the right control citation and remediation text while every other policy passed. Reverting restored a clean diff and a passing gate. Separately, running that same policy against a real plan rather than its own test fixtures caught a genuine gap I'd written myself: the CloudTrail bucket had no versioning either. Fixed in `808d48a`.

The evidence scripts were proven before CI existed. `capture-evidence.sh` produced a real signed bundle in the vault (run `local-test-1788677211`), and downloading it back into a clean directory confirmed the fingerprint matched and the signature verified. Running `verify-evidence.sh` against that same bundle then correctly *rejected* it, because it had been signed by a personal browser login rather than by CI. That rejection is the check doing its job.

A security review of `verify-evidence.sh` caught three flaws inherited from the lab material it was adapted from:

- **It accepted any signature.** It was set to match any signer from any GitHub repository, so anyone's signature would have verified. Fixed by pinning it to this repository's workflow.
- **It failed open on dates.** The retention check compared dates as plain text. Had AWS ever returned the word `None` instead of a date, that sorts after any real date and would have read as "still protected." Fixed by comparing numbers instead.
- **It could be pointed elsewhere.** The run ID was used unchecked to build a storage path, so a crafted value could have pulled evidence from a different part of the vault. Fixed with an input check.

A parallel review of the GAP-08 work caught two more that a working test would never surface: the log permissions didn't restrict *which* API Gateway could write to them, meaning any AWS account's could have, and the log group had quietly defaulted to AWS's own encryption key instead of ours. Both fixed in `7ed5d48` and re-verified live.

Infrastructure claims were checked against live AWS state rather than Terraform's own view of it. That discipline caught a real regression: closing GAP-02 applied cleanly but silently broke the running application, because the new encryption key's policy said "IAM controls access to this key" without granting anyone that access. `make test` started returning `Internal Server Error` until the Lambda got an explicit grant (`6919a6e`). CloudTrail was verified the same way: rather than trusting an `IsLogging: true` flag, I checked the storage bucket and confirmed real log files had landed, identified as ours by the trail name and date in each filename.

### A signed snapshot of the vault itself

`verify-evidence.sh` proves things about one evidence bundle. It doesn't prove the claims this write-up makes about the vault holding it. `scripts/capture-attestation.sh` closes that gap: it reads the vault's actual configuration straight from AWS, writes it to a single file, and signs that file, turning a claim in this document into a signed artifact. Run against 34024978457, it confirmed live that the deletion lock is on in GOVERNANCE mode with 365-day retention, versioning is enabled, storage is encrypted with our own key, and that specific evidence file is locked until `2027-09-06`. Downloading it back and verifying independently returned `Verified OK` with a matching fingerprint.

One caveat: it was signed from a laptop via a browser login, not by CI, so it carries my personal identity rather than the pipeline's. That's a real distinction, not an oversight. It says "the person holding this GitHub account attests the vault looked like this," not "CI observed this as part of an automated run." Having the pipeline generate it on every deploy is listed under what I didn't get to.

## Trade-offs and what I'd do with another sprint

One pattern stands out across the whole project: every layer that controls who is allowed to do what shipped with a real flaw on its first pass, and not one of them was caught by testing whether the thing worked. The deploy role would have let any branch assume admin-level permissions. The logging permissions would have let any AWS account write into our log group. The verification script accepted any signature, compared dates in a way that failed open, and could be pointed at the wrong part of the vault. The worst of them, a fork of this public repository being able to assume our role, was reachable by any stranger on the internet. All were found by deliberately reading working code adversarially rather than by running it. With another sprint I'd automate that reading: a policy that checks the *shape* of access rules, catching wildcards and missing conditions anywhere, rather than only the eight gaps named in `GAPS.md`.

A second pattern: closing a gap kept surfacing a dependency the starter never mentioned and no lab covered. Giving the Lambda access to the new encryption key, adding network permissions and private routes when it moved inside the VPC, and granting the logging and audit services their own use of that key were all found the same way, by deploying, watching it break, reading the error, and fixing it. The recurring lesson: creating a key doesn't grant anyone permission to use it, and each AWS service needs its own explicit grant on top. With more time I'd write that up as a short internal checklist so the next gap doesn't rediscover the same failure modes from scratch.

Two gaps stayed partial, and I'd close them properly rather than document around them. GAP-06's dead-letter queue only catches failures from background invocations, but this function is called directly by the API, so a real failure returns straight to the caller and never reaches the queue; the correct fix is a different failure-handling mechanism entirely. Reserved concurrency couldn't be set at all: this sandbox account's total limit is 10 and AWS holds 10 back as an unreserved floor, so no reservation is possible; in production I'd raise the quota first. GAP-08's missing firewall is architectural rather than a limit problem, since AWS's web application firewall doesn't support this type of API at all, so closing it means putting a CDN in front or migrating to a different API type, both bigger changes than this scope justifies.

Finally, the evidence vault's Object Lock mode (GOVERNANCE, not COMPLIANCE) and the fully automated apply-on-merge gate are both defensible for a solo, actively iterated capstone project, but I wouldn't carry either into a real production system unchanged. COMPLIANCE mode and a manual approval step in front of apply both trade iteration speed for a stronger guarantee, and that trade only makes sense once the system has stopped changing shape week to week.

## What I didn't get to

A few things stayed out of scope, named plainly rather than left implicit:

- **WAF in front of the API.** Architecturally blocked on HTTP APIs (see GAP-08 above), not attempted via CloudFront or a REST API migration.
- **A genuine failure path for GAP-06.** The DLQ exists but doesn't catch what actually fails in this Lambda's synchronous invocation path; a correct fix (Lambda Destinations, or a queue in front of API Gateway) wasn't built.
- **Any detective or alerting layer.** Everything built here is preventive: the gate blocks bad changes before they deploy. Nothing watches the running system and raises an alarm when something goes wrong, so a failure, a change applied outside the pipeline, or an active attack would sit unnoticed in CloudWatch Logs until someone went looking. The minimum fix is CloudWatch alarms routed to an SNS topic; the fuller one is AWS Config or Security Hub continuously checking posture against the same controls the gate enforces at deploy time. Worth naming plainly because GAP-06 maps to SI.L2-3.14.6, System Monitoring, and preventive controls alone don't really satisfy a monitoring requirement.
- **Reserved concurrency.** Blocked by this sandbox account's 10-execution quota; never requested an increase to test the real fix.
- **COMPLIANCE mode on the evidence vault's Object Lock.** Chose GOVERNANCE deliberately (see Design decisions) but never actually tried COMPLIANCE mode to confirm what breaks under active iteration.
- **A separate AWS account, or at least a separate plan-only trust boundary, for CI.** Everything in this project runs in one sandbox account; a real deployment would likely separate the account running `grc-gate-plan` from the one `grc-gate-apply` can actually change.
- **Automating the vault attestation in CI.** `scripts/capture-attestation.sh` exists and was run for real (see How the pipeline produces evidence), but only by hand from a laptop, so it carries a personal Sigstore identity instead of the CI identity the rest of the evidence chain uses. Wiring it into `grc-gate.yml` so it runs and signs automatically on every apply wasn't built.
- **Live regression testing for every policy.** Only GAP-04 (versioning) and GAP-07 (least privilege) were actually tested by deliberately reintroducing the real gap and confirming the gate fires. The other four policies are proven correct against their own test fixtures, not against a live plan carrying the actual regression.
- **Contributing the authored CMMC L2 subset catalog anywhere upstream.** It solves this project's immediate problem (no official Rev 2 OSCAL catalog exists) but stays local to this repo rather than becoming something the next capstone learner, or NIST/OSCAL's own project, could reuse.

## Residual risk register

These are the risks that remain live in the system as it stands today, distinct from work that's simply out of scope above. Each one is a real mechanism, not a hypothetical.

| Risk | Mechanism | Compensating control |
|---|---|---|
| Evidence could still be deleted before retention expires | GOVERNANCE mode Object Lock blocks deletion for everyone except a caller holding `s3:BypassGovernanceRetention`. Nobody has that grant today, but `grc-gate-apply` carries `IAMFullAccess`, so a compromised `main` push could grant it to itself | None beyond "nobody has the grant yet." COMPLIANCE mode would close this fully; see Trade-offs |
| A synchronous intake failure produces no durable record | GAP-06's DLQ only catches asynchronous invocation failures; API Gateway invokes this Lambda synchronously, so a real failure returns straight to the caller and is visible only in CloudWatch Logs, not in any queue | CloudWatch Logs retention only; no replay or alerting path |
| The intake API has no WAF layer | WAFv2 doesn't support HTTP APIs as an association target at all (per AWS's documentation, not something tried and watched fail here), so the API is exposed to the internet with throttling but no request-inspection layer (SQLi/XSS/bot filtering) | `default_route_settings` throttling limits volume but not payload content |
| A burst could exhaust this account's entire Lambda concurrency | Reserved concurrency couldn't be set (10-execution account quota, 10-unreserved floor, confirmed by a real `InvalidParameterValueException`), so the intake function competes for concurrency with anything else in the account rather than having a protected slice | None; would need a quota increase first |
| GAP-07's check has a blind spot before first deployment | The check can only read the permission document when the resources it references already exist. Run against a plan for infrastructure not yet deployed, the same wildcard permission would pass unnoticed. Reasoned from how Terraform assembles these documents, not confirmed by running it | None; named as a known limitation in Control coverage |
| GAP-03's encryption-in-transit rule has no check at all | The rule sits inside a document Terraform treats as one opaque string, so nothing can automatically detect it being removed or weakened | Manual review only |
| The deploy role can change anything in the account | `grc-gate-apply` holds broad permissions, trusted only from `main`. If `main` is ever compromised, through a stolen credential or a malicious merge, that reaches everything in the account, including the evidence | Branch scoping and the policy gate stop an *unauthorized* deploy; neither stops a compromised *authorized* one |
