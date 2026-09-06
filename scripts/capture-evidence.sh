#!/usr/bin/env bash
# scripts/capture-evidence.sh
# Adapted from Lab 2.5's bundle/manifest pattern, combined with the
# sign+upload logic from the labs' own working grc-gate.yml (Lab 4.4) so
# it can be called as a script from either a terminal or the pipeline,
# rather than living only inline in the workflow YAML.
#
# Usage:
#   capture-evidence.sh --workspace <path> --run-id <id> --sha <commit-sha> \
#     --vault <bucket> [--profile <p>]
#
# Expects scripts/policy-gate.sh to have already run against the same
# workspace, so evidence/grc-gate/conftest-results.json exists to bundle
# alongside the plan.
set -euo pipefail

PROFILE_ARG=""
WORKSPACE=""
RUN_ID=""
SHA=""
VAULT=""
POLICY_EVIDENCE_DIR="evidence/grc-gate"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --workspace) WORKSPACE="$2"; shift 2 ;;
    --run-id)    RUN_ID="$2";    shift 2 ;;
    --sha)       SHA="$2";       shift 2 ;;
    --vault)     VAULT="$2";     shift 2 ;;
    --profile)   PROFILE_ARG="--profile $2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

[[ -z "$WORKSPACE" || -z "$RUN_ID" || -z "$SHA" || -z "$VAULT" ]] && {
  echo "Usage: $0 --workspace <path> --run-id <id> --sha <commit-sha> --vault <bucket> [--profile <p>]" >&2
  exit 2
}

if command -v sha256sum >/dev/null 2>&1; then SHASUM="sha256sum"
elif command -v shasum    >/dev/null 2>&1; then SHASUM="shasum -a 256"
else echo "Need sha256sum or shasum" >&2; exit 2; fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

CAPTURED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)
BUNDLE_DIR="$WORK/bundle-$RUN_ID"
mkdir -p "$BUNDLE_DIR"

# Terraform plan/state.
( cd "$WORKSPACE" && [[ -f tfplan ]] && \
    terraform show -json tfplan > "$BUNDLE_DIR/plan.json" 2>/dev/null || true )
( cd "$WORKSPACE" && terraform state pull > "$BUNDLE_DIR/state.json" 2>/dev/null || true )
terraform version > "$BUNDLE_DIR/version.txt"

# Policy gate results (produced by scripts/policy-gate.sh).
[[ -f "$POLICY_EVIDENCE_DIR/conftest-results.json" ]] && \
  cp "$POLICY_EVIDENCE_DIR/conftest-results.json" "$BUNDLE_DIR/conftest-results.json"

# What was actually deployed.
git log -1 --pretty=full > "$BUNDLE_DIR/commit.txt" 2>/dev/null \
  || echo "no git commit available" > "$BUNDLE_DIR/commit.txt"

# manifest.json: filename, sha256, size, captured_at_utc per file.
{
  echo "["
  FIRST=1
  for f in "$BUNDLE_DIR"/*; do
    base=$(basename "$f")
    [[ "$base" == "manifest.json" ]] && continue
    HASH=$($SHASUM "$f" | awk '{print $1}')
    SIZE=$(wc -c < "$f" | tr -d ' ')
    [[ $FIRST -eq 1 ]] && FIRST=0 || printf ","
    printf '\n  {"filename":"%s","sha256":"%s","size":%s,"captured_at_utc":"%s"}' \
      "$base" "$HASH" "$SIZE" "$CAPTURED_AT"
  done
  echo
  echo "]"
} > "$BUNDLE_DIR/manifest.json"

BUNDLE="evidence-${RUN_ID}-${SHA}.tar.gz"
BUNDLE_PATH="$WORK/$BUNDLE"
( cd "$BUNDLE_DIR" && tar czf "$BUNDLE_PATH" . )

$SHASUM "$BUNDLE_PATH" | awk '{print $1}' > "$BUNDLE_PATH.sha256"

# Keyless signing via Sigstore. In CI this uses the GitHub OIDC token
# (permissions: id-token: write). From a laptop it opens a browser for
# interactive OIDC login - either way, no private key to manage or leak.
cosign sign-blob --yes --bundle "$BUNDLE_PATH.sig.bundle" "$BUNDLE_PATH"

KEY_PREFIX="runs/$RUN_ID"
aws $PROFILE_ARG s3 cp "$BUNDLE_PATH"            "s3://$VAULT/$KEY_PREFIX/$BUNDLE"
aws $PROFILE_ARG s3 cp "$BUNDLE_PATH.sha256"      "s3://$VAULT/$KEY_PREFIX/$BUNDLE.sha256"
aws $PROFILE_ARG s3 cp "$BUNDLE_PATH.sig.bundle"  "s3://$VAULT/$KEY_PREFIX/$BUNDLE.sig.bundle"

VERSION_ID=$(aws $PROFILE_ARG s3api head-object --bucket "$VAULT" --key "$KEY_PREFIX/$BUNDLE" --query VersionId --output text)

RECEIPT_PATH="$WORK/receipt.json"
cat > "$RECEIPT_PATH" <<EOF
{
  "run_id": "$RUN_ID",
  "vault": "$VAULT",
  "bundle_key": "$KEY_PREFIX/$BUNDLE",
  "version_id": "$VERSION_ID",
  "sha256": "$(cat "$BUNDLE_PATH.sha256")",
  "commit": "$SHA",
  "captured_at_utc": "$CAPTURED_AT"
}
EOF
aws $PROFILE_ARG s3 cp "$RECEIPT_PATH" "s3://$VAULT/$KEY_PREFIX/receipt.json"

mkdir -p evidence/grc-gate
cp "$RECEIPT_PATH" evidence/grc-gate/receipt.json
cat "$RECEIPT_PATH"
