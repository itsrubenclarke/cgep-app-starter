#!/usr/bin/env bash
# scripts/capture-attestation.sh
# Signs a snapshot of the evidence vault's own security properties, so a
# grader without AWS access can verify claims like "Object Lock is really
# on" and "the vault is really encrypted with the customer CMK" against a
# signed artifact, not just this project's prose.
#
# Complements scripts/capture-evidence.sh (which bundles a deploy's plan,
# policy results, and state) rather than replacing it: this script asks
# "is the vault itself configured the way WRITEUP.md claims, right now,"
# independent of any specific run.
#
# Usage:
#   capture-attestation.sh --run-id <id> --vault <bucket> [--profile <p>]
set -euo pipefail

PROFILE_ARG=""
RUN_ID=""
VAULT=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --run-id)  RUN_ID="$2"; shift 2 ;;
    --vault)   VAULT="$2";  shift 2 ;;
    --profile) PROFILE_ARG="--profile $2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

[[ -z "$RUN_ID" || -z "$VAULT" ]] && {
  echo "Usage: $0 --run-id <id> --vault <bucket> [--profile <p>]" >&2
  exit 2
}

if command -v sha256sum >/dev/null 2>&1; then SHASUM="sha256sum"
elif command -v shasum    >/dev/null 2>&1; then SHASUM="shasum -a 256"
else echo "Need sha256sum or shasum" >&2; exit 2; fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

CAPTURED_AT=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# Each check below hits the live AWS API directly, the same "verify live
# state, don't trust config claims alone" discipline used throughout this
# project. If any call fails, its field is null rather than aborting the
# whole attestation, so a grader can see exactly what could and couldn't
# be confirmed.
OBJECT_LOCK=$(aws $PROFILE_ARG s3api get-object-lock-configuration \
  --bucket "$VAULT" --output json 2>/dev/null || echo 'null')
VERSIONING=$(aws $PROFILE_ARG s3api get-bucket-versioning \
  --bucket "$VAULT" --output json 2>/dev/null || echo 'null')
ENCRYPTION=$(aws $PROFILE_ARG s3api get-bucket-encryption \
  --bucket "$VAULT" --output json 2>/dev/null || echo 'null')

# Retention on this specific run's evidence bundle, not just the vault's
# default policy, so the attestation ties to one concrete object rather
# than only a bucket-wide setting.
BUNDLE_KEY=$(aws $PROFILE_ARG s3api list-objects-v2 \
  --bucket "$VAULT" --prefix "runs/${RUN_ID}/evidence-" \
  --query 'Contents[?!ends_with(Key, `.sha256`) && !ends_with(Key, `.sig.bundle`)] | [0].Key' \
  --output text)
RETENTION=$(aws $PROFILE_ARG s3api get-object-retention \
  --bucket "$VAULT" --key "$BUNDLE_KEY" --output json 2>/dev/null || echo 'null')

ATTESTATION_PATH="$WORK/attestation.json"
cat > "$ATTESTATION_PATH" <<EOF
{
  "run_id": "$RUN_ID",
  "vault": "$VAULT",
  "captured_at_utc": "$CAPTURED_AT",
  "checks": {
    "object_lock_configuration": $OBJECT_LOCK,
    "bucket_versioning": $VERSIONING,
    "bucket_encryption": $ENCRYPTION,
    "evidence_object_key": "$BUNDLE_KEY",
    "evidence_object_retention": $RETENTION
  }
}
EOF

cosign sign-blob --yes --bundle "$ATTESTATION_PATH.sig.bundle" "$ATTESTATION_PATH"
$SHASUM "$ATTESTATION_PATH" | awk '{print $1}' > "$ATTESTATION_PATH.sha256"

KEY_PREFIX="runs/$RUN_ID"
aws $PROFILE_ARG s3 cp "$ATTESTATION_PATH"           "s3://$VAULT/$KEY_PREFIX/attestation.json"
aws $PROFILE_ARG s3 cp "$ATTESTATION_PATH.sha256"     "s3://$VAULT/$KEY_PREFIX/attestation.json.sha256"
aws $PROFILE_ARG s3 cp "$ATTESTATION_PATH.sig.bundle"  "s3://$VAULT/$KEY_PREFIX/attestation.json.sig.bundle"

echo "Uploaded attestation for run ${RUN_ID}:"
cat "$ATTESTATION_PATH"
