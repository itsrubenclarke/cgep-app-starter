#!/usr/bin/env bash
# scripts/verify-evidence.sh <run_id>
# Adapted from Lab 4.4. Runs the same three checks a grader runs:
# integrity (SHA256), authenticity + timestamp (Cosign against Sigstore's
# public transparency log), and preservation (Object Lock retention).
set -euo pipefail
RUN_ID="${1:?usage: verify-evidence.sh <run_id> [--vault <bucket>] [--profile <p>]}"
shift || true

# Reject anything that isn't a plain run-id segment before it's used to
# build an S3 key - otherwise a crafted value like "../other-prefix"
# could pull evidence from somewhere else in the vault entirely.
[[ "$RUN_ID" =~ ^[A-Za-z0-9._-]+$ ]] || { echo "FAIL: invalid run id \"$RUN_ID\"" >&2; exit 2; }
VAULT="${EVIDENCE_VAULT:-}"
PROFILE_ARG=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --vault)   VAULT="$2"; shift 2 ;;
    --profile) PROFILE_ARG="--profile $2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done
[[ -z "$VAULT" ]] && { echo "Set --vault or EVIDENCE_VAULT"; exit 2; }

if command -v sha256sum >/dev/null 2>&1; then SHASUM="sha256sum"
elif command -v shasum >/dev/null 2>&1; then SHASUM="shasum -a 256"
else echo "Need sha256sum or shasum" >&2; exit 2; fi

WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT; cd "$WORK"
PREFIX="runs/${RUN_ID}"

aws $PROFILE_ARG s3 cp "s3://${VAULT}/${PREFIX}/" . --recursive \
  --exclude "*" --include "evidence-*.tar.gz*" --include "receipt.json"

BUNDLE=$(ls evidence-*.tar.gz | head -1)

# 1. Integrity
EXPECTED=$(cat "${BUNDLE}.sha256")
ACTUAL=$($SHASUM "${BUNDLE}" | awk '{print $1}')
[[ "$EXPECTED" == "$ACTUAL" ]] || { echo "FAIL: SHA mismatch"; exit 1; }

# 2. Authenticity + timestamp. CI signs with a GitHub Actions OIDC token,
# so a real pipeline run's certificate identity always comes from
# token.actions.githubusercontent.com AND from this specific repo's
# grc-gate.yml workflow on main. token.actions.githubusercontent.com is
# a shared issuer used by every public GitHub Actions workflow on Earth -
# pinning only the issuer (identity-regexp ".*") would let anyone with
# their own throwaway repo sign a blob and have it "verify" here. The
# identity string Sigstore embeds for a GitHub Actions signer is
# https://github.com/<owner>/<repo>/.github/workflows/<file>@<ref>.
cosign verify-blob \
  --bundle "${BUNDLE}.sig.bundle" \
  --certificate-identity 'https://github.com/itsrubenclarke/cgep-app-starter/.github/workflows/grc-gate.yml@refs/heads/main' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  "${BUNDLE}"

# 3. Preservation. Compared as epoch seconds, not raw strings - a naive
# string comparison (e.g. [[ "$RETAIN_UNTIL" > "$NOW" ]]) fails open if
# AWS ever returns something like the literal text "None" for a missing
# retention: "None" sorts lexicographically after any date string
# ("N" > any digit), so a broken/absent retention would wrongly compare
# as "still active." Reject non-date values explicitly instead.
RETAIN_UNTIL=$(aws $PROFILE_ARG s3api get-object-retention \
  --bucket "${VAULT}" --key "${PREFIX}/${BUNDLE}" \
  --query 'Retention.RetainUntilDate' --output text)
# GNU date (CI/Linux) handles this ISO8601-with-microseconds format
# directly; BSD date (local macOS testing) doesn't support -d at all, so
# fall back to Python, which is already relied on elsewhere in this repo.
RETAIN_UNTIL_EPOCH=$(date -u -d "$RETAIN_UNTIL" +%s 2>/dev/null) || \
  RETAIN_UNTIL_EPOCH=$(python3 -c "
import sys, datetime
try:
    print(int(datetime.datetime.fromisoformat(sys.argv[1]).timestamp()))
except Exception:
    sys.exit(1)
" "$RETAIN_UNTIL" 2>/dev/null) || {
  echo "FAIL: no valid retention date on this object (got \"$RETAIN_UNTIL\")" >&2
  exit 1
}
NOW_EPOCH=$(date -u +%s)
[[ "$RETAIN_UNTIL_EPOCH" -gt "$NOW_EPOCH" ]] || { echo "FAIL: retention expired"; exit 1; }

echo "CHAIN INTACT for run ${RUN_ID}"
