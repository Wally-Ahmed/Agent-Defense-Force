#!/usr/bin/env bash
# mesh/complete_run.sh
#
# Drives the decision -> containment -> verify -> rollback tail of runs/six-live
# with the real coordinator and the real containment executor.
#
#   ./mesh/complete_run.sh [--incident-id <id>]
#
# ISOLATION, copied from containment/run_verify.sh: Jac anchors its object store
# at $PWD/.jac/data/anchor_store.db, so this runs from a scratch directory and
# gets an empty graph. The repo's shared state is never touched, and two runs
# cannot contaminate each other.
#
# CREDENTIALS: APP_CTX_SIGNING_KEY is required by app/security/keys.jac at import
# time and must be >=32 bytes. If the operator already exported one it is used
# and never printed; otherwise a throwaway is generated in memory for this run
# only. It authenticates nothing real and is never written to an artifact.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$REPO/runs/six-live/workspace"

rm -rf "$WORK"
mkdir -p "$WORK/var/audit" "$WORK/var/controls" "$WORK/var/containment"

export PYTHONPATH="$REPO${PYTHONPATH:+:$PYTHONPATH}"
export APP_AUDIT_LOG="$WORK/var/audit/audit.jsonl"
export CONTROLS_PATH="$WORK/var/controls/controls.json"
export CONTAINMENT_PENDING="$WORK/var/containment/pending.json"
if [ -z "${APP_CTX_SIGNING_KEY:-}" ]; then
  APP_CTX_SIGNING_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
  export APP_CTX_SIGNING_KEY
  echo "  (generated a throwaway APP_CTX_SIGNING_KEY for this run -- not logged, not stored)"
fi

# Stale .jir caches silently ignore edits (docs/running-tests.md).
find "$REPO" -type d -name .jac -not -path "$REPO/vendor/*" -print0 2>/dev/null \
  | xargs -0 rm -rf 2>/dev/null || true

cd "$WORK"
exec jac run "$REPO/mesh/complete_run.jac" "$@"
