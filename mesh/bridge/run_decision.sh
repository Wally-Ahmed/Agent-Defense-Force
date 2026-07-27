#!/usr/bin/env bash
# mesh/bridge/run_decision.sh — drive the live coordinator run for one run id.
#
#   MESH_RUN_ID=six-live bash mesh/bridge/run_decision.sh
#
# DECIDE -> CONTAIN -> VERIFY -> ROLLBACK, against the run's REAL effort
# receipts and the REAL assessments already on disk. It never launches a
# harness, never calls a model and never spends a token: the responders are
# built with spawn=false and read runs/<id>/assessments/*.json.
#
# WHY A WRAPPER AT ALL. Three things have to be true before run_decision.jac can
# import, and none of them can be arranged from inside it:
#
#   1. Jac keeps its object graph at `$PWD/.jac/data/anchor_store.db`. Running
#      from the repo root would seed the incident's world into the repo's shared
#      store and leave it there. A per-run workspace gives this run its own empty
#      graph — the convention containment/run_verify.sh established.
#   2. app/security/keys.jac raises at IMPORT time unless APP_CTX_SIGNING_KEY is
#      set, and the containment probes genuinely verify the ctx HMAC — there is
#      deliberately no way to skip that. So the key has to exist before the
#      interpreter reaches the first import.
#   3. The audit log is append-only and rollback cannot undo it. Pointing it at
#      the workspace keeps a verification run from accumulating in the repo's
#      real trail.
#
# APP_CTX_SIGNING_KEY is a throwaway generated per run. It is not a credential
# for anything real, it never leaves this process, and it is never written to
# disk or committed. Nothing here reads a credential from anywhere.

set -euo pipefail

SCRIPT_PATH="${BASH_SOURCE[0]}"
while [ -L "$SCRIPT_PATH" ]; do SCRIPT_PATH="$(readlink "$SCRIPT_PATH")"; done
BRIDGE_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"
REPO="$(cd "$BRIDGE_DIR/../.." && pwd)"

RUN_ID="${MESH_RUN_ID:-six-live}"
RUN_DIR="$REPO/runs/$RUN_ID"
WORK="${MESH_WORKSPACE:-$RUN_DIR/workspace}"

if [ ! -d "$RUN_DIR" ]; then
  echo "FATAL: no run directory at $RUN_DIR" >&2
  exit 1
fi
if [ ! -f "$RUN_DIR/effort.jsonl" ]; then
  echo "FATAL: no effort receipts at $RUN_DIR/effort.jsonl -- the gate cannot open" >&2
  exit 1
fi

# Jac cache hygiene. A stale .jac bytecode cache silently serves an old module
# and makes a fixed driver look broken. `-exec rm -rf {} +` rather than a pipe
# into xargs: BSD/macOS xargs still runs its utility once on empty input, so
# `xargs rm -rf` would fire a bare `rm -rf`. `-prune` stops find descending into
# a directory it is about to delete.
find "$REPO" -type d -name .jac -not -path "$REPO/vendor/*" \
  -prune -exec rm -rf {} + 2>/dev/null || true

# A fresh world every time: the run must not depend on what a previous run left.
rm -rf "$WORK/.jac" "$WORK/var"
mkdir -p "$WORK"
cd "$WORK"

export PYTHONPATH="$REPO"
export APP_CTX_SIGNING_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
export APP_AUDIT_LOG="$WORK/var/audit/audit.jsonl"
export CONTROLS_PATH="$WORK/var/controls/controls.json"
export CONTAINMENT_PENDING="$WORK/var/containment/pending.json"
export MESH_RUN_ID="$RUN_ID"

echo "run id    : $RUN_ID"
echo "repo      : $REPO"
echo "workspace : $WORK"
echo

jac run "$REPO/mesh/bridge/run_decision.jac"
