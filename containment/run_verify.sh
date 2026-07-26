#!/usr/bin/env bash
# containment/run_verify.sh — run the containment verification in an isolated
# object graph.
#
# Jac keeps its anchor store at `$PWD/.jac/data/anchor_store.db`, so running from
# a scratch directory with PYTHONPATH pointed at the repo gives this run its own
# empty graph. The repo's shared store, audit trail and control projection are
# never touched, and every run starts from the same known-empty world — which is
# what makes the numbers below reproducible rather than dependent on whatever
# happened to be in the graph.
#
# APP_CTX_SIGNING_KEY is a throwaway generated per run. It never leaves this
# script, is never written to disk, and is not a credential for anything real —
# the probes need SOME key because guard() verifies the ctx HMAC, and there is
# deliberately no way to skip that verification.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="${1:-$(mktemp -d)}"

mkdir -p "$WORK"
rm -rf "$WORK/.jac" "$WORK/var"

cd "$WORK"

export PYTHONPATH="$REPO"
export APP_CTX_SIGNING_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
export APP_AUDIT_LOG="$WORK/var/audit/audit.jsonl"
export CONTROLS_PATH="$WORK/var/controls/controls.json"
export CONTAINMENT_PENDING="$WORK/var/containment/pending.json"

echo "workspace : $WORK"
echo "repo      : $REPO"
echo

jac run "$REPO/containment/verify.jac"
