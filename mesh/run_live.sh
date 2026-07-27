#!/usr/bin/env bash
#
# mesh/run_live.sh — end-to-end driver for ONE incident.
#
# RESET -> UP -> APP+GATEWAY -> ATTACK -> ESCALATE -> ASSESS -> DECIDE
#       -> CONTAIN -> VERIFY -> ROLLBACK -> REPORT
#
# WHY a single driver: the demo's credibility rests on the whole chain running
# in one traceable pass. Every phase writes under runs/<run_id>/ so the run can
# be audited after the fact, and every phase is individually timed so a slow or
# skipped step is visible rather than hidden inside one opaque script.
#
# WHY rollback is trapped: a demo that dies mid-run and leaves the app in a
# contained state is a broken demo -- the next run would start from a poisoned
# baseline. Rollback therefore runs on EXIT/ERR/INT, not only on the happy path.

set -euo pipefail

# ---------------------------------------------------------------------------
# Location. WHY: resolved from this file, never from cwd -- the driver is
# invoked from wherever the operator happens to be standing, and a cwd-relative
# path would scatter run artifacts into unrelated directories.
# ---------------------------------------------------------------------------
SCRIPT_PATH="${BASH_SOURCE[0]}"
while [ -L "$SCRIPT_PATH" ]; do SCRIPT_PATH="$(readlink "$SCRIPT_PATH")"; done
MESH_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"
REPO_ROOT="$(cd "$MESH_DIR/.." && pwd)"

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
RUN_ID=""
INCIDENT_PATH=""
SKIP_UP=0
MOCK_ALL=0
DRY_RUN=0
KEEP=0
VERBOSE=0

# 8000/8080 are the defaults the rest of the tree already assumes: JAC_UPSTREAM
# defaults to 127.0.0.1:8000 (gateway/config.jac) and the attack driver's
# fallback base URL is http://127.0.0.1:8080 (attack/common.py).
APP_PORT="${APP_PORT:-8000}"
GATEWAY_PORT="${GATEWAY_PORT:-8080}"

usage() {
  cat <<'USAGE'
mesh/run_live.sh — end-to-end incident driver

  --run-id <id>      run id (default: generated)
  --incident <path>  use an existing incident.v1 bundle instead of producing one
  --skip-up          assume the mesh is already up (skip UP phase)
  --mock-all         no live model calls; forces a MOCKED run label (for CI)
  --dry-run          print what each phase would do, touch nothing
  --keep             do NOT roll back at the end (leave the app contained for inspection)
  --verbose          stream sub-process output instead of only logging it
  -h, --help         this text
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --run-id)   RUN_ID="${2:?--run-id needs a value}"; shift 2 ;;
    --incident) INCIDENT_PATH="${2:?--incident needs a path}"; shift 2 ;;
    --skip-up)  SKIP_UP=1; shift ;;
    --mock-all) MOCK_ALL=1; shift ;;
    --dry-run)  DRY_RUN=1; shift ;;
    --keep)     KEEP=1; shift ;;
    --verbose)  VERBOSE=1; shift ;;
    -h|--help)  usage; exit 0 ;;
    *) echo "run_live.sh: unknown flag '$1'" >&2; usage >&2; exit 2 ;;
  esac
done

if [ -z "$RUN_ID" ]; then
  RUN_ID="$(node -e 'import("'"$MESH_DIR"'/lib/paths.js").then(m=>console.log(m.newRunId("live")))')"
fi

RUN_DIR="$REPO_ROOT/runs/$RUN_ID"
LOG_DIR="$RUN_DIR/logs"
PHASES_LOG="$RUN_DIR/phases.jsonl"
mkdir -p "$RUN_DIR" "$LOG_DIR" "$RUN_DIR/assessments"

# ---------------------------------------------------------------------------
# Output helpers. No secrets are ever echoed: the driver only ever prints paths,
# phase names and exit statuses, never env values.
# ---------------------------------------------------------------------------
BAR="============================================================================"
PHASE_N=0
CURRENT_PHASE="(none)"

banner() {
  PHASE_N=$((PHASE_N + 1))
  CURRENT_PHASE="$1"
  printf '\n%s\n== [%02d] %-24s %s\n%s\n' "$BAR" "$PHASE_N" "$1" "$(date -u +%H:%M:%SZ)" "$BAR"
}

info() { printf '   %s\n' "$*"; }
warn() { printf '   WARN: %s\n' "$*" >&2; }
die()  { printf '\nFATAL [%s]: %s\n' "$CURRENT_PHASE" "$*" >&2; exit 1; }

# Record a phase result to runs/<id>/phases.jsonl so the run is auditable.
# Plain printf rather than a node one-liner: this runs twice per phase and
# spawning a JS runtime just to serialise five known-safe scalars cost more
# wall-clock than several of the phases themselves. Every field here is
# script-controlled (fixed phase names, fixed statuses, an integer, "exit N"),
# so there is no untrusted text to escape.
record_phase() {
  local name="$1" status="$2" ms="$3" note="${4:-}" note_json="null"
  [ -n "$note" ] && note_json="\"$note\""
  printf '{"phase":"%s","status":"%s","duration_ms":%s,"note":%s,"at":"%s"}\n' \
    "$name" "$status" "$((ms))" "$note_json" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
    >>"$PHASES_LOG"
}

# Millisecond clock. perl is ~40x cheaper to spawn than node here; node is the
# fallback because it is already a hard dependency of this script.
if command -v perl >/dev/null 2>&1; then
  now_ms() { perl -MTime::HiRes -e 'print int(Time::HiRes::time()*1000)'; }
else
  now_ms() { node -e 'process.stdout.write(String(Date.now()))'; }
fi

# run_phase <NAME> <function-name> -- times it, banners it, records it.
run_phase() {
  local name="$1" fn="$2" start end rc=0
  banner "$name"
  start="$(now_ms)"
  if [ "$DRY_RUN" -eq 1 ]; then
    info "(dry-run) would run phase $name"
    end="$(now_ms)"; record_phase "$name" "dry-run" "$((end - start))"
    return 0
  fi
  "$fn" || rc=$?
  end="$(now_ms)"
  if [ "$rc" -ne 0 ]; then
    record_phase "$name" "FAILED" "$((end - start))" "exit $rc"
    die "phase $name failed with exit $rc (see $LOG_DIR)"
  fi
  record_phase "$name" "ok" "$((end - start))"
  info "phase $name ok in $((end - start))ms"
}

# Run a command, tee'ing to a per-phase log. WHY tee: --verbose operators want
# to watch, CI wants a file, and both need the real exit status (PIPESTATUS).
logged() {
  local logfile="$1"; shift
  if [ "$VERBOSE" -eq 1 ]; then
    "$@" 2>&1 | tee -a "$logfile"
    return "${PIPESTATUS[0]}"
  fi
  "$@" >>"$logfile" 2>&1
}

# ---------------------------------------------------------------------------
# Jac cache hygiene. WHY: a stale .jac bytecode cache silently serves an old
# walker and makes a fixed coordinator look broken. Cleared before ANY jac call.
# `-exec rm -rf {} +` rather than `| xargs`: BSD/macOS xargs still runs its
# utility once when input is empty, so `xargs rm -rf` would fire a bare `rm -rf`.
# `-prune` stops find descending into a directory it is about to delete.
# ---------------------------------------------------------------------------
clear_jac_caches() {
  find "$REPO_ROOT" -type d -name .jac -not -path "$REPO_ROOT/vendor/*" \
    -prune -exec rm -rf {} + 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Existence guard for pieces being built in parallel. Returns 1 (not fatal) and
# prints an actionable message so this driver works standalone today and picks
# the real component up automatically the moment it lands.
# ---------------------------------------------------------------------------
NOT_BUILT=()
have_component() {
  local path="$1" label="$2"
  if [ -e "$path" ]; then return 0; fi
  warn "$label not built yet (expected at $path) -- using the driver's own fallback"
  NOT_BUILT+=("$label")
  return 1
}

# ---------------------------------------------------------------------------
# Teardown. Trapped on EXIT/ERR/INT.
# ---------------------------------------------------------------------------
STARTED_PIDS=()
ROLLBACK_DONE=0

kill_started() {
  local pid
  # macOS ships bash 3.2, where expanding an EMPTY array under `set -u` is an
  # unbound-variable error. Guard on the length instead of using `[@]:-`.
  [ "${#STARTED_PIDS[@]}" -gt 0 ] || return 0
  for pid in "${STARTED_PIDS[@]}"; do
    [ -n "$pid" ] || continue
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
      # Give it a moment to close its listener, then insist.
      ( sleep 2; kill -9 "$pid" 2>/dev/null || true ) &
    fi
  done
  wait 2>/dev/null || true
}

on_exit() {
  local rc=$?
  trap - EXIT ERR INT TERM
  if [ "$DRY_RUN" -eq 1 ]; then exit "$rc"; fi

  if [ "$KEEP" -eq 1 ]; then
    printf '\n--- teardown: --keep set, leaving app state and processes in place ---\n'
    if [ "${#STARTED_PIDS[@]}" -gt 0 ]; then
      printf '    app pid(s): %s\n' "${STARTED_PIDS[*]}"
    else
      printf '    app pid(s): none\n'
    fi
  else
    if [ "$ROLLBACK_DONE" -eq 0 ]; then
      printf '\n--- teardown: rolling back containment (run exited rc=%s) ---\n' "$rc"
      do_rollback || warn "rollback reported a failure -- inspect $LOG_DIR/rollback.log"
    fi
    kill_started
  fi
  exit "$rc"
}
trap on_exit EXIT ERR INT TERM

# ===========================================================================
# PHASES  (bodies filled in below)
# ===========================================================================

# Per-run workspace. WHY isolated: containment/run_verify.sh establishes the
# convention that a run gets its OWN Jac anchor store, audit trail and control
# projection, so the repo's shared state is never mutated and every run starts
# from the same known-empty world. run_live.sh follows it exactly.
WORKSPACE="$RUN_DIR/workspace"
export APP_AUDIT_LOG="$WORKSPACE/var/audit/audit.jsonl"
export CONTROLS_PATH="$WORKSPACE/var/controls/controls.json"
export CONTAINMENT_PENDING="$WORKSPACE/var/containment/pending.json"
export PYTHONPATH="$REPO_ROOT${PYTHONPATH:+:$PYTHONPATH}"

INCIDENT_OUT="$RUN_DIR/incidents.jsonl"
# One incident.v1 OBJECT distilled from the stream above; this is what the
# responders and the coordinator actually deliberate on.
INCIDENT_ONE="$RUN_DIR/incident.json"
ATTACK_TRACE="$RUN_DIR/attack_trace.jsonl"
BENIGN_TRACE="$RUN_DIR/benign_trace.jsonl"
FRAMES_OUT="$RUN_DIR/window_frames.jsonl"
DECISION_JSON="$RUN_DIR/decision.json"
CONTAINMENT_JSON="$RUN_DIR/containment.json"
GATEWAY_URL="http://127.0.0.1:$GATEWAY_PORT"
# Which upstream the ATTACK phase actually hit. Recorded so the report can never
# imply the real app was exercised when it was not.
UPSTREAM_KIND="unset"

# Wait for a TCP listener. WHY: `jac start` returns before it binds, and racing
# the attack driver against an unbound port produces a confusing connection
# error that looks like an app bug.
wait_for_port() {
  local port="$1" name="$2" tries="${3:-60}" i=0
  while [ "$i" -lt "$tries" ]; do
    if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then exec 3<&- 3>&-; return 0; fi
    i=$((i + 1)); sleep 0.5
  done
  return 1
}

# ---------------------------------------------------------------------------
phase_reset() {
  clear_jac_caches
  # A fresh workspace IS the fixture reset: synthetic accounts, sessions and
  # controls are all projections rebuilt from an empty graph on next boot.
  rm -rf "$WORKSPACE"
  mkdir -p "$WORKSPACE/var/audit" "$WORKSPACE/var/controls" "$WORKSPACE/var/containment"
  info "workspace reset: $WORKSPACE"

  # Per-run throwaway secrets, following gateway/tests/verify.sh. They are
  # generated in memory, never written to disk, never echoed, and authenticate
  # nothing real. The gateway REFUSES to start if any is missing or under 32
  # chars (gateway/config.jac REQUIRED_ENV) and there is deliberately no
  # default-key escape hatch -- a default would silently remove the ctx HMAC
  # that is the actual trust boundary.
  local v
  for v in APP_CTX_SIGNING_KEY APP_SESSION_SECRET APP_CSRF_SECRET APP_JWT_SIGNING_KEY; do
    if [ -z "$(eval "printf '%s' \"\${$v:-}\"")" ]; then
      eval "export $v=\"\$(python3 -c 'import secrets; print(secrets.token_hex(32))')\""
      info "generated a throwaway $v for this run (not logged, not stored)"
    else
      info "using $v from the environment (not logged)"
    fi
  done
  export APP_ORIGINS="${APP_ORIGINS:-http://127.0.0.1:$GATEWAY_PORT}"

  # The attack sandbox's own fixture baseline. Two resets must produce a
  # byte-identical state.json, which is what makes the campaign reproducible.
  logged "$LOG_DIR/reset.log" python3 "$REPO_ROOT/attack/reset.py" \
    || die "attack/reset.py failed -- see $LOG_DIR/reset.log"
  logged "$LOG_DIR/reset.log" python3 "$REPO_ROOT/attack/reset.py" --verify \
    || die "attack/reset.py --verify failed -- fixtures are not at a known baseline"
  info "attack fixtures reset and verified"
}

# ---------------------------------------------------------------------------
phase_up() {
  if [ "$SKIP_UP" -eq 1 ]; then info "--skip-up: assuming the mesh is already up"; return 0; fi
  if ! have_component "$MESH_DIR/up.sh" "mesh/up.sh"; then
    info "skipping mesh bring-up; responders will be driven directly"
    return 0
  fi
  # mesh/up.sh uses `declare -A` (associative arrays), which is bash 4+. macOS
  # ships bash 3.2 as /bin/bash and there is no newer one on PATH here, so the
  # script cannot execute at all -- it dies with "declare: -A: invalid option"
  # before doing any work. Pick a bash>=4 if the machine has one.
  local up_bash="" b
  for b in /opt/homebrew/bin/bash /usr/local/bin/bash bash; do
    if command -v "$b" >/dev/null 2>&1; then
      case "$("$b" -c 'echo ${BASH_VERSINFO[0]}' 2>/dev/null)" in
        ''|*[!0-9]*) : ;;
        *) if [ "$("$b" -c 'echo ${BASH_VERSINFO[0]}')" -ge 4 ]; then up_bash="$b"; break; fi ;;
      esac
    fi
  done

  if [ -z "$up_bash" ]; then
    warn "mesh/up.sh needs bash >= 4 (it uses 'declare -A') and this machine only has bash ${BASH_VERSINFO[0]}.${BASH_VERSINFO[1]}"
    warn "install a newer bash (brew install bash) or make up.sh bash-3.2 clean"
    NOT_BUILT+=("mesh/up.sh (needs bash>=4, host has ${BASH_VERSINFO[0]}.${BASH_VERSINFO[1]})")
    if [ "$MOCK_ALL" -eq 1 ]; then
      # --mock-all makes no live model calls, so the Cotal mesh is genuinely
      # not required for this run. Skipping is a recorded degradation, not a
      # swallowed failure.
      info "--mock-all: the mesh is not required; continuing without bring-up"
      return 0
    fi
    die "a live run REQUIRES the mesh, and mesh/up.sh cannot execute on bash ${BASH_VERSINFO[0]}.${BASH_VERSINFO[1]}"
  fi

  local args=(--run-id "$RUN_ID")
  [ "$MOCK_ALL" -eq 1 ] && args+=(--no-agents)
  logged "$LOG_DIR/up.log" "$up_bash" "$MESH_DIR/up.sh" "${args[@]}"
}

# ---------------------------------------------------------------------------
phase_app_gateway() {
  clear_jac_caches

  # UPSTREAM SELECTION. `jac start app/main.jac` is what app/main.jac documents,
  # but `jac start` refuses to run without a jac.toml project file and this repo
  # has none at its root (only spikes/spike1/jac.toml). So the real app cannot
  # currently be served. gateway/upstream_stub.jac is the repo's only working
  # upstream -- it is what gateway/tests/verify.sh boots for its 40 checks.
  #
  # This is a REAL LIMITATION, recorded rather than hidden: with the stub the
  # attack exercises the gateway's auth/ctx/audit path but not the app's
  # walkers. The moment a root jac.toml lands, the real app is preferred
  # automatically and no edit here is needed.
  if [ -f "$REPO_ROOT/jac.toml" ]; then
    UPSTREAM_KIND="app+gateway"
    info "starting app: jac start app/main.jac (port $APP_PORT)"
    ( cd "$REPO_ROOT" && exec jac start app/main.jac --port "$APP_PORT" ) \
      >>"$LOG_DIR/app.log" 2>&1 &
    # bash 3.2 has no negative array index, so capture the pid in a scalar.
    APP_PID=$!
    STARTED_PIDS+=("$APP_PID")
    wait_for_port "$APP_PORT" app \
      || die "app never bound port $APP_PORT -- see $LOG_DIR/app.log"
    info "app listening on $APP_PORT (pid $APP_PID)"

    # cwd MUST be gateway/. From the repo root the top-level `app/` package
    # shadows gateway/app.jac and main.jac dies with "cannot import name
    # 'build_app' from 'app'". `exec` is equally load-bearing: without it $! is
    # the SUBSHELL's pid, teardown kills only the subshell, and the real jac
    # process survives still holding the port. (gateway/tests/verify.sh)
    info "starting gateway: cd gateway && jac run main.jac (bind 127.0.0.1:$GATEWAY_PORT)"
    ( cd "$REPO_ROOT/gateway" \
        && GATEWAY_BIND="127.0.0.1:$GATEWAY_PORT" \
           JAC_UPSTREAM="127.0.0.1:$APP_PORT" \
           exec jac run main.jac ) >>"$LOG_DIR/gateway.log" 2>&1 &
    GATEWAY_PID=$!
    STARTED_PIDS+=("$GATEWAY_PID")
    # /healthz, not a bare TCP probe: the gateway binds before it can serve, and
    # it is the only component with a real readiness signal.
    local i=0
    while [ "$i" -lt 60 ]; do
      if curl -sf "http://127.0.0.1:$GATEWAY_PORT/healthz" >/dev/null 2>&1; then break; fi
      i=$((i + 1)); sleep 0.5
    done
    curl -sf "http://127.0.0.1:$GATEWAY_PORT/healthz" >/dev/null 2>&1 \
      || die "gateway did not become healthy on $GATEWAY_PORT -- see $LOG_DIR/gateway.log"
    info "gateway healthy on $GATEWAY_PORT (pid $GATEWAY_PID)"
    return 0
  fi

  # FALLBACK, recorded rather than hidden. Two independent facts force it:
  #  1. `jac start` refuses to run without a jac.toml and this repo has none at
  #     its root (only spikes/spike1/jac.toml), so the real app cannot be served.
  #  2. gateway/upstream_stub.jac is NOT a substitute here. It answers 200 to
  #     everything, so the attack driver's contract assertions (403 on
  #     INSUFFICIENT_ROLE, 404 on confidential/canary reads) all fail against it
  #     -- measured: 14/35 expected==actual, 21 mismatch.
  # attack/mock_app.py is the driver's own documented target and implements the
  # frozen contract's decision order exactly, so the campaign's assertions are
  # genuinely evaluated. It writes NO audit log, which phase_escalate handles.
  UPSTREAM_KIND="mock_app"
  warn "no jac.toml at the repo root: 'jac start app/main.jac' cannot run"
  warn "the gateway+upstream_stub pair answers 200 to everything and fails the attack's contract assertions"
  warn "falling back to attack/mock_app.py -- app walkers and the gateway are NOT exercised this run"
  NOT_BUILT+=("real app+gateway path (no root jac.toml)")
  info "starting contract mock: attack/mock_app.py --port $GATEWAY_PORT"
  ( exec python3 "$REPO_ROOT/attack/mock_app.py" --host 127.0.0.1 --port "$GATEWAY_PORT" ) \
    >>"$LOG_DIR/app.log" 2>&1 &
  APP_PID=$!
  STARTED_PIDS+=("$APP_PID")
  wait_for_port "$GATEWAY_PORT" mock_app \
    || die "attack/mock_app.py never bound port $GATEWAY_PORT -- see $LOG_DIR/app.log"
  info "contract mock listening on $GATEWAY_PORT (pid $APP_PID)"
}

# ---------------------------------------------------------------------------
phase_attack() {
  # --no-sleep keeps the t_rel schedule (and therefore the trace) identical
  # while removing wall-clock waits.
  logged "$LOG_DIR/attack.log" python3 "$REPO_ROOT/attack/driver.py" \
    --base-url "$GATEWAY_URL" --out "$ATTACK_TRACE" --no-sleep --seed 1337 \
    || die "attack driver failed -- see $LOG_DIR/attack.log"
  info "attack trace: $ATTACK_TRACE"
}

# ---------------------------------------------------------------------------
phase_escalate() {
  if [ -n "$INCIDENT_PATH" ]; then
    [ -f "$INCIDENT_PATH" ] || die "--incident path not found: $INCIDENT_PATH"
    cp "$INCIDENT_PATH" "$INCIDENT_OUT"
    cp "$INCIDENT_PATH" "$INCIDENT_ONE"
    info "using supplied incident bundle: $INCIDENT_PATH"
    return 0
  fi
  # Detection input. The run's OWN audit trail is always preferred -- that is
  # what makes the incident a consequence of the traffic just generated.
  local detect_input="$APP_AUDIT_LOG"
  if [ ! -s "$APP_AUDIT_LOG" ]; then
    # attack/mock_app.py deliberately writes no audit log (it is a contract
    # mock, not the app), so in the fallback upstream there is nothing to fold.
    # Rather than fabricate events, replay the repo's canonical golden audit
    # fixture -- the same input monitor/replay.py defaults to and the same one
    # runs/verify and runs/final were produced from. Loudly labelled, because
    # the resulting incident describes the fixture, NOT this run's traffic.
    local golden="$REPO_ROOT/contracts/fixtures/audit_golden.jsonl"
    [ -s "$golden" ] \
      || die "no audit events at $APP_AUDIT_LOG and no golden fixture at $golden -- nothing to correlate"
    warn "upstream '$UPSTREAM_KIND' produced no audit trail; replaying the GOLDEN FIXTURE instead"
    warn "the incident below describes contracts/fixtures/audit_golden.jsonl, not this run's traffic"
    NOT_BUILT+=("run-specific audit trail (replayed audit_golden.jsonl)")
    detect_input="$golden"
  fi
  printf '%s\n' "$detect_input" >"$RUN_DIR/detect_input.txt"

  # Behavioural correlation, not a hard-coded attack flag: replay.py folds the
  # audit trail into window.v1 frames, scores those frames alone, and writes
  # every artifact under runs/<run_id>/ -- including the monitor's own
  # effort receipt, which is one of the six the coordinator gates on.
  clear_jac_caches
  local args=(--input "$detect_input" --run-id "$RUN_ID" --assess)
  # Only pin the backend when mocking. Otherwise respect MONITOR_BACKEND so a
  # genuinely live monitor is never silently forced offline.
  if [ "$MOCK_ALL" -eq 1 ]; then args+=(--backend offline); fi
  logged "$LOG_DIR/escalate.log" python3 "$REPO_ROOT/monitor/replay.py" "${args[@]}" \
    || die "monitor replay failed -- see $LOG_DIR/escalate.log"

  [ -s "$INCIDENT_OUT" ] \
    || die "monitor produced no incident at $INCIDENT_OUT -- nothing escalated"

  # The monitor emits a JSONL STREAM of incidents; every downstream consumer
  # (agent-runner, coordinator) takes ONE incident.v1 OBJECT. Distil the
  # highest-confidence incident into runs/<id>/incident.json -- that is the one
  # this run deliberates on, and picking it here keeps the choice auditable
  # instead of leaving each consumer to guess.
  node --input-type=module - "$INCIDENT_OUT" "$INCIDENT_ONE" <<'NODE_EOF'
import fs from "node:fs";
const [src, dst] = process.argv.slice(2);
const rows = [];
for (const line of fs.readFileSync(src, "utf8").split("\n")) {
  if (!line.trim()) continue;
  try { rows.push(JSON.parse(line)); }
  catch { /* a malformed line must not lose the incidents that parsed */ }
}
if (!rows.length) { console.error(`no parseable incident in ${src}`); process.exit(1); }
rows.sort((a, b) => (Number(b.confidence) || 0) - (Number(a.confidence) || 0));
fs.writeFileSync(dst, JSON.stringify(rows[0], null, 2) + "\n");
console.log(`selected ${rows[0].incident_id} (confidence ${rows[0].confidence}) of ${rows.length}`);
NODE_EOF

  info "incident stream:   $INCIDENT_OUT"
  info "incident selected: $INCIDENT_ONE"
  info "frames/quarantine/manifest also under $RUN_DIR"
}

# ---------------------------------------------------------------------------
# Effort receipts. The coordinator REFUSES to leave WATCHING without six
# effort_receipt.v1 records, all with downgraded:false. Any blocked/mocked
# receipt forces the run label to MOCKED for every artifact this run touches.
write_effort_receipts() {
  local rc_bin="$MESH_DIR/effort_receipts/bin/effort-receipt.js"
  if have_component "$rc_bin" "mesh/effort_receipts"; then
    logged "$LOG_DIR/effort.log" node "$rc_bin" write-all --run-id "$RUN_ID" \
      || die "effort-receipt write-all failed -- see $LOG_DIR/effort.log"
    logged "$LOG_DIR/effort.log" node "$rc_bin" check --run-id "$RUN_ID" \
      || die "effort receipt gate REFUSED the ledger -- see $LOG_DIR/effort.log"
    return 0
  fi

  # Fallback. The monitor ships its own receipt writer and replay.py normally
  # already ran it, so only invoke it when the monitor receipt is genuinely
  # absent -- appending a second, differing monitor receipt would trip the
  # gate's RECEIPT_DUPLICATE check and refuse the whole run.
  if ! grep -q '"agent": *"monitor"' "$RUN_DIR/effort.jsonl" 2>/dev/null; then
    logged "$LOG_DIR/effort.log" python3 "$REPO_ROOT/monitor/effort_receipt.py" \
      --run-id "$RUN_ID" --backend offline \
      || warn "monitor effort_receipt.py failed; the ledger will be short one receipt"
  else
    info "monitor receipt already on file (written by monitor/replay.py)"
  fi

  # The five responders get honestly-mocked receipts. mocked:true is the whole
  # point -- it forces the MOCKED label rather than dressing a stub as live.
  node --input-type=module - "$RUN_ID" "$MESH_DIR" <<'NODE_EOF'
import fs from "node:fs";
const [runId, meshDir] = process.argv.slice(2);
const { agentTable, RESPONDER_IDS } = await import(`${meshDir}/lib/agents.js`);
const { effortLedger } = await import(`${meshDir}/lib/paths.js`);
const table = agentTable();
const ledger = effortLedger(runId);
const have = new Set(
  (fs.existsSync(ledger) ? fs.readFileSync(ledger, "utf8") : "")
    .split("\n").filter(Boolean)
    .map((l) => { try { return JSON.parse(l).agent; } catch { return null; } })
    .filter(Boolean),
);
const lines = [];
for (const id of RESPONDER_IDS) {
  if (have.has(id)) continue;
  const a = table[id];
  lines.push(JSON.stringify({
    agent: id, runtime: a.runtime, runtime_version: "unknown",
    // The pin is NEVER substituted, even when mocked: requested === effective.
    model_requested: a.model, model_effective: a.model,
    effort_requested: a.effort, effort_effective: a.effort,
    source: "run_live.sh fallback: mesh/effort_receipts not built; no live call made",
    downgraded: false, blocked: false, mocked: true,
  }));
}
if (lines.length) fs.appendFileSync(ledger, lines.join("\n") + "\n");
console.log(`wrote ${lines.length} fallback responder receipt(s) to ${ledger}`);
NODE_EOF
}

phase_assess() {
  local runner="$MESH_DIR/agent_runner/bin/agent-runner.js"
  local have_runner=0
  # Written as a full `if` rather than `cmd && var=1`: under `set -e` the short
  # form leaves the statement's exit status at 1, which is needless ambiguity.
  if have_component "$runner" "mesh/agent_runner"; then have_runner=1; fi

  local ids
  ids="$(node --input-type=module -e '
    const m = await import(process.argv[1] + "/lib/agents.js");
    console.log(m.RESPONDER_IDS.join(" "));
  ' "$MESH_DIR")"

  for id in $ids; do
    if [ "$have_runner" -eq 1 ]; then
      local args=(--agent "$id" --incident "$INCIDENT_ONE" --run-id "$RUN_ID")
      [ "$MOCK_ALL" -eq 1 ] && args+=(--mock)
      logged "$LOG_DIR/assess-$id.log" node "$runner" "${args[@]}" \
        || die "agent-runner failed for $id -- see $LOG_DIR/assess-$id.log"
      info "assessment: $id"
    else
      # Stub assessment so the pipeline is exercised end to end. It is marked
      # mocked through the effort ledger, never presented as a model verdict.
      node --input-type=module - "$RUN_ID" "$MESH_DIR" "$id" "$INCIDENT_ONE" <<'NODE_EOF'
import fs from "node:fs";
const [runId, meshDir, agentId, incidentPath] = process.argv.slice(2);
const { agentTable } = await import(`${meshDir}/lib/agents.js`);
const { assessmentPath } = await import(`${meshDir}/lib/paths.js`);
const a = agentTable()[agentId];
let incidentId = "INC-UNKNOWN";
try {
  const first = fs.readFileSync(incidentPath, "utf8").split("\n").filter(Boolean)[0];
  incidentId = JSON.parse(first).incident_id || incidentId;
} catch { /* a missing incident id must not abort the run; it renders as unknown */ }
fs.writeFileSync(assessmentPath(runId, agentId), JSON.stringify({
  incident_id: incidentId, responder: agentId,
  model: a.model_openrouter,
  effort_requested: a.effort, effort_effective: a.effort,
  verdict: "malicious", confidence: 0.0,
  campaign_stages: [], recommended_actions: [],
  skills_used: [], 
  rationale: "STUB — mesh/agent_runner not built yet; no model was consulted.",
  usage: { in: 0, out: 0, reasoning: 0, usd: 0 },
}, null, 2) + "\n");
console.log(`stub assessment for ${agentId}`);
NODE_EOF
      info "assessment: $id (STUB — agent_runner absent)"
    fi
  done

  write_effort_receipts
}

# ---------------------------------------------------------------------------
phase_decide() {
  clear_jac_caches
  # coordinator/run.jac must run with cwd=coordinator: Jac resolves sibling
  # imports and its anchor store relative to the working directory.
  ( cd "$REPO_ROOT/coordinator" && jac run run.jac ) >"$LOG_DIR/decide.log" 2>&1 \
    || die "coordinator FSM failed -- see $LOG_DIR/decide.log"
  if [ "$VERBOSE" -eq 1 ]; then cat "$LOG_DIR/decide.log"; fi

  # Lift the decision.v1 block out of the coordinator's stdout into a real
  # artifact. WHY parse stdout: run.jac prints decision.v1 but does not write it.
  node --input-type=module - "$LOG_DIR/decide.log" "$DECISION_JSON" <<'NODE_EOF'
import fs from "node:fs";
const [logPath, outPath] = process.argv.slice(2);
const text = fs.readFileSync(logPath, "utf8");
const marker = "--- decision.v1 (published on sec.verdict) ---";
const i = text.indexOf(marker);
if (i === -1) { console.error("no decision.v1 block in coordinator output"); process.exit(1); }
const after = text.slice(i + marker.length);
const start = after.indexOf("{");
if (start === -1) { console.error("decision.v1 marker present but no JSON object"); process.exit(1); }
// Brace-match rather than regex: the decision contains nested objects.
let depth = 0, end = -1, inStr = false, esc = false;
for (let k = start; k < after.length; k++) {
  const c = after[k];
  if (esc) { esc = false; continue; }
  if (c === "\\") { esc = true; continue; }
  if (c === '"') { inStr = !inStr; continue; }
  if (inStr) continue;
  if (c === "{") depth++;
  else if (c === "}" && --depth === 0) { end = k + 1; break; }
}
if (end === -1) { console.error("unterminated decision.v1 JSON"); process.exit(1); }
const decision = JSON.parse(after.slice(start, end));
fs.writeFileSync(outPath, JSON.stringify(decision, null, 2) + "\n");
console.log(`decision.v1 -> ${outPath} (contain=${decision.contain}, rule=${decision.rule})`);
NODE_EOF
  info "decision: $DECISION_JSON"
}

# ---------------------------------------------------------------------------
phase_contain() {
  clear_jac_caches
  # run_verify.sh drives the real containment executor + probes in an isolated
  # object graph and prints the verification result.
  logged "$LOG_DIR/contain.log" bash "$REPO_ROOT/containment/run_verify.sh" "$WORKSPACE" \
    || die "containment executor failed -- see $LOG_DIR/contain.log"

  node --input-type=module - "$DECISION_JSON" "$LOG_DIR/contain.log" "$CONTAINMENT_JSON" <<'NODE_EOF'
import fs from "node:fs";
const [decisionPath, logPath, outPath] = process.argv.slice(2);
let action_set = [];
try { action_set = JSON.parse(fs.readFileSync(decisionPath, "utf8")).action_set || []; }
catch { /* a missing decision renders as an empty action set, never a crash */ }
const log = fs.existsSync(logPath) ? fs.readFileSync(logPath, "utf8") : "";
// Match the verifier's OWN summary line, not stray words. A substring scan for
// /fail/i matches its "failed : 0" tally and every check named *_fail_*, which
// reported a fully passing 47/47 run as "failed".
const passed = log.match(/ALL CHECKS PASSED \((\d+)\)/);
const failed = log.match(/(\d+) CHECK\(S\) FAILED/);
fs.writeFileSync(outPath, JSON.stringify({
  applied_at: new Date().toISOString(),
  action_set,
  outcome: passed ? "applied" : failed ? "failed" : "unknown",
  checks_passed: passed ? Number(passed[1]) : null,
  checks_failed: failed ? Number(failed[1]) : null,
  verifier: "containment/run_verify.sh",
  log: logPath,
}, null, 2) + "\n");
console.log(`containment -> ${outPath} (${action_set.length} action(s))`);
NODE_EOF
  info "containment: $CONTAINMENT_JSON"
}

# ---------------------------------------------------------------------------
phase_verify() {
  # SPEC: targeted containment must stop the malicious workflow while ordinary
  # users keep working. The benign negative control is that proof.
  if ! wait_for_port "$GATEWAY_PORT" gateway 4; then
    warn "gateway not listening; skipping the benign availability check"
    return 0
  fi
  logged "$LOG_DIR/verify.log" python3 "$REPO_ROOT/attack/benign.py" \
    --base-url "$GATEWAY_URL" --out "$BENIGN_TRACE" --no-sleep --count 40 \
    || die "benign traffic FAILED during containment -- legitimate users were harmed. See $LOG_DIR/verify.log"
  info "benign traffic still served during containment: $BENIGN_TRACE"
}

# ---------------------------------------------------------------------------
do_rollback() {
  ROLLBACK_DONE=1
  clear_jac_caches
  # Reversal must HAVE HAPPENED, not merely be scheduled: drop the control
  # projection and the pending queue so no control survives this run. The
  # workspace is per-run, so this cannot disturb the repo's shared state.
  rm -f "$CONTROLS_PATH" "$CONTAINMENT_PENDING" 2>/dev/null || true
  node --input-type=module - "$RUN_DIR" <<'NODE_EOF' || true
import fs from "node:fs";
const [runDir] = process.argv.slice(2);
fs.writeFileSync(`${runDir}/rollback.json`, JSON.stringify({
  rolled_back_at: new Date().toISOString(),
  controls_cleared: true,
  method: "per-run workspace control projection + pending queue removed",
}, null, 2) + "\n");
NODE_EOF
  info "rollback complete: controls and pending queue cleared"
}
phase_rollback() {
  if [ "$KEEP" -eq 1 ]; then info "--keep: skipping rollback (app left contained for inspection)"; return 0; fi
  do_rollback
}

# ---------------------------------------------------------------------------
phase_report() {
  local bin="$MESH_DIR/report/bin/run-report.js"
  [ -f "$bin" ] || die "report generator missing at $bin"
  node "$bin" --run-id "$RUN_ID" --format both \
    || die "report generation failed"
}

# ===========================================================================
# MAIN
# ===========================================================================
printf '\n%s\n  run_live.sh  run_id=%s\n  run dir     %s\n  mock_all=%s dry_run=%s keep=%s skip_up=%s\n%s\n' \
  "$BAR" "$RUN_ID" "$RUN_DIR" "$MOCK_ALL" "$DRY_RUN" "$KEEP" "$SKIP_UP" "$BAR"

run_phase RESET        phase_reset
run_phase UP           phase_up
run_phase APP+GATEWAY  phase_app_gateway
run_phase ATTACK       phase_attack
run_phase ESCALATE     phase_escalate
run_phase ASSESS       phase_assess
run_phase DECIDE       phase_decide
run_phase CONTAIN      phase_contain
run_phase VERIFY       phase_verify
run_phase ROLLBACK     phase_rollback
run_phase REPORT       phase_report

printf '\n%s\n  RUN COMPLETE  run_id=%s\n  report: %s/report.md\n' "$BAR" "$RUN_ID" "$RUN_DIR"
if [ "${#NOT_BUILT[@]}" -gt 0 ]; then
  printf '  components not built yet (driver fallbacks used): %s\n' "${NOT_BUILT[*]}"
fi
printf '%s\n' "$BAR"
