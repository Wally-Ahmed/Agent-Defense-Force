#!/usr/bin/env bash
#
# mesh/up.sh — bring the Cotal mesh up, idempotently.
#
# PREFLIGHT -> NATS -> MINT -> ACL -> CONNECTORS -> AGENTS -> SUMMARY
#
# WHY a single script: every one of these steps has a "did it already happen?"
# question with a different answer source (a pidfile, a creds file, an npm
# manifest, a manager roster). Splitting them across scripts loses the shared
# agent table and invites a second, hand-typed copy of the ACL matrix — which is
# a security bug, not a style problem. The matrix is read from
# mesh/lib/agents.js (itself a transcription of the frozen
# contracts/mesh/channels.yaml) and is never retyped here.
#
# WHY nothing is `|| true`d: a mesh that half-came-up and reported success is
# worse than one that refused. The only tolerated failure in the whole script is
# ONE precisely-identified upstream defect (see PHASE 3), detected by its exact
# message, cited, and routed to Cotal's own alternate provisioning path.
# Everything else aborts.
#
# WHY it is written to bash 3.2: /bin/bash on macOS is 3.2.57 and there is no
# newer bash on this machine, so `#!/usr/bin/env bash` resolves to 3.2. That
# rules out associative arrays, `mapfile`, and a heredoc nested inside `$(...)`.
# The id->status maps below are therefore TSV strings with getter/setter
# functions, and the embedded Node programs are emitted by functions rather than
# captured into variables.
#
# CREDENTIAL RULE: this script prints credential PATHS, PERMISSION BITS, and the
# CHANNEL NAMES decoded out of a credential's NATS grants. It never prints,
# cats, logs, or copies credential material — not a prefix, not a byte.

set -euo pipefail

# ---------------------------------------------------------------------------
# Roots. Resolved from this file, never from cwd: up.sh is run from the repo
# root, from mesh/, and from CI, and a cwd-relative path would silently drop run
# artifacts into whatever directory the operator happened to be standing in.
# ---------------------------------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
MESH_DIR="${REPO_ROOT}/mesh"
AGENTS_JS_URL="file://${MESH_DIR}/lib/agents.js"
COTAL_CLONE="/Users/wally/Documents/GitHub/Cotal"
COTAL_CLONE_SHA="5da35eb3250133f7fd9d8a8d482c2a2b3fcfce89"
COTAL_ROOT="${REPO_ROOT}/.cotal"
CREDS_DIR="${COTAL_ROOT}/auth/creds"
PERSONA_DIR="${COTAL_ROOT}/agents"
NATS_PIDFILE="${COTAL_ROOT}/nats.pid"
NATS_LOG="${COTAL_ROOT}/nats.log"

AGENT_RUNNER="${MESH_DIR}/agent_runner/bin/agent-runner.js"
EFFORT_RECEIPT="${MESH_DIR}/effort_receipts/bin/effort-receipt.js"

# ---------------------------------------------------------------------------
# .env — loaded ONCE, here, before anything reads a credential or spawns a child.
#
# It used to be sourced halfway down, inside phase_preflight, which meant every
# process this script launched before that point ran without it. `set -a` marks
# what follows for export, so every child -- cotal, the connectors, the harnesses
# -- inherits these; hermes and opencode both read OPENROUTER_API_KEY straight
# out of that inherited environment and need no stored credential of their own.
#
# The VALUE is never echoed, logged or length-reported anywhere in this script.
# Only "empty / present / accepted (HTTP 200)" is ever printed.
# ---------------------------------------------------------------------------
if [ -f "${REPO_ROOT}/.env" ]; then
  # shellcheck disable=SC1091
  set -a; . "${REPO_ROOT}/.env"; set +a
fi

# ---------------------------------------------------------------------------
# Flags
# ---------------------------------------------------------------------------
RUN_ID=""
DRY_RUN=0
FORCE=0
NO_AGENTS=0
VERBOSE=0
INCIDENT=""

usage() {
  cat <<'USAGE'
mesh/up.sh - bring the Cotal mesh up, idempotently.

usage: mesh/up.sh [--run-id <id>] [--incident <path>] [--dry-run] [--force]
                  [--no-agents] [--verbose] [-h|--help]

  --run-id <id>     run identifier for artifacts + effort receipts (default: generated)
  --incident <path> incident.v1 JSON to hand to mesh/agent_runner (optional; when
                    omitted the AGENTS phase launches agents onto the mesh but
                    drives no assessment)
  --dry-run         print every command that would run; execute nothing mutating
  --force           re-mint creds and rewrite personas even when they already exist
  --no-agents       bring the mesh up (nats + creds + acl + connectors); launch no agents
  --verbose         echo every external command before running it
  -h, --help        this text

Phases: PREFLIGHT -> NATS -> MINT -> ACL -> CONNECTORS -> AGENTS -> SUMMARY.
Every phase is individually re-runnable; re-running the whole script is a no-op
for anything already done.
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --run-id)    RUN_ID="${2:?--run-id needs a value}"; shift 2 ;;
    --incident)  INCIDENT="${2:?--incident needs a path}"; shift 2 ;;
    --dry-run)   DRY_RUN=1; shift ;;
    --force)     FORCE=1; shift ;;
    --no-agents) NO_AGENTS=1; shift ;;
    --verbose)   VERBOSE=1; shift ;;
    -h|--help)   usage; exit 0 ;;
    *) printf 'mesh/up.sh: unknown flag "%s"\n\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
if [ -t 1 ]; then
  C_RST=$'\033[0m'; C_B=$'\033[1m'; C_DIM=$'\033[2m'
  C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'; C_CYA=$'\033[36m'
else
  C_RST=""; C_B=""; C_DIM=""; C_RED=""; C_GRN=""; C_YEL=""; C_CYA=""
fi

banner() {
  printf '\n%s%s==============================================================================%s\n' "$C_B" "$C_CYA" "$C_RST"
  printf '%s%s  PHASE: %s%s\n' "$C_B" "$C_CYA" "$1" "$C_RST"
  printf '%s%s==============================================================================%s\n' "$C_B" "$C_CYA" "$C_RST"
}
ok()   { printf '  %s[ OK ]%s %s\n' "$C_GRN" "$C_RST" "$*"; }
warn() { printf '  %s[WARN]%s %s\n' "$C_YEL" "$C_RST" "$*"; }
info() { printf '  %s[ .. ]%s %s\n' "$C_DIM" "$C_RST" "$*"; }
skip() { printf '  %s[SKIP]%s %s\n' "$C_DIM" "$C_RST" "$*"; }
plan() { printf '  %s[PLAN]%s %s\n' "$C_CYA" "$C_RST" "$*"; }
bad()  { printf '  %s[FAIL]%s %s\n' "$C_RED" "$C_RST" "$*"; }
die()  { printf '\n  %s[FAIL]%s %s\n\n' "$C_RED" "$C_RST" "$*" >&2; exit 1; }

# Strip Cotal's ANSI so its output can be parsed. macOS sed has no \x1b escape,
# so the ESC byte is injected literally via $'...'.
strip_ansi() { LC_ALL=C sed -E $'s/\033\\[[0-9;]*[a-zA-Z]//g'; }

# Run an external command, honouring --dry-run and --verbose. Never swallows a
# non-zero exit: callers that need to classify a failure use `run_soft`.
run() {
  if [ "$DRY_RUN" -eq 1 ]; then plan "$*"; return 0; fi
  if [ "$VERBOSE" -eq 1 ]; then printf '  %s$ %s%s\n' "$C_DIM" "$*" "$C_RST"; fi
  "$@"
}

# Like `run`, but returns the command's status instead of aborting so the caller
# can classify it. Combined output lands in RUN_OUT.
RUN_OUT=""
run_soft() {
  if [ "$DRY_RUN" -eq 1 ]; then plan "$*"; RUN_OUT=""; return 0; fi
  if [ "$VERBOSE" -eq 1 ]; then printf '  %s$ %s%s\n' "$C_DIM" "$*" "$C_RST"; fi
  local rc=0
  RUN_OUT="$("$@" 2>&1 | strip_ansi)" || rc=$?
  return $rc
}

# bash 3.2 has no associative arrays, so the two id->status maps are TSV strings
# with last-write-wins lookup.
CRED_STATUS_KV=""
cred_status_set() { CRED_STATUS_KV="${CRED_STATUS_KV}${1}"$'\t'"${2}"$'\n'; }
cred_status_get() { printf '%s' "$CRED_STATUS_KV" | awk -F'\t' -v k="$1" '$1==k{v=$2} END{print v}'; }

AGENT_STATUS_KV=""
agent_status_set() { AGENT_STATUS_KV="${AGENT_STATUS_KV}${1}"$'\t'"${2}"$'\n'; }
agent_status_get() { printf '%s' "$AGENT_STATUS_KV" | awk -F'\t' -v k="$1" '$1==k{v=$2} END{print v}'; }

# ---------------------------------------------------------------------------
# The agent table, read ONCE from mesh/lib/agents.js.
#
# WHY a Node subprocess rather than bash arrays: mesh/lib/agents.js is the single
# source of truth for the pins and the ACL. Re-encoding it in bash would create
# exactly the second copy this script exists to avoid. Emitted as TSV so bash can
# consume it without a JSON parser.
#
# Fields: id  profile  runtime  connector  model  effort  variant  publish  subscribe  harness
#   variant = the value for `cotal spawn --variant`, or "-" when the connector's
#             buildLaunch THROWS on any variant (claude, agy, hermes). Passing it
#             there is a hard launch failure, not a degrade.
#   harness = 1 for the six identities that launch a harness, 0 for the two
#             deterministic Jac identities (coordinator, svc_containment).
# ---------------------------------------------------------------------------
js_plan() {
  cat <<'NODEJS'
const { IDENTITIES, AGENT_IDS, ACL, PROFILE, agentTable } = await import(process.argv[1]);

// Which connector renders `variant` at all. Source: the connector registrations
// on the integration branch --
//   codex    supportsModelVariant: true   (extensions/connector-codex/src/index.ts:28)
//   opencode supportsModelVariant: true   (extensions/connector-opencode/src/extension.ts:110)
//   agy      supportsModelVariant: false, buildLaunch throws (connector-agy/src/index.ts:32,71)
//   claude   throws "claude connector: model variants are not supported"
//   hermes   throws "the Hermes connector does not support model variants"
const VARIANT_OK = { codex: true, opencode: true, claude: false, agy: false, hermes: false };

const table = agentTable();
const rows = [];
for (const id of IDENTITIES) {
  const a = table[id];
  const acl = ACL[id];
  const connector = a ? a.runtime : "-";
  rows.push([
    id,
    PROFILE[id],
    a ? a.runtime : "-",
    connector,
    a ? a.model : "-",
    a ? a.effort : "-",
    a && VARIANT_OK[connector] ? a.effort : "-",
    acl.publish.join(",") || "-",
    acl.subscribe.join(",") || "-",
    AGENT_IDS.includes(id) ? "1" : "0",
  ].join("\t"));
}
process.stdout.write(rows.join("\n") + "\n");
NODEJS
}

# ---------------------------------------------------------------------------
# ACL verification program. Two modes:
#   contract -- mesh/lib/agents.js vs the FROZEN contracts/mesh/channels.yaml,
#               plus the two named security invariants.
#   creds    -- decode each minted credential's NATS grants and assert the
#               channel sets equal the matrix. This is the only check that
#               proves the ACL at the TRANSPORT rather than in a config file.
# ---------------------------------------------------------------------------
js_acl() {
  cat <<'NODEJS'
import fs from "node:fs";
import path from "node:path";
const { IDENTITIES, ACL } = await import(process.argv[1]);

const repo = process.argv[2];
const credsDir = process.argv[3];
const mode = process.argv[4];
let bad = 0;

const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

if (mode === "contract") {
  // Deliberately a narrow, dependency-free scan of the `agents:` block rather
  // than a full YAML parse: the contract is FROZEN and its shape is fixed, and
  // adding a YAML dependency to read one frozen file is a worse trade than a
  // matcher that fails loudly if that shape ever changes.
  const y = fs.readFileSync(path.join(repo, "contracts/mesh/channels.yaml"), "utf8");
  const body = y.slice(y.indexOf("\nagents:"));
  const list = (s) =>
    s.trim() === "[]"
      ? []
      : s.replace(/^\[|\]$/g, "").split(",").map((t) => t.trim().replace(/^["']|["']$/g, "")).filter(Boolean);

  for (const id of IDENTITIES) {
    const blk = body.match(new RegExp(`\\n  ${id}:\\n([\\s\\S]*?)(?=\\n  [a-z_]+:\\n|\\n[a-z_]+:|$)`));
    if (!blk) { console.log(`DRIFT\t${id}: not found in the agents: block of contracts/mesh/channels.yaml`); bad++; continue; }
    const pubM = blk[1].match(/allowPublish:\s*(\[[^\]]*\])/);
    const subM = blk[1].match(/allowSubscribe:\s*(\[[^\]]*\])/);
    if (!pubM || !subM) { console.log(`DRIFT\t${id}: allowPublish/allowSubscribe missing in channels.yaml`); bad++; continue; }
    const cPub = list(pubM[1]), cSub = list(subM[1]);
    if (!eq(cPub, ACL[id].publish))   { console.log(`DRIFT\t${id} publish: contract=[${cPub}] agents.js=[${ACL[id].publish}]`); bad++; }
    if (!eq(cSub, ACL[id].subscribe)) { console.log(`DRIFT\t${id} subscribe: contract=[${cSub}] agents.js=[${ACL[id].subscribe}]`); bad++; }
  }
  if (!bad) console.log("MATCH\tall 8 identities agree with contracts/mesh/channels.yaml");

  // The two security properties channels.yaml enforces mechanically.
  for (const r of IDENTITIES.filter((i) => i.startsWith("responder_"))) {
    if (ACL[r].publish.includes("sec.incident")) {
      console.log(`INVARIANT-FAIL\t${r} may publish sec.incident -- assessment independence is broken`); bad++;
    }
  }
  if (!eq(ACL.monitor.publish, ["sec.incident"])) {
    console.log(`INVARIANT-FAIL\tmonitor publish is [${ACL.monitor.publish}], must be exactly [sec.incident]`); bad++;
  }
  if (ACL.monitor.subscribe.length) {
    console.log(`INVARIANT-FAIL\tmonitor subscribe is [${ACL.monitor.subscribe}], must be empty`); bad++;
  }
  if (!bad) console.log("INVARIANT-OK\tno responder publishes sec.incident; monitor publishes only sec.incident and subscribes to nothing");
}

if (mode === "creds") {
  // Reads the JWT block only, decodes its permission rows, and prints CHANNEL
  // NAMES. The credential itself -- the JWT and the nkey seed -- is never
  // printed, logged, or copied anywhere.
  for (const id of IDENTITIES) {
    const p = path.join(credsDir, `${id}.creds`);
    if (!fs.existsSync(p)) { console.log(`ABSENT\t${id}\t-\t-\t-`); continue; }
    const m = fs.readFileSync(p, "utf8")
      .match(/-----BEGIN NATS USER JWT-----\s*([A-Za-z0-9_\-.]+)\s*-+END NATS USER JWT-+/);
    if (!m) { console.log(`UNREADABLE\t${id}\t-\t-\t-`); bad++; continue; }
    const payload = JSON.parse(Buffer.from(m[1].split(".")[1], "base64url").toString("utf8"));
    const nats = payload.nats || {};
    // A chat grant is cotal.<space>.chat.<owner>.<actor>.<channel>; everything
    // else in the row set is DM/service/JetStream plumbing, not policy.
    const chanOf = (rows) =>
      (rows || [])
        .map((s) => s.match(/^cotal\.[^.]+\.chat\.[^.]+\.[^.]+\.(.+)$/))
        .filter(Boolean)
        .map((x) => x[1])
        .sort();
    const pub = chanOf(nats.pub && nats.pub.allow);
    const sub = chanOf(nats.sub && nats.sub.allow);
    const wantPub = [...ACL[id].publish].sort();
    const wantSub = [...ACL[id].subscribe].sort();
    const pubOk = eq(pub, wantPub);
    const subOk = eq(sub, wantSub);
    // Cotal defaults an EMPTY allowSubscribe to ["general"] (provision.ts:906),
    // so an identity whose contract subscribe is [] necessarily receives a read
    // on the unused `general` channel. That widening cannot be suppressed
    // through the CLI, so it is surfaced as WIDENED rather than silently
    // accepted -- it grants no sec.* read, so the security property still holds.
    const subWidened = wantSub.length === 0 && eq(sub, ["general"]);
    const verdict = pubOk && subOk ? "OK" : pubOk && subWidened ? "WIDENED" : "MISMATCH";
    if (verdict === "MISMATCH") bad++;
    console.log(`${verdict}\t${id}\t${payload.name}\tpub=[${pub}] want=[${wantPub}]\tsub=[${sub}] want=[${wantSub}]`);
  }
}
process.exit(bad ? 1 : 0);
NODEJS
}

# ---------------------------------------------------------------------------
# PHASE 1 — PREFLIGHT
# ---------------------------------------------------------------------------
BLOCKED_AGENTS=()   # agent ids whose harness cannot serve its pinned model today
BLOCKED_REASON=()   # parallel array: why, and the exact fix
PLAN_ROWS=()

phase_preflight() {
  banner "1/6 PREFLIGHT"
  local fail=0

  # node >= 22. Cotal's own bin/cotal.ts enforces this before it imports the
  # broker chain, because npm silently skips the optional nats-server binary
  # package on older Node -- so a Node 20 box fails much later, and far less
  # legibly, than it does here.
  if command -v node >/dev/null 2>&1; then
    local nv nmaj; nv="$(node --version)"; nmaj="${nv#v}"; nmaj="${nmaj%%.*}"
    if [ "$nmaj" -ge 22 ]; then ok "node ${nv} (>= 22 required)"
    else bad "node ${nv} is below the required v22"; fail=1; fi
  else
    bad "node not on PATH"; fail=1
  fi

  if command -v cotal >/dev/null 2>&1; then
    ok "cotal $(cotal --version 2>/dev/null | strip_ansi | head -1) at $(command -v cotal)"
  else
    bad "cotal not on PATH"; fail=1
  fi

  # `cotal up` resolves nats-server from PATH FIRST and only then from its
  # bundled fallback, so a Homebrew binary is what actually runs. Say which one.
  if command -v nats-server >/dev/null 2>&1; then
    ok "nats-server $(nats-server --version 2>&1 | head -1) at $(command -v nats-server) (PATH wins over Cotal's bundled fallback)"
  else
    warn "nats-server not on PATH -- cotal up will fall back to its bundled binary"
  fi

  # Cotal integration clone. A SHA drift is a WARNING, not a hard failure: all we
  # take from the clone is the two connector packages, and a rebased branch that
  # still builds them is usable. But it must be said out loud, because
  # connector-codex and connector-agy exist ONLY on this branch.
  if [ -d "${COTAL_CLONE}/.git" ]; then
    local sha br
    sha="$(git -C "${COTAL_CLONE}" rev-parse HEAD)"
    br="$(git -C "${COTAL_CLONE}" rev-parse --abbrev-ref HEAD)"
    if [ "$sha" = "$COTAL_CLONE_SHA" ]; then
      ok "Cotal clone ${COTAL_CLONE} @ ${br} ${sha:0:12} (expected SHA)"
    else
      warn "Cotal clone is at ${br} ${sha:0:12}, expected ${COTAL_CLONE_SHA:0:12} -- connector-codex/connector-agy come from this tree; verify they still build"
    fi
  else
    bad "Cotal integration clone missing at ${COTAL_CLONE} (connector-codex/connector-agy live only there)"; fail=1
  fi

  if [ ! -f "${MESH_DIR}/lib/agents.js" ];      then bad "missing ${MESH_DIR}/lib/agents.js"; fail=1; fi
  if [ ! -f "${MESH_DIR}/config/models.json" ]; then bad "missing ${MESH_DIR}/config/models.json"; fail=1; fi
  if [ ! -f "${REPO_ROOT}/contracts/mesh/channels.yaml" ]; then bad "missing frozen ACL contract contracts/mesh/channels.yaml"; fail=1; fi

  if [ "$fail" -eq 1 ]; then die "preflight failed -- fix the [FAIL] lines above before re-running"; fi

  # ---- harness CLIs + auth state -----------------------------------------
  printf '\n  %sHarness CLIs and auth state%s\n' "$C_B" "$C_RST"
  local claude_ok=0 codex_ok=0 agy_ok=0 opencode_ok=0 hermes_ok=0

  if command -v claude >/dev/null 2>&1; then
    # Claude Code keeps its OAuth in the macOS keychain rather than a dotfile, so
    # the keychain item is the only offline signal that a login exists.
    if security find-generic-password -s "Claude Code-credentials" >/dev/null 2>&1 || [ -f "${HOME}/.claude/.credentials.json" ]; then
      ok "claude   $(claude --version 2>&1 | head -1) -- authenticated"; claude_ok=1
    else
      warn "claude   present but NO credential found -- run: claude   then /login"
    fi
  else
    warn "claude   NOT on PATH"
  fi

  if command -v codex >/dev/null 2>&1; then
    if [ -s "${HOME}/.codex/auth.json" ]; then
      ok "codex    $(codex --version 2>&1 | head -1) -- authenticated (~/.codex/auth.json)"; codex_ok=1
    else
      warn "codex    present but NO credential found -- run: codex login"
    fi
  else
    warn "codex    NOT on PATH"
  fi

  if command -v agy >/dev/null 2>&1; then
    if [ -d "${HOME}/.gemini" ]; then
      ok "agy      $(agy --version 2>&1 | head -1) -- authenticated (~/.gemini)"; agy_ok=1
    else
      warn "agy      present but NO credential found -- run: agy   then sign in"
    fi
  else
    warn "agy      NOT on PATH"
  fi

  # ---- the OpenRouter key, checked ONCE for the three agents that ride it ----
  #
  # 2026-07-26 CORRECTION. This block used to gate opencode on `opencode auth
  # list` reporting a non-zero credential count, and reported "OPENROUTER_API_KEY
  # is EMPTY in .env" whenever the variable had not reached this shell. Both
  # readings were wrong, and between them they had three of the six agents
  # recorded as blocked while they were in fact perfectly able to run:
  #
  #   * `opencode auth list` counts credentials opencode has STORED. opencode
  #     reads its provider key from the ENVIRONMENT, so a count of 0 says nothing
  #     at all about whether it can reach a model. Verified live: with the key
  #     exported and zero stored credentials, `opencode run -m
  #     openrouter/z-ai/glm-5.2` answers normally. That count is now printed as
  #     information and is NEVER used as an auth signal.
  #   * the key was in .env the whole time and is valid. It is now sourced at the
  #     top of this script, so it is in the environment before anything spawns.
  #
  # Presence alone is still not evidence -- a stale or revoked key is present and
  # still 401s -- so it is validated against OpenRouter's own /auth/key endpoint.
  # A network failure is reported as UNVERIFIED and does not block: we refuse to
  # call an agent dead because the laptop is offline. The VALUE is never echoed,
  # logged, or length-reported; only "empty / present / accepted / rejected".
  local orkey="${OPENROUTER_API_KEY:-}" orcode="" orstate="empty"
  if [ -n "$orkey" ]; then
    if ! command -v curl >/dev/null 2>&1; then
      orstate="unverified"; orcode="no-curl"
    else
      orcode="$(curl -s -o /dev/null -w '%{http_code}' --max-time 8 \
        -H "Authorization: Bearer ${orkey}" https://openrouter.ai/api/v1/auth/key)" || orcode="000"
      case "$orcode" in
        200) orstate="accepted" ;;
        000) orstate="unverified" ;;
        *)   orstate="rejected" ;;
      esac
    fi
  fi
  case "$orstate" in
    accepted)   ok   "OpenRouter  OPENROUTER_API_KEY accepted (/auth/key HTTP 200) -- serves monitor, responder_kimi, responder_glm" ;;
    unverified) warn "OpenRouter  OPENROUTER_API_KEY present, UNVERIFIED (${orcode}) -- proceeding; a live call is the real test" ;;
    rejected)   warn "OpenRouter  OPENROUTER_API_KEY REJECTED (/auth/key HTTP ${orcode})" ;;
    *)          warn "OpenRouter  OPENROUTER_API_KEY is empty or absent in the environment and .env" ;;
  esac
  local orok=0
  if [ "$orstate" = "accepted" ] || [ "$orstate" = "unverified" ]; then orok=1; fi

  if command -v opencode >/dev/null 2>&1; then
    local oc occount="unknown"
    oc="$(opencode auth list 2>&1 | strip_ansi)" || true
    if printf '%s' "$oc" | grep -qE '[0-9]+ credentials?'; then
      occount="$(printf '%s' "$oc" | grep -oE '[0-9]+ credentials?' | head -1)"
    fi
    if [ "$orok" -eq 1 ]; then
      ok "opencode $(opencode --version 2>&1 | head -1) -- reads OPENROUTER_API_KEY from the environment (${occount} stored; NOT an auth signal)"
      opencode_ok=1
    else
      warn "opencode $(opencode --version 2>&1 | head -1) -- no OpenRouter key in the environment (${occount} stored)"
    fi
  else
    warn "opencode NOT on PATH"
  fi

  if command -v hermes >/dev/null 2>&1; then
    if [ "$orok" -eq 1 ]; then
      ok "hermes   $(hermes --version 2>&1 | head -1) -- reads OPENROUTER_API_KEY from the environment"; hermes_ok=1
    else
      warn "hermes   $(hermes --version 2>&1 | head -1) -- no OpenRouter key in the environment"
    fi
  else
    warn "hermes   NOT on PATH"
  fi

  # Map harness auth onto the six agent ids.
  if [ "$hermes_ok"   -eq 0 ]; then BLOCKED_AGENTS+=("monitor");               BLOCKED_REASON+=("hermes: OpenRouter key missing or rejected (/auth/key HTTP ${orcode:-none}). Fix: put a live key in .env as OPENROUTER_API_KEY"); fi
  if [ "$claude_ok"   -eq 0 ]; then BLOCKED_AGENTS+=("responder_claude");      BLOCKED_REASON+=("claude: no credential. Fix: run  claude  and complete /login"); fi
  if [ "$codex_ok"    -eq 0 ]; then BLOCKED_AGENTS+=("responder_codex");       BLOCKED_REASON+=("codex: no credential. Fix: run  codex login"); fi
  if [ "$agy_ok"      -eq 0 ]; then BLOCKED_AGENTS+=("responder_antigravity"); BLOCKED_REASON+=("agy: no credential. Fix: run  agy  and sign in"); fi
  if [ "$opencode_ok" -eq 0 ]; then BLOCKED_AGENTS+=("responder_kimi");        BLOCKED_REASON+=("opencode: no OpenRouter key in the environment (a stored-credential count of 0 is NOT the problem -- opencode reads the key from env). Fix: put a live key in .env as OPENROUTER_API_KEY"); fi
  if [ "$opencode_ok" -eq 0 ]; then BLOCKED_AGENTS+=("responder_glm");         BLOCKED_REASON+=("opencode: no OpenRouter key in the environment (a stored-credential count of 0 is NOT the problem -- opencode reads the key from env). Fix: put a live key in .env as OPENROUTER_API_KEY"); fi

  # ---- the plan ----------------------------------------------------------
  local plan_tsv line
  plan_tsv="$(node --input-type=module -e "$(js_plan)" -- "$AGENTS_JS_URL")" \
    || die "could not read the agent table from ${MESH_DIR}/lib/agents.js -- fix that file first"
  while IFS= read -r line; do
    if [ -n "$line" ]; then PLAN_ROWS+=("$line"); fi
  done <<< "$plan_tsv"
  if [ "${#PLAN_ROWS[@]}" -ne 8 ]; then
    die "expected 8 canonical identities from mesh/lib/agents.js, got ${#PLAN_ROWS[@]}"
  fi
  ok "agent table loaded: 8 identities, 6 harness agents (source: mesh/lib/agents.js)"

  printf '\n  %sPinned models (mesh/config/models.json -- NEVER substituted)%s\n' "$C_B" "$C_RST"
  local id prof rt conn model eff var pub sub harness
  while IFS=$'\t' read -r id prof rt conn model eff var pub sub harness; do
    if [ "$harness" != "1" ]; then continue; fi
    if [ "$var" = "-" ]; then
      printf '    %-22s %-9s %-24s effort=%-6s %s(connector rejects --variant; effort rides the model id / harness config)%s\n' \
        "$id" "$conn" "$model" "$eff" "$C_DIM" "$C_RST"
    else
      printf '    %-22s %-9s %-24s effort=%-6s --variant %s\n' "$id" "$conn" "$model" "$eff" "$var"
    fi
  done < <(printf '%s\n' "${PLAN_ROWS[@]}")

  if [ "${#BLOCKED_AGENTS[@]}" -gt 0 ]; then
    printf '\n  %s%sBLOCKED HARNESSES -- these agents cannot run live today%s\n' "$C_B" "$C_YEL" "$C_RST"
    local i
    for i in "${!BLOCKED_AGENTS[@]}"; do
      printf '    %s%-22s%s %s\n' "$C_YEL" "${BLOCKED_AGENTS[$i]}" "$C_RST" "${BLOCKED_REASON[$i]}"
    done
    printf '    %sThey are still brought up -- in MOCK mode -- so the mesh always has six.%s\n' "$C_DIM" "$C_RST"
  else
    ok "all six harnesses are authenticated -- no mocks needed"
  fi
}

is_blocked() {
  local want="$1" a
  for a in ${BLOCKED_AGENTS[@]+"${BLOCKED_AGENTS[@]}"}; do
    if [ "$a" = "$want" ]; then return 0; fi
  done
  return 1
}

# ---------------------------------------------------------------------------
# PHASE 2 — NATS
#
# `cotal up` ALWAYS spawns a separate nats-server OS process -- never embedded --
# and there is no `cotal init`: `cotal up` self-provisions the space's trust
# material. So "is the mesh up?" is answered by two independent facts, and both
# must agree before we skip: a live pid in .cotal/nats.pid AND a mesh in the
# machine-wide registry. One without the other is a half-dead stack, and we say
# so rather than minting credentials on top of it.
# ---------------------------------------------------------------------------
phase_nats() {
  banner "2/6 NATS"

  local pid_alive=0 mesh_listed=0 pid=""
  if [ -f "$NATS_PIDFILE" ]; then
    pid="$(tr -dc '0-9' < "$NATS_PIDFILE")"
    if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then pid_alive=1; fi
  fi
  if cotal meshes 2>/dev/null | strip_ansi | grep -qE 'nats://'; then mesh_listed=1; fi

  if [ "$pid_alive" -eq 1 ] && [ "$mesh_listed" -eq 1 ]; then
    ok "mesh already running -- nats-server pid ${pid} alive, registry entry present"
    info "$(cotal meshes 2>/dev/null | strip_ansi | head -1)"
    skip "cotal up (idempotent: nothing to start)"
    return 0
  fi

  if [ "$pid_alive" -ne "$mesh_listed" ]; then
    warn "half-up stack (nats pidfile alive=${pid_alive}, mesh registered=${mesh_listed}) -- tearing down before restarting"
    run cotal down || die "cotal down failed on a half-up stack; inspect ${NATS_LOG} and ${COTAL_ROOT}/manager.log"
  fi

  info "starting: cotal up --detach   (spawns nats-server + JetStream + manager + delivery daemon)"
  if [ "$DRY_RUN" -eq 1 ]; then
    plan "cotal up --detach"
    plan "# then verify: ${NATS_PIDFILE} pid alive, and 'cotal meshes' lists the space"
    return 0
  fi

  if ! cotal up --detach; then
    die "cotal up failed. Check, in order:
       1. ${NATS_LOG}                      -- did nats-server itself refuse to start?
       2. ${COTAL_ROOT}/manager.log        -- did the manager fail after the broker came up?
       3. lsof -nP -iTCP:4222 -sTCP:LISTEN -- is port 4222 already held by another broker?
       4. ${COTAL_ROOT}/auth/server.conf   -- is the generated JWT-auth config present?
       Recover with:  cotal down && rm -rf ${COTAL_ROOT}/nats && mesh/up.sh"
  fi

  if [ ! -f "$NATS_PIDFILE" ]; then die "cotal up returned 0 but wrote no pidfile at ${NATS_PIDFILE}"; fi
  pid="$(tr -dc '0-9' < "$NATS_PIDFILE")"
  kill -0 "$pid" 2>/dev/null || die "nats-server pid ${pid} from ${NATS_PIDFILE} is not alive -- see ${NATS_LOG}"
  ok "nats-server pid ${pid} alive (log: ${NATS_LOG})"
  cotal meshes 2>/dev/null | strip_ansi | grep -qE 'nats://' \
    || die "cotal up started nats-server but registered no mesh -- see ${COTAL_ROOT}/manager.log"
  ok "$(cotal meshes 2>/dev/null | strip_ansi | head -1)"
  ok "JetStream store: ${COTAL_ROOT}/nats    server config: ${COTAL_ROOT}/auth/server.conf"
}

# ---------------------------------------------------------------------------
# PHASE 3 — MINT
#
# Two artifacts per identity:
#
#  (a) the PERSONA at .cotal/agents/<id>.md. This is where the ACL is DECLARED.
#      Both `cotal mint --profile agent` and `cotal spawn` read it
#      (allowSubscribe / allowPublish / role / model), so generating it from
#      mesh/lib/agents.js keeps the frozen matrix and the wire in sync without a
#      second hand-typed copy.
#
#  (b) the CREDS file at .cotal/auth/creds/<id>.creds (0600, parent dir 0700).
#
# KNOWN UPSTREAM DEFECT on this build: `cotal mint --profile agent` is broken.
# implementations/cli/src/commands/mint.ts:88 calls mintCreds() without a
# lifecycleUid, and packages/core/src/provision.ts:911 then hard-throws
# "permissionsFor(agent): a lifecycleUid is required". observer/admin profiles
# work; the agent profile does not.
#
# We do NOT downgrade to observer to obtain a file. An observer cred carries a
# wildcard `chat.>` subscribe (provision.ts:833-850), which would hand every
# responder a read on every other responder's verdict -- destroying the exact
# property the frozen matrix exists to enforce.
#
# Cotal's own working path for an agent-profile cred is `cotal spawn`, which
# provisions it through provisionAgent() WITH a lifecycleUid, to the identical
# canonical path with the identical ACL flags (commands/spawn.ts:459-474). The
# harness identities are therefore routed there in PHASE 6. The two non-harness
# identities have no spawn path and are reported BLOCKED, never silently widened.
# ---------------------------------------------------------------------------
MINT_LIFECYCLE_DEFECT='permissionsFor(agent): a lifecycleUid is required'

phase_mint() {
  banner "3/6 MINT"

  if [ "$DRY_RUN" -eq 1 ]; then
    plan "mkdir -p ${PERSONA_DIR} ${CREDS_DIR}  (mode 0700)"
  else
    mkdir -p "$PERSONA_DIR" "$CREDS_DIR"
    chmod 700 "$PERSONA_DIR" "$CREDS_DIR"
  fi

  local id prof rt conn model eff var pub sub harness persona creds defect_hit=0

  while IFS=$'\t' read -r id prof rt conn model eff var pub sub harness; do
    persona="${PERSONA_DIR}/${id}.md"
    creds="${CREDS_DIR}/${id}.creds"

    # ---- (a) persona -----------------------------------------------------
    if [ -f "$persona" ] && [ "$FORCE" -eq 0 ]; then
      skip "persona ${persona} (exists; --force to rewrite)"
    elif [ "$DRY_RUN" -eq 1 ]; then
      plan "write persona ${persona}   [allowPublish=${pub} allowSubscribe=${sub} model=${model}]"
    else
      write_persona "$id" "$prof" "$rt" "$model" "$var" "$pub" "$sub" > "$persona"
      chmod 600 "$persona"
      ok "persona ${persona}   [allowPublish=${pub} allowSubscribe=${sub}]"
    fi

    # ---- (b) creds -------------------------------------------------------
    if [ -f "$creds" ] && [ "$FORCE" -eq 0 ]; then
      cred_status_set "$id" "exists"
      skip "creds ${creds} (exists; --force to re-mint)"
      continue
    fi

    local -a mint_args
    mint_args=("$id" "--profile" "$prof")
    if [ "$pub" != "-" ]; then mint_args+=("--allow-publish" "$pub"); fi
    if [ "$sub" != "-" ]; then mint_args+=("--allow-subscribe" "$sub"); fi

    if [ "$DRY_RUN" -eq 1 ]; then
      plan "cotal mint ${mint_args[*]}    -> ${creds}"
      cred_status_set "$id" "dry-run"
      continue
    fi

    if run_soft cotal mint "${mint_args[@]}"; then
      if [ ! -f "$creds" ]; then die "cotal mint ${id} reported success but wrote no file at ${creds}"; fi
      cred_status_set "$id" "minted"
      ok "minted ${id} -> ${creds}"
    else
      # Classify. Exactly ONE failure mode is tolerated, by exact message match.
      case "$RUN_OUT" in
        *"$MINT_LIFECYCLE_DEFECT"*)
          defect_hit=1
          if [ "$harness" = "1" ]; then cred_status_set "$id" "via-spawn"
          else                          cred_status_set "$id" "blocked-upstream"; fi
          ;;
        *)
          die "cotal mint ${id} failed with an unrecognised error -- refusing to continue:
${RUN_OUT}"
          ;;
      esac
    fi
  done < <(printf '%s\n' "${PLAN_ROWS[@]}")

  if [ "$defect_hit" -eq 1 ]; then
    printf '\n  %s%sKNOWN UPSTREAM DEFECT: cotal mint --profile agent is broken on this build%s\n' "$C_B" "$C_YEL" "$C_RST"
    cat <<EOF
    implementations/cli/src/commands/mint.ts:88 calls mintCreds() with no
    lifecycleUid; packages/core/src/provision.ts:911 then hard-throws
      "${MINT_LIFECYCLE_DEFECT}"
    for every agent-profile mint. observer/admin profiles are unaffected.

    NOT WORKED AROUND BY DOWNGRADING. An observer cred carries a wildcard
    'chat.>' subscribe (packages/core/src/provision.ts:833-850), which would let
    every responder read every other responder's verdict -- the precise property
    contracts/mesh/channels.yaml exists to enforce. Widening an ACL to obtain a
    file is a security regression, so it is refused.

    Routed instead to Cotal's own working agent-cred path:
      * the six HARNESS identities are provisioned by 'cotal spawn', which calls
        provisionAgent() WITH a lifecycleUid and writes the SAME canonical path
        with the SAME ACL flags (commands/spawn.ts:459-474)  ->  see PHASE 6.
      * coordinator and svc_containment have no harness and therefore no spawn
        path. They are reported BLOCKED: they cannot hold a correctly-scoped mesh
        credential on this Cotal build.
EOF
  fi
}

# Persona writer. Frontmatter keys are exactly the ones agent-file.ts accepts
# (name/kind/role/model/variant/subscribe/allowSubscribe/allowPublish); anything
# else is swept into `meta` and ignored, so no invented keys are emitted.
#
# NOTE the connector type is NOT expressible here -- agent-file.ts has no
# `agent:` key. It must come from `cotal spawn --agent <connector>`, and if that
# is omitted Cotal SILENTLY spawns the agent as `claude`. PHASE 6 passes it
# explicitly and then verifies the manager roster agrees.
write_persona() {
  local id="$1" prof="$2" rt="$3" model="$4" var="$5" pub="$6" sub="$7"
  local yl_pub="[]" yl_sub="[]"
  if [ "$pub" != "-" ]; then yl_pub="[${pub}]"; fi
  if [ "$sub" != "-" ]; then yl_sub="[${sub}]"; fi
  printf -- '---\n'
  printf 'name: %s\n' "$id"
  printf 'kind: agent\n'
  printf 'role: %s\n' "${id%%_*}"
  if [ "$model" != "-" ]; then printf 'model: %s\n' "$model"; fi
  if [ "$var"   != "-" ]; then printf 'variant: %s\n' "$var"; fi
  printf 'subscribe: %s\n' "$yl_sub"
  printf 'allowSubscribe: %s\n' "$yl_sub"
  printf 'allowPublish: %s\n' "$yl_pub"
  printf -- '---\n\n'
  printf 'Generated by mesh/up.sh from mesh/lib/agents.js (itself a transcription of the\n'
  printf 'FROZEN contracts/mesh/channels.yaml). Do not hand-edit: rerun mesh/up.sh --force.\n\n'
  printf 'Identity: %s    profile: %s    runtime: %s\n' "$id" "$prof" "$rt"
  printf 'allowPublish:   %s\n' "$pub"
  printf 'allowSubscribe: %s\n' "$sub"
}

# ---------------------------------------------------------------------------
# PHASE 4 — ACL
# ---------------------------------------------------------------------------
acl_creds_check() {
  local out rc=0 verdict id prof pubs subs
  out="$(node --input-type=module -e "$(js_acl)" -- "$AGENTS_JS_URL" "$REPO_ROOT" "$CREDS_DIR" creds)" || rc=$?
  while IFS=$'\t' read -r verdict id prof pubs subs; do
    case "$verdict" in
      OK)         ok   "${id} -- profile=${prof}  ${pubs}  ${subs}" ;;
      WIDENED)    warn "${id} -- profile=${prof}  ${pubs}  ${subs}  <- Cotal defaults an empty read ACL to [general] (provision.ts:906); no sec.* read is granted" ;;
      ABSENT)     skip "${id} -- no creds file yet at ${CREDS_DIR}/${id}.creds" ;;
      MISMATCH)   bad  "${id} -- ${pubs}  ${subs}" ;;
      UNREADABLE) bad  "${id} -- creds file present but its JWT block is unparseable" ;;
    esac
  done <<< "$out"
  return $rc
}

phase_acl() {
  banner "4/6 ACL"

  printf '  %sFrozen contract cross-check%s\n' "$C_B" "$C_RST"
  local out rc=0 tag rest
  out="$(node --input-type=module -e "$(js_acl)" -- "$AGENTS_JS_URL" "$REPO_ROOT" "$CREDS_DIR" contract)" || rc=$?
  while IFS=$'\t' read -r tag rest; do
    case "$tag" in
      MATCH)          ok "agents.js == contracts/mesh/channels.yaml (${rest})" ;;
      INVARIANT-OK)   ok "security invariants hold: ${rest}" ;;
      DRIFT)          bad "DRIFT ${rest}" ;;
      INVARIANT-FAIL) bad "${rest}" ;;
    esac
  done <<< "$out"
  if [ "$rc" -ne 0 ]; then
    die "the ACL matrix in mesh/lib/agents.js has drifted from the FROZEN contracts/mesh/channels.yaml, or a security invariant is broken. contracts/ is frozen -- fix mesh/lib/agents.js, never the contract."
  fi
  ok "ACL declared in 8 personas under ${PERSONA_DIR}"

  printf '\n  %sTransport-level check (decoded from the minted credentials)%s\n' "$C_B" "$C_RST"
  if [ "$DRY_RUN" -eq 1 ]; then
    plan "decode the NATS grants out of each ${CREDS_DIR}/<id>.creds and assert they equal the frozen matrix"
    return 0
  fi
  acl_creds_check || die "a minted credential's NATS grants do not match the frozen ACL matrix -- refusing to continue"
  info "identities shown as 'no creds file yet' are provisioned in PHASE 6 (see the MINT defect note) and re-checked in SUMMARY"
}

# ---------------------------------------------------------------------------
# PHASE 5 — CONNECTORS
#
# codex and agy are ABSENT from OFFICIAL_CONNECTORS
# (packages/workspace/src/official-connectors.ts:11-16), so the boot-time seed
# reconcile will NEVER install them -- they must be `cotal ext add`ed by hand,
# from the integration clone, on every fresh environment. opencode and hermes are
# first-party and normally already seeded; verify rather than assume.
# ---------------------------------------------------------------------------
phase_connectors() {
  banner "5/6 CONNECTORS"

  # name | provides-token | spec passed to `cotal ext add`
  local -a want
  want=(
    "opencode|connector:opencode|@cotal-ai/connector-opencode"
    "hermes|connector:hermes|@cotal-ai/connector-hermes"
    "codex|connector:codex|${COTAL_CLONE}/extensions/connector-codex"
    "agy|connector:agy|${COTAL_CLONE}/extensions/connector-agy"
  )

  local listed="" entry name token spec
  if [ "$DRY_RUN" -eq 0 ]; then
    listed="$(cotal ext list 2>&1 | strip_ansi)" \
      || die "cotal ext list failed -- the manifest at ~/.config/cotal/extensions/extensions.json may be corrupt"
  fi

  for entry in "${want[@]}"; do
    IFS='|' read -r name token spec <<< "$entry"
    if [ "$DRY_RUN" -eq 1 ]; then
      plan "if 'cotal ext list' lacks '${token}':   cotal ext add ${spec}"
      continue
    fi
    if printf '%s' "$listed" | grep -qF "$token"; then
      skip "${name} already registered (${token})"
      continue
    fi
    case "$spec" in
      /*) if [ ! -d "$spec" ]; then
            die "connector source missing: ${spec}
       connector-codex / connector-agy exist only on the integ/mesh branch of ${COTAL_CLONE}.
       Restore that clone at ${COTAL_CLONE_SHA} and re-run."
          fi ;;
    esac
    info "registering ${name} from ${spec}  (npm-installs into ~/.config/cotal/extensions; can take a minute)"
    cotal ext add "$spec" >/dev/null 2>&1 \
      || die "cotal ext add ${spec} failed. Try it directly for the full output:  cotal ext add ${spec}"
    ok "registered ${name}"
    listed="$(cotal ext list 2>&1 | strip_ansi)"
  done

  if [ "$DRY_RUN" -eq 1 ]; then return 0; fi

  local missing=()
  for entry in "${want[@]}"; do
    IFS='|' read -r name token spec <<< "$entry"
    if ! printf '%s' "$listed" | grep -qF "$token"; then missing+=("$name"); fi
  done
  if [ "${#missing[@]}" -gt 0 ]; then die "connectors still missing after registration: ${missing[*]}"; fi

  printf '\n  %sRegistered connectors (cotal ext list)%s\n' "$C_B" "$C_RST"
  printf '%s' "$listed" | grep -E '^@cotal-ai/' | sed 's/^/    /'

  if printf '%s' "$listed" | grep -qE 'connector-(codex|agy)@0\.13\.'; then
    printf '\n  %s%sVERSION SKEW (expected, inert)%s\n' "$C_B" "$C_YEL" "$C_RST"
    cat <<'EOF'
    connector-codex and connector-agy are stamped 0.13.1 against a 0.14.6 CLI.
    verifyInstalled (implementations/cli/src/seed/reconcile.ts:420-431) throws a
    "version-skewed payload" whenever an OFFICIAL_CONNECTORS member's installed
    version != the seed generation. These two escape it ONLY because they are
    absent from OFFICIAL_CONNECTORS. Do not add them to the seed set, and do not
    run `cotal ext seed --reset` expecting them to survive it.
EOF
  fi
}

# ---------------------------------------------------------------------------
# PHASE 6 — AGENTS
#
# `cotal spawn <persona> --agent <connector> --model <m> --detach`.
#
# --agent IS NOT OPTIONAL. agent-file.ts has no frontmatter key for the connector
# type, so with --agent omitted Cotal falls back to COTAL_DEFAULT_AGENT and
# SILENTLY spawns the agent as `claude` -- observed directly during bring-up: a
# hermes-pinned monitor came up as "monitor/monitor  claude . pty  idle". That is
# a silent runtime substitution, so it is passed explicitly AND the roster is
# verified afterwards, aborting on any disagreement.
#
# --variant goes ONLY to codex and opencode. claude, agy and hermes THROW on any
# variant (they do not degrade), so passing it is a hard launch failure. agy's
# effort is carried inside the model id itself (gemini-3.6-flash-high).
#
# --transcript is never passed: codex and agy throw "transcript mirroring is not
# implemented (v1)". The mesh's own tap at mesh/transcript/ covers that need.
# ---------------------------------------------------------------------------
MOCKED_AGENTS=()

# A DETACHED spawn only ever reports the last line the child printed, which for a
# crash-on-import is the useless "Node.js v25.6.1" banner. The actual cause is on
# the child's stdout, which only the FOREGROUND spawn surfaces. So when a
# detached launch fails we re-run it in the foreground under a bounded wait
# purely to capture the real error line. The agent has already proven it dies
# immediately, so this costs a couple of seconds; the wait is bounded anyway so a
# surprise success cannot wedge the bring-up.
diagnose_launch() {
  local id="$1" conn="$2" model="$3" var="$4"
  local tmp pidf waited=0 child line
  tmp="$(mktemp -t cotal-launch-diag)"
  pidf="${tmp}.pid"
  local -a fg
  fg=(cotal spawn "$id" --agent "$conn" --model "$model")
  if [ "$var" != "-" ]; then fg+=(--variant "$var"); fi
  ( "${fg[@]}" >"$tmp" 2>&1 & echo $! >"$pidf" )
  child="$(cat "$pidf")"
  while [ "$waited" -lt 25 ]; do
    if ! kill -0 "$child" 2>/dev/null; then break; fi
    sleep 1
    waited=$((waited + 1))
  done
  if kill -0 "$child" 2>/dev/null; then kill "$child" 2>/dev/null; fi
  line="$(grep -a -m1 -E 'fatal:|Error:|error:' "$tmp" | tr -d '\r' | cut -c1-240)"
  rm -f "$tmp" "$pidf"
  printf '%s' "$line"
}

phase_agents() {
  banner "6/6 AGENTS"

  local id prof rt conn model eff var pub sub harness roster="" row

  if [ "$NO_AGENTS" -eq 1 ]; then
    skip "--no-agents: the mesh is up; launching nothing"
    # Report what the manager roster ACTUALLY holds, not a blanket
    # "not-launched": --no-agents means "start nothing new", not "nothing is
    # running", and a stale label here would misreport a live mesh.
    if [ "$DRY_RUN" -eq 0 ]; then roster="$(cotal ps 2>&1 | strip_ansi)"; fi
    while IFS=$'\t' read -r id prof rt conn model eff var pub sub harness; do
      if [ -n "$roster" ] && printf '%s' "$roster" | grep -qE "^${id}/"; then
        agent_status_set "$id" "running"
      else
        agent_status_set "$id" "not-launched"
      fi
    done < <(printf '%s\n' "${PLAN_ROWS[@]}")
    return 0
  fi

  if [ "$DRY_RUN" -eq 0 ]; then roster="$(cotal ps 2>&1 | strip_ansi)"; fi

  while IFS=$'\t' read -r id prof rt conn model eff var pub sub harness; do
    if [ "$harness" != "1" ]; then
      # coordinator + svc_containment are deterministic Jac processes, not
      # harness agents: there is nothing to spawn.
      agent_status_set "$id" "no-harness"
      continue
    fi

    if is_blocked "$id"; then
      agent_status_set "$id" "MOCKED"
      MOCKED_AGENTS+=("$id")
      continue
    fi

    # Idempotency: the manager roster is authoritative for "already launched".
    if [ -n "$roster" ] && printf '%s' "$roster" | grep -qE "^${id}/"; then
      row="$(printf '%s' "$roster" | grep -E "^${id}/" | head -1)"
      if printf '%s' "$row" | grep -qE "(^|[[:space:]])${conn}([[:space:]]|\$)"; then
        agent_status_set "$id" "running"
        skip "${id} already running as ${conn} -- ${row}"
        continue
      fi
      die "${id} is on the manager roster but running under the WRONG connector:
       ${row}
       expected connector '${conn}'. That is a silent runtime substitution.
       Stop it and re-run:  cotal stop --name ${id} && mesh/up.sh"
    fi

    local -a spawn_args
    spawn_args=("$id" "--agent" "$conn" "--model" "$model" "--detach")
    if [ "$var" != "-" ]; then spawn_args+=("--variant" "$var"); fi

    if [ "$DRY_RUN" -eq 1 ]; then
      plan "cotal spawn ${spawn_args[*]}"
      if [ "$var" = "-" ]; then
        plan "  # no --variant: the ${conn} connector THROWS on any variant; effort '${eff}' rides the model id / harness config"
      fi
      agent_status_set "$id" "dry-run"
      continue
    fi

    if [ "$var" = "-" ]; then
      info "launching ${id}: connector=${conn} model=${model} effort=${eff} (no --variant: connector rejects it)"
    else
      info "launching ${id}: connector=${conn} model=${model} effort=${eff} --variant ${var}"
    fi

    # A spawn failure is a HARNESS failure, and the documented handling for a
    # harness that cannot serve its pin is: mark it MOCKED, name it, keep the pin
    # (never substitute). Aborting here instead would leave the mesh with fewer
    # than six agents -- the one outcome the bring-up is required to avoid. The
    # failure is recorded verbatim and shouted in the MOCKED banner, so nothing
    # is swallowed; only the abort is traded for a named, visible degradation.
    if ! run_soft cotal spawn "${spawn_args[@]}" || ! printf '%s' "$RUN_OUT" | grep -q 'spawned'; then
      bad "${id} FAILED TO LAUNCH under connector '${conn}' -- diagnosing, then falling back to MOCK"
      local detail
      detail="$(diagnose_launch "$id" "$conn" "$model" "$var")"
      if [ -z "$detail" ]; then
        detail="$(printf '%s' "$RUN_OUT" | grep -E '✗|Error|error' | tail -1)"
      fi
      if [ -z "$detail" ]; then detail="$(printf '%s' "$RUN_OUT" | tail -1)"; fi
      agent_status_set "$id" "MOCKED"
      MOCKED_AGENTS+=("$id")
      BLOCKED_AGENTS+=("$id")
      BLOCKED_REASON+=("${conn} harness failed at launch: ${detail}  |  Reproduce with the full stack:  cotal spawn ${id} --agent ${conn} --model ${model}   (foreground)  |  Manager log: ${COTAL_ROOT}/manager.log")
      continue
    fi

    # Verify the roster agrees on the connector -- the substitution guard.
    roster="$(cotal ps 2>&1 | strip_ansi)"
    row="$(printf '%s' "$roster" | grep -E "^${id}/" | head -1)" || row=""
    if [ -z "$row" ]; then die "${id} spawned but does not appear in 'cotal ps'"; fi
    if ! printf '%s' "$row" | grep -qE "(^|[[:space:]])${conn}([[:space:]]|\$)"; then
      die "MODEL/RUNTIME SUBSTITUTION: ${id} is pinned to connector '${conn}' but the manager reports:
       ${row}
       Refusing to continue -- a pin is never silently substituted."
    fi
    agent_status_set "$id" "launched"
    ok "${id} launched -- ${row}"
  done < <(printf '%s\n' "${PLAN_ROWS[@]}")

  # ---- the loud MOCKED banner -------------------------------------------
  if [ "${#MOCKED_AGENTS[@]}" -gt 0 ]; then
    printf '\n%s%s##############################################################################%s\n' "$C_B" "$C_YEL" "$C_RST"
    printf '%s%s#  MOCKED AGENTS -- %d of 6 are NOT running a live model%s\n' "$C_B" "$C_YEL" "${#MOCKED_AGENTS[@]}" "$C_RST"
    printf '%s%s##############################################################################%s\n' "$C_B" "$C_YEL" "$C_RST"
    local a i
    for a in "${MOCKED_AGENTS[@]}"; do
      for i in "${!BLOCKED_AGENTS[@]}"; do
        if [ "${BLOCKED_AGENTS[$i]}" = "$a" ]; then
          printf '  %s%-22s%s %s\n' "$C_YEL" "$a" "$C_RST" "${BLOCKED_REASON[$i]}"
        fi
      done
    done
    printf '  %sTheir pins are UNCHANGED and UNSUBSTITUTED; they simply are not executing.\n' "$C_DIM"
    printf '  A run containing a mocked agent is NOT a live six-model run and must not be\n'
    printf '  presented as one.%s\n' "$C_RST"
  fi

  # ---- effort receipts (owned by another agent, built in parallel) -------
  printf '\n  %sEffort receipts%s\n' "$C_B" "$C_RST"
  if [ -f "$EFFORT_RECEIPT" ]; then
    run node "$EFFORT_RECEIPT" write-all --run-id "$RUN_ID" \
      || die "effort-receipt write-all failed for run ${RUN_ID}"
    run node "$EFFORT_RECEIPT" check --run-id "$RUN_ID" \
      || die "effort-receipt check failed for run ${RUN_ID} -- an agent's effective effort does not match its pin"
    if [ "$DRY_RUN" -eq 0 ]; then ok "effort receipts written and checked for run ${RUN_ID}"; fi
  else
    warn "mesh/effort_receipts/bin/effort-receipt.js NOT BUILT YET -- skipping"
    info "  once it lands, up.sh runs:  node mesh/effort_receipts/bin/effort-receipt.js write-all --run-id ${RUN_ID}"
    info "                       then:  node mesh/effort_receipts/bin/effort-receipt.js check --run-id ${RUN_ID}"
  fi

  # ---- agent runner (owned by another agent, built in parallel) ----------
  printf '\n  %sAgent runner%s\n' "$C_B" "$C_RST"
  if [ -z "$INCIDENT" ]; then
    skip "no --incident given -- up.sh brings agents up but drives no assessment"
    info "  to drive one:  mesh/up.sh --incident <incident.v1.json>"
  elif [ ! -f "$AGENT_RUNNER" ]; then
    warn "mesh/agent_runner/bin/agent-runner.js NOT BUILT YET -- skipping (an --incident was supplied)"
    info "  once it lands, up.sh runs, per agent:"
    info "    node mesh/agent_runner/bin/agent-runner.js --agent <id> --incident ${INCIDENT} --run-id ${RUN_ID} [--mock]"
  else
    if [ ! -f "$INCIDENT" ]; then die "--incident ${INCIDENT} does not exist"; fi
    local -a ra
    while IFS=$'\t' read -r id prof rt conn model eff var pub sub harness; do
      if [ "$harness" != "1" ]; then continue; fi
      ra=("$AGENT_RUNNER" "--agent" "$id" "--incident" "$INCIDENT" "--run-id" "$RUN_ID")
      if is_blocked "$id"; then ra+=("--mock"); fi
      run node "${ra[@]}" || die "agent-runner failed for ${id} (run ${RUN_ID})"
    done < <(printf '%s\n' "${PLAN_ROWS[@]}")
    if [ "$DRY_RUN" -eq 0 ]; then ok "agent-runner driven for all six agents against ${INCIDENT}"; fi
  fi
}

# ---------------------------------------------------------------------------
# SUMMARY
# ---------------------------------------------------------------------------
phase_summary() {
  banner "SUMMARY -- run ${RUN_ID}"

  printf '  %s%-22s %-8s %-13s %-48s %-16s %s%s\n' "$C_B" "IDENTITY" "PROFILE" "STATUS" "CREDS PATH (MODE)" "PUBLISH" "SUBSCRIBE" "$C_RST"
  printf '  %s%s%s\n' "$C_DIM" "-------------------------------------------------------------------------------------------------------------------------------------" "$C_RST"

  local id prof rt conn model eff var pub sub harness creds cpath status perms
  while IFS=$'\t' read -r id prof rt conn model eff var pub sub harness; do
    creds="${CREDS_DIR}/${id}.creds"
    if [ -f "$creds" ]; then
      perms="$(stat -f '%OLp' "$creds" 2>/dev/null || stat -c '%a' "$creds")"
      cpath=".cotal/auth/creds/${id}.creds (${perms})"
      if [ "$perms" != "600" ]; then cpath="${cpath} <- EXPECTED 0600"; fi
    else
      case "$(cred_status_get "$id")" in
        blocked-upstream) cpath="none - cotal mint --profile agent broken upstream" ;;
        via-spawn)        cpath="none - agent not running" ;;
        dry-run)          cpath="(dry-run)" ;;
        *)                cpath="none" ;;
      esac
    fi
    status="$(agent_status_get "$id")"
    if [ -z "$status" ]; then status="$(cred_status_get "$id")"; fi
    if [ -z "$status" ]; then status="unknown"; fi
    printf '  %-22s %-8s %-13s %-48s %-16s %s\n' "$id" "$prof" "$status" "$cpath" "$pub" "$sub"
  done < <(printf '%s\n' "${PLAN_ROWS[@]}")

  if [ "$DRY_RUN" -eq 0 ]; then
    printf '\n  %sCredential permissions%s\n' "$C_B" "$C_RST"
    local n badperm=0 f p
    n="$(find "$CREDS_DIR" -maxdepth 1 -name '*.creds' 2>/dev/null | wc -l | tr -d ' ')"
    if [ "$n" = "0" ]; then
      warn "no credential files on disk (see the MINT defect note above)"
    else
      while IFS= read -r f; do
        p="$(stat -f '%OLp' "$f" 2>/dev/null || stat -c '%a' "$f")"
        if [ "$p" != "600" ]; then bad "${f} is mode ${p}, expected 600"; badperm=1; fi
      done < <(find "$CREDS_DIR" -maxdepth 1 -name '*.creds')
      if [ "$badperm" -eq 1 ]; then die "a credential file has the wrong permissions"; fi
      p="$(stat -f '%OLp' "$CREDS_DIR" 2>/dev/null || stat -c '%a' "$CREDS_DIR")"
      ok "${n} credential file(s) at mode 0600; ${CREDS_DIR} at mode 0${p}"
      ok "contents never read, echoed, or logged by this script"
    fi

    printf '\n  %sTransport-level ACL (decoded from the minted credentials)%s\n' "$C_B" "$C_RST"
    acl_creds_check || die "a minted credential's NATS grants do not match the frozen ACL matrix"

    write_run_artifact
  fi

  printf '\n  %sMesh is up.%s  Inspect with:  cotal ps | cotal meshes | cotal status\n' "$C_B" "$C_RST"
  printf '  Tear down with: cotal down\n'
  if [ "${#MOCKED_AGENTS[@]}" -gt 0 ]; then
    printf '\n  %sThis is NOT a live six-model run: %s mocked.%s\n' "$C_YEL" "${MOCKED_AGENTS[*]}" "$C_RST"
  fi
}

# Machine-readable artifact for run_live.sh and the run report. runs/ is
# gitignored, so nothing here is ever committed.
write_run_artifact() {
  local art="${REPO_ROOT}/runs/${RUN_ID}" first=1 a
  local id prof rt conn model eff var pub sub harness cp
  mkdir -p "$art"
  {
    printf '{\n  "run_id": "%s",\n  "generated_at": "%s",\n' "$RUN_ID" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    printf '  "mocked": ['
    for a in ${MOCKED_AGENTS[@]+"${MOCKED_AGENTS[@]}"}; do
      if [ "$first" -eq 0 ]; then printf ', '; fi
      printf '"%s"' "$a"; first=0
    done
    printf '],\n  "agents": {\n'
    first=1
    while IFS=$'\t' read -r id prof rt conn model eff var pub sub harness; do
      if [ "$first" -eq 0 ]; then printf ',\n'; fi
      first=0
      cp=""
      if [ -f "${CREDS_DIR}/${id}.creds" ]; then cp="${CREDS_DIR}/${id}.creds"; fi
      printf '    "%s": {"profile":"%s","runtime":"%s","model":"%s","effort":"%s","status":"%s","creds":"%s","publish":"%s","subscribe":"%s"}' \
        "$id" "$prof" "$rt" "$model" "$eff" "$(agent_status_get "$id")" "$cp" \
        "$(if [ "$pub" = "-" ]; then printf ''; else printf '%s' "$pub"; fi)" \
        "$(if [ "$sub" = "-" ]; then printf ''; else printf '%s' "$sub"; fi)"
    done < <(printf '%s\n' "${PLAN_ROWS[@]}")
    printf '\n  }\n}\n'
  } > "${art}/mesh-up.json"
  ok "wrote ${art}/mesh-up.json"
}

# ---------------------------------------------------------------------------
main() {
  if [ -z "$RUN_ID" ]; then
    RUN_ID="$(node --input-type=module -e "const {newRunId}=await import(process.argv[1]); process.stdout.write(newRunId('up'))" -- "file://${MESH_DIR}/lib/paths.js" 2>/dev/null)" \
      || RUN_ID="up-$(date -u +%Y%m%dT%H%M%S)-$$"
  fi

  if [ "$DRY_RUN" -eq 1 ]; then
    printf '%s%smesh/up.sh%s  run-id=%s  repo=%s   [DRY RUN -- nothing mutating will be executed]\n' "$C_B" "$C_CYA" "$C_RST" "$RUN_ID" "$REPO_ROOT"
  else
    printf '%s%smesh/up.sh%s  run-id=%s  repo=%s\n' "$C_B" "$C_CYA" "$C_RST" "$RUN_ID" "$REPO_ROOT"
  fi

  phase_preflight
  phase_nats
  phase_mint
  phase_acl
  phase_connectors
  phase_agents
  phase_summary
}

main "$@"
