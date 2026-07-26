# coordinator/ids.jac
#
# Canonical vocabulary for the deterministic coordinator. Every constant here is
# transcribed from a FROZEN contract; none of it is invented:
#
#   - agent ids               <- contracts/mesh/channels.yaml `agents`, README "Canonical agent ids"
#   - containment kinds       <- contracts/containment.contract.jac CONTAINMENT_KINDS
#                                (identical to assessment.v1 / decision.v1 action enums)
#   - blast_radius ordering   <- assessment.v1: "Ordered narrow < moderate < broad"
#   - decision rule string    <- decision.v1.rule (const, emitted verbatim)
#
# Nothing in this module performs I/O or calls a model. The coordinator is a vote
# counter, not a judge.

import json;

# --------------------------------------------------------------------------
# Canonical agent ids
# --------------------------------------------------------------------------

glob:pub RESPONDER_IDS: list = [
    "responder_claude",
    "responder_codex",
    "responder_antigravity",
    "responder_kimi",
    "responder_glm"
];

glob:pub MONITOR_ID: str = "monitor";
glob:pub COORDINATOR_ID: str = "coordinator";
glob:pub CONTAINMENT_SERVICE: str = "containment";

# The six agents that must each file an effort receipt before the coordinator
# may leave WATCHING (monitor + all five responders).
glob:pub EFFORT_GATE_AGENTS: list = [
    "monitor",
    "responder_claude",
    "responder_codex",
    "responder_antigravity",
    "responder_kimi",
    "responder_glm"
];

glob:pub REQUIRED_RECEIPTS: int = 6;

# --------------------------------------------------------------------------
# The ten containment kinds. FROZEN — must match contracts/containment.contract.jac
# exactly, and the enums in assessment.v1 + decision.v1.
# --------------------------------------------------------------------------

glob:pub CONTAINMENT_KINDS: list = [
    "revoke_session",
    "revoke_token",
    "suspend_principal",
    "throttle_source",
    "block_source",
    "force_reauth",
    "feature_readonly",
    "pause_queue",
    "rotate_service_credential",
    "raise_logging"
];

# The only kind a DEGRADED (sub-quorum) run may ever apply. Everything else is a
# revocation-class action and is forbidden without quorum.
glob:pub MONITOR_ONLY_KINDS: list = ["raise_logging"];

# Every kind that removes access, blocks traffic, or changes a credential. A
# DEGRADED or split run must produce ZERO of these — asserted by test.
glob:pub REVOCATION_KINDS: list = [
    "revoke_session",
    "revoke_token",
    "suspend_principal",
    "throttle_source",
    "block_source",
    "force_reauth",
    "feature_readonly",
    "pause_queue",
    "rotate_service_credential"
];

# --------------------------------------------------------------------------
# Verdicts, weights and the decision rule
# --------------------------------------------------------------------------

glob:pub VERDICTS: list = ["malicious", "suspicious", "benign"];

# score = SUM over responders of w(verdict) * confidence
glob:pub VERDICT_WEIGHTS: dict = {
    "malicious": 1.0,
    "suspicious": 0.4,
    "benign": -1.0
};

# CONTAIN iff (count(malicious) >= 3) AND (score >= 1.5)
glob:pub MALICIOUS_MAJORITY: int = 3;
glob:pub SCORE_THRESHOLD: float = 1.5;

# Fewer than this many assessments in hand -> DEGRADED, never a containment.
glob:pub QUORUM_FLOOR: int = 3;

# An action reaches the action_set only if at least this many responders
# independently proposed it. This is the least-privilege construction rule.
glob:pub MIN_PROPOSERS: int = 2;

# decision.v1.rule is a `const` in the schema — emit exactly this string.
glob:pub DECISION_RULE: str = "contain iff >=3/5 malicious AND score >= 1.5";

# Float rounding for the emitted score so the artifact is byte-stable across
# runs. Gating always uses the unrounded value; 6 dp is far below the 1.5 gate.
glob:pub SCORE_PRECISION: int = 6;

# --------------------------------------------------------------------------
# blast_radius ordering: narrow < moderate < broad. "Minimum" means narrowest.
# --------------------------------------------------------------------------

glob:pub BLAST_ORDER: dict = {"narrow": 0, "moderate": 1, "broad": 2};
glob:pub BLAST_BY_RANK: list = ["narrow", "moderate", "broad"];

# --------------------------------------------------------------------------
# States and timeouts. Cotal has NO task lifecycle; this table is ours.
# --------------------------------------------------------------------------

glob:pub S_WATCHING: str = "WATCHING";
glob:pub S_ESCALATED: str = "ESCALATED";
glob:pub S_ASSESSING: str = "ASSESSING";
glob:pub S_DELIBERATING: str = "DELIBERATING";
glob:pub S_DECIDING: str = "DECIDING";
glob:pub S_CONTAINING: str = "CONTAINING";
glob:pub S_VERIFYING: str = "VERIFYING";
glob:pub S_CONTAINED: str = "CONTAINED";
glob:pub S_ROLLED_BACK: str = "ROLLED_BACK";
glob:pub S_DEGRADED: str = "DEGRADED";

glob:pub STATES: list = [
    "WATCHING",
    "ESCALATED",
    "ASSESSING",
    "DELIBERATING",
    "DECIDING",
    "CONTAINING",
    "VERIFYING",
    "CONTAINED",
    "ROLLED_BACK",
    "DEGRADED"
];

# Milliseconds. 0 means "no timeout for this state".
glob:pub TIMEOUTS_MS: dict = {
    "WATCHING": 0,
    "ESCALATED": 5000,
    "ASSESSING": 180000,
    "DELIBERATING": 90000,
    "DECIDING": 2000,
    "CONTAINING": 30000,
    "VERIFYING": 45000,
    "CONTAINED": 900000,
    "ROLLED_BACK": 0,
    "DEGRADED": 0
};

# Containment execution limits.
glob:pub CONTAIN_ACTION_TIMEOUT_MS: int = 30000;
glob:pub CONTAIN_MAX_PARALLEL: int = 3;
glob:pub CONTAIN_MAX_REDELIVER: int = 1;

# Presence liveness. Responders heartbeat ~every 2s; a card older than 6s (or an
# explicit `offline`) resolves that slot to NO_VOTE IMMEDIATELY rather than
# burning the whole 180s ASSESSING window. This is layer 1 of the dead-responder
# defence and exists because upstream has a known "dead agents go dark" bug: a
# dead agent otherwise reports `working` forever.
glob:pub PRESENCE_HEARTBEAT_MS: int = 2000;
glob:pub PRESENCE_STALE_MS: int = 6000;
glob:pub PRESENCE_STATUSES: list = ["working", "idle", "offline"];

# Default action lifetime when a surviving action carries no ttl.
glob:pub DEFAULT_TTL_S: int = 900;

# Exactly one bounded deliberation round, per channels.yaml sec.deliberate.
glob:pub DELIBERATION_ROUNDS_MAX: int = 1;

# --------------------------------------------------------------------------
# Run labelling. A run containing any blocked/mocked agent is NOT an acceptance
# run and every artifact it touches carries RUN_MOCKED.
# --------------------------------------------------------------------------

glob:pub RUN_LIVE: str = "LIVE";
glob:pub RUN_MOCKED: str = "MOCKED";

# --------------------------------------------------------------------------
# Pure helpers. No I/O, no clock, no randomness.
# --------------------------------------------------------------------------

"""Return the narrower (minimum) of two blast_radius values."""
def blast_min(a: str, b: str) -> str {
    ra = BLAST_ORDER.get(a, 2);
    rb = BLAST_ORDER.get(b, 2);
    if ra <= rb {
        return BLAST_BY_RANK[ra];
    }
    return BLAST_BY_RANK[rb];
}

"""Canonical, order-independent serialisation of an action target.

Two proposals are 'the same action' when action AND target match. Targets are
dicts whose key order is not meaningful, and whose list values (session_ids,
src_ips) are sets in spirit, so both are normalised before comparison."""
def target_key(target: dict) -> str {
    norm: dict = {};
    for k in sorted(target.keys()) {
        v = target[k];
        if isinstance(v, list) {
            norm[k] = sorted([str(item) for item in v]);
        } else {
            norm[k] = v;
        }
    }
    return json.dumps(norm, sort_keys=True, separators=(",", ":"));
}

"""Identity of a proposed action: (kind, canonical target)."""
def action_key(action: str, target: dict) -> str {
    return f"{action}|{target_key(target)}";
}

"""Deterministic, order-independent fingerprint of a list of assessments.

Used to prove that the same assessments in any arrival order produce the same
decision out."""
def assessments_fingerprint(assessments: list) -> str {
    rows: list = [];
    for a in assessments {
        rows.append(json.dumps(a, sort_keys=True, separators=(",", ":")));
    }
    return json.dumps(sorted(rows), separators=(",", ":"));
}

"""True when `kind` is one of the ten frozen containment kinds."""
def is_valid_kind(kind: str) -> bool {
    return kind in CONTAINMENT_KINDS;
}

"""True when applying `kind` would remove access / block traffic / rotate creds."""
def is_revocation(kind: str) -> bool {
    return kind in REVOCATION_KINDS;
}
