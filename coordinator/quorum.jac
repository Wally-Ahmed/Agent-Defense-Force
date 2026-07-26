# coordinator/quorum.jac
#
# THE HEART. The coordinator is a VOTE COUNTER, not an LLM judge.
#
# Everything in this module is pure: no model calls, no I/O, no randomness, no
# wall clock, no `time`. Given the same assessments in any arrival order it emits
# a byte-identical decision.v1. That is not a nicety — it is the whole security
# argument. A containment decision you cannot reproduce is a containment decision
# you cannot audit.
#
# The rule, verbatim from decision.v1.rule:
#     contain iff >=3/5 malicious AND score >= 1.5
#
# There is deliberately NO flag, env var, debug switch or "test mode" anywhere in
# this file that can set `contain` true without the full rule passing. If you are
# reading this because you want to force containment for a demo: don't. Change
# the assessments, not the counter.

import json;

import from ids {
    VERDICTS,
    VERDICT_WEIGHTS,
    RESPONDER_IDS,
    MALICIOUS_MAJORITY,
    SCORE_THRESHOLD,
    QUORUM_FLOOR,
    MIN_PROPOSERS,
    DECISION_RULE,
    SCORE_PRECISION,
    DEFAULT_TTL_S,
    MONITOR_ONLY_KINDS,
    blast_min,
    target_key,
    action_key,
    is_valid_kind,
    is_revocation
}

# Marks an entry as belonging to the coordinator-local DEGRADED monitoring
# posture, so nothing downstream can mistake it for a decision.v1 action_set
# entry (it is not one — decision.v1 forbids the extra key).
glob:pub MONITOR_POSTURE_SOURCE: str = "degraded_monitor_only";

# The widest blast_radius, used as the fold identity and as the assumed value for
# a malformed proposal. Assuming "broad" for a malformed proposal is safe because
# blast_min only ever narrows: an unknown value can never widen the result.
glob:pub BLAST_WIDEST: str = "broad";


obj QuorumInput {
    has incident_id: str = "";
    # list[dict] assessment.v1. AT MOST ONE per responder — late duplicates are
    # dropped upstream by the coordinator, not here.
    has assessments: list = [];
    # list[str] responder ids that did not vote (timeout, crash, blocked, dark).
    has no_vote: list = [];
    has decided_at_ms: int = 0;
    # True when the run is MOCKED or any agent ran blocked. Can only ever make a
    # decision MORE degraded; it can never influence `contain`.
    has force_degraded: bool = False;
}


"""Canonical form of an action target: keys sorted, list values sorted.

Sorting the list values (session_ids, src_ips) is what makes two proposals of
'the same action' compare equal regardless of the order each responder happened
to list them in, and it is what makes the emitted JSON byte-stable."""
def canonical_target(target: dict) -> dict {
    norm: dict = {};
    for k in sorted(target.keys()) {
        v = target[k];
        if isinstance(v, list) {
            norm[k] = sorted([str(item) for item in v]);
        } else {
            norm[k] = v;
        }
    }
    return norm;
}


"""Count the verdicts. Sums to len(assessments) for well-formed input."""
def tally(assessments: list) -> dict {
    counts: dict = {"malicious": 0, "suspicious": 0, "benign": 0};
    for a in assessments {
        v = a.get("verdict", "");
        if v in counts {
            counts[v] = (counts[v] + 1);
        }
    }
    return counts;
}


"""UNCLAMPED weighted vote score: SUM over responders of w(verdict)*confidence.

w: malicious +1.0, suspicious +0.4, benign -1.0.

This MUST be allowed to go negative — five benign votes at full confidence is
-5.0, and that number is the honest signal. decision.v1.score has "minimum": 0,
so `decide` clamps the EMITTED value; the gate always tests this raw one. See the
long comment in `decide`."""
def raw_score(assessments: list) -> float {
    total: float = 0.0;
    for a in assessments {
        w = VERDICT_WEIGHTS.get(a.get("verdict", ""), 0.0);
        total = (total + (w * float(a.get("confidence", 0.0))));
    }
    return total;
}


"""Group every proposed action by (action, target) across all assessments.

Returns dict action_key -> {action, target, ttl_s, blast_radius, proposers}.
`ttl_s` is folded to the MINIMUM and `blast_radius` to the NARROWEST seen so far;
`proposers` is the DISTINCT responder ids, insertion-ordered (callers sort)."""
def group_proposals(assessments: list, only_kinds: list | None = None) -> dict {
    groups: dict = {};
    for a in assessments {
        responder = a.get("responder", "");
        for p in a.get("recommended_actions", []) {
            action = p.get("action", "");
            # A kind outside the frozen enum never enters the pipeline at all.
            # The executor implements exactly ten kinds; anything else is a
            # contract violation upstream, not something to improvise around.
            if not is_valid_kind(action) {
                continue;
            }
            if (only_kinds is not None) and (action not in only_kinds) {
                continue;
            }
            target = p.get("target", {});
            ttl = int(p.get("ttl_s", DEFAULT_TTL_S));
            blast = p.get("blast_radius", BLAST_WIDEST);
            k = action_key(action, target);
            g = groups.get(k, None);
            if g is None {
                groups[k] = {
                    "action": action,
                    "target": canonical_target(target),
                    "ttl_s": ttl,
                    "blast_radius": blast,
                    "proposers": []
                };
                g = groups[k];
            } else {
                # THE MIN-FOLD. Shortest ttl and narrowest blast win, so the
                # mesh's containment is bounded by the most cautious proposer of
                # each action — never by the loudest. An aggressive responder can
                # only ever shorten, never extend, what its peers already agreed
                # to.
                g["ttl_s"] = min(g["ttl_s"], ttl);
                g["blast_radius"] = blast_min(g["blast_radius"], blast);
            }
            # DISTINCT responders only. One responder listing the same action
            # twice is ONE proposer — otherwise a single agent could manufacture
            # its own quorum just by repeating itself.
            if responder not in g["proposers"] {
                g["proposers"].append(responder);
            }
        }
    }
    return groups;
}


"""The least-privilege action set: least-privilege BY CONSTRUCTION, not by review.

An action reaches this list only if at least MIN_PROPOSERS (2) DISTINCT responders
independently proposed it against the same target. That >=2 bar is the whole
anti-rogue-agent argument: one compromised, hallucinating or merely overconfident
responder cannot add a single containment action to the set, no matter how
confident it is or how many actions it lists.

Output is sorted by (action, canonical target) so the same inputs in any arrival
order produce a byte-identical list."""
def build_action_set(assessments: list) -> list {
    groups = group_proposals(assessments, None);
    out: list = [];
    for k in sorted(groups.keys()) {
        g = groups[k];
        if len(g["proposers"]) < MIN_PROPOSERS {
            continue;
        }
        out.append({
            "action": g["action"],
            "target": g["target"],
            "ttl_s": g["ttl_s"],
            "blast_radius": g["blast_radius"],
            "proposed_by": sorted(g["proposers"])
        });
    }
    return sorted(out, key=lambda e: any : (e["action"], target_key(e["target"])));
}


"""True when the mesh is genuinely split: quorum reached, but no verdict commands
a majority. 2-2-1 is a split; 3-1-1 is not (three agree)."""
def is_split(counts: dict, voted: int) -> bool {
    if voted < QUORUM_FLOOR {
        return False;
    }
    for v in VERDICTS {
        if counts.get(v, 0) >= MALICIOUS_MAJORITY {
            return False;
        }
    }
    return True;
}


"""The DEGRADED posture: what the coordinator may do when quorum is MISSED.

This is NOT a decision.v1 action_set — it carries an extra "source" key that
decision.v1 forbids (additionalProperties: false), and it is never dispatched to
toService:containment. It is a coordinator-local monitoring posture.

Only `raise_logging` is eligible. It is the one containment kind that removes no
access, blocks no traffic and rotates no credential, so it needs no >=2 bar: a
single responder asking for more telemetry on a half-blind mesh is strictly safe.
Every other kind is a revocation and is FORBIDDEN here — a mesh that could not
reach quorum has not earned the right to take anything away from anyone.

Falls back to a single default entry so a degraded run always produces an
explicit, auditable posture rather than silence."""
def monitor_only_posture(assessments: list, fallback_target: dict) -> list {
    groups = group_proposals(assessments, MONITOR_ONLY_KINDS);
    out: list = [];
    for k in sorted(groups.keys()) {
        g = groups[k];
        out.append({
            "action": g["action"],
            "target": g["target"],
            "ttl_s": g["ttl_s"],
            "blast_radius": g["blast_radius"],
            "proposed_by": sorted(g["proposers"]),
            "source": MONITOR_POSTURE_SOURCE
        });
    }
    if len(out) == 0 {
        out.append({
            "action": MONITOR_ONLY_KINDS[0],
            "target": canonical_target(fallback_target),
            "ttl_s": DEFAULT_TTL_S,
            "blast_radius": "narrow",
            "proposed_by": [],
            "source": MONITOR_POSTURE_SOURCE
        });
    }
    # HARD INVARIANT — zero revocation, checked on the way out rather than
    # trusted from the filter above. If this ever raises, a degraded run was one
    # step from revoking access without quorum, and crashing is the correct
    # outcome.
    for e in out {
        kind = e["action"];
        assert kind in MONITOR_ONLY_KINDS;
        assert not is_revocation(kind);
        if (kind not in MONITOR_ONLY_KINDS) or is_revocation(kind) {
            raise ValueError(f"monitor_only_posture invariant violated: degraded posture emitted non-monitor action {kind}");
        }
    }
    return out;
}


"""Apply the rule and emit a schema-valid decision.v1.

    contain iff quorum_met AND malicious >= 3 AND raw_score >= 1.5

No other path sets contain. There is no override."""
def decide(inp: QuorumInput) -> dict {
    counts = tally(inp.assessments);
    voted = len(inp.assessments);
    raw = raw_score(inp.assessments);

    quorum_met = (voted >= QUORUM_FLOOR);

    # THE GATE. Note it tests `raw`, the UNCLAMPED score — see below.
    contain = (
        quorum_met
        and (counts["malicious"] >= MALICIOUS_MAJORITY)
        and (raw >= SCORE_THRESHOLD)
    );

    # The action set exists only when the rule fired. decision.v1 requires it
    # empty otherwise, and an empty list is also the only honest answer: no
    # containment was authorised, so no containment is described.
    action_set: list = [];
    if contain {
        action_set = build_action_set(inp.assessments);
    }

    # Anything short of all five voices, or any mocked/blocked agent, and the
    # decision is labelled degraded. Still valid, never silently so.
    degraded = ((voted < len(RESPONDER_IDS)) or inp.force_degraded);

    # THE SCORE CLAMP — deliberate, and load-bearing to explain:
    #
    #   decision.v1.score declares "minimum": 0, but the raw weighted score is
    #   legitimately NEGATIVE for benign-leaning incidents (five benign votes at
    #   full confidence = -5.0). So the EMITTED score is clamped to
    #   max(0.0, raw) purely to stay schema-valid, while the CONTAIN GATE above
    #   always tests the UNCLAMPED `raw`.
    #
    #   This can never change an outcome: the threshold is +1.5, strictly above
    #   zero, and clamping only ever moves values from (-inf, 0) to exactly 0.0.
    #   Every value the clamp touches was already far below 1.5 and stays far
    #   below it, so `contain` is identical whether computed from raw or from the
    #   clamped value. The clamp is a presentation detail; the gate is the truth.
    #
    # Rounded to SCORE_PRECISION (6dp) so the artifact is byte-stable across
    # runs. 6dp is many orders of magnitude below the 1.5 gate, so rounding
    # cannot flip an outcome either — and in any case the gate never sees it.
    score = round(max(0.0, raw), SCORE_PRECISION);

    # Exactly the 11 keys decision.v1 requires. The schema is
    # additionalProperties: false — do not add a twelfth.
    return {
        "incident_id": inp.incident_id,
        "decided_at_ms": inp.decided_at_ms,
        "verdict_counts": counts,
        "score": score,
        "contain": contain,
        "quorum_met": quorum_met,
        "responders_voted": voted,
        # sorted + deduped: the schema demands uniqueItems, and sorting after the
        # set() keeps the output independent of set iteration order.
        "responders_no_vote": sorted(set(inp.no_vote)),
        "action_set": action_set,
        "degraded": degraded,
        "rule": DECISION_RULE
    };
}
