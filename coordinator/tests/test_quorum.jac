# coordinator/tests/test_quorum.jac
#
# Run from the coordinator directory (Jac resolves imports relative to the
# INVOCATION cwd, not the file):
#
#     cd coordinator && jac test tests/test_quorum.jac
#
# Every decision emitted anywhere in this suite is validated against the FROZEN
# decision.v1 contract before a single assertion is made about it — see
# `decided()`. A decision that passes our assertions but violates the contract is
# a decision the containment service would reject, so contract-first is the only
# order that means anything.

import json;

import from ids {
    RESPONDER_IDS,
    CONTAINMENT_KINDS,
    REVOCATION_KINDS,
    BLAST_ORDER,
    DEFAULT_TTL_S,
    SCORE_THRESHOLD,
    MALICIOUS_MAJORITY,
    action_key,
    target_key,
    assessments_fingerprint,
    is_revocation
}
import from schema_check { validate_payload, is_valid }
import from quorum {
    QuorumInput,
    tally,
    raw_score,
    build_action_set,
    is_split,
    monitor_only_posture,
    decide,
    MONITOR_POSTURE_SOURCE
}
import from tests.fixtures {
    act,
    assessment,
    aggressive_assessment,
    all_kinds_actions,
    target_principal,
    target_session,
    target_source,
    target_feature,
    TEST_INCIDENT
}

glob:pub DECIDED_AT: int = 1769472000000;
glob:pub AGGRESSOR: str = "responder_glm";


# --------------------------------------------------------------------------
# Test helpers
# --------------------------------------------------------------------------

"""Decide, CONTRACT-CHECK, and return. Every test goes through this door, so no
test can assert against a decision that would not survive the frozen schema."""
def decided(assessments: list, no_vote: list = []) -> dict {
    d = decide(QuorumInput(
        incident_id=TEST_INCIDENT,
        assessments=assessments,
        no_vote=list(no_vote),
        decided_at_ms=DECIDED_AT
    ));
    validate_payload("decision.v1", d);
    return d;
}


"""The action_set entry for `action`, or None."""
def entry_for(action_set: list, action: str) -> dict | None {
    for e in action_set {
        if e["action"] == action {
            return e;
        }
    }
    return None;
}


"""action_key -> entry, for cross-run comparison."""
def by_key(action_set: list) -> dict {
    out: dict = {};
    for e in action_set {
        out[action_key(e["action"], e["target"])] = e;
    }
    return out;
}


"""Every distinct containment kind present in an action_set."""
def kinds_in(action_set: list) -> list {
    return sorted(set([e["action"] for e in action_set]));
}


# --------------------------------------------------------------------------
# Fixture sanity: the builders themselves must honour the frozen contract.
# --------------------------------------------------------------------------

test "fixtures emit schema-valid assessment.v1 payloads" {
    P = target_principal();
    samples = [
        assessment("responder_claude", "malicious", 1.0, [act("revoke_session", P, 600, "narrow")]),
        assessment("responder_kimi", "suspicious", 0.4, []),
        assessment("responder_glm", "benign", 0.0, [act("raise_logging", target_source(), 900, "narrow")]),
        aggressive_assessment(AGGRESSOR, P)
    ];
    for a in samples {
        validate_payload("assessment.v1", a);
    }
    # The aggressive builder really does propose all ten frozen kinds.
    assert len(samples[3]["recommended_actions"]) == len(CONTAINMENT_KINDS);
    assert sorted(set([p["action"] for p in samples[3]["recommended_actions"]])) == sorted(CONTAINMENT_KINDS);
}


# --------------------------------------------------------------------------
# 1. Unanimous malicious
# --------------------------------------------------------------------------

test "all five agree malicious -> contain" {
    P = target_principal();
    shared = [act("revoke_session", P, 900, "narrow")];
    assessments: list = [];
    for r in RESPONDER_IDS {
        assessments.append(assessment(r, "malicious", 1.0, shared));
    }
    d = decided(assessments);

    assert d["contain"] == True;
    assert d["quorum_met"] == True;
    assert d["degraded"] == False;
    assert d["verdict_counts"]["malicious"] == 5;
    assert d["verdict_counts"]["suspicious"] == 0;
    assert d["verdict_counts"]["benign"] == 0;
    assert d["responders_voted"] == 5;
    assert d["responders_no_vote"] == [];
    assert d["score"] == 5.0;
    assert d["rule"] == "contain iff >=3/5 malicious AND score >= 1.5";
    # All five proposed it, so it clears the >=2 bar with room to spare.
    assert len(d["action_set"]) == 1;
    assert d["action_set"][0]["proposed_by"] == sorted(RESPONDER_IDS);
}


# --------------------------------------------------------------------------
# 2 & 3. The score is a real gate, not decoration.
# --------------------------------------------------------------------------

test "exactly 3/5 malicious with score >= 1.5 -> contain" {
    P = target_principal();
    shared = [act("revoke_session", P, 900, "narrow")];
    # 3 x malicious @0.75 = +2.25 ; 2 x benign @0.25 = -0.50 ; raw = 1.75 >= 1.5
    assessments = [
        assessment("responder_claude", "malicious", 0.75, shared),
        assessment("responder_codex", "malicious", 0.75, shared),
        assessment("responder_antigravity", "malicious", 0.75, shared),
        assessment("responder_kimi", "benign", 0.25, []),
        assessment("responder_glm", "benign", 0.25, [])
    ];
    assert raw_score(assessments) == 1.75;
    d = decided(assessments);

    assert d["verdict_counts"]["malicious"] == MALICIOUS_MAJORITY;
    assert d["score"] == 1.75;
    assert d["score"] >= SCORE_THRESHOLD;
    assert d["contain"] == True;
    assert d["quorum_met"] == True;
    assert len(d["action_set"]) == 1;
}


test "3/5 malicious but score < 1.5 -> no contain (the score is a real gate, not decoration)" {
    P = target_principal();
    shared = [act("revoke_session", P, 900, "narrow")];
    # Same 3/5 malicious MAJORITY as the test above, but held with low
    # confidence and pushed back on by two benign votes:
    # 3 x malicious @0.25 = +0.75 ; 2 x benign @0.25 = -0.50 ; raw = 0.25 < 1.5
    assessments = [
        assessment("responder_claude", "malicious", 0.25, shared),
        assessment("responder_codex", "malicious", 0.25, shared),
        assessment("responder_antigravity", "malicious", 0.25, shared),
        assessment("responder_kimi", "benign", 0.25, []),
        assessment("responder_glm", "benign", 0.25, [])
    ];
    assert raw_score(assessments) == 0.25;
    d = decided(assessments);

    # The majority arm of the rule PASSES...
    assert d["verdict_counts"]["malicious"] == MALICIOUS_MAJORITY;
    assert d["quorum_met"] == True;
    # ...and containment is still refused, purely on the score.
    assert d["score"] == 0.25;
    assert d["score"] < SCORE_THRESHOLD;
    assert d["contain"] == False;
    assert d["action_set"] == [];

    # And the action_set is empty because the GATE closed, not because nothing
    # cleared the >=2-proposer bar: three responders proposed this action, so it
    # would have survived construction. The score is what killed it.
    assert len(build_action_set(assessments)) == 1;
    assert build_action_set(assessments)[0]["action"] == "revoke_session";
}


# --------------------------------------------------------------------------
# 4. A lone aggressive responder adds nothing.
# --------------------------------------------------------------------------

test "one aggressive responder alone cannot add an action" {
    P = target_principal();
    SRC = target_source(["198.51.100.7"]);
    Q = target_feature("bulk_export");
    solo = [
        act("suspend_principal", P, 86400, "broad"),
        act("block_source", SRC, 86400, "broad"),
        act("feature_readonly", Q, 86400, "broad")
    ];
    # 3 x malicious @1.0 = +3.0 ; 2 x benign @0.5 = -1.0 ; raw = 2.0 -> contain
    assessments = [
        assessment("responder_claude", "malicious", 1.0, [act("revoke_session", P, 600, "moderate")]),
        assessment("responder_codex", "malicious", 1.0, [act("revoke_session", P, 900, "narrow")]),
        # The aggressor: real malicious verdict, but every action it proposes is
        # its own idea. Nobody seconded any of them.
        assessment("responder_antigravity", "malicious", 1.0, solo),
        assessment("responder_kimi", "benign", 0.5, []),
        assessment("responder_glm", "benign", 0.5, [])
    ];
    d = decided(assessments);
    assert d["contain"] == True;

    present = by_key(d["action_set"]);
    # Not one of its unilateral proposals made it through.
    for p in solo {
        assert action_key(p["action"], p["target"]) not in present;
    }
    # But the action two responders agreed on is there, unaffected.
    keep = entry_for(d["action_set"], "revoke_session");
    assert keep is not None;
    assert len(d["action_set"]) == 1;
    assert keep["proposed_by"] == ["responder_claude", "responder_codex"];
}


# --------------------------------------------------------------------------
# 5. The min-fold.
# --------------------------------------------------------------------------

test "min ttl and narrowest blast win across proposers" {
    P = target_principal();
    # Same action, same target, three different appetites for it.
    assessments = [
        assessment("responder_claude", "malicious", 1.0, [act("revoke_session", P, 1800, "broad")]),
        assessment("responder_codex", "malicious", 1.0, [act("revoke_session", P, 600, "moderate")]),
        assessment("responder_antigravity", "malicious", 1.0, [act("revoke_session", P, 900, "narrow")]),
        assessment("responder_kimi", "benign", 0.5, []),
        assessment("responder_glm", "benign", 0.5, [])
    ];
    d = decided(assessments);
    assert d["contain"] == True;
    assert len(d["action_set"]) == 1;

    e = d["action_set"][0];
    assert e["action"] == "revoke_session";
    # Shortest leash offered by anyone...
    assert e["ttl_s"] == 600;
    # ...and narrowest blast offered by anyone. Note neither came from the same
    # responder: ttl 600 is codex's, narrow is antigravity's. The result is more
    # cautious than ANY single proposer asked for.
    assert e["blast_radius"] == "narrow";
    assert e["proposed_by"] == ["responder_antigravity", "responder_claude", "responder_codex"];
    assert e["target"] == P;
}


# --------------------------------------------------------------------------
# 6. Self-seconding does not work.
# --------------------------------------------------------------------------

test "one responder proposing the same action twice is still one proposer" {
    P = target_principal();
    # claude lists revoke_token@P twice with different ttls. Two entries, one
    # responder, one proposer. It must not manufacture its own quorum.
    doubled = [
        act("revoke_token", P, 600, "narrow"),
        act("revoke_token", P, 1200, "moderate"),
        act("raise_logging", P, 900, "narrow")
    ];
    assessments = [
        assessment("responder_claude", "malicious", 1.0, doubled),
        assessment("responder_codex", "malicious", 1.0, [act("raise_logging", P, 1800, "moderate")]),
        assessment("responder_antigravity", "malicious", 1.0, []),
        assessment("responder_kimi", "benign", 0.5, []),
        assessment("responder_glm", "benign", 0.5, [])
    ];
    d = decided(assessments);
    assert d["contain"] == True;

    # The self-seconded action is absent...
    assert entry_for(d["action_set"], "revoke_token") is None;
    assert "revoke_token" not in kinds_in(d["action_set"]);
    # ...while the genuinely twice-proposed one survives, with exactly two
    # DISTINCT proposers on the audit trail.
    log = entry_for(d["action_set"], "raise_logging");
    assert log is not None;
    assert log["proposed_by"] == ["responder_claude", "responder_codex"];
    assert len(log["proposed_by"]) == 2;
    assert len(d["action_set"]) == 1;
}


# --------------------------------------------------------------------------
# 7. THE PROPERTY TEST.
# --------------------------------------------------------------------------

test "the mesh can only ever be as aggressive as its second-most-cautious member" {
    P = target_principal();

    # --- baseline mesh: five ordinary responders -------------------------
    base = [
        assessment("responder_claude", "malicious", 0.75, [
            act("revoke_session", P, 600, "moderate"),
            act("raise_logging", P, 900, "narrow")
        ]),
        assessment("responder_codex", "malicious", 0.75, [
            act("revoke_session", P, 1200, "narrow"),
            act("raise_logging", P, 1800, "moderate")
        ]),
        assessment("responder_antigravity", "malicious", 0.75, [
            act("revoke_session", P, 900, "moderate")
        ]),
        assessment("responder_kimi", "suspicious", 0.5, [
            act("raise_logging", P, 300, "narrow")
        ]),
        assessment(AGGRESSOR, "benign", 0.25, [])
    ];
    d0 = decided(base);
    assert d0["contain"] == True;
    assert len(d0["action_set"]) == 2;

    # --- same mesh, but ONE member replaced by a maximal aggressor -------
    # malicious @1.0, proposing ALL TEN containment kinds at the widest blast
    # and a full day of ttl, against the very target the others are discussing
    # so its proposals genuinely collide with theirs.
    hot = base[0:4] + [aggressive_assessment(AGGRESSOR, P)];
    d1 = decided(hot);
    # It even shifted the vote: 4/5 malicious now, score higher. It still cannot
    # widen a thing.
    assert d1["contain"] == True;
    assert d1["verdict_counts"]["malicious"] == 4;
    assert d1["score"] > d0["score"];

    b0 = by_key(d0["action_set"]);
    b1 = by_key(d1["action_set"]);

    # (a) Nothing in the new action_set rests on the aggressor's word alone.
    for (k, e) in b1.items() {
        others = [r for r in e["proposed_by"] if r != AGGRESSOR];
        assert len(others) >= 1;
    }

    # (b) Nothing it touched got longer or wider. The aggressor is a member of
    #     the fold, never its ceiling.
    for (k, e) in b1.items() {
        if k in b0 {
            assert e["ttl_s"] <= b0[k]["ttl_s"];
            assert BLAST_ORDER[e["blast_radius"]] <= BLAST_ORDER[b0[k]["blast_radius"]];
        }
    }
    # Concretely: the two runs agree on the same actions with the same targets,
    # ttls and blast radii. The ONLY difference the aggressor makes anywhere in
    # the action_set is its own name appearing on the audit trail of actions its
    # peers had already agreed on. It joins the fold; it does not move it.
    assert sorted(b1.keys()) == sorted(b0.keys());
    for (k, e) in b1.items() {
        shape1 = {"action": e["action"], "target": e["target"], "ttl_s": e["ttl_s"], "blast_radius": e["blast_radius"]};
        p = b0[k];
        shape0 = {"action": p["action"], "target": p["target"], "ttl_s": p["ttl_s"], "blast_radius": p["blast_radius"]};
        assert json.dumps(shape1, sort_keys=True) == json.dumps(shape0, sort_keys=True);
        added = sorted(set(e["proposed_by"]) - set(p["proposed_by"]));
        assert added == [] or added == [AGGRESSOR];
        # It never removed a proposer either.
        assert sorted(set(p["proposed_by"]) - set(e["proposed_by"])) == [];
    }

    # (c) Everything only IT proposed is gone. Compute that set rather than
    #     hard-coding it, so the assertion tracks CONTAINMENT_KINDS.
    seconded: list = [];
    for a in base[0:4] {
        for p in a["recommended_actions"] {
            seconded.append(action_key(p["action"], p["target"]));
        }
    }
    solo_keys = [action_key(kind, P) for kind in CONTAINMENT_KINDS if action_key(kind, P) not in seconded];
    assert len(solo_keys) >= 1;
    for k in solo_keys {
        assert k not in b1;
    }
    # 10 kinds proposed, 2 seconded by peers, 8 dropped on the floor.
    assert len(solo_keys) == 8;
    assert len(d1["action_set"]) == 2;
    # And every one of those 8 was a proposal the aggressor really did make.
    aggressive_keys = [action_key(p["action"], p["target"]) for p in hot[4]["recommended_actions"]];
    for k in solo_keys {
        assert k in aggressive_keys;
    }
}


# --------------------------------------------------------------------------
# 8. Determinism.
# --------------------------------------------------------------------------

test "determinism: same assessments in any order -> byte-identical decision out" {
    P = target_principal();
    SRC = target_source(["203.0.113.44", "203.0.113.9"]);
    base = [
        assessment("responder_claude", "malicious", 1.0, [
            # session_ids listed in one order here...
            act("revoke_session", target_session(["sess_9f2", "sess_1a0"]), 1200, "moderate"),
            act("raise_logging", P, 900, "narrow")
        ]),
        assessment("responder_codex", "malicious", 1.0, [
            # ...and the opposite order here. Same action, and it must be seen
            # as the same action.
            act("revoke_session", target_session(["sess_1a0", "sess_9f2"]), 600, "narrow"),
            act("block_source", SRC, 3600, "broad")
        ]),
        assessment("responder_antigravity", "malicious", 1.0, [
            act("raise_logging", P, 1800, "moderate"),
            act("block_source", target_source(["203.0.113.9", "203.0.113.44"]), 1800, "moderate")
        ]),
        assessment("responder_kimi", "benign", 0.5, []),
        assessment(AGGRESSOR, "benign", 0.5, [])
    ];

    # Deterministic permutations only: five rotations plus two reversals. No
    # `random` anywhere in this suite — a flaky determinism test proves nothing.
    perms: list = [];
    i = 0;
    while i < len(base) {
        perms.append(base[i:] + base[0:i]);
        i = (i + 1);
    }
    perms.append(list(reversed(base)));
    perms.append(list(reversed(base[2:] + base[0:2])));
    assert len(perms) == 7;

    blobs: list = [];
    prints: list = [];
    for perm in perms {
        assert len(perm) == 5;
        d = decided(perm, ["nobody_missing"][0:0]);
        blobs.append(json.dumps(d, sort_keys=True));
        prints.append(assessments_fingerprint(perm));
    }

    for b in blobs {
        assert b == blobs[0];
    }
    for f in prints {
        assert f == prints[0];
    }
    # The test is only meaningful if the decision has structure to scramble.
    first = json.loads(blobs[0]);
    assert first["contain"] == True;
    assert len(first["action_set"]) == 3;
    assert kinds_in(first["action_set"]) == ["block_source", "raise_logging", "revoke_session"];
}


# --------------------------------------------------------------------------
# 9. Split detection.
# --------------------------------------------------------------------------

test "is_split detects 2-2-1 and not 3-1-1" {
    assert is_split({"malicious": 2, "suspicious": 2, "benign": 1}, 5) == True;
    assert is_split({"malicious": 3, "suspicious": 1, "benign": 1}, 5) == False;
    assert is_split({"malicious": 1, "suspicious": 1, "benign": 3}, 5) == False;
    assert is_split({"malicious": 1, "suspicious": 1, "benign": 1}, 3) == True;
    # Below the quorum floor there is no split, only an absence of a mesh.
    assert is_split({"malicious": 1, "suspicious": 1, "benign": 0}, 2) == False;
    assert is_split({"malicious": 0, "suspicious": 0, "benign": 0}, 0) == False;

    # And the counts really do come from tally().
    votes = [
        assessment("responder_claude", "malicious", 1.0, []),
        assessment("responder_codex", "malicious", 1.0, []),
        assessment("responder_antigravity", "suspicious", 1.0, []),
        assessment("responder_kimi", "suspicious", 1.0, []),
        assessment(AGGRESSOR, "benign", 1.0, [])
    ];
    c = tally(votes);
    assert c == {"malicious": 2, "suspicious": 2, "benign": 1};
    assert is_split(c, len(votes)) == True;
    d = decided(votes);
    assert d["contain"] == False;
    assert d["quorum_met"] == True;
}


# --------------------------------------------------------------------------
# 10. The degraded posture takes nothing away.
# --------------------------------------------------------------------------

test "monitor_only_posture never contains a revocation" {
    P = target_principal();
    SRC = target_source();
    # A half-blind mesh that still wants blood: every revocation kind proposed,
    # by two responders, plus some raise_logging.
    loud = [
        assessment("responder_claude", "malicious", 1.0,
                   all_kinds_actions(P, 86400, "broad") + [act("raise_logging", SRC, 1200, "moderate")]),
        assessment("responder_codex", "malicious", 1.0,
                   all_kinds_actions(P, 3600, "moderate") + [act("raise_logging", SRC, 600, "narrow")])
    ];
    posture = monitor_only_posture(loud, P);

    assert len(posture) == 2;
    for e in posture {
        assert e["action"] == "raise_logging";
        assert not is_revocation(e["action"]);
        assert e["action"] not in REVOCATION_KINDS;
        assert e["source"] == MONITOR_POSTURE_SOURCE;
    }
    assert kinds_in(posture) == ["raise_logging"];

    # The min-fold applies here too: shortest ttl, narrowest blast.
    on_p = None;
    on_src = None;
    for e in posture {
        if e["target"] == P {
            on_p = e;
        } else {
            on_src = e;
        }
    }
    assert on_p is not None;
    assert on_p["ttl_s"] == 3600;
    assert on_p["blast_radius"] == "moderate";
    assert on_p["proposed_by"] == ["responder_claude", "responder_codex"];
    assert on_src is not None;
    assert on_src["ttl_s"] == 600;
    assert on_src["blast_radius"] == "narrow";

    # Empty input -> exactly one explicit default entry, never silence.
    empty = monitor_only_posture([], P);
    assert len(empty) == 1;
    assert empty[0]["action"] == "raise_logging";
    assert empty[0]["target"] == P;
    assert empty[0]["ttl_s"] == DEFAULT_TTL_S;
    assert empty[0]["blast_radius"] == "narrow";
    assert empty[0]["proposed_by"] == [];
    assert empty[0]["source"] == MONITOR_POSTURE_SOURCE;

    # Revocations ONLY -> still nothing revoked, still the default entry.
    revoke_only = [
        assessment("responder_claude", "malicious", 1.0, [act("suspend_principal", P, 86400, "broad")]),
        assessment("responder_codex", "malicious", 1.0, [act("block_source", SRC, 86400, "broad")])
    ];
    fallback = monitor_only_posture(revoke_only, P);
    assert len(fallback) == 1;
    assert fallback[0]["action"] == "raise_logging";
    assert fallback[0]["proposed_by"] == [];
}


# --------------------------------------------------------------------------
# 11. Benign-leaning incidents.
# --------------------------------------------------------------------------

test "all benign -> negative raw score, clamped score is schema-valid, contain false" {
    assessments: list = [];
    for r in RESPONDER_IDS {
        assessments.append(assessment(r, "benign", 1.0, []));
    }
    # The honest, UNCLAMPED signal is deeply negative.
    assert raw_score(assessments) == -5.0;
    assert raw_score(assessments) < 0.0;

    d = decided(assessments);
    # decision.v1.score has "minimum": 0, so the EMITTED value is clamped. The
    # gate tested the raw -5.0; clamping cannot rescue it, because the threshold
    # (+1.5) sits above the clamp floor (0.0).
    assert d["score"] == 0.0;
    assert d["score"] >= 0.0;
    assert is_valid("decision.v1", d) == True;
    assert d["contain"] == False;
    assert d["quorum_met"] == True;
    assert d["degraded"] == False;
    assert d["verdict_counts"]["benign"] == 5;
    assert d["action_set"] == [];
}


# --------------------------------------------------------------------------
# Sub-quorum and degraded labelling.
# --------------------------------------------------------------------------

test "sub-quorum can never contain and is always labelled degraded" {
    P = target_principal();
    shared = [act("revoke_session", P, 600, "narrow")];
    # Two maximally confident malicious votes. Below QUORUM_FLOOR, so the rule
    # cannot fire no matter how high the score is.
    two = [
        assessment("responder_claude", "malicious", 1.0, shared),
        assessment("responder_codex", "malicious", 1.0, shared)
    ];
    assert raw_score(two) == 2.0;
    assert raw_score(two) >= SCORE_THRESHOLD;

    d = decided(two, ["responder_kimi", "responder_antigravity", AGGRESSOR]);
    assert d["quorum_met"] == False;
    assert d["contain"] == False;
    assert d["action_set"] == [];
    assert d["degraded"] == True;
    assert d["responders_voted"] == 2;
    # sorted + unique, per the contract.
    assert d["responders_no_vote"] == ["responder_antigravity", "responder_glm", "responder_kimi"];

    # force_degraded (a MOCKED run) can only ever add degradation, never remove
    # it and never touch `contain`.
    full: list = [];
    for r in RESPONDER_IDS {
        full.append(assessment(r, "malicious", 1.0, shared));
    }
    live = decide(QuorumInput(incident_id=TEST_INCIDENT, assessments=full, decided_at_ms=DECIDED_AT));
    mocked = decide(QuorumInput(incident_id=TEST_INCIDENT, assessments=full, decided_at_ms=DECIDED_AT, force_degraded=True));
    validate_payload("decision.v1", live);
    validate_payload("decision.v1", mocked);
    assert live["degraded"] == False;
    assert mocked["degraded"] == True;
    assert mocked["contain"] == live["contain"];
    assert mocked["score"] == live["score"];
}
