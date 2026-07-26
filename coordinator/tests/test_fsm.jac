# coordinator/tests/test_fsm.jac
#
# END-TO-END integration test of the coordinator state machine. Every scenario
# is driven through the FULL FSM via run_incident() on the all-mock mesh — never
# by calling quorum.decide directly — and every emitted decision is re-validated
# against the frozen decision.v1 contract.
#
#   cd coordinator && ~/.local/bin/jac test tests/test_fsm.jac
#
# The clock is frozen at 1769472000000 (T0). The ASSESSING window is 180000ms,
# so the 180s deadline is T0+180000 = 1769472180000. Scenario 5 proves presence
# short-circuits that window by deciding AT T0.

import os;
import json;
import from typing { Any }
import from ids { is_revocation, RESPONDER_IDS }
import from clock { frozen_clock }
import from config { mock_config_with }
import from schema_check { validate_payload }
import from mocks.mock_containment { MockContainment }
import from fsm { Incident, CoordinatorFSM, build_fsm, run_incident }
import from tests.incidents {
    incident_payload, fallback_target,
    ov_all_malicious, ov_three_malicious_high, ov_three_malicious_low,
    ov_split_221, ov_two_dead, ov_three_dead, ov_late_responder,
    ov_aggressive_solo, ov_ttl_blast_cap
}

glob:pub TESTS_DIR: str = os.path.dirname(os.path.abspath(__file__));
glob:pub RECEIPTS_DIR: str = os.path.join(TESTS_DIR, "receipts");

glob:pub T0: int = 1769472000000;
glob:pub DEADLINE: int = 1769472180000;   # T0 + 180000ms ASSESSING window


"""Build a coordinator around a receipts file + mesh overrides + executor, drive
one incident all the way through, and hand back the settled FSM."""
def run_scenario(receipts_name: str, overrides: dict, executor: Any) -> CoordinatorFSM {
    receipts = os.path.join(RECEIPTS_DIR, receipts_name);
    clock = frozen_clock();
    cfg = mock_config_with(overrides);
    fsm = build_fsm(receipts, cfg, executor, clock, fallback_target());
    incident = Incident(
        incident_id="INC-TEST-0001",
        payload=incident_payload("INC-TEST-0001")
    );
    run_incident(fsm, incident);
    return fsm;
}

"""Number of times `val` appears in `seq`."""
def count_of(seq: list, val: str) -> int {
    return len([x for x in seq if x == val]);
}


# ==========================================================================
# 1. all five agree malicious -> contain
# ==========================================================================
test "all five agree malicious -> contain" {
    fsm = run_scenario("six_with_mocked.jsonl", ov_all_malicious(), MockContainment());
    validate_payload("decision.v1", fsm.decision);

    assert fsm.decision["contain"] == True;
    assert len(fsm.decision["action_set"]) > 0;
    assert fsm.decision["verdict_counts"]["malicious"] == 5;

    trace = fsm.log.state_trace();
    for s in ["ASSESSING", "DECIDING", "CONTAINING", "VERIFYING"] {
        assert s in trace;
    }
    assert "CONTAINED" in trace;
    assert fsm.state == "CONTAINED";
}


# ==========================================================================
# 2. exactly 3/5 malicious with score >= 1.5 -> contain
# ==========================================================================
test "exactly 3 of 5 malicious with score at least 1.5 contains" {
    fsm = run_scenario("six_with_mocked.jsonl", ov_three_malicious_high(), MockContainment());
    validate_payload("decision.v1", fsm.decision);

    assert fsm.decision["verdict_counts"]["malicious"] == 3;
    assert fsm.decision["score"] >= 1.5;
    assert fsm.decision["contain"] == True;
    assert len(fsm.decision["action_set"]) > 0;
}


# ==========================================================================
# 3. 3/5 malicious but score < 1.5 -> NO contain (proves the score gate)
# ==========================================================================
test "three of five malicious but score below 1.5 does not contain" {
    fsm = run_scenario("six_with_mocked.jsonl", ov_three_malicious_low(), MockContainment());
    validate_payload("decision.v1", fsm.decision);

    # the majority IS present — this is the score gate firing, not the majority
    assert fsm.decision["verdict_counts"]["malicious"] == 3;
    assert fsm.decision["score"] < 1.5;
    assert fsm.decision["contain"] == False;
    assert fsm.decision["action_set"] == [];
    assert "CONTAINING" not in fsm.log.state_trace();
    assert fsm.state == "WATCHING";
}


# ==========================================================================
# 4. 2-2-1 split -> one bounded deliberation round -> decide
# ==========================================================================
test "a 2-2-1 split runs exactly one deliberation round then decides" {
    fsm = run_scenario("six_with_mocked.jsonl", ov_split_221(), MockContainment());
    validate_payload("decision.v1", fsm.decision);

    trace = fsm.log.state_trace();
    assert count_of(trace, "DELIBERATING") == 1;   # exactly one bounded round
    assert "DECIDING" in trace;

    # DELIBERATING must precede DECIDING
    saw_delib = False;
    delib_then_deciding = False;
    for s in trace {
        if s == "DELIBERATING" { saw_delib = True; }
        if (s == "DECIDING") and saw_delib { delib_then_deciding = True; }
    }
    assert delib_then_deciding;

    # a decision was emitted (a still-split vote is a valid no-contain decision)
    assert "contain" in fsm.decision;
    assert fsm.decision["quorum_met"] == True;
}


# ==========================================================================
# 5. two responders dead -> still decides on three (presence short-circuit)
# ==========================================================================
test "two dead responders still decide on three via presence" {
    fsm = run_scenario("six_with_mocked.jsonl", ov_two_dead(), MockContainment());
    validate_payload("decision.v1", fsm.decision);

    assert fsm.decision["responders_voted"] == 3;
    assert fsm.decision["quorum_met"] == True;
    assert fsm.decision["degraded"] == True;

    nv = fsm.decision["responders_no_vote"];
    assert "responder_antigravity" in nv;
    assert "responder_glm" in nv;

    # THE PROOF: the dead two resolved via presence at T0, NOT at the 180s
    # timeout — the decision closed at T0, far before the deadline.
    assert fsm.decided_at_ms == T0;
    assert fsm.decided_at_ms != DEADLINE;
}


# ==========================================================================
# 6. three responders dead -> DEGRADED -> monitor-only, ZERO revocation
# ==========================================================================
test "three dead responders degrade to monitor-only with zero revocation" {
    executor = MockContainment();
    fsm = run_scenario("six_with_mocked.jsonl", ov_three_dead(), executor);
    validate_payload("decision.v1", fsm.decision);

    assert fsm.state == "DEGRADED";
    assert fsm.decision["contain"] == False;
    assert fsm.decision["quorum_met"] == False;

    # the posture is raise_logging-only, provably revocation-free
    assert len(fsm.posture) > 0;
    for pe in fsm.posture {
        assert pe["action"] == "raise_logging";
        assert not is_revocation(pe["action"]);
    }

    # a missed quorum shut NOTHING down — nothing reached the executor at all
    assert len(executor.applied) == 0;
    assert executor.zero_revocation_applied() == True;
}


# ==========================================================================
# 7. one late responder -> logged late, decision byte-identical
# ==========================================================================
test "a late responder is logged late and never changes the decision" {
    # A: glm's assessment is ready long after the vote closes but within the
    #    post-decision sweep. B: glm never surfaces at all. Both decide on the 4.
    fsm_a = run_scenario("six_with_mocked.jsonl", ov_late_responder(200000), MockContainment());
    fsm_b = run_scenario("six_with_mocked.jsonl", ov_late_responder(999999999), MockContainment());
    validate_payload("decision.v1", fsm_a.decision);
    validate_payload("decision.v1", fsm_b.decision);

    assert fsm_a.decision["responders_voted"] == 4;
    assert "responder_glm" in fsm_a.decision["responders_no_vote"];

    # the late one is captured, flagged late, and did NOT reopen the incident
    assert len(fsm_a.late_arrivals) == 1;
    assert fsm_a.late_arrivals[0]["late"] == True;
    assert fsm_a.late_arrivals[0]["responder"] == "responder_glm";

    # byte-identical decision with vs without the late arrival
    assert json.dumps(fsm_a.decision, sort_keys=True) == json.dumps(fsm_b.decision, sort_keys=True);
    assert len(fsm_b.late_arrivals) == 0;
}


# ==========================================================================
# 8. one aggressive responder's solo actions are excluded (>=2-proposer rule)
# ==========================================================================
test "an aggressive responder's solo actions are excluded from the set" {
    fsm = run_scenario("six_with_mocked.jsonl", ov_aggressive_solo(), MockContainment());
    validate_payload("decision.v1", fsm.decision);

    assert fsm.decision["contain"] == True;

    kinds = [a["action"] for a in fsm.decision["action_set"]];
    assert "revoke_session" in kinds;          # the 3-way agreed action survives
    assert "suspend_principal" not in kinds;   # solo broad/long actions dropped
    assert "block_source" not in kinds;
    assert "pause_queue" not in kinds;

    assert len(fsm.decision["action_set"]) == 1;
    only_action = fsm.decision["action_set"][0];
    assert len(only_action["proposed_by"]) == 4;   # claude, codex, kimi + the aggressor
}


# ==========================================================================
# 9. min-ttl and narrowest-blast cap across agreeing responders
# ==========================================================================
test "the surviving action carries the min ttl and narrowest blast" {
    executor = MockContainment();
    fsm = run_scenario("six_with_mocked.jsonl", ov_ttl_blast_cap(), executor);
    validate_payload("decision.v1", fsm.decision);

    assert fsm.decision["contain"] == True;
    assert len(fsm.decision["action_set"]) == 1;

    a = fsm.decision["action_set"][0];
    assert a["action"] == "revoke_session";
    assert a["ttl_s"] == 900;               # MIN of 3600 / 1800 / 900
    assert a["blast_radius"] == "narrow";   # NARROWEST of moderate / narrow / broad
    assert a["proposed_by"] == ["responder_claude", "responder_codex", "responder_kimi"];

    # the action actually dispatched to the executor carries the same caps
    assert len(executor.applied) == 1;
    assert executor.applied[0]["ttl_s"] == 900;
    assert executor.applied[0]["blast_radius"] == "narrow";
}


# ==========================================================================
# 10. effort gate blocks: five receipts refuses; six-with-one-downgraded refuses
# ==========================================================================
test "the effort gate refuses five receipts and a downgraded sixth" {
    # five receipts -> RECEIPTS_MISSING, never leaves WATCHING
    fsm5 = run_scenario("five_only.jsonl", {}, MockContainment());
    assert fsm5.state == "WATCHING";
    assert fsm5.gate_ok == False;
    assert fsm5.gate_reason == "RECEIPTS_MISSING";
    assert fsm5.decision == {};
    assert "ESCALATED" not in fsm5.log.state_trace();
    # nothing was escalated to any responder
    for rid in RESPONDER_IDS {
        assert fsm5.mesh[rid].escalated_at_ms == -1;
    }

    # six receipts but one downgraded -> RECEIPT_DOWNGRADED, same refusal
    fsm6 = run_scenario("six_one_downgraded.jsonl", {}, MockContainment());
    assert fsm6.state == "WATCHING";
    assert fsm6.gate_ok == False;
    assert fsm6.gate_reason == "RECEIPT_DOWNGRADED";
    assert fsm6.decision == {};
    assert "ESCALATED" not in fsm6.log.state_trace();
    for rid in RESPONDER_IDS {
        assert fsm6.mesh[rid].escalated_at_ms == -1;
    }
}


# ==========================================================================
# 11. determinism: scenario 1's decision is byte-identical across runs
# ==========================================================================
test "scenario one is byte-identical decision across two runs" {
    fsm1 = run_scenario("six_with_mocked.jsonl", ov_all_malicious(), MockContainment());
    fsm2 = run_scenario("six_with_mocked.jsonl", ov_all_malicious(), MockContainment());

    assert json.dumps(fsm1.decision, sort_keys=True) == json.dumps(fsm2.decision, sort_keys=True);
    assert fsm1.state == fsm2.state;
    assert fsm1.decided_at_ms == fsm2.decided_at_ms;
}


# ==========================================================================
# 12. CONTAINING NAK path: transient recovers, permanent aborts, others survive
# ==========================================================================
test "a permanent NAK aborts one action while the others still apply" {
    # block_source NAKs once then ACKs (transient, recovered by the one redeliver);
    # feature_readonly NAKs forever (aborted after redeliver).
    executor = MockContainment(nak_actions=["block_source"], nak_forever=["feature_readonly"]);
    fsm = run_scenario("six_with_mocked.jsonl", ov_all_malicious(), executor);
    validate_payload("decision.v1", fsm.decision);

    assert fsm.decision["contain"] == True;

    applied = executor.applied_kinds();
    assert "feature_readonly" not in applied;   # aborted after the redeliver
    assert "block_source" in applied;           # transient failure recovered
    assert "revoke_session" in applied;         # untouched actions survived
    assert "raise_logging" in applied;

    # feature_readonly was proposed but never applied
    proposed = [a["action"] for a in fsm.decision["action_set"]];
    assert "feature_readonly" in proposed;

    assert fsm.state in ["CONTAINED", "ROLLED_BACK"];
}


# ==========================================================================
# 13. CONTAINED -> ttl expiry -> auto ROLLBACK
#
# The last row of the state table: containment is NEVER permanent. Every action
# carries a ttl_s, and at the MINIMUM applied ttl the coordinator auto-expires
# the whole containment, rolls every applied action back, and emits the frozen
# `containment.expire` audit action. Without this test the expire arrow is code
# nobody ever executes.
# ==========================================================================
test "CONTAINED auto-expires at the minimum ttl and rolls back" {
    executor = MockContainment();
    fsm = run_scenario("six_with_mocked.jsonl", ov_all_malicious(), executor);

    # Precondition: we actually reached the holding state with work applied.
    assert fsm.state == "CONTAINED";
    assert fsm.decision["contain"] == True;
    applied_before = executor.applied_kinds();
    assert len(applied_before) > 0;

    # The hold is bounded by the SHORTEST surviving ttl — containment expires as
    # early as any responder was willing to accept.
    ttls = [int(a["ttl_s"]) for a in fsm.decision["action_set"]];
    assert fsm.min_ttl_s == min(ttls);
    assert fsm.min_ttl_s >= 1;

    held_at = fsm.clock.now_ms();
    fsm.tick_expire(Incident(
        incident_id="INC-TEST-0001",
        payload=incident_payload("INC-TEST-0001")
    ));

    # Landed in ROLLED_BACK, exactly ttl seconds later.
    assert fsm.state == "ROLLED_BACK";
    assert fsm.clock.now_ms() == (held_at + (fsm.min_ttl_s * 1000));

    # Every applied action was rolled back — nothing is left in force.
    assert len(executor.rolled_back) == len(fsm.applied_actions);

    # The frozen audit action was emitted, on the right arrow, and labelled.
    expires = fsm.log.of_action("containment.expire");
    assert len(expires) == 1;
    assert expires[0]["state_from"] == "CONTAINED";
    assert expires[0]["state_to"] == "ROLLED_BACK";
    assert expires[0]["run_label"] == "MOCKED";
    assert "ROLLED_BACK" in fsm.log.state_trace();
}
