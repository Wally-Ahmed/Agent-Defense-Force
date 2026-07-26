# coordinator/tests/test_effort_gate.jac
#
# Tests for the mandatory boot gate. Run from the coordinator/ directory:
#
#   cd coordinator && jac test tests/test_effort_gate.jac
#
# Every fixture under tests/receipts/ is a real JSONL file in the frozen
# effort_receipt.v1 shape — one receipt object per line, no wrapping array —
# so these tests exercise the same parse path a live runs/<id>/effort.jsonl
# takes. Nothing here mocks the schema validator: the contract is read off disk.

import os;
import json;
import from ids { EFFORT_GATE_AGENTS, REQUIRED_RECEIPTS, RUN_LIVE, RUN_MOCKED, S_WATCHING, S_ESCALATED }
import from events { EventLog, STATE_TRANSITION }
import from clock { frozen_clock }
import from effort_gate { GateResult, parse_receipts, evaluate_receipts, check_gate, enforce_gate }

# Resolved from THIS file, never from cwd.
glob:pub HERE: str = os.path.dirname(os.path.abspath(__file__));
glob:pub RECEIPT_DIR: str = os.path.join(HERE, "receipts");

# The eleven required properties of effort_receipt.v1, transcribed here on
# purpose: the no-bypass test must not lean on the module it is auditing.
glob:pub REQUIRED_FIELDS: list = [
    "agent",
    "runtime",
    "runtime_version",
    "model_requested",
    "model_effective",
    "effort_requested",
    "effort_effective",
    "source",
    "downgraded",
    "blocked",
    "mocked"
];

"""Absolute path of a receipt fixture."""
def fx(name: str) -> str {
    return os.path.join(RECEIPT_DIR, name);
}

"""Independently re-read a fixture WITHOUT using effort_gate.

This is the ground truth the no-bypass test compares the gate against. If the
gate ever opened on a file that does not really hold six clean receipts, this
reader would disagree with it."""
def audit_file(path: str) -> dict {
    handle = open(path, "r");
    raw = handle.read();
    handle.close();

    counts: dict = {};
    lines: int = 0;
    bad: int = 0;
    downgraded: int = 0;

    for line in raw.splitlines() {
        s = line.strip();
        if not s {
            continue;
        }
        lines = (lines + 1);
        row: dict = {};
        parsed_ok: bool = True;
        try {
            row = json.loads(s);
        } except Exception as e {
            parsed_ok = False;
        }
        if (not parsed_ok) or (not isinstance(row, dict)) {
            bad = (bad + 1);
            continue;
        }
        complete: bool = True;
        for k in REQUIRED_FIELDS {
            if k not in row {
                complete = False;
            }
        }
        # additionalProperties:false, so an extra key is just as invalid.
        if (not complete) or (len(row.keys()) != len(REQUIRED_FIELDS)) {
            bad = (bad + 1);
            continue;
        }
        if row["downgraded"] {
            downgraded = (downgraded + 1);
        }
        who = row["agent"];
        if who in EFFORT_GATE_AGENTS {
            counts[who] = (counts.get(who, 0) + 1);
        }
    }

    dupes: int = 0;
    for a in counts.keys() {
        if counts[a] > 1 {
            dupes = (dupes + 1);
        }
    }
    return {
        "lines": lines,
        "bad": bad,
        "downgraded": downgraded,
        "canonical_agents": len(counts.keys()),
        "dupes": dupes
    };
}

# ==========================================================================
# 1. Short of six -> the coordinator stays in WATCHING.
# ==========================================================================

test "effort gate: five receipts -> coordinator refuses to leave WATCHING" {
    log = EventLog();
    clk = frozen_clock();

    res = enforce_gate(fx("five_only.jsonl"), log, "INC-EG-001", clk.now_ms());

    assert res.ok == False;
    assert res.reason == "RECEIPTS_MISSING";
    assert res.receipts_seen == 5;
    assert len(res.agents_seen) == 5;
    assert res.missing == ["responder_kimi"];
    assert "responder_kimi" in res.detail;

    evs = log.of_action(STATE_TRANSITION);
    assert len(evs) == 1;
    assert evs[0]["state_from"] == "WATCHING";
    assert evs[0]["state_to"] == "WATCHING";
    assert evs[0]["detail"]["reason"] == "RECEIPTS_MISSING";
    assert evs[0]["detail"]["ok"] == False;
    assert "ESCALATED" not in log.state_trace();
}

# ==========================================================================
# 2. A single downgraded receipt blocks the whole mesh.
# ==========================================================================

test "effort gate: six receipts with one downgraded:true -> refuses" {
    log = EventLog();
    clk = frozen_clock();

    res = enforce_gate(fx("six_one_downgraded.jsonl"), log, "INC-EG-002", clk.now_ms());

    assert res.ok == False;
    assert res.reason == "RECEIPT_DOWNGRADED";
    # All six DID file — the file is complete. It is the downgrade that blocks.
    assert res.receipts_seen == REQUIRED_RECEIPTS;
    assert res.missing == [];
    assert res.agents_seen == sorted(EFFORT_GATE_AGENTS);
    assert res.downgraded_agents == ["responder_antigravity"];
    assert "responder_antigravity" in res.detail;

    evs = log.of_action(STATE_TRANSITION);
    assert len(evs) == 1;
    assert evs[0]["state_from"] == "WATCHING";
    assert evs[0]["state_to"] == "WATCHING";
    assert evs[0]["detail"]["downgraded_agents"] == ["responder_antigravity"];
}

# ==========================================================================
# 3. Six clean receipts -> the gate opens and the run is LIVE.
# ==========================================================================

test "six clean receipts -> gate opens, run is LIVE" {
    log = EventLog();
    clk = frozen_clock();

    res = enforce_gate(fx("six_clean.jsonl"), log, "INC-EG-003", clk.now_ms());

    assert res.ok == True;
    assert res.reason == "";
    assert res.run_label == "LIVE";
    assert res.run_label == RUN_LIVE;
    assert res.receipts_seen == REQUIRED_RECEIPTS;
    assert res.agents_seen == sorted(EFFORT_GATE_AGENTS);
    assert res.missing == [];
    assert res.unexpected == [];
    assert res.invalid == [];
    assert res.downgraded_agents == [];
    assert res.blocked_agents == [];
    assert res.mocked_agents == [];

    evs = log.of_action(STATE_TRANSITION);
    assert len(evs) == 1;
    assert evs[0]["state_from"] == "WATCHING";
    assert evs[0]["state_to"] == "ESCALATED";
    assert evs[0]["run_label"] == "LIVE";
    assert log.is_mocked() == False;
    assert log.all_labelled() == True;
}

# ==========================================================================
# 4. A mocked receipt labels the WHOLE run — retroactively.
# ==========================================================================

test "a mocked receipt labels the whole run MOCKED" {
    log = EventLog();
    clk = frozen_clock();

    # An event emitted BEFORE the gate runs. At emission time the log believes
    # it is a live run.
    before = log.emit(
        action=STATE_TRANSITION,
        incident_id="INC-EG-004",
        ts_ms=clk.now_ms(),
        detail={"note": "emitted before the effort gate ran"},
        state_from="WATCHING",
        state_to="WATCHING"
    );
    assert before["run_label"] == "LIVE";
    assert log.is_mocked() == False;

    clk.advance(250);
    res = enforce_gate(fx("six_with_mocked.jsonl"), log, "INC-EG-004", clk.now_ms());

    # A mocked run is a VALID run — it just is not an acceptance run.
    assert res.ok == True;
    assert res.reason == "";
    assert res.run_label == "MOCKED";
    assert res.run_label == RUN_MOCKED;
    assert res.mocked_agents == ["responder_kimi"];
    assert res.blocked_agents == [];
    assert res.agents_seen == sorted(EFFORT_GATE_AGENTS);

    # Retroactive labelling: EVERY event in the log now carries MOCKED,
    # including the one emitted before the gate ran.
    assert log.is_mocked() == True;
    assert len(log.events) == 2;
    for e in log.events {
        assert e.run_label == "MOCKED";
    }
    labels = [e["run_label"] for e in log.of_action(STATE_TRANSITION)];
    assert labels == ["MOCKED", "MOCKED"];
    assert log.all_labelled() == True;

    # ...and it survives serialisation, so no artifact this run touches can
    # report it as the live run.
    for row in log.to_jsonl().splitlines() {
        assert json.loads(row)["run_label"] == "MOCKED";
    }

    evs = log.of_action(STATE_TRANSITION);
    assert evs[1]["state_to"] == "ESCALATED";
}

# ==========================================================================
# 5. A blocked receipt labels the run the same way.
# ==========================================================================

test "a blocked receipt also labels the run MOCKED" {
    log = EventLog();
    clk = frozen_clock();

    early = log.emit(
        action=STATE_TRANSITION,
        incident_id="INC-EG-005",
        ts_ms=clk.now_ms(),
        detail={"note": "emitted before the effort gate ran"},
        state_from="WATCHING",
        state_to="WATCHING"
    );
    assert early["run_label"] == "LIVE";

    clk.advance(250);
    res = enforce_gate(fx("six_with_blocked.jsonl"), log, "INC-EG-005", clk.now_ms());

    assert res.ok == True;
    assert res.run_label == "MOCKED";
    assert res.blocked_agents == ["responder_antigravity"];
    assert res.mocked_agents == [];
    assert res.downgraded_agents == [];

    assert log.is_mocked() == True;
    for e in log.events {
        assert e.run_label == "MOCKED";
    }
    evs = log.of_action(STATE_TRANSITION);
    assert evs[1]["state_to"] == "ESCALATED";
    assert evs[1]["detail"]["run_label"] == "MOCKED";
}

# ==========================================================================
# 6. The contract says the receipt is written ONCE, at boot.
# ==========================================================================

test "duplicate receipt for one agent -> refuses" {
    log = EventLog();
    clk = frozen_clock();

    res = enforce_gate(fx("duplicate_agent.jsonl"), log, "INC-EG-006", clk.now_ms());

    assert res.ok == False;
    assert res.reason == "RECEIPT_DUPLICATE";
    # All six agents are present and none is downgraded — the file still fails.
    assert res.receipts_seen == 7;
    assert res.agents_seen == sorted(EFFORT_GATE_AGENTS);
    assert res.missing == [];
    assert res.downgraded_agents == [];
    assert "responder_codex" in res.detail;

    evs = log.of_action(STATE_TRANSITION);
    assert evs[0]["state_to"] == "WATCHING";
}

# ==========================================================================
# 7. Bad lines are reported, never silently dropped.
# ==========================================================================

test "malformed / schema-invalid receipt lines -> refuses, and are reported not silently dropped" {
    log = EventLog();
    clk = frozen_clock();

    res = enforce_gate(fx("malformed.jsonl"), log, "INC-EG-007", clk.now_ms());

    assert res.ok == False;
    assert res.reason == "RECEIPT_INVALID";

    # This is the whole point of the test. The file holds eight lines; six of
    # them are clean receipts covering all six canonical agents with no
    # downgrade. A reader that silently skipped the two bad lines would open the
    # gate. This one refuses, and says exactly which lines it could not read.
    assert res.receipts_seen == 8;
    assert res.agents_seen == sorted(EFFORT_GATE_AGENTS);
    assert res.missing == [];
    assert res.downgraded_agents == [];
    assert len(res.invalid) == 2;

    joined = " | ".join(res.invalid);
    assert "line 3" in joined;        # truncated -> not parseable JSON
    assert "line 6" in joined;        # parses, but violates effort_receipt.v1
    assert "not parseable JSON" in joined;
    assert "effort_receipt.v1" in joined;
    for entry in res.invalid {
        assert entry.startswith("line ");
    }

    # parse_receipts hands the bad lines back too, flagged rather than removed.
    recs = parse_receipts(fx("malformed.jsonl"));
    assert len(recs) == 8;
    flagged = [r["_line"] for r in recs if not r["_ok"]];
    assert flagged == [3];
    for r in recs {
        assert r["_raw"] != "";
    }

    evs = log.of_action(STATE_TRANSITION);
    assert evs[0]["state_to"] == "WATCHING";
    assert evs[0]["detail"]["reason"] == "RECEIPT_INVALID";
    assert evs[0]["detail"]["invalid"] == res.invalid;
    assert evs[0]["detail"]["missing"] == [];
}

# ==========================================================================
# 8. No file at all.
# ==========================================================================

test "missing receipts file -> refuses" {
    log = EventLog();
    clk = frozen_clock();

    absent = fx("no_such_run_effort.jsonl");
    assert os.path.exists(absent) == False;

    res = enforce_gate(absent, log, "INC-EG-008", clk.now_ms());

    assert res.ok == False;
    assert res.reason == "RECEIPTS_FILE_MISSING";
    assert res.receipts_seen == 0;
    assert res.agents_seen == [];
    assert res.missing == sorted(EFFORT_GATE_AGENTS);

    # A directory is not a receipt file either.
    dir_res = check_gate(RECEIPT_DIR);
    assert dir_res.ok == False;
    assert dir_res.reason == "RECEIPTS_FILE_MISSING";

    evs = log.of_action(STATE_TRANSITION);
    assert evs[0]["state_from"] == "WATCHING";
    assert evs[0]["state_to"] == "WATCHING";
}

# ==========================================================================
# 9. There is no way through the gate except six clean receipts.
# ==========================================================================

test "there is no bypass" {
    # (a) nothing at all can never open the gate, and the default is closed.
    empty = evaluate_receipts([]);
    assert empty.ok == False;
    assert empty.reason == "RECEIPTS_MISSING";
    assert empty.missing == sorted(EFFORT_GATE_AGENTS);
    assert GateResult().ok == False;
    assert GateResult().reason == "";

    # (b) EVERY fixture that opens the gate is independently re-read by
    #     audit_file(), which does not use effort_gate at all. If the gate ever
    #     opened on a file that did not really hold six schema-shaped,
    #     non-duplicate, non-downgraded canonical receipts, this disagrees.
    opened: int = 0;
    refused: int = 0;
    for name in sorted(os.listdir(RECEIPT_DIR)) {
        if not name.endswith(".jsonl") {
            continue;
        }
        path = fx(name);
        res = check_gate(path);
        truth = audit_file(path);
        if res.ok {
            opened = (opened + 1);
            assert truth["bad"] == 0;
            assert truth["dupes"] == 0;
            assert truth["downgraded"] == 0;
            assert truth["canonical_agents"] == REQUIRED_RECEIPTS;
            assert res.reason == "";
        } else {
            refused = (refused + 1);
            assert res.reason != "";
            assert res.reason in [
                "RECEIPTS_MISSING",
                "RECEIPT_DOWNGRADED",
                "RECEIPT_INVALID",
                "RECEIPT_DUPLICATE",
                "RECEIPTS_FILE_MISSING"
            ];
        }
    }
    # six_clean, six_with_mocked, six_with_blocked, six_plus_unexpected.
    assert opened == 4;
    # five_only, six_one_downgraded, duplicate_agent, malformed.
    assert refused == 4;

    # (c) no environment variable opens a gate the receipts leave shut.
    os.environ["EFFORT_GATE_BYPASS"] = "1";
    os.environ["SKIP_EFFORT_GATE"] = "true";
    os.environ["COORDINATOR_TEST_MODE"] = "1";
    os.environ["ALLOW_DOWNGRADE"] = "yes";
    try {
        still_short = check_gate(fx("five_only.jsonl"));
        assert still_short.ok == False;
        assert still_short.reason == "RECEIPTS_MISSING";
        still_down = check_gate(fx("six_one_downgraded.jsonl"));
        assert still_down.ok == False;
        assert still_down.reason == "RECEIPT_DOWNGRADED";
    } except Exception as e {
        raise e;
    }
    os.environ.pop("EFFORT_GATE_BYPASS", None);
    os.environ.pop("SKIP_EFFORT_GATE", None);
    os.environ.pop("COORDINATOR_TEST_MODE", None);
    os.environ.pop("ALLOW_DOWNGRADE", None);

    # (d) an extra agent cannot substitute for a missing canonical one.
    extra = check_gate(fx("six_plus_unexpected.jsonl"));
    assert extra.ok == True;
    assert extra.unexpected == ["responder_shadow"];
    assert extra.agents_seen == sorted(EFFORT_GATE_AGENTS);
    assert "responder_shadow" not in extra.agents_seen;
    assert extra.receipts_seen == 7;
}

# ==========================================================================
# 10. The gate is a deterministic function of the file.
# ==========================================================================

test "gate result is deterministic" {
    names = [
        "six_clean.jsonl",
        "five_only.jsonl",
        "six_one_downgraded.jsonl",
        "six_with_mocked.jsonl",
        "six_with_blocked.jsonl",
        "duplicate_agent.jsonl",
        "six_plus_unexpected.jsonl",
        "malformed.jsonl"
    ];
    for name in names {
        first = json.dumps(check_gate(fx(name)).as_dict(), sort_keys=True);
        i: int = 0;
        while i < 5 {
            again = json.dumps(check_gate(fx(name)).as_dict(), sort_keys=True);
            assert again == first;
            i = (i + 1);
        }
        # every list field really is sorted
        snap = check_gate(fx(name)).as_dict();
        for key in ["agents_seen", "missing", "unexpected", "downgraded_agents",
                    "blocked_agents", "mocked_agents", "invalid"] {
            assert snap[key] == sorted(snap[key]);
        }
    }

    # Arrival order does not change the verdict: receipts are appended by six
    # independent processes racing at boot, so the file's line order is not a
    # fact about the run.
    recs = parse_receipts(fx("six_clean.jsonl"));
    rev: list = [];
    j: int = (len(recs) - 1);
    while j >= 0 {
        rev.append(recs[j]);
        j = (j - 1);
    }
    forward = evaluate_receipts(recs).as_dict();
    backward = evaluate_receipts(rev).as_dict();
    assert json.dumps(forward, sort_keys=True) == json.dumps(backward, sort_keys=True);

    # A missing file is deterministic too.
    absent = fx("no_such_run_effort.jsonl");
    assert json.dumps(check_gate(absent).as_dict(), sort_keys=True) == json.dumps(check_gate(absent).as_dict(), sort_keys=True);
}

# ==========================================================================
# 11. evaluate_receipts is pure and also accepts bare receipt dicts.
# ==========================================================================

test "evaluate_receipts is pure and accepts bare receipt objects" {
    recs = parse_receipts(fx("six_clean.jsonl"));
    bare: list = [r["receipt"] for r in recs];

    from_records = evaluate_receipts(recs).as_dict();
    from_bare = evaluate_receipts(bare).as_dict();
    assert json.dumps(from_records, sort_keys=True) == json.dumps(from_bare, sort_keys=True);
    assert from_bare["ok"] == True;

    # Calling it twice on the same input does not mutate the input.
    once = json.dumps(evaluate_receipts(bare).as_dict(), sort_keys=True);
    twice = json.dumps(evaluate_receipts(bare).as_dict(), sort_keys=True);
    assert once == twice;
    assert len(bare) == REQUIRED_RECEIPTS;

    # A bare receipt that is not schema-valid is still caught.
    broken: list = [{"agent": "monitor", "downgraded": False}];
    res = evaluate_receipts(broken);
    assert res.ok == False;
    assert res.reason == "RECEIPT_INVALID";
    assert len(res.invalid) == 1;
}
