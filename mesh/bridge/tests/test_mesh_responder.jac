# mesh/bridge/tests/test_mesh_responder.jac
#
# Tests for the live bridge: the Jac layer that lets the deterministic
# coordinator consume REAL assessments off disk instead of recorded mocks.
#
# Run from the bridge directory (Jac resolves imports against the invocation
# cwd, not the file — docs/running-tests.md):
#
#   cd mesh/bridge && jac test tests/test_mesh_responder.jac
#
# What these assert, in one line each:
#   - importing the bridge registers kind "cotal" — that IS the whole wiring
#     step, and coordinator/ is not touched to get it;
#   - escalate() refuses an incident with no id, and a DEAD responder still
#     ACCEPTS one (durable channel: acceptance is not an answer);
#   - poll() is at-MOST-once: the same assessment is never handed up twice;
#   - an assessment for the wrong incident, the wrong responder, the wrong
#     schema or no valid JSON at all is REPORTED, never silently dropped;
#   - presence() is honest — it never reports `working` for a process that has
#     exited without answering, which is the upstream dark-agent bug;
#   - the swap is config-only: cotal_config() builds a five-responder mesh the
#     coordinator's own validate()/build_mesh() accept unchanged, a mixed run is
#     correctly forced to MOCKED, and today's all-live split labels LIVE.
#
# NOTE ON THE MIXED CONFIGS BELOW. TODAY_LIVE now holds all five responders and
# TODAY_BLOCKED is empty — every harness answers live (mesh_config.jac carries
# the correction). The MOCKED-propagation tests therefore write their live/mocked
# split out explicitly instead of reading it off TODAY_BLOCKED, because what they
# test is what a recording DOES to a run, not which agent happens to be blocked
# on any given day.
#
# SAFETY, and it is not optional. NO TEST IN THIS FILE MAY LAUNCH A HARNESS.
# mesh/agent_runner/bin/agent-runner.js drives a REAL model, so a unit test that
# escalates with spawn=True spends real tokens and takes real minutes. Every
# test here therefore either leaves `spawn` false, or points `runner_path` at a
# path that provably does not exist; the presence branches that depend on a live
# process are exercised with the ExitedProc / RunningProc stand-ins below.
#
# Every artifact these tests touch is written under a per-test temp directory
# (MeshResponder.bridge_dir() follows `assessments_dir`). Nothing here reads or
# writes the real runs/ tree, and nothing here holds a credential.

import os;
import json;
import shutil;
import tempfile;
import from typing { Any }
import from jsonschema { Draft202012Validator }

import from mesh_responder {
    MeshResponder,
    mesh_responder_from_opts,
    cotal_factory,
    assessment_errors,
    COTAL_KIND,
    RUNNER_JS,
    SCHEMA_PATH,
    R_INVALID_JSON,
    R_SCHEMA_INVALID,
    R_INCIDENT_MISMATCH,
    R_RESPONDER_MISMATCH,
    R_NOT_ESCALATED,
    R_UNSOLICITED_DUPLICATE
}
import from mesh_config {
    cotal_config,
    todays_config,
    all_live_config,
    block_report,
    TODAY_LIVE,
    TODAY_BLOCKED,
    BLOCK_REASONS
}
import from ids { RESPONDER_IDS, DELIBERATION_ROUNDS_MAX, PRESENCE_STATUSES, RUN_MOCKED, RUN_LIVE }
import from presence { PresenceCard, PresenceStore }
import from responder {
    ResponderHandle,
    is_known_kind,
    known_responder_kinds,
    build_responder
}
import from config { MeshConfig, ResponderConfig, build_mesh }

# --------------------------------------------------------------------------
# Fixtures
# --------------------------------------------------------------------------

"""A fresh temp directory that stands in for runs/<run_id>/assessments/."""
def temp_inbox -> str {
    return tempfile.mkdtemp(prefix="mesh-bridge-test-");
}

"""A schema-valid assessment.v1 for `responder` answering `incident_id`.

Built here rather than copied from a recording so these tests own their inputs.
Its validity against the FROZEN contract is asserted by a test below — if this
fixture ever drifted out of the schema, the at-most-once tests would be
measuring nothing."""
def valid_assessment(
    responder: str,
    incident_id: str,
    verdict: str = "malicious",
    rationale: str = "session reuse from a new ASN followed by a bulk export"
) -> dict {
    return {
        "incident_id": incident_id,
        "responder": responder,
        "model": "anthropic/claude-opus-5",
        "effort_requested": "max",
        "effort_effective": "max",
        "verdict": verdict,
        "confidence": 0.91,
        "campaign_stages": [1, 2, 3],
        "recommended_actions": [
            {
                "action": "revoke_session",
                "target": {"session_ids": ["sess_a1", "sess_b2"]},
                "ttl_s": 900,
                "blast_radius": "narrow"
            }
        ],
        "skills_used": [
            {"path": "skills/credential-stuffing.md", "sha": "b7d1c0a4"}
        ],
        "rationale": rationale,
        "usage": {"in": 8123, "out": 640, "reasoning": 2048, "usd": 0.184}
    };
}

"""The incident the responder seam actually reads."""
def sample_incident(incident_id: str = "inc-bridge-0001") -> dict {
    return {
        "incident_id": incident_id,
        "schema_version": "incident.v1",
        "detected_at_ms": 1769472000000,
        "join_keys": {"principal_hash": "ph_9f2c41ab7d0e5613", "tenant": "tenant_northwind"},
        "stage_signatures": [1, 2, 3, 4],
        "summary": "credential stuffing -> session hijack -> bulk export"
    };
}

"""Write `payload` where MeshResponder expects `agent`'s unicast DM to land."""
def write_inbox(inbox: str, agent: str, payload: Any) -> str {
    p = os.path.join(inbox, f"{agent}.json");
    with open(p, "w") as fh {
        if isinstance(payload, str) {
            fh.write(payload);
        } else {
            json.dump(payload, fh, sort_keys=True);
        }
    }
    return p;
}

"""A runner entry point that provably does not exist.

Every test that sets spawn=True uses this, so no test can ever start a real
harness however the repo's build state changes underneath it."""
def absent_runner(inbox: str) -> str {
    return os.path.join(inbox, "no-such-agent-runner.js");
}

"""A MeshResponder wired to `inbox`.

`spawn` stays false unless a test opts in, and even then `runner_path` is
forced to a nonexistent file — see the safety note at the top of this file."""
def bridge_for(agent: str, inbox: str, extra: dict = {}) -> MeshResponder {
    opts: dict = {"run_id": "test-run", "assessments_dir": inbox};
    for k in extra.keys() {
        opts[k] = extra[k];
    }
    if bool(opts.get("spawn", False)) and "runner_path" not in opts {
        opts["runner_path"] = absent_runner(inbox);
    }
    return mesh_responder_from_opts(agent, opts);
}

"""A stand-in for subprocess.Popen that reports a process which has EXITED.

Lets the honest-presence branch be tested without launching a real harness:
`poll()` returning a code is exactly what Popen.poll() does once the child is
gone."""
obj ExitedProc {
    has code: int = 0;
    def poll -> Any {
        return self.code;
    }
}

"""A stand-in for a process that is still running (Popen.poll() -> None)."""
obj RunningProc {
    def poll -> Any {
        return None;
    }
}

# ==========================================================================
# 1. Registration — the seam, with zero coordinator edits
# ==========================================================================

test "importing the bridge registers kind cotal in the coordinator registry" {
    # This is the ENTIRE wiring step. coordinator/responder.jac:151-155 exposes
    # register_responder_kind as the sanctioned extension point; nothing under
    # coordinator/ knows this module exists.
    assert is_known_kind(COTAL_KIND);
    assert COTAL_KIND in known_responder_kinds();
    # The kinds the coordinator already shipped are untouched.
    assert is_known_kind("mock");
    assert is_known_kind("live");
}

test "build_responder('cotal', ...) returns a plain ResponderHandle" {
    # The coordinator is not allowed to see past ResponderHandle. If this
    # narrowed, the seam would have leaked.
    h: Any = build_responder(COTAL_KIND, "responder_claude", {"run_id": "r1"});
    assert isinstance(h, ResponderHandle);
    assert isinstance(h, MeshResponder);
    assert h.responder_id == "responder_claude";
    assert h.kind == COTAL_KIND;
    assert h.is_canonical();
}

test "a cotal responder refuses to be built without a run to read" {
    raised = False;
    try {
        cotal_factory("responder_claude", {});
    } except ValueError as e {
        raised = True;
    }
    assert raised;
}

# ==========================================================================
# 2. The fixture is real — otherwise every test below measures nothing
# ==========================================================================

test "the test fixture is a schema-valid assessment.v1 against the frozen contract" {
    assert os.path.exists(SCHEMA_PATH);
    for rid in RESPONDER_IDS {
        a = valid_assessment(rid, "inc-fixture");
        assert assessment_errors(a) == [], f"{rid}: {assessment_errors(a)}";
        assert len(a["rationale"]) <= 400;
    }
}

# ==========================================================================
# 3. escalate — durable channel semantics
# ==========================================================================

test "escalate raises on an incident with no incident_id" {
    inbox = temp_inbox();
    r = bridge_for("responder_claude", inbox);
    raised = False;
    try {
        r.escalate({"summary": "no id here"}, 1000);
    } except ValueError as e {
        raised = True;
    }
    assert raised;
    # An empty-string id is just as invalid as a missing key.
    raised2 = False;
    try {
        r.escalate({"incident_id": ""}, 1000);
    } except ValueError as e {
        raised2 = True;
    }
    assert raised2;
    shutil.rmtree(inbox, ignore_errors=True);
}

test "a DEAD responder still ACCEPTS an escalation — acceptance is not an answer" {
    # The durable-channel backstop: a responder dead at delivery time must not
    # silently lose the incident, or a restart during ESCALATED drops a vote.
    inbox = temp_inbox();
    r = bridge_for("responder_codex", inbox);
    r.kill(500);
    assert not r.is_alive();
    r.escalate(sample_incident("inc-durable"), 1000);
    assert r.incident_id == "inc-durable";
    assert r.escalated_at_ms == 1000;
    # ...and it answers after reconnecting, because acceptance was recorded.
    write_inbox(inbox, "responder_codex", valid_assessment("responder_codex", "inc-durable"));
    assert r.poll(1500) == [];          # still dead: no answer
    r.revive(2000);
    got: Any = r.poll(2500);
    assert len(got) == 1;
    assert got[0]["incident_id"] == "inc-durable";
    shutil.rmtree(inbox, ignore_errors=True);
}

# ==========================================================================
# 4. poll — AT MOST ONCE. The hard requirement.
# ==========================================================================

test "poll returns each assessment EXACTLY ONCE and never again" {
    inbox = temp_inbox();
    r = bridge_for("responder_claude", inbox);
    r.escalate(sample_incident("inc-once"), 1000);
    write_inbox(inbox, "responder_claude", valid_assessment("responder_claude", "inc-once"));

    first: Any = r.poll(2000);
    assert len(first) == 1;
    assert first[0]["responder"] == "responder_claude";
    assert first[0]["incident_id"] == "inc-once";

    # The file is STILL on disk — at-least-once on the wire. The bridge must
    # not hand it up again, or the coordinator double-counts the verdict.
    assert os.path.exists(os.path.join(inbox, "responder_claude.json"));
    assert r.poll(2001) == [];
    assert r.poll(3000) == [];
    assert r.poll(999999) == [];
    shutil.rmtree(inbox, ignore_errors=True);
}

test "a byte-identical redelivery is recognised as the same DM, not a second vote" {
    inbox = temp_inbox();
    r = bridge_for("responder_glm", inbox);
    r.escalate(sample_incident("inc-redeliver"), 0);
    payload = valid_assessment("responder_glm", "inc-redeliver");
    write_inbox(inbox, "responder_glm", payload);
    assert len(r.poll(10)) == 1;
    # The at-least-once transport writes the very same payload again.
    write_inbox(inbox, "responder_glm", payload);
    assert r.poll(20) == [];
    assert len(r.rejected) == 0;   # a redelivery is not an error, just a no-op
    shutil.rmtree(inbox, ignore_errors=True);
}

test "poll returns nothing before the assessment file exists" {
    inbox = temp_inbox();
    r = bridge_for("responder_kimi", inbox);
    r.escalate(sample_incident("inc-pending"), 0);
    assert r.poll(0) == [];
    assert r.poll(180000) == [];
    assert len(r.rejected) == 0;
    shutil.rmtree(inbox, ignore_errors=True);
}

test "a second DIFFERENT assessment with no deliberation round open is refused" {
    # assessment.v1: exactly one assessment per responder per incident. A second
    # one nobody asked for is not a vote.
    inbox = temp_inbox();
    r = bridge_for("responder_claude", inbox);
    r.escalate(sample_incident("inc-dup"), 0);
    write_inbox(inbox, "responder_claude", valid_assessment("responder_claude", "inc-dup"));
    assert len(r.poll(10)) == 1;
    write_inbox(
        inbox,
        "responder_claude",
        valid_assessment("responder_claude", "inc-dup", "benign", "changed my mind")
    );
    assert r.poll(20) == [];
    assert len(r.rejected) == 1;
    assert r.rejected[0]["reason"] == R_UNSOLICITED_DUPLICATE;
    shutil.rmtree(inbox, ignore_errors=True);
}

test "the one bounded deliberation round admits exactly one revised assessment" {
    inbox = temp_inbox();
    r = bridge_for("responder_claude", inbox);
    r.escalate(sample_incident("inc-delib"), 0);
    write_inbox(inbox, "responder_claude", valid_assessment("responder_claude", "inc-delib"));
    assert len(r.poll(10)) == 1;

    r.open_deliberation("inc-delib", 1, 20);
    write_inbox(
        inbox,
        "responder_claude",
        valid_assessment("responder_claude", "inc-delib", "suspicious", "revised after round 1")
    );
    revised: Any = r.poll(30);
    assert len(revised) == 1;
    assert revised[0]["verdict"] == "suspicious";
    # And the revision, too, is delivered at most once.
    assert r.poll(40) == [];
    shutil.rmtree(inbox, ignore_errors=True);
}

# ==========================================================================
# 5. Nothing is silently dropped — a dropped assessment is a LOST VOTE
# ==========================================================================

test "an assessment for a DIFFERENT incident is not returned, and is reported" {
    inbox = temp_inbox();
    r = bridge_for("responder_codex", inbox);
    r.escalate(sample_incident("inc-current"), 1000);
    # A stale answer to last week's incident, left in the run directory.
    write_inbox(inbox, "responder_codex", valid_assessment("responder_codex", "inc-OLD"));
    assert r.poll(2000) == [];
    assert len(r.rejected) == 1;
    assert r.rejected[0]["reason"] == R_INCIDENT_MISMATCH;
    assert "inc-OLD" in r.rejected[0]["detail"];
    assert r.describe()["rejections"] == 1;
    assert not r.answered;
    shutil.rmtree(inbox, ignore_errors=True);
}

test "a schema-INVALID assessment is REPORTED, never silently dropped" {
    inbox = temp_inbox();
    r = bridge_for("responder_glm", inbox);
    r.escalate(sample_incident("inc-bad-schema"), 0);
    bad = valid_assessment("responder_glm", "inc-bad-schema");
    bad["verdict"] = "definitely_bad";     # outside the frozen enum
    del bad["usage"];                      # and a required field is gone
    write_inbox(inbox, "responder_glm", bad);

    assert r.poll(10) == [];
    assert len(r.rejected) == 1;
    assert r.rejected[0]["reason"] == R_SCHEMA_INVALID;
    assert r.rejected[0]["detail"] != "";           # the violations, not a shrug
    assert r.describe()["rejection_reasons"][R_SCHEMA_INVALID] == 1;
    shutil.rmtree(inbox, ignore_errors=True);
}

test "an assessment that is not valid JSON at all is REPORTED, never dropped" {
    inbox = temp_inbox();
    r = bridge_for("responder_kimi", inbox);
    r.escalate(sample_incident("inc-bad-json"), 0);
    write_inbox(inbox, "responder_kimi", "{not json at all,,,");
    assert r.poll(10) == [];
    assert len(r.rejected) == 1;
    assert r.rejected[0]["reason"] == R_INVALID_JSON;
    shutil.rmtree(inbox, ignore_errors=True);
}

test "an assessment signed by the wrong responder is refused and reported" {
    inbox = temp_inbox();
    r = bridge_for("responder_glm", inbox);
    r.escalate(sample_incident("inc-wrong-signer"), 0);
    # Independence is an ACL property; a file claiming another responder's id in
    # this responder's inbox is not that responder's vote.
    write_inbox(inbox, "responder_glm", valid_assessment("responder_claude", "inc-wrong-signer"));
    assert r.poll(10) == [];
    assert len(r.rejected) == 1;
    assert r.rejected[0]["reason"] == R_RESPONDER_MISMATCH;
    shutil.rmtree(inbox, ignore_errors=True);
}

test "an assessment arriving before any escalation is refused and reported" {
    inbox = temp_inbox();
    r = bridge_for("responder_codex", inbox);
    write_inbox(inbox, "responder_codex", valid_assessment("responder_codex", "inc-unasked"));
    assert r.poll(10) == [];
    assert len(r.rejected) == 1;
    assert r.rejected[0]["reason"] == R_NOT_ESCALATED;
    shutil.rmtree(inbox, ignore_errors=True);
}

test "a rejected assessment is refused once, not re-reported on every poll" {
    # Reporting must be a record, not a stuck alarm that grows without bound.
    inbox = temp_inbox();
    r = bridge_for("responder_kimi", inbox);
    r.escalate(sample_incident("inc-noise"), 0);
    write_inbox(inbox, "responder_kimi", "{broken");
    assert r.poll(10) == [];
    assert r.poll(20) == [];
    assert r.poll(30) == [];
    assert len(r.rejected) == 1;
    shutil.rmtree(inbox, ignore_errors=True);
}

# ==========================================================================
# 6. presence — honest, and never `working` forever
# ==========================================================================

test "presence returns exactly the PresenceCard.as_dict() key set, in order" {
    inbox = temp_inbox();
    r = bridge_for("responder_claude", inbox);
    card: Any = r.presence(1000);
    expected = PresenceCard(agent="responder_claude", status="idle", heartbeat_ms=1000, seq=1);
    assert list(card.keys()) == list(expected.as_dict().keys());
    assert card["agent"] == "responder_claude";
    assert card["status"] in PRESENCE_STATUSES;
    assert isinstance(card["heartbeat_ms"], int);
    assert isinstance(card["seq"], int);
    # It is a real card as far as the coordinator's presence store is concerned.
    store = PresenceStore();
    store.put(PresenceCard(
        agent=card["agent"],
        status=card["status"],
        heartbeat_ms=card["heartbeat_ms"],
        seq=card["seq"]
    ));
    assert store.is_live("responder_claude", 1000);
    shutil.rmtree(inbox, ignore_errors=True);
}

test "presence reports working while a spawned harness is genuinely running" {
    inbox = temp_inbox();
    r = bridge_for("responder_claude", inbox);
    r.escalate(sample_incident("inc-working"), 1000);
    # Adopt a running process AFTER escalate, so this test exercises the
    # presence branch without ever starting a real harness.
    r.spawn = True;
    r.proc = RunningProc();
    assert r.presence(2000)["status"] == "working";
    shutil.rmtree(inbox, ignore_errors=True);
}

test "presence NEVER reports working for a process that EXITED without answering" {
    # This is the upstream "dead agents go dark" bug, and the reason the bridge
    # derives status from observable state instead of asserting it.
    inbox = temp_inbox();
    r = bridge_for("responder_antigravity", inbox);
    r.escalate(sample_incident("inc-dark"), 1000);
    r.spawn = True;
    r.proc = ExitedProc(code=1);          # harness crashed, nothing on disk
    card: Any = r.presence(2000);
    assert card["status"] == "offline";
    # And the coordinator's own liveness check agrees, so the slot resolves to
    # NO_VOTE immediately instead of burning the 180s ASSESSING window.
    store = PresenceStore();
    store.put(PresenceCard(
        agent=card["agent"],
        status=card["status"],
        heartbeat_ms=card["heartbeat_ms"],
        seq=card["seq"]
    ));
    assert not store.is_live("responder_antigravity", 2000);
    shutil.rmtree(inbox, ignore_errors=True);
}

test "presence goes idle — not working forever — once the assessment lands" {
    inbox = temp_inbox();
    r = bridge_for("responder_claude", inbox);
    r.escalate(sample_incident("inc-answered"), 0);
    r.spawn = True;
    r.proc = RunningProc();
    assert r.presence(10)["status"] == "working";
    write_inbox(inbox, "responder_claude", valid_assessment("responder_claude", "inc-answered"));
    assert r.presence(20)["status"] == "idle";
    assert len(r.poll(20)) == 1;
    assert r.presence(30)["status"] == "idle";
    shutil.rmtree(inbox, ignore_errors=True);
}

test "a non-spawned responder that blows its answer budget reports offline" {
    inbox = temp_inbox();
    r = bridge_for("responder_kimi", inbox, {"poll_timeout_ms": 5000});
    r.escalate(sample_incident("inc-slow"), 1000);
    assert r.presence(3000)["status"] == "working";
    assert r.presence(6001)["status"] == "offline";
    shutil.rmtree(inbox, ignore_errors=True);
}

test "a KILLED responder reports offline, with a card frozen at the moment of death" {
    inbox = temp_inbox();
    r = bridge_for("responder_glm", inbox);
    r.escalate(sample_incident("inc-killed"), 1000);
    assert r.presence(1500)["status"] == "working";
    r.kill(2000);
    assert not r.is_alive();
    card: Any = r.presence(9000);
    assert card["status"] == "offline";
    assert card["heartbeat_ms"] == 2000;      # frozen where it died, not now_ms
    # Killed responders answer nothing, however long they hold the incident.
    write_inbox(inbox, "responder_glm", valid_assessment("responder_glm", "inc-killed"));
    assert r.poll(9000) == [];
    shutil.rmtree(inbox, ignore_errors=True);
}

test "the presence sequence advances monotonically, so a stuck card is visible" {
    inbox = temp_inbox();
    r = bridge_for("responder_codex", inbox);
    r.escalate(sample_incident("inc-seq"), 0);
    seqs: list = [];
    for t in [100, 200, 300] {
        seqs.append(r.presence(t)["seq"]);
    }
    assert seqs == sorted(seqs);
    assert seqs[0] < seqs[2];
    shutil.rmtree(inbox, ignore_errors=True);
}

# ==========================================================================
# 7. open_deliberation — exactly one bounded round
# ==========================================================================

test "open_deliberation rejects a round beyond DELIBERATION_ROUNDS_MAX" {
    inbox = temp_inbox();
    r = bridge_for("responder_claude", inbox);
    r.escalate(sample_incident("inc-rounds"), 0);
    raised = False;
    try {
        r.open_deliberation("inc-rounds", DELIBERATION_ROUNDS_MAX + 1, 10);
    } except ValueError as e {
        raised = True;
    }
    assert raised;
    assert r.deliberation_round == 0;
    shutil.rmtree(inbox, ignore_errors=True);
}

test "the deliberation budget is spent once and never refills" {
    inbox = temp_inbox();
    r = bridge_for("responder_claude", inbox);
    r.escalate(sample_incident("inc-budget"), 0);
    r.open_deliberation("inc-budget", 1, 10);
    assert r.deliberation_round == DELIBERATION_ROUNDS_MAX;
    r.open_deliberation("inc-budget", 1, 20);       # no-op, not an error
    assert r.deliberation_round == DELIBERATION_ROUNDS_MAX;
    shutil.rmtree(inbox, ignore_errors=True);
}

test "open_deliberation is a no-op for a responder that never got the incident" {
    inbox = temp_inbox();
    r = bridge_for("responder_glm", inbox);
    r.open_deliberation("inc-never", 1, 10);
    assert r.deliberation_round == 0;
    shutil.rmtree(inbox, ignore_errors=True);
}

# ==========================================================================
# 8. The spawn guard — mesh/agent_runner is built separately
# ==========================================================================

test "a spawn request with no agent_runner on disk fails CLEARLY, not with ENOENT" {
    inbox = temp_inbox();
    r = bridge_for("responder_claude", inbox, {"spawn": True});   # runner_path absent
    assert not os.path.exists(r.runner());
    msg = "";
    try {
        r.escalate(sample_incident("inc-no-runner"), 1000);
    } except RuntimeError as e {
        msg = str(e);
    }
    assert "agent_runner not built yet" in msg;
    # Acceptance was recorded BEFORE the launch attempt: the durable channel
    # does not lose the incident because a process could not start.
    assert r.incident_id == "inc-no-runner";
    assert r.escalated_at_ms == 1000;
    # ...and the responder does not then sit there claiming `working`.
    assert r.presence(2000)["status"] == "offline";
    assert "agent_runner not built yet" in r.describe()["launch_error"];
    shutil.rmtree(inbox, ignore_errors=True);
}

test "the default runner is exactly the documented agent_runner entry point" {
    # The command the bridge issues is
    #   node mesh/agent_runner/bin/agent-runner.js --agent <id> --incident <p> --run-id <id>
    # so the default path must be that file and nothing else.
    assert RUNNER_JS.endswith(
        os.path.join("mesh", "agent_runner", "bin", "agent-runner.js")
    );
    r = mesh_responder_from_opts("responder_claude", {"run_id": "r"});
    assert r.runner() == RUNNER_JS;
}

test "no test in this file can reach the real runs/ tree" {
    # bridge_dir() follows assessments_dir, so a redirected inbox keeps the
    # incident file and the harness log inside the same temp directory.
    inbox = temp_inbox();
    r = bridge_for("responder_glm", inbox);
    assert os.path.abspath(r.bridge_dir()).startswith(os.path.abspath(os.path.dirname(inbox)));
    assert "runs" not in os.path.abspath(r.assessment_path()).split(os.sep)[:-3];
    shutil.rmtree(inbox, ignore_errors=True);
}

# ==========================================================================
# 9. The swap is CONFIG-ONLY
# ==========================================================================

test "cotal_config builds a five-responder mesh the coordinator's validate() accepts" {
    cfg: Any = cotal_config("run-today", TODAY_LIVE, TODAY_BLOCKED, {"poll_timeout_ms": 30000});
    cfg.validate();                       # the coordinator's own validator
    assert len(cfg.responders) == 5;
    ids = [rc.responder_id for rc in cfg.responders];
    assert sorted(ids) == sorted(RESPONDER_IDS);
    assert len(set(ids)) == 5;
    # Canonical order, so the built config is byte-stable.
    assert ids == list(RESPONDER_IDS);
}

test "a mixed run is forced to MOCKED — one recording makes the whole run mocked" {
    # The split is written out here, not taken from TODAY_LIVE/TODAY_BLOCKED:
    # nothing is blocked today, and the rule under test is what ANY recording
    # does to a run, whatever today's harness health happens to be.
    cfg: Any = cotal_config(
        "run-mixed",
        ["responder_claude", "responder_antigravity", "responder_codex"],
        ["responder_kimi", "responder_glm"]
    );
    assert cfg.is_mocked();
    assert cfg.effective_run_label() == RUN_MOCKED;
    assert cfg.run_label == RUN_MOCKED;
    assert cfg.describe()["run_label"] == RUN_MOCKED;
    # Three real models is still not an acceptance run.
    rep: Any = block_report(cfg);
    assert rep["live_count"] == 3;
    assert rep["mocked"];

    # ...and it really is ONE recording that does it, not a majority of them.
    four: Any = cotal_config(
        "run-one-mock",
        ["responder_claude", "responder_antigravity", "responder_codex", "responder_kimi"],
        ["responder_glm"]
    );
    assert four.is_mocked();
    assert four.run_label == RUN_MOCKED;
    assert block_report(four)["live_count"] == 4;
}

test "today's config blocks nobody, so it computes LIVE" {
    # 2026-07-26: TODAY_BLOCKED is empty — all five harnesses answer live — so
    # the label todays_config() COMPUTES (never asserts) is LIVE. This is the
    # same propagation rule as the test above, read from the other end.
    cfg: Any = todays_config("run-today");
    assert not cfg.is_mocked();
    assert cfg.effective_run_label() == RUN_LIVE;
    assert cfg.run_label == RUN_LIVE;
    assert cfg.describe()["run_label"] == RUN_LIVE;
    rep: Any = block_report(cfg);
    assert rep["live_count"] == 5;
    assert not rep["mocked"];
    assert len(TODAY_BLOCKED) == 0;
}

test "the live/blocked split is the ONLY thing that changes between the two configs" {
    # Blocked side constructed explicitly — see the note at the top of the file.
    blocked: Any = cotal_config(
        "run-x",
        ["responder_claude", "responder_antigravity", "responder_codex"],
        ["responder_kimi", "responder_glm"]
    );
    unblocked: Any = cotal_config("run-x", RESPONDER_IDS, []);
    for rid in RESPONDER_IDS {
        a = blocked.entry(rid);
        b = unblocked.entry(rid);
        assert a is not None and b is not None;
        assert a.responder_id == b.responder_id;      # same ids
    }
    # ...and the difference is exactly the `kind` field.
    assert blocked.entry("responder_kimi").kind == "mock";
    assert unblocked.entry("responder_kimi").kind == COTAL_KIND;
    assert blocked.entry("responder_claude").kind == COTAL_KIND;
    # Today's split blocks nobody, so it is the unblocked config, row for row —
    # unblocking responder_kimi and responder_glm was exactly this `kind` flip.
    today: Any = todays_config("run-x");
    for rid in RESPONDER_IDS {
        assert today.entry(rid).responder_id == unblocked.entry(rid).responder_id;
        assert today.entry(rid).kind == unblocked.entry(rid).kind;
    }
}

test "the all-live mesh labels LIVE, and is the acceptance configuration" {
    cfg: Any = all_live_config("run-accept");
    cfg.validate();
    assert not cfg.is_mocked();
    assert cfg.effective_run_label() == RUN_LIVE;
    for rc in cfg.responders {
        assert rc.kind == COTAL_KIND;
    }
}

test "build_mesh constructs cotal handles the coordinator cannot tell from mocks" {
    # Mixed on purpose — a mesh with no mock in it cannot show that the
    # coordinator sees one uniform ResponderHandle either way. Split written out
    # explicitly; see the note at the top of the file.
    cfg: Any = cotal_config(
        "run-build",
        ["responder_claude", "responder_antigravity", "responder_codex"],
        ["responder_kimi", "responder_glm"],
        {"poll_timeout_ms": 1000}
    );
    mesh: Any = build_mesh(cfg, 0);
    assert len(mesh) == 5;
    for rid in RESPONDER_IDS {
        assert isinstance(mesh[rid], ResponderHandle);
        assert mesh[rid].responder_id == rid;
    }
    assert isinstance(mesh["responder_claude"], MeshResponder);
    assert not isinstance(mesh["responder_kimi"], MeshResponder);
    # build_mesh forces the label on the way through.
    assert cfg.run_label == RUN_MOCKED;

    # Today's config blocks nobody, so the same build_mesh yields five cotal
    # handles and the forced label is LIVE.
    live_cfg: Any = todays_config("run-build-live", {"poll_timeout_ms": 1000});
    live_mesh: Any = build_mesh(live_cfg, 0);
    assert len(live_mesh) == 5;
    for rid in RESPONDER_IDS {
        assert isinstance(live_mesh[rid], ResponderHandle);
        assert isinstance(live_mesh[rid], MeshResponder);
    }
    assert live_cfg.run_label == RUN_LIVE;
}

test "cotal_config refuses a mesh that is not exactly the five canonical ids" {
    bad_cases: list = [
        [["responder_claude"], ["responder_glm"]],                       # missing three
        [["responder_claude", "responder_claude"], []],                  # duplicate
        [["responder_claude", "monitor"], ["responder_glm"]]             # a stranger
    ];
    for case in bad_cases {
        raised = False;
        try {
            cotal_config("run-bad", case[0], case[1]);
        } except ValueError as e {
            raised = True;
        }
        assert raised, f"expected ValueError for {case}";
    }
}

test "every blocked responder carries a reason code, and no credential" {
    # Nothing is blocked today, so a report built from todays_config() would have
    # no blocked rows and this test would pass by having nothing to check. The
    # blocked rows are therefore constructed — the invariant under test is what a
    # blocked row must CARRY, not who happens to be blocked.
    cfg: Any = cotal_config(
        "run-reasons",
        ["responder_claude", "responder_antigravity", "responder_codex"],
        ["responder_kimi", "responder_glm"]
    );
    rep: Any = block_report(cfg);
    blocked_rows = [row for row in rep["responders"] if not row["live"]];
    assert len(blocked_rows) == 2;      # the loop below may never go vacuous
    for row in blocked_rows {
        assert row["blocked_reason"] != "";
    }
    # A live row is not annotated with a block reason at all.
    for row in rep["responders"] {
        if row["live"] {
            assert "blocked_reason" not in row;
        }
    }
    # The reason table stays in step with the blocked list: anything declared
    # blocked declares WHY. Both are empty today, so this holds vacuously — it is
    # kept to catch the first future block that forgets its reason code.
    for rid in TODAY_BLOCKED {
        assert rid in BLOCK_REASONS;
    }
    # ...and today's own report has nothing to explain.
    today_rep: Any = block_report(todays_config("run-reasons-today"));
    assert today_rep["live_count"] == 5;
    assert not today_rep["mocked"];
    assert [row for row in today_rep["responders"] if not row["live"]] == [];
}

test "config never carries anything credential-shaped into an artifact" {
    # ResponderConfig.describe() summarises opts BY KEY. Assert the keys the
    # bridge actually forwards are run wiring and nothing else.
    cfg: Any = todays_config("run-optkeys", {"poll_timeout_ms": 1000, "spawn": False});
    allowed = [
        "assessments_dir", "incident_path", "mocked", "poll_timeout_ms",
        "run_id", "runner_path", "spawn"
    ];
    for row in cfg.describe()["responders"] {
        for k in row["opt_keys"] {
            assert k in allowed, f"unexpected opt key {k} on {row['responder_id']}";
        }
    }
    # The live responder's own audit view is identity + health only.
    r = bridge_for("responder_claude", temp_inbox());
    d: Any = r.describe();
    assert sorted(d.keys()) == [
        "answered", "kind", "launch_error", "launched",
        "rejection_reasons", "rejections", "responder_id", "run_id"
    ];
}

# ==========================================================================
# 10. End to end through the seam
# ==========================================================================

test "a coordinator-shaped escalate/poll cycle over the whole mesh" {
    # Drive the mesh exactly as the FSM does: build handles from config, escalate
    # the same incident to every one, then poll. The live slots answer from real
    # files; the blocked slots answer from their recordings. Neither the loop
    # below nor the coordinator can tell which is which.
    #
    # The split is written out rather than read from TODAY_LIVE/TODAY_BLOCKED:
    # nothing is blocked today, and a mesh with no recording in it cannot show
    # that the drive loop is blind to the difference. The all-live cycle is the
    # test below.
    inbox = temp_inbox();
    live_ids: list = ["responder_claude", "responder_antigravity", "responder_codex"];
    mocked_ids: list = ["responder_kimi", "responder_glm"];
    cfg: Any = cotal_config(
        "run-e2e",
        live_ids,
        mocked_ids,
        {"assessments_dir": inbox, "poll_timeout_ms": 30000}
    );
    mesh: Any = build_mesh(cfg, 0);
    incident = sample_incident("inc-e2e");
    for rid in RESPONDER_IDS {
        mesh[rid].escalate(incident, 1000);
    }
    for rid in live_ids {
        write_inbox(inbox, rid, valid_assessment(rid, "inc-e2e"));
    }
    seen: dict = {};
    for round_no in [0, 1] {          # poll twice: nothing may arrive twice
        for rid in RESPONDER_IDS {
            for a in mesh[rid].poll(2000 + round_no) {
                key = f"{a['responder']}|{a['incident_id']}";
                assert key not in seen, f"double-counted {key}";
                seen[key] = a;
            }
        }
    }
    assert len(seen) == 5;            # three live + two recorded
    for rid in RESPONDER_IDS {
        assert f"{rid}|inc-e2e" in seen;
        assert assessment_errors(seen[f"{rid}|inc-e2e"]) == [];
    }
    assert cfg.run_label == RUN_MOCKED;
    shutil.rmtree(inbox, ignore_errors=True);
}

test "the same cycle over today's all-live mesh answers five times and labels LIVE" {
    # Identical drive loop, no recordings anywhere: every slot is a real cotal
    # responder reading a real file off disk. Same at-most-once guarantee, and
    # the label this time computes to LIVE — an acceptance-shaped run.
    inbox = temp_inbox();
    cfg: Any = todays_config(
        "run-e2e-live",
        {"assessments_dir": inbox, "poll_timeout_ms": 30000}
    );
    mesh: Any = build_mesh(cfg, 0);
    incident = sample_incident("inc-e2e-live");
    for rid in RESPONDER_IDS {
        mesh[rid].escalate(incident, 1000);
    }
    for rid in TODAY_LIVE {
        write_inbox(inbox, rid, valid_assessment(rid, "inc-e2e-live"));
    }
    seen: dict = {};
    for round_no in [0, 1] {          # poll twice: nothing may arrive twice
        for rid in RESPONDER_IDS {
            for a in mesh[rid].poll(2000 + round_no) {
                key = f"{a['responder']}|{a['incident_id']}";
                assert key not in seen, f"double-counted {key}";
                seen[key] = a;
            }
        }
    }
    assert len(seen) == 5;            # five live, nothing recorded
    for rid in RESPONDER_IDS {
        assert f"{rid}|inc-e2e-live" in seen;
        assert assessment_errors(seen[f"{rid}|inc-e2e-live"]) == [];
    }
    assert cfg.run_label == RUN_LIVE;
    shutil.rmtree(inbox, ignore_errors=True);
}
