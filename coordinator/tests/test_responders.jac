# coordinator/tests/test_responders.jac
#
# Tests for the responder seam and the presence liveness surface.
#
# Run from the coordinator directory (Jac resolves imports against the
# invocation cwd, not the file):
#
#   cd coordinator && jac test tests/test_responders.jac
#
# What these assert, in one line each:
#   - every recorded transcript is a schema-valid assessment.v1 against the
#     FROZEN contract, before and after the mock renders it;
#   - the live/mock seam is real (a LiveResponder type-checks as a
#     ResponderHandle and honestly raises on every transport method);
#   - presence liveness resolves a dead slot immediately instead of burning the
#     180s ASSESSING window;
#   - the durable-channel backstop holds: an incident escalated to a dead
#     responder is still answered after it reconnects;
#   - identical config + identical virtual clock => byte-identical output.

import json;
import os;
import from typing { Any }
import from jsonschema { Draft202012Validator }

import from ids { RESPONDER_IDS, PRESENCE_STALE_MS, RUN_MOCKED, RUN_LIVE }
import from clock { frozen_clock }
import from presence { PresenceCard, PresenceStore, seeded_store }
import from responder {
    ResponderHandle,
    LiveResponder,
    live_factory,
    build_responder,
    known_responder_kinds,
    is_known_kind
}
import from mocks.mock_responder {
    MockResponder,
    load_transcript,
    load_all_transcripts,
    mock_from_transcript,
    transcript_path
}
import from config {
    ResponderConfig,
    MeshConfig,
    default_mock_config,
    default_live_config,
    mock_config_with,
    build_mesh
}

glob:pub HERE: str = os.path.dirname(os.path.abspath(__file__));
glob:pub SCHEMA_PATH: str = os.path.join(
    HERE, "..", "..", "contracts", "mesh", "assessment.v1.schema.json"
);

"""The frozen assessment.v1 validator, read from contracts/ at test time.

Read, never copied: if the contract moves, these tests fail rather than pass
against a stale duplicate."""
def assessment_validator -> Any {
    with open(SCHEMA_PATH, "r") as fh {
        schema = json.load(fh);
    }
    Draft202012Validator.check_schema(schema);
    return Draft202012Validator(schema);
}

"""Sorted schema-violation messages for `payload`. Empty list means valid."""
def schema_errors(payload: Any) -> list {
    validator = assessment_validator();
    out: list = [];
    for e in validator.iter_errors(payload) {
        out.append(str(e.message));
    }
    return sorted(out);
}

"""Narrow an optional presence card, failing the test if there is none."""
def must_card(card: PresenceCard | None) -> PresenceCard {
    if card is None {
        raise AssertionError("expected a presence card, got none");
    }
    return card;
}

"""Narrow an optional config entry, failing the test if there is none."""
def must_entry(rc: ResponderConfig | None) -> ResponderConfig {
    if rc is None {
        raise AssertionError("expected a responder config entry, got none");
    }
    return rc;
}

"""A representative incident for the authorised scenario.

Only the fields the responder seam actually reads; the full incident.v1 shape is
exercised by the schema tests that own that contract."""
def sample_incident(incident_id: str = "inc-test-0001") -> dict {
    return {
        "incident_id": incident_id,
        "schema_version": "incident.v1",
        "detected_at_ms": 1769472000000,
        "join_keys": {
            "principal_hash": "ph_9f2c41ab7d0e5613",
            "tenant": "tenant_northwind"
        },
        "stage_signatures": [1, 2, 3, 4],
        "summary": "credential stuffing -> session hijack -> bulk export"
    };
}

# ==========================================================================
# 1. Transcripts
# ==========================================================================

test "every canonical responder has a transcript file on disk" {
    for rid in RESPONDER_IDS {
        assert os.path.exists(transcript_path(rid));
    }
    assert len(load_all_transcripts()) == 5;
}

test "every recorded transcript is a schema-valid assessment.v1" {
    for rid in RESPONDER_IDS {
        t: Any = load_transcript(rid);
        assert t["assessment"]["responder"] == rid;
        errs = schema_errors(t["assessment"]);
        assert errs == [], f"{rid} assessment: {errs}";
        assert len(t["assessment"]["rationale"]) <= 400;
    }
}

test "every recorded deliberation revision is a schema-valid assessment.v1" {
    for rid in RESPONDER_IDS {
        t: Any = load_transcript(rid);
        assert "deliberation" in t;
        revised: Any = t["deliberation"]["revised"];
        errs = schema_errors(revised);
        assert errs == [], f"{rid} revised: {errs}";
        assert revised["responder"] == rid;
        assert len(revised["rationale"]) <= 400;
    }
}

test "transcripts are genuinely different, so quorum logic has something to do" {
    verdicts: list = [];
    confidences: list = [];
    for rid in RESPONDER_IDS {
        a: Any = load_transcript(rid)["assessment"];
        verdicts.append(a["verdict"]);
        confidences.append(a["confidence"]);
    }
    assert len(set(verdicts)) > 1;
    assert len(set(confidences)) == 5;
}

test "a mock emits a schema-valid assessment carrying the incident id verbatim" {
    clock = frozen_clock();
    incident = sample_incident("inc-2026-07-26-verbatim");
    for rid in RESPONDER_IDS {
        mock = mock_from_transcript(rid, {});
        mock.escalate(incident, clock.now_ms());
        got: Any = mock.poll(clock.now_ms());
        assert len(got) == 1;
        a: Any = got[0];
        assert a["incident_id"] == "inc-2026-07-26-verbatim";
        assert a["responder"] == rid;
        assert schema_errors(a) == [];
    }
}

test "a mock's deliberation revision is schema-valid and bounded to one round" {
    clock = frozen_clock();
    mock = mock_from_transcript("responder_claude", {});
    incident = sample_incident("inc-split-0001");
    mock.escalate(incident, clock.now_ms());
    assert len(mock.poll(clock.now_ms())) == 1;

    mock.open_deliberation("inc-split-0001", 1, clock.advance(1000));
    revised: Any = mock.poll(clock.now_ms());
    assert len(revised) == 1;
    assert revised[0]["incident_id"] == "inc-split-0001";
    assert schema_errors(revised[0]) == [];

    # The round budget is one. A second open is a no-op, not a second revision.
    mock.open_deliberation("inc-split-0001", 1, clock.advance(1000));
    assert mock.poll(clock.now_ms()) == [];
}

# ==========================================================================
# 2. The seam
# ==========================================================================

test "a live responder is a ResponderHandle and raises on every transport method" {
    live = live_factory("responder_claude", {});
    assert isinstance(live, ResponderHandle);
    assert isinstance(live, LiveResponder);
    assert live.kind == "live";
    assert live.is_canonical();

    raised = 0;
    try { live.presence(0); } except NotImplementedError as e { raised += 1; }
    try { live.escalate({}, 0); } except NotImplementedError as e { raised += 1; }
    try { live.poll(0); } except NotImplementedError as e { raised += 1; }
    try { live.open_deliberation("i", 1, 0); } except NotImplementedError as e { raised += 1; }
    try { live.kill(0); } except NotImplementedError as e { raised += 1; }
    try { live.is_alive(); } except NotImplementedError as e { raised += 1; }
    assert raised == 6;
}

test "the abstract base itself is not usable as a responder" {
    base = ResponderHandle(responder_id="responder_glm");
    assert base.kind == "abstract";
    raised = 0;
    try { base.presence(0); } except NotImplementedError as e { raised += 1; }
    try { base.escalate({}, 0); } except NotImplementedError as e { raised += 1; }
    try { base.poll(0); } except NotImplementedError as e { raised += 1; }
    try { base.open_deliberation("i", 1, 0); } except NotImplementedError as e { raised += 1; }
    try { base.kill(0); } except NotImplementedError as e { raised += 1; }
    assert raised == 5;
}

test "a mock is indistinguishable from a live handle at the type level" {
    mock = mock_from_transcript("responder_kimi", {});
    live = live_factory("responder_kimi", {});
    assert isinstance(mock, ResponderHandle);
    assert isinstance(live, ResponderHandle);
    assert mock.kind == "mock";
    assert live.kind == "live";
}

test "the registry knows both kinds and rejects anything else" {
    assert is_known_kind("mock");
    assert is_known_kind("live");
    assert known_responder_kinds() == ["live", "mock"];
    raised = False;
    try {
        build_responder("telepathy", "responder_glm", {});
    } except ValueError as e {
        raised = True;
    }
    assert raised;
}

# ==========================================================================
# 3. Config -> mesh
# ==========================================================================

test "build_mesh returns five ResponderHandles keyed by the canonical ids" {
    clock = frozen_clock();
    mesh = build_mesh(default_mock_config(), clock.now_ms());
    assert len(mesh) == 5;
    assert sorted(mesh.keys()) == sorted(RESPONDER_IDS);
    for rid in RESPONDER_IDS {
        assert isinstance(mesh[rid], ResponderHandle);
        assert mesh[rid].responder_id == rid;
    }
}

test "swapping mock to live is one config field, and the mesh still builds" {
    clock = frozen_clock();
    cfg = default_mock_config();
    must_entry(cfg.entry("responder_codex")).kind = "live";     # <-- the entire swap
    mesh = build_mesh(cfg, clock.now_ms());
    assert len(mesh) == 5;
    for rid in RESPONDER_IDS {
        assert isinstance(mesh[rid], ResponderHandle);
    }
    # An all-live mesh builds too, and every handle is still just a handle.
    live_mesh = build_mesh(default_live_config(), clock.now_ms());
    assert len(live_mesh) == 5;
    for rid in RESPONDER_IDS {
        assert isinstance(live_mesh[rid], ResponderHandle);
    }
}

test "one mock anywhere in the mesh forces the run label to MOCKED" {
    cfg = default_mock_config();
    assert cfg.is_mocked();
    assert cfg.effective_run_label() == RUN_MOCKED;

    live_cfg = default_live_config();
    assert not live_cfg.is_mocked();
    assert live_cfg.effective_run_label() == RUN_LIVE;

    # A single mock contaminates an otherwise live run.
    must_entry(live_cfg.entry("responder_glm")).kind = "mock";
    assert live_cfg.is_mocked();
    assert live_cfg.effective_run_label() == RUN_MOCKED;
    build_mesh(live_cfg, 0);
    assert live_cfg.run_label == RUN_MOCKED;
}

test "config validation rejects a missing, duplicated or unknown responder" {
    cfg = default_mock_config();
    cfg.validate();

    short = MeshConfig(responders=cfg.responders[0:4]);
    raised = False;
    try { short.validate(); } except ValueError as e { raised = True; }
    assert raised;

    dup = MeshConfig(responders=cfg.responders + [cfg.responders[0]]);
    raised = False;
    try { dup.validate(); } except ValueError as e { raised = True; }
    assert raised;

    stranger = MeshConfig(
        responders=cfg.responders[0:4]
            + [ResponderConfig(responder_id="responder_nobody", kind="mock")]
    );
    raised = False;
    try { stranger.validate(); } except ValueError as e { raised = True; }
    assert raised;

    bad_kind = default_mock_config();
    must_entry(bad_kind.entry("responder_kimi")).kind = "telepathy";
    raised = False;
    try { bad_kind.validate(); } except ValueError as e { raised = True; }
    assert raised;
}

# ==========================================================================
# 4. Latency
# ==========================================================================

test "a 5000ms mock yields nothing at t+4999, exactly one at t+5000, nothing after" {
    clock = frozen_clock();
    t0 = clock.now_ms();
    mock = mock_from_transcript("responder_codex", {"latency_ms": 5000});
    mock.escalate(sample_incident(), t0);

    assert mock.poll(t0) == [];
    assert mock.poll(t0 + 4999) == [];

    got: Any = mock.poll(t0 + 5000);
    assert len(got) == 1;
    assert got[0]["responder"] == "responder_codex";

    # At-most-once: the same assessment is never returned twice.
    assert mock.poll(t0 + 5000) == [];
    assert mock.poll(t0 + 999999) == [];
}

# ==========================================================================
# 5. Death, and presence as the immediate resolver
# ==========================================================================

test "a dead mock never answers and its presence card is not live" {
    clock = frozen_clock();
    t0 = clock.now_ms();
    mock = mock_from_transcript("responder_glm", {"latency_ms": 1000});
    mock.escalate(sample_incident(), t0);
    mock.kill(t0 + 100);

    assert not mock.is_alive();
    assert mock.poll(t0 + 1000) == [];
    assert mock.poll(t0 + 180000) == [];      # the whole ASSESSING window

    store = PresenceStore();
    card: Any = mock.presence(t0 + 1000);
    assert card["status"] == "offline";
    store.put(PresenceCard(
        agent=card["agent"],
        status=card["status"],
        heartbeat_ms=card["heartbeat_ms"],
        seq=card["seq"]
    ));
    # Resolved dead IMMEDIATELY — not after 180s.
    assert not store.is_live("responder_glm", t0 + 1000);
}

test "a mock that goes dark still claims working, and presence catches it anyway" {
    clock = frozen_clock();
    t0 = clock.now_ms();
    mock = mock_from_transcript(
        "responder_antigravity",
        {"heartbeat_stops_at_ms": t0 + 1000}
    );
    store = PresenceStore();

    fresh: Any = mock.presence(t0 + 1000);
    assert fresh["status"] == "working";
    assert fresh["heartbeat_ms"] == t0 + 1000;

    dark: Any = mock.presence(t0 + 20000);
    # The upstream bug, faithfully reproduced: it still says `working`.
    assert dark["status"] == "working";
    assert dark["heartbeat_ms"] == t0 + 1000;

    store.put(PresenceCard(
        agent=dark["agent"],
        status=dark["status"],
        heartbeat_ms=dark["heartbeat_ms"],
        seq=dark["seq"]
    ));
    assert not store.is_live("responder_antigravity", t0 + 20000);
}

# ==========================================================================
# 6. Presence staleness
# ==========================================================================

test "a card 6001ms old is not live and a card 5999ms old is live" {
    assert PRESENCE_STALE_MS == 6000;
    store = PresenceStore();
    store.heartbeat("responder_claude", 1000);

    assert store.is_live("responder_claude", 1000 + 5999);
    assert store.is_live("responder_claude", 1000 + 6000);      # boundary is inclusive
    assert not store.is_live("responder_claude", 1000 + 6001);
}

test "an offline card is never live, however fresh, and a missing card is never live" {
    store = PresenceStore();
    store.mark_offline("responder_kimi", 5000);
    assert not store.is_live("responder_kimi", 5000);
    assert not store.is_live("responder_kimi", 5001);
    assert must_card(store.get("responder_kimi")).status == "offline";

    assert store.get("responder_nobody") is None;
    assert not store.is_live("responder_nobody", 0);
}

test "a heartbeat from the future is skew, not death" {
    store = PresenceStore();
    store.heartbeat("responder_glm", 900000);
    assert store.is_live("responder_glm", 800000);
    assert store.age_ms("responder_glm", 800000) == -100000;
}

test "heartbeat bumps seq and mark_offline is just a heartbeat with a status" {
    store = PresenceStore();
    store.heartbeat("responder_codex", 1000);
    assert must_card(store.get("responder_codex")).seq == 1;
    store.heartbeat("responder_codex", 3000);
    assert must_card(store.get("responder_codex")).seq == 2;
    assert must_card(store.get("responder_codex")).heartbeat_ms == 3000;
    store.mark_offline("responder_codex", 5000);
    assert must_card(store.get("responder_codex")).seq == 3;
    assert must_card(store.get("responder_codex")).status == "offline";

    raised = False;
    try { store.heartbeat("responder_codex", 6000, "vibing"); }
    except ValueError as e { raised = True; }
    assert raised;
}

test "dead_agents returns the sorted non-live ids and snapshot is key-sorted" {
    store = seeded_store(RESPONDER_IDS, 10000);
    assert store.dead_agents(RESPONDER_IDS, 10000) == [];
    assert store.live_agents(RESPONDER_IDS, 10000) == sorted(RESPONDER_IDS);

    store.mark_offline("responder_kimi", 10000);          # explicit offline
    store.heartbeat("responder_claude", 1000);            # stale by 9000ms at t=10000
    dead = store.dead_agents(RESPONDER_IDS, 10000);
    assert dead == ["responder_claude", "responder_kimi"];
    assert dead == sorted(dead);

    snap: Any = store.snapshot();
    assert list(snap.keys()) == sorted(RESPONDER_IDS);
    assert snap["responder_kimi"]["status"] == "offline";
    assert list(snap["responder_glm"].keys()) == ["agent", "status", "heartbeat_ms", "seq"];

    # Everything goes dead once the whole mesh is past the staleness window.
    assert store.dead_agents(RESPONDER_IDS, 10000 + 6001) == sorted(RESPONDER_IDS);
}

# ==========================================================================
# 7. Durable-channel backstop
# ==========================================================================

test "a responder killed before escalation still answers after it reconnects" {
    clock = frozen_clock();
    t0 = clock.now_ms();
    mock = mock_from_transcript("responder_kimi", {"latency_ms": 2000});

    # Dead BEFORE the incident is ever escalated.
    mock.kill(t0);
    assert not mock.is_alive();

    # The durable channel delivers anyway; acceptance is not an answer.
    mock.escalate(sample_incident("inc-durable-0001"), t0 + 1000);
    assert mock.poll(t0 + 1000) == [];
    assert mock.poll(t0 + 100000) == [];

    # Reconnect. The held escalation is re-armed, not dropped.
    mock.revive(t0 + 120000);
    assert mock.is_alive();
    assert mock.poll(t0 + 120000) == [];               # latency still applies
    got: Any = mock.poll(t0 + 122000);
    assert len(got) == 1;
    assert got[0]["incident_id"] == "inc-durable-0001";
    assert got[0]["responder"] == "responder_kimi";
    assert schema_errors(got[0]) == [];
    assert mock.poll(t0 + 122000) == [];               # still at-most-once

    # And it heartbeats again once revived.
    card: Any = mock.presence(t0 + 122000);
    assert card["status"] == "working";
    assert card["heartbeat_ms"] == t0 + 122000;
}

test "a responder that dies mid-flight holds its assessment rather than losing it" {
    clock = frozen_clock();
    t0 = clock.now_ms();
    mock = mock_from_transcript("responder_claude", {"latency_ms": 3000});
    mock.escalate(sample_incident("inc-midflight-0001"), t0);

    mock.kill(t0 + 1000);                 # dies while the answer is in flight
    assert mock.poll(t0 + 3000) == [];

    mock.revive(t0 + 10000);
    assert mock.poll(t0 + 12999) == [];
    got: Any = mock.poll(t0 + 13000);
    assert len(got) == 1;
    assert got[0]["incident_id"] == "inc-midflight-0001";
}

# ==========================================================================
# 8. Determinism
# ==========================================================================

test "two identical meshes on identical virtual clocks emit byte-identical JSON" {
    incident = sample_incident("inc-determinism-0001");

    clock_a = frozen_clock();
    mesh_a = build_mesh(default_mock_config(), clock_a.now_ms());
    out_a: list = [];
    for rid in RESPONDER_IDS {
        mesh_a[rid].escalate(incident, clock_a.now_ms());
    }
    clock_a.advance(1500);
    for rid in RESPONDER_IDS {
        for a in mesh_a[rid].poll(clock_a.now_ms()) {
            out_a.append(json.dumps(a, sort_keys=True, separators=(",", ":")));
        }
    }

    clock_b = frozen_clock();
    mesh_b = build_mesh(default_mock_config(), clock_b.now_ms());
    out_b: list = [];
    for rid in RESPONDER_IDS {
        mesh_b[rid].escalate(incident, clock_b.now_ms());
    }
    clock_b.advance(1500);
    for rid in RESPONDER_IDS {
        for a in mesh_b[rid].poll(clock_b.now_ms()) {
            out_b.append(json.dumps(a, sort_keys=True, separators=(",", ":")));
        }
    }

    assert len(out_a) == 5;
    assert out_a == out_b;
    assert json.dumps(out_a) == json.dumps(out_b);
}

test "a mesh with staggered latency is order-independent, not arrival-ordered" {
    incident = sample_incident("inc-stagger-0001");
    overrides = {
        "responder_claude": {"latency_ms": 4000},
        "responder_codex": {"latency_ms": 1000},
        "responder_antigravity": {"latency_ms": 9000},
        "responder_kimi": {"latency_ms": 200},
        "responder_glm": {"latency_ms": 7000}
    };

    collected: list = [];
    clock = frozen_clock();
    mesh = build_mesh(mock_config_with(overrides), clock.now_ms());
    for rid in RESPONDER_IDS {
        mesh[rid].escalate(incident, clock.now_ms());
    }
    for step in [200, 1000, 4000, 7000, 9000] {
        clock.set_ms(1769472000000 + step);
        for rid in RESPONDER_IDS {
            for a in mesh[rid].poll(clock.now_ms()) {
                collected.append(json.dumps(a, sort_keys=True, separators=(",", ":")));
            }
        }
    }
    assert len(collected) == 5;

    # Same mesh, polled in one shot after everyone is ready: same set of bytes.
    clock2 = frozen_clock();
    mesh2 = build_mesh(mock_config_with(overrides), clock2.now_ms());
    for rid in RESPONDER_IDS {
        mesh2[rid].escalate(incident, clock2.now_ms());
    }
    clock2.advance(9000);
    one_shot: list = [];
    for rid in RESPONDER_IDS {
        for a in mesh2[rid].poll(clock2.now_ms()) {
            one_shot.append(json.dumps(a, sort_keys=True, separators=(",", ":")));
        }
    }
    assert sorted(collected) == sorted(one_shot);
}

test "overrides are deterministic and never leak back into the transcript" {
    clock = frozen_clock();
    incident = sample_incident("inc-override-0001");
    forced = mock_from_transcript(
        "responder_glm",
        {"verdict_override": "benign", "confidence_override": 0.11}
    );
    forced.escalate(incident, clock.now_ms());
    got: Any = forced.poll(clock.now_ms())[0];
    assert got["verdict"] == "benign";
    assert got["confidence"] == 0.11;
    assert schema_errors(got) == [];

    # A mutation of a returned assessment cannot reach the next mock.
    got["verdict"] = "malicious";
    got["recommended_actions"] = [];
    clean = mock_from_transcript("responder_glm", {});
    clean.escalate(incident, clock.now_ms());
    fresh: Any = clean.poll(clock.now_ms())[0];
    recorded: Any = load_transcript("responder_glm")["assessment"];
    assert fresh["verdict"] == recorded["verdict"];
    assert fresh["recommended_actions"] == recorded["recommended_actions"];
}
