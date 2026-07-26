# coordinator/tests/incidents.jac
#
# Incident payloads and per-scenario mesh tuning for the end-to-end FSM tests.
#
# Every mesh override here maps a responder_id to an opts dict consumed by
# mock_from_transcript (latency_ms, dead, verdict_override, confidence_override,
# actions_override). All action dicts are built with fixtures.act, which refuses
# any kind outside the ten frozen CONTAINMENT_KINDS and keeps ttl_s / blast_radius
# schema-valid — so a scenario can never smuggle an invalid assessment.v1 in.
#
# The mesh is always mock (mock_config_with), so every run these drive is MOCKED.

import from config { MeshConfig, mock_config_with }
import from tests.fixtures { act }

# The primary target the recorded transcripts already act on — reused as the
# degraded posture's fallback and the incident's join_keys.
glob:pub PRIMARY_TARGET: dict = {
    "principal_hash": "ph_9f2c41ab7d0e5613",
    "tenant": "tenant_northwind"
};


"""A minimal incident.v1-ish payload. The mesh only reads incident_id; the rest
is here so the object is a plausible incident, not a bare id."""
def incident_payload(incident_id: str) -> dict {
    return {
        "incident_id": incident_id,
        "schema_version": "1.0.0",
        "tenant": "tenant_northwind",
        "summary": "credential stuffing -> session hijack -> data exfiltration",
        "join_keys": dict(PRIMARY_TARGET)
    };
}

"""Default entry for the DEGRADED monitor-only posture."""
def fallback_target -> dict {
    return dict(PRIMARY_TARGET);
}


# --------------------------------------------------------------------------
# Per-scenario mesh overrides. Each returns a dict for mock_config_with.
# --------------------------------------------------------------------------

"""S1 — all five malicious and confident (claude/codex/kimi are malicious in the
recordings; push the other two over too)."""
def ov_all_malicious -> dict {
    return {
        "responder_antigravity": {"verdict_override": "malicious", "confidence_override": 0.9},
        "responder_glm": {"verdict_override": "malicious", "confidence_override": 0.9}
    };
}

"""S2 — exactly 3/5 malicious at high confidence + 2 benign; score >= 1.5."""
def ov_three_malicious_high -> dict {
    return {
        "responder_antigravity": {"verdict_override": "benign", "confidence_override": 0.3},
        "responder_glm": {"verdict_override": "benign", "confidence_override": 0.3}
    };
}

"""S3 — 3/5 malicious but at LOW confidence + 2 benign; score < 1.5 -> no contain.
Proves the SCORE gate, not the majority: three malicious votes still present."""
def ov_three_malicious_low -> dict {
    return {
        "responder_claude": {"confidence_override": 0.3},
        "responder_codex": {"confidence_override": 0.3},
        "responder_kimi": {"confidence_override": 0.3},
        "responder_antigravity": {"verdict_override": "benign", "confidence_override": 0.3},
        "responder_glm": {"verdict_override": "benign", "confidence_override": 0.3}
    };
}

"""S4 — an engineered 2 malicious / 2 benign / 1 suspicious split."""
def ov_split_221 -> dict {
    return {
        "responder_claude": {"verdict_override": "malicious"},
        "responder_codex": {"verdict_override": "malicious"},
        "responder_antigravity": {"verdict_override": "benign"},
        "responder_kimi": {"verdict_override": "benign"},
        "responder_glm": {"verdict_override": "suspicious"}
    };
}

"""S5 — two responders dead; the live three (claude/codex/kimi, malicious) decide."""
def ov_two_dead -> dict {
    return {
        "responder_antigravity": {"dead": True},
        "responder_glm": {"dead": True}
    };
}

"""S6 — three responders dead; only two live -> sub-quorum -> DEGRADED.
kimi (live, malicious) still proposes raise_logging, so the monitor-only posture
is non-trivial and provably revocation-free."""
def ov_three_dead -> dict {
    return {
        "responder_claude": {"dead": True},
        "responder_codex": {"dead": True},
        "responder_antigravity": {"dead": True}
    };
}

"""S7 — four responders answer promptly; glm's assessment is ready only long
after the vote closes. `latency_ms` beyond the 180s window makes it a NO_VOTE at
decision time and a late arrival on the post-decision sweep."""
def ov_late_responder(latency_ms: int) -> dict {
    return {
        "responder_glm": {"latency_ms": latency_ms}
    };
}

"""S8 — three malicious responders agree on ONE action; a fourth (also malicious,
so containment still fires) piles on several broad/long actions nobody else
proposed. The solo actions must be dropped by the >=2-proposer rule."""
def ov_aggressive_solo -> dict {
    tgt = {"principal_hash": "ph_x8c1", "tenant": "tenant_northwind"};
    src = {"tenant": "tenant_northwind", "src_ips": ["203.0.113.9"]};
    q = {"tenant": "tenant_northwind", "queue": "export_jobs"};
    return {
        "responder_claude": {"verdict_override": "malicious", "confidence_override": 0.9,
                             "actions_override": [act("revoke_session", dict(tgt), 3600, "narrow")]},
        "responder_codex": {"verdict_override": "malicious", "confidence_override": 0.9,
                            "actions_override": [act("revoke_session", dict(tgt), 3600, "narrow")]},
        "responder_kimi": {"verdict_override": "malicious", "confidence_override": 0.9,
                           "actions_override": [act("revoke_session", dict(tgt), 3600, "narrow")]},
        "responder_antigravity": {"verdict_override": "malicious", "confidence_override": 0.9,
                                  "actions_override": [
                                      act("revoke_session", dict(tgt), 3600, "narrow"),
                                      act("suspend_principal", dict(tgt), 86400, "broad"),
                                      act("block_source", dict(src), 86400, "broad"),
                                      act("pause_queue", dict(q), 86400, "broad")
                                  ]},
        "responder_glm": {"verdict_override": "benign", "confidence_override": 0.3}
    };
}

"""S9 — three malicious responders propose the SAME action+target with different
ttl_s and blast_radius. The survivor must carry the MIN ttl and NARROWEST blast."""
def ov_ttl_blast_cap -> dict {
    tgt = {"principal_hash": "ph_y9d2", "tenant": "tenant_northwind"};
    return {
        "responder_claude": {"verdict_override": "malicious", "confidence_override": 0.9,
                             "actions_override": [act("revoke_session", dict(tgt), 3600, "moderate")]},
        "responder_codex": {"verdict_override": "malicious", "confidence_override": 0.9,
                            "actions_override": [act("revoke_session", dict(tgt), 1800, "narrow")]},
        "responder_kimi": {"verdict_override": "malicious", "confidence_override": 0.9,
                           "actions_override": [act("revoke_session", dict(tgt), 900, "broad")]},
        "responder_antigravity": {"verdict_override": "benign", "confidence_override": 0.3},
        "responder_glm": {"verdict_override": "benign", "confidence_override": 0.3}
    };
}


"""Build a mock MeshConfig for a scenario override dict."""
def scenario_config(overrides: dict) -> MeshConfig {
    return mock_config_with(overrides);
}
