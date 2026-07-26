# coordinator/tests/fixtures.jac
#
# Assessment builders shared by the coordinator tests.
#
# Every dict these produce is a SCHEMA-VALID assessment.v1 — the test suite
# validates them against the frozen contract before trusting a single assertion
# derived from them. A fixture that quietly drifts out of contract would turn the
# whole quorum suite into theatre, so the fixtures are contract-checked too.
#
# No builder here invents a containment kind: `act` refuses anything outside the
# ten frozen CONTAINMENT_KINDS.

import from ids { RESPONDER_IDS, CONTAINMENT_KINDS, is_valid_kind }

glob:pub TEST_INCIDENT: str = "INC-TEST-0001";

# Effective model ids (OpenRouter form) per responder, so `model` is plausible
# and distinct rather than copy-pasted.
glob:pub MODEL_BY_RESPONDER: dict = {
    "responder_claude": "anthropic/claude-opus-5",
    "responder_codex": "openai/gpt-5.6",
    "responder_antigravity": "google/gemini-3-pro",
    "responder_kimi": "moonshotai/kimi-k2.5",
    "responder_glm": "z-ai/glm-5"
};

glob:pub DEFAULT_SKILLS: list = [
    {
        "path": "skills/cybersec/session-hijack-triage.md",
        "sha": "b4f1c0a92e7d5138a6c0f2e9b71d4c83a05e6f2718c9d3b40a7e5216cf83d9e0"
    }
];


"""One proposed containment action, shaped like assessment.v1.recommended_actions[].

Rejects any kind outside the frozen enum — a fixture must never be the thing that
smuggles an eleventh containment kind into the system."""
def act(action: str, target: dict, ttl_s: int, blast_radius: str) -> dict {
    if not is_valid_kind(action) {
        raise ValueError(f"fixtures.act: {action} is not one of the ten frozen CONTAINMENT_KINDS");
    }
    return {
        "action": action,
        "target": dict(target),
        "ttl_s": ttl_s,
        "blast_radius": blast_radius
    };
}


"""A principal-scoped target (the common case: act on one user in one tenant)."""
def target_principal(h: str = "ph_abc123") -> dict {
    return {"principal_hash": h, "tenant": "tenant_acme"};
}


"""A session-scoped target. `session_ids` is deliberately unsorted at the call
site in some tests, to prove canonicalisation does its job."""
def target_session(ids: list = ["sess_9f2", "sess_1a0"]) -> dict {
    return {"principal_hash": "ph_abc123", "session_ids": list(ids)};
}


"""A source-address-scoped target, for throttle_source / block_source."""
def target_source(ips: list = ["203.0.113.44"]) -> dict {
    return {"tenant": "tenant_acme", "src_ips": list(ips)};
}


"""A feature-scoped target, for feature_readonly."""
def target_feature(f: str = "bulk_export") -> dict {
    return {"tenant": "tenant_acme", "feature": f};
}


"""A complete, schema-valid assessment.v1 for one responder.

`actions` is copied, never aliased, so a caller reusing a list across builders
cannot accidentally couple two responders' proposals together."""
def assessment(responder: str, verdict: str, confidence: float,
               actions: list = [], incident_id: str = TEST_INCIDENT) -> dict {
    return {
        "incident_id": incident_id,
        "responder": responder,
        "model": MODEL_BY_RESPONDER.get(responder, "anthropic/claude-opus-5"),
        "effort_requested": "high",
        "effort_effective": "high",
        "verdict": verdict,
        "confidence": confidence,
        "campaign_stages": [2, 3, 5],
        "recommended_actions": [dict(a) for a in actions],
        "skills_used": [dict(s) for s in DEFAULT_SKILLS],
        "rationale": f"{responder}: impossible-travel auth from a new ASN followed by bulk export on a dormant principal; scored {verdict}.",
        "usage": {"in": 4210, "out": 512, "reasoning": 128, "usd": 0.0231}
    };
}


"""Every one of the ten frozen containment kinds proposed against one target.

The raw material for the maximally-aggressive responder in the property test:
maximum breadth, widest blast, longest ttl. Least privilege has to survive this."""
def all_kinds_actions(target: dict, ttl_s: int = 86400, blast_radius: str = "broad") -> list {
    out: list = [];
    for kind in CONTAINMENT_KINDS {
        out.append(act(kind, target, ttl_s, blast_radius));
    }
    return out;
}


"""The maximally aggressive responder: certain it is malicious, wants everything,
for a day, as widely as possible — against the same target its peers are
discussing, so its proposals genuinely collide with theirs."""
def aggressive_assessment(responder: str, target: dict) -> dict {
    return assessment(responder, "malicious", 1.0, all_kinds_actions(target, 86400, "broad"));
}
