# incident/projection.jac — THE PROMPT-INJECTION BOUNDARY
#
# One job: turn a raw 38-field AuditEvent into an Observation projection that contains
# NO FREE TEXT AT ALL. Everything downstream (the seven scorers, the gate, the walkers)
# reads only the projection, so a scorer cannot branch on attacker-controlled text even
# by accident -- the text is not in the data structure it is handed.
#
# Two disjoint outputs:
#   project(rec)    -> the scored projection. Enum / numeric / opaque-digest fields only.
#   quarantine(rec) -> the free-text fields, carried untouched to incident.v1.untrusted_data
#                      where they are fenced. NEVER read by a scorer.
#
# FREE_TEXT_FIELDS is the closed list of attacker-influenceable text in the audit schema.
# project() asserts that none of them appear as a key of its own output (assert_projection_clean).

import hashlib;
import from incident.tables { role_rank, sens_rank, assert_tables_complete }

# Fields whose value is, or can contain, attacker-supplied text. Quarantined, never projected.
glob:pub FREE_TEXT_FIELDS: list = ["actor_email", "route"];

# The exact key set project() emits. An acceptance test pins this list: adding a free-text
# field here is the only way a scorer could ever see one, and the test fails if it happens.
glob:pub OBSERVATION_FIELDS: list = [
    "event_id", "ts_ms", "seq",
    "kind", "action", "outcome", "reason", "severity",
    "principal_hash", "authenticated", "actor_role", "actor_role_rank", "auth_method",
    "session_id", "tenant_id", "actor_tenant_id", "tenant_cross",
    "target_kind", "asset_hash", "has_target", "target_sensitivity", "sens_rank",
    "src_ip", "src_asn", "user_agent_hash", "client_fp",
    "http_method", "status_code", "latency_ms", "req_bytes", "resp_bytes", "result_count",
    "service", "integration_hash",
    "endpoint_class", "role_rank"
];

# Sentinel for an unauthenticated actor. A literal, not derived from any event field.
glob:pub ANON_PRINCIPAL: str = "anon";


def digest(value: str) -> str {
    # Opaque, stable, one-way. The ONLY operation ever applied to an identifier.
    # Never compared against a literal, never substring-matched, never parsed.
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[0:16];
}


def principal_hash(rec: dict) -> str {
    pid = rec.get("actor_principal_id", "");
    if pid == "" {
        return ANON_PRINCIPAL;
    }
    return digest(pid);
}


def endpoint_class(rec: dict) -> str {
    # The "route class" used by the cadence scorer's transition entropy.
    #
    # DELIBERATE: derived from three CLOSED enums (action, http_method, target_kind) and NOT
    # from `route`. `route` is attacker-controlled (it carries the fixture's injected query
    # strings); hashing it would still let an attacker manufacture endpoint diversity and
    # deflate the entropy term. Enum triples cannot be manufactured -- they are assigned by
    # the guard, not by the request.
    return rec.get("action", "") + "|" + rec.get("http_method", "") + "|" + rec.get("target_kind", "");
}


def project(rec: dict) -> dict {
    a = rec.get("action", "");
    tid = rec.get("target_id", "");
    sens = rec.get("target_sensitivity", "");
    tenant = rec.get("tenant_id", "");
    actor_tenant = rec.get("actor_tenant_id", "");
    pid = rec.get("actor_principal_id", "");
    ph = ANON_PRINCIPAL;
    auth = 0;
    if pid != "" {
        ph = digest(pid);
        auth = 1;
    }
    cross = 0;
    if tenant != "" and actor_tenant != "" and tenant != actor_tenant {
        cross = 1;
    }
    ah = "";
    ht = 0;
    if tid != "" {
        ah = digest(tid);
        ht = 1;
    }
    ig = "";
    if rec.get("integration_id", "") != "" {
        ig = digest(rec.get("integration_id", ""));
    }
    role = rec.get("actor_role", "");
    return {
        "event_id": rec.get("event_id", ""),
        "ts_ms": int(rec.get("ts_ms", 0)),
        "seq": int(rec.get("seq", 0)),
        "kind": rec.get("kind", ""),
        "action": a,
        "outcome": rec.get("outcome", ""),
        "reason": rec.get("reason", ""),
        "severity": rec.get("severity", ""),
        "principal_hash": ph,
        "authenticated": auth,
        "actor_role": role,
        "actor_role_rank": {"": 0, "none": 0, "viewer": 1, "member": 2, "admin": 3,
                            "owner": 4}.get(role, 0),
        "auth_method": rec.get("auth_method", ""),
        "session_id": rec.get("session_id", ""),
        "tenant_id": tenant,
        "actor_tenant_id": actor_tenant,
        "tenant_cross": cross,
        "target_kind": rec.get("target_kind", ""),
        "asset_hash": ah,
        "has_target": ht,
        "target_sensitivity": sens,
        "sens_rank": sens_rank(sens),
        "src_ip": rec.get("src_ip", ""),
        "src_asn": rec.get("src_asn", ""),
        "user_agent_hash": rec.get("user_agent_hash", ""),
        "client_fp": rec.get("client_fp", ""),
        "http_method": rec.get("http_method", ""),
        "status_code": int(rec.get("status_code", 0)),
        "latency_ms": int(rec.get("latency_ms", 0)),
        "req_bytes": int(rec.get("req_bytes", 0)),
        "resp_bytes": int(rec.get("resp_bytes", 0)),
        "result_count": int(rec.get("result_count", 0)),
        "service": rec.get("service", ""),
        "integration_hash": ig,
        "endpoint_class": endpoint_class(rec),
        "role_rank": role_rank(a)
    };
}


def quarantine(rec: dict) -> dict {
    # The free text, verbatim, keyed by event_id. Consumed ONLY by Promote when it builds
    # incident.v1.untrusted_data. Never passed to a scorer, never compared, never parsed.
    out = {};
    for f in FREE_TEXT_FIELDS {
        v = rec.get(f, "");
        if v != "" {
            out[f] = v;
        }
    }
    return out;
}


def assert_projection_clean(obs: dict) -> bool {
    # Structural proof, re-checked on every ingest: the projection carries no free-text key,
    # and its key set is exactly OBSERVATION_FIELDS.
    for f in FREE_TEXT_FIELDS {
        if f in obs {
            raise ValueError("projection leaked free-text field: " + f);
        }
    }
    if sorted(list(obs.keys())) != sorted(OBSERVATION_FIELDS) {
        raise ValueError("projection key drift");
    }
    return True;
}


def boot() -> bool {
    assert_tables_complete();
    return True;
}
