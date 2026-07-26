# incident/projection.jac — AuditEvent -> Observation, and the injection boundary.
#
# This module is the ONLY place in the detector that touches attacker-influenced
# text, and it is written so the text cannot leave. Two fields on the frozen
# AuditEvent are attacker-influenced:
#
#   actor_email  — the submitted login identifier (campaign stage 2)
#   route        — carries the request query string (campaign stages 4, 6, 8)
#
# `actor_email` is dropped: the detector already has actor_principal_id, which is
# server-assigned, so there is nothing an email can tell it that is not either
# redundant or hostile.
#
# `route` is reduced to `route_class`, a 12-hex digest of the normalized path
# TEMPLATE. Normalization strips the query string entirely and replaces every
# identifier-shaped segment with a fixed placeholder, so two requests to
# /api/tasks/tk_1 and /api/tasks/tk_2 collapse to the same class. The digest,
# not the template, is what leaves this function: downstream code can only
# compare route classes for equality and count them, which is all that
# route-transition entropy needs. There is no inverse.
#
# Anything a responder may still want to *read* is copied verbatim into a
# Quarantine record by `quarantine_of()`, tagged with a monitor-authored label,
# and is fenced by the emitter. Nothing in features/scorers/gate/stages imports
# this function.

import hashlib;
import from contracts.audit_event_contract { AuditEvent, ACTIONS, DENY_REASONS }

# Sensitivity ranks. Closed enum from the frozen contract.
glob:pub SENSITIVITY_RANK: dict = {"normal": 0, "confidential": 1, "canary": 2};

# Target kinds that require elevated authority to touch at all. Closed set drawn
# from the contract's target_kind vocabulary; membership is a property of the
# kind, never of anything the caller supplies.
glob:pub PRIVILEGED_KINDS: list = [
    "tenant", "member", "invite", "export", "auth", "token", "integration"
];

# Role rank. Used by the escalation scorer as the "required role" proxy: the
# actor's own role bounds what they may reach, so a climb in the authority level
# of what they attempt is visible as a climb in asset rank.
glob:pub ROLE_RANK: dict = {"none": 0, "viewer": 1, "member": 2, "admin": 3, "owner": 4};

# Axis of each detection family. Closed; the gate counts distinct values.
glob:pub FAMILY_AXIS: dict = {
    "denial_shape": "identity",
    "breadth":      "asset",
    "novelty":      "asset",
    "cadence":      "time",
    "pivot":        "source",
    "escalation":   "identity",
    "canary":       "asset"
};

glob:pub FAMILIES: list = [
    "denial_shape", "breadth", "novelty", "cadence", "pivot", "escalation", "canary"
];


"""True when a path segment looks like an identifier rather than a route word.

Deliberately conservative and total: it inspects only length and character
classes, never content, and cannot raise on any input."""
def _is_id_segment(seg: str) -> bool {
    if len(seg) == 0 {
        return False;
    }
    if len(seg) >= 8 {
        return True;
    }
    for ch in seg {
        if ch.isdigit() {
            return True;
        }
    }
    return False;
}


"""Collapse a raw route to an opaque route class.

The query string is discarded before anything else happens — that is where the
injection payloads live. Identifier-shaped path segments become `{id}`. The
resulting template is hashed; the template itself is never returned, so no
caller can reconstruct attacker text from a route class."""
def route_class(route: str) -> str {
    path = route.split("?")[0];
    parts = [];
    for seg in path.split("/") {
        if _is_id_segment(seg) {
            parts.append("{id}");
        } else {
            parts.append(seg);
        }
    }
    template = "/".join(parts);
    return hashlib.sha256(template.encode("utf-8")).hexdigest()[0:12];
}


"""Rank of what an attempt reaches for. Sensitivity dominates; a privileged
target kind is half a step. Enum lookups only — an unknown value ranks 0, it
never falls through to string inspection."""
def asset_rank(target_sensitivity: str, target_kind: str) -> int {
    s = int(SENSITIVITY_RANK.get(target_sensitivity, 0));
    p = 1 if target_kind in PRIVILEGED_KINDS else 0;
    return s * 2 + p;
}


"""Reject an event whose action or deny reason is outside the frozen closed
vocabulary. An unknown enum member is a contract violation upstream, and
scoring it would mean scoring a string nobody has agreed the meaning of."""
def vocabulary_ok(ev: dict) -> bool {
    if ev.get("action", "") not in ACTIONS {
        return False;
    }
    reason = ev.get("reason", "");
    if reason != "" and reason not in DENY_REASONS {
        return False;
    }
    if ev.get("outcome", "") not in ["allow", "deny", "error"] {
        return False;
    }
    return True;
}


"""Build the AuditEvent archetype from a raw record.

Kept so the frozen contract, not this module's idea of the field list, decides
what an audit event is: a field that disappears from the contract stops
compiling here."""
def audit_event_of(ev: dict) -> AuditEvent {
    return AuditEvent(
        event_id=ev.get("event_id", ""),
        schema_version=ev.get("schema_version", "1.0.0"),
        ts=ev.get("ts", ""),
        ts_ms=int(ev.get("ts_ms", 0)),
        kind=ev.get("kind", ""),
        action=ev.get("action", ""),
        outcome=ev.get("outcome", ""),
        reason=ev.get("reason", ""),
        severity=ev.get("severity", ""),
        actor_principal_id=ev.get("actor_principal_id", ""),
        actor_email=ev.get("actor_email", ""),
        actor_role=ev.get("actor_role", ""),
        auth_method=ev.get("auth_method", ""),
        session_id=ev.get("session_id", ""),
        token_id=ev.get("token_id", ""),
        tenant_id=ev.get("tenant_id", ""),
        actor_tenant_id=ev.get("actor_tenant_id", ""),
        target_kind=ev.get("target_kind", ""),
        target_id=ev.get("target_id", ""),
        parent_id=ev.get("parent_id", ""),
        target_sensitivity=ev.get("target_sensitivity", ""),
        src_ip=ev.get("src_ip", ""),
        src_asn=ev.get("src_asn", ""),
        user_agent_hash=ev.get("user_agent_hash", ""),
        client_fp=ev.get("client_fp", ""),
        request_id=ev.get("request_id", ""),
        http_method=ev.get("http_method", ""),
        route=ev.get("route", ""),
        status_code=int(ev.get("status_code", 0)),
        latency_ms=int(ev.get("latency_ms", 0)),
        req_bytes=int(ev.get("req_bytes", 0)),
        resp_bytes=int(ev.get("resp_bytes", 0)),
        result_count=int(ev.get("result_count", 0)),
        service=ev.get("service", ""),
        integration_id=ev.get("integration_id", ""),
        trace_id=ev.get("trace_id", ""),
        prev_event_id=ev.get("prev_event_id", ""),
        seq=int(ev.get("seq", 0))
    );
}


"""Project an AuditEvent onto the scoreable fields.

The returned dict is the exact field set of an Observation node: closed enums,
opaque identifiers, and numbers. `actor_email` and `route` are absent by
construction — this is the boundary."""
def project(a: AuditEvent) -> dict {
    return {
        "event_id": a.event_id,
        "ts_ms": a.ts_ms,
        "seq": a.seq,
        "kind": a.kind,
        "action": a.action,
        "outcome": a.outcome,
        "reason": a.reason,
        "severity": a.severity,
        "actor_role": a.actor_role,
        "auth_method": a.auth_method,
        "target_kind": a.target_kind,
        "target_sensitivity": a.target_sensitivity,
        "service": a.service,
        "http_method": a.http_method,
        "principal_id": a.actor_principal_id,
        "session_id": a.session_id,
        "tenant_id": a.tenant_id,
        "actor_tenant_id": a.actor_tenant_id,
        "target_id": a.target_id,
        "parent_id": a.parent_id,
        "src_ip": a.src_ip,
        "src_asn": a.src_asn,
        "client_fp": a.client_fp,
        "ua_hash": a.user_agent_hash,
        "integration_id": a.integration_id,
        "trace_id": a.trace_id,
        "route_class": route_class(a.route),
        "cross_tenant": (a.tenant_id != "" and a.actor_tenant_id != ""
                         and a.tenant_id != a.actor_tenant_id),
        "authenticated": a.actor_principal_id != "",
        "asset_rank": asset_rank(a.target_sensitivity, a.target_kind),
        "status_code": a.status_code,
        "latency_ms": a.latency_ms,
        "req_bytes": a.req_bytes,
        "resp_bytes": a.resp_bytes,
        "result_count": a.result_count
    };
}


"""Attacker-influenced text worth carrying to a human, with a monitor-authored
provenance label. Returned as records to be stored in Quarantine nodes; the
emitter fences them. Only fields whose *raw* form a responder might need to read
are included, and only when they carry something beyond the projection."""
def quarantine_of(a: AuditEvent) -> list {
    out = [];
    if a.actor_email != "" {
        out.append({"event_id": a.event_id, "label": "submitted_login_identifier",
                    "text": a.actor_email});
    }
    if "?" in a.route {
        out.append({"event_id": a.event_id, "label": "request_query_string",
                    "text": a.route});
    }
    return out;
}
