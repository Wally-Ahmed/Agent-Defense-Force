# FROZEN CONTRACT — do not edit without conductor approval. Consumed by: T1 gateway, T2 guard/authz, T3 domain walkers, T4 monitor/detection, T5 responder/containment, T6 dashboard
#
# IMPORT AS:
#   import from contracts.audit_event_contract { AuditEvent, ACTIONS, DENY_REASONS }
#
# The mandated path `contracts/audit_event_contract.jac` is a SYMLINK ALIAS to this
# file. Jac resolves imports through Python module paths, so a filename containing a
# dot (`audit_event_contract.jac`) is NOT importable — it parses as package
# `audit_event`, module `contract`. The undotted `audit_event_contract.jac` is
# therefore the real module. Identical content; always import the undotted name.
#
# The single audit record. Every guard() call emits exactly one AuditEvent.
# Domain walkers emit NO second event. See contracts/vocab.md for the emission
# map and severity assignment rules.
#
# NOTE ON DEFAULTS: every field carries a default. This is forced by Jac
# error[E2004] ("non default attribute follows default attribute") — the frozen
# field order puts `schema_version = "1.0.0"` at position 2, so every field after
# it must also be defaulted. Field ORDER below is exactly as specified. Treat the
# defaults as "unset" sentinels, not as valid values: emitters are expected to
# populate every field.

node AuditEvent {
    # --- envelope ---
    has event_id: str = "";               # uuid4
    has schema_version: str = "1.0.0";
    has ts: str = "";                     # ISO-8601 UTC, microseconds, "Z"
    has ts_ms: int = 0;                   # epoch millis
    has kind: str = "";                   # security | application
    has action: str = "";                 # one of ACTIONS
    has outcome: str = "";                # allow | deny | error
    has reason: str = "";                 # deny reason CODE (one of DENY_REASONS), "" when allow
    has severity: str = "";               # info | notice | warn | high

    # --- identity ---
    has actor_principal_id: str = "";     # "" when unauthenticated
    has actor_email: str = "";
    has actor_role: str = "";             # owner | admin | member | viewer | none
    has auth_method: str = "";            # password | session | api_token | none
    has session_id: str = "";
    has token_id: str = "";               # jti

    # --- tenancy ---
    has tenant_id: str = "";              # tenant the ACTION targeted
    has actor_tenant_id: str = "";        # tenant the ACTOR belongs to — mismatch means crossing

    # --- target ---
    has target_kind: str = "";            # tenant | project | task | comment | member | invite | export | auth | token | integration
    has target_id: str = "";
    has parent_id: str = "";              # "" if n/a
    has target_sensitivity: str = "";     # normal | confidential | canary

    # --- source fingerprint ---
    has src_ip: str = "";
    has src_asn: str = "";
    has user_agent_hash: str = "";        # sha256(ua)[:16]
    has client_fp: str = "";              # sha256(ua|accept-lang|accept-enc|tls_ja3)[:16]
    has request_id: str = "";
    has http_method: str = "";
    has route: str = "";
    has status_code: int = 0;
    has latency_ms: int = 0;
    has req_bytes: int = 0;
    has resp_bytes: int = 0;
    has result_count: int = 0;            # rows returned — the exfiltration signal

    # --- service ---
    has service: str = "";                # web | api | export | integration | scheduler
    has integration_id: str = "";

    # --- correlation ---
    has trace_id: str = "";
    has prev_event_id: str = "";          # previous event in same session
    has seq: int = 0;                     # monotonic per session
}

# Closed action vocabulary. Import this — do not retype the strings.
glob:pub ACTIONS: list[str] = [
    "auth.register",
    "auth.login",
    "auth.login_failed",
    "auth.logout",
    "auth.session_expired",
    "auth.token_issued",
    "auth.token_revoked",
    "auth.reauth_required",
    "tenant.create",
    "tenant.read",
    "member.invite",
    "member.accept",
    "member.role_change",
    "member.remove",
    "project.create",
    "project.read",
    "project.list",
    "project.update",
    "project.delete",
    "task.create",
    "task.read",
    "task.list",
    "task.update",
    "task.delete",
    "task.assign",
    "comment.create",
    "comment.read",
    "comment.list",
    "comment.delete",
    "export.request",
    "export.download",
    "search.query",
    "integration.call",
    "containment.propose",
    "containment.apply",
    "containment.verify",
    "containment.expire",
    "containment.rollback"
];

# Closed deny-reason enum. `AuditEvent.reason` is one of these, or "" when allow.
glob:pub DENY_REASONS: list[str] = [
    "NO_SESSION",
    "SESSION_EXPIRED",
    "TOKEN_REVOKED",
    "NOT_A_MEMBER",
    "INSUFFICIENT_ROLE",
    "TENANT_MISMATCH",
    "NOT_FOUND",
    "VALIDATION_FAILED",
    "RATE_LIMITED",
    "CSRF_INVALID",
    "SUSPENDED",
    "SOURCE_BLOCKED",
    "REAUTH_REQUIRED",
    "READONLY_MODE",
    "CTX_UNVERIFIED"
];
