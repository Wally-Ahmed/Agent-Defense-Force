# app/security/audit.jac -- the single audit sink.
#
# THE EMISSION RULE (contracts/vocab.md section 3): every guard() call emits
# exactly one AuditEvent. Not zero, not two. Domain walkers emit nothing.
# emit_audit() is the one function that writes an audit record, and it is the
# only place the 38-field envelope, the severity rules, the closed vocabularies,
# and the per-session hash chain are enforced.
#
# WHY A dict, NOT 38 PARAMETERS: a 38-parameter function is unmaintainable, and
# Jac's `has` typing on walkers pushes callers toward dict payloads anyway.
# The cost of a dict is that a typo becomes a silently-dropped field, so
# emit_audit() closes that hole from both ends: unknown keys are DISCARDED
# (a caller can never inject an unlisted field into the record) and every
# emitted event is filled out to all 38 contract fields (a caller can never
# emit a partial record).
#
# WHY TWO SINKS: the JSONL file is append-only, greppable, and survives a
# process that never gets to persist its graph; the graph node is what the T4
# monitor and T6 dashboard actually traverse. They fail independently, so they
# are wrapped independently -- losing one must not silently lose the event, and
# losing both is fatal.
#
# There is no "skip audit" parameter, no sampling rate, and no debug bypass. An
# audit trail with an off switch is not an audit trail.

import json;
import os;
import uuid;
import from datetime { datetime, timezone }
import from contracts.audit_event_contract { AuditEvent, ACTIONS, DENY_REASONS }
import from app.model.graph { Platform, AuditChain, Records, get_platform }

# --------------------------------------------------------------------------
# The record shape. AUDIT_FIELDS is the frozen field order from
# contracts/audit_event_contract.jac -- exactly 38 names. It is the write order
# for the JSONL sink (json.dumps preserves insertion order; sort_keys is never
# used) and the allow-list for caller-supplied keys.
# --------------------------------------------------------------------------

glob:pub AUDIT_FIELDS: list[str] = [
    # envelope
    "event_id",
    "schema_version",
    "ts",
    "ts_ms",
    "kind",
    "action",
    "outcome",
    "reason",
    "severity",
    # identity
    "actor_principal_id",
    "actor_email",
    "actor_role",
    "auth_method",
    "session_id",
    "token_id",
    # tenancy
    "tenant_id",
    "actor_tenant_id",
    # target
    "target_kind",
    "target_id",
    "parent_id",
    "target_sensitivity",
    # source fingerprint
    "src_ip",
    "src_asn",
    "user_agent_hash",
    "client_fp",
    "request_id",
    "http_method",
    "route",
    "status_code",
    "latency_ms",
    "req_bytes",
    "resp_bytes",
    "result_count",
    # service
    "service",
    "integration_id",
    # correlation
    "trace_id",
    "prev_event_id",
    "seq"
];

# The 7 int-typed fields. Everything else on the contract is a str.
glob:pub AUDIT_INT_FIELDS: list[str] = [
    "ts_ms",
    "status_code",
    "latency_ms",
    "req_bytes",
    "resp_bytes",
    "result_count",
    "seq"
];

glob:pub SCHEMA_VERSION: str = "1.0.0";

# Closed outcome vocabulary. The contract fixes the enum in a comment; this is
# the machine-readable form emit_audit() validates against.
glob:pub OUTCOMES: list[str] = ["allow", "deny", "error"];

glob:pub DEFAULT_AUDIT_LOG: str = "var/audit/audit.jsonl";

# --------------------------------------------------------------------------
# Severity inputs (contracts/vocab.md section 4).
# --------------------------------------------------------------------------

# Deny reasons that mean "an active boundary is being tested", not "a normal
# request was refused". CTX_UNVERIFIED is handled by its own rule above these.
glob:pub HIGH_DENY_REASONS: list[str] = [
    "TENANT_MISMATCH",
    "SOURCE_BLOCKED",
    "SUSPENDED"
];

# Bulk-egress thresholds. WORKING DEFAULTS -- T4 (monitor) owns the real
# numbers and may retune these once it has traffic to calibrate against.
# An allowed action at or above either threshold is the exfiltration signal.
glob:pub BULK_RESULT_THRESHOLD: int = 500;
glob:pub BULK_BYTES_THRESHOLD: int = 1000000;

# The two egress-heavy actions get a tighter pair: a 100-row search or a 250KB
# download is already worth looking at, where 100 rows of task.list is not.
# Also working defaults, also T4's to retune.
glob:pub EGRESS_RESULT_THRESHOLD: int = 100;
glob:pub EGRESS_BYTES_THRESHOLD: int = 250000;

glob:pub EGRESS_ACTIONS: list[str] = ["export.download", "search.query"];

# notice: allowed, but security-relevant -- the events you want in the timeline
# when reconstructing an incident. Named lists, not inline magic strings.
glob:pub NOTICE_AUTH_ACTIONS: list[str] = [
    "auth.login",
    "auth.logout",
    "auth.token_issued",
    "auth.token_revoked",
    "auth.register"
];

glob:pub NOTICE_MEMBER_ACTIONS: list[str] = [
    "member.invite",
    "member.accept",
    "member.role_change",
    "member.remove"
];

glob:pub NOTICE_EGRESS_ACTIONS: list[str] = ["export.request", "export.download"];

glob:pub NOTICE_SINGLETON_ACTIONS: list[str] = ["tenant.create", "integration.call"];

# --------------------------------------------------------------------------
# Clock. Epoch milliseconds is the app-internal time unit (see
# app/model/graph.jac); the contract's `ts` is the ISO rendering of the same
# instant, so the two can never disagree.
# --------------------------------------------------------------------------

"""Current UTC time as epoch milliseconds."""
def:pub now_ms() -> int {
    return int(datetime.now(timezone.utc).timestamp() * 1000);
}

"""Render epoch milliseconds as ISO-8601 UTC with microseconds and a Z suffix."""
def:pub iso_ts(ms: int) -> str {
    return datetime.fromtimestamp(ms / 1000.0, timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ"
    );
}

# --------------------------------------------------------------------------
# Classification.
# --------------------------------------------------------------------------

"""security vs application, per the auth/containment families plus every
non-success outcome. A deny or an error is security-relevant whatever the
action was -- that is the whole point of separating the streams."""
def:pub kind_for(action: str, outcome: str) -> str {
    if outcome == "deny" or outcome == "error" {
        return "security";
    }
    if action.startswith("auth.") or action.startswith("containment.") {
        return "security";
    }
    return "application";
}

"""contracts/vocab.md section 4, verbatim: evaluated top-down, first match
wins, highest matching rule takes the event. Returns high | warn | notice | info."""
def:pub severity_for(
    action: str,
    outcome: str,
    reason: str,
    target_sensitivity: str,
    result_count: int,
    resp_bytes: int
) -> str {
    # ---- high ----------------------------------------------------------
    # A forged or replayed ctx is a direct attempt to bypass the gateway.
    if outcome == "deny" and reason == "CTX_UNVERIFIED" {
        return "high";
    }
    # An active boundary is being tested.
    if outcome == "deny" and reason in HIGH_DENY_REASONS {
        return "high";
    }
    # Canaries have no legitimate traffic; a touch is a signal, on any outcome.
    if target_sensitivity == "canary" {
        return "high";
    }
    # The system is actively defending itself.
    if action.startswith("containment.") {
        return "high";
    }
    # Bulk egress on an ALLOWED action -- the exfiltration signal.
    if outcome == "allow" {
        result_cap = BULK_RESULT_THRESHOLD;
        bytes_cap = BULK_BYTES_THRESHOLD;
        if action in EGRESS_ACTIONS {
            result_cap = EGRESS_RESULT_THRESHOLD;
            bytes_cap = EGRESS_BYTES_THRESHOLD;
        }
        if result_count >= result_cap or resp_bytes >= bytes_cap {
            return "high";
        }
    }

    # ---- warn ----------------------------------------------------------
    if outcome == "error" {
        return "warn";
    }
    if outcome == "deny" {
        return "warn";
    }

    # ---- notice --------------------------------------------------------
    if action in NOTICE_AUTH_ACTIONS {
        return "notice";
    }
    if action in NOTICE_MEMBER_ACTIONS {
        return "notice";
    }
    if action in NOTICE_EGRESS_ACTIONS {
        return "notice";
    }
    if action in NOTICE_SINGLETON_ACTIONS {
        return "notice";
    }
    if outcome == "allow" and target_sensitivity == "confidential" {
        return "notice";
    }

    # ---- info ----------------------------------------------------------
    return "info";
}

# --------------------------------------------------------------------------
# Chain state. `seq` is monotonic per chain key and `prev_event_id` points at
# the previous event on that same key, so a deleted or dropped event leaves a
# detectable hole. Unverified / unauthenticated traffic still chains, under a
# synthetic key -- a gateway-bypass attempt therefore produces an ordered,
# gap-free record instead of a pile of unrelated singletons.
# --------------------------------------------------------------------------

"""The chain a given event belongs to. Session first; anonymous traffic falls
back to the strongest source signal available."""
def chain_key_for(session_id: str, client_fp: str, src_ip: str) -> str {
    if session_id != "" {
        return "session:" + session_id;
    }
    if client_fp != "" {
        return "anon:fp:" + client_fp;
    }
    if src_ip != "" {
        return "anon:ip:" + src_ip;
    }
    return "anon:unknown";
}

"""The AuditChain node for `key`, created under the Platform on first use.

Scans the Records edge, which also carries every AuditEvent -- fine at demo
volume, and the alternative (a second edge type) would change the frozen graph
shape in app/model/graph.jac."""
def find_or_create_chain(key: str) -> AuditChain {
    p = get_platform();
    chains = [p->:Records:->][?:AuditChain];
    for c in chains {
        if c.chain_key == key {
            return c;
        }
    }
    return (p +>:Records:+> AuditChain(chain_key=key, last_event_id="", seq=0))[0];
}

"""Advance the chain: bump seq and hand back the PREVIOUS event id.

last_event_id is deliberately not updated here -- the event id it should point
at does not exist until the event is built. commit_chain() closes the link."""
def next_chain(key: str) -> dict {
    chain = find_or_create_chain(key);
    prev = chain.last_event_id;
    chain.seq = chain.seq + 1;
    return {"seq": chain.seq, "prev_event_id": prev};
}

"""Close the link: the next event on this key will chain to `event_id`."""
def commit_chain(key: str, event_id: str) -> None {
    chain = find_or_create_chain(key);
    chain.last_event_id = event_id;
}

# --------------------------------------------------------------------------
# Sinks.
# --------------------------------------------------------------------------

"""Resolved path of the append-only JSONL sink. APP_AUDIT_LOG redirects it so
tests never write into the real trail."""
def:pub audit_log_path() -> str {
    return os.environ.get("APP_AUDIT_LOG", DEFAULT_AUDIT_LOG);
}

"""Append one event as a single compact JSON line.

Keys land in AUDIT_FIELDS order because `ev` was built in that order and
json.dumps preserves insertion order -- sort_keys is never used, so a diff of
two audit lines lines up field for field."""
def write_jsonl(ev: dict) -> None {
    path = audit_log_path();
    parent = os.path.dirname(path);
    if parent != "" {
        os.makedirs(parent, exist_ok=True);
    }
    handle = open(path, "a", encoding="utf-8");
    handle.write(json.dumps(ev, separators=(",", ":")) + "\n");
    handle.flush();
    handle.close();
}

"""Attach the event to the Platform as a graph node. AuditEvent's fields are
exactly the 38 keys of `ev`, so ** constructs it directly."""
def write_graph(ev: dict) -> None {
    p = get_platform();
    p +>:Records:+> AuditEvent(**ev);
}

# --------------------------------------------------------------------------
# THE emission function.
# --------------------------------------------------------------------------

"""A fresh event: all 38 contract fields at their contract defaults, in
contract order. Every emitted event carries all 38 -- never a partial record."""
def blank_event() -> dict {
    ev = {};
    for name in AUDIT_FIELDS {
        if name in AUDIT_INT_FIELDS {
            ev[name] = 0;
        } else {
            ev[name] = "";
        }
    }
    ev["schema_version"] = SCHEMA_VERSION;
    return ev;
}

"""Emit exactly one AuditEvent to both sinks and return the complete 38-field
record.

`fields` may carry any subset of the 38 contract field names; unknown keys are
silently discarded. Raises ValueError on a closed-vocabulary violation -- that
is a bug in the caller, not a runtime condition, and it is deliberately not
swallowed."""
def:pub emit_audit(fields: dict) -> dict {
    # 1. Full envelope at contract defaults.
    ev = blank_event();

    # 2. Overlay caller values. An unlisted key is dropped on the floor: no
    #    caller gets to widen the record shape.
    for (k, v) in fields.items() {
        if k in AUDIT_FIELDS {
            ev[k] = v;
        }
    }

    # 3. Envelope fields this module owns.
    if ev["event_id"] == "" {
        ev["event_id"] = str(uuid.uuid4());
    }
    if ev["ts_ms"] == 0 {
        ev["ts_ms"] = now_ms();
    }
    ev["ts"] = iso_ts(ev["ts_ms"]);
    ev["schema_version"] = SCHEMA_VERSION;
    if ev["kind"] == "" {
        ev["kind"] = kind_for(ev["action"], ev["outcome"]);
    }
    if ev["severity"] == "" {
        ev["severity"] = severity_for(
            ev["action"],
            ev["outcome"],
            ev["reason"],
            ev["target_sensitivity"],
            ev["result_count"],
            ev["resp_bytes"]
        );
    }

    # 4. Closed-vocabulary validation. Loud programmer-error checks: an
    #    unknown action or a prose `reason` corrupts every downstream query,
    #    so it fails here rather than becoming a bad row nobody notices.
    if ev["action"] not in ACTIONS {
        bad_action = ev["action"];
        raise ValueError(
            "emit_audit: action '" + str(bad_action) + "' is not in the closed "
            + "ACTIONS vocabulary (contracts/audit_event_contract.jac)"
        );
    }
    if ev["outcome"] not in OUTCOMES {
        bad_outcome = ev["outcome"];
        raise ValueError(
            "emit_audit: outcome '" + str(bad_outcome) + "' is not one of "
            + "allow | deny | error"
        );
    }
    if ev["outcome"] == "deny" and ev["reason"] not in DENY_REASONS {
        bad_reason = ev["reason"];
        raise ValueError(
            "emit_audit: deny reason '" + str(bad_reason) + "' is not in the "
            + "closed DENY_REASONS vocabulary. `reason` is a CODE, never prose."
        );
    }
    if ev["outcome"] == "allow" {
        ev["reason"] = "";
    }

    # 5. Chain. seq strictly increments per key; prev_event_id of event N is
    #    the event_id of event N-1 on that key, "" for the first.
    key = chain_key_for(ev["session_id"], ev["client_fp"], ev["src_ip"]);
    state = next_chain(key);
    ev["seq"] = state["seq"];
    ev["prev_event_id"] = state["prev_event_id"];
    commit_chain(key, ev["event_id"]);

    # 6. Dual sink, independently wrapped. One sink down is a degraded trail
    #    and must be screamed about; both down means the event is gone, which
    #    is fatal.
    jsonl_ok = False;
    graph_ok = False;
    first_error = "";

    try {
        write_jsonl(ev);
        jsonl_ok = True;
    } except Exception as e {
        first_error = "jsonl: " + str(e);
        print("AUDIT SINK FAILURE: jsonl sink failed for event "
              + str(ev["event_id"]) + ": " + str(e));
    }

    try {
        write_graph(ev);
        graph_ok = True;
    } except Exception as e2 {
        if first_error == "" {
            first_error = "graph: " + str(e2);
        } else {
            first_error = first_error + " | graph: " + str(e2);
        }
        print("AUDIT SINK FAILURE: graph sink failed for event "
              + str(ev["event_id"]) + ": " + str(e2));
    }

    if not jsonl_ok and not graph_ok {
        raise RuntimeError(
            "AUDIT SINK FAILURE: both sinks failed, event "
            + str(ev["event_id"]) + " is LOST -- " + first_error
        );
    }

    # 7. The complete record, for the caller to report on or assert against.
    return ev;
}
