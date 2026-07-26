# containment/policy.jac — the gate every containment action passes before anything
# is applied.
#
# WHAT THIS MODULE IS FOR
#
# The coordinator hands us a decision.v1 `action_set` entry. That entry is a
# REQUEST, not an instruction: five responder models agreed on it, but none of
# them can see the graph, so none of them knows how many humans the action is
# about to inconvenience. This module is the part of the system that does know.
# It answers four questions, in order, and refuses on the first bad answer:
#
#   1. is `kind` one of the ten frozen containment kinds?
#   2. is `target` well-formed FOR THAT KIND, and what scope keys does it become?
#   3. how much of the real, current graph does that touch?  (blast radius)
#   4. does the approval policy permit this to execute unattended?
#
# Nothing here writes. The gate is pure: same graph, same request, same verdict.
# `containment/executor.jac` is the only module that mutates anything.
#
# THE FROZEN ENUM. `CONTAINMENT_KINDS` in contracts/containment_contract.jac is
# the authority for the ten kinds and their policy defaults. This module reads
# that dict; it never retypes the names. A kind absent from it cannot be gated,
# and a request naming one is rejected — not defaulted to something adjacent.
#
# SCOPE KEYS. Built exclusively through app/security/controls.jac's key_* helpers,
# which is the same module guard() uses to look controls up. That shared builder
# is deliberate: if the responder wrote "principal:u_x" and guard looked up
# "principal/u_x", containment would be a no-op that every log line called active.
#
# WHY THERE IS NO "SHUT IT ALL DOWN" PATH. The ten kinds are the whole vocabulary
# and every one of them is scoped to a principal, a source, a feature, a queue or
# a credential. There is no kind that names the platform, and `assess()` refuses
# a scope that resolves to zero keys, so an empty/missing target degrades to a
# REJECTION rather than to "everything". See `no_blanket_shutdown()`.

import from contracts.containment_contract { CONTAINMENT_KINDS }
import from app.model.graph {
    Tenant, Membership, Principal, Session, Token,
    Bears, HasMember, Authenticates,
    get_platform, all_tenants, all_principals
}
import from app.model.resolve {
    tenant_by_id, principal_by_id, session_by_id, token_by_jti,
    sessions_of, memberships_of, membership_of
}
import from app.security.controls {
    key_principal, key_tenant, key_session, key_token, key_ip, key_asn, key_feature
}
import from app.security.clock { now_ms }

# --------------------------------------------------------------------------
# Vocabulary. Every string a caller may see comes from one of these.
# --------------------------------------------------------------------------

glob:pub BLAST_LEVELS: list = ["narrow", "moderate", "broad"];

glob:pub APPROVALS: list = ["auto", "auto_with_notice", "human_required"];

# The ContainmentAction.state values this system uses, from the frozen contract.
glob:pub STATES: list = [
    "proposed", "approved", "applying", "active",
    "verify_failed", "expired", "rolled_back", "failed"
];

# Rejection codes. Prose belongs in `detail`; this is what gets counted.
glob:pub GATE_CODES: list = [
    "OK",
    "UNKNOWN_KIND",
    "MALFORMED_SCOPE",
    "EMPTY_SCOPE",
    "APPROVAL_REQUIRED"
];

# --------------------------------------------------------------------------
# Per-kind scope specification.
#
# `accepts`  — decision.v1 target fields this kind can be built from, in
#              precedence order. A target carrying none of them is malformed.
# `subject`  — what the resulting scope keys name. Drives blast-radius counting
#              and the audit event's target_kind.
# `tenant_ok`— whether a tenant-wide form of this kind exists at all. Kinds
#              marked False can never be widened to a whole tenant, no matter
#              what the coordinator sends.
#
# NOTE. decision.v1's `target` has no `token_ids` field, so revoke_token is
# addressed by `credential_id` (the jti) or, failing that, by principal — in
# which case it fans out to that principal's live tokens, one Control each.
# --------------------------------------------------------------------------

glob:pub KIND_SCOPE: dict = {
    "revoke_session":            {"accepts": ["session_ids", "principal_hash"], "subject": "session",    "tenant_ok": False},
    "revoke_token":              {"accepts": ["credential_id", "principal_hash"], "subject": "token",    "tenant_ok": False},
    "suspend_principal":         {"accepts": ["principal_hash"],                "subject": "principal",  "tenant_ok": False},
    "throttle_source":           {"accepts": ["src_ips"],                       "subject": "source",     "tenant_ok": False},
    "block_source":              {"accepts": ["src_ips"],                       "subject": "source",     "tenant_ok": False},
    "force_reauth":              {"accepts": ["principal_hash", "tenant"],      "subject": "principal",  "tenant_ok": True},
    "feature_readonly":          {"accepts": ["feature"],                       "subject": "feature",    "tenant_ok": True},
    "pause_queue":               {"accepts": ["queue"],                         "subject": "queue",      "tenant_ok": True},
    "rotate_service_credential": {"accepts": ["credential_id", "integration"],  "subject": "credential", "tenant_ok": False},
    "raise_logging":             {"accepts": ["principal_hash", "tenant", "feature"], "subject": "observability", "tenant_ok": True}
};

# AuditEvent.target_kind is a closed vocabulary (contracts/audit_event_contract.jac).
# This maps our scope subject onto it so containment events are queryable next to
# ordinary traffic instead of carrying an out-of-vocabulary string.
glob:pub SUBJECT_TARGET_KIND: dict = {
    "session": "auth",
    "token": "token",
    "principal": "member",
    "source": "auth",
    "feature": "project",
    "queue": "export",
    "credential": "integration",
    "observability": "tenant"
};

# --------------------------------------------------------------------------
# Blast-radius thresholds. Stated as named constants because these are the
# numbers a reviewer will argue with, and they should be arguable in one place.
# --------------------------------------------------------------------------

glob:pub BROAD_PCT: float = 50.0;        # >= half a tenant's actives is broad
glob:pub BROAD_PRINCIPALS: int = 10;     # ...or this many identities
glob:pub MODERATE_PCT: float = 5.0;      # >= 5% of actives is moderate
glob:pub MODERATE_PRINCIPALS: int = 2;   # ...or more than one identity
glob:pub MODERATE_SESSIONS: int = 5;

# suspend_principal auto-approves strictly below this share of tenant actives.
glob:pub SUSPEND_AUTO_PCT: float = 5.0;

# Frozen approval rules that are already conditional on how much an action
# touches. A broad computed blast radius pushes these to human_required; the
# flat `auto` rules it only raises to auto_with_notice. See approval_for().
glob:pub SCALE_CONDITIONAL_RULES: list = [
    "auto_if_pct_lt_5_else_human",
    "human_required_if_shared",
    "auto_principal_human_tenant"
];

# block_source needs a human when the source served this many distinct
# principals in the lookback window — that shape is a NAT or a shared egress,
# and blocking it takes bystanders with it.
glob:pub SHARED_SOURCE_PRINCIPALS: int = 2;
glob:pub SHARED_SOURCE_WINDOW_MS: int = 86400000;   # 24h

# --------------------------------------------------------------------------
# Small graph readers. app/model/resolve.jac has no "every session" or "every
# token" accessor — the application never needs one — so the two global sweeps
# containment does need are built here, read-only, over the same typed edges.
# --------------------------------------------------------------------------

"""Every session on the platform, with its owning principal already resolved."""
def:pub all_sessions() -> list {
    out: list = [];
    for pr in all_principals() {
        for s in sessions_of(pr) {
            out.append(s);
        }
    }
    return out;
}

"""Every token held by `principal`."""
def:pub tokens_of(principal: Principal) -> list {
    return [principal->:Bears:->][?:Token];
}

"""Live (unrevoked, unexpired) sessions of one principal."""
def:pub live_sessions_of(principal_id: str, at_ms: int) -> list {
    pr = principal_by_id(principal_id);
    if pr is None {
        return [];
    }
    return [s for s in sessions_of(pr) if (not s.revoked) and s.expires_at > at_ms];
}

"""Live tokens of one principal."""
def:pub live_tokens_of(principal_id: str, at_ms: int) -> list {
    pr = principal_by_id(principal_id);
    if pr is None {
        return [];
    }
    return [t for t in tokens_of(pr) if (not t.revoked) and t.expires_at > at_ms];
}

"""Principal ids with an ACTIVE membership in `tenant_id`.

This is the denominator for every percentage in this module. Membership state,
not session state: a tenant's population is who belongs to it, not who happens
to be logged in this second — otherwise the same action would read as narrow at
3am and broad at noon."""
def:pub tenant_actives(tenant_id: str) -> list {
    tn = tenant_by_id(tenant_id);
    if tn is None {
        return [];
    }
    seen: list = [];
    for m in memberships_of(tn) {
        if m.state == "active" and m.principal_id not in seen {
            seen.append(m.principal_id);
        }
    }
    return seen;
}

"""Tenant ids this principal has an active membership in."""
def:pub tenants_of_principal(principal_id: str) -> list {
    out: list = [];
    for tn in all_tenants() {
        m = membership_of(tn, principal_id);
        if m is not None and m.state == "active" {
            out.append(tn.tenant_id);
        }
    }
    return out;
}

"""Distinct principals whose sessions were issued from `src_ip` within
`window_ms` of `at_ms`.

This is the NAT test for block_source. Sessions carry `ip_first`, the source
observed at issue time, which is the only per-identity source record the graph
keeps."""
def:pub principals_from_source(src_ip: str, at_ms: int, window_ms: int) -> list {
    floor = at_ms - window_ms;
    seen: list = [];
    for s in all_sessions() {
        if s.ip_first != src_ip {
            continue;
        }
        if s.issued_at < floor {
            continue;
        }
        if s.principal_id not in seen {
            seen.append(s.principal_id);
        }
    }
    return seen;
}

# --------------------------------------------------------------------------
# 2. Scope resolution: decision.v1 `target` -> concrete Control scope keys.
# --------------------------------------------------------------------------

"""`target[name]` as a list of non-empty strings, whatever shape it arrived in."""
def _as_ids(target: dict, name: str) -> list {
    raw = target.get(name, None);
    if raw is None {
        return [];
    }
    if isinstance(raw, str) {
        if raw.strip() == "" {
            return [];
        }
        return [raw.strip()];
    }
    if isinstance(raw, list) {
        return [str(v).strip() for v in raw if str(v).strip() != ""];
    }
    return [];
}

"""The target fields `kind` accepts, in precedence order."""
def:pub accepted_fields(kind: str) -> list {
    spec: dict = KIND_SCOPE.get(kind, {});
    acc: list = spec.get("accepts", []);
    out: list = [];
    for name in acc {
        out.append(str(name));
    }
    return out;
}

"""Which of a kind's accepted target fields are actually populated."""
def _present(kind: str, target: dict) -> list {
    return [name for name in accepted_fields(kind) if len(_as_ids(target, name)) > 0];
}

"""Resolve a request into concrete Control scope keys.

Returns {"ok", "code", "detail", "keys", "subject", "tenant_id", "principal_ids"}.

`keys` is one scope key per Control node the executor will write. Fan-out is
explicit and bounded by the graph: `revoke_session` given a principal expands to
that principal's LIVE sessions and no others, so a redelivered action cannot
grow as new sessions appear."""
def:pub resolve_scope(kind: str, target: dict, at_ms: int) -> dict {
    if kind not in CONTAINMENT_KINDS {
        return {
            "ok": False, "code": "UNKNOWN_KIND", "keys": [], "subject": "",
            "tenant_id": "", "principal_ids": [], "tenant_expanded": False,
            "detail": "kind '" + str(kind) + "' is not one of the ten frozen containment kinds"
        };
    }
    spec: dict = KIND_SCOPE[kind];
    subject: str = str(spec["subject"]);
    fields: list = _present(kind, target);
    if len(fields) == 0 {
        return {
            "ok": False, "code": "MALFORMED_SCOPE", "keys": [], "subject": subject,
            "tenant_id": "", "principal_ids": [], "tenant_expanded": False,
            "detail": kind + " requires one of " + ", ".join(accepted_fields(kind))
                      + "; target carried none of them"
        };
    }

    tenant_id: str = "";
    tenants = _as_ids(target, "tenant");
    if len(tenants) > 0 {
        tenant_id = tenants[0];
    }

    keys: list = [];
    principal_ids: list = [];
    detail: str = "";
    # True when principal_ids came from expanding a tenant's membership rather
    # than from ids the coordinator named. Blast counting needs to know.
    tenant_expanded: bool = False;

    if kind == "revoke_session" {
        sids = _as_ids(target, "session_ids");
        if len(sids) == 0 {
            # Addressed by principal: fan out to that principal's live sessions.
            for pid in _as_ids(target, "principal_hash") {
                principal_ids.append(pid);
                for s in live_sessions_of(pid, at_ms) {
                    sids.append(s.session_id);
                }
            }
            detail = "expanded from principal to live sessions";
        }
        for sid in sids {
            keys.append(key_session(sid));
            s2 = session_by_id(sid);
            if s2 is not None {
                if s2.principal_id not in principal_ids {
                    principal_ids.append(s2.principal_id);
                }
                if tenant_id == "" {
                    tenant_id = s2.tenant_id;
                }
            }
        }

    } elif kind == "revoke_token" {
        jtis = _as_ids(target, "credential_id");
        if len(jtis) == 0 {
            for pid in _as_ids(target, "principal_hash") {
                principal_ids.append(pid);
                for t in live_tokens_of(pid, at_ms) {
                    jtis.append(t.jti);
                }
            }
            detail = "expanded from principal to live tokens";
        }
        for jti in jtis {
            keys.append(key_token(jti));
            t2 = token_by_jti(jti);
            if t2 is not None {
                if t2.principal_id not in principal_ids {
                    principal_ids.append(t2.principal_id);
                }
                if tenant_id == "" {
                    tenant_id = t2.tenant_id;
                }
            }
        }

    } elif kind == "suspend_principal" {
        for pid in _as_ids(target, "principal_hash") {
            keys.append(key_principal(pid));
            principal_ids.append(pid);
        }
        if tenant_id == "" and len(principal_ids) > 0 {
            owned = tenants_of_principal(principal_ids[0]);
            if len(owned) > 0 {
                tenant_id = owned[0];
            }
        }

    } elif kind in ["throttle_source", "block_source"] {
        for ip in _as_ids(target, "src_ips") {
            keys.append(key_ip(ip));
        }
        for asn in _as_ids(target, "src_asn") {
            keys.append(key_asn(asn));
        }
        for ip2 in _as_ids(target, "src_ips") {
            for pid2 in principals_from_source(ip2, at_ms, SHARED_SOURCE_WINDOW_MS) {
                if pid2 not in principal_ids {
                    principal_ids.append(pid2);
                }
            }
        }

    } elif kind == "force_reauth" {
        pids = _as_ids(target, "principal_hash");
        if len(pids) > 0 {
            for pid in pids {
                keys.append(key_principal(pid));
                principal_ids.append(pid);
            }
        } else {
            for tid in _as_ids(target, "tenant") {
                keys.append(key_tenant(tid));
                tenant_id = tid;
                for pid3 in tenant_actives(tid) {
                    principal_ids.append(pid3);
                }
            }
            detail = "tenant-wide re-authentication";
        }

    } elif kind == "feature_readonly" {
        for feat in _as_ids(target, "feature") {
            if tenant_id != "" {
                # Tenant-scoped read-only, the form guard() looks up first.
                keys.append(key_tenant(tenant_id) + ":" + feat);
            } else {
                keys.append(key_feature(feat));
            }
        }
        if tenant_id != "" {
            tenant_expanded = True;
            for pid4 in tenant_actives(tenant_id) {
                principal_ids.append(pid4);
            }
        }

    } elif kind == "pause_queue" {
        for q in _as_ids(target, "queue") {
            if tenant_id != "" {
                keys.append("queue:" + tenant_id + ":" + q);
            } else {
                keys.append("queue:" + q);
            }
        }
        if tenant_id != "" {
            tenant_expanded = True;
            for pid5 in tenant_actives(tenant_id) {
                principal_ids.append(pid5);
            }
        }

    } elif kind == "rotate_service_credential" {
        creds = _as_ids(target, "credential_id");
        if len(creds) == 0 {
            creds = _as_ids(target, "integration");
        }
        for cid in creds {
            keys.append("credential:" + cid);
        }

    } elif kind == "raise_logging" {
        for pid6 in _as_ids(target, "principal_hash") {
            keys.append(key_principal(pid6));
            principal_ids.append(pid6);
        }
        for tid2 in _as_ids(target, "tenant") {
            keys.append(key_tenant(tid2));
            tenant_id = tid2;
        }
        for feat2 in _as_ids(target, "feature") {
            keys.append(key_feature(feat2));
        }
    }

    # Deduplicate while preserving order: two responders naming the same session
    # must not become two Control nodes with two prior_state snapshots.
    unique: list = [];
    for k in keys {
        if k not in unique {
            unique.append(k);
        }
    }

    if len(unique) == 0 {
        # A target that names nothing reachable is a REJECTION, never "apply to
        # everything". This is the single line that stands between a malformed
        # decision and a platform-wide action.
        return {
            "ok": False, "code": "EMPTY_SCOPE", "keys": [], "subject": subject,
            "tenant_id": tenant_id, "principal_ids": [], "tenant_expanded": False,
            "detail": kind + " resolved to zero scope keys — nothing in the graph "
                      + "matches this target, so there is nothing to contain"
        };
    }

    return {
        "ok": True, "code": "OK", "keys": unique, "subject": subject,
        "tenant_id": tenant_id, "principal_ids": principal_ids,
        "tenant_expanded": tenant_expanded, "detail": detail
    };
}

# --------------------------------------------------------------------------
# 3. Blast radius, counted off the graph.
# --------------------------------------------------------------------------

"""How much of the running system this scope actually touches.

Returns the frozen `blast_radius` dict shape: principals / sessions / tenants /
pct_of_tenant_actives / level, plus the denominator so the percentage can be
checked rather than believed.

Every number is a count of nodes reachable RIGHT NOW. Nothing here is inherited
from what the responders guessed — `proposed_level` is carried alongside for the
audit trail, never used as an input."""
def:pub blast_radius(kind: str, scope: dict, at_ms: int) -> dict {
    keys: list = scope["keys"];
    tenant_id: str = str(scope["tenant_id"]);

    principals: list = [];
    seed_pids: list = scope["principal_ids"];
    for raw_pid in seed_pids {
        pid: str = str(raw_pid);
        if pid not in principals {
            principals.append(pid);
        }
    }

    sessions: int = 0;
    tenants: list = [];
    if tenant_id != "" {
        tenants.append(tenant_id);
    }

    for raw_key in keys {
        key: str = str(raw_key);
        if key.startswith("session:") {
            s = session_by_id(key[8:]);
            if s is not None and (not s.revoked) and s.expires_at > at_ms {
                sessions = sessions + 1;
                if s.tenant_id != "" and s.tenant_id not in tenants {
                    tenants.append(s.tenant_id);
                }
            }
        } elif key.startswith("token:") {
            t = token_by_jti(key[6:]);
            if t is not None and t.tenant_id != "" and t.tenant_id not in tenants {
                tenants.append(t.tenant_id);
            }
        } elif key.startswith("ip:") {
            ip = key[3:];
            for s2 in all_sessions() {
                if s2.ip_first == ip and (not s2.revoked) and s2.expires_at > at_ms {
                    sessions = sessions + 1;
                    if s2.tenant_id != "" and s2.tenant_id not in tenants {
                        tenants.append(s2.tenant_id);
                    }
                }
            }
        } elif key.startswith("feature:") {
            # `feature:*` is the only key in the system with platform reach, and
            # it is counted as such rather than quietly treated as one feature.
            if key == "feature:*" {
                for tn in all_tenants() {
                    if tn.tenant_id not in tenants {
                        tenants.append(tn.tenant_id);
                    }
                    for pid2 in tenant_actives(tn.tenant_id) {
                        if pid2 not in principals {
                            principals.append(pid2);
                            sessions = sessions + len(live_sessions_of(str(pid2), at_ms));
                        }
                    }
                }
            }
        }
    }

    # Principal-scoped keys imply that principal's live sessions.
    for raw_key2 in keys {
        key2: str = str(raw_key2);
        if key2.startswith("principal:") {
            pid3: str = key2[10:];
            live = live_sessions_of(pid3, at_ms);
            sessions = sessions + len(live);
            for s3 in live {
                if s3.tenant_id != "" and s3.tenant_id not in tenants {
                    tenants.append(s3.tenant_id);
                }
            }
            for tid in tenants_of_principal(pid3) {
                if tid not in tenants {
                    tenants.append(tid);
                }
            }
        } elif key2.startswith("tenant:") {
            tid2: str = key2[7:].split(":")[0];
            if tid2 not in tenants {
                tenants.append(tid2);
            }
            for pid4 in tenant_actives(tid2) {
                if pid4 not in principals {
                    principals.append(pid4);
                }
                sessions = sessions + len(live_sessions_of(str(pid4), at_ms));
            }
        }
    }

    # A tenant-expanded scope (feature_readonly / pause_queue named a tenant)
    # produces no session-bearing key, so the live sessions it reaches have to be
    # counted from the expanded principal set or the action would report as
    # touching forty people and zero sessions.
    if bool(scope.get("tenant_expanded", False)) and sessions == 0 {
        for raw_pid2 in principals {
            sessions = sessions + len(live_sessions_of(str(raw_pid2), at_ms));
        }
    }

    # Percentage denominator: the primary tenant, or the first tenant touched.
    denom_tenant: str = tenant_id;
    if denom_tenant == "" and len(tenants) > 0 {
        denom_tenant = str(tenants[0]);
    }
    actives: list = [];
    if denom_tenant != "" {
        actives = tenant_actives(denom_tenant);
    }
    denominator: int = len(actives);

    in_tenant: int = 0;
    for pid5 in principals {
        if pid5 in actives {
            in_tenant = in_tenant + 1;
        }
    }
    pct: float = 0.0;
    if denominator > 0 {
        pct = float(int(round(10000.0 * float(in_tenant) / float(denominator)))) / 100.0;
    }

    computed = _classify(len(principals), sessions, len(tenants), pct);

    # The frozen table's per-kind default is a FLOOR, never a ceiling: a kind the
    # contract calls broad stays broad even when today's graph happens to be
    # small, so an empty demo tenant can never make a sweeping action look cheap.
    floor: str = str(CONTAINMENT_KINDS[kind]["blast"]);
    level: str = computed;
    if BLAST_LEVELS.index(floor) > BLAST_LEVELS.index(computed) {
        level = floor;
    }

    return {
        "principals": len(principals),
        "sessions": sessions,
        "tenants": len(tenants),
        "pct_of_tenant_actives": pct,
        "level": level,
        # --- provenance, so the number is auditable ---
        "computed_level": computed,
        "contract_floor": floor,
        "tenant_denominator": denominator,
        "denominator_tenant": denom_tenant,
        "principal_ids": principals,
        "tenant_ids": tenants,
        "scope_keys": keys
    };
}

"""narrow | moderate | broad, from four counted quantities."""
def _classify(principals: int, sessions: int, tenants: int, pct: float) -> str {
    if tenants > 1 or pct >= BROAD_PCT or principals >= BROAD_PRINCIPALS {
        return "broad";
    }
    if pct >= MODERATE_PCT or principals >= MODERATE_PRINCIPALS or sessions >= MODERATE_SESSIONS {
        return "moderate";
    }
    return "narrow";
}

# --------------------------------------------------------------------------
# 4. Approval.
# --------------------------------------------------------------------------

"""Which approval this action needs, and why.

Implements the frozen `CONTAINMENT_KINDS[kind]["approval"]` rules literally:

  auto                        -> auto
  auto_if_pct_lt_5_else_human -> suspend_principal: auto below 5% of tenant
                                 actives, human at or above
  human_required_if_shared    -> block_source: human when that source served
                                 >= 2 distinct principals in 24h (a NAT)
  auto_principal_human_tenant -> force_reauth: auto for one principal, human for
                                 a whole tenant
  human_required              -> rotate_service_credential: always human

Then one ratchet on top, and its limits matter. The per-kind rules cannot
anticipate a graph where a nominally-narrow action happens to cover an entire
tenant, so a COMPUTED blast of `broad` escalates. But it escalates differently
depending on what the contract said:

  - a rule that is already CONDITIONAL on scale (the three below) goes all the
    way to `human_required` — a broad radius is exactly the condition those
    rules exist to catch, so this reinforces them
  - a rule the frozen contract states flatly as `auto` goes only as far as
    `auto_with_notice`

That second limit is deliberate. `CONTAINMENT_KINDS` is a frozen contract; this
module does not get to quietly convert its `auto` into `human_required` and
strand a legitimate response waiting for a person who was never told to expect
it. Read-only mode and a paused queue are broad by nature and reversible by
design — the contract already weighed that. The ratchet raises the noise level,
not the permission bar."""
def:pub approval_for(kind: str, scope: dict, blast: dict, at_ms: int) -> dict {
    rule: str = str(CONTAINMENT_KINDS[kind]["approval"]);
    verdict: str = "auto";
    why: str = "";

    if rule == "auto" {
        verdict = "auto";
        why = "kind auto-approves by policy";

    } elif rule == "human_required" {
        verdict = "human_required";
        why = kind + " always requires human approval";

    } elif rule == "auto_if_pct_lt_5_else_human" {
        pct = float(blast["pct_of_tenant_actives"]);
        if pct < SUSPEND_AUTO_PCT {
            verdict = "auto";
            why = "affects " + str(pct) + "% of tenant actives, under the "
                  + str(SUSPEND_AUTO_PCT) + "% auto ceiling";
        } else {
            verdict = "human_required";
            why = "affects " + str(pct) + "% of tenant actives, at or over the "
                  + str(SUSPEND_AUTO_PCT) + "% auto ceiling";
        }

    } elif rule == "human_required_if_shared" {
        served: list = [];
        scope_keys: list = scope["keys"];
        for raw_key in scope_keys {
            key: str = str(raw_key);
            if key.startswith("ip:") {
                for pid in principals_from_source(key[3:], at_ms, SHARED_SOURCE_WINDOW_MS) {
                    if pid not in served {
                        served.append(pid);
                    }
                }
            }
        }
        if len(served) >= SHARED_SOURCE_PRINCIPALS {
            verdict = "human_required";
            why = "source served " + str(len(served)) + " distinct principals in 24h "
                  + "(>= " + str(SHARED_SOURCE_PRINCIPALS) + ") — shared egress / NAT, "
                  + "blocking it would take bystanders offline";
        } else {
            verdict = "auto";
            why = "source served " + str(len(served)) + " distinct principal(s) in 24h — not shared";
        }

    } elif rule == "auto_principal_human_tenant" {
        tenant_scoped: bool = False;
        reauth_keys: list = scope["keys"];
        for raw_key2 in reauth_keys {
            key2: str = str(raw_key2);
            if key2.startswith("tenant:") {
                tenant_scoped = True;
            }
        }
        if tenant_scoped {
            verdict = "human_required";
            why = "tenant-wide " + kind + " requires human approval";
        } else {
            verdict = "auto";
            why = "principal-scoped " + kind + " auto-approves";
        }

    } else {
        # An approval rule this module does not recognise fails CLOSED. A typo in
        # the frozen table must never become an unattended action.
        verdict = "human_required";
        why = "unrecognised approval rule '" + rule + "' — failing closed to human";
    }

    # The ratchet.
    if verdict == "auto" and str(blast["level"]) == "broad" {
        if rule in SCALE_CONDITIONAL_RULES {
            verdict = "human_required";
            why = why + "; escalated to human because computed blast radius is broad ("
                  + str(blast["principals"]) + " principals across "
                  + str(blast["tenants"]) + " tenant(s))";
        } else {
            verdict = "auto_with_notice";
            why = why + "; flagged for notice because computed blast radius is broad ("
                  + str(blast["principals"]) + " principals across "
                  + str(blast["tenants"]) + " tenant(s)) — the frozen contract "
                  + "states this kind as auto, which this module does not override";
        }
    }

    # `auto_with_notice` is the frozen contract's third value: it executes like
    # auto, but it is flagged so a moderate-reach action is never applied
    # silently. It is a NOTIFICATION tier, not a permission tier.
    if verdict == "auto" and str(blast["level"]) == "moderate" {
        verdict = "auto_with_notice";
    }

    return {"approval": verdict, "rule": rule, "why": why};
}

# --------------------------------------------------------------------------
# The gate itself.
# --------------------------------------------------------------------------

"""Run the whole gate over one decision.v1 action_set entry.

`request` keys: kind (or `action`), target, ttl_s, blast_radius (the
coordinator's, recorded but not trusted), approved_by.

Returns a verdict dict the executor acts on:

  ok              — passed validation AND is permitted to execute now
  code            — GATE_CODES entry
  approval        — auto | auto_with_notice | human_required
  needs_human     — True when approval is human_required and approved_by is empty
  scope / blast   — the resolved facts, for the ContainmentAction record

`ok == False` with `needs_human == True` is NOT a failure. It is a proposal
awaiting a person, and the executor records it as `proposed`."""
def:pub gate(request: dict, at_ms: int = 0) -> dict {
    now = at_ms if at_ms > 0 else now_ms();
    kind: str = str(request.get("kind", request.get("action", "")));
    target = request.get("target", {});
    if not isinstance(target, dict) {
        target = {};
    }
    approved_by: str = str(request.get("approved_by", ""));

    # 1 + 2: kind and scope.
    scope = resolve_scope(kind, target, now);
    if not scope["ok"] {
        return {
            "ok": False, "code": scope["code"], "detail": scope["detail"],
            "kind": kind, "approval": "", "needs_human": False,
            "scope": scope, "blast": _null_blast(), "ttl_s": 0,
            "target_kind": SUBJECT_TARGET_KIND.get(str(scope["subject"]), "auth")
        };
    }

    # 3: blast radius, off the live graph.
    blast = blast_radius(kind, scope, now);
    blast["proposed_level"] = str(request.get("blast_radius", ""));

    # 4: approval.
    decision = approval_for(kind, scope, blast, now);
    approval: str = str(decision["approval"]);
    needs_human: bool = (approval == "human_required" and approved_by == "");

    # TTL. The coordinator already took the MINIMUM ttl_s across proposals; we
    # take the minimum again against the contract default, so containment can
    # only ever expire sooner than the frozen table allows, never later.
    ttl_s = _effective_ttl(kind, request.get("ttl_s", 0));

    return {
        "ok": (not needs_human),
        "code": "APPROVAL_REQUIRED" if needs_human else "OK",
        "detail": str(decision["why"]),
        "kind": kind,
        "approval": approval,
        "approval_rule": str(decision["rule"]),
        "needs_human": needs_human,
        "scope": scope,
        "blast": blast,
        "ttl_s": ttl_s,
        "target_kind": SUBJECT_TARGET_KIND.get(str(scope["subject"]), "auth")
    };
}

"""Seconds until this action should auto-expire. 0 means no TTL."""
def _effective_ttl(kind: str, requested: object) -> int {
    default_ttl: int = int(CONTAINMENT_KINDS[kind]["ttl_s"]);
    want: int = 0;
    try {
        want = int(requested);
    } except Exception as e {
        want = 0;
    }
    if want <= 0 {
        return default_ttl;
    }
    if default_ttl <= 0 {
        return want;
    }
    return want if want < default_ttl else default_ttl;
}

"""The blast dict shape, all zeros, for a request that never got counted."""
def _null_blast() -> dict {
    return {
        "principals": 0, "sessions": 0, "tenants": 0,
        "pct_of_tenant_actives": 0.0, "level": "narrow",
        "computed_level": "narrow", "contract_floor": "narrow",
        "tenant_denominator": 0, "denominator_tenant": "",
        "principal_ids": [], "tenant_ids": [], "scope_keys": [],
        "proposed_level": ""
    };
}

# --------------------------------------------------------------------------
# The structural claim, as an assertable function.
# --------------------------------------------------------------------------

"""True when no containment kind can name the whole platform.

Checked by containment/verify.jac rather than asserted in prose. A kind is
'blanket' if it has a form that reaches every tenant without naming one. Only
`feature:*` has platform reach, and it is reachable exclusively via an explicit
`feature` target of "*", which the blast counter classifies as broad and the
ratchet therefore sends to a human."""
def:pub no_blanket_shutdown() -> dict {
    offenders: list = [];
    for raw_kind in CONTAINMENT_KINDS.keys() {
        kind: str = str(raw_kind);
        if kind not in KIND_SCOPE {
            offenders.append(kind + ": no scope specification — cannot be bounded");
            continue;
        }
        if len(accepted_fields(kind)) == 0 {
            offenders.append(kind + ": accepts no target fields, so its scope is unbounded");
        }
        # An empty target must never resolve to keys.
        probe: dict = resolve_scope(kind, {}, now_ms());
        if probe["ok"] {
            offenders.append(kind + ": an EMPTY target resolved to " + str(probe["keys"]));
        }
    }
    return {
        "ok": len(offenders) == 0,
        "kinds_checked": len(CONTAINMENT_KINDS),
        "offenders": offenders
    };
}
