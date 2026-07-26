# containment/probes.jac — did the containment do what it was supposed to, and
# is everyone else still working?
#
# A containment action that is "applied" is not yet a containment action that
# WORKS. Between writing a Control and believing in it sit two questions, and
# this module answers both by sending real requests through the real guard:
#
#   1. is the contained subject actually contained?
#   2. is everybody ELSE still able to do their job?
#
# Question 2 is the one this project exists to answer. "Legitimate users retain
# availability during containment" is otherwise a claim in a slide deck; here it
# is `legit_user_can_list_projects`, which picks a real colleague of the
# contained principal — same tenant, live session, not themselves under any
# control — signs a request as the gateway would, and calls guard(). If that
# request is denied, the containment is over: the executor rolls back
# immediately and automatically.
#
# HOW A PROBE MAKES A REQUEST. Through `authorize()` — the same function every
# walker calls, with a ctx signed by the same `sign_ctx` the gateway uses. There
# is no probe-only path into the app, no test hook, no bypass flag. That is the
# whole point: a probe that used a shortcut would be measuring the shortcut.
# Probe requests are stamped `service = "scheduler"` so a reader can tell
# self-checks from user traffic, and they are audited like anything else — a
# health probe is real traffic and hiding it would be a hole in the trail.
#
# WHAT A PROBE MAY NOT DO. Probes never write, never mutate a Control, never
# elevate. They read the graph and they make authorization calls. A probe that
# could change state could mask the failure it was hired to find.
#
# HONEST FAILURE. Four of the ten kinds (throttle_source, pause_queue,
# rotate_service_credential, raise_logging) have no reader inside guard() — they
# are enforced at the gateway or by surfaces outside this process. For those,
# `contained_subject_is_blocked` verifies what is actually verifiable here: that
# the Control is live and resolvable through the same lookup its consumer uses.
# It does NOT claim a block it cannot observe. Overstating that would be the
# most dangerous kind of green check.

import from app.security.authz { authorize }
import from app.security.ctxsig { sign_ctx, SIGNED_FIELDS }
import from app.security.clock { now_ms }
import from app.security.controls {
    is_live, live_controls, find_control,
    key_principal, key_tenant, key_session, key_token, key_ip, key_feature
}
import from app.model.graph { Tenant, Principal, Session, get_platform, all_tenants }
import from app.model.resolve {
    tenant_by_id, principal_by_id, session_by_id, sessions_of,
    memberships_of, principal_of
}
import from containment.policy { tenant_actives, live_sessions_of, tenants_of_principal }

# The probes this module can run, by name. `health_check` on a ContainmentAction
# names one of these; an unknown name is a FAILURE, never a skip.
glob:pub PROBE_NAMES: list = [
    "legit_user_can_list_projects",
    "contained_subject_is_blocked",
    "app_is_serving"
];

# Default probe per containment kind. Every kind gets one; the availability
# probe is the default for anything that touches an identity or a tenant,
# because that is where collateral damage happens.
glob:pub DEFAULT_PROBE: dict = {
    "revoke_session": "legit_user_can_list_projects",
    "revoke_token": "legit_user_can_list_projects",
    "suspend_principal": "legit_user_can_list_projects",
    "throttle_source": "app_is_serving",
    "block_source": "legit_user_can_list_projects",
    "force_reauth": "legit_user_can_list_projects",
    "feature_readonly": "legit_user_can_list_projects",
    "pause_queue": "app_is_serving",
    "rotate_service_credential": "app_is_serving",
    "raise_logging": "app_is_serving"
};

# Deny reason guard() produces for each kind that guard() actually reads.
# Sourced from app/security/authz.jac steps 2-3. A kind absent from this map is
# not enforced inside this process — see the module note above.
glob:pub EXPECTED_DENY: dict = {
    "revoke_session": "NO_SESSION",
    "revoke_token": "TOKEN_REVOKED",
    "suspend_principal": "SUSPENDED",
    "block_source": "SOURCE_BLOCKED",
    "force_reauth": "REAUTH_REQUIRED",
    "feature_readonly": "READONLY_MODE"
};

glob:pub GUARD_ENFORCED_KINDS: list = [
    "revoke_session", "revoke_token", "suspend_principal",
    "block_source", "force_reauth", "feature_readonly"
];

"""The probe name to run for `kind` when the action did not name one."""
def:pub default_probe_for(kind: str) -> str {
    return str(DEFAULT_PROBE.get(kind, "app_is_serving"));
}

# --------------------------------------------------------------------------
# Making a request the way the gateway would.
# --------------------------------------------------------------------------

"""A correctly-signed ctx for `session_id`, as the gateway would emit it.

Built FROM `SIGNED_FIELDS` rather than a hand-written list, so a new signed
field is covered automatically instead of silently unsigned. `auth_age_ms`
exists because a force_reauth probe has to be able to present a session whose
last password was a while ago — that is precisely the condition the control is
supposed to catch."""
def _probe_ctx(
    session_id: str,
    src_ip: str = "203.0.113.10",
    service: str = "scheduler",
    route: str = "/api/v1/projects",
    method: str = "GET",
    auth_age_ms: int = 0
) -> dict {
    ts = now_ms();
    stock: dict = {
        "request_id": "probe_" + str(ts),
        "src_ip": src_ip,
        "src_asn": "AS64500",
        "user_agent_hash": "ua_probe",
        "client_fp": "fp_probe",
        "session_id": session_id,
        "token_id": "",
        "service": service,
        "route": route,
        "http_method": method,
        "csrf_ok": True,
        "received_at_ms": ts,
        "sig_alg": "HMAC-SHA256",
        "issued_at_ms": ts,
        "session_auth_at_ms": ts - auth_age_ms
    };
    fields: dict = {};
    for raw_name in SIGNED_FIELDS {
        name: str = str(raw_name);
        if name in stock {
            fields[name] = stock[name];
        } elif name.endswith("_ms") or name.endswith("_at") {
            fields[name] = 0;
        } else {
            fields[name] = "";
        }
    }
    fields["sig"] = sign_ctx(fields);
    return fields;
}

"""A ctx for a token-bearing request (no session)."""
def _probe_ctx_token(jti: str, src_ip: str = "203.0.113.10") -> dict {
    fields: dict = _probe_ctx("", src_ip);
    fields["token_id"] = jti;
    fields["sig"] = sign_ctx(fields);
    return fields;
}

"""Run one authorization through the real guard and report the raw verdict."""
def _try(ctx: dict, action: str, target_kind: str, tenant_id: str, target_id: str = "") -> dict {
    try {
        d: dict = authorize(ctx, action, target_kind, tenant_id, target_id);
        return {"ok": bool(d["ok"]), "reason": str(d["reason"]), "error": ""};
    } except Exception as e {
        return {"ok": False, "reason": "", "error": str(e)};
    }
}

# --------------------------------------------------------------------------
# Finding a bystander.
# --------------------------------------------------------------------------

"""A live session belonging to somebody in `tenant_id` who is NOT contained.

"Not contained" is checked against the live Control set, not against the action
we just applied: if an earlier action already suspended this person, they are
not a valid witness for availability. Returns {} when the tenant has no
uncontained member with a live session — which the caller must treat as
"cannot prove availability", never as "availability proved"."""
def:pub find_bystander(tenant_id: str, exclude_principals: list, at_ms: int) -> dict {
    tn = tenant_by_id(tenant_id);
    if tn is None {
        return {};
    }
    for m in memberships_of(tn) {
        if m.state != "active" {
            continue;
        }
        pid: str = m.principal_id;
        if pid in exclude_principals {
            continue;
        }
        pr = principal_by_id(pid);
        if pr is None or pr.status != "active" {
            continue;
        }
        # Under a control that DENIES them outright? Then not a bystander.
        #
        # force_reauth is deliberately NOT in this list. Being asked to re-enter
        # a password is not a loss of availability — it is the containment
        # working as designed, and the user carries on. So a principal under
        # force_reauth stays a valid witness, and the probe below presents a
        # fresh step-up exactly as that user would after re-authenticating. If
        # force_reauth excluded them, a tenant-wide re-auth would have no
        # possible witness and would roll itself back every time.
        if find_control("suspend_principal", [key_principal(pid)], at_ms) is not None {
            continue;
        }
        for raw_s in live_sessions_of(pid, at_ms) {
            s: Session = raw_s;
            if find_control("revoke_session", [key_session(s.session_id)], at_ms) is not None {
                continue;
            }
            if find_control("block_source", [key_ip(s.ip_first)], at_ms) is not None {
                continue;
            }
            return {
                "principal_id": pid, "session_id": s.session_id,
                "tenant_id": tenant_id, "role": m.role, "src_ip": s.ip_first
            };
        }
    }
    return {};
}

# Kinds whose principal-scoped controls DENY the named identity outright, and
# whose subject therefore cannot stand as a witness that the app still works.
#
# force_reauth is not here on purpose: it interrupts a user, it does not lock
# them out, and the probe presents the fresh step-up a real user would.
glob:pub DENYING_PRINCIPAL_KINDS: list = ["suspend_principal"];

"""Principals that must NOT be picked as the availability witness.

Derived from the action's SCOPE KEYS, never from `principal_ids`. The two are
different sets and confusing them is a trap: a tenant-wide feature_readonly has
all forty members in its blast radius, but denies none of them — they are
exactly the people whose continued work proves the containment was narrow. If
blast radius drove this list, that action could never find a witness and would
roll itself back every time, for being correct."""
def:pub witness_exclusions(kind: str, action_scope: dict) -> list {
    if kind not in DENYING_PRINCIPAL_KINDS {
        return [];
    }
    out: list = [];
    keys: list = action_scope.get("keys", []);
    for raw_key in keys {
        key: str = str(raw_key);
        if key.startswith("principal:") {
            out.append(key[10:]);
        }
    }
    return out;
}

# --------------------------------------------------------------------------
# THE availability probe.
# --------------------------------------------------------------------------

"""A legitimate user in the SAME TENANT as the contained principal can still
list projects.

This is the whole thesis, expressed as an assertion. It fails — and therefore
rolls the containment back — if narrowly-scoped turned out to be wider than
intended.

`project.list` is the right operation to probe with: it is a read, so it is not
blocked by feature_readonly (which only stops writes) and not blocked by a
step-up demand on a write; it requires a real membership, so it cannot pass by
accident; and it is the ordinary thing a person does when they open the app."""
def:pub probe_legit_user_can_list_projects(kind: str, action_scope: dict, at_ms: int) -> dict {
    tenant_id: str = str(action_scope.get("tenant_id", ""));
    excluded: list = witness_exclusions(kind, action_scope);

    # No tenant in scope (a pure source/credential action): fall back to any
    # tenant that has an uncontained member, so the probe still means something.
    candidates: list = [];
    if tenant_id != "" {
        candidates.append(tenant_id);
    } else {
        for tn in all_tenants() {
            candidates.append(tn.tenant_id);
        }
    }

    for raw_tid in candidates {
        tid: str = str(raw_tid);
        who: dict = find_bystander(tid, excluded, at_ms);
        if len(who) == 0 {
            continue;
        }
        ctx: dict = _probe_ctx(str(who["session_id"]), str(who["src_ip"]));
        verdict: dict = _try(ctx, "project.list", "project", tid);
        return {
            "ok": bool(verdict["ok"]),
            "name": "legit_user_can_list_projects",
            "detail": "tenant=" + tid + " principal=" + str(who["principal_id"])
                      + " session=" + str(who["session_id"])
                      + " role=" + str(who["role"])
                      + " -> " + ("ALLOW" if verdict["ok"] else "DENY " + str(verdict["reason"]))
                      + (" err=" + str(verdict["error"]) if verdict["error"] != "" else ""),
            "witness": who,
            "verdict": verdict
        };
    }

    # Nobody to ask. Reported as a FAILED probe, not a pass: an unproven
    # availability claim must not be recorded as a proven one.
    return {
        "ok": False,
        "name": "legit_user_can_list_projects",
        "detail": "no uncontained member with a live session in "
                  + (tenant_id if tenant_id != "" else "any tenant")
                  + " — availability could not be demonstrated",
        "witness": {},
        "verdict": {}
    };
}

"""Can THIS specific principal list projects in `tenant_id`?

`probe_legit_user_can_list_projects` picks whichever witness it finds first,
which is the right behaviour for a health check but useless for auditing a whole
tenant one person at a time. This names the principal. Same signed ctx, same
guard, same audit trail — the only difference is who is asking."""
def:pub principal_can_list_projects(principal_id: str, tenant_id: str, at_ms: int) -> dict {
    live = live_sessions_of(principal_id, at_ms);
    if len(live) == 0 {
        return {"ok": False, "principal_id": principal_id,
                "reason": "NO_LIVE_SESSION", "detail": principal_id + ": no live session"};
    }
    sess: Session = live[0];
    ctx: dict = _probe_ctx(sess.session_id, sess.ip_first);
    v: dict = _try(ctx, "project.list", "project", tenant_id);
    return {
        "ok": bool(v["ok"]),
        "principal_id": principal_id,
        "session_id": sess.session_id,
        "reason": str(v["reason"]),
        "detail": principal_id + " (" + sess.session_id + ") -> "
                  + ("ALLOW" if v["ok"] else "DENY " + str(v["reason"]))
    };
}

# --------------------------------------------------------------------------
# The containment-took-effect probe.
# --------------------------------------------------------------------------

"""The contained subject is actually stopped.

For the six kinds guard() reads, this sends a request as the contained subject
and requires the exact deny reason that control produces. For the other four the
control has no in-process reader, so the check is that the Control is LIVE and
resolvable through `app/security/controls.jac` — the same lookup its real
consumer performs. That is stated in the detail string rather than dressed up as
a block."""
def:pub probe_contained_subject_is_blocked(kind: str, action_scope: dict, at_ms: int) -> dict {
    keys: list = action_scope.get("keys", []);
    if len(keys) == 0 {
        return {"ok": False, "name": "contained_subject_is_blocked",
                "detail": "action has no scope keys", "checks": []};
    }

    checks: list = [];
    all_ok: bool = True;

    if kind not in GUARD_ENFORCED_KINDS {
        for raw_key in keys {
            key: str = str(raw_key);
            hit = find_control(kind, [key], at_ms);
            live: bool = hit is not None;
            if not live {
                all_ok = False;
            }
            checks.append(kind + " " + key + ": control "
                          + ("LIVE (enforced outside this process)" if live else "NOT LIVE"));
        }
        return {
            "ok": all_ok, "name": "contained_subject_is_blocked",
            "detail": " | ".join(checks), "checks": checks
        };
    }

    want: str = str(EXPECTED_DENY[kind]);

    for raw_key2 in keys {
        key2: str = str(raw_key2);
        result: dict = _probe_subject(kind, key2, want, at_ms);
        if not bool(result["ok"]) {
            all_ok = False;
        }
        checks.append(str(result["detail"]));
    }

    return {
        "ok": all_ok, "name": "contained_subject_is_blocked",
        "detail": " | ".join(checks), "checks": checks
    };
}

"""One contained-subject check for one scope key."""
def _probe_subject(kind: str, key: str, want: str, at_ms: int) -> dict {
    # revoke_session — ask as that exact session.
    if key.startswith("session:") {
        sid: str = key[8:];
        s = session_by_id(sid);
        ip: str = s.ip_first if s is not None else "203.0.113.10";
        v: dict = _try(_probe_ctx(sid, ip), "project.list", "project",
                       s.tenant_id if s is not None else "");
        hit: bool = (not bool(v["ok"])) and str(v["reason"]) == want;
        return {"ok": hit, "detail": key + " -> "
                + ("DENY " + str(v["reason"]) if not v["ok"] else "ALLOW")
                + " (want DENY " + want + ")"};
    }

    # revoke_token — ask bearing that jti.
    if key.startswith("token:") {
        v2: dict = _try(_probe_ctx_token(key[6:]), "project.list", "project", "");
        hit2: bool = (not bool(v2["ok"])) and str(v2["reason"]) == want;
        return {"ok": hit2, "detail": key + " -> "
                + ("DENY " + str(v2["reason"]) if not v2["ok"] else "ALLOW")
                + " (want DENY " + want + ")"};
    }

    # suspend_principal / force_reauth — ask as one of that principal's sessions.
    if key.startswith("principal:") {
        pid: str = key[10:];
        live = live_sessions_of(pid, at_ms);
        if len(live) == 0 {
            # No live session to test with. The control is still verifiable.
            present: bool = find_control(kind, [key], at_ms) is not None;
            return {"ok": present, "detail": key + " -> no live session to test; control "
                    + ("LIVE" if present else "NOT LIVE")};
        }
        sess: Session = live[0];
        # force_reauth only bites operations that do not survive re-auth, and
        # only when the step-up clock is stale — so the probe presents a stale
        # one, which is exactly the state a hijacked long-lived session is in.
        act: str = "project.list";
        age: int = 0;
        if kind == "force_reauth" {
            age = 3600000;
        }
        v3: dict = _try(_probe_ctx(sess.session_id, sess.ip_first, "scheduler",
                                   "/api/v1/projects", "GET", age),
                        act, "project", sess.tenant_id);
        hit3: bool = (not bool(v3["ok"])) and str(v3["reason"]) == want;
        return {"ok": hit3, "detail": key + " -> "
                + ("DENY " + str(v3["reason"]) if not v3["ok"] else "ALLOW")
                + " (want DENY " + want + ")"};
    }

    # block_source — ask from that IP, as anyone who has a live session there.
    if key.startswith("ip:") {
        ip2: str = key[3:];
        for tn in all_tenants() {
            for m in memberships_of(tn) {
                for raw_s2 in live_sessions_of(m.principal_id, at_ms) {
                    s2: Session = raw_s2;
                    if s2.ip_first != ip2 {
                        continue;
                    }
                    v4: dict = _try(_probe_ctx(s2.session_id, ip2), "project.list",
                                    "project", s2.tenant_id);
                    hit4: bool = (not bool(v4["ok"])) and str(v4["reason"]) == want;
                    return {"ok": hit4, "detail": key + " -> "
                            + ("DENY " + str(v4["reason"]) if not v4["ok"] else "ALLOW")
                            + " (want DENY " + want + ")"};
                }
            }
        }
        present2: bool = find_control(kind, [key], at_ms) is not None;
        return {"ok": present2, "detail": key + " -> no live session from this source; control "
                + ("LIVE" if present2 else "NOT LIVE")};
    }

    # feature_readonly — a WRITE by a member of the affected tenant must fail.
    if key.startswith("tenant:") or key.startswith("feature:") {
        tid: str = "";
        if key.startswith("tenant:") {
            tid = key[7:].split(":")[0];
        }
        tenants: list = [];
        if tid != "" {
            tenants.append(tid);
        } else {
            for tn2 in all_tenants() {
                tenants.append(tn2.tenant_id);
            }
        }
        for raw_t in tenants {
            t: str = str(raw_t);
            who: dict = find_bystander(t, [], at_ms);
            if len(who) == 0 {
                continue;
            }
            v5: dict = _try(_probe_ctx(str(who["session_id"]), str(who["src_ip"]),
                                       "scheduler", "/api/v1/projects", "POST"),
                            "project.create", "project", t);
            hit5: bool = (not bool(v5["ok"])) and str(v5["reason"]) == want;
            return {"ok": hit5, "detail": key + " -> project.create "
                    + ("DENY " + str(v5["reason"]) if not v5["ok"] else "ALLOW")
                    + " (want DENY " + want + ")"};
        }
        present3: bool = find_control(kind, [key], at_ms) is not None;
        return {"ok": present3, "detail": key + " -> no member to test with; control "
                + ("LIVE" if present3 else "NOT LIVE")};
    }

    present4: bool = find_control(kind, [key], at_ms) is not None;
    return {"ok": present4, "detail": key + " -> control "
            + ("LIVE" if present4 else "NOT LIVE")};
}

# --------------------------------------------------------------------------
# The liveness probe.
# --------------------------------------------------------------------------

"""The application still serves ordinary traffic to somebody, somewhere.

Deliberately weak and deliberately broad: it walks every tenant looking for one
uncontained member who can complete a read. A containment that takes the whole
platform down fails here even when it looked narrow on paper."""
def:pub probe_app_is_serving(kind: str, action_scope: dict, at_ms: int) -> dict {
    excluded: list = witness_exclusions(kind, action_scope);
    tried: list = [];
    for tn in all_tenants() {
        who: dict = find_bystander(tn.tenant_id, excluded, at_ms);
        if len(who) == 0 {
            tried.append(tn.tenant_id + ":no-witness");
            continue;
        }
        v: dict = _try(_probe_ctx(str(who["session_id"]), str(who["src_ip"])),
                       "project.list", "project", tn.tenant_id);
        if bool(v["ok"]) {
            return {
                "ok": True, "name": "app_is_serving",
                "detail": "tenant=" + tn.tenant_id + " principal="
                          + str(who["principal_id"]) + " -> ALLOW",
                "witness": who
            };
        }
        tried.append(tn.tenant_id + ":DENY " + str(v["reason"]));
    }
    return {
        "ok": False, "name": "app_is_serving",
        "detail": "no tenant could complete project.list — " + ", ".join(tried),
        "witness": {}
    };
}

# --------------------------------------------------------------------------
# The entry point the executor calls.
# --------------------------------------------------------------------------

"""Run one named probe."""
def:pub run_probe(name: str, kind: str, action_scope: dict, at_ms: int = 0) -> dict {
    now: int = at_ms if at_ms > 0 else now_ms();
    if name == "legit_user_can_list_projects" {
        return probe_legit_user_can_list_projects(kind, action_scope, now);
    }
    if name == "contained_subject_is_blocked" {
        return probe_contained_subject_is_blocked(kind, action_scope, now);
    }
    if name == "app_is_serving" {
        return probe_app_is_serving(kind, action_scope, now);
    }
    # An unknown probe name is a FAILURE. Treating it as a skip would let a typo
    # in `health_check` silently disable verification for a whole kind.
    return {
        "ok": False, "name": name,
        "detail": "unknown probe '" + name + "' — not one of " + ", ".join(PROBE_NAMES)
    };
}

"""Full health verification for one applied action.

Three probes, always, in this order:

  1. the action's named probe (`health_check`, or the per-kind default)
  2. contained_subject_is_blocked — the containment did something
  3. legit_user_can_list_projects — it did not do too much

2 and 3 run even when 1 already covers one of them, because the pair is the
actual invariant: something stopped, nothing else did. `ok` is the AND — any
failure sends the executor into rollback."""
def:pub run_health(health_check: str, kind: str, action_scope: dict, at_ms: int = 0) -> dict {
    now: int = at_ms if at_ms > 0 else now_ms();
    name: str = health_check if health_check != "" else default_probe_for(kind);

    results: list = [];
    seen: list = [];

    primary: dict = run_probe(name, kind, action_scope, now);
    results.append(primary);
    seen.append(name);

    if "contained_subject_is_blocked" not in seen {
        results.append(run_probe("contained_subject_is_blocked", kind, action_scope, now));
        seen.append("contained_subject_is_blocked");
    }
    if "legit_user_can_list_projects" not in seen {
        results.append(run_probe("legit_user_can_list_projects", kind, action_scope, now));
        seen.append("legit_user_can_list_projects");
    }

    all_ok: bool = True;
    lines: list = [];
    failed: list = [];
    for r in results {
        rd: dict = r;
        passed: bool = bool(rd["ok"]);
        if not passed {
            all_ok = False;
            failed.append(str(rd["name"]));
        }
        lines.append(("PASS " if passed else "FAIL ") + str(rd["name"]) + ": " + str(rd["detail"]));
    }

    return {
        "ok": all_ok,
        "status": "pass" if all_ok else "fail",
        "primary": name,
        "probes": results,
        "failed": failed,
        "report": lines
    };
}
