# app/security/authz.jac — the body of guard(). The only authorization surface.
#
# `contracts/req_ctx_contract.impl.jac` is a six-line adapter over `authorize()`
# below; all the reasoning lives here. Splitting it that way keeps the frozen
# contract module free of application imports (and free of an import cycle),
# while leaving exactly ONE function in the codebase that decides anything.
#
# WHY ONE FUNCTION. Resolve, authorize and audit happen together, in one call,
# or not at all. An engineer cannot resolve a record and forget to authorize it,
# because resolution only happens inside the authorization path. An engineer
# cannot authorize and forget to audit, because the audit emission is the last
# statement of every branch. There is no "check permission" helper that returns
# a bool for a caller to ignore.
#
# ORDER OF CHECKS -- each step assumes only what the steps above it established:
#
#   1. ctx signature      -- until this passes, NOTHING in ctx is a fact
#   2. session / token    -- live, unrevoked, unexpired credential
#   3. containment        -- Control rows the responder has written
#   4. membership         -- an active Membership in the target tenant
#   5. role               -- rank >= the action's requirement
#   6. resolution         -- by traversal from that tenant, never by global id
#   7. audit              -- exactly one AuditEvent, allow or deny
#
# Step 7 is not optional and has no bypass parameter. Every `return` in this
# file goes through `_decide()`, which emits before it returns.

import from typing { cast }
import from contracts.audit_event_contract { ACTIONS, DENY_REASONS }
import from app.model.graph {
    Tenant, Membership, Principal, Session, Token, Project, Task, Comment, ExportJob
}
import from app.model.resolve {
    tenant_by_id, principal_by_id, session_by_id, token_by_jti, membership_of,
    resolve_in_tenant, sensitivity_of, projects_of, tasks_of, comments_of,
    exports_of, project_in, task_in, export_in, TRAVERSED_KINDS
}
import from app.security.clock { now_ms, REAUTH_MAX_AGE_MS }
import from app.security.ctxsig { verify_ctx }
import from app.security.controls {
    has_control, key_principal, key_tenant, key_session, key_token,
    source_keys, readonly_keys
}
import from app.security.roles {
    min_role_for, role_satisfies, is_write_action, survives_reauth,
    requires_stepup, TENANTLESS_ACTIONS, MEMBERSHIP_EXEMPT_ACTIONS
}
import from app.security.audit { emit_audit }

# --------------------------------------------------------------------------
# Actions whose blast radius guard() MEASURES rather than trusts.
#
# `result_count` is the bulk-exfiltration signal the monitor watches, so it must
# not be self-reported by the code being audited. For these actions guard()
# resolves the collection itself, counts it, records the count, and hands the
# SAME collection back on `Grant.node`. A walker therefore cannot return rows
# that guard did not count, and a compromised walker cannot under-report its own
# egress. The count in the audit log is a measurement, not a claim.
# --------------------------------------------------------------------------

glob:pub COUNTED_ACTIONS: list = [
    "project.list",
    "task.list",
    "comment.list",
    "export.download"
];

"""Assemble the tenant-scoped collection an action is allowed to return.

Returns a list. `target_id` names the parent to list from where the action
needs one (tasks of a project, comments of a task)."""
def _measure(tenant: Tenant, action: str, target_id: str) -> list {
    if action == "project.list" {
        return projects_of(tenant);
    }
    if action == "task.list" {
        parent = project_in(tenant, target_id);
        if parent is None {
            return [];
        }
        return tasks_of(parent);
    }
    if action == "comment.list" {
        parent = task_in(tenant, target_id);
        if parent is None {
            return [];
        }
        return comments_of(parent);
    }
    if action == "export.download" {
        job = export_in(tenant, target_id);
        if job is None {
            return [];
        }
        # An export's blast radius is its row count, not one job record.
        return [job];
    }
    return [];
}

"""Rows an export job would hand over, for the egress signal."""
def _export_rows(collection: list, action: str) -> int {
    if action == "export.download" and len(collection) == 1 {
        return getattr(collection[0], "row_count", 0);
    }
    return len(collection);
}

# --------------------------------------------------------------------------
# Decision assembly. Every exit from authorize() goes through here, so an
# unaudited decision is not expressible.
# --------------------------------------------------------------------------

"""Emit exactly one AuditEvent and return the decision dict.

`fields` carries whatever the caller established before the decision was
reached. Nothing about the outcome can be recorded without also being
returned, and nothing can be returned without also being recorded."""
def _decide(fields: dict, ok: bool, reason: str,
            tenant: object = None, principal: object = None,
            membership: object = None, resolved: object = None) -> dict {
    event = dict(fields);
    if ok {
        event["outcome"] = "allow";
        event["reason"] = "";
    } else {
        event["outcome"] = "deny";
        event["reason"] = reason;
    }
    emitted = emit_audit(event);
    return {
        "ok": ok,
        "reason": event["reason"],
        "tenant": tenant,
        "principal": principal,
        "membership": membership,
        "node": resolved,
        "event": emitted
    };
}

# --------------------------------------------------------------------------
# The function.
# --------------------------------------------------------------------------

"""Resolve + authorize + audit, atomically.

`ctx` is the RAW gateway payload as a plain dict -- untrusted until step 1
verifies its HMAC. Returns a dict the contract's `impl guard` block wraps in a
`Grant`. Exactly one AuditEvent is emitted per call, on every path."""
def:pub authorize(ctx: dict, action: str, target_kind: str,
                  tenant_id: str, target_id: str = "") -> dict {

    # An action outside the frozen vocabulary is a programmer error, not a
    # runtime condition. Failing loudly here is what keeps ACTIONS closed.
    if action not in ACTIONS {
        raise ValueError("guard() called with an action outside the frozen vocabulary: " + str(action));
    }

    now = now_ms();

    # ----------------------------------------------------------------------
    # STEP 1 -- the ctx signature. Until this passes, every field of `ctx` is
    # an attacker-supplied claim, including src_ip, session_id and csrf_ok.
    # ----------------------------------------------------------------------
    verdict = verify_ctx(ctx, now);
    if not verdict["ok"] {
        # DELIBERATELY MINIMAL. The claimed src_ip / session_id / client_fp are
        # NOT copied into this event. Recording a forged claim as though it were
        # an observation would poison the exact audit trail used to detect the
        # bypass -- an attacker could attribute their own probe to a victim's IP
        # and session. Only facts this process actually observed are recorded:
        # which action was attempted, against which target kind, and that the
        # context could not be verified. `service` is stamped "unverified" so a
        # reader is never in doubt about the provenance of the row.
        unverified: dict = {
            "action": action,
            "target_kind": target_kind,
            "target_id": target_id,
            "actor_principal_id": "",
            "actor_email": "",
            "actor_role": "none",
            "auth_method": "none",
            "session_id": "",
            "token_id": "",
            "tenant_id": "",
            "actor_tenant_id": "",
            "service": "unverified"
        };
        return _decide(unverified, False, "CTX_UNVERIFIED");
    }

    # ----------------------------------------------------------------------
    # ctx is now VERIFIED. Its fields may be treated as facts observed by the
    # gateway, because only the gateway holds APP_CTX_SIGNING_KEY.
    # ----------------------------------------------------------------------
    src_ip = ctx.get("src_ip", "");
    src_asn = ctx.get("src_asn", "");
    session_id = ctx.get("session_id", "");
    token_id = ctx.get("token_id", "");
    # Signed by the gateway from the session record; see the step-up block below.
    auth_at_ms = ctx.get("session_auth_at_ms", 0);

    base: dict = {
        "action": action,
        "target_kind": target_kind,
        "target_id": target_id,
        "tenant_id": tenant_id,
        "actor_role": "none",
        "auth_method": "none",
        "src_ip": src_ip,
        "src_asn": src_asn,
        "user_agent_hash": ctx.get("user_agent_hash", ""),
        "client_fp": ctx.get("client_fp", ""),
        "request_id": ctx.get("request_id", ""),
        "http_method": ctx.get("http_method", ""),
        "route": ctx.get("route", ""),
        "service": ctx.get("service", ""),
        "session_id": session_id,
        "token_id": token_id
    };

    # ----------------------------------------------------------------------
    # STEP 2 -- a live credential. Session OR API token, never both, never
    # neither. Revocation is honoured from two places: the flag on the node
    # (set by the responder or by logout) and a live containment Control.
    # ----------------------------------------------------------------------
    principal: Principal | None = None;
    actor_tenant_id = "";
    token_scope = "";

    if session_id != "" {
        session = session_by_id(session_id);
        if session is None {
            return _decide(base, False, "NO_SESSION");
        }
        if session.revoked or has_control("revoke_session", [key_session(session_id)], now) {
            return _decide(base, False, "NO_SESSION");
        }
        if session.expires_at <= now {
            return _decide(base, False, "SESSION_EXPIRED");
        }
        principal = principal_by_id(session.principal_id);
        if principal is None {
            # A session whose principal is gone is not a session.
            return _decide(base, False, "NO_SESSION");
        }
        actor_tenant_id = session.tenant_id;
        base["auth_method"] = "session";

    } elif token_id != "" {
        token = token_by_jti(token_id);
        if token is None {
            return _decide(base, False, "NO_SESSION");
        }
        if token.revoked or has_control("revoke_token", [key_token(token_id)], now) {
            return _decide(base, False, "TOKEN_REVOKED");
        }
        if token.expires_at <= now {
            return _decide(base, False, "SESSION_EXPIRED");
        }
        principal = principal_by_id(token.principal_id);
        if principal is None {
            return _decide(base, False, "NO_SESSION");
        }
        actor_tenant_id = token.tenant_id;
        token_scope = token.scope;
        base["auth_method"] = "api_token";

    } else {
        # No credential at all. A signed ctx proves the request came through
        # the gateway; it proves nothing about who sent it.
        return _decide(base, False, "NO_SESSION");
    }

    if principal is None {
        return _decide(base, False, "NO_SESSION");
    }
    # The branches above already returned on every None path; the cast tells
    # Jac's checker what the control flow already guarantees.
    actor = cast(Principal, principal);
    base["actor_principal_id"] = actor.principal_id;
    base["actor_email"] = actor.email;
    base["actor_tenant_id"] = actor_tenant_id;

    # A token's scope is a further narrowing on top of the role check below --
    # never a widening. An empty scope authorizes nothing.
    if base["auth_method"] == "api_token" {
        family = action.split(".")[0];
        granted = token_scope.split();
        if action not in granted and family not in granted {
            return _decide(base, False, "INSUFFICIENT_ROLE", principal=actor);
        }
    }

    # ----------------------------------------------------------------------
    # STEP 3 -- containment controls. These are how the responder's decisions
    # actually take effect; guard() is the enforcement point that reads them.
    # ----------------------------------------------------------------------
    if actor.status != "active" {
        return _decide(base, False, "SUSPENDED", principal=actor);
    }
    if has_control("suspend_principal", [key_principal(actor.principal_id)], now) {
        return _decide(base, False, "SUSPENDED", principal=actor);
    }
    if has_control("block_source", source_keys(src_ip, src_asn), now) {
        return _decide(base, False, "SOURCE_BLOCKED", principal=actor);
    }
    # Step-up authentication. Demanded in two independent circumstances:
    #
    #   (a) ALWAYS, for the four irreversible / exfiltrating operations listed
    #       in roles.STEPUP_ACTIONS. contracts/req_ctx_contract.jac mandates
    #       `now_ms - session_auth_at_ms <= 900000` for these. A stolen live
    #       session may browse; it may not grant itself a role, delete a
    #       colleague, or walk out with the dataset without the human at the
    #       keyboard proving they are still there.
    #   (b) ON DEMAND, when the responder has written a `force_reauth` control.
    #
    # The freshness clock is `session_auth_at_ms` from the VERIFIED ctx -- the
    # gateway stamps it from the session record and it is covered by the HMAC,
    # so a client cannot forge recency. It advances only on a password login or
    # a completed re-auth, never on mere activity: browsing for an hour is not
    # evidence that the human is still at the keyboard.
    if not survives_reauth(action) {
        reauth_keys = [key_principal(actor.principal_id)];
        if actor_tenant_id != "" {
            reauth_keys.append(key_tenant(actor_tenant_id));
        }
        demanded = requires_stepup(action) or has_control("force_reauth", reauth_keys, now);
        if demanded {
            # An API token can never present a password, so it can never
            # satisfy a step-up -- it is refused without consulting the clock.
            if base["auth_method"] != "session" {
                return _decide(base, False, "REAUTH_REQUIRED", principal=actor);
            }
            # 0 means UNKNOWN, and unknown is rejected EXPLICITLY rather than
            # left to `now - 0` happening to exceed the window. Relying on that
            # arithmetic would silently fail open the day someone rebases the
            # clock or switches the field to a relative offset.
            if auth_at_ms <= 0 {
                return _decide(base, False, "REAUTH_REQUIRED", principal=actor);
            }
            if (now - auth_at_ms) > REAUTH_MAX_AGE_MS {
                return _decide(base, False, "REAUTH_REQUIRED", principal=actor);
            }
            # A ctx claiming a FUTURE authentication is a forged or skewed
            # clock; freshness must never be obtainable by claiming tomorrow.
            if (auth_at_ms - now) > 1000 {
                return _decide(base, False, "REAUTH_REQUIRED", principal=actor);
            }
        }
    }
    if is_write_action(action) and has_control("feature_readonly", readonly_keys(tenant_id, action), now) {
        return _decide(base, False, "READONLY_MODE", principal=actor);
    }

    # ----------------------------------------------------------------------
    # Tenantless actions (creating a tenant) legitimately have no tenant to be
    # a member of. They still required a verified ctx, a live credential and a
    # clean control check to get here -- only steps 4-6 are skipped.
    # ----------------------------------------------------------------------
    if action in TENANTLESS_ACTIONS {
        return _decide(base, True, "", principal=actor);
    }

    # ----------------------------------------------------------------------
    # STEP 4 -- tenancy.
    # ----------------------------------------------------------------------
    tenant = tenant_by_id(tenant_id);
    if tenant is None {
        # A non-existent tenant and a tenant the caller may not see are
        # reported identically. Distinguishing them is a tenant-enumeration
        # oracle.
        return _decide(base, False, "NOT_FOUND", principal=actor);
    }
    if tenant.status != "active" {
        return _decide(base, False, "SUSPENDED", tenant=tenant, principal=actor);
    }

    # The credential is bound to ONE tenant. Presenting it against another is a
    # crossing attempt, and is the single highest-signal event this system
    # produces -- vocab.md escalates TENANT_MISMATCH to `high` unconditionally.
    #
    # `member.accept` is the one action exempt from this, and it must be: it is
    # how a principal ENTERS a tenant, so demanding they already be scoped to
    # that tenant is circular. The invite token is the credential for this step
    # -- 32 bytes of `secrets` entropy, stored only as a SHA-256 hash, and
    # matched by traversal from this tenant alone. A caller who guesses a
    # tenant_id still holds nothing.
    if actor_tenant_id != tenant_id and action not in MEMBERSHIP_EXEMPT_ACTIONS {
        return _decide(base, False, "TENANT_MISMATCH", tenant=tenant, principal=actor);
    }

    membership: Membership | None = None;
    if action not in MEMBERSHIP_EXEMPT_ACTIONS {
        found = membership_of(tenant, actor.principal_id);
        if found is None {
            return _decide(base, False, "NOT_A_MEMBER", tenant=tenant, principal=actor);
        }
        membership = cast(Membership, found);
        if membership.state != "active" {
            return _decide(base, False, "NOT_A_MEMBER", tenant=tenant, principal=actor);
        }
        base["actor_role"] = membership.role;

        # ------------------------------------------------------------------
        # STEP 5 -- role. The requirement comes from the ACTION_MIN_ROLE table
        # in app/security/roles.jac, never from an inline comparison here.
        # ------------------------------------------------------------------
        held: str = membership.role;
        if not role_satisfies(held, min_role_for(action)) {
            return _decide(base, False, "INSUFFICIENT_ROLE",
                           tenant=tenant, principal=actor, membership=membership);
        }
    }

    # ----------------------------------------------------------------------
    # STEP 6 -- resolution BY TRAVERSAL from this tenant. A valid id belonging
    # to another tenant is not rejected here; it is never reached. See
    # app/model/resolve.jac.
    # ----------------------------------------------------------------------
    resolved: object = None;
    if target_id != "" and target_kind in TRAVERSED_KINDS {
        resolved = resolve_in_tenant(tenant, target_kind, target_id);
        if resolved is None {
            return _decide(base, False, "NOT_FOUND",
                           tenant=tenant, principal=actor, membership=membership);
        }
        base["target_sensitivity"] = sensitivity_of(resolved);
        base["parent_id"] = getattr(resolved, "project_id", "") or getattr(resolved, "task_id", "");
    }

    # Measured egress, for the actions whose blast radius is a collection.
    if action in COUNTED_ACTIONS {
        collection = _measure(tenant, action, target_id);
        base["result_count"] = _export_rows(collection, action);
        resolved = collection;
    }

    # ----------------------------------------------------------------------
    # STEP 7 -- allow, audited.
    # ----------------------------------------------------------------------
    return _decide(base, True, "",
                   tenant=tenant, principal=actor, membership=membership, resolved=resolved);
}

# --------------------------------------------------------------------------
# Pre-authorization emission, for the two walkers that cannot call guard().
#
# `auth.register` and `auth.login` run BEFORE any principal is established, so
# there is nothing for guard() to authorize. They are public walkers, and
# vocab.md's emission map already carves out the pre-auth cases. They still
# verify the ctx signature -- an unsigned request must not be able to write a
# login record attributed to a spoofed source -- and they emit exactly one
# event each, through the same emit_audit() everything else uses.
# --------------------------------------------------------------------------

"""Verify a ctx for a pre-authentication walker.

Returns {"ok", "ctx"} where `ctx` is the verified payload, or emits a
CTX_UNVERIFIED event and returns ok=False. Same minimal-record rule as step 1:
a forged claim is never written down as an observation."""
def:pub require_verified_ctx(ctx: dict, action: str, target_kind: str) -> dict {
    if action not in ACTIONS {
        raise ValueError("require_verified_ctx() called with an unknown action: " + str(action));
    }
    verdict = verify_ctx(ctx, now_ms());
    if not verdict["ok"] {
        emit_audit({
            "action": action,
            "target_kind": target_kind,
            "outcome": "deny",
            "reason": "CTX_UNVERIFIED",
            "actor_principal_id": "",
            "actor_role": "none",
            "auth_method": "none",
            "service": "unverified"
        });
        return {"ok": False, "ctx": {}};
    }
    return {"ok": True, "ctx": ctx};
}

"""Emit one event for a pre-authentication outcome (register / login).

Thin, deliberately: it exists so the auth walkers cannot invent their own
emission shape, and so `grep emit_audit app/walkers` returns nothing."""
def:pub emit_preauth(ctx: dict, action: str, outcome: str, reason: str,
                     principal_id: str = "", email: str = "",
                     tenant_id: str = "", session_id: str = "") -> dict {
    return emit_audit({
        "action": action,
        "target_kind": "auth",
        "outcome": outcome,
        "reason": reason,
        "actor_principal_id": principal_id,
        "actor_email": email,
        "actor_role": "none",
        "auth_method": "password",
        "session_id": session_id,
        "tenant_id": tenant_id,
        "actor_tenant_id": tenant_id,
        "src_ip": ctx.get("src_ip", ""),
        "src_asn": ctx.get("src_asn", ""),
        "user_agent_hash": ctx.get("user_agent_hash", ""),
        "client_fp": ctx.get("client_fp", ""),
        "request_id": ctx.get("request_id", ""),
        "http_method": ctx.get("http_method", ""),
        "route": ctx.get("route", ""),
        "service": ctx.get("service", "")
    });
}
