# tests/fixtures.jac -- the world the domain-layer tests run against.
#
# Two tenants, five principals, one canary. Everything is built through the same
# typed edges the application walks, so a test can never accidentally reach a
# record by a route the application does not have.
#
# THE CANARY IS AN ORDINARY RECORD. `pr_canary` below differs from `pr_conf` in
# exactly one way: the string in its `sensitivity` field. Both map to the same
# role floor (`admin`), so both are denied to a member by the same expression.
# The fixture knows which one is the canary; the application does not.
#
# ctx payloads are SIGNED with the real signer (app/security/ctxsig.sign_ctx),
# because guard() verifies the HMAC before it trusts a single field. There is no
# test-only bypass -- if the signature were faked, guard would deny
# CTX_UNVERIFIED and every test here would be measuring nothing.

import from app.security.clock { now_ms }
import from app.security.ctxsig { sign_ctx, SIGNED_FIELDS }
import from app.model.graph {
    Platform, Tenant, Membership, Principal, Session, Project, Task, Comment,
    Hosts, Registers, HasMember, Identifies, Owns, Contains, Discusses,
    Authenticates, get_platform
}
import from app.model.resolve { tenant_by_id }

# A session is valid for an hour; a step-up is satisfied for fifteen minutes.
glob:pub HOUR_MS: int = 3600000;

"""Build (once) and return the fixture world.

Idempotent: the anchor store persists between `jac test` invocations, so the
second call finds `t_acme` already hosted and reuses it. Tests must therefore
treat the world as read-mostly and create their own records under their own
keys."""
def:pub world() -> dict {
    existing = tenant_by_id("t_acme");
    if existing is not None {
        return snapshot();
    }
    build();
    return snapshot();
}

"""Create every node and edge. Called once, by world()."""
def build() -> None {
    ts = now_ms();
    plat = get_platform();

    # --- principals -------------------------------------------------------
    people = [
        ("u_owner", "owner@acme.test"),
        ("u_admin", "admin@acme.test"),
        ("u_member", "member@acme.test"),
        ("u_viewer", "viewer@acme.test"),
        ("u_globex", "member@globex.test")
    ];
    made: dict = {};
    for row in people {
        pr = (plat +>:Registers:+> Principal(
            principal_id=str(row[0]), email=str(row[1]), pw_hash="x", status="active", created_at=ts
        ))[0];
        made[str(row[0])] = pr;
    }

    # --- tenants ----------------------------------------------------------
    acme = (plat +>:Hosts:+> Tenant(
        tenant_id="t_acme", name="Acme", plan="free", status="active", created_at=ts
    ))[0];
    globex = (plat +>:Hosts:+> Tenant(
        tenant_id="t_globex", name="Globex", plan="free", status="active", created_at=ts
    ))[0];

    # --- memberships. Roles live here, per tenant, never on a Principal. ---
    seats = [
        (acme, "m_owner", "u_owner", "owner"),
        (acme, "m_admin", "u_admin", "admin"),
        (acme, "m_member", "u_member", "member"),
        (acme, "m_viewer", "u_viewer", "viewer"),
        (globex, "m_globex", "u_globex", "member")
    ];
    for seat in seats {
        tnode = seat[0];
        mem = (tnode +>:HasMember:+> Membership(
            membership_id=str(seat[1]),
            principal_id=str(seat[2]),
            tenant_id=tnode.tenant_id,
            role=str(seat[3]),
            state="active",
            created_at=ts
        ))[0];
        mnode = mem;
        who = made[str(seat[2])];
        mnode +>:Identifies:+> who;
    }

    # --- sessions. Tenant-scoped: crossing with one is TENANT_MISMATCH. ----
    # `last_auth_at = ts` means a step-up is satisfied; `s_stale_admin` is the
    # same admin with a password presented an hour ago, so it is not.
    sessions = [
        ("s_owner", "u_owner", "t_acme", ts),
        ("s_admin", "u_admin", "t_acme", ts),
        ("s_member", "u_member", "t_acme", ts),
        ("s_viewer", "u_viewer", "t_acme", ts),
        ("s_globex", "u_globex", "t_globex", ts),
        ("s_stale_admin", "u_admin", "t_acme", ts - HOUR_MS)
    ];
    for srow in sessions {
        holder = made[str(srow[1])];
        holder +>:Authenticates:+> Session(
            session_id=str(srow[0]),
            principal_id=str(srow[1]),
            tenant_id=str(srow[2]),
            ip_first="203.0.113.10",
            fp="fp_test",
            issued_at=ts,
            expires_at=ts + HOUR_MS,
            last_auth_at=int(srow[3]),
            revoked=False
        );
    }

    # --- work objects -----------------------------------------------------
    # Three projects in Acme at three sensitivities. `pr_canary` and `pr_conf`
    # are the SAME kind of record with the same floor; nothing downstream
    # distinguishes them.
    specs = [
        (acme, "pr_normal", "ACME", "Roadmap", "normal"),
        (acme, "pr_conf", "CONF", "Board deck", "confidential"),
        (acme, "pr_canary", "CANARY", "Q4 compensation review", "canary"),
        (globex, "pr_globex", "GX", "Globex roadmap", "normal")
    ];
    projects: dict = {};
    for spec in specs {
        tnode = spec[0];
        proj = (tnode +>:Owns:+> Project(
            project_id=str(spec[1]),
            tenant_id=tnode.tenant_id,
            key=str(spec[2]),
            name=str(spec[3]),
            sensitivity=str(spec[4]),
            status="active",
            owner_user_id="u_owner",
            created_at=ts,
            updated_at=ts
        ))[0];
        projects[str(spec[1])] = proj;
    }

    # A task's effective sensitivity is stricter(project, task), so BOTH
    # directions of inheritance have to exist in the fixture or a filter that
    # only looks at one of them passes vacuously:
    #
    #   tk_conf   -- a CONFIDENTIAL child under a NORMAL parent. The parent is
    #                reachable by a member, so nothing above the task itself
    #                keeps it out of `task.list`. This is the row that fails if
    #                a list operation skips the per-record floor.
    #   tk_canary -- a NORMAL child under the CANARY parent. Its own field says
    #                `normal`, so a floor that reads only the record's own
    #                sensitivity waves it through -- while the project it lives
    #                in is the one record the whole demo exists to protect.
    tspecs = [
        ("pr_normal", "tk_normal", "Ship the beta", "normal"),
        ("pr_normal", "tk_conf", "Severance terms", "confidential"),
        ("pr_canary", "tk_canary", "Compensation bands", "normal"),
        ("pr_globex", "tk_globex", "Globex launch", "normal")
    ];
    tasks: dict = {};
    for tspec in tspecs {
        pnode = projects[str(tspec[0])];
        tk = (pnode +>:Contains:+> Task(
            task_id=str(tspec[1]),
            project_id=str(tspec[0]),
            title=str(tspec[2]),
            status="open",
            sensitivity=str(tspec[3]),
            created_by="u_owner",
            created_at=ts,
            updated_at=ts
        ))[0];
        tasks[str(tspec[1])] = tk;
    }

    # A Comment carries no sensitivity of its own -- it inherits its task's
    # effective value. `cm_conf` and `cm_canary` hang off the two inheriting
    # tasks above so `comment.list` has something to leak if the parent's
    # effective sensitivity is not the thing being gated on.
    cspecs = [
        ("tk_normal", "cm_normal", "Looks good to me.", "u_member", "pr_normal"),
        ("tk_conf", "cm_conf", "Numbers attached.", "u_owner", "pr_normal"),
        ("tk_canary", "cm_canary", "Band ranges below.", "u_owner", "pr_canary"),
        ("tk_globex", "cm_globex", "Globex internal note.", "u_globex", "pr_globex")
    ];
    for cspec in cspecs {
        tnode2 = tasks[str(cspec[0])];
        tnode2 +>:Discusses:+> Comment(
            comment_id=str(cspec[1]),
            task_id=str(cspec[0]),
            project_id=str(cspec[4]),
            body=str(cspec[2]),
            author_id=str(cspec[3]),
            created_at=ts
        );
    }
    return None;
}

"""The stable ids a test refers to. Handles are re-resolved on demand rather
than cached, so a test always sees current graph state."""
def:pub snapshot() -> dict {
    return {
        "acme": "t_acme",
        "globex": "t_globex",
        "normal_project": "pr_normal",
        "conf_project": "pr_conf",
        "canary_project": "pr_canary",
        "globex_project": "pr_globex",
        "normal_task": "tk_normal",
        "conf_task": "tk_conf",
        "canary_task": "tk_canary",
        "globex_task": "tk_globex",
        "normal_comment": "cm_normal",
        "conf_comment": "cm_conf",
        "canary_comment": "cm_canary",
        "globex_comment": "cm_globex"
    };
}

# --------------------------------------------------------------------------
# Signed request contexts.
# --------------------------------------------------------------------------

"""A fully-populated, correctly-signed ctx for `session_id`.

The signature is produced by the SAME function the gateway uses, so these
payloads are indistinguishable from real ones -- which is the point: the tests
exercise the real verification path, not a stubbed one."""
def:pub ctx_for(
    session_id: str,
    route: str = "/api/v1/x",
    method: str = "GET",
    request_id: str = "req_test",
    auth_age_ms: int = 0
) -> dict {
    ts = now_ms();
    # Built FROM ctxsig.SIGNED_FIELDS, not from a hand-written list: when a new
    # field is added to ReqCtx and to SIGNED_FIELDS, these fixtures sign it
    # automatically. A hand-written list would leave the new field unsigned and
    # every test here would quietly stop covering it.
    fields: dict = {};
    for name in SIGNED_FIELDS {
        fields[name] = _stock_value(name, session_id, route, method, request_id, ts, auth_age_ms);
    }
    fields["sig"] = sign_ctx(fields);
    return fields;
}

"""The value this fixture uses for one signed ctx field."""
def _stock_value(
    name: str, session_id: str, route: str, method: str,
    request_id: str, ts: int, auth_age_ms: int
) -> object {
    stock: dict = {
        "request_id": request_id,
        "src_ip": "203.0.113.10",
        "src_asn": "AS64500",
        "user_agent_hash": "ua_test",
        "client_fp": "fp_test",
        "session_id": session_id,
        "token_id": "",
        "service": "web",
        "route": route,
        "http_method": method,
        "csrf_ok": True,
        "received_at_ms": ts,
        "sig_alg": "HMAC-SHA256",
        "issued_at_ms": ts,
        # The step-up clock. 0 would read as "never authenticated"; the default
        # here is "a password was presented just now", and a test that wants a
        # stale step-up passes auth_age_ms explicitly.
        "session_auth_at_ms": ts - auth_age_ms
    };
    if name in stock {
        return stock[name];
    }
    # An unknown signed field is filled with a type-appropriate empty value
    # rather than skipped, so the canonical form still matches the signer's.
    if name.endswith("_ms") or name.endswith("_at") {
        return 0;
    }
    return "";
}
