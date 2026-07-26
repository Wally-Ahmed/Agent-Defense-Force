# tests/test_roles.test.jac — role escalation is denied, and fails closed.
#
# Every case here builds a real principal with a real membership at a real role
# and asks guard() for a real decision. Nothing calls role_satisfies() directly
# except the pure-policy tests at the bottom: testing the helper would prove the
# helper works, not that the helper is on the path a request actually takes.
#
# The two most important tests in this file are the ones that check the FAIL
# DIRECTION rather than the happy path:
#
#   - a membership whose state is "removed" is denied even at role owner, so
#     revocation beats seniority
#   - a membership whose role is a value the table has never heard of is
#     denied, not allowed, so a corrupted or injected role cannot escalate
#
# The graph persists between processes in .jac/data, so every fixture id is
# prefixed with a per-run token and no test asserts on a global count.

import secrets;
import from typing { cast }
import from contracts.req_ctx_contract { ReqCtx, Grant, guard }
import from app.model.graph {
    Platform, Tenant, Membership, Principal, Session, Project, Task,
    Hosts, Registers, HasMember, Identifies, Owns, Contains, Authenticates,
    get_platform
}
import from app.security.clock { now_ms, SESSION_TTL_MS }
import from app.security.ctxsig { sign_ctx }
import from app.security.roles {
    ROLE_RANK, ACTION_MIN_ROLE, rank_of, role_satisfies, min_role_for,
    assert_policy_complete, policy_gaps, policy_strays, requires_stepup,
    is_write_action
}

# --------------------------------------------------------------------------
# Fixture builder. One tenant, one project, one task, and a principal at
# whatever role the caller names, with a live tenant-scoped session.
# --------------------------------------------------------------------------

"""Unique-per-run id prefix, so a rerun never collides with a persisted graph."""
def run_tag() -> str {
    return secrets.token_hex(4);
}

"""Build a tenant + principal + membership at `role` + session, and return the
ids the tests need. `state` lets a test build a REMOVED membership."""
def make_actor(tag: str, who: str, role: str, state: str = "active") -> dict {
    p = get_platform();
    now = now_ms();
    tid = "T-" + tag;

    existing = [p->:Hosts:->][?:Tenant][?tenant_id == tid];
    if len(existing) > 0 {
        tenant = existing[0];
    } else {
        tenant = (p +>:Hosts:+> Tenant(tenant_id=tid, name="Acme " + tag))[0];
        project = (tenant +>:Owns:+> Project(
            project_id="PR-" + tag, tenant_id=tid, key="ACME"
        ))[0];
        project +>:Contains:+> Task(
            task_id="TK-" + tag, project_id="PR-" + tag, title="a task"
        );
    }

    pid = "P-" + tag + "-" + who;
    principal = (p +>:Registers:+> Principal(
        principal_id=pid, email=who + "." + tag + "@example.com", pw_hash="unused"
    ))[0];

    membership = (tenant +>:HasMember:+> Membership(
        membership_id="M-" + tag + "-" + who,
        principal_id=pid,
        tenant_id=tid,
        role=role,
        state=state
    ))[0];
    membership +>:Identifies:+> principal;

    sid = "S-" + tag + "-" + who;
    principal +>:Authenticates:+> Session(
        session_id=sid,
        principal_id=pid,
        tenant_id=tid,
        ip_first="10.0.0.7",
        fp="fp-" + tag,
        issued_at=now,
        expires_at=now + SESSION_TTL_MS,
        last_auth_at=now,
        revoked=False
    );

    return {
        "tenant_id": tid,
        "principal_id": pid,
        "session_id": sid,
        "project_id": "PR-" + tag,
        "task_id": "TK-" + tag
    };
}

"""A freshly signed, fresh-authentication ctx for `session_id`.

`session_auth_at_ms` is stamped NOW so that the step-up gate on the four
irreversible operations is satisfied and these tests measure ROLE, not
authentication recency -- that is test_auth's job."""
def ctx_for(session_id: str) -> ReqCtx {
    now = now_ms();
    fields: dict = {
        "request_id": "req-" + secrets.token_hex(3),
        "src_ip": "10.0.0.7",
        "src_asn": "AS64500",
        "user_agent_hash": "uah",
        "client_fp": "fp-test",
        "session_id": session_id,
        "token_id": "",
        "service": "web",
        "route": "/test",
        "http_method": "POST",
        "csrf_ok": True,
        "received_at_ms": now,
        "sig_alg": "HMAC-SHA256",
        "issued_at_ms": now,
        "session_auth_at_ms": now
    };
    fields["sig"] = sign_ctx(fields);
    return ReqCtx(**fields);
}

# --------------------------------------------------------------------------
# 1. viewer
# --------------------------------------------------------------------------

test "a viewer may read a project but may not delete one" {
    a = make_actor(run_tag(), "viewer", "viewer");
    c = ctx_for(a["session_id"]);

    allowed = guard(c, "project.read", "project", a["tenant_id"], a["project_id"]);
    assert allowed.ok;
    assert allowed.reason == "";

    denied = guard(c, "project.delete", "project", a["tenant_id"], a["project_id"]);
    assert not denied.ok;
    assert denied.reason == "INSUFFICIENT_ROLE";
}

test "a viewer may not create a project" {
    a = make_actor(run_tag(), "viewer", "viewer");
    c = ctx_for(a["session_id"]);
    g = guard(c, "project.create", "project", a["tenant_id"]);
    assert not g.ok;
    assert g.reason == "INSUFFICIENT_ROLE";
}

# --------------------------------------------------------------------------
# 2. member
# --------------------------------------------------------------------------

test "a member may create a project but may not delete one or invite" {
    a = make_actor(run_tag(), "member", "member");
    c = ctx_for(a["session_id"]);

    created = guard(c, "project.create", "project", a["tenant_id"]);
    assert created.ok;

    deleted = guard(c, "project.delete", "project", a["tenant_id"], a["project_id"]);
    assert not deleted.ok;
    assert deleted.reason == "INSUFFICIENT_ROLE";

    invited = guard(c, "member.invite", "invite", a["tenant_id"]);
    assert not invited.ok;
    assert invited.reason == "INSUFFICIENT_ROLE";
}

# --------------------------------------------------------------------------
# 3. admin
# --------------------------------------------------------------------------

test "an admin may delete and invite but may not apply containment" {
    a = make_actor(run_tag(), "admin", "admin");
    c = ctx_for(a["session_id"]);

    deleted = guard(c, "project.delete", "project", a["tenant_id"], a["project_id"]);
    assert deleted.ok;

    invited = guard(c, "member.invite", "invite", a["tenant_id"]);
    assert invited.ok;

    contained = guard(c, "containment.apply", "tenant", a["tenant_id"]);
    assert not contained.ok;
    assert contained.reason == "INSUFFICIENT_ROLE";
}

# --------------------------------------------------------------------------
# 4. owner
# --------------------------------------------------------------------------

test "an owner may do all of the above including containment" {
    a = make_actor(run_tag(), "owner", "owner");
    c = ctx_for(a["session_id"]);

    assert guard(c, "project.delete", "project", a["tenant_id"], a["project_id"]).ok;
    assert guard(c, "member.invite", "invite", a["tenant_id"]).ok;
    assert guard(c, "containment.apply", "tenant", a["tenant_id"]).ok;
}

# --------------------------------------------------------------------------
# 5. Revocation beats seniority.
# --------------------------------------------------------------------------

test "a removed membership is denied even at role owner" {
    a = make_actor(run_tag(), "exowner", "owner", "removed");
    c = ctx_for(a["session_id"]);

    # Not INSUFFICIENT_ROLE: the role is the highest there is. The membership
    # simply is not active, so there is no membership to carry a role at all.
    g = guard(c, "project.read", "project", a["tenant_id"], a["project_id"]);
    assert not g.ok;
    assert g.reason == "NOT_A_MEMBER";

    hard = guard(c, "containment.apply", "tenant", a["tenant_id"]);
    assert not hard.ok;
    assert hard.reason == "NOT_A_MEMBER";
}

# --------------------------------------------------------------------------
# 6. Unknown roles fail CLOSED.
# --------------------------------------------------------------------------

test "a role the table has never heard of authorizes nothing" {
    a = make_actor(run_tag(), "fake", "superadmin");
    c = ctx_for(a["session_id"]);

    # "superadmin" sounds more powerful than "owner" and is worth less than
    # "viewer". rank_of returns -1 for anything off the table, so an injected
    # or corrupted role value can never satisfy a requirement -- not even the
    # weakest one.
    g = guard(c, "project.read", "project", a["tenant_id"], a["project_id"]);
    assert not g.ok;
    assert g.reason == "INSUFFICIENT_ROLE";

    assert rank_of("superadmin") == -1;
    assert not role_satisfies("superadmin", "viewer");
}

test "an empty role string authorizes nothing" {
    a = make_actor(run_tag(), "blank", "");
    c = ctx_for(a["session_id"]);
    g = guard(c, "project.read", "project", a["tenant_id"], a["project_id"]);
    assert not g.ok;
    assert g.reason == "INSUFFICIENT_ROLE";
}

# --------------------------------------------------------------------------
# 7. The policy table itself.
# --------------------------------------------------------------------------

test "every frozen action has a role assignment and there are no strays" {
    # A gap means an action nobody assigned a role to; a stray means an entry
    # for an action that no longer exists. Either is a silent policy hole.
    gaps: str = ", ".join(policy_gaps());
    assert gaps == "", "actions with no role assignment: " + gaps;

    strays: str = ", ".join(policy_strays());
    assert strays == "", "policy entries that are not real actions: " + strays;

    assert assert_policy_complete();
}

test "an unlisted action fails closed at the strictest role" {
    # Not "viewer", not "" -- an action nobody has classified must be treated
    # as the most dangerous thing it could be.
    assert min_role_for("some.action.that.does.not.exist") == "owner";
    assert not role_satisfies("admin", min_role_for("some.action.that.does.not.exist"));
}

test "the rank ladder is strictly ordered" {
    assert rank_of("viewer") < rank_of("member");
    assert rank_of("member") < rank_of("admin");
    assert rank_of("admin") < rank_of("owner");
    assert role_satisfies("owner", "viewer");
    assert role_satisfies("admin", "member");
    assert not role_satisfies("member", "admin");
    assert not role_satisfies("viewer", "member");
}

test "an unclassified action is treated as a write for read-only mode" {
    # is_write_action defaults to True for anything not on READ_ACTIONS, so a
    # newly added action gets BLOCKED by a feature_readonly control rather than
    # sailing through it.
    assert is_write_action("some.action.that.does.not.exist");
    assert is_write_action("project.delete");
    assert not is_write_action("project.read");
}

test "the four irreversible operations demand step-up authentication" {
    assert requires_stepup("member.role_change");
    assert requires_stepup("member.remove");
    assert requires_stepup("export.request");
    assert requires_stepup("export.download");
    assert not requires_stepup("project.read");
    assert not requires_stepup("task.list");
}
