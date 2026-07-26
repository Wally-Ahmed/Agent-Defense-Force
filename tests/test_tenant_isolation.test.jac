# tests/test_tenant_isolation.test.jac — THE headline test.
#
# The claim under test: a resource belonging to tenant B is not reachable by a
# member of tenant A. Not "is compared and rejected" -- UNREACHABLE, because
# every lookup in app/model/resolve.jac starts at a Tenant node and walks the
# typed ownership edges. There is no code path that could return it.
#
# Two distinct denials prove two distinct halves of the boundary:
#
#   NOT_FOUND        -- the id is VALID and the record EXISTS, but the caller
#                       asked inside their OWN tenant, so the traversal from
#                       tenant A never visits it. Nothing "checked" the id.
#   TENANT_MISMATCH  -- the caller named tenant B explicitly. Their credential
#                       is bound to tenant A, so the crossing attempt is
#                       refused before any resolution happens at all.
#
# A test that only proved denial would also pass on a completely broken system,
# so every scenario is paired with a positive control that must still succeed.
#
# GRAPH PERSISTENCE: .jac/data/anchor_store.db survives between processes, so
# every fixture id is prefixed with a per-run random tag. Nothing here asserts
# on a global count of anything.

import secrets;
import from typing { cast }
import from contracts.req_ctx_contract { ReqCtx, Grant, guard }
import from app.model.graph {
    Platform, Tenant, Membership, Principal, Session, Project, Task, Comment,
    Hosts, Registers, HasMember, Identifies, Owns, Contains, Discusses, Authenticates,
    get_platform
}
import from app.model.resolve {
    tenant_by_id, project_in, task_in, comment_in
}
import from app.security.clock { now_ms, SESSION_TTL_MS }
import from app.security.ctxsig { sign_ctx }

# --------------------------------------------------------------------------
# Shared fixture. Jac test files are standalone modules, so the builder lives
# here rather than in a shared helper module.
# --------------------------------------------------------------------------

"""A per-run token. Fixture ids built from it cannot collide with rows a
previous run left behind in the persistent anchor store."""
def new_tag() -> str {
    return "iso-" + secrets.token_hex(4);
}

"""Sign a ctx exactly the way the gateway does, through the one canonical
implementation in app/security/ctxsig.jac. A test that hand-rolled the HMAC
would be testing its own arithmetic, not the system's."""
def mk_ctx(session_id: str, ip: str = "10.0.0.1") -> ReqCtx {
    now = now_ms();
    fields: dict = {
        "request_id": "req-" + secrets.token_hex(3),
        "src_ip": ip,
        "src_asn": "AS64500",
        "user_agent_hash": "uah",
        "client_fp": "fp-iso",
        "session_id": session_id,
        "token_id": "",
        "service": "web",
        "route": "/test",
        "http_method": "GET",
        "csrf_ok": True,
        "received_at_ms": now,
        "sig_alg": "HMAC-SHA256",
        "issued_at_ms": now
    };
    fields["sig"] = sign_ctx(fields);
    return ReqCtx(**fields);
}

"""Build two tenants, each with a project, a task and a comment, plus ONE
principal who is an active `member` of tenant A only, holding a live session
scoped to tenant A.

Ids are derived from `tag`, so a caller reconstructs any of them without the
builder handing back node handles. Returns nothing on purpose: the test must
reach the fixture the way production code does -- by traversal."""
def build(tag: str) {
    p = get_platform();
    now = now_ms();

    ta = (p +>:Hosts:+> Tenant(tenant_id=tag + "-tA", name="Tenant A"))[0];
    tb = (p +>:Hosts:+> Tenant(tenant_id=tag + "-tB", name="Tenant B"))[0];

    alice = (p +>:Registers:+> Principal(
        principal_id=tag + "-pA", email=tag + "-alice@example.com", pw_hash="x"
    ))[0];

    # Membership in tenant A ONLY. There is deliberately no membership in B.
    ma = (ta +>:HasMember:+> Membership(
        membership_id=tag + "-mA", principal_id=tag + "-pA",
        tenant_id=tag + "-tA", role="member", state="active"
    ))[0];
    ma +>:Identifies:+> alice;

    alice +>:Authenticates:+> Session(
        session_id=tag + "-sA", principal_id=tag + "-pA", tenant_id=tag + "-tA",
        issued_at=now, expires_at=now + SESSION_TTL_MS, last_auth_at=now
    );

    projA = (ta +>:Owns:+> Project(
        project_id=tag + "-prA", tenant_id=tag + "-tA", key="A1"
    ))[0];
    taskA = (projA +>:Contains:+> Task(
        task_id=tag + "-tkA", project_id=tag + "-prA", title="A task"
    ))[0];
    taskA +>:Discusses:+> Comment(
        comment_id=tag + "-cmA", task_id=tag + "-tkA", body="A comment",
        author_id=tag + "-pA"
    );

    projB = (tb +>:Owns:+> Project(
        project_id=tag + "-prB", tenant_id=tag + "-tB", key="B1"
    ))[0];
    taskB = (projB +>:Contains:+> Task(
        task_id=tag + "-tkB", project_id=tag + "-prB", title="B SECRET"
    ))[0];
    taskB +>:Discusses:+> Comment(
        comment_id=tag + "-cmB", task_id=tag + "-tkB", body="B SECRET comment",
        author_id="someone-else"
    );
}

# --------------------------------------------------------------------------
# Tasks
# --------------------------------------------------------------------------

test "a foreign task id asked for inside the caller's own tenant is NOT_FOUND" {
    tag = new_tag();
    build(tag);
    ctx = mk_ctx(tag + "-sA");

    # The id is VALID and the record EXISTS -- see the resolver test below,
    # which fetches the very same task out of tenant B. It is unreachable here
    # because the traversal never leaves tenant A, not because a check rejected
    # it. Nothing in guard() ever compared taskB.tenant_id to anything.
    g = guard(ctx, "task.read", "task", tag + "-tA", tag + "-tkB");
    assert not g.ok;
    assert g.reason == "NOT_FOUND";
}

test "naming tenant B with a tenant-A credential is TENANT_MISMATCH" {
    tag = new_tag();
    build(tag);
    ctx = mk_ctx(tag + "-sA");

    g = guard(ctx, "task.read", "task", tag + "-tB", tag + "-tkB");
    assert not g.ok;
    assert g.reason == "TENANT_MISMATCH";
}

test "the member CAN read a task in their own tenant (positive control)" {
    tag = new_tag();
    build(tag);
    ctx = mk_ctx(tag + "-sA");

    # Without this, every assertion above would still pass on a system that
    # denied absolutely everything.
    g = guard(ctx, "task.read", "task", tag + "-tA", tag + "-tkA");
    assert g.ok;
    assert g.reason == "";
    assert cast(Task, g.node).task_id == tag + "-tkA";
}

# --------------------------------------------------------------------------
# Projects
# --------------------------------------------------------------------------

test "a foreign project id asked for inside the caller's own tenant is NOT_FOUND" {
    tag = new_tag();
    build(tag);
    ctx = mk_ctx(tag + "-sA");

    g = guard(ctx, "project.read", "project", tag + "-tA", tag + "-prB");
    assert not g.ok;
    assert g.reason == "NOT_FOUND";
}

test "naming tenant B for a project is TENANT_MISMATCH" {
    tag = new_tag();
    build(tag);
    ctx = mk_ctx(tag + "-sA");

    g = guard(ctx, "project.read", "project", tag + "-tB", tag + "-prB");
    assert not g.ok;
    assert g.reason == "TENANT_MISMATCH";
}

test "the member CAN read a project in their own tenant (positive control)" {
    tag = new_tag();
    build(tag);
    ctx = mk_ctx(tag + "-sA");

    g = guard(ctx, "project.read", "project", tag + "-tA", tag + "-prA");
    assert g.ok;
    assert g.reason == "";
    assert cast(Project, g.node).project_id == tag + "-prA";
}

# --------------------------------------------------------------------------
# Comments -- three hops deep, the longest traversal in the model.
# --------------------------------------------------------------------------

test "a foreign comment id asked for inside the caller's own tenant is NOT_FOUND" {
    tag = new_tag();
    build(tag);
    ctx = mk_ctx(tag + "-sA");

    g = guard(ctx, "comment.read", "comment", tag + "-tA", tag + "-cmB");
    assert not g.ok;
    assert g.reason == "NOT_FOUND";
}

test "naming tenant B for a comment is TENANT_MISMATCH" {
    tag = new_tag();
    build(tag);
    ctx = mk_ctx(tag + "-sA");

    g = guard(ctx, "comment.read", "comment", tag + "-tB", tag + "-cmB");
    assert not g.ok;
    assert g.reason == "TENANT_MISMATCH";
}

test "the member CAN read a comment in their own tenant (positive control)" {
    tag = new_tag();
    build(tag);
    ctx = mk_ctx(tag + "-sA");

    g = guard(ctx, "comment.read", "comment", tag + "-tA", tag + "-cmA");
    assert g.ok;
    assert g.reason == "";
    assert cast(Comment, g.node).comment_id == tag + "-cmA";
}

# --------------------------------------------------------------------------
# The resolver, directly. This is where the isolation actually lives: guard()
# only reports what the traversal could reach. If these assertions hold, the
# boundary is structural and no amount of forgetting an `if` can move it.
# --------------------------------------------------------------------------

test "task_in() cannot reach tenant B's task from tenant A, but can from tenant B" {
    tag = new_tag();
    build(tag);

    # `tenant_by_id` is one of the two deliberate non-traversal lookups: a
    # Tenant is the root of a tenancy, so there is nothing above it to walk from.
    tA = cast(Tenant, tenant_by_id(tag + "-tA"));
    tB = cast(Tenant, tenant_by_id(tag + "-tB"));

    assert task_in(tA, tag + "-tkB") is None;
    assert task_in(tB, tag + "-tkB") is not None;

    # And the mirror image, so the asymmetry is not an artifact of ordering.
    assert task_in(tB, tag + "-tkA") is None;
    assert task_in(tA, tag + "-tkA") is not None;
}

test "project_in() and comment_in() are isolated the same way" {
    tag = new_tag();
    build(tag);

    tA = cast(Tenant, tenant_by_id(tag + "-tA"));
    tB = cast(Tenant, tenant_by_id(tag + "-tB"));

    assert project_in(tA, tag + "-prB") is None;
    assert project_in(tB, tag + "-prB") is not None;

    assert comment_in(tA, tag + "-cmB") is None;
    assert comment_in(tB, tag + "-cmB") is not None;
}
