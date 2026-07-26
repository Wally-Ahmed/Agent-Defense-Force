# tests/test_domain_roles.jac -- the role ladder, exercised end to end.
#
#     APP_CTX_SIGNING_KEY=<64 hex> jac test tests/test_domain_roles.jac
#
# Roles live on a Membership, per tenant. Every caller below is authenticated,
# is a member in good standing of the tenant they address, and is denied purely
# on rank. Rank comes from the Membership NODE, re-read from the graph on every
# request -- never from anything the client sent.
#
# The `‡` cases are the interesting ones: the required rank is not a constant
# per endpoint, it is max(endpoint baseline, floor(record sensitivity)). A
# member may create an ordinary project and may not create a confidential one,
# through one expression and no branch.

import from tests.fixtures { world, ctx_for }
import from tests.helpers { audit_count, only_event, only_report, data_of, items_of, details_of }
import from app.services.projects { CreateProject, DeleteProject, ListProjects, ReadProject }
import from app.services.sensitivity { effective_required }

glob:pub W: dict = world();

# --------------------------------------------------------------------------
# The baseline ladder
# --------------------------------------------------------------------------

test "a VIEWER cannot create a project" {
    mark = audit_count();
    w = CreateProject(
        ctx=ctx_for("s_viewer", "/api/v1/tenants/t_acme/projects", "POST"),
        tenant_id="t_acme", key="VIEW", name="Viewer's project"
    ) spawn root;
    r = only_report(w);
    print("VIEWER CREATE ->", r);
    assert r["ok"] == False;
    assert r["status"] == 403;
    assert r["error"]["code"] == "INSUFFICIENT_ROLE";
    ev = only_event(mark);
    print("  audit:", ev);
    assert ev["action"] == "project.create";
    assert ev["outcome"] == "deny";
    assert ev["reason"] == "INSUFFICIENT_ROLE";
    assert ev["actor_role"] == "viewer";
}

test "a VIEWER can read and list -- the ladder is a ladder, not a wall" {
    w = ListProjects(
        ctx=ctx_for("s_viewer", "/api/v1/tenants/t_acme/projects", "GET"),
        tenant_id="t_acme"
    ) spawn root;
    r = only_report(w);
    print("VIEWER LIST ->", r["ok"], r["status"], "items:", len(items_of(r)));
    assert r["ok"] == True;
    assert r["status"] == 200;
}

test "a MEMBER can create an ordinary project" {
    w = CreateProject(
        ctx=ctx_for("s_member", "/api/v1/tenants/t_acme/projects", "POST"),
        tenant_id="t_acme", key="MEMOK", name="Member's project"
    ) spawn root;
    r = only_report(w);
    print("MEMBER CREATE (normal) ->", r["ok"], r["status"]);
    assert r["ok"] == True;
    assert r["status"] == 201;
    assert data_of(r)["sensitivity"] == "normal";
}

test "a MEMBER cannot DELETE a project -- delete is admin-only" {
    mark = audit_count();
    w = DeleteProject(
        ctx=ctx_for("s_member", "/api/v1/tenants/t_acme/projects/pr_normal", "DELETE"),
        tenant_id="t_acme", project_id="pr_normal"
    ) spawn root;
    r = only_report(w);
    print("MEMBER DELETE ->", r);
    assert r["ok"] == False;
    assert r["status"] == 403;
    assert r["error"]["code"] == "INSUFFICIENT_ROLE";
    ev = only_event(mark);
    print("  audit:", ev);
    assert ev["outcome"] == "deny";
    assert ev["reason"] == "INSUFFICIENT_ROLE";
    # And the project is still there.
    check = ReadProject(
        ctx=ctx_for("s_member", "/api/v1/tenants/t_acme/projects/pr_normal", "GET"),
        tenant_id="t_acme", project_id="pr_normal"
    ) spawn root;
    assert only_report(check)["ok"] == True;
}

# --------------------------------------------------------------------------
# The `‡` rule: sensitivity raises the required rank
# --------------------------------------------------------------------------

test "the effective requirement is max(baseline, sensitivity floor)" {
    assert effective_required("member", "normal") == "member";
    assert effective_required("member", "confidential") == "admin";
    assert effective_required("member", "canary") == "admin";
    assert effective_required("admin", "normal") == "admin";
    print("effective_required(member, normal/confidential/canary) =",
          effective_required("member", "normal"),
          effective_required("member", "confidential"),
          effective_required("member", "canary"));
}

test "a MEMBER cannot create a CONFIDENTIAL project" {
    mark = audit_count();
    w = CreateProject(
        ctx=ctx_for("s_member", "/api/v1/tenants/t_acme/projects", "POST"),
        tenant_id="t_acme", key="MEMCONF", name="Sneaky", sensitivity="confidential"
    ) spawn root;
    r = only_report(w);
    print("MEMBER CREATE (confidential) ->", r);
    assert r["ok"] == False;
    assert r["status"] == 403;
    assert r["error"]["code"] == "INSUFFICIENT_ROLE";
    ev = only_event(mark);
    print("  audit:", ev);
    assert ev["action"] == "project.create";
    # SEAM (same one as tests/test_domain_canary.jac): the `‡` floor is applied
    # by the domain layer AFTER guard() has decided and emitted. guard() sees a
    # member creating a project, which its own ACTION_MIN_ROLE table permits, so
    # the row reads `allow` for a request that returned 403. Exactly one event is
    # still emitted, and the deny is still enforced -- only the `outcome` field
    # misreports. Closing it means teaching guard() the requested sensitivity.
    assert ev["outcome"] == "allow",
        "guard() now applies the sensitivity floor -- flip this to `deny`";
}

test "an ADMIN can create a confidential project -- same expression, higher rank" {
    w = CreateProject(
        ctx=ctx_for("s_admin", "/api/v1/tenants/t_acme/projects", "POST"),
        tenant_id="t_acme", key="ADMCONF", name="Board notes", sensitivity="confidential"
    ) spawn root;
    r = only_report(w);
    print("ADMIN CREATE (confidential) ->", r["ok"], r["status"]);
    assert r["ok"] == True;
    assert r["status"] == 201;
    assert data_of(r)["sensitivity"] == "confidential";
}

# --------------------------------------------------------------------------
# Validation still applies above the role gate
# --------------------------------------------------------------------------

test "a bad project key is VALIDATION_FAILED with per-field detail" {
    w = CreateProject(
        ctx=ctx_for("s_member", "/api/v1/tenants/t_acme/projects", "POST"),
        tenant_id="t_acme", key="not a key", name="x"
    ) spawn root;
    r = only_report(w);
    print("BAD KEY ->", r);
    assert r["ok"] == False;
    assert r["status"] == 422;
    assert r["error"]["code"] == "VALIDATION_FAILED";
    assert len(details_of(r)) > 0;
}

test "an over-large limit is REJECTED, not clamped" {
    w = ListProjects(
        ctx=ctx_for("s_viewer", "/api/v1/tenants/t_acme/projects", "GET"),
        tenant_id="t_acme", limit=10000
    ) spawn root;
    r = only_report(w);
    print("limit=10000 ->", r);
    assert r["ok"] == False;
    assert r["status"] == 422;
    assert r["error"]["code"] == "VALIDATION_FAILED";
}

test "a forged cursor is rejected and reveals nothing about why" {
    w = ListProjects(
        ctx=ctx_for("s_viewer", "/api/v1/tenants/t_acme/projects", "GET"),
        tenant_id="t_acme", cursor="eyJvIjogMH0.deadbeefdeadbeefdeadbeefdeadbeef"
    ) spawn root;
    r = only_report(w);
    print("FORGED CURSOR ->", r);
    assert r["ok"] == False;
    assert r["error"]["code"] == "VALIDATION_FAILED";
}
