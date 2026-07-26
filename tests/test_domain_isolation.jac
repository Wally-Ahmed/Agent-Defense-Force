# tests/test_domain_isolation.jac -- the isolation guarantee, exercised through
# the domain walkers.
#
# Run from the repo root (Jac resolves imports relative to the INVOCATION cwd):
#
#     APP_CTX_SIGNING_KEY=<64 hex> jac test tests/test_domain_isolation.jac
#
# THE CLAIM UNDER TEST: a fully authenticated, fully authorized member of tenant
# A, holding a REAL id belonging to tenant B, cannot read, update or delete it --
# and the answer is a 404 indistinguishable from the answer for an id that never
# existed.
#
# `pr_globex` is not a decoy. It exists, it is active, and a Globex member reads
# it happily. The Acme caller passes every check up to and including the role
# gate. The only thing between them and the record is that the traversal from
# their own tenant never reaches it.
#
# Each case also asserts the trail: exactly one AuditEvent, outcome `deny`.

import from tests.fixtures { world, ctx_for }
import from tests.helpers { audit_count, only_event }
import from app.services.projects { ReadProject, UpdateProject, DeleteProject, ListProjects }

glob:pub W: dict = world();

test "an Acme member cannot READ a Globex project by its real id" {
    mark = audit_count();
    w = ReadProject(
        ctx=ctx_for("s_member", "/api/v1/tenants/t_acme/projects/pr_globex", "GET"),
        tenant_id="t_acme",
        project_id="pr_globex"
    ) spawn root;
    r = w.reports[0];
    print("CROSS-TENANT READ ->", r);
    assert r["ok"] == False;
    assert r["status"] == 404;
    assert r["error"]["code"] == "NOT_FOUND";

    ev = only_event(mark);
    print("  audit:", ev);
    assert ev["action"] == "project.read";
    assert ev["outcome"] == "deny";
    assert ev["reason"] == "NOT_FOUND";
}

test "the 404 for a foreign id is identical to the 404 for a fictional id" {
    real_foreign = ReadProject(
        ctx=ctx_for("s_member", "/api/v1/tenants/t_acme/projects/pr_globex", "GET"),
        tenant_id="t_acme", project_id="pr_globex"
    ) spawn root;
    never_existed = ReadProject(
        ctx=ctx_for("s_member", "/api/v1/tenants/t_acme/projects/pr_nope", "GET"),
        tenant_id="t_acme", project_id="pr_nope"
    ) spawn root;
    a = real_foreign.reports[0];
    b = never_existed.reports[0];
    print("FOREIGN :", a);
    print("FICTION :", b);
    assert a["status"] == b["status"];
    assert a["error"]["code"] == b["error"]["code"];
    assert a["error"]["message"] == b["error"]["message"];
}

test "an Acme member cannot UPDATE a Globex project" {
    mark = audit_count();
    w = UpdateProject(
        ctx=ctx_for("s_member", "/api/v1/tenants/t_acme/projects/pr_globex", "PATCH"),
        tenant_id="t_acme", project_id="pr_globex", name="pwned"
    ) spawn root;
    r = w.reports[0];
    print("CROSS-TENANT UPDATE ->", r);
    assert r["ok"] == False;
    assert r["status"] == 404;
    assert r["error"]["code"] == "NOT_FOUND";
    ev = only_event(mark);
    print("  audit:", ev);
    assert ev["action"] == "project.update";
    assert ev["outcome"] == "deny";
}

test "an Acme OWNER cannot DELETE a Globex project -- rank does not cross" {
    mark = audit_count();
    w = DeleteProject(
        ctx=ctx_for("s_owner", "/api/v1/tenants/t_acme/projects/pr_globex", "DELETE"),
        tenant_id="t_acme", project_id="pr_globex"
    ) spawn root;
    r = w.reports[0];
    print("CROSS-TENANT DELETE (as owner) ->", r);
    assert r["ok"] == False;
    assert r["status"] == 404;
    assert r["error"]["code"] == "NOT_FOUND";
    ev = only_event(mark);
    print("  audit:", ev);
    assert ev["action"] == "project.delete";
    assert ev["outcome"] == "deny";
}

test "a Globex session addressing Acme is TENANT_MISMATCH, escalated high" {
    mark = audit_count();
    w = ListProjects(
        ctx=ctx_for("s_globex", "/api/v1/tenants/t_acme/projects", "GET"),
        tenant_id="t_acme"
    ) spawn root;
    r = w.reports[0];
    print("CREDENTIAL CROSSING ->", r);
    assert r["ok"] == False;
    assert r["error"]["code"] == "TENANT_MISMATCH";
    ev = only_event(mark);
    print("  audit:", ev);
    assert ev["outcome"] == "deny";
    assert ev["reason"] == "TENANT_MISMATCH";
    # vocab.md escalates a crossing attempt unconditionally: it is the
    # lateral-movement signal the monitor watches for.
    assert ev["severity"] == "high";
}

test "listing Acme projects never returns a Globex record" {
    w = ListProjects(
        ctx=ctx_for("s_owner", "/api/v1/tenants/t_acme/projects", "GET"),
        tenant_id="t_acme", limit=100
    ) spawn root;
    r = w.reports[0];
    assert r["ok"] == True;
    items: list = r["data"]["items"];
    ids = [i["project_id"] for i in items];
    print("ACME PROJECTS (as owner):", ids);
    assert "pr_globex" not in ids;
    for i in items {
        assert i["tenant_id"] == "t_acme";
    }
}
