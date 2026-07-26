# tests/test_domain_happy.jac -- the ordinary path, end to end.
#
#     APP_CTX_SIGNING_KEY=<64 hex> jac test tests/test_domain_happy.jac
#
# A member of Acme creates a project, a task on it and a comment on that task,
# then lists all three back. Every request must succeed, and every request must
# emit EXACTLY ONE AuditEvent carrying the right action.
#
# The "exactly one" assertion is the load-bearing half. contracts/vocab.md fixes
# the emission map at one event per guard() call -- not zero, not two -- because
# `result_count` and the rate signals the monitor reads are only meaningful if
# the count is exact. A walker that emitted its own event on top of guard's
# would double every number in the trail; a code path that skipped guard would
# be invisible in it. Both show up here as a failing count.

import from tests.fixtures { world, ctx_for }
import from tests.helpers { audit_count, only_event }
import from app.services.projects { CreateProject, ListProjects, ReadProject }
import from app.services.tasks { CreateTask, ListTasks, ReadTask }
import from app.services.comments { CreateComment, ListComments, ReadComment }

glob:pub W: dict = world();

# Ids minted during the run, shared between the ordered steps below.
glob:pub MADE: dict = {};

test "step 1 -- a member creates a project, one project.create event" {
    mark = audit_count();
    w = CreateProject(
        ctx=ctx_for("s_member", "/api/v1/tenants/t_acme/projects", "POST", "req_hp1"),
        tenant_id="t_acme", key="HAPPY", name="Happy path", description="built by a member"
    ) spawn root;
    r = w.reports[0];
    print("CREATE PROJECT ->", r);
    assert r["ok"] == True;
    assert r["status"] == 201;
    assert r["data"]["tenant_id"] == "t_acme";
    assert r["data"]["owner_user_id"] == "u_member";
    MADE["project_id"] = r["data"]["project_id"];

    ev = only_event(mark);
    print("  audit:", ev);
    assert ev["action"] == "project.create";
    assert ev["outcome"] == "allow";
    assert ev["reason"] == "";
    assert ev["actor_role"] == "member";
    assert ev["tenant_id"] == "t_acme";
}

test "step 2 -- the same member creates a task on it, one task.create event" {
    mark = audit_count();
    w = CreateTask(
        ctx=ctx_for("s_member", "/api/v1/tenants/t_acme/projects/x/tasks", "POST", "req_hp2"),
        tenant_id="t_acme", project_id=MADE["project_id"], title="Write the tests"
    ) spawn root;
    r = w.reports[0];
    print("CREATE TASK ->", r);
    assert r["ok"] == True;
    assert r["status"] == 201;
    assert r["data"]["project_id"] == MADE["project_id"];
    MADE["task_id"] = r["data"]["task_id"];

    ev = only_event(mark);
    print("  audit:", ev);
    assert ev["action"] == "task.create";
    assert ev["outcome"] == "allow";
    assert ev["actor_role"] == "member";
}

test "step 3 -- and a comment on that task, one comment.create event" {
    mark = audit_count();
    w = CreateComment(
        ctx=ctx_for("s_member", "/api/v1/tenants/t_acme/.../comments", "POST", "req_hp3"),
        tenant_id="t_acme",
        project_id=MADE["project_id"],
        task_id=MADE["task_id"],
        body="First."
    ) spawn root;
    r = w.reports[0];
    print("CREATE COMMENT ->", r);
    assert r["ok"] == True;
    assert r["status"] == 201;
    # Authorship comes from the authenticated principal, never from the body.
    assert r["data"]["author_user_id"] == "u_member";
    MADE["comment_id"] = r["data"]["comment_id"];

    ev = only_event(mark);
    print("  audit:", ev);
    assert ev["action"] == "comment.create";
    assert ev["outcome"] == "allow";
}

test "step 4 -- the project lists back, one project.list event" {
    mark = audit_count();
    w = ListProjects(
        ctx=ctx_for("s_member", "/api/v1/tenants/t_acme/projects", "GET", "req_hp4"),
        tenant_id="t_acme", limit=100
    ) spawn root;
    r = w.reports[0];
    assert r["ok"] == True;
    ids = [i["project_id"] for i in r["data"]["items"]];
    print("LIST PROJECTS ->", ids);
    assert MADE["project_id"] in ids;

    ev = only_event(mark);
    print("  audit:", ev);
    assert ev["action"] == "project.list";
    assert ev["outcome"] == "allow";
    # guard() MEASURES the collection rather than trusting the walker's own
    # count -- the exfiltration signal must not be self-reported.
    assert ev["result_count"] > 0;
}

test "step 5 -- the task lists back, one task.list event" {
    mark = audit_count();
    w = ListTasks(
        ctx=ctx_for("s_member", "/api/v1/tenants/t_acme/projects/x/tasks", "GET", "req_hp5"),
        tenant_id="t_acme", project_id=MADE["project_id"], limit=100
    ) spawn root;
    r = w.reports[0];
    assert r["ok"] == True;
    ids = [i["task_id"] for i in r["data"]["items"]];
    print("LIST TASKS ->", ids);
    assert MADE["task_id"] in ids;

    ev = only_event(mark);
    print("  audit:", ev);
    assert ev["action"] == "task.list";
    assert ev["outcome"] == "allow";
}

test "step 6 -- the comment lists back, one comment.list event" {
    mark = audit_count();
    w = ListComments(
        ctx=ctx_for("s_member", "/api/v1/tenants/t_acme/.../comments", "GET", "req_hp6"),
        tenant_id="t_acme", project_id=MADE["project_id"], task_id=MADE["task_id"], limit=100
    ) spawn root;
    r = w.reports[0];
    assert r["ok"] == True;
    ids = [i["comment_id"] for i in r["data"]["items"]];
    print("LIST COMMENTS ->", ids);
    assert MADE["comment_id"] in ids;

    ev = only_event(mark);
    print("  audit:", ev);
    assert ev["action"] == "comment.list";
    assert ev["outcome"] == "allow";
}

test "step 7 -- each record reads back individually, one event each" {
    mark = audit_count();
    pr = ReadProject(
        ctx=ctx_for("s_member", "/p", "GET", "req_hp7a"),
        tenant_id="t_acme", project_id=MADE["project_id"]
    ) spawn root;
    assert pr.reports[0]["ok"] == True;
    ev = only_event(mark);
    assert ev["action"] == "project.read";
    assert ev["outcome"] == "allow";

    mark2 = audit_count();
    tk = ReadTask(
        ctx=ctx_for("s_member", "/t", "GET", "req_hp7b"),
        tenant_id="t_acme", project_id=MADE["project_id"], task_id=MADE["task_id"]
    ) spawn root;
    assert tk.reports[0]["ok"] == True;
    ev2 = only_event(mark2);
    assert ev2["action"] == "task.read";
    assert ev2["outcome"] == "allow";

    mark3 = audit_count();
    cm = ReadComment(
        ctx=ctx_for("s_member", "/c", "GET", "req_hp7c"),
        tenant_id="t_acme", project_id=MADE["project_id"],
        task_id=MADE["task_id"], comment_id=MADE["comment_id"]
    ) spawn root;
    assert cm.reports[0]["ok"] == True;
    ev3 = only_event(mark3);
    assert ev3["action"] == "comment.read";
    assert ev3["outcome"] == "allow";
    print("READ BACK: project/task/comment all 200, one event each");
}
