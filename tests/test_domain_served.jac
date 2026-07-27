# tests/test_domain_served.jac -- the sensitivity floor on the SERVED path.
#
#     APP_CTX_SIGNING_KEY=<64 hex> jac test tests/test_domain_served.jac
#
# WHY THIS FILE EXISTS. `app/main.jac` serves `app.walkers.work`. Every other
# domain suite in this directory imports `app.services.*`, which is a DIFFERENT
# set of walkers over the same graph. Both sets are real; only one of them is
# reachable over HTTP. A suite that only ever exercised the services copy could
# be entirely green while the served endpoint returned records the caller was
# never authorized to see -- and it was: `project.list` handed a plain member
# `pr_conf` and `pr_canary`, sensitivity labels attached, on an audit row that
# said `outcome: allow`.
#
# Everything below therefore imports from `app.walkers.work` and nothing else.
# The point is not to re-test the floor -- test_domain_canary.jac does that
# against the services layer -- it is to test the floor WHERE THE REQUESTS
# ACTUALLY LAND.
#
# THE THREE PROPERTIES, for each of the three list actions:
#   1. a member receives only what their role may reach;
#   2. an admin still receives everything, so this is a floor and not a wall;
#   3. the audit row is honest -- `result_count` is what was RETURNED, and a
#      filtered-out record is never reported as part of an allowed set.
#
# Nothing here names a sensitivity value in an assertion about the CANARY
# specifically that is not also asserted for `confidential`. The canary is
# excluded by the same expression, and these tests are written so that they
# would fail identically if it were not.

import from tests.fixtures { world, ctx_for }
import from tests.helpers { audit_count, only_event, only_report }
import from app.walkers.work {
    ListProjects, ReadProject, ListTasks, ReadTask, ListComments
}

glob:pub W: dict = world();

"""Ids out of a served list report, under the key that walker uses."""
def ids_of(rep: dict, collection: str, key: str) -> list {
    rows: list = rep.get(collection, []);
    return sorted([r.get(key, "") for r in rows]);
}

# --------------------------------------------------------------------------
# project.list
# --------------------------------------------------------------------------

test "SERVED project.list hides above-floor projects from a member" {
    mark = audit_count();
    w = root() spawn ListProjects(
        ctx=ctx_for("s_member", "/api/v1/tenants/t_acme/projects", "GET"),
        tenant_id="t_acme"
    );
    r = only_report(w);
    ids = ids_of(r, "projects", "project_id");
    print("SERVED member project.list ->", ids);
    assert r["ok"] == True;
    assert "pr_normal" in ids;
    # Both above-floor records, asserted together: if only one of them were
    # excluded the canary would be distinguishable by its absence.
    assert "pr_conf" not in ids,
        f"a member listed a confidential project through the served walker: {ids}";
    assert "pr_canary" not in ids,
        f"a member listed the canary project through the served walker: {ids}";

    # And the labels did not ride along either -- an excluded record leaks just
    # as badly through its sensitivity field as through its id.
    labels = ids_of(r, "projects", "sensitivity");
    print("  sensitivities returned:", labels);
    assert "confidential" not in labels;
    assert "canary" not in labels;

    ev = only_event(mark);
    print("  audit:", ev);
    assert ev["action"] == "project.list";
    assert ev["outcome"] == "allow";
    # THE HONESTY PROPERTY. guard() measures the collection it hands back, so
    # the number in the trail is the number the caller received. A floor applied
    # after the measurement would leave `result_count` claiming rows that were
    # never returned -- an over-count the monitor reads as egress that did not
    # happen, and an `allow` covering records that were denied.
    assert ev["result_count"] == len(ids),
        f"audit says {ev['result_count']} rows, caller got {len(ids)}: {ids}";
    assert ev["result_count"] == r["count"];
}

test "SERVED project.list still returns every project to an admin" {
    w = root() spawn ListProjects(
        ctx=ctx_for("s_admin", "/api/v1/tenants/t_acme/projects", "GET"),
        tenant_id="t_acme"
    );
    r = only_report(w);
    ids = ids_of(r, "projects", "project_id");
    print("SERVED admin project.list ->", ids);
    assert r["ok"] == True;
    assert "pr_normal" in ids;
    assert "pr_conf" in ids;
    assert "pr_canary" in ids;
}

# --------------------------------------------------------------------------
# task.list -- a CONFIDENTIAL task under a NORMAL project
# --------------------------------------------------------------------------

test "SERVED task.list hides an above-floor task under a reachable project" {
    mark = audit_count();
    w = root() spawn ListTasks(
        ctx=ctx_for("s_member", "/api/v1/tenants/t_acme/projects/pr_normal/tasks", "GET"),
        tenant_id="t_acme", project_id="pr_normal"
    );
    r = only_report(w);
    ids = ids_of(r, "tasks", "task_id");
    print("SERVED member task.list(pr_normal) ->", ids);
    assert r["ok"] == True;
    # The parent is reachable, so nothing above the task keeps it out. Only the
    # per-record floor can.
    assert "tk_normal" in ids;
    assert "tk_conf" not in ids,
        f"a member listed a confidential task through the served walker: {ids}";

    ev = only_event(mark);
    print("  audit:", ev);
    assert ev["action"] == "task.list";
    assert ev["outcome"] == "allow";
    assert ev["result_count"] == len(ids),
        f"audit says {ev['result_count']} rows, caller got {len(ids)}: {ids}";
}

test "SERVED task.list still returns the confidential task to an admin" {
    w = root() spawn ListTasks(
        ctx=ctx_for("s_admin", "/api/v1/tenants/t_acme/projects/pr_normal/tasks", "GET"),
        tenant_id="t_acme", project_id="pr_normal"
    );
    r = only_report(w);
    ids = ids_of(r, "tasks", "task_id");
    print("SERVED admin task.list(pr_normal) ->", ids);
    assert r["ok"] == True;
    assert "tk_normal" in ids;
    assert "tk_conf" in ids;
}

# --------------------------------------------------------------------------
# task.read / comment.list -- sensitivity INHERITED from the parent
#
# `tk_canary` and `tk_conf` are the two halves of the same rule. A record's
# effective sensitivity is the stricter of its own and its parent's, so a
# record whose own field reads `normal` is still out of reach when it lives
# inside something that is not. Reading only the record's own field is how a
# `normal` task inside the canary project became readable, and how its comments
# became listable, through the served endpoints.
# --------------------------------------------------------------------------

test "SERVED task.read denies a normal task inside an above-floor project" {
    mark = audit_count();
    w = root() spawn ReadTask(
        ctx=ctx_for("s_member", "/api/v1/tenants/t_acme/tasks/tk_canary", "GET"),
        tenant_id="t_acme", task_id="tk_canary"
    );
    r = only_report(w);
    print("SERVED member task.read(tk_canary) ->", r);
    assert r["ok"] == False,
        "a member read a task inside the canary project through the served walker";
    # Masked, not explained: a 403 here would confirm the record exists.
    assert r["error"] == "NOT_FOUND";

    ev = only_event(mark);
    print("  audit:", ev);
    assert ev["outcome"] == "deny";
    assert ev["reason"] == "NOT_FOUND";
}

test "SERVED comment.list denies comments under an above-floor parent" {
    # Two parents, one confidential and one canary, asserted identically --
    # the exclusion is a property of the floor, not of either value.
    for tid in ["tk_conf", "tk_canary"] {
        mark = audit_count();
        w = root() spawn ListComments(
            ctx=ctx_for("s_member", "/api/v1/tenants/t_acme/tasks/" + tid + "/comments", "GET"),
            tenant_id="t_acme", task_id=tid
        );
        r = only_report(w);
        print(f"SERVED member comment.list({tid}) ->", r);
        assert r["ok"] == False,
            f"a member listed comments under {tid} through the served walker: {r}";
        assert r["error"] == "NOT_FOUND";

        ev = only_event(mark);
        print("  audit:", ev);
        assert ev["outcome"] == "deny";
        # Denied means nothing was handed over, and the row has to say so.
        assert ev["result_count"] == 0,
            f"a denied comment.list still reported {ev['result_count']} rows";
    }
}

test "SERVED comment.list still returns those comments to an admin" {
    for row in [("tk_conf", "cm_conf"), ("tk_canary", "cm_canary")] {
        tid = row[0];
        cid = row[1];
        w = root() spawn ListComments(
            ctx=ctx_for("s_admin", "/api/v1/tenants/t_acme/tasks/" + tid + "/comments", "GET"),
            tenant_id="t_acme", task_id=tid
        );
        r = only_report(w);
        ids = ids_of(r, "comments", "comment_id");
        print(f"SERVED admin comment.list({tid}) ->", ids);
        assert r["ok"] == True;
        assert cid in ids;
    }
}

# --------------------------------------------------------------------------
# The reachable case, so none of the above passes by denying everything.
# --------------------------------------------------------------------------

test "SERVED reads a member IS entitled to still succeed" {
    proj = root() spawn ReadProject(
        ctx=ctx_for("s_member", "/api/v1/tenants/t_acme/projects/pr_normal", "GET"),
        tenant_id="t_acme", project_id="pr_normal"
    );
    pr = only_report(proj);
    assert pr["ok"] == True, f"a member lost access to an ordinary project: {pr}";

    tk = root() spawn ReadTask(
        ctx=ctx_for("s_member", "/api/v1/tenants/t_acme/tasks/tk_normal", "GET"),
        tenant_id="t_acme", task_id="tk_normal"
    );
    tr = only_report(tk);
    assert tr["ok"] == True, f"a member lost access to an ordinary task: {tr}";

    mark = audit_count();
    cm = root() spawn ListComments(
        ctx=ctx_for("s_member", "/api/v1/tenants/t_acme/tasks/tk_normal/comments", "GET"),
        tenant_id="t_acme", task_id="tk_normal"
    );
    cr = only_report(cm);
    ids = ids_of(cr, "comments", "comment_id");
    print("SERVED member comment.list(tk_normal) ->", ids);
    assert cr["ok"] == True;
    assert "cm_normal" in ids;
    ev = only_event(mark);
    assert ev["outcome"] == "allow";
    assert ev["result_count"] == len(ids);
}
