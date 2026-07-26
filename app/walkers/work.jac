# app/walkers/work.jac — read paths over projects, tasks and comments.
#
# These are deliberately tiny, because the interesting part is what is ABSENT.
# There is no `if project.tenant_id != ctx.tenant_id` anywhere below, and no
# lookup by global id. Every walker hands guard() a target and receives the
# already-resolved node on `g.node`; resolution happened by traversal from the
# Tenant, inside the authorization call. A project id belonging to another
# tenant is not compared and rejected here — it was never reachable, so it
# arrives as NOT_FOUND, which is byte-identical to the answer for an id that
# does not exist anywhere. The endpoint is not an existence oracle.
#
# THE MEASUREMENT RULE for the three list walkers. `project.list`, `task.list`
# and `comment.list` are in COUNTED_ACTIONS, so guard() assembled the collection
# ITSELF, counted it into the audit row's `result_count`, and handed the SAME
# list back on `g.node`. These walkers therefore report `g.node` and never
# re-query. Re-querying would let a walker return rows guard() did not count,
# which is exactly how a compromised endpoint under-reports its own egress: the
# bulk-exfiltration signal the monitor watches must be a MEASUREMENT taken by
# the authorization layer, not a number claimed by the code being audited.
#
# guard() is the first statement of every walker here, and none of them emits an
# audit event — guard() already emitted exactly one.
#
# NOTE ON target_kind FOR THE CHILD LISTS. `task.list` is guarded with
# target_kind "project" and `comment.list` with target_kind "task": the resource
# being ADDRESSED is the parent whose children are being listed. This is not
# cosmetic. guard()'s resolution step looks `target_id` up as `target_kind`
# inside the tenant, so passing ("task", project_id) would try to resolve a
# project id as a task, miss, and deny NOT_FOUND on every call. The parent kind
# is what makes the parent both resolvable and tenant-checked before the
# collection is measured.

import from typing { cast }
import from contracts.req_ctx_contract { ReqCtx, Grant, guard }
import from app.security.reqctx { ctx_from }
import from app.model.graph { Project, Task, Comment }

walker:priv ListProjects {
    has ctx: dict = {};
    has tenant_id: str = "";

    can run with Root entry {
        g = guard(ctx_from(self.ctx), "project.list", "project", self.tenant_id);
        if not g.ok {
            report {"ok": False, "error": g.reason};
            return;
        }
        # g.node IS the measured collection. Do not re-query.
        measured: list = cast(list, g.node);
        rows: list = [];
        for p in measured {
            rows.append({
                "project_id": getattr(p, "project_id", ""),
                "key": getattr(p, "key", ""),
                "visibility": getattr(p, "visibility", ""),
                "sensitivity": getattr(p, "sensitivity", "")
            });
        }
        report {"ok": True, "projects": rows, "count": len(rows)};
    }
}

walker:priv ReadProject {
    has ctx: dict = {};
    has tenant_id: str = "";
    has project_id: str = "";

    can run with Root entry {
        g = guard(ctx_from(self.ctx), "project.read", "project",
                  self.tenant_id, self.project_id);
        if not g.ok {
            report {"ok": False, "error": g.reason};
            return;
        }
        project = cast(Project, g.node);
        report {
            "ok": True,
            "project": {
                "project_id": project.project_id,
                "key": project.key,
                "visibility": project.visibility,
                "sensitivity": project.sensitivity,
                "created_at": project.created_at
            }
        };
    }
}

walker:priv ListTasks {
    has ctx: dict = {};
    has tenant_id: str = "";
    has project_id: str = "";

    can run with Root entry {
        g = guard(ctx_from(self.ctx), "task.list", "project",
                  self.tenant_id, self.project_id);
        if not g.ok {
            report {"ok": False, "error": g.reason};
            return;
        }
        # g.node IS the measured collection. Do not re-query.
        measured: list = cast(list, g.node);
        rows: list = [];
        for t in measured {
            rows.append({
                "task_id": getattr(t, "task_id", ""),
                "title": getattr(t, "title", ""),
                "status": getattr(t, "status", ""),
                "assignee_id": getattr(t, "assignee_id", ""),
                "sensitivity": getattr(t, "sensitivity", "")
            });
        }
        report {"ok": True, "project_id": self.project_id, "tasks": rows, "count": len(rows)};
    }
}

walker:priv ReadTask {
    has ctx: dict = {};
    has tenant_id: str = "";
    has task_id: str = "";

    can run with Root entry {
        g = guard(ctx_from(self.ctx), "task.read", "task", self.tenant_id, self.task_id);
        if not g.ok {
            report {"ok": False, "error": g.reason};
            return;
        }
        task = cast(Task, g.node);
        report {
            "ok": True,
            "task": {
                "task_id": task.task_id,
                "project_id": task.project_id,
                "title": task.title,
                "status": task.status,
                "assignee_id": task.assignee_id,
                "sensitivity": task.sensitivity
            }
        };
    }
}

walker:priv ListComments {
    has ctx: dict = {};
    has tenant_id: str = "";
    has task_id: str = "";

    can run with Root entry {
        g = guard(ctx_from(self.ctx), "comment.list", "task",
                  self.tenant_id, self.task_id);
        if not g.ok {
            report {"ok": False, "error": g.reason};
            return;
        }
        # g.node IS the measured collection. Do not re-query.
        measured: list = cast(list, g.node);
        rows: list = [];
        for c in measured {
            rows.append({
                "comment_id": getattr(c, "comment_id", ""),
                "body": getattr(c, "body", ""),
                "author_id": getattr(c, "author_id", ""),
                "created_at": getattr(c, "created_at", 0)
            });
        }
        report {"ok": True, "task_id": self.task_id, "comments": rows, "count": len(rows)};
    }
}
