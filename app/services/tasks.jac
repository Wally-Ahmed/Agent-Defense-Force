# app/services/tasks.jac -- the six task walkers.
#
# THE SHAPE EVERY WALKER IN app/services/ HAS, in this order (see
# app/services/projects.jac for the full explanation of why):
#
#   1. guard(ReqCtx(**self.ctx), action, target_kind, tenant_id, target_id)
#      -- the FIRST executable statement, no exceptions.
#   2. open_scope()  -- re-read the Membership from the graph (defence in depth)
#   3. the operation's own role floor from contracts/app_api.md
#   4. resolution by traversal -- ALWAYS TWO HOPS for a task: find_project()
#      first (None -> NOT_FOUND), then find_task() from that resolved project
#      (None -> NOT_FOUND). Never app.model.resolve.task_in() directly: the
#      API path names the project, so the project belongs on the path, and a
#      task_id that is real but hangs off a DIFFERENT project in this same
#      tenant must be just as unreachable as one in a different tenant.
#   5. validation -> VALIDATION_FAILED
#   6. the sensitivity floor on the CURRENT and REQUESTED EFFECTIVE
#      sensitivity (the `‡` rule)
#   7. the mutation, then report
#
# WALKERS EMIT NO AUDIT EVENT. guard() already emitted exactly one -- see
# contracts/vocab.md and the longer note at the top of projects.jac.
#
# `has ctx: dict = {};` is mandatory on every walker below: a `has` field
# typed as an archetype silently degrades to `str` and the request fails with
# HTTP 422.
#
# EFFECTIVE SENSITIVITY: a task's is stricter(project.sensitivity,
# task.sensitivity) -- app.services.scope.task_sensitivity -- never the
# task's own `sensitivity` field read alone. A `confidential` project floors
# every task inside it, including one that itself asks for `normal`. Both the
# `‡` gate below and the `effective_sensitivity` response field use it.

import from contracts.req_ctx_contract { ReqCtx, Grant, guard }
import from app.model.graph { Project, Task, Contains }
import from app.model.resolve { comments_of, memberships_of }
import from app.security.clock { now_ms }
import from app.security.roles { role_satisfies }
import from app.services.scope {
    open_scope, find_project, find_task, visible_tasks, task_sensitivity
}
import from app.services.sensitivity { SENSITIVITY_VALUES, effective_required, stricter }
import from app.services.errors { deny, ok }
import from app.services.paging { resolve_limit, filter_key, decode_cursor, page }
import from app.services.validate {
    v_str, v_opt_str, v_opt_id, v_enum, v_opt_enum, v_str_list, clean, MAX_TITLE
}
import from app.services.ids { task_id as new_task_id }

# Task status/priority, straight from the contract schema (ListTasks' own
# query-filter enums, which spell out what the $ref-typed body fields could
# not). The graph node's bare default ("open") predates this enum and is
# never written by this file -- every task created here gets an explicit
# value from TASK_STATUS_VALUES.
glob:pub TASK_STATUS_VALUES: list = ["todo", "in_progress", "blocked", "done"];
glob:pub TASK_STATUS_FILTERS: list = ["todo", "in_progress", "blocked", "done", "all"];
glob:pub TASK_PRIORITY_VALUES: list = ["low", "normal", "high", "urgent"];

"""One task, as the contract's Task schema."""
def:pub task_view(project: Project, t: Task) -> dict {
    return {
        "task_id": t.task_id,
        "project_id": t.project_id,
        "tenant_id": project.tenant_id,
        "title": t.title,
        "description": t.description,
        "status": t.status,
        "priority": t.priority,
        "sensitivity": t.sensitivity,
        "effective_sensitivity": task_sensitivity(project, t),
        "assignee_user_id": t.assignee_id,
        "due_date": t.due_date,
        "labels": t.labels,
        "attachments": [],
        "comment_count": len(comments_of(t)),
        "created_by": t.created_by,
        "created_at": t.created_at,
        "updated_at": t.updated_at
    };
}

# --------------------------------------------------------------------------
# POST /tenants/{tenant_id}/projects/{project_id}/tasks -- member ‡ -- task.create -- 201
# --------------------------------------------------------------------------

walker:priv CreateTask {
    has ctx: dict = {};
    has tenant_id: str = "";
    has project_id: str = "";
    has title: str = "";
    has description: str = "";
    has status: str = "todo";
    has priority: str = "normal";
    has sensitivity: str = "normal";
    has assignee_user_id: str = "";
    has due_date: str = "";
    has labels: list = [];

    can go with entry {
        g = guard(ReqCtx(**self.ctx), "task.create", "task", self.tenant_id, "");
        rid = self.ctx.get("request_id", "");
        if not g.ok {
            report deny(g.reason, rid);
            disengage;
        }
        sr = open_scope(g, ReqCtx(**self.ctx), self.tenant_id);
        if sr.scope is None {
            report deny(sr.reason, rid);
            disengage;
        }
        sc = sr.scope;
        if not role_satisfies(sc.role, "member") {
            report deny("INSUFFICIENT_ROLE", rid);
            disengage;
        }
        # First hop of two: the project this task will be attached to. A
        # project_id from another tenant, or above the caller's reach, is
        # None here -- identical to one that never existed.
        proj = find_project(sc, self.project_id);
        if proj is None {
            report deny("NOT_FOUND", rid);
            disengage;
        }

        errs: list = [];
        v_str(errs, "title", self.title, 1, MAX_TITLE);
        v_opt_str(errs, "description", self.description, 8000);
        v_enum(errs, "status", self.status, TASK_STATUS_VALUES);
        v_enum(errs, "priority", self.priority, TASK_PRIORITY_VALUES);
        v_enum(errs, "sensitivity", self.sensitivity, SENSITIVITY_VALUES);
        v_opt_id(errs, "assignee_user_id", self.assignee_user_id);
        v_opt_str(errs, "due_date", self.due_date, 32);
        v_str_list(errs, "labels", self.labels);
        if not clean(errs) {
            report deny("VALIDATION_FAILED", rid, errs);
            disengage;
        }

        # The `‡` rule against the REQUESTED effective sensitivity: the
        # stricter of the project's own and the one this task would carry.
        # A `confidential` project floors every task created inside it even
        # when the task itself asks for `normal`.
        wanted = stricter(proj.sensitivity, self.sensitivity);
        if not role_satisfies(sc.role, effective_required("member", wanted)) {
            report deny("INSUFFICIENT_ROLE", rid);
            disengage;
        }

        # An assignee is resolved by traversal of THIS tenant's Membership
        # edges only -- never a global principal lookup. A principal in
        # another tenant is unreachable by this walk, which is the point.
        if self.assignee_user_id != "" {
            is_member = False;
            for m in memberships_of(sc.tenant) {
                if m.principal_id == self.assignee_user_id and m.state == "active" {
                    is_member = True;
                }
            }
            if not is_member {
                report deny("VALIDATION_FAILED", rid,
                            [{"field": "assignee_user_id",
                              "message": "does not name an active member of this tenant"}]);
                disengage;
            }
        }

        ts = now_ms();
        made = (proj +>:Contains:+> Task(
            task_id=new_task_id(),
            project_id=proj.project_id,
            title=self.title,
            status=self.status,
            assignee_id=self.assignee_user_id,
            sensitivity=self.sensitivity,
            created_at=ts,
            description=self.description,
            priority=self.priority,
            due_date=self.due_date,
            labels=self.labels,
            created_by=sc.principal_id,
            updated_at=ts
        ))[0];
        report ok(task_view(proj, made), 201);
        disengage;
    }
}

# --------------------------------------------------------------------------
# GET /tenants/{tenant_id}/projects/{project_id}/tasks -- viewer -- task.list -- 200
# --------------------------------------------------------------------------

walker:priv ListTasks {
    has ctx: dict = {};
    has tenant_id: str = "";
    has project_id: str = "";
    has limit: int = 0;
    has cursor: str = "";
    has status: str = "all";
    has priority: str = "";
    has assignee_user_id: str = "";

    can go with entry {
        g = guard(ReqCtx(**self.ctx), "task.list", "task", self.tenant_id, "");
        rid = self.ctx.get("request_id", "");
        if not g.ok {
            report deny(g.reason, rid);
            disengage;
        }
        sr = open_scope(g, ReqCtx(**self.ctx), self.tenant_id);
        if sr.scope is None {
            report deny(sr.reason, rid);
            disengage;
        }
        sc = sr.scope;
        if not role_satisfies(sc.role, "viewer") {
            report deny("INSUFFICIENT_ROLE", rid);
            disengage;
        }
        proj = find_project(sc, self.project_id);
        if proj is None {
            report deny("NOT_FOUND", rid);
            disengage;
        }

        errs: list = [];
        v_enum(errs, "status", self.status, TASK_STATUS_FILTERS);
        v_opt_enum(errs, "priority", self.priority, TASK_PRIORITY_VALUES);
        v_opt_id(errs, "assignee_user_id", self.assignee_user_id);
        lim = resolve_limit(self.limit);
        if lim < 0 {
            errs.append({"field": "limit", "message": "must be between 1 and 100"});
        }
        if not clean(errs) {
            report deny("VALIDATION_FAILED", rid, errs);
            disengage;
        }

        # visible_tasks() applies the sensitivity floor DURING traversal, so a
        # task above the caller's reach never enters the list, is never
        # counted in total_visible, and never influences a cursor.
        rows = [
            t for t in visible_tasks(sc, proj)
            if (self.status == "all" or t.status == self.status)
            and (self.priority == "" or t.priority == self.priority)
            and (self.assignee_user_id == "" or t.assignee_id == self.assignee_user_id)
        ];
        # project_id is folded into the filter key (not just tenant_id and the
        # endpoint) so a cursor minted while listing one project's tasks can
        # never be replayed against another project's list in this tenant.
        fkey = filter_key({
            "project_id": self.project_id,
            "status": self.status,
            "priority": self.priority,
            "assignee_user_id": self.assignee_user_id
        });
        ts = now_ms();
        offset = 0;
        if self.cursor != "" {
            offset = decode_cursor(self.cursor, self.tenant_id, "task.list", fkey, ts);
            if offset < 0 {
                report deny("VALIDATION_FAILED", rid,
                            [{"field": "cursor", "message": "is not a usable cursor"}]);
                disengage;
            }
        }
        pg = page(rows, lim, offset, self.tenant_id, "task.list", fkey, ts);
        window: list = pg["items"];
        report ok({
            "items": [task_view(proj, t) for t in window],
            "next_cursor": pg["next_cursor"],
            "has_more": pg["next_cursor"] != "",
            "total_visible": len(rows)
        }, 200);
        disengage;
    }
}

# --------------------------------------------------------------------------
# GET /tenants/{tenant_id}/projects/{project_id}/tasks/{task_id} -- viewer -- task.read
# --------------------------------------------------------------------------

walker:priv ReadTask {
    has ctx: dict = {};
    has tenant_id: str = "";
    has project_id: str = "";
    has task_id: str = "";

    can go with entry {
        g = guard(ReqCtx(**self.ctx), "task.read", "task", self.tenant_id, self.task_id);
        rid = self.ctx.get("request_id", "");
        if not g.ok {
            report deny(g.reason, rid);
            disengage;
        }
        sr = open_scope(g, ReqCtx(**self.ctx), self.tenant_id);
        if sr.scope is None {
            report deny(sr.reason, rid);
            disengage;
        }
        sc = sr.scope;
        if not role_satisfies(sc.role, "viewer") {
            report deny("INSUFFICIENT_ROLE", rid);
            disengage;
        }
        # Two hops from THIS tenant: project, then task inside it. A task_id
        # that is real but hangs off a different project (or a different
        # tenant, or above the caller's reach) is unreachable either way, and
        # the answer is the same 404.
        proj = find_project(sc, self.project_id);
        if proj is None {
            report deny("NOT_FOUND", rid);
            disengage;
        }
        t = find_task(sc, proj, self.task_id);
        if t is None {
            report deny("NOT_FOUND", rid);
            disengage;
        }
        report ok(task_view(proj, t), 200);
        disengage;
    }
}

# --------------------------------------------------------------------------
# PATCH /tenants/{tenant_id}/projects/{project_id}/tasks/{task_id} -- member ‡ -- task.update
# --------------------------------------------------------------------------

walker:priv UpdateTask {
    has ctx: dict = {};
    has tenant_id: str = "";
    has project_id: str = "";
    has task_id: str = "";
    has title: str = "";
    has description: str = "";
    has status: str = "";
    has priority: str = "";
    has sensitivity: str = "";
    has due_date: str = "";
    has labels: list = [];

    can go with entry {
        g = guard(ReqCtx(**self.ctx), "task.update", "task", self.tenant_id, self.task_id);
        rid = self.ctx.get("request_id", "");
        if not g.ok {
            report deny(g.reason, rid);
            disengage;
        }
        sr = open_scope(g, ReqCtx(**self.ctx), self.tenant_id);
        if sr.scope is None {
            report deny(sr.reason, rid);
            disengage;
        }
        sc = sr.scope;
        if not role_satisfies(sc.role, "member") {
            report deny("INSUFFICIENT_ROLE", rid);
            disengage;
        }
        proj = find_project(sc, self.project_id);
        if proj is None {
            report deny("NOT_FOUND", rid);
            disengage;
        }
        t = find_task(sc, proj, self.task_id);
        if t is None {
            report deny("NOT_FOUND", rid);
            disengage;
        }

        errs: list = [];
        v_opt_str(errs, "title", self.title, MAX_TITLE);
        v_opt_str(errs, "description", self.description, 8000);
        v_opt_enum(errs, "status", self.status, TASK_STATUS_VALUES);
        v_opt_enum(errs, "priority", self.priority, TASK_PRIORITY_VALUES);
        v_opt_enum(errs, "sensitivity", self.sensitivity, SENSITIVITY_VALUES);
        v_opt_str(errs, "due_date", self.due_date, 32);
        v_str_list(errs, "labels", self.labels);
        if not clean(errs) {
            report deny("VALIDATION_FAILED", rid, errs);
            disengage;
        }

        # The `‡` rule against BOTH the current and the requested EFFECTIVE
        # sensitivity -- the stricter of the project's and the task's own,
        # the same value the response reports as `effective_sensitivity`. The
        # current one is already implied (find_task would have returned None
        # otherwise) and is re-checked anyway, because relying on an earlier
        # check to still hold is how these bugs happen.
        if not role_satisfies(sc.role, effective_required("member", task_sensitivity(proj, t))) {
            report deny("INSUFFICIENT_ROLE", rid);
            disengage;
        }
        wanted_sensitivity = self.sensitivity if self.sensitivity != "" else t.sensitivity;
        if not role_satisfies(sc.role, effective_required("member", stricter(proj.sensitivity, wanted_sensitivity))) {
            report deny("INSUFFICIENT_ROLE", rid);
            disengage;
        }

        if self.title != "" { t.title = self.title; }
        if self.description != "" { t.description = self.description; }
        if self.status != "" { t.status = self.status; }
        if self.priority != "" { t.priority = self.priority; }
        if self.sensitivity != "" { t.sensitivity = self.sensitivity; }
        if self.due_date != "" { t.due_date = self.due_date; }
        if len(self.labels) > 0 { t.labels = self.labels; }
        t.updated_at = now_ms();
        report ok(task_view(proj, t), 200);
        disengage;
    }
}

# --------------------------------------------------------------------------
# DELETE /tenants/{tenant_id}/projects/{project_id}/tasks/{task_id} -- admin -- task.delete
# --------------------------------------------------------------------------

walker:priv DeleteTask {
    has ctx: dict = {};
    has tenant_id: str = "";
    has project_id: str = "";
    has task_id: str = "";

    can go with entry {
        g = guard(ReqCtx(**self.ctx), "task.delete", "task", self.tenant_id, self.task_id);
        rid = self.ctx.get("request_id", "");
        if not g.ok {
            report deny(g.reason, rid);
            disengage;
        }
        sr = open_scope(g, ReqCtx(**self.ctx), self.tenant_id);
        if sr.scope is None {
            report deny(sr.reason, rid);
            disengage;
        }
        sc = sr.scope;
        if not role_satisfies(sc.role, "admin") {
            report deny("INSUFFICIENT_ROLE", rid);
            disengage;
        }
        proj = find_project(sc, self.project_id);
        if proj is None {
            report deny("NOT_FOUND", rid);
            disengage;
        }
        t = find_task(sc, proj, self.task_id);
        if t is None {
            report deny("NOT_FOUND", rid);
            disengage;
        }

        # Detach this task's comments before the task itself. Unlike a
        # project delete (which leaves its tasks merely unreachable), the
        # contract requires the comments actually detached here.
        comments: list = comments_of(t);
        cascaded = len(comments);
        for c in comments {
            del c;
        }
        ts = now_ms();
        del t;
        report ok({
            "task_id": self.task_id,
            "project_id": self.project_id,
            "tenant_id": self.tenant_id,
            "deleted_at": ts,
            "cascaded": {"comments": cascaded}
        }, 200);
        disengage;
    }
}

# --------------------------------------------------------------------------
# POST /tenants/{tenant_id}/projects/{project_id}/tasks/{task_id}/assign -- member -- task.assign
# --------------------------------------------------------------------------

walker:priv AssignTask {
    has ctx: dict = {};
    has tenant_id: str = "";
    has project_id: str = "";
    has task_id: str = "";
    has assignee_user_id: str = "";

    can go with entry {
        g = guard(ReqCtx(**self.ctx), "task.assign", "task", self.tenant_id, self.task_id);
        rid = self.ctx.get("request_id", "");
        if not g.ok {
            report deny(g.reason, rid);
            disengage;
        }
        sr = open_scope(g, ReqCtx(**self.ctx), self.tenant_id);
        if sr.scope is None {
            report deny(sr.reason, rid);
            disengage;
        }
        sc = sr.scope;
        if not role_satisfies(sc.role, "member") {
            report deny("INSUFFICIENT_ROLE", rid);
            disengage;
        }
        proj = find_project(sc, self.project_id);
        if proj is None {
            report deny("NOT_FOUND", rid);
            disengage;
        }
        t = find_task(sc, proj, self.task_id);
        if t is None {
            report deny("NOT_FOUND", rid);
            disengage;
        }

        errs: list = [];
        v_opt_id(errs, "assignee_user_id", self.assignee_user_id);
        if not clean(errs) {
            report deny("VALIDATION_FAILED", rid, errs);
            disengage;
        }

        # "" clears the assignment. Anything else is resolved by traversal of
        # THIS tenant's Membership edges only -- never a global principal
        # lookup. A user id from another tenant is unreachable by this walk,
        # which is the point: it must 422 here, not silently attach a
        # foreign principal to a task it can never otherwise reach.
        if self.assignee_user_id != "" {
            is_member = False;
            for m in memberships_of(sc.tenant) {
                if m.principal_id == self.assignee_user_id and m.state == "active" {
                    is_member = True;
                }
            }
            if not is_member {
                report deny("VALIDATION_FAILED", rid,
                            [{"field": "assignee_user_id",
                              "message": "does not name an active member of this tenant"}]);
                disengage;
            }
        }

        t.assignee_id = self.assignee_user_id;
        t.updated_at = now_ms();
        report ok(task_view(proj, t), 200);
        disengage;
    }
}
