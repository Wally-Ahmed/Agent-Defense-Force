# app/services/projects.jac -- the five project walkers.
#
# THE SHAPE EVERY WALKER IN app/services/ HAS, in this order:
#
#   1. guard(ctx_from(self.ctx), action, target_kind, tenant_id, target_id)
#      -- the FIRST executable statement, no exceptions. guard() verifies the
#      ctx signature, the credential, containment controls, membership and the
#      action's minimum role, resolves the target by traversal, and emits the
#      single AuditEvent for this request. If it denies, we report and leave.
#   2. open_scope()  -- re-read the Membership from the graph (defence in depth)
#   3. the operation's own role floor from contracts/app_api.md, enforced as
#      max(contract baseline, guard's own table) so this layer can only be
#      stricter than guard, never looser
#   4. step-up, for the `†` operations
#   5. resolution by traversal from the Scope's tenant -- never by global id
#   6. validation -> VALIDATION_FAILED
#   7. the sensitivity floor on the CURRENT and REQUESTED values (the `‡` rule)
#   8. the mutation, then report
#
# WALKERS EMIT NO AUDIT EVENT. contracts/vocab.md: "every guard() call emits
# exactly one AuditEvent. Not zero, not two." A second emission here would
# double-count every request and corrupt the `result_count` signal the monitor
# reads.
#
# `has ctx: dict = {};` is mandatory and is NOT a style choice: a walker `has`
# field typed as an archetype silently degrades to `str` and the request fails
# with HTTP 422 (spikes/README.md, jfast_api.impl.jac:210). ReqCtx is rebuilt
# from the dict inside.

import from contracts.req_ctx_contract { ReqCtx, Grant, guard }
import from app.security.reqctx { ctx_from }
import from app.model.graph { Project, Owns }
import from app.model.resolve { projects_of, tasks_of }
import from app.security.clock { now_ms }
import from app.security.roles { role_satisfies }
import from app.services.scope { open_scope, find_project, visible_projects }
import from app.services.sensitivity {
    SENSITIVITY_VALUES, effective_required, can_reach
}
import from app.services.errors { deny, ok }
import from app.services.paging { resolve_limit, filter_key, decode_cursor, page }
import from app.services.validate {
    v_str, v_opt_str, v_pattern, v_enum, v_opt_enum, v_int, clean, MAX_BODY
}
import from app.services.ids { project_id as new_project_id }

# Project key format, straight from the contract schema.
glob:pub PROJECT_KEY_PATTERN: str = r"^[A-Z][A-Z0-9]{1,9}$";
glob:pub PROJECT_STATUS_VALUES: list = ["active", "archived"];
glob:pub PROJECT_STATUS_FILTERS: list = ["active", "archived", "all"];
glob:pub PROJECT_SORTS: list = ["created_at", "updated_at", "name"];

"""One project, as the contract's Project schema."""
def:pub project_view(p: Project) -> dict {
    return {
        "project_id": p.project_id,
        "tenant_id": p.tenant_id,
        "key": p.key,
        "name": p.name,
        "description": p.description,
        "sensitivity": p.sensitivity,
        "status": p.status,
        "owner_user_id": p.owner_user_id,
        "task_count": len(tasks_of(p)),
        "created_at": p.created_at,
        "updated_at": p.updated_at
    };
}

# --------------------------------------------------------------------------
# POST /tenants/{tenant_id}/projects -- member ‡ -- project.create -- 201
# --------------------------------------------------------------------------

walker:priv CreateProject {
    has ctx: dict = {};
    has tenant_id: str = "";
    has key: str = "";
    has name: str = "";
    has description: str = "";
    has sensitivity: str = "normal";

    can go with entry {
        g = guard(ctx_from(self.ctx), "project.create", "project", self.tenant_id, "");
        rid = self.ctx.get("request_id", "");
        if not g.ok {
            report deny(g.reason, rid);
            disengage;
        }
        sr = open_scope(g, ctx_from(self.ctx), self.tenant_id);
        if sr.scope is None {
            report deny(sr.reason, rid);
            disengage;
        }
        sc = sr.scope;
        if not role_satisfies(sc.role, "member") {
            report deny("INSUFFICIENT_ROLE", rid);
            disengage;
        }

        errs: list = [];
        v_pattern(errs, "key", self.key, PROJECT_KEY_PATTERN, 10);
        v_str(errs, "name", self.name, 1, 160);
        v_opt_str(errs, "description", self.description, MAX_BODY);
        v_enum(errs, "sensitivity", self.sensitivity, SENSITIVITY_VALUES);
        if not clean(errs) {
            report deny("VALIDATION_FAILED", rid, errs);
            disengage;
        }

        # The `‡` rule. Creating a record ABOVE the caller's reach is refused by
        # the same floor table that hides such a record from them on read.
        if not role_satisfies(sc.role, effective_required("member", self.sensitivity)) {
            report deny("INSUFFICIENT_ROLE", rid);
            disengage;
        }

        # A key must be unique inside the tenant -- checked by traversal, so the
        # answer says nothing about any other tenant's keys.
        for existing in projects_of(sc.tenant) {
            if existing.key == self.key {
                report deny("VALIDATION_FAILED", rid,
                            [{"field": "key", "message": "is already in use"}]);
                disengage;
            }
        }

        ts = now_ms();
        # tenant_id is taken from the resolved Scope, never from the body: the
        # new Project can only ever hang off the tenant guard() authorized.
        tnode = sc.tenant;
        made = (tnode +>:Owns:+> Project(
            project_id=new_project_id(),
            tenant_id=sc.tenant.tenant_id,
            key=self.key,
            name=self.name,
            description=self.description,
            sensitivity=self.sensitivity,
            status="active",
            owner_user_id=sc.principal_id,
            created_at=ts,
            updated_at=ts
        ))[0];
        report ok(project_view(made), 201);
        disengage;
    }
}

# --------------------------------------------------------------------------
# GET /tenants/{tenant_id}/projects -- viewer -- project.list -- 200
# --------------------------------------------------------------------------

walker:priv ListProjects {
    has ctx: dict = {};
    has tenant_id: str = "";
    has limit: int = 0;
    has cursor: str = "";
    has status: str = "active";
    has sort: str = "updated_at";

    can go with entry {
        g = guard(ctx_from(self.ctx), "project.list", "project", self.tenant_id, "");
        rid = self.ctx.get("request_id", "");
        if not g.ok {
            report deny(g.reason, rid);
            disengage;
        }
        sr = open_scope(g, ctx_from(self.ctx), self.tenant_id);
        if sr.scope is None {
            report deny(sr.reason, rid);
            disengage;
        }
        sc = sr.scope;
        if not role_satisfies(sc.role, "viewer") {
            report deny("INSUFFICIENT_ROLE", rid);
            disengage;
        }

        errs: list = [];
        v_enum(errs, "status", self.status, PROJECT_STATUS_FILTERS);
        v_enum(errs, "sort", self.sort, PROJECT_SORTS);
        lim = resolve_limit(self.limit);
        if lim < 0 {
            errs.append({"field": "limit", "message": "must be between 1 and 100"});
        }
        if not clean(errs) {
            report deny("VALIDATION_FAILED", rid, errs);
            disengage;
        }

        # visible_projects() applies the sensitivity floor DURING traversal, so
        # a record above the caller's reach never enters the list, never gets
        # counted in total_visible, and never influences a cursor.
        rows = [p for p in visible_projects(sc) if self.status == "all" or p.status == self.status];
        fkey = filter_key({"status": self.status, "sort": self.sort});
        ts = now_ms();
        offset = 0;
        if self.cursor != "" {
            offset = decode_cursor(self.cursor, self.tenant_id, "project.list", fkey, ts);
            if offset < 0 {
                report deny("VALIDATION_FAILED", rid,
                            [{"field": "cursor", "message": "is not a usable cursor"}]);
                disengage;
            }
        }
        pg = page(rows, lim, offset, self.tenant_id, "project.list", fkey, ts);
        window: list = pg["items"];
        report ok({
            "items": [project_view(p) for p in window],
            "next_cursor": pg["next_cursor"],
            "has_more": pg["next_cursor"] != "",
            "total_visible": len(rows)
        }, 200);
        disengage;
    }
}

# --------------------------------------------------------------------------
# GET /tenants/{tenant_id}/projects/{project_id} -- viewer -- project.read
# --------------------------------------------------------------------------

walker:priv ReadProject {
    has ctx: dict = {};
    has tenant_id: str = "";
    has project_id: str = "";

    can go with entry {
        g = guard(ctx_from(self.ctx), "project.read", "project", self.tenant_id, self.project_id);
        rid = self.ctx.get("request_id", "");
        if not g.ok {
            report deny(g.reason, rid);
            disengage;
        }
        sr = open_scope(g, ctx_from(self.ctx), self.tenant_id);
        if sr.scope is None {
            report deny(sr.reason, rid);
            disengage;
        }
        sc = sr.scope;
        if not role_satisfies(sc.role, "viewer") {
            report deny("INSUFFICIENT_ROLE", rid);
            disengage;
        }
        # Resolution by traversal from THIS tenant. A project_id belonging to
        # another tenant is not reachable, so this is None and the answer is a
        # 404 identical to the one for an id that never existed.
        p = find_project(sc, self.project_id);
        if p is None {
            report deny("NOT_FOUND", rid);
            disengage;
        }
        report ok(project_view(p), 200);
        disengage;
    }
}

# --------------------------------------------------------------------------
# PATCH /tenants/{tenant_id}/projects/{project_id} -- member ‡ -- project.update
# --------------------------------------------------------------------------

walker:priv UpdateProject {
    has ctx: dict = {};
    has tenant_id: str = "";
    has project_id: str = "";
    has name: str = "";
    has description: str = "";
    has status: str = "";
    has sensitivity: str = "";

    can go with entry {
        g = guard(ctx_from(self.ctx), "project.update", "project", self.tenant_id, self.project_id);
        rid = self.ctx.get("request_id", "");
        if not g.ok {
            report deny(g.reason, rid);
            disengage;
        }
        sr = open_scope(g, ctx_from(self.ctx), self.tenant_id);
        if sr.scope is None {
            report deny(sr.reason, rid);
            disengage;
        }
        sc = sr.scope;
        if not role_satisfies(sc.role, "member") {
            report deny("INSUFFICIENT_ROLE", rid);
            disengage;
        }
        p = find_project(sc, self.project_id);
        if p is None {
            report deny("NOT_FOUND", rid);
            disengage;
        }

        errs: list = [];
        v_opt_str(errs, "name", self.name, 160);
        v_opt_str(errs, "description", self.description, MAX_BODY);
        v_opt_enum(errs, "status", self.status, PROJECT_STATUS_VALUES);
        v_opt_enum(errs, "sensitivity", self.sensitivity, SENSITIVITY_VALUES);
        if not clean(errs) {
            report deny("VALIDATION_FAILED", rid, errs);
            disengage;
        }

        # The `‡` rule against BOTH the current and the requested value. The
        # current one is already implied (find_project would have returned None
        # otherwise) and is re-checked anyway, because relying on an earlier
        # check to still hold is how these bugs happen.
        wanted = self.sensitivity if self.sensitivity != "" else p.sensitivity;
        if not role_satisfies(sc.role, effective_required("member", p.sensitivity)) {
            report deny("INSUFFICIENT_ROLE", rid);
            disengage;
        }
        if not role_satisfies(sc.role, effective_required("member", wanted)) {
            report deny("INSUFFICIENT_ROLE", rid);
            disengage;
        }

        if self.name != "" { p.name = self.name; }
        if self.description != "" { p.description = self.description; }
        if self.status != "" { p.status = self.status; }
        if self.sensitivity != "" { p.sensitivity = self.sensitivity; }
        p.updated_at = now_ms();
        report ok(project_view(p), 200);
        disengage;
    }
}

# --------------------------------------------------------------------------
# DELETE /tenants/{tenant_id}/projects/{project_id} -- admin -- project.delete
# --------------------------------------------------------------------------

walker:priv DeleteProject {
    has ctx: dict = {};
    has tenant_id: str = "";
    has project_id: str = "";

    can go with entry {
        g = guard(ctx_from(self.ctx), "project.delete", "project", self.tenant_id, self.project_id);
        rid = self.ctx.get("request_id", "");
        if not g.ok {
            report deny(g.reason, rid);
            disengage;
        }
        sr = open_scope(g, ctx_from(self.ctx), self.tenant_id);
        if sr.scope is None {
            report deny(sr.reason, rid);
            disengage;
        }
        sc = sr.scope;
        if not role_satisfies(sc.role, "admin") {
            report deny("INSUFFICIENT_ROLE", rid);
            disengage;
        }
        p = find_project(sc, self.project_id);
        if p is None {
            report deny("NOT_FOUND", rid);
            disengage;
        }
        cascaded = len(tasks_of(p));
        ts = now_ms();
        # Detaching the node from the tenant is what removes access: nothing
        # else in the application can reach it, because nothing else looks up a
        # project except by walking this edge.
        del p;
        report ok({
            "project_id": self.project_id,
            "tenant_id": self.tenant_id,
            "deleted_at": ts,
            "cascaded": {"tasks": cascaded}
        }, 200);
        disengage;
    }
}
