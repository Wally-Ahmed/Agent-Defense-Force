# app/services/comments.jac -- the four comment walkers.
#
# Comments are the deepest resource in the hierarchy: reaching one is a THREE
# -hop traversal from the tenant --
#
#     Tenant --Owns--> Project --Contains--> Task --Discusses--> Comment
#
# -- so every walker below resolves project, then task, then (where relevant)
# the comment itself, and reports NOT_FOUND the instant any hop misses. A miss
# at hop one (a foreign project), hop two (a foreign task) and hop three (a
# foreign comment) are byte-identical responses, because all three come from
# the same traversal that simply never reaches the node -- see
# app/model/resolve.jac and app/services/scope.jac.
#
# A comment carries no sensitivity of its own (app/model/graph.jac has no such
# field on Comment): it inherits its task's EFFECTIVE sensitivity, and
# find_task() has already enforced that ceiling by the time find_comment() (or
# visible_comments()) runs below. Nothing here re-derives it, and there is no
# `‡` step in this file for that reason -- see app/services/sensitivity.jac.
#
# THE SHAPE (see app/services/projects.jac's header for the full account):
# guard() first, open_scope() second, the contract's own role floor third,
# traversal-scoped resolution fourth, validation fifth, then the mutation (if
# any) and report. WALKERS EMIT NO AUDIT EVENT -- guard() already emitted
# exactly one.
#
# `has ctx: dict = {};` is mandatory on every walker below, never a typed
# archetype -- a `has` field typed as an archetype silently degrades to `str`
# and the request fails with HTTP 422 (see projects.jac's header).

import from contracts.req_ctx_contract { ReqCtx, Grant, guard }
import from app.security.reqctx { ctx_from }
import from app.model.graph { Comment, Project, Task, Discusses }
import from app.security.clock { now_ms }
import from app.security.roles { role_satisfies }
import from app.services.scope {
    open_scope, find_project, find_task, find_comment, visible_comments
}
import from app.services.errors { deny, ok }
import from app.services.paging { resolve_limit, filter_key, decode_cursor, page }
import from app.services.validate { v_str, clean }
import from app.services.ids { comment_id as new_comment_id }

# Comment body ceiling, straight from the contract schema -- longer than
# MAX_BODY (app/services/validate.jac), which bounds a project/task blurb, not
# a discussion comment.
glob:pub COMMENT_BODY_MAX: int = 10000;

"""One comment, as the contract's Comment schema.

`tenant_id` is not a field on Comment (app/model/graph.jac) -- every walker
below splices it in from the already-authorized Scope right after calling
this, never from the request and never from a second traversal."""
def:pub comment_view(c: Comment) -> dict {
    return {
        "comment_id": c.comment_id,
        "task_id": c.task_id,
        "project_id": c.project_id,
        "author_user_id": c.author_id,
        "body": c.body,
        "created_at": c.created_at,
        "edited_at": c.edited_at
    };
}

# --------------------------------------------------------------------------
# POST .../tasks/{task_id}/comments -- member -- comment.create -- 201
# --------------------------------------------------------------------------

walker:priv CreateComment {
    has ctx: dict = {};
    has tenant_id: str = "";
    has project_id: str = "";
    has task_id: str = "";
    has body: str = "";

    can go with entry {
        g = guard(ctx_from(self.ctx), "comment.create", "comment", self.tenant_id, "");
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

        # Two-hop resolution within the caller's ceiling. A project or task the
        # caller cannot reach is None here, identical to one that never existed.
        proj = find_project(sc, self.project_id);
        if proj is None {
            report deny("NOT_FOUND", rid);
            disengage;
        }
        task = find_task(sc, proj, self.task_id);
        if task is None {
            report deny("NOT_FOUND", rid);
            disengage;
        }

        errs: list = [];
        v_str(errs, "body", self.body, 1, COMMENT_BODY_MAX);
        if not clean(errs) {
            report deny("VALIDATION_FAILED", rid, errs);
            disengage;
        }

        ts = now_ms();
        # author_id is taken from the authenticated Scope, never from the
        # body -- the request carries no author field at all, so there is
        # nothing for a caller to spoof.
        made = (task +>:Discusses:+> Comment(
            comment_id=new_comment_id(),
            task_id=task.task_id,
            project_id=proj.project_id,
            body=self.body,
            author_id=sc.principal_id,
            created_at=ts,
            edited_at=ts
        ))[0];
        view = comment_view(made);
        view["tenant_id"] = sc.tenant.tenant_id;
        report ok(view, 201);
        disengage;
    }
}

# --------------------------------------------------------------------------
# GET .../tasks/{task_id}/comments -- viewer -- comment.list -- 200
# --------------------------------------------------------------------------

walker:priv ListComments {
    has ctx: dict = {};
    has tenant_id: str = "";
    has project_id: str = "";
    has task_id: str = "";
    has limit: int = 0;
    has cursor: str = "";

    can go with entry {
        g = guard(ctx_from(self.ctx), "comment.list", "comment", self.tenant_id, "");
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
        proj = find_project(sc, self.project_id);
        if proj is None {
            report deny("NOT_FOUND", rid);
            disengage;
        }
        task = find_task(sc, proj, self.task_id);
        if task is None {
            report deny("NOT_FOUND", rid);
            disengage;
        }

        errs: list = [];
        lim = resolve_limit(self.limit);
        if lim < 0 {
            errs.append({"field": "limit", "message": "must be between 1 and 100"});
        }
        if not clean(errs) {
            report deny("VALIDATION_FAILED", rid, errs);
            disengage;
        }

        # visible_comments() needs no sensitivity filter of its own -- see the
        # file header. There are no query filters on this endpoint either, so
        # the filter key is constant.
        rows = visible_comments(sc, task);
        fkey = filter_key({});
        ts = now_ms();
        offset = 0;
        if self.cursor != "" {
            offset = decode_cursor(self.cursor, self.tenant_id, "comment.list", fkey, ts);
            if offset < 0 {
                report deny("VALIDATION_FAILED", rid,
                            [{"field": "cursor", "message": "is not a usable cursor"}]);
                disengage;
            }
        }
        pg = page(rows, lim, offset, self.tenant_id, "comment.list", fkey, ts);
        window: list = pg["items"];
        items: list = [];
        for c in window {
            view = comment_view(c);
            view["tenant_id"] = sc.tenant.tenant_id;
            items.append(view);
        }
        report ok({
            "items": items,
            "next_cursor": pg["next_cursor"],
            "has_more": pg["next_cursor"] != "",
            "total_visible": len(rows)
        }, 200);
        disengage;
    }
}

# --------------------------------------------------------------------------
# GET .../comments/{comment_id} -- viewer -- comment.read -- 200
# --------------------------------------------------------------------------

walker:priv ReadComment {
    has ctx: dict = {};
    has tenant_id: str = "";
    has project_id: str = "";
    has task_id: str = "";
    has comment_id: str = "";

    can go with entry {
        g = guard(ctx_from(self.ctx), "comment.read", "comment", self.tenant_id, self.comment_id);
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
        # Three-hop resolution, in order: a foreign or unreachable project,
        # task or comment at any hop is None, and every None reports the same
        # NOT_FOUND -- a prober cannot learn which hop failed.
        proj = find_project(sc, self.project_id);
        if proj is None {
            report deny("NOT_FOUND", rid);
            disengage;
        }
        task = find_task(sc, proj, self.task_id);
        if task is None {
            report deny("NOT_FOUND", rid);
            disengage;
        }
        c = find_comment(sc, task, self.comment_id);
        if c is None {
            report deny("NOT_FOUND", rid);
            disengage;
        }
        view = comment_view(c);
        view["tenant_id"] = sc.tenant.tenant_id;
        report ok(view, 200);
        disengage;
    }
}

# --------------------------------------------------------------------------
# DELETE .../comments/{comment_id} -- member, author-or-admin -- comment.delete
# --------------------------------------------------------------------------

walker:priv DeleteComment {
    has ctx: dict = {};
    has tenant_id: str = "";
    has project_id: str = "";
    has task_id: str = "";
    has comment_id: str = "";

    can go with entry {
        g = guard(ctx_from(self.ctx), "comment.delete", "comment", self.tenant_id, self.comment_id);
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
        # Baseline is `member`, not `admin`: an ordinary member must be able
        # to delete their OWN comment. The stricter author-or-admin condition
        # below can only be evaluated once the comment is resolved (there is
        # no author to compare against before that), so it necessarily comes
        # after resolution -- this is the contract's deliberately inverted
        # order (note D), not an oversight.
        if not role_satisfies(sc.role, "member") {
            report deny("INSUFFICIENT_ROLE", rid);
            disengage;
        }
        proj = find_project(sc, self.project_id);
        if proj is None {
            report deny("NOT_FOUND", rid);
            disengage;
        }
        task = find_task(sc, proj, self.task_id);
        if task is None {
            report deny("NOT_FOUND", rid);
            disengage;
        }
        c = find_comment(sc, task, self.comment_id);
        if c is None {
            report deny("NOT_FOUND", rid);
            disengage;
        }

        # Resolve-THEN-authorize is safe here specifically because find_task
        # (via find_comment) has already applied the sensitivity ceiling: a
        # comment reachable at this line is one the caller's ROLE was already
        # allowed to see. The check below therefore only discriminates among
        # comments already visible to the caller -- it can never be used to
        # learn whether an out-of-reach comment exists. Authorship is read
        # from the graph (`c.author_id`); the request carries no author field
        # for a caller to spoof.
        if c.author_id != sc.principal_id and not role_satisfies(sc.role, "admin") {
            report deny("INSUFFICIENT_ROLE", rid);
            disengage;
        }

        ts = now_ms();
        del c;
        report ok({
            "comment_id": self.comment_id,
            "task_id": self.task_id,
            "tenant_id": self.tenant_id,
            "deleted_at": ts
        }, 200);
        disengage;
    }
}
