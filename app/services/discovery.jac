# app/services/discovery.jac -- search, export and the one outbound-looking
# integration walker.
#
# THE SHAPE, same as every walker in app/services/ (see projects.jac):
#
#   1. guard(ctx_from(self.ctx), action, target_kind, tenant_id, target_id)
#      -- the FIRST executable statement, no exceptions.
#   2. open_scope() -- re-read the Membership from the graph (defence in depth)
#   3. the operation's own role floor -- for RequestExport / DownloadExport /
#      IntegrationCall this floor is stricter than a flat role string, so it
#      is spelled out per-walker below rather than a single role_satisfies()
#      call
#   4. step-up (`†`), for RequestExport, DownloadExport and a session-
#      authenticated IntegrationCall
#   5. resolution by traversal from the Scope's tenant -- never by global id
#   6. validation -> VALIDATION_FAILED
#   7. the mutation / computation, then report
#
# WALKERS EMIT NO AUDIT EVENT. guard() already emitted exactly one AuditEvent
# for this request; nothing here calls emit_audit or constructs one.
#
# `has ctx: dict = {};` is mandatory: a walker `has` field typed as an
# archetype silently degrades to `str` and the request fails with HTTP 422.
#
# SEARCHTENANT IS THE HIGHEST-RISK READ IN THE APP. It applies the IDENTICAL
# sensitivity predicate as every list/read: visible_projects() / visible_tasks()
# / visible_comments() already drop anything above the caller's reach, so this
# walker never scans projects_of()/tasks_of()/comments_of() (the raw,
# unfiltered collections) directly. A record the caller cannot reach is never
# scanned, never matched, never counted, and never yields a snippet.
#
# DOWNLOADEXPORT NEVER TRUSTS THE REQUEST-TIME CEILING. `ExportJob.
# sensitivity_ceiling` is recorded for comparison only; every record in the
# artifact is re-filtered against the DOWNLOADER'S CURRENT scope, rebuilt from
# visible_projects()/visible_tasks()/visible_comments() at download time. A
# role held at request time and revoked before download must not still be
# able to read the file.
#
# INTEGRATIONCALL MAKES NO NETWORK CALL. It validates, records the dispatch in
# the audit trail (via guard()'s own single AuditEvent) and returns a
# synthetic result. There is no outbound HTTP client anywhere in this file.

import from typing { cast }
import from contracts.req_ctx_contract { ReqCtx, Grant, guard }
import from app.security.reqctx { ctx_from }
import from app.model.graph { Project, Task, Comment, Membership, ExportJob, Exports }
import from app.security.clock { now_ms }
import from app.security.roles { role_satisfies }
import from app.services.scope {
    open_scope, step_up_ok, find_project, find_export,
    visible_projects, visible_tasks, visible_comments, visible_members,
    task_sensitivity, member_email
}
import from app.services.errors { deny, ok }
import from app.services.paging { resolve_limit, filter_key, decode_cursor, page }
import from app.services.validate {
    v_str, v_opt_str, v_opt_id, v_enum, v_pattern, v_str_list, add_err, clean, MAX_QUERY
}
import from app.services.ids { export_id as new_export_id, call_id as new_call_id }
import json;
import hashlib;

glob:pub SEARCH_TYPE_VALUES: list = ["project", "task", "comment"];
glob:pub EXPORT_FORMAT_VALUES: list = ["json", "csv"];
glob:pub EXPORT_INCLUDE_VALUES: list = ["projects", "tasks", "comments", "members"];
glob:pub INTEGRATION_CONNECTOR_VALUES: list = ["slack", "github", "webhook"];
glob:pub INTEGRATION_OPERATION_PATTERN: str = r"^[a-z][a-z0-9_.]{2,63}$";

# --------------------------------------------------------------------------
# Small view helpers, as project_view() does for projects.jac.
# --------------------------------------------------------------------------

"""One search hit, as the contract's search result item schema."""
def:pub search_item_view(kind: str, item_id: str, title: str, snippet: str, project_id: str, sensitivity: str) -> dict {
    return {
        "type": kind,
        "id": item_id,
        "title": title,
        "snippet": snippet,
        "project_id": project_id,
        "sensitivity": sensitivity
    };
}

"""One export job, as the contract's ExportJob schema (the 202 / not-ready
shape). DownloadExport's 200 shape is different (it carries `data` and a
checksum) and is built inline in that walker."""
def:pub export_job_view(j: ExportJob) -> dict {
    return {
        "export_id": j.job_id,
        "tenant_id": j.tenant_id,
        "status": j.state,
        "format": j.format,
        "include": j.include,
        "project_ids": j.project_ids,
        "requested_by": j.requested_by,
        "requested_at": j.created_at,
        "ready_at": j.ready_at,
        "expires_at": j.expires_at,
        "record_count": j.row_count,
        "sensitivity_ceiling": j.sensitivity_ceiling
    };
}

"""One project, shaped for an export payload."""
def:pub project_export_record(p: Project) -> dict {
    return {
        "project_id": p.project_id,
        "key": p.key,
        "name": p.name,
        "description": p.description,
        "sensitivity": p.sensitivity,
        "status": p.status,
        "owner_user_id": p.owner_user_id,
        "created_at": p.created_at,
        "updated_at": p.updated_at
    };
}

"""One task, shaped for an export payload. `sensitivity` is the task's
EFFECTIVE sensitivity (stricter of its project's and its own), not the raw
field -- the same value visible_tasks() already gated on."""
def:pub task_export_record(t: Task, sensitivity: str) -> dict {
    return {
        "task_id": t.task_id,
        "project_id": t.project_id,
        "title": t.title,
        "status": t.status,
        "assignee_id": t.assignee_id,
        "sensitivity": sensitivity,
        "priority": t.priority,
        "due_date": t.due_date,
        "labels": t.labels,
        "description": t.description,
        "created_by": t.created_by,
        "created_at": t.created_at,
        "updated_at": t.updated_at
    };
}

"""One comment, shaped for an export payload. `sensitivity` is inherited from
its task's effective value -- a Comment carries none of its own."""
def:pub comment_export_record(c: Comment, sensitivity: str) -> dict {
    return {
        "comment_id": c.comment_id,
        "task_id": c.task_id,
        "project_id": c.project_id,
        "body": c.body,
        "author_id": c.author_id,
        "sensitivity": sensitivity,
        "created_at": c.created_at,
        "edited_at": c.edited_at
    };
}

"""One membership, shaped for an export payload."""
def:pub member_export_record(m: Membership) -> dict {
    return {
        "membership_id": m.membership_id,
        "principal_id": m.principal_id,
        "email": member_email(m),
        "role": m.role,
        "state": m.state,
        "created_at": m.created_at
    };
}

"""A short excerpt of `text` centred on the (case-insensitive) first
occurrence of `needle`, or the front of `text` if there is no occurrence.
Built from `text` alone -- the caller already resolved `text` off an
already-authorized record before calling this."""
def _snippet(text: str, needle: str, width: int = 160) -> str {
    if len(text) <= width {
        return text;
    }
    idx = text.lower().find(needle.lower());
    if idx < 0 {
        return text[:width];
    }
    start = idx - 40;
    if start < 0 {
        start = 0;
    }
    end = start + width;
    if end > len(text) {
        end = len(text);
    }
    return text[start:end];
}

# --------------------------------------------------------------------------
# GET /tenants/{tenant_id}/search -- viewer -- search.query -- 200
# --------------------------------------------------------------------------

walker:priv SearchTenant {
    has ctx: dict = {};
    has tenant_id: str = "";
    has q: str = "";
    has types: list = [];
    has limit: int = 0;
    has cursor: str = "";

    can go with entry {
        g = guard(ctx_from(self.ctx), "search.query", "tenant", self.tenant_id, "");
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
        v_str(errs, "q", self.q, 1, MAX_QUERY);
        v_str_list(errs, "types", self.types, 3, 20);
        for tval in self.types {
            if tval not in SEARCH_TYPE_VALUES {
                add_err(errs, "types", "contains an unsupported value");
                break;
            }
        }
        lim = resolve_limit(self.limit);
        if lim < 0 {
            errs.append({"field": "limit", "message": "must be between 1 and 100"});
        }
        if not clean(errs) {
            report deny("VALIDATION_FAILED", rid, errs);
            disengage;
        }

        want_types = self.types if len(self.types) > 0 else SEARCH_TYPE_VALUES;
        needle = self.q.lower();
        t0 = now_ms();

        # IDENTICAL sensitivity predicate as project.list / task.list /
        # comment.list: visible_projects() / visible_tasks() / visible_comments()
        # already dropped anything above sc.role's reach, so nothing scanned
        # here was ever reachable-but-hidden -- it was never reachable at all.
        results: list = [];
        for raw_p in visible_projects(sc) {
            # visible_projects()/visible_tasks()/visible_comments() are declared
            # `-> list` in scope.jac (element type erased), so each element is
            # recast to its concrete node type once, immediately on receipt.
            p = cast(Project, raw_p);
            if "project" in want_types {
                hay = (p.name + " " + p.description).lower();
                if needle in hay {
                    src = p.description if p.description != "" else p.name;
                    results.append(search_item_view(
                        "project", p.project_id, p.name, _snippet(src, self.q),
                        p.project_id, p.sensitivity
                    ));
                }
            }
            if "task" in want_types or "comment" in want_types {
                for raw_t in visible_tasks(sc, p) {
                    t = cast(Task, raw_t);
                    tsens = task_sensitivity(p, t);
                    if "task" in want_types {
                        hay = (t.title + " " + t.description).lower();
                        if needle in hay {
                            src = t.description if t.description != "" else t.title;
                            results.append(search_item_view(
                                "task", t.task_id, t.title, _snippet(src, self.q),
                                p.project_id, tsens
                            ));
                        }
                    }
                    if "comment" in want_types {
                        for raw_c in visible_comments(sc, t) {
                            c = cast(Comment, raw_c);
                            if needle in c.body.lower() {
                                results.append(search_item_view(
                                    "comment", c.comment_id, t.title, _snippet(c.body, self.q),
                                    p.project_id, tsens
                                ));
                            }
                        }
                    }
                }
            }
        }

        # The query text is itself part of the filter: it must appear in the
        # cursor's filter key, or a cursor minted for one query could be
        # replayed against a different one mid-pagination.
        fkey = filter_key({"q": self.q, "types": sorted(want_types)});
        offset = 0;
        if self.cursor != "" {
            offset = decode_cursor(self.cursor, self.tenant_id, "search.query", fkey, t0);
            if offset < 0 {
                report deny("VALIDATION_FAILED", rid,
                            [{"field": "cursor", "message": "is not a usable cursor"}]);
                disengage;
            }
        }
        pg = page(results, lim, offset, self.tenant_id, "search.query", fkey, t0);
        window: list = pg["items"];
        report ok({
            "query": self.q,
            "items": window,
            "next_cursor": pg["next_cursor"],
            "has_more": pg["next_cursor"] != "",
            "total_visible": len(results),
            "took_ms": now_ms() - t0
        }, 200);
        disengage;
    }
}

# --------------------------------------------------------------------------
# POST /tenants/{tenant_id}/exports -- admin † -- export.request -- 202
# --------------------------------------------------------------------------

walker:priv RequestExport {
    has ctx: dict = {};
    has tenant_id: str = "";
    has format: str = "";
    has include: list = [];
    has project_ids: list = [];

    can go with entry {
        g = guard(ctx_from(self.ctx), "export.request", "export", self.tenant_id, "");
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
        if not step_up_ok(sc) {
            report deny("REAUTH_REQUIRED", rid);
            disengage;
        }

        errs: list = [];
        v_enum(errs, "format", self.format, EXPORT_FORMAT_VALUES);
        v_str_list(errs, "include", self.include, 4, 20);
        for item in self.include {
            if item not in EXPORT_INCLUDE_VALUES {
                add_err(errs, "include", "contains an unsupported value");
                break;
            }
        }
        if len(self.include) < 1 {
            add_err(errs, "include", "must include at least one entry");
        }
        v_str_list(errs, "project_ids", self.project_ids, 100, 64);
        if not clean(errs) {
            report deny("VALIDATION_FAILED", rid, errs);
            disengage;
        }

        # EVERY requested project_id must resolve inside THIS tenant. One
        # unresolvable id fails the WHOLE request rather than being silently
        # dropped, which would let a caller learn which ids exist elsewhere.
        for pid in self.project_ids {
            if find_project(sc, pid) is None {
                report deny("NOT_FOUND", rid);
                disengage;
            }
        }

        # visible_projects() is declared `-> list` in scope.jac (element type
        # erased), so every element is recast to Project once, immediately.
        projects: list[Project] = [];
        for raw_p in visible_projects(sc) {
            projects.append(cast(Project, raw_p));
        }
        if len(self.project_ids) > 0 {
            projects = [p for p in projects if p.project_id in self.project_ids];
        }
        # row_count is the number of records the REQUESTER could actually
        # reach, using the same visible_* gates as every other read -- never a
        # raw len(projects_of(...)).
        reachable: int = 0;
        if "projects" in self.include {
            reachable = reachable + len(projects);
        }
        if "tasks" in self.include or "comments" in self.include {
            for p in projects {
                tasks: list[Task] = [];
                for raw_t in visible_tasks(sc, p) {
                    tasks.append(cast(Task, raw_t));
                }
                if "tasks" in self.include {
                    reachable = reachable + len(tasks);
                }
                if "comments" in self.include {
                    for t in tasks {
                        reachable = reachable + len(visible_comments(sc, t));
                    }
                }
            }
        }
        if "members" in self.include {
            reachable = reachable + len(visible_members(sc));
        }

        ts = now_ms();
        tnode = sc.tenant;
        job = (tnode +>:Exports:+> ExportJob(
            job_id=new_export_id(),
            tenant_id=sc.tenant.tenant_id,
            state="ready",
            row_count=reachable,
            requested_by=sc.principal_id,
            created_at=ts,
            format=self.format,
            include=self.include,
            project_ids=self.project_ids,
            ready_at=ts,
            expires_at=ts + 86400000,
            sensitivity_ceiling=sc.role
        ))[0];
        report ok(export_job_view(job), 202);
        disengage;
    }
}

# --------------------------------------------------------------------------
# GET /tenants/{tenant_id}/exports/{export_id} -- admin † -- export.download -- 200
# --------------------------------------------------------------------------

walker:priv DownloadExport {
    has ctx: dict = {};
    has tenant_id: str = "";
    has export_id: str = "";

    can go with entry {
        g = guard(ctx_from(self.ctx), "export.download", "export", self.tenant_id, self.export_id);
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
        if not step_up_ok(sc) {
            report deny("REAUTH_REQUIRED", rid);
            disengage;
        }
        job = find_export(sc, self.export_id);
        if job is None {
            report deny("NOT_FOUND", rid);
            disengage;
        }
        if job.state != "ready" {
            report ok(export_job_view(job), 202);
            disengage;
        }

        # RE-FILTER every record against the DOWNLOADER'S CURRENT ceiling.
        # `job.sensitivity_ceiling` (recorded at request time) is never
        # trusted here -- the payload is rebuilt from visible_projects() /
        # visible_tasks() / visible_comments() right now, so a role change
        # between request and download is reflected, not ignored.
        projects: list[Project] = [];
        for raw_p in visible_projects(sc) {
            projects.append(cast(Project, raw_p));
        }
        want_ids = job.project_ids;
        if len(want_ids) > 0 {
            projects = [p for p in projects if p.project_id in want_ids];
        }
        data: dict = {};
        record_count: int = 0;
        if "projects" in job.include {
            rows: list = [project_export_record(p) for p in projects];
            data["projects"] = rows;
            record_count = record_count + len(rows);
        }
        if "tasks" in job.include {
            rows: list = [];
            for p in projects {
                for raw_t in visible_tasks(sc, p) {
                    t = cast(Task, raw_t);
                    rows.append(task_export_record(t, task_sensitivity(p, t)));
                }
            }
            data["tasks"] = rows;
            record_count = record_count + len(rows);
        }
        if "comments" in job.include {
            rows: list = [];
            for p in projects {
                for raw_t in visible_tasks(sc, p) {
                    t = cast(Task, raw_t);
                    for raw_c in visible_comments(sc, t) {
                        c = cast(Comment, raw_c);
                        rows.append(comment_export_record(c, task_sensitivity(p, t)));
                    }
                }
            }
            data["comments"] = rows;
            record_count = record_count + len(rows);
        }
        if "members" in job.include {
            rows: list = [];
            for raw_m in visible_members(sc) {
                rows.append(member_export_record(cast(Membership, raw_m)));
            }
            data["members"] = rows;
            record_count = record_count + len(rows);
        }

        canon = json.dumps(data, sort_keys=True, separators=(",", ":"));
        checksum = hashlib.sha256(canon.encode("utf-8")).hexdigest();
        report ok({
            "export_id": job.job_id,
            "tenant_id": job.tenant_id,
            "format": job.format,
            "generated_at": now_ms(),
            "record_count": record_count,
            "checksum_sha256": checksum,
            "sensitivity_ceiling_applied": sc.role,
            "data": data
        }, 200);
        disengage;
    }
}

# --------------------------------------------------------------------------
# POST /tenants/{tenant_id}/integrations/call
# -- member (api_token) / admin † (session) -- integration.call -- 200
# --------------------------------------------------------------------------

walker:priv IntegrationCall {
    has ctx: dict = {};
    has tenant_id: str = "";
    has connector: str = "";
    has operation: str = "";
    has payload: dict = {};
    has project_id: str = "";
    has idempotency_key: str = "";

    can go with entry {
        g = guard(ctx_from(self.ctx), "integration.call", "integration", self.tenant_id, "");
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

        # The contract's role rule: an API-token caller needs only `member`
        # rank, because guard() already enforced the token's own scope; a
        # user-session caller needs `admin` AND a recent password, because a
        # session carries no scope of its own to narrow it. No third path.
        if sc.auth_method == "api_token" {
            if not role_satisfies(sc.role, "member") {
                report deny("INSUFFICIENT_ROLE", rid);
                disengage;
            }
        } elif sc.auth_method == "session" {
            if not role_satisfies(sc.role, "admin") {
                report deny("INSUFFICIENT_ROLE", rid);
                disengage;
            }
            if not step_up_ok(sc) {
                report deny("REAUTH_REQUIRED", rid);
                disengage;
            }
        } else {
            report deny("INSUFFICIENT_ROLE", rid);
            disengage;
        }

        errs: list = [];
        v_enum(errs, "connector", self.connector, INTEGRATION_CONNECTOR_VALUES);
        v_pattern(errs, "operation", self.operation, INTEGRATION_OPERATION_PATTERN, 64);
        if not isinstance(self.payload, dict) {
            add_err(errs, "payload", "must be an object");
        } else {
            encoded = json.dumps(self.payload, sort_keys=True, separators=(",", ":")).encode("utf-8");
            if len(encoded) > 16384 {
                add_err(errs, "payload", "must serialise to at most 16384 bytes");
            }
        }
        v_opt_id(errs, "project_id", self.project_id);
        v_opt_str(errs, "idempotency_key", self.idempotency_key, 128);
        if not clean(errs) {
            report deny("VALIDATION_FAILED", rid, errs);
            disengage;
        }

        if self.project_id != "" {
            if find_project(sc, self.project_id) is None {
                report deny("NOT_FOUND", rid);
                disengage;
            }
        }

        # NO REAL NETWORK CALL. Nothing in this walker (or anywhere else in
        # this file) makes an outbound HTTP request to slack/github/a webhook.
        # This records the dispatch (guard()'s single AuditEvent already did
        # that) and returns a synthetic result.
        ts = now_ms();
        report ok({
            "call_id": new_call_id(),
            "tenant_id": sc.tenant.tenant_id,
            "connector": self.connector,
            "operation": self.operation,
            "status": "dispatched",
            "result": {"status": "dispatched"},
            "dispatched_at": ts,
            "latency_ms": 0,
            "idempotency_key": self.idempotency_key
        }, 200);
        disengage;
    }
}
