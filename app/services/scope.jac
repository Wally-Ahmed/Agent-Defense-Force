# app/services/scope.jac -- the caller's authorized view of one tenant.
#
# ============================== THE ONE RULE ================================
# Nothing in app/services/ resolves a tenant-owned resource by global id. Every
# lookup starts at the Tenant node on the Grant that guard() just returned and
# walks the typed edges
#
#     Tenant --:Owns:--> Project --:Contains:--> Task --:Discusses:--> Comment
#
# through app/model/resolve.jac, which owns every traversal in the application.
# A project id belonging to another tenant is not "found and rejected" -- it is
# never enumerated, because it hangs off a different Tenant. The answer is
# byte-identical to the answer for an id that never existed.
#
# This module adds ONE thing on top of app/model/resolve.jac: the sensitivity
# floor. resolve.jac reports a record's sensitivity (`sensitivity_of`) but does
# not gate on it, and guard() records it in the audit event without gating on it
# either. The gate lives here, in `app/services/sensitivity.can_reach`, applied
# identically by every list, read, update, delete and search below.
# ===========================================================================
#
# WHAT THIS MODULE IS NOT. It is not an authorization check and it cannot allow
# anything. guard() has already run and already emitted the audit event by the
# time any function here executes; everything here can only NARROW what guard
# allowed. The membership is re-read from the graph rather than taken from the
# transport, per contracts/app_api.md ("`ctx.tenant.role` is transport only:
# every walker re-reads the Membership node from the graph and re-evaluates the
# role itself") -- that re-read is defence in depth behind guard(), never a
# substitute for it.

import from typing { cast }
import from contracts.req_ctx_contract { ReqCtx, Grant }
import from app.model.graph {
    Tenant, Membership, Principal, Session, Project, Task, Comment, Invite, ExportJob
}
import from app.model.resolve {
    tenant_by_id, principal_by_id, session_by_id, membership_of, memberships_of,
    projects_of, project_in, tasks_of, comments_of, invites_of, exports_of,
    export_in, principal_of
}
import from app.model.graph { Hosts, HasMember, get_platform }
import from app.security.clock { now_ms, REAUTH_MAX_AGE_MS }
import from app.services.sensitivity { can_reach, stricter }

# --------------------------------------------------------------------------
# Scope -- everything a walker is allowed to know about who is calling.
# --------------------------------------------------------------------------

"""The authenticated caller, resolved against the graph, inside one tenant.

A walker never reads a role, a principal id or a tenant out of `ctx`. It reads
them from here, and every field here came out of the object graph."""
obj Scope {
    has tenant: Tenant;
    has membership: Membership;
    has role: str;
    has principal_id: str;
    has last_auth_at: int = 0;
    has auth_method: str = "none";
}

"""Either a Scope, or the deny code that stopped it from being opened."""
obj ScopeResult {
    has scope: (Scope | None) = None;
    has reason: str = "";
}

"""Open a scope for `tenant_id` from the Grant guard() returned.

Every field is taken from the graph handles on the Grant, and the Membership is
re-read from the tenant subtree regardless. Returns ScopeResult(scope=None,
reason=...) rather than raising, so the walker reports the code and disengages.

Reaching a deny here means guard() and this module disagree, which should be
impossible; it is handled fail-closed rather than assumed away."""
def:pub open_scope(g: Grant, ctx: ReqCtx, tenant_id: str) -> ScopeResult {
    if g.tenant is None or g.principal is None {
        return ScopeResult(scope=None, reason="NOT_FOUND");
    }
    tenant = cast(Tenant, g.tenant);
    actor = cast(Principal, g.principal);

    # The Grant must describe the tenant the request addressed. A disagreement
    # is a crossing, not a rounding error.
    if tenant.tenant_id != tenant_id {
        return ScopeResult(scope=None, reason="TENANT_MISMATCH");
    }

    # Re-read the Membership from THIS tenant's subtree. A membership in another
    # tenant is not reachable from here, so it cannot be mistaken for one here.
    found = membership_of(tenant, actor.principal_id);
    if found is None {
        return ScopeResult(scope=None, reason="NOT_A_MEMBER");
    }
    m = cast(Membership, found);
    if m.state != "active" {
        return ScopeResult(scope=None, reason="NOT_A_MEMBER");
    }

    last_auth = 0;
    method = "api_token";
    if ctx.session_id != "" {
        sess = session_by_id(ctx.session_id);
        if sess is not None {
            last_auth = cast(Session, sess).last_auth_at;
            method = "session";
        }
    }
    return ScopeResult(
        scope=Scope(
            tenant=tenant,
            membership=m,
            role=m.role,
            principal_id=actor.principal_id,
            last_auth_at=last_auth,
            auth_method=method
        ),
        reason=""
    );
}

"""True when the caller presented a password recently enough for a `†` action.

contracts/app_api.md gates member role change, member remove, export request,
export download and session-authenticated integration calls on
`auth_age_s <= 900`. Fail-closed: no session (an API-token principal, or a
session that has vanished) is not a recent password, so the answer is False and
the walker reports REAUTH_REQUIRED. Step-up is never satisfied by a claim in
`ctx`; it is measured against `Session.last_auth_at` in the graph."""
def:pub step_up_ok(sc: Scope) -> bool {
    if sc.auth_method != "session" {
        return False;
    }
    if sc.last_auth_at <= 0 {
        return False;
    }
    return (now_ms() - sc.last_auth_at) <= REAUTH_MAX_AGE_MS;
}

# --------------------------------------------------------------------------
# Projects
# --------------------------------------------------------------------------

"""Every project in this tenant the caller's role can reach, stable order."""
def:pub visible_projects(sc: Scope) -> list {
    out = [p for p in projects_of(sc.tenant) if can_reach(sc.role, p.sensitivity)];
    return sorted(out, key=lambda p: Project : (p.created_at, p.project_id));
}

"""One project, by traversal from the caller's tenant.

Returns None when the id names a project in another tenant, a project that does
not exist, or a project above the caller's reach. All three are the same answer
because all three are produced by the same expression."""
def:pub find_project(sc: Scope, project_id: str) -> (Project | None) {
    hit = project_in(sc.tenant, project_id);
    if hit is None {
        return None;
    }
    p = cast(Project, hit);
    if not can_reach(sc.role, p.sensitivity) {
        return None;
    }
    return p;
}

# --------------------------------------------------------------------------
# Tasks
# --------------------------------------------------------------------------

"""A task's effective sensitivity: the stricter of its project's and its own."""
def:pub task_sensitivity(project: Project, task: Task) -> str {
    return stricter(project.sensitivity, task.sensitivity);
}

"""Every task in this project the caller can reach, stable order."""
def:pub visible_tasks(sc: Scope, project: Project) -> list {
    out = [
        t for t in tasks_of(project)
        if can_reach(sc.role, task_sensitivity(project, t))
    ];
    return sorted(out, key=lambda t: Task : (t.created_at, t.task_id));
}

"""One task, by traversal from an already-resolved project."""
def:pub find_task(sc: Scope, project: Project, task_id: str) -> (Task | None) {
    if task_id == "" {
        return None;
    }
    for t in tasks_of(project) {
        if t.task_id == task_id and can_reach(sc.role, task_sensitivity(project, t)) {
            return t;
        }
    }
    return None;
}

# --------------------------------------------------------------------------
# Comments
# --------------------------------------------------------------------------

"""Every comment on this task, stable order.

A comment carries no sensitivity of its own; it inherits its task's effective
value, which the caller already had to clear to reach the task at all."""
def:pub visible_comments(sc: Scope, task: Task) -> list {
    return sorted(comments_of(task), key=lambda c: Comment : (c.created_at, c.comment_id));
}

"""One comment, by traversal from an already-resolved task."""
def:pub find_comment(sc: Scope, task: Task, comment_id: str) -> (Comment | None) {
    if comment_id == "" {
        return None;
    }
    for c in comments_of(task) {
        if c.comment_id == comment_id {
            return c;
        }
    }
    return None;
}

# --------------------------------------------------------------------------
# Members, invites, exports
# --------------------------------------------------------------------------

"""Every live membership in this tenant, stable order."""
def:pub visible_members(sc: Scope) -> list {
    out = [m for m in memberships_of(sc.tenant) if m.state != "removed"];
    return sorted(out, key=lambda m: Membership : (m.created_at, m.membership_id));
}

"""One membership, by its membership_id, by traversal from the caller's tenant.

app/model/resolve.membership_of() keys on principal_id, which is what guard()
needs; the public API addresses a membership by `membership_id`. Both walk the
same Tenant --HasMember--> edge set, so neither can reach another tenant's
membership."""
def:pub find_membership(sc: Scope, membership_id: str) -> (Membership | None) {
    if membership_id == "" {
        return None;
    }
    for m in memberships_of(sc.tenant) {
        if m.membership_id == membership_id and m.state != "removed" {
            return m;
        }
    }
    return None;
}

"""The email on the principal a membership identifies, or ""."""
def:pub member_email(m: Membership) -> str {
    p = principal_of(m);
    if p is None {
        return "";
    }
    return cast(Principal, p).email;
}

"""Every invite issued by this tenant."""
def:pub visible_invites(sc: Scope) -> list {
    return invites_of(sc.tenant);
}

"""Every export job belonging to this tenant, stable order."""
def:pub visible_exports(sc: Scope) -> list {
    return sorted(exports_of(sc.tenant), key=lambda j: ExportJob : (j.created_at, j.job_id));
}

"""One export job, by traversal from the caller's tenant."""
def:pub find_export(sc: Scope, job_id: str) -> (ExportJob | None) {
    hit = export_in(sc.tenant, job_id);
    if hit is None {
        return None;
    }
    return cast(ExportJob, hit);
}

# --------------------------------------------------------------------------
# The two pre-tenant surfaces. Both are in the contract; neither resolves a
# tenant-owned resource.
# --------------------------------------------------------------------------

"""Tenants this principal holds an active membership in.

`GET /tenants` is the one endpoint with no tenant in its path -- it is how a
caller discovers which tenants exist FOR THEM. It still resolves nothing by id:
a tenant appears only when an active Membership for this principal hangs off
it, so the result set is a projection of the caller's own memberships."""
def:pub tenants_for(principal_id: str) -> list {
    out = [];
    if principal_id == "" {
        return out;
    }
    plat = get_platform();
    ranked: list = [];
    for t in [plat->:Hosts:->][?:Tenant] {
        if t.status != "active" {
            continue;
        }
        for m in [t->:HasMember:->][?:Membership] {
            if m.principal_id == principal_id and m.state == "active" {
                ranked.append((t.created_at, t.tenant_id, t, m.role));
            }
        }
    }
    ranked.sort(key=lambda r: tuple : (r[0], r[1]));
    for row in ranked {
        out.append({"tenant": row[2], "role": row[3]});
    }
    return out;
}

"""The caller's role in a tenant, or "none". For surfaces with no Scope yet."""
def:pub role_in(tenant: Tenant, principal_id: str) -> str {
    m = membership_of(tenant, principal_id);
    if m is None {
        return "none";
    }
    mm = cast(Membership, m);
    if mm.state != "active" {
        return "none";
    }
    return mm.role;
}
