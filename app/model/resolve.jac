# app/model/resolve.jac — resolution by traversal. The isolation boundary.
#
# THE RULE THIS FILE ENFORCES: no tenant-owned resource is ever resolved by
# global id. Every lookup starts at a Tenant node and walks the typed ownership
# edges to reach the target:
#
#     Tenant --Owns--> Project --Contains--> Task --Discusses--> Comment
#
# The consequence is the whole point. A valid Task id belonging to tenant B,
# presented by a member of tenant A, is not "rejected by a check" -- it is
# UNREACHABLE. There is no code path that could return it, because the walk
# never leaves tenant A's subgraph. Isolation that depends on remembering to
# write `if resource.tenant_id != ctx.tenant_id` is isolation you will
# eventually forget; isolation that depends on which edges exist is not.
#
# Every function here returns `None` on miss. Callers translate that to
# NOT_FOUND. None of them accept a "search everywhere" flag, and none of them
# take a tenant-optional path -- adding one would silently delete the boundary.
#
# tenant_by_id() and principal_by_email() are the two deliberate exceptions and
# they are exceptions in name only: a Tenant IS the root of a tenancy (there is
# nothing above it to traverse from), and login must resolve an identity before
# any tenant context exists. Both scan only the platform-level collections,
# never a tenant's interior.

import from app.model.graph {
    Platform, Tenant, Membership, Principal, Session, Token,
    Project, Task, Comment, Invite, ExportJob,
    Hosts, Registers, HasMember, Identifies, Owns, Invited, Exports,
    Contains, Discusses, Authenticates, Bears,
    get_platform, all_tenants, all_principals
}

# --------------------------------------------------------------------------
# Platform-level entry points
# --------------------------------------------------------------------------

"""The Tenant node for `tenant_id`, or None. The root of every traversal."""
def:pub tenant_by_id(tenant_id: str) -> Tenant | None {
    if tenant_id == "" {
        return None;
    }
    for t in all_tenants() {
        if t.tenant_id == tenant_id {
            return t;
        }
    }
    return None;
}

"""The Principal for a principal_id, or None."""
def:pub principal_by_id(principal_id: str) -> Principal | None {
    if principal_id == "" {
        return None;
    }
    for p in all_principals() {
        if p.principal_id == principal_id {
            return p;
        }
    }
    return None;
}

"""The Principal for an email, or None.

Used ONLY by the login path, which has no tenant context yet. Callers must not
let the outcome of this lookup change what the client observes -- see
app/walkers/auth.jac, where a miss and a wrong password are indistinguishable."""
def:pub principal_by_email(email: str) -> Principal | None {
    needle = email.strip().lower();
    if needle == "" {
        return None;
    }
    for p in all_principals() {
        if p.email == needle {
            return p;
        }
    }
    return None;
}

# --------------------------------------------------------------------------
# Identity -> credentials. Sessions and tokens hang off their principal, so a
# session id is only ever resolvable through the principal that owns it.
# --------------------------------------------------------------------------

"""The Session for a session_id, or None. Scans principals' own session sets --
there is no global session table to enumerate or guess into."""
def:pub session_by_id(session_id: str) -> Session | None {
    if session_id == "" {
        return None;
    }
    for p in all_principals() {
        for s in [p->:Authenticates:->][?:Session] {
            if s.session_id == session_id {
                return s;
            }
        }
    }
    return None;
}

"""The Token for a jti, or None."""
def:pub token_by_jti(jti: str) -> Token | None {
    if jti == "" {
        return None;
    }
    for p in all_principals() {
        for t in [p->:Bears:->][?:Token] {
            if t.jti == jti {
                return t;
            }
        }
    }
    return None;
}

"""Every live (unrevoked) session belonging to a principal."""
def:pub sessions_of(principal: Principal) -> list[Session] {
    return [s for s in [principal->:Authenticates:->][?:Session] if not s.revoked];
}

# --------------------------------------------------------------------------
# Tenant interior. Everything below starts from a Tenant node.
# --------------------------------------------------------------------------

"""The Membership joining `principal_id` to `tenant`, or None.

Walks Tenant --HasMember--> Membership. A membership in another tenant is not
reachable from here, which is what makes role escalation across tenants
structurally impossible rather than merely checked."""
def:pub membership_of(tenant: Tenant, principal_id: str) -> Membership | None {
    if principal_id == "" {
        return None;
    }
    for m in [tenant->:HasMember:->][?:Membership] {
        if m.principal_id == principal_id {
            return m;
        }
    }
    return None;
}

"""Every membership in a tenant."""
def:pub memberships_of(tenant: Tenant) -> list[Membership] {
    return [tenant->:HasMember:->][?:Membership];
}

"""The Principal a membership identifies, or None."""
def:pub principal_of(membership: Membership) -> Principal | None {
    found = [membership->:Identifies:->][?:Principal];
    if len(found) > 0 {
        return found[0];
    }
    return None;
}

"""Projects owned by a tenant. Tenant --Owns--> Project."""
def:pub projects_of(tenant: Tenant) -> list[Project] {
    return [tenant->:Owns:->][?:Project];
}

"""The Project with `project_id` INSIDE this tenant, or None.

A project_id from another tenant returns None -- not because it was compared
and rejected, but because the walk never visits it."""
def:pub project_in(tenant: Tenant, project_id: str) -> Project | None {
    if project_id == "" {
        return None;
    }
    for p in [tenant->:Owns:->][?:Project] {
        if p.project_id == project_id {
            return p;
        }
    }
    return None;
}

"""Tasks in a project. Project --Contains--> Task."""
def:pub tasks_of(project: Project) -> list[Task] {
    return [project->:Contains:->][?:Task];
}

"""The Task with `task_id` inside this tenant, reached only through the
tenant's own projects: Tenant --Owns--> Project --Contains--> Task."""
def:pub task_in(tenant: Tenant, task_id: str) -> Task | None {
    if task_id == "" {
        return None;
    }
    for p in [tenant->:Owns:->][?:Project] {
        for t in [p->:Contains:->][?:Task] {
            if t.task_id == task_id {
                return t;
            }
        }
    }
    return None;
}

"""Comments on a task. Task --Discusses--> Comment."""
def:pub comments_of(task: Task) -> list[Comment] {
    return [task->:Discusses:->][?:Comment];
}

"""The Comment with `comment_id` inside this tenant, three hops deep:
Tenant --Owns--> Project --Contains--> Task --Discusses--> Comment."""
def:pub comment_in(tenant: Tenant, comment_id: str) -> Comment | None {
    if comment_id == "" {
        return None;
    }
    for p in [tenant->:Owns:->][?:Project] {
        for t in [p->:Contains:->][?:Task] {
            for c in [t->:Discusses:->][?:Comment] {
                if c.comment_id == comment_id {
                    return c;
                }
            }
        }
    }
    return None;
}

"""The Project a task belongs to, found by walking back through the tenant.
Used to populate an audit event's parent_id without trusting task.project_id."""
def:pub project_of_task(tenant: Tenant, task_id: str) -> Project | None {
    for p in [tenant->:Owns:->][?:Project] {
        for t in [p->:Contains:->][?:Task] {
            if t.task_id == task_id {
                return p;
            }
        }
    }
    return None;
}

"""Invites issued by a tenant."""
def:pub invites_of(tenant: Tenant) -> list[Invite] {
    return [tenant->:Invited:->][?:Invite];
}

"""The Invite with `invite_id` inside this tenant, or None."""
def:pub invite_in(tenant: Tenant, invite_id: str) -> Invite | None {
    if invite_id == "" {
        return None;
    }
    for i in [tenant->:Invited:->][?:Invite] {
        if i.invite_id == invite_id {
            return i;
        }
    }
    return None;
}

"""The pending Invite in this tenant matching a token hash, or None.

Matched on the HASH -- the invite token itself is never stored, so a database
read does not hand an attacker a working invite."""
def:pub invite_by_hash(tenant: Tenant, token_hash: str) -> Invite | None {
    if token_hash == "" {
        return None;
    }
    for i in [tenant->:Invited:->][?:Invite] {
        if i.token_hash == token_hash {
            return i;
        }
    }
    return None;
}

"""Export jobs belonging to a tenant."""
def:pub exports_of(tenant: Tenant) -> list[ExportJob] {
    return [tenant->:Exports:->][?:ExportJob];
}

"""The ExportJob with `job_id` inside this tenant, or None."""
def:pub export_in(tenant: Tenant, job_id: str) -> ExportJob | None {
    if job_id == "" {
        return None;
    }
    for j in [tenant->:Exports:->][?:ExportJob] {
        if j.job_id == job_id {
            return j;
        }
    }
    return None;
}

# --------------------------------------------------------------------------
# The dispatcher guard() uses. One entry point, one table of target kinds.
# --------------------------------------------------------------------------

# Target kinds that name a resource inside a tenant and are therefore resolved
# by traversal. Anything not listed resolves to the tenant itself.
glob:pub TRAVERSED_KINDS: list = ["project", "task", "comment", "invite", "export", "member"];

"""Resolve `target_id` of kind `target_kind` WITHIN `tenant`, or None.

The single resolution surface guard() calls. There is no variant of this
function that takes a tenant of None, and no flag that widens the search."""
def:pub resolve_in_tenant(tenant: Tenant, target_kind: str, target_id: str) -> object {
    if target_id == "" {
        return None;
    }
    if target_kind == "project" {
        return project_in(tenant, target_id);
    }
    if target_kind == "task" {
        return task_in(tenant, target_id);
    }
    if target_kind == "comment" {
        return comment_in(tenant, target_id);
    }
    if target_kind == "invite" {
        return invite_in(tenant, target_id);
    }
    if target_kind == "export" {
        return export_in(tenant, target_id);
    }
    if target_kind == "member" {
        return membership_of(tenant, target_id);
    }
    # tenant / auth / token / integration have no in-tenant child to resolve.
    return None;
}

"""The sensitivity label of a resolved node, for audit + severity.

Reads through an opaque handle with getattr so this works for any target kind
without the caller narrowing the type first."""
def:pub sensitivity_of(node: object) -> str {
    if node is None {
        return "";
    }
    return getattr(node, "sensitivity", "normal");
}
