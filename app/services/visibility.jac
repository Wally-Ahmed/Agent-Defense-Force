# app/services/visibility.jac -- THE one answer to "which records may this role
# see", for collections as well as for single records.
#
# ===================== WHY THIS MODULE HAD TO EXIST =========================
# The floor used to be applied in two places that could drift, and they did.
# `app/services/scope.jac` filtered its collections correctly; `guard()` in
# app/security/authz.jac applied the floor ONLY when a single `target_id` had
# been resolved, and measured list actions with an unfiltered traversal. The
# served walkers (`app/walkers/work.jac`, the ones `app/main.jac` actually
# binds) report the collection guard hands back -- so `project.list` returned
# every project in the tenant to a plain member, sensitivity labels attached,
# on an audit row that read `outcome: allow`. Two implementations of one rule
# is what made a green test suite and an open endpoint compatible.
#
# So: one implementation, here, at the bottom of the dependency graph. It
# imports the traversal helpers from app/model/resolve.jac and the floor table
# from app/services/sensitivity.jac, and it is imported by BOTH the
# authorization layer (which measures and gates) and the domain layer (which
# re-applies it as defence in depth). Neither one owns a copy.
# ===========================================================================
#
# ======================= WHY THERE IS NO CANARY BRANCH =====================
# Nothing below names a sensitivity value. Every decision is `can_reach(role,
# s)` and every combination is `stricter(a, b)`, both from the single floor
# table in app/services/sensitivity.jac, where the high sensitivities share one
# row. Delete that row and this file's behaviour is unchanged in shape: the
# value would fall through to the unknown-value default and be stricter still,
# never looser.
# ===========================================================================
#
# INHERITANCE, AND WHY IT IS PART OF THE SAME RULE. A record is no less
# sensitive than the thing it lives inside. A task's effective sensitivity is
# stricter(project, task) and a comment's is its task's -- so a record whose own
# field reads `normal` is still out of reach when its parent is not. Reading
# only a record's own field is not a milder version of this rule, it is a hole
# in it: the fixture's `tk_canary` is a `normal` task inside the one project the
# whole design exists to protect, and a floor that consulted only `task.sensitivity`
# handed it, and its comments, to a member.

import from typing { cast }
import from app.model.graph { Tenant, Project, Task, Comment }
import from app.model.resolve {
    projects_of, tasks_of, comments_of, project_of_task, task_in, sensitivity_of
}
import from app.services.sensitivity { can_reach, stricter }

# --------------------------------------------------------------------------
# Effective sensitivity -- a record's own value, raised by its ancestors'.
# --------------------------------------------------------------------------

"""A task's effective sensitivity: the stricter of its project's and its own."""
def:pub task_sensitivity(project: Project, task: Task) -> str {
    return stricter(project.sensitivity, task.sensitivity);
}

"""The sensitivity a resolved record is actually protected at, inherited.

`tenant` is the root of the traversal, exactly as everywhere else in this
codebase: the parent is found by walking down from the Tenant, never by
resolving a stored parent id globally. A record whose parent cannot be reached
from this tenant falls back to its own value, which is the strict direction --
it can only ever refuse a caller who would otherwise have been let through."""
def:pub effective_sensitivity(tenant: Tenant, target: object) -> str {
    if target is None {
        return "";
    }
    if isinstance(target, Comment) {
        holder = task_in(tenant, cast(Comment, target).task_id);
        if holder is None {
            return sensitivity_of(target);
        }
        return effective_sensitivity(tenant, holder);
    }
    if isinstance(target, Task) {
        t = cast(Task, target);
        parent = project_of_task(tenant, t.task_id);
        if parent is None {
            return t.sensitivity;
        }
        return task_sensitivity(cast(Project, parent), t);
    }
    return sensitivity_of(target);
}

"""True when `role` may reach this record, ancestors taken into account."""
def:pub may_reach(tenant: Tenant, role: str, target: object) -> bool {
    return can_reach(role, effective_sensitivity(tenant, target));
}

# --------------------------------------------------------------------------
# Collections. Filtered, then ordered stably.
#
# The order is fixed here rather than at each call site so that guard()'s
# MEASUREMENT and the domain layer's page are the same list in the same
# sequence -- a paginator that sorted differently from the thing that counted
# would make `result_count` unverifiable against what the caller received.
# --------------------------------------------------------------------------

"""Every project in this tenant `role` can reach, stable order."""
def:pub visible_projects_in(tenant: Tenant, role: str) -> list {
    out = [p for p in projects_of(tenant) if can_reach(role, p.sensitivity)];
    return sorted(out, key=lambda p: Project : (p.created_at, p.project_id));
}

"""Every task in this project `role` can reach, stable order.

The project is already resolved, so inheritance is a direct comparison rather
than another walk."""
def:pub visible_tasks_in(project: Project, role: str) -> list {
    out = [
        t for t in tasks_of(project)
        if can_reach(role, task_sensitivity(project, t))
    ];
    return sorted(out, key=lambda t: Task : (t.created_at, t.task_id));
}

"""Every comment on this task `role` can reach, stable order.

A Comment has no sensitivity of its own, so the gate is entirely its task's
effective value -- and that value is checked HERE rather than assumed to have
been checked by whoever resolved the task. An empty list for an unreachable
parent is what keeps this honest if a future caller reaches it by a route that
skipped the parent check."""
def:pub visible_comments_in(tenant: Tenant, task: Task, role: str) -> list {
    if not may_reach(tenant, role, task) {
        return [];
    }
    out = [c for c in comments_of(task)];
    return sorted(out, key=lambda c: Comment : (c.created_at, c.comment_id));
}
