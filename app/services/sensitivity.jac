# app/services/sensitivity.jac -- sensitivity as a ROLE FLOOR, expressed as data.
#
# app/security/roles.jac owns the rank ladder and the action -> minimum-role
# table; this module owns the one thing that table cannot express: a per-RECORD
# floor that raises the requirement above the action's baseline. It calls
# `role_satisfies` and `rank_of` from there and defines no ladder of its own,
# so there is exactly one definition of "admin outranks member" in the codebase.
#
# ======================= WHY THERE IS NO CANARY BRANCH =====================
# `SENSITIVITY_FLOOR` has three rows and no row is special. `confidential` and
# `canary` map to the SAME floor and therefore take the SAME code path; the
# words never appear in a conditional. Grep the whole of app/services/ for
# `"canary"` -- it appears in this table and in a validation whitelist, and
# nowhere else.
#
# The consequence is the property the demo rests on: a low-privilege member is
# denied the canary record by ORDINARY authorization. The denial is produced by
# the same expression that denies them any other above-rank record, returns the
# same 404, and is indistinguishable from it. If the `canary` row were deleted
# and the value fell through to the unknown-value default, not one authorization
# outcome would change. The distinct enum value exists only so the fixture
# generator and the EXTERNAL monitor know which record was seeded.
# ===========================================================================

import from app.security.roles { rank_of, role_satisfies }

# Reading a record of sensitivity S requires at least this role.
# contracts/app_api.md: "normal -> viewer, confidential -> admin, canary -> admin".
glob:pub SENSITIVITY_FLOOR: dict = {
    "normal": "viewer",
    "confidential": "admin",
    "canary": "admin"
};

# The values a client is permitted to WRITE into a sensitivity field. Used by
# validation, not by authorization.
glob:pub SENSITIVITY_VALUES: list = ["normal", "confidential", "canary"];

"""Minimum role required to reach a record of this sensitivity.

An unrecognised value floors at "owner", the strictest rank, so a typo or a
future enum member is unreachable rather than wide open."""
def:pub floor_for(sensitivity: str) -> str {
    return SENSITIVITY_FLOOR.get(sensitivity, "owner");
}

"""True when a caller holding `role` can reach a record of this sensitivity.

This single expression is the entire sensitivity gate. Every list, read,
update, delete and search in app/services/ funnels through it."""
def:pub can_reach(role: str, sensitivity: str) -> bool {
    return role_satisfies(role, floor_for(sensitivity));
}

"""The higher of two role names."""
def:pub higher(a: str, b: str) -> str {
    return a if rank_of(a) >= rank_of(b) else b;
}

"""Effective role requirement for an operation on a record of this sensitivity:
max(action baseline, floor(sensitivity)).

This is the contract's `‡` rule. Creating a project requires `member`; creating
a `confidential` or `canary` one requires `admin` -- because the floor is
higher, not because this function knows what a canary is."""
def:pub effective_required(base_role: str, sensitivity: str) -> str {
    return higher(base_role, floor_for(sensitivity));
}

"""The stricter of two sensitivities, ordered by the floor each implies.

A task's effective sensitivity is stricter(project, task); a comment inherits
its task's. Ordering by floor rather than by string means the comparison can
never drift away from the authorization table above it."""
def:pub stricter(a: str, b: str) -> str {
    return a if rank_of(floor_for(a)) >= rank_of(floor_for(b)) else b;
}
