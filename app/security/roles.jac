# app/security/roles.jac — the authorization policy, as data.
#
# The role required by an action is a TABLE, not a chain of `if` statements
# scattered through walkers. One table means: a reviewer can read the entire
# authorization policy in one screen; a missing entry is a visible hole rather
# than an accidental allow; and there is nowhere for an `if user == "admin"`
# shortcut to hide.
#
# Roles live on Membership, never on Principal. A principal is not "an admin" --
# a principal is an admin OF A TENANT, and may be a viewer in the next one.

import from contracts.audit_event_contract { ACTIONS }

# owner > admin > member > viewer. Higher rank satisfies any lower requirement.
glob:pub ROLE_RANK: dict = {
    "viewer": 0,
    "member": 1,
    "admin": 2,
    "owner": 3
};

glob:pub ROLES: list = ["viewer", "member", "admin", "owner"];

# --------------------------------------------------------------------------
# The policy table. Every one of the 38 actions in ACTIONS appears exactly
# once. `assert_policy_complete()` proves it, and a test calls that.
# --------------------------------------------------------------------------

glob:pub ACTION_MIN_ROLE: dict = {
    # --- auth: a live, verified session is the requirement; role is not. ----
    "auth.register": "viewer",
    "auth.login": "viewer",
    "auth.login_failed": "viewer",
    "auth.logout": "viewer",
    "auth.session_expired": "viewer",
    "auth.token_issued": "viewer",
    "auth.token_revoked": "viewer",
    "auth.reauth_required": "viewer",

    # --- tenancy ------------------------------------------------------------
    "tenant.create": "viewer",       # tenantless: see TENANTLESS_ACTIONS
    "tenant.read": "viewer",
    "member.invite": "admin",
    "member.accept": "viewer",       # membership-creating: see MEMBERSHIP_EXEMPT_ACTIONS
    "member.role_change": "admin",
    "member.remove": "admin",

    # --- projects -----------------------------------------------------------
    "project.create": "member",
    "project.read": "viewer",
    "project.list": "viewer",
    "project.update": "member",
    "project.delete": "admin",

    # --- tasks --------------------------------------------------------------
    "task.create": "member",
    "task.read": "viewer",
    "task.list": "viewer",
    "task.update": "member",
    "task.delete": "member",
    "task.assign": "member",

    # --- comments -----------------------------------------------------------
    "comment.create": "member",
    "comment.read": "viewer",
    "comment.list": "viewer",
    "comment.delete": "admin",

    # --- egress: the expensive ones. Admin, deliberately. --------------------
    "export.request": "admin",
    "export.download": "admin",
    "search.query": "viewer",
    "integration.call": "admin",

    # --- containment: the system defending itself. Owner only. ---------------
    "containment.propose": "owner",
    "containment.apply": "owner",
    "containment.verify": "owner",
    "containment.expire": "owner",
    "containment.rollback": "owner"
};

# Actions that legitimately have no tenant to be a member of yet. guard() still
# demands a verified ctx, a live session, and a clean control check for these;
# it skips only the membership and role steps. Keeping this list to two entries
# is the point -- every addition widens the unauthenticated-ish surface.
glob:pub TENANTLESS_ACTIONS: list = ["tenant.create"];

# Actions whose whole purpose is to CREATE the membership, so requiring one
# first is circular. The walker must validate a bearer secret (the invite token)
# by traversal from the target tenant; that secret is the real control.
glob:pub MEMBERSHIP_EXEMPT_ACTIONS: list = ["member.accept"];

# Read-only actions. Everything NOT on this list is treated as a write for the
# purposes of the `feature_readonly` containment control. Defaulting to "this is
# a write" is the fail-safe direction: a new action forgotten here gets blocked
# by read-only mode rather than sailing through it.
glob:pub READ_ACTIONS: list = [
    "tenant.read",
    "project.read",
    "project.list",
    "task.read",
    "task.list",
    "comment.read",
    "comment.list",
    "search.query",
    "export.download",
    "auth.logout",
    "auth.session_expired"
];

# Operations that ALWAYS require a recent password, containment control or not.
# Mandated by contracts/req_ctx_contract.jac (the `session_auth_at_ms` note):
# these four are the ones marked † in contracts/app_api.openapi.yaml, and they
# demand `now_ms - session_auth_at_ms <= 900000` or a REAUTH_REQUIRED denial.
#
# The common thread is that each one is irreversible or exfiltrating: a stolen
# live session should be able to browse, but it should NOT be able to hand
# itself a role, delete a colleague's access, or walk out with the dataset
# without the human at the keyboard proving they are still there.
glob:pub STEPUP_ACTIONS: list = [
    "member.role_change",
    "member.remove",
    "export.request",
    "export.download"
];

# Actions that must still work while a force_reauth control is active --
# otherwise the control locks the user out of the very flow that clears it.
glob:pub REAUTH_ALLOWED_ACTIONS: list = [
    "auth.login",
    "auth.logout",
    "auth.reauth_required",
    "auth.session_expired"
];

"""Rank of a role string. An unknown role ranks BELOW viewer, so a corrupted or
attacker-supplied role value can never satisfy a requirement."""
def:pub rank_of(role: str) -> int {
    return ROLE_RANK.get(role, -1);
}

"""True when `held` satisfies `required`."""
def:pub role_satisfies(held: str, required: str) -> bool {
    if required not in ROLE_RANK {
        # An action with no known requirement is not implicitly public.
        return False;
    }
    return rank_of(held) >= ROLE_RANK[required];
}

"""Minimum role for an action. An unknown action returns "owner" -- the
strictest value -- so a typo or an unlisted action fails closed instead of
falling through to allow."""
def:pub min_role_for(action: str) -> str {
    return ACTION_MIN_ROLE.get(action, "owner");
}

"""True when the action mutates state, for feature_readonly enforcement."""
def:pub is_write_action(action: str) -> bool {
    return action not in READ_ACTIONS;
}

"""True when the action may proceed while force_reauth is pending."""
def:pub survives_reauth(action: str) -> bool {
    return action in REAUTH_ALLOWED_ACTIONS;
}

"""True when the action demands a recent password regardless of any control."""
def:pub requires_stepup(action: str) -> bool {
    return action in STEPUP_ACTIONS;
}

"""Actions in ACTIONS that have no ACTION_MIN_ROLE entry. Must always be empty:
a missing entry means an action nobody assigned a role to."""
def:pub policy_gaps() -> list {
    return [a for a in ACTIONS if a not in ACTION_MIN_ROLE];
}

"""Keys in ACTION_MIN_ROLE that are not real actions -- a typo, or a stale entry
left behind after the vocabulary changed."""
def:pub policy_strays() -> list {
    return [a for a in ACTION_MIN_ROLE.keys() if a not in ACTIONS];
}

"""Entries in STEPUP_ACTIONS that are not real actions.

Must always be empty. Unlike ACTION_MIN_ROLE -- where an unknown action falls
back to "owner" and therefore fails CLOSED -- a typo in STEPUP_ACTIONS fails
OPEN: `requires_stepup("member.role_chnage")` is simply False, the gate never
fires, and the step-up requirement silently evaporates with no error anywhere.
That is the one failure mode this control cannot tolerate, so it is checked at
import time rather than trusted."""
def:pub stepup_strays() -> list {
    return [a for a in STEPUP_ACTIONS if a not in ACTIONS];
}

"""Raise unless the policy table covers exactly the frozen action vocabulary."""
def:pub assert_policy_complete() -> bool {
    gaps = policy_gaps();
    strays = policy_strays();
    if len(gaps) > 0 or len(strays) > 0 {
        raise RuntimeError(
            "FATAL: authorization policy does not match the frozen action "
            + "vocabulary. Unassigned actions: " + str(gaps)
            + " | unknown entries: " + str(strays)
        );
    }
    su_strays = stepup_strays();
    if len(su_strays) > 0 {
        raise RuntimeError(
            "FATAL: STEPUP_ACTIONS names actions outside the frozen "
            + "vocabulary: " + str(su_strays)
            + ". A typo here disables a step-up requirement SILENTLY, so it "
            + "stops the application instead."
        );
    }
    return True;
}

# Import-time enforcement: an action added to the frozen vocabulary without a
# role assignment stops the application rather than defaulting to something.
with entry {
    assert_policy_complete();
}
