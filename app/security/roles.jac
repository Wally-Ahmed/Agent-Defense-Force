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
# it skips only the membership and role steps. Keeping this list short is the
# point -- every addition widens the unauthenticated-ish surface.
#
# Membership of this list is NOT on its own enough to skip those steps. guard()
# additionally requires `tenant_id == ""` -- see the tenantless block in
# app/security/authz.jac. That second condition is what makes this list safe to
# extend: `tenant.read` is the audit action for BOTH `GET /tenants` (no tenant in
# the path) and `GET /tenants/{tenant_id}` (one very much in the path), and only
# the first may skip the tenancy checks. Without the tenant_id condition, adding
# `tenant.read` here would have let a Globex session read the Acme tenant record
# and the whole member roster with it.
#
#   tenant.create -- POST /tenants. There is no tenant yet to be a member of.
#   tenant.read   -- GET /tenants (ListMyTenants) ONLY, by the tenant_id == ""
#                    condition above. A freshly-logged-in principal has no tenant
#                    scope yet, and this endpoint is how they discover which
#                    tenants they belong to. The walker resolves nothing by id:
#                    tenants_for(principal_id) projects the caller's OWN active
#                    memberships, so a tenant they have no membership edge to
#                    never appears in the result.
glob:pub TENANTLESS_ACTIONS: list = ["tenant.create", "tenant.read"];

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

# Operations that require a recent password, containment control or not.
# Mandated by contracts/req_ctx_contract.jac (the `session_auth_at_ms` note):
# these are the five marked `x-step-up-required: true` in
# contracts/app_api.openapi.yaml, and they demand
# `now_ms - session_auth_at_ms <= 900000` or a REAUTH_REQUIRED denial.
#
# The common thread is that each one is irreversible or exfiltrating: a stolen
# live session should be able to browse, but it should NOT be able to hand
# itself a role, delete a colleague's access, or walk out with the dataset
# without the human at the keyboard proving they are still there.
#
# WHICH PRINCIPALS a requirement binds is part of the requirement, so it is a
# column in this table rather than a condition somewhere in a walker:
#
#   STEPUP_ALL          -- every principal. An API token can never present a
#                          password, so for these it is an outright refusal:
#                          there is no legitimate service-account path to an
#                          export or a role change at all.
#   STEPUP_USER_SESSION -- user-session principals ONLY. The contract's
#                          x-required-role for integration.call reads
#                          "service account: member + scope integration:call;
#                          user session: admin + step-up" -- two distinct
#                          principals with two distinct requirements. A service
#                          account has no interactive session to re-authenticate,
#                          so it is authorized by token scope + membership (the
#                          scope narrowing in authz.jac), and demanding step-up
#                          of it would deny every legitimate integration call.
glob:pub STEPUP_ALL: str = "all";
glob:pub STEPUP_USER_SESSION: str = "user_session";

glob:pub STEPUP_ACTIONS: dict = {
    "member.role_change": STEPUP_ALL,
    "member.remove": STEPUP_ALL,
    "export.request": STEPUP_ALL,
    "export.download": STEPUP_ALL,
    "integration.call": STEPUP_USER_SESSION
};

# The ONLY auth methods a STEPUP_USER_SESSION requirement does not bind: the
# non-interactive ones, where there is no human at a keyboard to re-authenticate.
#
# The test is deliberately written as membership of THIS list rather than as
# "is it a user session", because the two are not the same under an unexpected
# value. An empty, missing, unknown or misspelled auth_method is not on this
# list and therefore steps up -- the fail-CLOSED direction. Were the check
# inverted ("step up only if auth_method is session-ish"), any value the app did
# not recognise would buy a silent exemption.
glob:pub NON_INTERACTIVE_AUTH_METHODS: list = ["api_token"];

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

"""True when the action demands a recent password regardless of any control.

`auth_method` is the method the caller was ACTUALLY authenticated by, as
determined by authz.guard() from the credential it verified -- never a value the
client supplied. It defaults to "session", the strict reading: a caller that
does not say how it authenticated gets the user-session requirement, not the
service-account carve-out.

The carve-out is narrow by construction. It applies only to actions the table
marks STEPUP_USER_SESSION, and only to the auth methods in
NON_INTERACTIVE_AUTH_METHODS. Every other combination -- including an unknown
scope value and an unknown auth_method -- returns True and steps up."""
def:pub requires_stepup(action: str, auth_method: str = "session") -> bool {
    scope = STEPUP_ACTIONS.get(action, "");
    if scope == "" {
        return False;
    }
    if scope == STEPUP_USER_SESSION and auth_method in NON_INTERACTIVE_AUTH_METHODS {
        return False;
    }
    return True;
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
    return [a for a in STEPUP_ACTIONS.keys() if a not in ACTIONS];
}

"""Entries in STEPUP_ACTIONS whose scope column is not one of the two known
scopes -- checked at import time for the same reason as stepup_strays().

A bad scope value does not fail open (requires_stepup() returns True for
anything it does not recognise), but it silently converts a user-session-only
requirement into an all-principals one, which would deny every service-account
integration call in production. Loud at import beats mysterious at runtime."""
def:pub stepup_scope_strays() -> list {
    known = [STEPUP_ALL, STEPUP_USER_SESSION];
    return [a for a in STEPUP_ACTIONS.keys() if STEPUP_ACTIONS[a] not in known];
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
    scope_strays = stepup_scope_strays();
    if len(scope_strays) > 0 {
        raise RuntimeError(
            "FATAL: STEPUP_ACTIONS gives an unknown scope to: "
            + str(scope_strays)
            + ". The scope column must be STEPUP_ALL or STEPUP_USER_SESSION."
        );
    }
    return True;
}

# Import-time enforcement: an action added to the frozen vocabulary without a
# role assignment stops the application rather than defaulting to something.
with entry {
    assert_policy_complete();
}
