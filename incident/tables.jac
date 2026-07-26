# incident/tables.jac — CLOSED ENUM LOOKUP TABLES
#
# Every table here maps a value drawn from a CLOSED vocabulary (contracts/audit_event_contract.jac
# ACTIONS / DENY_REASONS, or a fixed enum such as target_sensitivity) to a small integer rank.
#
# INVARIANT (enforced by assert_tables_complete(), called at projection time):
#   No table is ever keyed by free text. Lookups are total over the closed vocabulary; an
#   unknown key returns a conservative default, it NEVER falls through to string inspection.

import from contracts.audit_event_contract { ACTIONS, DENY_REASONS }

# --- required-role rank -------------------------------------------------------------------
# The minimum role an action requires. Ordinal, monotone: none < viewer < member < admin < owner.
# This is the "required-role" axis of the escalation scorer.
glob:pub ROLE_RANK: dict = {
    "auth.register": 0, "auth.login": 0, "auth.login_failed": 0, "auth.logout": 0,
    "auth.session_expired": 0, "auth.token_issued": 0, "auth.token_revoked": 0,
    "auth.reauth_required": 0,
    "tenant.read": 1, "project.read": 1, "project.list": 1, "task.read": 1, "task.list": 1,
    "comment.read": 1, "comment.list": 1, "search.query": 1,
    "member.accept": 2, "task.create": 2, "task.update": 2, "task.delete": 2, "task.assign": 2,
    "comment.create": 2, "comment.delete": 2, "export.request": 2, "export.download": 2,
    "integration.call": 2,
    "project.create": 3, "project.update": 3, "project.delete": 3,
    "member.invite": 3, "member.role_change": 3, "member.remove": 3,
    "containment.propose": 3, "containment.apply": 3, "containment.verify": 3,
    "containment.expire": 3, "containment.rollback": 3,
    "tenant.create": 4
};

# --- target sensitivity rank --------------------------------------------------------------
glob:pub SENS_RANK: dict = {"": 0, "normal": 0, "confidential": 1, "canary": 2};

# --- actor role rank (granted role, distinct from required role) ---------------------------
glob:pub ACTOR_ROLE_RANK: dict = {"": 0, "none": 0, "viewer": 1, "member": 2, "admin": 3, "owner": 4};

# --- deny reason classes ------------------------------------------------------------------
# Authorization-boundary denials: the reasons an actor gets when probing what it may touch.
glob:pub AUTHZ_DENY: list = ["INSUFFICIENT_ROLE", "NOT_A_MEMBER", "TENANT_MISMATCH", "SUSPENDED",
                             "SOURCE_BLOCKED", "READONLY_MODE"];
# Session/credential denials.
glob:pub AUTHN_DENY: list = ["NO_SESSION", "SESSION_EXPIRED", "TOKEN_REVOKED", "REAUTH_REQUIRED",
                             "CSRF_INVALID", "CTX_UNVERIFIED"];

# --- action classes (enum-only, used for stage signatures) --------------------------------
glob:pub LIST_ACTIONS: list = ["project.list", "task.list", "comment.list", "search.query"];
glob:pub AUTH_FAIL_ACTIONS: list = ["auth.login_failed"];
glob:pub SEVERITY_RANK: dict = {"": 0, "info": 0, "notice": 1, "warn": 2, "high": 3};

# --- axes ---------------------------------------------------------------------------------
# The behavioural axis each detection family measures. Two families on the same axis are
# NOT independent evidence, which is what the "spanning >= 2 distinct axes" gate clause means.
glob:pub FAMILY_AXIS: dict = {
    "denial_shape": "identity",
    "breadth": "asset",
    "novelty": "asset",
    "cadence": "time",
    "pivot": "source",
    "escalation": "identity",
    "canary": "asset"
};

glob:pub FAMILIES: list = ["denial_shape", "breadth", "novelty", "cadence", "pivot",
                           "escalation", "canary"];

# The gate's mandatory-member set. At least one of these must fire or nothing is promoted.
# These are the three families a high-volume-but-legitimate workload structurally cannot produce:
# denial_shape needs denials, escalation needs post-denial climb, pivot needs identity/source
# multiplexing.
glob:pub MANDATORY_FAMILIES: list = ["denial_shape", "pivot", "escalation"];


def role_rank(action: str) -> int {
    # Total over ACTIONS. Unknown action -> 0 (conservative: contributes no escalation).
    return ROLE_RANK.get(action, 0);
}

def sens_rank(sensitivity: str) -> int {
    return SENS_RANK.get(sensitivity, 0);
}

def is_authz_deny(reason: str) -> bool {
    return reason in AUTHZ_DENY;
}

def assert_tables_complete() -> bool {
    # Fails loudly if the frozen contract vocabulary drifts past these tables.
    missing = [];
    for a in ACTIONS {
        if a not in ROLE_RANK {
            missing.append(a);
        }
    }
    if len(missing) > 0 {
        raise ValueError("ROLE_RANK missing actions: " + ",".join(sorted(missing)));
    }
    unknown = [];
    for r in (AUTHZ_DENY + AUTHN_DENY) {
        if r not in DENY_REASONS {
            unknown.append(r);
        }
    }
    if len(unknown) > 0 {
        raise ValueError("deny-reason classes not in DENY_REASONS: " + ",".join(sorted(unknown)));
    }
    return True;
}
