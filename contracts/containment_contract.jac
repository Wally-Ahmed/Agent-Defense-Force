# FROZEN CONTRACT — do not edit without conductor approval. Consumed by: T2 guard/authz, T4 monitor/detection, T5 responder/containment, T6 dashboard
#
# IMPORT AS:
#   import from contracts.containment_contract { ContainmentAction, Control, CONTAINMENT_KINDS }
#
# The mandated path `contracts/containment_contract.jac` is a SYMLINK ALIAS to this
# file — a filename containing a dot is not importable in Jac. Always import the
# undotted name.
#
# ContainmentAction is the proposal/audit record for a response action.
# Control is the single enforcement surface actually read by guard() and the
# gateway. Proposing a ContainmentAction changes nothing until a corresponding
# Control row is written and active.
#
# NOTE ON DEFAULTS: every field carries a default. Forced by Jac error[E2004]
# ("non default attribute follows default attribute") — the frozen field order
# puts `schema_version = "1.0.0"` at position 2 and `reversible = True` mid-struct,
# so every field after them must also be defaulted. Field ORDER is exactly as
# specified. Treat defaults as "unset" sentinels.
#
# NOTE ON `dict` / `list`: left deliberately un-parameterized. Jac widens a bare
# `dict` to `dict[Any]`, which is what lets consumers index into scope/params/
# blast_radius and use the result at any type. Parameterizing them (e.g.
# `dict[str, object]`) type-checks here but raises error[E1053] in every consumer
# that reads a value out. The `jac check` W1036 warnings on these fields are
# expected and intentional.

node ContainmentAction {
    has action_id: str = "";
    has schema_version: str = "1.0.0";
    has incident_id: str = "";
    has kind: str = "";                   # one of CONTAINMENT_KINDS
    has scope: dict = {};
    has params: dict = {};
    has blast_radius: dict = {};
    has approval: str = "";               # auto | auto_with_notice | human_required
    has approved_by: str = "";
    has state: str = "";                  # proposed | approved | applying | active | verify_failed | expired | rolled_back | failed
    has ttl_s: int = 0;
    has applied_at: str = "";
    has expires_at: str = "";
    has health_check: str = "";
    has health_status: str = "";          # unknown | pass | fail
    has prior_state: dict = {};
    has reversible: bool = True;
    has reason_codes: list = [];
    has created_by: str = "";             # monitor | responder:<model> | human
}

# The single enforcement surface read by guard() and the gateway.
node Control {
    has control_id: str = "";
    has kind: str = "";
    has scope_key: str = "";
    has params: dict = {};
    has expires_at: str = "";
    has active: bool = False;
}

# The 10 containment action kinds and their policy defaults.
# Keyed by kind; each value is {blast, approval, ttl_s}. ttl_s == 0 means the
# action does not auto-expire (it is permanent until explicitly rolled back).
glob:pub CONTAINMENT_KINDS: dict = {
    "revoke_session": {
        "blast": "narrow", "approval": "auto", "ttl_s": 0
    },
    "revoke_token": {
        "blast": "narrow", "approval": "auto", "ttl_s": 0
    },
    "suspend_principal": {
        "blast": "moderate", "approval": "auto_if_pct_lt_5_else_human", "ttl_s": 1800
    },
    "throttle_source": {
        "blast": "narrow", "approval": "auto", "ttl_s": 900
    },
    "block_source": {
        "blast": "moderate", "approval": "human_required_if_shared", "ttl_s": 900
    },
    "force_reauth": {
        "blast": "moderate", "approval": "auto_principal_human_tenant", "ttl_s": 3600
    },
    "feature_readonly": {
        "blast": "moderate", "approval": "auto", "ttl_s": 900
    },
    "pause_queue": {
        "blast": "moderate", "approval": "auto", "ttl_s": 600
    },
    "rotate_service_credential": {
        "blast": "broad", "approval": "human_required", "ttl_s": 0
    },
    "raise_logging": {
        "blast": "narrow", "approval": "auto", "ttl_s": 3600
    }
};
