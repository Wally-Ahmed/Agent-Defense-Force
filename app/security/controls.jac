# app/security/controls.jac — reading the containment enforcement surface.
#
# `Control` (contracts/containment_contract.jac) is the ONLY thing guard() reads
# to learn that the responder has taken action. Proposing a ContainmentAction
# changes nothing; writing an active Control changes everything. This module is
# the read side of that surface -- it never writes one. T5 owns writes.
#
# Scope keys are strings so a control can name a subject without the responder
# needing a handle to a graph node:
#
#     principal:<principal_id>      suspend_principal, force_reauth
#     tenant:<tenant_id>            force_reauth, feature_readonly
#     session:<session_id>          revoke_session
#     token:<jti>                   revoke_token
#     ip:<src_ip>                   block_source, throttle_source
#     asn:<src_asn>                 block_source, throttle_source
#     feature:<name>                feature_readonly (platform-wide)
#
# An EXPIRED control is dead. An INACTIVE control is dead. A control with an
# unparseable expires_at is treated as expired -- a corrupt control must not be
# able to become a permanent lockout nobody can find.

import from contracts.containment_contract { Control }
import from app.model.graph { Control as _GraphControl, all_controls }
import from app.security.clock { now_ms, iso_to_ms }

"""True when a control is currently in force.

`active` must be set AND the expiry must not have passed. `expires_at == ""`
means no TTL (permanent until rolled back), which the frozen CONTAINMENT_KINDS
table expresses as ttl_s == 0."""
def:pub is_live(control: Control, at_ms: int) -> bool {
    if not control.active {
        return False;
    }
    if control.expires_at == "" {
        return True;
    }
    # on_error = -1 sorts before any real timestamp, so an unparseable expiry
    # reads as long-expired rather than as never-expiring.
    expiry = iso_to_ms(control.expires_at, -1);
    return expiry > at_ms;
}

"""Every live control right now."""
def:pub live_controls(at_ms: int) -> list[Control] {
    return [c for c in all_controls() if is_live(c, at_ms)];
}

"""The first live control of `kind` whose scope_key is one of `keys`, or None.

Matching on an explicit key list rather than a prefix means a control scoped to
`principal:alice` can never be made to match `principal:alice-evil` by a
substring accident."""
def:pub find_control(kind: str, keys: list, at_ms: int) -> Control | None {
    for c in live_controls(at_ms) {
        if c.kind == kind and c.scope_key in keys {
            return c;
        }
    }
    return None;
}

"""True when any live control of `kind` names one of `keys`."""
def:pub has_control(kind: str, keys: list, at_ms: int) -> bool {
    return find_control(kind, keys, at_ms) is not None;
}

# --------------------------------------------------------------------------
# Scope-key builders. Centralised so the responder (T5) and guard (T2) cannot
# drift on the string format -- a mismatch there would silently disarm a
# containment action while every log line claims it is active.
# --------------------------------------------------------------------------

def:pub key_principal(principal_id: str) -> str { return "principal:" + principal_id; }
def:pub key_tenant(tenant_id: str) -> str       { return "tenant:" + tenant_id; }
def:pub key_session(session_id: str) -> str     { return "session:" + session_id; }
def:pub key_token(jti: str) -> str              { return "token:" + jti; }
def:pub key_ip(src_ip: str) -> str              { return "ip:" + src_ip; }
def:pub key_asn(src_asn: str) -> str            { return "asn:" + src_asn; }
def:pub key_feature(name: str) -> str           { return "feature:" + name; }

"""Every scope key that could name this request's source."""
def:pub source_keys(src_ip: str, src_asn: str) -> list {
    keys: list = [];
    if src_ip != "" {
        keys.append(key_ip(src_ip));
    }
    if src_asn != "" {
        keys.append(key_asn(src_asn));
    }
    return keys;
}

"""Every scope key that could put this request's feature surface in read-only.

A control may name the whole platform (`feature:*`), one tenant, or one
tenant-plus-family (`tenant:<id>:project`), so all three are checked."""
def:pub readonly_keys(tenant_id: str, action: str) -> list {
    family = action.split(".")[0];
    keys: list = [key_feature("*"), key_feature(family)];
    if tenant_id != "" {
        keys.append(key_tenant(tenant_id));
        keys.append(key_tenant(tenant_id) + ":" + family);
    }
    return keys;
}
