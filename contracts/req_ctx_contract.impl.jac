# Implementation of the frozen `guard()` declaration in req_ctx_contract.jac.
#
# Jac binds `X.impl.jac` to module `X.jac` automatically, so this sidecar is the
# only place a body for `guard` actually takes effect -- an `impl guard` block
# written in some other module type-checks but never binds, and callers silently
# get the unimplemented declaration.
#
# This file is an ADAPTER and nothing else. All authorization reasoning lives in
# app/security/authz.jac; keeping it there means the frozen contract module
# carries no application imports and there is no import cycle between the
# contract and the code that implements it. It also means the audit emission,
# the resolution, and the decision cannot be separated -- `authorize()` performs
# all three or none.
#
# The `ReqCtx` -> dict conversion is written out field by field on purpose.
# Reflecting over the object (`__dict__`) would silently start forwarding any
# field a future edit adds, including one an attacker controls; an explicit list
# means a new ReqCtx field is inert until someone deliberately adds it here AND
# to ctxsig.SIGNED_FIELDS.

import from app.security.authz { authorize }

impl guard {
    payload: dict = {
        "request_id": ctx.request_id,
        "src_ip": ctx.src_ip,
        "src_asn": ctx.src_asn,
        "user_agent_hash": ctx.user_agent_hash,
        "client_fp": ctx.client_fp,
        "session_id": ctx.session_id,
        "token_id": ctx.token_id,
        "service": ctx.service,
        "route": ctx.route,
        "http_method": ctx.http_method,
        "csrf_ok": ctx.csrf_ok,
        "received_at_ms": ctx.received_at_ms,
        "sig": ctx.sig,
        "sig_alg": ctx.sig_alg,
        "issued_at_ms": ctx.issued_at_ms,
        # Step-up freshness. Forwarded deliberately, per the note above: it is
        # a SIGNED field, so omitting it here would not merely disable the
        # step-up check -- it would break verification outright, because the
        # verifier reconstructs the canonical bytes from this dict.
        "session_auth_at_ms": ctx.session_auth_at_ms
    };

    decision = authorize(payload, action, target_kind, tenant_id, target_id);

    return Grant(
        ok=decision["ok"],
        reason=decision["reason"],
        tenant=decision["tenant"],
        principal=decision["principal"],
        membership=decision["membership"],
        node=decision["node"]
    );
}
