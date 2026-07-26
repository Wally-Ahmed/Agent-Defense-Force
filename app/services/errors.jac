# app/services/errors.jac -- the one place a domain walker turns a deny reason
# into a response body.
#
# Domain walkers emit NO audit event (contracts/vocab.md: "every guard() call
# emits exactly one AuditEvent. Not zero, not two"). guard() has already written
# the record by the time control reaches here; this module only shapes the
# payload the gateway hands back to the client.
#
# The message strings are deliberately generic and identical across causes. A
# 404 for "a project in another tenant" is byte-identical to a 404 for "a
# project id that never existed", because the traversal that produced them could
# not tell the two apart either -- see app/services/scope.jac.

import from contracts.audit_event_contract { DENY_REASONS }

# Deny code -> HTTP status. Exactly the table in contracts/app_api.md.
glob:pub STATUS_FOR: dict = {
    "NO_SESSION": 401,
    "SESSION_EXPIRED": 401,
    "TOKEN_REVOKED": 401,
    "REAUTH_REQUIRED": 401,
    "CTX_UNVERIFIED": 401,
    "NOT_A_MEMBER": 403,
    "INSUFFICIENT_ROLE": 403,
    "TENANT_MISMATCH": 403,
    "CSRF_INVALID": 403,
    "SUSPENDED": 403,
    "SOURCE_BLOCKED": 403,
    "NOT_FOUND": 404,
    "VALIDATION_FAILED": 422,
    "READONLY_MODE": 423,
    "RATE_LIMITED": 429
};

# One generic sentence per code. No code, id, or role is interpolated into any
# of these: the message must not become an oracle the caller can read.
glob:pub MESSAGE_FOR: dict = {
    "NO_SESSION": "Authentication required.",
    "SESSION_EXPIRED": "Session expired.",
    "TOKEN_REVOKED": "Credential revoked.",
    "REAUTH_REQUIRED": "Recent authentication required.",
    "CTX_UNVERIFIED": "Authentication required.",
    "NOT_A_MEMBER": "Forbidden.",
    "INSUFFICIENT_ROLE": "Forbidden.",
    "TENANT_MISMATCH": "Forbidden.",
    "CSRF_INVALID": "Forbidden.",
    "SUSPENDED": "Forbidden.",
    "SOURCE_BLOCKED": "Forbidden.",
    "NOT_FOUND": "Not found.",
    "VALIDATION_FAILED": "Request failed validation.",
    "READONLY_MODE": "This feature is read-only.",
    "RATE_LIMITED": "Too many requests."
};

"""HTTP status for a deny code. Unknown codes are 403, never 200."""
def:pub status_for(code: str) -> int {
    return STATUS_FOR.get(code, 403);
}

"""The error envelope for a deny.

`details` is populated only for VALIDATION_FAILED -- the contract permits field
level feedback there and nowhere else, because everywhere else it would leak
the existence of the thing being denied."""
def:pub deny(code: str, request_id: str = "", details: (list | None) = None) -> dict {
    safe = code if code in DENY_REASONS else "NOT_FOUND";
    body: dict = {
        "code": safe,
        "message": MESSAGE_FOR.get(safe, "Forbidden."),
        "request_id": request_id
    };
    if safe == "VALIDATION_FAILED" and details {
        body["details"] = details;
    }
    return {"ok": False, "status": status_for(safe), "error": body};
}

"""A success envelope. `status` is the per-operation OK code from the contract.

The payload is nested under `data` rather than merged into the envelope so that
a resource field named `status` (a Project has one) can never be mistaken for
the HTTP status, in either direction."""
def:pub ok(payload: dict, status: int = 200) -> dict {
    return {"ok": True, "status": status, "data": payload};
}
