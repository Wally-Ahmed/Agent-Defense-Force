"""ReqCtx canonicalization, signing, and verification — the trust boundary.

This module is the single source of truth for the ctx signature on BOTH sides of
the boundary. The gateway calls `sign_ctx()`; `guard()` (track T2) should import
and call `verify_ctx()` from here rather than re-deriving the encoding.

  import from gateway.ctxsig { verify_ctx }

contracts/req_ctx_contract.jac warns that a signer/verifier canonicalization
mismatch FAILS OPEN — the worst possible outcome. Sharing one implementation is
how that class of bug is made impossible rather than merely unlikely.

CANONICALIZATION (contract rule 1): the JSON serialization of every ReqCtx field
EXCEPT `sig`, with sort_keys=True, separators=(',',':'), encoded UTF-8.

VERIFICATION (contract rules 2 and 3): constant-time compare via
hmac.compare_digest, never `==`; missing/failed signature or `issued_at_ms` older
than 30s means the request is FULLY UNAUTHENTICATED and denies with
CTX_UNVERIFIED.
"""

import hmac;
import json;
import hashlib;
import from typing { Any }

# Every ReqCtx field, in the frozen order from contracts/req_ctx_contract.jac.
glob:pub CTX_FIELDS: list = [
    "request_id",
    "src_ip",
    "src_asn",
    "user_agent_hash",
    "client_fp",
    "session_id",
    "token_id",
    "service",
    "route",
    "http_method",
    "csrf_ok",
    "received_at_ms",
    "sig",
    "sig_alg",
    "issued_at_ms"
];

# Everything that goes into the signature: all fields except `sig`.
glob:pub SIGNED_FIELDS: list = [
    "request_id",
    "src_ip",
    "src_asn",
    "user_agent_hash",
    "client_fp",
    "session_id",
    "token_id",
    "service",
    "route",
    "http_method",
    "csrf_ok",
    "received_at_ms",
    "sig_alg",
    "issued_at_ms"
];

glob:pub BOOL_FIELDS: list = ["csrf_ok"];
glob:pub INT_FIELDS: list = ["received_at_ms", "issued_at_ms"];

glob:pub SIG_ALG: str = "HMAC-SHA256";
glob:pub CTX_MAX_AGE_MS: int = 30000;
glob:pub REASON_UNVERIFIED: str = "CTX_UNVERIFIED";

"""Canonical signing input: JSON over every ReqCtx field except `sig`.

sort_keys=True, separators=(',',':'), UTF-8 — byte-identical on both sides.
Raises KeyError if any signed field is absent: `sig` is the only field permitted
to be missing, and a partially-populated ctx must never be signed or accepted."""
def canonical_bytes(ctx: dict) -> bytes {
    payload: dict = {};
    for f in SIGNED_FIELDS {
        if f not in ctx {
            raise KeyError(f"ctx is missing required signed field '{f}'");
        }
        payload[f] = ctx[f];
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8");
}

"""HMAC-SHA256 hex digest over the canonical bytes, keyed by the signing key."""
def sign_ctx(ctx: dict, key: str) -> str {
    return hmac.new(key.encode("utf-8"), canonical_bytes(ctx), hashlib.sha256).hexdigest();
}

"""Return a copy of `ctx` with a fresh `sig`. Any pre-existing `sig` is discarded."""
def signed_ctx(ctx: dict, key: str) -> dict {
    out: dict = {};
    for f in SIGNED_FIELDS {
        out[f] = ctx[f];
    }
    out["sig"] = sign_ctx(out, key);
    return out;
}

"""sha256 over the canonical JSON of the FULL injected ctx (including `sig`).

Carried as the `ctx_hash` claim of the upstream JWT so a walker can prove the ctx
body it received is the one the gateway signed the JWT for."""
def ctx_hash(ctx: dict) -> str {
    ordered: dict = {};
    for f in CTX_FIELDS {
        if f in ctx {
            ordered[f] = ctx[f];
        }
    }
    blob = json.dumps(ordered, sort_keys=True, separators=(",", ":")).encode("utf-8");
    return hashlib.sha256(blob).hexdigest();
}

"""Type discipline over an untrusted ctx dict.

A ctx whose `csrf_ok` is the STRING "true" rather than the boolean True would
canonicalize differently, so types are part of the contract, not a nicety.
Returns "" when the shape is acceptable, else a short machine reason."""
def _shape_error(ctx: Any) -> str {
    if not isinstance(ctx, dict) {
        return "ctx_not_object";
    }
    for k in ctx.keys() {
        if k not in CTX_FIELDS {
            return "unknown_field";
        }
    }
    for f in CTX_FIELDS {
        if f not in ctx {
            return "missing_field";
        }
    }
    for f in BOOL_FIELDS {
        if not isinstance(ctx[f], bool) {
            return "bad_type";
        }
    }
    for f in INT_FIELDS {
        v = ctx[f];
        if isinstance(v, bool) or not isinstance(v, int) {
            return "bad_type";
        }
    }
    for f in CTX_FIELDS {
        if f in BOOL_FIELDS or f in INT_FIELDS {
            continue;
        }
        if not isinstance(ctx[f], str) {
            return "bad_type";
        }
    }
    return "";
}

"""Verify an untrusted ctx payload. THE function guard() must call first.

Returns {"ok": bool, "reason": str, "detail": str}. `reason` is "" on success and
CTX_UNVERIFIED on every failure — a forged, replayed, unsigned, mistyped, or
stale ctx are all the same thing to a caller: fully unauthenticated.

`detail` is a short machine token for local logging only. Per contracts/vocab.md
the emitted audit event must carry actor_principal_id "" and only OBSERVED
transport facts — never the claimed src_ip/session_id/csrf_ok from this payload.

NO FIELD OF `ctx` MAY BE TRUSTED UNTIL THIS RETURNS ok=True."""
def verify_ctx(ctx: Any, key: str, now_ms: int, max_age_ms: int = 0) -> dict {
    window = max_age_ms;
    if window <= 0 {
        window = CTX_MAX_AGE_MS;
    }

    shape = _shape_error(ctx);
    if shape {
        return {"ok": False, "reason": REASON_UNVERIFIED, "detail": shape};
    }

    # Algorithm agility without algorithm confusion: exactly one alg is accepted.
    if ctx["sig_alg"] != SIG_ALG {
        return {"ok": False, "reason": REASON_UNVERIFIED, "detail": "bad_alg"};
    }

    claimed = ctx["sig"];
    if not claimed {
        return {"ok": False, "reason": REASON_UNVERIFIED, "detail": "unsigned"};
    }

    expected = sign_ctx(ctx, key);
    # Constant-time. NEVER `==` (contract rule 2).
    if not hmac.compare_digest(str(claimed), expected) {
        return {"ok": False, "reason": REASON_UNVERIFIED, "detail": "bad_sig"};
    }

    issued = ctx["issued_at_ms"];
    age = now_ms - issued;
    if age > window {
        return {"ok": False, "reason": REASON_UNVERIFIED, "detail": "stale"};
    }
    # A context stamped in the future is as suspect as a stale one. One second of
    # slack absorbs ordinary clock skew between the gateway and the upstream.
    if age < -1000 {
        return {"ok": False, "reason": REASON_UNVERIFIED, "detail": "future"};
    }

    return {"ok": True, "reason": "", "detail": ""};
}
