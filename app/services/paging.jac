# app/services/paging.jac -- limit + opaque cursor for every list endpoint.
#
# The attacker in this scenario enumerates WITHIN the rules, so the rules have to
# hold rather than merely exist:
#
#   * `limit` has a hard ceiling of 100 and is REJECTED, not clamped. Clamping
#     turns a policy violation into a silent success and erases the signal that
#     someone asked for 10000 rows.
#   * `cursor` is opaque and HMAC-signed, BOUND to (tenant_id, endpoint,
#     filter_key). A cursor minted while listing tenant A's projects is not a
#     valid cursor for tenant B, for a different endpoint, or for a different
#     filter set -- so a cursor can never be used to step sideways out of the
#     scope it was issued in.
#   * Cursors expire after 900 s, so a captured cursor is not a durable handle.
#
# The cursor key is DERIVED from APP_CTX_SIGNING_KEY by HMAC domain separation
# rather than read from a second environment variable: one secret to provision,
# one secret to rotate, and no path where the cursor key is accidentally the
# ctx key itself.

import json;
import hmac;
import hashlib;
import base64;
import from app.security.keys { ctx_signing_key }

# Contract: default 25, max 100, rejected not clamped.
glob:pub DEFAULT_LIMIT: int = 25;
glob:pub MAX_LIMIT: int = 100;

# Cursor time-to-live.
glob:pub CURSOR_TTL_MS: int = 900000;

# Domain separator. Changing this string invalidates every outstanding cursor,
# which is the intended way to revoke them all at once.
glob:pub CURSOR_KEY_INFO: bytes = "northwind/cursor/v1".encode("utf-8");

# Truncated tag length in hex chars. 32 hex = 128 bits, ample for a 900 s token.
glob:pub TAG_HEX: int = 32;

"""The cursor-signing key, derived from the ctx signing key.

Derivation is one HMAC with a fixed info string, so the cursor key is a
one-way function of the ctx key: recovering the ctx key from a leaked cursor
key is not possible, and the two can never collide."""
def _cursor_key() -> bytes {
    return hmac.new(ctx_signing_key(), CURSOR_KEY_INFO, hashlib.sha256).digest();
}

"""base64url without padding -- safe in a query string, no escaping needed."""
def _b64e(raw: bytes) -> str {
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=");
}

"""Inverse of _b64e. Returns b"" on anything malformed rather than raising."""
def _b64d(text: str) -> bytes {
    pad = "=" * ((4 - (len(text) % 4)) % 4);
    try {
        return base64.urlsafe_b64decode(text + pad);
    } except Exception {
        return "".encode("utf-8");
    }
}

"""Resolve the requested page size.

`limit` of 0 means "unspecified" and yields the default. Anything above
MAX_LIMIT returns -1, which the caller turns into VALIDATION_FAILED. Nothing is
clamped: an over-large request is a rejected request."""
def:pub resolve_limit(limit: int) -> int {
    if isinstance(limit, bool) or not isinstance(limit, int) {
        return -1;
    }
    if limit == 0 {
        return DEFAULT_LIMIT;
    }
    if limit < 1 or limit > MAX_LIMIT {
        return -1;
    }
    return limit;
}

"""A stable key for the filter set a cursor was issued under.

Any filter the endpoint honours must appear here. A cursor is only valid for
the identical filter set, so adding a filter without adding it to this dict
would let a caller change the filter mid-pagination and skip the predicate."""
def:pub filter_key(filters: dict) -> str {
    canon = json.dumps(filters, sort_keys=True, separators=(",", ":"));
    return hashlib.sha256(canon.encode("utf-8")).hexdigest()[:16];
}

"""Mint an opaque cursor for `offset`, bound to tenant + endpoint + filters."""
def:pub encode_cursor(
    tenant_id: str, endpoint: str, fkey: str, offset: int, now_ms: int
) -> str {
    payload: dict = {
        "t": tenant_id,
        "e": endpoint,
        "f": fkey,
        "o": offset,
        "x": now_ms + CURSOR_TTL_MS
    };
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8");
    tag = hmac.new(_cursor_key(), raw, hashlib.sha256).hexdigest()[:TAG_HEX];
    return _b64e(raw) + "." + tag;
}

"""Validate a cursor and return its offset, or -1 if it is not usable.

-1 covers every failure identically -- malformed, bad signature, expired, or
issued for a different tenant / endpoint / filter set. The caller reports
VALIDATION_FAILED and learns nothing about which it was.

The tag is compared with hmac.compare_digest, never `==`."""
def:pub decode_cursor(
    cursor: str, tenant_id: str, endpoint: str, fkey: str, now_ms: int
) -> int {
    if not isinstance(cursor, str) or cursor == "" or len(cursor) > 512 {
        return -1;
    }
    parts = cursor.split(".");
    if len(parts) != 2 {
        return -1;
    }
    raw = _b64d(parts[0]);
    if len(raw) == 0 {
        return -1;
    }
    want = hmac.new(_cursor_key(), raw, hashlib.sha256).hexdigest()[:TAG_HEX];
    if not hmac.compare_digest(want, parts[1]) {
        return -1;
    }
    try {
        payload = json.loads(raw.decode("utf-8"));
    } except Exception {
        return -1;
    }
    if not isinstance(payload, dict) {
        return -1;
    }
    if payload.get("t", None) != tenant_id {
        return -1;
    }
    if payload.get("e", None) != endpoint {
        return -1;
    }
    if payload.get("f", None) != fkey {
        return -1;
    }
    expiry = payload.get("x", 0);
    if not isinstance(expiry, int) or now_ms > expiry {
        return -1;
    }
    offset = payload.get("o", -1);
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0 {
        return -1;
    }
    return offset;
}

"""Slice one page out of an already-filtered, already-sorted list.

`items` must be the post-authorization list: pagination never sees a record the
caller could not reach, so `next_cursor` can never step onto one either.
Returns {"items": [...], "next_cursor": str, "total_returned": int}."""
def:pub page(
    items: list,
    limit: int,
    offset: int,
    tenant_id: str,
    endpoint: str,
    fkey: str,
    now_ms: int
) -> dict {
    window = items[offset:(offset + limit)];
    nxt = "";
    if (offset + limit) < len(items) {
        nxt = encode_cursor(tenant_id, endpoint, fkey, offset + limit, now_ms);
    }
    return {"items": window, "next_cursor": nxt, "total_returned": len(window)};
}
