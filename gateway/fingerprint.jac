"""Transport-fact observation: client fingerprints, request ids, and redaction.

These are the facts a Jac walker structurally cannot see — jac_scale consumes the
HTTP request at the boundary and forwards only walker kwargs (serve.endpoints.
impl.jac:93-126). The gateway observes them here and hands them inward inside the
signed ReqCtx.

Everything in this module is derived from OBSERVED transport data. Nothing here
ever reads a claimed value out of a request body.
"""

import uuid;
import hashlib;
import from typing { Any }

# Header names we will never echo into a log line.
glob:pub SENSITIVE_HEADERS: list = [
    "authorization",
    "cookie",
    "set-cookie",
    "x-csrf-token",
    "proxy-authorization",
    "x-api-key"
];

glob:pub SENSITIVE_BODY_KEYS: list = [
    "password",
    "new_password",
    "old_password",
    "current_password",
    "token",
    "api_token",
    "secret",
    "csrf",
    "csrf_token",
    "authorization",
    "cookie",
    "private_key",
    "client_secret"
];

glob:pub REDACTED: str = "[redacted]";

"""sha256(ua)[:16] — the user-agent fingerprint carried on every audit event."""
def ua_hash(user_agent: str) -> str {
    return hashlib.sha256(user_agent.encode("utf-8")).hexdigest()[:16];
}

"""sha256(ua|accept-language|accept-encoding)[:16].

The audit contract's comment mentions a `tls_ja3` component; the gateway
terminates plain HTTP behind a TLS terminator and never observes a JA3, so the
three headers it does observe are the whole input. Recorded here so the omission
is a documented decision rather than a silent gap."""
def client_fp(user_agent: str, accept_language: str, accept_encoding: str) -> str {
    blob = f"{user_agent}|{accept_language}|{accept_encoding}";
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:16];
}

"""A fresh request id. 16 hex chars, matching the golden fixture's shape."""
def new_request_id -> str {
    return uuid.uuid4().hex[:16];
}

"""A fresh trace id. 32 hex chars, matching the golden fixture's shape."""
def new_trace_id -> str {
    return uuid.uuid4().hex;
}

"""The observed peer address.

`X-Forwarded-For` is honoured ONLY when the immediate peer is in
`trusted_proxies`; otherwise the transport-level peer wins. An untrusted client
must never be able to choose its own `src_ip` and thereby launder its way past a
source-keyed rate limit or a containment control."""
def observed_ip(peer: str, forwarded_for: str, trusted_proxies: list) -> str {
    if not peer {
        return "";
    }
    if forwarded_for and peer in trusted_proxies {
        first = forwarded_for.split(",")[0].strip();
        if first {
            return first;
        }
    }
    return peer;
}

"""Stable, non-reversing hash of an email for throttle keys and log lines.

The plaintext address never reaches a rate-limiter key or a log line."""
def email_hash(email: str) -> str {
    return hashlib.sha256(email.strip().lower().encode("utf-8")).hexdigest()[:16];
}

"""Header map with every credential-bearing value replaced. Log this, not the raw map."""
def redact_headers(headers: dict) -> dict {
    out: dict = {};
    for k in headers.keys() {
        if k.lower() in SENSITIVE_HEADERS {
            out[k] = REDACTED;
        } else {
            out[k] = headers[k];
        }
    }
    return out;
}

"""Body with every credential-bearing value replaced, recursively."""
def redact_body(body: Any) -> Any {
    if isinstance(body, dict) {
        out: dict = {};
        for k in body.keys() {
            if str(k).lower() in SENSITIVE_BODY_KEYS {
                out[k] = REDACTED;
            } else {
                out[k] = redact_body(body[k]);
            }
        }
        return out;
    }
    if isinstance(body, list) {
        return [redact_body(item) for item in body];
    }
    return body;
}

"""Last 6 characters of an opaque id, for correlating logs without leaking the id."""
def tail(value: str, keep: int = 6) -> str {
    if not value {
        return "";
    }
    if len(value) <= keep {
        return REDACTED;
    }
    return f"...{value[-keep:]}";
}
