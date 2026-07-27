"""Session store, cookie handling, CSRF double-submit, and upstream JWT minting.

The session cookie is `__Host-sid`: HttpOnly, Secure, SameSite=Lax, Path=/, no
Domain attribute (the `__Host-` prefix makes those first three mandatory and is
why a subdomain cannot overwrite it). Its value is an opaque id plus a keyed tag,
so a guessed or tampered cookie is rejected before the store is ever consulted.

CSRF is double-submit: a non-HttpOnly `__Host-csrf` cookie plus an `X-CSRF-Token`
header, compared in constant time, with the token value itself HMAC-bound to the
session id so a token minted for one session cannot be replayed into another.

The store is process-local by design — no session material is written to disk.
Restarting the gateway invalidates every session, which is the correct failure
direction.
"""

import time;
import uuid;
import hmac;
import hashlib;
import secrets;
import from threading { Lock }
import jwt;
import from typing { Any }
import from config {
    SID_COOKIE, CSRF_COOKIE, SID_COOKIE_ATTRS, CSRF_COOKIE_ATTRS,
    SESSION_IDLE_S, SESSION_ABSOLUTE_S, JWT_ISS, JWT_AUD, JWT_TTL_S
}
import from ctxsig { ctx_hash }

glob SESSION_LOCK: Lock = Lock();

glob:pub ANON_BINDING: str = "anon";

"""Keyed tag over an opaque id, truncated to 32 hex characters."""
def _tag(secret: str, value: str) -> str {
    return hmac.new(secret.encode("utf-8"), value.encode("utf-8"), hashlib.sha256).hexdigest()[:32];
}

"""Stable, non-reversible handle for an API bearer token.

    token_handle(secret) == "tok_" + sha256(secret).hexdigest()[:16]

This is the ONLY derivation of a token identity in the system, and both sides of
the trust boundary must compute it identically: the gateway stamps the handle
into the signed ctx as `token_id`, the app looks a token record up by the same
handle. An unkeyed sha256 (not the HMAC `_tag` above) is deliberate — a keyed tag
would need the gateway's session secret to travel to the app.

The handle is the ONLY thing derived from the token that is allowed to leave this
function's caller: the raw secret is never forwarded upstream, never logged, and
never written to the audit sink."""
def token_handle(secret: str) -> str {
    return "tok_" + hashlib.sha256(secret.encode("utf-8")).hexdigest()[:16];
}

"""Render a Set-Cookie header value. `max_age` of 0 clears the cookie."""
def set_cookie_value(name: str, value: str, attrs: str, max_age: int) -> str {
    return f"{name}={value}; {attrs}; Max-Age={max_age}";
}

"""Clear a cookie: empty value, Max-Age=0, same attributes."""
def clear_cookie_value(name: str, attrs: str) -> str {
    return f"{name}=; {attrs}; Max-Age=0";
}

# ---------------------------------------------------------------------------
# CSRF
# ---------------------------------------------------------------------------

"""Mint a CSRF token bound to `binding` (a session id, or ANON_BINDING).

Shape is `<nonce>.<tag>`: the nonce keeps every token unique so one leak does not
grant a permanent credential, and the tag binds it to the session so a token
minted before login is not accepted after it."""
def mint_csrf(secret: str, binding: str) -> str {
    nonce = secrets.token_urlsafe(24);
    return f"{nonce}.{_tag(secret, binding + '|' + nonce)}";
}

"""Constant-time validation of a double-submitted CSRF token.

Requires all three: a cookie value, a header value, that they are equal, and that
the token's tag verifies against `binding`. Every comparison uses
hmac.compare_digest."""
def csrf_valid(secret: str, binding: str, cookie_val: str, header_val: str) -> bool {
    if not cookie_val or not header_val {
        return False;
    }
    if not hmac.compare_digest(cookie_val, header_val) {
        return False;
    }
    if "." not in cookie_val {
        return False;
    }
    parts = cookie_val.rsplit(".", 1);
    nonce = parts[0];
    tag = parts[1];
    if not nonce or not tag {
        return False;
    }
    expected = _tag(secret, binding + "|" + nonce);
    return hmac.compare_digest(tag, expected);
}

# ---------------------------------------------------------------------------
# Sessions
# ---------------------------------------------------------------------------

"""One server-side session record. Never serialized to a client."""
obj Session {
    has session_id: str = "";
    has principal_id: str = "";
    has email: str = "";
    has tenant_id: str = "";
    has role: str = "";
    has token_id: str = "";
    has auth_method: str = "session";
    has created_ms: int = 0;
    has last_seen_ms: int = 0;
    has authed_at_ms: int = 0;

    """Age of the last full authentication, in seconds — the step-up input."""
    def auth_age_s(now_ms: int) -> int {
        return int((now_ms - self.authed_at_ms) / 1000);
    }
}

"""In-memory session store with idle and absolute expiry.

`lookup` returns a dict {"session": Session|None, "reason": str} where reason is
"" on success, NO_SESSION when nothing valid was presented, and SESSION_EXPIRED
when a real session aged out — the distinction the openapi's deny table draws."""
obj SessionStore {
    has secret: str = "";
    has idle_s: int = 0;
    has absolute_s: int = 0;
    has _sessions: dict = {};

    """Effective idle window, defaulting to the contract value."""
    def _idle -> int {
        if self.idle_s > 0 {
            return self.idle_s;
        }
        return SESSION_IDLE_S;
    }

    """Effective absolute lifetime, defaulting to the contract value."""
    def _absolute -> int {
        if self.absolute_s > 0 {
            return self.absolute_s;
        }
        return SESSION_ABSOLUTE_S;
    }

    """Create a session and return it. `authed_at_ms` seeds step-up freshness."""
    def create(principal_id: str, email: str, tenant_id: str, role: str,
               now_ms: int, auth_method: str = "session") -> Session {
        sid = "sess_" + uuid.uuid4().hex[:20];
        s = Session(
            session_id=sid,
            principal_id=principal_id,
            email=email,
            tenant_id=tenant_id,
            role=role,
            token_id="tok_" + uuid.uuid4().hex[:16],
            auth_method=auth_method,
            created_ms=now_ms,
            last_seen_ms=now_ms,
            authed_at_ms=now_ms
        );
        with SESSION_LOCK {
            self._sessions[sid] = s;
        }
        return s;
    }

    """The cookie value for a session: `<sid>.<keyed tag>`."""
    def cookie_for(session_id: str) -> str {
        return f"{session_id}.{_tag(self.secret, session_id)}";
    }

    """Recover the session id from a cookie value, or "" when the tag fails.

    Verifying the tag first means an attacker cannot probe the store with guessed
    session ids at all — the request is rejected before any lookup."""
    def sid_from_cookie(cookie_val: str) -> str {
        if not cookie_val or "." not in cookie_val {
            return "";
        }
        parts = cookie_val.rsplit(".", 1);
        sid = parts[0];
        tag = parts[1];
        if not sid or not tag {
            return "";
        }
        if not hmac.compare_digest(tag, _tag(self.secret, sid)) {
            return "";
        }
        return sid;
    }

    """Resolve a cookie value to a live session, applying both expiry rules."""
    def lookup(cookie_val: str, now_ms: int) -> dict {
        sid = self.sid_from_cookie(cookie_val);
        if not sid {
            return {"session": None, "reason": "NO_SESSION"};
        }
        with SESSION_LOCK {
            s = self._sessions.get(sid);
            if s is None {
                return {"session": None, "reason": "NO_SESSION"};
            }
            if (now_ms - s.created_ms) > (self._absolute() * 1000) {
                del self._sessions[sid];
                return {"session": None, "reason": "SESSION_EXPIRED"};
            }
            if (now_ms - s.last_seen_ms) > (self._idle() * 1000) {
                del self._sessions[sid];
                return {"session": None, "reason": "SESSION_EXPIRED"};
            }
            s.last_seen_ms = now_ms;
            return {"session": s, "reason": ""};
        }
    }

    """Issue a new session id for the same principal — login/refresh/reauth.

    Rotation on authentication is what stops a pre-login fixated session id from
    surviving into the authenticated session."""
    def rotate(session_id: str, now_ms: int, reauth: bool = False) -> Any {
        with SESSION_LOCK {
            old = self._sessions.get(session_id);
            if old is None {
                return None;
            }
            del self._sessions[session_id];
            new_sid = "sess_" + uuid.uuid4().hex[:20];
            old.session_id = new_sid;
            old.last_seen_ms = now_ms;
            if reauth {
                old.authed_at_ms = now_ms;
            }
            self._sessions[new_sid] = old;
            return old;
        }
    }

    """Terminate a session. Idempotent."""
    def destroy(session_id: str) -> None {
        with SESSION_LOCK {
            if session_id in self._sessions {
                del self._sessions[session_id];
            }
        }
    }

    """Revoke every session for a principal — the `revoke_session` containment hook."""
    def revoke_principal(principal_id: str) -> int {
        removed = 0;
        with SESSION_LOCK {
            doomed: list = [];
            for sid in self._sessions.keys() {
                if self._sessions[sid].principal_id == principal_id {
                    doomed.append(sid);
                }
            }
            for sid in doomed {
                del self._sessions[sid];
                removed += 1;
            }
        }
        return removed;
    }

    """Number of live sessions. Diagnostics only; never exposed publicly."""
    def count -> int {
        return len(self._sessions);
    }
}

# ---------------------------------------------------------------------------
# Upstream JWT
# ---------------------------------------------------------------------------

"""Mint the short-lived bearer token forwarded to the Jac upstream.

Claims are exactly those named by `x-northwind-internal-surface`: iss, aud, iat,
exp, jti, ctx_hash — where ctx_hash is sha256 over the canonical JSON of the
injected ctx, so a walker can prove the ctx body it received is the one this
token was minted for. TTL is 90 seconds.

`alg` is ES256 when APP_JWT_SIGNING_KEY holds a PEM private key (the contract's
choice) and HS256 when it holds a symmetric secret."""
def mint_upstream_jwt(ctx: dict, key: str, alg: str, now_ms: int, ttl_s: int = 0) -> str {
    ttl = ttl_s;
    if ttl <= 0 {
        ttl = JWT_TTL_S;
    }
    iat = int(now_ms / 1000);
    claims = {
        "iss": JWT_ISS,
        "aud": JWT_AUD,
        "iat": iat,
        "exp": iat + ttl,
        "jti": uuid.uuid4().hex,
        "ctx_hash": ctx_hash(ctx)
    };
    return jwt.encode(claims, key, algorithm=alg);
}
