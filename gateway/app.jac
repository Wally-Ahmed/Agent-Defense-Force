"""The ASGI front door.

Everything a Jac walker cannot see is observed here and handed inward inside a
signed ReqCtx: source IP, cookies, headers, client fingerprint, CSRF state.
jac_scale consumes the HTTP request at its boundary and forwards only walker
kwargs plus a resolved username (serve.endpoints.impl.jac:93-126), which is why
this layer has to exist at all.

REQUEST PIPELINE, in the order of the openapi's `x-northwind-decision-order`:

  1. Observe transport facts        (never a claimed value from a body)
  2. CORS: preflight, and Origin enforcement on state-changing methods
  3. Route resolution               unrouted -> 404, never a path pass-through
  4. Rate limit                     -> 429 RATE_LIMITED   [gateway emits]
  5. Session resolution             cookie -> keyed tag -> server-side store
  6. CSRF double-submit on non-GET  -> 403 CSRF_INVALID   [gateway emits]
  7. Build + HMAC-sign the ReqCtx
  8. STRIP any client-supplied `ctx`, inject ours
  9. Mint the 90s upstream JWT carrying ctx_hash
 10. Proxy to POST /walker/<Walker>, unwrap {"status", "reports"}
 11. Login post-processing         -> auth.login_failed   [gateway emits]

WHAT THIS LAYER DELIBERATELY DOES NOT DECIDE. Authorization, tenancy, and
containment denials other than throttling are left to guard(), because
contracts/vocab.md gives the gateway exactly three audit events and every guard()
call emits exactly one. A denial issued here that guard() would otherwise have
recorded is a hole in the audit chain, not a saved round trip.

There is no bypass header, no debug flag, and no unauthenticated escape hatch
anywhere in this file.
"""

import json;
import time;
import httpx;
import from typing { Any }
import from starlette.applications { Starlette }
import from starlette.routing { Route }
import from starlette.responses { JSONResponse, Response }
import from starlette.middleware.base { BaseHTTPMiddleware }

import from config {
    Settings, load_settings, resolve_route, allowed_for_path, fallback_route_class,
    PATH_PREFIX, SID_COOKIE, CSRF_COOKIE, CSRF_HEADER, REQUEST_ID_HEADER,
    SID_COOKIE_ATTRS, CSRF_COOKIE_ATTRS, SECURITY_HEADERS,
    CORS_METHODS, CORS_ALLOW_HEADERS, CORS_EXPOSE_HEADERS, CORS_MAX_AGE_S,
    DENY_STATUS, DENY_MESSAGE, SESSION_IDLE_S, ACTION_LOGIN_FAILED
}
import from ctxsig { signed_ctx, SIG_ALG }
import from fingerprint {
    ua_hash, client_fp, new_request_id, new_trace_id, observed_ip, email_hash
}
import from audit { AuditSink, with_transport, severity_for }
import from policy { RateLimiter, ControlSource }
import from sessions {
    SessionStore, mint_csrf, csrf_valid, mint_upstream_jwt,
    set_cookie_value, clear_cookie_value, ANON_BINDING
}

glob:pub GW_STATE: dict = {};

"""The assembled gateway. Populated once by build_app()."""
def gw -> Any {
    return GW_STATE["gw"];
}

"""Everything the request pipeline needs, assembled once at startup."""
obj Gateway {
    has settings: Settings = Settings();
    has store: SessionStore = SessionStore();
    has limiter: RateLimiter = RateLimiter();
    has sink: AuditSink = AuditSink();
    has trusted_proxies: list = [];
}

"""Current wall clock in epoch milliseconds."""
def now_ms -> int {
    return int(time.time() * 1000);
}

# ---------------------------------------------------------------------------
# Responses
# ---------------------------------------------------------------------------

"""Build the frozen error envelope: {"error": {code, message, request_id, ...}}."""
def error_body(code: str, request_id: str, extra: dict = {}) -> dict {
    msg = DENY_MESSAGE.get(code, "Request rejected.");
    inner: dict = {"code": code, "message": msg, "request_id": request_id};
    for k in extra.keys() {
        inner[k] = extra[k];
    }
    return {"error": inner};
}

"""A deny response carrying the contract's status for `code`."""
def deny_response(code: str, request_id: str, extra: dict = {}, headers: dict = {}) -> Any {
    status = DENY_STATUS.get(code, 403);
    return JSONResponse(error_body(code, request_id, extra), status_code=status, headers=headers);
}

# ---------------------------------------------------------------------------
# Observation
# ---------------------------------------------------------------------------

"""Collect the observed transport facts for a request.

Every value here is read off the connection or a header the client cannot use to
impersonate another source: `X-Forwarded-For` is honoured only from a configured
trusted proxy, so a direct client cannot choose its own `src_ip` and launder past
a source-keyed limit."""
def observe(request: Any, trusted: list) -> dict {
    hdrs = request.headers;
    peer = "";
    if request.client {
        peer = str(request.client.host);
    }
    ua = hdrs.get("user-agent", "");
    lang = hdrs.get("accept-language", "");
    enc = hdrs.get("accept-encoding", "");
    return {
        "request_id": new_request_id(),
        "trace_id": new_trace_id(),
        "src_ip": observed_ip(peer, hdrs.get("x-forwarded-for", ""), trusted),
        "src_asn": "",
        "user_agent_hash": ua_hash(ua),
        "client_fp": client_fp(ua, lang, enc),
        "http_method": request.method.upper(),
        "route": str(request.url.path),
        "origin": hdrs.get("origin", ""),
        "service": "web",
        "req_bytes": 0
    };
}

# ---------------------------------------------------------------------------
# CORS
# ---------------------------------------------------------------------------

"""CORS response headers for an allowed origin, or {} when the origin is not on
the allowlist.

This is what overrides jac-scale's default `allow_origins=['*']` with
`allow_credentials=True` (serve.core.impl.jac:60-66). That combination is a real
weakness — a wildcard origin paired with credentials — and the gateway never
emits `*` for any origin under any configuration."""
def cors_headers(origin: str, st: Settings, preflight: bool) -> dict {
    if not origin or not st.origin_allowed(origin) {
        return {};
    }
    out: dict = {
        "Access-Control-Allow-Origin": origin,
        "Access-Control-Allow-Credentials": "true",
        "Vary": "Origin"
    };
    if preflight {
        out["Access-Control-Allow-Methods"] = ", ".join(CORS_METHODS);
        out["Access-Control-Allow-Headers"] = ", ".join(CORS_ALLOW_HEADERS);
        out["Access-Control-Max-Age"] = str(CORS_MAX_AGE_S);
    }
    out["Access-Control-Expose-Headers"] = ", ".join(CORS_EXPOSE_HEADERS);
    return out;
}

# ---------------------------------------------------------------------------
# Security headers middleware
# ---------------------------------------------------------------------------

"""Stamps the security headers onto every response — including error responses
and responses produced by an unhandled exception, which is why it is middleware
rather than a helper the handler has to remember to call."""
class SecurityHeadersMiddleware(BaseHTTPMiddleware) {
    async def dispatch(self: SecurityHeadersMiddleware, request: Any, call_next: Any) -> Any {
        response = await call_next(request);
        for k in SECURITY_HEADERS.keys() {
            response.headers[k] = SECURITY_HEADERS[k];
        }
        response.headers["Content-Security-Policy"] = gw().settings.csp;
        rid = getattr(request.state, "request_id", "");
        if rid {
            response.headers[REQUEST_ID_HEADER] = rid;
        }
        return response;
    }
}

# ---------------------------------------------------------------------------
# Body handling — the ctx strip
# ---------------------------------------------------------------------------

"""Parse a JSON request body into a flat dict, dropping anything unusable.

A body that is not a JSON object contributes no walker fields at all."""
async def read_body(request: Any) -> dict {
    raw = await request.body();
    if not raw {
        return {};
    }
    try {
        parsed = json.loads(raw.decode("utf-8"));
    } except Exception {
        return {};
    }
    if not isinstance(parsed, dict) {
        return {};
    }
    return parsed;
}

"""Strip every client-supplied `ctx` key from a request body.

THE CLIENT MUST NOT INFLUENCE A SINGLE FIELD OF THE INJECTED CONTEXT. The strip
is unconditional and case-insensitive, and it happens before anything reads the
body — a caller that sends `ctx`, `CTX`, or `Ctx` claiming csrf_ok, someone
else's session_id, or a spoofed src_ip loses all of it here. Returns the cleaned
body and whether anything was removed (recorded for detection, since a client
sending its own ctx is by definition probing the trust boundary)."""
def strip_client_ctx(body: dict) -> dict {
    cleaned: dict = {};
    stripped = False;
    for k in body.keys() {
        if str(k).lower() == "ctx" {
            stripped = True;
            continue;
        }
        cleaned[k] = body[k];
    }
    return {"body": cleaned, "stripped": stripped};
}

# ---------------------------------------------------------------------------
# The pipeline
# ---------------------------------------------------------------------------

# Action used when a route has no mapped `audit_action`.
#
# CONDUCTOR FLAG — vocabulary gap. GET /auth/session is mapped
# `audit_action: null` with the note "no action in the closed vocabulary; none
# emitted on 200". But a RATE_LIMITED or CSRF_INVALID denial on that route MUST
# be recorded, and `AuditEvent.action` must be one of the 38 frozen ACTIONS.
# `tenant.read` is the least-wrong member of the closed set for "read my own
# session state"; nothing better exists. Raised rather than silently invented.
glob:pub FALLBACK_ACTION: str = "tenant.read";

"""Emit one gateway audit event. Only ever called for the three cases
contracts/vocab.md assigns to the gateway."""
def emit_gateway_event(obs: dict, action: str, reason: str, status_code: int,
                       session_id: str, extra: dict = {}) -> dict {
    fields = with_transport({
        "kind": "security",
        "action": action,
        "outcome": "deny",
        "reason": reason,
        "severity": severity_for(action, "deny", reason, False),
        "auth_method": "none",
        "session_id": session_id,
        "target_kind": "auth",
        "target_sensitivity": "normal",
        "status_code": status_code
    }, obs);
    for k in extra.keys() {
        fields[k] = extra[k];
    }
    return gw().sink.emit(fields);
}

"""The single request handler. Every public route funnels through here."""
async def handle(request: Any) -> Any {
    st = gw().settings;
    started = time.time();
    obs = observe(request, gw().trusted_proxies);
    request.state.request_id = obs["request_id"];
    rid = obs["request_id"];
    origin = obs["origin"];
    method = obs["http_method"];
    path = obs["route"];

    # -- 2. CORS ------------------------------------------------------------
    if method == "OPTIONS" {
        allowed = allowed_for_path(path);
        if not allowed {
            return JSONResponse(error_body("NOT_FOUND", rid), status_code=404);
        }
        if origin and not st.origin_allowed(origin) {
            # A preflight from an origin that is not on the allowlist is refused
            # outright rather than answered with a silently useless response.
            return JSONResponse(error_body("CSRF_INVALID", rid), status_code=403);
        }
        return Response(status_code=204, headers=cors_headers(origin, st, True));
    }

    cors = cors_headers(origin, st, False);

    # An Origin header that is present and not on the allowlist, on a
    # state-changing method, is a cross-site request. Browsers would block
    # reading the response but the side effect would already have happened, so
    # the gateway refuses it server-side. CSRF_INVALID is the contract's code for
    # exactly this class.
    if origin and not st.origin_allowed(origin) and method != "GET" {
        action = _action_for(path, method);
        if path.endswith("/auth/login") {
            action = ACTION_LOGIN_FAILED;
        }
        emit_gateway_event(obs, action, "CSRF_INVALID", 403, "");
        return deny_response("CSRF_INVALID", rid, {}, cors);
    }

    # -- 3. Route resolution ------------------------------------------------
    route = resolve_route(method, path);
    if route is None {
        other = allowed_for_path(path);
        if other {
            hdrs: dict = {"Allow": ", ".join(other)};
            for k in cors.keys() {
                hdrs[k] = cors[k];
            }
            return JSONResponse(error_body("NOT_FOUND", rid), status_code=405, headers=hdrs);
        }
        # Unrouted traffic still consumes a bucket so path scanning is throttled,
        # but it is never proxied — the upstream walker surface is not reachable
        # by path pass-through.
        gw().limiter.check(obs["src_ip"], fallback_route_class(method), "", now_ms());
        return JSONResponse(error_body("NOT_FOUND", rid), status_code=404, headers=cors);
    }

    obs["service"] = "api" if route["route_class"] == "integration" else "web";

    # -- 5. Session resolution (before rate limiting so the identity bucket
    #       has an identity to key on) ---------------------------------------
    sid_cookie = request.cookies.get(SID_COOKIE, "");
    found = gw().store.lookup(sid_cookie, now_ms());
    session = found["session"];
    session_id = "";
    principal_id = "";
    token_id = "";
    identity = "";
    # Step-up freshness, stamped into the signed ctx below. 0 means UNKNOWN and
    # guard() reads it as infinitely old, so every path that fails to set it
    # (no session, bearer token, expired session) fails CLOSED for the
    # step-up-protected actions. This is the ONLY place it is sourced: it comes
    # off the server-side session record, never off the request.
    session_auth_at_ms = 0;
    bearer = request.headers.get("authorization", "");
    is_bearer = bearer.lower().startswith("bearer ");

    if session is not None {
        session_id = session.session_id;
        principal_id = session.principal_id;
        token_id = session.token_id;
        identity = principal_id;
        # `authed_at_ms` advances on password login and on a completed re-auth
        # (SessionStore.rotate(reauth=True)) -- NOT on ordinary activity, which
        # only moves `last_seen_ms`. That distinction is the whole control.
        session_auth_at_ms = session.authed_at_ms;
    } elif is_bearer {
        # An API token authenticates without ambient authority; the token itself
        # is resolved upstream. Key the identity bucket on a hash of it so one
        # token cannot outrun its budget by rotating source addresses.
        identity = "tok:" + email_hash(bearer[7:]);
    }

    audit_session = session_id;
    if not audit_session {
        audit_session = f"sess_anon_{obs['request_id']}";
    }

    # -- 4. Rate limit ------------------------------------------------------
    limit = gw().limiter.check(obs["src_ip"], route["route_class"], identity, now_ms());
    rl_headers: dict = {};
    for k in cors.keys() {
        rl_headers[k] = cors[k];
    }
    if limit.limit > 0 {
        rl_headers["X-RateLimit-Limit"] = str(limit.limit);
        rl_headers["X-RateLimit-Remaining"] = str(limit.remaining);
        rl_headers["X-RateLimit-Reset"] = str(limit.reset_epoch_s);
    }
    if not limit.allowed {
        rl_headers["Retry-After"] = str(limit.retry_after_s);
        emit_gateway_event(obs, route["audit_action"] or FALLBACK_ACTION, "RATE_LIMITED", 429,
                           audit_session, {"actor_principal_id": principal_id, "token_id": token_id});
        return deny_response("RATE_LIMITED", rid, {"retry_after_s": limit.retry_after_s}, rl_headers);
    }

    body = await read_body(request);
    obs["req_bytes"] = len(json.dumps(body).encode("utf-8")) if body else 0;

    # -- Login throttle: exponential backoff after repeated failures ---------
    login_email = "";
    login_key = "";
    if route["walker"] == "LoginUser" {
        login_email = str(body.get("email", ""));
        login_key = email_hash(login_email);
        backoff = gw().limiter.login_backoff(login_key, obs["src_ip"], now_ms());
        if backoff > 0 {
            rl_headers["Retry-After"] = str(backoff);
            emit_gateway_event(obs, ACTION_LOGIN_FAILED, "RATE_LIMITED", 429, audit_session);
            return deny_response("RATE_LIMITED", rid, {"retry_after_s": backoff}, rl_headers);
        }
    }

    # -- 6. CSRF double-submit ----------------------------------------------
    csrf_ok = False;
    if method == "GET" {
        csrf_ok = True;
    } elif is_bearer and session is None {
        # Bearer carries no ambient authority, so there is nothing for a
        # cross-site request to ride on and no CSRF token is required.
        csrf_ok = True;
    } else {
        binding = session_id if session_id else ANON_BINDING;
        csrf_ok = csrf_valid(
            st.csrf_secret, binding,
            request.cookies.get(CSRF_COOKIE, ""),
            request.headers.get(CSRF_HEADER, "")
        );
        if not csrf_ok {
            action = route["audit_action"] or FALLBACK_ACTION;
            if route["walker"] == "LoginUser" {
                action = ACTION_LOGIN_FAILED;
            }
            emit_gateway_event(obs, action, "CSRF_INVALID", 403, audit_session,
                               {"actor_principal_id": principal_id});
            return deny_response("CSRF_INVALID", rid, {}, rl_headers);
        }
    }

    # -- 7/8. Build, sign, and inject the context ---------------------------
    issued = now_ms();
    ctx = signed_ctx({
        "request_id": obs["request_id"],
        "src_ip": obs["src_ip"],
        "src_asn": obs["src_asn"],
        "user_agent_hash": obs["user_agent_hash"],
        "client_fp": obs["client_fp"],
        "session_id": session_id,
        "token_id": token_id,
        "service": obs["service"],
        "route": route["template"],
        "http_method": method,
        "csrf_ok": csrf_ok,
        "received_at_ms": issued,
        "sig_alg": SIG_ALG,
        "issued_at_ms": issued,
        "session_auth_at_ms": session_auth_at_ms
    }, st.ctx_signing_key);

    scrub = strip_client_ctx(body);
    upstream_body: dict = {};
    for k in scrub["body"].keys() {
        upstream_body[k] = scrub["body"][k];
    }
    for k in request.query_params.keys() {
        # A query string cannot smuggle a ctx past the body strip either.
        if str(k).lower() == "ctx" {
            continue;
        }
        upstream_body[k] = request.query_params[k];
    }
    for k in route["params"].keys() {
        upstream_body[k] = route["params"][k];
    }
    # Injected last and unconditionally: nothing above can reach this key.
    upstream_body["ctx"] = ctx;

    if scrub["stripped"] {
        # A caller that ships its own ctx is probing the trust boundary. The
        # emission map gives the gateway only three audit events, so this is
        # logged rather than emitted — visible to an operator, absent from the
        # audit chain that guard() owns.
        print(
            f"[gateway] stripped client-supplied ctx request_id={rid} "
            + f"src_ip={obs['src_ip']} route={route['template']}",
            flush=True
        );
    }

    # -- 9/10. Proxy --------------------------------------------------------
    jwt_token = mint_upstream_jwt(ctx, st.jwt_key, st.jwt_alg, issued);
    auth_header = f"Bearer {jwt_token}";
    if st.upstream_bearer {
        # The upstream may additionally enforce jac-scale's own bearer auth. When
        # a service token is configured it carries the Authorization header and
        # the gateway JWT travels alongside it.
        auth_header = f"Bearer {st.upstream_bearer}";
    }
    up_headers: dict = {
        "Authorization": auth_header,
        "X-Gateway-Jwt": jwt_token,
        "Content-Type": "application/json",
        REQUEST_ID_HEADER: rid
    };
    url = f"{st.upstream}/walker/{route['walker']}";

    status = 502;
    payload: Any = None;
    try {
        async with httpx.AsyncClient(timeout=st.upstream_timeout_s) as client {
            up = await client.post(url, json=upstream_body, headers=up_headers);
        }
        status = up.status_code;
        try {
            raw = up.json();
        } except Exception {
            raw = None;
        }
        if isinstance(raw, dict) and "reports" in raw {
            reports = raw.get("reports", []);
            if isinstance(reports, list) and len(reports) > 0 {
                payload = reports[0];
            } else {
                payload = {};
            }
            inner = raw.get("status", status);
            if isinstance(inner, int) and inner > 0 {
                status = inner;
            }
        } else {
            payload = raw;
        }
    } except Exception as exc {
        # Never leak an upstream exception message to the caller.
        print(f"[gateway] upstream error request_id={rid} kind={type(exc).__name__}", flush=True);
        return JSONResponse(
            {"error": {"code": "UPSTREAM_UNAVAILABLE", "message": "Upstream unavailable.", "request_id": rid}},
            status_code=502, headers=rl_headers
        );
    }

    if payload is None {
        payload = {};
    }

    resp_headers: dict = {};
    for k in rl_headers.keys() {
        resp_headers[k] = rl_headers[k];
    }
    response = JSONResponse(payload, status_code=status, headers=resp_headers);

    # -- 11. Login post-processing ------------------------------------------
    if route["walker"] == "LoginUser" {
        if status >= 200 and status < 300 {
            gw().limiter.login_ok(login_key, obs["src_ip"]);
            _establish_session(response, payload, login_email, obs);
        } else {
            fails = gw().limiter.login_failed(login_key, obs["src_ip"], now_ms());
            latency = int((time.time() - started) * 1000);
            fields = with_transport({
                "kind": "security",
                "action": ACTION_LOGIN_FAILED,
                "outcome": "deny",
                "reason": "NO_SESSION",
                "severity": severity_for(ACTION_LOGIN_FAILED, "deny", "NO_SESSION", fails > 1),
                "actor_principal_id": "",
                "actor_email": login_email,
                "auth_method": "password",
                "session_id": audit_session,
                "target_kind": "auth",
                "target_sensitivity": "normal",
                "status_code": status,
                "latency_ms": latency
            }, obs);
            gw().sink.emit(fields);
            # The public body is the upstream's; it must not disclose whether the
            # account exists, which is why the contract fixes one message.
            response = JSONResponse(error_body("NO_SESSION", rid), status_code=401, headers=resp_headers);
        }
    } elif route["walker"] == "LogoutSession" and status >= 200 and status < 300 {
        if session_id {
            gw().store.destroy(session_id);
        }
        response.headers.append("set-cookie", clear_cookie_value(SID_COOKIE, SID_COOKIE_ATTRS));
        response.headers.append("set-cookie", clear_cookie_value(CSRF_COOKIE, CSRF_COOKIE_ATTRS));
    }

    # Anonymous callers get a pre-session CSRF cookie on any GET so that login
    # itself is CSRF-protected.
    if method == "GET" and session is None and CSRF_COOKIE not in request.cookies {
        token = mint_csrf(st.csrf_secret, ANON_BINDING);
        response.headers.append("set-cookie",
            set_cookie_value(CSRF_COOKIE, token, CSRF_COOKIE_ATTRS, SESSION_IDLE_S));
    }

    return response;
}

"""Best-effort audit action for a path when no route matched — used only to label
a pre-routing denial. Never used to dispatch."""
def _action_for(path: str, method: str) -> str {
    r = resolve_route(method, path);
    if r is None {
        return FALLBACK_ACTION;
    }
    return r["audit_action"] or FALLBACK_ACTION;
}

"""Mint a gateway session from a successful upstream login and set both cookies.

The upstream returns the authenticated principal; the gateway is what turns that
into browser-facing state. The session id is generated here and never derived
from anything the client sent, so a fixated cookie cannot survive login."""
def _establish_session(response: Any, payload: Any, email: str, obs: dict) -> None {
    principal = "";
    tenant = "";
    role = "";
    if isinstance(payload, dict) {
        principal = str(payload.get("principal_id", "") or payload.get("user_id", ""));
        tenant = str(payload.get("tenant_id", ""));
        role = str(payload.get("role", ""));
    }
    s = gw().store.create(principal, email, tenant, role, now_ms(), "session");
    response.headers.append("set-cookie",
        set_cookie_value(SID_COOKIE, gw().store.cookie_for(s.session_id), SID_COOKIE_ATTRS, SESSION_IDLE_S));
    response.headers.append("set-cookie",
        set_cookie_value(CSRF_COOKIE, mint_csrf(gw().settings.csrf_secret, s.session_id),
                         CSRF_COOKIE_ATTRS, SESSION_IDLE_S));
}

"""Liveness probe. Exposes nothing about configuration, sessions, or secrets."""
async def healthz(request: Any) -> Any {
    request.state.request_id = new_request_id();
    return JSONResponse({"status": "ok"});
}

# ---------------------------------------------------------------------------
# Assembly
# ---------------------------------------------------------------------------

"""Build the ASGI application.

Calling this is what enforces the refuse-to-start rule: load_settings() raises
when APP_CTX_SIGNING_KEY (or any other required secret) is absent, and there is
no code path that supplies a default."""
def build_app(settings: Any = None) -> Any {
    st = settings;
    if st is None {
        st = load_settings();
    }
    GW_STATE["gw"] = Gateway(
        settings=st,
        store=SessionStore(secret=st.session_secret),
        limiter=RateLimiter(controls=ControlSource(path=st.controls_path)),
        sink=AuditSink(path=st.audit_path),
        trusted_proxies=[]
    );
    gw().sink.ensure();

    routes = [
        Route("/healthz", healthz, methods=["GET"]),
        Route(PATH_PREFIX + "/{rest:path}", handle,
              methods=["GET", "POST", "PATCH", "DELETE", "OPTIONS"])
    ];
    app = Starlette(routes=routes);
    app.add_middleware(SecurityHeadersMiddleware);
    return app;
}
