"""Gateway configuration: environment, constants, and the public route table.

Every secret is read from the environment. There is no default key, no dev-mode
fallback, and no bypass flag anywhere in this package. `require_env()` raises and
the process refuses to start when a required secret is absent — see the trust
model in contracts/req_ctx_contract.jac.
"""

import os;
import from typing { Any }

# ---------------------------------------------------------------------------
# Required secrets. Absent => refuse to start, loudly.
# ---------------------------------------------------------------------------

# The HMAC key over the injected ReqCtx. Mandated by contracts/req_ctx_contract.jac
# rule 4/5: read from the environment, never hard-coded, never defaulted.
glob:pub ENV_CTX_KEY: str = "APP_CTX_SIGNING_KEY";
glob:pub ENV_SESSION_SECRET: str = "APP_SESSION_SECRET";
glob:pub ENV_CSRF_SECRET: str = "APP_CSRF_SECRET";
glob:pub ENV_JWT_KEY: str = "APP_JWT_SIGNING_KEY";

glob:pub REQUIRED_ENV: list = [
    "APP_CTX_SIGNING_KEY",
    "APP_SESSION_SECRET",
    "APP_CSRF_SECRET",
    "APP_JWT_SIGNING_KEY"
];

# Minimum acceptable length for a symmetric secret. Generate with
#   openssl rand -hex 32
glob:pub MIN_SECRET_LEN: int = 32;

# ---------------------------------------------------------------------------
# Public surface constants (contracts/app_api.openapi.yaml `x-northwind-gateway`)
# ---------------------------------------------------------------------------

glob:pub PATH_PREFIX: str = "/api/v1";

glob:pub SID_COOKIE: str = "__Host-sid";
glob:pub CSRF_COOKIE: str = "__Host-csrf";
glob:pub CSRF_HEADER: str = "X-CSRF-Token";
glob:pub REQUEST_ID_HEADER: str = "X-Request-Id";

# `__Host-` prefix rules: Secure, Path=/, and NO Domain attribute.
# NOTE ON SameSite: the frozen openapi says `SameSite=Lax` for __Host-csrf; the
# gateway build order specifies `SameSite=Strict`. Strict is the strictly stronger
# choice and is what we ship — a double-submit CSRF cookie is only ever read by
# same-origin script, so Strict costs nothing. Divergence is deliberate.
glob:pub SID_COOKIE_ATTRS: str = "HttpOnly; Secure; SameSite=Lax; Path=/";
glob:pub CSRF_COOKIE_ATTRS: str = "Secure; SameSite=Strict; Path=/";

glob:pub SESSION_IDLE_S: int = 1800;
glob:pub SESSION_ABSOLUTE_S: int = 43200;
glob:pub STEP_UP_MAX_AUTH_AGE_S: int = 900;

# Upstream JWT (x-northwind-internal-surface).
glob:pub JWT_ISS: str = "northwind-gateway";
glob:pub JWT_AUD: str = "northwind-jac";
glob:pub JWT_TTL_S: int = 90;

# ReqCtx replay bound (contracts/req_ctx_contract.jac rule 3).
glob:pub CTX_MAX_AGE_MS: int = 30000;

# ---------------------------------------------------------------------------
# Security response headers.
# ---------------------------------------------------------------------------
# CSP note: the openapi specifies `default-src 'none'`; the build order specifies
# `default-src 'self'`. We ship `'self'` (the explicit instruction) while keeping
# the contract's frame-ancestors/base-uri hardening. Override with $APP_CSP.
glob:pub DEFAULT_CSP: str = "default-src 'self'; frame-ancestors 'none'; base-uri 'none'";

glob:pub SECURITY_HEADERS: dict = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "X-Frame-Options": "DENY",
    "Permissions-Policy": "accelerometer=(), camera=(), geolocation=(), gyroscope=(), magnetometer=(), microphone=(), payment=(), usb=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cache-Control": "no-store"
};

# ---------------------------------------------------------------------------
# CORS. Explicit allowlist only. This OVERRIDES jac-scale's default
# allow_origins=['*'] + allow_credentials=True (serve.core.impl.jac:60-66), which
# is a genuine weakness we deliberately do not inherit.
# ---------------------------------------------------------------------------

glob:pub CORS_METHODS: list = ["GET", "POST", "PATCH", "DELETE", "OPTIONS"];
glob:pub CORS_ALLOW_HEADERS: list = [
    "Content-Type",
    "X-CSRF-Token",
    "Idempotency-Key",
    "X-Northwind-Source-Id"
];
glob:pub CORS_EXPOSE_HEADERS: list = [
    "X-Request-Id",
    "Retry-After",
    "X-RateLimit-Limit",
    "X-RateLimit-Remaining",
    "X-RateLimit-Reset"
];
glob:pub CORS_MAX_AGE_S: int = 600;

# ---------------------------------------------------------------------------
# Deny reason -> public HTTP status (openapi `x-northwind-deny-reasons`).
# ---------------------------------------------------------------------------

glob:pub DENY_STATUS: dict = {
    "NO_SESSION": 401,
    "SESSION_EXPIRED": 401,
    "TOKEN_REVOKED": 401,
    "REAUTH_REQUIRED": 401,
    "NOT_A_MEMBER": 403,
    "INSUFFICIENT_ROLE": 403,
    "TENANT_MISMATCH": 403,
    "CSRF_INVALID": 403,
    "SUSPENDED": 403,
    "SOURCE_BLOCKED": 403,
    "NOT_FOUND": 404,
    "VALIDATION_FAILED": 422,
    "READONLY_MODE": 423,
    "RATE_LIMITED": 429,
    "CTX_UNVERIFIED": 401
};

glob:pub DENY_MESSAGE: dict = {
    "NO_SESSION": "Invalid email or password.",
    "SESSION_EXPIRED": "Session expired.",
    "TOKEN_REVOKED": "Token revoked.",
    "REAUTH_REQUIRED": "Re-authentication required.",
    "CSRF_INVALID": "CSRF validation failed.",
    "RATE_LIMITED": "Too many requests.",
    "NOT_FOUND": "Not found.",
    "VALIDATION_FAILED": "Request validation failed.",
    "SOURCE_BLOCKED": "Forbidden.",
    "SUSPENDED": "Forbidden.",
    "CTX_UNVERIFIED": "Unauthenticated."
};

# ---------------------------------------------------------------------------
# Rate-limit budgets per route class. Transcribed from the openapi
# `x-northwind-gateway.rate_limits`. `ip_*` is the (src_ip, route_class) bucket
# required by the build order; `id_*` is the per-identity bucket the contract
# specifies. Both are enforced; the tighter one wins.
# ---------------------------------------------------------------------------

glob:pub RATE_BUDGETS: dict = {
    "auth_login":      {"ip_limit": 20,   "ip_window_s": 900,  "id_limit": 0,   "id_window_s": 900},
    "auth_register":   {"ip_limit": 3,    "ip_window_s": 3600, "id_limit": 0,   "id_window_s": 3600},
    "auth":            {"ip_limit": 60,   "ip_window_s": 60,   "id_limit": 60,  "id_window_s": 60},
    "read":            {"ip_limit": 1200, "ip_window_s": 60,   "id_limit": 600, "id_window_s": 60},
    "search":          {"ip_limit": 1200, "ip_window_s": 60,   "id_limit": 600, "id_window_s": 60},
    "write":           {"ip_limit": 240,  "ip_window_s": 60,   "id_limit": 120, "id_window_s": 60},
    "export_request":  {"ip_limit": 20,   "ip_window_s": 3600, "id_limit": 5,   "id_window_s": 3600},
    "export_download": {"ip_limit": 1200, "ip_window_s": 60,   "id_limit": 600, "id_window_s": 60},
    "integration":     {"ip_limit": 120,  "ip_window_s": 60,   "id_limit": 60,  "id_window_s": 60}
};

# Login throttle keyed (email, src_ip): exponential backoff after this many
# consecutive failures. delay = LOGIN_BACKOFF_BASE_S * 2^(failures - threshold),
# capped at LOGIN_BACKOFF_MAX_S.
glob:pub LOGIN_FAIL_THRESHOLD: int = 5;
glob:pub LOGIN_BACKOFF_BASE_S: int = 2;
glob:pub LOGIN_BACKOFF_MAX_S: int = 900;
glob:pub LOGIN_FAIL_WINDOW_S: int = 900;

# ---------------------------------------------------------------------------
# The public route table, transcribed from the openapi `paths:` block and
# `x-northwind-mapping`. Columns:
#   0 method  1 path template  2 walker  3 route_class  4 mutating  5 step_up
#   6 audit_action
# Path templates are relative to PATH_PREFIX. Anything not on this table 404s at
# the gateway and never reaches the upstream — the upstream's walker surface is
# never exposed by path pass-through.
# ---------------------------------------------------------------------------

glob:pub ROUTES: list = [
    ["POST",   "/auth/register",                                                        "RegisterUser",     "auth_register",   True,  False, "auth.register"],
    ["POST",   "/auth/login",                                                           "LoginUser",        "auth_login",      True,  False, "auth.login"],
    ["POST",   "/auth/logout",                                                          "LogoutSession",    "auth",            True,  False, "auth.logout"],
    ["POST",   "/auth/refresh",                                                         "RefreshSession",   "auth",            True,  False, "auth.token_issued"],
    ["POST",   "/auth/reauth",                                                          "ReauthSession",    "auth",            True,  False, "auth.reauth_required"],
    ["GET",    "/auth/session",                                                         "GetSession",       "read",            False, False, ""],
    ["GET",    "/tenants",                                                              "ListMyTenants",    "read",            False, False, "tenant.read"],
    ["POST",   "/tenants",                                                              "CreateTenant",     "write",           True,  False, "tenant.create"],
    ["GET",    "/tenants/{tenant_id}",                                                  "ReadTenant",       "read",            False, False, "tenant.read"],
    ["GET",    "/tenants/{tenant_id}/members",                                          "ListMembers",      "read",            False, False, "tenant.read"],
    ["POST",   "/tenants/{tenant_id}/members/invites",                                  "InviteMember",     "write",           True,  False, "member.invite"],
    ["POST",   "/tenants/{tenant_id}/invites/accept",                                   "AcceptInvite",     "write",           True,  False, "member.accept"],
    ["PATCH",  "/tenants/{tenant_id}/members/{membership_id}",                          "ChangeMemberRole", "write",           True,  True,  "member.role_change"],
    ["DELETE", "/tenants/{tenant_id}/members/{membership_id}",                          "RemoveMember",     "write",           True,  True,  "member.remove"],
    ["GET",    "/tenants/{tenant_id}/projects",                                         "ListProjects",     "read",            False, False, "project.list"],
    ["POST",   "/tenants/{tenant_id}/projects",                                         "CreateProject",    "write",           True,  False, "project.create"],
    ["GET",    "/tenants/{tenant_id}/projects/{project_id}",                            "ReadProject",      "read",            False, False, "project.read"],
    ["PATCH",  "/tenants/{tenant_id}/projects/{project_id}",                            "UpdateProject",    "write",           True,  False, "project.update"],
    ["DELETE", "/tenants/{tenant_id}/projects/{project_id}",                            "DeleteProject",    "write",           True,  False, "project.delete"],
    ["GET",    "/tenants/{tenant_id}/projects/{project_id}/tasks",                      "ListTasks",        "read",            False, False, "task.list"],
    ["POST",   "/tenants/{tenant_id}/projects/{project_id}/tasks",                      "CreateTask",       "write",           True,  False, "task.create"],
    ["GET",    "/tenants/{tenant_id}/projects/{project_id}/tasks/{task_id}",            "ReadTask",         "read",            False, False, "task.read"],
    ["PATCH",  "/tenants/{tenant_id}/projects/{project_id}/tasks/{task_id}",            "UpdateTask",       "write",           True,  False, "task.update"],
    ["DELETE", "/tenants/{tenant_id}/projects/{project_id}/tasks/{task_id}",            "DeleteTask",       "write",           True,  False, "task.delete"],
    ["POST",   "/tenants/{tenant_id}/projects/{project_id}/tasks/{task_id}/assign",     "AssignTask",       "write",           True,  False, "task.assign"],
    ["GET",    "/tenants/{tenant_id}/projects/{project_id}/tasks/{task_id}/comments",   "ListComments",     "read",            False, False, "comment.list"],
    ["POST",   "/tenants/{tenant_id}/projects/{project_id}/tasks/{task_id}/comments",   "CreateComment",    "write",           True,  False, "comment.create"],
    ["GET",    "/tenants/{tenant_id}/projects/{project_id}/tasks/{task_id}/comments/{comment_id}", "ReadComment",   "read",  False, False, "comment.read"],
    ["DELETE", "/tenants/{tenant_id}/projects/{project_id}/tasks/{task_id}/comments/{comment_id}", "DeleteComment", "write", True,  False, "comment.delete"],
    ["GET",    "/tenants/{tenant_id}/search",                                           "SearchTenant",     "search",          False, False, "search.query"],
    ["POST",   "/tenants/{tenant_id}/exports",                                          "RequestExport",    "export_request",  True,  True,  "export.request"],
    ["GET",    "/tenants/{tenant_id}/exports/{export_id}",                              "DownloadExport",   "export_download", False, True,  "export.download"],
    ["POST",   "/tenants/{tenant_id}/integrations/call",                                "IntegrationCall",  "integration",     True,  True,  "integration.call"]
];

# The action emitted when a login attempt fails
# (x-northwind-mapping: audit_action_on_failure on POST /auth/login).
glob:pub ACTION_LOGIN_FAILED: str = "auth.login_failed";

# ---------------------------------------------------------------------------
# Environment access.
# ---------------------------------------------------------------------------

"""Read an optional environment variable, falling back to `fallback`."""
def env_str(name: str, fallback: str = "") -> str {
    v = os.environ.get(name);
    if v is None {
        return fallback;
    }
    s = str(v).strip();
    if not s {
        return fallback;
    }
    return s;
}

"""Read an optional integer environment variable."""
def env_int(name: str, fallback: int) -> int {
    raw = env_str(name, "");
    if not raw {
        return fallback;
    }
    try {
        return int(raw);
    } except Exception {
        return fallback;
    }
}

"""Fail-closed read of a required secret.

Raises RuntimeError when the variable is absent, empty, or shorter than
MIN_SECRET_LEN. There is deliberately no default value and no dev-mode escape
hatch: contracts/req_ctx_contract.jac rule 5 requires the process to refuse to
start rather than run with a guessable key."""
def require_env(name: str) -> str {
    raw = os.environ.get(name);
    if raw is None or not str(raw).strip() {
        raise RuntimeError(
            f"FATAL: required environment variable {name} is not set. "
            + "The gateway refuses to start without it. There is no default key. "
            + f"Generate one with:  export {name}=$(openssl rand -hex 32)"
        );
    }
    val = str(raw).strip();
    if len(val) < MIN_SECRET_LEN {
        raise RuntimeError(
            f"FATAL: {name} is {len(val)} characters; at least {MIN_SECRET_LEN} are required. "
            + f"Generate one with:  export {name}=$(openssl rand -hex 32)"
        );
    }
    return val;
}

"""Parsed, validated gateway settings. Constructing this object is what enforces
the refuse-to-start rule."""
obj Settings {
    has ctx_signing_key: str = "";
    has session_secret: str = "";
    has csrf_secret: str = "";
    has jwt_key: str = "";
    has jwt_alg: str = "HS256";
    has origins: list = [];
    has bind_host: str = "127.0.0.1";
    has bind_port: int = 8080;
    has upstream: str = "http://127.0.0.1:8000";
    has audit_path: str = "var/audit/audit.jsonl";
    has controls_path: str = "var/controls/controls.json";
    has csp: str = "";
    has upstream_bearer: str = "";
    has upstream_timeout_s: float = 10.0;

    """Origin allowlist membership. Never wildcards."""
    def origin_allowed(origin: str) -> bool {
        if not origin {
            return False;
        }
        return origin in self.origins;
    }
}

"""Build Settings from the environment. Raises RuntimeError if any required
secret is missing — this is the refuse-to-start path."""
def load_settings -> Settings {
    ctx_key = require_env(ENV_CTX_KEY);
    sess = require_env(ENV_SESSION_SECRET);
    csrf = require_env(ENV_CSRF_SECRET);
    jwtk = require_env(ENV_JWT_KEY);

    alg = env_str("APP_JWT_ALG", "");
    if not alg {
        if "-----BEGIN" in jwtk {
            alg = "ES256";
        } else {
            alg = "HS256";
        }
    }

    raw_origins = env_str("APP_ORIGINS", "http://127.0.0.1:8080");
    origins: list = [];
    for o in raw_origins.split(",") {
        t = o.strip().rstrip("/");
        if t and t != "*" {
            origins.append(t);
        }
    }

    bind = env_str("GATEWAY_BIND", "127.0.0.1:8080");
    host = "127.0.0.1";
    port = 8080;
    if ":" in bind {
        bits = bind.rsplit(":", 1);
        host = bits[0];
        try {
            port = int(bits[1]);
        } except Exception {
            port = 8080;
        }
    }

    up = env_str("JAC_UPSTREAM", "127.0.0.1:8000");
    if not up.startswith("http://") and not up.startswith("https://") {
        up = f"http://{up}";
    }

    return Settings(
        ctx_signing_key=ctx_key,
        session_secret=sess,
        csrf_secret=csrf,
        jwt_key=jwtk,
        jwt_alg=alg,
        origins=origins,
        bind_host=host,
        bind_port=port,
        upstream=up.rstrip("/"),
        # Same sink, same env var as the application's emitter
        # (app/security/audit.jac:313) so gateway and guard() events land in one
        # file and the per-session seq chain has no holes. AUDIT_PATH is kept as
        # an alias only because this module shipped with it first.
        audit_path=env_str("APP_AUDIT_LOG", env_str("AUDIT_PATH", "var/audit/audit.jsonl")),
        controls_path=env_str("CONTROLS_PATH", "var/controls/controls.json"),
        csp=env_str("APP_CSP", DEFAULT_CSP),
        upstream_bearer=env_str("JAC_UPSTREAM_BEARER", ""),
        upstream_timeout_s=float(env_int("UPSTREAM_TIMEOUT_S", 10))
    );
}

# ---------------------------------------------------------------------------
# Route matching.
# ---------------------------------------------------------------------------

"""Match a concrete path against a `{param}` template.

Returns the extracted params, or None when the template does not match."""
def match_template(template: str, path: str) -> Any {
    t_parts = template.strip("/").split("/");
    p_parts = path.strip("/").split("/");
    if len(t_parts) != len(p_parts) {
        return None;
    }
    params: dict = {};
    idx = 0;
    while idx < len(t_parts) {
        tp = t_parts[idx];
        pp = p_parts[idx];
        if tp.startswith("{") and tp.endswith("}") {
            if not pp {
                return None;
            }
            params[tp[1:-1]] = pp;
        } elif tp != pp {
            return None;
        }
        idx += 1;
    }
    return params;
}

"""Resolve (method, path) to a route table row.

`path` is the full request path including PATH_PREFIX. Returns a dict with keys
walker/route_class/mutating/step_up/params/template, or None when unrouted.
`allowed_methods` on a path mismatch is returned separately by allowed_for_path."""
def resolve_route(method: str, path: str) -> Any {
    if not path.startswith(PATH_PREFIX) {
        return None;
    }
    rel = path[len(PATH_PREFIX):];
    if not rel {
        rel = "/";
    }
    for row in ROUTES {
        if row[0] != method.upper() {
            continue;
        }
        params = match_template(row[1], rel);
        if params is None {
            continue;
        }
        return {
            "method": row[0],
            "template": row[1],
            "walker": row[2],
            "route_class": row[3],
            "mutating": row[4],
            "step_up": row[5],
            "audit_action": row[6],
            "params": params
        };
    }
    return None;
}

"""Methods routable for a path, used to answer OPTIONS and to 405 correctly."""
def allowed_for_path(path: str) -> list {
    if not path.startswith(PATH_PREFIX) {
        return [];
    }
    rel = path[len(PATH_PREFIX):];
    if not rel {
        rel = "/";
    }
    out: list = [];
    for row in ROUTES {
        if match_template(row[1], rel) is not None {
            out.append(row[0]);
        }
    }
    return out;
}

"""The route class used for rate limiting when no route matched.

Unrouted traffic still consumes a bucket so that path-scanning is throttled."""
def fallback_route_class(method: str) -> str {
    if method.upper() == "GET" {
        return "read";
    }
    return "write";
}
