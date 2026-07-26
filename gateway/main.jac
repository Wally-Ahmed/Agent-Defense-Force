"""Gateway entrypoint.

    jac run gateway/main.jac

Binds $GATEWAY_BIND (default 127.0.0.1:8080) and proxies to $JAC_UPSTREAM
(default 127.0.0.1:8000).

The process REFUSES TO START when APP_CTX_SIGNING_KEY is absent from the
environment. That is not a convenience check: `jac start` binds 0.0.0.0
unconditionally and has no --host flag (jfast_api.impl.jac:74), so the upstream
is directly reachable and this gateway is bypassable. The only thing standing
between a hand-written `ctx` POSTed straight to :8000 and a full authentication
bypass is the HMAC over that context — a default or absent key would silently
remove it. See contracts/req_ctx_contract.jac.
"""

import sys;
import uvicorn;
import from typing { Any }
import from config { load_settings, REQUIRED_ENV }
import from app { build_app }

"""Load settings, build the app, and serve. Exits 2 on a configuration failure."""
def main -> int {
    try {
        settings = load_settings();
    } except Exception as exc {
        print(str(exc), file=sys.stderr);
        print(
            "The gateway will not start with a missing or weak secret, and there is no "
            + "default key. Required: " + ", ".join(REQUIRED_ENV),
            file=sys.stderr
        );
        return 2;
    }

    app = build_app(settings);
    print(f"[gateway] listening on {settings.bind_host}:{settings.bind_port}");
    print(f"[gateway] upstream    {settings.upstream}");
    print(f"[gateway] origins     {settings.origins}");
    print(f"[gateway] audit sink  {settings.audit_path}");
    print(f"[gateway] ctx signing HMAC-SHA256, upstream jwt {settings.jwt_alg}");
    uvicorn.run(app, host=settings.bind_host, port=settings.bind_port, log_level="warning");
    return 0;
}

with entry:__main__ {
    code = main();
    if code != 0 {
        sys.exit(code);
    }
}
