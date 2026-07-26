"""Minimal stand-in for the Jac application upstream — STUB, NOT THE APP.

WHY THIS EXISTS. The application track (walkers + guard()) has not landed, but
the single most important property of this design cannot be demonstrated without
an upstream: that a forged `ctx` POSTed straight to :8000, bypassing the gateway,
is REJECTED. `jac start` binds 0.0.0.0 unconditionally and has no --host flag
(jfast_api.impl.jac:74), so that bypass is always reachable and the HMAC is the
only thing standing in its way.

WHAT IT IMPLEMENTS. Exactly the shape `jac start` exposes — POST /walker/<Name>
returning {"status": int, "reports": [payload]} — plus the verification half of
contracts/req_ctx_contract.jac: verify ctx.sig with hmac.compare_digest BEFORE
trusting any field, deny CTX_UNVERIFIED on failure, and record only OBSERVED
transport facts on that denial, never the claimed ones.

HOW TO SWAP IT OUT. Delete this file and run the real `jac start`. The gateway
needs no change: it already posts to /walker/<Walker> with the walker's flat
`has` fields plus a top-level signed `ctx`. The only requirement on the real app
is that guard() calls `verify_ctx` from gateway/ctxsig.jac (or reproduces its
canonicalization byte for byte) before reading a single field of ctx.

    jac run gateway/upstream_stub.jac
"""

import os;
import sys;
import time;
import uvicorn;
import from typing { Any }
import from starlette.applications { Starlette }
import from starlette.routing { Route }
import from starlette.responses { JSONResponse }
import from ctxsig { verify_ctx }
import from config { require_env, env_str, env_int }

glob STUB_STATE: dict = {};

"""Fixture principals the stub authenticates. Passwords come from the
environment; there is no hard-coded credential in this file."""
def _fixture_users -> dict {
    pw = env_str("STUB_LOGIN_PASSWORD", "");
    if not pw {
        return {};
    }
    return {
        "lena.hart@globex.test": {
            "password": pw, "principal_id": "u_lh_1001",
            "tenant_id": "t_globex", "role": "owner"
        }
    };
}

"""Handle POST /walker/<name> exactly as jac start would shape it."""
async def walker(request: Any) -> Any {
    name = request.path_params.get("name", "");
    key = STUB_STATE["key"];
    observed_ip = "";
    if request.client {
        observed_ip = str(request.client.host);
    }

    try {
        body = await request.json();
    } except Exception {
        body = {};
    }
    if not isinstance(body, dict) {
        body = {};
    }

    ctx = body.get("ctx");
    now = int(time.time() * 1000);

    # THE TRUST BOUNDARY. Nothing below this block may read a field of ctx until
    # the signature has verified.
    result = verify_ctx(ctx, key, now);
    if not result["ok"] {
        # Only OBSERVED facts are recorded — never the claimed src_ip,
        # session_id, or csrf_ok from an unverified payload (contracts/vocab.md).
        print(
            f"[upstream] DENY CTX_UNVERIFIED walker={name} "
            + f"observed_src_ip={observed_ip} detail={result['detail']}",
            file=sys.stderr
        );
        return JSONResponse(
            {"status": 401, "reports": [{
                "error": {"code": "CTX_UNVERIFIED", "message": "Unauthenticated.", "request_id": ""}
            }]},
            status_code=401
        );
    }

    # From here the ctx is trusted.
    if name == "LoginUser" {
        users = _fixture_users();
        email = str(body.get("email", ""));
        password = str(body.get("password", ""));
        user = users.get(email);
        if user is None or user["password"] != password {
            return JSONResponse({"status": 401, "reports": [{
                "error": {"code": "NO_SESSION", "message": "Invalid email or password.", "request_id": ""}
            }]}, status_code=401);
        }
        return JSONResponse({"status": 200, "reports": [{
            "principal_id": user["principal_id"],
            "tenant_id": user["tenant_id"],
            "role": user["role"]
        }]}, status_code=200);
    }

    echo: dict = {};
    for k in body.keys() {
        if k != "ctx" {
            echo[k] = body[k];
        }
    }
    return JSONResponse({"status": 200, "reports": [{
        "walker": name,
        "ctx_verified": True,
        "ctx_seen": ctx,
        "fields_seen": echo
    }]}, status_code=200);
}

"""Build the stub ASGI app. Requires APP_CTX_SIGNING_KEY, like the real app."""
def build_stub -> Any {
    STUB_STATE["key"] = require_env("APP_CTX_SIGNING_KEY");
    return Starlette(routes=[Route("/walker/{name}", walker, methods=["POST"])]);
}

with entry:__main__ {
    app = build_stub();
    port = env_int("STUB_PORT", 8000);
    print(f"[upstream] stub listening on 127.0.0.1:{port}");
    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning");
}
