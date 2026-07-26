"""Cross-implementation proof: the gateway's signer and the app's verifier agree.

    PYTHONPATH=. APP_CTX_SIGNING_KEY=... jac run gateway/tests/crossverify.jac

(PYTHONPATH=. is required from the repo root so that both `gateway.*` and
`app.security.*` resolve as packages.)

contracts/req_ctx_contract.jac rule 1 warns that a canonicalization mismatch
between signer (T1) and verifier (T2) FAILS OPEN — the worst possible outcome —
and that both must produce BYTE-IDENTICAL input. Two independent implementations
now exist: gateway/ctxsig.jac and app/security/ctxsig.jac. This asserts they are
interchangeable in both directions, so the drift the contract warns about is
caught here rather than in production.
"""

import os;
import sys;
import time;
import from gateway.ctxsig {
    signed_ctx as gw_signed_ctx,
    sign_ctx as gw_sign,
    canonical_bytes as gw_canon,
    verify_ctx as gw_verify,
    SIGNED_FIELDS as gw_signed
}
import from app.security.ctxsig {
    sign_ctx as app_sign,
    canonical_ctx_bytes as app_canon,
    verify_ctx as app_verify,
    SIGNED_FIELDS as app_signed
}

glob FAILURES: list = [];

"""Assert and record."""
def check(label: str, cond: bool) -> None {
    if cond {
        print(f"  PASS  {label}");
    } else {
        print(f"  FAIL  {label}");
        FAILURES.append(label);
    }
}

with entry:__main__ {
    key = os.environ.get("APP_CTX_SIGNING_KEY", "");
    if not key {
        print("APP_CTX_SIGNING_KEY must be set", file=sys.stderr);
        sys.exit(2);
    }
    now = int(time.time() * 1000);
    base = {
        "request_id": "abc123def4567890",
        "src_ip": "198.51.100.11",
        "src_asn": "AS64496",
        "user_agent_hash": "7e1a94c05b2d63f8",
        "client_fp": "ecefe37b9e250d03",
        "session_id": "sess_b00_b5ba888417a5",
        "token_id": "",
        "service": "web",
        "route": "/tenants/{tenant_id}/projects",
        "http_method": "POST",
        "csrf_ok": True,
        "received_at_ms": now,
        "sig_alg": "HMAC-SHA256",
        "issued_at_ms": now,
        # Step-up freshness. A SIGNED field, so it is part of the canonical
        # bytes both sides must agree on byte-for-byte.
        "session_auth_at_ms": now - 60000
    };

    print("=== canonical form ===");
    a = gw_canon(base);
    b = app_canon(base);
    check("canonical bytes are byte-identical", a == b);
    print(f"    gateway: {a[:88]}...");
    print(f"    app    : {b[:88]}...");

    print("=== signatures ===");
    sg = gw_sign(base, key);
    sa = app_sign(base);
    check("HMAC digests match", sg == sa);
    print(f"    gateway: {sg}");
    print(f"    app    : {sa}");

    print("=== gateway signs -> app verifies ===");
    ctx = gw_signed_ctx(base, key);
    r1 = app_verify(ctx, now);
    check("app accepts a gateway-signed ctx", r1["ok"]);

    print("=== app signs -> gateway verifies ===");
    ctx2 = dict(base);
    ctx2["sig"] = app_sign(base);
    r2 = gw_verify(ctx2, key, now);
    check("gateway accepts an app-signed ctx", r2["ok"]);

    print("=== both reject the same forgeries ===");
    tampered = dict(ctx);
    tampered["src_ip"] = "10.6.6.6";
    check("both reject a tampered src_ip",
          (not app_verify(tampered, now)["ok"]) and (not gw_verify(tampered, key, now)["ok"]));

    unsigned = dict(ctx);
    unsigned["sig"] = "";
    check("both reject an unsigned ctx",
          (not app_verify(unsigned, now)["ok"]) and (not gw_verify(unsigned, key, now)["ok"]));

    check("both reject a ctx older than 30s",
          (not app_verify(ctx, now + 31000)["ok"]) and (not gw_verify(ctx, key, now + 31000)["ok"]));

    bad_alg = gw_signed_ctx({**base, "sig_alg": "none"}, key);
    check("both reject sig_alg downgrade",
          (not app_verify(bad_alg, now)["ok"]) and (not gw_verify(bad_alg, key, now)["ok"]));

    # The whole point of adding session_auth_at_ms to the SIGNED set: an
    # attacker who could rewrite it in flight would manufacture step-up
    # freshness and walk straight through the REAUTH_REQUIRED gate. Flipping it
    # on an otherwise-valid, correctly-signed ctx must invalidate the HMAC on
    # BOTH sides.
    forged_freshness = dict(ctx);
    forged_freshness["session_auth_at_ms"] = now;
    check("both reject a forged session_auth_at_ms",
          (not app_verify(forged_freshness, now)["ok"])
          and (not gw_verify(forged_freshness, key, now)["ok"]));

    # Field-set drift is the failure the contract calls out as fail-open. If one
    # side ever stops signing a field the other signs, this catches it here.
    check("both sides sign the same field SET",
          sorted(gw_signed) == sorted(app_signed));
    print(f"    signed fields ({len(gw_signed)}): {sorted(gw_signed)}");

    if FAILURES {
        print(f"\n{len(FAILURES)} FAILED: {FAILURES}");
        sys.exit(1);
    }
    print("\nALL CROSS-IMPLEMENTATION CHECKS PASSED");
}
