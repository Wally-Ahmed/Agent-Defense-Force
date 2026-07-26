# Spikes — verified framework behavior

Two time-boxed spikes run at 14:00 PDT to retire the largest Jac unknowns before
eleven tracks built on top of them. Every claim here was observed, not inferred.

## Spike 1 — structured context into a walker

**`has ctx: dict` works.** Nested objects, bools, and lists survive intact, and
`ReqCtx(**ctx)` reconstruction inside the walker works.

**`has ctx: ReqCtx` does NOT work** — HTTP 422. `jfast_api.impl.jac:210` silently
degrades any non-whitelisted type to `str`. Only `str/int/float/bool/list/dict`
are safe as walker `has` field types.

→ Every protected walker declares `has ctx: dict = {};` and rebuilds internally.

## Spike 2 — Jac ASGI gateway

**Works.** A Jac file can import starlette/uvicorn, subclass `BaseHTTPMiddleware`,
and see cookies, headers, and `client.host` — exactly what walkers cannot. No
Python fallback needed.

## The constraint that shaped the security design

`jac start` has **no `--host` flag** and binds `0.0.0.0` unconditionally
(`jfast_api.impl.jac:74`, `serve.core.impl.jac:251`). The backend on :8000 is
therefore directly reachable and the gateway can be bypassed.

A bypassing client could POST straight to `/walker/<Name>` with a hand-written
`ctx` claiming `csrf_ok: true`, someone else's `session_id`, and a spoofed
`src_ip` — a full authentication and audit bypass.

**A firewall rule is not an acceptable mitigation**: environment-specific,
silently absent on a fresh clone, invisible in code review. Instead the injected
context is **HMAC-signed** by the gateway and verified by `guard()` in
constant time before any field is trusted. See `contracts/req_ctx_contract.jac`.

## Also confirmed

- `jac start` serves `/walker/<Name>`; auth is `Authorization: Bearer <jwt>` from
  `/user/login`. Priv walker returns 401 without a token.
- jac-scale's default CORS really is `allow_origins=['*']` with
  `allow_credentials=True` (`serve.core.impl.jac:60-66`) — we override it.
- `bcrypt` 4.3.0 is importable from the jac tool venv.
- `jac check` prints a misleading "1 failed" banner while exiting 0. Trust the
  exit code, not the banner.

## Not observed (do not assume)

- `jac start --scale` was never exercised.
- The auth flow was verified with a throwaway loopback user only.
