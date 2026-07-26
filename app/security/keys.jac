# app/security/keys.jac — secret material, loaded from the environment, once.
#
# THE STARTUP CONTRACT: if APP_CTX_SIGNING_KEY is not in the environment, this
# module raises at import time and the application does not start. There is no
# default key, no generated-on-first-run key, no DEBUG escape, no dev-mode
# bypass, and no commented-out fallback. A signing key that can be absent is a
# signing key that can be guessed, and the whole ctx trust model rests on it.
#
# This is deliberately the loudest failure in the codebase.

import os;

# Minimum key length. A 16-byte key is not a rounding error away from
# brute-forcible, it is the difference between a real HMAC and a costume.
glob:pub MIN_KEY_BYTES: int = 32;

"""Read a required secret from the environment or refuse to continue.

Raises RuntimeError -- never returns a default, never returns an empty string."""
def require_env(name: str, min_len: int = 1) -> str {
    raw = os.environ.get(name, "");
    if raw == "" {
        raise RuntimeError(
            "FATAL: " + name + " is not set. This application refuses to start "
            + "without it. There is no default and no dev-mode bypass -- generate "
            + "one with `python3 -c \"import secrets;print(secrets.token_hex(32))\"` "
            + "and export " + name + " before starting."
        );
    }
    if len(raw.encode("utf-8")) < min_len {
        raise RuntimeError(
            "FATAL: " + name + " is shorter than the required minimum of "
            + str(min_len) + " bytes. Refusing to start with a weak key."
        );
    }
    return raw;
}

"""The HMAC key guard() verifies every ReqCtx signature against.

Read fresh from the environment on every call rather than cached in a global,
so that a test (or an operator rotating the key) never finds itself talking to
a stale copy captured at import time. The cost is one dict lookup per request."""
def:pub ctx_signing_key() -> bytes {
    return require_env("APP_CTX_SIGNING_KEY", MIN_KEY_BYTES).encode("utf-8");
}

# Import-time enforcement. Importing anything under app/security/ transitively
# imports this module, so the whole application inherits the refusal to start.
with entry {
    require_env("APP_CTX_SIGNING_KEY", MIN_KEY_BYTES);
}
