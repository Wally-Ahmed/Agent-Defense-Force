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

# Minimum number of DISTINCT characters in the key material.
#
# WHY THIS EXISTS: a length check alone measures the wrong thing. `" " * 32`,
# `"a" * 32`, `"0" * 64` and `"ab" * 32` all clear a 32-byte bar while carrying
# somewhere between zero and one byte of actual entropy. They are not keys, they
# are strings of the right shape -- and they arrive by accident, from an operator
# holding down a character to "just get it started" or a fixture nobody revisited.
# A signing key that can be guessed in one attempt fails the ctx trust model just
# as completely as a signing key that is absent, so it has to fail just as loudly.
#
# The bar is deliberately crude: counting distinct characters is not an entropy
# estimate and does not pretend to be one. It is a floor that rejects degenerate
# input while staying far below anything a real key produces. `openssl rand -hex
# 32` yields ~16 distinct characters out of an alphabet of 16; a readable test key
# like "test-signing-key-for-unit-tests!" yields 14. Neither is close to the line.
# Nothing here upgrades a mediocre key into a good one -- it only refuses input
# that is provably not key material at all.
glob:pub MIN_DISTINCT_CHARS: int = 8;

"""Read a required secret from the environment or refuse to continue.

Generic on purpose: every required secret earns the same checks by going through
this one function, so a new secret cannot quietly get a weaker standard than the
ctx signing key.

Whitespace is stripped before the key is MEASURED but never before it is
RETURNED -- the caller gets the exact bytes the operator exported, so a key is
never silently rewritten into something the other side of the HMAC will not
reproduce. Measuring the whitespace-free core is what stops padding from being a
way to reach the length bar.

Raises RuntimeError -- never returns a default, never returns an empty string.
The messages name the failure without ever echoing the value: an error that
prints the key it rejected leaks it into logs, terminals and screen shares."""
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

    # All whitespace removed, not merely trimmed: interior padding is padding too.
    core = "".join(raw.split());

    if core == "" {
        raise RuntimeError(
            "FATAL: " + name + " is set but contains only whitespace. That is an "
            + "unset variable wearing a disguise -- almost always a quoting "
            + "mistake in a shell script or .env file. Refusing to start. "
            + "Generate a real one with "
            + "`python3 -c \"import secrets;print(secrets.token_hex(32))\"`."
        );
    }
    if len(core.encode("utf-8")) < min_len {
        raise RuntimeError(
            "FATAL: " + name + " has fewer than the required minimum of "
            + str(min_len) + " non-whitespace bytes. Refusing to start with a weak "
            + "key. Whitespace is not counted, so padding a short key out to "
            + "length will not satisfy this check -- the key itself must be "
            + str(min_len) + " bytes or longer."
        );
    }
    if len(set(core)) < MIN_DISTINCT_CHARS {
        raise RuntimeError(
            "FATAL: " + name + " is long enough but is built from fewer than "
            + str(MIN_DISTINCT_CHARS) + " distinct characters. A repeated or "
            + "single-character string is not key material no matter how long it "
            + "is -- it is guessable in roughly one attempt. Refusing to start. "
            + "Generate a real one with "
            + "`python3 -c \"import secrets;print(secrets.token_hex(32))\"`."
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
