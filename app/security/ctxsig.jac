# app/security/ctxsig.jac — the ctx trust boundary.
#
# WHY THIS FILE EXISTS. `jac start` binds 0.0.0.0 unconditionally and offers no
# --host flag (jfast_api.impl.jac:74, serve.core.impl.jac:251). The Jac backend
# on :8000 is therefore reachable directly and the gateway on :8080 can be
# skipped entirely. Without this module an attacker POSTs straight to
# /walker/<Name> with a hand-written ctx claiming someone else's session_id, a
# spoofed src_ip, and csrf_ok: true -- a total authentication and audit bypass.
# A firewall rule is not a mitigation: it is environment-specific, silently
# absent on a fresh clone, and invisible in code review.
#
# So the gateway SIGNS the context and guard() VERIFIES it before reading a
# single field. The gateway stops being the enforcement point and becomes just
# the signer; enforcement lives here, in the process that owns the data.
#
# CANONICALIZATION IS PART OF THE CONTRACT (contracts/req_ctx_contract.jac):
# the signed input is the JSON serialization of every ReqCtx field EXCEPT `sig`,
# with sort_keys=True, separators=(",", ":"), encoded UTF-8. Signer and verifier
# must produce byte-identical input. A mismatch here fails OPEN, which is the
# worst possible outcome, so the canonical form is built in exactly one place --
# `canonical_ctx_bytes` below -- and both sides call it.

import json;
import hmac;
import hashlib;
import from app.security.keys { ctx_signing_key }

# Every ReqCtx field except `sig`. Order is irrelevant to the output (sort_keys
# sorts it) but the SET is load-bearing: adding a field to ReqCtx without adding
# it here would leave that field unsigned and therefore attacker-controlled.
glob:pub SIGNED_FIELDS: list = [
    "request_id",
    "src_ip",
    "src_asn",
    "user_agent_hash",
    "client_fp",
    "session_id",
    "token_id",
    "service",
    "route",
    "http_method",
    "csrf_ok",
    "received_at_ms",
    "sig_alg",
    "issued_at_ms",
    # Step-up freshness. Signed like everything else: if this were left out of
    # the set, a client could claim a recent authentication and satisfy the
    # step-up check with an unsigned, attacker-chosen timestamp.
    "session_auth_at_ms"
];

# Replay bound. A captured-and-replayed ctx older than this is refused even if
# the signature is perfect.
glob:pub CTX_MAX_AGE_MS: int = 30000;

# Only algorithm we accept. `sig_alg` exists for agility, not for negotiation:
# an attacker must not be able to downgrade us by naming a weaker primitive,
# and "none" must never be a value we tolerate.
glob:pub ALLOWED_SIG_ALGS: list = ["HMAC-SHA256"];

"""Default value for a signed field, used to normalize a partially-populated
payload into the same canonical form the signer produced."""
def _default_for(name: str) -> object {
    if name == "csrf_ok" {
        return False;
    }
    if name in ["received_at_ms", "issued_at_ms", "session_auth_at_ms"] {
        # int, NOT "". A missing session_auth_at_ms must canonicalize to the
        # same `0` the gateway would have signed; defaulting it to the empty
        # string would serialize as `"session_auth_at_ms":""` and diverge from
        # the signer by one byte -- the exact fail-open this module exists to
        # prevent. 0 is also the fail-closed "unknown" sentinel guard() denies on.
        return 0;
    }
    if name == "sig_alg" {
        return "HMAC-SHA256";
    }
    return "";
}

"""The one canonical byte string both signer and verifier hash.

Takes a plain dict of ctx fields. Unknown keys are DROPPED and missing keys are
filled with their ReqCtx defaults, so the verifier reconstructs byte-identical
input from a payload that may carry extra junk. Dropping unknown keys also means
an attacker cannot perturb the canonical form by appending fields."""
def:pub canonical_ctx_bytes(fields: dict) -> bytes {
    canon: dict = {};
    for name in SIGNED_FIELDS {
        if name in fields {
            canon[name] = fields[name];
        } else {
            canon[name] = _default_for(name);
        }
    }
    return json.dumps(canon, sort_keys=True, separators=(",", ":")).encode("utf-8");
}

"""Produce the hex HMAC-SHA256 for a ctx payload. The gateway calls this.

Exposed so that the signer and the verifier can never drift: there is one
implementation of the signature, not two."""
def:pub sign_ctx(fields: dict) -> str {
    return hmac.new(ctx_signing_key(), canonical_ctx_bytes(fields), hashlib.sha256).hexdigest();
}

"""Verify a ctx payload's signature and freshness.

Returns a dict: {"ok": bool, "detail": str}. `detail` is for the operator log
only -- it is NEVER surfaced to the caller and never written into an audit
`reason`, because telling a probe WHICH check it failed is free reconnaissance.

Fails closed on every path:
  - `sig` empty or missing            -> unsigned, therefore unverified
  - `sig_alg` not in ALLOWED_SIG_ALGS -> refuses algorithm downgrade
  - HMAC mismatch                     -> compared with hmac.compare_digest,
                                         constant time, never `==`
  - issued_at_ms older than 30s       -> replay
  - issued_at_ms in the future        -> clock-skew forgery
  - signing key unavailable           -> the exception propagates; a process
                                         that cannot verify must not serve"""
def:pub verify_ctx(fields: dict, now_ms: int) -> dict {
    sig = fields.get("sig", "");
    if not isinstance(sig, str) or sig == "" {
        return {"ok": False, "detail": "ctx is unsigned"};
    }

    alg = fields.get("sig_alg", "");
    if alg not in ALLOWED_SIG_ALGS {
        return {"ok": False, "detail": "unsupported sig_alg"};
    }

    expected = sign_ctx(fields);

    # Constant time. `==` on a hex digest leaks the length of the matching
    # prefix through timing and is how signature oracles get built.
    if not hmac.compare_digest(expected, sig) {
        return {"ok": False, "detail": "hmac mismatch"};
    }

    issued = fields.get("issued_at_ms", 0);
    if not isinstance(issued, int) or isinstance(issued, bool) {
        return {"ok": False, "detail": "issued_at_ms not an int"};
    }
    age = now_ms - issued;
    if age > CTX_MAX_AGE_MS {
        return {"ok": False, "detail": "ctx expired"};
    }
    # A ctx stamped in the future is either a broken clock or a forgery. One
    # second of tolerance absorbs NTP jitter between gateway and backend.
    if age < -1000 {
        return {"ok": False, "detail": "ctx issued in the future"};
    }

    return {"ok": True, "detail": ""};
}

"""SHA-256 of a value, hex, truncated. Used for user-agent and client
fingerprints, and for invite tokens -- never for passwords, which use bcrypt."""
def:pub sha256_hex(value: str, width: int = 64) -> str {
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:width];
}
