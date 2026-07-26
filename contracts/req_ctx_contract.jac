# FROZEN CONTRACT — do not edit without conductor approval. Consumed by: T1 gateway, T2 guard/authz, T3 domain walkers, T5 responder/containment
#
# ============================ CRITICAL — READ THIS ============================
# Walkers receive `has ctx: dict` — a PLAIN DICT, because Jac walker `has` fields
# deserialize from the JSON request body. guard() constructs ReqCtx(**ctx)
# internally.
#
#   DO NOT type a walker's `has ctx` as ReqCtx.
#
#   CORRECT:   walker CreateProject { has ctx: dict = {}; ... }
#   WRONG:     walker CreateProject { has ctx: ReqCtx; ... }
#
# =============================================================================
#
# SAFE WALKER `has` FIELD TYPES: only str / int / float / bool / list / dict
# survive request deserialization. A custom archetype used as a walker `has` type
# silently degrades to `str` and the request fails with HTTP 422
# (jfast_api.impl.jac:210). This is the mechanical reason ctx is a dict: walkers
# declare `has ctx: dict = {};` and rebuild `ReqCtx(**ctx)` internally.
#
# IMPORT AS:
#   import from contracts.req_ctx_contract { ReqCtx, Grant, guard }
#
# The mandated path `contracts/req_ctx_contract.jac` is a SYMLINK ALIAS to this
# file — a filename containing a dot is not importable in Jac. Always import the
# undotted name.
#
# ================== TRUST MODEL — ctx IS NOT TRUSTED INPUT ===================
# THREAT: `jac start` cannot be bound to loopback — the bind address is hardcoded
# 0.0.0.0 (jfast_api.impl.jac:74; serve.core.impl.jac:251 passes only a port, and
# no --host flag exists). The Jac backend on :8000 is therefore directly reachable
# and the gateway on :8080 can be bypassed entirely. An attacker POSTs straight to
# /walker/<Name> with a hand-written ctx claiming `csrf_ok: true`, someone else's
# `session_id`, and a spoofed `src_ip` — a full authentication and audit bypass.
# A firewall rule is NOT an acceptable mitigation: it is environment-specific,
# silently absent on a fresh clone, and invisible in code review.
#
# MITIGATION: the injected context is cryptographically verifiable. The gateway
# (T1) signs it; guard() (T2) verifies it. Both MUST honor these rules:
#
# 1. CANONICALIZATION IS PART OF THE CONTRACT. The signed input is the JSON
#    serialization of every ReqCtx field EXCEPT `sig`, with sort_keys=True,
#    separators=(',',':'), encoded UTF-8. Signer and verifier must produce
#    BYTE-IDENTICAL input. A mismatch here fails open — the worst outcome — so do
#    not improvise the encoding.
#
# 2. guard() MUST VERIFY `sig` BEFORE TRUSTING ANY FIELD OF ctx. Compare with
#    hmac.compare_digest (constant-time). NEVER use `==`.
#
# 3. Verification failure, missing signature, or `issued_at_ms` older than 30
#    SECONDS ⇒ the request is FULLY UNAUTHENTICATED. Deny with reason code
#    CTX_UNVERIFIED and emit the audit event with actor_principal_id "" and the
#    OBSERVED transport facts only — never the claimed ones.
#
# 4. The key is read from the environment variable APP_CTX_SIGNING_KEY. It is
#    never hard-coded and never committed.
#
# 5. NO BYPASS OF ANY KIND. No debug flag, no `if not sig and DEV_MODE` escape
#    hatch, no default key. If APP_CTX_SIGNING_KEY is absent from the environment
#    the app MUST REFUSE TO START, loudly. A dev-mode bypass is exactly the
#    backdoor this design proves does not exist.
# =============================================================================
#
# NOTE ON DEFAULTS: every field carries a default so that ReqCtx(**ctx) tolerates
# a partially-populated gateway payload instead of raising TypeError. Field ORDER
# is exactly as specified. Treat defaults as "unset" sentinels — the gateway is
# expected to inject every field. `sig` defaulting to "" is deliberately
# FAIL-CLOSED: an unsigned ctx is an unverified ctx and must be denied.

# What the gateway injects on every request. NOT trusted until `sig` verifies.
obj ReqCtx {
    has request_id: str = "";
    has src_ip: str = "";
    has src_asn: str = "";
    has user_agent_hash: str = "";
    has client_fp: str = "";
    has session_id: str = "";
    has token_id: str = "";
    has service: str = "";
    has route: str = "";
    has http_method: str = "";
    has csrf_ok: bool = False;
    has received_at_ms: int = 0;

    # --- context signature (appended; field order above is unchanged) ---
    # HMAC-SHA256 over the canonical JSON of every field above + sig_alg +
    # issued_at_ms (i.e. every ReqCtx field except `sig`), keyed by the
    # APP_CTX_SIGNING_KEY environment variable. "" means UNSIGNED ⇒ deny
    # CTX_UNVERIFIED. Verify with hmac.compare_digest, never `==`.
    has sig: str = "";
    has sig_alg: str = "HMAC-SHA256";     # algorithm agility
    has issued_at_ms: int = 0;            # replay bound — reject if older than 30s
}

# The authorization decision returned by guard().
#
# NOTE ON `object`: tenant / principal / membership / node are opaque node handles,
# typed `object` as frozen. Jac's checker rejects direct attribute access on an
# `object` (error[E1030]) and rejects narrowing it by annotated assignment
# (error[E1001]). To read fields off them in consumer code, use typing.cast:
#
#   import from typing { cast }
#   t = cast(Tenant, grant.tenant).tenant_id;
#
# `getattr(grant.tenant, "tenant_id")` also type-checks if you prefer it.
obj Grant {
    has ok: bool = False;
    has reason: str = "";                 # deny reason CODE from DENY_REASONS, "" when ok
    has tenant: object = None;
    has principal: object = None;
    has membership: object = None;
    has node: object = None;
}

# The signature every track must call. Track T2 implements it; this is the
# declaration only. Exactly one AuditEvent is emitted per guard() call.
def guard(ctx: ReqCtx, action: str, target_kind: str, tenant_id: str, target_id: str = "") -> Grant;
