# app/security/reqctx.jac — rebuilding ReqCtx inside a walker.
#
# Walker `has` fields deserialize straight from the JSON request body, and only
# str/int/float/bool/list/dict survive that trip: a custom archetype silently
# degrades to `str` and the request dies with HTTP 422 (jfast_api.impl.jac:210).
# So every protected walker declares `has ctx: dict = {};` and rebuilds the
# object here.
#
# `ReqCtx(**payload)` cannot be called on the raw body directly -- an attacker
# adds one unknown key and the constructor raises TypeError, turning a clean
# CTX_UNVERIFIED denial into an unhandled 500 with no audit record. Filtering to
# the known field set first means junk is DROPPED rather than fatal, and the
# request proceeds to a proper, audited denial.

import from contracts.req_ctx_contract { ReqCtx }
import from app.security.ctxsig { SIGNED_FIELDS }

# Every ReqCtx field: the signed set plus the signature itself.
glob:pub CTX_FIELDS: list = SIGNED_FIELDS + ["sig"];

"""Rebuild a ReqCtx from a walker's raw `ctx` dict.

Unknown keys are dropped and missing keys fall back to their ReqCtx defaults,
which are fail-closed (`sig` defaults to "" -- an unsigned ctx). This function
does NOT verify anything; the result is untrusted until guard() checks the
signature."""
def:pub ctx_from(payload: dict) -> ReqCtx {
    filtered = {k: v for (k, v) in payload.items() if k in CTX_FIELDS};
    return ReqCtx(**filtered);
}
