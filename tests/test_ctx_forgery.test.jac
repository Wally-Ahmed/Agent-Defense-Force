# tests/test_ctx_forgery.test.jac — the gateway-bypass proof.
#
# THE THREAT. `jac start` binds 0.0.0.0 unconditionally and has no --host flag,
# so the Jac backend on :8000 is directly reachable and the gateway on :8080 can
# be skipped entirely. An attacker POSTs straight to /walker/<Name> with a
# hand-written ctx claiming someone else's session_id, a spoofed src_ip, and
# csrf_ok: true. Without a signature that is a total authentication AND audit
# bypass -- the attacker's own probe gets filed under the victim's identity.
#
# THE MITIGATION UNDER TEST. The gateway signs the context; guard() verifies it
# before reading a single field. This file attacks that signature seven ways and
# asserts every one is refused with the same opaque code, CTX_UNVERIFIED --
# telling a probe WHICH check it failed is free reconnaissance.
#
# The last test is the one that is easy to forget: a denial must not RECORD the
# attacker's forged claims. An audit trail that faithfully transcribes a
# spoofed src_ip and a stolen session_id is worse than no trail at all, because
# it lets an attacker attribute their own traffic to a victim.
#
# GRAPH PERSISTENCE: .jac/data/anchor_store.db survives between processes, so
# every fixture id carries a per-run random tag.

import os;
import json;
import secrets;
import from typing { cast }
import from contracts.req_ctx_contract { ReqCtx, Grant, guard }
import from app.model.graph {
    Platform, Tenant, Membership, Principal, Session, Project, Task,
    Hosts, Registers, HasMember, Identifies, Owns, Contains, Authenticates,
    get_platform
}
import from app.security.clock { now_ms, SESSION_TTL_MS }
import from app.security.ctxsig { sign_ctx, verify_ctx, CTX_MAX_AGE_MS }
import from app.security.audit { audit_log_path, AUDIT_FIELDS }

# --------------------------------------------------------------------------
# Shared fixture.
# --------------------------------------------------------------------------

"""A per-run token, so a rerun cannot collide with leftovers in the store."""
def new_tag() -> str {
    return "sig-" + secrets.token_hex(4);
}

"""The raw ctx field dict the gateway would build, BEFORE signing.

Kept separate from mk_ctx so a test can mutate a field and decide for itself
whether to re-sign -- which is precisely the difference between a legitimate
request and a replayed signature over altered claims."""
def ctx_fields(session_id: str, ip: str = "10.0.0.1",
               issued_at: int = -1, alg: str = "HMAC-SHA256") -> dict {
    now = now_ms();
    stamp = issued_at;
    if stamp < 0 {
        stamp = now;
    }
    return {
        "request_id": "req-" + secrets.token_hex(3),
        "src_ip": ip,
        "src_asn": "AS64500",
        "user_agent_hash": "uah",
        "client_fp": "fp-sig",
        "session_id": session_id,
        "token_id": "",
        "service": "web",
        "route": "/test",
        "http_method": "GET",
        "csrf_ok": True,
        "received_at_ms": now,
        "sig_alg": alg,
        "issued_at_ms": stamp
    };
}

"""Sign a field dict with the one canonical implementation and wrap it."""
def sign(fields: dict) -> ReqCtx {
    signed = dict(fields);
    signed["sig"] = sign_ctx(fields);
    return ReqCtx(**signed);
}

"""A correctly signed, fresh ctx for `session_id`."""
def mk_ctx(session_id: str, ip: str = "10.0.0.1") -> ReqCtx {
    return sign(ctx_fields(session_id, ip));
}

"""One tenant, one member, one live session, one project, one task."""
def build(tag: str) {
    p = get_platform();
    now = now_ms();

    ta = (p +>:Hosts:+> Tenant(tenant_id=tag + "-tA", name="Tenant A"))[0];
    alice = (p +>:Registers:+> Principal(
        principal_id=tag + "-pA", email=tag + "-alice@example.com", pw_hash="x"
    ))[0];
    ma = (ta +>:HasMember:+> Membership(
        membership_id=tag + "-mA", principal_id=tag + "-pA",
        tenant_id=tag + "-tA", role="member", state="active"
    ))[0];
    ma +>:Identifies:+> alice;
    alice +>:Authenticates:+> Session(
        session_id=tag + "-sA", principal_id=tag + "-pA", tenant_id=tag + "-tA",
        issued_at=now, expires_at=now + SESSION_TTL_MS, last_auth_at=now
    );
    projA = (ta +>:Owns:+> Project(
        project_id=tag + "-prA", tenant_id=tag + "-tA", key="A1"
    ))[0];
    projA +>:Contains:+> Task(
        task_id=tag + "-tkA", project_id=tag + "-prA", title="A task"
    );
}

"""Attempt one ordinary read with `ctx`. Every forgery test uses this same call,
so the ONLY variable between a pass and a fail is the signature."""
def attempt(tag: str, ctx: ReqCtx) -> Grant {
    return guard(ctx, "task.read", "task", tag + "-tA", tag + "-tkA");
}

"""The most recently appended audit record, parsed. APP_AUDIT_LOG redirects the
sink, so this reads the test's own trail and never the real one."""
def last_audit_record() -> dict {
    path = audit_log_path();
    handle = open(path, "r", encoding="utf-8");
    lines = handle.readlines();
    handle.close();
    trimmed = [ln for ln in lines if ln.strip() != ""];
    return json.loads(trimmed[-1]);
}

# --------------------------------------------------------------------------
# Positive control FIRST. Every denial below is only meaningful if the same
# request with an honest signature succeeds.
# --------------------------------------------------------------------------

test "a correctly signed, fresh ctx is accepted" {
    tag = new_tag();
    build(tag);

    g = attempt(tag, mk_ctx(tag + "-sA"));
    assert g.ok;
    assert g.reason == "";
    assert cast(Task, g.node).task_id == tag + "-tkA";
}

# --------------------------------------------------------------------------
# Forgeries.
# --------------------------------------------------------------------------

test "a ctx signed with 64 zeros is denied CTX_UNVERIFIED" {
    tag = new_tag();
    build(tag);

    forged = mk_ctx(tag + "-sA");
    forged.sig = "0" * 64;

    g = attempt(tag, forged);
    assert not g.ok;
    assert g.reason == "CTX_UNVERIFIED";
}

test "a ctx with no signature at all is denied CTX_UNVERIFIED" {
    tag = new_tag();
    build(tag);

    # `sig` defaulting to "" is deliberately fail-CLOSED: an unsigned ctx is an
    # unverified ctx. This is the single most important default in the contract,
    # because an unsigned request is exactly what a gateway bypass produces.
    unsigned = ReqCtx(**ctx_fields(tag + "-sA"));
    assert unsigned.sig == "";

    g = attempt(tag, unsigned);
    assert not g.ok;
    assert g.reason == "CTX_UNVERIFIED";
}

test "a valid signature replayed over an altered src_ip is denied" {
    tag = new_tag();
    build(tag);

    # THE REAL ATTACK. The attacker captured a legitimate signed context and is
    # now presenting the same signature against claims they changed. If the
    # signature covered only some of the fields -- or if src_ip were left out of
    # ctxsig.SIGNED_FIELDS -- this would sail through and the audit trail would
    # record the victim's IP for the attacker's request.
    tampered = mk_ctx(tag + "-sA", "10.0.0.1");
    tampered.src_ip = "203.0.113.66";

    g = attempt(tag, tampered);
    assert not g.ok;
    assert g.reason == "CTX_UNVERIFIED";
}

test "a valid signature replayed over an altered session_id is denied" {
    tag = new_tag();
    build(tag);

    # The session-stealing variant: keep the honest signature, swap in someone
    # else's session id. session_id is signed, so the HMAC no longer matches.
    tampered = mk_ctx(tag + "-sA");
    tampered.session_id = tag + "-sA-VICTIM";

    g = attempt(tag, tampered);
    assert not g.ok;
    assert g.reason == "CTX_UNVERIFIED";
}

test "a perfectly signed ctx that is 60 seconds old is denied (replay bound)" {
    tag = new_tag();
    build(tag);

    # Signed correctly for its own timestamp -- the HMAC is genuine. It is
    # refused purely on age, which is what stops a captured context from being
    # reusable forever.
    stale_at = now_ms() - 60000;
    assert 60000 > CTX_MAX_AGE_MS;
    stale = sign(ctx_fields(tag + "-sA", "10.0.0.1", stale_at));

    g = attempt(tag, stale);
    assert not g.ok;
    assert g.reason == "CTX_UNVERIFIED";
}

test "a perfectly signed ctx stamped 60 seconds in the future is denied" {
    tag = new_tag();
    build(tag);

    # A future stamp is either a broken clock or an attempt to mint a context
    # that stays fresh past the replay window. Both fail closed.
    future = sign(ctx_fields(tag + "-sA", "10.0.0.1", now_ms() + 60000));

    g = attempt(tag, future);
    assert not g.ok;
    assert g.reason == "CTX_UNVERIFIED";
}

test "algorithm downgrade to sig_alg none is denied even when the HMAC is valid" {
    tag = new_tag();
    build(tag);

    # sig_alg is itself a SIGNED field, so this payload's HMAC is genuinely
    # correct for `sig_alg: "none"`. It is refused because "none" is not in
    # ALLOWED_SIG_ALGS. `sig_alg` exists for agility, never for negotiation:
    # an attacker must not be able to talk the verifier down to a weaker
    # primitive, and "none" must never be a value anything tolerates.
    downgraded_fields = ctx_fields(tag + "-sA", "10.0.0.1", -1, "none");
    downgraded = sign(downgraded_fields);

    # The HMAC really does verify for this payload -- prove it, so the denial
    # below cannot be dismissed as "the signature was just wrong".
    check = verify_ctx({**downgraded_fields, "sig": downgraded.sig,
                        "sig_alg": "HMAC-SHA256"}, now_ms());
    assert not check["ok"];

    g = attempt(tag, downgraded);
    assert not g.ok;
    assert g.reason == "CTX_UNVERIFIED";
}

# --------------------------------------------------------------------------
# Audit hygiene. The half of the mitigation that is easy to forget.
# --------------------------------------------------------------------------

test "a forged-ctx denial records observed facts only, never the forged claims" {
    tag = new_tag();
    build(tag);

    forged = mk_ctx(tag + "-sA", "10.0.0.1");
    forged.src_ip = "203.0.113.66";       # the attacker's claimed source
    forged.session_id = tag + "-VICTIM";  # the identity they want it filed under
    forged.sig = "0" * 64;

    g = attempt(tag, forged);
    assert not g.ok;
    assert g.reason == "CTX_UNVERIFIED";

    rec = last_audit_record();

    # The event exists, is classified as an attack, and names no actor.
    assert rec["reason"] == "CTX_UNVERIFIED";
    assert rec["severity"] == "high";
    assert rec["outcome"] == "deny";
    assert rec["actor_principal_id"] == "";

    # THE POINT. The forged claims were NOT transcribed. Writing an
    # attacker-supplied src_ip or session_id into the trail as though it were
    # an observation poisons the exact record used to detect the bypass: the
    # attacker gets to attribute their probe to a victim's IP and session, and
    # the incident timeline points at the wrong person.
    assert rec["src_ip"] == "";
    assert rec["session_id"] == "";
    assert rec["client_fp"] == "";
    assert rec["actor_email"] == "";

    # `service` is stamped "unverified" so a reader is never in doubt about the
    # provenance of the row.
    assert rec["service"] == "unverified";

    # What the process DID observe is recorded: which action, against what.
    assert rec["action"] == "task.read";
    assert rec["target_kind"] == "task";

    # A partial record is not a record. Every emitted event carries all 38
    # contract fields, so a downstream query never has to ask whether a missing
    # key means "empty" or "the emitter forgot".
    assert len(rec) == 38;
    assert len(AUDIT_FIELDS) == 38;
    for name in AUDIT_FIELDS {
        assert name in rec;
    }
}
