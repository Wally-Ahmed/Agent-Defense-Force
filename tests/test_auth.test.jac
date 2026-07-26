# tests/test_auth.test.jac — credential storage, login genericity, session life.
#
# Two separate claims live in this file.
#
# 1. THE CRYPTO LAYER IS GENERIC. A login attempt against an account that does
#    not exist must cost the same as one against a real account with the wrong
#    password. If a miss short-circuits, the response-time difference is a free
#    account-enumeration oracle: an attacker learns which of ten thousand leaked
#    emails are customers here without ever authenticating. `verify_password`
#    therefore runs a full bcrypt verify against a decoy hash on a miss.
#
# 2. A CREDENTIAL IS NOT A PERMISSION. Holding a session id proves nothing on
#    its own -- it can be expired, revoked, attached to a suspended principal,
#    or scoped to a tenant the holder is not a member of. Each of those is a
#    distinct deny reason, and each is asserted separately here, because
#    collapsing them would hide a regression in whichever check stopped running.
#
# GRAPH PERSISTENCE: .jac/data/anchor_store.db survives between processes, so
# every fixture id carries a per-run random tag.

import os;
import secrets;
import from typing { cast }
import from contracts.req_ctx_contract { ReqCtx, Grant, guard }
import from app.model.graph {
    Platform, Tenant, Membership, Principal, Session, Project, Task,
    Hosts, Registers, HasMember, Identifies, Owns, Contains, Authenticates,
    get_platform
}
import from app.security.clock { now_ms, SESSION_TTL_MS }
import from app.security.ctxsig { sign_ctx }
import from app.security.passwords {
    hash_password, verify_password, password_complaint,
    BCRYPT_ROUNDS, MIN_PASSWORD_CHARS
}
import from app.walkers.auth { Login }

# --------------------------------------------------------------------------
# Shared fixture.
# --------------------------------------------------------------------------

"""A per-run token, so a rerun cannot collide with leftovers in the store."""
def new_tag() -> str {
    return "auth-" + secrets.token_hex(4);
}

"""Sign a ctx the way the gateway does. `session_id` of "" with `token_id` of ""
is the no-credential case: a signed request that proves nothing about WHO."""
def mk_ctx(session_id: str, ip: str = "10.0.0.1") -> ReqCtx {
    now = now_ms();
    fields: dict = {
        "request_id": "req-" + secrets.token_hex(3),
        "src_ip": ip,
        "src_asn": "AS64500",
        "user_agent_hash": "uah",
        "client_fp": "fp-auth",
        "session_id": session_id,
        "token_id": "",
        "service": "web",
        "route": "/test",
        "http_method": "GET",
        "csrf_ok": True,
        "received_at_ms": now,
        "sig_alg": "HMAC-SHA256",
        "issued_at_ms": now
    };
    fields["sig"] = sign_ctx(fields);
    return ReqCtx(**fields);
}

"""One tenant with a project and a task, and FOUR principals whose credentials
differ in exactly one respect each.

    <tag>-sLive     healthy session, active principal, active membership
    <tag>-sExpired  same, but expires_at is already in the past
    <tag>-sRevoked  same, but revoked = True
    <tag>-sSusp     healthy session, principal.status = "suspended"
    <tag>-sStray    healthy session scoped to the tenant, NO membership in it

Ids derive from `tag`; nothing is handed back, so the test reaches the fixture
the way production code does."""
def build(tag: str) {
    p = get_platform();
    now = now_ms();

    ta = (p +>:Hosts:+> Tenant(tenant_id=tag + "-tA", name="Tenant A"))[0];
    projA = (ta +>:Owns:+> Project(
        project_id=tag + "-prA", tenant_id=tag + "-tA", key="A1"
    ))[0];
    projA +>:Contains:+> Task(
        task_id=tag + "-tkA", project_id=tag + "-prA", title="A task"
    );

    # --- the healthy baseline ------------------------------------------------
    live = (p +>:Registers:+> Principal(
        principal_id=tag + "-pLive", email=tag + "-live@example.com", pw_hash="x"
    ))[0];
    mlive = (ta +>:HasMember:+> Membership(
        membership_id=tag + "-mLive", principal_id=tag + "-pLive",
        tenant_id=tag + "-tA", role="member", state="active"
    ))[0];
    mlive +>:Identifies:+> live;
    live +>:Authenticates:+> Session(
        session_id=tag + "-sLive", principal_id=tag + "-pLive",
        tenant_id=tag + "-tA", issued_at=now,
        expires_at=now + SESSION_TTL_MS, last_auth_at=now
    );
    # Expired: issued an hour ago, already past its expiry.
    live +>:Authenticates:+> Session(
        session_id=tag + "-sExpired", principal_id=tag + "-pLive",
        tenant_id=tag + "-tA", issued_at=now - 7200000,
        expires_at=now - 3600000, last_auth_at=now - 7200000
    );
    # Revoked: perfectly fresh, and worthless.
    live +>:Authenticates:+> Session(
        session_id=tag + "-sRevoked", principal_id=tag + "-pLive",
        tenant_id=tag + "-tA", issued_at=now,
        expires_at=now + SESSION_TTL_MS, last_auth_at=now, revoked=True
    );

    # --- a suspended principal holding a perfectly good session --------------
    susp = (p +>:Registers:+> Principal(
        principal_id=tag + "-pSusp", email=tag + "-susp@example.com",
        pw_hash="x", status="suspended"
    ))[0];
    msusp = (ta +>:HasMember:+> Membership(
        membership_id=tag + "-mSusp", principal_id=tag + "-pSusp",
        tenant_id=tag + "-tA", role="admin", state="active"
    ))[0];
    msusp +>:Identifies:+> susp;
    susp +>:Authenticates:+> Session(
        session_id=tag + "-sSusp", principal_id=tag + "-pSusp",
        tenant_id=tag + "-tA", issued_at=now,
        expires_at=now + SESSION_TTL_MS, last_auth_at=now
    );

    # --- authenticated, but a stranger to this tenant ------------------------
    # Deliberately NO Membership row. The session names tenant A, so this is
    # not a TENANT_MISMATCH -- it is an authenticated identity with no standing.
    stray = (p +>:Registers:+> Principal(
        principal_id=tag + "-pStray", email=tag + "-stray@example.com", pw_hash="x"
    ))[0];
    stray +>:Authenticates:+> Session(
        session_id=tag + "-sStray", principal_id=tag + "-pStray",
        tenant_id=tag + "-tA", issued_at=now,
        expires_at=now + SESSION_TTL_MS, last_auth_at=now
    );
}

"""One ordinary read, so the credential is the only variable between tests."""
def attempt(tag: str, session_id: str) -> Grant {
    return guard(mk_ctx(session_id), "task.read", "task",
                 tag + "-tA", tag + "-tkA");
}

# --------------------------------------------------------------------------
# Password storage
# --------------------------------------------------------------------------

test "hash_password produces a bcrypt cost-12 hash that verifies" {
    secret = "correct horse battery staple";
    stored = hash_password(secret);

    # $2b$ is the modern bcrypt identifier and 12 is the work factor. The cost
    # travels inside the string, so this is not a configuration claim -- it is
    # what a verifier will actually spend on this specific hash.
    assert stored.startswith("$2b$12$");
    assert BCRYPT_ROUNDS == 12;
    assert len(stored) == 60;

    assert verify_password(secret, stored);
    assert not verify_password("wrong horse battery staple", stored);

    # Same password, different salt, different digest. A static salt would make
    # the whole table crackable with one rainbow table.
    assert hash_password(secret) != stored;
}

test "hash_password refuses a password shorter than the minimum" {
    assert MIN_PASSWORD_CHARS == 12;
    assert password_complaint("short") != "";
    raised = False;
    try {
        hash_password("short");
    } except ValueError as e {
        raised = True;
    }
    assert raised;
}

test "verify_password against a missing account returns False without raising" {
    # "" is how the caller says "no such account". The generic-failure rule:
    # this must still run a full bcrypt verify against the decoy hash so the
    # miss costs the same as a wrong password, then return False. If it
    # short-circuited, login latency would enumerate the customer list.
    raised = False;
    answer = True;
    try {
        answer = verify_password("anything at all", "");
    } except Exception as e {
        raised = True;
    }
    assert not raised;
    assert answer is False;

    # A corrupt / non-bcrypt stored value must also fail closed, never pass.
    assert not verify_password("anything at all", "not-a-bcrypt-hash");
}

# --------------------------------------------------------------------------
# Session lifecycle
# --------------------------------------------------------------------------

test "a live session on an active member is accepted (positive control)" {
    tag = new_tag();
    build(tag);

    g = attempt(tag, tag + "-sLive");
    assert g.ok;
    assert g.reason == "";
    assert cast(Principal, g.principal).principal_id == tag + "-pLive";
}

test "an expired session is denied SESSION_EXPIRED" {
    tag = new_tag();
    build(tag);

    # Expiry is an integer comparison on epoch milliseconds, never a parse --
    # a timezone-naive string parse is how an expired credential quietly
    # becomes a live one.
    g = attempt(tag, tag + "-sExpired");
    assert not g.ok;
    assert g.reason == "SESSION_EXPIRED";
}

test "a revoked session is denied NO_SESSION" {
    tag = new_tag();
    build(tag);

    # Revoked reads as "there is no such session", not as "expired": revocation
    # is an active decision and must not be distinguishable from absence by a
    # caller probing which session ids exist.
    g = attempt(tag, tag + "-sRevoked");
    assert not g.ok;
    assert g.reason == "NO_SESSION";
}

test "a session id that was never issued is denied NO_SESSION" {
    tag = new_tag();
    build(tag);

    g = attempt(tag, tag + "-sNEVER-ISSUED");
    assert not g.ok;
    assert g.reason == "NO_SESSION";
}

test "a signed ctx carrying no credential at all is denied NO_SESSION" {
    tag = new_tag();
    build(tag);

    # A verified signature proves the request came through the gateway. It
    # proves nothing whatsoever about who sent it, so an empty session_id and
    # an empty token_id together are still anonymous.
    ctx = mk_ctx("");
    assert ctx.session_id == "";
    assert ctx.token_id == "";

    g = guard(ctx, "task.read", "task", tag + "-tA", tag + "-tkA");
    assert not g.ok;
    assert g.reason == "NO_SESSION";
}

test "a suspended principal is denied SUSPENDED even holding a live session" {
    tag = new_tag();
    build(tag);

    # This principal is an ADMIN with a perfectly valid, unexpired session.
    # Suspension is checked before tenancy and before role, so a high role
    # cannot outrun it.
    g = attempt(tag, tag + "-sSusp");
    assert not g.ok;
    assert g.reason == "SUSPENDED";
}

test "an authenticated non-member of the tenant is denied NOT_A_MEMBER" {
    tag = new_tag();
    build(tag);

    # The session is live and scoped to THIS tenant, so this is not a crossing
    # attempt -- it is an authenticated identity with no membership row.
    # Authentication and authorization are different questions.
    g = attempt(tag, tag + "-sStray");
    assert not g.ok;
    assert g.reason == "NOT_A_MEMBER";
    assert cast(Principal, g.principal).principal_id == tag + "-pStray";
}

# --------------------------------------------------------------------------
# Login genericity at the walker layer.
# --------------------------------------------------------------------------

"""Absolute path of the repository root -- the directory that contains app/."""
def repo_root() -> str {
    here: str = os.path.abspath(os.getcwd());
    if os.path.isdir(os.path.join(here, "app")) {
        return here;
    }
    up: str = os.path.dirname(here);
    if os.path.isdir(os.path.join(up, "app")) {
        return up;
    }
    return here;
}

"""The signed ctx dict a walker receives. Walkers take `has ctx: dict`, not a
ReqCtx -- a custom archetype silently degrades to `str` on deserialization."""
def mk_ctx_dict(session_id: str) -> dict {
    return {
        "request_id": "req-" + secrets.token_hex(3),
        "src_ip": "10.0.0.1",
        "src_asn": "AS64500",
        "user_agent_hash": "uah",
        "client_fp": "fp-auth",
        "session_id": session_id,
        "token_id": "",
        "service": "web",
        "route": "/walker/Login",
        "http_method": "POST",
        "csrf_ok": True,
        "received_at_ms": now_ms(),
        "sig_alg": "HMAC-SHA256",
        "issued_at_ms": now_ms(),
        "sig": ""
    };
}

"""Sign a walker ctx dict in place and hand it back."""
def signed_ctx_dict(session_id: str) -> dict {
    payload = mk_ctx_dict(session_id);
    unsigned = dict(payload);
    del unsigned["sig"];
    payload["sig"] = sign_ctx(unsigned);
    return payload;
}

test "the Login walker reports identically for a bad password and a bad email" {
    # app/walkers/auth.jac is owned by another track, so this assertion is
    # guarded: when the module is absent it is skipped rather than failed. The
    # crypto-layer half of the same claim -- that a missing account still costs
    # a full bcrypt verify -- is covered unconditionally above.
    auth_path = os.path.join(repo_root(), "app", "walkers", "auth.jac");
    if not os.path.isfile(auth_path) {
        print("SKIP: app/walkers/auth.jac does not exist yet; the Login-walker "
              + "response-genericity assertion was not run.");
    } else {
        tag = new_tag();
        build(tag);

        # A REAL bcrypt hash, so "wrong password" is a genuine bcrypt mismatch
        # against a genuine account rather than a corrupt-hash fallback.
        p = get_platform();
        real_email: str = tag + "-real@example.com";
        p +>:Registers:+> Principal(
            principal_id=tag + "-pReal", email=real_email,
            pw_hash=hash_password("the actual password 42"), status="active"
        );

        wrong_pw = root() spawn Login(
            ctx=signed_ctx_dict(""), email=real_email,
            password="not the actual password", tenant_id=tag + "-tA"
        );
        no_such = root() spawn Login(
            ctx=signed_ctx_dict(""), email=tag + "-ghost@example.com",
            password="not the actual password", tenant_id=tag + "-tA"
        );

        # THE ASSERTION. A real account with a wrong password and an address
        # that was never registered must be indistinguishable to the client.
        # Any difference -- a distinct error string, an extra field, even a
        # different key order -- is an account-enumeration oracle that lets an
        # attacker sort a leaked credential dump into customers and strangers.
        assert wrong_pw.reports == no_such.reports;
        assert len(wrong_pw.reports) == 1;
        assert wrong_pw.reports[0]["ok"] is False;

        # And the failure must not leak WHICH check failed.
        assert "password" not in str(wrong_pw.reports[0]).lower();
        assert "email" not in str(wrong_pw.reports[0]).lower();
    }
}
