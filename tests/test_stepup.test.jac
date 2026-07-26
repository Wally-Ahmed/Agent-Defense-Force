# tests/test_stepup.test.jac — step-up authentication, against the real guard().
#
# The claim under test: the irreversible / exfiltrating operations in
# app/security/roles.jac's STEPUP_ACTIONS demand a password proved within the
# last REAUTH_MAX_AGE_MS (15 minutes). A live session is not enough. A stolen
# session may browse; it may not walk out with the dataset.
#
# WHICH PRINCIPALS each requirement binds is part of the requirement. Four of the
# five bind every principal. `integration.call` binds user sessions only, because
# the contract gives it two requirements -- one for a service account presenting
# an API token, one for a human at a keyboard -- and a service account has no
# interactive session to re-authenticate. The last four tests pin that carve-out
# open in one direction and shut in the other.
#
# The freshness clock is `session_auth_at_ms` on the VERIFIED ctx. Three things
# make that field the right one to test through, and each is asserted here:
#
#   NOT ACTIVITY   — the Session node in the fixture always carries a FRESH
#                    `last_auth_at`. Every denial below therefore cannot be
#                    blamed on the session record; guard() reads the signed ctx,
#                    and browsing for an hour is not evidence that the human is
#                    still at the keyboard.
#   FAIL-CLOSED    — 0 means UNKNOWN (no session, an API token, a gateway that
#                    did not stamp it) and must read as INFINITELY OLD. Unknown
#                    must never read as fresh.
#   UNFORGEABLE    — `session_auth_at_ms` is in ctxsig.SIGNED_FIELDS, so every
#                    ctx here is signed through app/security/ctxsig.jac exactly
#                    the way the gateway signs it. Nothing hand-rolls an HMAC.
#
# NON-VACUITY: a test that only proved denial would also pass on a system that
# denied everything. The control case runs a NON-step-up action with the SAME
# stale clock and the SAME signed ctx and requires it to SUCCEED, so the denials
# are pinned to the step-up gate and not to a broken fixture, an expired
# session, or a missing membership.
#
# GRAPH PERSISTENCE: .jac/data/anchor_store.db survives between processes, so
# every fixture id is prefixed with a per-run random tag.

import secrets;
import from contracts.req_ctx_contract { ReqCtx, Grant, guard }
import from app.model.graph {
    Platform, Tenant, Membership, Principal, Session, Project, Token,
    Hosts, Registers, HasMember, Identifies, Owns, Authenticates, Bears,
    get_platform
}
import from app.security.clock { now_ms, SESSION_TTL_MS, REAUTH_MAX_AGE_MS }
import from app.security.ctxsig { sign_ctx }
import from app.security.roles { requires_stepup }

# --------------------------------------------------------------------------
# Fixture. Jac test files are standalone modules, so the builder lives here
# rather than in tests/fixtures.jac -- and a per-run tag keeps it from
# colliding with rows a previous run left in the persistent anchor store.
# --------------------------------------------------------------------------

"""A per-run token, so fixture ids cannot collide across runs."""
def new_tag() -> str {
    return "su-" + secrets.token_hex(4);
}

"""Sign a ctx exactly the way the gateway does, through the one canonical
implementation in app/security/ctxsig.jac.

`session_auth_at_ms` is a PARAMETER: it is the only thing that varies between
the cases below, and because it is a SIGNED field the signature is recomputed
over each value. A caller cannot claim freshness the signer did not grant."""
def mk_ctx(session_id: str, session_auth_at_ms: int, ip: str = "10.0.0.1") -> ReqCtx {
    now = now_ms();
    fields: dict = {
        "request_id": "req-" + secrets.token_hex(3),
        "src_ip": ip,
        "src_asn": "AS64500",
        "user_agent_hash": "uah",
        "client_fp": "fp-stepup",
        "session_id": session_id,
        "token_id": "",
        "service": "web",
        "route": "/test",
        "http_method": "POST",
        "csrf_ok": True,
        "received_at_ms": now,
        "sig_alg": "HMAC-SHA256",
        "issued_at_ms": now,
        "session_auth_at_ms": session_auth_at_ms
    };
    fields["sig"] = sign_ctx(fields);
    return ReqCtx(**fields);
}

"""The same ctx, but presenting an API TOKEN instead of a session.

`session_id` is empty and `token_id` carries the jti, which is what makes
guard() derive `auth_method = "api_token"`. `session_auth_at_ms` is 0 -- not an
oversight but the truth: a service account never authenticated interactively and
has no password recency to report. Every ctx here is signed the same way; the
credential presented is the only difference."""
def mk_token_ctx(jti: str, session_auth_at_ms: int = 0, ip: str = "10.0.0.1") -> ReqCtx {
    now = now_ms();
    fields: dict = {
        "request_id": "req-" + secrets.token_hex(3),
        "src_ip": ip,
        "src_asn": "AS64500",
        "user_agent_hash": "uah",
        "client_fp": "fp-stepup",
        "session_id": "",
        "token_id": jti,
        "service": "api",
        "route": "/test",
        "http_method": "POST",
        "csrf_ok": True,
        "received_at_ms": now,
        "sig_alg": "HMAC-SHA256",
        "issued_at_ms": now,
        "session_auth_at_ms": session_auth_at_ms
    };
    fields["sig"] = sign_ctx(fields);
    return ReqCtx(**fields);
}

"""One tenant, one principal who is an ACTIVE ADMIN of it, one live session,
and one project for the control case to list.

`export.request` requires `admin` (app/security/roles.jac), so this principal
satisfies the role check outright -- every denial below therefore has to come
from the step-up gate, which sits between the credential check and the role
check in authorize().

`last_auth_at` on the Session node is deliberately FRESH in every case. The
gate does not read it; it reads the signed ctx. Setting it to `now` means a
stale-ctx denial cannot be an artifact of a stale session record."""
def build(tag: str) {
    p = get_platform();
    now = now_ms();

    t = (p +>:Hosts:+> Tenant(
        tenant_id=tag + "-t", name="Stepup Co", created_at=now
    ))[0];

    admin = (p +>:Registers:+> Principal(
        principal_id=tag + "-pAdmin", email=tag + "-admin@example.com", pw_hash="x"
    ))[0];

    m = (t +>:HasMember:+> Membership(
        membership_id=tag + "-mAdmin", principal_id=tag + "-pAdmin",
        tenant_id=tag + "-t", role="admin", state="active", created_at=now
    ))[0];
    m +>:Identifies:+> admin;

    admin +>:Authenticates:+> Session(
        session_id=tag + "-sAdmin", principal_id=tag + "-pAdmin",
        tenant_id=tag + "-t", issued_at=now, expires_at=now + SESSION_TTL_MS,
        last_auth_at=now
    );

    t +>:Owns:+> Project(
        project_id=tag + "-pr", tenant_id=tag + "-t", key="SU1", created_at=now
    );

    # A service account's API token, held by that SAME admin principal and
    # scoped to `integration.call`. Same principal, same membership, same role
    # as every session case above -- so when the token case comes out ALLOWED
    # and a session case with an identical clock comes out DENIED, the only
    # variable that could explain it is the authentication method.
    admin +>:Bears:+> Token(
        jti=tag + "-tok", principal_id=tag + "-pAdmin", tenant_id=tag + "-t",
        kind="api", scope="integration.call", issued_at=now,
        expires_at=now + SESSION_TTL_MS, revoked=False
    );
}

# 20 minutes. Comfortably past REAUTH_MAX_AGE_MS (15 minutes) without being so
# far past that the test would still pass if the window were widened by an order
# of magnitude.
glob STALE_AGE_MS: int = 1200000;

# --------------------------------------------------------------------------
# Case 1 -- STALE. The whole point of the control.
# --------------------------------------------------------------------------

test "STALE: an admin who last proved a password 20 minutes ago is denied export.request" {
    tag = new_tag();
    build(tag);

    # Live session, active admin membership, correct tenant, verified ctx.
    # The ONLY defect is that the human last authenticated 20 minutes ago.
    ctx = mk_ctx(tag + "-sAdmin", now_ms() - STALE_AGE_MS);

    g = guard(ctx, "export.request", "export", tag + "-t", "");
    assert not g.ok;
    assert g.reason == "REAUTH_REQUIRED";
}

# --------------------------------------------------------------------------
# Case 2 -- FRESH. The control is a gate, not a wall: re-authenticating opens it.
# --------------------------------------------------------------------------

test "FRESH: the same admin, re-authenticated just now, is allowed export.request" {
    tag = new_tag();
    build(tag);

    # Same principal, same session, same action, same tenant. Only the signed
    # `session_auth_at_ms` differs from case 1.
    ctx = mk_ctx(tag + "-sAdmin", now_ms());

    g = guard(ctx, "export.request", "export", tag + "-t", "");
    assert g.ok;
    assert g.reason == "";
}

# --------------------------------------------------------------------------
# Case 3 -- FAIL-CLOSED ON UNKNOWN. The critical one.
# --------------------------------------------------------------------------

test "UNKNOWN: session_auth_at_ms = 0 is denied -- unknown never reads as fresh" {
    tag = new_tag();
    build(tag);

    # 0 is the "unset" default on every ReqCtx field. A gateway that forgot to
    # stamp this one, or a credential that can never present a password, must
    # land in DENY -- not sail through because nobody looked.
    ctx = mk_ctx(tag + "-sAdmin", 0);

    g = guard(ctx, "export.request", "export", tag + "-t", "");
    assert not g.ok;
    assert g.reason == "REAUTH_REQUIRED";
}

# --------------------------------------------------------------------------
# Case 4 -- THE CONTROL CASE. Proves the suite is not vacuously passing.
# --------------------------------------------------------------------------

test "CONTROL: a NON-step-up action with the SAME stale clock is still ALLOWED" {
    tag = new_tag();
    build(tag);

    # Byte-for-byte the situation that was denied in case 1 -- same fixture,
    # same admin, same 20-minute-old authentication. `project.list` is simply
    # not in STEPUP_ACTIONS.
    ctx = mk_ctx(tag + "-sAdmin", now_ms() - STALE_AGE_MS);

    g = guard(ctx, "project.list", "project", tag + "-t", "");
    assert g.ok;
    assert g.reason == "";
}

test "CONTROL, tightened: ONE signed ctx, two actions, opposite outcomes" {
    tag = new_tag();
    build(tag);

    # The strongest form of the control: not a comparable ctx, the SAME ctx
    # object -- identical signature bytes, identical session, identical stale
    # clock -- handed to guard() twice. Nothing but the action differs, so the
    # denial can only be the step-up gate firing on a STEPUP_ACTIONS member.
    ctx = mk_ctx(tag + "-sAdmin", now_ms() - STALE_AGE_MS);

    denied = guard(ctx, "export.request", "export", tag + "-t", "");
    allowed = guard(ctx, "project.list", "project", tag + "-t", "");

    assert not denied.ok;
    assert denied.reason == "REAUTH_REQUIRED";
    assert allowed.ok;
    assert allowed.reason == "";
}

# --------------------------------------------------------------------------
# Case 5 -- freshness must not be obtainable by claiming tomorrow.
# --------------------------------------------------------------------------

test "FUTURE: a ctx claiming it authenticates 10 minutes from now is denied" {
    tag = new_tag();
    build(tag);

    # `now - auth_at_ms` is NEGATIVE here, so a naive `age > MAX` comparison
    # would read this as the freshest possible authentication. A forged or
    # skewed clock must not be a way through the gate.
    ctx = mk_ctx(tag + "-sAdmin", now_ms() + 600000);

    g = guard(ctx, "export.request", "export", tag + "-t", "");
    assert not g.ok;
    assert g.reason == "REAUTH_REQUIRED";
}

# --------------------------------------------------------------------------
# Boundary. Pins the window to REAUTH_MAX_AGE_MS rather than to a number this
# test made up, so widening the constant is a visible edit and not a silent one.
# --------------------------------------------------------------------------

test "BOUNDARY: just inside REAUTH_MAX_AGE_MS is allowed, just outside is denied" {
    tag = new_tag();
    build(tag);

    # 5s of slack absorbs the clock ticking between mk_ctx() and guard().
    inside = mk_ctx(tag + "-sAdmin", now_ms() - (REAUTH_MAX_AGE_MS - 5000));
    outside = mk_ctx(tag + "-sAdmin", now_ms() - (REAUTH_MAX_AGE_MS + 5000));

    gi = guard(inside, "export.request", "export", tag + "-t", "");
    assert gi.ok;
    assert gi.reason == "";

    go = guard(outside, "export.request", "export", tag + "-t", "");
    assert not go.ok;
    assert go.reason == "REAUTH_REQUIRED";
}

# --------------------------------------------------------------------------
# The other three STEPUP_ACTIONS. Case 1 proves the gate exists; this proves it
# is wired to the whole list and not to `export.request` alone.
# --------------------------------------------------------------------------

test "the gate covers every action in STEPUP_ACTIONS, not just export.request" {
    tag = new_tag();
    build(tag);
    ctx = mk_ctx(tag + "-sAdmin", now_ms() - STALE_AGE_MS);

    # `member.role_change` and `member.remove` also require admin, which this
    # principal is; `export.download` requires admin too. Each must still be
    # refused for staleness alone.
    for (action, kind) in [
        ("member.role_change", "member"),
        ("member.remove", "member"),
        ("export.download", "export")
    ] {
        g = guard(ctx, action, kind, tag + "-t", "");
        assert not g.ok , f"{action} was allowed with a 20-minute-old authentication";
        assert g.reason == "REAUTH_REQUIRED" , f"{action} denied for {g.reason}, not REAUTH_REQUIRED";
    }
}

# --------------------------------------------------------------------------
# integration.call -- the fifth x-step-up-required operation, and the only one
# whose requirement is scoped to a KIND OF PRINCIPAL.
#
# contracts/app_api.openapi.yaml gives it two requirements, not one:
#   "service account: member + scope integration:call; user session: admin +
#    step-up"
# so the three cases below have to come out differently from one another. A
# single unconditional rule cannot satisfy that contract: enforce step-up on
# everyone and every legitimate service-account call breaks; enforce it on
# nobody and a stolen browser session walks data out through a connector.
# --------------------------------------------------------------------------

test "USER SESSION, STALE: integration.call is denied with a 20-minute-old password" {
    tag = new_tag();
    build(tag);

    # Identical in every respect to case 1 except the action.
    ctx = mk_ctx(tag + "-sAdmin", now_ms() - STALE_AGE_MS);

    g = guard(ctx, "integration.call", "integration", tag + "-t", "");
    assert not g.ok;
    assert g.reason == "REAUTH_REQUIRED";
}

test "USER SESSION, FRESH: integration.call is allowed after re-authenticating" {
    tag = new_tag();
    build(tag);

    # The gate is a gate, not a wall, for this action too.
    ctx = mk_ctx(tag + "-sAdmin", now_ms());

    g = guard(ctx, "integration.call", "integration", tag + "-t", "");
    assert g.ok;
    assert g.reason == "";
}

test "SERVICE ACCOUNT: an API token calls integration.call with session_auth_at_ms = 0" {
    tag = new_tag();
    build(tag);

    # THE CARVE-OUT. `session_auth_at_ms = 0` is the value that denies every
    # other step-up action outright (case 3) -- and it is the only value a
    # service account can ever honestly present, because it never typed a
    # password. A service account has no interactive session to re-authenticate,
    # so step-up cannot be its control; the `integration.call` token scope and
    # its tenant membership are. Enforcing step-up here would not harden
    # anything, it would simply break every legitimate integration call.
    ctx = mk_token_ctx(tag + "-tok", 0);

    g = guard(ctx, "integration.call", "integration", tag + "-t", "");
    assert g.ok , f"the service-account carve-out is broken: integration.call denied for {g.reason}";
    assert g.reason == "";
}

test "SERVICE ACCOUNT, tightened: the carve-out is per-ACTION, not a token exemption" {
    tag = new_tag();
    build(tag);

    # The narrowness of the carve-out, stated as a test: the SAME token, the
    # same zero clock, is still refused `export.request`, which the table scopes
    # to every principal. If someone ever replaces the auth-method condition
    # with a blanket "tokens skip step-up", this is the assertion that fails.
    ctx = mk_token_ctx(tag + "-tok", 0);

    allowed = guard(ctx, "integration.call", "integration", tag + "-t", "");
    denied = guard(ctx, "export.request", "export", tag + "-t", "");

    assert allowed.ok;
    # The token's scope does not cover exports either, so accept the scope
    # refusal as well -- the load-bearing claim is that it is NOT allowed.
    assert not denied.ok;
    assert denied.reason in ["REAUTH_REQUIRED", "INSUFFICIENT_ROLE"];
}

test "FAIL CLOSED: an unrecognised auth_method gets the user-session requirement" {
    # guard() itself only ever derives "session" or "api_token" from the
    # credential it verified, so this property is asserted on the rule directly.
    # It is the guarantee that matters when a THIRD authentication method is
    # added later: the carve-out is written as membership of an explicit
    # non-interactive list, so a method nobody has taught the table about
    # inherits the STRICT requirement rather than the exemption.
    for method in ["", "none", "password", "session", "unknown", "Api_Token", "api-token"] {
        assert requires_stepup("integration.call", method) ,
            f"auth_method '{method}' skipped step-up on integration.call";
    }

    # The default, for a caller that does not say how it authenticated at all.
    assert requires_stepup("integration.call");

    # And the one value that does carve out -- exactly one, spelled exactly.
    assert not requires_stepup("integration.call", "api_token");

    # Which changes nothing for the all-principals actions.
    assert requires_stepup("export.request", "api_token");
    assert requires_stepup("member.role_change", "api_token");
    assert requires_stepup("member.remove", "api_token");
    assert requires_stepup("export.download", "api_token");

    # And nothing for actions that were never step-up at all.
    assert not requires_stepup("project.list", "session");
    assert not requires_stepup("project.list", "api_token");
}
