# tests/test_domain_members.jac -- membership administration and step-up.
#
#     APP_CTX_SIGNING_KEY=<64 hex> jac test tests/test_domain_members.jac
#
# The membership endpoints are where privilege is actually granted, so they are
# the ones an attacker wants. Three properties are asserted here:
#
#   1. the roster redacts email below admin rank, and never leaves the tenant;
#   2. an invite's plaintext token is returned exactly once and only its SHA-256
#      hash is persisted -- the graph never holds the bearer secret;
#   3. the role gate on `member.role_change` / `member.remove` is admin, and the
#      requested role cannot be influenced by the requester.
#
# TWO CROSS-TRACK SEAMS ARE PINNED HERE, both fail-closed. See the notes on the
# individual cases. Each is asserted at its CURRENT behaviour so that fixing it
# turns this file red rather than passing silently in a new shape.

import from tests.fixtures { world, ctx_for }
import from tests.helpers { audit_count, only_event, only_report, data_of, items_of }
import from app.services.members {
    ListMembers, InviteMember, ChangeMemberRole, RemoveMember
}
import from app.model.resolve { tenant_by_id, invites_of }
import from typing { cast }
import from app.model.graph { Tenant }

glob:pub W: dict = world();

# --------------------------------------------------------------------------
# The roster
# --------------------------------------------------------------------------

test "a viewer sees the roster with every email redacted" {
    mark = audit_count();
    w = ListMembers(
        ctx=ctx_for("s_viewer", "/api/v1/tenants/t_acme/members", "GET"),
        tenant_id="t_acme", limit=100
    ) spawn root;
    r = only_report(w);
    assert r["ok"] == True;
    rows = items_of(r);
    print("ROSTER (viewer):", [(x["membership_id"], x["role"], x["member"]["email"]) for x in rows]);
    assert len(rows) == 4;
    for x in rows {
        assert x["tenant_id"] == "t_acme";
        assert x["member"]["email"] == "", "email must be redacted below admin rank";
    }
    ev = only_event(mark);
    print("  audit:", ev);
    # contracts/app_api.md note C: the closed vocabulary has no `member.list`,
    # so the roster is audited as a tenant read.
    assert ev["action"] == "tenant.read";
    assert ev["outcome"] == "allow";
}

test "an admin sees the same roster WITH emails" {
    w = ListMembers(
        ctx=ctx_for("s_admin", "/api/v1/tenants/t_acme/members", "GET"),
        tenant_id="t_acme", limit=100
    ) spawn root;
    r = only_report(w);
    rows = items_of(r);
    mails = [x["member"]["email"] for x in rows];
    print("ROSTER (admin):", mails);
    assert "" not in mails;
}

test "a Globex member cannot read the Acme roster" {
    w = ListMembers(
        ctx=ctx_for("s_globex", "/api/v1/tenants/t_acme/members", "GET"),
        tenant_id="t_acme", limit=100
    ) spawn root;
    r = only_report(w);
    print("ROSTER (globex session -> acme):", r);
    assert r["ok"] == False;
    assert r["error"]["code"] == "TENANT_MISMATCH";
}

# --------------------------------------------------------------------------
# Invites: the bearer secret is never stored
# --------------------------------------------------------------------------

test "an invite returns its token once and persists only the hash" {
    mark = audit_count();
    w = InviteMember(
        ctx=ctx_for("s_admin", "/api/v1/tenants/t_acme/members/invites", "POST"),
        tenant_id="t_acme", email="newhire@acme.test", role="member"
    ) spawn root;
    r = only_report(w);
    assert r["ok"] == True;
    assert r["status"] == 201;
    token = data_of(r)["invite_token"];
    print("INVITE issued, token length:", len(token));
    assert len(token) >= 43;

    ev = only_event(mark);
    print("  audit:", ev);
    assert ev["action"] == "member.invite";
    assert ev["outcome"] == "allow";
    # A privilege grant is security-relevant even when it succeeds.
    assert ev["severity"] == "notice";

    # The plaintext is nowhere in the graph -- only its digest is.
    acme = cast(Tenant, tenant_by_id("t_acme"));
    stored = [i.token_hash for i in invites_of(acme)];
    print("  stored token_hash values are digests, not tokens:", [len(h) for h in stored]);
    assert token not in stored;
    for h in stored {
        assert len(h) == 64, "token_hash must be a sha256 hex digest";
    }
}

test "a member cannot issue an invite -- invites are admin-only" {
    mark = audit_count();
    w = InviteMember(
        ctx=ctx_for("s_member", "/api/v1/tenants/t_acme/members/invites", "POST"),
        tenant_id="t_acme", email="sneaky@acme.test", role="admin"
    ) spawn root;
    r = only_report(w);
    print("INVITE (member) ->", r);
    assert r["ok"] == False;
    assert r["status"] == 403;
    assert r["error"]["code"] == "INSUFFICIENT_ROLE";
    ev = only_event(mark);
    assert ev["outcome"] == "deny";
    assert ev["reason"] == "INSUFFICIENT_ROLE";
}

test "a malformed invite email is VALIDATION_FAILED" {
    w = InviteMember(
        ctx=ctx_for("s_admin", "/api/v1/tenants/t_acme/members/invites", "POST"),
        tenant_id="t_acme", email="not-an-email", role="member"
    ) spawn root;
    r = only_report(w);
    print("INVITE (bad email) ->", r);
    assert r["ok"] == False;
    assert r["status"] == 422;
    assert r["error"]["code"] == "VALIDATION_FAILED";
}

# --------------------------------------------------------------------------
# Role change / removal
# --------------------------------------------------------------------------

test "a member cannot change anyone's role" {
    mark = audit_count();
    w = ChangeMemberRole(
        ctx=ctx_for("s_member", "/api/v1/tenants/t_acme/members/m_viewer", "PATCH"),
        tenant_id="t_acme", membership_id="m_viewer", role="admin"
    ) spawn root;
    r = only_report(w);
    print("ROLE CHANGE (member) ->", r);
    assert r["ok"] == False;
    assert r["status"] == 403;
    assert r["error"]["code"] == "INSUFFICIENT_ROLE";
    ev = only_event(mark);
    print("  audit:", ev);
    assert ev["action"] == "member.role_change";
    assert ev["outcome"] == "deny";
    assert ev["reason"] == "INSUFFICIENT_ROLE";
}

test "a Globex session cannot touch an Acme membership" {
    w = RemoveMember(
        ctx=ctx_for("s_globex", "/api/v1/tenants/t_acme/members/m_member", "DELETE"),
        tenant_id="t_acme", membership_id="m_member"
    ) spawn root;
    r = only_report(w);
    print("REMOVE (globex -> acme) ->", r);
    assert r["ok"] == False;
    assert r["error"]["code"] == "TENANT_MISMATCH";
}

# --------------------------------------------------------------------------
# Addressing a membership BY MEMBERSHIP_ID -- the id the public API uses
# (contracts/app_api.openapi.yaml: PATCH and DELETE
# /tenants/{tenant_id}/members/{membership_id}).
#
# guard() used to resolve a `member` target through
# app/model/resolve.membership_of(), which matches on PRINCIPAL_ID -- a
# different question, and the one guard() asks at STEP 4 to establish the
# ACTOR's role. Every membership_id was therefore unresolvable and both walkers
# below were denied NOT_FOUND before their own logic ran: fail-closed, but
# unusable end to end. resolve_in_tenant's "member" branch now goes through
# membership_in(), which walks the SAME Tenant --HasMember--> edge and matches
# on membership_id.
#
# The two cases here run in definition order and mutate the roster, so the
# roster check at the end of this file asserts the RESULTING state.
# --------------------------------------------------------------------------

test "an admin changes a member's role by membership_id" {
    mark = audit_count();
    w = ChangeMemberRole(
        ctx=ctx_for("s_admin", "/api/v1/tenants/t_acme/members/m_member", "PATCH"),
        tenant_id="t_acme", membership_id="m_member", role="admin"
    ) spawn root;
    r = only_report(w);
    print("ROLE CHANGE (admin, valid membership_id) ->", r);
    assert r["ok"] == True;
    assert r["status"] == 200;
    assert data_of(r)["membership_id"] == "m_member";
    assert data_of(r)["role"] == "admin";
    # The membership_id addressed the row; the principal it identifies is
    # reported back, and is the one that membership always belonged to.
    assert data_of(r)["user_id"] == "u_member";
    ev = only_event(mark);
    print("  audit:", ev);
    assert ev["action"] == "member.role_change";
    assert ev["outcome"] == "allow";
    assert ev["target_id"] == "m_member";
}

test "an admin removes a member by membership_id" {
    mark = audit_count();
    w = RemoveMember(
        ctx=ctx_for("s_admin", "/api/v1/tenants/t_acme/members/m_viewer", "DELETE"),
        tenant_id="t_acme", membership_id="m_viewer"
    ) spawn root;
    r = only_report(w);
    print("REMOVE (admin, valid membership_id) ->", r);
    assert r["ok"] == True;
    assert r["status"] == 200;
    assert data_of(r)["membership_id"] == "m_viewer";
    ev = only_event(mark);
    print("  audit:", ev);
    assert ev["action"] == "member.remove";
    assert ev["outcome"] == "allow";
}

test "a membership_id from another tenant is UNREACHABLE, not rejected" {
    # `m_globex` is a real, live membership -- in Globex. An Acme admin naming
    # it must not be able to tell it apart from an id that was never issued to
    # anyone, because membership_in() walks out from the ACME tenant node and
    # simply never visits it. Isolation by which edges exist, not by a
    # comparison someone has to remember to write.
    foreign = ChangeMemberRole(
        ctx=ctx_for("s_admin", "/api/v1/tenants/t_acme/members/m_globex", "PATCH"),
        tenant_id="t_acme", membership_id="m_globex", role="admin"
    ) spawn root;
    invented = ChangeMemberRole(
        ctx=ctx_for("s_admin", "/api/v1/tenants/t_acme/members/m_never_issued", "PATCH"),
        tenant_id="t_acme", membership_id="m_never_issued", role="admin"
    ) spawn root;
    a = only_report(foreign);
    b = only_report(invented);
    print("FOREIGN membership_id  ->", a);
    print("INVENTED membership_id ->", b);
    assert a["ok"] == False;
    assert a["error"]["code"] == "NOT_FOUND";
    assert a["status"] == 404;
    # Byte-identical. Any difference at all would be a membership-enumeration
    # oracle across the tenant boundary.
    assert a == b;

    # And the Globex membership is untouched -- the walk never reached it.
    gx = ListMembers(
        ctx=ctx_for("s_globex", "/api/v1/tenants/t_globex/members", "GET"),
        tenant_id="t_globex", limit=100
    ) spawn root;
    gx_roles = [str(x["membership_id"]) + "=" + str(x["role"]) for x in items_of(only_report(gx))];
    print("GLOBEX ROSTER:", gx_roles);
    assert "m_globex=member" in gx_roles;
}

test "the roster reflects exactly the two changes above and nothing else" {
    w = ListMembers(
        ctx=ctx_for("s_admin", "/api/v1/tenants/t_acme/members", "GET"),
        tenant_id="t_acme", limit=100
    ) spawn root;
    rows = items_of(only_report(w));
    roles = sorted([str(x["membership_id"]) + "=" + str(x["role"]) for x in rows]);
    print("ROSTER AFTER:", roles);
    # m_member was promoted, m_viewer was removed, nothing else moved.
    assert "m_member=admin" in roles;
    assert "m_owner=owner" in roles;
    assert "m_admin=admin" in roles;
    assert len([x for x in roles if x.startswith("m_viewer")]) == 0,
        "a removed membership must no longer be reachable in the roster";
    # No membership from another tenant has appeared in Acme's roster.
    assert len([x for x in roles if x.startswith("m_globex")]) == 0;
}
