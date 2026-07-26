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

# ---------------------------------------------------------------------- SEAM
# guard() resolves a `member` target through
# app/model/resolve.membership_of(tenant, target_id), which matches on
# PRINCIPAL_ID. The public API addresses a membership by MEMBERSHIP_ID
# (contracts/app_api.openapi.yaml: PATCH /tenants/{tenant_id}/members/{membership_id}).
# The two walkers below therefore pass a membership_id that guard() cannot
# resolve, and guard() denies NOT_FOUND before the walker's own logic runs.
#
# This is FAIL-CLOSED -- nothing is granted that should not be -- but it makes
# ChangeMemberRole and RemoveMember unusable end to end.
#
# THE FIX, one function in app/model/resolve.jac (the security track's file):
#
#     def:pub membership_in(tenant: Tenant, membership_id: str) -> Membership | None {
#         for m in [tenant->:HasMember:->][?:Membership] {
#             if m.membership_id == membership_id { return m; }
#         }
#         return None;
#     }
#
# and route `resolve_in_tenant`'s "member" branch through it. It stays inside
# the same Tenant --HasMember--> traversal, so it cannot reach another tenant's
# membership and the isolation guarantee is untouched.
#
# Asserted at CURRENT behaviour on purpose: applying the fix turns these two
# cases red and forces them to be rewritten as the success paths they should be.
# --------------------------------------------------------------------------

test "SEAM -- an admin role change is denied NOT_FOUND by guard's member lookup" {
    mark = audit_count();
    w = ChangeMemberRole(
        ctx=ctx_for("s_admin", "/api/v1/tenants/t_acme/members/m_member", "PATCH"),
        tenant_id="t_acme", membership_id="m_member", role="admin"
    ) spawn root;
    r = only_report(w);
    print("ROLE CHANGE (admin, valid membership_id) ->", r);
    assert r["ok"] == False,
        "resolve.jac now resolves a member by membership_id -- rewrite this as the success path";
    assert r["error"]["code"] == "NOT_FOUND";
    ev = only_event(mark);
    print("  audit:", ev);
    assert ev["action"] == "member.role_change";
    assert ev["outcome"] == "deny";
    assert ev["reason"] == "NOT_FOUND";
}

test "SEAM -- and so is a removal, by the identical lookup" {
    w = RemoveMember(
        ctx=ctx_for("s_admin", "/api/v1/tenants/t_acme/members/m_viewer", "DELETE"),
        tenant_id="t_acme", membership_id="m_viewer"
    ) spawn root;
    r = only_report(w);
    print("REMOVE (admin, valid membership_id) ->", r);
    assert r["ok"] == False,
        "resolve.jac now resolves a member by membership_id -- rewrite this as the success path";
    assert r["error"]["code"] == "NOT_FOUND";
}

test "the roster is unchanged by every denied attempt above" {
    w = ListMembers(
        ctx=ctx_for("s_admin", "/api/v1/tenants/t_acme/members", "GET"),
        tenant_id="t_acme", limit=100
    ) spawn root;
    rows = items_of(only_report(w));
    roles = sorted([str(x["membership_id"]) + "=" + str(x["role"]) for x in rows]);
    print("ROSTER AFTER:", roles);
    assert "m_member=member" in roles;
    assert "m_viewer=viewer" in roles;
    assert "m_owner=owner" in roles;
}
