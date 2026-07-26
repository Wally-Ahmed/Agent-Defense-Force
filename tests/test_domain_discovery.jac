# tests/test_domain_discovery.jac -- search, export, integrations, tenants.
#
#     APP_CTX_SIGNING_KEY=<64 hex> jac test tests/test_domain_discovery.jac
#
# SEARCH IS THE HARDEST READ IN THE APPLICATION. Every other endpoint is handed
# an id and asked "may they have this one?". Search is asked "what is there?" and
# has to answer without ever naming a record the caller cannot reach -- not the
# record, not its id, not a snippet of it, not its existence in a count. The way
# that is achieved here is by refusing to build a second query path: search
# iterates the SAME `visible_projects` / `visible_tasks` / `visible_comments`
# collections that the list endpoints use, so the predicate cannot drift.
#
# The canary case below is the sharpest form of the whole demo. A member
# searching for the exact words in the canary project's title gets zero results,
# and an admin searching the identical string gets it -- from one code path, with
# no branch on the word "canary" anywhere in it.
#
# EXPORT AND INTEGRATIONS are the egress endpoints, so they carry the `†`
# step-up rule: admin rank is not enough on its own, a password must have been
# presented within the last 15 minutes.

import from tests.fixtures { world, ctx_for }
import from tests.helpers { audit_count, only_event, only_report, data_of, items_of }
import from app.services.discovery {
    SearchTenant, RequestExport, DownloadExport, IntegrationCall
}
import from app.services.tenants { ListMyTenants, CreateTenant, ReadTenant }
import from typing { cast }
import from app.model.graph { Principal, Session, Authenticates }
import from app.model.resolve { principal_by_id }
import from app.security.clock { now_ms }

glob:pub W: dict = world();
glob:pub MADE: dict = {};

# --------------------------------------------------------------------------
# Search
# --------------------------------------------------------------------------

test "a member searching the canary's own words finds nothing" {
    mark = audit_count();
    w = SearchTenant(
        ctx=ctx_for("s_member", "/api/v1/tenants/t_acme/search", "GET"),
        tenant_id="t_acme", q="compensation", limit=50
    ) spawn root;
    r = only_report(w);
    print("SEARCH (member, q=compensation):", data_of(r));
    assert r["ok"] == True;
    assert len(items_of(r)) == 0;
    # Not merely absent from the page -- absent from the count too, so the
    # number itself cannot be used as an existence oracle.
    assert data_of(r)["total_visible"] == 0;

    ev = only_event(mark);
    print("  audit:", ev);
    assert ev["action"] == "search.query";
    assert ev["outcome"] == "allow";
}

test "an admin searching the identical string finds it -- same code path" {
    w = SearchTenant(
        ctx=ctx_for("s_admin", "/api/v1/tenants/t_acme/search", "GET"),
        tenant_id="t_acme", q="compensation", limit=50
    ) spawn root;
    r = only_report(w);
    rows = items_of(r);
    print("SEARCH (admin, q=compensation):", [(x["type"], x["id"], x["sensitivity"]) for x in rows]);
    assert len(rows) == 2;
    ids = [x["id"] for x in rows];
    assert "pr_canary" in ids;
    assert "tk_canary" in ids;
}

test "search never crosses the tenant boundary" {
    w = SearchTenant(
        ctx=ctx_for("s_owner", "/api/v1/tenants/t_acme/search", "GET"),
        tenant_id="t_acme", q="globex", limit=50
    ) spawn root;
    r = only_report(w);
    rows = items_of(r);
    print("SEARCH (acme owner, q=globex):", rows);
    # An Acme owner outranks everyone in Acme and still cannot see Globex.
    assert len(rows) == 0;
}

test "a search cursor and limit are validated like every other list" {
    w = SearchTenant(
        ctx=ctx_for("s_member", "/api/v1/tenants/t_acme/search", "GET"),
        tenant_id="t_acme", q="x", limit=10000
    ) spawn root;
    r = only_report(w);
    print("SEARCH limit=10000 ->", r);
    assert r["ok"] == False;
    assert r["error"]["code"] == "VALIDATION_FAILED";
}

# --------------------------------------------------------------------------
# Export: admin AND step-up
# --------------------------------------------------------------------------

test "an admin with a fresh step-up may request an export" {
    mark = audit_count();
    w = RequestExport(
        ctx=ctx_for("s_admin", "/api/v1/tenants/t_acme/exports", "POST"),
        tenant_id="t_acme", format="json", include=["projects", "tasks"]
    ) spawn root;
    r = only_report(w);
    print("EXPORT REQUEST (fresh step-up) ->", data_of(r));
    assert r["ok"] == True;
    assert r["status"] == 202;
    MADE["export_id"] = data_of(r)["export_id"];

    ev = only_event(mark);
    print("  audit:", ev);
    assert ev["action"] == "export.request";
    assert ev["outcome"] == "allow";
    # Data egress is security-relevant even when allowed.
    assert ev["severity"] == "notice";
}

test "the SAME admin with a stale password is denied REAUTH_REQUIRED" {
    mark = audit_count();
    w = RequestExport(
        ctx=ctx_for("s_stale_admin", "/api/v1/tenants/t_acme/exports", "POST"),
        tenant_id="t_acme", format="json", include=["projects"]
    ) spawn root;
    r = only_report(w);
    print("EXPORT REQUEST (stale step-up) ->", r);
    assert r["ok"] == False;
    assert r["status"] == 401;
    assert r["error"]["code"] == "REAUTH_REQUIRED";
    # Same principal, same admin membership, same tenant -- the only difference
    # is when a password was last presented, read from Session.last_auth_at in
    # the graph and never from anything the client sent.
    ev = only_event(mark);
    print("  audit:", ev);
    assert ev["actor_role"] == "admin";
}

test "a member cannot request an export at any freshness" {
    w = RequestExport(
        ctx=ctx_for("s_member", "/api/v1/tenants/t_acme/exports", "POST"),
        tenant_id="t_acme", format="json", include=["projects"]
    ) spawn root;
    r = only_report(w);
    print("EXPORT REQUEST (member) ->", r);
    assert r["ok"] == False;
    assert r["status"] == 403;
    assert r["error"]["code"] == "INSUFFICIENT_ROLE";
}

test "downloading an export is gated on step-up too, and re-filters on read" {
    ok_dl = DownloadExport(
        ctx=ctx_for("s_admin", "/api/v1/tenants/t_acme/exports/x", "GET"),
        tenant_id="t_acme", export_id=MADE["export_id"]
    ) spawn root;
    a = only_report(ok_dl);
    print("EXPORT DOWNLOAD (fresh) ->", a["ok"], a["status"]);
    assert a["ok"] == True;

    stale = DownloadExport(
        ctx=ctx_for("s_stale_admin", "/api/v1/tenants/t_acme/exports/x", "GET"),
        tenant_id="t_acme", export_id=MADE["export_id"]
    ) spawn root;
    b = only_report(stale);
    print("EXPORT DOWNLOAD (stale) ->", b);
    assert b["ok"] == False;
    assert b["error"]["code"] == "REAUTH_REQUIRED";
}

test "an export id from another tenant is unreachable" {
    w = DownloadExport(
        ctx=ctx_for("s_admin", "/api/v1/tenants/t_acme/exports/x", "GET"),
        tenant_id="t_acme", export_id="x_does_not_exist_here"
    ) spawn root;
    r = only_report(w);
    print("EXPORT DOWNLOAD (foreign id) ->", r);
    assert r["ok"] == False;
    assert r["error"]["code"] == "NOT_FOUND";
}

# --------------------------------------------------------------------------
# Integrations
# --------------------------------------------------------------------------

test "a user session needs admin for an integration call, not member" {
    w = IntegrationCall(
        ctx=ctx_for("s_member", "/api/v1/tenants/t_acme/integrations/call", "POST"),
        tenant_id="t_acme", connector="slack", operation="post_message", payload={"text": "hi"}
    ) spawn root;
    r = only_report(w);
    print("INTEGRATION (member session) ->", r);
    assert r["ok"] == False;
    assert r["status"] == 403;
    assert r["error"]["code"] == "INSUFFICIENT_ROLE";
}

test "an admin session with step-up may dispatch an integration call" {
    mark = audit_count();
    w = IntegrationCall(
        ctx=ctx_for("s_admin", "/api/v1/tenants/t_acme/integrations/call", "POST"),
        tenant_id="t_acme", connector="slack", operation="post_message", payload={"text": "hi"}
    ) spawn root;
    r = only_report(w);
    print("INTEGRATION (admin session) ->", r["ok"], r["status"]);
    assert r["ok"] == True;
    ev = only_event(mark);
    assert ev["action"] == "integration.call";
    assert ev["outcome"] == "allow";
}

test "an unknown connector is VALIDATION_FAILED, not a dispatch" {
    w = IntegrationCall(
        ctx=ctx_for("s_admin", "/api/v1/tenants/t_acme/integrations/call", "POST"),
        tenant_id="t_acme", connector="attacker_host", operation="exfiltrate", payload={}
    ) spawn root;
    r = only_report(w);
    print("INTEGRATION (unknown connector) ->", r);
    assert r["ok"] == False;
    assert r["error"]["code"] == "VALIDATION_FAILED";
}

# --------------------------------------------------------------------------
# Tenants
# --------------------------------------------------------------------------

test "a viewer can read the tenant they belong to" {
    mark = audit_count();
    w = ReadTenant(
        ctx=ctx_for("s_viewer", "/api/v1/tenants/t_acme", "GET"), tenant_id="t_acme"
    ) spawn root;
    r = only_report(w);
    print("READ TENANT (viewer) ->", data_of(r));
    assert r["ok"] == True;
    assert data_of(r)["my_role"] == "viewer";
    assert data_of(r)["my_membership_id"] == "m_viewer";
    ev = only_event(mark);
    assert ev["action"] == "tenant.read";
    assert ev["outcome"] == "allow";
}

test "a Globex session cannot read the Acme tenant record" {
    w = ReadTenant(
        ctx=ctx_for("s_globex", "/api/v1/tenants/t_acme", "GET"), tenant_id="t_acme"
    ) spawn root;
    r = only_report(w);
    print("READ TENANT (globex -> acme) ->", r);
    assert r["ok"] == False;
    assert r["error"]["code"] == "TENANT_MISMATCH";
}

# --------------------------------------------------------------------------
# `GET /tenants` -- the one endpoint in the contract with no tenant in its path.
# It is how a caller discovers which tenants exist FOR THEM, so it has to work
# before any tenant scope exists. Its audit action is `tenant.read`
# (contracts/app_api.md note C), which guard() used to treat as unconditionally
# tenant-scoped -- an empty tenant_id failed the STEP 4 lookup and the endpoint
# could never succeed.
#
# `tenant.read` is now on TENANTLESS_ACTIONS, but guard() skips the tenancy
# steps only when the REQUEST carries no tenant scope either (`tenant_id == ""`).
# That second condition is what keeps the same action safe on
# `GET /tenants/{tenant_id}`, which shares it -- the two cases below pin both
# halves, and the Globex case above pins the half that must still be refused.
# --------------------------------------------------------------------------

"""A session for `principal_id` that is bound to NO tenant.

Exactly the state of a session between password login and choosing a tenant:
`tenant_id` is "". Built here rather than in tests/fixtures.jac because it is
the specific precondition these two cases are about."""
def scopeless_session(principal_id: str, session_id: str) -> str {
    ts = now_ms();
    who = cast(Principal, principal_by_id(principal_id));
    who +>:Authenticates:+> Session(
        session_id=session_id,
        principal_id=principal_id,
        tenant_id="",
        ip_first="203.0.113.10",
        fp="fp_test",
        issued_at=ts,
        expires_at=ts + 3600000,
        last_auth_at=ts,
        revoked=False
    );
    return session_id;
}

test "GET /tenants succeeds for a freshly-logged-in principal with no tenant scope" {
    sid = scopeless_session("u_member", "s_scopeless");
    mark = audit_count();
    w = ListMyTenants(
        ctx=ctx_for(sid, "/api/v1/tenants", "GET"), limit=50
    ) spawn root;
    r = only_report(w);
    print("LIST MY TENANTS (no tenant scope) ->", r);
    assert r["ok"] == True;
    assert r["status"] == 200;
    ids = sorted([str(i["tenant_id"]) for i in items_of(r)]);
    print("  tenants ->", ids);
    # The projection is the caller's OWN active memberships, so Acme appears and
    # Globex -- where this principal holds nothing -- does not. Being tenantless
    # widened which ENDPOINT is reachable, never which rows it returns.
    assert "t_acme" in ids;
    assert "t_globex" not in ids;
    assert data_of(r)["total_visible"] == len(ids);
    ev = only_event(mark);
    print("  audit:", ev);
    assert ev["action"] == "tenant.read";
    assert ev["outcome"] == "allow";
    assert ev["tenant_id"] == "";
}

test "the tenantless carve-out does NOT extend to GET /tenants/{tenant_id}" {
    # Same action, same principal, same scopeless session -- but this request
    # names a tenant, so guard() must run the tenancy steps in full. If the
    # carve-out were keyed on the action alone, this would be allowed and any
    # caller could read any tenant record by naming it.
    sid = scopeless_session("u_member", "s_scopeless2");
    r = only_report(ReadTenant(
        ctx=ctx_for(sid, "/api/v1/tenants/t_globex", "GET"), tenant_id="t_globex"
    ) spawn root);
    print("READ TENANT (scopeless session -> globex) ->", r);
    assert r["ok"] == False,
        "a tenantless action presented WITH a tenant_id must not skip steps 4-6";
    assert r["error"]["code"] in ["TENANT_MISMATCH", "NOT_A_MEMBER"];
}

test "creating a tenant makes the creator its owner and nobody else" {
    mark = audit_count();
    w = CreateTenant(
        ctx=ctx_for("s_member", "/api/v1/tenants", "POST"),
        tenant_id="t_newco", name="NewCo", plan="free"
    ) spawn root;
    r = only_report(w);
    print("CREATE TENANT ->", r);
    assert r["ok"] == True;
    assert r["status"] == 201;
    assert data_of(r)["my_role"] == "owner";
    assert data_of(r)["member_count"] == 1;
    ev = only_event(mark);
    print("  audit:", ev);
    assert ev["action"] == "tenant.create";
    assert ev["outcome"] == "allow";
    assert ev["severity"] == "notice";
}

test "a duplicate tenant id is VALIDATION_FAILED, not a second tenant" {
    w = CreateTenant(
        ctx=ctx_for("s_member", "/api/v1/tenants", "POST"),
        tenant_id="t_acme", name="Impostor"
    ) spawn root;
    r = only_report(w);
    print("CREATE TENANT (duplicate) ->", r);
    assert r["ok"] == False;
    assert r["error"]["code"] == "VALIDATION_FAILED";
}
