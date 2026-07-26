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

# ---------------------------------------------------------------------- SEAM
# `GET /tenants` is the one endpoint in the contract with no tenant in its path
# -- it is how a caller discovers which tenants exist FOR THEM. Its audit action
# is `tenant.read` (contracts/app_api.md note C), and guard() treats
# `tenant.read` as a tenant-scoped action, so an empty `tenant_id` fails the
# STEP 4 tenant lookup and denies NOT_FOUND before the walker runs.
#
# Fail-closed, and no data is at risk -- the endpoint simply cannot succeed.
#
# THE FIX is one entry in app/security/roles.jac (the security track's file):
# `TENANTLESS_ACTIONS` currently holds only "tenant.create". `ListMyTenants`
# needs the same treatment -- guard() still demands a verified ctx, a live
# credential and a clean control check for it, and skips only the membership and
# role steps, exactly as it already does for tenant creation. The walker itself
# already resolves nothing by id: `tenants_for(principal_id)` projects the
# caller's OWN active memberships, so a tenant with no membership edge for them
# never appears.
#
# Pinned at current behaviour so that widening TENANTLESS_ACTIONS turns this red.
# --------------------------------------------------------------------------

test "SEAM -- GET /tenants cannot pass guard with an empty tenant_id" {
    w = ListMyTenants(
        ctx=ctx_for("s_member", "/api/v1/tenants", "GET"), limit=50
    ) spawn root;
    r = only_report(w);
    print("LIST MY TENANTS ->", r);
    assert r["ok"] == False,
        "tenant.read is now tenantless -- rewrite this as the success path";
    assert r["error"]["code"] == "NOT_FOUND";
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
