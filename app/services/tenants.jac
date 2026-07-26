# app/services/tenants.jac -- the tenant-surface walkers: list mine, create,
# read one.
#
# THE SHAPE, same as every walker in app/services/ (see projects.jac):
#
#   1. guard(ReqCtx(**self.ctx), action, target_kind, tenant_id, target_id)
#      -- the FIRST executable statement, no exceptions.
#   2. open_scope() -- re-read the Membership from the graph (defence in
#      depth) -- EXCEPT ListMyTenants and CreateTenant, which have no tenant
#      in their path and therefore no Membership to re-read yet. See below.
#   3. the operation's own role floor, enforced as max(contract baseline,
#      guard's own table) so this layer can only be stricter than guard,
#      never looser
#   4. resolution by traversal from the Scope's tenant -- never by global id
#   5. validation -> VALIDATION_FAILED
#   6. the mutation, then report
#
# WALKERS EMIT NO AUDIT EVENT. contracts/vocab.md: "every guard() call emits
# exactly one AuditEvent. Not zero, not two." A second emission here would
# double-count every request and corrupt the `result_count` signal the monitor
# reads.
#
# `has ctx: dict = {};` is mandatory and is NOT a style choice: a walker `has`
# field typed as an archetype silently degrades to `str` and the request fails
# with HTTP 422. ReqCtx is rebuilt from the dict inside.
#
# THE TWO TENANTLESS SURFACES. `GET /tenants` and `POST /tenants` are the only
# endpoints in the whole contract with no tenant in their path, so there is no
# Membership to re-read before one exists -- both skip open_scope() entirely
# and read the caller straight off the Grant instead:
# `principal = cast(Principal, g.principal);`. guard() has already
# authenticated the caller by the time either walker's first line runs; the
# tenantless path is a documented seam in guard()'s own table (`tenant.create`
# is the only entry in TENANTLESS_ACTIONS), not a bypass invented here.
#
# CREATETENANT'S OWNERSHIP INVARIANT. The walker creates the Tenant AND
# exactly ONE Membership, at role `owner`, for the AUTHENTICATED principal --
# never a caller-supplied owner, never an attachment to an existing tenant.
# The Membership is linked to the Principal with the `Identifies` edge
# (Membership -> Principal), the same edge app/model/resolve.principal_of()
# reads back.

import from typing { cast }
import from contracts.req_ctx_contract { ReqCtx, Grant, guard }
import from app.model.graph { Tenant, Membership, Principal, Hosts, HasMember, Identifies, get_platform }
import from app.model.resolve { tenant_by_id, memberships_of, projects_of }
import from app.security.clock { now_ms }
import from app.security.roles { role_satisfies }
import from app.services.scope { open_scope, tenants_for }
import from app.services.errors { deny, ok }
import from app.services.paging { resolve_limit, filter_key, decode_cursor, page }
import from app.services.validate { v_str, v_id, v_pattern, v_enum, clean, MAX_NAME }
import from app.services.ids { membership_id as new_membership_id }

# Caller-chosen tenant slug: lowercase, must start with a letter, 3-64 chars.
glob:pub TENANT_ID_PATTERN: str = r"^[a-z][a-z0-9_-]{2,63}$";
glob:pub TENANT_PLAN_VALUES: list = ["free", "team", "business"];

"""One tenant, as the contract's Tenant schema, from the caller's own
perspective (their role and membership inside it)."""
def:pub tenant_view(t: Tenant, my_role: str, my_membership_id: str) -> dict {
    return {
        "tenant_id": t.tenant_id,
        "name": t.name,
        "plan": t.plan,
        "status": t.status,
        "created_at": t.created_at,
        "member_count": len(memberships_of(t)),
        "project_count": len(projects_of(t)),
        "my_role": my_role,
        "my_membership_id": my_membership_id
    };
}

"""The caller's own membership_id inside `t`.

`t` always comes from tenants_for(), which only ever returns tenants where an
active Membership for this principal already hangs off it, so this cannot
miss in practice; "" is the fail-closed answer if it somehow did."""
def _membership_id_in(t: Tenant, principal_id: str) -> str {
    for m in memberships_of(t) {
        if m.principal_id == principal_id {
            return m.membership_id;
        }
    }
    return "";
}

# --------------------------------------------------------------------------
# GET /tenants -- authenticated, no tenant in the path -- tenant.read -- 200
# --------------------------------------------------------------------------

walker ListMyTenants {
    has ctx: dict = {};
    has limit: int = 0;
    has cursor: str = "";

    can go with entry {
        # `tenant.read` is the only real action in the frozen vocabulary that
        # fits this read; there is no `tenant.list`. tenant_id is "" because
        # there is no tenant in this path -- this is the one seam noted in the
        # brief: guard() may deny an empty tenant_id for a non-tenantless
        # action, and if it does, that denial is reported as-is.
        g = guard(ReqCtx(**self.ctx), "tenant.read", "tenant", "", "");
        rid = self.ctx.get("request_id", "");
        if not g.ok {
            report deny(g.reason, rid);
            disengage;
        }
        # No open_scope(): there is no single tenant to open a Scope inside.
        # The caller is read straight off the Grant guard() already verified.
        principal = cast(Principal, g.principal);

        errs: list = [];
        lim = resolve_limit(self.limit);
        if lim < 0 {
            errs.append({"field": "limit", "message": "must be between 1 and 100"});
        }
        if not clean(errs) {
            report deny("VALIDATION_FAILED", rid, errs);
            disengage;
        }

        # tenants_for() IS the traversal: a tenant appears only when an active
        # Membership for THIS principal hangs off it (app/services/scope.jac).
        # There is no global "all tenants" scan anywhere in this walker.
        rows = tenants_for(principal.principal_id);
        fkey = filter_key({});
        ts = now_ms();
        offset = 0;
        if self.cursor != "" {
            offset = decode_cursor(self.cursor, "", "tenant.list", fkey, ts);
            if offset < 0 {
                report deny("VALIDATION_FAILED", rid,
                            [{"field": "cursor", "message": "is not a usable cursor"}]);
                disengage;
            }
        }
        pg = page(rows, lim, offset, "", "tenant.list", fkey, ts);
        window: list = pg["items"];
        items: list = [
            tenant_view(row["tenant"], row["role"], _membership_id_in(row["tenant"], principal.principal_id))
            for row in window
        ];
        report ok({
            "items": items,
            "next_cursor": pg["next_cursor"],
            "has_more": pg["next_cursor"] != "",
            "total_visible": len(rows)
        }, 200);
        disengage;
    }
}

# --------------------------------------------------------------------------
# POST /tenants -- authenticated, tenantless -- tenant.create -- 201
# --------------------------------------------------------------------------

walker CreateTenant {
    has ctx: dict = {};
    has tenant_id: str = "";
    has name: str = "";
    has plan: str = "free";

    can go with entry {
        # `tenant.create` is guard()'s one TENANTLESS_ACTION: it skips
        # membership/role entirely and still authenticates the caller. tenant_id
        # and target_id are "" -- there is no tenant to scope this to yet.
        g = guard(ReqCtx(**self.ctx), "tenant.create", "tenant", "", "");
        rid = self.ctx.get("request_id", "");
        if not g.ok {
            report deny(g.reason, rid);
            disengage;
        }
        principal = cast(Principal, g.principal);

        errs: list = [];
        # v_pattern only runs once v_id already passed, so a malformed value
        # is reported once with the specific slug complaint, not twice.
        if v_id(errs, "tenant_id", self.tenant_id) {
            v_pattern(errs, "tenant_id", self.tenant_id, TENANT_ID_PATTERN, 64);
        }
        v_str(errs, "name", self.name, 1, MAX_NAME);
        v_enum(errs, "plan", self.plan, TENANT_PLAN_VALUES);
        if not clean(errs) {
            report deny("VALIDATION_FAILED", rid, errs);
            disengage;
        }

        # A tenant_id must be globally unique. This is the one sanctioned
        # global lookup in the app (app/model/resolve.jac: "a Tenant IS the
        # root of a tenancy; there is nothing above it to traverse from").
        if tenant_by_id(self.tenant_id) is not None {
            report deny("VALIDATION_FAILED", rid,
                        [{"field": "tenant_id", "message": "is already in use"}]);
            disengage;
        }

        ts = now_ms();
        plat = get_platform();
        t = (plat +>:Hosts:+> Tenant(
            tenant_id=self.tenant_id,
            name=self.name,
            plan=self.plan,
            status="active",
            created_at=ts
        ))[0];
        # Exactly ONE Membership, at role `owner`, for the AUTHENTICATED
        # principal. principal_id comes from g.principal, never from the
        # request body -- the caller cannot name a different owner, and this
        # walker attaches the new tenant to nothing else.
        m = (t +>:HasMember:+> Membership(
            membership_id=new_membership_id(),
            principal_id=principal.principal_id,
            tenant_id=t.tenant_id,
            role="owner",
            state="active",
            created_at=ts
        ))[0];
        mnode = m;
        mnode +>:Identifies:+> principal;
        report ok(tenant_view(t, "owner", m.membership_id), 201);
        disengage;
    }
}

# --------------------------------------------------------------------------
# GET /tenants/{tenant_id} -- viewer -- tenant.read -- 200
# --------------------------------------------------------------------------

walker ReadTenant {
    has ctx: dict = {};
    has tenant_id: str = "";

    can go with entry {
        g = guard(ReqCtx(**self.ctx), "tenant.read", "tenant", self.tenant_id, "");
        rid = self.ctx.get("request_id", "");
        if not g.ok {
            report deny(g.reason, rid);
            disengage;
        }
        sr = open_scope(g, ReqCtx(**self.ctx), self.tenant_id);
        if sr.scope is None {
            report deny(sr.reason, rid);
            disengage;
        }
        sc = sr.scope;
        if not role_satisfies(sc.role, "viewer") {
            report deny("INSUFFICIENT_ROLE", rid);
            disengage;
        }
        # No further traversal needed: open_scope() already re-read the
        # Membership from THIS tenant, so sc.tenant / sc.role / sc.membership
        # are the whole answer.
        report ok(tenant_view(sc.tenant, sc.role, sc.membership.membership_id), 200);
        disengage;
    }
}
