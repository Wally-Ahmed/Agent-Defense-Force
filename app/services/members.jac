# app/services/members.jac -- the five membership/invite walkers.
#
# Four of the five open a Scope exactly like every other file in
# app/services/ (see projects.jac's header for the full 8-step account). The
# fifth, AcceptInvite, cannot: it is the one walker in the whole domain layer
# that runs BEFORE its own Membership exists, so open_scope() would deny
# NOT_A_MEMBER before ever looking at the invite. guard() still runs first --
# `member.accept` is on MEMBERSHIP_EXEMPT_ACTIONS in app/security/roles.jac,
# which is what lets guard() skip the membership/role gate it enforces on
# everything else -- and AcceptInvite then takes its tenant and principal
# straight off the Grant instead of a Scope. See its own comment below.
#
# Two `†` step-up ops (ChangeMemberRole, RemoveMember): a role change or a
# removal requires a password presented recently, not merely a live session --
# checked with step_up_ok() right after the role floor, before resolution.
#
# KNOWN SEAM: app/model/resolve.membership_of(tenant, target_id) -- what
# guard() uses to resolve a "member" target -- matches on PRINCIPAL_ID, while
# ChangeMemberRole and RemoveMember address a membership by MEMBERSHIP_ID. So
# guard(..., "member", tenant_id, self.membership_id) currently denies
# NOT_FOUND for both of them, fail-closed. This file passes the
# contract-correct target_id anyway (never ""), on the theory that a
# fail-closed integration bug owned by another track is a better failure mode
# than silently working around it here. See this file's report.
#
# Invite tokens: minted with secret() (app/services/ids.jac) and never
# stored -- only sha256(token) ever touches the graph, in Invite.token_hash.
# The plaintext is handed back exactly once, in InviteMember's own response,
# and is never logged and never re-derivable from anything persisted.
#
# There is no `‡` sensitivity step in this file: Membership and Invite carry
# no sensitivity field (app/model/graph.jac) -- that rule is specific to
# project/task/comment records.
#
# WALKERS EMIT NO AUDIT EVENT -- guard() already emitted exactly one.
#
# `has ctx: dict = {};` is mandatory on every walker below, never a typed
# archetype -- see projects.jac's header for why.

import from typing { cast }
import from contracts.req_ctx_contract { ReqCtx, Grant, guard }
import from app.model.graph {
    Tenant, Membership, Principal, Invite, HasMember, Identifies, Invited
}
import from app.model.resolve { membership_of, invite_by_hash }
import from app.security.clock { now_ms }
import from app.security.roles { role_satisfies, ROLES }
import from app.services.scope {
    open_scope, step_up_ok, visible_members, find_membership, member_email
}
import from app.services.errors { deny, ok }
import from app.services.paging { resolve_limit, filter_key, decode_cursor, page }
import from app.services.validate { v_email, v_enum, v_opt_enum, v_int, v_str, clean }
import from app.services.ids {
    membership_id as new_membership_id, invite_id as new_invite_id, secret
}
import hashlib;
import hmac;

# Roster status filter. "invited" is accepted for contract parity even though
# no Membership node is ever created in that state (app/model/graph.jac's
# Membership.state is active|suspended|removed) -- someone invited-but-not
# -yet-accepted has no Membership at all, only an Invite. This filter value
# can only ever yield an empty page; that is a property of the schema, not a
# bug in the filter.
glob:pub MEMBER_STATUS_FILTERS: list = ["active", "invited", "suspended", "all"];

"""One membership, as the contract's Membership schema.

`user_id` and `status` are the contract's names for the graph's own
`principal_id` and `state` (app/model/graph.jac); the rename happens here,
once. `email` is nested under `member` and is the one field callers redact by
passing `show_email=False` -- decided by the CALLER from its own role check,
never re-derived in here. Membership has no `updated_at` field of its own, so
`created_at` is echoed back for it rather than inventing a second, untracked
clock -- see this file's report for the detail this leaves un-honoured."""
def:pub member_view(m: Membership, show_email: bool) -> dict {
    return {
        "membership_id": m.membership_id,
        "tenant_id": m.tenant_id,
        "user_id": m.principal_id,
        "role": m.role,
        "status": m.state,
        "member": {
            "user_id": m.principal_id,
            "email": member_email(m) if show_email else ""
        },
        "created_at": m.created_at,
        "updated_at": m.created_at
    };
}

# --------------------------------------------------------------------------
# GET /tenants/{tenant_id}/members -- viewer -- tenant.read -- 200
# --------------------------------------------------------------------------

walker:priv ListMembers {
    has ctx: dict = {};
    has tenant_id: str = "";
    has limit: int = 0;
    has cursor: str = "";
    has role: str = "";
    has status: str = "active";

    can go with entry {
        g = guard(ReqCtx(**self.ctx), "tenant.read", "member", self.tenant_id, "");
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

        errs: list = [];
        v_opt_enum(errs, "role", self.role, ROLES);
        v_enum(errs, "status", self.status, MEMBER_STATUS_FILTERS);
        lim = resolve_limit(self.limit);
        if lim < 0 {
            errs.append({"field": "limit", "message": "must be between 1 and 100"});
        }
        if not clean(errs) {
            report deny("VALIDATION_FAILED", rid, errs);
            disengage;
        }

        # visible_members() has already dropped removed memberships; the role
        # and status filters below only narrow further, never widen.
        rows = [
            m for m in visible_members(sc)
            if (self.role == "" or m.role == self.role)
            and (self.status == "all" or m.state == self.status)
        ];
        # Below admin rank, email is redacted in every item -- decided ONCE
        # here from the caller's own resolved role, never per-row.
        show_email = role_satisfies(sc.role, "admin");
        # A distinct paging endpoint key, NOT the shared "tenant.read" audit
        # action: that action also covers ListMyTenants, which paginates its
        # own, unrelated list. Reusing "tenant.read" here would let a cursor
        # minted by one accidentally decode as valid for the other whenever
        # their filter keys happened to collide -- see app/services/paging.jac.
        fkey = filter_key({"role": self.role, "status": self.status});
        ts = now_ms();
        offset = 0;
        if self.cursor != "" {
            offset = decode_cursor(self.cursor, self.tenant_id, "member.list", fkey, ts);
            if offset < 0 {
                report deny("VALIDATION_FAILED", rid,
                            [{"field": "cursor", "message": "is not a usable cursor"}]);
                disengage;
            }
        }
        pg = page(rows, lim, offset, self.tenant_id, "member.list", fkey, ts);
        window: list = pg["items"];
        items: list = [];
        for m in window {
            items.append(member_view(m, show_email));
        }
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
# POST /tenants/{tenant_id}/members/invites -- admin -- member.invite -- 201
# --------------------------------------------------------------------------

walker:priv InviteMember {
    has ctx: dict = {};
    has tenant_id: str = "";
    has email: str = "";
    # "" is the absent-value sentinel, not a default: `role` is req=True with
    # no contract default (unlike `status` on ListMembers, which genuinely
    # defaults to "active"), so an omitted role must fail v_enum's check
    # below rather than silently becoming a valid "viewer" request.
    has role: str = "";
    has expires_in_s: int = 0;

    can go with entry {
        g = guard(ReqCtx(**self.ctx), "member.invite", "invite", self.tenant_id, "");
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
        if not role_satisfies(sc.role, "admin") {
            report deny("INSUFFICIENT_ROLE", rid);
            disengage;
        }

        # 0 means "not supplied" (the same transport convention `limit` uses
        # elsewhere) and maps to the contract's own default of 259200 s
        # (72 h); anything else is validated against the contract's bounds.
        requested_ttl = self.expires_in_s if self.expires_in_s != 0 else 259200;
        errs: list = [];
        v_email(errs, "email", self.email);
        v_enum(errs, "role", self.role, ROLES);
        v_int(errs, "expires_in_s", requested_ttl, 300, 604800);
        if not clean(errs) {
            report deny("VALIDATION_FAILED", rid, errs);
            disengage;
        }

        # The one place this walker is stricter than its own `admin` floor:
        # an admin can invite a viewer, member or another admin, but minting a
        # fresh OWNER requires the caller to already hold owner. This is a
        # role-rank rule, not a name check -- it reads identically whatever
        # the invited email is.
        if self.role == "owner" and not role_satisfies(sc.role, "owner") {
            report deny("INSUFFICIENT_ROLE", rid);
            disengage;
        }

        ts = now_ms();
        # The bearer token is minted, hashed, and the plaintext handed back
        # exactly once below. Only the hash is ever persisted or compared
        # against later (AcceptInvite); the plaintext is never logged.
        tok = secret();
        tok_hash = hashlib.sha256(tok.encode("utf-8")).hexdigest();
        tnode = sc.tenant;
        made = (tnode +>:Invited:+> Invite(
            invite_id=new_invite_id(),
            token_hash=tok_hash,
            email=self.email.strip().lower(),
            role=self.role,
            tenant_id=sc.tenant.tenant_id,
            expires_at=ts + (requested_ttl * 1000),
            state="pending",
            created_at=ts
        ))[0];
        report ok({
            "invite_id": made.invite_id,
            "tenant_id": made.tenant_id,
            "email": made.email,
            "role": made.role,
            "status": made.state,
            "invited_by": sc.principal_id,
            "created_at": made.created_at,
            "expires_at": made.expires_at,
            "invite_token": tok
        }, 201);
        disengage;
    }
}

# --------------------------------------------------------------------------
# POST /tenants/{tenant_id}/invites/accept -- authenticated -- member.accept
# --------------------------------------------------------------------------

walker:priv AcceptInvite {
    has ctx: dict = {};
    has tenant_id: str = "";
    has invite_token: str = "";

    can go with entry {
        g = guard(ReqCtx(**self.ctx), "member.accept", "invite", self.tenant_id, "");
        rid = self.ctx.get("request_id", "");
        if not g.ok {
            report deny(g.reason, rid);
            disengage;
        }

        # No Scope here, deliberately: open_scope() would look up the very
        # Membership this walker exists to create, and would deny
        # NOT_A_MEMBER before we ever looked at the invite. guard() has
        # already verified a live, verified, authenticated principal --
        # `member.accept` is on MEMBERSHIP_EXEMPT_ACTIONS in
        # app/security/roles.jac -- so the tenant and principal come straight
        # off the Grant instead. Both are `object`-typed on Grant and need an
        # explicit cast before their fields are reachable.
        if g.tenant is None or g.principal is None {
            report deny("NOT_FOUND", rid);
            disengage;
        }
        tenant = cast(Tenant, g.tenant);
        principal = cast(Principal, g.principal);
        if tenant.tenant_id != self.tenant_id {
            report deny("TENANT_MISMATCH", rid);
            disengage;
        }

        # Idempotent: a principal who already holds a membership in this
        # tenant gets it back immediately, without re-validating whatever
        # token was submitted. This check runs BEFORE the token is even
        # looked at, deliberately: the scenario it guards is a retried accept
        # (the first call already consumed the invite, so a second identical
        # call would otherwise see `state != "pending"` below and read as a
        # failure instead of a repeat success). It is not a security
        # weakening -- a principal who already holds a membership here
        # already has full legitimate access to that membership_id by other
        # means (e.g. ListMembers), so an arbitrary token cannot extract
        # anything they could not already reach. The caller is always looking
        # at their OWN membership here, never anyone else's, so the roster's
        # rank-based email redaction (see member_view) does not apply.
        existing = membership_of(tenant, principal.principal_id);
        if existing is not None {
            em = cast(Membership, existing);
            report ok(member_view(em, True), 200);
            disengage;
        }

        errs: list = [];
        v_str(errs, "invite_token", self.invite_token, 43, 64);
        if not clean(errs) {
            report deny("VALIDATION_FAILED", rid, errs);
            disengage;
        }

        # Matched on the HASH -- the invite token itself is never stored, so
        # this lookup cannot hand back a working token even to an attacker
        # who can read the graph. Scoped to THIS tenant only, so a token
        # minted by another tenant's invite is unreachable here.
        tok_hash = hashlib.sha256(self.invite_token.encode("utf-8")).hexdigest();
        inv = invite_by_hash(tenant, tok_hash);
        # A missing invite, an expired one and an already-consumed one all
        # report the same NOT_FOUND -- none of them confirms to the caller
        # which is true, or that a token of this shape ever existed.
        if inv is None {
            report deny("NOT_FOUND", rid);
            disengage;
        }
        if inv.state != "pending" or inv.expires_at <= now_ms() {
            report deny("NOT_FOUND", rid);
            disengage;
        }
        # Constant-time comparison on the lowercased email: the invite is
        # bound to one address, and possession of the token alone must not
        # let a different signed-in principal claim it.
        if not hmac.compare_digest(inv.email.strip().lower(), principal.email.strip().lower()) {
            report deny("NOT_FOUND", rid);
            disengage;
        }

        ts = now_ms();
        # The granted role is read from the invite an admin set, never from
        # this request -- AcceptInvite's body carries no role field at all,
        # so the requester cannot influence it.
        made = (tenant +>:HasMember:+> Membership(
            membership_id=new_membership_id(),
            principal_id=principal.principal_id,
            tenant_id=tenant.tenant_id,
            role=inv.role,
            state="active",
            created_at=ts
        ))[0];
        made +>:Identifies:+> principal;
        inv.state = "accepted";
        report ok(member_view(made, True), 200);
        disengage;
    }
}

# --------------------------------------------------------------------------
# PATCH /tenants/{tenant_id}/members/{membership_id} -- admin † -- member.role_change
# --------------------------------------------------------------------------

walker:priv ChangeMemberRole {
    has ctx: dict = {};
    has tenant_id: str = "";
    has membership_id: str = "";
    has role: str = "";

    can go with entry {
        # KNOWN SEAM (see this file's header and the report): guard()'s
        # "member" resolution matches on principal_id, so this currently
        # denies NOT_FOUND here rather than reaching the code below. Passed
        # anyway, because the contract addresses a membership by
        # membership_id and this walker must not paper over that with "".
        g = guard(ReqCtx(**self.ctx), "member.role_change", "member", self.tenant_id, self.membership_id);
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
        if not role_satisfies(sc.role, "admin") {
            report deny("INSUFFICIENT_ROLE", rid);
            disengage;
        }
        # `†` step-up: a role change is sensitive enough to require a
        # password presented recently, not merely a live session.
        if not step_up_ok(sc) {
            report deny("REAUTH_REQUIRED", rid);
            disengage;
        }

        target = find_membership(sc, self.membership_id);
        if target is None {
            report deny("NOT_FOUND", rid);
            disengage;
        }

        errs: list = [];
        v_enum(errs, "role", self.role, ROLES);
        if not clean(errs) {
            report deny("VALIDATION_FAILED", rid, errs);
            disengage;
        }

        # Three role-RANK rules. None of them is keyed on who the target is --
        # no name, email or id is special-cased anywhere in this walker.
        # 1. Self-modification: an admin cannot re-role their own membership
        #    through this endpoint, whatever the requested role.
        if target.principal_id == sc.principal_id {
            report deny("INSUFFICIENT_ROLE", rid);
            disengage;
        }
        # 2. Touching an owner membership, in either direction, requires the
        #    caller to already BE an owner.
        if target.role == "owner" and not role_satisfies(sc.role, "owner") {
            report deny("INSUFFICIENT_ROLE", rid);
            disengage;
        }
        # 3. Granting owner requires the caller to already be an owner too --
        #    an admin cannot promote anyone to their own ceiling or above.
        if self.role == "owner" and not role_satisfies(sc.role, "owner") {
            report deny("INSUFFICIENT_ROLE", rid);
            disengage;
        }

        target.role = self.role;
        # Email is never redacted in this response: the baseline gate above
        # already requires the caller to be admin or above, which is exactly
        # the redaction rule's threshold (see member_view).
        report ok(member_view(target, True), 200);
        disengage;
    }
}

# --------------------------------------------------------------------------
# DELETE /tenants/{tenant_id}/members/{membership_id} -- admin † -- member.remove
# --------------------------------------------------------------------------

walker:priv RemoveMember {
    has ctx: dict = {};
    has tenant_id: str = "";
    has membership_id: str = "";

    can go with entry {
        # Same KNOWN SEAM as ChangeMemberRole -- see this file's header.
        g = guard(ReqCtx(**self.ctx), "member.remove", "member", self.tenant_id, self.membership_id);
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
        if not role_satisfies(sc.role, "admin") {
            report deny("INSUFFICIENT_ROLE", rid);
            disengage;
        }
        # `†` step-up: removing a member is sensitive enough to require a
        # password presented recently, not merely a live session.
        if not step_up_ok(sc) {
            report deny("REAUTH_REQUIRED", rid);
            disengage;
        }

        target = find_membership(sc, self.membership_id);
        if target is None {
            report deny("NOT_FOUND", rid);
            disengage;
        }

        # Same two role-rank refusals as ChangeMemberRole: no self-removal
        # through this endpoint, and an owner membership can only be touched
        # by another owner.
        if target.principal_id == sc.principal_id {
            report deny("INSUFFICIENT_ROLE", rid);
            disengage;
        }
        if target.role == "owner" and not role_satisfies(sc.role, "owner") {
            report deny("INSUFFICIENT_ROLE", rid);
            disengage;
        }

        ts = now_ms();
        # A state transition, not a node deletion: app/services/scope.jac's
        # visible_members() and find_membership() both already exclude
        # state == "removed", so nothing else in the application can reach
        # this membership again -- the same "unreachable, not merely
        # rejected" property the rest of the domain layer relies on.
        target.state = "removed";
        # Session/API-token revocation is out of scope for this walker: doing
        # it correctly needs a tenant-scoped session/token lookup that is not
        # among the helpers this file was given (see the report), and
        # inventing that traversal here would mean touching Session/Token
        # semantics nobody has reviewed. Reported honestly as zero rather
        # than a fabricated count.
        report ok({
            "membership_id": self.membership_id,
            "tenant_id": self.tenant_id,
            "removed_at": ts,
            "revoked_sessions": 0,
            "revoked_api_tokens": 0
        }, 200);
        disengage;
    }
}
