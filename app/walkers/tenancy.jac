# app/walkers/tenancy.jac — tenants, invitations and membership roles.
#
# Every walker here is `:priv` and calls guard() as its FIRST statement. None of
# them writes its own audit event: guard() already wrote exactly one AuditEvent
# for the request, and a second would double-count the monitor's signals. The
# post-guard rejections below therefore report an error and emit NOTHING — the
# audit row for the request is guard()'s allow, which is the truth: the caller
# WAS authorized to attempt the operation, and the operation was refused on a
# domain invariant.
#
# THE ESCALATION RULES, in one place:
#   * an invite may not carry a role above the inviter's own;
#   * a role change may not raise anyone above the caller's own role;
#   * nobody changes their OWN role;
#   * nobody modifies a membership that outranks them (so an admin can never
#     touch an owner);
#   * the last active owner of a tenant cannot be removed, including by
#     themselves.
#
# Roles are compared with rank_of() from app/security/roles.jac, never with an
# inline string comparison — an unknown role ranks BELOW viewer there, so a
# corrupted or attacker-supplied role value can never win a comparison.

import from typing { cast }
import from contracts.req_ctx_contract { ReqCtx, Grant, guard }
import from app.security.reqctx { ctx_from }
import from app.security.clock { now_ms, INVITE_TTL_MS }
import from app.security.passwords { new_secret, token_digest }
import from app.security.roles { ROLES, rank_of }
import from app.model.graph {
    Platform, Tenant, Membership, Principal, Invite,
    Hosts, HasMember, Identifies, Invited, get_platform, Session
}
import from app.model.resolve {
    membership_of, memberships_of, invite_by_hash, session_by_id
}

walker:priv CreateTenant {
    has ctx: dict = {};
    has name: str = "";

    can run with Root entry {
        # tenant_id is "" because "tenant.create" is in TENANTLESS_ACTIONS: there
        # is no tenant to be a member of yet. guard() still demands a verified
        # ctx, a live unrevoked credential and a clean containment check; only
        # the membership and role steps are skipped.
        g = guard(ctx_from(self.ctx), "tenant.create", "tenant", "");
        if not g.ok {
            report {"ok": False, "error": g.reason};
            return;
        }
        label: str = self.name.strip();
        if label == "" {
            report {"ok": False, "error": "VALIDATION_FAILED"};
            return;
        }

        actor = cast(Principal, g.principal);
        now = now_ms();
        tid: str = new_secret(12);
        platform = get_platform();

        tenant = (platform +>:Hosts:+> Tenant(
            tenant_id=tid,
            name=label,
            plan="free",
            status="active",
            created_at=now
        ))[0];

        # The creator is the first owner. Written as an edge, not a flag: the
        # tenant's membership set IS the access list, and Tenant -HasMember->
        # Membership -Identifies-> Principal is the only path to it.
        membership = (tenant +>:HasMember:+> Membership(
            membership_id=new_secret(12),
            principal_id=actor.principal_id,
            tenant_id=tid,
            role="owner",
            state="active",
            created_at=now
        ))[0];
        membership +>:Identifies:+> actor;

        # Bind the caller's TENANTLESS session to the tenant they just created.
        # A session is tenant-scoped, so without this the founder would create a
        # workspace and immediately be denied TENANT_MISMATCH on every action
        # inside it until they logged in again.
        #
        # This is a re-scope, never a widening: the session is looked up by the
        # id in the VERIFIED ctx (so it is the caller's own), it is moved only
        # if it is currently unscoped, and the destination is a tenant in which
        # this principal is, as of three lines ago, the owner. A session already
        # bound to some other tenant is left exactly where it is.
        bound: str = ctx_from(self.ctx).session_id;
        current = session_by_id(bound);
        if current is not None {
            live = cast(Session, current);
            if live.tenant_id == "" and live.principal_id == actor.principal_id {
                live.tenant_id = tid;
            }
        }

        report {"ok": True, "tenant_id": tid, "name": label, "role": "owner"};
    }
}

walker:priv ReadTenant {
    has ctx: dict = {};
    has tenant_id: str = "";

    can run with Root entry {
        g = guard(ctx_from(self.ctx), "tenant.read", "tenant", self.tenant_id);
        if not g.ok {
            report {"ok": False, "error": g.reason};
            return;
        }
        tenant = cast(Tenant, g.tenant);
        membership = cast(Membership, g.membership);
        report {
            "ok": True,
            "tenant_id": tenant.tenant_id,
            "name": tenant.name,
            "plan": tenant.plan,
            "status": tenant.status,
            "created_at": tenant.created_at,
            "role": membership.role
        };
    }
}

walker:priv InviteMember {
    has ctx: dict = {};
    has tenant_id: str = "";
    has email: str = "";
    has role: str = "viewer";

    can run with Root entry {
        g = guard(ctx_from(self.ctx), "member.invite", "invite", self.tenant_id);
        if not g.ok {
            report {"ok": False, "error": g.reason};
            return;
        }
        inviter = cast(Membership, g.membership);
        tenant = cast(Tenant, g.tenant);

        wanted: str = self.role.strip().lower();
        addr: str = self.email.strip().lower();

        if wanted not in ROLES or addr == "" or "@" not in addr {
            report {"ok": False, "error": "VALIDATION_FAILED"};
            return;
        }
        # An admin cannot mint an owner. Authority is not a thing you can hand
        # out more of than you hold.
        if rank_of(wanted) > rank_of(inviter.role) {
            report {"ok": False, "error": "VALIDATION_FAILED"};
            return;
        }

        now = now_ms();
        secret: str = new_secret();
        expires: int = now + INVITE_TTL_MS;
        # ONLY the digest is stored. A read of the graph — a dump, a backup, a
        # compromised export — therefore does not hand anyone a working invite.
        invite = (tenant +>:Invited:+> Invite(
            invite_id=new_secret(12),
            token_hash=token_digest(secret),
            email=addr,
            role=wanted,
            tenant_id=tenant.tenant_id,
            expires_at=expires,
            state="pending",
            created_at=now
        ))[0];

        # The raw token appears exactly here, once. It is not readable back out
        # of the graph afterwards, by anyone, including an owner.
        report {
            "ok": True,
            "invite_id": invite.invite_id,
            "token": secret,
            "email": addr,
            "role": wanted,
            "expires_at": expires
        };
    }
}

walker:priv AcceptInvite {
    has ctx: dict = {};
    has tenant_id: str = "";
    has token: str = "";

    can run with Root entry {
        # "member.accept" is in MEMBERSHIP_EXEMPT_ACTIONS — requiring a
        # membership to create a membership is circular. guard() still enforces
        # the verified ctx, the live credential, containment, the tenant's
        # existence and the tenant binding of the credential; the invite token
        # below is the control that stands in for the missing membership.
        g = guard(ctx_from(self.ctx), "member.accept", "invite", self.tenant_id);
        if not g.ok {
            report {"ok": False, "error": g.reason};
            return;
        }
        tenant = cast(Tenant, g.tenant);
        actor = cast(Principal, g.principal);
        now = now_ms();

        if self.token == "" {
            report {"ok": False, "error": "NOT_FOUND"};
            return;
        }

        # Looked up by HASH, and only inside the guarded tenant. An invite issued
        # by another tenant is unreachable from here rather than reachable and
        # rejected.
        found = invite_by_hash(tenant, token_digest(self.token));
        if found is None {
            report {"ok": False, "error": "NOT_FOUND"};
            return;
        }
        invite = cast(Invite, found);

        # A used, revoked or expired invite is reported exactly like a token that
        # never existed, so the endpoint is not an invite oracle.
        if invite.state != "pending" {
            report {"ok": False, "error": "NOT_FOUND"};
            return;
        }
        if invite.expires_at <= now {
            invite.state = "expired";
            report {"ok": False, "error": "NOT_FOUND"};
            return;
        }

        existing = membership_of(tenant, actor.principal_id);
        if existing is not None {
            # Already a member. The invite is consumed, but the role on the
            # existing membership is NOT overwritten -- an invite must never
            # become a second path to a role change.
            invite.state = "accepted";
            report {
                "ok": True,
                "tenant_id": tenant.tenant_id,
                "role": cast(Membership, existing).role
            };
            return;
        }

        membership = (tenant +>:HasMember:+> Membership(
            membership_id=new_secret(12),
            principal_id=actor.principal_id,
            tenant_id=tenant.tenant_id,
            role=invite.role,
            state="active",
            created_at=now
        ))[0];
        membership +>:Identifies:+> actor;
        invite.state = "accepted";

        report {"ok": True, "tenant_id": tenant.tenant_id, "role": invite.role};
    }
}

walker:priv ChangeRole {
    has ctx: dict = {};
    has tenant_id: str = "";
    has principal_id: str = "";
    has role: str = "";

    can run with Root entry {
        g = guard(ctx_from(self.ctx), "member.role_change", "member",
                  self.tenant_id, self.principal_id);
        if not g.ok {
            report {"ok": False, "error": g.reason};
            return;
        }
        caller = cast(Membership, g.membership);
        target = cast(Membership, g.node);
        wanted: str = self.role.strip().lower();

        if wanted not in ROLES {
            report {"ok": False, "error": "VALIDATION_FAILED"};
            return;
        }
        # 1. No minting authority you do not hold.
        if rank_of(wanted) > rank_of(caller.role) {
            report {"ok": False, "error": "INSUFFICIENT_ROLE"};
            return;
        }
        # 2. No self-escalation. The caller never edits their own row, in either
        #    direction: allowing a "harmless" self-demotion is what strands a
        #    tenant, and allowing a self-promotion is the whole attack.
        if target.principal_id == caller.principal_id {
            report {"ok": False, "error": "INSUFFICIENT_ROLE"};
            return;
        }
        # 3. No editing upward. An admin cannot touch an owner's membership --
        #    otherwise "admin" quietly means "can demote the owner and take the
        #    tenant". Combined with (2), the last owner of a tenant cannot be
        #    demoted at all: only an owner outranks an owner, and the sole owner
        #    is the caller.
        if rank_of(target.role) > rank_of(caller.role) {
            report {"ok": False, "error": "INSUFFICIENT_ROLE"};
            return;
        }

        previous: str = target.role;
        target.role = wanted;
        report {
            "ok": True,
            "principal_id": target.principal_id,
            "previous_role": previous,
            "role": wanted
        };
    }
}

walker:priv RemoveMember {
    has ctx: dict = {};
    has tenant_id: str = "";
    has principal_id: str = "";

    can run with Root entry {
        g = guard(ctx_from(self.ctx), "member.remove", "member",
                  self.tenant_id, self.principal_id);
        if not g.ok {
            report {"ok": False, "error": g.reason};
            return;
        }
        caller = cast(Membership, g.membership);
        target = cast(Membership, g.node);
        tenant = cast(Tenant, g.tenant);

        # No removing upward: an admin cannot remove an owner.
        if rank_of(target.role) > rank_of(caller.role) {
            report {"ok": False, "error": "INSUFFICIENT_ROLE"};
            return;
        }

        # A tenant with no owner is a tenant nobody can administer and nobody can
        # repair. This check covers self-removal too: the last owner deleting
        # themselves is the same condition.
        if target.role == "owner" and target.state == "active" {
            owners: int = 0;
            for m in memberships_of(tenant) {
                if m.role == "owner" and m.state == "active" {
                    owners = owners + 1;
                }
            }
            if owners <= 1 {
                report {"ok": False, "error": "the last owner of a tenant cannot be removed"};
                return;
            }
        }

        target.state = "removed";
        report {"ok": True, "principal_id": target.principal_id, "state": "removed"};
    }
}
