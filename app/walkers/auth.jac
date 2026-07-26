# app/walkers/auth.jac — the identity surface: register, login, logout, step-up,
# API tokens.
#
# TWO STRUCTURAL RULES HOLD IN THIS FILE.
#
# 1. Every `walker:priv` calls guard() as its FIRST executable statement. Not
#    after a validation, not after a log line — first. Resolution, authorization
#    and audit happen inside that one call, so there is no window in which this
#    walker has touched a record it was not yet allowed to touch.
#
# 2. No walker here calls emit_audit(). guard() already emitted exactly one
#    AuditEvent for the request, and `result_count` / `outcome` in that row are
#    the monitor's signals. A second emission from application code would
#    double-count and corrupt them. The only exceptions are Register and Login,
#    which run BEFORE any principal exists and therefore have nothing for guard()
#    to authorize; they call emit_preauth() exactly once each, on every path.
#
# THE ENUMERATION RULE. Register and Login are the two endpoints an attacker
# points a leaked-credential list at. Neither is allowed to tell that attacker
# anything:
#   * Register reports the SAME body for a fresh email and a taken one.
#   * Login reports the SAME body for a missing account, a wrong password, a
#     disabled principal, and a principal with no membership in the tenant — and
#     spends the same bcrypt work on all four, because verify_password() is
#     called on every path with "" standing in for a missing hash.

import from typing { cast }
import from contracts.req_ctx_contract { ReqCtx, Grant, guard }
import from app.security.reqctx { ctx_from }
import from app.security.authz { require_verified_ctx, emit_preauth }
import from app.security.clock { now_ms, SESSION_TTL_MS, API_TOKEN_TTL_MS }
import from app.security.passwords {
    hash_password, verify_password, new_secret, token_digest,
    password_complaint, secret_equals
}
import from app.security.roles { min_role_for, role_satisfies, rank_of }
import from contracts.audit_event_contract { ACTIONS }
import from app.model.graph {
    Platform, Tenant, Membership, Principal, Session, Token,
    Registers, Authenticates, Bears, get_platform
}
import from app.model.resolve {
    principal_by_email, session_by_id, membership_of, tenant_by_id
}

# --------------------------------------------------------------------------
# Scope arithmetic for minted API tokens.
#
# A token must never widen what its holder can already do. The requested scope
# is therefore INTERSECTED with the caller's role, entry by entry, before it is
# written to the Token node. A member asking for "member.invite" gets an empty
# scope back, not an admin token.
#
# A scope entry is either a full action ("task.read") or a family prefix
# ("task"). A family is priced at the STRICTEST action inside it, because
# granting the family grants every one of them. An unknown action or an unknown
# family prices at "owner", so a typo fails closed instead of sailing through.
# --------------------------------------------------------------------------

"""The role a scope entry really costs: the strictest requirement it grants.

The parameter is named `item` because `entry` is a Jac keyword."""
def _scope_min_role(item: str) -> str {
    if "." in item {
        return min_role_for(item);
    }
    prefix: str = item + ".";
    strictest: str = "viewer";
    matched: bool = False;
    for a in ACTIONS {
        action: str = a;
        if action.startswith(prefix) {
            matched = True;
            need: str = min_role_for(action);
            if rank_of(need) > rank_of(strictest) {
                strictest = need;
            }
        }
    }
    if not matched {
        return "owner";
    }
    return strictest;
}

# --------------------------------------------------------------------------
# Pre-authentication walkers. Public by necessity — there is no credential yet.
# --------------------------------------------------------------------------

walker:pub Register {
    has ctx: dict = {};
    has email: str = "";
    has password: str = "";

    can run with Root entry {
        v = require_verified_ctx(self.ctx, "auth.register", "auth");
        if not v["ok"] {
            report {"ok": False, "error": "CTX_UNVERIFIED"};
            return;
        }

        addr: str = self.email.strip().lower();
        complaint: str = password_complaint(self.password);

        # Password rules are surfaced here and ONLY here: at registration the
        # account does not exist yet, so a complaint reveals nothing about
        # anybody. Login never repeats them.
        if addr == "" or "@" not in addr {
            emit_preauth(self.ctx, "auth.register", "deny", "VALIDATION_FAILED", email=addr);
            report {"ok": False, "error": "a valid email address is required"};
            return;
        }
        if complaint != "" {
            emit_preauth(self.ctx, "auth.register", "deny", "VALIDATION_FAILED", email=addr);
            report {"ok": False, "error": complaint};
            return;
        }

        # The generic acknowledgement. Built once, reported identically whether
        # the address was free or already taken, and carrying no principal_id --
        # an id in the body would be a difference an attacker could measure.
        acknowledged: dict = {"ok": True, "email": addr, "status": "registered"};

        existing = principal_by_email(addr);
        if existing is not None {
            # Taken. Nothing is created and nothing is said. The audit row
            # records the collision so an operator can see the enumeration
            # attempt that the client cannot.
            emit_preauth(self.ctx, "auth.register", "deny", "VALIDATION_FAILED", email=addr);
            report acknowledged;
            return;
        }

        now = now_ms();
        platform = get_platform();
        pid: str = new_secret(16);
        platform +>:Registers:+> Principal(
            principal_id=pid,
            email=addr,
            pw_hash=hash_password(self.password),
            status="active",
            mfa=False,
            created_at=now
        );
        emit_preauth(self.ctx, "auth.register", "allow", "", principal_id=pid, email=addr);
        report acknowledged;
    }
}

walker:pub Login {
    has ctx: dict = {};
    has email: str = "";
    has password: str = "";
    has tenant_id: str = "";

    can run with Root entry {
        v = require_verified_ctx(self.ctx, "auth.login", "auth");
        if not v["ok"] {
            report {"ok": False, "error": "CTX_UNVERIFIED"};
            return;
        }
        vctx: dict = v["ctx"];
        addr: str = self.email.strip().lower();

        # The lookup may miss, and the miss must not change the WORK that
        # follows. A missing account passes "" to verify_password, which burns a
        # full bcrypt verify against a decoy hash before returning False.
        # Branching around this call — returning early on a miss — would hand
        # back a response-time account-enumeration oracle for free.
        found = principal_by_email(addr);
        stored: str = "";
        principal_id: str = "";
        if found is not None {
            known = cast(Principal, found);
            stored = known.pw_hash;
            principal_id = known.principal_id;
        }
        matched = verify_password(self.password, stored);

        # ONE deny funnel, four causes. No account, wrong password, a
        # non-active principal, and no active membership in the requested tenant
        # all set the same flag and leave through the same statement, so the
        # body, the error string and the field set are identical for all four.
        denied: bool = not matched;
        if not denied and found is None {
            denied = True;
        }
        if not denied {
            actor = cast(Principal, found);
            if actor.status != "active" {
                denied = True;
            }
        }
        if not denied {
            member_ok: bool = False;
            t = tenant_by_id(self.tenant_id);
            if t is not None {
                tenant = cast(Tenant, t);
                if tenant.status == "active" {
                    mem = membership_of(tenant, principal_id);
                    if mem is not None {
                        if cast(Membership, mem).state == "active" {
                            member_ok = True;
                        }
                    }
                }
            }
            if not member_ok {
                denied = True;
            }
        }

        if denied {
            # principal_id is written to the AUDIT ROW, never to the response.
            # The operator gets to see which known account was targeted; the
            # client learns only that something did not line up.
            emit_preauth(self.ctx, "auth.login_failed", "deny", "VALIDATION_FAILED",
                         principal_id=principal_id, email=addr, tenant_id=self.tenant_id);
            report {"ok": False, "error": "invalid credentials"};
            return;
        }

        actor = cast(Principal, found);
        now = now_ms();
        sid: str = new_secret();
        expires: int = now + SESSION_TTL_MS;
        ip: str = vctx.get("src_ip", "");
        fp: str = vctx.get("client_fp", "");

        # The session is TENANT-SCOPED at issue time. Reusing it against another
        # tenant_id is what guard() reports as TENANT_MISMATCH.
        actor +>:Authenticates:+> Session(
            session_id=sid,
            principal_id=actor.principal_id,
            tenant_id=self.tenant_id,
            ip_first=ip,
            fp=fp,
            issued_at=now,
            expires_at=expires,
            last_auth_at=now,
            revoked=False
        );
        emit_preauth(self.ctx, "auth.login", "allow", "",
                     principal_id=actor.principal_id, email=addr,
                     tenant_id=self.tenant_id, session_id=sid);
        report {"ok": True, "session_id": sid, "expires_at": expires};
    }
}

# --------------------------------------------------------------------------
# Authenticated walkers. guard() first, always.
# --------------------------------------------------------------------------

walker:priv Logout {
    has ctx: dict = {};
    has tenant_id: str = "";

    can run with Root entry {
        g = guard(ctx_from(self.ctx), "auth.logout", "auth", self.tenant_id);
        if not g.ok {
            report {"ok": False, "error": g.reason};
            return;
        }
        # guard() verified the ctx signature, so session_id on it is now a fact
        # the gateway observed rather than a claim the client made. A caller can
        # only ever revoke the session they actually presented.
        sid: str = self.ctx.get("session_id", "");
        current = session_by_id(sid);
        if current is not None {
            cast(Session, current).revoked = True;
        }
        report {"ok": True};
    }
}

walker:priv SessionInfo {
    has ctx: dict = {};
    has tenant_id: str = "";

    can run with Root entry {
        g = guard(ctx_from(self.ctx), "tenant.read", "tenant", self.tenant_id);
        if not g.ok {
            report {"ok": False, "error": g.reason};
            return;
        }
        actor = cast(Principal, g.principal);
        mem = cast(Membership, g.membership);
        tenant = cast(Tenant, g.tenant);
        sid: str = self.ctx.get("session_id", "");
        expires: int = 0;
        current = session_by_id(sid);
        if current is not None {
            expires = cast(Session, current).expires_at;
        }
        # pw_hash is deliberately absent, and there is no verbose/debug flag
        # that would add it.
        report {
            "ok": True,
            "principal_id": actor.principal_id,
            "email": actor.email,
            "role": mem.role,
            "tenant_id": tenant.tenant_id,
            "session_expires_at": expires
        };
    }
}

walker:priv Reauth {
    has ctx: dict = {};
    has tenant_id: str = "";
    has password: str = "";

    can run with Root entry {
        g = guard(ctx_from(self.ctx), "auth.reauth_required", "auth", self.tenant_id);
        if not g.ok {
            report {"ok": False, "error": g.reason};
            return;
        }
        actor = cast(Principal, g.principal);
        if not verify_password(self.password, actor.pw_hash) {
            report {"ok": False, "error": "invalid credentials"};
            return;
        }
        # last_auth_at is the step-up clock guard() reads when a force_reauth
        # containment control is active. Stamping it here is the ONLY way that
        # control is cleared — there is no flag that switches it off.
        sid: str = self.ctx.get("session_id", "");
        current = session_by_id(sid);
        if current is not None {
            cast(Session, current).last_auth_at = now_ms();
        }
        report {"ok": True};
    }
}

walker:priv IssueToken {
    has ctx: dict = {};
    has tenant_id: str = "";
    has scope: str = "";

    can run with Root entry {
        g = guard(ctx_from(self.ctx), "auth.token_issued", "token", self.tenant_id);
        if not g.ok {
            report {"ok": False, "error": g.reason};
            return;
        }
        actor = cast(Principal, g.principal);
        held: str = cast(Membership, g.membership).role;

        # A token is a NARROWING of its holder's authority, never a widening.
        # Entries the caller's own role cannot satisfy are dropped, not granted,
        # so a member cannot mint an admin-scoped token and then present it back.
        granted: list = [];
        dropped: list = [];
        for raw in self.scope.split() {
            item: str = raw;
            if role_satisfies(held, _scope_min_role(item)) {
                granted.append(item);
            } else {
                dropped.append(item);
            }
        }

        now = now_ms();
        jti: str = new_secret();
        expires: int = now + API_TOKEN_TTL_MS;
        effective: str = " ".join(granted);
        actor +>:Bears:+> Token(
            jti=jti,
            principal_id=actor.principal_id,
            tenant_id=self.tenant_id,
            kind="api",
            scope=effective,
            issued_at=now,
            expires_at=expires,
            revoked=False
        );
        # The jti is shown exactly once, here. Nothing else in this application
        # reads it back out to a client.
        report {
            "ok": True,
            "jti": jti,
            "scope": effective,
            "dropped_scope": dropped,
            "expires_at": expires
        };
    }
}

walker:priv RevokeToken {
    has ctx: dict = {};
    has tenant_id: str = "";
    has jti: str = "";

    can run with Root entry {
        g = guard(ctx_from(self.ctx), "auth.token_revoked", "token", self.tenant_id);
        if not g.ok {
            report {"ok": False, "error": g.reason};
            return;
        }
        actor = cast(Principal, g.principal);
        # Resolved through the caller's OWN Bears edge, never by a global jti
        # lookup: another principal's token is unreachable from here rather than
        # reachable-and-rejected.
        if self.jti != "" {
            for t in [actor->:Bears:->][?:Token] {
                if secret_equals(t.jti, self.jti) {
                    t.revoked = True;
                }
            }
        }
        # The same body whether the jti existed, belonged to someone else, or
        # was invented. Reporting "not found" here would turn this endpoint into
        # a jti oracle.
        report {"ok": True};
    }
}
