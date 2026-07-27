# mesh/bridge/mesh_world.jac
#
# The synthetic world the live incident is about.
#
# containment/executor.jac has exactly one power: it writes Control nodes onto
# the app's object graph. For that to mean anything, the graph has to contain
# the entities the incident NAMES — the tenant, the compromised principal, its
# sessions and token — otherwise every action resolves to an empty scope and the
# gate rejects it before a single Control is written. A containment run against
# an empty graph is not a containment run; it is a no-op wearing its costume.
#
# So this module seeds a world FROM THE INCIDENT ITSELF: every id here is read
# out of `incident.join_keys`, never hard-coded. Point it at a different
# incident.v1 and it seeds that incident's world instead.
#
# WHY THE BYSTANDERS. The containment probes are not decorative. After each
# apply, `probes.run_health` looks for an UNCONTAINED member of the same tenant
# and checks that they can still list their projects — the availability half of
# "contain the attacker, not the product". `find_bystander` returning nothing is
# reported as a probe FAILURE, so a tenant of one would make every containment
# roll itself back. The bystanders also give `policy.blast_radius` an honest
# denominator: suspending 1 of 41 actives is 2.4% and auto-approves, whereas
# suspending the only principal in a tenant is a blanket shutdown and is refused.
# Their IPs are deliberately disjoint from the incident's attack sources so that
# `block_source` is narrow rather than a shared-NAT case needing a human.
#
# NOTHING HERE IS A BACKDOOR. These are ordinary Principal/Session/Token nodes
# created through the same constructors the app uses. There is no test hook, no
# bypass flag, and no privileged path — the containment gate, the approval
# policy and the probes all run against them exactly as they would in production.
#
# THIS IS THE DOCUMENTED SYNTHETIC TEST IDENTITY. No real credential, no real
# person and no real tenant is represented. `pw_hash` is the literal string "x"
# because nothing in the containment path ever authenticates a password; the
# probes sign their own request context with APP_CTX_SIGNING_KEY, which the
# caller supplies as a per-run throwaway.
#
# Run it from an isolated CWD. Jac's anchor store lives at
# `$PWD/.jac/data/anchor_store.db`, so seeding from a scratch workspace gives
# this run its own empty graph and leaves the repo's shared store untouched —
# the same convention containment/run_verify.sh established.

import os;
import sys;

glob:pub HERE: str = os.path.dirname(os.path.abspath(__file__));
glob:pub REPO_ROOT: str = os.path.dirname(os.path.dirname(HERE));

with entry {
    # Jac resolves `import from <name>` against sys.path, which starts at the
    # INVOCATION directory, not this file's directory. The containment and app
    # modules import each other by their full dotted path from the repo root,
    # so the repo root is what has to be on the path. Runs at module load, in
    # source order, BEFORE the imports below it.
    if REPO_ROOT not in sys.path {
        sys.path.insert(0, REPO_ROOT);
    }
}

import from app.model.graph {
    Platform, Tenant, Membership, Principal, Session, Token, Project,
    Hosts, Registers, HasMember, Identifies, Owns, Authenticates, Bears,
    get_platform
}
import from app.model.resolve { principal_by_id }
import from app.security.clock { now_ms }

glob:pub HOUR_MS: int = 3600000;

"""How many uncontained members the incident's tenant gets.

40 is not arbitrary. `suspend_principal` auto-approves only below 5% of a
tenant's actives (policy.SUSPEND_AUTO_PCT); with the compromised principal that
is 1/41 = 2.4%, so the coordinator's decision is executable without inventing a
human approver. Drop this below 20 and the same decision would legitimately
stall awaiting sign-off."""
glob:pub BYSTANDERS: int = 40;

"""Zero-padded index, so ids sort lexicographically."""
def pad(n: int) -> str {
    s: str = str(n);
    while len(s) < 3 {
        s = "0" + s;
    }
    return s;
}

"""Read a list-valued join key, tolerating a bare string or an absent key."""
def _ids(join_keys: dict, field: str) -> list {
    raw = join_keys.get(field, []);
    if isinstance(raw, str) {
        if raw == "" {
            return [];
        }
        return [raw];
    }
    if raw is None {
        return [];
    }
    return [str(x) for x in raw];
}

"""Seed the world an incident.v1 describes. Returns what it created.

Reads `incident["join_keys"]` for the tenant, the compromised principal, its
session ids and the attack source IPs. Every one of those becomes a real node,
so the containment scope resolver has something to resolve against.

Idempotent on the tenant: if `tenant` already exists this is a no-op returning
`seeded: False`, so a driver that re-runs in a dirty workspace does not build a
second, conflicting world."""
def:pub seed_incident_world(incident: dict, bystanders: int = 0) -> dict {
    ts: int = now_ms();
    join_keys: dict = incident.get("join_keys", {});

    tenant_id: str = str(join_keys.get("tenant", ""));
    principal_id: str = str(join_keys.get("principal_hash", ""));
    session_ids: list = _ids(join_keys, "session_ids");
    src_ips: list = _ids(join_keys, "src_ips");

    if tenant_id == "" or principal_id == "" {
        raise ValueError(
            "incident.join_keys must carry both `tenant` and `principal_hash`; "
            + "without them there is no world to seed and containment would "
            + "resolve every action to an empty scope"
        );
    }

    n: int = bystanders;
    if n <= 0 {
        n = BYSTANDERS;
    }

    plat = get_platform();

    # Already seeded — say so rather than building a second world on top.
    if principal_by_id(principal_id) is not None {
        return {
            "seeded": False,
            "tenant_id": tenant_id,
            "principal_id": principal_id,
            "detail": "world already present in this graph; nothing created"
        };
    }

    tenant = (plat +>:Hosts:+> Tenant(
        tenant_id=tenant_id, name="Northwind (synthetic)", plan="pro",
        status="active", created_at=ts
    ))[0];

    # ---- the compromised identity ---------------------------------------
    subject = (plat +>:Registers:+> Principal(
        principal_id=principal_id, email=principal_id + "@synthetic.invalid",
        pw_hash="x", status="active", created_at=ts
    ))[0];
    subject_mem = (tenant +>:HasMember:+> Membership(
        membership_id="m_subject", principal_id=principal_id, tenant_id=tenant_id,
        role="member", state="active", created_at=ts
    ))[0];
    subject_mem +>:Identifies:+> subject;

    # One live session per session id the incident named, each pinned to one of
    # the attack sources so `block_source` and `revoke_session` address the same
    # activity the monitor actually saw.
    made_sessions: list = [];
    si: int = 0;
    for sid in session_ids {
        ip: str = "198.51.100.1";
        if len(src_ips) > 0 {
            ip = src_ips[si % len(src_ips)];
        }
        subject +>:Authenticates:+> Session(
            session_id=sid, principal_id=principal_id, tenant_id=tenant_id,
            ip_first=ip, fp="fp_incident", issued_at=ts,
            expires_at=ts + HOUR_MS, last_auth_at=ts, revoked=False
        );
        made_sessions.append(sid);
        si = si + 1;
    }

    # An API token, so `revoke_token` addressed by principal has a subject.
    subject +>:Bears:+> Token(
        jti="jti_" + principal_id, principal_id=principal_id, tenant_id=tenant_id,
        kind="api", scope="project task", issued_at=ts,
        expires_at=ts + HOUR_MS, revoked=False
    );

    # ---- the bystanders --------------------------------------------------
    # Sources in 192.0.2.0/24 (TEST-NET-1), deliberately disjoint from the
    # incident's attack IPs: a bystander sharing an attack source would make
    # `block_source` a shared-NAT case requiring a human, which would be a
    # property of this fixture rather than of the incident.
    made_bystanders: list = [];
    i: int = 0;
    while i < n {
        bid: str = "bp_" + pad(i);
        bystander = (plat +>:Registers:+> Principal(
            principal_id=bid, email=bid + "@synthetic.invalid", pw_hash="x",
            status="active", created_at=ts
        ))[0];
        bmem = (tenant +>:HasMember:+> Membership(
            membership_id="bm_" + pad(i), principal_id=bid, tenant_id=tenant_id,
            role="member", state="active", created_at=ts
        ))[0];
        bmem +>:Identifies:+> bystander;
        bystander +>:Authenticates:+> Session(
            session_id="bs_" + pad(i), principal_id=bid, tenant_id=tenant_id,
            ip_first="192.0.2." + str(1 + (i % 250)), fp="fp_bystander",
            issued_at=ts, expires_at=ts + HOUR_MS, last_auth_at=ts, revoked=False
        );
        made_bystanders.append(bid);
        i = i + 1;
    }

    # Something for the availability probe to actually list.
    tenant +>:Owns:+> Project(
        project_id="pr_roadmap", tenant_id=tenant_id, key="NW",
        name="Roadmap", sensitivity="normal", created_at=ts
    );
    tenant +>:Owns:+> Project(
        project_id="pr_board", tenant_id=tenant_id, key="NWB",
        name="Board deck", sensitivity="confidential", created_at=ts
    );

    return {
        "seeded": True,
        "tenant_id": tenant_id,
        "principal_id": principal_id,
        "sessions": made_sessions,
        "src_ips": src_ips,
        "bystanders": len(made_bystanders),
        "actives": len(made_bystanders) + 1,
        "detail": "seeded from incident.join_keys"
    };
}
