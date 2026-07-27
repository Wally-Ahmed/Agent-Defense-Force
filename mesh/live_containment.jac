# mesh/live_containment.jac
#
# The REAL containment executor, wearing the interface the coordinator FSM calls.
#
# WHY THIS FILE EXISTS
#
#   coordinator/fsm.jac calls exactly four members on whatever it is handed as
#   `executor`:  apply(action, now_ms) -> {"status": "ack"|"nak"},
#                health_probe(action, now_ms) -> {"health": "pass"|"fail"},
#                rollback(action, now_ms),
#                .applied  (list)
#
#   containment/executor.jac is NOT an object. It is a module of free functions
#   over a Jac object graph — execute(request) runs gate -> snapshot -> apply ->
#   verify -> auto-rollback internally, and rollback() takes a ContainmentAction
#   GRAPH NODE plus a cause string. Every one of the four members mismatches on
#   name, arity and return shape. Until now the FSM had only ever been driven by
#   coordinator/mocks/mock_containment.jac.
#
#   So this is an ADAPTER, not a second implementation. It contains no
#   containment logic of its own: no policy, no probe, no rollback mechanics, no
#   approval decision. Every one of those comes out of containment/. What this
#   file does is translate two vocabularies and remember which rep belongs to
#   which action. If it ever starts deciding something, it has become a mock and
#   the run is no longer live.
#
# WHAT IS REAL HERE, EXACTLY
#
#   real: containment.policy.gate (scope resolution, blast radius, approval),
#         containment.executor.execute (Control writes, audit, idempotency),
#         containment.probes.run_health (in-process authz probes),
#         containment.executor.rollback (prior-state restore).
#   fixture: the object graph those run against — the tenant, the compromised
#         principal, its sessions, and the bystanders. Same discipline as
#         containment/verify.jac::build_world(): containment against a subject
#         that does not exist is not containment, it is an EMPTY_SCOPE refusal.
#         The world is seeded FROM the incident's own join_keys, so nothing
#         about it is chosen to make an action pass.
#
# NOTHING HERE APPROVES ANYTHING. `approved_by` is left empty on every request.
# An action whose kind needs a human comes back from the real gate as
# APPROVAL_REQUIRED and is reported as such. Filling that field in would be a
# bypass of the approval policy, not a fix.

import os;
import hashlib;
import json;
import from typing { Any }

import from contracts.containment_contract {
    Control, ContainmentAction, CONTAINMENT_KINDS
}
import from app.model.graph {
    Platform, Tenant, Membership, Principal, Session, Token, Project,
    Hosts, Registers, HasMember, Identifies, Owns, Authenticates, Bears,
    get_platform
}
import from app.model.resolve { principal_by_id }
import from app.security.clock { now_ms }
import from containment.executor {
    execute, rollback, find_action, control_surface, TERMINAL_STATES
}

glob HOUR_MS: int = 3600000;

# Bystander count. Taken from containment/verify.jac, which uses 40 for the same
# reason: the suspend_principal approval rule is a PERCENTAGE of tenant actives,
# and a tiny tenant makes one suspension look like a mass action. This number is
# the established fixture convention in this repo, not a value tuned until the
# gate said yes — and whatever the gate says about it is reported verbatim.
glob BYSTANDERS: int = 40;


def pad(n: int) -> str {
    s: str = str(n);
    while len(s) < 3 {
        s = "0" + s;
    }
    return s;
}


"""Seed the object graph the incident describes, from the incident's OWN
join_keys. Returns a description of what was built, for the artifact.

The compromised identity gets exactly the sessions the incident names, on
exactly the source addresses the incident names. Bystanders are ordinary members
of the same tenant on unrelated addresses — they are what
probes.probe_legit_user_can_list_projects looks for, and they are the negative
control for the whole containment claim: if they stop being served, containment
was not targeted."""
def seed_incident_world(join_keys: dict) -> dict {
    ts: int = now_ms();
    plat = get_platform();

    tenant_id: str = str(join_keys.get("tenant", ""));
    subject: str = str(join_keys.get("principal_hash", ""));
    session_ids: list = list(join_keys.get("session_ids", []));
    src_ips: list = list(join_keys.get("src_ips", []));
    if tenant_id == "" or subject == "" {
        raise ValueError("join_keys must carry tenant and principal_hash");
    }

    ten = (plat +>:Hosts:+> Tenant(
        tenant_id=tenant_id, name="Northwind", plan="pro",
        status="active", created_at=ts))[0];

    # --- the compromised identity, exactly as the incident names it ---------
    sub = (plat +>:Registers:+> Principal(
        principal_id=subject, email="svc_ingest@northwind.test", pw_hash="x",
        status="active", created_at=ts))[0];
    smem = (ten +>:HasMember:+> Membership(
        membership_id="m_" + subject, principal_id=subject, tenant_id=tenant_id,
        role="member", state="active", created_at=ts))[0];
    smem +>:Identifies:+> sub;

    i: int = 0;
    for sid in session_ids {
        ip: str = str(src_ips[i % len(src_ips)]) if len(src_ips) > 0 else "198.51.100.37";
        sub +>:Authenticates:+> Session(
            session_id=str(sid), principal_id=subject, tenant_id=tenant_id,
            ip_first=ip, fp="fp_attacker", issued_at=ts,
            expires_at=ts + HOUR_MS, last_auth_at=ts, revoked=False);
        i = i + 1;
    }

    # A service credential for the compromised identity, so revoke_token and
    # rotate_service_credential have a real subject if the quorum proposes them.
    sub +>:Bears:+> Token(
        jti="svc-backup", principal_id=subject, tenant_id=tenant_id,
        kind="api", scope="project task export", issued_at=ts,
        expires_at=ts + HOUR_MS, revoked=False);

    # --- bystanders: ordinary members, unrelated addresses ------------------
    j: int = 0;
    while j < BYSTANDERS {
        pid: str = "np_" + pad(j);
        pr = (plat +>:Registers:+> Principal(
            principal_id=pid, email=pid + "@northwind.test", pw_hash="x",
            status="active", created_at=ts))[0];
        mem = (ten +>:HasMember:+> Membership(
            membership_id="nm_" + pad(j), principal_id=pid, tenant_id=tenant_id,
            role="member", state="active", created_at=ts))[0];
        mem +>:Identifies:+> pr;
        pr +>:Authenticates:+> Session(
            session_id="ns_" + pad(j), principal_id=pid, tenant_id=tenant_id,
            ip_first="192.0.2." + str(10 + j), fp="fp_bystander", issued_at=ts,
            expires_at=ts + HOUR_MS, last_auth_at=ts, revoked=False);
        j = j + 1;
    }

    ten +>:Owns:+> Project(project_id="npr_1", tenant_id=tenant_id, key="NW",
                           name="Roadmap", sensitivity="normal", created_at=ts);
    ten +>:Owns:+> Project(project_id="npr_2", tenant_id=tenant_id, key="NW2",
                           name="Export staging", sensitivity="confidential",
                           created_at=ts);

    return {
        "tenant": tenant_id,
        "subject_principal": subject,
        "subject_sessions": [str(s) for s in session_ids],
        "subject_src_ips": [str(x) for x in src_ips],
        "bystanders": BYSTANDERS,
        "tenant_actives": BYSTANDERS + 1,
        "projects": 2
    };
}


# --------------------------------------------------------------------------
# The adapter
# --------------------------------------------------------------------------

"""Deterministic action_id for (incident, kind, canonical target).

Mirrors containment.executor._derive_action_id so a redelivery of the same
action lands on the executor's own idempotency key rather than minting a second
apply. The FSM's action dicts carry no action_id of their own."""
def derive_action_id(incident_id: str, kind: str, target: dict) -> str {
    norm: dict = {};
    for k in sorted(target.keys()) {
        v = target[k];
        norm[k] = sorted([str(x) for x in v]) if isinstance(v, list) else v;
    }
    canon: str = json.dumps(norm, sort_keys=True, separators=(",", ":"));
    seed: str = incident_id + "|" + kind + "|" + canon;
    digest: str = hashlib.sha256(seed.encode("utf-8")).hexdigest()[:16];
    return incident_id + ":" + kind + ":" + digest;
}


"""containment/executor.jac, wearing coordinator/fsm.jac's executor interface.

`applied` holds the raw action dicts the FSM handed us that came back ACTIVE.
`reports` holds the executor's full reportort per action_id — that is the evidence,
and it is what health_probe reads instead of inventing a second verdict."""
obj LiveContainment {
    has incident_id: str = "";
    has applied: list = [];          # required by fsm.summary()
    has rolled_back: list = [];
    has reports: dict = {};          # action_id -> execute() rep
    has trace: list = [];            # ordered log of every executor interaction

    def key_for(action: dict) -> str {
        return derive_action_id(
            self.incident_id,
            str(action.get("action", "")),
            action.get("target", {})
        );
    }

    """Apply ONE action through the real executor.

    The request is built straight from the decision.v1 action_set entry. No
    field is invented and `approved_by` is deliberately left empty: whether this
    kind may proceed without a human is containment/policy.jac's call, not ours.

    execute() returns `state`, not `status`. `active` is the only state that
    means the Control is live and enforcing, so that is the only one mapped to
    ack. `proposed` (a real human-approval hold) and `verify_failed` (the
    executor's own probes failed and it already rolled the action back) both map
    to nak, which is honest: nothing is enforcing."""
    def apply(action: dict, now_ms_arg: int) -> dict {
        kind: str = str(action.get("action", ""));
        target: dict = action.get("target", {});
        aid: str = self.key_for(action);
        request: dict = {
            "action_id": aid,
            "incident_id": self.incident_id,
            "action": kind,
            "target": target,
            "ttl_s": int(action.get("ttl_s", 0)),
            "blast_radius": str(action.get("blast_radius", "")),
            "proposed_by": list(action.get("proposed_by", [])),
            "approved_by": "",          # never auto-approve; the gate decides
            "params": {},
            "health_check": "",         # executor picks the contract default
            "created_by": "coordinator"
        };
        rep: dict = execute(request);
        self.reports[aid] = rep;

        state: str = str(rep.get("state", ""));
        health: dict = rep.get("health", {}) or {};
        entry: dict = {
            "phase": "apply",
            "action_id": aid,
            "kind": kind,
            "state": state,
            "ok": bool(rep.get("ok", False)),
            "approval": str(rep.get("approval", "")),
            "idempotent": bool(rep.get("idempotent", False)),
            "ttl_s": rep.get("ttl_s", None),
            "blast": (rep.get("blast", {}) or {}).get("level", ""),
            "scope_keys": len((rep.get("scope", {}) or {}).get("keys", [])),
            "controls_written": len(rep.get("controls", []) or []),
            "health_status": str(health.get("status", "")),
            "health_failed": list(health.get("failed", []) or []),
            "health_report": [str(x) for x in (health.get("report", []) or [])],
            "detail": str(rep.get("detail", ""))
        };
        self.trace.append(entry);

        if state == "active" {
            self.applied.append(action);
            return {"status": "ack", "action": kind, "target": target,
                    "action_id": aid, "state": state};
        }
        return {"status": "nak", "action": kind, "target": target,
                "action_id": aid, "state": state,
                "detail": str(rep.get("detail", ""))};
    }

    """The health verdict for an applied action.

    READ, not re-run. containment/executor.jac::execute already called
    probes.run_health as part of the apply, and already auto-rolled-back on
    failure. Probing a second time here would either duplicate work or — on the
    failure path — interrogate a world the executor has already restored, and
    rep the wrong answer. So this returns the real probe result the real
    executor recorded, unmodified."""
    def health_probe(action: dict, now_ms_arg: int) -> dict {
        aid: str = self.key_for(action);
        rep: dict = self.reports.get(aid, {});
        health: dict = rep.get("health", {}) or {};
        status: str = str(health.get("status", ""));
        if status == "" {
            # No probe result at all is a failure, never an assumed pass.
            status = "fail";
        }
        self.trace.append({
            "phase": "verify",
            "action_id": aid,
            "kind": str(action.get("action", "")),
            "health": status,
            "primary_probe": str(health.get("primary", "")),
            "probes_run": len(health.get("probes", []) or []),
            "failed": list(health.get("failed", []) or [])
        });
        return {"action": str(action.get("action", "")),
                "target": action.get("target", {}),
                "health": status};
    }

    """Reverse ONE action through the real executor.

    Resolves the ContainmentAction graph act_node by action_id and hands it to
    containment.executor.rollback, which replays the recorded prior_state. An
    action already in a terminal state is not resurrected to be re-reversed."""
    def rollback(action: dict, now_ms_arg: int) -> dict {
        aid: str = self.key_for(action);
        act_node = find_action(aid);
        if act_node is None {
            self.trace.append({"phase": "rollback", "action_id": aid,
                               "kind": str(action.get("action", "")),
                               "state": "absent", "restored": []});
            return {"action": str(action.get("action", "")),
                    "target": action.get("target", {}), "status": "absent"};
        }
        if act_node.state in TERMINAL_STATES {
            self.trace.append({"phase": "rollback", "action_id": aid,
                               "kind": str(action.get("action", "")),
                               "state": str(act_node.state),
                               "restored": [], "note": "already terminal"});
            return {"action": str(action.get("action", "")),
                    "target": action.get("target", {}),
                    "status": str(act_node.state)};
        }
        result: dict = rollback(act_node, "coordinator ttl expiry");
        self.rolled_back.append(action);
        self.trace.append({
            "phase": "rollback",
            "action_id": aid,
            "kind": str(action.get("action", "")),
            "state": str(result.get("state", "")),
            "restored": list(result.get("restored", [])),
            "surface_after": len(result.get("surface_after", []) or [])
        });
        return {"action": str(action.get("action", "")),
                "target": action.get("target", {}),
                "status": str(result.get("state", ""))};
    }

    """Sorted kinds actually enforcing, read out of the real control surface."""
    def live_control_kinds -> list {
        kinds: list = [];
        for row in control_surface() {
            if row.get("active", False) and row.get("kind", "") not in kinds {
                kinds.append(str(row.get("kind", "")));
            }
        }
        return sorted(kinds);
    }
}
