# containment/verify.jac — the seven claims, executed against a real graph.
#
# Run:  jac run containment/verify.jac
#
# Every number printed below is read out of the object graph or out of the audit
# trail at the moment it is printed. Nothing is asserted from a constant.
#
# THE WORLD. Built here rather than borrowed from tests/fixtures.jac because two
# of the seven claims are about PERCENTAGES, and a four-person tenant cannot
# distinguish "2.5% of actives" from "25% of actives" — the suspend_principal
# approval rule would be untestable on both sides. So: one 40-member tenant
# (t_verify) where suspending one person is 2.5% and auto-approves, and one
# four-member tenant (t_small) where suspending one person is 25% and needs a
# human. Same code path, opposite verdicts, because the graph is different.
#
# ISOLATION. Run this from a scratch directory with PYTHONPATH pointed at the
# repo and it gets its own `.jac/data/anchor_store.db`; the repo's shared graph
# is never touched. `containment/run_verify.sh` does exactly that.

import os;
import json;
import time;

import from contracts.containment_contract { ContainmentAction, Control, CONTAINMENT_KINDS }
import from app.model.graph {
    Platform, Tenant, Membership, Principal, Session, Token, Project,
    Hosts, Registers, HasMember, Identifies, Owns, Authenticates, Bears, Enforces,
    get_platform, all_controls, all_tenants
}
import from app.model.resolve { tenant_by_id, principal_by_id, session_by_id }
import from app.security.clock { now_ms, iso_ts, iso_to_ms }
import from app.security.audit { emit_audit, audit_log_path }
import from app.security.controls { live_controls, find_control, is_live }
import from containment.policy {
    gate, blast_radius, resolve_scope, approval_for, no_blanket_shutdown,
    tenant_actives, live_sessions_of
}
import from containment.executor {
    execute, execute_decision, rollback, find_action, all_actions, control_surface,
    find_control_node, project_controls, controls_path, pending_path, Proposes
}
import from containment.probes {
    run_health, run_probe, find_bystander, probe_legit_user_can_list_projects,
    principal_can_list_projects
}
import from containment.expiry { sweep_once, is_expired, due, run_scheduler }

glob HOUR_MS: int = 3600000;
glob BIG: int = 40;          # members of t_verify
glob SMALL: int = 4;         # members of t_small

glob PASSES: list = [];
glob FAILURES: list = [];

# --------------------------------------------------------------------------
# Reporting.
# --------------------------------------------------------------------------

def hr(title: str) {
    print("");
    print("=" * 78);
    print(title);
    print("=" * 78);
}

def check(label: str, condition: bool, evidence: str) {
    mark: str = "PASS" if condition else "FAIL";
    print("  [" + mark + "] " + label);
    if evidence != "" {
        print("         " + evidence);
    }
    if condition {
        PASSES.append(label);
    } else {
        FAILURES.append(label + " :: " + evidence);
    }
}

def show_controls(note: str) {
    rows: list = control_surface();
    print("         " + note + " control surface (" + str(len(rows)) + "):");
    for r in rows {
        row: dict = r;
        print("           - " + str(row["kind"]) + " " + str(row["scope_key"])
              + " active=" + str(row["active"])
              + " expires_at=" + (str(row["expires_at"]) if row["expires_at"] != "" else "(none)")
              + " params=" + json.dumps(row["params"]));
    }
}

# --------------------------------------------------------------------------
# Audit trail readback. The trail is the record; we read it, not our own memory.
# --------------------------------------------------------------------------

def audit_rows() -> list {
    path: str = audit_log_path();
    if not os.path.isfile(path) {
        return [];
    }
    out: list = [];
    handle = open(path, "r", encoding="utf-8");
    for line in handle.readlines() {
        text: str = line.strip();
        if text == "" {
            continue;
        }
        try {
            out.append(json.loads(text));
        } except Exception as e {
            continue;
        }
    }
    handle.close();
    return out;
}

def containment_events(action_id: str) -> list {
    out: list = [];
    for r in audit_rows() {
        row: dict = r;
        act: str = str(row.get("action", ""));
        if act.startswith("containment.") and str(row.get("target_id", "")) == action_id {
            out.append(row);
        }
    }
    return out;
}

def event_summary(action_id: str) -> str {
    parts: list = [];
    for e in containment_events(action_id) {
        ev: dict = e;
        parts.append(str(ev["action"]) + "/" + str(ev["outcome"])
                     + "(" + str(ev["severity"]) + ")");
    }
    return " -> ".join(parts) if len(parts) > 0 else "(none)";
}

# --------------------------------------------------------------------------
# The world.
# --------------------------------------------------------------------------

def pad(n: int) -> str {
    return str(n).zfill(3);
}

"""Narrow an Any-typed value to a dict. Jac's checker will not let a value read
out of a bare list/dict be assigned to a `dict` local; this is the one-line
adapter that says so explicitly."""
def as_dict(value: object) -> dict {
    if isinstance(value, dict) {
        return value;
    }
    return {};
}

"""Same, for a list."""
def as_list(value: object) -> list {
    if isinstance(value, list) {
        return value;
    }
    return [];
}

def build_world() {
    ts: int = now_ms();
    plat = get_platform();

    big = (plat +>:Hosts:+> Tenant(tenant_id="t_verify", name="Verify Corp",
                                   plan="pro", status="active", created_at=ts))[0];
    small = (plat +>:Hosts:+> Tenant(tenant_id="t_small", name="Small Co",
                                     plan="free", status="active", created_at=ts))[0];

    # --- t_verify: 40 members, each with one live session ---------------
    # Sources are deliberately not uniform: vp_000 is alone on its IP (so
    # block_source on it is narrow and auto-approves), while vp_010/011/012
    # share 203.0.113.200 — a NAT, which the approval policy must catch.
    i: int = 0;
    while i < BIG {
        pid: str = "vp_" + pad(i);
        pr = (plat +>:Registers:+> Principal(
            principal_id=pid, email=pid + "@verify.test", pw_hash="x",
            status="active", created_at=ts))[0];
        mem = (big +>:HasMember:+> Membership(
            membership_id="vm_" + pad(i), principal_id=pid, tenant_id="t_verify",
            role="member", state="active", created_at=ts))[0];
        mem +>:Identifies:+> pr;

        ip: str = "198.51.100." + str(10 + i);
        if i == 0 {
            ip = "198.51.100.66";
        }
        if i in [10, 11, 12] {
            ip = "203.0.113.200";
        }
        pr +>:Authenticates:+> Session(
            session_id="vs_" + pad(i), principal_id=pid, tenant_id="t_verify",
            ip_first=ip, fp="fp_verify", issued_at=ts,
            expires_at=ts + HOUR_MS, last_auth_at=ts, revoked=False);
        i = i + 1;
    }

    # An API token for the compromised identity, so revoke_token has a subject.
    p0 = principal_by_id("vp_000");
    if p0 is not None {
        holder: Principal = p0;
        holder +>:Bears:+> Token(
            jti="jti_v0", principal_id="vp_000", tenant_id="t_verify",
            kind="api", scope="project task", issued_at=ts,
            expires_at=ts + HOUR_MS, revoked=False);
    }

    big +>:Owns:+> Project(project_id="vpr_1", tenant_id="t_verify", key="VER",
                           name="Roadmap", sensitivity="normal", created_at=ts);
    big +>:Owns:+> Project(project_id="vpr_2", tenant_id="t_verify", key="VER2",
                           name="Board deck", sensitivity="confidential", created_at=ts);

    # --- t_small: 4 members. One suspension here is 25% of actives. -----
    j: int = 0;
    while j < SMALL {
        spid: str = "sp_" + pad(j);
        spr = (plat +>:Registers:+> Principal(
            principal_id=spid, email=spid + "@small.test", pw_hash="x",
            status="active", created_at=ts))[0];
        smem = (small +>:HasMember:+> Membership(
            membership_id="sm_" + pad(j), principal_id=spid, tenant_id="t_small",
            role="member", state="active", created_at=ts))[0];
        smem +>:Identifies:+> spr;
        spr +>:Authenticates:+> Session(
            session_id="ss_" + pad(j), principal_id=spid, tenant_id="t_small",
            ip_first="192.0.2." + str(20 + j), fp="fp_small", issued_at=ts,
            expires_at=ts + HOUR_MS, last_auth_at=ts, revoked=False);
        j = j + 1;
    }
    small +>:Owns:+> Project(project_id="spr_1", tenant_id="t_small", key="SM",
                             name="Plan", sensitivity="normal", created_at=ts);
}

# --------------------------------------------------------------------------
# Request builder.
# --------------------------------------------------------------------------

def req(action_id: str, kind: str, target: dict, ttl_s: int = 0,
        approved_by: str = "", params: dict = {}) -> dict {
    return {
        "action_id": action_id,
        "incident_id": "inc_verify_001",
        "action": kind,
        "target": target,
        "ttl_s": ttl_s,
        "blast_radius": "narrow",
        "proposed_by": ["responder_a", "responder_b"],
        "approved_by": approved_by,
        "params": params,
        "created_by": "responder:verify"
    };
}

# ==========================================================================
# 1. Apply each of the ten action kinds.
# ==========================================================================

def verify_1_all_kinds() -> dict {
    hr("VERIFICATION 1 — all ten containment kinds apply, write a Control, and "
       + "emit audit");

    # Every kind, with a target that is well-formed for it. The three that need
    # a human carry an explicit approval; #3 proves what happens without one.
    plan: list = [
        ("revoke_session",            {"session_ids": ["vs_001"]},                                 0,    ""),
        ("revoke_token",              {"credential_id": "jti_v0"},                                 0,    ""),
        ("suspend_principal",         {"principal_hash": "vp_002", "tenant": "t_verify"},          1800, ""),
        ("throttle_source",           {"src_ips": ["198.51.100.77"]},                              900,  ""),
        ("block_source",              {"src_ips": ["198.51.100.66"]},                              900,  ""),
        ("force_reauth",              {"principal_hash": "vp_003"},                                3600, ""),
        ("feature_readonly",          {"feature": "project", "tenant": "t_verify"},                900,  ""),
        ("pause_queue",               {"queue": "export", "tenant": "t_verify"},                   600,  ""),
        ("rotate_service_credential", {"credential_id": "svc_billing_key"},                        0,    "sec-lead@verify.test"),
        ("raise_logging",             {"tenant": "t_verify"},                                      3600, "")
    ];

    applied: int = 0;
    n: int = 0;
    ids: list = [];
    for row in plan {
        kind: str = str(row[0]);
        target: dict = as_dict(row[1]);
        ttl: int = int(row[2]);
        approver: str = str(row[3]);
        aid: str = "act_k" + str(n) + "_" + kind;
        ids.append(aid);

        res: dict = execute(req(aid, kind, target, ttl, approver));
        ctl_rows: list = [];
        scope: dict = res["scope"];
        keys: list = scope.get("keys", []);
        for raw_key in keys {
            key: str = str(raw_key);
            found = find_control_node(kind, key);
            if found is not None {
                c: Control = found;
                ctl_rows.append(c.kind + " " + c.scope_key + " active=" + str(c.active)
                                + " expires_at=" + (c.expires_at if c.expires_at != "" else "(none)"));
            }
        }
        blast: dict = res["blast"];
        ok: bool = bool(res["ok"]) and str(res["state"]) == "active" and len(ctl_rows) > 0;
        if ok {
            applied = applied + 1;
        }
        print("");
        print("  " + kind + "  [" + str(res["state"]) + "]  approval="
              + str(res["approval"])
              + ("  approved_by=" + str(res["approved_by"]) if str(res["approved_by"]) != "" else ""));
        print("      Control : " + (" ; ".join(ctl_rows) if len(ctl_rows) > 0 else "(none)"));
        print("      blast   : " + str(blast["level"]) + " (principals="
              + str(blast["principals"]) + " sessions=" + str(blast["sessions"])
              + " tenants=" + str(blast["tenants"]) + " pct="
              + str(blast["pct_of_tenant_actives"]) + "%)");
        print("      audit   : " + event_summary(aid));
        print("      health  : " + str(res["health_status"]));
        if str(res["health_status"]) != "pass" {
            h: dict = as_dict(res.get("health", {}));
            for hl in as_list(h.get("report", [])) {
                print("         " + str(hl));
            }
        }
        n = n + 1;
    }

    check("all 10 kinds applied a Control and reached state=active",
          applied == 10, str(applied) + "/10 applied");

    # Every kind emitted propose + apply + verify.
    complete: int = 0;
    for raw_id in ids {
        aid2: str = str(raw_id);
        names: list = [];
        for e in containment_events(aid2) {
            ev: dict = e;
            names.append(str(ev["action"]));
        }
        if "containment.propose" in names and "containment.apply" in names
           and "containment.verify" in names {
            complete = complete + 1;
        }
    }
    check("every applied kind emitted propose + apply + verify",
          complete == 10, str(complete) + "/10 have the full event triple");

    # Clean up so later verifications start from a known surface.
    for raw_id2 in ids {
        a = find_action(str(raw_id2));
        if a is not None {
            act: ContainmentAction = a;
            if act.state == "active" {
                rollback(act, "verification 1 teardown");
            }
        }
    }
    check("teardown left an empty control surface",
          len(control_surface()) == 0,
          str(len(control_surface())) + " controls remain after rolling all 10 back");
    return {"applied": applied};
}

# ==========================================================================
# 2. Idempotency.
# ==========================================================================

def verify_2_idempotency() -> dict {
    hr("VERIFICATION 2 — the same action_id delivered twice has no second effect");

    aid: str = "act_idem_001";
    r1: dict = execute(req(aid, "revoke_session", {"session_ids": ["vs_004"]}, 0));
    surface_1: list = control_surface();
    events_1: int = len(containment_events(aid));

    print("  first delivery  : state=" + str(r1["state"]) + " controls="
          + str(len(surface_1)) + " containment events=" + str(events_1));

    r2: dict = execute(req(aid, "revoke_session", {"session_ids": ["vs_004"]}, 0));
    surface_2: list = control_surface();
    events_2: int = len(containment_events(aid));

    print("  second delivery : state=" + str(r2["state"]) + " idempotent="
          + str(r2["idempotent"]) + " controls=" + str(len(surface_2))
          + " containment events=" + str(events_2));
    print("  detail          : " + str(r2["detail"]));

    check("redelivery reported idempotent", bool(r2["idempotent"]),
          "idempotent=" + str(r2["idempotent"]));
    check("no second Control written",
          len(surface_1) == len(surface_2) and json.dumps(surface_1) == json.dumps(surface_2),
          "surface identical before/after redelivery ("
          + str(len(surface_1)) + " control(s))");
    check("no second audit event emitted", events_1 == events_2,
          str(events_1) + " events before, " + str(events_2) + " after");

    # The dangerous variant: a redelivery must not re-snapshot. If it did, the
    # snapshot would record the CONTAINED state as "prior", and rollback would
    # become a no-op that restored nothing.
    a = find_action(aid);
    snapshot_ok: bool = False;
    if a is not None {
        act: ContainmentAction = a;
        prior: dict = act.prior_state;
        rows: list = prior.get("controls", []);
        first: dict = rows[0] if len(rows) > 0 else {};
        snapshot_ok = (len(rows) == 1) and (not bool(first.get("existed", True)));
        print("  prior_state     : " + json.dumps(prior));
    }
    check("prior_state still records the pre-containment world",
          snapshot_ok, "snapshot says the control did not exist before — "
          + "a redelivery did NOT overwrite it with the contained state");

    # Roll back and confirm the reversal really happened.
    if a is not None {
        act2: ContainmentAction = a;
        rollback(act2, "verification 2 teardown");
    }
    check("rollback after redelivery still empties the surface",
          len(control_surface()) == 0, str(len(control_surface())) + " controls remain");
    return {};
}

# ==========================================================================
# 3. Approval policy.
# ==========================================================================

def verify_3_approval() -> dict {
    hr("VERIFICATION 3 — human-required actions do not execute without a human");

    # (a) rotate_service_credential, no approver.
    aid: str = "act_rot_noapproval";
    r: dict = execute(req(aid, "rotate_service_credential",
                          {"credential_id": "svc_billing_key"}, 0, ""));
    ctl = find_control_node("rotate_service_credential", "credential:svc_billing_key");
    print("  rotate_service_credential (no approver)");
    print("      state    : " + str(r["state"]));
    print("      approval : " + str(r["approval"]));
    print("      detail   : " + str(r["detail"]));
    print("      Control  : " + ("WRITTEN — POLICY BREACH" if ctl is not None else "none written"));
    print("      audit    : " + event_summary(aid));

    check("rotate_service_credential without approval is recorded `proposed`",
          str(r["state"]) == "proposed", "state=" + str(r["state"]));
    check("rotate_service_credential without approval wrote NO Control",
          ctl is None, "control lookup returned " + ("a node" if ctl is not None else "None"));
    check("the refused action is still on the audit trail (not silently dropped)",
          len(containment_events(aid)) > 0, event_summary(aid));

    # Surfaced, not dropped: it is in the pending queue on disk.
    pend_path: str = pending_path();
    pend_ids: list = [];
    if os.path.isfile(pend_path) {
        handle = open(pend_path, "r", encoding="utf-8");
        blob: dict = json.loads(handle.read());
        handle.close();
        rows: list = blob.get("pending", []);
        for raw in rows {
            row: dict = raw;
            pend_ids.append(str(row["action_id"]));
        }
    }
    print("      pending queue (" + pend_path + "): " + json.dumps(pend_ids));
    check("the refused action is SURFACED in the pending-approval queue",
          aid in pend_ids, "pending contains " + json.dumps(pend_ids));

    # (b) The same action WITH an approver does execute.
    r2: dict = execute(req(aid, "rotate_service_credential",
                           {"credential_id": "svc_billing_key"}, 0, "sec-lead@verify.test"));
    ctl2 = find_control_node("rotate_service_credential", "credential:svc_billing_key");
    print("");
    print("  rotate_service_credential (approved by sec-lead@verify.test)");
    print("      state    : " + str(r2["state"]) + "   Control: "
          + ("written" if ctl2 is not None else "none"));
    check("the same action DOES execute once a human approves",
          str(r2["state"]) == "active" and ctl2 is not None,
          "state=" + str(r2["state"]));
    a = find_action(aid);
    if a is not None {
        rollback(a, "verification 3 teardown");
    }

    # (c) block_source on a source serving 3 principals.
    print("");
    shared_ip: str = "203.0.113.200";
    scope_nat: dict = resolve_scope("block_source", {"src_ips": [shared_ip]}, now_ms());
    blast_nat: dict = blast_radius("block_source", scope_nat, now_ms());
    appr_nat: dict = approval_for("block_source", scope_nat, blast_nat, now_ms());
    print("  block_source " + shared_ip + " (a NAT)");
    print("      principals served in 24h : "
          + json.dumps(scope_nat["principal_ids"]));
    print("      approval                 : " + str(appr_nat["approval"]));
    print("      why                      : " + str(appr_nat["why"]));

    aid3: str = "act_block_nat";
    r3: dict = execute(req(aid3, "block_source", {"src_ips": [shared_ip]}, 900, ""));
    ctl3 = find_control_node("block_source", "ip:" + shared_ip);
    print("      state                    : " + str(r3["state"]));
    print("      Control                  : "
          + ("WRITTEN — POLICY BREACH" if ctl3 is not None else "none written"));

    check("block_source on a source serving 3 principals requires human approval",
          str(appr_nat["approval"]) == "human_required",
          str(len(scope_nat["principal_ids"])) + " principals in 24h -> "
          + str(appr_nat["approval"]));
    check("...and therefore does not execute unapproved",
          str(r3["state"]) == "proposed" and ctl3 is None,
          "state=" + str(r3["state"]));

    # (d) The contrast: a source serving one principal auto-approves.
    solo_ip: str = "198.51.100.66";
    scope_solo: dict = resolve_scope("block_source", {"src_ips": [solo_ip]}, now_ms());
    blast_solo: dict = blast_radius("block_source", scope_solo, now_ms());
    appr_solo: dict = approval_for("block_source", scope_solo, blast_solo, now_ms());
    print("");
    print("  block_source " + solo_ip + " (one identity)");
    print("      principals served in 24h : " + json.dumps(scope_solo["principal_ids"]));
    print("      approval                 : " + str(appr_solo["approval"])
          + "  (" + str(appr_solo["why"]) + ")");
    check("the same kind auto-approves when the source is NOT shared",
          str(appr_solo["approval"]) in ["auto", "auto_with_notice"],
          str(appr_solo["approval"]));

    # (e) suspend_principal: the 5% rule, both sides.
    print("");
    for pair in [("t_verify", "vp_005"), ("t_small", "sp_001")] {
        tid: str = str(pair[0]);
        pid: str = str(pair[1]);
        sc: dict = resolve_scope("suspend_principal",
                                 {"principal_hash": pid, "tenant": tid}, now_ms());
        bl: dict = blast_radius("suspend_principal", sc, now_ms());
        ap: dict = approval_for("suspend_principal", sc, bl, now_ms());
        print("  suspend_principal " + pid + " in " + tid
              + ": " + str(bl["pct_of_tenant_actives"]) + "% of "
              + str(bl["tenant_denominator"]) + " actives -> " + str(ap["approval"]));
    }
    sc_big: dict = resolve_scope("suspend_principal",
                                 {"principal_hash": "vp_005", "tenant": "t_verify"}, now_ms());
    bl_big: dict = blast_radius("suspend_principal", sc_big, now_ms());
    ap_big: dict = approval_for("suspend_principal", sc_big, bl_big, now_ms());
    sc_sm: dict = resolve_scope("suspend_principal",
                                {"principal_hash": "sp_001", "tenant": "t_small"}, now_ms());
    bl_sm: dict = blast_radius("suspend_principal", sc_sm, now_ms());
    ap_sm: dict = approval_for("suspend_principal", sc_sm, bl_sm, now_ms());
    check("suspend_principal auto-approves below 5% of tenant actives",
          str(ap_big["approval"]) in ["auto", "auto_with_notice"],
          "t_verify: " + str(bl_big["pct_of_tenant_actives"]) + "% -> " + str(ap_big["approval"]));
    check("suspend_principal requires a human at or above 5% of tenant actives",
          str(ap_sm["approval"]) == "human_required",
          "t_small: " + str(bl_sm["pct_of_tenant_actives"]) + "% -> " + str(ap_sm["approval"]));
    return {};
}

# ==========================================================================
# 4. Health-probe failure -> automatic rollback.
# ==========================================================================

def verify_4_probe_failure() -> dict {
    hr("VERIFICATION 4 — a containment that breaks the app rolls itself back");

    # Suspend EVERY member of t_small. A human approves it, and it is still
    # undone: after it lands there is nobody left in the tenant who can work, so
    # `legit_user_can_list_projects` fails and the executor reverses itself
    # without asking anyone.
    everyone: list = tenant_actives("t_small");
    surface_before: list = control_surface();
    print("  applying suspend_principal to ALL " + str(len(everyone))
          + " members of t_small: " + json.dumps(everyone));
    print("  (human-approved — approval is not a licence to break availability)");

    aid: str = "act_overbroad";
    r: dict = execute(req(aid, "suspend_principal",
                          {"principal_hash": everyone, "tenant": "t_small"},
                          1800, "sec-lead@verify.test"));

    blast: dict = r["blast"];
    print("");
    print("      blast          : " + str(blast["level"]) + " — "
          + str(blast["principals"]) + " principals, "
          + str(blast["pct_of_tenant_actives"]) + "% of "
          + str(blast["tenant_denominator"]) + " actives");
    print("      final state    : " + str(r["state"]));
    print("      health_status  : " + str(r["health_status"]));
    health: dict = as_dict(r.get("health", {}));
    probe_lines: list = as_list(health.get("report", []));
    for line in probe_lines {
        print("      probe          : " + str(line));
    }
    print("      audit          : " + event_summary(aid));

    surface_after: list = control_surface();
    print("      controls before apply : " + str(len(surface_before)));
    print("      controls after  rollback : " + str(len(surface_after)));

    names: list = [];
    for e in containment_events(aid) {
        ev: dict = e;
        names.append(str(ev["action"]) + "/" + str(ev["outcome"]));
    }

    check("health probe failed", str(r["health_status"]) == "fail",
          "health_status=" + str(r["health_status"]));
    check("the action rolled itself back automatically",
          str(r["state"]) == "rolled_back", "state=" + str(r["state"]));
    check("containment.verify was recorded as an error, then containment.rollback",
          "containment.verify/error" in names and "containment.rollback/allow" in names,
          " -> ".join(names));
    check("system restored: control surface identical to before the apply",
          json.dumps(surface_before) == json.dumps(surface_after),
          str(len(surface_before)) + " control(s) before, "
          + str(len(surface_after)) + " after");

    # And the people are working again.
    witness: dict = find_bystander("t_small", [], now_ms());
    probe: dict = probe_legit_user_can_list_projects(
        "suspend_principal", {"tenant_id": "t_small", "keys": [], "principal_ids": []}, now_ms());
    print("      post-rollback availability : " + str(probe["detail"]));
    check("t_small members can work again after the rollback",
          bool(probe["ok"]), str(probe["detail"]));
    return {};
}

# ==========================================================================
# 5. TTL expiry -> rollback, with prior_state fully restored.
# ==========================================================================

def verify_5_ttl() -> dict {
    hr("VERIFICATION 5 — TTL expiry rolls back and restores prior_state exactly");

    # A control ALREADY EXISTS on this scope key, with its own params and its
    # own expiry. Containment overwrites it, then the TTL fires. Restoring
    # "nothing" would be easy; restoring THIS is the real test.
    plat = get_platform();
    pre_expiry: str = iso_ts(now_ms() + 7200000);
    plat +>:Enforces:+> Control(
        control_id="pre_existing_raise_logging",
        kind="raise_logging",
        scope_key="tenant:t_verify",
        params={"level": "info", "sampling": 0.1, "owner": "platform-sre"},
        expires_at=pre_expiry,
        active=True);

    surface_before: list = control_surface();
    print("  pre-existing control on the same scope key:");
    show_controls("before");

    aid: str = "act_ttl_001";
    r: dict = execute(req(aid, "raise_logging", {"tenant": "t_verify"}, 1,
                          "", {"level": "debug", "sampling": 1.0}));
    print("");
    print("      applied  : state=" + str(r["state"]) + " ttl_s=" + str(r["ttl_s"])
          + " expires_at=" + str(r["expires_at"]));
    show_controls("after apply");

    found = find_action(aid);
    assert found is not None, "verification 5: action " + aid + " was not recorded";
    act: ContainmentAction = found;

    # Nothing is due yet.
    early: dict = sweep_once(now_ms());
    print("      sweep before TTL : swept=" + str(early["swept"])
          + " expired=" + str(early["expired"]));
    check("a sweep before the deadline changes nothing",
          int(early["expired"]) == 0 and str(act.state) == "active",
          "expired=" + str(early["expired"]) + " state=" + str(act.state));

    print("      waiting for the 1s TTL to elapse...");
    time.sleep(1.4);

    swept: dict = sweep_once(now_ms());
    print("      sweep after TTL  : swept=" + str(swept["swept"])
          + " expired=" + str(swept["expired"]) + " at=" + str(swept["at"]));
    swept_rows: list = swept["actions"];
    for h in swept_rows {
        row: dict = h;
        print("        " + str(row["action_id"]) + " -> " + str(row["state"])
              + " : " + str(row["detail"]));
        restored_rows: list = row.get("restored", []);
        for what in restored_rows {
            print("           restored: " + str(what));
        }
    }

    surface_after: list = control_surface();
    show_controls("after expiry");

    names: list = [];
    for e in containment_events(aid) {
        ev: dict = e;
        names.append(str(ev["action"]));
    }

    check("the expired action reached state=rolled_back",
          str(act.state) == "rolled_back", "state=" + str(act.state));
    check("containment.expire AND containment.rollback were both emitted",
          "containment.expire" in names and "containment.rollback" in names,
          " -> ".join(names));
    check("prior_state fully restored — control surface byte-identical to before",
          json.dumps(surface_before) == json.dumps(surface_after),
          "before == after: " + str(json.dumps(surface_before) == json.dumps(surface_after)));

    restored = find_control_node("raise_logging", "tenant:t_verify");
    detail: str = "(missing)";
    params_ok: bool = False;
    expiry_ok: bool = False;
    id_ok: bool = False;
    if restored is not None {
        c: Control = restored;
        detail = "control_id=" + c.control_id + " params=" + json.dumps(c.params)
                 + " expires_at=" + c.expires_at;
        params_ok = json.dumps(c.params) == json.dumps({"level": "info", "sampling": 0.1, "owner": "platform-sre"});
        expiry_ok = c.expires_at == pre_expiry;
        id_ok = c.control_id == "pre_existing_raise_logging";
    }
    check("the pre-existing control's params, expiry and id all came back",
          params_ok and expiry_ok and id_ok, detail);

    # The audit history survives the rollback.
    check("audit history was NOT erased by the rollback",
          len(containment_events(aid)) >= 4,
          str(len(containment_events(aid))) + " containment events still on the trail: "
          + event_summary(aid));

    # Teardown: remove the pre-existing control so later checks start clean.
    leftover = find_control_node("raise_logging", "tenant:t_verify");
    if leftover is not None {
        victim: Control = leftover;
        del victim;
    }
    project_controls();
    return {};
}

# ==========================================================================
# 6. THE AVAILABILITY PROOF.
# ==========================================================================

def verify_6_availability() -> dict {
    hr("VERIFICATION 6 — with the compromised identity suspended, a legitimate "
       + "user in the SAME TENANT keeps working");

    compromised: str = "vp_000";
    aid: str = "act_avail_001";
    r: dict = execute(req(aid, "suspend_principal",
                          {"principal_hash": compromised, "tenant": "t_verify"}, 1800));

    blast: dict = r["blast"];
    print("  suspend_principal " + compromised + " in t_verify");
    print("      approval : " + str(r["approval"]) + "   state: " + str(r["state"]));
    print("      blast    : " + str(blast["level"]) + " — "
          + str(blast["principals"]) + " principal, "
          + str(blast["sessions"]) + " session(s), "
          + str(blast["pct_of_tenant_actives"]) + "% of "
          + str(blast["tenant_denominator"]) + " tenant actives");
    ctl = find_control_node("suspend_principal", "principal:" + compromised);
    if ctl is not None {
        c: Control = ctl;
        print("      Control  : " + c.kind + " " + c.scope_key + " active="
              + str(c.active) + " expires_at=" + c.expires_at);
    }

    health: dict = r.get("health", {});
    print("");
    print("  --- SIDE A: the compromised identity ---");
    blocked: dict = run_probe("contained_subject_is_blocked", "suspend_principal",
                              r["scope"], now_ms());
    print("      " + str(blocked["detail"]));

    print("");
    print("  --- SIDE B: a legitimate colleague in the same tenant ---");
    avail: dict = run_probe("legit_user_can_list_projects", "suspend_principal",
                            r["scope"], now_ms());
    print("      " + str(avail["detail"]));

    # Not just one colleague: every other member of the tenant, one at a time,
    # each through the real guard under their own session.
    print("");
    print("  --- and the rest of the tenant, asked individually ---");
    per_user: dict = _each_member_lists_projects("t_verify", ["vp_000"]);
    working: int = int(per_user["ok_count"]);
    denied: list = per_user["denied"];
    print("      " + str(working) + "/" + str(BIG - 1)
          + " other t_verify members completed project.list");
    print("      sample: " + " | ".join(per_user["sample"]));
    if len(denied) > 0 {
        print("      denied: " + json.dumps(denied));
    }

    check("the compromised identity is blocked (DENY SUSPENDED)",
          bool(blocked["ok"]), str(blocked["detail"]));
    check("a legitimate user in the SAME tenant still lists projects",
          bool(avail["ok"]), str(avail["detail"]));
    check("every other member of the tenant is unaffected",
          working == (BIG - 1) and len(denied) == 0,
          str(working) + "/" + str(BIG - 1) + " working, denied=" + json.dumps(denied));
    check("the action's own health verification passed",
          str(r["health_status"]) == "pass", "health_status=" + str(r["health_status"])
          + " | " + " ; ".join(health.get("report", [])));

    # Roll back and confirm the compromised identity works again.
    a = find_action(aid);
    if a is not None {
        act: ContainmentAction = a;
        rollback(act, "verification 6 teardown");
    }
    after: dict = _each_member_lists_projects("t_verify", []);
    print("");
    print("      after rollback: " + str(after["ok_count"]) + "/" + str(BIG)
          + " members (including " + compromised + ") complete project.list");
    check("rollback restores the contained identity too",
          int(after["ok_count"]) == BIG,
          str(after["ok_count"]) + "/" + str(BIG));
    return {};
}

"""Ask every active member of a tenant to list projects, one at a time.

Each request goes through `authorize()` under that member's own live session, so
this is 39 real authorizations, not one result generalised."""
def _each_member_lists_projects(tenant_id: str, omit: list) -> dict {
    ok_count: int = 0;
    denied: list = [];
    sample: list = [];
    for raw_pid in tenant_actives(tenant_id) {
        pid: str = str(raw_pid);
        if pid in omit {
            continue;
        }
        verdict: dict = principal_can_list_projects(pid, tenant_id, now_ms());
        if bool(verdict["ok"]) {
            ok_count = ok_count + 1;
        } else {
            denied.append(str(verdict["detail"]));
        }
        if len(sample) < 3 {
            sample.append(str(verdict["detail"]));
        }
    }
    return {"ok_count": ok_count, "denied": denied, "sample": sample};
}

# ==========================================================================
# 7. Blast radius, from real state.
# ==========================================================================

def verify_7_blast() -> dict {
    hr("VERIFICATION 7 — blast radius is counted off the graph, narrow vs broad");

    cases: list = [
        ("NARROW", "revoke_session", {"session_ids": ["vs_007"]}),
        ("NARROW", "revoke_token", {"credential_id": "jti_v0"}),
        ("MODERATE", "block_source", {"src_ips": ["203.0.113.200"]}),
        ("BROAD", "force_reauth", {"tenant": "t_verify"}),
        ("BROAD", "feature_readonly", {"feature": "*"})
    ];

    seen: list = [];
    for row in cases {
        label: str = str(row[0]);
        kind: str = str(row[1]);
        target: dict = as_dict(row[2]);
        sc: dict = resolve_scope(kind, target, now_ms());
        if not sc["ok"] {
            print("  " + kind + ": " + str(sc["detail"]));
            continue;
        }
        bl: dict = blast_radius(kind, sc, now_ms());
        ap: dict = approval_for(kind, sc, bl, now_ms());
        seen.append(str(bl["level"]));
        print("");
        print("  " + kind + "  " + json.dumps(target));
        print("      scope keys            : " + json.dumps(sc["keys"])[:120]);
        print("      principals touched    : " + str(bl["principals"]));
        print("      live sessions touched : " + str(bl["sessions"]));
        print("      tenants touched       : " + str(bl["tenants"]));
        print("      pct of tenant actives : " + str(bl["pct_of_tenant_actives"])
              + "%  (of " + str(bl["tenant_denominator"]) + " in "
              + str(bl["denominator_tenant"]) + ")");
        print("      computed level        : " + str(bl["computed_level"])
              + "   contract floor: " + str(bl["contract_floor"])
              + "   -> effective: " + str(bl["level"]));
        print("      approval              : " + str(ap["approval"]));
    }

    narrow: dict = blast_radius("revoke_session",
                                resolve_scope("revoke_session", {"session_ids": ["vs_007"]}, now_ms()),
                                now_ms());
    broad: dict = blast_radius("force_reauth",
                               resolve_scope("force_reauth", {"tenant": "t_verify"}, now_ms()),
                               now_ms());

    check("a single-session revoke is counted narrow",
          str(narrow["level"]) == "narrow",
          "principals=" + str(narrow["principals"]) + " sessions="
          + str(narrow["sessions"]) + " pct=" + str(narrow["pct_of_tenant_actives"])
          + "% -> " + str(narrow["level"]));
    check("a tenant-wide force_reauth is counted broad",
          str(broad["level"]) == "broad",
          "principals=" + str(broad["principals"]) + " sessions="
          + str(broad["sessions"]) + " pct=" + str(broad["pct_of_tenant_actives"])
          + "% -> " + str(broad["level"]));
    check("the numbers come from real state (broad touches the whole tenant)",
          int(broad["principals"]) == BIG and int(broad["tenant_denominator"]) == BIG,
          str(broad["principals"]) + " principals of " + str(broad["tenant_denominator"])
          + " actives — the graph really has " + str(len(tenant_actives("t_verify"))));
    return {};
}

# ==========================================================================
# 8. Structural claims: no blanket shutdown, no unapproved execution.
# ==========================================================================

def verify_8_structural() -> dict {
    hr("VERIFICATION 8 — structural: no blanket shutdown exists");

    result: dict = no_blanket_shutdown();
    print("  kinds checked : " + str(result["kinds_checked"]));
    print("  offenders     : " + json.dumps(result["offenders"]));
    check("no containment kind has an unbounded or empty-target form",
          bool(result["ok"]), json.dumps(result["offenders"]));

    # An empty target on every kind must be rejected, not widened.
    rejected: int = 0;
    for raw_kind in CONTAINMENT_KINDS.keys() {
        kind: str = str(raw_kind);
        r: dict = execute(req("act_empty_" + kind, kind, {}, 0, "sec-lead@verify.test"));
        if str(r["state"]) == "failed" {
            rejected = rejected + 1;
        }
    }
    check("an empty target is REJECTED for all 10 kinds (never treated as 'all')",
          rejected == 10, str(rejected) + "/10 rejected with state=failed");

    # A kind outside the frozen enum cannot execute.
    bogus: dict = execute(req("act_bogus", "disable_everything",
                              {"tenant": "t_verify"}, 0, "sec-lead@verify.test"));
    print("  invented kind 'disable_everything' -> state=" + str(bogus["state"])
          + " : " + str(bogus["detail"]));
    check("a kind outside the frozen enum cannot execute",
          str(bogus["state"]) == "failed" and len(control_surface()) == 0,
          "state=" + str(bogus["state"]) + ", controls=" + str(len(control_surface())));

    print("  final control surface: " + str(len(control_surface())) + " control(s)");
    return {};
}

# ==========================================================================
# 9. The coordinator interface and the gateway projection.
# ==========================================================================

def verify_9_decision() -> dict {
    hr("VERIFICATION 9 — decision.v1 in, Controls out; and the gateway can read "
       + "them");

    base: dict = {
        "incident_id": "inc_dec_001",
        "decided_at_ms": now_ms(),
        "verdict_counts": {"malicious": 4, "suspicious": 1, "benign": 0},
        "score": 2.1,
        "quorum_met": True,
        "responders_voted": 5,
        "responders_no_vote": [],
        "degraded": False,
        "rule": "contain iff >=3/5 malicious AND score >= 1.5",
        "action_set": [
            {"action": "revoke_session", "target": {"session_ids": ["vs_020"]},
             "ttl_s": 900, "blast_radius": "narrow",
             "proposed_by": ["hermes", "athena"]},
            {"action": "throttle_source", "target": {"src_ips": ["198.51.100.31"]},
             "ttl_s": 900, "blast_radius": "narrow",
             "proposed_by": ["hermes", "athena", "apollo"]}
        ]
    };

    # contain=false must do nothing at all.
    no_contain: dict = dict(base);
    no_contain["contain"] = False;
    r0: dict = execute_decision(no_contain);
    print("  contain=false   : executed=" + str(r0["executed"])
          + " controls=" + str(len(control_surface()))
          + "  (" + str(r0["detail"]) + ")");
    check("a decision with contain=false applies nothing",
          int(r0["executed"]) == 0 and len(control_surface()) == 0,
          "executed=" + str(r0["executed"]));

    # quorum_met=false likewise, even with contain=true.
    no_quorum: dict = dict(base);
    no_quorum["contain"] = True;
    no_quorum["quorum_met"] = False;
    r1: dict = execute_decision(no_quorum);
    print("  quorum_met=false: executed=" + str(r1["executed"])
          + " controls=" + str(len(control_surface())));
    check("a decision without quorum applies nothing even when contain=true",
          int(r1["executed"]) == 0 and len(control_surface()) == 0,
          "executed=" + str(r1["executed"]));

    # The real thing.
    live: dict = dict(base);
    live["contain"] = True;
    r2: dict = execute_decision(live);
    print("");
    print("  contain=true    : " + str(r2["detail"]));
    for raw in as_list(r2["results"]) {
        one: dict = as_dict(raw);
        print("      " + str(one["kind"]) + " " + str(one["action_id"])
              + " -> " + str(one["state"]));
    }
    show_controls("after decision");
    check("a containing decision applied every action in its action_set",
          int(r2["applied"]) == 2, str(r2["applied"]) + "/2 applied");

    # Redelivery of the WHOLE decision — the at-least-once case.
    surface_1: list = control_surface();
    r3: dict = execute_decision(live);
    surface_2: list = control_surface();
    idem: int = 0;
    for raw2 in as_list(r3["results"]) {
        one2: dict = as_dict(raw2);
        if bool(one2["idempotent"]) {
            idem = idem + 1;
        }
    }
    print("  redelivery      : " + str(idem) + "/2 recognised as repeats, controls "
          + str(len(surface_1)) + " -> " + str(len(surface_2)));
    check("redelivering the whole decision is a no-op (derived action_ids are stable)",
          idem == 2 and json.dumps(surface_1) == json.dumps(surface_2),
          str(idem) + "/2 idempotent, surface unchanged="
          + str(json.dumps(surface_1) == json.dumps(surface_2)));

    # The gateway projection.
    path: str = controls_path();
    handle = open(path, "r", encoding="utf-8");
    blob: dict = json.loads(handle.read());
    handle.close();
    rows: list = as_list(blob["controls"]);
    bare: list = [];
    canonical: list = [];
    for raw3 in rows {
        row: dict = as_dict(raw3);
        if str(row["kind"]) == "throttle_source" {
            if str(row["scope_key"]).startswith("ip:") {
                canonical.append(str(row["scope_key"]));
            } else {
                bare.append(str(row["scope_key"]));
            }
        }
    }
    print("");
    print("  gateway projection (" + path + "): " + str(len(rows)) + " row(s)");
    print("      canonical throttle scope_keys : " + json.dumps(canonical));
    print("      gateway-dialect aliases       : " + json.dumps(bare));
    check("the projection carries a scope_key the gateway's throttle_rpm matches",
          "198.51.100.31" in bare,
          "bare-IP aliases present: " + json.dumps(bare));
    check("...alongside the canonical key guard() uses",
          "ip:198.51.100.31" in canonical, json.dumps(canonical));

    # Teardown.
    for raw4 in as_list(r2["results"]) {
        one3: dict = as_dict(raw4);
        a = find_action(str(one3["action_id"]));
        if a is not None {
            act: ContainmentAction = a;
            if act.state == "active" {
                rollback(act, "verification 9 teardown");
            }
        }
    }
    check("teardown left an empty control surface",
          len(control_surface()) == 0, str(len(control_surface())) + " remain");
    return {};
}

# ==========================================================================

with entry:__main__ {
    print("containment executor — verification run");
    print("audit log   : " + audit_log_path());
    print("controls    : " + controls_path());
    print("pending     : " + pending_path());

    build_world();
    print("world       : t_verify(" + str(len(tenant_actives("t_verify")))
          + " actives) t_small(" + str(len(tenant_actives("t_small"))) + " actives)");

    verify_1_all_kinds();
    verify_2_idempotency();
    verify_3_approval();
    verify_4_probe_failure();
    verify_5_ttl();
    verify_6_availability();
    verify_7_blast();
    verify_8_structural();
    verify_9_decision();

    hr("SUMMARY");
    print("  passed : " + str(len(PASSES)));
    print("  failed : " + str(len(FAILURES)));
    for f in FAILURES {
        print("    FAIL " + str(f));
    }
    print("");
    if len(FAILURES) == 0 {
        print("ALL CHECKS PASSED (" + str(len(PASSES)) + ")");
    } else {
        print(str(len(FAILURES)) + " CHECK(S) FAILED");
    }
}
