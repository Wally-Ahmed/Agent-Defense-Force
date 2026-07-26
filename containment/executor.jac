# containment/executor.jac — turning a coordinator decision into a narrow,
# reversible change to the running system.
#
# THE PIPELINE
#
#     gate  ->  snapshot  ->  apply  ->  verify  ->  (rollback on failure)
#
# and nothing else. Each arrow is a state transition on a `ContainmentAction`
# node and each transition emits exactly one `containment.*` AuditEvent, so the
# trail reads as a sentence: proposed, applied, verified — or rolled back.
#
# THE ONE SURFACE. This module writes `Control` nodes. That is the entire extent
# of its power over the application. It does not call into walkers, does not set
# flags on `Principal`, does not revoke a `Session` node's `revoked` field, does
# not touch the gateway process. guard() reads `Control`; the gateway reads a
# JSON projection of the same node set; therefore removing the Control node is
# sufficient to undo the action completely. Reaching into app internals would
# buy nothing and would cost the property that makes rollback trustworthy.
#
# SNAPSHOT BEFORE WRITE, ALWAYS. `prior_state` is captured before the first
# mutation, and if it cannot be captured the action does not run. An action we
# cannot undo is not containment, it is damage — so "no snapshot, no apply" is a
# hard gate, not an aspiration.
#
# IDEMPOTENCY. The coordinator dispatches over an at-least-once anycast queue.
# Redelivery is not an edge case, it is the normal case, and `execute()` is keyed
# on `action_id`: a second delivery of an already-active action returns the first
# outcome and writes NOTHING — no second Control, no second snapshot (which would
# overwrite the real prior state with the contained state and make rollback a
# no-op), no second audit event. Terminal actions (rolled back, expired, failed)
# stay terminal; a redelivery cannot resurrect one.
#
# WHAT CANNOT HAPPEN HERE. There is no code path that writes a control naming
# the whole platform, and no path that applies a `human_required` action without
# an `approved_by`. Both are enforced in containment/policy.jac and re-checked
# here before the write, because a gate you only run once is a gate somebody will
# eventually route around.

import os;
import json;
import time;

import from contracts.containment_contract { ContainmentAction, Control, CONTAINMENT_KINDS }
import from app.model.graph { Platform, Enforces, get_platform, all_controls }
import from app.security.audit { emit_audit }
import from app.security.clock { now_ms, iso_ts, iso_to_ms }
import from app.security.controls { is_live }
import from containment.policy { gate, BLAST_LEVELS }
import from containment.probes { run_health, default_probe_for }

# Platform -> ContainmentAction. Declared here rather than in app/model/graph.jac
# because the application has no business knowing that containment proposals
# exist; it only ever reads `Control`.
edge Proposes {}

# Where the gateway (a separate process) reads its projection of the Control set.
# Same default as gateway/config.jac; CONTROLS_PATH overrides both in lockstep.
glob:pub DEFAULT_CONTROLS_PATH: str = "var/controls/controls.json";

# Human-required actions that arrived without approval land here so a person can
# see them. Recorded, surfaced, and NOT executed — never silently dropped.
glob:pub DEFAULT_PENDING_PATH: str = "var/containment/pending.json";

"""Path of the Control projection the gateway polls."""
def:pub controls_path() -> str {
    return os.environ.get("CONTROLS_PATH", DEFAULT_CONTROLS_PATH);
}

"""Path of the pending-approval queue."""
def:pub pending_path() -> str {
    return os.environ.get("CONTAINMENT_PENDING", DEFAULT_PENDING_PATH);
}

# --------------------------------------------------------------------------
# ContainmentAction storage.
# --------------------------------------------------------------------------

"""Every ContainmentAction ever recorded, in creation order."""
def:pub all_actions() -> list {
    p = get_platform();
    return [p->:Proposes:->][?:ContainmentAction];
}

"""The action with this id, or None. The idempotency key."""
def:pub find_action(action_id: str) -> ContainmentAction | None {
    for a in all_actions() {
        act: ContainmentAction = a;
        if act.action_id == action_id {
            return act;
        }
    }
    return None;
}

"""States from which nothing further will be applied."""
glob:pub TERMINAL_STATES: list = ["rolled_back", "expired", "failed", "verify_failed"];

# --------------------------------------------------------------------------
# Control read/write. The whole enforcement surface, in four functions.
# --------------------------------------------------------------------------

"""The Control node for (kind, scope_key), live or not, or None.

Matched on the exact pair. Two different kinds may legitimately name the same
scope_key (a principal can be both suspended and forced to re-auth) and they are
separate controls with separate lifetimes."""
def:pub find_control_node(kind: str, scope_key: str) -> Control | None {
    for c in all_controls() {
        ctl: Control = c;
        if ctl.kind == kind and ctl.scope_key == scope_key {
            return ctl;
        }
    }
    return None;
}

"""A Control's six contract fields as a plain dict — the snapshot unit."""
def:pub control_state(control: Control) -> dict {
    return {
        "control_id": control.control_id,
        "kind": control.kind,
        "scope_key": control.scope_key,
        "params": control.params,
        "expires_at": control.expires_at,
        "active": control.active
    };
}

"""Every Control on the platform, as dicts, sorted — a comparable fingerprint.

Used to prove that after rollback the control surface is byte-identical to what
it was before apply. Sorting by control_id makes the comparison independent of
graph traversal order."""
def:pub control_surface() -> list {
    index: dict = {};
    keys: list = [];
    for c in all_controls() {
        st: dict = control_state(c);
        # Sort key includes kind + scope_key so two controls that somehow share
        # a control_id still both appear, in a deterministic order.
        sort_key: str = str(st["control_id"]) + "|" + str(st["kind"]) + "|" + str(st["scope_key"]);
        keys.append(sort_key);
        index[sort_key] = st;
    }
    rows: list = [];
    for k in sorted(keys) {
        rows.append(index[k]);
    }
    return rows;
}

"""Write the JSON projection the gateway reads.

Every control, live or not, with its `active` flag as recorded — the gateway
applies its own expiry check, and handing it a pre-filtered list would hide a
stale control from the one process that could notice."""
def:pub project_controls() -> str {
    path: str = controls_path();
    parent: str = os.path.dirname(path);
    if parent != "" {
        os.makedirs(parent, exist_ok=True);
    }
    blob: dict = {"controls": control_surface(), "generated_at": iso_ts(now_ms())};
    handle = open(path, "w", encoding="utf-8");
    handle.write(json.dumps(blob, indent=2, sort_keys=False));
    handle.write("\n");
    handle.close();
    return path;
}

# --------------------------------------------------------------------------
# Audit.
# --------------------------------------------------------------------------

"""Emit one containment.* event.

`outcome` is allow for a transition that happened, deny for one the policy
refused (reason must then be a DENY_REASONS code), error for a health failure —
which is not a denial of anything, it is the system reporting that its own
action did not hold."""
def:pub emit_containment(
    action: ContainmentAction, what: str, outcome: str,
    reason: str = "", target_kind: str = "auth", count: int = 0
) -> dict {
    return emit_audit({
        "action": "containment." + what,
        "outcome": outcome,
        "reason": reason,
        "actor_principal_id": "",
        "actor_role": "none",
        "auth_method": "none",
        "tenant_id": str(action.blast_radius.get("denominator_tenant", "")),
        "actor_tenant_id": "",
        "target_kind": target_kind,
        "target_id": action.action_id,
        "parent_id": action.incident_id,
        "service": "scheduler",
        "request_id": action.action_id,
        "route": "containment/" + action.kind,
        "result_count": count
    });
}

# --------------------------------------------------------------------------
# THE ENTRY POINT.
# --------------------------------------------------------------------------

"""Execute one decision.v1 action_set entry.

`request` keys:
  action_id     required, the idempotency key
  incident_id   the incident this resolves
  action / kind one of the ten frozen kinds
  target        decision.v1 target object
  ttl_s         coordinator's minimum TTL
  blast_radius  coordinator's minimum blast (recorded, never trusted)
  proposed_by   responder ids
  approved_by   a human, when the action needs one
  health_check  probe name; defaults per kind
  created_by    monitor | responder:<model> | human

Returns a report dict: {ok, state, action_id, idempotent, gate, applied,
controls, health, audit, detail}."""
def:pub execute(request: dict) -> dict {
    now: int = now_ms();
    action_id: str = str(request.get("action_id", ""));
    if action_id == "" {
        return _report(None, False, "failed", "action_id is required — it is the "
                       + "idempotency key and without it redelivery double-applies");
    }

    # ------------------------------------------------------------------
    # 0. IDEMPOTENCY. Before anything else, before any write.
    # ------------------------------------------------------------------
    existing = find_action(action_id);
    if existing is not None {
        prior: ContainmentAction = existing;
        if prior.state in ["active", "applying"] {
            rep: dict = _report(prior, True, prior.state,
                                "already active — redelivery ignored, no second Control written");
            rep["idempotent"] = True;
            return rep;
        }
        if prior.state in TERMINAL_STATES {
            rep2: dict = _report(prior, True, prior.state,
                                 "already terminal (" + prior.state
                                 + ") — redelivery does not resurrect it");
            rep2["idempotent"] = True;
            return rep2;
        }
        # state == proposed: a human approval arriving later is a legitimate
        # transition, not a redelivery. Fall through and re-gate with it.
        if str(request.get("approved_by", "")) == "" {
            rep3: dict = _report(prior, False, "proposed",
                                 "still awaiting human approval");
            rep3["idempotent"] = True;
            return rep3;
        }
    }

    # ------------------------------------------------------------------
    # 1. POLICY GATE.
    # ------------------------------------------------------------------
    verdict: dict = gate(request, now);
    kind: str = str(verdict["kind"]);
    scope: dict = verdict["scope"];
    blast: dict = verdict["blast"];
    target_kind: str = str(verdict["target_kind"]);

    action: ContainmentAction = _upsert_action(existing, request, verdict, now);

    if str(verdict["code"]) in ["UNKNOWN_KIND", "MALFORMED_SCOPE", "EMPTY_SCOPE"] {
        action.state = "failed";
        emit_containment(action, "propose", "deny", "VALIDATION_FAILED", target_kind);
        _write_pending();
        return _report(action, False, "failed", str(verdict["detail"]));
    }

    # The proposal is well-formed. Record it.
    emit_containment(action, "propose", "allow", "", target_kind,
                     len(scope["keys"]));

    if bool(verdict["needs_human"]) {
        # RECORDED, SURFACED, NOT EXECUTED. This is the branch the whole
        # approval policy exists for: the action stays `proposed`, appears in
        # the pending queue, and no Control is written. It is neither applied
        # nor thrown away.
        action.state = "proposed";
        _write_pending();
        return _report(action, False, "proposed",
                       "human approval required: " + str(verdict["detail"]));
    }

    action.state = "approved";
    action.approved_by = str(request.get("approved_by", ""));

    # ------------------------------------------------------------------
    # 2. SNAPSHOT, THEN APPLY. In that order, without exception.
    # ------------------------------------------------------------------
    surface_before: list = control_surface();
    snapshot: dict = {};
    try {
        snapshot = _snapshot(kind, scope["keys"], now);
    } except Exception as e {
        action.state = "failed";
        emit_containment(action, "propose", "error", "", target_kind);
        _write_pending();
        return _report(action, False, "failed",
                       "prior_state snapshot failed, so nothing was applied: " + str(e));
    }
    if len(snapshot.get("controls", [])) != len(scope["keys"]) {
        action.state = "failed";
        emit_containment(action, "propose", "error", "", target_kind);
        return _report(action, False, "failed",
                       "snapshot covered " + str(len(snapshot.get("controls", [])))
                       + " of " + str(len(scope["keys"]))
                       + " scope keys — refusing to apply what cannot be undone");
    }
    action.prior_state = snapshot;
    action.state = "applying";

    written: list = [];
    try {
        written = _apply(action, kind, scope["keys"], request, now);
    } except Exception as e2 {
        # A partial write is the one thing worse than no write. Undo whatever
        # landed, using the snapshot we already hold.
        _restore(action);
        action.state = "failed";
        emit_containment(action, "rollback", "error", "", target_kind);
        project_controls();
        return _report(action, False, "failed", "apply failed and was undone: " + str(e2));
    }

    action.state = "active";
    action.applied_at = iso_ts(now);
    action.health_status = "unknown";
    project_controls();
    emit_containment(action, "apply", "allow", "", target_kind, len(written));

    # ------------------------------------------------------------------
    # 3. VERIFY.
    # ------------------------------------------------------------------
    health: dict = run_health(action.health_check, kind, scope, now_ms());
    action.health_status = str(health["status"]);

    if bool(health["ok"]) {
        emit_containment(action, "verify", "allow", "", target_kind, len(written));
        rep4: dict = _report(action, True, "active", "applied and verified");
        rep4["health"] = health;
        rep4["controls"] = written;
        rep4["surface_before"] = surface_before;
        return rep4;
    }

    # ------------------------------------------------------------------
    # 4. ROLLBACK. Immediate, automatic, no human in the loop — a containment
    #    that broke the app is not a containment worth keeping for one more
    #    request.
    # ------------------------------------------------------------------
    emit_containment(action, "verify", "error", "", target_kind, len(written));
    action.state = "verify_failed";
    rollback(action, "health probe failed: " + " ; ".join(health["failed"]));

    rep5: dict = _report(action, False, action.state,
                         "health check failed, containment automatically rolled back");
    rep5["health"] = health;
    rep5["controls"] = written;
    rep5["surface_before"] = surface_before;
    rep5["surface_after"] = control_surface();
    return rep5;
}

# --------------------------------------------------------------------------
# ROLLBACK — the property everything else is arranged around.
# --------------------------------------------------------------------------

"""Restore `prior_state` and mark the action rolled back.

COMPLETE means complete: a control that did not exist before is DELETED, not
deactivated. Leaving an inactive husk behind would be a visible difference
between "before" and "after", and the claim this system makes is that there is
none. What is emphatically NOT deleted is the record — the ContainmentAction
node keeps its full history and every audit event stays exactly where it was.
Rollback restores access; it never erases the account of what happened."""
def:pub rollback(action: ContainmentAction, cause: str) -> dict {
    restored: list = _restore(action);
    action.state = "rolled_back";
    project_controls();
    emit_containment(action, "rollback", "allow", "",
                     _target_kind_of(action), len(restored));
    _write_pending();
    return {
        "ok": True, "action_id": action.action_id, "state": action.state,
        "restored": restored, "cause": cause, "surface_after": control_surface()
    };
}

"""Put every touched scope key back exactly as it was. Returns what it did."""
def _restore(action: ContainmentAction) -> list {
    prior: dict = action.prior_state;
    rows: list = prior.get("controls", []);
    done: list = [];
    for raw in rows {
        row: dict = raw;
        kind: str = str(row["kind"]);
        scope_key: str = str(row["scope_key"]);
        found = find_control_node(kind, scope_key);
        if bool(row["existed"]) {
            before: dict = row["before"];
            if found is None {
                # It was removed while we held it. Recreate it verbatim.
                p = get_platform();
                p +>:Enforces:+> Control(
                    control_id=str(before["control_id"]),
                    kind=str(before["kind"]),
                    scope_key=str(before["scope_key"]),
                    params=before["params"],
                    expires_at=str(before["expires_at"]),
                    active=bool(before["active"])
                );
                done.append("recreated " + kind + " " + scope_key);
            } else {
                target: Control = found;
                target.control_id = str(before["control_id"]);
                target.params = before["params"];
                target.expires_at = str(before["expires_at"]);
                target.active = bool(before["active"]);
                done.append("restored " + kind + " " + scope_key
                            + " active=" + str(before["active"]));
            }
        } else {
            if found is not None {
                victim: Control = found;
                del victim;
                done.append("deleted " + kind + " " + scope_key);
            } else {
                done.append("already absent " + kind + " " + scope_key);
            }
        }
    }
    return done;
}

# --------------------------------------------------------------------------
# Internals.
# --------------------------------------------------------------------------

"""Capture the exact prior state of every scope key this action will touch."""
def _snapshot(kind: str, keys: list, at_ms: int) -> dict {
    rows: list = [];
    for raw_key in keys {
        scope_key: str = str(raw_key);
        found = find_control_node(kind, scope_key);
        if found is None {
            rows.append({
                "kind": kind, "scope_key": scope_key,
                "existed": False, "before": {}
            });
        } else {
            rows.append({
                "kind": kind, "scope_key": scope_key,
                "existed": True, "before": control_state(found)
            });
        }
    }
    return {"controls": rows, "taken_at": iso_ts(at_ms), "taken_at_ms": at_ms};
}

"""Write the Control nodes. Called only after a complete snapshot exists."""
def _apply(action: ContainmentAction, kind: str, keys: list,
           request: dict, at_ms: int) -> list {
    expires_at: str = "";
    if action.ttl_s > 0 {
        expires_at = iso_ts(at_ms + action.ttl_s * 1000);
    }
    action.expires_at = expires_at;

    params: dict = {};
    raw_params = request.get("params", {});
    if isinstance(raw_params, dict) {
        params = raw_params;
    }
    if kind == "throttle_source" and "rate_per_min" not in params {
        # The gateway reads this key; a throttle without a rate is not a throttle.
        params["rate_per_min"] = 6;
    }

    p = get_platform();
    written: list = [];
    control_ids: list = [];
    i: int = 0;
    for raw_key in keys {
        scope_key: str = str(raw_key);
        control_id: str = action.action_id + "#" + str(i);
        found = find_control_node(kind, scope_key);
        if found is None {
            p +>:Enforces:+> Control(
                control_id=control_id, kind=kind, scope_key=scope_key,
                params=params, expires_at=expires_at, active=True
            );
        } else {
            live: Control = found;
            live.control_id = control_id;
            live.params = params;
            live.expires_at = expires_at;
            live.active = True;
        }
        control_ids.append(control_id);
        written.append({
            "control_id": control_id, "kind": kind, "scope_key": scope_key,
            "params": params, "expires_at": expires_at, "active": True
        });
        i = i + 1;
    }

    merged: dict = action.params;
    merged["control_ids"] = control_ids;
    merged["scope_keys"] = keys;
    merged["control_params"] = params;
    action.params = merged;
    return written;
}

"""Create or update the ContainmentAction record from the gate verdict."""
def _upsert_action(existing: ContainmentAction | None, request: dict,
                   verdict: dict, at_ms: int) -> ContainmentAction {
    kind: str = str(verdict["kind"]);
    scope: dict = verdict["scope"];
    blast: dict = verdict["blast"];
    health_check: str = str(request.get("health_check", ""));
    if health_check == "" {
        health_check = default_probe_for(kind);
    }
    reasons: list = [];
    raw_reasons: list = [];
    if isinstance(request.get("proposed_by", []), list) {
        raw_reasons = request.get("proposed_by", []);
    }
    for r in raw_reasons {
        reasons.append(str(r));
    }

    scope_record: dict = {
        "keys": scope["keys"],
        "subject": scope["subject"],
        "tenant_id": scope["tenant_id"],
        "principal_ids": scope["principal_ids"],
        "target": request.get("target", {})
    };

    if existing is not None {
        record: ContainmentAction = existing;
        record.scope = scope_record;
        record.blast_radius = blast;
        record.approval = str(verdict["approval"]);
        record.ttl_s = int(verdict["ttl_s"]);
        record.health_check = health_check;
        record.approved_by = str(request.get("approved_by", ""));
        return record;
    }

    p = get_platform();
    return (p +>:Proposes:+> ContainmentAction(
        action_id=str(request.get("action_id", "")),
        incident_id=str(request.get("incident_id", "")),
        kind=kind,
        scope=scope_record,
        params={},
        blast_radius=blast,
        approval=str(verdict["approval"]),
        approved_by=str(request.get("approved_by", "")),
        state="proposed",
        ttl_s=int(verdict["ttl_s"]),
        applied_at="",
        expires_at="",
        health_check=health_check,
        health_status="unknown",
        prior_state={},
        reversible=True,
        reason_codes=reasons,
        created_by=str(request.get("created_by", "coordinator"))
    ))[0];
}

"""AuditEvent target_kind for an action already on the graph."""
def _target_kind_of(action: ContainmentAction) -> str {
    from_scope: dict = action.scope;
    subject: str = str(from_scope.get("subject", ""));
    mapping: dict = {
        "session": "auth", "token": "token", "principal": "member",
        "source": "auth", "feature": "project", "queue": "export",
        "credential": "integration", "observability": "tenant"
    };
    return str(mapping.get(subject, "auth"));
}

"""Rewrite the pending-approval queue from graph state.

Derived, never appended to: an action that gets approved and applied leaves the
queue automatically, and the file can be deleted without losing anything."""
def:pub _write_pending() -> str {
    path: str = pending_path();
    parent: str = os.path.dirname(path);
    if parent != "" {
        os.makedirs(parent, exist_ok=True);
    }
    rows: list = [];
    for a in all_actions() {
        act: ContainmentAction = a;
        if act.state == "proposed" and act.approval == "human_required" {
            rows.append({
                "action_id": act.action_id,
                "incident_id": act.incident_id,
                "kind": act.kind,
                "scope": act.scope,
                "blast_radius": act.blast_radius,
                "approval": act.approval,
                "state": act.state,
                "ttl_s": act.ttl_s,
                "health_check": act.health_check,
                "created_by": act.created_by,
                "reason_codes": act.reason_codes
            });
        }
    }
    handle = open(path, "w", encoding="utf-8");
    handle.write(json.dumps({"pending": rows, "generated_at": iso_ts(now_ms())}, indent=2));
    handle.write("\n");
    handle.close();
    return path;
}

"""Everything a caller needs to know about one execution."""
def _report(action: ContainmentAction | None, ok: bool, state: str, detail: str) -> dict {
    if action is None {
        return {
            "ok": ok, "state": state, "detail": detail, "action_id": "",
            "kind": "", "approval": "", "idempotent": False,
            "controls": [], "blast": {}, "health": {}, "scope": {}
        };
    }
    rec: ContainmentAction = action;
    return {
        "ok": ok,
        "state": state,
        "detail": detail,
        "action_id": rec.action_id,
        "incident_id": rec.incident_id,
        "kind": rec.kind,
        "approval": rec.approval,
        "approved_by": rec.approved_by,
        "idempotent": False,
        "ttl_s": rec.ttl_s,
        "expires_at": rec.expires_at,
        "applied_at": rec.applied_at,
        "health_check": rec.health_check,
        "health_status": rec.health_status,
        "scope": rec.scope,
        "blast": rec.blast_radius,
        "prior_state": rec.prior_state,
        "controls": [],
        "health": {}
    };
}
