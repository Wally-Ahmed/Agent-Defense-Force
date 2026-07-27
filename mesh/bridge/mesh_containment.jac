# mesh/bridge/mesh_containment.jac
#
# THE SECOND SEAM.
#
# mesh_responder.jac swapped a recorded responder for a real model without the
# coordinator noticing. This does the same on the other side of the decision:
# it swaps `coordinator/mocks/mock_containment.jac` for the REAL enforcement
# surface — containment/executor.jac — without the coordinator noticing either.
#
# The coordinator's FSM duck-types its executor. Three methods, quoted from the
# call sites in coordinator/fsm.jac:
#
#     apply(action: dict, now_ms: int)        -> {"status": "ack"|"nak", ...}
#     health_probe(action: dict, now_ms: int) -> {"health": "pass"|"fail", ...}
#     rollback(action: dict, now_ms: int)     -> {"status": "rolled_back", ...}
#
# containment/executor.jac speaks a different dialect: one `execute(request)`
# keyed on an idempotency id, and a `rollback(node, cause)` that takes the live
# ContainmentAction GRAPH NODE. This object is the whole of the translation.
#
# WHAT IT DOES NOT DO. It does not decide anything. It does not soften a gate,
# skip an approval, widen a scope or retry past the coordinator's single
# redeliver. Every action still goes through `policy.gate` — unknown kind,
# malformed scope, blast radius and human-approval rules all apply exactly as
# they do to any other caller. When the policy says an action needs a human and
# no human has signed, this reports NAK and the coordinator aborts that action.
# That is the correct outcome, not an obstacle to be engineered around.
#
# THE ACTION_ID. containment/executor.jac derives one deterministically when a
# decision.v1 entry does not carry it, because decision.v1 forbids the field:
#
#     sha256(incident_id + "|" + kind + "|" + json(target, sorted))[:16]
#
# The same scheme is reproduced here, deliberately identically, so that an action
# applied through this adapter is the SAME action `execute_decision()` would have
# created for the same decision. Redelivery is then a no-op through either door,
# and `find_action()` can still locate the node at rollback time — the action_id
# string is the only thing that has to survive between apply and rollback,
# because the undo data lives on the node itself as `prior_state`.
#
# TIME. The coordinator passes its own virtual `now_ms`; the containment side
# ignores it and uses the app's real clock, exactly as `execute()` does
# internally. The two timelines are not interchangeable: session expiry, TTLs
# and the probes are all evaluated against real wall-clock state on the graph,
# and feeding them a frozen 1769472600000 would make live sessions look expired.
# The coordinator's virtual time stays where it belongs — in the audit trail.
#
# No credential, endpoint or host name lives here.

import os;
import sys;
import json;
import hashlib;

glob:pub HERE: str = os.path.dirname(os.path.abspath(__file__));
glob:pub REPO_ROOT: str = os.path.dirname(os.path.dirname(HERE));

with entry {
    # Same bootstrap, same reason as mesh_world.jac: containment/ and app/
    # import each other by full dotted path from the repo root, so the repo root
    # is what must be on sys.path before the imports below run.
    if REPO_ROOT not in sys.path {
        sys.path.insert(0, REPO_ROOT);
    }
}

import from containment.executor {
    execute, rollback, find_action, control_surface, TERMINAL_STATES
}
import from containment.probes { run_health, default_probe_for }
import from app.security.clock { now_ms }

"""States in which an action is genuinely holding a Control open."""
glob:pub LIVE_STATES: list = ["active"];

"""Reverse one action through the real executor.

A module-level indirection rather than a direct call inside the object, so that
`MeshContainment.rollback` (the coordinator's protocol) and
`containment.executor.rollback` (the enforcement surface) can never be confused
for one another at a call site."""
def _reverse(node: object, cause: str) -> dict {
    return rollback(node, cause);
}

"""The action_id containment/executor.jac would derive for this entry.

Byte-identical to `executor._derive_action_id`, on purpose — see the header."""
def:pub derive_action_id(incident_id: str, kind: str, target: object) -> str {
    canonical: str = json.dumps(target, sort_keys=True, separators=(",", ":"));
    digest: str = hashlib.sha256(
        (incident_id + "|" + kind + "|" + canonical).encode("utf-8")
    ).hexdigest()[:16];
    return incident_id + ":" + kind + ":" + digest;
}


"""A coordinator-protocol executor backed by the real containment surface.

Audit surfaces, mirroring MockContainment so `fsm.summary()` reads the same:
  applied      action dicts that actually took effect (a Control was written)
  rolled_back  action dicts that were reversed
  reports      every execute()/rollback() report, in order — the full trail

`approvals` maps an action_id to the human who signed it. It is empty by
default and there is no way to make it non-empty from inside this file: a human
approval has to be supplied by a human, from outside."""
obj MeshContainment {
    has incident_id: str = "";
    has approvals: dict = {};

    has applied: list = [];
    has rolled_back: list = [];
    has aborted: list = [];
    has reports: list = [];

    # ---- internal bookkeeping (not configuration) ------------------------
    has _ids: dict = {};      # action_key -> action_id
    has _scopes: dict = {};   # action_key -> resolved scope, for the re-probe
    has _kinds: dict = {};    # action_key -> kind

    """Local identity of an action_set entry: kind + canonical target."""
    def _key(action: dict) -> str {
        kind: str = str(action.get("action", ""));
        target = action.get("target", {});
        return kind + "|" + json.dumps(target, sort_keys=True, separators=(",", ":"));
    }

    """The idempotency key this action will be executed under."""
    def action_id_for(action: dict) -> str {
        return derive_action_id(
            self.incident_id,
            str(action.get("action", "")),
            action.get("target", {})
        );
    }

    """Dispatch one decision.v1 action_set entry to the real executor.

    ACK only when the executor reports `state == "active"` — i.e. a Control was
    actually written AND its health probe passed. Every other terminal state is
    a NAK:

      proposed       the policy requires a human approval nobody has given
      failed         the gate rejected it (unknown kind, empty or malformed
                     scope, or the snapshot could not be taken)
      verify_failed  it was applied, the probe failed, and the executor already
                     reversed it automatically — reporting ACK here would tell
                     the coordinator it is holding a control that no longer
                     exists

    The coordinator's single redeliver is handled by the executor's own
    idempotency ledger, so a second delivery of an already-active action returns
    the same ACK without writing a second Control."""
    def apply(action: dict, now_ms_virtual: int) -> dict {
        kind: str = str(action.get("action", ""));
        target = action.get("target", {});
        key: str = self._key(action);
        aid: str = self.action_id_for(action);
        self._ids[key] = aid;
        self._kinds[key] = kind;

        request: dict = {
            "action_id": aid,
            "incident_id": self.incident_id,
            "action": kind,
            "target": target,
            "ttl_s": int(action.get("ttl_s", 0)),
            "blast_radius": str(action.get("blast_radius", "")),
            "proposed_by": action.get("proposed_by", []),
            "approved_by": str(self.approvals.get(aid, "")),
            "params": action.get("params", {}),
            "created_by": "coordinator"
        };

        report: dict = execute(request);
        self.reports.append({"phase": "apply", "action_id": aid, "report": report});

        state: str = str(report.get("state", ""));
        scope = report.get("scope", {});
        if scope is not None {
            self._scopes[key] = scope;
        }

        if state in LIVE_STATES {
            already: list = [self._key(a) for a in self.applied];
            if key not in already {
                self.applied.append(dict(action));
            }
            return {
                "status": "ack", "action": kind, "target": target,
                "action_id": aid, "state": state,
                "detail": str(report.get("detail", ""))
            };
        }

        already_ab: list = [self._key(a) for a in self.aborted];
        if key not in already_ab {
            self.aborted.append(dict(action));
        }
        return {
            "status": "nak", "action": kind, "target": target,
            "action_id": aid, "state": state,
            "detail": str(report.get("detail", ""))
        };
    }

    """Re-run the real health probes against the applied control.

    `execute()` already probed this action once, in isolation, at the moment it
    was written. This is a SECOND, later probe taken after the whole action_set
    is in place, which is the one that matters: it is the only check that
    catches actions which are individually harmless but collectively lock a
    legitimate user out. `run_health` is the same function `execute()` calls —
    there is no probe-only path and no bypass.

    An action that never went active reports `fail`, so the coordinator does not
    count a control it is not holding."""
    def health_probe(action: dict, now_ms_virtual: int) -> dict {
        kind: str = str(action.get("action", ""));
        target = action.get("target", {});
        key: str = self._key(action);
        aid: str = self._ids.get(key, "");

        found = find_action(aid);
        if found is None {
            return {
                "action": kind, "target": target, "health": "fail",
                "detail": "no containment action was recorded for this entry"
            };
        }
        record = found;
        if record.state not in LIVE_STATES {
            return {
                "action": kind, "target": target, "health": "fail",
                "detail": "action is in state '" + str(record.state)
                          + "', not holding a control"
            };
        }

        scope = self._scopes.get(key, record.scope);
        health: dict = run_health(
            record.health_check, kind, scope, now_ms()
        );
        self.reports.append({"phase": "verify", "action_id": aid, "report": health});

        return {
            "action": kind, "target": target,
            "health": str(health.get("status", "fail")),
            "detail": "; ".join(health.get("report", []))
        };
    }

    """Reverse one action on the real surface.

    Delegates to `containment.executor.rollback`, which restores `prior_state`
    exactly: a Control that did not exist before is DELETED rather than
    deactivated, so the control surface returns byte-identical to what it was.
    What is not erased — deliberately — is the record: the ContainmentAction node
    and every audit event stay exactly where they are.

    Idempotent. An action already in a terminal state (including one the
    executor auto-reversed when its probe failed) is reported as reversed
    without being touched again."""
    def rollback(action: dict, now_ms_virtual: int) -> dict {
        kind: str = str(action.get("action", ""));
        target = action.get("target", {});
        key: str = self._key(action);
        aid: str = self._ids.get(key, "");

        keep: list = [];
        for a in self.applied {
            if self._key(a) != key {
                keep.append(a);
            }
        }
        self.applied = keep;

        already: list = [self._key(x) for x in self.rolled_back];
        if key not in already {
            self.rolled_back.append(dict(action));
        }

        found = find_action(aid);
        if found is None {
            return {
                "action": kind, "target": target, "status": "rolled_back",
                "action_id": aid, "detail": "nothing was ever applied for this entry"
            };
        }
        record = found;
        if record.state in TERMINAL_STATES {
            return {
                "action": kind, "target": target, "status": "rolled_back",
                "action_id": aid,
                "detail": "already terminal (" + str(record.state) + ")"
            };
        }

        result: dict = _reverse(record, "coordinator lifecycle: containment expired");
        self.reports.append({"phase": "rollback", "action_id": aid, "report": result});
        return {
            "action": kind, "target": target, "status": "rolled_back",
            "action_id": aid,
            "restored": result.get("restored", []),
            "detail": "reversed on the real control surface"
        };
    }

    """The audit list of applied action KINDS, sorted."""
    def applied_kinds -> list {
        return sorted([a.get("action", "") for a in self.applied]);
    }

    """The live Control surface, as executor.control_surface() sees it.

    This is the rollback oracle: capture it before containment and again after
    the reversal, and the two must be byte-identical."""
    def surface -> list {
        return control_surface();
    }
}
