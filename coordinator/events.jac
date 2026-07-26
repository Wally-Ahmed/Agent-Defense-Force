# coordinator/events.jac
#
# Structured event emission for the coordinator.
#
# Two rules this module enforces mechanically:
#
#  1. EVERY state transition emits an event. The containment-relevant ones carry
#     an `action` drawn from the frozen audit vocabulary in
#     contracts/audit_event.contract.jac:
#        containment.propose | containment.apply | containment.verify
#      | containment.expire  | containment.rollback
#     Non-containment transitions carry `state.transition`, which keeps the
#     frozen ACTIONS enum honest instead of inventing new members of it.
#
#  2. EVERY event carries `run_label`. If the run contains any blocked or mocked
#     agent the label is MOCKED, and there is no code path that can emit an
#     unlabelled event — a mocked run is therefore never reportable as the live
#     run, in any artifact it touches.

import json;
import from ids { RUN_LIVE, RUN_MOCKED }

# Members of the frozen ACTIONS enum that the coordinator may emit.
glob:pub CONTAINMENT_ACTIONS: list = [
    "containment.propose",
    "containment.apply",
    "containment.verify",
    "containment.expire",
    "containment.rollback"
];

# Coordinator-local lifecycle marker. Not a member of the frozen ACTIONS enum
# and deliberately namespaced so it can never be mistaken for one.
glob:pub STATE_TRANSITION: str = "state.transition";

obj MeshEvent {
    has seq: int = 0;
    has ts_ms: int = 0;
    has action: str = "";
    has incident_id: str = "";
    has state_from: str = "";
    has state_to: str = "";
    has run_label: str = "LIVE";
    has detail: dict = {};

    """Plain-dict form, suitable for JSONL."""
    def as_dict -> dict {
        return {
            "seq": self.seq,
            "ts_ms": self.ts_ms,
            "action": self.action,
            "incident_id": self.incident_id,
            "state_from": self.state_from,
            "state_to": self.state_to,
            "run_label": self.run_label,
            "detail": self.detail
        };
    }
}

obj EventLog {
    # Stamped onto every event. Set to RUN_MOCKED by the effort gate whenever any
    # receipt carries blocked:true or mocked:true.
    has run_label: str = "LIVE";
    has events: list = [];
    has _seq: int = 0;

    """True when this log is labelled as a non-acceptance (mocked) run."""
    def is_mocked -> bool {
        return (self.run_label == RUN_MOCKED);
    }

    """Force the whole log — retroactively — into MOCKED. Irreversible by design:
    once a run has touched a mocked agent it can never be relabelled LIVE."""
    def mark_mocked -> None {
        self.run_label = RUN_MOCKED;
        for e in self.events {
            e.run_label = RUN_MOCKED;
        }
    }

    """Emit one structured event. Returns the event's dict form."""
    def emit(action: str, incident_id: str, ts_ms: int, detail: dict = {},
             state_from: str = "", state_to: str = "") -> dict {
        self._seq = (self._seq + 1);
        ev = MeshEvent(
            seq=self._seq,
            ts_ms=ts_ms,
            action=action,
            incident_id=incident_id,
            state_from=state_from,
            state_to=state_to,
            run_label=self.run_label,
            detail=detail
        );
        self.events.append(ev);
        return ev.as_dict();
    }

    """Emit a state transition. `action` defaults to the coordinator-local
    state.transition marker; containment-relevant transitions pass one of
    CONTAINMENT_ACTIONS instead."""
    def transition(incident_id: str, ts_ms: int, state_from: str, state_to: str,
                   action: str = "", detail: dict = {}) -> dict {
        act = action;
        if not act {
            act = STATE_TRANSITION;
        }
        return self.emit(
            action=act,
            incident_id=incident_id,
            ts_ms=ts_ms,
            detail=detail,
            state_from=state_from,
            state_to=state_to
        );
    }

    """All events whose action equals `action`."""
    def of_action(action: str) -> list {
        return [e.as_dict() for e in self.events if e.action == action];
    }

    """All emitted state_to values, in order — the transition trace."""
    def state_trace -> list {
        out: list = [];
        for e in self.events {
            if e.state_to {
                out.append(e.state_to);
            }
        }
        return out;
    }

    """JSONL rendering of the whole log, one event per line."""
    def to_jsonl -> str {
        lines: list = [];
        for e in self.events {
            lines.append(json.dumps(e.as_dict(), sort_keys=True, separators=(",", ":")));
        }
        return "\n".join(lines);
    }

    """True iff every event carries a non-empty run_label. Invariant check."""
    def all_labelled -> bool {
        for e in self.events {
            if not e.run_label {
                return False;
            }
        }
        return True;
    }
}
