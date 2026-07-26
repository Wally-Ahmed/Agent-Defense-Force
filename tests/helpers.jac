# tests/helpers.jac -- reading the audit trail back out of the graph.
#
# guard() writes every AuditEvent to two sinks: an append-only JSONL file and a
# node hung off the Platform by a `Records` edge. The tests read the graph sink,
# because it needs no filesystem setup and it is the same record.
#
# The tests assert on the COUNT as well as the content. contracts/vocab.md fixes
# the emission map at exactly one event per guard() call -- not zero, not two --
# so a walker that quietly emitted a second event, or a code path that skipped
# guard() and emitted none, is a failing test rather than a subtle drift in the
# numbers the monitor reads.

import from contracts.audit_event_contract { AuditEvent }
import from app.model.graph { Records, get_platform }

"""Every AuditEvent currently on the Platform, oldest first."""
def:pub audit_events() -> list {
    plat = get_platform();
    rows = [e for e in [plat->:Records:->][?:AuditEvent]];
    rows.sort(key=lambda e: AuditEvent : e.ts_ms);
    return rows;
}

"""How many events exist right now. Take one before an action and one after;
the difference is what that single request emitted."""
def:pub audit_count() -> int {
    return len(audit_events());
}

"""The events emitted since `mark`, in order."""
def:pub audit_since(mark: int) -> list {
    rows = audit_events();
    return rows[mark:];
}

"""Compact view of one event, for readable assertion failures."""
def:pub summarize(e: AuditEvent) -> dict {
    return {
        "action": e.action,
        "outcome": e.outcome,
        "reason": e.reason,
        "severity": e.severity,
        "actor_role": e.actor_role,
        "tenant_id": e.tenant_id,
        "actor_tenant_id": e.actor_tenant_id,
        "target_kind": e.target_kind,
        "target_id": e.target_id,
        "target_sensitivity": e.target_sensitivity,
        "result_count": e.result_count
    };
}

"""The single event a request emitted, asserting there was exactly one."""
def:pub only_event(mark: int) -> dict {
    rows = audit_since(mark);
    assert len(rows) == 1 , f"expected exactly 1 audit event, got {len(rows)}: {[summarize(r) for r in rows]}";
    return summarize(rows[0]);
}
