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

"""The report list a spawned walker produced.

`jac check` cannot infer a type for the result of a `spawn` expression, so
`w.reports` reads as an attribute on Unknown and fails static analysis even
though it runs correctly. Going through this accessor keeps `jac check` green on
the test tree without weakening anything: an empty list from a walker that
reported nothing is itself an assertion failure at the call site."""
def:pub reports_of(w: object) -> list {
    return getattr(w, "reports", []);
}

"""The single report a walker produced, asserting there was exactly one.

Every walker in app/services/ reports once and disengages, so a second report
is a bug in the walker rather than something a test should quietly index past."""
def:pub only_report(w: object) -> dict {
    rows = reports_of(w);
    assert len(rows) == 1 , f"expected exactly 1 report, got {len(rows)}: {rows}";
    return rows[0];
}

"""The `data` payload of a success envelope.

Same reason as `reports_of`: an expression like `r["data"]["items"]` types as
Unknown under `jac check` even though it evaluates correctly. Narrowing through
these two accessors keeps static analysis honest about the test tree."""
def:pub data_of(r: dict) -> dict {
    out: dict = r.get("data", {});
    return out;
}

"""The `items` array of a paginated success envelope."""
def:pub items_of(r: dict) -> list {
    out: list = data_of(r).get("items", []);
    return out;
}

"""The `error` object of a deny envelope."""
def:pub error_of(r: dict) -> dict {
    out: dict = r.get("error", {});
    return out;
}

"""The per-field `details` array of a VALIDATION_FAILED envelope."""
def:pub details_of(r: dict) -> list {
    out: list = error_of(r).get("details", []);
    return out;
}
