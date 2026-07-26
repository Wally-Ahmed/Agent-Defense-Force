import from typing { cast }
import from contracts.audit_event_contract { AuditEvent, ACTIONS, DENY_REASONS }
import from contracts.req_ctx_contract { ReqCtx, Grant, guard }
import from contracts.containment_contract { ContainmentAction, Control, CONTAINMENT_KINDS }

node Tenant { has tenant_id: str = ""; }

# Simulates a T3 domain walker: ctx is a PLAIN DICT, per the contract note.
walker CreateProject {
    has ctx: dict = {};
    has name: str = "";
}

def consume_grant(g: Grant) -> str {
    return cast(Tenant, g.tenant).tenant_id;
}

with entry:__main__ {
    # 1. AuditEvent: partial construction must work (all fields defaulted).
    e = AuditEvent(
        event_id="evt-1", ts_ms=1, kind="security", action="export.download",
        outcome="deny", reason="TENANT_MISMATCH", severity="high", result_count=9000
    );
    print("AuditEvent  |", e.schema_version, e.action, e.reason, e.result_count, e.seq);

    # 2. Vocab constants are importable and closed.
    print("vocab       |", len(ACTIONS), "actions,", len(DENY_REASONS), "deny reasons");
    print("membership  |", "export.download" in ACTIONS, "TENANT_MISMATCH" in DENY_REASONS);

    # 3. ReqCtx built from a plain dict, exactly as guard() does internally.
    raw = {"request_id": "r1", "src_ip": "10.0.0.1", "csrf_ok": True, "received_at_ms": 42};
    c = ReqCtx(**raw);
    print("ReqCtx      |", c.request_id, c.src_ip, c.csrf_ok, c.received_at_ms, "|route=", c.route);

    # 4. Grant with opaque node handles + the documented cast() escape.
    t = Tenant(tenant_id="tenant-7");
    g = Grant(ok=True, tenant=t);
    print("Grant       |", g.ok, consume_grant(g), "| reason=", g.reason);

    # 5. Containment records + policy table.
    ca = ContainmentAction(action_id="ca-1", kind="block_source", scope={"src_ip": "10.0.0.1"}, reason_codes=["TENANT_MISMATCH"]);
    ctl = Control(control_id="ctl-1", kind="block_source", scope_key="ip:10.0.0.1", active=True);
    print("Containment |", ca.schema_version, ca.reversible, ca.reason_codes, "|", ctl.active);
    pol = CONTAINMENT_KINDS["block_source"];
    print("policy      |", pol["blast"], pol["approval"], pol["ttl_s"], "| kinds=", len(CONTAINMENT_KINDS));

    # 6. Walker with plain-dict ctx.
    w = CreateProject(ctx={"request_id": "r1"}, name="p1");
    print("walker      |", w.ctx["request_id"], w.name);
}
