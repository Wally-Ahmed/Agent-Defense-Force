import from contracts.req_ctx_contract { ReqCtx, Grant, guard }

impl guard {
    return Grant(ok=True, reason="");
}

with entry:__main__ {
    c = ReqCtx(request_id="r1");
    g = guard(c, "project.read", "project", "t1");
    print("impl works ->", g.ok, "| reason=", g.reason);
}
