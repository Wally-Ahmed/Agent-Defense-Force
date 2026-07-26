"""Spike1: can a Jac walker served over HTTP receive a nested dict as a `has` field?"""

obj ReqCtx {
    has request_id: str = "";
    has src_ip: str = "";
    has session_id: str = "";
    has csrf_ok: bool = False;
}

walker:pub echo_pub {
    has ctx: dict = {};
    has label: str = "";
    has n: int = 0;

    can run with Root entry {
        print("echo_pub received ctx:", self.ctx);
        print("echo_pub type(ctx):", type(self.ctx));
        client_fp = self.ctx.get("client_fp", None);
        print("echo_pub type(ctx['client_fp']):", type(client_fp));
        allowed = ["request_id", "src_ip", "session_id", "csrf_ok"];
        filtered = {k: v for (k, v) in self.ctx.items() if k in allowed};
        rebuilt = ReqCtx(**filtered);
        print("echo_pub rebuilt ReqCtx:", rebuilt);
        report {
            "label": self.label,
            "n": self.n,
            "ctx_type": str(type(self.ctx)),
            "client_fp_type": str(type(client_fp)),
            "client_fp": client_fp,
            "rebuilt_request_id": rebuilt.request_id,
            "rebuilt_csrf_ok": rebuilt.csrf_ok,
            "ctx_echo": self.ctx
        };
    }
}

walker:priv echo_priv {
    has ctx: dict = {};
    has label: str = "";

    can run with Root entry {
        print("echo_priv received ctx:", self.ctx);
        print("echo_priv type(ctx):", type(self.ctx));
        client_fp = self.ctx.get("client_fp", None);
        print("echo_priv type(ctx['client_fp']):", type(client_fp));
        allowed = ["request_id", "src_ip", "session_id", "csrf_ok"];
        filtered = {k: v for (k, v) in self.ctx.items() if k in allowed};
        rebuilt = ReqCtx(**filtered);
        print("echo_priv rebuilt ReqCtx:", rebuilt);
        report {
            "label": self.label,
            "ctx_type": str(type(self.ctx)),
            "client_fp_type": str(type(client_fp)),
            "rebuilt_request_id": rebuilt.request_id,
            "ctx_echo": self.ctx
        };
    }
}

walker:pub echo_typed {
    has ctx: ReqCtx;
    has label: str = "";

    can run with Root entry {
        print("echo_typed received ctx:", self.ctx);
        print("echo_typed type(ctx):", type(self.ctx));
        report {
            "label": self.label,
            "ctx_type": str(type(self.ctx)),
            "request_id": self.ctx.request_id,
            "csrf_ok": self.ctx.csrf_ok
        };
    }
}
