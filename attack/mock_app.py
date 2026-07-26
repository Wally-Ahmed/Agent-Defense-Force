#!/usr/bin/env python3
"""
Deterministic mock of the Northwind Projects public API -- for VERIFYING the
attack driver and benign generator without the live app.

It implements exactly enough of the frozen contract's decision order to return
the contract-correct status for every request the driver/benign send:

  route not found ............... 404 NOT_FOUND
  POST /auth/login .............. 401 NO_SESSION (generic, byte-identical body)
  no/invalid Bearer on authed op  401 NO_SESSION
  api_token tenant != path tenant 403 TENANT_MISMATCH
  role < required for the op ..... 403 INSUFFICIENT_ROLE
  create/patch AS !normal by <admin  403 INSUFFICIENT_ROLE
  read/list confidential|canary id by <admin  404 NOT_FOUND
  otherwise ..................... 200 / 201 / 202 with a result_count

Binds to loopback only. This is test scaffolding, NOT the real application.
"""

from __future__ import annotations

import json
import os
import re
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common  # noqa: E402

RANK = {"public": -1, "authenticated": 0, "viewer": 1, "member": 2, "admin": 3, "owner": 4}

# (method, compiled path regex without query, opname, required_role)
ROUTES = [
    ("GET", r"^/api/v1/tenants$", "ListMyTenants", "authenticated"),
    ("POST", r"^/api/v1/tenants$", "CreateTenant", "authenticated"),
    ("GET", r"^/api/v1/tenants/([^/]+)$", "ReadTenant", "viewer"),
    ("GET", r"^/api/v1/tenants/([^/]+)/members$", "ListMembers", "viewer"),
    ("POST", r"^/api/v1/tenants/([^/]+)/members/invites$", "InviteMember", "admin"),
    ("PATCH", r"^/api/v1/tenants/([^/]+)/members/([^/]+)$", "ChangeMemberRole", "admin"),
    ("DELETE", r"^/api/v1/tenants/([^/]+)/members/([^/]+)$", "RemoveMember", "admin"),
    ("POST", r"^/api/v1/tenants/([^/]+)/projects$", "CreateProject", "member"),
    ("GET", r"^/api/v1/tenants/([^/]+)/projects$", "ListProjects", "viewer"),
    ("GET", r"^/api/v1/tenants/([^/]+)/projects/([^/]+)$", "ReadProject", "viewer"),
    ("PATCH", r"^/api/v1/tenants/([^/]+)/projects/([^/]+)$", "UpdateProject", "member"),
    ("DELETE", r"^/api/v1/tenants/([^/]+)/projects/([^/]+)$", "DeleteProject", "admin"),
    ("POST", r"^/api/v1/tenants/([^/]+)/projects/([^/]+)/tasks$", "CreateTask", "member"),
    ("GET", r"^/api/v1/tenants/([^/]+)/projects/([^/]+)/tasks$", "ListTasks", "viewer"),
    ("GET", r"^/api/v1/tenants/([^/]+)/projects/([^/]+)/tasks/([^/]+)$", "ReadTask", "viewer"),
    ("PATCH", r"^/api/v1/tenants/([^/]+)/projects/([^/]+)/tasks/([^/]+)$", "UpdateTask", "member"),
    ("DELETE", r"^/api/v1/tenants/([^/]+)/projects/([^/]+)/tasks/([^/]+)$", "DeleteTask", "admin"),
    ("POST", r"^/api/v1/tenants/([^/]+)/projects/([^/]+)/tasks/([^/]+)/comments$", "CreateComment", "member"),
    ("GET", r"^/api/v1/tenants/([^/]+)/projects/([^/]+)/tasks/([^/]+)/comments$", "ListComments", "viewer"),
    ("GET", r"^/api/v1/tenants/([^/]+)/search$", "SearchTenant", "viewer"),
    ("POST", r"^/api/v1/tenants/([^/]+)/exports$", "RequestExport", "admin"),
    ("GET", r"^/api/v1/tenants/([^/]+)/exports/([^/]+)$", "DownloadExport", "admin"),
    ("POST", r"^/api/v1/tenants/([^/]+)/integrations/call$", "IntegrationCall", "member"),
]
COMPILED = [(m, re.compile(rx), op, role) for (m, rx, op, role) in ROUTES]


class State:
    def __init__(self, fx: dict) -> None:
        self.tokens = {}
        for kind in ("compromised", "benign_bulk"):
            sa = fx["service_accounts"][kind]
            self.tokens[sa["token"]] = {
                "tenant": sa["tenant"], "role": sa["role"],
                "scopes": set(sa.get("scopes", [])), "kind": "api_token",
            }
        self.project_sens = {}
        self.task_sens = {}
        self.members = set()
        for tenant, res in fx["resources"].items():
            for pid, pdata in res.get("projects", {}).items():
                self.project_sens[pid] = pdata.get("sensitivity", "normal")
                for tk in pdata.get("tasks", []):
                    # task inherits the project's sensitivity (no own sens in fixture)
                    self.task_sens[tk] = pdata.get("sensitivity", "normal")
            for mid in res.get("members", {}):
                self.members.add(mid)

    def sens_project(self, pid): return self.project_sens.get(pid, "normal")
    def sens_task(self, tk): return self.task_sens.get(tk, "normal")


def _err(code, status, msg):
    return status, {"error": {"code": code, "message": msg, "request_id": "req_mock"}}


LOGIN_FAIL = (401, {"error": {"code": "NO_SESSION",
                              "message": "Authentication failed.",
                              "request_id": "req_mock_login"}})


def classify(state: State, method: str, raw_path: str, headers, body: dict | None):
    path = raw_path.split("?", 1)[0]

    # Web root served by the gateway.
    if method == "GET" and path == "/":
        return 200, {"service": "northwind-mock", "status": "ok"}

    # Login always fails here (attacker has no valid password). Byte-identical body.
    if method == "POST" and path == "/api/v1/auth/login":
        return LOGIN_FAIL

    # Match a known operation; unknown route -> 404 (router-level, before authz).
    match = None
    for (m, rx, op, role) in COMPILED:
        if m == method:
            g = rx.match(path)
            if g:
                match = (op, role, g.groups())
                break
    if not match:
        return _err("NOT_FOUND", 404, "No such route.")
    op, required_role, groups = match

    # Principal from Bearer token.
    principal = None
    auth = headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        principal = state.tokens.get(auth[len("Bearer "):].strip())

    # ---- decision order (subset relevant to the campaign) ----
    if principal is None:
        return _err("NO_SESSION", 401, "No valid session.")

    path_tenant = groups[0] if (groups and op != "ListMyTenants") else None
    if op == "ListMyTenants":
        path_tenant = None

    # TENANT_MISMATCH: api_token bound to tenant A, path addresses tenant B.
    if path_tenant is not None and principal["kind"] == "api_token" \
            and principal["tenant"] != path_tenant:
        return _err("TENANT_MISMATCH", 403, "Credential is bound to a different tenant.")

    rank = RANK.get(principal["role"], 0)

    # Effective-role bump: creating/updating a record AS non-normal needs admin.
    eff_required = required_role
    if op in ("CreateProject", "UpdateProject"):
        sens = (body or {}).get("sensitivity", "normal")
        if sens != "normal":
            eff_required = "admin"

    if rank < RANK[eff_required]:
        return _err("INSUFFICIENT_ROLE", 403, "Insufficient role for this operation.")

    # IntegrationCall (same-tenant) requires the integration:call scope.
    if op == "IntegrationCall" and "integration:call" not in principal["scopes"]:
        return _err("INSUFFICIENT_ROLE", 403, "Missing integration:call scope.")

    # Sensitivity gating during resolution (read/list/comment by id).
    def gated(sens):
        return sens in ("confidential", "canary") and rank < RANK["admin"]

    if op == "ReadProject":
        if gated(state.sens_project(groups[1])):
            return _err("NOT_FOUND", 404, "Not found.")
        return 200, {"id": groups[1], "result_count": 1}
    if op in ("ReadTask", "UpdateTask"):
        eff = max(state.sens_project(groups[1]), state.sens_task(groups[2]),
                  key=lambda s: ("normal", "confidential", "canary").index(s))
        if gated(eff):
            return _err("NOT_FOUND", 404, "Not found.")
        return 200, {"id": groups[2], "result_count": 1}
    if op in ("ListComments", "CreateComment"):
        eff = max(state.sens_project(groups[1]), state.sens_task(groups[2]),
                  key=lambda s: ("normal", "confidential", "canary").index(s))
        if gated(eff):
            return _err("NOT_FOUND", 404, "Not found.")
        return (201 if op == "CreateComment" else 200), {"result_count": 9}

    # Success payloads with deterministic result_count.
    if op == "ListMyTenants":
        return 200, {"result_count": 1, "items": ["t_acme"]}
    if op == "ListProjects":
        return 200, {"result_count": 5}
    if op == "ListTasks":
        return 200, {"result_count": 100}  # full page (limit=100) -> loud lists
    if op == "SearchTenant":
        return 200, {"result_count": 12}
    if op == "CreateProject":
        return 201, {"id": "p_new", "result_count": 1}
    if op == "CreateTask":
        return 201, {"id": "tk_new", "result_count": 1}
    if op == "RequestExport":
        return 202, {"export_id": "ex_new", "status": "queued", "result_count": 1}
    if op == "DownloadExport":
        return 200, {"export_id": groups[1], "result_count": 1}
    return 200, {"result_count": 1}


class Handler(BaseHTTPRequestHandler):
    state: State = None  # set on the server

    def _body(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        if not length:
            return None
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return None

    def _handle(self, method):
        body = self._body() if method in ("POST", "PATCH", "PUT") else None
        status, payload = classify(self.state, method, self.path, self.headers, body)
        data = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self): self._handle("GET")
    def do_POST(self): self._handle("POST")
    def do_PATCH(self): self._handle("PATCH")
    def do_DELETE(self): self._handle("DELETE")

    def log_message(self, *a):  # keep the mock quiet
        pass


def main() -> int:
    import argparse
    p = argparse.ArgumentParser(description="Deterministic contract mock (loopback only).")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)
    args = p.parse_args()
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        raise common.SandboxViolation(f"mock refuses to bind non-loopback host {args.host!r}.")
    Handler.state = State(common.load_fixture("seed.json"))
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"# mock listening on http://{args.host}:{args.port} (loopback only)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
