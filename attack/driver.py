#!/usr/bin/env python3
"""
Deterministic 10-step attack driver for the authorized Northwind Projects demo.

WHAT THIS IS
  A seeded, fixed campaign that a single compromised LOW-PRIVILEGE service token
  runs against the frozen public API contract (contracts/app_api.openapi.yaml).
  Every request is one a real client could make -- the maliciousness is in the
  PATTERN across identities/sessions/sources/time/failed-actions, not in any
  single call. There is no backdoor, no "attack mode" endpoint, no privileged
  bypass. The compromised identity enters ONLY through the documented fixture
  Bearer token (attack/fixtures/compromised.json).

DETERMINISM
  --seed 1337 seeds all jitter. t_rel in the trace is the PLANNED schedule
  (deterministic), not wall-clock, so `same seed => byte-identical trace`.

SANDBOX (mechanical, not by convention)
  * Hard-asserts ATTACK_BASE_URL is loopback; refuses anything else, before I/O.
  * Only egress is ATTACK_BASE_URL + reads of attack/fixtures/*.
  * "Rotating sources" are X-Forwarded-For values in RFC-5737 ranges only,
    trusted by the app solely from loopback. Fixture data, not spoofing.

EXPECTED STATUS PER STEP
  Each request declares the EXACT status the frozen contract's decision order
  yields for this member principal, and asserts actual == expected. Where the
  golden fixture's simplified audit `route`/status differs from the frozen
  contract (e.g. member reading a confidential record), the CONTRACT wins:
    - admin-only op by a member ......... 403 INSUFFICIENT_ROLE
    - read/list a confidential|canary id  404 NOT_FOUND (unreachable by traversal)
    - create/patch a record AS !normal .. 403 INSUFFICIENT_ROLE (effective role bump)
    - Bearer token addressing another tenant  403 TENANT_MISMATCH
    - admin-gated export download by member   403 INSUFFICIENT_ROLE
"""

from __future__ import annotations

import argparse
import os
import random
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import common  # noqa: E402


def build_plan(seed: int, fx: dict, comp: dict) -> list[dict]:
    """Return the fixed, ordered list of campaign requests.

    Jitter is drawn from a seeded RNG so the schedule is reproducible. Each entry
    carries the exact contract-derived expected_status (+ expected reason).
    """
    rng = random.Random(seed)
    B = fx["api_base_path"]  # "/api/v1"
    inj = fx["injection_payloads"]
    src = fx["sources"]
    tok = comp["credential"]["token"]
    UA_ATTACK = inj["user_agent"]  # user-agent injection vector, carried on every authed call
    recon_ip = src["recon_and_spray_ip"]
    rot = src["rotation_ips"]

    auth = {"Authorization": "Bearer " + tok, "User-Agent": UA_ATTACK}

    def jitter(lo: float, hi: float) -> float:
        return round(rng.uniform(lo, hi), 3)

    plan: list[dict] = []

    def add(step, stage, action, method, path, expected, *, reason="", sleep=0.0,
            xff=None, headers=None, body=None, injection=None, note=""):
        plan.append({
            "step": step, "stage": stage, "action": action, "method": method,
            "path": path, "expected_status": expected, "expected_reason": reason,
            "sleep": sleep, "xff": xff, "headers": headers or {}, "body": body,
            "injection": injection, "note": note,
        })

    # ---- STEP 1: Reconnaissance (unauthenticated GETs on ordinary routes) ----
    add(1, "reconnaissance", "recon.web_root", "GET", "/", 200,
        sleep=0.0, xff=recon_ip, headers={"User-Agent": "curl/8.4.0"},
        note="unauth web root served by gateway")
    add(1, "reconnaissance", "recon.list_projects_unauth", "GET",
        f"{B}/tenants/t_acme/projects", 401, reason="NO_SESSION",
        sleep=jitter(0.3, 0.9), xff=recon_ip, headers={"User-Agent": "curl/8.4.0"},
        note="ordinary API route without a credential")
    add(1, "reconnaissance", "recon.unknown_route", "GET", f"{B}/status", 404,
        reason="NOT_FOUND", sleep=jitter(0.3, 0.9), xff=recon_ip,
        headers={"User-Agent": "curl/8.4.0"}, note="nonexistent route -> router 404")

    # ---- STEP 2: Failed logins / password spraying (generic 401, no disclosure) ----
    for i, email in enumerate(fx["spray_targets"]):
        add(2, "password_spraying", "spray.login_failed", "POST",
            f"{B}/auth/login", 401, reason="NO_SESSION",
            sleep=jitter(0.4, 1.1), xff=recon_ip,
            headers={"User-Agent": "python-requests/2.32"},
            body={"email": email, "password": f"Winter2026!{i}"},
            injection=("login_email" if i < 2 else None),
            note="byte-identical body for every account; no existence disclosure")

    # ---- STEP 3: Successful use of the pre-compromised identity (Bearer) ----
    add(3, "compromised_use", "compromised.list_my_tenants", "GET",
        f"{B}/tenants", 200, sleep=jitter(0.8, 1.6), xff=recon_ip, headers=auth,
        note="first successful authenticated call with the leaked fixture token")

    # ---- STEP 4: High-speed enumeration (paginated lists, rising distinct ids) ----
    add(4, "enumeration", "enum.list_projects", "GET",
        f"{B}/tenants/t_acme/projects?limit=100", 200, sleep=jitter(0.6, 1.9),
        xff=recon_ip, headers=auth)
    add(4, "enumeration", "enum.read_project", "GET",
        f"{B}/tenants/t_acme/projects/p_ac_101", 200, sleep=jitter(0.6, 1.9),
        xff=recon_ip, headers=auth)
    add(4, "enumeration", "enum.read_project", "GET",
        f"{B}/tenants/t_acme/projects/p_ac_103", 200, sleep=jitter(0.6, 1.9),
        xff=recon_ip, headers=auth)
    add(4, "enumeration", "enum.list_tasks", "GET",
        f"{B}/tenants/t_acme/projects/p_ac_101/tasks?limit=100", 200,
        sleep=jitter(0.6, 1.9), xff=recon_ip, headers=auth)
    add(4, "enumeration", "enum.search", "GET",
        f"{B}/tenants/t_acme/search?q=" + _q(inj["search_q_stage4"]), 200,
        sleep=jitter(0.6, 1.9), xff=recon_ip, headers=auth, injection="search_q",
        note="injection payload in search q= (attacker-controlled query string)")

    # ---- STEP 5: Permission-boundary probing (INSUFFICIENT_ROLE) ----
    add(5, "boundary_probing", "probe.change_member_role", "PATCH",
        f"{B}/tenants/t_acme/members/mem_ac_os_1003", 403, reason="INSUFFICIENT_ROLE",
        sleep=jitter(0.5, 1.2), xff=recon_ip, headers=auth,
        body={"role": "admin"}, note="admin-only op; step-up N/A to Bearer -> 403 not 401")
    add(5, "boundary_probing", "probe.remove_member", "DELETE",
        f"{B}/tenants/t_acme/members/mem_ac_pn_1006", 403, reason="INSUFFICIENT_ROLE",
        sleep=jitter(0.5, 1.2), xff=recon_ip, headers=auth)
    add(5, "boundary_probing", "probe.delete_project", "DELETE",
        f"{B}/tenants/t_acme/projects/p_ac_104", 403, reason="INSUFFICIENT_ROLE",
        sleep=jitter(0.5, 1.2), xff=recon_ip, headers=auth)

    # ---- STEP 6: Rapid adaptation -- pivot to a DIFFERENT endpoint class <1s after each deny ----
    add(6, "rapid_adaptation", "adapt.deny.invite_member", "POST",
        f"{B}/tenants/t_acme/members/invites", 403, reason="INSUFFICIENT_ROLE",
        sleep=jitter(0.5, 1.0), xff=recon_ip, headers=auth,
        body={"email": "mule@northwind.test", "role": "member"})
    add(6, "rapid_adaptation", "adapt.pivot.list_comments", "GET",
        f"{B}/tenants/t_acme/projects/p_ac_101/tasks/tk_ac_2011/comments", 200,
        sleep=0.384, xff=recon_ip, headers=auth,
        note="pivot <1s to a different endpoint class after the deny")
    add(6, "rapid_adaptation", "adapt.deny.request_export", "POST",
        f"{B}/tenants/t_acme/exports", 403, reason="INSUFFICIENT_ROLE",
        sleep=jitter(0.4, 0.9), xff=recon_ip, headers=auth,
        body={"format": "json", "include": ["projects", "tasks"]})
    add(6, "rapid_adaptation", "adapt.pivot.search", "GET",
        f"{B}/tenants/t_acme/search?q=" + _q(inj["search_q_stage6"]), 200,
        sleep=0.612, xff=recon_ip, headers=auth, injection="search_q",
        note="pivot <1s; injection payload in search q=")
    add(6, "rapid_adaptation", "adapt.deny.delete_project", "DELETE",
        f"{B}/tenants/t_acme/projects/p_ac_104", 403, reason="INSUFFICIENT_ROLE",
        sleep=jitter(0.4, 0.9), xff=recon_ip, headers=auth)
    add(6, "rapid_adaptation", "adapt.pivot.create_project", "POST",
        f"{B}/tenants/t_acme/projects", 201, sleep=0.471, xff=recon_ip, headers=auth,
        body={"key": "RECON", "name": "sprint planning", "sensitivity": "normal"},
        note="pivot <1s to a create -- a normal project a member may create")

    # ---- STEP 7: Session/token reuse across rotating synthetic sources ----
    for ip in rot:
        add(7, "source_rotation", "rotate.list_tasks", "GET",
            f"{B}/tenants/t_acme/projects/p_ac_101/tasks?limit=100", 200,
            sleep=jitter(0.3, 0.7), xff=ip, headers=auth,
            note="same token+UA, new X-Forwarded-For in 203.0.113.0/24")

    # ---- STEP 8: Discovery of higher-value resources (confidential) ----
    add(8, "sensitivity_climb", "climb.read_confidential_project", "GET",
        f"{B}/tenants/t_acme/projects/p_ac_190", 404, reason="NOT_FOUND",
        sleep=jitter(0.6, 1.3), xff=rot[1], headers=auth,
        note="confidential id unreachable to a member -> 404 (identical to nonexistent)")
    add(8, "sensitivity_climb", "climb.create_as_confidential", "POST",
        f"{B}/tenants/t_acme/projects", 403, reason="INSUFFICIENT_ROLE",
        sleep=jitter(0.6, 1.3), xff=rot[1], headers=auth,
        body={"key": "FIN", "name": inj["project_name_stage8"], "sensitivity": "confidential"},
        injection="project_name",
        note="requested sensitivity!=normal bumps effective role to admin -> 403; injection in name")
    add(8, "sensitivity_climb", "climb.comment_on_confidential", "POST",
        f"{B}/tenants/t_acme/projects/p_ac_190/tasks/tk_ac_2990/comments", 404,
        reason="NOT_FOUND", sleep=jitter(0.6, 1.3), xff=rot[1], headers=auth,
        body={"body": inj["comment_body_stage8"]}, injection="comment_body",
        note="parent confidential -> unreachable -> 404; injection in comment body")
    add(8, "sensitivity_climb", "climb.search_finance", "GET",
        f"{B}/tenants/t_acme/search?q=finance", 200, sleep=jitter(0.6, 1.3),
        xff=rot[1], headers=auth,
        note="search applies same predicate; confidential rows never surface")

    # ---- STEP 9: Lateral movement via integration.call, cross-tenant ----
    add(9, "lateral_movement", "lateral.integration_globex", "POST",
        f"{B}/tenants/t_globex/integrations/call", 403, reason="TENANT_MISMATCH",
        sleep=jitter(0.5, 1.1), xff=rot[2], headers=auth,
        body={"connector": "webhook", "operation": "ingest_batch",
              "payload": {"filename": inj["filename_stage9"], "rows": 5000}},
        injection="filename",
        note="token bound to t_acme addressing t_globex -> TENANT_MISMATCH; filename injection in payload")
    add(9, "lateral_movement", "lateral.integration_initech", "POST",
        f"{B}/tenants/t_initech/integrations/call", 403, reason="TENANT_MISMATCH",
        sleep=jitter(0.5, 1.1), xff=rot[2], headers=auth,
        body={"connector": "slack", "operation": "post_message",
              "payload": {"text": "sync"}})

    # ---- STEP 10: Attempted access to the canary record / protected export ----
    add(10, "canary", "canary.read_project", "GET",
        f"{B}/tenants/t_acme/projects/p_ac_999", 404, reason="NOT_FOUND",
        sleep=jitter(0.6, 1.4), xff=rot[3], headers=auth,
        note="canary project: SAME code path as confidential -> 404. Not special-cased.")
    add(10, "canary", "canary.download_export", "GET",
        f"{B}/tenants/t_acme/exports/ex_ac_canary_01", 403, reason="INSUFFICIENT_ROLE",
        sleep=jitter(0.6, 1.4), xff=rot[3], headers=auth,
        note="export download is admin-gated -> 403 by ordinary role check")
    add(10, "canary", "canary.read_task", "GET",
        f"{B}/tenants/t_acme/projects/p_ac_101/tasks/tk_ac_9999", 404, reason="NOT_FOUND",
        sleep=jitter(0.6, 1.4), xff=rot[3], headers=auth,
        note="canary task unreachable to a member -> 404. Not special-cased.")

    return plan


def _q(s: str) -> str:
    from urllib.parse import quote
    return quote(s, safe="")


def run(args) -> int:
    base = common.env_base_url(args.base_url)
    # Front-door sandbox assertion (before ANY network I/O).
    common.assert_loopback(base)

    fx = common.load_fixture("seed.json")
    comp = common.load_fixture("compromised.json")
    plan = build_plan(args.seed, fx, comp)

    # Pre-flight: every declared X-Forwarded-For must be RFC-5737. Refuse early.
    for entry in plan:
        if entry["xff"] is not None:
            common.validate_xff(entry["xff"])

    client = common.SandboxHTTPClient(base, timeout=args.timeout)
    clock = common.SimClock()

    out_path = args.out or os.path.join(common.HERE, "attack_trace.jsonl")
    records: list[dict] = []
    spray_bodies: list[bytes] = []
    passed = failed = errored = 0

    print(f"# attack driver | base={base} | seed={args.seed} | steps=10 | requests={len(plan)}")
    print(f"# sandbox: loopback-asserted, XFF in RFC-5737 only, fixture token only")

    for entry in plan:
        t_rel = clock.advance(entry["sleep"])
        if not args.no_sleep and entry["sleep"] > 0:
            time.sleep(min(entry["sleep"], args.max_sleep))

        method, path = entry["method"], entry["path"]
        try:
            resp = client.request(method, path, headers=entry["headers"],
                                  body=entry["body"], xff=entry["xff"])
            actual = resp.status
            rc = resp.result_count()
            if entry["stage"] == "password_spraying":
                spray_bodies.append(resp.body)
        except ConnectionError as exc:
            actual = 0
            rc = 0
            errored += 1
            print(f"  ! step {entry['step']:>2} {entry['action']:<34} CONNECT-FAIL: {exc}")

        ok = (actual == entry["expected_status"])
        if actual != 0:
            passed += ok
            failed += (not ok)

        rec = {
            "step": entry["step"],
            "t_rel": t_rel,
            "action": entry["action"],
            "method": method,
            "path": path,
            "src_ip": entry["xff"],
            "expected_status": entry["expected_status"],
            "expected_reason": entry["expected_reason"],
            "actual_status": actual,
            "result_count": rc,
            "injection": entry["injection"],
            "ok": ok,
        }
        records.append(rec)
        flag = "OK " if ok else ("ERR" if actual == 0 else "XX ")
        inj = f" [inj:{entry['injection']}]" if entry["injection"] else ""
        print(f"  {flag} step {entry['step']:>2} t={t_rel:7.3f} {method:<6} "
              f"exp={entry['expected_status']} act={actual} {entry['action']}{inj}")

    # Step-2 assertion: spray responses must NOT disclose account existence.
    disclosure_ok = _assert_no_account_disclosure(spray_bodies, fx["spray_targets"])

    with open(out_path, "w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(common.trace_line(rec) + "\n")

    total = len(records)
    print(f"\n# trace written: {out_path}")
    print(f"# result: {passed}/{total} expected==actual"
          + (f" | {failed} mismatch" if failed else "")
          + (f" | {errored} connect-fail" if errored else ""))
    print(f"# step-2 non-disclosure assertion: {'PASS' if disclosure_ok else 'FAIL'}")

    if errored:
        return 2  # target unreachable
    return 0 if (failed == 0 and disclosure_ok) else 1


def _assert_no_account_disclosure(bodies: list[bytes], emails: list[str]) -> bool:
    """The password-spray responses must be byte-identical and leak nothing about
    which accounts exist."""
    if not bodies:
        return True
    if len(set(bodies)) != 1:
        print("  ! spray bodies are NOT byte-identical -> potential account enumeration")
        return False
    text = bodies[0].decode("utf-8", "replace").lower()
    banned = ["exists", "not found", "no such", "unknown user", "unknown account",
              "suspended", "incorrect password", "valid email"]
    for email in emails:
        if email.lower() in text:
            print(f"  ! spray body echoes submitted email {email!r} -> disclosure")
            return False
    for word in banned:
        if word in text:
            print(f"  ! spray body contains disclosing phrase {word!r}")
            return False
    return True


def main() -> int:
    p = argparse.ArgumentParser(description="Deterministic 10-step attack driver (authorized demo).")
    p.add_argument("--seed", type=int, default=1337)
    p.add_argument("--base-url", default=None,
                   help="loopback base URL; else ATTACK_BASE_URL; else http://127.0.0.1:8080")
    p.add_argument("--out", default=None, help="trace output path (default attack/attack_trace.jsonl)")
    p.add_argument("--no-sleep", action="store_true",
                   help="skip real sleeps (t_rel schedule is unchanged -> same trace)")
    p.add_argument("--max-sleep", type=float, default=2.0, help="cap any single real sleep")
    p.add_argument("--timeout", type=float, default=5.0)
    return run(p.parse_args())


if __name__ == "__main__":
    sys.exit(main())
