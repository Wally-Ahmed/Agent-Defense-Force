#!/usr/bin/env python3
"""
Benign high-volume load generator -- the NEGATIVE CONTROL.

A legitimate bulk reporting integration (svc_reporting@globex.test) runs a large,
fast, automated job: hundreds of task.list / project.read / export.request calls
at machine speed with high result counts. It must NOT trigger an incident.

It is deliberately LOUDER than the attacker on raw volume (far more requests and
far more rows returned) yet carries NONE of the campaign's behavioural signals:
  * ~zero denials (single privileged tenant, only legitimate operations)
  * single source IP (198.51.100.200)
  * single, stable User-Agent
  * entirely within its own tenant (t_globex) -- no cross-tenant attempts
  * only previously-seen endpoint classes -- no novelty
  * always normal sensitivity -- no confidential/canary, never touches a canary

Runs at >=3x the attacker's request rate by default (benign ~4.5 rps vs attacker
~1.5 rps). Same loopback sandbox guarantees as the driver.

NOTE (contract reconciliation): the golden fixture labels this account role=member,
but RequestExport is admin-only in the frozen contract with no service-account
scope exception (row 31). For the LIVE control to run export.request with ZERO
denials it must be admin. The seed fixture provisions it as admin in t_globex.
That does not weaken the control: an admin reporting integration exporting inside
its own tenant is entirely ordinary and still exhibits no incident signals.
"""

from __future__ import annotations

import argparse
import os
import random
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import common  # noqa: E402

ATTACKER_RPS = 1.5  # nominal attacker request rate (see driver schedule)
BENIGN_RPS = 4.5    # 3x attacker


def build_load(seed: int, count: int, fx: dict) -> list[dict]:
    rng = random.Random(seed)
    B = fx["api_base_path"]
    svc = fx["service_accounts"]["benign_bulk"]
    tenant = svc["tenant"]  # t_globex
    projects = list(fx["resources"][tenant]["projects"].keys())
    ua = "GlobexReporting/3.1 (+bulk-export; scheduled)"
    src = fx["sources"]["benign_ip"]
    auth = {"Authorization": "Bearer " + svc["token"], "User-Agent": ua}

    plan: list[dict] = []
    # Five batches spread across the window, like a real scheduled reporting run.
    batches = 5
    per_batch = max(1, count // batches)
    for b in range(batches):
        for _ in range(per_batch):
            r = rng.random()
            pid = rng.choice(projects)
            if r < 0.55:
                plan.append({"action": "task.list", "method": "GET",
                             "path": f"{B}/tenants/{tenant}/projects/{pid}/tasks?limit=100",
                             "expected": 200})
            elif r < 0.9:
                plan.append({"action": "project.read", "method": "GET",
                             "path": f"{B}/tenants/{tenant}/projects/{pid}",
                             "expected": 200})
            else:
                plan.append({"action": "export.request", "method": "POST",
                             "path": f"{B}/tenants/{tenant}/exports",
                             "expected": 202,
                             "body": {"format": "csv", "include": ["projects", "tasks"]}})
        # small inter-batch gap (kept short so the sustained request rate stays
        # >=3x the attacker; a real scheduled job would space batches further)
        if b < batches - 1:
            plan.append({"action": "_batch_gap", "method": None, "path": None,
                         "expected": None, "gap": round(rng.uniform(0.1, 0.25), 3)})
    for entry in plan:
        entry.setdefault("headers", auth)
        entry.setdefault("xff", src)
        entry.setdefault("body", None)
    return plan


def run(args) -> int:
    base = common.env_base_url(args.base_url)
    common.assert_loopback(base)

    fx = common.load_fixture("seed.json")
    plan = build_load(args.seed, args.count, fx)
    for e in plan:
        if e.get("xff"):
            common.validate_xff(e["xff"])

    rps = args.rps if args.rps else BENIGN_RPS
    interval = 1.0 / rps
    client = common.SandboxHTTPClient(base, timeout=args.timeout)
    clock = common.SimClock()
    out_path = args.out or os.path.join(common.HERE, "benign_trace.jsonl")

    records = []
    denials = errored = total_rows = req_n = 0
    srcs, uas, tenants_touched = set(), set(), set()
    sensitivities = set()

    print(f"# benign load | base={base} | seed={args.seed} | target rps={rps} "
          f"(~{rps/ATTACKER_RPS:.1f}x attacker) | requests≈{sum(1 for e in plan if e['method'])}")

    for e in plan:
        if e["method"] is None:  # inter-batch gap
            clock.advance(e["gap"])
            if not args.no_sleep:
                time.sleep(min(e["gap"], args.max_sleep))
            continue
        t_rel = clock.advance(interval)
        if not args.no_sleep:
            time.sleep(min(interval, args.max_sleep))
        req_n += 1
        try:
            resp = client.request(e["method"], e["path"], headers=e["headers"],
                                  body=e["body"], xff=e["xff"])
            actual = resp.status
            rc = resp.result_count()
        except ConnectionError as exc:
            actual, rc = 0, 0
            errored += 1
            if errored <= 3:
                print(f"  ! connect-fail: {exc}")
        total_rows += rc
        ok = (actual == e["expected"])
        if actual not in (0, e["expected"]):
            denials += 1
        srcs.add(e["xff"]); uas.add(e["headers"].get("User-Agent")); tenants_touched.add("t_globex")
        sensitivities.add("normal")
        records.append({"seq": req_n, "t_rel": t_rel, "action": e["action"],
                        "method": e["method"], "path": e["path"], "src_ip": e["xff"],
                        "expected_status": e["expected"], "actual_status": actual,
                        "result_count": rc, "ok": ok})

    with open(out_path, "w", encoding="utf-8") as fh:
        for rec in records:
            fh.write(common.trace_line(rec) + "\n")

    print(f"\n# trace written: {out_path}")
    print(f"# requests={req_n} rows_returned={total_rows} denials={denials} "
          f"distinct_src={len(srcs)} distinct_ua={len(uas)} "
          f"tenants={sorted(tenants_touched)} sensitivities={sorted(sensitivities)}")
    control_ok = (denials == 0 and errored == 0 and len(srcs) == 1 and len(uas) == 1
                  and tenants_touched == {"t_globex"} and sensitivities == {"normal"})
    print(f"# negative-control invariants (0 denials, 1 src, 1 ua, single tenant, "
          f"normal only): {'PASS' if control_ok else 'FAIL' + (' (target down)' if errored else '')}")
    if errored:
        return 2
    return 0 if control_ok else 1


def main() -> int:
    p = argparse.ArgumentParser(description="Benign high-volume negative control (authorized demo).")
    p.add_argument("--seed", type=int, default=1337)
    p.add_argument("--count", type=int, default=300, help="approx number of requests (hundreds)")
    p.add_argument("--rps", type=float, default=None, help=f"requests/sec (default {BENIGN_RPS}=3x attacker)")
    p.add_argument("--base-url", default=None)
    p.add_argument("--out", default=None)
    p.add_argument("--no-sleep", action="store_true")
    p.add_argument("--max-sleep", type=float, default=1.0)
    p.add_argument("--timeout", type=float, default=5.0)
    return run(p.parse_args())


if __name__ == "__main__":
    sys.exit(main())
