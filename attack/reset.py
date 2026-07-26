#!/usr/bin/env python3
"""
Re-seed the authorized attack sandbox to a KNOWN baseline state.

Restores all synthetic accounts, sessions, services, and fixtures:
  * accounts   -> all active, none suspended
  * sessions   -> all cleared / rotated (none live)
  * services   -> both fixture service tokens active, none revoked
  * containment -> all flags cleared (no rate-limit, read-only, or reauth holds)
  * fixtures   -> seed.json / compromised.json validated & present

seed.json is the authoritative fixture; this script DERIVES the canonical runtime
baseline (state.json) from it, so there is no duplicated source of truth to drift.
Output is deterministic (sorted, no timestamps) => running reset twice is a no-op
diff. `--verify` asserts the sandbox is already in the known state.

Acceptance: `reset.py` then `reset.py --verify` must both exit 0, and two resets
must produce byte-identical state.json.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common  # noqa: E402

STATE_PATH = os.path.join(common.FIXTURES_DIR, "state.json")
REQUIRED_CANARY = {"projects": ["p_ac_999"], "tasks": ["tk_ac_9999"], "exports": ["ex_ac_canary_01"]}


def _validate_fixtures(fx: dict, comp: dict) -> list[str]:
    problems = []
    sa = fx.get("service_accounts", {})
    if "compromised" not in sa or "benign_bulk" not in sa:
        problems.append("seed.json missing service_accounts.compromised or .benign_bulk")
    if comp.get("identity", {}).get("email") != "svc_ingest@northwind.test":
        problems.append("compromised.json identity email drifted")
    if comp.get("identity", {}).get("role") != "member":
        problems.append("compromised identity must be role=member")
    acme = fx.get("resources", {}).get("t_acme", {})
    if acme.get("canary_projects") != REQUIRED_CANARY["projects"]:
        problems.append("canary project id drifted")
    for tok_owner in ("compromised", "benign_bulk"):
        if not sa.get(tok_owner, {}).get("token", "").startswith("nwp_fixture_"):
            problems.append(f"{tok_owner} token is not a nwp_fixture_ token")
    return problems


def build_baseline(fx: dict) -> dict:
    """Derive the canonical known-state baseline from the authoritative seed."""
    sa = fx["service_accounts"]
    accounts = []
    for email in fx["spray_targets"]:
        accounts.append({"email": email, "kind": "user", "suspended": False})
    for kind in ("compromised", "benign_bulk"):
        accounts.append({"email": sa[kind]["email"], "kind": "service_account",
                         "tenant": sa[kind]["tenant"], "role": sa[kind]["role"],
                         "suspended": False})
    accounts.sort(key=lambda a: a["email"])

    services = []
    for kind in ("compromised", "benign_bulk"):
        services.append({"token_id": sa[kind]["token_id"], "email": sa[kind]["email"],
                         "tenant": sa[kind]["tenant"], "role": sa[kind]["role"],
                         "status": "active", "revoked": False,
                         "scopes": sorted(sa[kind].get("scopes", []))})
    services.sort(key=lambda s: s["token_id"])

    acme = fx["resources"]["t_acme"]
    baseline = {
        "schema_version": fx["schema_version"],
        "seed": fx["seed"],
        "accounts": accounts,
        "sessions": [],  # all cleared / rotated
        "services": services,
        "containment": {  # all flags cleared -> nothing contained
            "suspended_accounts": [],
            "revoked_tokens": [],
            "rate_limited_sources": [],
            "readonly_features": [],
            "reauth_required": [],
        },
        "canary": {
            "projects": acme.get("canary_projects", []),
            "tasks": acme.get("canary_tasks", []),
            "exports": acme.get("canary_exports", []),
        },
        "sensitivity_counts": _sens_counts(fx),
    }
    return baseline


def _sens_counts(fx: dict) -> dict:
    counts = {"normal": 0, "confidential": 0, "canary": 0}
    for res in fx["resources"].values():
        for pdata in res.get("projects", {}).values():
            counts[pdata.get("sensitivity", "normal")] += 1
    return counts


def _canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, indent=2) + "\n"


def run(args) -> int:
    fx = common.load_fixture("seed.json")
    comp = common.load_fixture("compromised.json")

    problems = _validate_fixtures(fx, comp)
    if problems:
        print("# RESET FAILED -- fixtures are not in a known state:")
        for p in problems:
            print("  - " + p)
        return 1

    baseline = build_baseline(fx)
    canonical = _canonical(baseline)
    digest = hashlib.sha256(canonical.encode()).hexdigest()[:16]

    if args.verify:
        if not os.path.exists(STATE_PATH):
            print("# VERIFY FAILED -- state.json missing; run reset first.")
            return 1
        with open(STATE_PATH, encoding="utf-8") as fh:
            current = fh.read()
        if current != canonical:
            print("# VERIFY FAILED -- sandbox state differs from the known baseline.")
            return 1
        print(f"# VERIFY OK -- sandbox is in the known baseline state (sha={digest}).")
        return 0

    with open(STATE_PATH, "w", encoding="utf-8") as fh:
        fh.write(canonical)

    if args.clean:
        for name in ("attack_trace.jsonl", "benign_trace.jsonl"):
            path = os.path.join(common.HERE, name)
            if os.path.exists(path):
                os.remove(path)
                print(f"  cleaned {name}")

    n_acc = len(baseline["accounts"])
    n_svc = len(baseline["services"])
    print("# RESET OK -- sandbox restored to known baseline")
    print(f"  accounts : {n_acc} active, 0 suspended")
    print(f"  sessions : 0 (all cleared/rotated)")
    print(f"  services : {n_svc} active, 0 revoked")
    print(f"  containment: all flags cleared")
    print(f"  canary   : {baseline['canary']}")
    print(f"  state    : {STATE_PATH} (sha={digest})")
    return 0


def main() -> int:
    p = argparse.ArgumentParser(description="Re-seed the attack sandbox to a known state.")
    p.add_argument("--verify", action="store_true", help="assert current state == baseline (exit 0/1)")
    p.add_argument("--clean", action="store_true", help="also delete attack_trace.jsonl / benign_trace.jsonl")
    return run(p.parse_args())


if __name__ == "__main__":
    sys.exit(main())
