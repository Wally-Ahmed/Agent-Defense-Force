#!/usr/bin/env python3
"""Thin subprocess driver for the escalation policy.

This module contains NO rule logic. Every threshold, predicate, correlation
window and incident field is defined in `monitor/escalation_policy.jac`, which
is the single source of truth for the escalation rule. This file only:

    frames (dicts)  ->  JSONL bytes  ->  `jac run escalation_policy.jac`
    stdout JSONL    ->  incident.v1 dicts

There is deliberately no Python re-implementation and no fallback path: if the
`jac` binary is missing or the policy exits non-zero, `run_policy` raises
RuntimeError carrying the policy's stderr. A silent fallback would mean two
implementations of the rule, and the one that is reviewed and frozen is the Jac
one.

CLI:
    python3 monitor/detect.py --frames <frames.jsonl> [--quarantine <q.jsonl>] \
                              --out <incidents.jsonl>
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from typing import Any, Dict, List, Optional

MONITOR_DIR = os.path.dirname(os.path.abspath(__file__))
POLICY_FILE = "escalation_policy.jac"


def run_policy(
    frames: list,
    quarantine: Optional[list] = None,
    jac_bin: str = "jac",
) -> List[Dict[str, Any]]:
    """Run the Jac escalation policy over `frames` and return incident.v1 dicts.

    Args:
        frames:     window.v1 frames (dicts), ordered by window_start_ms.
        quarantine: optional quarantine records. When not None they are sent as
                    a leading ``{"__config__": {"quarantine": [...]}}`` line.
        jac_bin:    the jac executable to invoke.

    Raises:
        RuntimeError: if `jac` is not on PATH, the policy exits non-zero, or its
                      stdout is not parseable JSONL.
    """
    payload_lines: List[str] = []
    if quarantine is not None:
        payload_lines.append(
            json.dumps({"__config__": {"quarantine": list(quarantine)}}, sort_keys=True)
        )
    for frame in frames:
        payload_lines.append(json.dumps(frame, sort_keys=True))
    payload = "".join(line + "\n" for line in payload_lines)

    try:
        proc = subprocess.run(
            [jac_bin, "run", POLICY_FILE],
            cwd=MONITOR_DIR,
            input=payload,
            capture_output=True,
            text=True,
        )
    except FileNotFoundError as exc:
        raise RuntimeError(
            f"escalation policy could not run: {jac_bin!r} not found on PATH. "
            "The escalation rule lives only in "
            f"{os.path.join(MONITOR_DIR, POLICY_FILE)}; there is no Python fallback."
        ) from exc
    except OSError as exc:
        raise RuntimeError(f"escalation policy could not run: {exc}") from exc

    if proc.returncode != 0:
        raise RuntimeError(
            f"{jac_bin} run {POLICY_FILE} exited {proc.returncode}\n"
            f"--- stderr ---\n{proc.stderr}"
        )

    incidents: List[Dict[str, Any]] = []
    for lineno, line in enumerate(proc.stdout.splitlines(), start=1):
        line = line.strip()
        if not line:
            continue
        try:
            incidents.append(json.loads(line))
        except json.JSONDecodeError as exc:
            raise RuntimeError(
                f"policy stdout line {lineno} is not valid JSON: {exc}\n"
                f"line: {line[:400]}\n--- stderr ---\n{proc.stderr}"
            ) from exc
    return incidents


def _read_jsonl(path: str) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as handle:
        for lineno, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise RuntimeError(f"{path}:{lineno}: invalid JSON: {exc}") from exc
    return records


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run monitor/escalation_policy.jac over window.v1 frames."
    )
    parser.add_argument("--frames", required=True, help="window.v1 frames as JSONL")
    parser.add_argument("--quarantine", help="quarantine records as JSONL (optional)")
    parser.add_argument("--out", required=True, help="incident.v1 output as JSONL")
    parser.add_argument("--jac-bin", default="jac", help="jac executable (default: jac)")
    args = parser.parse_args(argv)

    frames = _read_jsonl(args.frames)
    quarantine = _read_jsonl(args.quarantine) if args.quarantine else None

    incidents = run_policy(frames, quarantine=quarantine, jac_bin=args.jac_bin)

    with open(args.out, "w", encoding="utf-8") as handle:
        for incident in incidents:
            handle.write(json.dumps(incident, sort_keys=True) + "\n")

    print(
        f"{len(frames)} frames -> {len(incidents)} incidents -> {args.out}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
