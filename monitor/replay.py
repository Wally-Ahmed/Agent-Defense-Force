#!/usr/bin/env python3
"""Deterministic offline replay: golden fixture -> window.v1 -> incident.v1.

No model call at all. This is how the detection logic is tested and how the
system is demonstrated if a provider times out.

    python3 monitor/replay.py --run-id demo1
    python3 monitor/replay.py --input <other.jsonl> --run-id demo2 --assess

Pipeline
    audit JSONL
      -> audit_window.iter_frames()      15s tumbling windows, 6-window ring,
                                         cluster resolution, sanitisation
      -> window.v1 frames (+ quarantine sidecar, never model input)
      -> escalation_policy.jac           the escalation rule, run via detect.run_policy()
      -> incident.v1

`--assess` additionally runs the swappable model layer (monitor/hermes_client.py).
Offline that is a deterministic function with no network; live it is Hermes +
GLM-5.2 at xhigh via OpenRouter, selected by MONITOR_BACKEND. Either way an
effort_receipt.v1 is written at boot, and every artifact produced by an offline
run is labelled MOCKED.

Artifacts land in runs/<run_id>/ (gitignored):
    effort.jsonl        one effort_receipt.v1 line, written at boot
    frames.jsonl        the window.v1 stream the monitor scored
    quarantine.jsonl    fenced untrusted text -- forensics only, never model input
    incidents.jsonl     the incident.v1 output
    replay_manifest.json  what ran, with the MOCKED label when applicable
"""
from __future__ import annotations

import argparse
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import audit_window  # noqa: E402
import detect  # noqa: E402
import effort_receipt  # noqa: E402

DEFAULT_INPUT = os.path.join(REPO, "contracts", "fixtures", "audit_golden.jsonl")


def _write_jsonl(path, rows):
    with open(path, "w", encoding="utf-8") as fh:
        for r in rows:
            fh.write(json.dumps(r, separators=(",", ":"), sort_keys=True) + "\n")
    return path


def replay(input_path, run_id, assess=False, backend=None):
    run_dir = os.path.join(REPO, "runs", run_id)
    os.makedirs(run_dir, exist_ok=True)

    backend_name = backend or os.environ.get("MONITOR_BACKEND", "offline")

    # 1. effort receipt at boot -- before any scoring happens
    receipt_path, receipt = effort_receipt.emit_receipt(backend_name, run_id)
    mocked = bool(receipt.get("mocked"))

    # 2. aggregate: raw audit events -> window.v1 frames + quarantine sidecar
    with open(input_path, encoding="utf-8") as fh:
        events = [json.loads(l) for l in fh if l.strip()]
    quarantine = []
    frames = list(audit_window.iter_frames(events, quarantine_sink=quarantine.append))

    # 3. detect: the escalation rule (monitor/escalation_policy.jac). No model call.
    incidents = detect.run_policy(frames, quarantine=quarantine)

    frames_path = _write_jsonl(os.path.join(run_dir, "frames.jsonl"), frames)
    quar_path = _write_jsonl(os.path.join(run_dir, "quarantine.jsonl"), quarantine)
    inc_path = _write_jsonl(os.path.join(run_dir, "incidents.jsonl"), incidents)

    manifest = {
        "run_id": run_id,
        "input": os.path.relpath(input_path, REPO),
        "events_in": len(events),
        "frames_out": len(frames),
        "actor_rows": sum(len(f["actors"]) for f in frames),
        "quarantine_records": len(quarantine),
        "incidents": len(incidents),
        "model_calls": 0,
        "backend": backend_name,
        "mocked": mocked,
        "label": "MOCKED" if mocked else "LIVE",
        "artifacts": {
            "effort_receipt": os.path.relpath(receipt_path, REPO),
            "frames": os.path.relpath(frames_path, REPO),
            "quarantine": os.path.relpath(quar_path, REPO),
            "incidents": os.path.relpath(inc_path, REPO),
        },
    }

    # 4. optional, separate, swappable model layer
    if assess:
        import hermes_client  # noqa: E402

        be = hermes_client.get_backend(backend_name)
        assessments = []
        for inc in incidents:
            # The whole run goes in; build_model_input bounds it to the 6-window ring
            # (MODEL_INPUT_RING_WINDOWS) before the allowlist runs. Detection above already
            # ran over every frame — this bounds only what the model is shown.
            model_input = hermes_client.build_model_input(inc, frames)
            assessments.append({
                "incident_id": inc["incident_id"],
                "assessment": be.assess(model_input),
            })
        _write_jsonl(os.path.join(run_dir, "assessments.jsonl"), assessments)
        manifest["model_calls"] = len(assessments)
        manifest["artifacts"]["assessments"] = os.path.join("runs", run_id, "assessments.jsonl")

    with open(os.path.join(run_dir, "replay_manifest.json"), "w", encoding="utf-8") as fh:
        json.dump(manifest, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return manifest, incidents


def main(argv=None):
    ap = argparse.ArgumentParser(description="Deterministic offline replay of the monitor.")
    ap.add_argument("--input", default=DEFAULT_INPUT)
    ap.add_argument("--run-id", default="replay")
    ap.add_argument("--assess", action="store_true",
                    help="also run the swappable model layer (offline backend by default)")
    ap.add_argument("--backend", choices=["offline", "live"], default=None)
    a = ap.parse_args(argv)

    manifest, incidents = replay(a.input, a.run_id, assess=a.assess, backend=a.backend)
    if manifest["mocked"]:
        print("=== MOCKED RUN -- offline deterministic backend, no model was called ===")
    json.dump(manifest, sys.stdout, indent=2, sort_keys=True)
    sys.stdout.write("\n")
    for inc in incidents:
        print("\nincident %s  conf=%.4f  stages=%s  families=%s"
              % (inc["incident_id"], inc["confidence"],
                 inc["stage_signatures"], inc["families"]))
        print("  " + inc["summary"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
