#!/usr/bin/env python3
"""Amplify the benign bulk importer to >=3x the attacker's request rate.

TEST-SIDE FIXTURE GENERATOR. Lives under monitor/tests/ and is NEVER imported by
monitor code. It reads the labels sidecar because that is exactly what labels are
for -- selecting a known-benign population to build a negative control. The
detector under test never sees labels and never sees this file.

The governing acceptance test: the benign bulk importer must stay silent even when
it is running far louder than the attacker. If raising its volume escalates it, the
design is wrong -- the fix is the design, not a threshold.

Amplification preserves SHAPE and changes only RATE:
  - same route-template mix, same 0 denials, same single source IP,
    same single user agent, same single session, same tenant, same sensitivity
  - each original bulk event is replayed N times inside its own 15s window with
    deterministic sub-window jitter and fresh event/request ids
Nothing else about the stream is touched, so any escalation this produces would be
attributable to volume alone.
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import sys

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
GOLDEN = os.path.join(REPO, "contracts", "fixtures", "audit_golden.jsonl")
LABELS = os.path.join(REPO, "contracts", "fixtures", "audit_golden.labels.jsonl")
WINDOW_MS = 15000


def _load():
    events = [json.loads(l) for l in open(GOLDEN, encoding="utf-8") if l.strip()]
    labels = [json.loads(l) for l in open(LABELS, encoding="utf-8") if l.strip()]
    if len(events) != len(labels):
        raise SystemExit("fixture/labels length mismatch")
    return events, labels


def peak_rates(events, labels):
    """Peak requests-per-15s-window for each population, and the derived RPS."""
    t0 = min(e["ts_ms"] for e in events)
    per = collections.defaultdict(collections.Counter)
    for e, l in zip(events, labels):
        per[l["population"]][(e["ts_ms"] - t0) // WINDOW_MS] += 1
    out = {}
    for pop, c in per.items():
        peak = max(c.values())
        span = (max(e["ts_ms"] for e, l in zip(events, labels) if l["population"] == pop)
                - min(e["ts_ms"] for e, l in zip(events, labels) if l["population"] == pop)) / 1000.0
        n = sum(c.values())
        out[pop] = {
            "events": n,
            "peak_req_per_window": peak,
            "peak_rps": round(peak / (WINDOW_MS / 1000.0), 4),
            "mean_rps": round(n / span, 4) if span else 0.0,
        }
    return out


def amplify(events, labels, factor):
    """Return a new event stream with the bulk population replayed `factor` times."""
    out = []
    seq = collections.Counter()
    for idx, (e, l) in enumerate(zip(events, labels)):
        if l["population"] != "bulk":
            out.append(e)
            continue
        win_start = (e["ts_ms"] // WINDOW_MS) * WINDOW_MS
        for k in range(factor):
            c = dict(e)
            # deterministic sub-window jitter; stays inside the SAME 15s window
            offset = (k * 311 + idx * 7) % WINDOW_MS
            c["ts_ms"] = win_start + offset
            if k:
                suffix = "%02x%02x" % (idx % 256, k % 256)
                c["event_id"] = c["event_id"][:-4] + suffix
                c["request_id"] = c["request_id"][:-4] + suffix
                c["trace_id"] = c["trace_id"][:-4] + suffix
            seq[c["session_id"]] += 1
            c["seq"] = seq[c["session_id"]]
            out.append(c)
    out.sort(key=lambda x: (x["ts_ms"], x["event_id"]))
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--factor", type=int, default=3,
                    help="replay multiplier applied to the bulk population")
    ap.add_argument("--out", required=True, help="output audit JSONL path")
    ap.add_argument("--stats", action="store_true")
    a = ap.parse_args(argv)
    if a.factor < 1:
        raise SystemExit("--factor must be >= 1")

    events, labels = _load()
    before = peak_rates(events, labels)
    amplified = amplify(events, labels, a.factor)

    with open(a.out, "w", encoding="utf-8") as fh:
        for e in amplified:
            fh.write(json.dumps(e, separators=(",", ":"), sort_keys=False) + "\n")

    if a.stats:
        bulk_peak = before["bulk"]["peak_req_per_window"] * a.factor
        camp_peak = before["campaign"]["peak_req_per_window"]
        stats = {
            "factor": a.factor,
            "baseline": before,
            "amplified_bulk_peak_req_per_window": bulk_peak,
            "amplified_bulk_peak_rps": round(bulk_peak / (WINDOW_MS / 1000.0), 4),
            "campaign_peak_req_per_window": camp_peak,
            "bulk_over_campaign_peak_ratio": round(bulk_peak / camp_peak, 2),
            "total_events_out": len(amplified),
        }
        json.dump(stats, sys.stdout, indent=2)
        sys.stdout.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
