# incident/pipeline.jac — one place that wires the four walkers together.
#
# The runner and every test go through `analyze()`, so a test can never exercise
# a different pipeline from the one that ships.
#
# THE FIXTURE PATH IS RESOLVED FROM __file__, AND IT RESOLVES TO THE SCORED
# INPUT ONLY. `audit_golden.jsonl` is the 250-event stream. The ground-truth
# sidecar that sits beside it is never opened here or anywhere else on the
# detection path; only tests/labels.jac may name it, and
# tests/test_no_label_leak.jac proves the separation both statically (it greps
# every production source in this package) and at runtime (it records every path
# a full detection run opens).

import json;
import os;

import from incident.graph { IncidentGraph, Incident, Signal, Raised, Emitted }
import from incident.walkers { IngestAudit, Correlate, Promote, Explain, rows_by_subject }
import from incident.gate { WINDOW_MS, STEP_MS }

glob:pub HERE: str = os.path.dirname(os.path.abspath(__file__));
glob:pub REPO_ROOT: str = os.path.dirname(HERE);

# The scored input. There is deliberately no constant anywhere in this package
# naming the labels sidecar.
glob:pub GOLDEN_EVENTS: str = os.path.join(
    REPO_ROOT, "contracts", "fixtures", "audit_golden.jsonl"
);


"""Read a JSON-lines file into a list of dicts."""
def load_jsonl(path: str) -> list {
    out = [];
    with open(path, "r") as fh {
        for line in fh {
            stripped = line.strip();
            if stripped == "" {
                continue;
            }
            out.append(json.loads(stripped));
        }
    }
    return out;
}


"""The golden audit stream."""
def load_golden() -> list {
    return load_jsonl(GOLDEN_EVENTS);
}


"""Ingest, correlate, promote. Returns the graph and the three walkers.

`theta_override` below 0 leaves gate.THETA in force; a non-negative value
re-decides only the aggregate clause, which is how the threshold-sensitivity
test sweeps THETA without editing the source."""
def analyze(events: list, theta_override: float = -1.0,
            window_ms: int = WINDOW_MS, step_ms: int = STEP_MS,
            require_mandatory: bool = True) -> dict {
    g = IncidentGraph(run_id="run");
    ingest = IngestAudit(events=events);
    ingest spawn g;
    correlate = Correlate(window_ms=window_ms, step_ms=step_ms);
    correlate spawn g;
    promote = Promote(theta_override=theta_override, require_mandatory=require_mandatory);
    promote spawn g;
    return {"graph": g, "ingest": ingest, "correlate": correlate, "promote": promote};
}


"""Every Incident raised on a graph, in a stable order."""
def incidents_of(g: IncidentGraph) -> list {
    bykey = {};
    for inc in [g ->:Raised:-> Incident] {
        bykey[str(inc.first_ts_ms).zfill(20) + "|" + str(inc.incident_id)] = inc;
    }
    out = [];
    for k in sorted(list(bykey.keys())) {
        out.append(bykey[k]);
    }
    return out;
}


"""Explain one incident."""
def explain(g: IncidentGraph, incident_id: str) -> Explain {
    e = Explain(incident_id=incident_id);
    e spawn g;
    return e;
}
