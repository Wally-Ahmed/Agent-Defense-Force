# incident/tests/test_no_label_leak.jac — the detector never sees ground truth.
#
#   jac test incident/tests/test_no_label_leak.jac      # from the repository root
#
# The golden fixture keeps its labels in a sidecar, `audit_golden.labels.jsonl`,
# separate from the scored stream, precisely so detection cannot cheat. If any
# production module read that file, every acceptance test in this package would
# pass vacuously and the negative control would prove nothing.
#
# This is asserted two ways, because either one alone is weak:
#
#   STATIC   every production source under incident/ is read and searched. A
#            source that names the sidecar, or reads a label-shaped key, fails.
#   RUNTIME  builtins.open is wrapped for the duration of a full
#            ingest -> correlate -> promote -> explain -> emit run, and every
#            path the pipeline opens is recorded. Static analysis cannot see a
#            path assembled at runtime; this can.
#
# The static half deliberately does NOT ban the word "label" in prose. A comment
# explaining why the sidecar is off limits is not a leak, and a test that
# punished documentation would be quietly deleted the first time it got in
# someone's way. What it bans is the sidecar's filename and the label keys.

import os;
import json;
import builtins;
import from typing { Any, cast }

import from incident.graph { IncidentGraph, Incident }
import from incident.pipeline { load_golden, analyze, incidents_of, explain, GOLDEN_EVENTS }
import from incident.walkers { rows_by_subject }
import from incident.emit { to_incident_v1 }

glob:pub HERE: str = os.path.dirname(os.path.abspath(__file__));
glob:pub PKG: str = os.path.dirname(HERE);

# The sidecar's filename, assembled from parts so this test file itself is not
# a counterexample to the pattern it enforces.
glob:pub SIDECAR: str = "audit_golden" + ".labels" + ".jsonl";

# Substrings that would indicate a production module reading ground truth.
glob:pub FORBIDDEN: list = [
    "audit_golden" + ".labels",
    "." + "labels" + ".jsonl",
    "\"" + "population" + "\"",
    "is_" + "attack",
    "ground_" + "truth"
];

glob:pub OPENED: list = [];
glob:pub REAL_OPEN: Any = builtins.open;


"""Wrapper that records every path the process opens."""
def tracking_open(*args: Any, **kwargs: Any) -> Any {
    if len(args) > 0 {
        OPENED.append(str(args[0]));
    }
    return REAL_OPEN(*args, **kwargs);
}


"""Every production .jac under incident/ — that is, everything except tests/."""
def production_sources() -> list {
    out = [];
    for (dirpath, dirnames, filenames) in os.walk(PKG) {
        if os.path.basename(dirpath) == "tests" {
            continue;
        }
        sep: str = str(os.sep);
        marker: str = sep + "tests" + sep;
        probe: str = str(dirpath) + sep;
        if marker in probe {
            continue;
        }
        for fn in filenames {
            if str(fn).endswith(".jac") {
                out.append(os.path.join(dirpath, str(fn)));
            }
        }
    }
    return sorted(out);
}


"""File contents as text."""
def read_text(path: str) -> str {
    with open(path, "r") as fh {
        return str(fh.read());
    }
}


test "the labels sidecar exists, so this test is not vacuous" {
    # NB: never name a local `root` in Jac — bare `root` is rewritten to the
    # builtin `root()` graph accessor, and the local is then called as a function.
    repo_root = os.path.dirname(PKG);
    sidecar_path = os.path.join(repo_root, "contracts", "fixtures", SIDECAR);
    assert os.path.isfile(sidecar_path);
    # And the scored input is a different file.
    assert GOLDEN_EVENTS != sidecar_path;
    assert os.path.isfile(GOLDEN_EVENTS);
}


test "STATIC: no production module names the labels sidecar" {
    sources = production_sources();
    # A shrinking module list would silently weaken this test.
    assert len(sources) >= 9;

    offenders = [];
    for src in sources {
        text = read_text(str(src));
        for needle in FORBIDDEN {
            if str(needle) in text {
                offenders.append(str(src) + " contains " + str(needle));
            }
        }
    }
    assert offenders == [];
}


test "STATIC: no production module imports the test-side label loader" {
    sources = production_sources();
    for src in sources {
        text = read_text(str(src));
        assert "incident.tests" not in text;
        assert "load_" + "labels" not in text;
    }
}


test "STATIC: the modules under test really are the ones that run" {
    # Guards against the list above going stale or the package being renamed:
    # every module the pipeline imports must appear in production_sources().
    names = [];
    for src in production_sources() {
        names.append(os.path.basename(str(src)));
    }
    for required in ["graph.jac", "projection.jac", "baseline.jac", "features.jac",
                     "scorers_sv.jac", "gate.jac", "stages.jac", "walkers.jac",
                     "emit.jac", "pipeline.jac"] {
        assert required in names;
    }
    # The mandated dotted path exists and is an alias for the real module, so
    # the scan above covers it either way.
    assert "scorers.sv.jac" in names;
}


test "RUNTIME: a full detection run opens no labels file" {
    OPENED.clear();
    builtins.open = tracking_open;
    opened_snapshot = [];
    try {
        events = load_golden();
        r = analyze(events);
        g = cast(IncidentGraph, r["graph"]);
        incs = incidents_of(g);
        assert len(incs) >= 1;
        inc = cast(Incident, incs[0]);
        e = explain(g, inc.incident_id);
        rows: list = list(rows_by_subject(g).get(inc.subject_key, []));
        payload = to_incident_v1(g, inc, rows, inc.last_ts_ms, e.summary);
        assert payload["schema_version"] == "incident.v1";
    } finally {
        builtins.open = REAL_OPEN;
        opened_snapshot = list(OPENED);
    }

    # The wrapper actually saw something, or this proves nothing.
    assert len(opened_snapshot) >= 2;

    for opened in opened_snapshot {
        p = str(opened);
        assert SIDECAR not in p;
        assert "." + "labels" + "." not in p;
    }

    # Positive statement of what the detector IS allowed to read: the scored
    # event stream and the frozen mesh schemas. Anything else is a new
    # dependency somebody has to justify.
    for opened in opened_snapshot {
        p = str(opened);
        allowed = p.endswith("audit_golden.jsonl") or p.endswith(".schema.json");
        assert allowed;
    }
}
