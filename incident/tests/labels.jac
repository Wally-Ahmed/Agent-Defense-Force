# incident/tests/labels.jac — GROUND TRUTH, FOR ASSERTIONS ONLY.
#
# This is the ONLY module anywhere in `incident/` that opens
# contracts/fixtures/audit_golden.labels.jsonl, and it lives under tests/ so
# that fact is visible from the directory listing.
#
# The sidecar exists so detection cannot cheat. If any production module read
# it, every acceptance test would pass vacuously: the negative control ("the
# bulk importer is not promoted") only means something if the detector cannot
# tell bulk from campaign except by how they behave.
#
# tests/test_no_label_leak.jac greps every production source under incident/ and
# fails if the sidecar, or any label-shaped key, appears in one. That test
# excludes this file and the tests directory by construction — this is the
# quarantine, not a leak.

import json;
import os;

glob:pub HERE: str = os.path.dirname(os.path.abspath(__file__));
glob:pub PKG: str = os.path.dirname(HERE);
glob:pub REPO_ROOT: str = os.path.dirname(PKG);
glob:pub LABELS_PATH: str = os.path.join(
    REPO_ROOT, "contracts", "fixtures", "audit_golden.labels.jsonl"
);


"""event_id -> {"population", "stage"}. Test-side only."""
def load_labels() -> dict {
    out = {};
    with open(LABELS_PATH, "r") as fh {
        for line in fh {
            stripped = line.strip();
            if stripped == "" {
                continue;
            }
            rec = json.loads(stripped);
            out[str(rec["event_id"])] = rec;
        }
    }
    return out;
}


"""The population an evidence set predominantly belongs to."""
def majority_population(evidence: list, labels: dict) -> str {
    counts = {};
    for e in evidence {
        rec = labels.get(str(e), None);
        if rec is None {
            continue;
        }
        pop = str(rec["population"]);
        counts[pop] = int(counts.get(pop, 0)) + 1;
    }
    best = "";
    best_n = -1;
    for k in sorted(list(counts.keys())) {
        if int(counts[k]) > best_n {
            best = k;
            best_n = int(counts[k]);
        }
    }
    return best;
}


"""Populations present in a subject cluster's rows."""
def population_of_rows(rows: list, labels: dict) -> str {
    ids = [];
    for r in rows {
        ids.append(str(r["event_id"]));
    }
    return majority_population(ids, labels);
}
