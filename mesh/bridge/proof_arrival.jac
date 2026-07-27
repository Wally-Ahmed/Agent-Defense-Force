# mesh/bridge/proof_arrival.jac
#
# THE ARRIVAL PROOF. Takes a completed run's real assessments and drives them
# through the COORDINATOR'S OWN factory path — `build_responder("cotal", ...)` —
# to demonstrate that live model output reaches the coordinator as
# ResponderHandle.poll() results, indistinguishable from a mock.
#
# Why this exists as a checked-in file rather than a one-off: "the assessment
# arrived at the coordinator" is the single claim the whole mesh rests on, and
# it should be re-runnable by anyone against any run directory rather than
# living in a shell transcript someone has to take on faith.
#
# It deliberately uses `build_responder` (coordinator/responder.jac) instead of
# constructing a MeshResponder directly: that is the exact call `config.jac`
# makes, so if this passes, the config-only mock->live swap genuinely works.
#
# spawn is FALSE here — this reads assessments that already exist on disk. It
# never launches a harness and never spends a token.
#
# Usage:  jac run mesh/bridge/proof_arrival.jac         (run id below)

import os;
import sys;
import json;

glob:pub HERE: str = os.path.dirname(os.path.abspath(__file__));
glob:pub REPO_ROOT: str = os.path.dirname(os.path.dirname(HERE));

with entry {
    if REPO_ROOT not in sys.path { sys.path.insert(0, REPO_ROOT); }
    if os.path.join(REPO_ROOT, "coordinator") not in sys.path {
        sys.path.insert(0, os.path.join(REPO_ROOT, "coordinator"));
    }
}

import from responder { build_responder, is_known_kind, known_responder_kinds }
import mesh_responder;   # THE SEAM: importing this registers kind "cotal"


"""Run id to inspect. Override with MESH_PROOF_RUN_ID."""
def proof_run_id -> str {
    return os.environ.get("MESH_PROOF_RUN_ID", "live-mesh-proof");
}

"""The incident these assessments answer."""
def proof_incident -> dict {
    path = os.path.join(REPO_ROOT, "mesh", "fixtures", "incident-live.json");
    handle = open(path, "r");
    doc = json.loads(handle.read());
    handle.close();
    return doc;
}

with entry:__main__ {
    run_id = proof_run_id();
    incident = proof_incident();
    now_ms = 1769472600000;

    print("=" * 72);
    print(f"ARRIVAL PROOF  run_id={run_id}  incident={incident['incident_id']}");
    print(f"registered responder kinds: {known_responder_kinds()}");
    print(f"is_known_kind('cotal') = {is_known_kind('cotal')}");
    print("=" * 72);

    adir = os.path.join(REPO_ROOT, "runs", run_id, "assessments");
    present: list = [];
    if os.path.isdir(adir) {
        for fn in sorted(os.listdir(adir)) {
            if fn.endswith(".json") { present.append(fn[:-5]); }
        }
    }
    print(f"assessments on disk: {present}");
    print("");

    total = 0;
    for rid in present {
        # The coordinator's OWN factory call. `kind` is the only thing that
        # differs from a mock run.
        handle = build_responder(
            "cotal",
            rid,
            {"run_id": run_id, "spawn": False}
        );
        handle.escalate(incident, now_ms);

        got = handle.poll(now_ms + 1000);
        again = handle.poll(now_ms + 2000);   # at-most-once: must be empty

        print(f"--- {rid} (kind={handle.kind}) ---");
        print(f"    presence : {handle.presence(now_ms + 1000)}");
        for a in got {
            total += 1;
            print(f"    ARRIVED  : verdict={a['verdict']} confidence={a['confidence']} "
                  f"model={a['model']} effort={a['effort_effective']}");
            print(f"               stages={a['campaign_stages']} "
                  f"actions={len(a['recommended_actions'])} "
                  f"usd={a['usage']['usd']}");
        }
        print(f"    second poll returned {len(again)} (at-most-once: expect 0)");
        print("");
    }

    print("=" * 72);
    print(f"TOTAL ASSESSMENTS ARRIVED AT COORDINATOR: {total}");
    print("=" * 72);
}
