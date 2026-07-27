# mesh/bridge/run_decision.jac
#
# THE LIVE COORDINATOR RUN: decision -> containment -> verify -> rollback.
#
# coordinator/run.jac is the MOCKED demo. It hard-codes tests/receipts/
# six_with_mocked.jsonl, a MockContainment, a frozen clock and INC-DEMO-0001,
# prints its decision and writes nothing to disk. That is exactly what it should
# be, and it is not what an acceptance run needs. This is the mesh-owned
# equivalent, and the ONLY things it changes are the four injected collaborators
# `build_fsm` already takes as arguments:
#
#     receipts_path  runs/<run_id>/effort.jsonl   the run's REAL six receipts
#     cfg            all_live_config(run_id)      five real models, run_label LIVE
#     executor       MeshContainment              the REAL containment surface
#     clock          frozen at the incident's own detected_at_ms
#
# Not one line of coordinator/ is modified, imported differently, or bypassed.
# The FSM, the effort gate, the quorum arithmetic, the presence layer and the
# audit trail are the same code the 64-test coordinator suite covers.
#
# THE GATE IS NOT BYPASSED — IT IS THE POINT. `run_incident` calls
# `enforce_gate(receipts_path, ...)` first, and returns a WATCHING summary with
# an EMPTY decision if it fails. Six receipts, all six agents, none downgraded,
# none blocked, none mocked, is the only condition that opens it. Feeding it the
# run's real effort.jsonl is what makes the decision below an acceptance result
# rather than a demo. This driver checks `fsm.gate_ok` explicitly and exits
# non-zero if the gate held, because a silent empty decision is the one failure
# mode that could be mistaken for success.
#
# ROLLBACK IS REAL AND IS VERIFIED. Containment writes Control nodes onto the
# object graph and projects them into the file the gateway polls. `tick_expire`
# drives the coordinator's own CONTAINED -> ROLLED_BACK transition at the
# minimum applied TTL, which reverses every action through
# containment/executor.rollback. The oracle is `control_surface()` captured
# before, during and after: the before and after must be byte-identical, and
# this driver asserts that rather than asserting it happened.
#
# Run it through mesh/bridge/run_decision.sh, which gives it an isolated Jac
# anchor store, a scratch audit log and a throwaway ctx signing key. Running it
# directly against the repo's CWD would mutate the shared object graph.
#
#   MESH_RUN_ID=six-live bash mesh/bridge/run_decision.sh

import os;
import sys;
import json;

glob:pub HERE: str = os.path.dirname(os.path.abspath(__file__));
glob:pub REPO_ROOT: str = os.path.dirname(os.path.dirname(HERE));
glob:pub COORD_DIR: str = os.path.join(REPO_ROOT, "coordinator");

with entry {
    # Three roots, three reasons:
    #   REPO_ROOT  containment/ and app/ import each other by dotted path
    #   COORD_DIR  coordinator modules import each other by bare name
    #   HERE       the mesh bridge modules, when jac was invoked from elsewhere
    for p in [REPO_ROOT, COORD_DIR, HERE] {
        if p not in sys.path {
            sys.path.insert(0, p);
        }
    }
}

import from clock { frozen_clock }
import from fsm { Incident, build_fsm, run_incident }
import from schema_check { validate_payload }
import from ids { RESPONDER_IDS }

import from mesh_config { all_live_config, block_report }
import from mesh_containment { MeshContainment }
import from mesh_world { seed_incident_world }
import mesh_responder;   # THE SEAM: importing this registers responder kind "cotal"


"""Run id to drive. Override with MESH_RUN_ID."""
def run_id -> str {
    return os.environ.get("MESH_RUN_ID", "six-live");
}

"""The incident.v1 the responders actually assessed."""
def incident_doc -> dict {
    path: str = os.environ.get(
        "MESH_INCIDENT_PATH",
        os.path.join(REPO_ROOT, "mesh", "fixtures", "incident-live.json")
    );
    handle = open(path, "r", encoding="utf-8");
    doc: dict = json.loads(handle.read());
    handle.close();
    return doc;
}

"""Write `payload` as pretty, key-sorted JSON. Returns the path."""
def write_json(path: str, payload: object) -> str {
    parent: str = os.path.dirname(path);
    if parent != "" {
        os.makedirs(parent, exist_ok=True);
    }
    handle = open(path, "w", encoding="utf-8");
    handle.write(json.dumps(payload, indent=2, sort_keys=True) + "\n");
    handle.close();
    return path;
}

"""The default entry for the DEGRADED monitor-only posture.

Taken from the incident's own join keys rather than a fixture, so a degraded
run raises logging on the identity this incident is actually about. Unused when
quorum is met, but `build_fsm` requires it and a wrong value would only surface
on the one path where nothing else can."""
def fallback_target_of(incident: dict) -> dict {
    join_keys: dict = incident.get("join_keys", {});
    out: dict = {};
    if "principal_hash" in join_keys {
        out["principal_hash"] = str(join_keys["principal_hash"]);
    }
    if "tenant" in join_keys {
        out["tenant"] = str(join_keys["tenant"]);
    }
    return out;
}

def hr(title: str) {
    print("");
    print("=" * 74);
    print("  " + title);
    print("=" * 74);
}


with entry:__main__ {
    rid: str = run_id();
    incident: dict = incident_doc();
    incident_id: str = str(incident["incident_id"]);

    run_dir: str = os.path.join(REPO_ROOT, "runs", rid);
    receipts: str = os.path.join(run_dir, "effort.jsonl");

    hr("LIVE COORDINATOR RUN  run_id=" + rid + "  incident=" + incident_id);
    print("  receipts   : " + receipts);
    print("  run dir    : " + run_dir);
    print("  workspace  : " + os.getcwd() + "   (isolated Jac anchor store)");

    if not os.path.isfile(receipts) {
        raise ValueError(
            "no effort receipts at " + receipts
            + " — the gate cannot open and there is nothing to decide"
        );
    }

    # ---------------------------------------------------------------------
    # 0. SEED. The incident's world has to exist for containment to address it.
    # ---------------------------------------------------------------------
    hr("0. WORLD");
    seeded: dict = seed_incident_world(incident);
    print("  " + json.dumps(seeded, sort_keys=True));

    # ---------------------------------------------------------------------
    # 1. WIRE. Four injected collaborators, nothing else.
    # ---------------------------------------------------------------------
    hr("1. MESH");
    cfg = all_live_config(rid, {"spawn": False});
    blocks: dict = block_report(cfg);
    print("  run_label  : " + str(blocks["run_label"]));
    print("  live       : " + str(blocks["live_count"]) + "/" + str(len(RESPONDER_IDS)));
    for row in blocks["responders"] {
        print("    " + str(row["responder_id"]).ljust(24) + " kind=" + str(row["kind"]));
    }

    # The coordinator's virtual timeline starts when the monitor detected the
    # incident, so the audit trail's timestamps are the incident's own.
    clock = frozen_clock(int(incident.get("detected_at_ms", 0)));
    executor = MeshContainment(incident_id=incident_id);
    fsm = build_fsm(receipts, cfg, executor, clock, fallback_target_of(incident));

    surface_before: list = executor.surface();
    print("  controls before: " + str(len(surface_before)));

    # ---------------------------------------------------------------------
    # 2. DRIVE. Gate -> escalate -> assess -> decide -> contain -> verify.
    # ---------------------------------------------------------------------
    inc = Incident(incident_id=incident_id, payload=incident);
    summary: dict = run_incident(fsm, inc);

    hr("2. EFFORT GATE");
    print("  open       : " + str(fsm.gate_ok));
    print("  reason     : " + (fsm.gate_reason if fsm.gate_reason != "" else "(none - gate open)"));
    print("  run_label  : " + str(fsm.run_label));
    if not fsm.gate_ok {
        # A held gate leaves an EMPTY decision and a WATCHING state. Failing
        # loudly here is the difference between "the run was refused" and "the
        # run silently produced nothing".
        print("");
        print("  GATE HELD — no decision was made. Nothing was written.");
        sys.exit(2);
    }

    hr("3. DECISION");
    validate_payload("decision.v1", fsm.decision);
    d: dict = fsm.decision;
    print("  contain      : " + str(d["contain"]));
    print("  quorum_met   : " + str(d["quorum_met"]));
    print("  degraded     : " + str(d["degraded"]));
    print("  score        : " + str(d["score"]));
    print("  verdicts     : " + json.dumps(d["verdict_counts"], sort_keys=True));
    print("  voted        : " + str(d["responders_voted"]) + "/" + str(len(RESPONDER_IDS))
          + "   no_vote=" + str(d["responders_no_vote"]));
    print("  rule         : " + str(d["rule"]));
    print("  action_set   : " + str(len(d["action_set"])) + " action(s)");
    for a in d["action_set"] {
        print("    " + str(a["action"]).ljust(28)
              + " ttl=" + str(a["ttl_s"]).rjust(7)
              + "s blast=" + str(a["blast_radius"]).ljust(9)
              + " by=" + str(len(a["proposed_by"])) + " responders");
    }

    decision_path: str = write_json(os.path.join(run_dir, "decision.json"), d);
    print("");
    print("  -> " + decision_path);

    # ---------------------------------------------------------------------
    # 3. CONTAINMENT + VERIFICATION (already driven by the FSM above).
    # ---------------------------------------------------------------------
    hr("4. CONTAINMENT (real surface)");
    print("  state        : " + str(fsm.state));
    applied_actions: list = [dict(a) for a in fsm.applied_actions];
    aborted_actions: list = [dict(a) for a in fsm.aborted_actions];
    print("  applied      : " + str(len(applied_actions)) + "  " + str(executor.applied_kinds()));
    print("  aborted      : " + str(len(aborted_actions)));
    for ab in aborted_actions {
        print("    " + str(ab["action"]) + " -> refused by the containment gate");
    }
    for rep in executor.reports {
        if str(rep["phase"]) == "apply" {
            r: dict = rep["report"];
            print("    apply  " + str(r.get("kind", "")).ljust(28)
                  + " state=" + str(r.get("state", "")).ljust(14)
                  + " approval=" + str(r.get("approval", "")));
            print("           " + str(r.get("detail", "")));
        }
    }

    surface_contained: list = executor.surface();
    print("");
    print("  controls held: " + str(len(surface_contained)));
    for c in surface_contained {
        print("    " + str(c["kind"]).ljust(28) + " " + str(c["scope_key"]));
    }

    hr("5. VERIFY (post-apply health probes)");
    verify_rows: list = [];
    for rep2 in executor.reports {
        if str(rep2["phase"]) == "verify" {
            h: dict = rep2["report"];
            verify_rows.append({
                "action_id": str(rep2["action_id"]),
                "status": str(h.get("status", "")),
                "primary": str(h.get("primary", "")),
                "failed": h.get("failed", []),
                "report": h.get("report", [])
            });
            print("    " + str(h.get("status", "")).ljust(6) + " "
                  + str(rep2["action_id"]));
            for line in h.get("report", []) {
                print("           " + str(line));
            }
        }
    }

    # ---------------------------------------------------------------------
    # 4. ROLLBACK. The coordinator's own CONTAINED -> ROLLED_BACK transition.
    # ---------------------------------------------------------------------
    hr("6. ROLLBACK (TTL expiry -> real reversal)");
    state_before_expiry: str = str(fsm.state);
    print("  state        : " + state_before_expiry);
    print("  min_ttl_s    : " + str(fsm.min_ttl_s));
    fsm.tick_expire(inc);
    print("  state        : " + str(fsm.state) + "   (after tick_expire)");

    surface_after: list = executor.surface();
    clean: bool = json.dumps(surface_before, sort_keys=True) == json.dumps(surface_after, sort_keys=True);
    print("  controls     : " + str(len(surface_before)) + " -> "
          + str(len(surface_contained)) + " -> " + str(len(surface_after)));
    print("  surface restored byte-identical : " + str(clean));

    # The projection the gateway polls has to agree with the graph.
    proj_path: str = os.environ.get("CONTROLS_PATH", "var/controls/controls.json");
    proj_rows: list = [];
    if os.path.isfile(proj_path) {
        ph = open(proj_path, "r", encoding="utf-8");
        proj: dict = json.loads(ph.read());
        ph.close();
        proj_rows = proj.get("controls", []);
    }
    print("  gateway projection: " + str(len(proj_rows)) + " control(s) at " + proj_path);

    # ---------------------------------------------------------------------
    # 5. ARTIFACTS.
    # ---------------------------------------------------------------------
    outcome: str = "applied_then_rolled_back";
    if len(applied_actions) == 0 {
        outcome = "nothing_applied";
    } elif not clean {
        outcome = "rollback_incomplete";
    }

    containment: dict = {
        "schema": "mesh.containment_result.v0",
        "incident_id": incident_id,
        "run_id": rid,
        "outcome": outcome,
        "executor": "containment/executor.jac (real Control surface)",
        "coordinator_state": str(fsm.state),
        "state_at_containment": state_before_expiry,
        "action_set": applied_actions,
        "aborted": aborted_actions,
        "controls_held": surface_contained,
        "verify": verify_rows,
        "rollback": {
            "trigger": "coordinator tick_expire at the minimum applied TTL",
            "min_ttl_s": fsm.min_ttl_s,
            "rolled_back": [dict(a) for a in executor.rolled_back],
            "surface_before": surface_before,
            "surface_contained": surface_contained,
            "surface_after": surface_after,
            "surface_restored_byte_identical": clean,
            "gateway_projection_controls_after": len(proj_rows),
            "gateway_projection_path": proj_path
        },
        "reports": executor.reports
    };
    containment_path: str = write_json(os.path.join(run_dir, "containment.json"), containment);
    print("");
    print("  -> " + containment_path);

    events_path: str = os.path.join(run_dir, "coordinator_events.jsonl");
    eh = open(events_path, "w", encoding="utf-8");
    eh.write(fsm.log.to_jsonl() + "\n");
    eh.close();
    print("  -> " + events_path);

    summary_path: str = write_json(os.path.join(run_dir, "coordinator_summary.json"), summary);
    print("  -> " + summary_path);

    hr("RESULT");
    print("  run_label        : " + str(fsm.run_label));
    print("  final_state      : " + str(fsm.state));
    print("  contained        : " + str(d["contain"]));
    print("  actions applied  : " + str(len(applied_actions)));
    print("  rolled back      : " + str(len(executor.rolled_back)));
    print("  fixtures clean   : " + str(clean));
    print("  state trace      : " + " -> ".join(fsm.log.state_trace()));

    if not clean {
        print("");
        print("  ROLLBACK DID NOT RESTORE THE CONTROL SURFACE.");
        sys.exit(3);
    }
}
