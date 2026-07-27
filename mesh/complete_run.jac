# mesh/complete_run.jac
#
# The decision -> containment -> verify -> rollback tail of a live run, driven by
# the REAL coordinator FSM and the REAL containment executor against artifacts
# that already exist on disk.
#
#   cd <scratch> && PYTHONPATH=<repo> jac run <repo>/mesh/complete_run.jac
#   (mesh/complete_run.sh does exactly that, with the isolation env set)
#
# WHAT IS REAL
#   - the five assessments: read off disk, produced by five real models in a run
#     that already happened and already cost real money. NOT regenerated. They
#     reach the FSM through mesh/bridge/mesh_responder.jac (kind "cotal"), which
#     re-validates each one against the frozen assessment.v1 schema before it is
#     allowed to count as a vote.
#   - the effort gate: run against runs/six-live/effort.jsonl, the real receipts.
#   - the quorum: coordinator/quorum.jac, untouched.
#   - containment: containment/executor.jac via mesh/live_containment.jac.
#
# WHAT IS NOT A MODEL CALL
#   Nothing here calls a model. `spawn` is False on every responder handle, so
#   the bridge only ever READS the assessment files. This is the recorded-DM
#   replay of a live deliberation, not a new one.
#
# ON THE INCIDENT ID  (read this before changing it)
#   The five assessments all answer incident_id "inc-2026-07-26-live01" — the
#   incident in mesh/fixtures/incident-live.json that the harnesses were actually
#   given. runs/six-live/incidents.jsonl holds three DIFFERENT incidents, emitted
#   by the monitor from the attack traffic (inc_ebdc9299dcbf72b9 and two others),
#   against tenant t_acme.
#
#   Escalating a monitor incident to these handles is not a shortcut that happens
#   to work — mesh_responder.poll() rejects every assessment with
#   R_INCIDENT_MISMATCH, because attaching one incident's verdicts to another
#   incident's decision is exactly the bug that guard exists to prevent. Pass
#   --incident-id to see it happen; it is reported, not worked around.

import os;
import sys;
import json;
import from typing { Any }

glob:pub HERE: str = os.path.dirname(os.path.abspath(__file__));
glob:pub REPO_ROOT: str = os.path.dirname(HERE);
glob:pub COORD_DIR: str = os.path.join(REPO_ROOT, "coordinator");

with entry {
    # Jac resolves `import from <name>` against sys.path, which starts at the
    # INVOCATION directory. The coordinator uses flat sibling imports, the
    # containment tree uses repo-root-absolute package paths, and this file
    # needs both. Same bootstrap mesh/bridge/mesh_responder.jac uses.
    for p in [REPO_ROOT, COORD_DIR, HERE] {
        if p not in sys.path {
            sys.path.insert(0, p);
        }
    }
}

# Importing the bridge IS the wiring step: it registers responder kind "cotal".
import from bridge.mesh_responder { COTAL_KIND, MeshResponder }
import from live_containment { LiveContainment, seed_incident_world }
import from clock { frozen_clock }
import from config { MeshConfig, ResponderConfig }
import from ids { RESPONDER_IDS }
import from fsm { Incident, build_fsm, run_incident }
import from schema_check { validate_payload, is_valid }
import from containment.executor { control_surface, controls_path }

glob RUN_ID: str = "six-live";
glob RUN_DIR: str = os.path.join(REPO_ROOT, "runs", RUN_ID);
glob ASSESS_DIR: str = os.path.join(RUN_DIR, "assessments");
glob RECEIPTS: str = os.path.join(RUN_DIR, "effort.jsonl");
glob INCIDENT_FIXTURE: str = os.path.join(REPO_ROOT, "mesh", "fixtures", "incident-live.json");
glob INCIDENTS_JSONL: str = os.path.join(RUN_DIR, "incidents.jsonl");


def hr(title: str) {
    print("");
    print("=" * 74);
    print("  " + title);
    print("=" * 74);
}


"""Load the incident the harnesses were actually given."""
def load_fixture_incident() -> dict {
    with open(INCIDENT_FIXTURE, "r") as fh {
        return json.load(fh);
    }
}


"""Load one incident.v1 object out of the monitor's stream by id."""
def load_monitor_incident(incident_id: str) -> dict {
    with open(INCIDENTS_JSONL, "r") as fh {
        for line in fh {
            s = line.strip();
            if s == "" {
                continue;
            }
            rec = json.loads(s);
            if rec.get("incident_id", "") == incident_id {
                return rec;
            }
        }
    }
    raise ValueError("no incident " + incident_id + " in " + INCIDENTS_JSONL);
}


"""Five cotal responders, each reading its own already-written assessment file.

spawn=False: nothing is launched, no model is called, no token is spent. The
handles are pure readers of the recorded unicast DMs."""
def live_mesh_config() -> MeshConfig {
    entries: list = [];
    for rid in RESPONDER_IDS {
        entries.append(ResponderConfig(
            responder_id=rid,
            kind=COTAL_KIND,
            opts={
                "run_id": RUN_ID,
                "assessments_dir": ASSESS_DIR,
                "spawn": False,
                "poll_timeout_ms": 0
            }
        ));
    }
    # run_label is advisory here; the effort gate recomputes it from the real
    # receipts and that answer is the one that lands in the artifacts.
    return MeshConfig(responders=entries, run_label="LIVE");
}


def write_json(path: str, payload: Any) {
    os.makedirs(os.path.dirname(path), exist_ok=True);
    with open(path, "w") as fh {
        json.dump(payload, fh, indent=2, sort_keys=True);
        fh.write("\n");
    }
}


with entry:__main__ {
    argv: list = sys.argv[1:];
    incident_id: str = "";
    n: int = 0;
    while n < len(argv) {
        if argv[n] == "--incident-id" and (n + 1) < len(argv) {
            incident_id = argv[n + 1];
            n = n + 1;
        }
        n = n + 1;
    }

    # ------------------------------------------------------------------
    # The incident
    # ------------------------------------------------------------------
    fixture = load_fixture_incident();
    fixture_id: str = str(fixture.get("incident_id", ""));
    if incident_id == "" or incident_id == fixture_id {
        incident_id = fixture_id;
        payload = fixture;
        source: str = "mesh/fixtures/incident-live.json (the incident the five harnesses answered)";
    } else {
        payload = load_monitor_incident(incident_id);
        source = "runs/" + RUN_ID + "/incidents.jsonl (monitor-derived)";
    }
    join_keys: dict = payload.get("join_keys", {});

    hr("INPUTS");
    print("  incident_id      : " + incident_id);
    print("  incident source  : " + source);
    print("  assessments dir  : " + ASSESS_DIR);
    print("  effort receipts  : " + RECEIPTS);
    print("  controls path    : " + controls_path());
    print("  assessment files : " + str(sorted([
        f for f in os.listdir(ASSESS_DIR) if f.endswith(".json")
    ])));

    # ------------------------------------------------------------------
    # The world the containment executor will act on
    # ------------------------------------------------------------------
    world = seed_incident_world(join_keys);
    hr("WORLD (seeded from the incident's own join_keys)");
    print(json.dumps(world, indent=2, sort_keys=True));

    # ------------------------------------------------------------------
    # The real FSM
    # ------------------------------------------------------------------
    clock = frozen_clock();
    cfg = live_mesh_config();
    executor = LiveContainment(incident_id=incident_id);
    fallback: dict = {
        "principal_hash": str(join_keys.get("principal_hash", "")),
        "tenant": str(join_keys.get("tenant", ""))
    };
    fsm = build_fsm(RECEIPTS, cfg, executor, clock, fallback);

    print("");
    print("  cfg.is_mocked()  : " + str(cfg.is_mocked()));
    print("  responder kinds  : " + str(sorted(set([r.kind for r in cfg.responders]))));

    incident = Incident(incident_id=incident_id, payload=payload);
    summary = run_incident(fsm, incident);

    # ------------------------------------------------------------------
    # Gate + decision
    # ------------------------------------------------------------------
    hr("EFFORT GATE (real receipts)");
    print("  gate_ok    : " + str(fsm.gate_ok));
    print("  gate_reason: '" + str(fsm.gate_reason) + "'");
    print("  run_label  : " + str(fsm.run_label));
    print("  log.is_mocked(): " + str(fsm.log.is_mocked()));

    hr("RESPONDER INTAKE");
    for rid in RESPONDER_IDS {
        h = fsm.mesh[rid];
        print("  " + json.dumps(h.describe(), sort_keys=True));
        for r in h.rejected {
            print("      REJECTED: " + str(r["reason"]) + " -- " + str(r["detail"])[:160]);
        }
    }

    hr("DECISION (coordinator/quorum.jac)");
    print("  state_trace : " + " -> ".join(fsm.log.state_trace()));
    print("  final_state : " + str(fsm.state));
    if len(fsm.decision) == 0 {
        print("  NO DECISION — the gate refused, nothing was escalated.");
    } else {
        print("  verdict_counts   : " + json.dumps(fsm.decision.get("verdict_counts", {}), sort_keys=True));
        print("  score            : " + str(fsm.decision.get("score", 0)));
        print("  responders_voted : " + str(fsm.decision.get("responders_voted", 0)));
        print("  responders_no_vote: " + str(fsm.decision.get("responders_no_vote", [])));
        print("  quorum_met       : " + str(fsm.decision.get("quorum_met", False)));
        print("  contain          : " + str(fsm.decision.get("contain", False)));
        print("  degraded         : " + str(fsm.decision.get("degraded", False)));
        print("  rule             : " + str(fsm.decision.get("rule", "")));
        print("");
        print("  action_set (" + str(len(fsm.decision.get("action_set", []))) + "):");
        for a in fsm.decision.get("action_set", []) {
            print("    - " + str(a["action"])
                  + "  ttl_s=" + str(a["ttl_s"])
                  + "  blast=" + str(a["blast_radius"])
                  + "  proposed_by=" + str(sorted(a["proposed_by"])));
            print("        target=" + json.dumps(a["target"], sort_keys=True));
        }
    }

    decision_ok: bool = False;
    decision_err: str = "";
    if len(fsm.decision) > 0 {
        try {
            validate_payload("decision.v1", fsm.decision);
            decision_ok = True;
        } except Exception as e {
            decision_err = str(e);
        }
        write_json(os.path.join(RUN_DIR, "decision.json"), fsm.decision);
    }
    print("");
    print("  decision.v1 schema-valid: " + str(decision_ok)
          + ("" if decision_err == "" else "  -- " + decision_err[:400]));

    # ------------------------------------------------------------------
    # Containment: apply -> probe -> hold -> roll back
    # ------------------------------------------------------------------
    hr("CONTAINMENT (containment/executor.jac, real gate + real probes)");
    print("  applied  : " + str(len(fsm.applied_actions)));
    print("  aborted  : " + str(len(fsm.aborted_actions)));
    for a in fsm.aborted_actions {
        print("      ABORTED: " + str(a["action"]) + " " + json.dumps(a["target"], sort_keys=True));
    }
    print("  live control kinds while CONTAINED: " + str(executor.live_control_kinds()));
    surface_contained: list = control_surface();
    print("  control surface rows while CONTAINED: " + str(len(surface_contained)));
    print("  state after run_incident: " + str(fsm.state));

    # THE ROLLBACK. CONTAINED is a holding state; tick_expire advances the clock
    # to the minimum applied ttl and reverses every applied action through the
    # real executor.
    fsm.tick_expire(incident);
    surface_after: list = control_surface();
    print("");
    print("  after tick_expire -> state: " + str(fsm.state));
    print("  live control kinds after rollback: " + str(executor.live_control_kinds()));
    print("  control surface rows after rollback: " + str(len(surface_after)));

    print("");
    print("  executor trace:");
    for t in executor.trace {
        print("    " + json.dumps(t, sort_keys=True));
    }

    hr("STATE TRACE");
    print("  " + " -> ".join(fsm.log.state_trace()));

    # ------------------------------------------------------------------
    # Artifacts
    # ------------------------------------------------------------------
    contained_kinds: list = sorted([str(a["action"]) for a in fsm.applied_actions]);
    containment: dict = {
        "schema": "containment_result.v0 (driver artifact -- no frozen schema exists)",
        "incident_id": incident_id,
        "run_id": RUN_ID,
        "executor": "containment/executor.jac (real; no mock in this path)",
        "adapter": "mesh/live_containment.jac",
        "world": world,
        "action_set": fsm.decision.get("action_set", []),
        "applied": fsm.applied_actions,
        "applied_kinds": contained_kinds,
        "aborted": fsm.aborted_actions,
        "aborted_kinds": sorted([str(a["action"]) for a in fsm.aborted_actions]),
        "outcome": ("applied" if len(fsm.applied_actions) > 0 and len(fsm.aborted_actions) == 0
                    else ("partial" if len(fsm.applied_actions) > 0 else "none_applied")),
        "health": ("pass" if fsm.state in ["CONTAINED", "ROLLED_BACK"] and len(fsm.applied_actions) > 0
                   else "n/a"),
        "min_ttl_s": fsm.min_ttl_s,
        "control_surface_while_contained": surface_contained,
        "control_surface_after_rollback": surface_after,
        "rolled_back": [str(a["action"]) for a in executor.rolled_back],
        "rollback_complete": len(surface_after) == 0,
        "final_state": fsm.state,
        "state_trace": fsm.log.state_trace(),
        "trace": executor.trace,
        "controls_path": controls_path()
    };
    write_json(os.path.join(RUN_DIR, "containment.json"), containment);

    write_json(os.path.join(RUN_DIR, "coordinator_events.json"), {
        "incident_id": incident_id,
        "run_label": fsm.run_label,
        "summary": summary,
        "events": [e.as_dict() for e in fsm.log.events]
    });

    hr("SUMMARY");
    print(json.dumps(summary, indent=2, sort_keys=True));
    print("");
    print(">>> run_label=" + str(fsm.run_label)
          + "  gate_ok=" + str(fsm.gate_ok)
          + "  contain=" + str(fsm.decision.get("contain", False))
          + "  applied=" + str(len(fsm.applied_actions))
          + "  final_state=" + str(fsm.state)
          + "  controls_left=" + str(len(surface_after)));
}
