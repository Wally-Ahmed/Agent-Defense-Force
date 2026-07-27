# mesh/complete_run.jac
#
# The decision -> containment -> verify -> rollback tail of a live run, driven by
# the REAL coordinator FSM and the REAL containment executor against artifacts
# that already exist on disk.
#
#   cd <scratch> && PYTHONPATH=<repo> jac run <repo>/mesh/complete_run.jac \
#       [--run-id <id>] [--incident-id <id>]
#   (mesh/complete_run.sh does exactly that, with the isolation env set)
#
#   --run-id selects which runs/<id>/ tree is read and written; it defaults to
#   "six-live", so a bare invocation is unchanged.
#
# WHAT IS REAL
#   - the five assessments: read off disk, produced by five real models in a run
#     that already happened and already cost real money. NOT regenerated. They
#     reach the FSM through mesh/bridge/mesh_responder.jac (kind "cotal"), which
#     re-validates each one against the frozen assessment.v1 schema before it is
#     allowed to count as a vote.
#   - the effort gate: run against runs/<run-id>/effort.jsonl, the real receipts.
#   - the quorum: coordinator/quorum.jac, untouched.
#   - containment: containment/executor.jac via mesh/live_containment.jac.
#
# WHAT IS NOT A MODEL CALL
#   Nothing here calls a model. `spawn` is False on every responder handle, so
#   the bridge only ever READS the assessment files. This is the recorded-DM
#   replay of a live deliberation, not a new one.
#
# ON THE INCIDENT ID  (read this before changing it)
#   A set of assessments answers exactly ONE incident, and WHICH one is read back
#   off the assessment files themselves — assessments_incident_id() — never
#   assumed. The two shapes both occur:
#     - runs/six-live: the five assessments answer "inc-2026-07-26-live01", the
#       incident in mesh/fixtures/incident-live.json the harnesses were given.
#       runs/six-live/incidents.jsonl holds three DIFFERENT monitor incidents
#       (inc_ebdc9299dcbf72b9 and two others) against tenant t_acme.
#     - runs/six-live-e2e: the five responders were called live against a REAL
#       monitor-detected incident read out of runs/<run>/incidents.jsonl, so the
#       assessments answer THAT id and the fixture is never opened at all.
#
#   The guard therefore keys off what the assessments actually answer, not off
#   the fixture: when the escalated incident_id differs from the answered one,
#   this driver writes ONLY incident_mismatch_probe.json and leaves decision.json
#   and containment.json untouched.
#
#   Escalating some other incident to these handles is not a shortcut that
#   happens to work — mesh_responder.poll() rejects every assessment with
#   R_INCIDENT_MISMATCH, because attaching one incident's verdicts to another
#   incident's decision is exactly the bug that guard exists to prevent. Pass a
#   mismatched --incident-id to see it happen; it is reported, not worked around.

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
import from containment.policy { tenant_actives }
import from containment.probes { principal_can_list_projects }
import from app.security.clock { now_ms }

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


"""The incident_id the assessments on disk ACTUALLY answer.

Reads it out of the files rather than assuming it, because the answered incident
is a property of the run: a fixture-driven run answers the fixture, and a
monitor-driven run answers whatever the monitor emitted. Returns "" when the
directory holds no assessments, or when the files disagree — a split set is
itself a defect and must not be averaged into a single confident answer."""
def assessments_incident_id() -> str {
    if not os.path.isdir(ASSESS_DIR) {
        return "";
    }
    ids: list = [];
    for f in sorted(os.listdir(ASSESS_DIR)) {
        if not f.endswith(".json") {
            continue;
        }
        with open(os.path.join(ASSESS_DIR, f), "r") as fh {
            rec = json.load(fh);
        }
        got: str = str(rec.get("incident_id", ""));
        if got not in ids {
            ids.append(got);
        }
    }
    if len(ids) == 1 {
        return ids[0];
    }
    if len(ids) > 1 {
        print("  WARNING: the assessment files DISAGREE on incident_id: "
              + str(sorted(ids))
              + " -- refusing to name a single answered incident.");
    }
    return "";
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
    run_id: str = RUN_ID;
    n: int = 0;
    while n < len(argv) {
        if argv[n] == "--incident-id" and (n + 1) < len(argv) {
            incident_id = argv[n + 1];
            n = n + 1;
        } elif argv[n] == "--run-id" and (n + 1) < len(argv) {
            run_id = argv[n + 1];
            n = n + 1;
        }
        n = n + 1;
    }

    # Every run-scoped path is re-derived from the chosen run id, and RUN_ID
    # itself is rebound HERE — before live_mesh_config() reads it into each
    # ResponderConfig and before it lands in containment.json as "run_id". A run
    # must never be able to name a run it did not come from.
    RUN_ID = run_id;
    RUN_DIR = os.path.join(REPO_ROOT, "runs", RUN_ID);
    ASSESS_DIR = os.path.join(RUN_DIR, "assessments");
    RECEIPTS = os.path.join(RUN_DIR, "effort.jsonl");
    INCIDENTS_JSONL = os.path.join(RUN_DIR, "incidents.jsonl");

    # ------------------------------------------------------------------
    # The incident
    # ------------------------------------------------------------------
    # The fixture is OPTIONAL. With no --incident-id this is the fixture-driven
    # run and the fixture is the incident. With --incident-id the monitor stream
    # is the first authority, and when the id is found there the fixture file is
    # never opened — a monitor-driven run must not have the fixture anywhere in
    # its provenance.
    payload: dict = {};
    source: str = "";
    fixture_source: str = "mesh/fixtures/incident-live.json (the incident the five harnesses answered)";
    if incident_id == "" {
        payload = load_fixture_incident();
        incident_id = str(payload.get("incident_id", ""));
        source = fixture_source;
    } else {
        try {
            payload = load_monitor_incident(incident_id);
            source = "runs/" + RUN_ID + "/incidents.jsonl (monitor-derived)";
        } except (ValueError, OSError) as e {
            # Not in the monitor stream. Fall back to the fixture ONLY when the
            # request names the fixture's own incident; otherwise the original
            # "no such incident" is the honest answer and it propagates.
            fixture = load_fixture_incident();
            if str(fixture.get("incident_id", "")) != incident_id {
                raise;
            }
            payload = fixture;
            source = fixture_source;
        }
    }
    join_keys: dict = payload.get("join_keys", {});

    hr("INPUTS");
    print("  run_id           : " + RUN_ID);
    print("  incident_id      : " + incident_id);
    print("  incident source  : " + source);
    print("  assessments dir  : " + ASSESS_DIR);
    print("  effort receipts  : " + RECEIPTS);
    print("  controls path    : " + controls_path());
    print("  assessment files : " + str(sorted([
        f for f in os.listdir(ASSESS_DIR) if f.endswith(".json")
    ])));
    # What the recorded assessments answer, read from the files themselves. This
    # -- not the fixture -- is what the escalated incident has to match.
    answered_id: str = assessments_incident_id();
    print("  assessments answer incident_id: "
          + (answered_id if answered_id != "" else "(none -- empty or split)"));

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
        if incident_id == answered_id {
            write_json(os.path.join(RUN_DIR, "decision.json"), fsm.decision);
        }
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

    # ------------------------------------------------------------------
    # THE AVAILABILITY PROOF, counted rather than sampled.
    #
    # run_health's `legit_user_can_list_projects` asks ONE witness, which is the
    # right cost for a health check and too weak to put in an artifact. This
    # asks EVERY member of the tenant, one at a time, through the same signed
    # ctx and the same guard(), while the containment is still standing. The
    # claim being evidenced is narrowness: the compromised identity is stopped
    # and nobody else is.
    # ------------------------------------------------------------------
    subject_pid: str = str(world["subject_principal"]);
    tenant_of_run: str = str(world["tenant"]);
    avail_ok: list = [];
    avail_denied: list = [];
    for m_pid in tenant_actives(tenant_of_run) {
        pid_s: str = str(m_pid);
        if pid_s == subject_pid {
            continue;
        }
        v_a: dict = principal_can_list_projects(pid_s, tenant_of_run, now_ms());
        if bool(v_a["ok"]) {
            avail_ok.append(pid_s);
        } else {
            avail_denied.append(pid_s + " (" + str(v_a["reason"]) + ")");
        }
    }
    subject_v: dict = principal_can_list_projects(subject_pid, tenant_of_run, now_ms());
    availability: dict = {
        "tenant": tenant_of_run,
        "tenant_actives": len(avail_ok) + len(avail_denied) + 1,
        "bystanders_tested": len(avail_ok) + len(avail_denied),
        "bystanders_serving": len(avail_ok),
        "bystanders_denied": len(avail_denied),
        "denied_detail": avail_denied,
        "contained_subject": subject_pid,
        "contained_subject_serving": bool(subject_v["ok"]),
        "contained_subject_reason": str(subject_v["reason"]),
        "ok": len(avail_denied) == 0 and not bool(subject_v["ok"])
    };
    print("");
    print("  AVAILABILITY while CONTAINED (every member asked, not sampled):");
    print("    tenant                  : " + tenant_of_run);
    print("    bystanders serving      : " + str(len(avail_ok)) + " / "
          + str(len(avail_ok) + len(avail_denied)));
    print("    bystanders denied       : " + str(len(avail_denied))
          + ("" if len(avail_denied) == 0 else " -> " + json.dumps(avail_denied)));
    print("    contained subject       : " + subject_pid + " -> "
          + ("STILL SERVING (containment failed)" if subject_v["ok"]
             else "DENY " + str(subject_v["reason"])));
    print("    availability proof holds: " + str(availability["ok"]));

    # THE ROLLBACK. CONTAINED is a holding state; tick_expire advances the clock
    # to the minimum applied ttl and reverses every applied action through the
    # real executor.
    fsm.tick_expire(incident);
    surface_after: list = control_surface();
    print("");
    print("  after tick_expire -> state: " + str(fsm.state));
    print("  live control kinds after rollback: " + str(executor.live_control_kinds()));
    print("  control surface rows after rollback: " + str(len(surface_after)));

    # THE ROLLBACK ORACLE. Not "we called rollback" and not "the count fell" —
    # the control surface has to be byte-identical to the world before the first
    # action was applied. Anything else means the application is still contained.
    restored: bool = executor.surface_restored();
    diff: dict = executor.surface_diff();
    print("");
    print("  baseline rows              : " + str(len(executor.baseline)));
    print("  surface restored to baseline: " + str(restored));
    if not restored {
        print("  STILL ENFORCING (leftover) : " + json.dumps(diff["leftover"]));
        print("  MISSING (lost)             : " + json.dumps(diff["lost"]));
    }

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
    # Findings observed in THIS run, recorded in the artifact rather than
    # smoothed out of it. Neither was worked around: no probe was loosened, no
    # threshold moved, no action re-approved.
    findings: list = [];
    for t in executor.trace {
        if t.get("phase", "") == "apply" and t.get("health_status", "") == "fail" {
            findings.append({
                "finding": "health_probe_failed",
                "kind": t.get("kind", ""),
                "action_id": t.get("action_id", ""),
                "failed_probes": t.get("health_failed", []),
                "probe_report": t.get("health_report", []),
                "note": "The action self-aborted and the executor auto-rolled it back. "
                        + "Read `probe_report`: it names the probe and the exact verdict. "
                        + "Order-dependence used to land here -- an earlier action in the "
                        + "same action_set denied the subject first and short-circuited "
                        + "guard() before this kind's own reason could be observed. That "
                        + "is now handled inside containment/probes.jac, which accepts a "
                        + "strictly-earlier-stage denial ONLY when a live containment "
                        + "control accounts for it AND this action's own control is live "
                        + "under guard()'s own key. Anything reaching this list now is a "
                        + "real verification failure, not a masking artefact."
            });
        }
    }

    contained_kinds: list = sorted([str(a["action"]) for a in fsm.applied_actions]);
    containment: dict = {
        "findings": findings,
        "schema": "containment_result.v0 (driver artifact -- no frozen schema exists)",
        "incident_id": incident_id,
        "run_id": RUN_ID,
        "executor": "containment/executor.jac (real; no mock in this path)",
        "adapter": "mesh/live_containment.jac",
        "world": world,
        # Counted while the containment was standing, one member at a time.
        "availability_while_contained": availability,
        # `action_set` on the CONTAINMENT artifact means "what actually took
        # effect", not "what was decided". mesh/report reads this key to render
        # its "Actions applied" table, and listing the decided set there would
        # claim eight enforcing controls when five were enforcing. The full
        # decided set is one section up in the report, from decision.json, and
        # is kept here too under its own name so the artifact stands alone.
        "action_set": fsm.applied_actions,
        "decided_action_set": fsm.decision.get("action_set", []),
        "applied": fsm.applied_actions,
        "applied_kinds": contained_kinds,
        "aborted": fsm.aborted_actions,
        "aborted_kinds": sorted([str(a["action"]) for a in fsm.aborted_actions]),
        "outcome": ("applied" if len(fsm.applied_actions) > 0 and len(fsm.aborted_actions) == 0
                    else ("partial" if len(fsm.applied_actions) > 0 else "none_applied")),
        "health": ("pass" if fsm.state in ["CONTAINED", "ROLLED_BACK"] and len(fsm.applied_actions) > 0
                   else "n/a"),
        "min_ttl_s": fsm.min_ttl_s,
        "control_surface_before": executor.baseline,
        "control_surface_while_contained": surface_contained,
        "control_surface_after_rollback": surface_after,
        "rolled_back": [str(a["action"]) for a in executor.rolled_back],
        # Measured against the pre-containment baseline, not against zero: the
        # claim is "the world is as it was", which is what has to be checked.
        "rollback_complete": restored,
        "rollback_diff": diff,
        "rollback_order": "LIFO — prior_state snapshots nest, so they unwind from the top",
        "final_state": fsm.state,
        "state_trace": fsm.log.state_trace(),
        "trace": executor.trace,
        "controls_path": controls_path()
    };
    if incident_id != answered_id {
        # A negative control must never overwrite the acceptance artifacts.
        write_json(os.path.join(RUN_DIR, "incident_mismatch_probe.json"), {
            "escalated_incident_id": incident_id,
            "assessments_answer_incident_id": answered_id,
            "decision": fsm.decision,
            "final_state": fsm.state,
            "state_trace": fsm.log.state_trace(),
            "rejections": {rid: fsm.mesh[rid].rejected for rid in RESPONDER_IDS}
        });
        print("");
        print("  NEGATIVE CONTROL -- wrote incident_mismatch_probe.json only; "
              + "decision.json and containment.json were NOT touched.");
        sys.exit(0);
    }

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
          + "  controls_left=" + str(len(surface_after))
          + "  rollback_complete=" + str(restored));

    if not restored {
        # Loud, non-zero, and last. A run that leaves the application contained
        # is a failed run however good the decision was.
        print("");
        print("FATAL: rollback did NOT restore the control surface.");
        print("       still enforcing: " + json.dumps(diff["leftover"]));
        sys.exit(3);
    }
}
