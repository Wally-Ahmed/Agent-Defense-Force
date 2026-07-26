# coordinator/run.jac
#
# Runnable demo. Drives ONE clean incident through the full coordinator FSM on
# the all-mock mesh, using the six_with_mocked.jsonl effort receipts so the run
# is HONESTLY mocked (one receipt carries mocked:true) — the mock mesh would
# force MOCKED regardless. Prints the final state, the decision.v1, whether it
# contained, the action_set, and the whole event trail.
#
#   cd coordinator && ~/.local/bin/jac run run.jac

import json;
import os;
import from clock { frozen_clock }
import from config { default_mock_config }
import from mocks.mock_containment { MockContainment }
import from fsm { Incident, build_fsm, run_incident }
import from tests.incidents { incident_payload, fallback_target }

glob:pub HERE: str = os.path.dirname(os.path.abspath(__file__));


with entry:__main__ {
    receipts = os.path.join(HERE, "tests", "receipts", "six_with_mocked.jsonl");

    clock = frozen_clock();
    cfg = default_mock_config();
    executor = MockContainment();
    fsm = build_fsm(receipts, cfg, executor, clock, fallback_target());

    incident = Incident(
        incident_id="INC-DEMO-0001",
        payload=incident_payload("INC-DEMO-0001")
    );

    summary = run_incident(fsm, incident);

    print("================================================================");
    print("  MOCKED coordinator run — NOT an acceptance/live result");
    print(f"  run_label = {fsm.run_label}    log.is_mocked() = {fsm.log.is_mocked()}");
    print("================================================================");
    print(f"final_state : {fsm.state}");
    print(f"contained   : {fsm.decision.get('contain', False)}");
    print(f"quorum_met  : {fsm.decision.get('quorum_met', False)}");
    print(f"degraded    : {fsm.decision.get('degraded', False)}");
    print("");
    print("--- action_set (dispatched to toService:containment) ---");
    print(json.dumps(fsm.decision.get("action_set", []), indent=2, sort_keys=True));
    print("");
    print("--- decision.v1 (published on sec.verdict) ---");
    print(json.dumps(fsm.decision, indent=2, sort_keys=True));
    print("");
    print("--- event trail (JSONL, one event per line) ---");
    print(fsm.log.to_jsonl());
    print("");
    print("--- run summary ---");
    print(json.dumps(summary, indent=2, sort_keys=True));
    print("");
    print(f">>> MOCKED RUN — run_label={fsm.run_label}, final_state={fsm.state}, contained={fsm.decision.get('contain', False)}");
}
