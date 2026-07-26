# incident/run_golden.jac — run the detector over the golden audit stream.
#
#   jac run incident/run_golden.jac            # from the repository root
#
# Prints, in order: ingest counts, every window that fired at least one family,
# the promoted incidents with their Explain timeline, and the incident.v1
# payload that would be published on `sec.incident`.

import json;
import from typing { cast }

import from incident.graph { IncidentGraph, Incident, Signal, Observation, Emitted, Observes }
import from incident.pipeline { load_golden, analyze, incidents_of, explain }
import from incident.walkers { rows_by_subject }
import from incident.emit { to_incident_v1 }
import from incident.gate { THETA, MIN_FAMILIES, MIN_AXES, MANDATORY_FAMILIES }


with entry:__main__ {
    events = load_golden();
    print("=== INPUT ===");
    print("events                 :", len(events));

    result = analyze(events);
    g = cast(IncidentGraph, result["graph"]);
    ingest = result["ingest"];
    correlate = result["correlate"];
    promote = result["promote"];

    print("");
    print("=== INGEST ===");
    print("ingested               :", ingest.ingested);
    print("duplicates skipped     :", ingest.duplicates);
    print("rejected (vocabulary)  :", ingest.rejected);

    by_subject = rows_by_subject(g);
    print("subject clusters       :", len(by_subject));
    for k in sorted(list(by_subject.keys())) {
        rows: list = list(by_subject[k]);
        total_rows: int = 0;
        for r in rows {
            total_rows += int(r["result_count"]);
        }
        print("  " + str(k) + "  events=" + str(len(rows)) + "  rows_returned=" + str(total_rows));
    }

    print("");
    print("=== CORRELATE ===");
    print("windows scored         :", correlate.windows_scored);
    print("signals emitted        :", correlate.signals_emitted);
    for t in correlate.trace {
        if len(list(t["fired"])) > 0 {
            print("  w_end=" + str(t["window_end_ms"]) + "  " + str(t["subject"])
                  + "  n=" + str(t["n_events"]) + "  fired=" + str(t["fired"]));
        }
    }

    print("");
    print("=== PROMOTE ===");
    print("gate: >=" + str(MIN_FAMILIES) + " families, >=" + str(MIN_AXES)
          + " axes, >=1 shared join key, aggregate >= " + str(THETA)
          + ", >=1 of " + str(MANDATORY_FAMILIES));
    print("windows evaluated      :", promote.evaluated);
    print("windows promoted       :", promote.promoted);

    incidents = incidents_of(g);
    print("incidents raised       :", len(incidents));

    for raw in incidents {
        inc = cast(Incident, raw);
        print("");
        print("=== INCIDENT " + inc.incident_id + " ===");
        print("subject     :", inc.subject_key);
        print("state       :", inc.state);
        print("confidence  :", inc.confidence);
        print("families    :", inc.families);
        print("axes        :", inc.axes);
        print("windows     :", inc.window_count, " peak aggregate:", inc.peak_score);
        print("evidence    :", len(inc.evidence), "events");
        print("span_ms     :", inc.last_ts_ms - inc.first_ts_ms);

        e = explain(g, inc.incident_id);
        print("");
        print("--- EXPLAIN: evidence timeline ---");
        for step in e.timeline {
            print("  stage " + str(step["stage"]) + "  " + str(step["stage_name"])
                  + "  ts=" + str(step["ts_ms"]) + "  " + str(step["action"])
                  + "/" + str(step["outcome"])
                  + ("/" + str(step["reason"]) if str(step["reason"]) != "" else ""));
        }
        print("");
        print("--- EXPLAIN: signal timeline ---");
        for s in e.signal_timeline {
            print("  w_end=" + str(s["window_end_ms"]) + "  " + str(s["family"])
                  + " (" + str(s["axis"]) + ") score=" + str(s["score"])
                  + " evidence=" + str(s["n_evidence"]));
        }
        print("");
        print("summary     :", e.summary);

        subj_rows: list = list(rows_by_subject(g).get(inc.subject_key, []));
        payload = to_incident_v1(g, inc, subj_rows, inc.last_ts_ms, e.summary);
        print("");
        print("--- incident.v1 (schema-validated) ---");
        print(json.dumps(payload, indent=2, sort_keys=True));
    }

    if len(incidents) == 0 {
        print("");
        print("NO INCIDENT PROMOTED.");
    }
}
