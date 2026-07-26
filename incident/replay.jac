# incident/replay.jac — deterministic offline replay: Ingest -> Correlate -> Promote -> Explain.
#
#   jac run incident/replay.jac <audit.jsonl> [--theta F] [--out DIR] [--repeat N] [--quiet]
#
# No model call anywhere in this path. The only file opened for reading is the audit stream
# named on the command line.

import sys;
import json;
import os;
import from incident.graph { CorrelationGraph }
import from incident.projection { boot }
import from incident.walkers { IngestAudit, Correlate, Promote, Explain }
import from incident.gate { THETA, WINDOW_MS }


def read_events(path: str) -> list {
    out = [];
    with open(path, "r") as fh {
        for line in fh {
            s = line.strip();
            if s != "" {
                out.append(json.loads(s));
            }
        }
    }
    return out;
}


def parse_args(argv: list) -> dict {
    cfg = {"path": "contracts/fixtures/audit_golden.jsonl", "theta": THETA,
           "out": "incident/out", "repeat": 1, "quiet": False};
    i = 0;
    positional = [];
    while i < len(argv) {
        a = argv[i];
        if a == "--theta" {
            cfg["theta"] = float(argv[i + 1]);
            i += 2;
        } elif a == "--out" {
            cfg["out"] = argv[i + 1];
            i += 2;
        } elif a == "--repeat" {
            cfg["repeat"] = int(argv[i + 1]);
            i += 2;
        } elif a == "--quiet" {
            cfg["quiet"] = True;
            i += 1;
        } else {
            positional.append(a);
            i += 1;
        }
    }
    if len(positional) > 0 {
        cfg["path"] = positional[0];
    }
    return cfg;
}


def write_jsonl(path: str, rows: list) -> None {
    with open(path, "w") as fh {
        for r in rows {
            fh.write(json.dumps(r, sort_keys=True) + "\n");
        }
    }
}


def render_explain(reports: list) -> str {
    lines = [];
    for rep in reports {
        lines.append("=" * 96);
        lines.append("INCIDENT " + rep["incident_id"] + "   confidence=" + str(rep["confidence"])
                     + "   aggregate=" + str(rep["aggregate"]));
        lines.append("  families : " + ", ".join(rep["families"]));
        lines.append("  axes     : " + ", ".join(rep["axes"]));
        lines.append("  stages   : " + ", ".join([str(s) for s in rep["stage_signatures"]]));
        lines.append("  window   : [" + str(rep["window_start_ms"]) + " .. "
                     + str(rep["window_end_ms"]) + "]  (" + str(WINDOW_MS // 1000) + "s slide)");
        jk = rep["join_keys"];
        lines.append("  principal: " + jk["principal_hash"] + "   tenant: " + jk["tenant"]);
        lines.append("  sessions : " + ", ".join(jk["session_ids"]));
        lines.append("  src_ips  : " + ", ".join(jk["src_ips"]));
        lines.append("");
        lines.append("  SIGNALS");
        for s in rep["signals"] {
            lines.append("    " + s["family"].ljust(14) + " axis=" + s["axis"].ljust(9)
                         + " score=" + str(s["score"]).ljust(7)
                         + " events=" + str(s["evidence_count"]).ljust(4)
                         + " " + json.dumps(s["detail"], sort_keys=True));
        }
        lines.append("");
        lines.append("  EVIDENCE TIMELINE (" + str(len(rep["timeline"])) + " events)");
        lines.append("    " + "rel_s".rjust(8) + "  " + "action".ljust(20)
                     + "  " + "outcome".ljust(6) + "  " + "reason".ljust(18)
                     + "  " + "sens".ljust(13) + "  " + "src_ip".ljust(15) + "  families");
        for t in rep["timeline"] {
            lines.append("    " + str(t["rel_s"]).rjust(8) + "  " + t["action"].ljust(20)
                         + "  " + t["outcome"].ljust(6) + "  " + (t["reason"] or "-").ljust(18)
                         + "  " + (t["sensitivity"] or "-").ljust(13)
                         + "  " + (t["src_ip"] or "-").ljust(15)
                         + "  " + ",".join(t["families"]));
        }
        lines.append("");
    }
    if len(reports) == 0 {
        lines.append("(no incidents promoted)");
    }
    return "\n".join(lines);
}


with entry:__main__ {
    boot();
    argv = sys.argv[1:];
    cfg = parse_args(argv);
    events = read_events(cfg["path"]);

    g = CorrelationGraph(label="incident");
    r = 0;
    total_ing = 0;
    total_dup = 0;
    while r < cfg["repeat"] {
        w = IngestAudit(records=events);
        g spawn w;
        total_ing += w.ingested;
        total_dup += w.duplicates;
        r += 1;
    }

    cor = Correlate(theta=cfg["theta"]);
    g spawn cor;
    pro = Promote();
    g spawn pro;
    exp = Explain();
    g spawn exp;

    os.makedirs(cfg["out"], exist_ok=True);
    sig_rows = [];
    for k in sorted(list(g.idx_signal.keys())) {
        s = g.idx_signal[k];
        sig_rows.append({"subject": s.subject, "family": s.family, "axis": s.axis,
                         "score": s.score, "window_start_ms": s.window_start_ms,
                         "window_end_ms": s.window_end_ms, "join_keys": s.join_keys,
                         "evidence": s.evidence, "detail": s.detail});
    }
    write_jsonl(cfg["out"] + "/signals.jsonl", sig_rows);
    write_jsonl(cfg["out"] + "/incidents.jsonl", pro.incidents);
    write_jsonl(cfg["out"] + "/window_trace.jsonl", g.window_trace);
    with open(cfg["out"] + "/explain.txt", "w") as fh {
        fh.write(render_explain(exp.report) + "\n");
    }

    subjects = {};
    for t in g.window_trace {
        subjects[t["subject"]] = 1;
    }
    summary = {
        "events_in": len(events),
        "ingested": total_ing,
        "duplicates_skipped": total_dup,
        "observations": len(g.rows),
        "windows_evaluated": cor.windows,
        "signal_fires": cor.signals_fired,
        "distinct_signals": len(g.idx_signal),
        "subjects_with_signals": sorted(list(subjects.keys())),
        "incidents": len(pro.incidents),
        "theta": cfg["theta"],
        "window_ms": WINDOW_MS,
        "incident_ids": [i["incident_id"] for i in pro.incidents]
    };
    with open(cfg["out"] + "/summary.json", "w") as fh {
        fh.write(json.dumps(summary, indent=2, sort_keys=True) + "\n");
    }
    print(json.dumps(summary, sort_keys=True));
    if not cfg["quiet"] {
        sys.stderr.write(render_explain(exp.report) + "\n");
    }
}
