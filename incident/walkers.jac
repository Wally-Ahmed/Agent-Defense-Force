# incident/walkers.jac — IngestAudit, Correlate, Promote, Explain.
#
# NO detection path in this file (or anywhere under incident/, excluding tests/) opens a file.
# The only file read in the whole pipeline is the audit stream itself, in replay.jac. That is
# what makes "the detector never reads the labels" checkable rather than asserted:
# tests/guards/sitecustomize.py wraps builtins.open and hard-fails on any path containing
# "label", and the acceptance run executes under it.

import math;
import from incident.graph { CorrelationGraph, Observation, Identity, Session, Source, Asset,
                             Service, Baseline, Signal, Incident,
                             PerformedBy, InSession, FromSource, Targeted, Via, Supports,
                             SharesFingerprint, PivotedTo, HasBaseline, Holds }
import from incident.projection { project, quarantine, assert_projection_clean, ANON_PRINCIPAL }
import from incident.baselines { BUCKET_MS, observe, principal_scope, tenant_scope }
import from incident.scorers_sv { score_all }
import from incident.gate { WINDOW_MS, THETA, evaluate, confidence, incident_id,
                            stage_signatures }

glob:pub FENCE_OPEN: str = "<<<UNTRUSTED>>>";
glob:pub FENCE_CLOSE: str = "<<</UNTRUSTED>>>";
glob:pub MAX_FENCE_CHARS: int = 4000;
glob:pub FP_UNION_MAX_PRINCIPALS: int = 2;


# ================================================================== IngestAudit =============

walker IngestAudit {
    has records: list = [];
    has ingested: int = 0;
    has duplicates: int = 0;

    can go with CorrelationGraph entry {
        for rec in self.records {
            eid = rec.get("event_id", "");
            if eid == "" {
                continue;
            }
            if eid in here.seen_events {
                self.duplicates += 1;              # idempotent on event_id
                continue;
            }
            o = project(rec);
            assert_projection_clean(o);
            here.seen_events[eid] = 1;
            here.rows.append(o);
            here.quarantine[eid] = quarantine(rec);
            self.ingested += 1;
            materialize(here, o);
        }
        # Deterministic total order. Decorate-sort-undecorate rather than a key lambda so the
        # tie-break (ts_ms, seq, event_id) is explicit and stable across runs.
        deco = [];
        for r in here.rows {
            deco.append((r["ts_ms"], r["seq"], r["event_id"], r));
        }
        ordered = [];
        for d in sorted(deco) {
            ordered.append(d[3]);
        }
        here.rows = ordered;
    }
}


def materialize(g: CorrelationGraph, o: dict) -> None {
    # Build the entity graph. Every lookup is by exact key through an index dict, so ingest is
    # O(1) per event and the node set is deduped.
    obs = Observation(event_id=o["event_id"], ts_ms=o["ts_ms"], action=o["action"],
                      outcome=o["outcome"], reason=o["reason"], severity=o["severity"],
                      target_sensitivity=o["target_sensitivity"], target_kind=o["target_kind"],
                      role_rank=o["role_rank"], sens_rank=o["sens_rank"],
                      result_count=o["result_count"], tenant_cross=o["tenant_cross"],
                      endpoint_class=o["endpoint_class"]);
    g +>:Holds:+> obs;

    if o["authenticated"] == 1 {
        ik = o["principal_hash"];
        if ik not in g.idx_identity {
            ident = Identity(principal_hash=ik, tenant_id=o["actor_tenant_id"], authenticated=1);
            g +>:Holds:+> ident;
            g.idx_identity[ik] = ident;
        }
        obs +>:PerformedBy:+> g.idx_identity[ik];
        hist = g.asset_history.setdefault(ik, {});
        if o["has_target"] == 1 and o["asset_hash"] not in hist {
            hist[o["asset_hash"]] = o["ts_ms"];
        }
    }

    sk = o["session_id"];
    if sk != "" {
        if sk not in g.idx_session {
            sess = Session(session_id=sk, first_ts_ms=o["ts_ms"]);
            g +>:Holds:+> sess;
            g.idx_session[sk] = sess;
        }
        obs +>:InSession:+> g.idx_session[sk];
    }

    src = o["src_ip"] + "|" + o["client_fp"];
    if o["src_ip"] != "" {
        if src not in g.idx_source {
            s = Source(src_ip=o["src_ip"], src_asn=o["src_asn"], client_fp=o["client_fp"]);
            g +>:Holds:+> s;
            # SharesFingerprint: the edge that survives source rotation.
            for other in sorted(list(g.idx_source.keys())) {
                on = g.idx_source[other];
                if on.client_fp != "" and on.client_fp == o["client_fp"] {
                    s +>:SharesFingerprint(client_fp=o["client_fp"]):+> on;
                }
            }
            g.idx_source[src] = s;
        }
        obs +>:FromSource:+> g.idx_source[src];
        # PivotedTo: one source driving more than one authenticated identity.
        if o["authenticated"] == 1 {
            ph = o["principal_hash"];
            known = g.idx_src_prins.setdefault(src, {});
            if ph not in known {
                for other in sorted(list(known.keys())) {
                    g.idx_identity[other] +>:PivotedTo(via=o["src_ip"]):+> g.idx_identity[ph];
                }
                known[ph] = 1;
            }
        }
    }

    if o["has_target"] == 1 {
        ak = o["asset_hash"];
        if ak not in g.idx_asset {
            a = Asset(asset_hash=ak, kind=o["target_kind"], sensitivity=o["target_sensitivity"]);
            g +>:Holds:+> a;
            g.idx_asset[ak] = a;
        }
        obs +>:Targeted:+> g.idx_asset[ak];
    }

    if o["service"] != "" {
        if o["service"] not in g.idx_service {
            sv = Service(name=o["service"]);
            g +>:Holds:+> sv;
            g.idx_service[o["service"]] = sv;
        }
        obs +>:Via:+> g.idx_service[o["service"]];
    }
}


# ================================================================== clustering ==============
# Connected components over {principal, session, client_fp}. src_ip is DELIBERATELY not a
# union token: shared egress IPs (NAT, VPN) would fuse unrelated actors, and source rotation is
# a signal we want to observe rather than a key we want to merge on.

def uf_find(parent: dict, x: str) -> str {
    r = x;
    while parent[r] != r {
        r = parent[r];
    }
    c = x;
    while parent[c] != c {
        nxt = parent[c];
        parent[c] = r;
        c = nxt;
    }
    return r;
}

def uf_union(parent: dict, a: str, b: str) -> None {
    ra = uf_find(parent, a);
    rb = uf_find(parent, b);
    if ra == rb {
        return;
    }
    if ra < rb {
        parent[rb] = ra;
    } else {
        parent[ra] = rb;
    }
}

def cluster(rows: list) -> dict {
    # fingerprint promiscuity: a fingerprint driving many authenticated principals is a shared
    # client build, not one actor. Only rare fingerprints are allowed to merge components.
    fp_prins = {};
    for r in rows {
        if r["authenticated"] == 1 and r["client_fp"] != "" {
            fp_prins.setdefault(r["client_fp"], {})[r["principal_hash"]] = 1;
        }
    }
    parent = {};
    row_tokens = [];
    for r in rows {
        toks = [];
        if r["authenticated"] == 1 {
            toks.append("p:" + r["principal_hash"]);
        }
        if r["session_id"] != "" {
            toks.append("s:" + r["session_id"]);
        }
        fp = r["client_fp"];
        if fp != "" and len(fp_prins.get(fp, {})) <= FP_UNION_MAX_PRINCIPALS {
            toks.append("f:" + fp);
        }
        if len(toks) == 0 {
            toks = ["e:" + r["event_id"]];
        }
        for t in toks {
            if t not in parent {
                parent[t] = t;
            }
        }
        i = 1;
        while i < len(toks) {
            uf_union(parent, toks[0], toks[i]);
            i += 1;
        }
        row_tokens.append(toks);
    }
    groups = {};
    for (i, r) in enumerate(rows) {
        comp = uf_find(parent, row_tokens[i][0]);
        groups.setdefault(comp, []).append(r);
    }
    # Stable, content-derived label: smallest principal token, else smallest session token.
    out = {};
    for comp in sorted(list(groups.keys())) {
        members = groups[comp];
        pr = [];
        se = [];
        for r in members {
            if r["authenticated"] == 1 {
                pr.append("p:" + r["principal_hash"]);
            }
            if r["session_id"] != "" {
                se.append("s:" + r["session_id"]);
            }
        }
        label = comp;
        if len(pr) > 0 {
            label = sorted(pr)[0];
        } elif len(se) > 0 {
            label = sorted(se)[0];
        }
        out[label] = members;
    }
    return out;
}


def primary_of(rows: list, field: str, fallback: str) -> str {
    counts = {};
    for r in rows {
        v = r[field];
        if field == "principal_hash" and r["authenticated"] != 1 {
            continue;
        }
        if v == "" {
            continue;
        }
        counts[v] = counts.get(v, 0) + 1;
    }
    if len(counts) == 0 {
        return fallback;
    }
    best = "";
    bestn = -1;
    for k in sorted(list(counts.keys())) {
        if counts[k] > bestn {
            bestn = counts[k];
            best = k;
        }
    }
    return best;
}


def bucket_metrics(rows: list) -> dict {
    # Per 60 s tumbling bucket, per baseline scope: the metrics the EWMA learns from.
    acc = {};
    for r in rows {
        b = r["ts_ms"] // BUCKET_MS;
        scopes = [tenant_scope(r["actor_tenant_id"])];
        if r["authenticated"] == 1 {
            scopes.append(principal_scope(r["principal_hash"]));
        }
        for sc in scopes {
            cell = acc.setdefault(b, {}).setdefault(sc, {"n": 0, "d": 0, "a": {}, "k": {}});
            cell["n"] += 1;
            if r["outcome"] == "deny" {
                cell["d"] += 1;
            }
            if r["has_target"] == 1 {
                cell["a"][r["asset_hash"]] = 1;
            }
            if r["target_kind"] != "" {
                cell["k"][r["target_kind"]] = 1;
            }
        }
    }
    return acc;
}


# ================================================================== Correlate ===============

walker Correlate {
    has theta: float = THETA;
    has window_ms: int = WINDOW_MS;
    has windows: int = 0;
    has signals_fired: int = 0;

    can go with CorrelationGraph entry {
        rows = here.rows;
        n = len(rows);
        if n == 0 {
            return;
        }
        buckets = bucket_metrics(rows);
        bucket_ids = sorted(list(buckets.keys()));
        next_bucket = 0;
        left = 0;
        promoted_subjects = {};

        i = 0;
        while i < n {
            wend = rows[i]["ts_ms"];
            wstart = wend - self.window_ms;
            while left < n and rows[left]["ts_ms"] < wstart {
                left += 1;
            }
            # advance the window right edge over every event sharing this millisecond
            j = i;
            while j + 1 < n and rows[j + 1]["ts_ms"] == wend {
                j += 1;
            }

            # SCORE-THEN-LEARN: fold in every 60 s bucket that has closed at or before wend.
            while (next_bucket < len(bucket_ids)
                   and (bucket_ids[next_bucket] + 1) * BUCKET_MS <= wend) {
                b = bucket_ids[next_bucket];
                for sc in sorted(list(buckets[b].keys())) {
                    c = buckets[b][sc];
                    observe(here.baseline_store, sc, "events", float(c["n"]));
                    observe(here.baseline_store, sc, "distinct_assets", float(len(c["a"])));
                    observe(here.baseline_store, sc, "distinct_kinds", float(len(c["k"])));
                    observe(here.baseline_store, sc, "deny_ratio",
                            float(c["d"]) / float(max(c["n"], 1)));
                }
                next_bucket += 1;
            }

            win = rows[left:(j + 1)];
            self.windows += 1;
            groups = cluster(win);
            for subject in sorted(list(groups.keys())) {
                members = groups[subject];
                pp = primary_of(members, "principal_hash", ANON_PRINCIPAL);
                pt = primary_of(members, "actor_tenant_id", "");
                prior = {};
                seenp = {};
                for r in members {
                    if r["authenticated"] == 1 {
                        seenp[r["principal_hash"]] = 1;
                    }
                }
                for ph in sorted(list(seenp.keys())) {
                    for (a, first_ts) in here.asset_history.get(ph, {}).items() {
                        if first_ts < wstart {
                            prior[a] = 1;
                        }
                    }
                }
                ctx = {"store": here.baseline_store, "primary_principal": pp,
                       "primary_tenant": pt, "prior_assets": prior,
                       "window_start_ms": wstart, "window_end_ms": wend};
                sigs = score_all(members, ctx);
                for s in sigs {
                    if s["fired"] {
                        self.signals_fired += 1;
                        upsert_signal(here, subject, s, wstart, wend);
                    }
                }
                verdict = evaluate(sigs, self.theta);
                if len(verdict["families"]) > 0 {
                    all_scores = {};
                    for s in sigs {
                        all_scores[s["family"]] = s["score"];
                    }
                    here.window_trace.append({
                        "window_end_ms": wend, "subject": subject, "scores": all_scores,
                        "families": verdict["families"], "axes": verdict["axes"],
                        "aggregate": verdict["aggregate"], "clauses": verdict["clauses"],
                        "promote": verdict["promote"],
                        "mandatory": verdict["mandatory"],
                        "shared_join_keys": verdict["shared_join_keys"]
                    });
                }
                if verdict["promote"] {
                    ev = [];
                    for r in members {
                        ev.append(r["event_id"]);
                    }
                    rec = {
                        "subject": subject, "window_start_ms": wstart, "window_end_ms": wend,
                        "verdict": verdict, "evidence": ev,
                        "stages": stage_signatures(members),
                        "principal_hash": pp, "tenant": pt,
                        "session_ids": sorted(list({r["session_id"]: 1 for r in members}.keys())),
                        "src_ips": sorted(list({r["src_ip"]: 1 for r in members}.keys())),
                        "user_agents": sorted(list({r["user_agent_hash"]: 1
                                                    for r in members}.keys())),
                        "first_ts": members[0]["ts_ms"], "last_ts": members[-1]["ts_ms"]
                    };
                    if subject not in promoted_subjects {
                        # First crossing. This window end is detected_at_ms and seeds the
                        # (stable) incident_id.
                        rec["detected_at_ms"] = wend;
                        promoted_subjects[subject] = len(here.promotions);
                        here.promotions.append(rec);
                    } else {
                        # The incident stays open: later windows accrete families, axes,
                        # evidence, stages and sources. detected_at_ms never moves.
                        here.promotions[promoted_subjects[subject]] = merge_promotion(
                            here.promotions[promoted_subjects[subject]], rec);
                    }
                }
            }
            i = j + 1;
        }
        materialize_baselines(here);
    }
}


def materialize_baselines(g: CorrelationGraph) -> None {
    # Project the EWMA store into Baseline nodes so the learned state is queryable from the
    # graph itself, not just from walker-local memory.
    for k in sorted(list(g.baseline_store.keys())) {
        st = g.baseline_store[k];
        parts = k.split("|");
        if k not in g.idx_baseline {
            b = Baseline(scope_key=parts[0], metric=parts[1]);
            g +>:HasBaseline:+> b;
            g.idx_baseline[k] = b;
        }
        node_b = g.idx_baseline[k];
        node_b.ewma_mean = round(st["mean"], 6);
        node_b.ewma_std = round(math.sqrt(max(st["var"], 0.0)), 6);
        node_b.n = st["n"];
    }
}


def union_sorted(a: list, b: list) -> list {
    m = {};
    for x in (a + b) {
        m[x] = 1;
    }
    return sorted(list(m.keys()));
}


def merge_promotion(cur: dict, nxt: dict) -> dict {
    cv = cur["verdict"];
    nv = nxt["verdict"];
    cv["families"] = union_sorted(cv["families"], nv["families"]);
    cv["axes"] = union_sorted(cv["axes"], nv["axes"]);
    cv["mandatory"] = union_sorted(cv["mandatory"], nv["mandatory"]);
    cv["shared_join_keys"] = union_sorted(cv["shared_join_keys"], nv["shared_join_keys"]);
    cv["aggregate"] = max(cv["aggregate"], nv["aggregate"]);
    cur["verdict"] = cv;
    cur["evidence"] = union_sorted(cur["evidence"], nxt["evidence"]);
    cur["stages"] = sorted(list({s: 1 for s in (cur["stages"] + nxt["stages"])}.keys()));
    cur["session_ids"] = union_sorted(cur["session_ids"], nxt["session_ids"]);
    cur["src_ips"] = union_sorted(cur["src_ips"], nxt["src_ips"]);
    cur["user_agents"] = union_sorted(cur["user_agents"], nxt["user_agents"]);
    cur["window_end_ms"] = max(cur["window_end_ms"], nxt["window_end_ms"]);
    cur["first_ts"] = min(cur["first_ts"], nxt["first_ts"]);
    cur["last_ts"] = max(cur["last_ts"], nxt["last_ts"]);
    return cur;
}


def upsert_signal(g: CorrelationGraph, subject: str, s: dict, wstart: int, wend: int) -> None {
    key = subject + "|" + s["family"];
    if key not in g.idx_signal {
        sn = Signal(family=s["family"], axis=s["axis"], score=s["score"],
                      window_start_ms=wstart, window_end_ms=wend,
                      join_keys=s["join_keys"], evidence=s["evidence"], detail=s["detail"],
                      subject=subject);
        g +>:Holds:+> sn;
        g.idx_signal[key] = sn;
        return;
    }
    sn = g.idx_signal[key];
    if s["score"] > sn.score {
        sn.score = s["score"];
        sn.detail = s["detail"];
    }
    sn.window_end_ms = wend;
    merged = {};
    for e in (sn.evidence + s["evidence"]) {
        merged[e] = 1;
    }
    sn.evidence = sorted(list(merged.keys()));
    jk = {};
    for k in (sn.join_keys + s["join_keys"]) {
        jk[k] = 1;
    }
    sn.join_keys = sorted(list(jk.keys()));
}


# ================================================================== Promote =================

walker Promote {
    has incidents: list = [];

    can go with CorrelationGraph entry {
        for p in here.promotions {
            v = p["verdict"];
            iid = incident_id(p["subject"], p["detected_at_ms"]);
            conf = confidence(v, len(p["stages"]));
            inc = Incident(incident_id=iid, state="open", confidence=conf,
                           first_ts=p["first_ts"], last_ts=p["last_ts"],
                           axes=v["axes"], families=v["families"], subject=p["subject"],
                           join_keys={"principal_hash": p["principal_hash"],
                                      "tenant": p["tenant"],
                                      "session_ids": p["session_ids"],
                                      "src_ips": p["src_ips"],
                                      "user_agents": p["user_agents"]},
                           evidence=p["evidence"], stage_signatures=p["stages"],
                           aggregate=v["aggregate"], window_start_ms=p["window_start_ms"],
                           window_end_ms=p["window_end_ms"],
                           detected_at_ms=p["detected_at_ms"]);
            here +>:Holds:+> inc;
            for f in v["families"] {
                k = p["subject"] + "|" + f;
                if k in here.idx_signal {
                    inc +>:Supports:+> here.idx_signal[k];
                }
            }
            self.incidents.append(emit_incident_v1(here, inc, p));
        }
    }
}


def fence(label: str, values: list) -> dict {
    body = "\n".join(values);
    budget = MAX_FENCE_CHARS - len(FENCE_OPEN) - len(FENCE_CLOSE) - 2;
    if len(body) > budget {
        body = body[0:budget];
    }
    return {"label": label, "text": FENCE_OPEN + "\n" + body + "\n" + FENCE_CLOSE};
}


def emit_incident_v1(g: CorrelationGraph, inc: Incident, p: dict) -> dict {
    # QUARANTINE ASSEMBLY. This is the ONLY place free text re-enters the pipeline, and it goes
    # straight into untrusted_data.fenced without being read, matched, or scored.
    by_label = {};
    for eid in inc.evidence {
        for (field, value) in sorted(list(g.quarantine.get(eid, {}).items())) {
            by_label.setdefault(field, {})[value] = 1;
        }
    }
    fenced = [];
    for label in sorted(list(by_label.keys())) {
        fenced.append(fence(label, sorted(list(by_label[label].keys()))));
    }
    v = p["verdict"];
    summary = ("Correlated campaign on " + str(len(v["families"])) + " detection families ("
               + ", ".join(v["families"]) + ") across " + str(len(v["axes"])) + " axes ("
               + ", ".join(v["axes"]) + "); mandatory member(s): " + ", ".join(v["mandatory"])
               + ". " + str(len(inc.evidence)) + " correlated events over "
               + str(round(float(inc.last_ts - inc.first_ts) / 1000.0, 1))
               + "s, joined on " + str(len(v["shared_join_keys"]))
               + " shared key(s). Aggregate score " + str(v["aggregate"]) + " >= theta "
               + str(v["theta"]) + ".");
    if len(summary) > 600 {
        summary = summary[0:597] + "...";
    }
    return {
        "incident_id": inc.incident_id,
        "schema_version": "incident.v1",
        "detected_at_ms": inc.detected_at_ms,
        "confidence": inc.confidence,
        "axes": inc.axes,
        "families": inc.families,
        "join_keys": {"principal_hash": inc.join_keys["principal_hash"],
                      "tenant": inc.join_keys["tenant"],
                      "session_ids": inc.join_keys["session_ids"],
                      "src_ips": inc.join_keys["src_ips"],
                      "user_agents": inc.join_keys["user_agents"]},
        "evidence": inc.evidence,
        "stage_signatures": inc.stage_signatures,
        "summary": summary,
        "untrusted_data": {"fenced": fenced}
    };
}


# ================================================================== Explain =================

walker Explain {
    has incident_id_filter: str = "";
    has report: list = [];

    can go with CorrelationGraph entry {
        incs = [here ->:Holds:-> [?:Incident]];
        by_event = {};
        for r in here.rows {
            by_event[r["event_id"]] = r;
        }
        for inc in incs {
            if self.incident_id_filter != "" and inc.incident_id != self.incident_id_filter {
                continue;
            }
            sigs = [inc ->:Supports:-> [?:Signal]];
            fam_of_event = {};
            fam_rows = [];
            by_family = {};
            for s in sigs {
                by_family[s.family] = s;
            }
            for fam in sorted(list(by_family.keys())) {
                s = by_family[fam];
                fam_rows.append({"family": s.family, "axis": s.axis, "score": s.score,
                                 "window_start_ms": s.window_start_ms,
                                 "window_end_ms": s.window_end_ms,
                                 "join_keys": s.join_keys, "detail": s.detail,
                                 "evidence_count": len(s.evidence)});
                for e in s.evidence {
                    fam_of_event.setdefault(e, {})[s.family] = 1;
                }
            }
            timeline = [];
            ev_order = [];
            for e in sorted(list(fam_of_event.keys())) {
                ev_order.append((by_event[e]["ts_ms"], e));
            }
            for (_ts, eid) in sorted(ev_order) {
                r = by_event[eid];
                timeline.append({
                    "ts_ms": r["ts_ms"], "rel_s": round(float(r["ts_ms"] - inc.first_ts) / 1000.0, 2),
                    "event_id": eid, "action": r["action"], "outcome": r["outcome"],
                    "reason": r["reason"], "target_kind": r["target_kind"],
                    "sensitivity": r["target_sensitivity"], "src_ip": r["src_ip"],
                    "session_id": r["session_id"],
                    "families": sorted(list(fam_of_event[eid].keys()))
                });
            }
            self.report.append({
                "incident_id": inc.incident_id, "confidence": inc.confidence,
                "families": inc.families, "axes": inc.axes,
                "stage_signatures": inc.stage_signatures,
                "join_keys": inc.join_keys, "aggregate": inc.aggregate,
                "window_start_ms": inc.window_start_ms, "window_end_ms": inc.window_end_ms,
                "detected_at_ms": inc.detected_at_ms,
                "signals": fam_rows, "timeline": timeline,
                "evidence_count": len(inc.evidence)
            });
        }
    }
}
