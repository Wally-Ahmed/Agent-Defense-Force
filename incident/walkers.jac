# incident/walkers.jac — IngestAudit, Correlate, Promote, Explain.
#
# The pipeline, and what each stage is allowed to know:
#
#   IngestAudit  raw audit records -> graph. Idempotent on event_id. Validates
#                the closed vocabulary, projects away attacker text, builds the
#                entity nodes and the subject clusters.
#   Correlate    graph -> Signals. Slides the window, computes features, resolves
#                baselines, runs the seven scorers, writes a Signal per firing
#                family. Knows nothing about promotion.
#   Promote      Signals -> Incident. Applies the gate and merges qualifying
#                windows into one incident per subject. Knows nothing about
#                scoring.
#   Explain      Incident -> evidence timeline for a responder.
#
# WALKER FIELD TYPES. Every `has` here is str/int/float/bool/list/dict. Per
# spikes/README.md, jfast_api silently degrades any other declared type to `str`
# and the walker 422s when served over HTTP. These walkers are usable from
# `jac start` unchanged because of that discipline, not by accident.
#
# SUBJECT CLUSTERING. A campaign is not one principal: the golden fixture's
# attacker spends its first seven events unauthenticated, with an empty
# actor_principal_id, before the stolen credential is ever used. Keying windows
# on principal alone would therefore split the incident in half and lose the
# reconnaissance. Subjects are union-find clusters over (session_id, principal_id,
# client_fp) — the same relations the graph already names SharesFingerprint and
# PivotedTo. src_ip is deliberately NOT a clustering key: NAT would merge
# strangers.

import json;
import hashlib;
import from typing { cast }

import from incident.graph {
    IncidentGraph, Observation, Identity, Session, Source, Asset, Service,
    Baseline, Signal, Incident, Quarantine,
    PerformedBy, InSession, FromSource, Targeted, Via,
    SharesFingerprint, PivotedTo, Supports,
    Observes, Knows, Measures, Emitted, Raised, Quarantined
}
import from incident.projection {
    AuditEvent, audit_event_of, project, quarantine_of, vocabulary_ok, FAMILY_AXIS
}
import from incident.baseline {
    Stat, ewma_update, zscore, z_to_score, scope_chain, MIN_SAMPLES
}
import from incident.features { WindowFeatures, extract, NOVELTY_MIN_PRIOR }
import from incident.scorers_sv { FamilyScore, score_all }
import from incident.gate { GateVerdict, evaluate, confidence_of, WINDOW_MS, STEP_MS, THETA }
import from incident.stages { signatures, stage_name }

# Observation fields, in node-declaration order. Used to read a node back into a
# plain row dict so the pure feature/stage code never receives a graph handle.
glob:pub OBS_FIELDS: list = [
    "event_id", "ts_ms", "seq", "kind", "action", "outcome", "reason", "severity",
    "actor_role", "auth_method", "target_kind", "target_sensitivity", "service",
    "http_method", "principal_id", "session_id", "tenant_id", "actor_tenant_id",
    "target_id", "parent_id", "src_ip", "src_asn", "client_fp", "ua_hash",
    "integration_id", "trace_id", "route_class", "cross_tenant", "authenticated",
    "asset_rank", "status_code", "latency_ms", "req_bytes", "resp_bytes",
    "result_count"
];

# Metrics carried in Baseline nodes. Each is a window-level statistic, so the
# baseline of a metric is the EWMA over that scope's previous windows.
glob:pub BASELINE_METRICS: list = [
    "deny_ratio", "deny_reasons", "d_target_id", "d_target_kind", "route_entropy"
];


# --------------------------------------------------------------------------
# union-find over join keys
# --------------------------------------------------------------------------

"""Representative of a join key's cluster, with path compression."""
def uf_find(parent: dict, x: str) -> str {
    if x not in parent {
        parent[x] = x;
        return x;
    }
    cur = x;
    while str(parent[cur]) != cur {
        parent[cur] = parent[str(parent[cur])];
        cur = str(parent[cur]);
    }
    return cur;
}


"""Merge two join keys into one subject cluster."""
def uf_union(parent: dict, a: str, b: str) -> None {
    ra = uf_find(parent, a);
    rb = uf_find(parent, b);
    if ra != rb {
        parent[ra] = rb;
    }
}


# --------------------------------------------------------------------------
# graph helpers
# --------------------------------------------------------------------------

"""Read an Observation node back into a plain dict.

Everything downstream of this point works on dicts of enums, opaque ids and
numbers. Nothing downstream holds a graph handle, which is what keeps the
feature and scorer code pure and independently testable."""
def row_of(o: Observation) -> dict {
    return {
        "event_id": o.event_id, "ts_ms": o.ts_ms, "seq": o.seq, "kind": o.kind,
        "action": o.action, "outcome": o.outcome, "reason": o.reason,
        "severity": o.severity, "actor_role": o.actor_role,
        "auth_method": o.auth_method, "target_kind": o.target_kind,
        "target_sensitivity": o.target_sensitivity, "service": o.service,
        "http_method": o.http_method, "principal_id": o.principal_id,
        "session_id": o.session_id, "tenant_id": o.tenant_id,
        "actor_tenant_id": o.actor_tenant_id, "target_id": o.target_id,
        "parent_id": o.parent_id, "src_ip": o.src_ip, "src_asn": o.src_asn,
        "client_fp": o.client_fp, "ua_hash": o.ua_hash,
        "integration_id": o.integration_id, "trace_id": o.trace_id,
        "route_class": o.route_class, "cross_tenant": o.cross_tenant,
        "authenticated": o.authenticated, "asset_rank": o.asset_rank,
        "status_code": o.status_code, "latency_ms": o.latency_ms,
        "req_bytes": o.req_bytes, "resp_bytes": o.resp_bytes,
        "result_count": o.result_count
    };
}


"""The subject cluster a row belongs to. Session is always present (the audit
contract guarantees a non-empty session_id even for pre-auth traffic), so it is
the anchor the other keys are merged into."""
def subject_of(g: IncidentGraph, row: dict) -> str {
    return uf_find(g.cluster_parent, "S|" + str(row.get("session_id", "")));
}


"""Every subject's rows, in timestamp order, keyed by cluster representative."""
def rows_by_subject(g: IncidentGraph) -> dict {
    out = {};
    for o in [g ->:Observes:-> Observation] {
        r = row_of(o);
        k = subject_of(g, r);
        if k not in out {
            out[k] = [];
        }
        out[k].append(r);
    }
    for k in out.keys() {
        bykey = {};
        rows: list = list(out[k]);
        for r in rows {
            kk = str(int(r.get("ts_ms", 0))).zfill(20) + "|" + str(r.get("event_id", ""));
            bykey[kk] = r;
        }
        ordered = [];
        for kk in sorted(list(bykey.keys())) {
            ordered.append(bykey[kk]);
        }
        out[k] = ordered;
    }
    return out;
}


"""Join keys carried by a set of rows. These are the correlation handles the
gate intersects and the responders contain on."""
def join_keys_of(rows: list) -> list {
    keys = set();
    for r in rows {
        p = str(r.get("principal_id", ""));
        s = str(r.get("session_id", ""));
        ip = str(r.get("src_ip", ""));
        fp = str(r.get("client_fp", ""));
        a = str(r.get("target_id", ""));
        if p != "" {
            keys.add("principal|" + p);
        }
        if s != "" {
            keys.add("session|" + s);
        }
        if ip != "" {
            keys.add("source|" + ip);
        }
        if fp != "" {
            keys.add("source|fp:" + fp);
        }
        if a != "" {
            keys.add("asset|" + a);
        }
    }
    return sorted(list(keys));
}


"""The rows that actually support each family, so evidence is the events a
family cited rather than the whole window."""
def evidence_rows(family: str, rows: list, prior_targets: set) -> list {
    out = [];
    if family == "denial_shape" {
        for r in rows {
            if r.get("outcome", "") == "deny" {
                out.append(r);
            }
        }
    } elif family == "canary" {
        for r in rows {
            if r.get("target_sensitivity", "") == "canary" {
                out.append(r);
            }
        }
    } elif family == "novelty" {
        for r in rows {
            t = str(r.get("target_id", ""));
            if t != "" and t not in prior_targets {
                out.append(r);
            }
        }
    } elif family == "escalation" {
        seen_deny = False;
        for r in rows {
            if seen_deny {
                out.append(r);
            }
            if r.get("outcome", "") == "deny" {
                seen_deny = True;
            }
        }
    } elif family == "pivot" {
        counts = {};
        for r in rows {
            fp = str(r.get("client_fp", ""));
            ip = str(r.get("src_ip", ""));
            if fp == "" or ip == "" {
                continue;
            }
            if fp not in counts {
                counts[fp] = set();
            }
            counts[fp].add(ip);
        }
        for r in rows {
            fp = str(r.get("client_fp", ""));
            if fp in counts and len(counts[fp]) >= 2 {
                out.append(r);
            }
        }
    } else {
        out = rows;
    }
    if len(out) == 0 {
        out = rows;
    }
    return out;
}


"""Fetch or create the Baseline node for one (scope, metric)."""
def baseline_node(g: IncidentGraph, scope_key: str, metric: str) -> Baseline {
    key = "B|" + scope_key + "||" + metric;
    if key in g.idx {
        return cast(Baseline, g.idx[key]);
    }
    b = Baseline(scope_key=scope_key, metric=metric);
    g +>:Measures:+> b;
    g.idx[key] = b;
    return b;
}


"""Resolve a metric to the narrowest warm baseline in the scope chain.

Falls outward — principal, then tenant, then global — and reports which scope
answered so a responder can see whether a deviation was measured against the
account itself or against its tenant."""
def resolve_stat(g: IncidentGraph, chain: list, metric: str) -> Stat {
    for scope in chain {
        b = baseline_node(g, str(scope), metric);
        if b.n >= MIN_SAMPLES {
            return Stat(mean=b.ewma_mean, var=b.ewma_var, n=b.n, warm=True,
                        scope=b.scope_key);
        }
    }
    return Stat(warm=False, scope="");
}


"""Fold a window's metrics into every scope in the chain."""
def learn(g: IncidentGraph, chain: list, values: dict) -> None {
    for scope in chain {
        for metric in BASELINE_METRICS {
            b = baseline_node(g, str(scope), metric);
            upd = ewma_update(b.ewma_mean, b.ewma_var, b.n, float(values[metric]));
            b.ewma_mean = float(upd["mean"]);
            b.ewma_var = float(upd["var"]);
            b.n = int(upd["n"]);
        }
    }
}


"""Deterministic incident id: a digest of the subject cluster and the first
timestamp. Same events in, same id out, on any machine."""
def incident_id_for(subject_key: str, first_ts_ms: int) -> str {
    raw = subject_key + "|" + str(first_ts_ms);
    return "inc_" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[0:16];
}


# --------------------------------------------------------------------------
# IngestAudit
# --------------------------------------------------------------------------

"""Raw audit records into the graph. Idempotent on event_id: re-ingesting the
same file is a no-op, which is what makes replay safe and makes an at-least-once
audit transport survivable."""
walker IngestAudit {
    has events: list = [];
    has ingested: int = 0;
    has duplicates: int = 0;
    has rejected: int = 0;

    can run with IncidentGraph entry {
        for ev in self.events {
            eid = str(ev.get("event_id", ""));
            if eid == "" {
                self.rejected += 1;
                continue;
            }
            if eid in here.seen_events {
                self.duplicates += 1;
                continue;
            }
            if not vocabulary_ok(ev) {
                self.rejected += 1;
                continue;
            }
            here.seen_events[eid] = 1;

            a = audit_event_of(ev);
            row = project(a);
            obs = Observation(**row);
            here +>:Observes:+> obs;

            ts = int(row["ts_ms"]);
            ident = self.ensure_identity(here, str(row["principal_id"]),
                                         str(row["actor_tenant_id"]),
                                         str(row["actor_role"]), ts);
            sess = self.ensure_session(here, str(row["session_id"]),
                                       str(row["client_fp"]), ts);
            src = self.ensure_source(here, str(row["src_ip"]), str(row["src_asn"]),
                                     str(row["client_fp"]), ts);
            asset = self.ensure_asset(here, str(row["target_kind"]),
                                      str(row["target_id"]),
                                      str(row["target_sensitivity"]));
            svc = self.ensure_service(here, str(row["service"]));

            ident +>:PerformedBy:+> obs;
            obs +>:InSession:+> sess;
            if src is not None {
                obs +>:FromSource:+> src;
            }
            if asset is not None {
                obs +>:Targeted:+> asset;
            }
            if svc is not None {
                obs +>:Via:+> svc;
            }

            # Attacker-influenced text goes to the quarantine subgraph, which no
            # scorer can reach: there is no edge from Observation to Quarantine.
            for q in quarantine_of(a) {
                here +>:Quarantined:+> Quarantine(**q);
            }

            # Subject clustering. Session is the anchor; principal and client
            # fingerprint are merged into it.
            skey = "S|" + str(row["session_id"]);
            uf_find(here.cluster_parent, skey);
            if str(row["principal_id"]) != "" {
                uf_union(here.cluster_parent, skey, "P|" + str(row["principal_id"]));
            }
            if str(row["client_fp"]) != "" {
                uf_union(here.cluster_parent, skey, "F|" + str(row["client_fp"]));
            }

            here.n_ingested += 1;
            self.ingested += 1;
        }
        here.n_duplicates += self.duplicates;
        here.n_rejected += self.rejected;
        self.link_fingerprints(here);
    }

    def ensure_identity(g: IncidentGraph, pid: str, tenant: str, role: str,
                        ts: int) -> Identity {
        key = "I|" + pid + "|" + tenant;
        if key in g.idx {
            n = cast(Identity, g.idx[key]);
            n.last_ts_ms = ts;
            return n;
        }
        n = Identity(principal_id=pid, tenant_id=tenant, role=role,
                     first_ts_ms=ts, last_ts_ms=ts);
        g +>:Knows:+> n;
        g.idx[key] = n;
        return n;
    }

    def ensure_session(g: IncidentGraph, sid: str, fp: str, ts: int) -> Session {
        key = "S|" + sid;
        if key in g.idx {
            n = cast(Session, g.idx[key]);
            n.last_ts_ms = ts;
            return n;
        }
        n = Session(session_id=sid, client_fp=fp, first_ts_ms=ts, last_ts_ms=ts);
        g +>:Knows:+> n;
        g.idx[key] = n;
        return n;
    }

    def ensure_source(g: IncidentGraph, ip: str, asn: str, fp: str,
                      ts: int) -> Source | None {
        if ip == "" {
            return None;
        }
        key = "R|" + ip;
        if key in g.idx {
            n = cast(Source, g.idx[key]);
            n.last_ts_ms = ts;
            return n;
        }
        n = Source(src_ip=ip, src_asn=asn, client_fp=fp, first_ts_ms=ts,
                   last_ts_ms=ts);
        g +>:Knows:+> n;
        g.idx[key] = n;
        return n;
    }

    def ensure_asset(g: IncidentGraph, kind: str, aid: str,
                     sensitivity: str) -> Asset | None {
        if aid == "" {
            return None;
        }
        key = "A|" + kind + "|" + aid;
        if key in g.idx {
            return cast(Asset, g.idx[key]);
        }
        n = Asset(kind=kind, asset_id=aid, sensitivity=sensitivity);
        g +>:Knows:+> n;
        g.idx[key] = n;
        return n;
    }

    def ensure_service(g: IncidentGraph, name: str) -> Service | None {
        if name == "" {
            return None;
        }
        key = "V|" + name;
        if key in g.idx {
            return cast(Service, g.idx[key]);
        }
        n = Service(name=name);
        g +>:Knows:+> n;
        g.idx[key] = n;
        return n;
    }

    """One fingerprint seen from several addresses is the SharesFingerprint
    relation; one fingerprint used by several principals is PivotedTo. Both are
    materialised as edges so a responder can walk them, rather than being
    recomputed inside a scorer."""
    def link_fingerprints(g: IncidentGraph) -> None {
        by_fp_src = {};
        by_fp_ident = {};
        for o in [g ->:Observes:-> Observation] {
            fp = o.client_fp;
            if fp == "" {
                continue;
            }
            if o.src_ip != "" {
                if fp not in by_fp_src {
                    by_fp_src[fp] = {};
                }
                by_fp_src[fp][o.src_ip] = 1;
            }
            if o.principal_id != "" {
                if fp not in by_fp_ident {
                    by_fp_ident[fp] = {};
                }
                ident_key: str = str(o.principal_id) + "|" + str(o.actor_tenant_id);
                by_fp_ident[fp][ident_key] = 1;
            }
        }
        for fp in sorted(list(by_fp_src.keys())) {
            ips = sorted(list(by_fp_src[fp].keys()));
            i = 1;
            while i < len(ips) {
                a = cast(Source, g.idx["R|" + str(ips[i - 1])]);
                b = cast(Source, g.idx["R|" + str(ips[i])]);
                a +>:SharesFingerprint:+> b;
                i += 1;
            }
        }
        for fp in sorted(list(by_fp_ident.keys())) {
            ids = sorted(list(by_fp_ident[fp].keys()));
            i = 1;
            while i < len(ids) {
                a = cast(Identity, g.idx["I|" + str(ids[i - 1])]);
                b = cast(Identity, g.idx["I|" + str(ids[i])]);
                a +>:PivotedTo:+> b;
                i += 1;
            }
        }
    }
}


# --------------------------------------------------------------------------
# Correlate
# --------------------------------------------------------------------------

"""Slide the window, score the seven families, write a Signal per firing family.

Windows advance on a single global time grid so two subjects are always compared
over the same interval. Baselines are read BEFORE the window is folded into
them, so a window is never scored against a baseline that already contains it."""
walker Correlate {
    has window_ms: int = WINDOW_MS;
    has step_ms: int = STEP_MS;
    has min_window_events: int = 3;
    has signals_emitted: int = 0;
    has windows_scored: int = 0;
    has trace: list = [];        # one entry per scored window, for tests/Explain

    can run with IncidentGraph entry {
        by_subject = rows_by_subject(here);
        if len(by_subject) == 0 {
            return;
        }
        t_min = -1;
        t_max = -1;
        for k in by_subject.keys() {
            rows = by_subject[k];
            a = int(rows[0]["ts_ms"]);
            b = int(rows[len(rows) - 1]["ts_ms"]);
            if t_min < 0 or a < t_min {
                t_min = a;
            }
            if t_max < 0 or b > t_max {
                t_max = b;
            }
        }

        subjects = sorted(list(by_subject.keys()));
        w_end = t_min + self.window_ms;
        while w_end <= t_max + self.step_ms {
            w_start = w_end - self.window_ms;
            for skey in subjects {
                self.score_window(here, skey, by_subject[skey], w_start, w_end);
            }
            w_end += self.step_ms;
        }
    }

    def score_window(g: IncidentGraph, subject_key: str, all_rows: list,
                     w_start: int, w_end: int) -> None {
        window = [];
        prior = set();
        for r in all_rows {
            ts = int(r["ts_ms"]);
            if ts <= w_start {
                t = str(r.get("target_id", ""));
                if t != "" {
                    prior.add(t);
                }
            } elif ts <= w_end {
                window.append(r);
            }
        }
        if len(window) < self.min_window_events {
            return;
        }

        principal = "";
        tenant = "";
        for r in window {
            if principal == "" and str(r.get("principal_id", "")) != "" {
                principal = str(r["principal_id"]);
            }
            if tenant == "" and str(r.get("actor_tenant_id", "")) != "" {
                tenant = str(r["actor_tenant_id"]);
            }
        }
        chain = scope_chain(principal, tenant, subject_key);

        f = extract(window, w_start, w_end, prior);
        scores = score_all(
            f,
            resolve_stat(g, chain, "deny_ratio"),
            resolve_stat(g, chain, "deny_reasons"),
            resolve_stat(g, chain, "d_target_id"),
            resolve_stat(g, chain, "d_target_kind"),
            resolve_stat(g, chain, "route_entropy"),
            NOVELTY_MIN_PRIOR
        );

        fired = [];
        for s in scores {
            if not s.fired {
                continue;
            }
            ev_rows = evidence_rows(s.family, window, prior);
            ids = [];
            for r in ev_rows {
                ids.append(str(r["event_id"]));
            }
            sig = Signal(
                family=s.family, axis=s.axis, score=s.score,
                window_start_ms=w_start, window_end_ms=w_end,
                subject_key=subject_key,
                join_keys=join_keys_of(ev_rows),
                evidence=ids,
                detail=s.detail
            );
            g +>:Emitted:+> sig;
            self.signals_emitted += 1;
            fired.append(s.family);
        }

        self.windows_scored += 1;
        self.trace.append({
            "subject": subject_key, "window_end_ms": w_end,
            "n_events": f.n_events, "fired": sorted(fired),
            "total_result_count": f.total_result_count
        });

        # Learn only after scoring, so this window never informs its own baseline.
        learn(g, chain, {
            "deny_ratio": f.deny_ratio,
            "deny_reasons": float(f.n_deny_reasons),
            "d_target_id": float(f.d_target_id),
            "d_target_kind": float(f.d_target_kind),
            "route_entropy": f.route_entropy
        });
    }
}


# --------------------------------------------------------------------------
# Promote
# --------------------------------------------------------------------------

"""Apply the gate to each window's Signals and merge qualifying windows into one
Incident per subject.

Merging rather than re-raising is the difference between an incident and an
alert storm: the campaign in the golden fixture qualifies in several separate
windows as it moves through its stages, and a responder needs one case file that
grew, not five alerts to correlate by hand."""
walker Promote {
    has theta_override: float = -1.0;   # < 0 keeps gate.THETA; used by the sweep test
    # Ablation knob. Setting this False removes the {denial_shape, pivot,
    # escalation} requirement, which is how tests demonstrate what that clause is
    # and is not doing. Production never sets it.
    has require_mandatory: bool = True;
    has promoted: int = 0;
    has evaluated: int = 0;
    has rejected: list = [];            # (subject, window_end, failed clauses)

    can run with IncidentGraph entry {
        groups = {};
        for sig in [here ->:Emitted:-> Signal] {
            key: str = str(sig.subject_key) + "@" + str(sig.window_end_ms);
            if key not in groups {
                groups[key] = [];
            }
            groups[key].append(sig);
        }
        by_subject_rows = rows_by_subject(here);

        for key in sorted(list(groups.keys())) {
            sigs: list[Signal] = [];
            for raw_sig in list(groups[key]) {
                sigs.append(cast(Signal, raw_sig));
            }
            scores: list[FamilyScore] = [];
            fjk = {};
            evidence = set();
            subject_key = "";
            w_start = 0;
            w_end = 0;
            for sig in sigs {
                subject_key = sig.subject_key;
                w_start = sig.window_start_ms;
                w_end = sig.window_end_ms;
                scores.append(FamilyScore(family=sig.family, axis=sig.axis,
                                          score=sig.score, fired=True,
                                          detail=sig.detail));
                fjk[sig.family] = sig.join_keys;
                for e in sig.evidence {
                    evidence.add(str(e));
                }
            }
            verdict = evaluate(scores, fjk);
            if not self.require_mandatory {
                kept = [];
                for c in verdict.failed {
                    if c != "no_denial_pivot_or_escalation" {
                        kept.append(c);
                    }
                }
                verdict.failed = kept;
                verdict.promote = len(kept) == 0;
            }
            if self.theta_override >= 0.0 {
                # Re-decide the aggregate clause only; every structural clause
                # stands. This exists so a test can sweep THETA and demonstrate
                # it is not the discriminator.
                failed = [];
                for c in verdict.failed {
                    if c != "aggregate<theta" {
                        failed.append(c);
                    }
                }
                if verdict.aggregate < self.theta_override {
                    failed.append("aggregate<theta");
                }
                verdict.failed = failed;
                verdict.promote = len(failed) == 0;
            }
            self.evaluated += 1;
            if not verdict.promote {
                self.rejected.append({"subject": subject_key, "window_end_ms": w_end,
                                      "families": verdict.families,
                                      "axes": verdict.axes,
                                      "aggregate": verdict.aggregate,
                                      "failed": verdict.failed});
                continue;
            }
            self.merge(here, subject_key, w_start, w_end, verdict, sorted(list(evidence)),
                       sigs, by_subject_rows.get(subject_key, []));
            self.promoted += 1;
        }
    }

    def merge(g: IncidentGraph, subject_key: str, w_start: int, w_end: int,
              verdict: GateVerdict, evidence: list, sigs: list[Signal],
              subject_rows: list) -> None {
        key = "N|" + subject_key;
        inc: Incident | None = None;
        if key in g.idx {
            inc = cast(Incident, g.idx[key]);
        } else {
            first_ts = w_start;
            if len(subject_rows) > 0 {
                first_ts = int(subject_rows[0]["ts_ms"]);
            }
            inc = Incident(incident_id=incident_id_for(subject_key, first_ts),
                           subject_key=subject_key, state="open",
                           first_ts_ms=first_ts, last_ts_ms=w_end);
            g +>:Raised:+> inc;
            g.idx[key] = inc;
        }

        fams = set(inc.families);
        for x in verdict.families {
            fams.add(str(x));
        }
        inc.families = sorted(list(fams));

        axes = set(inc.axes);
        for x in verdict.axes {
            axes.add(str(x));
        }
        inc.axes = sorted(list(axes));

        ev = set(inc.evidence);
        for x in evidence {
            ev.add(str(x));
        }
        inc.evidence = sorted(list(ev));

        if w_end > inc.last_ts_ms {
            inc.last_ts_ms = w_end;
        }
        inc.window_count += 1;
        if verdict.aggregate > inc.peak_score {
            inc.peak_score = verdict.aggregate;
        }
        c = confidence_of(verdict);
        if c > inc.confidence {
            inc.confidence = c;
        }

        jk = dict(inc.join_keys);
        for k in verdict.shared_join_keys {
            jk[str(k)] = 1;
        }
        inc.join_keys = jk;

        # Stage signatures over the incident's own evidence only.
        cited = set(inc.evidence);
        cited_rows = [];
        for r in subject_rows {
            if str(r["event_id"]) in cited {
                cited_rows.append(r);
            }
        }
        inc.stage_signatures = signatures(cited_rows);

        for sig in sigs {
            inc +>:Supports:+> sig;
        }
    }
}


# --------------------------------------------------------------------------
# Explain
# --------------------------------------------------------------------------

"""The responder-facing account of an incident: what fired, when, and which
attack stages the behaviour matched.

Every string it emits is monitor-authored — stage names come from the closed
STAGE_NAMES table and family names from the closed family enum. No attacker text
reaches this walker; the quarantine subgraph is the emitter's business, not
Explain's."""
walker Explain {
    has incident_id: str = "";
    has found: bool = False;
    has summary: str = "";
    has timeline: list = [];
    has signal_timeline: list = [];
    has stages_seen: list = [];
    has families: list = [];
    has axes: list = [];
    has evidence_count: int = 0;

    can run with IncidentGraph entry {
        target: Incident | None = None;
        for inc in [here ->:Raised:-> Incident] {
            if self.incident_id == "" or inc.incident_id == self.incident_id {
                target = inc;
                break;
            }
        }
        if target is None {
            return;
        }
        inc_t: Incident = cast(Incident, target);
        self.found = True;
        self.families = list(inc_t.families);
        self.axes = list(inc_t.axes);
        self.stages_seen = list(inc_t.stage_signatures);
        self.evidence_count = len(inc_t.evidence);

        by_subject = rows_by_subject(here);
        rows: list = list(by_subject.get(inc_t.subject_key, []));
        cited: set[str] = set();
        for e in inc_t.evidence {
            cited.add(str(e));
        }

        # Stage timeline: the first event that evidenced each stage, in order.
        seen_stages = set();
        for r in rows {
            if str(r["event_id"]) not in cited {
                continue;
            }
            upto = [];
            for r2 in rows {
                if int(r2["ts_ms"]) <= int(r["ts_ms"]) and str(r2["event_id"]) in cited {
                    upto.append(r2);
                }
            }
            for s in signatures(upto) {
                if s in seen_stages {
                    continue;
                }
                seen_stages.add(s);
                self.timeline.append({
                    "stage": s,
                    "stage_name": stage_name(int(s)),
                    "ts_ms": int(r["ts_ms"]),
                    "event_id": str(r["event_id"]),
                    "action": str(r["action"]),
                    "outcome": str(r["outcome"]),
                    "reason": str(r["reason"])
                });
            }
        }

        for sig in [inc_t ->:Supports:-> Signal] {
            self.signal_timeline.append({
                "window_end_ms": sig.window_end_ms,
                "family": sig.family,
                "axis": sig.axis,
                "score": sig.score,
                "n_evidence": len(list(sig.evidence))
            });
        }
        st_by_key = {};
        for x in self.signal_timeline {
            kk = str(int(x["window_end_ms"])).zfill(20) + "|" + str(x["family"]);
            st_by_key[kk] = x;
        }
        ordered_signals = [];
        for kk in sorted(list(st_by_key.keys())) {
            ordered_signals.append(st_by_key[kk]);
        }
        self.signal_timeline = ordered_signals;

        names = [];
        for s in self.stages_seen {
            names.append(stage_name(int(s)));
        }
        self.summary = (
            "Correlated " + str(len(self.families)) + " detection families across "
            + str(len(self.axes)) + " behavioural axes over "
            + str(int((inc_t.last_ts_ms - inc_t.first_ts_ms) / 1000)) + "s: "
            + ", ".join(self.families) + ". Stages evidenced: " + ", ".join(names) + "."
        );
    }
}
