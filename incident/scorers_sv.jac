# incident/scorers_sv.jac — the seven detection families.
#
# (Mandated path `incident/scorers.sv.jac` is a symlink to this file. A dotted filename is not
#  importable in Jac -- `scorers.sv.jac` parses as package `scorers`, module `sv` -- so the
#  undotted name is the real module, matching the convention in contracts/.)
#
# CONTRACT FOR EVERY SCORER IN THIS FILE:
#   * Pure. Same (obs, ctx) in -> same dict out. No I/O, no clock, no global mutation.
#   * Reads ONLY the Observation projection (incident/projection.jac), which by construction
#     contains no free text. `actor_email` and `route` do not exist in the input at all, so no
#     scorer can branch on them -- injection resistance is structural, not a code-review promise.
#   * Every string it does touch (session_id, client_fp, src_ip, asset_hash, endpoint_class) is
#     used ONLY through equality, set membership, and counting. Never substring, never regex,
#     never compared to a literal that an event could contain.
#
# Each returns: {family, axis, score(0..1), fired, detail, evidence[event_id], join_keys[]}

import math;
import from incident.tables { FAMILY_AXIS, is_authz_deny }
import from incident.baselines { z_for, BUCKET_MS }

# Per-family firing thresholds. Structural, not tuned: each is the point at which the family's
# own components say "this is not ordinary", independent of any other family.
glob:pub FIRE: dict = {
    "denial_shape": 0.50,
    "breadth": 0.50,
    "novelty": 0.60,
    "cadence": 0.60,
    "pivot": 0.40,
    "escalation": 0.45,
    "canary": 0.99
};

# Minimum support for novelty. Not a tuning dial: they are the point below which the ratio has
# no statistical meaning at all.
glob:pub MIN_NOVELTY_ASSETS: int = 4;    # distinct targets in the window
glob:pub MIN_NOVELTY_PRIOR: int = 8;     # distinct targets the principal touched before it
glob:pub MIN_NOVELTY_NOVEL: int = 3;     # distinct never-seen targets inside it


# ------------------------------------------------------------------ shared pure helpers ----

def clamp01(x: float) -> float {
    return max(0.0, min(1.0, x));
}

def norm_z(z: float, cap: float) -> float {
    return clamp01(max(z, 0.0) / cap);
}

def ids(rows: list) -> list {
    out = [];
    for r in rows {
        out.append(r["event_id"]);
    }
    return out;
}

def subject_keys(rows: list) -> list {
    # Correlation keys the evidence actually carries. The unauthenticated sentinel is NEVER
    # emitted as a principal key -- "anon" is a placeholder, not an entity, and joining on it
    # would fuse unrelated anonymous traffic into one imaginary actor.
    keys = {};
    for r in rows {
        if r["authenticated"] == 1 {
            keys["principal:" + r["principal_hash"]] = 1;
        }
        if r["session_id"] != "" {
            keys["session:" + r["session_id"]] = 1;
        }
        if r["client_fp"] != "" {
            keys["fp:" + r["client_fp"]] = 1;
        }
    }
    return sorted(list(keys.keys()));
}

def asset_keys(rows: list) -> list {
    keys = {};
    for r in rows {
        if r["has_target"] == 1 {
            keys["asset:" + r["asset_hash"]] = 1;
        }
    }
    return sorted(list(keys.keys()));
}

def distinct(rows: list, field: str) -> list {
    seen = {};
    for r in rows {
        v = r[field];
        if v != "" {
            seen[v] = 1;
        }
    }
    return sorted(list(seen.keys()));
}

def group_count(rows: list, key_field: str, value_field: str) -> dict {
    # key -> sorted list of distinct values. Used by pivot for its span computations.
    acc = {};
    for r in rows {
        k = r[key_field];
        v = r[value_field];
        if k == "" or v == "" {
            continue;
        }
        acc.setdefault(k, {})[v] = 1;
    }
    out = {};
    for k in sorted(list(acc.keys())) {
        out[k] = sorted(list(acc[k].keys()));
    }
    return out;
}

def bucket_peaks(rows: list) -> dict {
    # Peak per-minute distinct-asset and distinct-kind counts inside the window. Comparing a
    # per-minute peak against a per-minute-bucket baseline keeps the units honest.
    buckets = {};
    for r in rows {
        b = r["ts_ms"] // BUCKET_MS;
        cell = buckets.setdefault(b, {"assets": {}, "kinds": {}, "n": 0});
        cell["n"] += 1;
        if r["has_target"] == 1 {
            cell["assets"][r["asset_hash"]] = 1;
        }
        if r["target_kind"] != "" {
            cell["kinds"][r["target_kind"]] = 1;
        }
    }
    pa = 0;
    pk = 0;
    pn = 0;
    for b in sorted(list(buckets.keys())) {
        pa = max(pa, len(buckets[b]["assets"]));
        pk = max(pk, len(buckets[b]["kinds"]));
        pn = max(pn, buckets[b]["n"]);
    }
    return {"assets": pa, "kinds": pk, "events": pn};
}

def result(family: str, score: float, detail: dict, evidence: list, join_keys: list) -> dict {
    s = clamp01(score);
    return {
        "family": family,
        "axis": FAMILY_AXIS[family],
        "score": round(s, 4),
        "fired": s >= FIRE[family],
        "detail": detail,
        "evidence": evidence,
        "join_keys": join_keys
    };
}


# ------------------------------------------------------------------ 1. denial_shape --------
# Axis: identity. Deny RATIO and the count of DISTINCT deny reason codes, both against the
# principal's own EWMA baseline. A workload with zero denials scores exactly 0 and can never
# fire -- there is no threshold at which "no denials" becomes denial-shaped.

def score_denial_shape(obs: list, ctx: dict) -> dict {
    n = len(obs);
    if n == 0 {
        return result("denial_shape", 0.0, {"events": 0}, [], []);
    }
    denies = [];
    reasons = {};
    for r in obs {
        if r["outcome"] == "deny" {
            denies.append(r);
            if r["reason"] != "" {
                reasons[r["reason"]] = 1;
            }
        }
    }
    d = len(denies);
    k = len(reasons);
    if d == 0 {
        return result("denial_shape", 0.0, {"events": n, "denies": 0, "reason_codes": 0}, [], []);
    }
    ratio = float(d) / float(n);
    z = z_for(ctx["store"], ctx["primary_principal"], ctx["primary_tenant"], "deny_ratio", ratio);
    ratio_c = clamp01(ratio / 0.25);              # a quarter of requests denied saturates
    reason_c = clamp01(float(max(k - 1, 0)) / 2.0);  # >= 3 distinct codes saturates
    z_c = norm_z(z, 3.0);
    score = 0.40 * ratio_c + 0.40 * reason_c + 0.20 * z_c;
    # Structural floor: one-off denials with a single cause are ordinary operation.
    if d < 2 or k < 2 {
        score = min(score, FIRE["denial_shape"] - 0.01);
    }
    detail = {"events": n, "denies": d, "deny_ratio": round(ratio, 4), "reason_codes": k,
              "reasons": sorted(list(reasons.keys())), "z_deny_ratio": round(z, 3)};
    return result("denial_shape", score, detail, ids(denies), subject_keys(denies));
}


# ------------------------------------------------------------------ 2. breadth -------------
# Axis: asset. Distinct target_id and distinct target_kind per minute, z-scored against the
# principal's own EWMA. This is the family the bulk importer is DESIGNED to trip; it is here to
# be insufficient on its own.

def score_breadth(obs: list, ctx: dict) -> dict {
    if len(obs) == 0 {
        return result("breadth", 0.0, {}, [], []);
    }
    peaks = bucket_peaks(obs);
    z_a = z_for(ctx["store"], ctx["primary_principal"], ctx["primary_tenant"],
                "distinct_assets", float(peaks["assets"]));
    z_k = z_for(ctx["store"], ctx["primary_principal"], ctx["primary_tenant"],
                "distinct_kinds", float(peaks["kinds"]));
    score = 0.60 * norm_z(z_a, 3.0) + 0.40 * norm_z(z_k, 2.0);
    targeted = [];
    for r in obs {
        if r["has_target"] == 1 {
            targeted.append(r);
        }
    }
    detail = {"peak_distinct_assets": peaks["assets"], "peak_distinct_kinds": peaks["kinds"],
              "z_assets": round(z_a, 3), "z_kinds": round(z_k, 3),
              "window_distinct_assets": len(distinct(obs, "asset_hash"))};
    return result("breadth", score, detail, ids(targeted),
                  subject_keys(obs) + asset_keys(targeted));
}


# ------------------------------------------------------------------ 3. novelty -------------
# Axis: asset. Fraction of the window's targets this principal has never touched before the
# window opened. A stable path set (the bulk importer re-reading the same 27 objects) scores ~0
# no matter how many times it reads them.

def score_novelty(obs: list, ctx: dict) -> dict {
    win_assets = {};
    rows = [];
    for r in obs {
        if r["has_target"] == 1 {
            win_assets[r["asset_hash"]] = 1;
            rows.append(r);
        }
    }
    total = len(win_assets);
    prior = ctx["prior_assets"];             # {asset_hash: 1}, first-seen strictly before window
    prior_n = len(prior);
    # Minimum support. "Never touched before" is meaningless for a principal with no history,
    # and a 1-of-2 novel ratio is noise, not discovery.
    if total < MIN_NOVELTY_ASSETS or prior_n < MIN_NOVELTY_PRIOR {
        return result("novelty", 0.0, {"window_assets": total, "prior_assets": prior_n,
                                       "cold": True}, [], []);
    }
    novel = [];
    for a in sorted(list(win_assets.keys())) {
        if a not in prior {
            novel.append(a);
        }
    }
    if len(novel) < MIN_NOVELTY_NOVEL {
        return result("novelty", 0.0, {"window_assets": total, "prior_assets": prior_n,
                                       "novel_assets": len(novel), "cold": False}, [], []);
    }
    frac = float(len(novel)) / float(total);
    novel_rows = [];
    for r in rows {
        if r["asset_hash"] not in prior {
            novel_rows.append(r);
        }
    }
    detail = {"window_assets": total, "prior_assets": prior_n, "novel_assets": len(novel),
              "novel_fraction": round(frac, 4), "cold": False};
    return result("novelty", frac, detail, ids(novel_rows),
                  subject_keys(novel_rows) + asset_keys(novel_rows));
}


# ------------------------------------------------------------------ 4. cadence -------------
# Axis: time. Inter-arrival stdev/mean (low = machine-driven) plus endpoint-class transition
# entropy (low = a script walking a fixed loop). Deliberately volume-blind: it says "automated",
# never "malicious". The bulk importer scores high here and that is correct.

def score_cadence(obs: list, ctx: dict) -> dict {
    n = len(obs);
    if n < 6 {
        return result("cadence", 0.0, {"events": n, "too_few": True}, [], []);
    }
    deltas = [];
    i = 1;
    while i < n {
        d = obs[i]["ts_ms"] - obs[i - 1]["ts_ms"];
        # Idle gaps between bursts are not cadence. 30 s is the human think-time ceiling used by
        # the fixture; above it the two events are not part of one rhythm.
        if d >= 0 and d <= 30000 {
            deltas.append(float(d));
        }
        i += 1;
    }
    if len(deltas) < 5 {
        return result("cadence", 0.0, {"events": n, "deltas": len(deltas), "too_few": True}, [], []);
    }
    mean = sum(deltas) / float(len(deltas));
    if mean <= 0.0 {
        return result("cadence", 0.0, {"events": n, "degenerate": True}, [], []);
    }
    acc = 0.0;
    for d in deltas {
        acc += (d - mean) * (d - mean);
    }
    sd = math.sqrt(acc / float(len(deltas)));
    cv = sd / mean;
    regularity = clamp01(1.0 - cv);

    # transition entropy over the ENUM-DERIVED endpoint class (never over raw `route`)
    trans = {};
    i = 1;
    while i < n {
        t = obs[i - 1]["endpoint_class"] + ">" + obs[i]["endpoint_class"];
        trans[t] = trans.get(t, 0) + 1;
        i += 1;
    }
    tot = float(n - 1);
    h = 0.0;
    for t in sorted(list(trans.keys())) {
        p = float(trans[t]) / tot;
        h -= p * math.log(p);
    }
    hmax = math.log(max(tot, 2.0));
    norm_h = clamp01(h / hmax);
    score = 0.60 * regularity + 0.40 * (1.0 - norm_h);
    detail = {"events": n, "deltas": len(deltas), "mean_ms": round(mean, 1),
              "cv": round(cv, 4), "regularity": round(regularity, 4),
              "distinct_transitions": len(trans), "norm_entropy": round(norm_h, 4)};
    return result("cadence", score, detail, ids(obs), subject_keys(obs));
}


# ------------------------------------------------------------------ 5. pivot ---------------
# Axis: source/session. One session_id or client_fp seen across >= 2 src_ip or >= 2 ASN, or one
# source seen driving >= 2 distinct AUTHENTICATED principals. Only counts authenticated
# principals: "anonymous traffic then a login from the same IP" is what every normal sign-in
# looks like, and treating it as a pivot would fire on the whole user base.

def score_pivot(obs: list, ctx: dict) -> dict {
    if len(obs) == 0 {
        return result("pivot", 0.0, {}, [], []);
    }
    sess_ip = group_count(obs, "session_id", "src_ip");
    fp_ip = group_count(obs, "client_fp", "src_ip");
    sess_asn = group_count(obs, "session_id", "src_asn");
    fp_asn = group_count(obs, "client_fp", "src_asn");

    auth_rows = [];
    for r in obs {
        if r["authenticated"] == 1 {
            auth_rows.append(r);
        }
    }
    ip_prin = group_count(auth_rows, "src_ip", "principal_hash");
    fp_prin = group_count(auth_rows, "client_fp", "principal_hash");

    ip_span = 0;
    span_key = "";
    for g in [sess_ip, fp_ip] {
        for k in sorted(list(g.keys())) {
            if len(g[k]) > ip_span {
                ip_span = len(g[k]);
                span_key = k;
            }
        }
    }
    asn_span = 0;
    for g in [sess_asn, fp_asn] {
        for k in sorted(list(g.keys())) {
            asn_span = max(asn_span, len(g[k]));
        }
    }
    prin_span = 0;
    for g in [ip_prin, fp_prin] {
        for k in sorted(list(g.keys())) {
            prin_span = max(prin_span, len(g[k]));
        }
    }
    score = 0.0;
    if ip_span >= 2 or asn_span >= 2 or prin_span >= 2 {
        score = clamp01(0.34 * float(ip_span - 1) + 0.34 * float(max(asn_span - 1, 0))
                        + 0.50 * float(max(prin_span - 1, 0)));
        score = max(score, 0.40);         # any confirmed multiplexing is at least a fire
    }
    ev = [];
    if span_key != "" {
        for r in obs {
            if r["session_id"] == span_key or r["client_fp"] == span_key {
                ev.append(r);
            }
        }
    }
    if len(ev) == 0 {
        ev = obs;
    }
    detail = {"ip_span": ip_span, "asn_span": asn_span, "principal_span": prin_span,
              "distinct_src_ips": len(distinct(obs, "src_ip")),
              "distinct_client_fp": len(distinct(obs, "client_fp"))};
    return result("pivot", score, detail, ids(ev), subject_keys(ev));
}


# ------------------------------------------------------------------ 6. escalation ----------
# Axis: identity. Monotonic climb in required-role rank and/or target_sensitivity rank of the
# attempts made AFTER the first denial. Denials are the precondition: with none, the post-deny
# sequence is empty and the score is 0 by construction.

def score_escalation(obs: list, ctx: dict) -> dict {
    n = len(obs);
    first_deny = -1;
    n_deny = 0;
    i = 0;
    while i < n {
        if obs[i]["outcome"] == "deny" {
            if first_deny < 0 {
                first_deny = i;
            }
            n_deny += 1;
        }
        i += 1;
    }
    if first_deny < 0 {
        return result("escalation", 0.0, {"denies": 0, "no_denials": True}, [], []);
    }
    pre_role = 0;
    pre_sens = 0;
    i = 0;
    while i < first_deny {
        pre_role = max(pre_role, obs[i]["role_rank"]);
        pre_sens = max(pre_sens, obs[i]["sens_rank"]);
        i += 1;
    }
    post = [];
    i = first_deny;
    while i < n {
        post.append(obs[i]);
        i += 1;
    }
    post_role = pre_role;
    post_sens = pre_sens;
    bumps = 0;
    climbing = [];
    run_level = pre_role + 2 * pre_sens;
    for r in post {
        lvl = r["role_rank"] + 2 * r["sens_rank"];
        if lvl > run_level {
            bumps += 1;
            run_level = lvl;
            climbing.append(r);
        }
        post_role = max(post_role, r["role_rank"]);
        post_sens = max(post_sens, r["sens_rank"]);
    }
    role_climb = max(0, post_role - pre_role);
    sens_climb = max(0, post_sens - pre_sens);
    score = 0.0;
    if (role_climb >= 1 or sens_climb >= 1) and n_deny >= 2 {
        score = clamp01(0.30 * float(role_climb) + 0.35 * float(sens_climb)
                        + 0.15 * float(bumps));
    }
    ev = climbing;
    if len(ev) == 0 {
        ev = post;
    }
    detail = {"denies": n_deny, "pre_role_rank": pre_role, "post_role_rank": post_role,
              "pre_sens_rank": pre_sens, "post_sens_rank": post_sens,
              "role_climb": role_climb, "sens_climb": sens_climb, "monotonic_bumps": bumps};
    return result("escalation", score, detail, ids(ev), subject_keys(ev));
}


# ------------------------------------------------------------------ 7. canary --------------
# Axis: asset. Any touch of a canary-sensitivity object. Binary by design: a canary exists only
# to be untouched, so there is no "a little bit of canary".

def score_canary(obs: list, ctx: dict) -> dict {
    hits = [];
    for r in obs {
        if r["target_sensitivity"] == "canary" {
            hits.append(r);
        }
    }
    if len(hits) == 0 {
        return result("canary", 0.0, {"canary_touches": 0}, [], []);
    }
    detail = {"canary_touches": len(hits),
              "canary_assets": len(distinct(hits, "asset_hash")),
              "denied": len([r for r in hits if r["outcome"] == "deny"])};
    return result("canary", 1.0, detail, ids(hits), subject_keys(hits) + asset_keys(hits));
}


# ------------------------------------------------------------------ dispatcher -------------

def score_all(obs: list, ctx: dict) -> list {
    return [
        score_denial_shape(obs, ctx),
        score_breadth(obs, ctx),
        score_novelty(obs, ctx),
        score_cadence(obs, ctx),
        score_pivot(obs, ctx),
        score_escalation(obs, ctx),
        score_canary(obs, ctx)
    ];
}
