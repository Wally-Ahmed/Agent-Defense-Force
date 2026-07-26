# incident/features.jac — window -> numbers.
#
# The scorers take a WindowFeatures and nothing else. Every field on it is an
# int, a float or a bool, which is what makes "scorers are pure functions over
# enum and numeric fields only" a property the type checker enforces rather than
# a claim in a comment: there is no string on the object for a scorer to read,
# so no route, email or user agent can reach one even by accident.
#
# This module does read string-typed fields off the Observation projections, but
# only opaque identifiers (target_id, session_id, client_fp, src_ip, src_asn)
# and closed enums (outcome, reason, target_sensitivity, target_kind). It
# compares and counts them; it never parses or interprets them. Raw `route` and
# `actor_email` never reach here at all — projection.jac dropped them.

import math;

# Inter-arrival runs shorter than this cannot say anything about regularity;
# three gaps of similar length happen constantly in human traffic.
glob:pub CADENCE_RUN: int = 5;

# A window with fewer events than this is not evidence of anything.
glob:pub MIN_WINDOW_EVENTS: int = 3;

# Novelty is meaningless until a principal has a habit to depart from.
glob:pub NOVELTY_MIN_PRIOR: int = 5;


obj WindowFeatures {
    has window_start_ms: int = 0;
    has window_end_ms: int = 0;
    has n_events: int = 0;

    # denial shape
    has n_deny: int = 0;
    has deny_ratio: float = 0.0;
    has n_deny_reasons: int = 0;

    # breadth
    has d_target_id: int = 0;
    has d_target_kind: int = 0;

    # novelty
    has prior_targets: int = 0;
    has novelty_frac: float = 0.0;

    # cadence
    has iat_cv_min: float = -1.0;      # -1.0 == undefined (too few gaps)
    has route_entropy: float = 0.0;
    has d_route_class: int = 0;

    # pivot
    has max_ips_per_identifier: int = 1;
    has max_asns_per_identifier: int = 1;
    has max_principals_per_source: int = 1;
    has d_src_ip: int = 0;

    # escalation
    has escalation_delta: int = 0;
    has n_cross_tenant: int = 0;

    # canary
    has n_canary: int = 0;

    # volume, carried for the record and deliberately NOT scored on its own
    has total_result_count: int = 0;
}


"""Arithmetic mean, 0.0 for an empty list."""
def mean_of(xs: list) -> float {
    if len(xs) == 0 {
        return 0.0;
    }
    total = 0.0;
    for x in xs {
        total += float(x);
    }
    return total / float(len(xs));
}


"""Population standard deviation."""
def stdev_of(xs: list) -> float {
    if len(xs) < 2 {
        return 0.0;
    }
    m = mean_of(xs);
    acc = 0.0;
    for x in xs {
        d = float(x) - m;
        acc += d * d;
    }
    return math.sqrt(acc / float(len(xs)));
}


"""Smallest coefficient of variation over any run of `k` consecutive gaps.

Whole-window CV is the wrong statistic for "is this automated": a script that
fires five batches ten minutes apart has an enormous whole-window CV and a tiny
within-batch one. Taking the minimum over sliding runs asks the question that
matters — was there ever a stretch where the timing was machine-regular —
instead of averaging that stretch away. Returns -1.0 when there are too few
gaps to say."""
def min_rolling_cv(gaps: list, k: int) -> float {
    if len(gaps) < k {
        return -1.0;
    }
    best = -1.0;
    i = 0;
    while i + k <= len(gaps) {
        run = gaps[i:(i + k)];
        m = mean_of(run);
        if m > 0.0 {
            cv = stdev_of(run) / m;
            if best < 0.0 or cv < best {
                best = cv;
            }
        }
        i += 1;
    }
    return best;
}


"""Shannon entropy in bits of the transitions between consecutive labels.

Labels here are opaque route classes. High entropy means the actor almost never
repeats a transition — scripted breadth-first exploration. Low entropy means a
short repeated cycle, which is what a paginating report looks like."""
def transition_entropy(labels: list) -> float {
    if len(labels) < 2 {
        return 0.0;
    }
    counts = {};
    total = 0;
    i = 1;
    while i < len(labels) {
        key = str(labels[i - 1]) + ">" + str(labels[i]);
        counts[key] = int(counts.get(key, 0)) + 1;
        total += 1;
        i += 1;
    }
    h = 0.0;
    for k in counts.keys() {
        p = float(counts[k]) / float(total);
        h -= p * math.log2(p);
    }
    return h;
}


"""Distinct non-empty values of one field across the window."""
def distinct(rows: list, field: str) -> int {
    seen = set();
    for r in rows {
        v = r.get(field, "");
        if v != "" {
            seen.add(v);
        }
    }
    return len(seen);
}


"""Largest number of distinct `value_field`s seen under any single non-empty
`key_field` — the shape of "one session across many addresses"."""
def max_fanout(rows: list, key_field: str, value_field: str) -> int {
    groups = {};
    for r in rows {
        k = r.get(key_field, "");
        v = r.get(value_field, "");
        if k == "" or v == "" {
            continue;
        }
        if k not in groups {
            groups[k] = set();
        }
        groups[k].add(v);
    }
    best = 1;
    for k in groups.keys() {
        n = len(groups[k]);
        if n > best {
            best = n;
        }
    }
    return best;
}


"""Climb in what the actor reaches for, measured strictly AFTER the first denial.

The ordering is the whole point. Everyone touches a confidential document
sometimes; what distinguishes probing is being told no and then reaching
*higher* rather than retrying or stopping. Ranks come from the closed
sensitivity and target-kind enums (projection.asset_rank), so this is a
comparison of two small integers, never of text."""
def escalation_after_deny(rows: list) -> int {
    first_deny = -1;
    i = 0;
    while i < len(rows) {
        if rows[i].get("outcome", "") == "deny" {
            first_deny = i;
            break;
        }
        i += 1;
    }
    if first_deny < 0 {
        return 0;
    }
    pre = 0;
    j = 0;
    while j <= first_deny {
        r = int(rows[j].get("asset_rank", 0));
        if r > pre {
            pre = r;
        }
        j += 1;
    }
    post = 0;
    j = first_deny + 1;
    while j < len(rows) {
        r = int(rows[j].get("asset_rank", 0));
        if r > post {
            post = r;
        }
        j += 1;
    }
    d = post - pre;
    return d if d > 0 else 0;
}


"""Everything the seven scorers are allowed to see, computed from one window.

`rows` must be the subject's Observation projections inside the window, in
timestamp order. `prior_target_ids` is the set of target ids the subject touched
strictly before the window opened — novelty is measured against that, so
overlapping windows cannot launder a target into "already seen"."""
def extract(rows: list, window_start_ms: int, window_end_ms: int,
            prior_target_ids: set) -> WindowFeatures {
    f = WindowFeatures(window_start_ms=window_start_ms, window_end_ms=window_end_ms);
    f.n_events = len(rows);
    if len(rows) == 0 {
        return f;
    }

    denies = 0;
    reasons = set();
    targets = set();
    canaries = 0;
    crossings = 0;
    rows_total = 0;
    gaps = [];
    classes = [];
    prev_ts = -1;
    for r in rows {
        if r.get("outcome", "") == "deny" {
            denies += 1;
            rs = r.get("reason", "");
            if rs != "" {
                reasons.add(rs);
            }
        }
        t = r.get("target_id", "");
        if t != "" {
            targets.add(t);
        }
        if r.get("target_sensitivity", "") == "canary" {
            canaries += 1;
        }
        if r.get("cross_tenant", False) {
            crossings += 1;
        }
        rows_total += int(r.get("result_count", 0));
        ts = int(r.get("ts_ms", 0));
        if prev_ts >= 0 {
            gaps.append(float(ts - prev_ts));
        }
        prev_ts = ts;
        classes.append(r.get("route_class", ""));
    }

    f.n_deny = denies;
    f.deny_ratio = float(denies) / float(len(rows));
    f.n_deny_reasons = len(reasons);
    f.d_target_id = len(targets);
    f.d_target_kind = distinct(rows, "target_kind");

    f.prior_targets = len(prior_target_ids);
    if len(targets) > 0 {
        fresh = 0;
        for t in targets {
            if t not in prior_target_ids {
                fresh += 1;
            }
        }
        f.novelty_frac = float(fresh) / float(len(targets));
    }

    f.iat_cv_min = min_rolling_cv(gaps, CADENCE_RUN);
    f.route_entropy = transition_entropy(classes);
    f.d_route_class = distinct(rows, "route_class");

    ip_by_session = max_fanout(rows, "session_id", "src_ip");
    ip_by_fp = max_fanout(rows, "client_fp", "src_ip");
    f.max_ips_per_identifier = ip_by_session if ip_by_session > ip_by_fp else ip_by_fp;
    asn_by_session = max_fanout(rows, "session_id", "src_asn");
    asn_by_fp = max_fanout(rows, "client_fp", "src_asn");
    f.max_asns_per_identifier = asn_by_session if asn_by_session > asn_by_fp else asn_by_fp;
    f.max_principals_per_source = max_fanout(rows, "src_ip", "principal_id");
    f.d_src_ip = distinct(rows, "src_ip");

    f.escalation_delta = escalation_after_deny(rows);
    f.n_cross_tenant = crossings;
    f.n_canary = canaries;
    f.total_result_count = rows_total;
    return f;
}
