# incident/baselines.jac — per-principal AND per-tenant EWMA baselines.
#
# Why per-principal: a naturally chatty account (the bulk reporting integration) accumulates a
# HIGH mean, so its own volume stops being a deviation after a couple of buckets. That is the
# mechanism that keeps volume-derived families from carrying an incident on their own.
#
# Learning unit: a TUMBLING 60 s bucket, epoch-aligned. Sliding 600 s windows overlap ~99 %, so
# learning from every sliding window would drive the EWMA mean onto the current value and every
# z-score to ~0. Tumbling buckets keep the baseline independent of the window being scored.
#
# Ordering: SCORE, THEN LEARN. A window is always scored against baseline state built strictly
# from buckets that closed before it, so a window can never explain itself away.

import math;

glob:pub BUCKET_MS: int = 60000;
glob:pub ALPHA: float = 0.25;
glob:pub MIN_N: int = 3;                 # below this a scope is "cold" and yields no z-score

# Per-metric noise floor for the z denominator. Prevents a scope with a near-zero observed
# variance (a perfectly regular workload) from producing an infinite z on its first wobble.
glob:pub STD_FLOOR: dict = {
    "deny_ratio": 0.05,
    "distinct_assets": 1.0,
    "distinct_kinds": 0.5,
    "events": 2.0
};


def bucket_of(ts_ms: int) -> int {
    return ts_ms // BUCKET_MS;
}


def principal_scope(principal_hash: str) -> str {
    return "principal:" + principal_hash;
}


def tenant_scope(tenant_id: str) -> str {
    return "tenant:" + tenant_id;
}


def new_state() -> dict {
    return {"mean": 0.0, "var": 0.0, "n": 0};
}


def learn(state: dict, x: float) -> dict {
    # Incremental EWMA mean + EWMA variance (West's form). Deterministic, order-dependent by
    # design -- events are consumed in ts_ms order, so the order is fixed by the input.
    if state["n"] == 0 {
        return {"mean": x, "var": 0.0, "n": 1};
    }
    delta = x - state["mean"];
    mean = state["mean"] + ALPHA * delta;
    var = (1.0 - ALPHA) * (state["var"] + ALPHA * delta * delta);
    return {"mean": mean, "var": var, "n": state["n"] + 1};
}


def zscore(state: dict, metric: str, x: float) -> float {
    if state["n"] < MIN_N {
        return 0.0;                      # cold scope: no opinion, never a signal
    }
    floor = STD_FLOOR.get(metric, 1.0);
    std = math.sqrt(max(state["var"], 0.0));
    if std < floor {
        std = floor;
    }
    return (x - state["mean"]) / std;
}


def lookup(store: dict, scope_key: str, metric: str) -> dict {
    return store.get(scope_key + "|" + metric, new_state());
}


def observe(store: dict, scope_key: str, metric: str, x: float) -> dict {
    k = scope_key + "|" + metric;
    store[k] = learn(store.get(k, new_state()), x);
    return store;
}


def z_for(store: dict, principal_hash: str, tenant_id: str, metric: str, x: float) -> float {
    # Per-principal first. Fall back to the tenant baseline while the principal is cold --
    # that is what makes a brand-new high-volume principal measurable at all, and it is why the
    # bulk importer's FIRST batch registers as breadth while its later batches do not.
    ps = lookup(store, principal_scope(principal_hash), metric);
    if ps["n"] >= MIN_N {
        return zscore(ps, metric, x);
    }
    ts = lookup(store, tenant_scope(tenant_id), metric);
    return zscore(ts, metric, x);
}
