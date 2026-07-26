# incident/baseline.jac — per-principal and per-tenant EWMA baselines.
#
# WHY THE BASELINE IS PER-PRINCIPAL FIRST.
# The bulk reporting integration in the golden fixture returns ~69x more rows
# than the campaign does. Any detector that scores raw volume against a global
# mean flags it and misses the attack. Scoring against the *principal's own*
# EWMA inverts that: a naturally chatty account has a high mean and a wide band,
# so its ordinary Tuesday is a z of ~0, while a quiet service account that
# suddenly enumerates is several sigma out on numbers a global model would call
# small.
#
# WHY THERE IS A TENANT SCOPE TOO.
# A principal seen for the first time has no history, and "no history" must not
# mean "no baseline", or every new account would be either invisible or
# instantly anomalous. Scoring falls outward — principal, then tenant, then
# global — to the narrowest scope that is warm.
#
# WHY THE BASELINE IS NOT GUARDED AGAINST ANOMALIES.
# It is tempting to refuse to learn from windows that already look anomalous, so
# an attacker cannot slowly retrain their own baseline. Measured on the fixture
# that guard does more harm than good: a legitimately chatty account whose first
# two windows happen to be quiet can never afterwards establish its true level,
# because every window that would teach the baseline its real magnitude is
# rejected as anomalous. That is precisely the bulk importer's failure mode, and
# it is the opposite of what a per-principal baseline is for. The EWMA therefore
# learns unconditionally with a deliberately slow alpha (0.10, an effective
# memory of ~19 windows), which no single burst can move far.

import math;

# EWMA smoothing factor. 0.10 ~= a 19-sample memory: fast enough to track a
# principal that genuinely changes shape over an hour, far too slow for a
# ten-minute burst to retrain.
glob:pub EWMA_ALPHA: float = 0.10;

# A scope is warm once it has this many samples. Below it the scope is skipped
# and scoring falls outward.
glob:pub MIN_SAMPLES: int = 3;

# The single z-to-score constant, applied identically to every z-scored family.
# score = clamp(z / Z_FULL), so a family fires (score >= 0.5) at z >= 2.0 — the
# ~97.7th percentile of a normal — and saturates at z >= 4.0. One constant, not
# seven, so no family can be quietly tuned relative to the others.
glob:pub Z_FULL: float = 4.0;
glob:pub FIRE_THRESHOLD: float = 0.5;

# Relative floor on the standard deviation. Without it a metric that has been
# constant so far has std 0 and every subsequent value is infinitely anomalous;
# a single deny in an account that has never denied would saturate the score.
glob:pub STD_REL_FLOOR: float = 0.05;


# A resolved baseline: the numbers a scorer is allowed to compare against, plus
# whether the scope that produced them had enough history to be believed.
obj Stat {
    has mean: float = 0.0;
    has var: float = 0.0;
    has n: int = 0;
    has warm: bool = False;
    has scope: str = "";
}


"""Clamp to the unit interval. Every family score is expressed here."""
def clamp01(x: float) -> float {
    if x < 0.0 {
        return 0.0;
    }
    if x > 1.0 {
        return 1.0;
    }
    return x;
}


"""Map a z-score to a family score. The one place a deviation becomes evidence."""
def z_to_score(z: float) -> float {
    return clamp01(z / Z_FULL);
}


"""Fold one observation into an EWMA mean/variance pair.

Returns the updated triple as a dict so the caller can write it back onto a
Baseline node without this module needing to know about the graph. The first
sample seeds the mean and leaves the variance at zero — the STD_REL_FLOOR is
what keeps that from producing an infinite z on sample two."""
def ewma_update(mean: float, var: float, n: int, x: float) -> dict {
    if n <= 0 {
        return {"mean": x, "var": 0.0, "n": 1};
    }
    d = x - mean;
    new_mean = mean + EWMA_ALPHA * d;
    new_var = (1.0 - EWMA_ALPHA) * (var + EWMA_ALPHA * d * d);
    return {"mean": new_mean, "var": new_var, "n": n + 1};
}


"""Standard deviation with the relative floor already applied."""
def floored_std(mean: float, var: float) -> float {
    std = math.sqrt(var) if var > 0.0 else 0.0;
    ref = abs(mean) if abs(mean) > 1.0 else 1.0;
    floor = STD_REL_FLOOR * ref;
    return std if std > floor else floor;
}


"""How many standard deviations x sits above this baseline."""
def zscore(x: float, mean: float, var: float) -> float {
    return (x - mean) / floored_std(mean, var);
}


"""Scope keys to try, narrowest first, for a principal in a tenant.

A subject with no authenticated principal (pre-auth reconnaissance) is keyed by
its own subject cluster instead, so it is still measured against itself rather
than collapsing into an anonymous global bucket."""
def scope_chain(principal_id: str, tenant_id: str, subject_key: str) -> list {
    chain = [];
    if principal_id != "" {
        chain.append("P|" + principal_id);
    } else {
        chain.append("S|" + subject_key);
    }
    if tenant_id != "" {
        chain.append("T|" + tenant_id);
    }
    chain.append("G|*");
    return chain;
}
