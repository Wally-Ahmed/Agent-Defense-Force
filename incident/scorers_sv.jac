# incident/scorers.jac — the seven detection families.
#
# NOTE ON THE FILENAME. The specification names this file `scorers.sv.jac`, and
# that path exists — as a symlink to this one. A dotted Jac filename is not
# importable: Jac resolves imports through Python module paths, so
# `scorers.sv.jac` parses as package `scorers`, module `sv`. This is the same
# constraint that renamed the frozen contracts to undotted names.
#
# The underscore spelling is load-bearing, not cosmetic. Naming the real module
# `scorers.jac` and aliasing `scorers.sv.jac` beside it sends jaclang 0.13.5's
# parser into unbounded recursion — `jac check` and `jac test` both die with
# RecursionError — because the resolver tries to descend into the `scorers`
# module looking for a `sv` submodule. With the real module spelled
# `scorers_sv.jac` there is no such module to descend into and the alias is
# inert. Import `incident.scorers_sv`; never import through the dotted path.
#
# EVERY SCORER IS A PURE FUNCTION OF NUMBERS.
# The only inputs are a WindowFeatures (int/float/bool fields exclusively) and
# resolved baseline Stats. That is not a style preference: `route` and
# `actor_email` in the audit stream carry attacker-authored text, and the golden
# fixture ships live prompt-injection payloads in both. A scorer that read a
# string would be a scorer an attacker could write. The type signature is the
# boundary — there is no string on WindowFeatures to read.
#
# ONE SHARED SENSITIVITY, NOT SEVEN.
# Each z-scored family converts its deviation with the same z_to_score: fires at
# z >= 2, saturates at z >= 4. Families that are structural rather than
# statistical (pivot, escalation, canary) express the same 0.5 fire point in
# their own units, and the mapping is stated in each docstring. Nothing here has
# a per-family constant that could be nudged to make one fixture pass.
#
# | family       | axis     | metric                                              |
# |--------------|----------|-----------------------------------------------------|
# | denial_shape | identity | deny ratio AND distinct deny reason codes, vs base   |
# | breadth      | asset    | distinct target_id and target_kind, z-scored         |
# | novelty      | asset    | fraction of targets never touched by this principal  |
# | cadence      | time     | min rolling inter-arrival CV + route-transition H    |
# | pivot        | source   | one session/fp over >=2 ips or asns, or one source   |
# |              |          | over >=2 principals                                  |
# | escalation   | identity | climb in sensitivity/authority AFTER a denial        |
# | canary       | asset    | any target_sensitivity == "canary"                   |

import from incident.features { WindowFeatures }
import from incident.baseline { Stat, zscore, z_to_score, clamp01, FIRE_THRESHOLD }
import from incident.projection { FAMILY_AXIS }

# Coefficient of variation below which a run of inter-arrivals is not human.
# Human think-time in the fixture never produces a 5-gap run under 0.42; a
# scheduler's jitter lands near 0.08. 0.30 sits in that gap and is a statement
# about how hands work, not a number fitted to this file.
glob:pub CADENCE_CV_FLOOR: float = 0.30;

# Escalation is measured in asset-rank steps, where a full sensitivity step
# (normal -> confidential) is 2 and merely reaching a privileged target kind is
# 1. Dividing by 4 puts the fire point at exactly one sensitivity step: being
# denied and then reaching for a *more sensitive class* of thing. Touching a
# privileged kind after a denial, on its own, is half a signal.
glob:pub ESCALATION_FULL_STEPS: float = 4.0;

# Pivot fires at two distinct addresses (or ASNs, or principals) under one
# identifier and saturates at three.
glob:pub PIVOT_FULL_FANOUT: float = 2.0;


obj FamilyScore {
    has family: str = "";
    has axis: str = "";
    has score: float = 0.0;
    has fired: bool = False;
    has detail: dict = {};
}


"""Assemble a FamilyScore, deriving the axis from the closed family->axis map so
a family can never be filed under an axis it does not belong to."""
def _mk(family: str, score: float, detail: dict) -> FamilyScore {
    s = clamp01(score);
    return FamilyScore(
        family=family,
        axis=str(FAMILY_AXIS.get(family, "")),
        score=s,
        fired=s >= FIRE_THRESHOLD,
        detail=detail
    );
}


"""denial_shape (identity) — being told no, in several different ways.

Deny RATIO alone is a retry detector: a benign client that fails once and tries
the same call again produces a spike of one reason code. Counting DISTINCT deny
reason codes is what separates that from probing, which collects NO_SESSION,
INSUFFICIENT_ROLE, NOT_A_MEMBER, TENANT_MISMATCH and REAUTH_REQUIRED on the way
through a permission boundary. Both are scored against the same baseline and
averaged, so a high ratio with one reason code cannot fire this family alone."""
def denial_shape(f: WindowFeatures, ratio_stat: Stat, reasons_stat: Stat) -> FamilyScore {
    if not ratio_stat.warm or not reasons_stat.warm {
        return _mk("denial_shape", 0.0, {"cold": 1.0});
    }
    z_ratio = zscore(f.deny_ratio, ratio_stat.mean, ratio_stat.var);
    z_reasons = zscore(float(f.n_deny_reasons), reasons_stat.mean, reasons_stat.var);
    score = 0.5 * (z_to_score(z_ratio) + z_to_score(z_reasons));
    return _mk("denial_shape", score, {
        "deny_ratio": f.deny_ratio,
        "n_deny": float(f.n_deny),
        "n_deny_reasons": float(f.n_deny_reasons),
        "z_deny_ratio": z_ratio,
        "z_deny_reasons": z_reasons
    });
}


"""breadth (asset) — how much of the estate one actor touched.

Distinct target ids and distinct target kinds, both z-scored against the
principal's own baseline. Per-principal is what makes this survive the bulk
importer: 27 distinct targets is enormous for a person and unremarkable for the
reporting job that does it every window."""
def breadth(f: WindowFeatures, id_stat: Stat, kind_stat: Stat) -> FamilyScore {
    if not id_stat.warm or not kind_stat.warm {
        return _mk("breadth", 0.0, {"cold": 1.0});
    }
    z_id = zscore(float(f.d_target_id), id_stat.mean, id_stat.var);
    z_kind = zscore(float(f.d_target_kind), kind_stat.mean, kind_stat.var);
    score = 0.5 * (z_to_score(z_id) + z_to_score(z_kind));
    return _mk("breadth", score, {
        "d_target_id": float(f.d_target_id),
        "d_target_kind": float(f.d_target_kind),
        "z_d_target_id": z_id,
        "z_d_target_kind": z_kind
    });
}


"""novelty (asset) — the fraction of targets this principal has never touched.

Expressed as the fraction itself, so it fires when at least half of what the
actor reached for in this window is new to them. Suppressed entirely until the
principal has touched NOVELTY_MIN_PRIOR distinct targets: before that, every
target is new by definition and the metric would flag every account's first ten
minutes. Prior targets are those seen strictly BEFORE the window opened, so
overlapping windows cannot launder a fresh target into a familiar one."""
def novelty(f: WindowFeatures, min_prior: int) -> FamilyScore {
    if f.prior_targets < min_prior {
        return _mk("novelty", 0.0, {"cold": 1.0, "prior_targets": float(f.prior_targets)});
    }
    return _mk("novelty", f.novelty_frac, {
        "novelty_frac": f.novelty_frac,
        "prior_targets": float(f.prior_targets),
        "d_target_id": float(f.d_target_id)
    });
}


"""cadence (time) — timing that is not a person, or exploration that is not work.

Two independent tells, scored as whichever is stronger. Regularity: the
tightest run of five consecutive inter-arrivals in the window; below
CADENCE_CV_FLOOR nobody is typing. Route-transition entropy: how unpredictable
the next endpoint class is given the last one, z-scored against baseline — a
scripted sweep almost never repeats a transition, while real work and paginated
reporting both cycle."""
def cadence(f: WindowFeatures, entropy_stat: Stat) -> FamilyScore {
    regularity = 0.0;
    if f.iat_cv_min >= 0.0 {
        regularity = clamp01((CADENCE_CV_FLOOR - f.iat_cv_min) / CADENCE_CV_FLOOR);
    }
    entropy_score = 0.0;
    z_h = 0.0;
    if entropy_stat.warm {
        z_h = zscore(f.route_entropy, entropy_stat.mean, entropy_stat.var);
        entropy_score = z_to_score(z_h);
    }
    score = regularity if regularity > entropy_score else entropy_score;
    return _mk("cadence", score, {
        "iat_cv_min": f.iat_cv_min,
        "regularity": regularity,
        "route_entropy": f.route_entropy,
        "z_route_entropy": z_h,
        "d_route_class": float(f.d_route_class)
    });
}


"""pivot (source/session) — one actor wearing several addresses, or one address
wearing several actors.

Purely structural: no baseline can help here, because the first time a session
appears from two networks is exactly the event of interest. Fires at a fanout of
two under a single session id or client fingerprint, which is the shape of
source rotation that keeps a stolen session alive across a blocklist."""
def pivot(f: WindowFeatures) -> FamilyScore {
    ip_score = clamp01(float(f.max_ips_per_identifier - 1) / PIVOT_FULL_FANOUT);
    asn_score = clamp01(float(f.max_asns_per_identifier - 1) / PIVOT_FULL_FANOUT);
    prin_score = clamp01(float(f.max_principals_per_source - 1) / PIVOT_FULL_FANOUT);
    score = ip_score;
    if asn_score > score {
        score = asn_score;
    }
    if prin_score > score {
        score = prin_score;
    }
    return _mk("pivot", score, {
        "max_ips_per_identifier": float(f.max_ips_per_identifier),
        "max_asns_per_identifier": float(f.max_asns_per_identifier),
        "max_principals_per_source": float(f.max_principals_per_source),
        "d_src_ip": float(f.d_src_ip)
    });
}


"""escalation (identity) — reaching higher after being refused.

Requires a denial in the window: a rising sensitivity gradient with no refusals
is somebody's ordinary promotion to more interesting work. What is scored is the
gap between the highest asset rank reached before the first denial and the
highest reached after it, so the order of events, not their contents, is the
evidence."""
def escalation(f: WindowFeatures) -> FamilyScore {
    if f.n_deny <= 0 {
        return _mk("escalation", 0.0, {"n_deny": 0.0});
    }
    score = clamp01(float(f.escalation_delta) / ESCALATION_FULL_STEPS);
    return _mk("escalation", score, {
        "escalation_delta": float(f.escalation_delta),
        "n_deny": float(f.n_deny),
        "n_cross_tenant": float(f.n_cross_tenant)
    });
}


"""canary (asset) — a resource that exists only to be touched by the wrong person.

There is no baseline and no ratio. A canary has no legitimate reader, so one
touch is the whole signal."""
def canary(f: WindowFeatures) -> FamilyScore {
    hit = 1.0 if f.n_canary > 0 else 0.0;
    return _mk("canary", hit, {"n_canary": float(f.n_canary)});
}


"""Run all seven families over one window. Returns FamilyScores in a fixed order
so two runs over the same input produce byte-identical output."""
def score_all(f: WindowFeatures,
              s_deny_ratio: Stat, s_deny_reasons: Stat,
              s_d_target_id: Stat, s_d_target_kind: Stat,
              s_route_entropy: Stat, novelty_min_prior: int) -> list[FamilyScore] {
    return [
        denial_shape(f, s_deny_ratio, s_deny_reasons),
        breadth(f, s_d_target_id, s_d_target_kind),
        novelty(f, novelty_min_prior),
        cadence(f, s_route_entropy),
        pivot(f),
        escalation(f),
        canary(f)
    ];
}
