# incident/gate.jac — the promotion gate.
#
# THE RULE.
#   Create an Incident iff, within a 10-minute sliding window:
#     >= 3 distinct families fire,
#     spanning >= 2 distinct axes,
#     sharing >= 1 join key (principal, session, source or asset),
#     aggregate score >= THETA,
#     and at least one of {denial_shape, pivot, escalation} is among them.
#
# WHY THE MANDATORY MEMBER IS THE LOAD-BEARING CLAUSE.
# The other four families measure *volume and variety*: breadth, novelty,
# cadence and canary all describe how much and how oddly an account moved. A
# legitimate high-throughput integration is, by construction, high volume and
# high variety — the golden fixture's bulk importer returns 69x more rows than
# the campaign does, and on the fixture it does fire three of those families in
# one window with an aggregate above THETA. What it never does is get told no,
# rotate its source, or climb after a refusal. Those three are the families that
# describe *friction with the authorization system*, and friction is the thing a
# legitimate integration does not generate. Requiring one of them is what makes
# the benign case pass cleanly without a rate limit, a volume exemption, or a
# named allowlist entry.
#
# WHY THE JOIN KEY IS INTERSECTED, NOT ASSUMED.
# Families firing in the same ten minutes are a coincidence unless they are
# about the same thing. The gate intersects the join keys of the events each
# firing family actually cited, so "denial_shape and pivot fired" only counts
# when the denials and the rotation share a principal, a session, a source or an
# asset — not merely a clock.
#
# ON THETA. See THETA's comment: it is a structural floor, and it is measurably
# not the discriminator on the golden fixture.

import from incident.baseline { FIRE_THRESHOLD }

glob:pub WINDOW_MS: int = 600000;   # 10-minute sliding window
glob:pub STEP_MS: int = 60000;      # advanced one minute at a time

glob:pub MIN_FAMILIES: int = 3;
glob:pub MIN_AXES: int = 2;
glob:pub MANDATORY_FAMILIES: list = ["denial_shape", "pivot", "escalation"];

# THETA is the aggregate (sum of firing family scores) floor.
#
# Chosen structurally, before running the fixture: the weakest configuration the
# family/axis rules allow is three families at the bare fire threshold, summing
# to 1.5. THETA = 2.0 excludes exactly that case — it says three families is not
# enough if all three are marginal; at least one of them must be at full
# strength. It is not derived from any measured value in the fixture.
#
# It is also, on this fixture, not the discriminator. Sweeping THETA from 0.0 to
# 3.0 changes nothing about which populations promote: the campaign promotes at
# every value in that range and the bulk importer and the benign users promote
# at none of them, because they are stopped by the family, axis and mandatory
# member rules long before the aggregate is consulted. That is the intended
# design — the gate is structural, and THETA is a floor under it, not the thing
# doing the work. tests/test_golden.jac asserts this sweep so the property
# cannot silently rot into a tuned threshold.
glob:pub THETA: float = 2.0;


obj GateVerdict {
    has promote: bool = False;
    has families: list = [];        # firing family names, sorted
    has axes: list = [];            # distinct axes, sorted
    has aggregate: float = 0.0;
    has mandatory: list = [];       # which of the mandatory three fired
    has shared_join_keys: list = [];
    has failed: list = [];          # which clauses failed, for Explain
}


"""Apply the gate to one window's FamilyScores.

`family_join_keys` maps a family name to the join keys of the events that family
cited. Only firing families are considered, in every clause."""
def evaluate(scores: list, family_join_keys: dict) -> GateVerdict {
    v = GateVerdict();
    fired = [];
    axes = set();
    agg = 0.0;
    mandatory = [];
    shared: set[str] = set();
    first = True;

    for s in scores {
        if not s.fired {
            continue;
        }
        fired.append(s.family);
        axes.add(s.axis);
        agg += s.score;
        if s.family in MANDATORY_FAMILIES {
            mandatory.append(s.family);
        }
        keys: set[str] = set();
        raw: list = list(family_join_keys.get(s.family, []));
        for k in raw {
            keys.add(str(k));
        }
        if first {
            shared = keys;
            first = False;
        } else {
            shared = shared & keys;
        }
    }

    v.families = sorted(fired);
    v.axes = sorted(list(axes));
    v.aggregate = agg;
    v.mandatory = sorted(mandatory);
    v.shared_join_keys = sorted(list(shared));

    failed = [];
    if len(fired) < MIN_FAMILIES {
        failed.append("families<" + str(MIN_FAMILIES));
    }
    if len(axes) < MIN_AXES {
        failed.append("axes<" + str(MIN_AXES));
    }
    if len(shared) < 1 {
        failed.append("no_shared_join_key");
    }
    if agg < THETA {
        failed.append("aggregate<theta");
    }
    if len(mandatory) < 1 {
        failed.append("no_denial_pivot_or_escalation");
    }
    v.failed = failed;
    v.promote = len(failed) == 0;
    return v;
}


"""Monitor confidence for a promoted window.

Deliberately conservative and bounded: it grows with how many independent
families and axes agreed, not with how loud any one of them was, because a
single family screaming is exactly the shape of a false positive. Capped below
1.0 — a correlation engine that reports certainty is lying."""
def confidence_of(v: GateVerdict) -> float {
    if not v.promote {
        return 0.0;
    }
    base = 0.40;
    base += 0.07 * float(len(v.families) - MIN_FAMILIES + 1);
    base += 0.05 * float(len(v.axes) - MIN_AXES + 1);
    base += 0.04 * float(len(v.mandatory));
    if base > 0.97 {
        base = 0.97;
    }
    return float(int(base * 10000.0)) / 10000.0;
}
