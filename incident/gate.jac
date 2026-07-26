# incident/gate.jac — THE PROMOTION GATE.
#
#   Promote iff, inside one 10-minute sliding window:
#     (1) >= 3 DISTINCT families fired
#     (2) spanning >= 2 DISTINCT axes
#     (3) sharing >= 1 join key across every fired signal
#     (4) aggregate score >= theta
#     (5) at least one of {denial_shape, pivot, escalation} is among them
#
# Clause (5) is what carries the negative control, not theta. A legitimate high-volume workload
# fires breadth (asset axis) and cadence (time axis) and nothing else: it has no denials, so
# denial_shape is 0 and escalation's post-denial sequence is empty; it runs one principal from
# one source, so every pivot span is 1. Those three zeros are structural, not threshold-relative
# -- see tests/test_theta_not_load_bearing (theta = 0.0 and the bulk importer is still silent).

import hashlib;
import from incident.tables { MANDATORY_FAMILIES, is_authz_deny, LIST_ACTIONS }

glob:pub WINDOW_MS: int = 600000;          # the 10-minute sliding window
glob:pub THETA: float = 1.80;              # see module docstring: NOT load-bearing

glob:pub AUTH_ACTIONS: list = ["auth.register", "auth.login", "auth.login_failed", "auth.logout",
                               "auth.session_expired", "auth.token_issued", "auth.token_revoked",
                               "auth.reauth_required"];


def intersect_keys(sigs: list) -> list {
    # Join keys common to EVERY fired signal. Non-empty means the families are talking about one
    # entity rather than coincidental neighbours in the same window.
    if len(sigs) == 0 {
        return [];
    }
    common = {};
    for k in sigs[0]["join_keys"] {
        common[k] = 1;
    }
    i = 1;
    while i < len(sigs) {
        nxt = {};
        for k in sigs[i]["join_keys"] {
            if k in common {
                nxt[k] = 1;
            }
        }
        common = nxt;
        i += 1;
    }
    return sorted(list(common.keys()));
}


def evaluate(signals: list, theta: float) -> dict {
    fired = [];
    for s in signals {
        if s["fired"] {
            fired.append(s);
        }
    }
    fams = {};
    axes = {};
    agg = 0.0;
    for s in fired {
        fams[s["family"]] = 1;
        axes[s["axis"]] = 1;
        agg += s["score"];
    }
    families = sorted(list(fams.keys()));
    axis_list = sorted(list(axes.keys()));
    shared = intersect_keys(fired);
    mandatory = [];
    for f in families {
        if f in MANDATORY_FAMILIES {
            mandatory.append(f);
        }
    }
    clauses = {
        "families_ge_3": len(families) >= 3,
        "axes_ge_2": len(axis_list) >= 2,
        "shared_join_key": len(shared) >= 1,
        "aggregate_ge_theta": agg >= theta,
        "mandatory_member": len(mandatory) >= 1
    };
    promote = True;
    for c in sorted(list(clauses.keys())) {
        if not clauses[c] {
            promote = False;
        }
    }
    return {
        "promote": promote,
        "clauses": clauses,
        "families": families,
        "axes": axis_list,
        "mandatory": mandatory,
        "shared_join_keys": shared,
        "aggregate": round(agg, 4),
        "theta": theta,
        "fired": fired
    };
}


def confidence(verdict: dict, n_stages: int) -> float {
    c = (0.30 + 0.08 * float(len(verdict["families"]))
         + 0.05 * float(len(verdict["axes"]))
         + 0.06 * float(len(verdict["mandatory"]))
         + 0.01 * float(n_stages));
    return round(min(0.98, max(0.0, c)), 4);
}


def incident_id(subject: str, window_end_ms: int) -> str {
    raw = subject + "|" + str(window_end_ms);
    return "inc_" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[0:16];
}


# ---------------------------------------------------------------- stage signatures ---------
# Which of the ten authorized-scenario steps the evidence shows. Derived ONLY from closed enums
# and timestamps -- no labels file, no free text, no per-fixture special cases.

def stage_signatures(obs: list) -> list {
    stages = {};
    n = len(obs);
    recon = 0;
    sprays = 0;
    authz_denies = 0;
    logins_ok = 0;
    token_issued = 0;
    lists_ok = [];
    sess_ip = {};
    for r in obs {
        if r["authenticated"] == 0 and r["action"] not in AUTH_ACTIONS {
            recon += 1;
        }
        if r["action"] == "auth.login_failed" {
            sprays += 1;
        }
        if r["action"] == "auth.login" and r["outcome"] == "allow" {
            logins_ok += 1;
        }
        if r["action"] == "auth.token_issued" and r["outcome"] == "allow" {
            token_issued += 1;
        }
        if r["outcome"] == "deny" and is_authz_deny(r["reason"]) {
            authz_denies += 1;
        }
        if r["action"] in LIST_ACTIONS and r["outcome"] == "allow" {
            lists_ok.append(r);
        }
        if r["session_id"] != "" and r["src_ip"] != "" {
            sess_ip.setdefault(r["session_id"], {})[r["src_ip"]] = 1;
        }
        if r["sens_rank"] == 1 {
            stages[8] = 1;
        }
        if r["sens_rank"] == 2 {
            stages[10] = 1;
        }
        if r["action"] == "integration.call" and (r["tenant_cross"] == 1
                                                  or r["reason"] == "TENANT_MISMATCH") {
            stages[9] = 1;
        }
    }
    if recon >= 2 {
        stages[1] = 1;
    }
    if sprays >= 3 {
        stages[2] = 1;
    }
    if sprays >= 3 and logins_ok >= 1 and token_issued >= 1 {
        stages[3] = 1;
    }
    if len(lists_ok) >= 3 {
        gaps = [];
        i = 1;
        while i < len(lists_ok) {
            gaps.append(lists_ok[i]["ts_ms"] - lists_ok[i - 1]["ts_ms"]);
            i += 1;
        }
        fast = 0;
        for g in gaps {
            if g <= 5000 {
                fast += 1;
            }
        }
        if fast >= 2 {
            stages[4] = 1;
        }
    }
    if authz_denies >= 2 {
        stages[5] = 1;
    }
    i = 1;
    while i < n {
        prev = obs[i - 1];
        cur = obs[i];
        if (prev["outcome"] == "deny" and (cur["ts_ms"] - prev["ts_ms"]) <= 1000
                and cur["endpoint_class"] != prev["endpoint_class"]) {
            stages[6] = 1;
        }
        i += 1;
    }
    for s in sorted(list(sess_ip.keys())) {
        if len(sess_ip[s]) >= 2 {
            stages[7] = 1;
        }
    }
    return sorted(list(stages.keys()));
}
