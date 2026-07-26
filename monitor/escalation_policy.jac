# =============================================================================
# monitor/escalation_policy.jac  —  NORMATIVE escalation/detection policy
# =============================================================================
#
# WHY THIS RULE IS IN JAC
# -----------------------
# The project thesis is *enforceable Jac policy*: the things that decide what
# happens to a principal are written in Jac, where they can be read, reviewed and
# frozen as a unit — not scattered through glue code. Escalation is a policy
# decision (it is what turns behaviour into an incident that responders act on),
# so the rule lives here and ONLY here. `monitor/detect.py` is a transport: it
# serialises frames to this process' stdin and parses incidents from its stdout.
# It contains no thresholds, no predicates, and no fallback re-implementation —
# if `jac` cannot run, the driver raises. There is exactly one implementation of
# the escalation rule and it is this file.
#
# VOLUME IS DELIBERATELY NEVER A SIGNATURE
# ----------------------------------------
# Not one of the ten stage signatures can fire because an actor was *busy*.
# `req` and `export_bytes` appear in exactly ONE predicate (S8 value_discovery),
# and there only in conjunction with novelty (new_endpoints_first_seen >= 1) AND
# friction (deny_ratio > 0) AND a warmed-up per-actor baseline. `req` itself is
# only ever read as a liveness guard (req > 0 in S3). A `result_count` feature
# does not exist in window.v1 and is not consulted. Consequence, asserted by
# test: a bulk importer moving 250 KB/window escalates nothing, and the SAME
# importer at 3x volume (39 req, 750 KB/window) still escalates nothing. Loud is
# not the same as hostile; every trigger below is about SHAPE — novelty, denial
# shape, breadth, cadence, pivot speed, escalation surface, canary contact.
#
# WHAT THIS FILE MAY NOT DO
# -------------------------
#   * No hard-coded "attack" flag. `canary_touch` is a property of the RESOURCE
#     (a synthetic record was touched), it is one signature out of ten, and it
#     can never escalate on its own (threshold is 3 distinct signatures).
#   * No allowlist or denylist of principals or tenants. Nothing in here compares
#     a principal_hash against a constant.
#   * No test mode, no env var, no CLI flag that forces or suppresses escalation.
#     The only input is the JSONL frame stream on stdin.
#   * No label/ground-truth file is opened, referenced, or reachable from here.
#     Every decision is computed from the numeric features of window.v1.
#
# PROMPT-INJECTION BOUNDARY
# -------------------------
# Every scored field (axes, families, stage_signatures, confidence, summary) is
# monitor-authored and derived from numbers plus the constants below. The only
# strings ever copied out of the input are principal_hash, tenant and session
# ids — identity join keys, not free text. Attacker-influenced text can only
# leave this file inside `untrusted_data.fenced`, fenced and capped, and it is
# NEVER read by any predicate here.
#
# I/O
# ---
#   stdin : window.v1 frames as JSONL, ordered by window_start_ms. An optional
#           FIRST line {"__config__": {"quarantine": [...]}} carries quarantine
#           records; it is config, not a frame.
#   stdout: incident.v1 objects as JSONL, one per line.
#   stderr: diagnostics only. Nothing on stderr affects a decision.
#
# Run:  cd monitor && jac run escalation_policy.jac
# =============================================================================

import json;
import sys;
import math;
import hashlib;
import re;

# -----------------------------------------------------------------------------
# CONSTANTS — the whole tunable surface of the policy, in one block.
# -----------------------------------------------------------------------------

glob:pub WINDOW_MS: int = 15000;              # tumbling window width (window.v1)
glob:pub RING_WINDOWS: int = 6;               # per-actor rows retained for baselines
glob:pub CORRELATION_MS: int = 90000;         # signatures correlate across 90s
glob:pub ESCALATE_MIN_SIGNATURES: int = 3;    # distinct stages needed to escalate
glob:pub WARMUP_WINDOWS: int = 3;             # prior rows before p95 comparisons count
glob:pub PIVOT_MS: float = 1000.0;            # sub-1s post-deny retry == machine speed
glob:pub DENY_FLOOR: float = 0.2;             # denial share that counts as probing
glob:pub RECON_EARLY_WINDOWS: int = 3;        # "recon" only applies while an actor is new

# Quarantine hygiene (untrusted_data), transcribed from incident.v1.
glob:pub UNTRUSTED_MAX_ITEMS: int = 8;
glob:pub UNTRUSTED_MAX_CHARS: int = 4000;
glob:pub FENCE_PATTERN: str = "^<<<UNTRUSTED>>>[\\s\\S]*<<</UNTRUSTED>>>$";
glob:pub SUMMARY_MAX_CHARS: int = 600;

# -----------------------------------------------------------------------------
# The ten stage signatures. 1:1 with the ten authorized-scenario attack steps
# named in incident.v1. Families are the closed enum from incident.v1.
# -----------------------------------------------------------------------------

glob:pub SIGNATURE_NAME: dict = {
    1: "recon",
    2: "credential_spraying",
    3: "compromised_identity_use",
    4: "enumeration",
    5: "boundary_probe",
    6: "rapid_adaptation",
    7: "source_rotation",
    8: "value_discovery",
    9: "lateral_movement",
    10: "canary_touch"
};

glob:pub SIGNATURE_FAMILY: dict = {
    1: "novelty",
    2: "denial_shape",
    3: "escalation",
    4: "breadth",
    5: "denial_shape",
    6: "pivot",
    7: "cadence",
    8: "escalation",
    9: "escalation",
    10: "canary"
};

# axes == the window.v1 FEATURE NAMES each predicate actually reads to decide.
# Monitor-authored labels only; nothing here is derived from attacker text.
# (S2 reads auth_fail, S5 reads authz_deny + deny_ratio; when both fire the union
#  is exactly {auth_fail, authz_deny, deny_ratio}.)
glob:pub SIGNATURE_AXES: dict = {
    1: ["new_endpoints_first_seen", "deny_ratio"],
    2: ["auth_fail"],
    3: ["session_ids"],
    4: ["distinct_paths", "path_entropy", "new_endpoints_first_seen"],
    5: ["authz_deny", "deny_ratio"],
    6: ["post_deny_pivot_ms_p50"],
    7: ["src_ips_distinct", "ua_distinct"],
    8: ["new_endpoints_first_seen", "export_bytes"],
    9: ["cross_tenant_attempts", "integration_calls"],
    10: ["canary_touch"]
};

# The frame's top-level `baseline` is a GLOBAL p95 across all actors. It is
# carried into the diagnostic reasoning (stderr) so an analyst can see how the
# actor sat against the population, but it is deliberately NOT allowed to gate a
# predicate or add an axis: every predicate below compares an actor to ITS OWN
# ring, and the emitted axes must be reproducible from the ten predicates alone.
glob:pub BASELINE_FIELDS: dict = {
    "req": "p95_req",
    "distinct_paths": "p95_distinct_paths",
    "path_entropy": "p95_path_entropy",
    "auth_fail": "p95_auth_fail",
    "authz_deny": "p95_authz_deny",
    "deny_ratio": "p95_deny_ratio",
    "new_endpoints_first_seen": "p95_new_endpoints_first_seen",
    "src_ips_distinct": "p95_src_ips_distinct",
    "ua_distinct": "p95_ua_distinct",
    "cross_tenant_attempts": "p95_cross_tenant_attempts",
    "post_deny_pivot_ms_p50": "p95_post_deny_pivot_ms_p50",
    "integration_calls": "p95_integration_calls",
    "export_bytes": "p95_export_bytes"
};

# -----------------------------------------------------------------------------
# Numeric helpers
# -----------------------------------------------------------------------------

def fnum(row: dict, field: str) -> float {
    "Numeric field of an actor row, 0.0 when absent. Never raises on shape.";
    v = row.get(field, 0);
    if v is None {
        return 0.0;
    }
    if v == True {
        return 1.0;
    }
    if v == False {
        return 0.0;
    }
    return float(v);
}

def inum(row: dict, field: str) -> int {
    "Integer field of an actor row, 0 when absent.";
    return int(fnum(row, field));
}

def p95(vals: list) -> float {
    "p95 with linear interpolation. 0.0 for an empty sample (a cold actor has no baseline).";
    if len(vals) == 0 {
        return 0.0;
    }
    s = sorted(vals);
    k = 0.95 * float(len(s) - 1);
    lo = int(math.floor(k));
    hi = int(math.ceil(k));
    if lo == hi {
        return float(s[lo]);
    }
    return float(s[lo]) + (float(s[hi]) - float(s[lo])) * (k - float(lo));
}

def col(rows: list, field: str) -> list {
    "Column of one feature across the actor's own prior rows.";
    out = [];
    for r in rows {
        out.append(fnum(r, field));
    }
    return out;
}

def actor_key(principal: str, tenant: str) -> str {
    return principal + " " + tenant;
}

def incident_id(principal: str, tenant: str, wend: int) -> str {
    "Deterministic: sha256 over the identity + the window that raised it.";
    raw = principal + "|" + tenant + "|" + str(wend);
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest();
    return "inc_" + digest[0:16];
}

def union_key(sigs: list) -> str {
    "Canonical string for a union set, used to suppress duplicate emissions.";
    return ",".join([str(x) for x in sorted(sigs)]);
}

# -----------------------------------------------------------------------------
# THE TEN STAGE SIGNATURES
#
#   arow  = this actor's feature row for the CURRENT window
#   prior = this actor's own prior rows in the ring (up to RING_WINDOWS,
#           NOT including arow).  P95(f) below == p95 over `prior`.
#
# Returns the sorted list of signature ids that fired.
# -----------------------------------------------------------------------------

def score_row(arow: dict, prior: list) -> list {
    nprior = len(prior);
    fired = [];

    req = inum(arow, "req");
    distinct_paths = inum(arow, "distinct_paths");
    path_entropy = fnum(arow, "path_entropy");
    auth_fail = inum(arow, "auth_fail");
    authz_deny = inum(arow, "authz_deny");
    deny_ratio = fnum(arow, "deny_ratio");
    new_endpoints = inum(arow, "new_endpoints_first_seen");
    src_ips = inum(arow, "src_ips_distinct");
    ua_distinct = inum(arow, "ua_distinct");
    cross_tenant = inum(arow, "cross_tenant_attempts");
    integration_calls = inum(arow, "integration_calls");
    export_bytes = fnum(arow, "export_bytes");
    pivot_p50 = fnum(arow, "post_deny_pivot_ms_p50");
    canary = arow.get("canary_touch", False);
    sessions = arow.get("session_ids", []);

    # -- roll-ups over the actor's own prior rows -----------------------------
    prior_auth_fail = 0;
    prior_sessions = set();
    prior_had_auth_fail = False;
    for r in prior {
        af = inum(r, "auth_fail");
        prior_auth_fail += af;
        if af > 0 {
            prior_had_auth_fail = True;
        }
        for s in r.get("session_ids", []) {
            prior_sessions.add(s);
        }
    }

    # S1 recon (novelty)
    #   Touching endpoints for the first time AND getting told no, while the
    #   actor is still young enough that "first time" means something.
    if new_endpoints >= 1 and deny_ratio > 0.0 and nprior <= RECON_EARLY_WINDOWS {
        fired.append(1);
    }

    # S2 credential_spraying (denial_shape)
    #   Two failures in one window, or a slow drip that reaches 3 across the ring.
    if auth_fail >= 2 or (auth_fail >= 1 and (prior_auth_fail + auth_fail) >= 3) {
        fired.append(2);
    }

    # S3 compromised_identity_use (escalation)
    #   A session id never seen in this actor's ring appears in a CLEAN window
    #   (no failures, no denials, real traffic) right after windows that DID have
    #   auth failures — i.e. a successful auth minted a new session.
    has_new_session = False;
    for s in sessions {
        if s not in prior_sessions {
            has_new_session = True;
        }
    }
    if has_new_session and auth_fail == 0 and deny_ratio == 0.0 and req > 0 and prior_had_auth_fail {
        fired.append(3);
    }

    # S4 enumeration (breadth)
    #   Breadth above the actor's OWN p95. The warmup gate is what stops a
    #   cold-start bulk importer from looking novel: with < WARMUP_WINDOWS prior
    #   rows an actor has no baseline, so it cannot break one.
    if nprior >= WARMUP_WINDOWS {
        wide = (float(distinct_paths) > p95(col(prior, "distinct_paths"))
                and path_entropy > p95(col(prior, "path_entropy")));
        novel = float(new_endpoints) > max(1.0, p95(col(prior, "new_endpoints_first_seen")));
        if wide or novel {
            fired.append(4);
        }
    }

    # S5 boundary_probe (denial_shape)
    #   Authorization denials that are a real share of the traffic, not a stray 403.
    if authz_deny >= 1 and deny_ratio >= DENY_FLOOR {
        fired.append(5);
    }

    # S6 rapid_adaptation (pivot)
    #   Denied, then trying something else in under a second — machine speed,
    #   not a human re-reading the error.
    if (authz_deny + auth_fail) >= 1 and pivot_p50 > 0.0 and pivot_p50 < PIVOT_MS {
        fired.append(6);
    }

    # S7 source_rotation (cadence)
    #   More source IPs or user agents than this actor has ever needed. Counts
    #   only — window.v1 never carries the addresses or the UA text.
    if (float(src_ips) > max(1.0, p95(col(prior, "src_ips_distinct")))
            or float(ua_distinct) > max(1.0, p95(col(prior, "ua_distinct")))) {
        fired.append(7);
    }

    # S8 value_discovery (escalation)
    #   The ONLY predicate that reads export_bytes, and it cannot fire on volume:
    #   novelty AND friction AND a warmed-up baseline are all required first.
    if (nprior >= WARMUP_WINDOWS and new_endpoints >= 1 and deny_ratio > 0.0
            and export_bytes > max(p95(col(prior, "export_bytes")), 1.0)) {
        fired.append(8);
    }

    # S9 lateral_movement (escalation)
    #   Reaching for another tenant at all, or leaning on integrations harder
    #   than usual while being denied.
    if (cross_tenant >= 1
            or (float(integration_calls) > max(1.0, p95(col(prior, "integration_calls")))
                and deny_ratio > 0.0)) {
        fired.append(9);
    }

    # S10 canary_touch (canary)
    #   A property of the RESOURCE, not a verdict about the actor: one signature
    #   out of ten, and three are needed to escalate.
    if canary == True {
        fired.append(10);
    }

    return sorted(fired);
}

# -----------------------------------------------------------------------------
# Quarantine (untrusted_data). Emitted for downstream responders; NEVER an input
# to any decision above. Records arrive only via the __config__ preamble.
# -----------------------------------------------------------------------------

def build_untrusted(quarantine: list, principal: str, lo_ms: int, hi_ms: int) -> dict {
    fenced = [];
    for rec in quarantine {
        if len(fenced) >= UNTRUSTED_MAX_ITEMS {
            break;
        }
        if rec.get("cluster_id", "") != principal {
            continue;
        }
        rec_start = rec.get("window_start_ms", -1);
        if rec_start is None {
            continue;
        }
        rec_start = int(rec_start);
        if rec_start < lo_ms or rec_start >= hi_ms {
            continue;
        }
        text = rec.get("fenced", "");
        label = rec.get("label", "quarantined_text");
        if not isinstance(text, str) or not isinstance(label, str) {
            continue;
        }
        if len(text) > UNTRUSTED_MAX_CHARS {
            continue;
        }
        if re.match(FENCE_PATTERN, text) is None {
            continue;
        }
        if len(label) == 0 {
            label = "quarantined_text";
        }
        fenced.append({"label": label, "text": text});
    }
    return {"fenced": fenced};
}

# -----------------------------------------------------------------------------
# Summary. Numbers and monitor-authored labels only. The sole strings copied in
# are principal_hash and tenant (identity join keys, hashed upstream).
# -----------------------------------------------------------------------------

def build_summary(principal: str, tenant: str, uni: list, fams: list, nwindows: int,
                  peak_deny: float, own_p95_deny: float, fastest_pivot: float,
                  new_endpoints: int, cross_tenant: int) -> str {
    ph = principal[0:48];
    tn = tenant[0:48];
    ids = ",".join([str(x) for x in uni]);
    famtxt = ",".join(fams);
    parts = ("Correlated identity cluster " + ph + " in tenant " + tn + " showed "
        + str(len(uni)) + " distinct stage signatures (" + ids + ") within 90s across "
        + str(nwindows) + " windows. Families: " + famtxt + ". Peak deny_ratio "
        + str(round(peak_deny, 4)) + " vs own p95 " + str(round(own_p95_deny, 4))
        + "; fastest post-deny pivot " + str(round(fastest_pivot, 1)) + " ms; new endpoints "
        + str(new_endpoints) + "; cross-tenant attempts " + str(cross_tenant)
        + ". Volume was not a trigger.");
    if len(parts) > SUMMARY_MAX_CHARS {
        parts = parts[0:SUMMARY_MAX_CHARS];
    }
    return parts;
}

# -----------------------------------------------------------------------------
# Per-actor state:
#   ring     : last RING_WINDOWS rows of THIS actor  [{wstart, wend, row}]
#   log      : per-window scoring record for the last CORRELATION_MS
#              [{wstart, wend, sigs, sessions, deny_ratio, pivot, new_ep, cross}]
#   emitted  : union_key strings already emitted for this actor
# -----------------------------------------------------------------------------

def new_state() -> dict {
    return {"ring": [], "log": [], "emitted": []};
}

with entry:__main__ {
    data = sys.stdin.read();
    lines = data.splitlines();

    quarantine = [];
    first = True;
    frames_seen = 0;
    incidents_emitted = 0;
    state = {};

    for raw_line in lines {
        line = raw_line.strip();
        if len(line) == 0 {
            continue;
        }

        parsed = json.loads(line);

        # Optional config preamble (first line only).
        if first == True {
            first = False;
            if "__config__" in parsed {
                cfg = parsed["__config__"];
                quarantine = cfg.get("quarantine", []);
                sys.stderr.write("[cfg] quarantine records=" + str(len(quarantine)) + "\n");
                continue;
            }
        }

        frames_seen += 1;
        wstart = int(parsed.get("window_start_ms", 0));
        wend = int(parsed.get("window_end_ms", wstart + WINDOW_MS));
        actors = parsed.get("actors", []);
        gbaseline = parsed.get("baseline", {});

        # Deterministic actor order regardless of producer ordering.
        by_key = {};
        order = [];
        for arow in actors {
            k = actor_key(arow.get("principal_hash", ""), arow.get("tenant", ""));
            by_key[k] = arow;
            order.append(k);
        }
        order = sorted(order);

        for k in order {
            arow = by_key[k];
            principal = arow.get("principal_hash", "");
            tenant = arow.get("tenant", "");

            if k not in state {
                state[k] = new_state();
            }
            st = state[k];

            # --- baselines come from the actor's OWN prior rows ---------------
            prior = [];
            for e in st["ring"] {
                prior.append(e["row"]);
            }

            sigs = score_row(arow, prior);

            # --- 90s correlation log -----------------------------------------
            st["log"].append({
                "wstart": wstart,
                "wend": wend,
                "sigs": sigs,
                "sessions": arow.get("session_ids", []),
                "deny_ratio": fnum(arow, "deny_ratio"),
                "pivot": fnum(arow, "post_deny_pivot_ms_p50"),
                "new_ep": inum(arow, "new_endpoints_first_seen"),
                "cross": inum(arow, "cross_tenant_attempts")
            });
            kept = [];
            for e in st["log"] {
                if (wend - e["wend"]) <= CORRELATION_MS {
                    kept.append(e);
                }
            }
            st["log"] = kept;

            uni_set = set();
            for e in st["log"] {
                for sid in e["sigs"] {
                    uni_set.add(sid);
                }
            }
            uni = sorted(list(uni_set));

            # --- diagnostics (stderr only; never a decision input) ------------
            gbreaks = [];
            for feat in sorted(list(BASELINE_FIELDS.keys())) {
                gp = float(gbaseline.get(BASELINE_FIELDS[feat], 0));
                if fnum(arow, feat) > gp and gp > 0.0 {
                    gbreaks.append(feat);
                }
            }
            sys.stderr.write("[w " + str(wstart) + "] " + principal + "/" + tenant
                + " nprior=" + str(len(prior))
                + " fired=" + str(sigs)
                + " union90s=" + str(uni)
                + " global_p95_breaks=" + str(gbreaks) + "\n");

            # --- ring update (after scoring: `prior` must exclude this row) ---
            st["ring"].append({"wstart": wstart, "wend": wend, "row": arow});
            if len(st["ring"]) > RING_WINDOWS {
                st["ring"] = st["ring"][-RING_WINDOWS:];
            }

            # --- escalation ---------------------------------------------------
            if len(uni) < ESCALATE_MIN_SIGNATURES {
                continue;
            }
            ukey = union_key(uni);
            if ukey in st["emitted"] {
                continue;
            }
            st["emitted"].append(ukey);

            fam_set = set();
            axis_set = set();
            for sid in uni {
                fam_set.add(SIGNATURE_FAMILY[sid]);
                for ax in SIGNATURE_AXES[sid] {
                    axis_set.add(ax);
                }
            }
            fams = sorted(list(fam_set));
            axes = sorted(list(axis_set));

            evidence = [];
            session_set = set();
            peak_deny = 0.0;
            fastest_pivot = 0.0;
            new_ep_total = 0;
            cross_total = 0;
            lo_ms = wend;
            for e in st["log"] {
                if len(e["sigs"]) > 0 {
                    evidence.append("window:" + str(e["wstart"]) + ":" + principal);
                }
                for s in e["sessions"] {
                    session_set.add(s);
                }
                if e["deny_ratio"] > peak_deny {
                    peak_deny = e["deny_ratio"];
                }
                if e["pivot"] > 0.0 {
                    if fastest_pivot == 0.0 or e["pivot"] < fastest_pivot {
                        fastest_pivot = e["pivot"];
                    }
                }
                new_ep_total += e["new_ep"];
                cross_total += e["cross"];
                if e["wstart"] < lo_ms {
                    lo_ms = e["wstart"];
                }
            }

            own_p95_deny = p95(col(prior, "deny_ratio"));

            inc = {
                "incident_id": incident_id(principal, tenant, wend),
                "schema_version": "incident.v1",
                "detected_at_ms": wend,
                "confidence": round(min(0.98, 0.40 + 0.09 * float(len(uni)) + 0.03 * float(len(fams))), 4),
                "axes": axes,
                "families": fams,
                "join_keys": {
                    "principal_hash": principal,
                    "tenant": tenant,
                    "session_ids": sorted(list(session_set))
                },
                "evidence": evidence,
                "stage_signatures": uni,
                "summary": build_summary(principal, tenant, uni, fams, len(evidence),
                                         peak_deny, own_p95_deny, fastest_pivot,
                                         new_ep_total, cross_total),
                "untrusted_data": build_untrusted(quarantine, principal, lo_ms, wend)
            };

            print(json.dumps(inc));
            incidents_emitted += 1;
            sys.stderr.write("[escalate] " + inc["incident_id"] + " union=" + str(uni)
                + " families=" + str(fams) + " confidence=" + str(inc["confidence"]) + "\n");
        }
    }

    sys.stderr.write("[done] frames=" + str(frames_seen)
        + " actors_tracked=" + str(len(state))
        + " incidents=" + str(incidents_emitted) + "\n");
}
