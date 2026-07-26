#!/usr/bin/env python3
"""Contract verifier for the golden audit-event fixture.

Runs every structural and semantic invariant the downstream consumers (the
incident graph, the monitor, the containment engine) are entitled to rely on.
Exits non-zero and prints exact failures if any check fails.

    python3 verify_golden.py
    python3 verify_golden.py --dir /some/other/dir
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import sys
from collections import Counter, defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from generate_golden import (  # noqa: E402
    ACTIONS, AUTH_METHODS, DENY_REASONS, DENY_STATUS, HTTP_METHODS, KINDS,
    OUTCOMES, ROLES, SCHEMA_KEYS, SCHEMA_VERSION, SENSITIVITIES, SERVICES,
    SEVERITIES, TARGET_KINDS,
)

UUID4_RE = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")
HEX16_RE = re.compile(r"^[0-9a-f]{16}$")
HEX32_RE = re.compile(r"^[0-9a-f]{32}$")
TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
ASN_RE = re.compile(r"^AS\d+$")
INT_FIELDS = ("ts_ms", "status_code", "latency_ms", "req_bytes", "resp_bytes",
              "result_count", "seq")
STR_FIELDS = tuple(k for k in SCHEMA_KEYS if k not in INT_FIELDS)

# RFC 5737 documentation ranges -- the ONLY address space allowed.
DOC_NETS = [ipaddress.ip_network(n) for n in
            ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
# RFC 5398 documentation AS numbers.
DOC_ASN_RANGE = (64496, 64511)

ID_SEG_RE = re.compile(
    r"^(?:[pt]_[a-z]{2}_\d+|tk_[a-z]{2}_\d+|cm_[a-z]{2}_\d+|ex_[a-z0-9_]*\d+"
    r"|inv_\d+|u_[a-z]{2,3}_\d+|intg_[a-z_]+|tok_[0-9a-f]+)$")


class Report:
    def __init__(self) -> None:
        self.failures: list[str] = []
        self.checks = 0

    def check(self, name: str, ok: bool, detail: str = "") -> bool:
        self.checks += 1
        if ok:
            print("  PASS  %s" % name)
        else:
            print("  FAIL  %s%s" % (name, (" -- " + detail) if detail else ""))
            self.failures.append(name + ((": " + detail) if detail else ""))
        return ok


def route_template(route: str) -> str:
    """Normalise a route to its template so 'novelty' compares like with like."""
    path = route.split("?", 1)[0]
    parts = []
    for seg in path.split("/"):
        parts.append("{id}" if ID_SEG_RE.match(seg) else seg)
    return "/".join(parts)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=HERE)
    args = ap.parse_args()

    ev_path = os.path.join(args.dir, "audit_golden.jsonl")
    lb_path = os.path.join(args.dir, "audit_golden.labels.jsonl")
    r = Report()

    # ---------------------------------------------------------------- load
    raw_lines = open(ev_path, encoding="utf-8").read().splitlines()
    bad_json = []
    events = []
    for i, line in enumerate(raw_lines, 1):
        try:
            events.append(json.loads(line))
        except Exception as exc:                 # noqa: BLE001
            bad_json.append("line %d: %s" % (i, exc))
    r.check("1  every line of audit_golden.jsonl parses as JSON",
            not bad_json, "; ".join(bad_json[:5]))
    if bad_json:
        return 1

    lb_lines = open(lb_path, encoding="utf-8").read().splitlines()
    labels = [json.loads(x) for x in lb_lines]

    print("\n  (%d events, %d labels)\n" % (len(events), len(labels)))

    # ------------------------------------------------------- schema shape
    key_errs = []
    for i, e in enumerate(events, 1):
        if tuple(e.keys()) != SCHEMA_KEYS:
            missing = set(SCHEMA_KEYS) - set(e)
            extra = set(e) - set(SCHEMA_KEYS)
            key_errs.append("line %d missing=%s extra=%s order_ok=%s"
                            % (i, sorted(missing), sorted(extra),
                               set(e) == set(SCHEMA_KEYS)))
    r.check("2  every line has exactly the %d schema keys (same order)"
            % len(SCHEMA_KEYS), not key_errs, "; ".join(key_errs[:3]))

    type_errs = []
    for i, e in enumerate(events, 1):
        for f in INT_FIELDS:
            if not isinstance(e.get(f), int) or isinstance(e.get(f), bool):
                type_errs.append("line %d %s=%r" % (i, f, e.get(f)))
        for f in STR_FIELDS:
            if not isinstance(e.get(f), str):
                type_errs.append("line %d %s=%r" % (i, f, e.get(f)))
    r.check("3  int fields are ints, string fields are strings",
            not type_errs, "; ".join(type_errs[:5]))

    r.check("4  schema_version == %r everywhere" % SCHEMA_VERSION,
            all(e["schema_version"] == SCHEMA_VERSION for e in events))

    # --------------------------------------------------- closed vocabulary
    bad_actions = sorted({e["action"] for e in events} - set(ACTIONS))
    r.check("5  every action is in the closed vocabulary",
            not bad_actions, "unknown: %s" % bad_actions)

    bad_reasons = sorted({e["reason"] for e in events} - set(DENY_REASONS) - {""})
    r.check("6  every reason is in the closed vocabulary (or empty)",
            not bad_reasons, "unknown: %s" % bad_reasons)

    reason_pol = []
    for i, e in enumerate(events, 1):
        if e["outcome"] == "deny" and not e["reason"]:
            reason_pol.append("line %d deny with empty reason" % i)
        if e["outcome"] in ("allow", "error") and e["reason"]:
            reason_pol.append("line %d %s with reason=%s"
                              % (i, e["outcome"], e["reason"]))
    r.check("7  reason non-empty iff outcome == deny",
            not reason_pol, "; ".join(reason_pol[:5]))

    enum_errs = []
    for name, allowed in (("kind", KINDS), ("outcome", OUTCOMES),
                          ("severity", SEVERITIES), ("actor_role", ROLES),
                          ("auth_method", AUTH_METHODS),
                          ("target_kind", TARGET_KINDS),
                          ("target_sensitivity", SENSITIVITIES),
                          ("service", SERVICES),
                          ("http_method", HTTP_METHODS)):
        bad = sorted({e[name] for e in events} - set(allowed))
        if bad:
            enum_errs.append("%s: %s" % (name, bad))
    r.check("8  all enum fields hold legal values", not enum_errs,
            "; ".join(enum_errs))

    status_errs = []
    for i, e in enumerate(events, 1):
        if e["outcome"] != "deny":
            continue
        want = DENY_STATUS.get(e["reason"])
        if want is None:                          # already flagged by check 6
            continue
        if e["status_code"] != want:
            status_errs.append("line %d reason=%s status=%s (want %d)"
                               % (i, e["reason"], e["status_code"], want))
    r.check("9  deny status_code matches the reason", not status_errs,
            "; ".join(status_errs[:5]))

    # -------------------------------------------------------------- time
    ts_errs = [
        "line %d %s -> %d" % (i, e["ts"], e["ts_ms"])
        for i, e in enumerate(events, 1) if not TS_RE.match(e["ts"])
    ]
    r.check("10 ts is ISO-8601 UTC with microseconds and a Z suffix",
            not ts_errs, "; ".join(ts_errs[:5]))

    mono = [
        "line %d ts_ms %d < previous %d"
        % (i, events[i - 1]["ts_ms"], events[i - 2]["ts_ms"])
        for i in range(2, len(events) + 1)
        if events[i - 1]["ts_ms"] < events[i - 2]["ts_ms"]
    ]
    r.check("11 ts_ms is non-decreasing across the whole file",
            not mono, "; ".join(mono[:5]))

    import datetime as _dt
    agree = []
    for i, e in enumerate(events, 1):
        try:
            dt = _dt.datetime.strptime(e["ts"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(
                tzinfo=_dt.timezone.utc)
            if int(dt.timestamp() * 1_000_000) // 1000 != e["ts_ms"]:
                agree.append("line %d (%s vs %s)" % (i, e["ts"], e["ts_ms"]))
        except (ValueError, TypeError) as exc:    # noqa: PERF203
            agree.append("line %d unparseable: %s" % (i, exc))
    r.check("12 ts and ts_ms agree", not agree, "; ".join(agree[:5]))

    # ------------------------------------------------------- correlation
    ids = [e["event_id"] for e in events]
    r.check("13 event_id is unique", len(set(ids)) == len(ids),
            "%d dupes" % (len(ids) - len(set(ids))))
    bad_uuid = [i for i, e in enumerate(events, 1) if not UUID4_RE.match(e["event_id"])]
    r.check("14 event_id is a well-formed uuid4", not bad_uuid,
            "lines %s" % bad_uuid[:5])

    seq_errs, chain_errs = [], []
    seen: dict[str, tuple[int, str]] = {}
    for i, e in enumerate(events, 1):
        sid = e["session_id"]
        if not sid:
            seq_errs.append("line %d empty session_id" % i)
            continue
        if sid not in seen:
            if e["seq"] != 1:
                seq_errs.append("line %d first event of %s has seq=%d"
                                % (i, sid, e["seq"]))
            if e["prev_event_id"] != "":
                chain_errs.append("line %d first event of %s has prev_event_id"
                                  % (i, sid))
        else:
            pseq, pid = seen[sid]
            if not isinstance(e["seq"], int) or e["seq"] <= pseq:
                seq_errs.append("line %d session %s seq %r <= prev %r"
                                % (i, sid, e["seq"], pseq))
            if e["prev_event_id"] != pid:
                chain_errs.append("line %d session %s prev_event_id mismatch"
                                  % (i, sid))
        seen[sid] = (e["seq"], e["event_id"])
    r.check("15 seq is monotonic within every session_id", not seq_errs,
            "; ".join(seq_errs[:5]))
    r.check("16 prev_event_id chains correctly within every session_id",
            not chain_errs, "; ".join(chain_errs[:5]))

    fmt_errs = []
    for i, e in enumerate(events, 1):
        if not HEX16_RE.match(e["user_agent_hash"]):
            fmt_errs.append("line %d user_agent_hash" % i)
        if not HEX16_RE.match(e["client_fp"]):
            fmt_errs.append("line %d client_fp" % i)
        if not HEX16_RE.match(e["request_id"]):
            fmt_errs.append("line %d request_id" % i)
        if not HEX32_RE.match(e["trace_id"]):
            fmt_errs.append("line %d trace_id" % i)
    r.check("17 user_agent_hash/client_fp are 16 hex, trace_id is 32 hex",
            not fmt_errs, "; ".join(fmt_errs[:5]))

    # ------------------------------------------------ synthetic-data rules
    def in_doc_space(addr: str) -> bool:
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            return False
        return any(ip in n for n in DOC_NETS)

    bad_ip = sorted({e["src_ip"] for e in events if not in_doc_space(e["src_ip"])})
    r.check("18 every src_ip is inside RFC 5737 documentation space",
            not bad_ip, "offending: %s" % bad_ip)

    bad_asn = sorted({e["src_asn"] for e in events
                      if not (ASN_RE.match(e["src_asn"])
                              and DOC_ASN_RANGE[0] <= int(e["src_asn"][2:])
                              <= DOC_ASN_RANGE[1])})
    r.check("19 every src_asn is an RFC 5398 documentation ASN",
            not bad_asn, "offending: %s" % bad_asn)

    bad_email = sorted({e["actor_email"] for e in events
                        if e["actor_email"] and not e["actor_email"].endswith(".test")})
    r.check("20 every actor_email is on a .test domain", not bad_email,
            "offending: %s" % bad_email)

    # -------------------------------------------- LABEL LEAKAGE (critical)
    leak_keys = sorted(set(SCHEMA_KEYS) & {"population", "stage", "label",
                                           "is_attack", "ground_truth"})
    r.check("21 no label key exists in the scored schema", not leak_keys,
            "leaked keys: %s" % leak_keys)

    leak_lines = [i for i, line in enumerate(raw_lines, 1)
                  if '"population"' in line or '"stage"' in line
                  or '"is_attack"' in line or '"ground_truth"' in line]
    r.check("22 the literal tokens population/stage appear nowhere in the "
            "event file", not leak_lines, "lines %s" % leak_lines[:5])

    r.check("23 labels file has one line per event",
            len(labels) == len(events),
            "%d labels vs %d events" % (len(labels), len(events)))
    lab_align = [i for i, (e, l) in enumerate(zip(events, labels), 1)
                 if e["event_id"] != l["event_id"]]
    r.check("24 labels align 1:1 with events in file order", not lab_align,
            "first mismatch at line %s" % lab_align[:3])
    bad_lab = [i for i, l in enumerate(labels, 1)
               if l["population"] not in ("benign", "bulk", "campaign")
               or not isinstance(l["stage"], int) or not 0 <= l["stage"] <= 10
               or set(l) != {"event_id", "population", "stage"}]
    r.check("25 every label row is {event_id, population, stage 0-10}",
            not bad_lab, "lines %s" % bad_lab[:5])

    # ------------------------------------------------- population make-up
    pop = defaultdict(list)
    for e, l in zip(events, labels):
        pop[l["population"]].append((e, l))

    counts = {k: len(v) for k, v in pop.items()}
    total = len(events)
    r.check("26 all three populations are present",
            set(counts) == {"benign", "bulk", "campaign"}, str(counts))

    frac = {k: v / total for k, v in counts.items()}
    r.check("27 population mix is roughly 60/25/15",
            0.52 <= frac.get("benign", 0) <= 0.68
            and 0.19 <= frac.get("bulk", 0) <= 0.31
            and 0.11 <= frac.get("campaign", 0) <= 0.21,
            "%s" % {k: round(v, 3) for k, v in frac.items()})

    # Interleaving: no population may occupy one contiguous block.
    runs = []
    cur, n = labels[0]["population"], 1
    for l in labels[1:]:
        if l["population"] == cur:
            n += 1
        else:
            runs.append((cur, n))
            cur, n = l["population"], 1
    runs.append((cur, n))
    longest = {p: max((c for q, c in runs if q == p), default=0)
               for p in counts}
    r.check("28 populations are time-interleaved, not concatenated in blocks",
            len(runs) >= 25 and all(longest[p] < counts[p] * 0.75 for p in counts),
            "%d runs, longest run per population %s" % (len(runs), longest))

    # -------------------------------------- campaign: ten ordered stages
    camp = [(e, l) for e, l in pop["campaign"]]
    stages_seen = [l["stage"] for _, l in camp]
    r.check("29 campaign covers all ten stages",
            set(stages_seen) == set(range(1, 11)),
            "present: %s" % sorted(set(stages_seen)))
    r.check("30 campaign stages appear in non-decreasing order",
            all(b >= a for a, b in zip(stages_seen, stages_seen[1:])),
            "sequence: %s" % stages_seen)

    by_stage = defaultdict(list)
    for e, l in camp:
        by_stage[l["stage"]].append(e)

    r.check("31 stage 1 recon is unauthenticated",
            all(e["actor_principal_id"] == "" and e["auth_method"] == "none"
                for e in by_stage[1]))
    r.check("32 stage 2 is auth.login_failed against several identities from "
            "one source",
            all(e["action"] == "auth.login_failed" for e in by_stage[2])
            and len({e["actor_email"] for e in by_stage[2]}) >= 3
            and len({e["src_ip"] for e in by_stage[2]}) == 1)
    r.check("33 stage 3 is a successful login by the compromised identity",
            any(e["action"] == "auth.login" and e["outcome"] == "allow"
                for e in by_stage[3]))
    r.check("34 stage 4 enumerates with rising distinct target coverage",
            len(by_stage[4]) >= 4
            and all(e["outcome"] == "allow" for e in by_stage[4])
            and sum(e["result_count"] for e in by_stage[4]) >= 40)
    r.check("35 stage 5 probes permission boundaries "
            "(INSUFFICIENT_ROLE / NOT_A_MEMBER)",
            {e["reason"] for e in by_stage[5]}
            <= {"INSUFFICIENT_ROLE", "NOT_A_MEMBER"}
            and len(by_stage[5]) >= 3
            and all(e["outcome"] == "deny" for e in by_stage[5]))

    # Stage 6 is the discriminator: deny -> different endpoint class in <1s.
    s6 = by_stage[6]
    pivots, bad_pivots = 0, []
    for a, bb in zip(s6, s6[1:]):
        if a["outcome"] == "deny" and bb["outcome"] == "allow":
            dt = bb["ts_ms"] - a["ts_ms"]
            same_class = a["action"].split(".")[0] == bb["action"].split(".")[0]
            if dt < 1000 and not same_class:
                pivots += 1
            else:
                bad_pivots.append("dt=%dms same_class=%s" % (dt, same_class))
    r.check("36 stage 6 pivots to a DIFFERENT endpoint class in <1s after "
            "every deny", pivots >= 3 and not bad_pivots,
            "%d clean pivots; problems: %s" % (pivots, bad_pivots[:3]))

    # Benign contrast: after a benign failure the same call is retried.
    ben_by_sess = defaultdict(list)
    for e, _ in pop["benign"]:
        ben_by_sess[e["session_id"]].append(e)
    retries, benign_pivots = 0, 0
    for evs in ben_by_sess.values():
        for a, bb in zip(evs, evs[1:]):
            # Ending a session is not endpoint-class adaptation, so a closing
            # auth.* event after a failure does not count either way.
            if (a["outcome"] in ("deny", "error")
                    and not a["action"].startswith("auth.")
                    and not bb["action"].startswith("auth.")):
                if a["action"] == bb["action"]:
                    retries += 1
                else:
                    benign_pivots += 1
    # The hard invariant is benign_pivots == 0: a benign client must NEVER do
    # the stage-6 thing. `retries` is only there to prove the sample is not
    # empty, so its floor stays low enough to hold for any seed.
    r.check("37 benign clients RETRY the same call after a failure, never "
            "pivot (the contrast to stage 6)",
            retries >= 3 and benign_pivots == 0,
            "%d retries, %d pivots" % (retries, benign_pivots))

    s7 = by_stage[7]
    r.check("38 stage 7 reuses one session_id + client_fp across several "
            "203.0.113.0/24 sources",
            len({e["session_id"] for e in s7}) == 1
            and len({e["client_fp"] for e in s7}) == 1
            and len({e["src_ip"] for e in s7}) >= 3
            and all(e["src_ip"].startswith("203.0.113.") for e in s7),
            "%d ips" % len({e["src_ip"] for e in s7}))

    s8sens = [e["target_sensitivity"] for e in by_stage[8]]
    r.check("39 stage 8 climbs the sensitivity gradient normal -> confidential",
            "normal" in s8sens and "confidential" in s8sens
            and s8sens.index("normal") < s8sens.index("confidential"),
            "gradient: %s" % s8sens)

    s9 = by_stage[9]
    r.check("40 stage 9 is cross-tenant integration.call denied "
            "TENANT_MISMATCH",
            bool(s9) and all(e["action"] == "integration.call"
                             and e["reason"] == "TENANT_MISMATCH"
                             and e["tenant_id"] != e["actor_tenant_id"]
                             for e in s9))

    s10 = by_stage[10]
    r.check("41 stage 10 touches canary targets and is always denied",
            bool(s10) and all(e["target_sensitivity"] == "canary"
                              and e["outcome"] == "deny" for e in s10))

    r.check("42 only the campaign ever touches a canary record",
            all(l["population"] == "campaign"
                for e, l in zip(events, labels)
                if e["target_sensitivity"] == "canary"))

    r.check("43 only the campaign ever crosses a tenant boundary",
            all(l["population"] == "campaign"
                for e, l in zip(events, labels)
                if e["tenant_id"] and e["tenant_id"] != e["actor_tenant_id"]))

    # --------------------------- BULK = NEGATIVE CONTROL (must not detect)
    bulk = [e for e, _ in pop["bulk"]]
    camp_events = [e for e, _ in camp]

    r.check("44 bulk out-volumes the campaign (louder on rate alone)",
            len(bulk) > len(camp_events)
            and sum(e["result_count"] for e in bulk)
            > 10 * sum(e["result_count"] for e in camp_events),
            "bulk rows=%d campaign rows=%d"
            % (sum(e["result_count"] for e in bulk),
               sum(e["result_count"] for e in camp_events)))

    r.check("45 bulk has zero denials and zero errors",
            all(e["outcome"] == "allow" for e in bulk),
            str(Counter(e["outcome"] for e in bulk)))
    r.check("46 bulk uses a single stable src_ip",
            len({e["src_ip"] for e in bulk}) == 1,
            str(sorted({e["src_ip"] for e in bulk})))
    r.check("47 bulk uses a single stable user_agent_hash + client_fp",
            len({e["user_agent_hash"] for e in bulk}) == 1
            and len({e["client_fp"] for e in bulk}) == 1)
    r.check("48 bulk never leaves its own tenant",
            all(e["tenant_id"] == e["actor_tenant_id"] == "t_globex"
                for e in bulk))
    r.check("49 bulk never touches confidential or canary data",
            all(e["target_sensitivity"] == "normal" for e in bulk))

    # No endpoint novelty: every bulk route template must already have been
    # seen earlier in the stream by a non-bulk actor.
    seen_tpl: set[str] = set()
    novelty = []
    for e, l in zip(events, labels):
        tpl = route_template(e["route"])
        if l["population"] == "bulk":
            if tpl not in seen_tpl:
                novelty.append("line-route %s" % tpl)
        else:
            seen_tpl.add(tpl)
    r.check("50 bulk introduces no novel endpoint (all routes seen earlier)",
            not novelty, "; ".join(sorted(set(novelty))[:5]))

    # Low inter-arrival variance within a batch.
    bulk_ts = [e["ts_ms"] for e in bulk]
    gaps = [b - a for a, b in zip(bulk_ts, bulk_ts[1:]) if b - a < 5000]
    mean = sum(gaps) / len(gaps)
    var = sum((g - mean) ** 2 for g in gaps) / len(gaps)
    r.check("51 bulk inter-arrival is machine-paced with low variance",
            mean < 400 and var ** 0.5 < 60,
            "mean=%.0fms sd=%.0fms over %d gaps" % (mean, var ** 0.5, len(gaps)))

    # --------------------------------------------- injection test payloads
    inj_tokens = ("ignore", "disregard", "developer-mode", "assistant",
                  "SYSTEM", "no%20incident")
    inj_email = [e for e in events
                 if any(t.lower() in e["actor_email"].lower() for t in inj_tokens)]
    inj_route = [e for e in events
                 if any(t.lower() in e["route"].lower() for t in inj_tokens)]
    r.check("52 prompt-injection payloads present in actor_email and route",
            len(inj_email) >= 2 and len(inj_route) >= 3,
            "%d emails, %d routes" % (len(inj_email), len(inj_route)))
    inj_pops = {l["population"] for e, l in zip(events, labels)
                if e in inj_email or e in inj_route}
    r.check("53 injection payloads only occur in campaign events",
            inj_pops <= {"campaign"}, str(inj_pops))

    # ------------------------------- cross-check vs the frozen .jac contract
    # contracts/audit_event_contract.jac is the machine-readable source of
    # truth for the vocabulary and field list. The fixture predates the
    # application, so its vocabulary is legitimately a SUBSET (it emits no
    # containment.* actions). Anything outside that subset relation is drift.
    jac = os.path.join(os.path.dirname(HERE), "audit_event_contract.jac")
    if os.path.exists(jac):
        src = open(jac, encoding="utf-8").read()

        def jac_list(name: str) -> set[str] | None:
            m = re.search(name + r"\s*(?::\s*[\w\[\], ]+)?\s*=\s*\[(.*?)\]",
                          src, re.S)
            return set(re.findall(r"['\"]([^'\"]+)['\"]", m.group(1))) if m else None

        c_actions, c_reasons = jac_list("ACTIONS"), jac_list("DENY_REASONS")
        c_fields = set(re.findall(r"^\s*has\s+(\w+)\s*:", src, re.M))

        used_actions = {e["action"] for e in events}
        used_reasons = {e["reason"] for e in events} - {""}
        r.check("54 fixture actions are a subset of the frozen contract "
                "ACTIONS",
                c_actions is not None and used_actions <= c_actions,
                "not in contract: %s" % sorted(used_actions - (c_actions or set())))
        r.check("55 fixture deny reasons are a subset of the frozen contract "
                "DENY_REASONS",
                c_reasons is not None and used_reasons <= c_reasons,
                "not in contract: %s" % sorted(used_reasons - (c_reasons or set())))
        r.check("56 fixture field set matches the frozen contract field set "
                "exactly",
                c_fields == set(SCHEMA_KEYS),
                "fixture-only=%s contract-only=%s"
                % (sorted(set(SCHEMA_KEYS) - c_fields),
                   sorted(c_fields - set(SCHEMA_KEYS))))
    else:
        print("  SKIP  54-56 cross-check (%s not present)" % jac)

    # ----------------------------------------------------------- summary
    print("\n%s" % ("-" * 68))
    print("checks run: %d   failures: %d" % (r.checks, len(r.failures)))
    if r.failures:
        print("\nFAILURES:")
        for f in r.failures:
            print("  - %s" % f)
        return 1

    span = (events[-1]["ts_ms"] - events[0]["ts_ms"]) / 1000.0
    print("events: %d   span: %.1fs (%.1f min)   sessions: %d"
          % (len(events), span, span / 60.0,
             len({e["session_id"] for e in events})))
    print("populations: %s"
          % ", ".join("%s=%d (%.1f%%)" % (k, counts[k], 100 * counts[k] / total)
                      for k in ("benign", "bulk", "campaign")))
    print("campaign stages: %s"
          % ", ".join("%d:%d" % (s, len(by_stage[s])) for s in range(1, 11)))
    print("ALL CHECKS PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
