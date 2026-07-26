# coordinator/effort_gate.jac
#
# THE BOOT GATE. The coordinator REFUSES to leave WATCHING unless six
# effort_receipt.v1 records exist — `monitor` plus all five responders — every
# one of them with downgraded:false. That turns "we never silently downgrade
# effort" from a promise in a README into a condition the state machine cannot
# get past.
#
# Two properties this module exists to make mechanical:
#
#  1. NO SILENT DOWNGRADE. Every line of runs/<id>/effort.jsonl is validated
#     against the FROZEN contract contracts/mesh/effort_receipt.v1.schema.json
#     with Draft202012Validator. A line that does not parse, or parses but does
#     not validate, is REPORTED in `invalid` — never dropped. Dropping a bad
#     line would let a downgrade hide inside a typo.
#
#  2. NO MISLABELLED RUN. A receipt carrying blocked:true or mocked:true is
#     PERMITTED to exist — that run is still a valid run — but it is not an
#     acceptance run, so `run_label` becomes MOCKED and enforce_gate calls
#     log.mark_mocked(), which retroactively stamps MOCKED onto every event the
#     log already holds as well as every event it will ever emit. A mocked run
#     is therefore never reportable as the live run, in any artifact it touches.
#     run_label is computed even when the gate REFUSES, because a failed mocked
#     run must still be labelled.
#
# THERE IS NO BYPASS. This module reads no environment variable, takes no flag,
# has no "test mode" and no default-true. The only way past the gate is six
# schema-valid, non-duplicate, non-downgraded receipts from exactly the six
# canonical agents. It holds no credentials and never contacts a provider.

import os;
import json;
import from typing { Any }
import from jsonschema { Draft202012Validator }
import from ids { EFFORT_GATE_AGENTS, REQUIRED_RECEIPTS, RUN_LIVE, RUN_MOCKED, S_WATCHING, S_ESCALATED }

# --------------------------------------------------------------------------
# Failure reason codes. Machine-readable, stable, and the only values `reason`
# ever takes besides "" (which means the gate opened).
# --------------------------------------------------------------------------

glob:pub R_OK: str = "";
glob:pub R_RECEIPTS_MISSING: str = "RECEIPTS_MISSING";
glob:pub R_RECEIPT_DOWNGRADED: str = "RECEIPT_DOWNGRADED";
glob:pub R_RECEIPT_INVALID: str = "RECEIPT_INVALID";
glob:pub R_RECEIPT_DUPLICATE: str = "RECEIPT_DUPLICATE";
glob:pub R_RECEIPTS_FILE_MISSING: str = "RECEIPTS_FILE_MISSING";

glob:pub GATE_REASONS: list = [
    "RECEIPTS_FILE_MISSING",
    "RECEIPT_INVALID",
    "RECEIPT_DUPLICATE",
    "RECEIPTS_MISSING",
    "RECEIPT_DOWNGRADED"
];

# Reason precedence, strictest first. A file with a corrupt line is reported as
# corrupt before it is reported as short, because the corrupt line might BE the
# missing agent — guessing which failure "really" applies is how a downgrade
# slips through.

# --------------------------------------------------------------------------
# Contract location. Resolved from THIS file, never from cwd, because Jac
# resolves imports relative to the invocation directory and tests are run from
# coordinator/ while the schema lives in the repo-root contracts/ tree.
# --------------------------------------------------------------------------

glob:pub HERE: str = os.path.dirname(os.path.abspath(__file__));
glob:pub REPO_ROOT: str = os.path.dirname(HERE);
glob:pub SCHEMA_PATH: str = os.path.join(REPO_ROOT, "contracts", "mesh", "effort_receipt.v1.schema.json");

"""Read a whole text file. The only file I/O in this module."""
def _read_text(path: str) -> str {
    handle = open(path, "r");
    raw = handle.read();
    handle.close();
    return raw;
}

"""Load the frozen effort_receipt.v1 schema from disk."""
def _load_schema(path: str) -> dict {
    return json.loads(_read_text(path));
}

# Loaded ONCE at import so evaluate_receipts() performs no I/O of its own and
# stays a pure function of its argument.
glob:pub EFFORT_SCHEMA: dict = _load_schema(SCHEMA_PATH);
glob:pub RECEIPT_VALIDATOR: Any = Draft202012Validator(EFFORT_SCHEMA);

# --------------------------------------------------------------------------
# Result
# --------------------------------------------------------------------------

obj GateResult {
    # True iff the coordinator may leave WATCHING.
    has ok: bool = False;
    # One of GATE_REASONS, or "" when ok.
    has reason: str = "";
    # Human-readable explanation. Never contains a credential or a token.
    has detail: str = "";
    # "LIVE" | "MOCKED". Computed even when ok is False.
    has run_label: str = "LIVE";
    # Every non-blank line the file offered, including the invalid ones. Proof
    # that nothing was silently dropped.
    has receipts_seen: int = 0;
    has agents_seen: list = [];
    has missing: list = [];
    has unexpected: list = [];
    has downgraded_agents: list = [];
    has blocked_agents: list = [];
    has mocked_agents: list = [];
    has invalid: list = [];

    """Deterministic dict form. Every list field is sorted, so
    json.dumps(r.as_dict(), sort_keys=True) is byte-stable for a given file."""
    def as_dict -> dict {
        return {
            "ok": self.ok,
            "reason": self.reason,
            "detail": self.detail,
            "run_label": self.run_label,
            "receipts_seen": self.receipts_seen,
            "agents_seen": sorted(self.agents_seen),
            "missing": sorted(self.missing),
            "unexpected": sorted(self.unexpected),
            "downgraded_agents": sorted(self.downgraded_agents),
            "blocked_agents": sorted(self.blocked_agents),
            "mocked_agents": sorted(self.mocked_agents),
            "invalid": sorted(self.invalid)
        };
    }
}

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

"""Order-independent, duplicate-free, sorted. Used for every agent-name list so
the result is byte-stable regardless of the order receipts were appended in."""
def _uniq_sorted(items: list) -> list {
    seen: dict = {};
    for x in items {
        seen[x] = True;
    }
    return sorted(seen.keys());
}

"""Normalise one element of the evaluate_receipts() argument.

parse_receipts() emits parse RECORDS (dicts carrying `_line`/`_ok`/`_error`/
`receipt`). A caller holding already-decoded receipt objects may pass those
directly instead; effort_receipt.v1 sets additionalProperties:false, so a real
receipt can never carry `_line` and the two forms cannot be confused."""
def _as_record(item: dict, index: int) -> dict {
    if "_line" in item {
        return item;
    }
    return {"_line": (index + 1), "_ok": True, "_error": "", "_raw": "", "receipt": item};
}

# --------------------------------------------------------------------------
# Parse
# --------------------------------------------------------------------------

"""Parse a JSONL effort-receipt file into one record per non-blank line.

The file format is JSONL — one receipt object per line, appended at boot. There
is no wrapping array, so a partial write corrupts exactly one line and the rest
of the file stays readable. That is precisely why bad lines are REPORTED rather
than skipped: a reader that silently ignores the line it cannot read is a reader
that cannot tell a clean boot from a truncated one.

Each returned record is a dict:
    _line   1-based line number in the file
    _ok     True when the line decoded to a JSON object
    _error  "" when _ok, else why the line could not be read
    _raw    the raw line text, stripped
    receipt the decoded object ({} when _ok is False)

Returns [] when the path is not a readable file; check_gate() reports that case
separately as RECEIPTS_FILE_MISSING."""
def parse_receipts(path: str) -> list {
    out: list = [];
    if not os.path.isfile(path) {
        return out;
    }
    raw = "";
    try {
        raw = _read_text(path);
    } except Exception as e {
        out.append({
            "_line": 0,
            "_ok": False,
            "_error": f"receipt file could not be read ({type(e).__name__})",
            "_raw": "",
            "receipt": {}
        });
        return out;
    }
    n: int = 0;
    for line in raw.splitlines() {
        n = (n + 1);
        stripped = line.strip();
        if not stripped {
            continue;
        }
        rec: dict = {"_line": n, "_ok": False, "_error": "", "_raw": stripped, "receipt": {}};
        try {
            parsed = json.loads(stripped);
            if isinstance(parsed, dict) {
                rec["_ok"] = True;
                rec["receipt"] = parsed;
            } else {
                rec["_error"] = "not a JSON object";
            }
        } except Exception as e {
            # Only the exception CLASS is recorded, never its message: decoder
            # messages carry byte offsets and wording that drift between Python
            # releases, and this string ends up in a byte-stable artifact.
            rec["_error"] = f"not parseable JSON ({type(e).__name__})";
        }
        out.append(rec);
    }
    return out;
}

# --------------------------------------------------------------------------
# Evaluate — pure. No file I/O, no clock, no env, no randomness.
# --------------------------------------------------------------------------

"""Decide whether the coordinator may leave WATCHING.

Accepts either parse records from parse_receipts() or bare receipt dicts.

ok is True ONLY when all of the following hold:
  * every line was parseable JSON and validated against effort_receipt.v1
  * no canonical agent filed more than once (the contract says ONCE, at boot)
  * all six of EFFORT_GATE_AGENTS filed
  * no receipt anywhere carries downgraded:true

run_label is MOCKED when ANY schema-valid receipt carries blocked:true or
mocked:true, and is computed even on the failure paths. Invalid lines do not
contribute to run_label — they are untrusted by definition — but an invalid line
blocks the gate outright, so an untrusted line can never let a run proceed.

A receipt from an agent outside EFFORT_GATE_AGENTS lands in `unexpected` and
does NOT count toward the six. It still counts for downgraded/blocked/mocked:
this gate fails closed, and an unexpected agent admitting a downgrade is
evidence about the run whoever filed it."""
def evaluate_receipts(receipts: list) -> GateResult {
    invalid: list = [];
    unexpected: list = [];
    downgraded: list = [];
    blocked: list = [];
    mocked: list = [];
    counts: dict = {};

    idx: int = -1;
    for item in receipts {
        idx = (idx + 1);
        rec: dict = _as_record(item, idx);
        ln = rec.get("_line", (idx + 1));

        if not rec.get("_ok", False) {
            why = rec.get("_error", "");
            if not why {
                why = "unreadable receipt line";
            }
            invalid.append(f"line {ln}: {why}");
            continue;
        }

        body = rec.get("receipt", {});
        errs = sorted([e.message for e in RECEIPT_VALIDATOR.iter_errors(body)]);
        if errs {
            who = body.get("agent", "?");
            if not isinstance(who, str) {
                who = "?";
            }
            joined = "; ".join(errs);
            invalid.append(f"line {ln}: agent={who}: effort_receipt.v1: {joined}");
            continue;
        }

        # Past this point the receipt is schema-valid, so every required field
        # is present and the three flags are genuine booleans.
        agent = body["agent"];
        if body["downgraded"] {
            downgraded.append(agent);
        }
        if body["blocked"] {
            blocked.append(agent);
        }
        if body["mocked"] {
            mocked.append(agent);
        }

        if agent not in EFFORT_GATE_AGENTS {
            unexpected.append(agent);
            continue;
        }
        counts[agent] = (counts.get(agent, 0) + 1);
    }

    seen: list = sorted(counts.keys());
    dupes: list = sorted([a for a in counts.keys() if counts[a] > 1]);
    missing: list = sorted([a for a in EFFORT_GATE_AGENTS if a not in counts]);

    res = GateResult(
        ok=False,
        reason="",
        detail="",
        run_label=RUN_LIVE,
        receipts_seen=len(receipts),
        agents_seen=seen,
        missing=missing,
        unexpected=_uniq_sorted(unexpected),
        downgraded_agents=_uniq_sorted(downgraded),
        blocked_agents=_uniq_sorted(blocked),
        mocked_agents=_uniq_sorted(mocked),
        invalid=sorted(invalid)
    );

    # Labelling is independent of the verdict: a run that FAILED the gate while
    # touching a mocked agent is still a mocked run.
    if res.blocked_agents or res.mocked_agents {
        res.run_label = RUN_MOCKED;
    } else {
        res.run_label = RUN_LIVE;
    }

    # The single, complete definition of "may leave WATCHING". Nothing else in
    # this module writes res.ok.
    res.ok = (
        (not res.invalid)
        and (not dupes)
        and (not missing)
        and (len(seen) == REQUIRED_RECEIPTS)
        and (not res.downgraded_agents)
    );

    if res.invalid {
        res.reason = R_RECEIPT_INVALID;
        res.detail = f"{len(res.invalid)} receipt line(s) failed effort_receipt.v1 validation or were not parseable JSON: " + " | ".join(res.invalid);
    } elif dupes {
        res.reason = R_RECEIPT_DUPLICATE;
        res.detail = "each agent files its effort receipt exactly once at boot; more than one receipt from: " + ", ".join(dupes);
    } elif missing or (len(seen) != REQUIRED_RECEIPTS) {
        res.reason = R_RECEIPTS_MISSING;
        res.detail = f"{len(seen)} of {REQUIRED_RECEIPTS} required effort receipts present; no receipt from: " + ", ".join(missing);
    } elif res.downgraded_agents {
        res.reason = R_RECEIPT_DOWNGRADED;
        res.detail = "effort was downgraded or the model was substituted for: " + ", ".join(res.downgraded_agents);
    } else {
        res.reason = R_OK;
        res.detail = f"{REQUIRED_RECEIPTS} of {REQUIRED_RECEIPTS} effort receipts present and none downgraded; run is " + res.run_label;
    }

    return res;
}

# --------------------------------------------------------------------------
# Check
# --------------------------------------------------------------------------

"""Parse `path` and evaluate it. Deterministic: the same file always yields the
same GateResult, and json.dumps(result.as_dict(), sort_keys=True) is stable."""
def check_gate(path: str) -> GateResult {
    if not os.path.isfile(path) {
        return GateResult(
            ok=False,
            reason=R_RECEIPTS_FILE_MISSING,
            detail="no readable effort receipt file at " + os.path.basename(path) + f"; the coordinator cannot leave WATCHING without {REQUIRED_RECEIPTS} effort_receipt.v1 records",
            run_label=RUN_LIVE,
            receipts_seen=0,
            agents_seen=[],
            missing=sorted(EFFORT_GATE_AGENTS),
            unexpected=[],
            downgraded_agents=[],
            blocked_agents=[],
            mocked_agents=[],
            invalid=[]
        );
    }
    return evaluate_receipts(parse_receipts(path));
}

# --------------------------------------------------------------------------
# Enforce
# --------------------------------------------------------------------------

"""Run the gate and record the outcome on the mesh event log.

  * a MOCKED run calls log.mark_mocked() FIRST, so the transition emitted below
    is labelled MOCKED and so is every event the log already held
  * the outcome is always emitted as a state.transition:
        pass -> WATCHING -> ESCALATED
        fail -> WATCHING -> WATCHING, with the reason in the event detail
  * the GateResult is returned to the caller

The signature has no flag, no override and no default that opens the gate.
Callers cannot pass anything that changes the verdict — the only input to the
verdict is the receipt file."""
def enforce_gate(path: str, log: Any, incident_id: str, ts_ms: int) -> GateResult {
    res = check_gate(path);

    if res.run_label == RUN_MOCKED {
        log.mark_mocked();
    }

    detail: dict = {
        "gate": "effort_receipt.v1",
        "required_receipts": REQUIRED_RECEIPTS,
        "ok": res.ok,
        "reason": res.reason,
        "explain": res.detail,
        "run_label": res.run_label,
        "receipts_seen": res.receipts_seen,
        "agents_seen": sorted(res.agents_seen),
        "missing": sorted(res.missing),
        "unexpected": sorted(res.unexpected),
        "downgraded_agents": sorted(res.downgraded_agents),
        "blocked_agents": sorted(res.blocked_agents),
        "mocked_agents": sorted(res.mocked_agents),
        "invalid": sorted(res.invalid)
    };

    state_to = S_WATCHING;
    if res.ok {
        state_to = S_ESCALATED;
    }

    log.transition(
        incident_id=incident_id,
        ts_ms=ts_ms,
        state_from=S_WATCHING,
        state_to=state_to,
        detail=detail
    );

    return res;
}
