# incident/emit.jac — Incident -> the frozen incident.v1 payload.
#
# This is the only module that reads the Quarantine subgraph, and the only place
# attacker-influenced text appears in any output. It appears exactly once, inside
# `untrusted_data.fenced`, wrapped in the fence markers the frozen schema
# mandates, with a monitor-authored provenance label beside it. Every scored
# field — axes, families, stage_signatures, confidence, summary — is built from
# numbers and closed enums that were computed without ever seeing that text.
#
# Paths resolve from __file__, never from cwd, for the same reason
# coordinator/schema_check.jac does: a module cannot assume it was launched from
# its own directory, and a validator that silently validates nothing is worse
# than no validator.

import json;
import os;
import hashlib;
import from typing { cast }
import from jsonschema { Draft202012Validator }

import from incident.graph { IncidentGraph, Incident, Quarantine, Quarantined }

glob:pub HERE: str = os.path.dirname(os.path.abspath(__file__));
glob:pub SCHEMA_DIR: str = os.path.join(os.path.dirname(HERE), "contracts", "mesh");
glob:pub SCHEMA_CACHE: dict = {};

glob:pub FENCE_OPEN: str = "<<<UNTRUSTED>>>";
glob:pub FENCE_CLOSE: str = "<<</UNTRUSTED>>>";
glob:pub FENCE_MAX: int = 4000;
glob:pub SUMMARY_MAX: int = 600;


"""Load and memoise a frozen mesh schema by short name."""
def load_schema(name: str) -> dict {
    if name in SCHEMA_CACHE {
        return dict(SCHEMA_CACHE[name]);
    }
    path = os.path.join(SCHEMA_DIR, name + ".schema.json");
    if not os.path.isfile(path) {
        raise ValueError("emit: no such frozen contract: " + path);
    }
    with open(path, "r") as fh {
        schema = json.load(fh);
    }
    SCHEMA_CACHE[name] = schema;
    return schema;
}


"""Validate a payload against a frozen mesh schema. Raises on the first error."""
def validate_incident(payload: dict) -> None {
    v = Draft202012Validator(load_schema("incident.v1"));
    problems = [];
    for err in v.iter_errors(payload) {
        problems.append(str(list(err.path)) + ": " + str(err.message));
    }
    if len(problems) > 0 {
        raise ValueError("incident.v1 violation -> " + "; ".join(sorted(problems)));
    }
}


"""Pseudonymous principal identifier.

The frozen schema calls this a *pseudonymous* identifier and the coordinator's
fixtures show the `ph_` prefix, so the raw principal id is hashed rather than
passed through. Containment does not suffer: session_ids and src_ips travel
verbatim in the same object, and those are what a responder actually revokes or
blocks."""
def principal_hash(principal_id: str, subject_key: str) -> str {
    seed = principal_id if principal_id != "" else subject_key;
    return "ph_" + hashlib.sha256(seed.encode("utf-8")).hexdigest()[0:12];
}


"""Wrap untrusted text in the mandated fence, truncating the TEXT to fit the
4000-character cap rather than dropping the fence — an unfenced blob would be
indistinguishable from monitor-authored content downstream."""
def fence(text: str) -> str {
    budget: int = FENCE_MAX - len(FENCE_OPEN) - len(FENCE_CLOSE);
    body: str = str(text);
    if len(body) > budget {
        body = body[0:budget];
    }
    return FENCE_OPEN + body + FENCE_CLOSE;
}


"""Every quarantined blob belonging to this incident's evidence, fenced."""
def fenced_for(g: IncidentGraph, evidence: list) -> list {
    cited: set[str] = set();
    for e in evidence {
        cited.add(str(e));
    }
    out = [];
    seen: set[str] = set();
    for q in [g ->:Quarantined:-> Quarantine] {
        if q.event_id not in cited {
            continue;
        }
        key = str(q.label) + "|" + str(q.text);
        if key in seen {
            continue;
        }
        seen.add(key);
        out.append({"label": str(q.label), "text": fence(str(q.text))});
    }
    bykey = {};
    for item in out {
        bykey[str(item["label"]) + "|" + str(item["text"])] = item;
    }
    ordered = [];
    for k in sorted(list(bykey.keys())) {
        ordered.append(bykey[k]);
    }
    return ordered;
}


"""Build the incident.v1 payload for one Incident node.

`rows` are the subject's Observation projections, used only to collect the
verbatim correlation handles (sessions, addresses, user-agent hashes) the
schema's join_keys asks for. No free text is read here."""
def to_incident_v1(g: IncidentGraph, inc: Incident, rows: list,
                   detected_at_ms: int, summary: str) -> dict {
    cited: set[str] = set();
    for e in inc.evidence {
        cited.add(str(e));
    }
    sessions: set[str] = set();
    ips: set[str] = set();
    uas: set[str] = set();
    principal = "";
    tenant = "";
    for r in rows {
        if str(r.get("event_id", "")) not in cited {
            continue;
        }
        if str(r.get("session_id", "")) != "" {
            sessions.add(str(r["session_id"]));
        }
        if str(r.get("src_ip", "")) != "" {
            ips.add(str(r["src_ip"]));
        }
        if str(r.get("ua_hash", "")) != "" {
            uas.add(str(r["ua_hash"]));
        }
        if principal == "" and str(r.get("principal_id", "")) != "" {
            principal = str(r["principal_id"]);
        }
        if tenant == "" and str(r.get("actor_tenant_id", "")) != "" {
            tenant = str(r["actor_tenant_id"]);
        }
    }

    trimmed: str = str(summary);
    if len(trimmed) > SUMMARY_MAX {
        trimmed = trimmed[0:(SUMMARY_MAX - 1)] + ".";
    }

    payload = {
        "incident_id": inc.incident_id,
        "schema_version": "incident.v1",
        "detected_at_ms": int(detected_at_ms),
        "confidence": float(inc.confidence),
        "axes": sorted([str(x) for x in inc.axes]),
        "families": sorted([str(x) for x in inc.families]),
        "join_keys": {
            "principal_hash": principal_hash(principal, inc.subject_key),
            "tenant": tenant,
            "session_ids": sorted(list(sessions)),
            "src_ips": sorted(list(ips)),
            "user_agents": sorted(list(uas))
        },
        "evidence": sorted([str(x) for x in inc.evidence]),
        "stage_signatures": sorted([int(x) for x in inc.stage_signatures]),
        "summary": trimmed,
        "untrusted_data": {"fenced": fenced_for(g, inc.evidence)}
    };
    validate_incident(payload);
    return payload;
}
