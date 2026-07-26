#!/usr/bin/env python3
"""monitor/skills_bridge.py — targeted access to the pinned cybersecurity-skills index.

Stdlib only, Python 3.9 compatible. No network.

The pinned library holds 817 skills. Loading it wholesale would be both enormous and
pointless: an incident calls for a handful of techniques, not a library. This module builds a
search query from the incident's MONITOR-AUTHORED fields, asks skills/search.py for the top N,
records the selection in the audit log, and reads back only those files, capped in size and
count.

PROMPT-INJECTION NOTE. The query is built from `families`, `axes`, and `stage_signatures`
only — closed enums, shape-checked labels, and integers. It is never built from
`untrusted_data`, from `summary`, from `evidence`, or from any string carried in on a window
frame. An attacker who could steer this query would be able to steer which defensive playbook
the monitor reads; that channel is closed the same way the model-input channel is closed in
hermes_client.build_model_input().
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_REPO_ROOT = _HERE.parent
SELECTION_LOG_PATH = _REPO_ROOT / "skills" / "selection_log.py"

#: The only trees load_selected() will read from. skills/ holds the index and its tooling;
#: vendor/cybersecurity-skills/ holds the pinned 817-skill library the index points into.
#: A selected path that resolves outside both is refused, not read.
ALLOWED_SKILL_ROOTS = (
    _REPO_ROOT / "skills",
    _REPO_ROOT / "vendor" / "cybersecurity-skills",
)

AGENT = "monitor"
DEFAULT_TOP = 5
MAX_SKILL_FILES = 8
DEFAULT_MAX_BYTES = 20000

#: The ten authorized-scenario attack steps, as search vocabulary.
STAGE_SIGNATURE_NAMES = {
    1: "reconnaissance",
    2: "failed logins password spraying",
    3: "compromised valid account credential abuse",
    4: "high-speed enumeration discovery",
    5: "permission boundary probing privilege escalation",
    6: "post-deny adaptation evasion",
    7: "rotating source identities proxy infrastructure",
    8: "sensitive data discovery collection",
    9: "lateral movement via integrations",
    10: "canary token protected export exfiltration",
}

#: incident.v1 families -> defensive vocabulary.
FAMILY_TERMS = {
    "denial_shape": "authorization denial anomaly detection",
    "breadth": "enumeration breadth detection",
    "novelty": "novel endpoint access anomaly",
    "cadence": "automated request cadence detection",
    "pivot": "attacker pivot endpoint class change",
    "escalation": "privilege escalation detection",
    "canary": "canary token honeytoken alerting",
}

#: The call contract this module expects of skills/search.py. Reported verbatim in the
#: structured `blocked` result so the owning track has the exact shape to build against.
SEARCH_CONTRACT = {
    "module": "skills/search.py",
    "function": "search(query, top=5, domain=None, framework=None) -> dict",
    "returns": {
        "results": [{"id": "str", "path": "str", "score": "float", "...": "optional extras"}],
        "repo_sha": "str",
    },
    "notes": (
        "Called indirectly via skills/selection_log.py::search_and_log(run_id, agent, "
        "incident_id, query, top, domain, framework), which logs path + repo SHA per "
        "selection to runs/<run_id>/skills_selected.jsonl."
    ),
}

#: Shape check for monitor-authored axis labels reaching the query (same rule as
#: hermes_client._AXIS_RE).
_AXIS_RE = re.compile(r"^[a-z0-9][a-z0-9_.]{0,63}$")


def _load_selection_log():
    """Load skills/selection_log.py by file path so cwd never matters."""
    if not SELECTION_LOG_PATH.exists():
        raise ImportError("skills/selection_log.py not found at %s" % SELECTION_LOG_PATH)
    spec = importlib.util.spec_from_file_location("_monitor_selection_log", SELECTION_LOG_PATH)
    if spec is None or spec.loader is None:
        raise ImportError("could not create an import spec for %s" % SELECTION_LOG_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        sys.modules.pop(spec.name, None)
        raise ImportError("failed to import %s: %s" % (SELECTION_LOG_PATH, exc))
    return module


def _is_within(candidate, root):
    """True iff `candidate` resolves inside `root`. Blocks ../ traversal and symlink escape."""
    try:
        candidate.relative_to(root.resolve())
    except (ValueError, OSError):
        return False
    return True


def query_for_incident(incident):
    """Build a skills-search query from MONITOR-AUTHORED fields only.

    Sources, and nothing else:
      * `families`      — closed incident.v1 enum, mapped to defensive vocabulary.
      * `stage_signatures` — integers 1..10, mapped to their step names.
      * `axes`          — monitor-authored labels, shape-checked before use.

    Never sourced: `untrusted_data`, `summary`, `evidence`, `incident_id`, or any string that
    arrived on a window frame. Those are attacker-influenceable, and a query is an instruction
    about what defensive guidance to load.
    """
    if not isinstance(incident, dict):
        raise TypeError("incident must be a dict, got %s" % type(incident).__name__)

    terms = []

    for family in sorted({f for f in (incident.get("families") or []) if isinstance(f, str)}):
        phrase = FAMILY_TERMS.get(family)
        if phrase:
            terms.append(phrase)

    for sig in sorted(
        {
            s
            for s in (incident.get("stage_signatures") or [])
            if isinstance(s, int) and not isinstance(s, bool) and 1 <= s <= 10
        }
    ):
        terms.append(STAGE_SIGNATURE_NAMES[sig])

    for axis in sorted({a for a in (incident.get("axes") or []) if isinstance(a, str)}):
        if _AXIS_RE.match(axis):
            terms.append(axis.replace("_", " ").replace(".", " "))

    if not terms:
        terms.append("behavioral anomaly detection incident response")

    # Deduplicate while preserving order, then flatten to a single query string.
    seen = set()
    ordered = []
    for term in terms:
        key = term.strip().lower()
        if key and key not in seen:
            seen.add(key)
            ordered.append(term.strip())
    return " ".join(ordered)


def select_skills(incident, run_id, top=DEFAULT_TOP):
    """Search the pinned index for this incident and log the selection.

    Delegates to skills/selection_log.py::search_and_log(), which calls skills/search.py and
    records path + repo SHA per selection.

    skills/search.py is owned by another track. If it is missing (or does not define
    ``search()``), search_and_log() raises ImportError. That is NOT fatal here: this function
    returns a structured ``{"status": "blocked", "reason": ..., "contract": ...}`` and still
    writes a selection-log entry through log_selection() with an empty ``selected`` list, so
    the audit trail records that a search was attempted, when, and with what query.
    """
    if not isinstance(incident, dict):
        raise TypeError("incident must be a dict, got %s" % type(incident).__name__)

    incident_id = incident.get("incident_id")
    if not isinstance(incident_id, str) or not incident_id:
        raise ValueError("incident.incident_id is required and must be a non-empty string")

    query = query_for_incident(incident)
    selection_log = _load_selection_log()

    try:
        result = selection_log.search_and_log(
            run_id=run_id,
            agent=AGENT,
            incident_id=incident_id,
            query=query,
            top=top,
        )
    except ImportError as exc:
        # skills/search.py is not available yet. Record the attempt, then report blocked.
        log_path = selection_log.log_selection(
            run_id=run_id,
            agent=AGENT,
            incident_id=incident_id,
            query=query,
            selected=[],
        )
        return {
            "status": "blocked",
            "reason": str(exc),
            "contract": SEARCH_CONTRACT,
            "query": query,
            "incident_id": incident_id,
            "selected": [],
            "log_path": str(log_path),
        }

    results = result.get("results") or []
    return {
        "status": "ok",
        "query": query,
        "incident_id": incident_id,
        "selected": [
            {
                "id": item.get("id", ""),
                "path": item.get("path", ""),
                "score": item.get("score", 0.0),
            }
            for item in results
            if isinstance(item, dict)
        ],
        "repo_sha": result.get("repo_sha", ""),
        "log_path": result.get("log_path", ""),
    }


def load_selected(selection, max_bytes=DEFAULT_MAX_BYTES):
    """Read back ONLY the selected skill files, capped in size and count.

    Never walks the library, never globs, never reads a file that was not returned by the
    search. Each file is truncated at `max_bytes`; at most MAX_SKILL_FILES files are opened,
    total. A path that escapes the skills tree, or does not exist, is reported as an error
    entry rather than read.

    Returns a list of {"id", "path", "bytes", "truncated", "text"} or {"id", "path", "error"}.
    """
    if not isinstance(selection, dict):
        raise TypeError("selection must be a dict, got %s" % type(selection).__name__)

    loaded = []
    for item in (selection.get("selected") or [])[:MAX_SKILL_FILES]:
        if not isinstance(item, dict):
            continue
        raw_path = item.get("path") or ""
        entry_id = item.get("id", "")
        if not raw_path:
            loaded.append({"id": entry_id, "path": "", "error": "empty path"})
            continue

        candidate = Path(raw_path)
        if not candidate.is_absolute():
            candidate = _REPO_ROOT / candidate
        try:
            resolved = candidate.resolve()
        except OSError as exc:
            loaded.append({"id": entry_id, "path": raw_path, "error": "unresolvable: %s" % exc})
            continue

        # Containment: never read outside the pinned skill trees.
        if not any(_is_within(resolved, root) for root in ALLOWED_SKILL_ROOTS):
            loaded.append(
                {
                    "id": entry_id,
                    "path": str(resolved),
                    "error": "path outside the pinned skill trees — refusing to read",
                }
            )
            continue

        if not resolved.is_file():
            loaded.append({"id": entry_id, "path": str(resolved), "error": "not a file"})
            continue

        try:
            data = resolved.read_bytes()[: max_bytes + 1]
        except OSError as exc:
            loaded.append({"id": entry_id, "path": str(resolved), "error": "read failed: %s" % exc})
            continue

        truncated = len(data) > max_bytes
        data = data[:max_bytes]
        loaded.append(
            {
                "id": entry_id,
                "path": str(resolved),
                "bytes": len(data),
                "truncated": truncated,
                "text": data.decode("utf-8", "replace"),
            }
        )
    return loaded


# --- CLI -------------------------------------------------------------------------------


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="skills_bridge.py",
        description="Select cybersecurity skills for one incident, from monitor-authored fields only.",
    )
    parser.add_argument("--incident", required=True, help="Path to an incident.v1 JSON file.")
    parser.add_argument("--run-id", required=True, help="Run identifier (a plain path segment).")
    parser.add_argument("--top", type=int, default=DEFAULT_TOP, help="How many skills to select.")
    parser.add_argument(
        "--load",
        action="store_true",
        help="Also read back the selected skill files (capped in size and count).",
    )
    args = parser.parse_args(argv)

    incident = json.loads(Path(args.incident).read_text(encoding="utf-8"))
    selection = select_skills(incident, run_id=args.run_id, top=args.top)
    print(json.dumps(selection, indent=2, ensure_ascii=False, sort_keys=True))

    if args.load:
        files = load_selected(selection)
        summary = [
            {k: v for k, v in entry.items() if k != "text"} for entry in files
        ]
        print("--- loaded skill files ---")
        print(json.dumps(summary, indent=2, ensure_ascii=False, sort_keys=True))

    return 0 if selection.get("status") == "ok" else 0


if __name__ == "__main__":
    raise SystemExit(main())
