#!/usr/bin/env python3
"""skills/selection_log.py — append-only JSONL logger for cybersecurity-skill selections.

Stdlib only. No network calls. (subprocess is used only to invoke the local `git`
binary against the already-vendored checkout on disk — nothing touches a socket.)

Writes one JSON record per line to:

    runs/<run_id>/skills_selected.jsonl        (relative to the repo root)

Record shape (exactly these keys)::

    {
      "ts": "<ISO8601 UTC, e.g. 2026-07-26T18:04:11Z>",
      "agent": "<str>",
      "incident_id": "<str>",
      "query": "<str>",
      "selected": [{"id": "...", "path": "...", "score": 0.0}, ...],
      "repo_sha": "673da1f3b0b7be34ffc9624ef3858fe45f1c3bed"
    }

Concurrency
-----------
Multiple agent processes may append to this same file at once (up to six runtimes in
this project). Safety relies on ONE assumption, documented here rather than enforced
with a lock: a single ``os.write()`` syscall, on a file descriptor opened with
``O_APPEND``, writing one complete JSONL line, will not interleave with a concurrent
writer's own single-write() call on a local (non-network) POSIX filesystem, as long as
the line stays under the filesystem's atomic-write threshold (in practice several KB —
comfortably above the size of one of these records, which holds a handful of
id/path/score entries). ``O_APPEND`` additionally makes the seek-to-end + write atomic
against races on the file's length. So: one write() call == one full, uninterleaved
line. This does NOT hold on NFS-style network filesystems or if a record ever grows to
tens of KB — neither applies here.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

PINNED_REPO_SHA = "673da1f3b0b7be34ffc9624ef3858fe45f1c3bed"


def _repo_root() -> Path:
    """Repo root, resolved from this file's own location (skills/selection_log.py)."""
    return Path(__file__).resolve().parent.parent


def _now_iso() -> str:
    """ISO8601 UTC, second precision, Z suffix — e.g. 2026-07-26T18:04:11Z."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _resolve_repo_sha() -> str:
    """Resolve the vendored skills repo's pinned commit SHA, in order:

    1. ``git -C vendor/cybersecurity-skills rev-parse HEAD`` (live checkout)
    2. the ``repo_sha`` recorded in ``skills/index.json``
    3. the hardcoded ``PINNED_REPO_SHA`` constant

    Never returns an empty string.
    """
    repo_root = _repo_root()
    vendor_dir = repo_root / "vendor" / "cybersecurity-skills"
    try:
        proc = subprocess.run(
            ["git", "-C", str(vendor_dir), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        sha = proc.stdout.strip()
        if proc.returncode == 0 and sha:
            return sha
    except (OSError, subprocess.SubprocessError):
        pass

    index_path = repo_root / "skills" / "index.json"
    try:
        with index_path.open("r", encoding="utf-8") as fh:
            data = json.load(fh)
        sha = data.get("repo_sha")
        if sha:
            return str(sha)
    except (OSError, ValueError, AttributeError, json.JSONDecodeError):
        pass

    return PINNED_REPO_SHA


def _normalize_selected(selected: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Extract just id/path/score from each entry.

    Accepts either the raw ``results`` list from search.py (each item also carries
    name/one_line/domains/frameworks/tactics/matched) or an already-trimmed list of
    ``{"id", "path", "score"}`` dicts. Either way, only id/path/score are kept.
    """
    normalized: List[Dict[str, Any]] = []
    for item in selected:
        if not isinstance(item, dict):
            raise TypeError(f"each `selected` entry must be a dict, got {type(item).__name__}")
        normalized.append(
            {
                "id": item.get("id", ""),
                "path": item.get("path", ""),
                "score": item.get("score", 0.0),
            }
        )
    return normalized


def _validate_run_id(run_id: str) -> str:
    if not run_id or "/" in run_id or "\\" in run_id or run_id in (".", ".."):
        raise ValueError(f"invalid run_id (must be a plain path segment, no separators): {run_id!r}")
    return run_id


def log_selection(
    run_id: str,
    agent: str,
    incident_id: str,
    query: str,
    selected: List[Dict[str, Any]],
    repo_sha: Optional[str] = None,
) -> Path:
    """Append one JSONL record to runs/<run_id>/skills_selected.jsonl (repo-root relative).

    Returns the Path written to. Append-only: never truncates or rewrites existing
    lines (see module docstring for the concurrency assumption this relies on).
    """
    run_id = _validate_run_id(run_id)
    resolved_sha = repo_sha if repo_sha else _resolve_repo_sha()

    record = {
        "ts": _now_iso(),
        "agent": str(agent),
        "incident_id": str(incident_id),
        "query": str(query),
        "selected": _normalize_selected(selected),
        "repo_sha": resolved_sha,
    }

    out_path = _repo_root() / "runs" / run_id / "skills_selected.jsonl"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    line = (json.dumps(record, ensure_ascii=False) + "\n").encode("utf-8")

    # Single os.write() of the complete line on an O_APPEND fd -- see module docstring
    # ("Concurrency") for why this is safe across concurrent multi-process appends.
    fd = os.open(str(out_path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    try:
        os.write(fd, line)
    finally:
        os.close(fd)

    return out_path


def _load_search_module():
    """Load skills/search.py by file path so this works regardless of cwd or sys.path.

    Raises ImportError with a clear message (no raw traceback) if it's missing, fails
    to import, or doesn't define search().
    """
    search_path = _repo_root() / "skills" / "search.py"
    if not search_path.exists():
        raise ImportError(
            f"skills/search.py not found at {search_path}. "
            "search_and_log() requires skills/search.py to exist first."
        )

    spec = importlib.util.spec_from_file_location("_cybersec_skills_search", search_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"could not create an import spec for {search_path}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    try:
        spec.loader.exec_module(module)
    except Exception as exc:
        sys.modules.pop(spec.name, None)
        raise ImportError(f"failed to import {search_path}: {exc}") from exc

    if not hasattr(module, "search"):
        sys.modules.pop(spec.name, None)
        raise ImportError(f"{search_path} does not define a search() function")

    return module


def search_and_log(
    run_id: str,
    agent: str,
    incident_id: str,
    query: str,
    top: int = 5,
    domain: Optional[str] = None,
    framework: Optional[str] = None,
) -> Dict[str, Any]:
    """Run skills/search.py's search(), log the selection, and return the search
    result dict with an added "log_path" key (str, JSON-serializable)."""
    module = _load_search_module()
    result = module.search(query, top=top, domain=domain, framework=framework)

    log_path = log_selection(
        run_id=run_id,
        agent=agent,
        incident_id=incident_id,
        query=query,
        selected=result.get("results", []),
        repo_sha=result.get("repo_sha"),
    )

    out = dict(result)
    out["log_path"] = str(log_path)
    return out


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Search the pinned cybersecurity-skills index and log the selection (append-only JSONL)."
    )
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--agent", required=True)
    parser.add_argument("--incident-id", required=True)
    parser.add_argument("--query", default=None, help="Search query (required unless --selected-json is given)")
    parser.add_argument("--top", type=int, default=5)
    parser.add_argument("--domain", default=None)
    parser.add_argument("--framework", default=None)
    parser.add_argument(
        "--selected-json",
        default=None,
        metavar="PATH_OR_-",
        help="Log an already-computed search.py result without re-searching. "
        "Use '-' to read the JSON object from stdin, or give a file path.",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    try:
        if args.selected_json is not None:
            raw = sys.stdin.read() if args.selected_json == "-" else Path(args.selected_json).read_text(encoding="utf-8")
            payload = json.loads(raw)

            if isinstance(payload, list):
                selected = payload
                query = args.query if args.query is not None else ""
                repo_sha = None
                output: Dict[str, Any] = {"query": query, "results": payload}
            elif isinstance(payload, dict):
                selected = payload.get("results", payload.get("selected", []))
                query = args.query if args.query is not None else payload.get("query", "")
                repo_sha = payload.get("repo_sha")
                output = dict(payload)
            else:
                raise ValueError("--selected-json input must be a JSON object or array")

            log_path = log_selection(
                run_id=args.run_id,
                agent=args.agent,
                incident_id=args.incident_id,
                query=query,
                selected=selected,
                repo_sha=repo_sha,
            )
            output["log_path"] = str(log_path)
            print(json.dumps(output))
        else:
            if args.query is None:
                parser.error("--query is required unless --selected-json is given")
            result = search_and_log(
                run_id=args.run_id,
                agent=args.agent,
                incident_id=args.incident_id,
                query=args.query,
                top=args.top,
                domain=args.domain,
                framework=args.framework,
            )
            print(json.dumps(result))
    except Exception as exc:  # surface one clear line on stderr, not a raw traceback
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
