#!/usr/bin/env python3
"""search.py -- offline lexical search over skills/index.json.

Stdlib only. No network, no API key, no embedding service. Loads the index
once, scores all candidates with a transparent keyword/BM25-ish scheme, and
returns/prints in well under a second.

CLI:
    python3 skills/search.py "<query>" [--top N] [--domain D] [--framework F]
    python3 skills/search.py --compact-menu
    python3 skills/search.py "<query>" --json-only

Importable (other scripts -- an MCP wrapper, skills/selection_log.py -- load
this module by file path and call search() directly, so this is the one
code path every consumer shares):

    from search import search
    result = search("compromised credential lateral movement enumeration", top=5)
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sys
from pathlib import Path

INDEX_PATH = Path(__file__).resolve().parent / "index.json"

# Kept textually in sync with build_index.py's STOPWORDS -- query tokens and
# index-time slug/one_line tokens are dropped through the same filter so the
# two sides speak the same vocabulary.
STOPWORDS = {
    "a", "an", "the", "and", "or", "but", "of", "in", "on", "at", "to", "for",
    "with", "by", "from", "as", "is", "are", "was", "were", "be", "been",
    "being", "this", "that", "these", "those", "it", "its", "into", "than",
    "then", "when", "using", "use", "used", "your", "you", "we", "can",
    "will", "shall", "may", "might", "must", "should", "would", "could",
    "do", "does", "did", "has", "have", "had", "not", "no", "if", "so",
    "such", "via", "across", "per", "over", "under", "between", "about",
    "also", "which", "who", "whom", "their", "them", "they", "he", "she",
    "his", "her", "our", "ours", "i", "me", "my", "mine", "up", "out",
    "off", "down", "all", "any", "each", "other", "some", "most", "own",
    "same", "too", "very", "just", "how", "what", "where", "why", "because",
    "one", "onto", "within",
}

TOKEN_RE = re.compile(r"[a-z0-9]+")
TECH_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
SPLIT_PARTS_RE = re.compile(r"[-_/ ]+")

_INDEX_CACHE = None


def _load_index() -> dict:
    global _INDEX_CACHE
    if _INDEX_CACHE is None:
        if not INDEX_PATH.exists():
            raise FileNotFoundError(
                f"index not found at {INDEX_PATH}; run `python3 skills/build_index.py` first"
            )
        with open(INDEX_PATH, "r", encoding="utf-8") as f:
            _INDEX_CACHE = json.load(f)
    return _INDEX_CACHE


def tokenize(text: str) -> list:
    return TOKEN_RE.findall(text.lower())


def stem(tok: str) -> str:
    """Light plural/-ing stemming. No external libs."""
    if len(tok) > 4 and tok.endswith("ies"):
        return tok[:-3] + "y"
    if len(tok) > 4 and tok.endswith("ing"):
        return tok[:-3]
    if len(tok) > 4 and tok.endswith("es") and tok[-3] in "sxzh":
        return tok[:-2]
    if len(tok) > 3 and tok.endswith("s") and not tok.endswith("ss"):
        return tok[:-1]
    return tok


def query_terms(query: str) -> list:
    toks = [t for t in tokenize(query) if len(t) >= 3 and t not in STOPWORDS]
    return [stem(t) for t in toks]


def _parts(s: str) -> list:
    return [p for p in SPLIT_PARTS_RE.split(s.lower()) if p]


def _field_hit(term: str, values: list) -> bool:
    """term is already lowercased+stemmed. values is a list of raw index
    strings (keywords / domains / frameworks). Matches on exact string,
    or on any stemmed hyphen/space-separated part of the string."""
    for v in values:
        vl = v.lower()
        if term == vl:
            return True
        for part in _parts(vl):
            if term == stem(part):
                return True
    return False


NAME_WEIGHT = 30.0
ONE_LINE_PHRASE_WEIGHT = 18.0
TECH_ID_WEIGHT = 50.0
RAW_TERM_TACTIC_WEIGHT = 40.0
KEYWORD_WEIGHT = 7.0
TACTIC_WEIGHT = 9.0
DOMAIN_WEIGHT = 4.0
NAME_TOKEN_WEIGHT = 5.0
ONE_LINE_TOKEN_WEIGHT = 2.5


def score_skill(rec: dict, raw_query_lower: str, q_terms: list,
                technique_ids: list, raw_terms_upper: list):
    score = 0.0
    matched = []
    matched_seen = set()  # lowercased forms, so "T1078" and "t1078" count as one

    def add_matched(tok):
        key = tok.lower()
        if key not in matched_seen:
            matched_seen.add(key)
            matched.append(tok)

    name_l = rec["name"].lower()
    one_line_l = rec["one_line"].lower()

    if raw_query_lower and raw_query_lower in name_l:
        score += NAME_WEIGHT
    if raw_query_lower and raw_query_lower in one_line_l:
        score += ONE_LINE_PHRASE_WEIGHT

    tactics_upper = [t.upper() for t in rec["tactics"]]

    # Direct ATT&CK-technique-id queries (e.g. "T1078", "T1583.001") get a
    # big, unambiguous boost against the tactics list.
    for tid in technique_ids:
        if tid in tactics_upper:
            score += TECH_ID_WEIGHT
            add_matched(tid)

    # Generalize the same idea to any other whitespace-delimited raw query
    # term that exactly matches a tactic id verbatim (NIST CSF "DE.CM-01",
    # ATLAS "AML.T0052", F3 "F1020.002", AI-RMF "MEASURE-2.7", ...).
    for term in raw_terms_upper:
        if term in tactics_upper and term not in technique_ids:
            score += RAW_TERM_TACTIC_WEIGHT
            add_matched(term)

    name_tokens = [stem(t) for t in tokenize(name_l) if len(t) >= 3]
    one_line_tokens = [stem(t) for t in tokenize(one_line_l) if len(t) >= 3]

    kw_norm = 1.0 + math.log(1 + len(rec["keywords"]))
    tac_norm = 1.0 + math.log(1 + len(rec["tactics"]))
    nl_norm = 1.0 + math.log(1 + len(name_tokens))
    ol_norm = 1.0 + math.log(1 + len(one_line_tokens))

    for term in q_terms:
        hit = False
        if _field_hit(term, rec["keywords"]):
            score += KEYWORD_WEIGHT / kw_norm
            hit = True
        if any(term == stem(p) for t in rec["tactics"] for p in _parts(t)):
            score += TACTIC_WEIGHT / tac_norm
            hit = True
        if _field_hit(term, rec["domains"]):
            score += DOMAIN_WEIGHT
            hit = True
        if term in name_tokens:
            score += NAME_TOKEN_WEIGHT / nl_norm
            hit = True
        if term in one_line_tokens:
            score += ONE_LINE_TOKEN_WEIGHT / ol_norm
            hit = True
        if hit:
            add_matched(term)

    return score, matched


def _as_filter_list(value):
    if value is None:
        return None
    return value if isinstance(value, list) else [value]


def search(query: str, top: int = 5, domain=None, framework=None) -> dict:
    """Search the pinned cybersecurity-skill index.

    Args:
        query: free-text query. ATT&CK technique ids (T1078, T1583.001) and
            other exact tactic ids (DE.CM-01, AML.T0052, ...) get a large
            direct-match boost.
        top: max results to return (default 5).
        domain: optional domain filter, a string or list of strings;
            case-insensitive substring match against each skill's domains.
        framework: optional framework filter, a string or list of strings;
            case-insensitive substring match against each skill's frameworks.

    Returns: the exact stdout JSON contract as a dict (see module docstring
        callers) -- query/repo_sha/index_schema/total_indexed/filters/count/results.
    """
    idx = _load_index()
    all_skills = idx["skills"]

    domain_filters = _as_filter_list(domain)
    framework_filters = _as_filter_list(framework)

    candidates = all_skills
    if domain_filters:
        dfl = [d.lower() for d in domain_filters]
        candidates = [
            r for r in candidates
            if any(any(f in d.lower() for d in r["domains"]) for f in dfl)
        ]
    if framework_filters:
        ffl = [f.lower() for f in framework_filters]
        candidates = [
            r for r in candidates
            if any(any(f in fw.lower() for fw in r["frameworks"]) for f in ffl)
        ]

    q = (query or "").strip()
    raw_query_lower = q.lower()
    q_terms = query_terms(q) if q else []
    technique_ids = list(dict.fromkeys(m.group(0).upper() for m in TECH_ID_RE.finditer(q)))
    raw_terms_upper = [t.upper() for t in q.split() if t]

    scored = []
    for rec in candidates:
        s, matched = score_skill(rec, raw_query_lower, q_terms, technique_ids, raw_terms_upper)
        if s > 0:
            scored.append((s, rec, matched))

    scored.sort(key=lambda x: -x[0])
    top_n = max(0, top)
    chosen = scored[:top_n]

    results = [
        {
            "id": rec["id"],
            "name": rec["name"],
            "path": rec["path"],
            "one_line": rec["one_line"],
            "score": round(s, 2),
            "domains": rec["domains"],
            "frameworks": rec["frameworks"],
            "tactics": rec["tactics"],
            "matched": matched,
        }
        for s, rec, matched in chosen
    ]

    return {
        "query": q,
        "repo_sha": idx.get("repo_sha", ""),
        "index_schema": idx.get("schema", ""),
        "total_indexed": idx.get("total_skills", len(all_skills)),
        "filters": {
            "domain": domain if domain else None,
            "framework": framework if framework else None,
        },
        "count": len(results),
        "results": results,
    }


def compact_menu() -> list:
    """The full 817-skill menu, trimmed to {id, name, one_line} each."""
    idx = _load_index()
    return [
        {"id": r["id"], "name": r["name"], "one_line": r["one_line"]}
        for r in idx["skills"]
    ]


def _build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="search.py",
        description="Offline lexical search over the pinned cybersecurity-skills index.",
    )
    parser.add_argument("query", nargs="?", default=None, help="free-text search query")
    parser.add_argument("--top", type=int, default=5)
    parser.add_argument("--domain", action="append", default=None,
                         help="filter by domain substring; repeatable")
    parser.add_argument("--framework", action="append", default=None,
                         help="filter by framework substring; repeatable")
    parser.add_argument("--compact-menu", action="store_true",
                         help="dump {id, name, one_line} for all indexed skills and exit")
    parser.add_argument("--json-only", action="store_true",
                         help="emit compact single-line JSON (default is indented JSON)")
    return parser


def main(argv=None) -> int:
    parser = _build_arg_parser()
    args = parser.parse_args(argv)

    try:
        if args.compact_menu:
            payload = compact_menu()
        else:
            if not args.query:
                raise ValueError("query is required unless --compact-menu is given")
            domain = args.domain[0] if args.domain and len(args.domain) == 1 else args.domain
            framework = args.framework[0] if args.framework and len(args.framework) == 1 else args.framework
            payload = search(args.query, top=args.top, domain=domain, framework=framework)
    except Exception as e:
        # Contract: non-zero exit, JSON {"error": ...} and nothing else on stdout.
        print(json.dumps({"error": str(e)}))
        return 1

    compact_output = args.json_only or args.compact_menu
    if compact_output:
        print(json.dumps(payload, ensure_ascii=False, separators=(",", ":")))
    else:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
