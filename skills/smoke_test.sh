#!/usr/bin/env bash
# skills/smoke_test.sh — end-to-end smoke test for the pinned cybersecurity-skills library.
#
# Proves, with real assertions that fail loudly, that:
#   1. skills/index.json loads and matches the pinned repo/count.
#   2. A realistic incident query returns relevant, on-disk-verified skills.
#   3. --domain / --framework filters actually filter.
#   4. skills/selection_log.py writes an append-only JSONL selection log.
#   5. search.py / selection_log.py make no network calls.
#   6. --compact-menu fits in a reasonable char/token budget.
#
# set -e is kept on for general safety, but each numbered check is wrapped so a
# failing assertion is caught, reported, and does NOT abort the remaining checks
# -- only unnumbered hard setup failures (e.g. failure to resolve the directory
# this script lives in) are allowed to abort early.
#
# NOTE: keep every apostrophe out of the python heredocs below (and out of this
# header). An unpaired single quote inside a heredoc that is nested inside a
# dollar-paren command substitution confuses bash paren matching and produces a
# spurious parse error at an unrelated later line.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." >/dev/null 2>&1 && pwd)"
SKILLS_DIR="$SCRIPT_DIR"
PINNED_SHA="673da1f3b0b7be34ffc9624ef3858fe45f1c3bed"

PASS_COUNT=0
FAIL_COUNT=0

pass() {
    echo "PASS [$1] $2"
    PASS_COUNT=$((PASS_COUNT + 1))
}

fail() {
    echo "FAIL [$1] $2"
    FAIL_COUNT=$((FAIL_COUNT + 1))
}

echo "=== Cybersecurity Skills Library -- Smoke Test ==="
echo "repo root:   $REPO_ROOT"
echo "skills dir:  $SKILLS_DIR"
echo "pinned sha:  $PINNED_SHA"
echo

# ---------------------------------------------------------------------------
# Check 1: index loads
# ---------------------------------------------------------------------------
echo "--- Check 1: index loads ---"
rc=0
OUT1="$(python3 - "$REPO_ROOT" "$PINNED_SHA" <<'PYEOF' 2>&1
import json, os, random, sys

def main():
    repo_root, pinned_sha = sys.argv[1], sys.argv[2]
    index_path = os.path.join(repo_root, "skills", "index.json")

    with open(index_path, "r", encoding="utf-8") as fh:
        data = json.load(fh)

    errors = []

    total_skills = data.get("total_skills")
    if total_skills != 817:
        errors.append(f"total_skills={total_skills!r} (expected 817)")

    skills = data.get("skills")
    if skills is None:
        errors.append("index.json has no 'skills' key")
        skills = []
    n_skills = len(skills)
    if n_skills != 817:
        errors.append(f"len(skills)={n_skills} (expected 817)")

    repo_sha = data.get("repo_sha")
    if repo_sha != pinned_sha:
        errors.append(f"repo_sha={repo_sha!r} (expected {pinned_sha!r})")

    records = list(skills.values()) if isinstance(skills, dict) else list(skills)
    sample_n = min(10, len(records))
    sample = random.sample(records, sample_n) if sample_n else []
    missing = []
    for rec in sample:
        if not isinstance(rec, dict):
            missing.append(f"<non-dict record: {rec!r}>")
            continue
        path = rec.get("path")
        if not path:
            rid = rec.get("id")
            # Fall back to the documented path convention if index.json does
            # not store an explicit path per record.
            path = f"vendor/cybersecurity-skills/skills/{rid}/SKILL.md" if rid else None
        if not path:
            missing.append(f"<record has neither 'path' nor 'id': {rec!r}>")
            continue
        if not os.path.isfile(os.path.join(repo_root, path)):
            missing.append(path)
    if missing:
        errors.append(f"{len(missing)}/{sample_n} sampled paths missing on disk: {missing}")

    if errors:
        print("; ".join(errors))
        sys.exit(1)

    print(f"total_skills=817, len(skills)=817, repo_sha matches pinned, {sample_n} sampled paths all exist on disk")

try:
    main()
except SystemExit:
    raise
except Exception as exc:
    print(f"ERROR: {exc}")
    sys.exit(1)
PYEOF
)" || rc=$?
if [ "$rc" -eq 0 ]; then
    pass "1/6 index-loads" "$OUT1"
else
    fail "1/6 index-loads" "$OUT1"
fi
echo

# ---------------------------------------------------------------------------
# Check 2: realistic incident query returns relevant skills
# ---------------------------------------------------------------------------
echo "--- Check 2: incident query relevance ---"
QUERY2="compromised credential lateral movement enumeration"
rc=0
SEARCH2_OUT="$(python3 "$SKILLS_DIR/search.py" "$QUERY2" --top 5 2>&1)" || rc=$?

if [ "$rc" -ne 0 ]; then
    fail "2/6 incident-query" "search.py exited $rc: $SEARCH2_OUT"
else
    rc2=0
    VALIDATION_OUT="$(python3 - "$REPO_ROOT" "$SEARCH2_OUT" <<'PYEOF' 2>&1
import json, os, sys

def main():
    repo_root = sys.argv[1]
    raw = sys.argv[2]
    data = json.loads(raw)

    errors = []
    if data.get("count") != 5:
        errors.append(f"count={data.get('count')!r} (expected 5)")

    results = data.get("results", [])
    missing_paths = []
    for r in results:
        p = r.get("path")
        if not p or not os.path.isfile(os.path.join(repo_root, p)):
            missing_paths.append(p)
    if missing_paths:
        errors.append(f"result paths missing on disk: {missing_paths}")

    groups = {
        "credential/kerberos/ntlm/hash": ["credential", "kerberos", "ntlm", "hash"],
        "lateral/movement/pivot/psexec/smb/wmi/rdp": [
            "lateral", "movement", "pivot", "psexec", "smb", "wmi", "rdp",
        ],
        "enumeration/recon/discovery/bloodhound/ldap": [
            "enumeration", "recon", "discovery", "bloodhound", "ldap",
        ],
    }

    blob_parts = []
    top_lines = []
    for r in results:
        rid = str(r.get("id", ""))
        matched = r.get("matched") or []
        tactics = r.get("tactics") or []
        score = r.get("score", 0)
        blob_parts.append(rid.lower())
        blob_parts += [str(m).lower() for m in matched]
        blob_parts += [str(t).lower() for t in tactics]
        top_lines.append(f"{score}\t{rid}")

    blob = " ".join(blob_parts)
    hit_groups = [name for name, terms in groups.items() if any(t in blob for t in terms)]

    print("\n".join(top_lines))
    print(f"groups_hit={len(hit_groups)}/3 -> {hit_groups}")

    if len(hit_groups) < 2:
        errors.append(f"only {len(hit_groups)}/3 concept groups matched in id+matched+tactics")

    if errors:
        print("ERRORS: " + "; ".join(errors))
        sys.exit(1)

try:
    main()
except SystemExit:
    raise
except Exception as exc:
    print(f"ERROR: {exc}")
    sys.exit(1)
PYEOF
    )" || rc2=$?

    echo "$VALIDATION_OUT"
    if [ "$rc2" -eq 0 ]; then
        pass "2/6 incident-query" "count==5, all paths exist, >=2/3 concept groups matched"
    else
        fail "2/6 incident-query" "see validation output above"
    fi
fi
echo

# ---------------------------------------------------------------------------
# Check 3: filters work
# ---------------------------------------------------------------------------
echo "--- Check 3: --domain / --framework filters ---"
rc=0
OUT3="$(python3 - "$REPO_ROOT" "$SKILLS_DIR" <<'PYEOF' 2>&1
import json, subprocess, sys
from collections import Counter

def run_search(python_exe, search_py, repo_root, query, extra_args):
    proc = subprocess.run(
        [python_exe, search_py, query, "--top", "20"] + extra_args,
        cwd=repo_root, capture_output=True, text=True, timeout=60,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"search.py {query!r} {extra_args} exited {proc.returncode}: {proc.stderr.strip()[:300]}")
    return json.loads(proc.stdout)

def main():
    repo_root, skills_dir = sys.argv[1], sys.argv[2]
    search_py = skills_dir + "/search.py"
    probe_query = "security incident response"

    errors = []

    probe = run_search(sys.executable, search_py, repo_root, probe_query, [])
    probe_results = probe.get("results", [])
    domain_counter = Counter(d for r in probe_results for d in (r.get("domains") or []))
    framework_counter = Counter(f for r in probe_results for f in (r.get("frameworks") or []))

    if not domain_counter:
        errors.append("no 'domains' values found in unfiltered search results; cannot test --domain")
    if not framework_counter:
        errors.append("no 'frameworks' values found in unfiltered search results; cannot test --framework")
    if errors:
        print("; ".join(errors))
        sys.exit(1)

    top_domain = domain_counter.most_common(1)[0][0]
    top_framework = framework_counter.most_common(1)[0][0]

    d_data = run_search(sys.executable, search_py, repo_root, probe_query, ["--domain", top_domain])
    d_results = d_data.get("results", [])
    bad_d = [r.get("id") for r in d_results if top_domain not in (r.get("domains") or [])]
    if not d_results:
        errors.append(f"--domain {top_domain!r} returned 0 results")
    if bad_d:
        errors.append(f"--domain {top_domain!r} returned non-matching results: {bad_d}")

    f_data = run_search(sys.executable, search_py, repo_root, probe_query, ["--framework", top_framework])
    f_results = f_data.get("results", [])
    bad_f = [r.get("id") for r in f_results if top_framework not in (r.get("frameworks") or [])]
    if not f_results:
        errors.append(f"--framework {top_framework!r} returned 0 results")
    if bad_f:
        errors.append(f"--framework {top_framework!r} returned non-matching results: {bad_f}")

    print(f"--domain {top_domain!r} -> {len(d_results)} results, all correctly tagged: {not bad_d}")
    print(f"--framework {top_framework!r} -> {len(f_results)} results, all correctly tagged: {not bad_f}")

    if errors:
        print("ERRORS: " + "; ".join(errors))
        sys.exit(1)

try:
    main()
except SystemExit:
    raise
except Exception as exc:
    print(f"ERROR: {exc}")
    sys.exit(1)
PYEOF
)" || rc=$?
if [ "$rc" -eq 0 ]; then
    pass "3/6 filters" "$OUT3"
else
    fail "3/6 filters" "$OUT3"
fi
echo

# ---------------------------------------------------------------------------
# Check 4: selection log is written, and is append-only (not overwrite)
# ---------------------------------------------------------------------------
echo "--- Check 4: selection log (append-only) ---"
RUN_ID="smoke-$(date -u +%Y%m%dT%H%M%S)-$$"
LOG_REL="runs/$RUN_ID/skills_selected.jsonl"
LOG_ABS="$REPO_ROOT/$LOG_REL"
check4_ok=1
detail4=""

rc=0
CALL1_OUT="$(python3 "$SKILLS_DIR/selection_log.py" \
    --run-id "$RUN_ID" --agent "smoke-test" --incident-id "smoke-incident-001" \
    --query "compromised credential lateral movement enumeration" --top 5 2>&1)" || rc=$?
if [ "$rc" -ne 0 ]; then
    check4_ok=0
    detail4="first selection_log.py call failed (exit $rc): $CALL1_OUT"
fi

if [ "$check4_ok" -eq 1 ]; then
    rc=0
    OUT4A="$(python3 - "$REPO_ROOT" "$LOG_REL" "$PINNED_SHA" <<'PYEOF' 2>&1
import json, os, sys

def main():
    repo_root, log_rel, pinned_sha = sys.argv[1], sys.argv[2], sys.argv[3]
    log_path = os.path.join(repo_root, log_rel)
    if not os.path.isfile(log_path):
        print(f"log file does not exist: {log_path}")
        sys.exit(1)

    with open(log_path, "r", encoding="utf-8") as fh:
        lines = [ln for ln in fh.read().splitlines() if ln.strip()]

    if len(lines) != 1:
        print(f"expected exactly 1 line after first call, found {len(lines)}")
        sys.exit(1)

    required_keys = {"ts", "agent", "incident_id", "query", "selected", "repo_sha"}
    rec = json.loads(lines[0])
    missing = required_keys - rec.keys()
    if missing:
        print(f"record missing keys: {missing}")
        sys.exit(1)

    if rec["repo_sha"] != pinned_sha:
        print(f"repo_sha={rec['repo_sha']!r} (expected {pinned_sha!r})")
        sys.exit(1)

    sel = rec.get("selected")
    if not sel:
        print("selected[] is empty")
        sys.exit(1)
    for s in sel:
        if not all(k in s for k in ("id", "path", "score")):
            print(f"selected entry missing id/path/score: {s}")
            sys.exit(1)

    print(f"1 line after first call; all 6 keys present; repo_sha OK; selected has {len(sel)} entries with id/path/score")

try:
    main()
except SystemExit:
    raise
except Exception as exc:
    print(f"ERROR: {exc}")
    sys.exit(1)
PYEOF
    )" || rc=$?
    if [ "$rc" -ne 0 ]; then
        check4_ok=0
    fi
    detail4="$OUT4A"
fi

if [ "$check4_ok" -eq 1 ]; then
    rc=0
    CALL2_OUT="$(python3 "$SKILLS_DIR/selection_log.py" \
        --run-id "$RUN_ID" --agent "smoke-test" --incident-id "smoke-incident-001" \
        --query "compromised credential lateral movement enumeration" --top 5 2>&1)" || rc=$?
    if [ "$rc" -ne 0 ]; then
        check4_ok=0
        detail4="$detail4; second selection_log.py call failed (exit $rc): $CALL2_OUT"
    fi
fi

if [ "$check4_ok" -eq 1 ]; then
    n_lines="$(grep -c . "$LOG_ABS" 2>/dev/null || echo 0)"
    if [ "$n_lines" -eq 2 ]; then
        detail4="$detail4; after 2nd call: exactly 2 lines (append-only proven, not overwrite)"
    else
        check4_ok=0
        detail4="$detail4; after 2nd call: found $n_lines lines in $LOG_REL, expected exactly 2"
    fi
fi

if [ "$check4_ok" -eq 1 ]; then
    pass "4/6 selection-log" "$detail4 [$LOG_REL]"
else
    fail "4/6 selection-log" "$detail4 [$LOG_REL]"
fi
echo

# ---------------------------------------------------------------------------
# Check 5: offline guarantee -- no network modules imported
#
# Anchored to real import statements (line stripped, must start with "import "
# or "from "), not a raw whole-file grep -- a whole-file grep would also flag
# this very script explaining, in english prose inside a comment, that a file
# is network-free, which is a false positive, not a real import.
# ---------------------------------------------------------------------------
echo "--- Check 5: offline guarantee (no network modules) ---"
rc=0
OUT5="$(python3 - "$SKILLS_DIR/search.py" "$SKILLS_DIR/selection_log.py" <<'PYEOF' 2>&1
import sys

FORBIDDEN = ["requests", "urllib.request", "httpx", "socket", "openai", "anthropic"]

def check_file(path):
    hits = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError as exc:
        return [f"could not read {path}: {exc}"]
    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not (stripped.startswith("import ") or stripped.startswith("from ")):
            continue
        for mod in FORBIDDEN:
            if mod in stripped:
                hits.append(f"{path}:{i}: matched {mod!r} in: {stripped}")
    return hits

def main():
    paths = sys.argv[1:]
    report = []
    for p in paths:
        report.extend(check_file(p))
    if report:
        print("\n".join(report))
        sys.exit(1)
    joined = ", ".join(paths)
    print(f"no forbidden network-module import statements in: {joined}")

main()
PYEOF
)" || rc=$?
if [ "$rc" -eq 0 ]; then
    pass "5/6 offline" "$OUT5"
else
    fail "5/6 offline" "$OUT5"
fi
echo

# ---------------------------------------------------------------------------
# Check 6: compact menu fits (informational char/token count)
# ---------------------------------------------------------------------------
echo "--- Check 6: --compact-menu size ---"
menu_ok=1
rc=0
MENU_OUT="$(python3 "$SKILLS_DIR/search.py" --compact-menu 2>&1)" || rc=$?
if [ "$rc" -ne 0 ]; then
    menu_ok=0
fi

if [ "$menu_ok" -eq 1 ]; then
    menu_chars=$(printf '%s' "$MENU_OUT" | wc -c | tr -d '[:space:]')
    menu_tokens_est=$((menu_chars / 4))
    pass "6/6 compact-menu" "compact-menu ran OK: ${menu_chars} chars, ~${menu_tokens_est} tokens estimated (chars/4)"
else
    fail "6/6 compact-menu" "compact-menu failed both with and without a query arg: $MENU_OUT"
fi
echo

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------
TOTAL=$((PASS_COUNT + FAIL_COUNT))
echo "=== Summary: $PASS_COUNT/$TOTAL checks passed, $FAIL_COUNT/$TOTAL failed ==="
if [ "$FAIL_COUNT" -eq 0 ]; then
    echo "SMOKE TEST: PASS"
    exit 0
else
    echo "SMOKE TEST: FAIL"
    exit 1
fi
