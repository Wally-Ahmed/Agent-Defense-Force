#!/usr/bin/env python3
"""build_index.py -- regenerate skills/index.json from the vendored, pinned
mukul975/Anthropic-Cybersecurity-Skills repo at vendor/cybersecurity-skills.

Community-maintained library (NOT an official Anthropic release). Stdlib only,
no network. This file contains its own minimal YAML-frontmatter reader: the
vendor's own root index.json is known to mis-handle folded block scalars
(">-") -- e.g. it records the description of
skills/achieving-cmmc-level-2-compliance literally as the string ">-" -- so we
do not reuse or trust it.

Run from anywhere:
    python3 skills/build_index.py
"""
from __future__ import annotations

import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

PINNED_SHA = "673da1f3b0b7be34ffc9624ef3858fe45f1c3bed"
REPO_ROOT = Path(__file__).resolve().parent.parent
VENDOR_ROOT_REL = "vendor/cybersecurity-skills"
VENDOR_DIR = REPO_ROOT / VENDOR_ROOT_REL
SKILLS_DIR = VENDOR_DIR / "skills"
OUT_PATH = Path(__file__).resolve().parent / "index.json"

# subdomain -> canonical domain slug. Raw subdomain is kept alongside the
# canonical form whenever they differ, so both are searchable.
DOMAIN_ALIASES = {
    "identity-and-access-management": "identity-access-management",
    "identity-security": "identity-access-management",
    "zero-trust": "zero-trust-architecture",
    "ot-security": "ot-ics-security",
    "security-operations": "soc-operations",
    "red-team": "red-teaming",
    "offensive-security": "penetration-testing",
}

# frontmatter key -> framework family slug, in the order tactics are flattened.
FRAMEWORK_KEYS = [
    ("mitre_attack", "mitre-attack"),
    ("nist_csf", "nist-csf"),
    ("d3fend_techniques", "d3fend"),
    ("atlas_techniques", "mitre-atlas"),
    ("nist_ai_rmf", "nist-ai-rmf"),
    ("mitre_f3", "mitre-f3"),
]

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
KEY_LINE_RE = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*):(.*)$")
SENTENCE_END_RE = re.compile(r"[.!?](?=\s|$)")


def tokenize(text: str) -> list:
    return TOKEN_RE.findall(text.lower())


def meaningful_tokens(text: str) -> list:
    return [t for t in tokenize(text) if len(t) >= 3 and t not in STOPWORDS]


# ---------------------------------------------------------------------------
# Minimal YAML-frontmatter reader.
#
# Only needs to handle the flat shapes actually present in this corpus: plain
# scalars (possibly folded across indented continuation lines), single/double
# quoted scalars (possibly spanning multiple lines), block scalars (>, >-, |,
# |-), and block sequences ("- item" lines, indented 0 or 2 spaces under their
# key). mitre_f3 is the one nested mapping present -- it is handled as a
# special case (raw text regex for its "- id: ..." entries) rather than by
# building a general recursive-mapping parser.
# ---------------------------------------------------------------------------

def split_frontmatter(text: str):
    lines = text.split("\n")
    if not lines or lines[0].strip() != "---":
        raise ValueError("missing opening '---'")
    end = None
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            end = i
            break
    if end is None:
        raise ValueError("missing closing '---'")
    return lines[1:end], lines[end + 1:]


def _strip_quotes(s: str) -> str:
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in ("'", '"'):
        inner = s[1:-1]
        if s[0] == "'":
            inner = inner.replace("''", "'")
        else:
            inner = inner.replace('\\"', '"').replace("\\\\", "\\")
        return inner
    return s


def _dedent(lines: list) -> list:
    indents = [len(l) - len(l.lstrip(" ")) for l in lines if l.strip() != ""]
    if not indents:
        return [l.strip() for l in lines]
    m = min(indents)
    return [l[m:] if len(l) >= m else l.lstrip(" ") for l in lines]


def parse_scalar_block(block: list):
    """Parse one top-level key's raw lines into a str, a list[str], or a
    {"_raw": text} marker for a nested mapping (only mitre_f3 needs this)."""
    first = block[0]
    rest = block[1:]
    first_stripped = first.strip()

    if first_stripped == "":
        content = [l for l in rest if l.strip() != ""]
        if not content:
            return ""
        if content[0].lstrip().startswith("- "):
            items = []
            for l in rest:
                s = l.strip()
                if not s.startswith("-"):
                    continue
                items.append(_strip_quotes(s[1:].strip()))
            return items
        # Nested mapping (mitre_f3). Hand back raw text; the one caller that
        # needs this regex-extracts "- id: ..." entries out of it.
        return {"_raw": "\n".join(rest)}

    if first_stripped[0] in ">|":
        indicator = first_stripped
        dedented = _dedent(rest)
        if indicator[0] == ">":
            paras, cur = [], []
            for l in dedented:
                if l.strip() == "":
                    if cur:
                        paras.append(" ".join(cur))
                        cur = []
                else:
                    cur.append(l.strip())
            if cur:
                paras.append(" ".join(cur))
            text = "\n\n".join(paras)
        else:  # literal block '|' / '|-'
            text = "\n".join(dedented)
        return text.strip()

    if first_stripped[0] in "'\"":
        quote = first_stripped[0]
        joined = "\n".join([first_stripped] + [l.strip() for l in rest])
        i, n = 1, len(joined)
        while i < n:
            if joined[i] == quote:
                if quote == "'" and i + 1 < n and joined[i + 1] == "'":
                    i += 2
                    continue
                break
            i += 1
        inner = joined[1:i]
        if quote == "'":
            inner = inner.replace("''", "'")
        else:
            inner = inner.replace('\\"', '"').replace("\\\\", "\\")
        return re.sub(r"\s+", " ", inner).strip()

    # Plain scalar, possibly folded across indented continuation lines.
    parts = [first_stripped]
    for l in rest:
        s = l.strip()
        if s:
            parts.append(s)
    return " ".join(parts)


def parse_frontmatter(fm_lines: list) -> dict:
    entries = []
    i, n = 0, len(fm_lines)
    while i < n:
        m = KEY_LINE_RE.match(fm_lines[i])
        if not m:
            i += 1
            continue
        key = m.group(1)
        block = [m.group(2)]
        i += 1
        while i < n and not KEY_LINE_RE.match(fm_lines[i]):
            block.append(fm_lines[i])
            i += 1
        entries.append((key, block))
    return {key: parse_scalar_block(block) for key, block in entries}


def extract_h1(body_lines: list):
    in_fence = False
    for line in body_lines:
        s = line.strip()
        if s.startswith("```") or s.startswith("~~~"):
            in_fence = not in_fence
            continue
        if in_fence:
            continue
        if s.startswith("# "):
            return s[2:].strip()
    return None


def first_prose_sentence(body_lines: list) -> str:
    in_fence = False
    for line in body_lines:
        s = line.strip()
        if s.startswith("```") or s.startswith("~~~"):
            in_fence = not in_fence
            continue
        if in_fence or not s or s.startswith("#") or s.startswith("-") or s.startswith("|"):
            continue
        m = re.search(r"(.+?[.!?])(\s|$)", s)
        return (m.group(1) if m else s).strip()
    return ""


def collapse_ws(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip()


def make_one_line(desc, body_lines) -> str:
    """Collapse description to a single line, truncate to <=160 chars on a
    word boundary (no ellipsis), and prefer ending on a full sentence when one
    is available within budget. Falls back to the body's first prose sentence
    if the frontmatter description parsed to nothing usable."""
    text = collapse_ws(desc) if isinstance(desc, str) else ""
    if not text or text == ">-":
        text = collapse_ws(first_prose_sentence(body_lines))
    if len(text) > 160:
        cut = text[:160]
        sp = cut.rfind(" ")
        if sp > 40:
            cut = cut[:sp]
        text = cut.rstrip(" ,;:-")
    if text and text[-1] not in ".!?":
        # Only treat . / ! / ? as a sentence boundary when followed by
        # whitespace or end-of-string -- otherwise "crt.sh", "v1.2", "e.g.x"
        # style in-word periods get mistaken for sentence ends.
        matches = list(SENTENCE_END_RE.finditer(text))
        if matches and matches[-1].end() >= 40:
            text = text[: matches[-1].end()]
    return text


def canonical_domains(subdomain: str) -> list:
    sub = (subdomain or "").strip()
    if not sub or sub == "cybersecurity":
        return []
    canon = DOMAIN_ALIASES.get(sub, sub)
    return [canon] if canon == sub else [canon, sub]


def compute_frameworks_and_tactics(fm: dict):
    frameworks = []
    tactics = []
    seen = set()
    for key, fam in FRAMEWORK_KEYS:
        val = fm.get(key)
        if not val:
            continue
        if key == "mitre_f3":
            frameworks.append(fam)
            raw = val.get("_raw", "") if isinstance(val, dict) else ""
            ids = [_strip_quotes(x) for x in re.findall(r"-\s*id:\s*(\S+)", raw)]
        else:
            if not isinstance(val, list):
                continue
            frameworks.append(fam)
            ids = val
        for tid in ids:
            if tid not in seen:
                seen.add(tid)
                tactics.append(tid)
    return frameworks, tactics


def compute_keywords(tags: list, slug: str, one_line: str) -> list:
    out, seen = [], set()

    def add(tok):
        t = tok.lower().strip()
        if t and t not in seen:
            seen.add(t)
            out.append(t)

    for t in tags or []:
        add(t)
    for t in meaningful_tokens(slug.replace("-", " ")):
        add(t)
    for t in meaningful_tokens(one_line):
        add(t)
    return out[:40]


def get_repo_sha(vendor_dir: Path) -> str:
    try:
        r = subprocess.run(
            ["git", "-C", str(vendor_dir), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=True,
        )
        sha = r.stdout.strip()
        if sha:
            return sha
    except Exception:
        pass
    git_head = vendor_dir / ".git" / "HEAD"
    if git_head.exists():
        content = git_head.read_text().strip()
        if content.startswith("ref:"):
            ref = content.split(" ", 1)[1].strip()
            ref_path = vendor_dir / ".git" / ref
            if ref_path.exists():
                return ref_path.read_text().strip()
        else:
            return content
    raise RuntimeError("could not determine vendor repo HEAD sha via git or .git/HEAD")


def main() -> int:
    sha = get_repo_sha(VENDOR_DIR)
    if sha != PINNED_SHA:
        print(
            f"FATAL: vendor/cybersecurity-skills HEAD is {sha!r}, expected pinned "
            f"{PINNED_SHA!r}. Refusing to build an index against a moved vendor repo.",
            file=sys.stderr,
        )
        return 1

    if not SKILLS_DIR.is_dir():
        print(f"FATAL: skills dir not found: {SKILLS_DIR}", file=sys.stderr)
        return 1

    slugs = sorted(p.name for p in SKILLS_DIR.iterdir() if (p / "SKILL.md").is_file())
    notes = []
    records = []
    seen_ids = set()

    for slug in slugs:
        skill_path = SKILLS_DIR / slug / "SKILL.md"
        rel_path = f"{VENDOR_ROOT_REL}/skills/{slug}/SKILL.md"
        text = skill_path.read_text(encoding="utf-8")

        try:
            fm_lines, body_lines = split_frontmatter(text)
            fm = parse_frontmatter(fm_lines)
        except Exception as e:
            notes.append(f"{slug}: frontmatter parse failed ({e}); treated as body-only")
            fm = {}
            body_lines = text.split("\n")

        name = extract_h1(body_lines)
        if not name:
            name = slug.replace("-", " ").title()
            notes.append(f"{slug}: no H1 in body (only heading found was inside a code "
                          f"fence or absent) -- used title-cased slug for name")

        desc = fm.get("description", "")
        one_line = make_one_line(desc, body_lines)
        if one_line in ("", ">-"):
            notes.append(f"{slug}: description+body both yielded junk one_line, forced to name")
            one_line = collapse_ws(name) or slug

        subdomain = fm.get("subdomain", "")
        if not isinstance(subdomain, str):
            subdomain = ""
        domains = canonical_domains(subdomain)

        frameworks, tactics = compute_frameworks_and_tactics(fm)

        tags = fm.get("tags", [])
        if not isinstance(tags, list):
            tags = []
        keywords = compute_keywords(tags, slug, one_line)

        if slug in seen_ids:
            notes.append(f"{slug}: DUPLICATE id -- skipped")
            continue
        seen_ids.add(slug)

        abs_path = REPO_ROOT / rel_path
        if not abs_path.is_file():
            raise RuntimeError(f"generated path does not exist on disk: {rel_path}")

        records.append({
            "id": slug,
            "name": name,
            "path": rel_path,
            "one_line": one_line,
            "domains": domains,
            "frameworks": frameworks,
            "tactics": tactics,
            "keywords": keywords,
        })

    if len(records) != 817:
        print(f"WARNING: expected 817 skills, built {len(records)}", file=sys.stderr)

    index = {
        "schema": "cybersec-skill-index/1",
        "repo": "mukul975/Anthropic-Cybersecurity-Skills",
        "repo_sha": sha,
        "license": "Apache-2.0",
        "vendor_root": VENDOR_ROOT_REL,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "total_skills": len(records),
        "skills": records,
    }

    OUT_PATH.write_text(
        json.dumps(index, ensure_ascii=False, separators=(",", ":")),
        encoding="utf-8",
    )

    size_kb = OUT_PATH.stat().st_size / 1024
    print(f"Wrote {OUT_PATH} ({size_kb:.1f} KB) with {len(records)} skills.", file=sys.stderr)
    if notes:
        print(f"{len(notes)} parse notes:", file=sys.stderr)
        for note in notes:
            print(f"  - {note}", file=sys.stderr)
    else:
        print("No parse anomalies.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
