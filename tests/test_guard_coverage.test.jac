# tests/test_guard_coverage.test.jac — the anti-forgetting mechanism.
#
# "Every protected operation is authorized server-side" is the kind of claim
# that is true on the day it is written and quietly false three commits later.
# The failure mode is never a bad guard() call -- it is a NEW walker that
# forgets to make one at all, which no amount of testing the existing walkers
# will ever catch.
#
# So this file does not test behaviour. It reads the source of every walker in
# app/ and asserts a STRUCTURAL property:
#
#   1. every `walker:priv` calls guard() as its FIRST executable statement
#   2. no walker under app/walkers/ calls emit_audit() at all -- guard() already
#      emitted exactly one event, and a second one corrupts the trail
#   3. every `walker:pub` calls require_verified_ctx() as its first executable
#      statement -- a public walker still must not trust an unsigned ctx
#
# FIRST statement, not "somewhere in the body": a guard() call that happens
# after the walker has already read or written a node is not an authorization
# check, it is a post-hoc opinion about work that already occurred.
#
# `has` field declarations sit outside the ability body, so they are naturally
# excluded from "first executable statement".
#
# ANTI-VACUOUS: a regex that silently stops matching would turn this whole file
# into a no-op that passes forever. The walker set is therefore asserted
# NON-EMPTY whenever app/walkers/ has any source in it.
#
# The parser is deliberately defensive: a file with no walkers, an unbalanced
# brace, or an unreadable byte must degrade to "nothing to check here", never
# to a crash that reads as a green test run.

import os;
import re;
import glob;

# --------------------------------------------------------------------------
# Locating the tree under test. `jac test` may be invoked from the repo root
# or from tests/, so the root is found by looking for app/ rather than assumed.
# --------------------------------------------------------------------------

"""Absolute path of the repository root -- the directory that contains app/."""
def repo_root() -> str {
    here: str = os.path.abspath(os.getcwd());
    if os.path.isdir(os.path.join(here, "app")) {
        return here;
    }
    up: str = os.path.dirname(here);
    if os.path.isdir(os.path.join(up, "app")) {
        return up;
    }
    return here;
}

"""Every readable .jac file under app/, excluding anything under tests/.

`os.path.isfile` is load-bearing: jac leaves bytecode directories literally
named `.jac` next to the sources, and `*.jac` matches them."""
def app_sources() -> list {
    base: str = repo_root();
    pattern = os.path.join(base, "app", "**", "*.jac");
    out: list = [];
    for path in sorted(glob.glob(pattern, recursive=True)) {
        if not os.path.isfile(path) {
            continue;
        }
        norm: str = path.replace(os.sep, "/");
        if "/tests/" in norm {
            continue;
        }
        out.append(path);
    }
    return out;
}

"""Same, but only the domain-walker package. Empty when it does not exist."""
def walker_sources() -> list {
    base: str = repo_root();
    wdir = os.path.join(base, "app", "walkers");
    if not os.path.isdir(wdir) {
        return [];
    }
    out: list = [];
    for path in sorted(glob.glob(os.path.join(wdir, "**", "*.jac"), recursive=True)) {
        if os.path.isfile(path) {
            out.append(path);
        }
    }
    return out;
}

"""Path as it should appear in a failure message: relative to the repo root."""
def rel(path: str) -> str {
    base: str = repo_root();
    if path.startswith(base) {
        return path[len(base):].lstrip("/").lstrip(os.sep);
    }
    return path;
}

"""File contents, or "" when the file cannot be read. A parser that raises on a
weird byte would turn a source-scanning test into a flaky one."""
def read_text(path: str) -> str {
    try {
        handle = open(path, "r", encoding="utf-8", errors="replace");
        body: str = handle.read();
        handle.close();
        return body;
    } except Exception as e {
        return "";
    }
}

# --------------------------------------------------------------------------
# A very small, very defensive Jac reader.
# --------------------------------------------------------------------------

# `walker:priv Name {` / `walker:pub Name {`, tolerating whitespace around `:`.
glob:pub PRIV_WALKER_RE: str = r"walker\s*:\s*priv\s+(\w+)\s*\{";
glob:pub PUB_WALKER_RE: str = r"walker\s*:\s*pub\s+(\w+)\s*\{";

# `can <name> with entry {`, `can <name> with Root entry {`,
# `can <name> with `root entry {`.
glob:pub ENTRY_ABILITY_RE: str = r"can\s+\w+\s+with\s+[^{}\n]*?entry\s*\{";

"""Index of the `}` that closes the `{` at `open_idx`, or -1 if unbalanced.

Brace counting, not parsing. A brace inside a string literal could in principle
fool it; the consequence is a body that is too long or too short, and the only
thing read out of the body is its first statement, so the check stays correct."""
def match_brace(text: str, open_idx: int) -> int {
    depth = 0;
    i = open_idx;
    n = len(text);
    while i < n {
        ch = text[i];
        if ch == "{" {
            depth = depth + 1;
        } elif ch == "}" {
            depth = depth - 1;
            if depth == 0 {
                return i;
            }
        }
        i = i + 1;
    }
    return -1;
}

"""The first EXECUTABLE line of a body: the first line that is not blank, not a
`#` comment, and not part of a docstring."""
def first_statement(body: str) -> str {
    lines = body.split("\n");
    i = 0;
    n = len(lines);
    while i < n {
        line: str = lines[i].strip();
        if line == "" or line.startswith("#") {
            i = i + 1;
            continue;
        }
        if line.startswith('"""') {
            # Single-line docstring: `"""text"""` on one line.
            if len(line) > 5 and line.endswith('"""') {
                i = i + 1;
                continue;
            }
            # Multi-line: consume through the closing delimiter.
            i = i + 1;
            while i < n {
                probe: str = lines[i].strip();
                i = i + 1;
                if probe.endswith('"""') {
                    break;
                }
            }
            continue;
        }
        return line;
    }
    return "";
}

"""Every (name, first_statement) pair for walkers matching `pattern` in `text`.

A walker with no entry ability yields a first statement of "<no entry ability>",
which fails the caller's containment check -- a walker that cannot be entered
still must not be silently exempt from the rule."""
def walkers_with_first_statement(text: str, pattern: str) -> list {
    found: list = [];
    for m in re.finditer(pattern, text) {
        name: str = m.group(1);
        brace = text.find("{", m.start());
        if brace < 0 {
            found.append((name, "<unparseable walker header>"));
            continue;
        }
        close = match_brace(text, brace);
        if close < 0 {
            close = len(text);
        }
        walker_body: str = text[brace + 1:close];
        ability = re.search(ENTRY_ABILITY_RE, walker_body);
        if ability is None {
            found.append((name, "<no entry ability>"));
            continue;
        }
        abrace = walker_body.find("{", ability.start());
        if abrace < 0 {
            found.append((name, "<unparseable ability header>"));
            continue;
        }
        aclose = match_brace(walker_body, abrace);
        if aclose < 0 {
            aclose = len(walker_body);
        }
        found.append((name, first_statement(walker_body[abrace + 1:aclose])));
    }
    return found;
}

# --------------------------------------------------------------------------
# 1. Every private walker guards first.
# --------------------------------------------------------------------------

test "every walker:priv calls guard() as its first executable statement" {
    problems: list = [];
    names: list = [];

    for path in app_sources() {
        text = read_text(path);
        if text == "" {
            continue;
        }
        for (name, stmt) in walkers_with_first_statement(text, PRIV_WALKER_RE) {
            names.append(name);
            if "guard(" not in stmt {
                problems.append(
                    "walker:priv " + name + " in " + rel(path)
                    + " does not call guard() as its first statement"
                    + " (found: " + stmt + ")"
                );
            }
        }
    }

    # Compared as a STRING, not as a count: Jac lowers `assert a == b, msg` to a
    # comparison assertion and DROPS the message, so `assert len(problems) == 0`
    # reports only "1 != 0" and the engineer never learns which walker is
    # unguarded. Asserting the joined text against "" puts the offending walker
    # and file into the failure output itself.
    complaint: str = " | ".join(problems);
    assert complaint == "", complaint;

    # Anti-vacuous guard. If the regex ever stops matching -- a syntax change, a
    # typo, a refactor -- this test must fail loudly rather than pass by finding
    # nothing to check.
    if len(walker_sources()) == 0 {
        print("SKIP: app/walkers/ has no .jac sources yet; "
              + "the non-empty walker-set assertion is not yet meaningful.");
    } else {
        found_any: bool = len(names) > 0;
        assert found_any, (
            "no walker:priv declarations were found anywhere under app/ even "
            + "though app/walkers/ has sources -- the coverage regex has "
            + "stopped matching and this test has silently become a no-op"
        );
    }
}

# --------------------------------------------------------------------------
# 2. Domain walkers emit nothing.
# --------------------------------------------------------------------------

test "no walker under app/walkers/ calls emit_audit" {
    sources = walker_sources();
    if len(sources) == 0 {
        print("SKIP: app/walkers/ does not exist yet (or has no .jac sources); "
              + "the emit_audit prohibition cannot be checked.");
    } else {
        offenders: list = [];
        for path in sources {
            if "emit_audit" in read_text(path) {
                offenders.append(rel(path));
            }
        }
        # guard() already emitted EXACTLY ONE AuditEvent for this operation.
        # A second emission from the walker is not extra safety -- it is a
        # duplicate row, a broken per-session hash chain, and a count the
        # monitor cannot trust. Pre-auth walkers use emit_preauth() instead.
        offender_text: str = ", ".join(offenders);
        assert offender_text == "", (
            "these files under app/walkers/ reference emit_audit, but domain "
            + "walkers must emit nothing (guard() already did): " + offender_text
        );
    }
}

# --------------------------------------------------------------------------
# 3. Public walkers still verify the signature.
# --------------------------------------------------------------------------

test "every walker:pub verifies the ctx signature as its first statement" {
    sources = walker_sources();
    if len(sources) == 0 {
        print("SKIP: app/walkers/ does not exist yet (or has no .jac sources); "
              + "the walker:pub require_verified_ctx rule cannot be checked.");
    } else {
        problems: list = [];
        for path in sources {
            text = read_text(path);
            if text == "" {
                continue;
            }
            for (name, stmt) in walkers_with_first_statement(text, PUB_WALKER_RE) {
                if "require_verified_ctx(" not in stmt {
                    problems.append(
                        "walker:pub " + name + " in " + rel(path)
                        + " does not call require_verified_ctx() as its first "
                        + "statement (found: " + stmt + ")"
                    );
                }
            }
        }
        # A public walker is public in the sense that it precedes
        # authentication -- register and login. It is NOT public in the sense
        # of trusting whatever ctx the caller posted: an unsigned request must
        # not be able to write a login record attributed to a spoofed source.
        complaint: str = " | ".join(problems);
        assert complaint == "", complaint;
    }
}
