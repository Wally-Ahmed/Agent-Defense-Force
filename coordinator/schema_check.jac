# coordinator/schema_check.jac
#
# Contract enforcement at the boundary. The schemas under contracts/mesh/ are
# FROZEN; this module is the only thing in the coordinator that reads them, and
# it never writes them.
#
# Why paths resolve from HERE and never from cwd: Jac resolves *imports* relative
# to the invocation cwd, so a module cannot assume it was launched from its own
# directory. Data files must therefore be located from __file__, otherwise
# `jac test coordinator/tests/test_quorum.jac` and
# `cd coordinator && jac test tests/test_quorum.jac` would disagree about where
# the contracts live. One of them would silently validate nothing.

import json;
import os;
import from jsonschema { Draft202012Validator }

# Directory of THIS file (…/coordinator), and the frozen contract directory
# beside it (…/contracts/mesh).
glob:pub HERE: str = os.path.dirname(os.path.abspath(__file__));
glob:pub SCHEMA_DIR: str = os.path.join(os.path.dirname(HERE), "contracts", "mesh");

# name -> parsed schema dict. Schemas are frozen, so a process-lifetime cache can
# never go stale. Kept module-level (not per-call) because validate_payload is on
# the hot path of every decision emitted.
glob:pub SCHEMA_CACHE: dict = {};

# name -> Draft202012Validator. Compiling a validator is the expensive half.
glob:pub VALIDATOR_CACHE: dict = {};


"""Absolute path of a frozen contract schema, e.g. "decision.v1"."""
def schema_path(name: str) -> str {
    return os.path.join(SCHEMA_DIR, f"{name}.schema.json");
}


"""Load (and memoise) a frozen JSON Schema by short name, e.g. "decision.v1"."""
def load_schema(name: str) -> dict {
    hit = SCHEMA_CACHE.get(name, None);
    if hit is not None {
        return hit;
    }
    path = schema_path(name);
    if not os.path.isfile(path) {
        raise ValueError(f"schema_check: no such frozen contract: {path}");
    }
    with open(path, "r") as fh {
        schema = json.load(fh);
    }
    SCHEMA_CACHE[name] = schema;
    return schema;
}


"""Compiled validator for a frozen contract, memoised alongside its schema."""
def validator_for(name: str) -> Draft202012Validator {
    hit = VALIDATOR_CACHE.get(name, None);
    if hit is not None {
        return hit;
    }
    v = Draft202012Validator(load_schema(name));
    VALIDATOR_CACHE[name] = v;
    return v;
}


"""Validate `payload` against the frozen contract `name`.

Returns None on success; raises ValueError with every violation listed (path,
message) on failure. Errors are sorted by JSON pointer so the message is stable
across runs — a flapping error message is a debugging tax nobody needs."""
def validate_payload(name: str, payload: dict) -> None {
    v = validator_for(name);
    errs = sorted(v.iter_errors(payload), key=lambda e: any : (list(e.absolute_path), e.message));
    if len(errs) == 0 {
        return None;
    }
    lines: list = [];
    for e in errs {
        where = "/".join([str(p) for p in e.absolute_path]);
        if where == "" {
            where = "<root>";
        }
        lines.append(f"  {where}: {e.message}");
    }
    body = "\n".join(lines);
    raise ValueError(f"{name} contract violation ({len(errs)} error(s)):\n{body}");
}


"""True when `payload` satisfies the frozen contract `name`. Never raises on an
invalid payload — only on an unknown/unreadable schema."""
def is_valid(name: str, payload: dict) -> bool {
    return validator_for(name).is_valid(payload);
}
