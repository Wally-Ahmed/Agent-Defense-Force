#!/usr/bin/env python3
"""monitor/effort_receipt.py — the monitor's effort_receipt.v1 boot receipt.

Stdlib only, Python 3.9 compatible. No network. `subprocess` is used solely to invoke the
local `hermes` binary for a version / config read-back; nothing opens a socket.

Emits exactly ONE effort_receipt.v1 line, at boot, appended to::

    runs/<run_id>/effort.jsonl        (relative to the repo root)

matching contracts/mesh/effort_receipt.v1.schema.json (11 required keys,
additionalProperties: false). The coordinator refuses to leave WATCHING until six such
receipts exist — the monitor plus all five responders — every one with downgraded:false.

NO SECRETS. The only environment variable read here is the PRESENCE of OPENROUTER_API_KEY.
Its value is never read into a variable, never logged, never echoed, never hashed, and never
measured — not its length, not a prefix. `_api_key_present()` returns a bool and nothing else.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

# --- constants -------------------------------------------------------------------------

AGENT = "monitor"
RUNTIME = "hermes"
MODEL_REQUESTED = "z-ai/glm-5.2"
EFFORT_REQUESTED = "xhigh"

HERMES_VERSION_TIMEOUT_S = 10
RUNTIME_UNAVAILABLE = "unavailable"

BACKEND_OFFLINE = "offline"
BACKEND_LIVE = "live"

#: Hermes' own reasoning-effort ladder (hermes_constants.parse_reasoning_effort), weakest to
#: strongest. Used to decide whether effort_effective is *weaker* than effort_requested.
#: An unrecognised / unreadable effective effort ranks below every real level, so a failed
#: read-back is treated as a downgrade. That is the safe direction: never assume no downgrade.
EFFORT_RANK = {
    "none": 0,
    "minimal": 1,
    "low": 2,
    "medium": 3,
    "high": 4,
    "xhigh": 5,
}

REQUIRED_KEYS = (
    "agent",
    "runtime",
    "runtime_version",
    "model_requested",
    "model_effective",
    "effort_requested",
    "effort_effective",
    "source",
    "downgraded",
    "blocked",
    "mocked",
)

_STRING_KEYS = frozenset(
    [
        "agent",
        "runtime",
        "runtime_version",
        "model_requested",
        "model_effective",
        "effort_requested",
        "effort_effective",
        "source",
    ]
)
_BOOL_KEYS = frozenset(["downgraded", "blocked", "mocked"])


# --- helpers ---------------------------------------------------------------------------


def _repo_root():
    """Repo root, resolved from this file's own location (monitor/effort_receipt.py)."""
    return Path(__file__).resolve().parent.parent


def _api_key_present():
    """True iff OPENROUTER_API_KEY is set and non-empty.

    Deliberately returns a bare bool. The key's VALUE never leaves this function — it is not
    returned, stored, logged, or measured.
    """
    return bool((os.environ.get("OPENROUTER_API_KEY") or "").strip())


def _run(argv, timeout_s):
    """Run a local command, returning (returncode, stdout, stderr). Never raises on failure."""
    try:
        proc = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_s,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return (None, "", "")
    out = (proc.stdout or b"").decode("utf-8", "replace")
    err = (proc.stderr or b"").decode("utf-8", "replace")
    return (proc.returncode, out, err)


def hermes_version():
    """Read the runtime version back by running `hermes --version` (10s timeout).

    Returns (version_string, raw_first_line). version_string is RUNTIME_UNAVAILABLE when the
    binary is missing, errors, or prints nothing parseable.

    Real output of `hermes --version` on this machine, first line::

        Hermes Agent v0.16.0 (2026.6.5)
    """
    rc, out, _err = _run([RUNTIME, "--version"], HERMES_VERSION_TIMEOUT_S)
    if rc is None or rc != 0:
        return (RUNTIME_UNAVAILABLE, "")

    first_line = ""
    for line in out.splitlines():
        if line.strip():
            first_line = line.strip()
            break
    if not first_line:
        return (RUNTIME_UNAVAILABLE, "")

    match = re.search(r"v?(\d+\.\d+(?:\.\d+)*)", first_line)
    return (match.group(1) if match else first_line, first_line)


def _hermes_config_path():
    """Path to the hermes config.yaml, asked of hermes itself (`hermes config path`).

    Returns None when hermes is unavailable. The file itself may not exist yet — hermes only
    materialises it on the first `hermes config set`.
    """
    rc, out, _err = _run([RUNTIME, "config", "path"], HERMES_VERSION_TIMEOUT_S)
    if rc is None or rc != 0:
        return None
    text = out.strip().splitlines()
    return Path(text[0].strip()) if text and text[0].strip() else None


def _scan_hermes_config():
    """Read model + agent.reasoning_effort back out of the hermes config file.

    Stdlib only, so this is a deliberately narrow two-level scan rather than a YAML parse.
    It handles exactly the shape `hermes config set` writes, verified against a real run::

        agent:
          reasoning_effort: xhigh

    Returns (model_or_None, effort_or_None, config_path_or_None).
    """
    cfg_path = _hermes_config_path()
    if cfg_path is None or not cfg_path.exists():
        return (None, None, cfg_path)

    try:
        text = cfg_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return (None, None, cfg_path)

    model = None
    effort = None
    section = None
    for raw in text.splitlines():
        line = raw.rstrip()
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        stripped = line.strip()
        if indent == 0:
            section = stripped[:-1] if stripped.endswith(":") else stripped.split(":", 1)[0]
            if stripped.startswith("model:"):
                value = stripped.split(":", 1)[1].strip().strip("\"'")
                if value:
                    model = value
            continue
        if ":" not in stripped:
            continue
        key, value = stripped.split(":", 1)
        key = key.strip()
        value = value.strip().strip("\"'")
        if section == "agent" and key == "reasoning_effort" and value:
            effort = value
        elif section == "model" and key in ("name", "id") and value:
            model = value
    return (model, effort, cfg_path)


def _is_downgrade(effort_effective, model_effective):
    """downgraded == effort weaker than requested, OR model differs from requested."""
    if model_effective != MODEL_REQUESTED:
        return True
    requested_rank = EFFORT_RANK.get(EFFORT_REQUESTED, -1)
    effective_rank = EFFORT_RANK.get(str(effort_effective).strip().lower(), -1)
    return effective_rank < requested_rank


# --- receipt construction ---------------------------------------------------------------


def build_receipt(backend, run_id):
    """Build the monitor's effort_receipt.v1 dict for `backend` ("offline" or "live").

    `run_id` is accepted for symmetry with emit_receipt() and validated here so a bad id
    fails before any subprocess work; it is not itself a receipt field (the receipt's
    location on disk carries the run).

    OFFLINE READING OF THE SCHEMA (deliberate, and the reason downgraded is false here):
    `downgraded` means the runtime bound something *weaker than asked for* — a substituted
    model or a reduced effort. The offline deterministic backend does not bind a model at
    ALL. Nothing was requested of a provider, so nothing was substituted or reduced; there
    is no weaker binding to report. That state is what `mocked` exists to express, and it is
    reported as mocked=true. Setting downgraded=true here would assert a provider downgrade
    that never happened and would conflate "answered from a deterministic local function"
    with "the provider quietly gave us less than we paid for" — the exact distinction the
    schema draws between `mocked` and `downgraded`. The run is still correctly barred from
    acceptance, because mocked=true and blocked=true both mark it as such and the receipt
    labels every artifact it touches MOCKED.
    """
    backend = str(backend or BACKEND_OFFLINE).strip().lower()
    if backend not in (BACKEND_OFFLINE, BACKEND_LIVE):
        raise ValueError(
            "backend must be %r or %r, got %r" % (BACKEND_OFFLINE, BACKEND_LIVE, backend)
        )
    _validate_run_id(run_id)

    version, version_line = hermes_version()
    runtime_missing = version == RUNTIME_UNAVAILABLE
    key_present = _api_key_present()

    if backend == BACKEND_OFFLINE:
        model_effective = "%s (offline deterministic backend)" % MODEL_REQUESTED
        effort_effective = "%s (not exercised — offline backend)" % EFFORT_REQUESTED
        if runtime_missing:
            source = (
                "`hermes --version` unavailable (runtime not installed or not on PATH); "
                "effort not exercised — offline deterministic backend"
            )
        else:
            source = (
                "stdout of `hermes --version` (%s); effort not exercised — offline "
                "deterministic backend" % (version_line or version)
            )
        receipt = {
            "agent": AGENT,
            "runtime": RUNTIME,
            "runtime_version": version,
            "model_requested": MODEL_REQUESTED,
            "model_effective": model_effective,
            "effort_requested": EFFORT_REQUESTED,
            "effort_effective": effort_effective,
            "source": source,
            # See the docstring above: a mock is not a downgrade.
            "downgraded": False,
            "blocked": runtime_missing or not key_present,
            "mocked": True,
        }
        return validate_receipt(receipt)

    # --- live -----------------------------------------------------------------------------
    # Read back from the runtime rather than assuming. `hermes -z/--oneshot` prints ONLY the
    # final response text — it emits no per-response metadata block — so the effective model
    # and effort are read from the runtime's own config file, which is where
    # `hermes config set agent.reasoning_effort xhigh` puts them. That file IS the runtime's
    # answer to "what will you bind", so it is a read-back, not an assumption.
    cfg_model, cfg_effort, cfg_path = _scan_hermes_config()
    model_effective = cfg_model or "unknown (no model read back from hermes config)"
    effort_effective = cfg_effort or "unknown (no agent.reasoning_effort read back from hermes config)"
    if runtime_missing:
        source = "`hermes --version` unavailable (runtime not installed or not on PATH)"
    else:
        source = (
            "stdout of `hermes --version` (%s) for runtime_version; `hermes config path` -> "
            "%s keys `model` and `agent.reasoning_effort` for the effective model/effort "
            "read-back (hermes -z emits no per-response metadata)"
            % (version_line or version, cfg_path if cfg_path else "<config path unavailable>")
        )
    receipt = {
        "agent": AGENT,
        "runtime": RUNTIME,
        "runtime_version": version,
        "model_requested": MODEL_REQUESTED,
        "model_effective": model_effective,
        "effort_requested": EFFORT_REQUESTED,
        "effort_effective": effort_effective,
        "source": source,
        "downgraded": _is_downgrade(effort_effective, model_effective),
        "blocked": runtime_missing or not key_present,
        "mocked": False,
    }
    return validate_receipt(receipt)


def validate_receipt(receipt):
    """Validate against the frozen schema's required keys / types. Raises on failure.

    Checks: object-ness, all 11 required keys present, no extra keys
    (additionalProperties: false), the 8 string keys are non-empty strings (minLength: 1),
    and the 3 boolean keys are real bools (not truthy ints).
    """
    if not isinstance(receipt, dict):
        raise TypeError("receipt must be a dict, got %s" % type(receipt).__name__)

    missing = [k for k in REQUIRED_KEYS if k not in receipt]
    if missing:
        raise ValueError("effort_receipt.v1 missing required key(s): %s" % ", ".join(missing))

    extra = [k for k in receipt if k not in REQUIRED_KEYS]
    if extra:
        raise ValueError(
            "effort_receipt.v1 has additionalProperties (schema forbids): %s" % ", ".join(sorted(extra))
        )

    for key in sorted(_STRING_KEYS):
        value = receipt[key]
        if not isinstance(value, str) or not value:
            raise ValueError(
                "effort_receipt.v1 field %r must be a non-empty string, got %r" % (key, value)
            )
    for key in sorted(_BOOL_KEYS):
        if not isinstance(receipt[key], bool):
            raise ValueError(
                "effort_receipt.v1 field %r must be a boolean, got %r" % (key, receipt[key])
            )
    return receipt


def _validate_run_id(run_id):
    if not run_id or "/" in run_id or "\\" in run_id or run_id in (".", ".."):
        raise ValueError(
            "invalid run_id (must be a plain path segment, no separators): %r" % (run_id,)
        )
    return run_id


def receipt_path(run_id):
    """runs/<run_id>/effort.jsonl, repo-root relative."""
    return _repo_root() / "runs" / _validate_run_id(run_id) / "effort.jsonl"


def emit_receipt(backend, run_id):
    """Append the monitor's receipt to runs/<run_id>/effort.jsonl. Returns (path, receipt).

    "One receipt per agent, written ONCE at boot" (frozen schema). This is therefore
    idempotent: if a byte-identical monitor receipt is already on file for this run, it is
    not appended a second time. A monitor receipt that DIFFERS from the one on file is
    appended, because a changed binding is a fact the audit trail must keep — the append-only
    file is never rewritten or truncated.
    """
    receipt = build_receipt(backend, run_id)
    out_path = receipt_path(run_id)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    line = json.dumps(receipt, ensure_ascii=False, sort_keys=True)

    if out_path.exists():
        try:
            existing = out_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            existing = []
        for raw in existing:
            raw = raw.strip()
            if not raw:
                continue
            try:
                parsed = json.loads(raw)
            except ValueError:
                continue
            if isinstance(parsed, dict) and parsed.get("agent") == AGENT:
                if json.dumps(parsed, ensure_ascii=False, sort_keys=True) == line:
                    return (out_path, receipt)

    # Single os.write() of the complete line on an O_APPEND fd: safe against concurrent
    # appends from the other five agent processes writing this same file.
    payload = (line + "\n").encode("utf-8")
    fd = os.open(str(out_path), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    try:
        os.write(fd, payload)
    finally:
        os.close(fd)

    return (out_path, receipt)


# --- CLI -------------------------------------------------------------------------------


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="effort_receipt.py",
        description="Emit the monitor's effort_receipt.v1 line to runs/<run_id>/effort.jsonl.",
    )
    parser.add_argument("--run-id", required=True, help="Run identifier (a plain path segment).")
    parser.add_argument(
        "--backend",
        default=os.environ.get("MONITOR_BACKEND", BACKEND_OFFLINE),
        choices=[BACKEND_OFFLINE, BACKEND_LIVE],
        help="Which monitor backend this receipt describes (default: offline).",
    )
    parser.add_argument(
        "--no-write",
        action="store_true",
        help="Build and print the receipt without appending it to effort.jsonl.",
    )
    args = parser.parse_args(argv)

    if args.no_write:
        receipt = build_receipt(args.backend, args.run_id)
        path = None
    else:
        path, receipt = emit_receipt(args.backend, args.run_id)

    print(json.dumps(receipt, indent=2, ensure_ascii=False, sort_keys=True))
    if path is not None:
        sys.stderr.write("wrote: %s\n" % path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
