#!/usr/bin/env python3
"""Minimal stdio MCP server for the pinned cybersecurity-skills library.

Transport: MCP stdio -- newline-delimited JSON-RPC 2.0 on stdin/stdout, one
message per line, no embedded newlines, stderr reserved for logging. See:
https://modelcontextprotocol.io/specification/2025-06-18/basic/transports
Protocol version handshaked here: 2025-06-18.

This server is a convenience layer, NOT the primary discovery mechanism.
The primary, uniform mechanism across all five non-Claude runtimes is the
plain shell call documented in skills/README.md:

    python3 skills/search.py "<query>" --top 5 [--domain D] [--framework F]

That script prints one JSON object to stdout and is also importable as
search(query, top=5, domain=None, framework=None) -> dict. This server
wraps that exact function -- it does not reimplement scoring -- so every
runtime (shell or MCP) gets byte-identical results.

Tools exposed:
  skill_search(query, top=5, domain=None, framework=None)
      -> delegates to skills/search.py:search()
  skill_load(id)
      -> reads the one matching entry in skills/index.json, resolves its
         SKILL.md path, strips the YAML frontmatter, and returns the body
         text -- enough to act on one skill without opening the library.
"""
import json
import os
import sys

PROTOCOL_VERSION = "2025-06-18"
SERVER_NAME = "cybersec-skills"
SERVER_VERSION = "1.0.0"

SKILLS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SKILLS_DIR)

# --- Guarded import of skills/search.py -------------------------------------
# search.py is built by a sibling process and may not exist yet (or may be
# mid-edit) when this file is loaded. Keep this module importable and
# syntactically valid regardless, and surface a clear, actionable error at
# call time -- not an import-time crash -- if it is missing.
_search = None
_SEARCH_IMPORT_ERROR = None
try:
    if SKILLS_DIR not in sys.path:
        sys.path.insert(0, SKILLS_DIR)
    from search import search as _search  # noqa: E402
except Exception as exc:  # broad on purpose: search.py must never crash this file
    _SEARCH_IMPORT_ERROR = f"{type(exc).__name__}: {exc}"


def _log(message):
    print(f"[mcp_server] {message}", file=sys.stderr, flush=True)


def _find_records(index):
    """Return the list of skill-record dicts inside index.json, whatever its
    top-level key is named. index.json's schema is owned by a sibling
    process; look for the first top-level list whose entries look like
    skill records rather than hardcoding a key name.
    """
    for value in index.values():
        if isinstance(value, list) and value and isinstance(value[0], dict) and "id" in value[0]:
            return value
    return []


def _load_index():
    index_path = os.path.join(SKILLS_DIR, "index.json")
    with open(index_path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _resolve_skill_path(record, index):
    """Resolve a skill record's SKILL.md to an absolute path on disk.

    Tries the record's `path` field as repo-root-relative, vendor_root-
    relative, and skills/-relative in turn, and accepts either a direct
    SKILL.md path or a skill directory (appending SKILL.md).
    """
    raw = record.get("path") or ""
    if os.path.isabs(raw):
        candidates = [raw]
    else:
        bases = [REPO_ROOT]
        vendor_root = index.get("vendor_root")
        if vendor_root:
            bases.append(os.path.join(REPO_ROOT, vendor_root))
            bases.append(vendor_root)
        bases.append(SKILLS_DIR)
        candidates = [os.path.join(base, raw) for base in bases]

    for candidate in candidates:
        if os.path.isfile(candidate):
            return candidate
        skill_md = os.path.join(candidate, "SKILL.md")
        if os.path.isfile(skill_md):
            return skill_md
    return None


def _strip_frontmatter(text):
    """Strip a leading '---' ... '---' YAML frontmatter block, if present."""
    if not text.startswith("---"):
        return text
    lines = text.split("\n")
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            return "\n".join(lines[i + 1:]).lstrip("\n")
    return text


def tool_skill_search(arguments):
    if _search is None:
        raise RuntimeError(
            "skills/search.py is missing or failed to import "
            f"({_SEARCH_IMPORT_ERROR}). skill_search delegates to its "
            "search() function and cannot run without it -- once it "
            "exists on disk, this tool needs no other change."
        )
    query = arguments.get("query", "")
    top = arguments.get("top", 5)
    domain = arguments.get("domain")
    framework = arguments.get("framework")
    return _search(query, top=top, domain=domain, framework=framework)


def tool_skill_load(arguments):
    skill_id = arguments.get("id")
    if not skill_id:
        raise ValueError("skill_load requires a non-empty 'id' argument")
    index = _load_index()
    record = next((r for r in _find_records(index) if r.get("id") == skill_id), None)
    if record is None:
        raise ValueError(f"no skill with id {skill_id!r} in skills/index.json")
    path = _resolve_skill_path(record, index)
    if path is None:
        raise ValueError(
            f"skill {skill_id!r} is indexed but its SKILL.md could not be "
            f"located on disk (path field was {record.get('path')!r})"
        )
    with open(path, "r", encoding="utf-8") as fh:
        body = _strip_frontmatter(fh.read())
    return {
        "id": skill_id,
        "name": record.get("name"),
        "path": os.path.relpath(path, REPO_ROOT),
        "repo_sha": index.get("repo_sha"),
        "body": body,
    }


TOOLS = {
    "skill_search": {
        "description": (
            "Search the pinned cybersecurity-skills index (817 skills) and "
            "return the top-scoring matches as JSON. Delegates to skills/"
            "search.py's search() -- the same code path as the shell CLI -- "
            "so results are byte-identical across every runtime."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Incident/task description to search for.",
                },
                "top": {
                    "type": "integer",
                    "description": "Maximum number of results to return.",
                    "default": 5,
                },
                "domain": {
                    "type": "string",
                    "description": "Optional domain filter.",
                },
                "framework": {
                    "type": "string",
                    "description": "Optional framework filter (e.g. mitre_attack).",
                },
            },
            "required": ["query"],
        },
        "handler": tool_skill_search,
    },
    "skill_load": {
        "description": (
            "Load exactly one skill's SKILL.md body text (frontmatter "
            "stripped) by id, so a runtime can act on one skill without "
            "opening the 817-skill library."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "id": {
                    "type": "string",
                    "description": "Skill id, as returned by skill_search.",
                },
            },
            "required": ["id"],
        },
        "handler": tool_skill_load,
    },
}


def _send(message):
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()


def _send_result(request_id, result):
    _send({"jsonrpc": "2.0", "id": request_id, "result": result})


def _send_error(request_id, code, message, data=None):
    error = {"code": code, "message": message}
    if data is not None:
        error["data"] = data
    _send({"jsonrpc": "2.0", "id": request_id, "error": error})


def handle_initialize(msg):
    _send_result(msg.get("id"), {
        "protocolVersion": PROTOCOL_VERSION,
        "capabilities": {"tools": {}},
        "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
        "instructions": (
            "Two tools: skill_search(query, top, domain, framework) and "
            "skill_load(id). Search first, load only the ids you actually "
            "need (at most a handful), and log selections via "
            "skills/selection_log.py. Never enumerate the full library "
            "through this server."
        ),
    })


def handle_tools_list(msg):
    tools = [
        {
            "name": name,
            "description": spec["description"],
            "inputSchema": spec["inputSchema"],
        }
        for name, spec in TOOLS.items()
    ]
    _send_result(msg.get("id"), {"tools": tools})


def handle_tools_call(msg):
    request_id = msg.get("id")
    params = msg.get("params") or {}
    name = params.get("name")
    arguments = params.get("arguments") or {}

    spec = TOOLS.get(name)
    if spec is None:
        _send_error(request_id, -32602, f"Unknown tool: {name}")
        return

    try:
        payload = spec["handler"](arguments)
        _send_result(request_id, {
            "content": [{"type": "text", "text": json.dumps(payload)}],
            "isError": False,
        })
    except Exception as exc:
        # Tool-level errors are reported inside the result per spec, not as
        # a protocol-level JSON-RPC error -- keeps the server alive and the
        # client informed.
        _send_result(request_id, {
            "content": [{"type": "text", "text": f"{type(exc).__name__}: {exc}"}],
            "isError": True,
        })


def dispatch(msg):
    method = msg.get("method")
    request_id = msg.get("id")

    if method == "initialize":
        handle_initialize(msg)
    elif method == "notifications/initialized":
        return  # notification: no response
    elif method == "tools/list":
        handle_tools_list(msg)
    elif method == "tools/call":
        handle_tools_call(msg)
    elif method == "ping":
        _send_result(request_id, {})
    elif request_id is not None:
        _send_error(request_id, -32601, f"Method not found: {method}")
    # unknown notifications (no id) are ignored per spec


def main():
    _log(f"{SERVER_NAME} {SERVER_VERSION} ready (protocol {PROTOCOL_VERSION})")
    if _SEARCH_IMPORT_ERROR:
        _log(f"warning: skills/search.py not importable yet: {_SEARCH_IMPORT_ERROR}")
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError as exc:
            _send_error(None, -32700, f"Parse error: {exc}")
            continue
        try:
            if isinstance(msg, list):
                for item in msg:
                    dispatch(item)
            else:
                dispatch(msg)
        except Exception as exc:
            request_id = msg.get("id") if isinstance(msg, dict) else None
            _send_error(request_id, -32603, f"Internal error: {exc}")


if __name__ == "__main__":
    main()
