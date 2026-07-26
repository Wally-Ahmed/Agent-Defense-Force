# skills/ — pinned cybersecurity-skills library

Operator documentation for the vendored cybersecurity-skills library and how
every runtime in the mesh discovers and uses it.

## Attribution and license

- Upstream: https://github.com/mukul975/Anthropic-Cybersecurity-Skills
- Author: mahipal (GitHub: mukul975)
- License: Apache-2.0. Full text preserved at
  `vendor/cybersecurity-skills/LICENSE` — do not remove or edit it.
- **This is a community-maintained library. It is not an official Anthropic
  release.** The upstream repository's name notwithstanding, Anthropic did
  not publish, review, or endorse this content. State this explicitly in
  any demo, slide, or writeup that references it.
- Pinned commit: `673da1f3b0b7be34ffc9624ef3858fe45f1c3bed`, 817 skills. See
  `PINNED.md` for the full pin record and the exact commands to reconstruct
  `vendor/cybersecurity-skills/` from scratch.

## What is in `skills/`

- `PINNED.md` — the committed pin record: upstream URL, exact SHA, license,
  and the reproducible clone commands for `vendor/cybersecurity-skills/`.
- `build_index.py` — builds `index.json` from the vendored skill tree.
- `index.json` — the 817-record index (`id, name, path, one_line, domains,
  frameworks, tactics, keywords`, plus top-level `repo_sha`, `vendor_root`,
  `total_skills`, `schema`). Machine-read only — never load it wholesale
  into an agent's context.
- `search.py` — the CLI and importable `search()` every runtime calls to
  find relevant skills. Single source of truth for scoring.
- `selection_log.py` — appends an audit record to
  `runs/<run_id>/skills_selected.jsonl` for every selection made.
- `mcp_server.py` — optional stdio MCP wrapper over `search.py`, for
  runtimes that prefer MCP to a raw shell call.
- `smoke_test.sh` — minimal end-to-end check that search and load work.

## The non-negotiable rule

**Never inject the full library into any context.** Every runtime, every
time: search → select at most 5 skills → load only those paths. Every
selection is logged with the skill's path and the pinned repo SHA
(`runs/<run_id>/skills_selected.jsonl`, format above). This applies to all
six runtimes without exception — no harness gets a shortcut that dumps
`index.json` or the `skills/` tree into its own context.

## Discovery mechanism: the uniform shell contract

**Decision: a documented shell call is the primary, uniform discovery
mechanism for all five non-Claude runtimes** (Hermes, Codex, Antigravity,
and both OpenCode profiles). An MCP wrapper (`mcp_server.py`) is available
as an optional convenience layer over the identical code path — never a
separate implementation.

Why shell-first rather than MCP-first:

1. **Universal tool access.** All five harnesses already have shell/bash
   tool access; MCP client support and configuration surface vary between
   them (see the per-runtime notes below).
2. **Antigravity's MCP config is machine-global.** Per `BLOCKED.md` (B1),
   Antigravity's MCP configuration is a single machine-wide file, so
   whatever it points at runs as one worker per machine. Making MCP the
   *primary* mechanism would break the multi-worker mesh for that runtime.
   The shell contract has no such constraint: no daemon, no per-harness
   login, no shared global state.
3. **One code path, byte-identical results.** Every runtime that shells out
   to `search.py` gets the same JSON as every other runtime, because they
   all call the same `search()` function. That keeps skill selections
   comparable and auditable across the mesh. `mcp_server.py` calls that
   same function rather than reimplementing scoring, so the convenience
   layer never drifts from the shell contract.

### The uniform contract (shown once)

```bash
python3 /Users/wally/Documents/GitHub/JacHacksSF-2026/skills/search.py "<incident description>" --top 5 [--domain D] [--framework F]
```

Prints one JSON object to stdout, shaped:

```json
{"query": "...", "repo_sha": "673da1f3b0b7be34ffc9624ef3858fe45f1c3bed", "index_schema": "cybersec-skill-index/1", "total_indexed": 817, "filters": {"domain": null, "framework": null}, "count": 5, "results": [{"id": "...", "name": "...", "path": "...", "one_line": "...", "score": 0.0, "domains": [], "frameworks": [], "tactics": [], "matched": []}]}
```

Every runtime follows the same three steps, regardless of how it invokes
the script:

1. Run the search with the incident/task description as the query.
2. Read only the `path` fields in `results` — open at most 5 `SKILL.md`
   files, never the whole library.
3. Log exactly the subset actually opened (not the full candidate list):
   ```bash
   python3 skills/selection_log.py --run-id <run_id> --agent <runtime-name> \
     --incident-id <incident_id> --query "<query>" --selected-json -
   ```
   piping a JSON array of the opened results' `{id, path, score}` objects on
   stdin (a file path also works in place of `-`); a simpler `--query`-only
   call (no `--selected-json`) re-runs the search and logs its full result
   set instead, if per-selection precision does not matter for a given
   runtime. Either form appends one line to
   `runs/<run_id>/skills_selected.jsonl` shaped `{ts, agent, incident_id,
   query, selected:[{id,path,score}], repo_sha}`.

Use absolute paths in every runtime's wiring — several of these harnesses
run with a working directory unrelated to this repo.

## Per-runtime wiring

### Hermes (GLM-5.2, continuous monitor)

Hermes is this project's own monitor; as of this writing its agent loop has
not been implemented yet (only the mesh schemas under `contracts/mesh/`
exist). This note is forward-looking, not a verified path: wire the shell
contract directly into Hermes's tool-calling loop as a subprocess call to
`search.py`, not through MCP. Hermes runs continuously and calls this far
more often than the other five responders, so avoiding MCP's handshake and
a persistent server process is the leaner choice. Log every selection the
same way, with `agent: "hermes"`.

### Claude Code (Opus 5)

Already wired natively: `.claude/skills/cybersec-skills/SKILL.md` (this
repo). Claude Code auto-discovers skills under `.claude/skills/<name>/
SKILL.md` and triggers on the frontmatter `description` — no separate
registration step. Under the hood it runs the identical `search.py` /
`selection_log.py` calls, so Claude Code's selections are directly
comparable to the other five runtimes even though it does not consume the
shell-contract text directly — it has its own native packaging of the same
contract.

### Codex (GPT-5.6 Sol)

- **Instruction wiring:** Codex reads `AGENTS.md` at the repo root as its
  project-instructions file, but prefers a local `AGENTS.override.md` over
  `AGENTS.md` when present (confirmed in Codex's own source,
  `codex-rs/core/src/agents_md.rs`). **Caveat found during this build:**
  this repo's root `AGENTS.md` is currently claude-mem's auto-regenerated
  context dump (see `.gitignore` — it is rewritten every session), so
  anything hand-written directly into `AGENTS.md` will not persist. Put the
  shell-contract instruction in `AGENTS.override.md` instead so it survives
  claude-mem's rewrites (that file does not exist yet — create it if/when
  Codex needs the instruction to persist across sessions).
- **MCP (optional convenience layer):** `~/.codex/config.toml`, see the
  snippet below.

### Google Antigravity (`agy`, Gemini 3.1 Pro)

`agy` is not installed in this environment yet (`BLOCKED.md` B1), so none of
this has been locally verified end to end — confirm against the installed
CLI once B1 clears. Per Google's published Antigravity CLI docs:

- Global MCP config: `~/.gemini/config/mcp_config.json` (machine-wide —
  this is the file `BLOCKED.md` means by "one worker per machine").
- Workspace-scoped MCP config: `.agents/mcp_config.json`, relative to the
  project. Prefer this over the global file where available, precisely to
  avoid the one-worker constraint the shell contract exists to route
  around.
- Both use the `mcpServers` JSON shape given below.
- Instruction wiring (non-MCP): not verified locally — check `agy`'s own
  instructions-file convention once installed. Until then this repo has no
  confirmed place to put the shell-contract text for Antigravity; flag this
  gap rather than guessing at a path.

### OpenCode / Kimi K3

Same OpenCode installation and config file as the GLM-5.2 profile below
(`model: moonshotai/kimi-k3` per `BLOCKED.md`'s pinned model IDs) — wire the
instruction and MCP entry once in the shared `opencode.json` and both
profiles pick it up:

- **Instruction:** OpenCode also reads `AGENTS.md` (its `/init` command
  creates/updates it), so it has the same clobber problem noted above for
  Codex. Use `opencode.json`'s `"instructions"` array instead — entries
  there are concatenated across global and local config, not
  nearest-file-wins, so point it at a stable file (this README, or a short
  dedicated doc) instead of the claude-mem-owned `AGENTS.md`.
- **MCP:** `opencode.json`'s `"mcp"."servers"` block, see the OpenCode-
  specific snippet below — this is OpenCode's own schema, not the generic
  `mcpServers` shape.

### OpenCode / GLM-5.2

Same installation, config file, and wiring as the Kimi K3 profile above
(`model: z-ai/glm-5.2` per `BLOCKED.md`). Each profile is its own entry
under `opencode.json`'s `"agents"` block with its own `model` field; the
shared `"instructions"` array and `"mcp"` block apply to both without
duplication.

## MCP config snippets (optional convenience layer)

All three snippets launch the same server the same way:

```
command: python3
args:    ["/Users/wally/Documents/GitHub/JacHacksSF-2026/skills/mcp_server.py"]
```

exposing `skill_search(query, top, domain, framework)` and `skill_load(id)`.

### Codex — `~/.codex/config.toml`

```toml
[mcp_servers.cybersec-skills]
command = "python3"
args = ["/Users/wally/Documents/GitHub/JacHacksSF-2026/skills/mcp_server.py"]
```

### Generic `mcpServers` JSON (Antigravity's `mcp_config.json`, global or workspace)

```json
{
  "mcpServers": {
    "cybersec-skills": {
      "command": "python3",
      "args": ["/Users/wally/Documents/GitHub/JacHacksSF-2026/skills/mcp_server.py"]
    }
  }
}
```

### OpenCode — `opencode.json`

OpenCode's own MCP schema differs from the generic shape above (verified
against OpenCode's config schema): it nests servers under `"mcp"."servers"`
and uses a single `"command"` array rather than separate `command`/`args`
fields.

```jsonc
{
  "mcp": {
    "servers": {
      "cybersec-skills": {
        "type": "local",
        "command": ["python3", "/Users/wally/Documents/GitHub/JacHacksSF-2026/skills/mcp_server.py"]
      }
    }
  }
}
```

## Regenerating the index

After re-vendoring (see `PINNED.md`), or any time the vendor tree changes:

```bash
python3 skills/build_index.py
```

Then verify with the smoke test:

```bash
bash skills/smoke_test.sh
```
