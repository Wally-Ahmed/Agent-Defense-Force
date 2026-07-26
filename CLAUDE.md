# JacHacksSF 2026

## Memory & recall

Before answering anything about past decisions, prior work, or "what did we do
about X", search the existing memory rather than guessing:

- `mempalace search "<question>"` — semantic search over mined project files and
  conversations.
- The per-project auto-memory lives at
  `~/.claude/projects/-Users-wally-Documents-GitHub-JacHacksSF-2026/memory/`;
  `MEMORY.md` there is the index loaded into every session.

Write a memory when a fact is durable and not derivable from the code or git
history — project goals, constraints, decisions with a rationale, or user
preferences about how work should be done. One fact per file, indexed in
`MEMORY.md`. Do not record what the repo already says.

## Derived artifacts

`graphify-out/`, `.mempalace/`, `mempalace.yaml`, and `entities.json` are
gitignored and machine-local. They are rebuilt, never hand-edited:

- `graphify update .` rebuilds the graph (the `post-commit` hook does this
  automatically in the background after each commit).
- `mempalace mine .` refiles project files into the palace.

## graphify

This project has a knowledge graph at graphify-out/ with god nodes, community structure, and cross-file relationships.

Rules:
- For codebase questions, first run `graphify query "<question>"` when graphify-out/graph.json exists. Use `graphify path "<A>" "<B>"` for relationships and `graphify explain "<concept>"` for focused concepts. These return a scoped subgraph, usually much smaller than GRAPH_REPORT.md or raw grep output.
- If graphify-out/wiki/index.md exists, use it for broad navigation instead of raw source browsing.
- Read graphify-out/GRAPH_REPORT.md only for broad architecture review or when query/path/explain do not surface enough context.
- After modifying code, run `graphify update .` to keep the graph current (AST-only, no API cost).
