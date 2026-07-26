# JacHacksSF 2026

Project repository for JacHacks SF 2026.

## Tooling

This repo is wired for graph-assisted, memory-backed development. See
[CLAUDE.md](CLAUDE.md) for the agent-facing rules.

| Tool | What it does | Where it lives |
| --- | --- | --- |
| **graphify** | Builds a knowledge graph of the codebase; rebuilt automatically after every commit | `graphify-out/` (gitignored) |
| **MemPalace** | Semantic memory over project files and conversations | `.mempalace/` (gitignored) |
| **Auto-memory** | Durable per-project facts loaded into every Claude Code session | `~/.claude/projects/-Users-wally-Documents-GitHub-JacHacksSF-2026/memory/` |
| **git hooks** | `post-commit` / `post-checkout` keep the graph in sync | `.git/hooks/` |

### Everyday commands

```bash
graphify query "how does X work"    # ask the graph before grepping
graphify explain "SomeConcept"      # explain a node and its neighbours
graphify path "A" "B"               # shortest path between two nodes
graphify update .                   # manual graph rebuild

mempalace search "what did we decide about Y"
mempalace mine .                    # file project files into the palace
mempalace status                    # what's been filed
```

### Rebuilding from a fresh clone

Derived artifacts are gitignored, so after cloning:

```bash
graphify hook install    # reinstall git hooks
graphify update .        # build the graph
mempalace init . --yes   # recreate the palace, then mine
mempalace mine .
```
