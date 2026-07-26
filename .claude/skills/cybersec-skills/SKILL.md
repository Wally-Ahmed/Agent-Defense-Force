---
name: cybersec-skills
description: Search and load skills from the pinned, community-maintained cybersecurity-skills library (817 skills covering MITRE ATT&CK, NIST CSF 2.0, MITRE ATLAS, D3FEND, NIST AI RMF, and MITRE F3). Trigger for any live security incident, threat-hunting, digital-forensics, or detection-engineering question -- whenever concrete technique, tooling, or playbook guidance is needed for an active investigation, containment decision, or attack/defense analysis. Do not trigger for general programming questions unrelated to security operations.
---

# Cybersecurity skills library (community-maintained, pinned)

This gives search access to 817 cybersecurity skills vendored at
`vendor/cybersecurity-skills/`, pinned at the SHA recorded in
`skills/PINNED.md`.

**Attribution:** community-maintained
(https://github.com/mukul975/Anthropic-Cybersecurity-Skills, author mahipal /
mukul975, Apache-2.0). Despite the upstream repository's name, **this is not
an official Anthropic release.** See `skills/PINNED.md` and
`vendor/cybersecurity-skills/LICENSE`.

## The rule

**Never read `skills/index.json` wholesale. Never load the 817-skill
library into context.** Search does the matching; you only ever need the
handful of results it returns.

## Procedure

1. Search, don't browse. From the repo root:
   ```bash
   python3 skills/search.py "<incident description>" --top 5
   ```
   Add `--domain <D>` or `--framework <F>` to narrow the search if the
   relevant domain/framework is already known. This prints one JSON object
   to stdout with a `results` array of `{id, name, path, one_line, score,
   domains, frameworks, tactics, matched}`.

2. Read only the returned paths. Open at most a handful of the returned
   `SKILL.md` files -- the ones that actually look relevant to the current
   incident. Never open the whole `skills/` directory, never open every
   result, and never open `skills/index.json` itself.

3. Log every selection -- after deciding which `SKILL.md` files were
   actually opened, log exactly that subset (not the full candidate list):
   ```bash
   python3 skills/selection_log.py \
     --run-id "<run_id>" --agent "claude-code" --incident-id "<incident_id>" \
     --query "<the query you searched>" --selected-json -
   ```
   piping a JSON array of the opened results' `{id, path, score}` objects on
   stdin (a file path also works in place of `-`). This appends one line to
   `runs/<run_id>/skills_selected.jsonl` shaped `{ts, agent, incident_id,
   query, selected:[{id,path,score}], repo_sha}`. Reuse whatever run id
   already identifies the current mesh run; if none exists yet, mint a
   timestamp-based one and keep using it for the rest of the incident.

4. Apply the loaded skill's guidance to the incident at hand.

## Why this matters

This is one of six runtimes sharing the same pinned skills library (Hermes,
Claude Code, Codex, Google Antigravity, and two OpenCode profiles). All six
follow the same search -> select at most 5 -> load -> log pattern, against
the same pinned repo SHA, so skill usage stays auditable and comparable
across the mesh. See `skills/README.md` for the full cross-runtime contract
and rationale.
