# `contracts/mesh/` — frozen mesh-side interface contracts

**FROZEN CONTRACT — do not edit any file in this directory without conductor approval.**

Multiple agents build against these in parallel. A change here silently breaks work already in
flight, so treat every file as immutable: if something is wrong, report it to the conductor and get
a new version (`*.v2.*`) rather than editing v1 in place.

All schemas are **JSON Schema draft 2020-12**. Each file is self-contained (no cross-file `$ref`),
so a validator only ever needs the one file it is checking.

## Who writes what, who reads it

| Contract | Producer | Consumer | Transport |
|---|---|---|---|
| `window.v1.schema.json` | feature aggregator (telemetry side of the app) | **monitor** | direct read into the monitor process |
| `incident.v1.schema.json` | **monitor** | all 5 responders | Cotal `channel: sec.incident` (multicast, durable) |
| `assessment.v1.schema.json` | each responder | **coordinator** | Cotal `to: coordinator` (unicast, at-least-once) — **never broadcast** |
| `decision.v1.schema.json` | **coordinator** | `svc_containment`, monitor, responders, observers | Cotal `channel: sec.verdict` + `toService: containment` (anycast) |
| `effort_receipt.v1.schema.json` | every agent, once at boot | **coordinator** (WATCHING gate), audit | append-only `runs/<id>/effort.jsonl` |
| `usage.v1.schema.json` | every model-backed agent | run cost report | append-only `runs/<id>/usage.jsonl` |
| `channels.yaml` | — (config) | Cotal / Jac policy layer | — |
| `prices.json` | — (config) | cost estimator | — |

## Canonical agent ids

Used verbatim in `channels.yaml`, `assessment.v1.responder`, `effort_receipt.v1.agent`,
`usage.v1.agent`, and `decision.v1.responders_no_vote` / `action_set[].proposed_by`:

`monitor` · `responder_claude` · `responder_codex` · `responder_antigravity` · `responder_kimi` ·
`responder_glm` · `coordinator` · `svc_containment`

## The flow

1. The feature aggregator emits a `window.v1` every **15 s** (tumbling). The monitor keeps a
   **6-window ring buffer** (90 s) and scores the current window against it. The monitor never
   sees raw logs.
2. On a correlated campaign the monitor publishes exactly one `incident.v1` to `sec.incident`.
   That channel is its **only** write capability.
3. All five responders receive it and each returns one `assessment.v1` by **unicast DM** to the
   coordinator. Responders have `allowPublish: []` on `sec.incident`, so no responder can see
   another's verdict — independence is enforced by the transport, not by instruction.
4. The coordinator counts votes **deterministically** — it is not an LLM judge. One rule:
   `contain iff >=3/5 malicious AND score >= 1.5`. It emits one `decision.v1` on `sec.verdict`.
5. If the verdicts split, the coordinator opens `sec.deliberate` for exactly **one bounded round**,
   then closes it.
6. If `contain` is true, the `action_set` goes to `toService: containment` — **anycast**, so
   exactly one executor instance acts (no double-revoke, redelivered if it dies mid-action).

## Rules that live in more than one file — keep them identical

- **The ten containment kinds** are enumerated in both `assessment.v1` and `decision.v1`:
  `revoke_session`, `revoke_token`, `suspend_principal`, `throttle_source`, `block_source`,
  `force_reauth`, `feature_readonly`, `pause_queue`, `rotate_service_credential`, `raise_logging`.
  The two enums must never diverge, and both are frozen against
  `contracts/containment.contract.jac` — that Jac contract's `Control` node and `guard()` path key
  on these exact names. Any change requires conductor approval.
- **`blast_radius` is ordered** `narrow < moderate < broad`. "Minimum blast radius" means
  *narrowest*.
- **`action_set` derivation**: keep an action only if **>= 2** responders proposed it (same
  `action` **and** same `target`); take the **minimum** `ttl_s` and the **minimum** (narrowest)
  `blast_radius` across those proposals; record the proposers in `proposed_by`.
- **Stage numbering 1–10** is shared by `incident.v1.stage_signatures` and
  `assessment.v1.campaign_stages`, and maps to the ten authorized-scenario attack steps in
  `SPEC.md`.
- **The WATCHING gate**: the coordinator refuses to leave WATCHING unless **six** effort receipts
  exist (monitor + five responders), every one with `downgraded: false`. `blocked: true` /
  `mocked: true` mark an agent that cannot run live yet; any run containing one is labeled
  `MOCKED` and cannot be an acceptance run.

## Prompt-injection boundary

Attacker-controlled free text appears in exactly one place in the entire mesh:
`incident.v1.untrusted_data.fenced[].text`, wrapped as `<<<UNTRUSTED>>>…<<</UNTRUSTED>>>`.
It is never copied into a scored field (`axes`, `families`, `stage_signatures`, `confidence`,
`summary`), never parsed as instructions, and never interpolated into a prompt outside its fence.
No credentials, tokens, raw usernames, or emails appear in any contract — principals travel as
`principal_hash`.

## Validating

Every `*.schema.json` here is meta-valid draft 2020-12. To re-check after any approved change:

```bash
python3 -m venv /tmp/cvenv && /tmp/cvenv/bin/pip install -q jsonschema pyyaml
/tmp/cvenv/bin/python - <<'PY'
import json, glob, yaml
from jsonschema import Draft202012Validator
for p in sorted(glob.glob("contracts/mesh/*.schema.json")):
    s = json.load(open(p)); Draft202012Validator.check_schema(s)
    assert s.get("additionalProperties") is False and {"$id","title","description","required"} <= s.keys(), p
    print("meta-valid", p)
json.load(open("contracts/mesh/prices.json"))
yaml.safe_load(open("contracts/mesh/channels.yaml"))
print("prices.json + channels.yaml parse")
PY
```

Validate your own emissions against the matching schema before sending them on the wire —
`Draft202012Validator(schema).validate(payload)`.
