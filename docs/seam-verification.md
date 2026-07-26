# Seam verification — Phase 2

Each seam proven independently before any end-to-end attempt. Every result below
was produced by running the thing, not by reading its tests.

| # | Seam | Evidence | State |
|---|---|---|---|
| 1 | app → audit | live app events carry **exactly** the 38 golden-fixture fields, zero drift | ✅ |
| 2 | audit → monitor | real events aggregate into valid `window.v1` frames (`actors`, `baseline`, bounds) | ✅ |
| 3 | audit → incident graph | emits **schema-valid `incident.v1`**: 7/7 families, 4/4 axes, stages 1–10, 38 evidence events, confidence 0.72 | ✅ |
| 4 | incident → coordinator | full FSM `ESCALATED→ASSESSING→DECIDING→CONTAINING→VERIFYING→CONTAINED`, 5 voted, quorum met | ✅ MOCKED |
| 5 | coordinator → containment | 47 checks; 39/39 uncontained members keep working; TTL rollback restores byte-identical state | ✅ |
| 6 | containment → app/gateway | `Control` nodes read at one choke point; `ip:` key dialect fixed so a throttle is not silently inert | ✅ |
| 7 | monitor → Cotal → responders | mesh runtime | in progress |

## Why seam 1 matters most

The detection layers were built against `contracts/fixtures/audit_golden.jsonl`
before the app existed. Seam 1 proves that bet paid: the app's live output is
byte-compatible with the fixture schema, so the incident graph and monitor
consume real events **without translation**. Contract-first worked.

## Labeling

Seam 4 is honestly `MOCKED` — the coordinator stamps `run_label: MOCKED` and
`mocked: true` into its own output whenever any responder is a mock. That label
is machine-set, not editorial, so a mocked run cannot be mistaken for the live
acceptance run.

## What remains

Only live model calls. Every structural path is proven. See `BLOCKED.md` — one
OpenRouter key plus one `opencode auth login` converts four mocked agents to
live, and the swap is config-only by construction.
