# Agent-Defense-Force

**A six-model AI mesh that catches an autonomous attacker using a valid credential.**

JacHacks SF 2026 — *Agentic AI · Best JacHammer · AI for Defense*

---

## The problem

A stolen valid credential driven by an autonomous agent looks **ordinary one request at a
time**. Rate limits don't fire. Authentication doesn't fail. Every individual call is
something a legitimate user might plausibly make.

Traditional controls are built to reject **invalid** requests. They have nothing to say
about valid requests arriving in a malicious *shape*.

## What we built

Four pieces, proven end-to-end in a sandbox.

### 1. A demo company that is *not* deliberately vulnerable

An ordinary multi-tenant project-management SaaS, written in **Jac** — workspaces,
projects, tasks, comments, members, invites.

It is competently secured: bcrypt password hashing, server-side authorization on every
protected operation, role-based access, tenant isolation, schema validation, CSRF
protection, restrictive CORS, security headers, rate limiting, login throttling,
environment-based secrets, short-lived revocable tokens, and structured audit events.

**No backdoor. No hidden admin bypass. No deliberate injection flaw.** The demo does not
depend on the company being easy to hack — that is the entire point. Ordinary controls
visibly keep working *throughout* the attack.

Because Jac makes the graph the database with no raw SQL surface, "no SQL injection" is
satisfied **structurally**, not by discipline.

### 2. A continuous monitor

A Hermes agent running **GLM-5.2 at `xhigh`** effort, reading *pre-aggregated behavioral
features* — never raw logs, never free text. Escalation is behavioral: there is no
hard-coded "attack" flag anywhere in the codebase.

**Volume alone is never a signature — shape is.** Denial patterns, pivot latency after a
refusal, identity/source decoupling, and reach toward never-before-touched resources are
signal. Request count is not. Benign traffic at 3× the attacker's request rate does not
become an incident.

### 3. Five frontier models responding as a team

When the monitor escalates, five models wake and assess **independently** — DM'd to the
coordinator, never broadcast, so no model anchors on another's answer. ACL-enforced at the
transport, not honour-system.

| Harness | Model | Effort |
|---|---|---|
| Claude Code | Claude Opus 5 | max |
| Codex | GPT-5.6 Sol | max |
| Antigravity (`agy`) | Gemini 3.6 | high |
| OpenCode | Kimi K3 | max |
| OpenCode | GLM-5.2 | max |

Every runtime emits an **effort receipt**. The coordinator refuses to leave `WATCHING`
without six receipts marked `downgraded: false` — never-downgrade is an enforced gate, not
a promise.

A **deterministic weighted quorum** decides: contain iff ≥3/5 malicious **and** score ≥1.5.
The action set is what ≥2 responders independently proposed, each capped at the **minimum**
TTL and narrowest blast radius any of them proposed — so the mesh can only ever be as
aggressive as its second-most-cautious member.

Containment is targeted, never a blanket shutdown: block correlated sources, revoke
sessions, force reauthentication, flip a feature read-only, pause a queue, rotate service
credentials. Every action carries a blast-radius estimate, a TTL, health verification, and
automatic rollback. **Legitimate users keep working throughout** — and health probes prove
it during the run.

Coordination runs over **Cotal** (NATS + JetStream). Cotal has no task lifecycle, so the
escalation → assess → decide → contain → verify → rollback state machine is ours, timeouts
and dead-responder handling included.

### 4. A narrated walkthrough

17 scenes, ~12 minutes, built from real run artifacts.

---

## Verified results

From a real end-to-end live run (`runs/six-live-e2e/`):

- **6/6** effort receipts — `mocked:false blocked:false downgraded:false`
- Five live models all answering **the monitor's own detection**, zero mismatch rejections
- Quorum **5/5 malicious, score 4.54**, contain
- Containment **applied → verified → rolled back, 0 controls remaining**
- **$0.049** metered

The five models converged without seeing each other's answers: all five returned
**malicious**, all five reported campaign stages `[2,3,4]`, and two of them
(claude, kimi) independently picked up an additional stage 6. **Four of the five**
explicitly flagged the planted prompt injection in their rationales.

Confidences landed at **0.85–0.95** (claude 0.85, glm 0.90, kimi 0.90, codex 0.94,
antigravity 0.95) — lower than the 0.93–0.99 the same models returned on a much richer
fixture, and five actions cleared the two-proposer bar rather than eight. Sparser
evidence, less certainty, fewer actions. That is **reasoning, not pattern-matching**.

Test suites run from cleared caches: app+domain **129**, coordinator **64**, incident
**46**, mesh bridge **41**, gateway **40**, attack driver **35/35**, fixture verifier
**56**, monitor **6**.

## What we did not do

Reported honestly, because a security demo that overstates itself is worth nothing:

- Two benign false-positive classes remain open — ASN rotation behind NAT can trip `pivot`,
  and a 404 currently counts as authorization friction.
- Detection correlates over 90s = seven 15s windows, but the monitor's ring shows six, so
  the model sees 2/3 of evidence windows on some incidents. Flagged, not silently tuned.

An agent was tasked to **attack** these claims rather than confirm them. It found a real
CRITICAL bug — a list-operation sensitivity bypass where 61 green tests imported a
different module than the server actually served. Fixed in `7c47464`, with the two
divergent implementations unified so it cannot recur.

## Running it

See **[RUNBOOK.md](RUNBOOK.md)** for the demo in the order it is shown, and
**[SPEC.md](SPEC.md)** for the full acceptance criteria.

```bash
./mesh/up.sh              # bring the mesh up
python3 attack/reset.py   # reset to a known state
./mesh/run_live.sh        # the full live path, traffic → rollback
```

## Attribution

The cybersecurity skills library is
[`mukul975/Anthropic-Cybersecurity-Skills`](https://github.com/mukul975/Anthropic-Cybersecurity-Skills)
— 817 skills mapped to MITRE ATT&CK, NIST CSF 2.0, MITRE ATLAS, D3FEND, NIST AI RMF, and
MITRE F3, Apache 2.0. Despite the repository name this is a **community-maintained**
library, not an official Anthropic release. It is made *discoverable* to every harness and
never injected into any context — agents search the index and load only what the incident
calls for.

Built on [Jac](https://github.com/jaseci-labs/jaseci) 0.13.5 and
[Cotal](https://github.com/Cotal-AI/Cotal).

---

## Repo tooling

This repo is wired for graph-assisted, memory-backed development — see
[CLAUDE.md](CLAUDE.md) for the agent-facing rules. Derived artifacts (`graphify-out/`,
`.mempalace/`) are gitignored; rebuild after a fresh clone with:

```bash
graphify hook install && graphify update .
mempalace init . --yes && mempalace mine .
```
