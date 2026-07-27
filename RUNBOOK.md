# RUNBOOK — driving the demo

Every entry point below was verified to exist. Read `docs/running-tests.md` before
running any test suite: **Jac resolves sibling imports relative to the working
directory**, so each component has a required cwd, and running from the wrong
place fails every import in a way that looks like catastrophic breakage and is
not.

## Before anything

```bash
set -a; . ./.env; set +a          # never echo these values
```

`.env` is gitignored and must contain `APP_CTX_SIGNING_KEY` (the app refuses to
start without it — no default, no dev bypass) and `OPENROUTER_API_KEY`.

**Clear the Jac cache after editing any `.jac` file:**

```bash
find . -type d -name .jac -not -path './vendor/*' | xargs rm -rf
```

Jac silently serves stale compiled modules otherwise. A 13-test file once
reported "Ran 8 tests" with no error.

---

## The demo, in the order it is shown

### 1. Bring the mesh up

```bash
./mesh/up.sh
```

Starts NATS if it is not already running, mints credentials for the eight Cotal
identities, applies the channel ACLs, registers the connectors, and launches the
six agents at their pinned models and efforts. Idempotent — safe to re-run.

Check it took: `ls .cotal/agents/` should list 8.

### 2. Reset to a known state

```bash
python3 attack/reset.py
```

Restores every synthetic account, session, service, and fixture. Run this
between takes so the demo is repeatable.

### 3. Start the application

```bash
jac run app/main.jac        # backend
jac run gateway/main.jac    # edge, from cwd=gateway/
```

The gateway binds `127.0.0.1:8080`; the Jac backend binds `0.0.0.0:8000`
unconditionally (no `--host` flag exists). That is why the gateway HMAC-signs
the request context — see `spikes/README.md`.

### 4. Generate traffic

```bash
python3 attack/benign.py     # the legitimate bulk importer — the negative control
python3 attack/driver.py     # the ten-stage campaign, seeded and deterministic
```

The driver refuses any non-loopback target, asserted on every request with no
flag to disable it.

### 5. Detect

```bash
jac run incident/run_golden.jac      # emits a schema-valid incident.v1
python3 monitor/replay.py            # offline, deterministic, no model call
python3 monitor/replay.py --backend live   # real Hermes/GLM-5.2 call
```

### 6. The full live path

```bash
./mesh/run_live.sh
```

Reset → app + gateway → attack → monitor escalates → five responders assess →
coordinator decides → containment applies → verify → rollback. Writes
`runs/<run_id>/` with effort receipts, assessments, transcripts, and a report.

### 7. Present

```bash
python3 -m http.server 8912 --directory walkthrough
```

17 scenes, 11m46s of narration. Falls back to captions and silent timing if a
clip is missing, so a broken audio file cannot strand the presentation.

---

## Verifying claims on demand

| Claim | Command | cwd |
|---|---|---|
| App security (auth, tenancy, forgery, step-up) | `for t in tests/*.test.jac tests/test_domain_*.jac; do jac test "$t"; done` | repo root |
| Coordinator quorum + FSM | `for t in tests/test_*.jac; do jac test "$t"; done` | `coordinator/` |
| Gateway edge controls | `./tests/verify.sh` | `gateway/` |
| Containment + availability | `./containment/run_verify.sh` | repo root |
| Incident detection | `for t in incident/tests/test_*.jac; do jac test "$t"; done` | repo root |
| Monitor detection | `python3 monitor/tests/test_acceptance.py` | repo root |
| Golden fixture integrity | `python3 contracts/fixtures/verify_golden.py` | repo root |
| Skills library | `bash skills/smoke_test.sh` | repo root |

---

## Known operational traps

- **`gateway/tests/verify.sh` can fail spuriously on its first run after a cache
  clear** (observed 32/7, then 40/0 on every run after). Everything recompiles
  under a fixture timeout. Re-run once before believing a gateway failure.
- **Concurrent test runs contend on the Jac graph DB** and fail with
  `database is locked`. Run suites serially.
- **One `agy` worker per machine** — it merges its MCP entry into a global
  config. Close any interactive `agy` session before a live run.
- **Only OpenRouter costs metered money.** Claude Code, Codex, and Antigravity
  are subscription-backed. See `docs/cost-accounting.md` — the run report prices
  everything at API rates, which overstates actual spend by roughly 34×.
