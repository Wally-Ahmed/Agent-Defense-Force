# Running the test suites

**Jac resolves `import from <name>` relative to the current working directory.**
A suite that imports its siblings must be run from its own package root, or
every import fails with `ModuleNotFoundError` — which looks exactly like a code
regression and is not one.

| Suite | Run from | Command |
|---|---|---|
| App security core (55) | repo root | `for t in tests/*.test.jac; do jac test "$t"; done` |
| Coordinator (64) | `coordinator/` | `for t in tests/test_*.jac; do jac test "$t"; done` |
| Gateway (40) | `gateway/` | `./tests/verify.sh` |
| Incident graph (13) | repo root | `python3 incident/tests/test_acceptance.py` |
| Monitor (6) | repo root | `python3 monitor/tests/test_acceptance.py` |
| Attack driver (35) | repo root | `python3 attack/driver.py` (against `attack/mock_app.py`) |
| Fixture verifier (56) | repo root | `python3 contracts/fixtures/verify_golden.py` |

Source the gitignored `.env` first for anything that touches the app:
`set -a; . ./.env; set +a`.

Notes:
- `coordinator/tests/incidents.jac` is fixture data, not a suite — it has no tests.
- `gateway/tests/verify.sh` must run with `cwd=gateway/`; the root `app/` package
  otherwise shadows `gateway/app.jac`.
- `jac check` prints a misleading "N failed" banner while exiting 0. Trust the
  exit code.

## Two traps that produce false results

**1. Stale compiled modules.** Jac caches to per-directory `.jac/cache/*.jir` keyed on the
base module, so edits to a `.test.jac` annex can be **silently ignored** — a 13-test file
reporting "Ran 8 tests" with no error. Clear before trusting any result:

```bash
find . -type d -path '*/.jac/cache' -not -path './vendor/*' | xargs rm -rf
```

**2. Cold-cache first run.** Immediately after clearing, the first `gateway/tests/verify.sh`
can report spurious failures (observed: 32/7) while every subsequent run is 40/0. Everything
recompiles under a fixture timeout. Re-run once before believing a gateway failure.
