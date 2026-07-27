# Cost accounting — subscription vs metered

The run report's `usd` column prices **every** agent at public API rates from
`contracts/mesh/prices.json`. That is the right way to compare model cost, but it
is **not** what was spent. Three of the six harnesses authenticate against a paid
subscription and never touch a metered balance.

## The six, by billing path

| Agent | Auth | Run cost | Actually charged? |
|---|---|---|---|
| `responder_claude` | native Max subscription | $1.60058 | **No** — subscription quota |
| `responder_codex` | ChatGPT subscription | $0.123065 | **No** — subscription quota |
| `responder_antigravity` | native Google account | unpriced | **No** — subscription; agy emits no token counts |
| `monitor` (hermes) | OpenRouter | not reported | **Yes** — metered |
| `responder_kimi` | OpenRouter | $0.049899 | **Yes** — metered |
| `responder_glm` | OpenRouter | $0.002347 | **Yes** — metered |

## The corrected figure

- **Reported total: $1.775891** — the API-equivalent cost of all five responders.
- **Actually metered: ≈$0.052** (kimi + glm) plus the monitor's hermes call, which
  reports no per-response metadata.

So the headline number overstates real spend by roughly **34×**. Both numbers are
useful — the imputed one for comparing models, the metered one for the bill — but
they must not be conflated, and the imputed one must never be presented as money
spent.

## ⚠️ Operational constraint

The OpenRouter account read **$7.48 remaining** (lifetime usage $462.52 of $470
credits) at the time of the live run. Metered spend per run is small (~$0.05), but
the **monitor is the expensive one**: it ran at `xhigh` with a 92k-character prompt
before the ring-buffer bound landed, and it fires once per incident. Re-running the
full live path repeatedly on a near-empty balance is the realistic way to run out
mid-demo.

Watch the balance, not just the per-run cost. `COST_WARN_USD=50` is far above the
funds actually available.
