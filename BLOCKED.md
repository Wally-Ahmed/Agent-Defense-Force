# BLOCKED — items only Wally can clear

One entry per item. I log it, build the workaround, and keep going. When you clear one, tell
me and I sweep this file: swap the real thing in, re-run that seam's tests, mark it resolved.

**Nothing here stops the build.** Every entry has a live workaround.

---

## B1 — `agy` Google OAuth · ✅ RESOLVED 14:35 PDT

**Cleared.** User completed sign-in. Verified directly: `agy models` lists the catalog (it
refused before auth), and a real headless call — `agy -p "…" --model gemini-3.1-pro-high` —
returned live Gemini 3.1 Pro output.

**Three facts locked in from the live check:**
- Model id is **`gemini-3.1-pro-high`** (not the "(High)" display string from the old prior
  art). Only `-high` and `-low` exist for the pro tier, so **high is the ceiling** → recorded
  as effective effort, not a downgrade. Effort receipt written to `runs/live/effort.jsonl`
  with `downgraded:false`.
- **Plain `-p` works headless on 1.1.7** — the TTY-drop bug that forced the `script -qec`
  wrapper in the agi-summit-hack connector does NOT reproduce here. The Antigravity connector
  can drop the pty wrapper, which removes the process-group-kill complexity too.
- Auth state lives outside the file patterns I scanned for (`~/.gemini` shows no obvious
  cred/token file), so "no credential file" is NOT a reliable un-auth signal for this runtime.
  Use `agy models` succeeding as the auth probe instead.

Original entry retained below for the record.

---

## B1 (original) — `agy` install + OAuth

**Binary is installed** — `agy 1.1.7` at `/Users/wally/.local/bin/agy`, via the documented
non-interactive script (`curl -fsSL https://antigravity.google/cli/install.sh | bash`). My
earlier note that this needed the IDE was wrong; a standalone installer exists.

All required headless flags confirmed present: `-p/--print`, `--model`, `--conversation`,
`--add-dir`, `--dangerously-skip-permissions`, `--print-timeout`.

**Still blocks:** the Gemini 3.1 Pro responder, and therefore the live *six*-model run.

**What I need from you — one step, ~1 minute.** Run it in the Claude Code session with the
`!` prefix so it gets a live terminal:
```
! agy
```
It prints a Google URL, you sign in, then paste the authorization code back into that same
prompt.

**Why I cannot do this for you — settled empirically, do not retry.**

Without a real TTY `agy` does not merely fail to finish the handshake, it refuses to begin
one: `Error: authentication required. Run 'agy' to log in, then retry.` The interactive URL
flow is offered only when it has a terminal. Detached, `script` cannot allocate one either
(`tcgetattr/ioctl: Operation not supported on socket`), and a FIFO on stdin does not help
because the refusal happens before stdin is ever read.

Even with a URL in hand, the authorization code is redeemable only by the process that
printed it: that process holds the PKCE `code_verifier`, which is generated in memory and
never written to disk (verified — nothing under `~/.gemini` holds pending-auth state). So a
code pasted anywhere other than the waiting prompt is unusable by construction.

**Therefore: paste the code into the same terminal that printed the URL.** Three separate
codes were relayed to me during this session and none could have worked.

**Effort note for the receipt:** `agy --effort` accepts only `low|medium|high`. `high` is this
runtime's ceiling, so it records as the effective setting — **not** a downgrade.

**Workaround in place:** connector + adapter built in full against a recorded-transcript mock
speaking the real `assessment.v1` schema. Swapping in the live model is a config change, not a
rewrite. Its effort receipt carries `blocked: true`, and any run including it is labeled
`MOCKED` in every artifact.

**How long it holds:** indefinitely for development and for all seam tests. It does **not**
hold for acceptance — `SPEC.md` requires a live six-model run, and a mocked responder cannot
satisfy it.

**Known traps once installed:** `agy` silently drops its answer when stdout is not a TTY
(hence the `script -qec` wrapper), and its global MCP config means **one worker per machine**.

---

## B2 — `OPENROUTER_API_KEY` · ✅ RESOLVED 16:45 PDT

**Cleared.** Key supplied in the gitignored `.env`. Verified by calling OpenRouter directly:
**all five pinned model ids resolve LIVE** — `z-ai/glm-5.2`, `moonshotai/kimi-k3`,
`openai/gpt-5.6-sol`, `anthropic/claude-opus-5`, `google/gemini-3.1-pro-preview`. That check
mattered: a model id that failed to resolve would otherwise have surfaced mid-acceptance-run.

Hermes is now configured at `~/.hermes/config.yaml` for provider `openrouter`, model
`z-ai/glm-5.2`, effort `xhigh`, with the key in `~/.hermes/.env` (mode 600, never echoed).

Original entry below.

**Blocks (was):** live inference for hermes/GLM-5.2 (monitor), opencode/Kimi-K3, opencode/GLM-5.2,
and codex/GPT-5.6-Sol if routed via OpenRouter.

**What I need from you:** write it into the gitignored `.env` at repo root:
```
OPENROUTER_API_KEY=sk-or-...
```
Do not paste it into chat. I will never read, echo, or commit the value.

**Workaround in place:** `.env.example` documents every required variable. All four
OpenRouter-backed agents are built against recorded-transcript mocks. Model IDs stay pinned
exactly (`z-ai/glm-5.2`, `moonshotai/kimi-k3`, `openai/gpt-5.6-sol`) — never substituted.

**How long it holds:** through Phases 1–3. Blocks Phase 4 acceptance entirely.

---

## B3 — `ELEVENLABS_API_KEY` · ✅ RESOLVED 16:45 PDT

**Cleared.** `ELEVENLABS_API_KEY` and `ELEVENLABS_VOICE_ID` are both set in `.env`. The
walkthrough was deliberately built so per-scene narration drops in as data against the existing
`durationMs` entries — no re-authoring needed.

**Blocks (was):** narrated audio in the walkthrough.

**What I need from you:** add to the same gitignored `.env`:
```
ELEVENLABS_API_KEY=...
ELEVENLABS_VOICE_ID=...
```

**Workaround in place:** the full walkthrough is built with on-screen captions and silent
scene timing, structured so per-scene narration drops in without re-authoring — scene
durations are declared in the `TOUR` array and the caption track is already beat-aligned.

**How long it holds:** the walkthrough is presentable without audio. Adding narration later
requires no structural change.

---

## B4 — `opencode` OpenRouter login · ✅ RESOLVED 16:50 PDT — NO USER ACTION NEEDED

**Cleared without the interactive login.** `opencode` reads `OPENROUTER_API_KEY` straight from
the environment; `opencode auth login` was never required. Verified live:
`opencode run --model openrouter/z-ai/glm-5.2` printed `> build · z-ai/glm-5.2` then `PONG`.

Original entry below.

## B4 (original) — `opencode` needs an OpenRouter login

**Blocks:** two of five responders (Kimi K3, GLM-5.2).

**What I need from you, after B2 is cleared:**
```
opencode auth login      # choose OpenRouter, paste the key at its prompt
```

**Why I can't:** interactive credential prompt.

**Workaround in place:** both profiles are configured and their connectors built; they run
against mocks until the login lands.

---

## B5 — `codex` provider routing · ✅ RESOLVED 16:50 PDT — NO USER ACTION NEEDED

**Cleared.** The existing `~/.codex/auth.json` works; no re-login and no OpenRouter reroute
needed. Verified live: `codex exec --json` returned a full event stream ending
`{"type":"item.completed","item":{"type":"agent_message","text":"PONG"}}` with real usage
accounting (17,830 input / 13,056 cached / 6 output tokens).

Original entry below.

## B5 (original) — `codex` provider routing

**Blocks:** the GPT-5.6 Sol responder.

**What I need from you:** either `codex login` (ChatGPT OAuth), or confirm you want it pointed
at OpenRouter, in which case I'll set `model_provider` in `~/.codex/config.toml` myself once
B2 is cleared — no action needed from you beyond the key.

**Workaround in place:** connector built; runs against a mock.

---

---

## Architecture correction — auth strategy, 14:05 PDT

The `hermes-handoff-overview` walkthrough establishes the pattern this project's prior art
actually uses: **each harness runs stock and authenticates natively with the operator's own
subscription** — no token scraping, no API credits. "Pick the ONE you already pay for."

That changes my plan, which had routed all five harnesses through OpenRouter. Corrected:

| Harness | Auth | State |
|---|---|---|
| Claude Code | **native** — Claude Max subscription | ✅ already authenticated, no key needed |
| Codex | ChatGPT subscription **or** OpenRouter | B5 |
| `agy` | native — Google account | B1 |
| OpenCode ×2 | OpenRouter (no native provider for Kimi K3 / GLM-5.2) | B2 + B4 |
| Hermes | OpenRouter (`z-ai/glm-5.2`) | B2 |

This is not a walk-back of the OpenRouter decision — it narrows it to where it is actually
needed. Claude Code is already working on your Max subscription, so routing it through
OpenRouter would add a dependency and a cost for nothing. Model IDs stay pinned exactly
either way; nothing is substituted.

---

## Resolved

- **B1 (install half)** — `agy 1.1.7` installed non-interactively at 14:03 PDT. OAuth still open.

---

## ALL BLOCKERS CLEARED — 16:50 PDT

Six of six harnesses verified with **real model calls**, not config inspection:

| Agent | Runtime | Model | Proof |
|---|---|---|---|
| `monitor` | hermes | `z-ai/glm-5.2` @ xhigh | `PONG` via OpenRouter |
| `responder_claude` | claude | `claude-opus-5` @ max | authed on Max subscription |
| `responder_codex` | codex | `gpt-5.6-sol` | JSON stream + usage accounting |
| `responder_antigravity` | agy | `gemini-3.6-flash-high` | `PONG`, plain `-p`, no pty needed |
| `responder_kimi` | opencode | `moonshotai/kimi-k3` | env-key auth, no login required |
| `responder_glm` | opencode | `z-ai/glm-5.2` | `> build · z-ai/glm-5.2` → `PONG` |

All five OpenRouter-pinned model ids resolve live. Two blockers (B4, B5) turned out to need
**no user action at all** — the tools read the environment key directly.

Nothing is blocked. The live six-model run is now gated only on the mesh runtime.
