# BLOCKED — items only Wally can clear

One entry per item. I log it, build the workaround, and keep going. When you clear one, tell
me and I sweep this file: swap the real thing in, re-run that seam's tests, mark it resolved.

**Nothing here stops the build.** Every entry has a live workaround.

---

## B1 — `agy` (Google Antigravity) not installed · OPEN

**Blocks:** the Gemini 3.1 Pro responder, and therefore the live *six*-model run. Five-model
runs are unaffected.

**What I need from you:**
1. Install the Antigravity IDE, then complete Google OAuth sign-in.
2. Verify: `which agy && agy --version && agy --list-models`
3. Confirm the model list shows **`Gemini 3.1 Pro (High)`** — the reasoning level is baked
   into the model name; there is no separate effort flag.

**Why I can't:** no npm/brew package exists. It ships inside the IDE and requires interactive
Google OAuth. There is no non-interactive path and the spec forbids substituting a different
model.

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

## B2 — `OPENROUTER_API_KEY` not supplied · OPEN

**Blocks:** live inference for hermes/GLM-5.2 (monitor), opencode/Kimi-K3, opencode/GLM-5.2,
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

## B3 — `ELEVENLABS_API_KEY` not supplied · OPEN

**Blocks:** narrated audio in the walkthrough.

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

## B4 — `opencode` needs an OpenRouter login · OPEN

**Blocks:** two of five responders (Kimi K3, GLM-5.2).

**What I need from you, after B2 is cleared:**
```
opencode auth login      # choose OpenRouter, paste the key at its prompt
```

**Why I can't:** interactive credential prompt.

**Workaround in place:** both profiles are configured and their connectors built; they run
against mocks until the login lands.

---

## B5 — `codex` provider routing · OPEN

**Blocks:** the GPT-5.6 Sol responder.

**What I need from you:** either `codex login` (ChatGPT OAuth), or confirm you want it pointed
at OpenRouter, in which case I'll set `model_provider` in `~/.codex/config.toml` myself once
B2 is cleared — no action needed from you beyond the key.

**Workaround in place:** connector built; runs against a mock.

---

## Resolved

_none yet_
