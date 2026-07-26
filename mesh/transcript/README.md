# Transcript tap

Mirrors **every harness's full CLI output** into the Cotal chat channel `tr-<agent_id>`, so a
viewer watching the mesh chat sees what they would see if they were sitting in front of each
agent's terminal — prompts, tool calls, tool results, reasoning, errors and exit codes.

This exists because upstream Cotal does not do it. Per `docs/cotal-integration.md`:
`connector-codex/src/index.ts:40` and `connector-agy/src/index.ts:44` **throw**
`"transcript mirroring is not implemented (v1)"`; the hermes connector mirrors nothing; and
`connector-opencode/src/transcript.ts:46-63` publishes only a condensed digest that drops
reasoning, one-lines tool arguments, truncates tool results at 700 chars and skips diffs.
Nothing in Cotal taps a pty or stdout.

## Design: wrap, don't patch

The tap is a **standalone process that we own, sitting around each harness invocation**. It
spawns the CLI itself, so it sees 100% of the bytes — there is no connector, plugin API or
session-file digest in between. No upstream connector is forked; the repo already carries three
PRs on `integ/mesh` and more divergence would be a maintenance trap.

It talks to Cotal through exactly two public primitives, the same ones the upstream mirrors use:

- `configFromEnv()` and `MeshAgent.send(text, channel)` from `@cotal-ai/connector-core`
- `transcriptChannel(name)` from the same package, imported at runtime so our channel names can
  never drift from Cotal's (a local copy of the rule is used only when the SDK is absent)

**Language: plain ESM JavaScript, zero npm dependencies, Node builtins only.** Cotal's ecosystem
is TypeScript/Node, so JS/TS is native here; JS specifically because the tap must run with no
install step and no build while other tracks are still moving, and the one dependency that
matters (`@cotal-ai/connector-core`) is loaded dynamically from the global `cotal-ai` install
rather than vendored.

```
child stdout/stderr
  -> line split            complete lines only, so a secret can never be halved
                           by a chunk boundary and match nothing
  -> PEM guard             the one credential form that spans newlines
  -> REDACT                nothing leaves the process before this
  -> .raw spool            byte stream, post-redaction, never truncated
  -> display render        strip the CRLF terminator, collapse \r overwrites the
                           way a terminal would, strip ANSI, then adapter.render()
                           expands structured events into the lines a human saw
  -> coalesce              flush on idle (250ms) or byte cap
  -> frame + monotonic seq
  -> emitFrame             the single exit: .log spool (write-ahead, synchronous
                           NDJSON), then the sink queue — best-effort, never
                           blocks the harness
```

## Usage

```sh
node mesh/transcript/src/cli.js doctor          # which CLIs, channels and sinks are available

node mesh/transcript/src/cli.js run \
  --agent responder_claude \
  --incident inc-2026-07-26-0001 \
  --run-id run-42 \
  --prompt-file incident.txt

node mesh/transcript/src/cli.js replay \
  --spool runs/run-42/transcripts/responder_claude.log   # push a spooled run to chat later
```

Programmatically:

```js
import { runTap, adapterForAgent, AGENT_MODEL } from "./mesh/transcript/src/index.js";

const res = await runTap({
  agentId: "responder_claude",
  adapter: adapterForAgent("responder_claude"),
  model: AGENT_MODEL.responder_claude,
  incidentId: "inc-2026-07-26-0001",
  prompt,
});
```

## Capture point per runtime

The six agents are exactly those in `contracts/mesh/channels.yaml` with a CLI runtime
(`coordinator` and `svc_containment` are `runtime: jac`, `model: null` — no harness to tap).

| Agent | Runtime | Capture point | Structured events? |
|---|---|---|---|
| `responder_claude` | claude_code | piped stdout of `claude -p --output-format stream-json --verbose`, prompt on stdin | yes — NDJSON |
| `responder_codex` | codex | piped stdout of `codex exec --json --skip-git-repo-check -`, prompt on stdin | yes — JSONL |
| `responder_antigravity` | agy | **pseudo-tty** via `script(1)` | no |
| `responder_kimi` | opencode | piped stdout+stderr of `opencode run --print-logs` | opt-in (`--format json`) |
| `responder_glm` | opencode | same, different model | opt-in |
| `monitor` | hermes | **pseudo-tty** via `script(1)`, `hermes chat -q "<prompt>" -v` | no |

Notes that matter:

- **agy requires the pty.** Under a non-tty stdout `agy -p` exits 0 and *silently drops its final
  answer*. The pty is simultaneously the only way to get a complete answer and the capture point.
  agy exposes no JSON mode at all, so the pty byte stream **is** the transcript.
- **Process-group kill.** Under a pty, `script(1)` is the direct child and the harness is its
  grandchild, so `kill(pid)` would reap `script` and orphan the harness. Every spawn is
  `detached: true` and the timeout path sends `kill(-pid, SIGTERM)` then `SIGKILL` after a grace
  period (`src/pty.js`). `script` is invoked as `script -qec '<cmd>' /dev/null` on util-linux and
  `script -q /dev/null /bin/sh -c '<cmd>'` on BSD/macOS.
- **hermes deliberately does not use `--oneshot`.** Hermes' documented one-shot flag `-z` prints
  "ONLY the final response text — no banner, no spinner, no tool previews", which is the exact
  opposite of the requirement. `chat -q … -v` is non-interactive *and* keeps the tool previews.
  Set `TRANSCRIPT_HERMES_ONESHOT=1` for the terse form.
- **opencode is not driven the way Cotal drives it.** Upstream runs `opencode serve` + `attach`
  and mirrors through the plugin API — the path that produces the digest. The tap wraps
  `opencode run`, opencode's own one-shot mode, to get the literal terminal stream instead.
- **claude uses `stream-json`, not `text`.** `--output-format text` emits only the final answer;
  `stream-json` emits every event the interactive UI draws, including `thinking` blocks and full
  `tool_result` bodies. The renderer turns each event back into the line a human would have seen.

### Approval-bypass flags are OFF by default

Every one of these harnesses has a `--dangerously-*` / `--yolo` / `--auto` flag, and the upstream
connectors pass them. The tap does **not**, unless
`TRANSCRIPT_ALLOW_UNSAFE_HARNESS_FLAGS=1` is set. Capturing output is a logging change; widening
what a harness may do is a permission escalation, and the two should not ride in together.
Anything after `--` on the CLI is passed through to the harness verbatim if a caller wants
something specific.

## Redaction

**Redaction happens before the chunk leaves the process** — before the sink, before the spool,
before anything is written anywhere. `src/redact.js`.

Two layers:

1. **Pattern-based** (`PATTERNS`, applied most-specific first). Kinds: `pem_block`, `jwt`,
   `openrouter_key` (`sk-or-…`), `anthropic_key` (`sk-ant-…`), `openai_key` (`sk-…`, incl.
   `sk-proj-`/`sk-svcacct-`/`sk-admin-`), `github_token` (`ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_`/
   `github_pat_`), `aws_key_id` (`AKIA`/`ASIA`), `google_api_key` (`AIza…`), `slack_token`
   (`xox[baprse]-`), `nats_seed` (`SU…`/`SA…`/`SO…` 58-char base32), `nats_nkey` (56-char public
   nkey), `vendor_key` (`sk_live_`/`pk_test_`/`whsec_`/`hf_`/`npm_`), `bearer`
   (`Bearer <token>`, scheme word kept), `auth_header` (`Authorization:`/`X-Api-Key:`, including
   `Basic <base64>`), `basic_auth_url` (`https://user:pass@host`), `url_secret_param`
   (`?token=`/`&api_key=`/`code=`/…, name kept), `assignment` (`ANYTHING_KEY|TOKEN|SECRET|
   PASSWORD|CREDENTIAL|SEED|PASSPHRASE|AUTH = value`), `private_key_line` (`ssh-rsa`/`ssh-ed25519`).
   Replacement is `[REDACTED:<kind>]`, so a viewer sees *what* was removed.

2. **Exact-match on this process's own secrets.** `secretsFromEnv()` collects the literal values
   of every env var whose name looks sensitive (`*_KEY`, `*_TOKEN`, `API_KEY`, `ACCESS_TOKEN`,
   `PRIVATE_KEY`, …) and `makeRedactor()` binds them, so a real key that leaks into harness output
   in a shape no regex knows about is still caught. Disable with `TRANSCRIPT_REDACT_ENV=0`.

Two streaming-specific hazards, both closed:

- **Redaction is per complete line, not per chunk.** A secret straddling two `data` events would
  be split in half and match nothing in either half. Lines are safe because a single-line secret
  cannot contain a newline.
- **PEM blocks span lines**, so line-granularity redaction cannot see one whole. `makePemGuard()`
  in `src/tap.js` is a stateful per-stream guard: the `-----BEGIN …-----` line becomes
  `[REDACTED:pem_block]` and every line up to `-----END …-----` is dropped.

Meta frames the tap composes itself (the START banner, which echoes the harness argv) go through
the redactor too.

**Known limits**, per the redactor's own analysis: prefix-less high-entropy tokens (bare hex /
base64 / UUID session ids), `Authorization`-less custom header names, and JSON keys where the
secret word is not the name's suffix. Bind those explicitly via env, which layer 2 then catches.

## Sinks

Selected by `TRANSCRIPT_SINK`. Both sinks call the same `renderChat()` in `src/frame.js`, so the
bytes are identical — only the destination differs.

| Value | Destination |
|---|---|
| `file` (default) | `runs/<run_id>/chat/tr-<agent>.txt` — **works with no mesh running** |
| `cotal` | the Cotal chat channel `tr-<agent_id>` |
| `both` | each independently; either may fail without affecting the other |
| `none` | spool only |

The `cotal` sink loads `@cotal-ai/connector-core` dynamically, searching `$COTAL_SDK_DIR`, this
repo's `node_modules`, `~/.config/cotal/extensions/node_modules`, and the global npm root derived
from wherever `cotal` sits on `PATH`. If the SDK, the identity env or the broker is missing it
returns a *broken sink* rather than throwing, and the run continues spool-only.

Cotal env it needs (none of it lives in this repo — no credentials in code or config): an identity
(`COTAL_NAME` / `COTAL_AGENT_FILE` / `COTAL_LINK`), transport (`COTAL_SERVERS`, default
`nats://127.0.0.1:4222`, or `COTAL_LINK`), and `COTAL_ALLOW_PUBLISH` **must list `tr-<agent_id>`**
— publish is default-deny.

## Ordering, attribution and failure isolation

Every frame carries `agent_id`, `incident_id`, a **dense monotonic `seq` starting at 1**, an ISO
`ts` and a monotonic `mono_ms`. Sequence numbers are dense, so a gap in a spool is proof of loss,
not of reordering. The rendered chat prefix is:

```
[responder_claude · inc-…-26-0001 · #000019 · 21:29:49.300Z] ⤷ result [toolu_…] (15 chars)
                                                                 probe: 21:29:45
```

Continuation lines are indented 4 spaces so a multi-line block cannot be mistaken for another
agent's interleaved output. The incident id is shortened head-and-tail (not a plain prefix)
because real ids are date-prefixed and would otherwise all render identically.

**Every frame is written to disk synchronously *before* the sink is asked to publish it.** If the
mesh is down, if a publish hangs, or if the process is SIGKILLed mid-run, the complete transcript
is still on disk and `transcript-tap replay` can push it to chat afterwards. Losing chat output
must never lose an assessment.

- `runs/<run_id>/transcripts/<agent>.log` — NDJSON envelopes (replayable)
- `runs/<run_id>/transcripts/<agent>.raw` — the redacted byte stream as the CLI emitted it

Publishing runs on a serial queue that preserves sequence order and never blocks the child. A
failed publish is counted, recorded as a `transcript.sink_error` frame *in the spool only*
(publishing a publish-failure would loop), and the run continues.

## Truncation

**Nothing is truncated by default.**

- `TRANSCRIPT_CHUNK_BYTES` (default 3500) is a **split** point, not a cut: a line larger than the
  cap is emitted as sequenced `part i/n` frames whose concatenation reconstructs it exactly.
  Cotal itself chunks chat at 6000 chars, so this stays comfortably inside the transport limit.
  The value is floored at 64 bytes — a cap of 0 would classify every line as oversized and a
  single-digit cap would emit one frame per character.
- `TRANSCRIPT_MAX_CHAT_BYTES` (default **0 = unlimited**) is the only setting that can drop chat
  output. When set and exceeded, a `transcript.truncated` frame is published saying so explicitly
  and naming the spool path, and the run result carries `truncated: true`. **The disk spool is
  never truncated, whatever this is set to.**
- One rendering-level exception, and it is announced rather than silent: Claude Code's
  `system/hook_*` and `system/thinking_tokens` telemetry is summarised to a single line in chat,
  because a human never sees those in the terminal and their payloads embed whole config and
  memory files. The event is still shown; the full payload stays in `.raw`.
  `TRANSCRIPT_CLAUDE_SYSTEM=full` restores it, `=off` hides it entirely.

## Environment

| Variable | Default | Effect |
|---|---|---|
| `TRANSCRIPT_SINK` | `file` | `file` \| `cotal` \| `both` \| `none` |
| `TRANSCRIPT_RUNS_DIR` | `<repo>/runs` | where spools and file-sink output go |
| `TRANSCRIPT_RUN_ID` | `run-<epoch>` | default run id (overridden by `--run-id`) |
| `TRANSCRIPT_INCIDENT_ID` | `no-incident` | default incident id (overridden by `--incident`) |
| `TRANSCRIPT_ECHO` | off | `1` also mirrors chat lines to stderr |
| `TRANSCRIPT_FLUSH_MS` | `250` | streaming cadence |
| `TRANSCRIPT_CHUNK_BYTES` | `3500` | per-message payload cap (splits); floored at 64 |
| `TRANSCRIPT_MAX_CHAT_BYTES` | `0` | chat volume cap; 0 = unlimited |
| `TRANSCRIPT_TIMEOUT_MS` | `900000` | harness timeout before process-group kill |
| `TRANSCRIPT_KILL_GRACE_MS` | `5000` | SIGTERM → SIGKILL grace |
| `TRANSCRIPT_KEEP_ANSI` | off | `1` keeps ANSI escapes in chat |
| `TRANSCRIPT_REDACT_ENV` | on | `0` disables exact-match env-value redaction |
| `TRANSCRIPT_PUBLISH_TIMEOUT_MS` | `5000` | per-publish timeout |
| `TRANSCRIPT_ALLOW_UNSAFE_HARNESS_FLAGS` | off | `1` opts into each harness's approval-bypass flag |
| `TRANSCRIPT_<RUNTIME>_BIN` | the CLI name | override the binary path per runtime |
| `TRANSCRIPT_CLAUDE_SYSTEM` | `summary` | `full` \| `summary` \| `off` |
| `TRANSCRIPT_CLAUDE_PARTIAL` | off | `1` adds `--include-partial-messages` |
| `TRANSCRIPT_CODEX_EFFORT` | unset | rendered as `-c model_reasoning_effort="…"` |
| `TRANSCRIPT_OPENCODE_FORMAT` | `default` | `json` for raw events |
| `TRANSCRIPT_OPENCODE_VARIANT` / `_AGENT` / `_PTY` | unset | passthrough |
| `TRANSCRIPT_AGY_PRINT_TIMEOUT` | `25m` | agy's own `--print-timeout` |
| `TRANSCRIPT_HERMES_ONESHOT` | off | `1` uses `-z` (final answer only) |
| `TRANSCRIPT_HERMES_PTY` | on | `0` disables the pty |

## Tests

```sh
cd mesh/transcript && node --test "test/*.test.js"
```

(On Node 25 `node --test test/` does **not** recurse into a directory — use the quoted glob.)

Covers: redaction against synthetic secrets in every pattern class, idempotence and
non-secret survival; dense-sequence ordering and attribution under five concurrent interleaved
taps; oversized-line splitting with byte-exact reconstruction; spool completeness when the sink is
broken; torn-final-line tolerance; replay; and the pty timeout's process-group kill. The tests use
`/bin/sh` fake adapters and a temp `TRANSCRIPT_RUNS_DIR` — they never call a real model.

## Files

```
src/tap.js              the tap: spawn, capture, redact, sequence, spool, publish
src/redact.js           credential redactor (also usable standalone)
src/frame.js            envelope + the single shared chat renderer
src/spool.js            write-ahead disk spool and replay reader
src/pty.js              script(1) wrapping and process-group kill
src/sinks/{index,file,cotal}.js
src/adapters/{claude,codex,agy,opencode,hermes,common,index}.js
src/cli.js              run | replay | doctor
```
