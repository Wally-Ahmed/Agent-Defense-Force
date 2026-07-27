// mesh/effort_receipts/src/probe.js — read EFFECTIVE model + effort back from a live runtime.
//
// WHY THIS FILE EXISTS. A receipt that records what we ASKED for proves nothing: the
// whole failure mode we are defending against is a harness that accepts a flag, quietly
// ignores it, and serves a weaker model or a cheaper reasoning level anyway. So every
// probe here ACTUALLY EXECUTES the CLI and reports what came back, and `source` states
// exactly where the value came from. Where a runtime genuinely does not echo a value,
// the probe SAYS SO in `source` rather than laundering the requested value into an
// "effective" one. An honest "accepted, server-validated, not echoed" is worth more than
// a confident lie.
//
// PROVENANCE STRENGTH, measured against the real CLIs on 2026-07-26 (see each probe):
//   claude : model READ BACK from the system/init event. Effort NOT echoed, but the CLI
//            warns on stderr and falls back to default when it rejects a level, so the
//            ABSENCE of that warning is positive evidence the level was accepted.
//   codex  : NEITHER model nor effort is echoed. Both are validated server-side (an
//            invalid value fails the turn with HTTP 400), so a completed turn is the
//            evidence. Recorded as accepted-input provenance, explicitly labelled.
//   agy    : neither echoed in output, but the CLI validates the (model, effort) PAIR
//            before it runs and exits non-zero on any invalid combination, and
//            `agy models` independently confirms the pinned id exists.
//   opencode : model READ BACK from the `--print-logs` stream, which names the model the
//            build agent actually bound (`message=stream ... modelID=<id> ... small=false
//            agent=build`) and repeats it in the `> build · <id>` header. Effort is NOT
//            echoed and NOT validated -- verified live, `--variant bogus-xyz` also exits 0
//            and answers normally -- so `--variant` is recorded as a DELIVERED input and
//            `source` says exactly that.
//   hermes : echoes NOTHING -- `-z` prints the answer text and no metadata at all. The
//            model is recorded as the accepted `-m/--provider` input, proven by an exit-0
//            live call. Effort has no CLI flag in v0.16.0 at all; its only channel is the
//            config key `agent.reasoning_effort`, which IS read back from the config file.
//
// 2026-07-26 CORRECTION. Until today this file declared opencode and hermes "not
// authenticated" and failed both probes on sight -- opencode because `opencode auth list`
// reports 0 STORED credentials, hermes because OPENROUTER_API_KEY looked absent. Both
// readings were wrong. The key is in the repo-root .env, is valid (OpenRouter /auth/key
// -> HTTP 200), and BOTH runtimes read it straight out of their inherited environment;
// opencode never needed a stored credential. What was actually missing was any code in
// mesh/ that loaded .env — now mesh/lib/env.js, called from the bins. A stored-credential
// count is NOT an authentication signal for opencode and must never be used as one again.
//
// NO CREDENTIAL EVER LEAVES THIS FILE. Key checks report a boolean presence and nothing
// else; no probe echoes an environment value, and `evidence` is truncated CLI output
// that is never allowed to carry a key.

import fs from "node:fs";
import path from "node:path";
import { spawn } from "node:child_process";
import { REPO_ROOT } from "../../lib/paths.js";
import { agentTable, openrouterId, harnessModelId, harnessRoutingArgs } from "../../lib/agents.js";
import { loadRepoEnv, envPresent } from "../../lib/env.js";

/** Default ceilings. Version calls are cheap; model calls make a real API round trip. */
export const VERSION_TIMEOUT_MS = 20_000;
export const PROBE_TIMEOUT_MS = 240_000;

/** Longest CLI snippet we retain as evidence. Bounded so a receipt log stays readable. */
const EVIDENCE_MAX = 400;

/**
 * Run a command to completion with a HARD timeout.
 *
 * The `timeout` binary is not present on this macOS box, and shelling out to one would
 * be the wrong layer anyway: a probe that can hang is a probe that can wedge mesh
 * bring-up forever. The timer lives in Node, escalates SIGTERM -> SIGKILL so a CLI that
 * ignores the polite signal still dies, and resolves rather than rejects so a hung
 * runtime becomes an honest failed probe instead of an exception in the caller.
 */
export function runCommand(cmd, args, opts = {}) {
  const { timeoutMs = VERSION_TIMEOUT_MS, input = null, cwd = REPO_ROOT, env = process.env } = opts;
  return new Promise((resolve) => {
    let child;
    try {
      child = spawn(cmd, args, { cwd, env, stdio: ["pipe", "pipe", "pipe"] });
    } catch (err) {
      resolve({ code: -1, stdout: "", stderr: String(err && err.message), timedOut: false, spawnError: true });
      return;
    }

    let stdout = "";
    let stderr = "";
    let timedOut = false;
    let settled = false;

    // Cap retained output. A runaway CLI must not be able to exhaust memory here.
    const CAP = 2_000_000;
    child.stdout.on("data", (d) => { if (stdout.length < CAP) stdout += d.toString(); });
    child.stderr.on("data", (d) => { if (stderr.length < CAP) stderr += d.toString(); });

    const killTimer = setTimeout(() => {
      timedOut = true;
      try { child.kill("SIGTERM"); } catch { /* already gone */ }
      // Escalate: a CLI blocked on network I/O may never handle SIGTERM.
      setTimeout(() => { try { child.kill("SIGKILL"); } catch { /* already gone */ } }, 3_000).unref();
    }, timeoutMs);

    const finish = (code) => {
      if (settled) return;
      settled = true;
      clearTimeout(killTimer);
      resolve({ code, stdout, stderr, timedOut, spawnError: false });
    };

    child.on("error", (err) => {
      stderr += String(err && err.message);
      finish(-1);
    });
    child.on("close", (code) => finish(code === null ? -1 : code));

    if (input !== null) {
      child.stdin.on("error", () => { /* CLI may close stdin early; not our failure */ });
      child.stdin.end(input);
    } else {
      child.stdin.end();
    }
  });
}

/**
 * Strip ANSI escapes. opencode renders a boxed TUI with colour even when its stdout is
 * a pipe, so `auth list` arrives with SGR codes embedded.
 *
 * Both patterns are anchored on the literal ESC byte, written as an explicit \u001B
 * escape rather than a raw control character so no editor or copy-paste can silently
 * mangle them. Matching on a bare "[" would eat ordinary text -- a model id or an error
 * message containing a bracket would be corrupted, and this output becomes receipt
 * evidence.
 */
const ANSI_CSI = /\u001B\[[0-9;?]*[ -\/]*[@-~]/g;
const ANSI_OSC = /\u001B\][^\u0007]*\u0007/g;
function stripAnsi(s) {
  return String(s).replace(ANSI_OSC, "").replace(ANSI_CSI, "");
}

/** First non-empty line, trimmed. Version banners are multi-line for some CLIs. */
function firstLine(s) {
  for (const line of stripAnsi(s).split("\n")) {
    const t = line.trim();
    if (t) return t;
  }
  return "";
}

function clip(s, n = EVIDENCE_MAX) {
  const t = stripAnsi(String(s)).trim().replace(/\s+/g, " ");
  return t.length > n ? `${t.slice(0, n)}...` : t;
}

/** A uniform failed-probe record. `ok:false` is what turns an agent into a blocked receipt. */
function failed(runtimeVersion, source, error, evidence = "") {
  return {
    runtime_version: runtimeVersion || "",
    model_effective: "",
    effort_effective: "",
    source,
    evidence: clip(evidence),
    ok: false,
    error,
  };
}

/**
 * Read a key's PRESENCE from the environment or the repo .env, never its value.
 *
 * Returns a boolean and nothing else. The value is compared against empty and then
 * dropped on the floor; it is never returned, logged, or written to a receipt. .env is
 * consulted because the mesh CLIs load it themselves, so "not exported in my shell" is
 * not the same question as "will hermes find a key".
 *
 * Delegates to mesh/lib/env.js so there is exactly ONE .env parser in the tree. A second,
 * subtly different parser here is how a key can be visible to one component and invisible
 * to another -- which is the shape of the bug this whole correction is about.
 */
export function keyPresent(name) {
  return envPresent(name);
}

/**
 * Normalise a runtime's NATIVE model id into the OpenRouter namespace.
 *
 * The receipt contract states model_requested/model_effective are OpenRouter ids, but
 * the harnesses speak their own dialect (`claude-opus-5`, `gpt-5.6-sol`,
 * `gemini-3.6-flash-high`). mesh/lib/agents.js is explicit that OPENROUTER_ID is a
 * NAMING map, not a substitution map: both sides always denote the same model. Without
 * this normalisation every single agent would compare unequal and the gate would report
 * six substitutions that never happened. An id the map does not know passes through
 * unchanged, so a genuine substitution still compares unequal and is still caught.
 */
export function toOpenRouterId(nativeId) {
  return openrouterId(String(nativeId || "").trim());
}

// ---------------------------------------------------------------------------
// claude_code — responder_claude
// ---------------------------------------------------------------------------

/**
 * Probe Claude Code.
 *
 * MODEL: genuinely read back. `claude -p --output-format stream-json --verbose` emits a
 * `{"type":"system","subtype":"init",...}` event whose `model` field is the model the
 * session actually bound. The terminal `result` event independently repeats it under
 * `modelUsage[<model>].canonicalModel`; we prefer init and fall back to modelUsage.
 *
 * EFFORT: NOT echoed by any event — there is no effort field in init, assistant, or
 * result. But the CLI is not silent about rejecting one. Verified live:
 *     claude --effort bogus
 *     -> stderr: "Warning: Unknown --effort value 'bogus' - ignoring it and using the
 *                 default effort. Valid values: low, medium, high, xhigh, max."
 * and the session then runs at DEFAULT effort. That is precisely the silent downgrade
 * this whole subsystem exists to catch, so the probe looks for that warning explicitly.
 * Absence of the warning on an otherwise successful run is positive evidence the level
 * was accepted; presence of it means the level was discarded, and we report an unknown
 * effective effort so the gate fails closed rather than recording a level we know was
 * thrown away.
 */
export async function probeClaude(pin, opts = {}) {
  const timeoutMs = opts.timeoutMs ?? PROBE_TIMEOUT_MS;
  const v = await runCommand("claude", ["--version"], { timeoutMs: VERSION_TIMEOUT_MS });
  const version = firstLine(v.stdout) || firstLine(v.stderr);
  if (v.code !== 0 || !version) {
    return failed("", "`claude --version` (non-zero exit)", "claude CLI not runnable", `${v.stdout}${v.stderr}`);
  }

  const args = [
    "-p",
    "--output-format", "stream-json",
    "--verbose",
    "--model", pin.model,
    "--effort", pin.effort,
    "Say OK",
  ];
  const r = await runCommand("claude", args, { timeoutMs });
  if (r.timedOut) {
    return failed(version, "`claude -p --output-format stream-json` (timed out)", `probe exceeded ${timeoutMs}ms`, r.stderr);
  }
  if (r.code !== 0) {
    return failed(version, "`claude -p --output-format stream-json` (non-zero exit)", `claude exited ${r.code}`, `${r.stdout}\n${r.stderr}`);
  }

  let initModel = "";
  let usageModel = "";
  let initRaw = "";
  for (const line of r.stdout.split("\n")) {
    const t = line.trim();
    if (!t) continue;
    let ev;
    try { ev = JSON.parse(t); } catch { continue; }
    if (ev && ev.type === "system" && ev.subtype === "init" && typeof ev.model === "string") {
      initModel = ev.model;
      initRaw = JSON.stringify({ type: ev.type, subtype: ev.subtype, model: ev.model });
    }
    if (ev && ev.type === "result" && ev.modelUsage && typeof ev.modelUsage === "object") {
      const keys = Object.keys(ev.modelUsage);
      if (keys.length) usageModel = ev.modelUsage[keys[0]].canonicalModel || keys[0];
    }
  }

  const effectiveNative = initModel || usageModel;
  if (!effectiveNative) {
    return failed(version, "`claude -p --output-format stream-json` (no init/result model)", "claude did not report a session model", r.stdout);
  }

  // The rejection warning goes to stderr; treat any casing/spelling of it as a rejection.
  const rejected = /Unknown\s+--effort\s+value/i.test(r.stderr);
  const effortEffective = rejected ? "unknown-default" : pin.effort;

  const modelWhere = initModel ? "system/init event" : "result.modelUsage.canonicalModel";
  const source = rejected
    ? `model read back from ${modelWhere} of \`claude -p --output-format stream-json --verbose\`; effort NOT accepted -- claude warned "Unknown --effort value" on stderr and fell back to its default, so the effective level is unknown`
    : `model read back from ${modelWhere} of \`claude -p --output-format stream-json --verbose\`; effort NOT echoed by the runtime -- recorded as the accepted \`--effort ${pin.effort}\` input, which claude validates (it warns "Unknown --effort value ... using the default effort" on stderr and downgrades when it rejects a level; no such warning was emitted)`;

  return {
    runtime_version: version,
    model_effective: toOpenRouterId(effectiveNative),
    effort_effective: effortEffective,
    source,
    evidence: clip(initRaw || `modelUsage=${usageModel}`),
    ok: true,
    error: "",
  };
}

// ---------------------------------------------------------------------------
// codex — responder_codex
// ---------------------------------------------------------------------------

/**
 * Probe Codex.
 *
 * HONEST LIMITATION: codex echoes NEITHER the model NOR the reasoning effort. The
 * verified `codex exec --json` event stream for a successful turn is exactly:
 *     {"type":"thread.started","thread_id":...}
 *     {"type":"turn.started"}
 *     {"type":"item.completed","item":{...,"type":"agent_message","text":...}}
 *     {"type":"turn.completed","usage":{...,"reasoning_output_tokens":N}}
 * There is no model field and no reasoning_effort field anywhere in it. `usage`
 * carries reasoning_output_tokens, which is a token COUNT, not the configured level,
 * and inferring a level from it would be a guess dressed up as a measurement.
 *
 * What we CAN prove is acceptance, because both values are validated end-to-end and an
 * invalid one fails the turn rather than being silently ignored. Verified live:
 *   -c model_reasoning_effort="bogus" -> turn.failed, HTTP 400:
 *       "[ReasoningEffortParam] [reasoning.effort] [invalid_enum_value] Invalid value:
 *        'bogus'. Supported values are: 'none','minimal','low','medium','high','xhigh','max'."
 *   --model bogus-model-xyz          -> turn.failed, HTTP 400:
 *       "The 'bogus-model-xyz' model is not supported when using Codex with a ChatGPT account."
 * So a turn that reaches turn.completed is proof the server accepted this exact model
 * and this exact effort. `source` says that in those words -- accepted and validated,
 * NOT read back -- so nobody mistakes this for an echo.
 */
export async function probeCodex(pin, opts = {}) {
  const timeoutMs = opts.timeoutMs ?? PROBE_TIMEOUT_MS;
  const v = await runCommand("codex", ["--version"], { timeoutMs: VERSION_TIMEOUT_MS });
  const version = firstLine(v.stdout) || firstLine(v.stderr);
  if (v.code !== 0 || !version) {
    return failed("", "`codex --version` (non-zero exit)", "codex CLI not runnable", `${v.stdout}${v.stderr}`);
  }

  const args = [
    "exec", "--json", "--skip-git-repo-check",
    "--model", pin.model,
    "-c", `model_reasoning_effort="${pin.effort}"`,
  ];
  const r = await runCommand("codex", args, { timeoutMs, input: "Reply with exactly PONG." });
  if (r.timedOut) {
    return failed(version, "`codex exec --json` (timed out)", `probe exceeded ${timeoutMs}ms`, r.stderr);
  }

  let completed = false;
  let failedTurn = "";
  let usageRaw = "";
  for (const line of r.stdout.split("\n")) {
    const t = line.trim();
    if (!t) continue;
    let ev;
    try { ev = JSON.parse(t); } catch { continue; }
    if (!ev || typeof ev.type !== "string") continue;
    if (ev.type === "turn.completed") { completed = true; usageRaw = JSON.stringify(ev.usage || {}); }
    if (ev.type === "turn.failed" || ev.type === "error") {
      failedTurn = typeof ev.message === "string" ? ev.message : JSON.stringify(ev.error || ev);
    }
  }

  if (!completed) {
    // A rejected model or effort lands here. Never assume the pin was honoured.
    return failed(
      version,
      "`codex exec --json` (turn did not complete)",
      failedTurn ? `codex rejected the probe: ${clip(failedTurn, 200)}` : `codex exited ${r.code} without turn.completed`,
      `${failedTurn}\n${r.stderr}`,
    );
  }

  return {
    runtime_version: version,
    model_effective: toOpenRouterId(pin.model),
    effort_effective: pin.effort,
    source:
      `codex echoes NEITHER model nor effort -- its \`codex exec --json\` stream is only ` +
      `thread.started/turn.started/item.completed/turn.completed and carries no model or ` +
      `reasoning_effort field. Recorded as the ACCEPTED, SERVER-VALIDATED input ` +
      `\`--model ${pin.model} -c model_reasoning_effort="${pin.effort}"\`, confirmed live by a ` +
      `successful turn.completed: an unsupported effort fails the turn with HTTP 400 ` +
      `[invalid_enum_value] and an unsupported model fails it with HTTP 400 ` +
      `invalid_request_error, so completion proves both values were accepted (NOT read back)`,
    evidence: clip(`turn.completed usage=${usageRaw}`),
    ok: true,
    error: "",
  };
}

// ---------------------------------------------------------------------------
// agy (Antigravity) — responder_antigravity
// ---------------------------------------------------------------------------

/**
 * Probe Antigravity.
 *
 * Effort is baked into the model NAME here (`gemini-3.6-flash-high`), and `agy --effort`
 * is a separate flag whose valid set is verified to be EXACTLY (low, medium, high):
 *     agy -p ... --effort max
 *     -> Error: invalid model selection (--model "gemini-3.6-flash-high" --effort "max"):
 *               invalid --effort "max" (valid: low, medium, high)
 * That is the hard evidence behind responder_antigravity's effort_ceiling of "high":
 * `high` is not a compromise, it is the strongest level this runtime can express, and
 * the receipt writer must not score it as a downgrade.
 *
 * agy validates the (model, effort) PAIR up front and exits 1 on any invalid
 * combination -- including a real model with a bad effort, and a bad model with any
 * effort -- so an exit-0 `-p` run is proof the pair was accepted. `agy models`
 * independently confirms the pinned id is on the served list. The response text itself
 * echoes nothing, so we say so.
 */
export async function probeAgy(pin, opts = {}) {
  const timeoutMs = opts.timeoutMs ?? PROBE_TIMEOUT_MS;
  const v = await runCommand("agy", ["--version"], { timeoutMs: VERSION_TIMEOUT_MS });
  const version = firstLine(v.stdout) || firstLine(v.stderr);
  if (v.code !== 0 || !version) {
    return failed("", "`agy --version` (non-zero exit)", "agy CLI not runnable", `${v.stdout}${v.stderr}`);
  }

  // `agy models` is the real subcommand (there is no --list-models; verified via `agy --help`).
  const list = await runCommand("agy", ["models"], { timeoutMs: VERSION_TIMEOUT_MS });
  const listed = stripAnsi(list.stdout)
    .split("\n")
    .map((s) => s.trim())
    .filter(Boolean);
  const inCatalog = listed.includes(pin.model);
  if (!inCatalog) {
    return failed(
      version,
      "stdout of `agy models`",
      `pinned model "${pin.model}" is not in the agy model catalog`,
      listed.join(","),
    );
  }

  const r = await runCommand("agy", ["-p", "Say OK", "--model", pin.model, "--effort", pin.effort], { timeoutMs });
  if (r.timedOut) {
    return failed(version, "`agy -p --model --effort` (timed out)", `probe exceeded ${timeoutMs}ms`, r.stderr);
  }
  if (r.code !== 0) {
    // agy prints "invalid model selection (...)" here; surface it verbatim, it is the truth.
    return failed(
      version,
      "`agy -p --model --effort` (non-zero exit)",
      `agy rejected the pinned selection: ${clip(r.stderr || r.stdout, 200)}`,
      `${r.stdout}\n${r.stderr}`,
    );
  }

  return {
    runtime_version: version,
    model_effective: toOpenRouterId(pin.model),
    effort_effective: pin.effort,
    source:
      `pinned id confirmed present in stdout of \`agy models\`; accepted by a successful ` +
      `\`agy -p --model ${pin.model} --effort ${pin.effort}\` (exit 0). agy does not echo the ` +
      `model or effort in its response, but it validates the pair BEFORE running and exits 1 ` +
      `on any invalid combination -- \`--effort max\` on this model fails with ` +
      `'invalid --effort "max" (valid: low, medium, high)', which is why high is this ` +
      `runtime's documented ceiling and not a downgrade`,
    evidence: clip(`agy models lists ${pin.model}; probe stdout=${firstLine(r.stdout)}`),
    ok: true,
    error: "",
  };
}

// ---------------------------------------------------------------------------
// opencode — responder_kimi, responder_glm
// ---------------------------------------------------------------------------

/** The one-line answer every live probe asks for. Short, deterministic, cheap. */
const PONG_PROMPT = "Reply with exactly the word PONG and nothing else.";

/**
 * The model opencode's BUILD agent actually bound, out of `--print-logs`.
 *
 * Two different models appear in that stream and picking the wrong one would report a
 * substitution that never happened. Every `opencode run` also fires a tiny side call to
 * auto-title the session, logged as `small=true agent=title` with whatever cheap model
 * the account defaults to (observed: google/gemini-3.6-flash). The line that answers the
 * prompt is the one with `small=false agent=build`, so this matches on that explicitly
 * rather than taking the first or last modelID it finds.
 *
 * @returns {{model: string, provider: string, where: string, raw: string}|null}
 */
export function readOpencodeModel(text) {
  const clean = stripAnsi(String(text));

  for (const line of clean.split("\n")) {
    if (!/message=stream\b/.test(line)) continue;
    if (!/\bsmall=false\b/.test(line)) continue;
    const model = line.match(/\bmodelID=(\S+)/);
    if (!model) continue;
    const provider = line.match(/\bproviderID=(\S+)/);
    return {
      model: model[1],
      provider: provider ? provider[1] : "",
      where: "`message=stream ... small=false agent=build` log line of `opencode run --print-logs`",
      raw: `providerID=${provider ? provider[1] : "?"} modelID=${model[1]} small=false`,
    };
  }

  // Fallback: the human header opencode prints above the answer, e.g.
  //   > build · z-ai/glm-5.2
  // It names the build agent's model unambiguously, so it is a sound second source —
  // but it is absent in --format json mode, which is why the log line is preferred.
  const header = clean.match(/^>\s*build\s*·\s*(\S+)\s*$/m);
  if (header) {
    return {
      model: header[1],
      provider: "",
      where: "the `> build · <model>` header line printed by `opencode run`",
      raw: `> build · ${header[1]}`,
    };
  }
  return null;
}

/**
 * Probe opencode.
 *
 * AUTH. opencode reads its provider key from the ENVIRONMENT. `opencode auth list`
 * counts credentials it has STORED, and a count of 0 says nothing whatsoever about
 * whether it can reach a model -- treating that count as an auth signal is exactly the
 * mistake that had both opencode responders recorded as blocked. So the real check is
 * OPENROUTER_API_KEY presence plus a live call that either works or does not.
 *
 * MODEL: genuinely read back, see readOpencodeModel() above.
 *
 * EFFORT: `--variant` is opencode's documented reasoning-effort channel ("model variant
 * (provider-specific reasoning effort, e.g., high, max, minimal)", `opencode run --help`).
 * opencode neither echoes the variant nor rejects an unknown one -- verified live,
 * `--variant bogus-xyz` exits 0 and answers normally -- so the value is DELIVERED, not
 * confirmed by the harness. What the SERVING ROUTE does with it was measured directly:
 *
 *   * `POST /chat/completions` with `reasoning:{enabled:true,effort:"max"}` returns
 *     HTTP 200 for BOTH pins and bills reasoning tokens, so `max` is not rejected;
 *   * an A/B on one identical prompt against z-ai/glm-5.2 gave 1303 reasoning tokens at
 *     `max` versus 944 at `minimal`, so the parameter demonstrably changes behaviour.
 *     The two calls landed on different upstream providers, so that is DIRECTIONAL
 *     evidence, not a controlled measurement, and is described as such.
 *
 * ONE DISCREPANCY, recorded rather than smoothed over: opencode's model catalog
 * (models.dev) declares z-ai/glm-5.2's effort ladder as ["high","xhigh"] with no "max",
 * while moonshotai/kimi-k3's is ["low","high","max"]. The live route accepts "max" for
 * both. Where a third-party catalog and the serving route disagree about acceptance, the
 * route is authoritative -- but the discrepancy is named in `source` so a reader can see
 * the soft spot instead of inheriting our conclusion. If the catalog is later shown to be
 * right, the correct fix is an explicit `effort_ceiling` in mesh/config/models.json (the
 * mechanism responder_antigravity already uses), NOT a quieter source string.
 */
export async function probeOpencode(pin, opts = {}) {
  const timeoutMs = opts.timeoutMs ?? PROBE_TIMEOUT_MS;
  const v = await runCommand("opencode", ["--version"], { timeoutMs: VERSION_TIMEOUT_MS });
  const version = firstLine(v.stdout) || firstLine(v.stderr);
  if (v.code !== 0 || !version) {
    return failed("", "`opencode --version` (non-zero exit)", "opencode CLI not runnable", `${v.stdout}${v.stderr}`);
  }

  if (pin.via === "openrouter" && !keyPresent("OPENROUTER_API_KEY")) {
    return failed(
      version,
      "`opencode --version` succeeded but OPENROUTER_API_KEY is absent/empty in both the environment and .env (presence checked as a boolean; the value is never read, logged, or stored), so opencode cannot reach its pinned model and none is claimed",
      "OPENROUTER_API_KEY not set; opencode cannot run live",
      "OPENROUTER_API_KEY present=false",
    );
  }

  // The provider-prefixed launch form. A NAMING transform, never a substitution — the
  // read-back below is compared against the canonical pin, so a genuine swap still fails.
  const harnessModel = harnessModelId("opencode", pin.model, pin.via);
  const args = ["run", "--print-logs", "-m", harnessModel, "--variant", pin.effort, PONG_PROMPT];
  const r = await runCommand("opencode", args, { timeoutMs });

  if (r.timedOut) {
    return failed(version, "`opencode run --print-logs` (timed out)", `probe exceeded ${timeoutMs}ms`, r.stderr);
  }
  if (r.code !== 0) {
    return failed(
      version,
      "`opencode run --print-logs` (non-zero exit)",
      `opencode exited ${r.code} on the pinned model: ${clip(r.stderr || r.stdout, 200)}`,
      `${r.stdout}\n${r.stderr}`,
    );
  }

  const read = readOpencodeModel(`${r.stdout}\n${r.stderr}`);
  if (!read) {
    return failed(
      version,
      "`opencode run --print-logs` (no model reported in the stream)",
      "opencode completed but named no build model; refusing to assume the pin was honoured",
      `${r.stdout}\n${r.stderr}`,
    );
  }

  return {
    runtime_version: version,
    // toOpenRouterId is an identity here (the pin already IS an OpenRouter id) but is
    // applied uniformly so the comparison the gate makes is namespace-consistent.
    model_effective: toOpenRouterId(read.model),
    effort_effective: pin.effort,
    source:
      `model READ BACK from ${read.where} after a successful ` +
      `\`opencode run -m ${harnessModel} --variant ${pin.effort}\` (exit 0); the ` +
      `\`openrouter/\` prefix is opencode's provider selector and the runtime reports the ` +
      `canonical id back. Effort NOT echoed and NOT validated by opencode -- verified live, ` +
      `\`--variant bogus-xyz\` also exits 0 and answers normally -- so "${pin.effort}" is ` +
      `recorded as the DELIVERED \`--variant\` input, not a read-back. The SERVING ROUTE ` +
      `does accept it: OpenRouter returns HTTP 200 for reasoning.effort="${pin.effort}" on ` +
      `this model and bills reasoning tokens, and an A/B on one identical prompt gave 1303 ` +
      `reasoning tokens at max vs 944 at minimal (different upstream providers, so ` +
      `directional evidence, not a controlled measurement). CAVEAT, recorded not smoothed ` +
      `over: opencode's models.dev catalog lists z-ai/glm-5.2's effort ladder as ` +
      `[high, xhigh] with no "max" (moonshotai/kimi-k3's is [low, high, max]); the live ` +
      `route accepts max for both and is treated as authoritative for acceptance`,
    evidence: clip(read.raw),
    ok: true,
    error: "",
  };
}

// ---------------------------------------------------------------------------
// hermes — monitor
// ---------------------------------------------------------------------------

/**
 * The model and provider hermes REPORTS FOR ITSELF, from `hermes status`.
 *
 * `hermes status` renders hermes' own resolved runtime state, printing (verbatim):
 *     Model:        z-ai/glm-5.2
 *     Provider:     OpenRouter
 * That is hermes telling us which model it is bound to, which is a stronger source than
 * us parsing its YAML — but be precise about what it is NOT: it is the runtime's
 * CONFIGURED binding, not a per-response echo of what served one particular `-z` call.
 * hermes emits no per-response metadata at all. `source` says exactly that, so nobody
 * reads this as proof-of-serving.
 *
 * @returns {{model: string, provider: string}}
 */
export function readHermesStatus(text) {
  const clean = stripAnsi(String(text));
  const model = clean.match(/^\s*Model:\s*(\S+)\s*$/m);
  const provider = clean.match(/^\s*Provider:\s*(\S+)\s*$/m);
  return {
    model: model ? model[1] : "",
    provider: provider ? provider[1] : "",
  };
}

/**
 * hermes' reasoning effort, read back out of its own config file.
 *
 * hermes v0.16.0 has NO effort flag: `hermes --help` and `hermes chat --help` expose
 * nothing of the kind. Its single channel is the config key `agent.reasoning_effort`,
 * which cli.py turns into an OpenRouter `reasoning` block via
 * hermes_constants.parse_reasoning_effort. So the config file IS the effective setting,
 * and reading it back is a genuine read-back of the value the runtime will use -- just
 * one taken out of band rather than out of the response stream, which `source` states.
 *
 * Deliberately a narrow two-level scan rather than a YAML parse: this runs at mesh
 * bring-up with zero dependencies, and it only has to handle the shape
 * `hermes config set` writes. It mirrors monitor/effort_receipt.py's _scan_hermes_config
 * so the two receipt writers cannot disagree about what hermes is configured to do.
 *
 * @returns {{model: string, effort: string, path: string}}
 */
export function scanHermesConfig(configPath) {
  const out = { model: "", effort: "", path: configPath || "" };
  if (!out.path) return out;
  let text;
  try { text = fs.readFileSync(out.path, "utf8"); } catch { return out; }

  let section = "";
  for (const raw of text.split("\n")) {
    const line = raw.replace(/\r$/, "");
    const stripped = line.trim();
    if (!stripped || stripped.startsWith("#")) continue;
    const indent = line.length - line.replace(/^\s+/, "").length;

    if (indent === 0) {
      section = stripped.endsWith(":") ? stripped.slice(0, -1) : stripped.split(":")[0];
      const inline = stripped.match(/^model:\s*(.+)$/);
      if (inline) {
        const v = inline[1].trim().replace(/^["']|["']$/g, "");
        if (v) out.model = v;
      }
      continue;
    }
    const kv = stripped.match(/^([^:]+):\s*(.*)$/);
    if (!kv) continue;
    const key = kv[1].trim();
    const value = kv[2].trim().replace(/^["']|["']$/g, "");
    if (!value) continue;
    if (section === "agent" && key === "reasoning_effort") out.effort = value;
    else if (section === "model" && (key === "default" || key === "name" || key === "id")) out.model = value;
  }
  return out;
}

/**
 * Probe hermes.
 *
 * AUTH. hermes reaches its model over OpenRouter and reads OPENROUTER_API_KEY itself out
 * of the environment it inherits. The key is checked for PRESENCE ONLY -- keyPresent()
 * returns a boolean, and the value is never read into a variable that leaves this module,
 * never logged, and never written to a receipt.
 *
 * MODEL. hermes emits NO per-response metadata: `-z` prints the final answer text and
 * nothing else (no banner, no model line, no usage). So there is no echo to read, and the
 * model is established from three independent facts rather than one: the pinned
 * `-m <pin> --provider openrouter` was ACCEPTED by an exit-0 live call that returned text;
 * `hermes status` reports the runtime bound to that same model and to provider OpenRouter;
 * and hermes' own config file names it too. `source` states that this is acceptance plus a
 * runtime self-report, NOT a per-response echo, so nobody mistakes it for claude's
 * provenance. If `hermes status` ever disagrees with the pin, that disagreement is
 * recorded as the effective model and the gate catches it -- it is not smoothed over.
 *
 * EFFORT. Read back from `agent.reasoning_effort`, see scanHermesConfig() above. Note
 * that hermes' ladder tops out below the mesh's: hermes_constants.VALID_REASONING_EFFORTS
 * is exactly (minimal, low, medium, high, xhigh) -- there is no "max". `xhigh` is this
 * runtime's ceiling, and it is precisely what mesh/config/models.json pins the monitor to,
 * so the monitor runs flat out and this is NOT a downgrade.
 */
export async function probeHermes(pin, opts = {}) {
  const timeoutMs = opts.timeoutMs ?? PROBE_TIMEOUT_MS;
  const v = await runCommand("hermes", ["--version"], { timeoutMs: VERSION_TIMEOUT_MS });
  const version = firstLine(v.stdout) || firstLine(v.stderr);
  if (v.code !== 0 || !version) {
    return failed("", "`hermes --version` (non-zero exit)", "hermes CLI not runnable", `${v.stdout}${v.stderr}`);
  }

  if (pin.via === "openrouter" && !keyPresent("OPENROUTER_API_KEY")) {
    return failed(
      version,
      "`hermes --version` succeeded but OPENROUTER_API_KEY is absent/empty in both the environment and .env (presence checked as a boolean; the value is never read, logged, or stored), so hermes cannot reach its model and no effective model is claimed",
      "OPENROUTER_API_KEY not set; hermes cannot run live",
      "OPENROUTER_API_KEY present=false",
    );
  }

  const cfgPath = await runCommand("hermes", ["config", "path"], { timeoutMs: VERSION_TIMEOUT_MS });
  const cfg = scanHermesConfig(firstLine(cfgPath.stdout));
  const st = await runCommand("hermes", ["status"], { timeoutMs: VERSION_TIMEOUT_MS });
  const status = readHermesStatus(`${st.stdout}\n${st.stderr}`);

  const routing = harnessRoutingArgs("hermes", pin.via);
  const args = ["-z", PONG_PROMPT, "-m", pin.model, ...routing, "--ignore-rules"];
  const r = await runCommand("hermes", args, { timeoutMs });

  if (r.timedOut) {
    return failed(version, "`hermes -z` (timed out)", `probe exceeded ${timeoutMs}ms`, r.stderr);
  }
  if (r.code !== 0) {
    return failed(
      version,
      "`hermes -z` (non-zero exit)",
      `hermes rejected the pinned selection or failed the call: ${clip(r.stderr || r.stdout, 200)}`,
      `${r.stdout}\n${r.stderr}`,
    );
  }
  const answer = firstLine(r.stdout);
  if (!answer) {
    return failed(
      version,
      "`hermes -z` (exit 0 but no output)",
      "hermes returned nothing; refusing to claim the model answered",
      `${r.stdout}\n${r.stderr}`,
    );
  }

  // An unset effort is NOT quietly promoted to the pin. hermes falls back to its own
  // default when the key is missing, which is a weaker level than we asked for, so an
  // off-scale marker is recorded and isDowngraded() fails closed on it.
  const effortEffective = cfg.effort || "unset-hermes-default";

  // Precedence for the model: what the RUNTIME says about itself first, then its config
  // file, and only then the accepted input. Whatever is used is named in `source`, and a
  // value that contradicts the pin is reported as-is so the gate can catch it.
  let modelEffective = "";
  let modelWhere = "";
  if (status.model) {
    modelEffective = status.model;
    modelWhere = `\`hermes status\` reporting "Model: ${status.model}"${status.provider ? ` / "Provider: ${status.provider}"` : ""}`;
  } else if (cfg.model) {
    modelEffective = cfg.model;
    modelWhere = `the \`model\` key of ${cfg.path || "<hermes config>"}`;
  } else {
    modelEffective = pin.model;
    modelWhere = "the accepted `-m` input alone (neither `hermes status` nor the config named a model)";
  }

  return {
    runtime_version: version,
    model_effective: toOpenRouterId(modelEffective),
    effort_effective: effortEffective,
    source:
      `hermes emits NO per-response metadata -- \`-z\` prints only the answer text -- so this ` +
      `is acceptance plus a runtime self-report, NOT an echo. The pinned selection ` +
      `\`-m ${pin.model} ${routing.join(" ")}\` was ACCEPTED by a live call that exited 0 and ` +
      `returned text, and the model is read back from ${modelWhere}. Effort has NO CLI flag in ` +
      `hermes v0.16.0 (absent from \`hermes --help\` and \`hermes chat --help\`); its only ` +
      `channel is the config key \`agent.reasoning_effort\`, READ BACK as "${effortEffective}" ` +
      `from ${cfg.path || "<hermes config path unavailable>"}. hermes' ladder is exactly ` +
      `(minimal, low, medium, high, xhigh) -- it has no "max" -- so xhigh is this runtime's ` +
      `ceiling and is exactly what the mesh pins, not a compromise`,
    evidence: clip(
      `hermes -z exit=0 answer=${answer}; hermes status Model=${status.model || "-"} ` +
      `Provider=${status.provider || "-"}; agent.reasoning_effort=${effortEffective}`,
    ),
    ok: true,
    error: "",
  };
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/** runtime key (from models.json) -> probe implementation. */
export const PROBES = {
  claude: probeClaude,
  codex: probeCodex,
  agy: probeAgy,
  opencode: probeOpencode,
  hermes: probeHermes,
};

/**
 * Probe the runtime backing `agentId` and return its effective settings.
 *
 * Never throws for a runtime failure -- a probe that blows up would take mesh bring-up
 * with it, and "the probe crashed" is itself a result the receipt should record. Only an
 * unknown agent id (a programming error) throws.
 */
export async function probeForAgent(agentId, opts = {}) {
  // The OpenRouter-backed runtimes read their key out of the environment they inherit
  // from this process, so .env has to be in process.env BEFORE any probe spawns. Done
  // here, at the entry point every probe goes through, rather than at import time: an
  // import that mutates the caller's environment is a trap for the tests. Idempotent,
  // never overrides an already-exported value, and never prints one.
  loadRepoEnv();
  const table = agentTable();
  const pin = table[agentId];
  if (!pin) throw new Error(`unknown agent id "${agentId}"; expected one of ${Object.keys(table).join(", ")}`);
  const impl = PROBES[pin.runtime];
  if (!impl) {
    return failed("", `no probe implemented for runtime "${pin.runtime}"`, `unsupported runtime "${pin.runtime}"`);
  }
  try {
    return await impl(pin, opts);
  } catch (err) {
    return failed("", `probe for runtime "${pin.runtime}" threw`, `probe error: ${err && err.message}`);
  }
}

/**
 * Probe several agents CONCURRENTLY.
 *
 * The six agents share no state and hit five independent runtimes, so running them in
 * series would just add up every network round trip for no benefit. Promise.all is safe
 * because probeForAgent never rejects.
 */
export async function probeAgents(agentIds, opts = {}) {
  const results = await Promise.all(agentIds.map((id) => probeForAgent(id, opts)));
  const out = {};
  agentIds.forEach((id, i) => { out[id] = results[i]; });
  return out;
}
