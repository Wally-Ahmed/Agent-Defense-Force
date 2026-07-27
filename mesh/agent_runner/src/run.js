// run.js — one CLI invocation -> one validated, delivered assessment.v1.
//
// The pipeline, in order:
//   incident.v1
//     -> buildPrompt()          untrusted_data fenced behind a nonce
//     -> runTap()               the harness runs UNDER THE TAP, always, so every
//                               byte lands in runs/<run>/transcripts/ and on the
//                               Cotal channel tr-<agent_id>. There is no second
//                               spawn path in this file: output that skipped the
//                               tap would be output nobody can audit.
//     -> extractAnswerText()    unwrap the answer from the event stream
//     -> extractUsage()         real telemetry, or an admitted zero
//     -> estimateUsd()          frozen price table, `priced:false` when absent
//     -> parseAssessment()      extract + coerce + validate against the contract
//     -> sendAssessment()       unicast DM to the coordinator + durable file
//
// MODEL SUBSTITUTION IS NEVER PERFORMED. If a harness cannot serve its pinned
// model the agent is reported blocked and keeps its exact pin. There is no
// fallback model and no "close enough" — a mesh that quietly ran a different
// model would produce an audit trail that is a lie.

import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { agentTable, RESPONDER_IDS } from "../../lib/agents.js";
import { envPresent } from "../../lib/env.js";
import { REPO_ROOT } from "../../lib/paths.js";
import { estimateUsd } from "../../lib/prices.js";
import { runTap, adapterForRuntime } from "../../transcript/src/index.js";
import { buildPrompt } from "./prompt.js";
import { parseAssessment, extractAnswerText } from "./parse.js";
import { extractUsage } from "./usage.js";
import { mockRawText, mockUsage, hasMock, MOCK_DIR } from "./mock.js";
import { sendAssessment } from "./dm.js";

/**
 * How each runtime is told what reasoning effort to use.
 *
 * `enforced` answers ONE question: can we confirm the level was honoured?
 *   true  — the value reaches the runtime through a documented channel AND there
 *           is evidence it took effect (read back, or rejected-if-invalid).
 *   false — the value is delivered, but the runtime neither echoes it nor
 *           rejects a bogus one, so nothing here can prove it took effect.
 *
 * Recording an unverifiable value as if it were verified would be the "silent
 * downgrade" the spec forbids, just pointing the other way. The receipt's own
 * `source` (written by effort_receipts/src/probe.js) carries the full provenance;
 * this flag is the one-bit summary the runner keeps in its notes.
 */
export const EFFORT_PLAN = {
  claude_code: (effort) => ({
    extraArgs: ["--effort", effort],
    env: {},
    source: `flag:--effort ${effort}`,
    enforced: true,
  }),
  codex: (effort) => ({
    extraArgs: [],
    env: { TRANSCRIPT_CODEX_EFFORT: effort },
    source: `env:TRANSCRIPT_CODEX_EFFORT -> -c model_reasoning_effort="${effort}"`,
    enforced: true,
  }),
  agy: (effort) => ({
    extraArgs: ["--effort", effort],
    env: {},
    // The pin itself carries the tier ("gemini-3.6-flash-HIGH"); the flag makes
    // the same value explicit at the CLI. Belt and braces, on purpose.
    source: `model-name-baked + flag:--effort ${effort}`,
    enforced: true,
  }),
  opencode: (effort) => ({
    extraArgs: [],
    // --format json is not cosmetic. In its default renderer opencode prints a
    // human transcript with no token accounting at all; in JSON mode the closing
    // step_finish event carries part.tokens{input,output,reasoning}, which is the
    // only place real usage exists for this runtime. Verified on opencode 1.18.5.
    env: { TRANSCRIPT_OPENCODE_VARIANT: effort, TRANSCRIPT_OPENCODE_FORMAT: "json" },
    source: `env:TRANSCRIPT_OPENCODE_VARIANT -> --variant ${effort}`,
    // ACCEPTED, NOT VALIDATED. opencode neither echoes the variant nor rejects an
    // unknown one — verified live: `--variant bogus-xyz` also exits 0 and answers
    // normally. So the flag is delivered and the run completes, but the runtime
    // gives us nothing to read back; the probe's `source` says so in those words.
    enforced: false,
  }),
  hermes: (effort) => ({
    extraArgs: [],
    env: {},
    // hermes v0.16.0 has NO effort flag anywhere (`hermes --help`, `hermes chat
    // --help`). Its one channel is the config key `agent.reasoning_effort`, which
    // cli.py reads into an OpenRouter `reasoning` block via
    // hermes_constants.parse_reasoning_effort. That value is READ BACK from the
    // config file by the probe, so this is enforced-and-verified rather than
    // hopeful — but it is verified out of band, not from the response stream.
    source: `config:~/.hermes/config.yaml agent.reasoning_effort = "${effort}" (hermes exposes no effort CLI flag; value read back from the config file, not the response)`,
    enforced: true,
  }),
};

/** Resolve an executable on PATH without shelling out. */
export function resolveBin(name) {
  if (name.includes(path.sep)) return fs.existsSync(name) ? name : null;
  const dirs = String(process.env.PATH || "").split(path.delimiter);
  dirs.push(path.join(process.env.HOME || "", ".local", "bin")); // childEnv() adds this
  for (const d of dirs) {
    if (!d) continue;
    const p = path.join(d, name);
    try {
      fs.accessSync(p, fs.constants.X_OK);
      return p;
    } catch {
      /* next */
    }
  }
  return null;
}

function binFor(adapter) {
  const override = {
    claude_code: "TRANSCRIPT_CLAUDE_BIN",
    codex: "TRANSCRIPT_CODEX_BIN",
    agy: "TRANSCRIPT_AGY_BIN",
    opencode: "TRANSCRIPT_OPENCODE_BIN",
    hermes: "TRANSCRIPT_HERMES_BIN",
  }[adapter.runtime];
  return (override && process.env[override]) || adapter.cli;
}

/** Best-effort `<cli> --version`. Never fatal — an unknown version is recorded. */
export function runtimeVersion(bin) {
  if (!bin) return "unknown";
  try {
    const out = execFileSync(bin, ["--version"], {
      encoding: "utf8",
      timeout: 8000,
      stdio: ["ignore", "pipe", "pipe"],
    });
    return String(out).trim().split("\n")[0].trim() || "unknown";
  } catch {
    return "unknown";
  }
}

/**
 * Can this agent reach its pinned model right now?
 * Cheap and non-destructive: a missing CLI or an absent credential is worth
 * knowing BEFORE burning a 15-minute harness timeout on a call that cannot work.
 */
export function preflight(agent, adapter, opts = {}) {
  const reasons = [];
  const bin = binFor(adapter);
  const resolved = resolveBin(bin);
  if (!resolved) reasons.push(`CLI "${bin}" not found on PATH`);
  // Only pins routed strictly through OpenRouter need that key. responder_codex
  // is "chatgpt-or-openrouter" and authenticates against a ChatGPT subscription,
  // so demanding the key there would block an agent that is in fact live.
  //
  // envPresent() consults the real environment AND the repo-root .env. Reading
  // only process.env is what produced the false "OPENROUTER_API_KEY is empty"
  // verdict that had monitor/responder_kimi/responder_glm recorded as blocked:
  // the key was in .env all along and nothing in mesh/ had ever loaded it. The
  // bins now call loadRepoEnv() so the value is also in process.env for the
  // child harnesses; this check no longer depends on that having happened.
  if (agent.via === "openrouter" && !envPresent("OPENROUTER_API_KEY", ...(opts.envFile ? [opts.envFile] : []))) {
    reasons.push("OPENROUTER_API_KEY is unset or empty in both the environment and .env");
  }
  return { ok: reasons.length === 0, reasons, bin, resolvedBin: resolved };
}

/** Set env vars for the duration of `fn`, then restore exactly. */
async function withEnv(vars, fn) {
  const saved = new Map();
  for (const [k, v] of Object.entries(vars)) {
    saved.set(k, process.env[k]);
    process.env[k] = v;
  }
  try {
    return await fn();
  } finally {
    for (const [k, v] of saved) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

/**
 * @param {object} o
 * @param {string} o.agentId       one of RESPONDER_IDS
 * @param {object} o.incident      an incident.v1
 * @param {string} o.runId
 * @param {boolean} [o.mock]       use the recorded transcript instead of the CLI
 * @param {number} [o.timeoutMs]
 * @param {string} [o.cwd]
 * @param {boolean} [o.force]      attempt the live call even if preflight fails
 * @param {string} [o.envFile]     dotenv file preflight consults for credential
 *                                 PRESENCE (a path, never a value); default is the
 *                                 repo root's .env
 * @param {string|object} [o.transport] see dm.js
 * @returns {Promise<object>} {ok, assessment, receiptInput, tap, errors, mocked, blocked, ...}
 */
export async function runResponder(o) {
  const { agentId, incident, runId } = o;
  const errors = [];
  const table = o.table ?? agentTable();
  const agent = table[agentId];

  if (!agent) {
    throw new Error(`unknown agent "${agentId}" — expected one of: ${RESPONDER_IDS.join(", ")}`);
  }
  if (!RESPONDER_IDS.includes(agentId)) {
    throw new Error(
      `"${agentId}" is not a responder — it produces no assessment.v1 (responders: ${RESPONDER_IDS.join(", ")})`,
    );
  }
  if (!incident?.incident_id) {
    throw new Error("incident is missing incident_id — nothing to answer");
  }

  const adapter = adapterForRuntime(agent.tap_runtime);
  const planner = EFFORT_PLAN[agent.tap_runtime];
  if (!planner) throw new Error(`no effort plan for runtime "${agent.tap_runtime}"`);
  const plan = planner(agent.effort);

  const prompt = buildPrompt(incident, { agentId });

  const base = {
    agentId,
    runId,
    incidentId: incident.incident_id,
    runtime: agent.tap_runtime,
    model: agent.model,
    modelOpenrouter: agent.model_openrouter,
    effort: agent.effort,
    promptChars: prompt.length,
  };

  let tap = null;
  let rawText = "";
  let rawUsage;
  let mocked = Boolean(o.mock);
  let blocked = false;
  let pre = null;

  if (mocked) {
    if (!hasMock(agentId, o.mockDir ?? MOCK_DIR)) {
      throw new Error(`--mock requested but no recorded transcript exists for "${agentId}"`);
    }
    rawText = mockRawText(agentId, incident, o.mockDir ?? MOCK_DIR);
    rawUsage = mockUsage(agentId, o.mockDir ?? MOCK_DIR);
  } else {
    pre = preflight(agent, adapter, { envFile: o.envFile });
    if (!pre.ok && !o.force) {
      // Blocked, and it keeps its exact pin. No substitute model, no silent mock.
      return blockedResult(base, agent, adapter, pre, [
        `${agentId} is blocked: ${pre.reasons.join("; ")}`,
        `pinned model "${agent.model}" is NOT substituted — rerun with --mock for the recorded transcript, or fix the credential`,
      ]);
    }
    tap = await withEnv(plan.env, () =>
      runTap({
        agentId,
        adapter,
        // The harness-native form of the pin (see HARNESS_MODEL in lib/agents.js):
        // identical to the pin for claude/codex/agy, provider-prefixed for
        // opencode. A naming transform, never a substitution — the canonical id
        // is what goes into assessment.v1 and the receipt, below.
        model: agent.model_harness,
        incidentId: incident.incident_id,
        runId,
        prompt,
        cwd: o.cwd || REPO_ROOT,
        // Routing args (hermes' --provider openrouter) ride alongside the effort
        // plan's own args. Both are launch mechanics; neither selects a model.
        extraArgs: [...plan.extraArgs, ...(agent.harness_args || [])],
        timeoutMs: o.timeoutMs,
      }),
    );
    if (!tap.ok) {
      errors.push(
        `harness exited code=${tap.exitCode ?? "null"} signal=${tap.signal ?? "none"}` +
          (tap.timedOut ? " (TIMED OUT)" : "") +
          (tap.error ? ` error=${tap.error}` : ""),
      );
    }
    // runTap returns metadata, not content — the transcript is on disk at
    // tap.spool.raw. Read it back rather than re-plumbing the tap.
    rawText = readSpoolRaw(tap, errors);
    rawUsage = extractUsage(agent.tap_runtime, { rawText });
  }

  const price = estimateUsd(agent.model_openrouter, rawUsage);
  const usage = {
    in: rawUsage.in,
    out: rawUsage.out,
    reasoning: rawUsage.reasoning,
    usd: price.usd,
  };

  const ctx = {
    incidentId: incident.incident_id,
    agentId,
    model: agent.model_openrouter, // assessment.v1.model is an OpenRouter id
    effortRequested: agent.effort,
    effortEffective: agent.effort,
    usage,
  };

  // Try the unwrapped answer first; fall back to the whole transcript, because a
  // harness that crashed mid-stream can still have printed a complete object.
  const answer = mocked ? "" : extractAnswerText(agent.tap_runtime, rawText);
  let parsed = answer ? parseAssessment(answer, ctx) : { ok: false, errors: [] };
  let parsedFrom = "answer";
  if (!parsed.ok) {
    const whole = parseAssessment(rawText, ctx);
    if (whole.ok || !answer) {
      parsed = whole;
      parsedFrom = answer ? "full-transcript-fallback" : "full-transcript";
    }
  }

  if (!parsed.ok) {
    // NEVER emit an invalid assessment. An unparseable or non-conforming reply
    // is a failed responder, and the coordinator must see four verdicts rather
    // than five with one fabricated.
    errors.push(...parsed.errors);
    return {
      ...base,
      ok: false,
      assessment: null,
      rejected: parsed.rejected ?? null,
      receiptInput: receiptFor(base, agent, adapter, plan, { mocked, blocked, pre }),
      receiptNotes: notesFor(plan, pre, rawUsage, price, mocked),
      tap,
      dm: null,
      usage,
      usageReported: rawUsage.reported,
      priced: price.priced,
      extraction: parsed.extraction ?? null,
      parsedFrom,
      errors,
      mocked,
      blocked,
    };
  }

  const dm = await sendAssessment(parsed.assessment, { runId, agentId, transport: o.transport });
  errors.push(...dm.errors);

  return {
    ...base,
    ok: true,
    assessment: parsed.assessment,
    assessmentPath: dm.path,
    receiptInput: receiptFor(base, agent, adapter, plan, { mocked, blocked, pre }),
    receiptNotes: notesFor(plan, pre, rawUsage, price, mocked),
    tap,
    dm,
    usage,
    usageReported: rawUsage.reported,
    priced: price.priced,
    extraction: parsed.extraction,
    parsedFrom,
    errors,
    mocked,
    blocked,
  };
}

function readSpoolRaw(tap, errors) {
  const p = tap?.spool?.raw;
  if (!p) {
    errors.push("tap returned no spool path — nothing to parse");
    return "";
  }
  try {
    return fs.readFileSync(p, "utf8");
  } catch (err) {
    errors.push(`could not read transcript ${p}: ${err.message}`);
    return "";
  }
}

/** Exactly the 11 fields of effort_receipt.v1 — the writer passes this through. */
function receiptFor(base, agent, adapter, plan, { mocked, blocked, pre }) {
  return {
    agent: base.agentId,
    runtime: agent.tap_runtime,
    runtime_version: mocked ? "n/a (recorded transcript)" : runtimeVersion(pre?.resolvedBin ?? binFor(adapter)),
    model_requested: agent.model_openrouter,
    // Identical to model_requested BY CONSTRUCTION: there is no substitution
    // path in this runner. A blocked agent keeps its pin rather than swapping.
    model_effective: agent.model_openrouter,
    effort_requested: agent.effort,
    effort_effective: agent.effort,
    source: mocked ? `mock:recorded-transcript (${plan.source})` : plan.source,
    downgraded: false,
    blocked,
    mocked,
  };
}

/** Everything the receipt schema has no field for. Kept beside it, not inside. */
function notesFor(plan, pre, rawUsage, price, mocked) {
  return {
    effort_enforced: plan.enforced,
    effort_channel: plan.source,
    preflight_ok: pre ? pre.ok : null,
    preflight_reasons: pre ? pre.reasons : [],
    usage_reported: rawUsage?.reported ?? false,
    usage_source: rawUsage?.source ?? null,
    priced: price?.priced ?? false,
    mocked,
  };
}

function blockedResult(base, agent, adapter, pre, errors) {
  const plan = EFFORT_PLAN[agent.tap_runtime](agent.effort);
  return {
    ...base,
    ok: false,
    assessment: null,
    rejected: null,
    receiptInput: receiptFor(base, agent, adapter, plan, { mocked: false, blocked: true, pre }),
    receiptNotes: notesFor(plan, pre, null, null, false),
    tap: null,
    dm: null,
    usage: { in: 0, out: 0, reasoning: 0, usd: 0 },
    usageReported: false,
    priced: false,
    extraction: null,
    parsedFrom: null,
    errors,
    mocked: false,
    blocked: true,
  };
}
