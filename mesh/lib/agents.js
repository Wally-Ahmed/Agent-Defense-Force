// mesh/lib/agents.js — the canonical agent table.
//
// SINGLE SOURCE OF TRUTH for "which agent runs on which harness, pinned to which
// model, at which effort". Everything else in mesh/ derives from this file, so a
// model pin exists in exactly one place and cannot drift between the runner, the
// effort receipts, the bring-up script and the run report.
//
// The pins themselves are READ FROM mesh/config/models.json at import time — they
// are NOT duplicated here. A model is never substituted at runtime: if a harness
// cannot serve its pinned id, the agent is marked blocked and keeps its exact pin.
// There is no fallback model anywhere in this tree, by design.
//
// The eight canonical identities come from contracts/mesh/channels.yaml (frozen).
// `coordinator` and `svc_containment` are runtime "jac" with model null — they
// have no harness, so they appear in IDENTITIES (they need mesh credentials) but
// not in AGENTS (they have nothing to launch).

import fs from "node:fs";
import path from "node:path";
import { REPO_ROOT } from "./paths.js";

export const MODELS_PATH = path.join(REPO_ROOT, "mesh", "config", "models.json");

/** Raw contents of mesh/config/models.json, minus the underscore-prefixed notes. */
export function loadModelPins(file = MODELS_PATH) {
  const raw = JSON.parse(fs.readFileSync(file, "utf8"));
  const out = {};
  for (const [k, v] of Object.entries(raw)) {
    if (k.startsWith("_")) continue;
    out[k] = v;
  }
  return out;
}

/**
 * The eight canonical mesh identities, in channels.yaml order. `cotal mint` runs
 * once per entry in up.sh; the ACL matrix is applied per entry.
 */
export const IDENTITIES = [
  "monitor",
  "responder_claude",
  "responder_codex",
  "responder_antigravity",
  "responder_kimi",
  "responder_glm",
  "coordinator",
  "svc_containment",
];

/** The six identities that actually launch a harness (monitor + five responders). */
export const AGENT_IDS = [
  "monitor",
  "responder_claude",
  "responder_codex",
  "responder_antigravity",
  "responder_kimi",
  "responder_glm",
];

/** The five responder ids, in channels.yaml order. */
export const RESPONDER_IDS = AGENT_IDS.filter((a) => a !== "monitor");

/** Cotal connection profile per identity. Drives `cotal mint --profile`. */
export const PROFILE = {
  monitor: "agent",
  responder_claude: "agent",
  responder_codex: "agent",
  responder_antigravity: "agent",
  responder_kimi: "agent",
  responder_glm: "agent",
  // The coordinator subscribes to sec.incident + sec.deliberate and calls a
  // service; svc_containment answers it. Both are plain agents on the wire —
  // neither needs observer/admin wildcards, and giving them any would hand the
  // decider a `chat.>` subscribe it has no reason to hold.
  coordinator: "agent",
  svc_containment: "agent",
};

/**
 * The frozen ACL matrix from contracts/mesh/channels.yaml, transcribed to the
 * flags `cotal mint` takes. Kept here as data so up.sh stays a thin driver and
 * so tests can diff this against channels.yaml mechanically.
 *
 * NOTE the two security properties this table encodes, from channels.yaml:
 *  - every responder has publish [] on sec.incident, so no responder can ever
 *    observe another responder's verdict (independence is transport-enforced);
 *  - the monitor publishes sec.incident and NOTHING else, with no DM and no
 *    service call, so a fully prompt-injected monitor still cannot act.
 */
export const ACL = {
  monitor: { publish: ["sec.incident"], subscribe: [] },
  responder_claude: {
    publish: ["sec.deliberate"],
    subscribe: ["sec.incident", "sec.verdict", "sec.deliberate"],
  },
  responder_codex: {
    publish: ["sec.deliberate"],
    subscribe: ["sec.incident", "sec.verdict", "sec.deliberate"],
  },
  responder_antigravity: {
    publish: ["sec.deliberate"],
    subscribe: ["sec.incident", "sec.verdict", "sec.deliberate"],
  },
  responder_kimi: {
    publish: ["sec.deliberate"],
    subscribe: ["sec.incident", "sec.verdict", "sec.deliberate"],
  },
  responder_glm: {
    publish: ["sec.deliberate"],
    subscribe: ["sec.incident", "sec.verdict", "sec.deliberate"],
  },
  coordinator: {
    publish: ["sec.verdict", "sec.deliberate"],
    subscribe: ["sec.incident", "sec.deliberate"],
  },
  svc_containment: { publish: [], subscribe: [] },
};

/**
 * Pinned short model id -> canonical OpenRouter id.
 *
 * assessment.v1.model and contracts/mesh/prices.json are both keyed in
 * OpenRouter `org/model` form, but the harnesses take their own native ids
 * (`claude-opus-5`, `gpt-5.6-sol`, `gemini-3.6-flash-high`). This is the ONLY
 * place the two namespaces meet. It is a NAMING map, not a substitution map:
 * both sides always denote the same model.
 */
export const OPENROUTER_ID = {
  "claude-opus-5": "anthropic/claude-opus-5",
  "gpt-5.6-sol": "openai/gpt-5.6-sol",
  "gemini-3.6-flash-high": "google/gemini-3.6-flash-high",
  "moonshotai/kimi-k3": "moonshotai/kimi-k3",
  "z-ai/glm-5.2": "z-ai/glm-5.2",
};

export function openrouterId(shortId) {
  return OPENROUTER_ID[shortId] || shortId;
}

/**
 * Canonical OpenRouter id -> the string THIS HARNESS'S CLI wants on the wire.
 *
 * Same principle as OPENROUTER_ID above and the same guarantee: a NAMING
 * transform, never a substitution. `openrouter/z-ai/glm-5.2` and `z-ai/glm-5.2`
 * denote one model; the prefix is opencode's provider-routing selector, exactly
 * as documented by `opencode run --help` ("-m, --model  model to use in the
 * format of provider/model"). Verified live on opencode 1.18.5: with
 * `-m openrouter/z-ai/glm-5.2` the run logs
 * `llm.provider=openrouter llm.model=z-ai/glm-5.2` — the harness itself splits
 * the prefix back off and reports the canonical id.
 *
 * ONLY the canonical id (`model`/`model_openrouter`) is ever written into
 * assessment.v1 or effort_receipt.v1. The harness form exists solely to launch
 * the CLI and must never reach an artifact.
 */
export const HARNESS_MODEL = {
  // opencode routes by `provider/model`, so an OpenRouter-served pin is prefixed.
  opencode: (canonical, via) => (via === "openrouter" ? `openrouter/${canonical}` : canonical),
  // hermes takes the bare id and selects the provider with a separate --provider
  // flag (see HARNESS_ROUTING_ARGS); prefixing it would make the id unresolvable.
  hermes: (canonical) => canonical,
};

/** The model string to hand `<cli> --model`. Identity for runtimes not listed. */
export function harnessModelId(runtime, canonicalModel, via) {
  const fn = HARNESS_MODEL[runtime];
  return fn ? fn(canonicalModel, via) : canonicalModel;
}

/**
 * Extra CLI arguments a harness needs to reach its pin, beyond the model name.
 *
 * These are ROUTING arguments only — which provider serves the pinned model.
 * They never change WHICH model runs. hermes v0.16.0 exposes `--provider` as a
 * top-level flag (`hermes --help`); without it hermes falls back to its own
 * configured default provider, which is not something the mesh should depend on.
 */
export const HARNESS_ROUTING_ARGS = {
  hermes: (via) => (via === "openrouter" ? ["--provider", "openrouter"] : []),
};

/** Routing args for a runtime, or [] when it needs none. */
export function harnessRoutingArgs(runtime, via) {
  const fn = HARNESS_ROUTING_ARGS[runtime];
  return fn ? fn(via) : [];
}

/**
 * The transcript tap's runtime key for an agent. The tap calls claude's runtime
 * "claude_code" (matching channels.yaml), while models.json calls it "claude".
 */
export const TAP_RUNTIME = {
  hermes: "hermes",
  claude: "claude_code",
  codex: "codex",
  agy: "agy",
  opencode: "opencode",
};

/**
 * Build the full agent table: pins joined to ACL, profile and naming.
 * Throws if models.json and channels.yaml have drifted apart.
 */
export function agentTable(file = MODELS_PATH) {
  const pins = loadModelPins(file);
  const out = {};
  for (const id of AGENT_IDS) {
    const pin = pins[id];
    if (!pin) throw new Error(`mesh/config/models.json is missing agent "${id}"`);
    out[id] = {
      agent_id: id,
      runtime: pin.runtime,
      tap_runtime: TAP_RUNTIME[pin.runtime] || pin.runtime,
      model: pin.model,
      model_openrouter: openrouterId(pin.model),
      // The two harness-facing fields. `model_harness` is what the CLI is
      // launched with; `harness_args` is how it is told which provider serves
      // it. Neither is ever written into an artifact — see HARNESS_MODEL.
      // NOTE the input is pin.model, NOT model_openrouter. claude/codex/agy are
      // driven by their native short ids (`claude-opus-5`), and handing them the
      // OpenRouter form would break three agents that already work. For the two
      // OpenRouter-served runtimes the pin already IS the canonical id, so the
      // transform below has the canonical string to work from either way.
      model_harness: harnessModelId(pin.runtime, pin.model, pin.via),
      harness_args: harnessRoutingArgs(pin.runtime, pin.via),
      effort: pin.effort,
      effort_ceiling: pin.effort_ceiling || null,
      via: pin.via,
      profile: PROFILE[id],
      acl: ACL[id],
    };
  }
  return out;
}

/** Transcript channel name for an agent, per Cotal's transcriptChannel() rule. */
export function transcriptChannel(agentId) {
  return `tr-${String(agentId).toLowerCase().replace(/[^a-z0-9_-]+/g, "-")}`;
}
