// adapters/index.js — agent id -> runtime adapter.
//
// The six entries below are exactly the six agents in
// contracts/mesh/channels.yaml that have a `runtime` with a CLI. The mapping is
// derived from that frozen contract and must stay in sync with it; `coordinator`
// and `svc_containment` are runtime "jac" with model null, so they have no
// harness to tap.

import { claudeAdapter } from "./claude.js";
import { codexAdapter } from "./codex.js";
import { agyAdapter } from "./agy.js";
import { opencodeAdapter } from "./opencode.js";
import { hermesAdapter } from "./hermes.js";
import { loadChannelFn } from "./common.js";

export const ADAPTERS = {
  claude_code: claudeAdapter,
  codex: codexAdapter,
  agy: agyAdapter,
  opencode: opencodeAdapter,
  hermes: hermesAdapter,
};

/** agent_id -> runtime, per contracts/mesh/channels.yaml. */
export const AGENT_RUNTIME = {
  monitor: "hermes",
  responder_claude: "claude_code",
  responder_codex: "codex",
  responder_antigravity: "agy",
  responder_kimi: "opencode",
  responder_glm: "opencode",
};

/** Default model per agent, per contracts/mesh/channels.yaml. */
export const AGENT_MODEL = {
  monitor: "z-ai/glm-5.2",
  responder_claude: "anthropic/claude-opus-5",
  responder_codex: "openai/gpt-5.6-sol",
  responder_antigravity: "google/gemini-3.1-pro-preview",
  responder_kimi: "moonshotai/kimi-k3",
  responder_glm: "z-ai/glm-5.2",
};

export function adapterForAgent(agentId) {
  const runtime = AGENT_RUNTIME[agentId];
  if (!runtime) {
    throw new Error(
      `unknown agent id "${agentId}" — expected one of: ${Object.keys(AGENT_RUNTIME).join(", ")}`,
    );
  }
  return ADAPTERS[runtime];
}

export function adapterForRuntime(runtime) {
  const a = ADAPTERS[runtime];
  if (!a) {
    throw new Error(
      `unknown runtime "${runtime}" — expected one of: ${Object.keys(ADAPTERS).join(", ")}`,
    );
  }
  return a;
}

/** Resolve Cotal's own transcriptChannel() once, if the SDK is present. */
export { loadChannelFn };
