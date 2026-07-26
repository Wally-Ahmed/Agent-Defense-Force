// adapters/opencode.js — OpenCode CLI (used by BOTH responder_kimi and responder_glm).
//
// CAPTURE POINT: piped stdout+stderr of `opencode run --print-logs`.
//
// Note this is deliberately NOT how Cotal drives opencode. The upstream
// connector runs `opencode serve` + `opencode attach` and mirrors a condensed
// digest through the plugin API — the path that drops reasoning and cuts tool
// results at 700 chars. `opencode run` is the harness's own one-shot mode, and
// wrapping it gives us the literal terminal stream instead.
//
// `--print-logs` is what adds the internal log lines a user would otherwise only
// see with the TUI open; `--format json` (opt-in) swaps the human renderer for
// raw JSON events, which the renderer below pretty-prints without dropping
// anything it does not recognise.

import { channelFor, childEnv, show, block, tryJson, unsafeAllowed } from "./common.js";

const JSON_MODE = () => process.env.TRANSCRIPT_OPENCODE_FORMAT === "json";

export const opencodeAdapter = {
  runtime: "opencode",
  cli: "opencode",
  capturePoint: "piped stdout+stderr — opencode run --print-logs",
  channel: channelFor,

  async build({ prompt, model, cwd, extraArgs }) {
    const args = ["run", "--print-logs"];
    if (JSON_MODE()) args.push("--format", "json");
    if (model) args.push("-m", model);
    const variant = process.env.TRANSCRIPT_OPENCODE_VARIANT;
    if (variant) args.push("--variant", variant);
    const agent = process.env.TRANSCRIPT_OPENCODE_AGENT;
    if (agent) args.push("--agent", agent);
    if (unsafeAllowed()) args.push("--auto"); // auto-approve permission prompts
    args.push(...extraArgs);
    args.push(prompt); // `opencode run [message..]` takes the prompt positionally
    return {
      command: process.env.TRANSCRIPT_OPENCODE_BIN || "opencode",
      args,
      env: childEnv(),
      cwd,
      pty: process.env.TRANSCRIPT_OPENCODE_PTY === "1",
      model,
    };
  },

  render(line) {
    if (!JSON_MODE()) return line ? [line] : []; // already the human view
    const ev = tryJson(line);
    if (!ev) return line ? [line] : [];

    const type = ev.type ?? ev.event ?? ev.part?.type;
    switch (type) {
      case "text":
      case "message.part.updated":
        return block("◇ assistant:", ev.text ?? ev.part?.text ?? show(ev));
      case "reasoning":
        return block("✳ reasoning:", ev.text ?? show(ev));
      case "tool":
      case "tool.call":
        return block(`⚒ ${ev.tool ?? ev.name ?? "?"}`, show(ev.input ?? ev.state?.input));
      case "tool.result":
        return block(`⤷ result ${ev.tool ?? ""}`, show(ev.output ?? ev.state?.output));
      case "step.finish":
        return [`✓ step finished${ev.usage ? ` · usage=${show(ev.usage)}` : ""}`];
      case "error":
        return [`✗ error: ${ev.message ?? show(ev)}`];
      default:
        return [`· ${line}`];
    }
  },
};
