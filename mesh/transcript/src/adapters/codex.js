// adapters/codex.js — OpenAI Codex CLI.
//
// CAPTURE POINT: piped stdout of `codex exec --json`, prompt on stdin via the
// `-` positional. No pty required.
//
// Upstream's connector-codex consumes only four event types (thread.started,
// turn.completed, turn.failed, item.completed/agent_message) and drops every
// other line — and then throws outright on transcript mirroring. Here every
// event is rendered, and any event shape we do not recognise is emitted whole
// rather than swallowed.

import { channelFor, childEnv, show, block, tryJson, unsafeAllowed } from "./common.js";

export const codexAdapter = {
  runtime: "codex",
  cli: "codex",
  capturePoint: "piped stdout — codex exec --json (prompt on stdin)",
  channel: channelFor,

  async build({ prompt, model, cwd, extraArgs }) {
    const args = ["exec", "--json", "--skip-git-repo-check"];
    if (model) args.push("--model", model);
    const effort = process.env.TRANSCRIPT_CODEX_EFFORT;
    if (effort) args.push("-c", `model_reasoning_effort="${effort}"`);
    if (unsafeAllowed()) args.push("--dangerously-bypass-approvals-and-sandbox");
    args.push(...extraArgs);
    args.push("-"); // read the prompt from stdin
    return {
      command: process.env.TRANSCRIPT_CODEX_BIN || "codex",
      args,
      env: childEnv(),
      cwd,
      pty: false,
      stdin: prompt,
      model,
    };
  },

  render(line) {
    const ev = tryJson(line);
    if (!ev) return line ? [line] : [];

    switch (ev.type) {
      case "thread.started":
        return [`⏺ thread ${ev.thread_id ?? "?"}`];
      case "turn.started":
        return [`▸ turn started`];
      case "turn.completed":
        return [`✓ turn completed${ev.usage ? ` · usage=${show(ev.usage)}` : ""}`];
      case "turn.failed":
        return [`✗ turn failed: ${ev.error?.message ?? show(ev.error)}`];
      case "item.started":
      case "item.updated":
      case "item.completed":
        return renderItem(ev.type.split(".")[1], ev.item ?? {});
      case "error":
        return [`✗ error: ${ev.message ?? show(ev)}`];
      default:
        return [`· ${line}`];
    }
  },
};

function renderItem(phase, item) {
  const tag = phase === "completed" ? "" : ` (${phase})`;
  switch (item.type) {
    case "agent_message":
      return block(`◇ assistant${tag}:`, item.text ?? show(item));
    case "reasoning":
      // Kept in full. This is the reasoning trace upstream never mirrors.
      return block(`✳ reasoning${tag}:`, item.text ?? item.summary ?? show(item));
    case "command_execution": {
      const head = `⚒ exec${tag}: ${item.command ?? show(item)}` +
        (item.exit_code !== undefined ? ` (exit ${item.exit_code})` : "");
      return item.aggregated_output || item.output
        ? block(head, item.aggregated_output ?? item.output)
        : [head];
    }
    case "file_change":
      return block(
        `✎ file_change${tag}: ${(item.changes ?? []).map((c) => `${c.kind ?? "?"} ${c.path ?? "?"}`).join(", ") || show(item)}`,
        item.diff ?? "", // diffs are kept; upstream skips patch parts entirely
      );
    case "mcp_tool_call":
      return block(
        `⚒ mcp${tag}: ${item.server ?? "?"}.${item.tool ?? "?"}`,
        show(item.result ?? item.arguments),
      );
    case "todo_list":
      return block(`☰ todo${tag}:`, (item.items ?? []).map((t) => `- [${t.completed ? "x" : " "}] ${t.text ?? show(t)}`).join("\n"));
    case "web_search":
      return [`🔎 web_search${tag}: ${item.query ?? show(item)}`];
    case "error":
      return [`✗ error${tag}: ${item.message ?? show(item)}`];
    default:
      return [`· item/${item.type ?? "?"}${tag}: ${show(item)}`];
  }
}
