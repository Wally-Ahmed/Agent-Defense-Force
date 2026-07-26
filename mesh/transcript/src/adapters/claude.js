// adapters/claude.js — Claude Code.
//
// CAPTURE POINT: piped stdout of `claude -p --output-format stream-json --verbose`.
// No pty needed — Claude Code explicitly supports non-interactive `--print` and
// skips the workspace-trust dialog when stdout is not a tty.
//
// We choose stream-json over `--output-format text` deliberately: text emits ONLY
// the final answer, while stream-json emits every event the interactive UI draws
// — tool_use with full input, tool_result with full output, thinking blocks, and
// the closing cost/usage record. The renderer below turns each event back into
// the line a human would have seen, with NOTHING dropped or truncated. That is
// strictly more than upstream's session-JSONL digest, which drops reasoning and
// cuts tool results at 700 chars.

import { channelFor, childEnv, show, block, tryJson, unsafeAllowed } from "./common.js";

export const claudeAdapter = {
  runtime: "claude_code",
  cli: "claude",
  capturePoint: "piped stdout — claude -p --output-format stream-json --verbose",
  channel: channelFor,

  async build({ prompt, model, cwd, extraArgs }) {
    const args = ["-p", "--output-format", "stream-json", "--verbose"];
    if (model) args.push("--model", model);
    if (process.env.TRANSCRIPT_CLAUDE_PARTIAL === "1") args.push("--include-partial-messages");
    if (unsafeAllowed()) args.push("--permission-mode", "bypassPermissions");
    args.push(...extraArgs);
    return {
      command: process.env.TRANSCRIPT_CLAUDE_BIN || "claude",
      args,
      env: childEnv(),
      cwd,
      pty: false,
      // Prompt on stdin rather than argv: no length limit, no quoting hazard,
      // and the prompt never appears in `ps` output.
      stdin: prompt,
      model,
    };
  },

  render(line) {
    const ev = tryJson(line);
    if (!ev) return line ? [line] : [];

    switch (ev.type) {
      case "system":
        if (ev.subtype === "init") {
          return [
            `⏺ session ${ev.session_id ?? "?"} · model ${ev.model ?? "?"} · cwd ${ev.cwd ?? "?"}` +
              (Array.isArray(ev.tools) ? ` · ${ev.tools.length} tools` : ""),
          ];
        }
        // Hook lifecycle and token-counter events are harness telemetry a human
        // never sees in the terminal, and their payloads embed whole config and
        // memory files. Summarised to one line by default — the event is still
        // announced, never silently dropped, and the full payload remains in the
        // .raw spool. TRANSCRIPT_CLAUDE_SYSTEM=full restores it; =off hides it.
        if (TELEMETRY.test(ev.subtype ?? "")) {
          const mode = process.env.TRANSCRIPT_CLAUDE_SYSTEM || "summary";
          if (mode === "off") return [];
          if (mode !== "full") {
            const bits = [ev.hook_name, ev.hook_event, ev.status, ev.estimated_tokens]
              .filter((x) => x !== undefined && x !== null)
              .join(" · ");
            return [`⏺ system/${ev.subtype}${bits ? ` (${bits})` : ""}`];
          }
        }
        return [`⏺ system/${ev.subtype ?? "?"} ${show(omit(ev, ["type", "subtype"]))}`];

      case "assistant":
      case "user":
        return renderMessage(ev);

      case "stream_event":
        return renderPartial(ev);

      case "result": {
        const head =
          `✓ result/${ev.subtype ?? "?"} · ${ev.duration_ms ?? "?"}ms` +
          (ev.num_turns !== undefined ? ` · turns=${ev.num_turns}` : "") +
          (ev.total_cost_usd !== undefined ? ` · $${ev.total_cost_usd}` : "") +
          (ev.usage ? ` · usage=${show(ev.usage)}` : "") +
          (ev.is_error ? " · IS_ERROR" : "");
        return ev.result ? block(head, ev.result) : [head];
      }

      default:
        // Unknown event type: dump it whole rather than lose it.
        return [`· ${line}`];
    }
  },
};

const TELEMETRY = /^(hook_|thinking_tokens$)/;

function omit(o, keys) {
  const out = {};
  for (const [k, v] of Object.entries(o)) if (!keys.includes(k)) out[k] = v;
  return out;
}

function renderMessage(ev) {
  const role = ev.type === "assistant" ? "assistant" : "user";
  const content = ev.message?.content;
  if (typeof content === "string") return block(`◇ ${role}:`, content);
  if (!Array.isArray(content)) return [`◇ ${role}: ${show(ev.message)}`];

  const out = [];
  for (const part of content) {
    switch (part.type) {
      case "text":
        out.push(...block("◇ assistant:", part.text));
        break;
      case "thinking":
      case "redacted_thinking":
        // Upstream drops reasoning entirely. We keep it — the mesh's reasoning
        // being visible is the point of this whole component.
        out.push(...block("✳ thinking:", part.thinking ?? part.data ?? show(part)));
        break;
      case "tool_use":
        out.push(...block(`⚒ ${part.name} [${part.id ?? "?"}]`, show(part.input)));
        break;
      case "tool_result": {
        const body =
          typeof part.content === "string"
            ? part.content
            : Array.isArray(part.content)
              ? part.content.map((c) => (c?.type === "text" ? c.text : show(c))).join("\n")
              : show(part.content);
        const marker = `⤷ result [${part.tool_use_id ?? "?"}]${part.is_error ? " ERROR" : ""} (${body.length} chars)`;
        out.push(...block(marker, body)); // NOT truncated
        break;
      }
      case "image":
        out.push(`🖼 image (${part.source?.media_type ?? "?"})`);
        break;
      default:
        out.push(`· ${role}/${part.type}: ${show(part)}`);
    }
  }
  return out;
}

function renderPartial(ev) {
  const e = ev.event ?? {};
  if (e.type === "content_block_delta") {
    const d = e.delta ?? {};
    const t = d.text ?? d.partial_json ?? d.thinking;
    return t ? [`… ${t}`] : [];
  }
  return [];
}
