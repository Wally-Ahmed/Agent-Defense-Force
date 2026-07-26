// adapters/hermes.js — Hermes Agent (the `monitor`).
//
// CAPTURE POINT: the pseudo-tty created by script(1), around
// `hermes chat -q "<prompt>" -v`.
//
// Flag choice matters here more than anywhere else. Hermes' documented one-shot
// switch, `-z/--oneshot`, prints "ONLY the final response text — no banner, no
// spinner, no tool previews". That is the exact opposite of this component's
// requirement, so the tap does NOT use it. `chat -q` is the non-interactive
// single-query mode that still renders the banner, tool previews and progress,
// and `-v` adds verbose detail. `-Q/--quiet` is likewise avoided.
//
// The pty exists because those previews are terminal-rendered; piped, Hermes
// degrades its renderer and the tool previews we specifically want disappear.
// Set TRANSCRIPT_HERMES_ONESHOT=1 to fall back to `-z` (final answer only) if a
// caller ever wants the terse form.
//
// Hermes exposes no JSON event stream (`hermes --help` / `hermes chat --help`
// have no --json or --format); structured access is only via `hermes acp` or
// `hermes mcp`, both of which are long-lived servers rather than one-shot runs.

import { channelFor, childEnv, promptFile, unsafeAllowed } from "./common.js";
import { shellQuote } from "../pty.js";

export const hermesAdapter = {
  runtime: "hermes",
  cli: "hermes",
  capturePoint: "pseudo-tty via script(1) — hermes chat -q -v (NOT --oneshot: that strips the transcript)",
  channel: channelFor,

  async build({ prompt, model, cwd, extraArgs, agentId, runId }) {
    const bin = process.env.TRANSCRIPT_HERMES_BIN || "hermes";
    const pf = promptFile(runId, agentId, prompt);
    const parts = [bin];

    if (process.env.TRANSCRIPT_HERMES_ONESHOT === "1") {
      parts.push("-z", `"$(cat ${shellQuote(pf.file)})"`);
    } else {
      parts.push("chat", "-q", `"$(cat ${shellQuote(pf.file)})"`, "-v");
    }
    if (model) parts.push("-m", shellQuote(model));
    if (unsafeAllowed()) parts.push("--accept-hooks", "--yolo");
    for (const a of extraArgs) parts.push(shellQuote(a));

    return {
      command: "/bin/sh",
      args: ["-c", parts.join(" ")],
      env: childEnv(),
      cwd,
      pty: process.env.TRANSCRIPT_HERMES_PTY === "0" ? false : true,
      model,
      cleanup: pf.cleanup,
    };
  },

  render: null,
};
