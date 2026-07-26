// adapters/agy.js — Antigravity CLI.
//
// CAPTURE POINT: the pseudo-tty created by script(1). LOAD-BEARING, not a
// preference: under a non-tty stdout, `agy -p` exits 0 and silently drops its
// final response. So the pty is simultaneously the only way to get a complete
// answer and our capture point.
//
// Because script(1) is the direct child and `agy` is its grandchild, the tap
// spawns this detached (own process group) and the timeout path kills with
// kill(-pid, SIGTERM) then SIGKILL — see src/pty.js. A plain kill(pid) would
// reap script and leave agy running.
//
// agy has no JSON event mode at all (`agy --help` exposes no --json /
// --output-format), so the pty byte stream IS the transcript. That is fine: it
// is literally what a human would see.

import path from "node:path";
import { channelFor, childEnv, promptFile, unsafeAllowed } from "./common.js";
import { shellQuote } from "../pty.js";

export const agyAdapter = {
  runtime: "agy",
  cli: "agy",
  capturePoint: "pseudo-tty via script(1) — REQUIRED, agy drops its answer off-tty",
  channel: channelFor,

  async build({ prompt, model, cwd, extraArgs, agentId, runId }) {
    const pf = promptFile(runId, agentId, prompt);
    // agy writes new files into ~/.gemini/antigravity-cli/scratch/ unless
    // --add-dir names the work root, so it is passed unconditionally.
    const parts = [
      process.env.TRANSCRIPT_AGY_BIN || "agy",
      "-p",
      `"$(cat ${shellQuote(pf.file)})"`, // raw: command substitution must survive
    ];
    if (model) parts.push("--model", shellQuote(model));
    parts.push("--print-timeout", shellQuote(process.env.TRANSCRIPT_AGY_PRINT_TIMEOUT || "25m"));
    parts.push("--add-dir", shellQuote(cwd));
    parts.push("--log-file", shellQuote(path.join(path.dirname(pf.file), "agy.log")));
    if (unsafeAllowed()) parts.push("--dangerously-skip-permissions");
    for (const a of extraArgs) parts.push(shellQuote(a));

    return {
      command: "/bin/sh",
      args: ["-c", parts.join(" ")],
      env: childEnv(),
      cwd,
      pty: true, // <- the whole reason this adapter exists
      model,
      cleanup: pf.cleanup,
    };
  },

  // No structured events to expand; the pty stream is already the human view.
  // ANSI stripping and \r-overwrite collapsing happen generically in tap.js.
  render: null,
};
