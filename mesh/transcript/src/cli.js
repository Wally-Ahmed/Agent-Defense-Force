#!/usr/bin/env node
// cli.js — run one harness under the tap, replay a spool, or check the setup.

import fs from "node:fs";
import { runTap } from "./tap.js";
import { readSpool } from "./spool.js";
import { createSink } from "./sinks/index.js";
import { renderChat } from "./frame.js";
import {
  ADAPTERS,
  AGENT_RUNTIME,
  AGENT_MODEL,
  adapterForAgent,
  loadChannelFn,
} from "./adapters/index.js";

const USAGE = `
transcript-tap — mirror a harness's full CLI output into the Cotal chat channel tr-<agent_id>

  transcript-tap run --agent <id> (--prompt <text> | --prompt-file <path>) [options] [-- <extra harness args>]
  transcript-tap replay --spool <path/to/<agent>.log>
  transcript-tap doctor

run options
  --agent <id>          one of: ${Object.keys(AGENT_RUNTIME).join(", ")}
  --prompt <text>       the prompt
  --prompt-file <path>  read the prompt from a file ("-" for stdin)
  --model <m>           overrides the channels.yaml default for the agent
  --run-id <id>         default: $TRANSCRIPT_RUN_ID or run-<epoch>
  --incident <id>       default: $TRANSCRIPT_INCIDENT_ID or "no-incident"
  --cwd <dir>           working directory for the harness
  --timeout <ms>        default: $TRANSCRIPT_TIMEOUT_MS or 900000
  --json                print the machine-readable result object

environment
  TRANSCRIPT_SINK             file (default) | cotal | both | none
  TRANSCRIPT_ECHO=1           also mirror chat lines to this process's stderr
  TRANSCRIPT_FLUSH_MS         streaming cadence, default 250
  TRANSCRIPT_CHUNK_BYTES      per-message payload cap, default 3500 (SPLITS, never truncates)
  TRANSCRIPT_MAX_CHAT_BYTES   0 = unlimited (default). The only setting that drops chat output.
  TRANSCRIPT_KEEP_ANSI=1      keep ANSI escapes in chat output
  TRANSCRIPT_REDACT_ENV=0     disable exact-match redaction of secret-looking env values
  TRANSCRIPT_ALLOW_UNSAFE_HARNESS_FLAGS=1  opt in to each harness's approval-bypass flag (OFF by default)
`;

function parseArgs(argv) {
  const out = { _: [], extra: [] };
  const i0 = argv.indexOf("--");
  const head = i0 === -1 ? argv : argv.slice(0, i0);
  if (i0 !== -1) out.extra = argv.slice(i0 + 1);
  for (let i = 0; i < head.length; i++) {
    const a = head[i];
    if (a.startsWith("--")) {
      const key = a.slice(2);
      const next = head[i + 1];
      if (next === undefined || next.startsWith("--")) out[key] = true;
      else {
        out[key] = next;
        i++;
      }
    } else out._.push(a);
  }
  return out;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const cmd = args._[0];

  if (!cmd || args.help || cmd === "help") {
    process.stdout.write(USAGE);
    return 0;
  }

  await loadChannelFn(); // resolve Cotal's transcriptChannel() if the SDK is here

  if (cmd === "doctor") return doctor();
  if (cmd === "replay") return replay(args);
  if (cmd === "run") return run(args);

  process.stderr.write(`unknown command "${cmd}"\n${USAGE}`);
  return 2;
}

async function run(args) {
  if (!args.agent) {
    process.stderr.write("--agent is required\n");
    return 2;
  }
  let prompt = args.prompt;
  if (args["prompt-file"]) {
    prompt =
      args["prompt-file"] === "-"
        ? fs.readFileSync(0, "utf8")
        : fs.readFileSync(args["prompt-file"], "utf8");
  }
  if (typeof prompt !== "string" || !prompt.length) {
    process.stderr.write("--prompt or --prompt-file is required\n");
    return 2;
  }

  const adapter = adapterForAgent(args.agent);
  const res = await runTap({
    agentId: args.agent,
    adapter,
    prompt,
    model: args.model || AGENT_MODEL[args.agent],
    runId: args["run-id"],
    incidentId: args.incident,
    cwd: args.cwd,
    timeoutMs: args.timeout ? Number(args.timeout) : undefined,
    extraArgs: args.extra,
  });

  if (args.json) process.stdout.write(JSON.stringify(res, null, 2) + "\n");
  else {
    process.stdout.write(
      `${res.agent_id} (${res.runtime}) exit=${res.exitCode} frames=${res.frames} ` +
        `captured=${res.captured_bytes}B redactions=${res.redactions} ` +
        `truncated=${res.truncated}\n  spool: ${res.spool.log}\n  sink:  ${res.sink}\n`,
    );
    if (res.stats?.sinkErrors?.length) {
      process.stdout.write(`  sink errors (${res.stats.sinkErrors.length}): ${res.stats.sinkErrors[0]}\n`);
    }
  }
  return res.ok ? 0 : 1;
}

/** Push an already-spooled transcript to the configured sink after the fact. */
async function replay(args) {
  const path_ = args.spool || args._[1];
  if (!path_) {
    process.stderr.write("--spool <path> is required\n");
    return 2;
  }
  const frames = readSpool(path_);
  if (!frames.length) {
    process.stderr.write(`no frames in ${path_}\n`);
    return 1;
  }
  const first = frames[0];
  const sink = await createSink({
    run_id: first.run_id,
    incident_id: first.incident_id,
    agent_id: first.agent_id,
    runtime: first.runtime,
    channel: adapterForAgent(first.agent_id).channel(first.agent_id),
  });
  for (const f of frames) sink.publish(f);
  const info = await sink.close(60_000);
  process.stdout.write(
    `replayed ${frames.length} frames from ${path_} -> ${sink.description} ` +
      `(published=${sink.stats.published} failed=${sink.stats.failed} undelivered=${info.undelivered})\n`,
  );
  return sink.stats.failed || info.undelivered ? 1 : 0;
}

async function doctor() {
  const { execFileSync } = await import("node:child_process");
  const lines = ["transcript-tap doctor", ""];
  for (const [agent, runtime] of Object.entries(AGENT_RUNTIME)) {
    const a = ADAPTERS[runtime];
    let where = "NOT FOUND on PATH";
    try {
      where = execFileSync("sh", ["-c", `command -v ${a.cli}`], { encoding: "utf8" }).trim();
    } catch {
      /* not installed */
    }
    lines.push(
      `  ${agent.padEnd(22)} runtime=${runtime.padEnd(12)} channel=${a.channel(agent)}`,
      `  ${" ".repeat(22)} cli=${a.cli} @ ${where}`,
      `  ${" ".repeat(22)} capture: ${a.capturePoint}`,
      "",
    );
  }
  lines.push(`  sink mode: ${process.env.TRANSCRIPT_SINK || "file (default)"}`);
  const { loadCotalSdk } = await import("./sinks/cotal.js");
  try {
    await loadCotalSdk();
    lines.push("  cotal SDK: found (@cotal-ai/connector-core)");
  } catch (err) {
    lines.push(`  cotal SDK: ${err.message} — the cotal sink will degrade to spool-only`);
  }
  process.stdout.write(lines.join("\n") + "\n");
  return 0;
}

main().then(
  (code) => process.exit(code ?? 0),
  (err) => {
    process.stderr.write(`transcript-tap: ${err?.stack || err}\n`);
    process.exit(1);
  },
);
