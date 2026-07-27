#!/usr/bin/env node
// agent-runner — run ONE responder against ONE incident.
//
// Deliberately single-agent: five responders judging independently means five
// separate processes, so nothing in one responder's address space can observe
// another's. Fan-out is the caller's job (mesh/run_live.sh), not this file's.

import fs from "node:fs";
import path from "node:path";
import { RESPONDER_IDS } from "../../lib/agents.js";
import { loadRepoEnv } from "../../lib/env.js";
import { newRunId, readJson } from "../../lib/paths.js";
import { runResponder } from "../src/run.js";

// Load the repo-root .env BEFORE anything reads a credential or spawns a harness.
// It belongs here, in the entry point, rather than in src/: a library import must
// not mutate the caller's environment behind its back, and the unit tests set
// process.env themselves. Everything the child harnesses need arrives through the
// tap's childEnv(), which copies process.env — and putting the value in
// process.env is also what keeps the tap's secret redaction covering it.
// Names only are ever visible; loadRepoEnv() never returns or prints a value.
loadRepoEnv();

const USAGE = `agent-runner — one responder, one incident, one assessment.v1

  agent-runner --agent <id> --incident <path> [options]

Required:
  --agent <id>          one of: ${RESPONDER_IDS.join(", ")}
  --incident <path>     path to an incident.v1 JSON file

Options:
  --run-id <id>         run identifier (default: a fresh one)
  --mock                use the recorded transcript instead of the live CLI
  --timeout-ms <n>      harness timeout (default: the tap's own, 900000)
  --cwd <path>          working directory for the harness
  --transport <mode>    auto | file | cotal   (default: auto)
  --force               attempt the live call even if preflight says blocked
  --json                print the full result as JSON
  -h, --help            this text

Exit codes: 0 on a valid, delivered assessment; 1 otherwise.`;

function parseArgs(argv) {
  const out = { transport: "auto" };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const need = (name) => {
      const v = argv[++i];
      if (v === undefined) throw new Error(`${name} requires a value`);
      return v;
    };
    switch (a) {
      case "--agent":
        out.agent = need(a);
        break;
      case "--incident":
        out.incident = need(a);
        break;
      case "--run-id":
        out.runId = need(a);
        break;
      case "--timeout-ms":
        out.timeoutMs = Number(need(a));
        break;
      case "--cwd":
        out.cwd = path.resolve(need(a));
        break;
      case "--transport":
        out.transport = need(a);
        break;
      case "--mock":
        out.mock = true;
        break;
      case "--force":
        out.force = true;
        break;
      case "--json":
        out.json = true;
        break;
      case "-h":
      case "--help":
        out.help = true;
        break;
      default:
        throw new Error(`unknown argument "${a}"`);
    }
  }
  return out;
}

async function main() {
  let args;
  try {
    args = parseArgs(process.argv.slice(2));
  } catch (err) {
    process.stderr.write(`agent-runner: ${err.message}\n\n${USAGE}\n`);
    process.exit(2);
  }

  if (args.help || process.argv.length <= 2) {
    process.stdout.write(`${USAGE}\n`);
    process.exit(args.help ? 0 : 2);
  }
  if (!args.agent || !args.incident) {
    process.stderr.write(`agent-runner: --agent and --incident are both required\n\n${USAGE}\n`);
    process.exit(2);
  }
  if (!RESPONDER_IDS.includes(args.agent)) {
    process.stderr.write(
      `agent-runner: "${args.agent}" is not a responder (expected: ${RESPONDER_IDS.join(", ")})\n`,
    );
    process.exit(2);
  }
  const incidentPath = path.resolve(args.incident);
  if (!fs.existsSync(incidentPath)) {
    process.stderr.write(`agent-runner: no such incident file: ${incidentPath}\n`);
    process.exit(2);
  }

  let incident;
  try {
    incident = readJson(incidentPath);
  } catch (err) {
    process.stderr.write(`agent-runner: could not read incident: ${err.message}\n`);
    process.exit(2);
  }

  const runId = args.runId || newRunId();
  let result;
  try {
    result = await runResponder({
      agentId: args.agent,
      incident,
      runId,
      mock: args.mock,
      timeoutMs: Number.isFinite(args.timeoutMs) ? args.timeoutMs : undefined,
      cwd: args.cwd,
      transport: args.transport,
      force: args.force,
    });
  } catch (err) {
    process.stderr.write(`agent-runner: ${err.message}\n`);
    process.exit(1);
  }

  if (args.json) {
    // The result carries only ids, paths, counts and the assessment itself —
    // never an environment value, so there is nothing here to redact.
    process.stdout.write(JSON.stringify(result, null, 2) + "\n");
  }

  const tags = [
    result.mocked ? "MOCKED" : "live",
    result.blocked ? "BLOCKED" : null,
    result.usageReported ? null : "usage:not-reported",
    result.priced ? null : "cost:unpriced",
  ].filter(Boolean);

  if (result.ok) {
    const a = result.assessment;
    process.stdout.write(
      `${result.assessmentPath}\n` +
        `${result.agentId} ${a.verdict} conf=${a.confidence} ` +
        `stages=[${a.campaign_stages.join(",")}] actions=${a.recommended_actions.length} ` +
        `model=${a.model} effort=${a.effort_effective} ` +
        `tokens=${a.usage.in}/${a.usage.out}/${a.usage.reasoning} usd=${a.usage.usd} ` +
        `dm=${result.dm.transport} [${tags.join(" ")}]\n`,
    );
    for (const e of result.errors) process.stderr.write(`  note: ${e}\n`);
    process.exit(0);
  }

  process.stderr.write(
    `${result.agentId} FAILED [${tags.join(" ")}] — no assessment emitted\n`,
  );
  for (const e of result.errors) process.stderr.write(`  - ${e}\n`);
  process.exit(1);
}

main().catch((err) => {
  process.stderr.write(`agent-runner: unexpected failure: ${err?.stack || err}\n`);
  process.exit(1);
});
