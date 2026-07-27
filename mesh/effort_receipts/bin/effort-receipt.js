#!/usr/bin/env node
// mesh/effort_receipts/bin/effort-receipt.js — write and check effort receipts.
//
// The producer side of the WATCHING gate. `write-all` probes every runtime for real and
// appends one effort_receipt.v1 per agent to runs/<run_id>/effort.jsonl; `check` runs the
// fast JS mirror of coordinator/effort_gate.jac so bring-up fails in milliseconds, with
// the same reason code the Jac gate would produce, instead of after the whole mesh is up.
//
// CREDENTIAL RULE, enforced by construction: nothing in this file reads a secret. The
// only credential-adjacent output anywhere in the tree is a PRESENCE BOOLEAN produced by
// probe.js's keyPresent(). No key value is printed, stored, or written to a receipt.
//
// loadRepoEnv() below moves .env into process.env so the probes can actually LAUNCH the
// OpenRouter-backed runtimes (hermes, opencode x2) instead of reporting them blocked for
// want of a key that was on disk the whole time. It returns variable NAMES, never values.

import process from "node:process";
import { AGENT_IDS } from "../../lib/agents.js";
import { loadRepoEnv } from "../../lib/env.js";
import { effortLedger } from "../../lib/paths.js";
import { probeForAgent, probeAgents } from "../src/probe.js";
import { buildReceipt, writeReceipt } from "../src/receipt.js";
import { checkGate } from "../src/gate.js";

const USAGE = `effort-receipt — produce and verify effort_receipt.v1 records

  write     --agent <id> --run-id <id> [--mocked] [--blocked]
  write-all --run-id <id> [--mocked]
  check     --run-id <id>

Agents: ${AGENT_IDS.join(", ")}

  write      probe one runtime and append its receipt
  write-all  probe all six CONCURRENTLY and append every receipt
  check      run the effort gate; exits non-zero when the gate is shut
`;

/** Minimal flag parser. No dependency is worth pulling in for three flags. */
function parseArgs(argv) {
  const out = { _: [], flags: {} };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    if (!a.startsWith("--")) { out._.push(a); continue; }
    const key = a.slice(2);
    const next = argv[i + 1];
    if (next === undefined || next.startsWith("--")) {
      out.flags[key] = true;
    } else {
      out.flags[key] = next;
      i += 1;
    }
  }
  return out;
}

function die(msg, code = 2) {
  process.stderr.write(`${msg}\n`);
  process.exit(code);
}

/** One line per receipt, showing what the runtime actually gave back. */
function printReceipt(r, wrote) {
  const flags = [
    r.downgraded ? "DOWNGRADED" : "ok",
    r.blocked ? "blocked" : "live",
    r.mocked ? "mocked" : "real",
  ].join("/");
  const note = wrote.written ? "written" : `skipped (${wrote.reason})`;
  process.stdout.write(
    `${r.agent.padEnd(22)} ${r.runtime.padEnd(12)} ${String(r.runtime_version).padEnd(24)} ` +
    `${r.model_effective.padEnd(30)} ${r.effort_effective.padEnd(16)} ${flags.padEnd(26)} ${note}\n`,
  );
  process.stdout.write(`  source: ${r.source}\n`);
}

async function cmdWrite(flags) {
  const agentId = flags.agent;
  const runId = flags["run-id"];
  if (typeof agentId !== "string") die("write requires --agent <id>");
  if (typeof runId !== "string") die("write requires --run-id <id>");
  if (!AGENT_IDS.includes(agentId)) die(`unknown agent "${agentId}"; expected one of ${AGENT_IDS.join(", ")}`);

  const probe = await probeForAgent(agentId);
  const receipt = buildReceipt({
    agentId,
    probe,
    mocked: flags.mocked === true || flags.mocked === "true",
    blocked: flags.blocked === true || flags.blocked === "true",
  });
  const wrote = writeReceipt(runId, receipt);
  printReceipt(receipt, wrote);
  process.stdout.write(`\nledger: ${effortLedger(runId)}\n`);
  return 0;
}

async function cmdWriteAll(flags) {
  const runId = flags["run-id"];
  if (typeof runId !== "string") die("write-all requires --run-id <id>");

  // Six independent runtimes, no shared state -- probe them all at once rather than
  // paying every network round trip in series.
  process.stdout.write(`probing ${AGENT_IDS.length} runtimes concurrently...\n\n`);
  const probes = await probeAgents(AGENT_IDS);

  const forcedMock = flags.mocked === true || flags.mocked === "true";
  for (const agentId of AGENT_IDS) {
    const receipt = buildReceipt({ agentId, probe: probes[agentId], mocked: forcedMock });
    const wrote = writeReceipt(runId, receipt);
    printReceipt(receipt, wrote);
  }

  process.stdout.write(`\nledger: ${effortLedger(runId)}\n\n`);
  return cmdCheck(flags);
}

function cmdCheck(flags) {
  const runId = flags["run-id"];
  if (typeof runId !== "string") die("check requires --run-id <id>");

  const g = checkGate(runId);
  process.stdout.write("EFFORT GATE\n");
  process.stdout.write(`  open       : ${g.open}\n`);
  process.stdout.write(`  reason     : ${g.reason || "(none - gate open)"}\n`);
  process.stdout.write(`  run_label  : ${g.run_label}\n`);
  process.stdout.write(`  receipts   : ${g.receipts.length}/${AGENT_IDS.length}\n`);
  if (g.missing.length) process.stdout.write(`  missing    : ${g.missing.join(", ")}\n`);
  if (g.duplicates.length) process.stdout.write(`  duplicates : ${g.duplicates.join(", ")}\n`);
  if (g.invalid.length) process.stdout.write(`  invalid    : ${g.invalid.join(" | ")}\n`);
  if (g.detail) process.stdout.write(`  detail     : ${g.detail}\n`);

  if (g.receipts.length) {
    process.stdout.write("\n  agent                  runtime      version                  model_effective                effort      D/B/M\n");
    for (const r of g.receipts) {
      process.stdout.write(
        `  ${r.agent.padEnd(22)} ${r.runtime.padEnd(12)} ${String(r.runtime_version).slice(0, 24).padEnd(24)} ` +
        `${r.model_effective.padEnd(30)} ${r.effort_effective.padEnd(11)} ` +
        `${r.downgraded ? "D" : "-"}${r.blocked ? "B" : "-"}${r.mocked ? "M" : "-"}\n`,
      );
    }
  }

  // The Jac gate is authoritative; this exit code just lets a shell script stop early.
  process.stdout.write(`\n${g.open ? "GATE OPEN" : "GATE SHUT"} (${g.reason || "ok"}) - run is ${g.run_label}\n`);
  return g.open ? 0 : 1;
}

async function main() {
  loadRepoEnv();
  const argv = process.argv.slice(2);
  if (!argv.length || argv[0] === "--help" || argv[0] === "-h" || argv[0] === "help") {
    process.stdout.write(USAGE);
    return 0;
  }
  const cmd = argv[0];
  const { flags } = parseArgs(argv.slice(1));

  if (cmd === "write") return cmdWrite(flags);
  if (cmd === "write-all") return cmdWriteAll(flags);
  if (cmd === "check") return cmdCheck(flags);

  process.stderr.write(`unknown command "${cmd}"\n\n${USAGE}`);
  return 2;
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    // A crash must not look like a passing gate.
    process.stderr.write(`effort-receipt failed: ${err && err.stack ? err.stack : err}\n`);
    process.exit(2);
  });
