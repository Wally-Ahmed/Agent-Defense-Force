#!/usr/bin/env node
// mesh/report/bin/run-report.js — thin CLI over src/report.js.
//
// All logic lives in src/report.js; this file only parses argv, enforces the
// preconditions the driver depends on, and prints. It exits 2 (not 1) on a usage
// or precondition failure so a driver can tell "you called me wrong / the run
// isn't there" apart from an unexpected crash.

import process from "node:process";

import { generateReport, resolveRunRoot, runExists, FORMATS } from "../src/report.js";

const USAGE = `usage: run-report.js --run-id <id> [--format md|json|both]

  --run-id <id>   REQUIRED. Names runs/<id>/, which must already exist.
  --format        md (default) writes report.md; json writes report.json;
                  both writes each.

The rendered markdown is always printed to stdout so the run driver's log
captures it, whatever --format wrote to disk.`;

function fail(message) {
  process.stderr.write(`run-report: ${message}\n\n${USAGE}\n`);
  process.exit(2);
}

function parseArgs(argv) {
  const opts = { runId: null, format: "md" };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const eq = arg.indexOf("=");
    const [flag, inlineValue] = eq > 0 ? [arg.slice(0, eq), arg.slice(eq + 1)] : [arg, null];
    const take = () => {
      if (inlineValue !== null) return inlineValue;
      i += 1;
      return argv[i];
    };
    switch (flag) {
      case "--run-id":
        opts.runId = take();
        break;
      case "--format":
        opts.format = take();
        break;
      case "-h":
      case "--help":
        process.stdout.write(`${USAGE}\n`);
        process.exit(0);
        break;
      default:
        fail(`unknown argument "${arg}"`);
    }
  }
  return opts;
}

const opts = parseArgs(process.argv.slice(2));

if (!opts.runId) fail("--run-id is required");
if (!opts.format) fail("--format needs a value");
if (!FORMATS.includes(opts.format)) {
  fail(`--format "${opts.format}" is not one of ${FORMATS.join(", ")}`);
}

const runRoot = resolveRunRoot(opts.runId);
// Checked before anything else touches the path: paths.js's runDir() mkdirs on
// demand, so without this guard a typo'd run id would create an empty run
// directory and then be reported on as a totally missing run.
if (!runExists(runRoot)) {
  fail(`run directory does not exist: ${runRoot}`);
}

let result;
try {
  result = generateReport({ runId: opts.runId, format: opts.format });
} catch (err) {
  // buildReport/renderMarkdown degrade rather than throw, so anything reaching
  // here is a real fault (unwritable run dir, bad format) and must be loud.
  process.stderr.write(`run-report: failed to generate report — ${err && err.message}\n`);
  process.exit(1);
}

process.stdout.write(`${result.markdown}\n`);
for (const p of result.written) process.stderr.write(`run-report: wrote ${p}\n`);
process.exit(0);
