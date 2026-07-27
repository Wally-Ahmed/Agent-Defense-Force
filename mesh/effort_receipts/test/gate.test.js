// Tests for src/gate.js — the fast pre-check that mirrors coordinator/effort_gate.jac.
// The reason-code PRECEDENCE is the thing under test: a mesh that reports the wrong
// code sends an operator chasing the wrong failure.

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

import { RUNS_DIR } from "../../lib/paths.js";
import { AGENT_IDS } from "../../lib/agents.js";
import { parseReceiptLines } from "../src/receipt.js";
import {
  CANONICAL_AGENTS,
  RECEIPTS_FILE_MISSING,
  RECEIPTS_MISSING,
  RECEIPT_DOWNGRADED,
  RECEIPT_DUPLICATE,
  RECEIPT_INVALID,
  REQUIRED_RECEIPTS,
  checkGate,
  evaluateReceipts,
} from "../src/gate.js";

let counter = 0;

/** Lay down a literal effort.jsonl for a throwaway run, then delete the directory. */
function withLedger(text, fn) {
  counter += 1;
  const runId = `test-gate-${process.pid}-${Date.now().toString(36)}-${counter}`;
  const dir = path.join(RUNS_DIR, runId);
  try {
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, "effort.jsonl"), text, "utf8");
    return fn(runId);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

function rcpt(agent, over = {}) {
  return {
    agent,
    runtime: "opencode",
    runtime_version: "1.0.0",
    model_requested: "z-ai/glm-5.2",
    model_effective: "z-ai/glm-5.2",
    effort_requested: "max",
    effort_effective: "max",
    source: "test fixture",
    downgraded: false,
    blocked: false,
    mocked: false,
    ...over,
  };
}

function six(overridesByAgent = {}) {
  return CANONICAL_AGENTS.map((a) => rcpt(a, overridesByAgent[a] || {}));
}

function jsonl(objects) {
  return `${objects.map((o) => (typeof o === "string" ? o : JSON.stringify(o))).join("\n")}\n`;
}

function evaluate(objects) {
  return evaluateReceipts(parseReceiptLines(jsonl(objects)));
}

test("the six canonical agents are monitor plus the five responders", () => {
  assert.deepEqual(CANONICAL_AGENTS, [...AGENT_IDS]);
  assert.equal(REQUIRED_RECEIPTS, 6);
  assert.equal(CANONICAL_AGENTS.length, 6);
  assert.equal(CANONICAL_AGENTS[0], "monitor");
});

test("all six clean receipts open the gate with an empty reason", () => {
  withLedger(jsonl(six()), (runId) => {
    const result = checkGate(runId);
    assert.equal(result.open, true);
    assert.equal(result.reason, "");
    assert.equal(result.run_label, "LIVE");
    assert.equal(result.receipts.length, 6);
    assert.deepEqual(result.missing, []);
    assert.deepEqual(result.invalid, []);
    assert.deepEqual(result.duplicates, []);
    assert.deepEqual(result.agents_seen, [...CANONICAL_AGENTS].sort());
    assert.equal(result.receipts_seen, 6);
  });
});

test("a missing ledger file reports RECEIPTS_FILE_MISSING with all six missing", () => {
  const runId = `test-gate-absent-${process.pid}-${Date.now().toString(36)}`;
  const result = checkGate(runId);
  assert.equal(result.open, false);
  assert.equal(result.reason, RECEIPTS_FILE_MISSING);
  assert.deepEqual(result.missing, [...CANONICAL_AGENTS].sort());
  assert.deepEqual(result.receipts, []);
  assert.deepEqual(result.invalid, []);
  assert.deepEqual(result.duplicates, []);
  assert.equal(result.run_label, "LIVE", "run_label is computed even on the failure path");
  assert.equal(result.receipts_seen, 0);
  assert.equal(
    fs.existsSync(path.join(RUNS_DIR, runId)),
    false,
    "a gate check must not create the run directory it was asked about",
  );
});

test("a short ledger reports RECEIPTS_MISSING and names who is absent", () => {
  const four = six().slice(0, 4);
  withLedger(jsonl(four), (runId) => {
    const result = checkGate(runId);
    assert.equal(result.open, false);
    assert.equal(result.reason, RECEIPTS_MISSING);
    assert.equal(result.receipts_seen, 4);
    assert.deepEqual(result.missing, CANONICAL_AGENTS.slice(4).sort());
  });
});

test("invalid AND short reports RECEIPT_INVALID, not RECEIPTS_MISSING", () => {
  const lines = [
    JSON.stringify(rcpt("monitor")),
    "{ this is not json",
    JSON.stringify(rcpt("responder_claude", { downgraded: "false" })),
  ];
  withLedger(`${lines.join("\n")}\n`, (runId) => {
    const result = checkGate(runId);
    assert.equal(result.open, false);
    assert.equal(
      result.reason,
      RECEIPT_INVALID,
      "unreadable lines outrank a short count: we cannot know what they contained",
    );
    assert.equal(result.invalid.length, 2);
    assert.equal(result.invalid[0], "line 2: not parseable JSON (SyntaxError)");
    assert.match(result.invalid[1], /^line 3: agent=responder_claude: effort_receipt\.v1: /);
    assert.ok(result.missing.length > 0, "the ledger really is short as well");
  });
});

test("a non-object JSON line is reported, never dropped", () => {
  const result = evaluate([...six(), "[1,2,3]", "42", "null"]);
  assert.equal(result.reason, RECEIPT_INVALID);
  assert.deepEqual(result.invalid, [
    "line 7: not a JSON object",
    "line 8: not a JSON object",
    "line 9: not a JSON object",
  ]);
});

test("an invalid receipt with a non-string agent reports agent=?", () => {
  const result = evaluate([{ agent: 7, runtime: "opencode" }]);
  assert.equal(result.reason, RECEIPT_INVALID);
  assert.match(result.invalid[0], /^line 1: agent=\?: effort_receipt\.v1: /);
});

test("duplicate plus missing reports RECEIPT_DUPLICATE, not RECEIPTS_MISSING", () => {
  const lines = [rcpt("monitor"), rcpt("monitor"), rcpt("responder_claude")];
  withLedger(jsonl(lines), (runId) => {
    const result = checkGate(runId);
    assert.equal(result.open, false);
    assert.equal(result.reason, RECEIPT_DUPLICATE);
    assert.deepEqual(result.duplicates, ["monitor"]);
    assert.ok(result.missing.includes("responder_glm"));
  });
});

test("a complete but downgraded ledger reports RECEIPT_DOWNGRADED", () => {
  const lines = six({ responder_codex: { downgraded: true, effort_effective: "medium" } });
  withLedger(jsonl(lines), (runId) => {
    const result = checkGate(runId);
    assert.equal(result.open, false);
    assert.equal(result.reason, RECEIPT_DOWNGRADED);
    assert.deepEqual(result.downgraded, ["responder_codex"]);
    assert.deepEqual(result.missing, []);
    assert.deepEqual(result.invalid, []);
    assert.equal(result.run_label, "LIVE", "a downgrade is not a mock");
  });
});

test("precedence chain: strictest reason wins at every step", () => {
  // invalid > duplicate
  assert.equal(evaluate([...six(), rcpt("monitor"), "{bad"]).reason, RECEIPT_INVALID);
  // duplicate > missing
  assert.equal(evaluate([rcpt("monitor"), rcpt("monitor")]).reason, RECEIPT_DUPLICATE);
  // missing > downgraded
  assert.equal(evaluate([rcpt("monitor", { downgraded: true })]).reason, RECEIPTS_MISSING);
  // downgraded > open
  assert.equal(evaluate(six({ monitor: { downgraded: true } })).reason, RECEIPT_DOWNGRADED);
  // nothing wrong at all
  assert.equal(evaluate(six()).reason, "");
});

test("run_label flips to MOCKED when any receipt is blocked or mocked", () => {
  const mockedOne = evaluate(six({ responder_glm: { mocked: true } }));
  assert.equal(mockedOne.run_label, "MOCKED");
  assert.equal(mockedOne.open, true, "a mocked-but-complete mesh still passes the gate");
  assert.deepEqual(mockedOne.mocked, ["responder_glm"]);

  const blockedOne = evaluate(six({ responder_kimi: { blocked: true, mocked: true } }));
  assert.equal(blockedOne.run_label, "MOCKED");
  assert.deepEqual(blockedOne.blocked, ["responder_kimi"]);
});

test("run_label is still computed when the gate REFUSES", () => {
  // Short AND mocked: the run is not an acceptance run, and it must be labeled as
  // such even though the gate is closed.
  const short = evaluate([rcpt("monitor", { blocked: true, mocked: true })]);
  assert.equal(short.open, false);
  assert.equal(short.reason, RECEIPTS_MISSING);
  assert.equal(short.run_label, "MOCKED");

  // Downgraded AND mocked.
  const downgraded = evaluate(six({ responder_codex: { downgraded: true, mocked: true } }));
  assert.equal(downgraded.reason, RECEIPT_DOWNGRADED);
  assert.equal(downgraded.run_label, "MOCKED");

  // A blocked agent that is ALSO unexpected still forces the label — a run cannot
  // shed MOCKED by using an unrecognised agent id.
  const unexpectedBlocked = evaluate([...six(), rcpt("responder_ghost", { blocked: true, mocked: true })]);
  assert.equal(unexpectedBlocked.run_label, "MOCKED");
  assert.deepEqual(unexpectedBlocked.unexpected, ["responder_ghost"]);
});

test("invalid lines do not contribute to run_label", () => {
  // The only "mocked" marker sits on a line that fails the schema, so it proves
  // nothing and the label stays LIVE while the gate reports RECEIPT_INVALID.
  const result = evaluate([...six(), { agent: "responder_ghost", mocked: true }]);
  assert.equal(result.reason, RECEIPT_INVALID);
  assert.equal(result.run_label, "LIVE");
  assert.deepEqual(result.mocked, []);
});

test("blank lines are skipped and never counted as invalid", () => {
  const body = six().map((r) => JSON.stringify(r));
  const text = ["", body[0], "   ", body[1], "", body[2], body[3], "\t", body[4], "", body[5], "", ""].join("\n");
  withLedger(text, (runId) => {
    const result = checkGate(runId);
    assert.deepEqual(result.invalid, [], "whitespace-only lines are not receipts at all");
    assert.equal(result.open, true);
    assert.equal(result.reason, "");
    assert.equal(result.receipts_seen, 6);
  });
});

test("an unexpected agent lands in `unexpected` and does not satisfy the six", () => {
  const lines = [...six().slice(0, 5), rcpt("responder_ghost")];
  withLedger(jsonl(lines), (runId) => {
    const result = checkGate(runId);
    assert.equal(result.open, false);
    assert.equal(result.reason, RECEIPTS_MISSING);
    assert.deepEqual(result.unexpected, ["responder_ghost"]);
    assert.equal(result.receipts_seen, 5, "a non-canonical agent does not count toward the six");
    assert.deepEqual(result.missing, [CANONICAL_AGENTS[5]]);
    assert.equal(result.agents_seen.includes("responder_ghost"), false);
    assert.equal(result.receipts.length, 6, "it was still a schema-valid receipt that we saw");
  });
});

test("list fields come back sorted so output is byte-stable", () => {
  const shuffled = [...six()].reverse();
  const a = evaluate(shuffled);
  const b = evaluate(six());
  assert.deepEqual(a.agents_seen, b.agents_seen);
  assert.deepEqual(a.agents_seen, [...a.agents_seen].sort());

  const missing = evaluate([rcpt("responder_kimi"), rcpt("monitor")]);
  assert.deepEqual(missing.missing, [...missing.missing].sort());
});
