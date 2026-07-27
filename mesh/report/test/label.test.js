// Tests for computeLabel() — the run label is the report's load-bearing claim,
// so each of the five ways a run can fail to be LIVE gets its own test.

import test from "node:test";
import assert from "node:assert/strict";

import { AGENT_IDS } from "../../lib/agents.js";
import { computeLabel } from "../src/report.js";

/** A clean effort_receipt.v1 — every flag explicitly false, as the contract requires. */
function receipt(agent, over = {}) {
  return {
    agent,
    runtime: "hermes",
    runtime_version: "0.16.0",
    model_requested: "z-ai/glm-5.2",
    model_effective: "z-ai/glm-5.2",
    effort_requested: "xhigh",
    effort_effective: "xhigh",
    source: "stdout of `hermes --version` (Hermes Agent v0.16.0)",
    downgraded: false,
    blocked: false,
    mocked: false,
    ...over,
  };
}

function cleanReceipts() {
  return AGENT_IDS.map((id) => receipt(id));
}

test("1. six clean receipts label the run LIVE", () => {
  const r = computeLabel(cleanReceipts());
  assert.equal(r.label, "LIVE");
  assert.deepEqual(r.blocked, []);
  assert.deepEqual(r.mocked, []);
  assert.deepEqual(r.downgraded, []);
  assert.deepEqual(r.missing, []);
  assert.match(r.reasons.join("; "), /LIVE: 6 of 6 receipts/);
});

test("2. one mocked:true receipt labels the run MOCKED and names the agent", () => {
  const receipts = cleanReceipts().map((r) =>
    r.agent === "responder_kimi" ? { ...r, mocked: true } : r,
  );
  const label = computeLabel(receipts);
  assert.equal(label.label, "MOCKED");
  assert.deepEqual(label.mocked, ["responder_kimi"]);
  assert.deepEqual(label.blocked, []);
  assert.match(label.reasons.join("; "), /MOCKED_FLAG: responder_kimi/);
});

test("3. one blocked:true receipt labels the run MOCKED and names the agent", () => {
  const receipts = cleanReceipts().map((r) =>
    r.agent === "monitor" ? { ...r, blocked: true } : r,
  );
  const label = computeLabel(receipts);
  assert.equal(label.label, "MOCKED");
  assert.deepEqual(label.blocked, ["monitor"]);
  assert.deepEqual(label.mocked, []);
  assert.match(label.reasons.join("; "), /BLOCKED: monitor/);
});

test("4. one downgraded:true receipt labels MOCKED with an explicit DOWNGRADED reason", () => {
  const receipts = cleanReceipts().map((r) =>
    r.agent === "responder_glm" ? { ...r, downgraded: true } : r,
  );
  const label = computeLabel(receipts);
  assert.equal(label.label, "MOCKED");
  assert.deepEqual(label.downgraded, ["responder_glm"]);
  // A downgraded effort must never read as live, and the reason must say so by
  // name rather than hiding inside a generic count.
  assert.ok(
    label.reasons.some((x) => x.startsWith("DOWNGRADED: ")),
    `expected a DOWNGRADED reason, got ${JSON.stringify(label.reasons)}`,
  );
  assert.match(label.reasons.join("; "), /DOWNGRADED: responder_glm/);
});

test("5. only five receipts labels MOCKED and names the missing agent", () => {
  const receipts = cleanReceipts().filter((r) => r.agent !== "responder_codex");
  assert.equal(receipts.length, 5);
  const label = computeLabel(receipts);
  assert.equal(label.label, "MOCKED");
  assert.deepEqual(label.missing, ["responder_codex"]);
  assert.match(label.reasons.join("; "), /RECEIPT_COUNT: 5 of 6 expected receipts/);
  assert.match(label.reasons.join("; "), /MISSING_RECEIPT: responder_codex/);
});
