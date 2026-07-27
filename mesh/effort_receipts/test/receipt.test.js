// Tests for src/receipt.js — the effort scale, the hand-rolled schema validator,
// downgrade detection (including the effort-ceiling exception) and the
// validate-then-atomically-append writer.

import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

import { RUNS_DIR } from "../../lib/paths.js";
import { AGENT_IDS, agentTable } from "../../lib/agents.js";
import {
  EFFORT_SCALE,
  buildReceipt,
  effortRank,
  isDowngraded,
  ledgerPathFor,
  loadEffortSchema,
  parseReceiptLines,
  readReceipts,
  validateAgainstSchema,
  validateReceipt,
  writeReceipt,
} from "../src/receipt.js";

let counter = 0;

/** Run `fn` against a throwaway run id under runs/, then delete the directory. */
function withRun(fn) {
  counter += 1;
  const runId = `test-${process.pid}-${Date.now().toString(36)}-${counter}`;
  const dir = path.join(RUNS_DIR, runId);
  try {
    return fn(runId, dir);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

/** A schema-valid baseline receipt; override any field to make it interesting. */
function fixture(over = {}) {
  return {
    agent: "responder_glm",
    runtime: "opencode",
    runtime_version: "0.1.0",
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

test("EFFORT_SCALE is ordered weakest to strongest and ranks unknown values as -1", () => {
  assert.deepEqual(EFFORT_SCALE, ["none", "minimal", "low", "medium", "high", "xhigh", "max"]);
  assert.ok(effortRank("none") < effortRank("low"));
  assert.ok(effortRank("low") < effortRank("medium"));
  assert.ok(effortRank("medium") < effortRank("high"));
  assert.ok(effortRank("high") < effortRank("xhigh"));
  assert.ok(effortRank("xhigh") < effortRank("max"));
  assert.equal(effortRank("ludicrous"), -1);
  assert.equal(effortRank(undefined), -1);
});

test("downgrade detection walks the effort scale", () => {
  const same = { modelRequested: "m", modelEffective: "m" };

  assert.equal(
    isDowngraded({ ...same, effortRequested: "max", effortEffective: "high" }),
    true,
    "max requested but high in force is a downgrade",
  );
  assert.equal(
    isDowngraded({ ...same, effortRequested: "high", effortEffective: "max" }),
    false,
    "stronger than requested is not a downgrade",
  );
  assert.equal(
    isDowngraded({ ...same, effortRequested: "max", effortEffective: "max" }),
    false,
    "equal effort is not a downgrade",
  );
  assert.equal(
    isDowngraded({ ...same, effortRequested: "xhigh", effortEffective: "minimal" }),
    true,
  );
});

test("an unrecognised effective effort fails closed", () => {
  assert.equal(
    isDowngraded({
      modelRequested: "m",
      modelEffective: "m",
      effortRequested: "max",
      effortEffective: "turbo",
    }),
    true,
    "an off-scale readback cannot be proven strong enough, so it counts as a downgrade",
  );
});

test("effort_ceiling exception: an agent at its documented maximum is not downgraded", () => {
  // responder_antigravity: `agy --effort` only accepts (low|medium|high), so "high"
  // IS agy's maximum and reading it back is the strongest thing that runtime can say.
  const agy = agentTable().responder_antigravity;
  assert.equal(agy.effort, "high");
  assert.equal(agy.effort_ceiling, "high");

  assert.equal(
    isDowngraded({
      modelRequested: agy.model_openrouter,
      modelEffective: agy.model_openrouter,
      effortRequested: agy.effort,
      effortEffective: agy.effort,
      effortCeiling: agy.effort_ceiling,
    }),
    false,
  );

  // The same values WITHOUT a declared ceiling, asked for above the ceiling, are a
  // downgrade — proving the exception is doing the work and not the scale.
  assert.equal(
    isDowngraded({
      modelRequested: "m",
      modelEffective: "m",
      effortRequested: "max",
      effortEffective: "high",
      effortCeiling: null,
    }),
    true,
  );
});

test("effort_ceiling does NOT rescue a model substitution", () => {
  assert.equal(
    isDowngraded({
      modelRequested: "google/gemini-3.6-flash-high",
      modelEffective: "google/gemini-3.6-flash-low",
      effortRequested: "high",
      effortEffective: "high",
      effortCeiling: "high",
    }),
    true,
    "a substituted model is downgraded regardless of sitting at the effort ceiling",
  );
});

test("model substitution is a downgrade even when effort matches exactly", () => {
  assert.equal(
    isDowngraded({
      modelRequested: "anthropic/claude-opus-5",
      modelEffective: "anthropic/claude-sonnet-5",
      effortRequested: "max",
      effortEffective: "max",
    }),
    true,
  );
});

test("the schema validator enforces the frozen contract", () => {
  const schema = loadEffortSchema();
  assert.deepEqual(validateReceipt(fixture()), []);

  const missingKey = fixture();
  delete missingKey.source;
  const missingErrors = validateReceipt(missingKey);
  assert.equal(missingErrors.length, 1);
  assert.match(missingErrors[0], /'source' is a required property/);

  const wrongType = validateReceipt(fixture({ downgraded: "false" }));
  assert.equal(wrongType.length, 1);
  assert.match(wrongType[0], /downgraded.*is not of type 'boolean'/);

  const extraProp = validateReceipt(fixture({ evidence: { stdout: "..." } }));
  assert.equal(extraProp.length, 1);
  assert.match(extraProp[0], /'evidence' was unexpected \(additionalProperties is false\)/);

  const emptyString = validateReceipt(fixture({ source: "" }));
  assert.equal(emptyString.length, 1);
  assert.match(emptyString[0], /minLength 1/);

  // Non-objects are rejected outright, and null must not slip through as "object".
  assert.equal(validateAgainstSchema(schema, null).length, 1);
  assert.equal(validateAgainstSchema(schema, []).length, 1);
  assert.equal(validateAgainstSchema(schema, "receipt").length, 1);
});

test("the validator supports enum even though the frozen schema has none today", () => {
  const schema = { type: "object", properties: { level: { type: "string", enum: ["a", "b"] } } };
  assert.deepEqual(validateAgainstSchema(schema, { level: "a" }), []);
  assert.equal(validateAgainstSchema(schema, { level: "z" }).length, 1);
  assert.equal(loadEffortSchema(), loadEffortSchema(), "schema is cached, not re-read");
});

test("writeReceipt throws on a malformed receipt and writes nothing", () => {
  const bad = fixture({ downgraded: "false", extra_key: 1 });
  delete bad.runtime_version;

  withRun((runId) => {
    assert.throws(() => writeReceipt(runId, bad), /effort_receipt\.v1:/);
    assert.equal(
      fs.existsSync(ledgerPathFor(runId)),
      false,
      "a line the Jac gate would reject must never reach the ledger",
    );
    assert.deepEqual(readReceipts(runId), []);
  });

  withRun((runId) => {
    assert.throws(() => writeReceipt(runId, fixture({ agent: "" })), /minLength 1/);
    assert.equal(fs.existsSync(ledgerPathFor(runId)), false);
  });
});

test("writeReceipt appends exactly one line and is idempotent per agent", () => {
  withRun((runId) => {
    const receipt = fixture();

    const first = writeReceipt(runId, receipt);
    assert.equal(first.written, true);
    assert.equal(first.reason, "appended");

    const second = writeReceipt(runId, receipt);
    assert.equal(second.written, false, "a second boot must be a no-op, not a duplicate");
    assert.equal(second.reason, "already_present");

    // Even a slightly different receipt for the same agent must not append again —
    // the gate rejects two receipts for one agent with RECEIPT_DUPLICATE.
    const third = writeReceipt(runId, fixture({ source: "a second probe" }));
    assert.equal(third.written, false);

    const text = fs.readFileSync(ledgerPathFor(runId), "utf8");
    const lines = text.split("\n").filter((l) => l.trim() !== "");
    assert.equal(lines.length, 1);
    assert.equal(text.endsWith("\n"), true, "JSONL lines are newline-terminated");
    assert.equal(lines[0].includes("\n"), false, "no pretty-printing: one object per line");
    assert.deepEqual(JSON.parse(lines[0]), receipt);

    // A different agent still appends normally.
    writeReceipt(runId, fixture({ agent: "responder_kimi" }));
    const records = readReceipts(runId);
    assert.equal(records.length, 2);
    assert.deepEqual(
      records.map((r) => r.receipt.agent).sort(),
      ["responder_glm", "responder_kimi"],
    );
  });
});

test("buildReceipt emits exactly the eleven contract keys for every agent", () => {
  const table = agentTable();
  for (const agentId of AGENT_IDS) {
    const spec = table[agentId];
    const receipt = buildReceipt({
      agentId,
      probe: {
        ok: true,
        runtime_version: "9.9.9",
        model_effective: spec.model_openrouter,
        effort_effective: spec.effort,
        source: `stdout of \`${spec.runtime} --version\``,
        evidence: { stdout: "must never be copied into the receipt" },
      },
    });

    assert.deepEqual(validateReceipt(receipt), [], `${agentId} receipt must be schema-valid`);
    assert.equal(Object.keys(receipt).length, 11);
    assert.equal(Object.hasOwn(receipt, "evidence"), false);
    assert.equal(receipt.agent, agentId);
    assert.equal(receipt.runtime, spec.tap_runtime, "the receipt speaks the contract's runtime name");
    assert.equal(receipt.model_requested, spec.model_openrouter, "model_requested is an OpenRouter id");
    assert.equal(receipt.effort_requested, spec.effort);
    assert.equal(receipt.downgraded, false);
    assert.equal(receipt.blocked, false);
    assert.equal(receipt.mocked, false);
  }

  // The one agent whose tap runtime name differs from models.json's runtime key.
  assert.equal(table.responder_claude.runtime, "claude");
  assert.equal(buildReceipt({ agentId: "responder_claude", probe: { ok: true, runtime_version: "1", model_effective: table.responder_claude.model_openrouter, effort_effective: "max", source: "s" } }).runtime, "claude_code");
  assert.equal(buildReceipt({ agentId: "monitor", probe: { ok: true, runtime_version: "1", model_effective: table.monitor.model_openrouter, effort_effective: "xhigh", source: "s" } }).runtime, "hermes");
});

test("buildReceipt flags a real downgrade read back from a successful probe", () => {
  const spec = agentTable().responder_codex;
  const receipt = buildReceipt({
    agentId: "responder_codex",
    probe: {
      ok: true,
      runtime_version: "2.0.0",
      model_effective: spec.model_openrouter,
      effort_effective: "medium",
      source: "response.usage.reasoning_effort",
    },
  });
  assert.equal(receipt.effort_requested, "max");
  assert.equal(receipt.effort_effective, "medium");
  assert.equal(receipt.downgraded, true);
  assert.deepEqual(validateReceipt(receipt), []);
});

test("buildReceipt: antigravity at its ceiling is live and NOT downgraded", () => {
  const spec = agentTable().responder_antigravity;
  const receipt = buildReceipt({
    agentId: "responder_antigravity",
    probe: {
      ok: true,
      runtime_version: "0.4.2",
      model_effective: spec.model_openrouter,
      effort_effective: "high",
      source: "stdout of `agy --list-models`",
    },
  });
  assert.equal(receipt.effort_effective, "high");
  assert.equal(receipt.downgraded, false);
  assert.equal(receipt.blocked, false);
});

test("buildReceipt blocked path retains the pin and does not claim a downgrade", () => {
  const spec = agentTable().responder_kimi;

  const noProbe = buildReceipt({ agentId: "responder_kimi", probe: { ok: false, error: "opencode: not authenticated" } });
  assert.equal(noProbe.blocked, true);
  assert.equal(noProbe.mocked, true, "blocked implies the run is not an acceptance run");
  assert.equal(noProbe.downgraded, false, "a blocked agent has not run at all; that is not a downgrade");
  assert.equal(noProbe.model_effective, spec.model_openrouter, "the exact pin is retained, never substituted");
  assert.equal(noProbe.model_requested, noProbe.model_effective);
  assert.equal(noProbe.effort_effective, spec.effort);
  assert.equal(noProbe.runtime_version, "unknown");
  assert.equal(noProbe.source, "opencode: not authenticated");
  assert.deepEqual(validateReceipt(noProbe), []);

  // A CLI can report --version while still refusing to run unauthenticated.
  const versionOnly = buildReceipt({
    agentId: "responder_kimi",
    probe: { ok: false, runtime_version: "0.9.1", error: "opencode: auth required" },
  });
  assert.equal(versionOnly.runtime_version, "0.9.1");
  assert.equal(versionOnly.blocked, true);

  // Missing readback values block even when the probe claims success.
  const hollow = buildReceipt({ agentId: "responder_kimi", probe: { ok: true, source: "handshake echo" } });
  assert.equal(hollow.blocked, true);
  assert.equal(hollow.source, "handshake echo");

  // No probe at all is a block, and every string field is still non-empty.
  const bare = buildReceipt({ agentId: "responder_kimi" });
  assert.equal(bare.blocked, true);
  assert.deepEqual(validateReceipt(bare), []);
});

test("buildReceipt honours explicit mocked and blocked flags", () => {
  const spec = agentTable().responder_glm;
  const goodProbe = {
    ok: true,
    runtime_version: "1.2.3",
    model_effective: spec.model_openrouter,
    effort_effective: spec.effort,
    source: "config echo at handshake",
  };

  const mocked = buildReceipt({ agentId: "responder_glm", probe: goodProbe, mocked: true });
  assert.equal(mocked.mocked, true);
  assert.equal(mocked.blocked, false);
  assert.equal(mocked.downgraded, false);

  const forcedBlock = buildReceipt({ agentId: "responder_glm", probe: goodProbe, blocked: true });
  assert.equal(forcedBlock.blocked, true);
  assert.equal(forcedBlock.mocked, true);
  assert.equal(forcedBlock.source, "config echo at handshake");
});

test("buildReceipt throws on an unknown agent id", () => {
  assert.throws(() => buildReceipt({ agentId: "responder_nobody" }), /unknown agentId/);
  assert.throws(() => buildReceipt({}), /unknown agentId/);
});

test("parseReceiptLines numbers every line but skips blanks", () => {
  const records = parseReceiptLines(['{"agent":"monitor"}', "", "   ", "{oops", "[1,2]", ""].join("\n"));
  assert.equal(records.length, 3, "blank and whitespace-only lines are not records at all");
  assert.deepEqual(
    records.map((r) => r.line),
    [1, 4, 5],
    "line numbers count blanks so they match what an editor shows",
  );
  assert.equal(records[0].ok, true);
  assert.equal(records[1].ok, false);
  assert.equal(records[1].error, "not parseable JSON (SyntaxError)");
  assert.equal(records[2].ok, false);
  assert.equal(records[2].error, "not a JSON object");
});

test("readReceipts on a run that does not exist returns [] and creates nothing", () => {
  const runId = `test-absent-${process.pid}-${Date.now().toString(36)}`;
  assert.deepEqual(readReceipts(runId), []);
  assert.equal(
    fs.existsSync(path.join(RUNS_DIR, runId)),
    false,
    "reading a ledger must not bring the run directory into existence",
  );
});
