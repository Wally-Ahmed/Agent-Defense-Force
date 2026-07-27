import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { agentTable, RESPONDER_IDS } from "../../lib/agents.js";
import { RUNS_DIR, CONTRACTS_DIR, readJson } from "../../lib/paths.js";
import { runResponder, EFFORT_PLAN, preflight, resolveBin } from "../src/run.js";
import { adapterForRuntime } from "../../transcript/src/index.js";
import { INCIDENT } from "./fixtures.js";

const TABLE = agentTable();
const RUN_ID = `test-agentrunner-run-${process.pid}`;

test.after(() => {
  fs.rmSync(path.join(RUNS_DIR, RUN_ID), { recursive: true, force: true });
  fs.rmSync(NO_ENV_FILE, { force: true });
});

test("the mock path produces a valid, delivered assessment", async () => {
  const r = await runResponder({
    agentId: "responder_glm",
    incident: INCIDENT,
    runId: RUN_ID,
    mock: true,
    transport: "file",
  });
  assert.equal(r.ok, true, r.errors.join("; "));
  assert.equal(r.mocked, true);
  assert.equal(r.assessment.incident_id, INCIDENT.incident_id);
  assert.equal(r.assessment.responder, "responder_glm");
  assert.equal(r.assessment.model, "z-ai/glm-5.2");
  assert.ok(fs.existsSync(r.assessmentPath));
  assert.deepEqual(readJson(r.assessmentPath), r.assessment);
});

test("the mock's receipt is stamped mocked and reports usage as unmeasured", async () => {
  const r = await runResponder({
    agentId: "responder_kimi",
    incident: INCIDENT,
    runId: RUN_ID,
    mock: true,
    transport: "file",
  });
  assert.equal(r.receiptInput.mocked, true);
  assert.equal(r.receiptInput.blocked, false);
  assert.equal(r.receiptInput.downgraded, false);
  assert.equal(r.usageReported, false);
  assert.match(r.receiptInput.source, /^mock:recorded-transcript/);
});

test("receiptInput carries exactly the 11 effort_receipt.v1 fields", async () => {
  const schema = readJson(path.join(CONTRACTS_DIR, "effort_receipt.v1.schema.json"));
  const r = await runResponder({
    agentId: "responder_claude",
    incident: INCIDENT,
    runId: RUN_ID,
    mock: true,
    transport: "file",
  });
  assert.deepEqual(Object.keys(r.receiptInput).sort(), [...schema.required].sort());
});

test("the pinned model is never substituted — requested equals effective", async () => {
  for (const id of RESPONDER_IDS) {
    const r = await runResponder({
      agentId: id,
      incident: INCIDENT,
      runId: RUN_ID,
      mock: true,
      transport: "file",
    });
    assert.equal(r.ok, true, `${id}: ${r.errors.join("; ")}`);
    assert.equal(r.receiptInput.model_requested, TABLE[id].model_openrouter);
    assert.equal(r.receiptInput.model_effective, TABLE[id].model_openrouter);
    assert.equal(r.receiptInput.effort_requested, TABLE[id].effort);
    assert.equal(r.receiptInput.effort_effective, TABLE[id].effort);
    assert.equal(r.receiptInput.downgraded, false);
  }
});

test("the monitor is rejected — it produces incidents, not assessments", async () => {
  await assert.rejects(
    () => runResponder({ agentId: "monitor", incident: INCIDENT, runId: RUN_ID, mock: true }),
    /is not a responder/,
  );
  await assert.rejects(
    () => runResponder({ agentId: "responder_nope", incident: INCIDENT, runId: RUN_ID }),
    /unknown agent/,
  );
});

// UPDATED 2026-07-26. This used to assert "only hermes is unenforced", which was a
// stale encoding of the belief that hermes had no effort channel. Measured against
// the real CLIs: hermes DOES have one (the config key `agent.reasoning_effort`,
// which the probe reads back), and opencode's `--variant` is the one that cannot be
// confirmed — verified live, `--variant bogus-xyz` exits 0 and answers normally, so
// opencode neither echoes nor validates the level. The flag flipped for both.
test("every runtime has an effort plan, and only opencode's level is unconfirmable", () => {
  for (const id of ["monitor", ...RESPONDER_IDS]) {
    const a = TABLE[id];
    const plan = EFFORT_PLAN[a.tap_runtime];
    assert.ok(plan, `no effort plan for ${a.tap_runtime}`);
    const p = plan(a.effort);
    assert.equal(p.enforced, a.tap_runtime !== "opencode", `${id}: wrong enforced flag`);
    // The requested level must appear verbatim in every source string, enforced or
    // not — an audit reader has to see which level this plan is talking about.
    assert.ok(p.source.includes(a.effort), `${id}: effort not in source string`);
  }
});

test("effort reaches the harness argv or env exactly as documented", () => {
  const claude = EFFORT_PLAN.claude_code("max");
  assert.deepEqual(claude.extraArgs, ["--effort", "max"]);

  const codex = EFFORT_PLAN.codex("max");
  assert.deepEqual(codex.env, { TRANSCRIPT_CODEX_EFFORT: "max" });

  const agy = EFFORT_PLAN.agy("high");
  assert.deepEqual(agy.extraArgs, ["--effort", "high"]);

  // TRANSCRIPT_OPENCODE_FORMAT rides along because opencode's default renderer
  // reports no token counts at all; only --format json carries part.tokens.
  const oc = EFFORT_PLAN.opencode("max");
  assert.deepEqual(oc.env, {
    TRANSCRIPT_OPENCODE_VARIANT: "max",
    TRANSCRIPT_OPENCODE_FORMAT: "json",
  });
  assert.deepEqual(oc.extraArgs, []);

  // Hermes' channel is its config file, not argv or env — nothing is smuggled onto
  // the command line, and the probe reads the level back from the config instead.
  const hermes = EFFORT_PLAN.hermes("xhigh");
  assert.deepEqual(hermes.extraArgs, []);
  assert.deepEqual(hermes.env, {});
  assert.match(hermes.source, /agent\.reasoning_effort/);
  assert.match(hermes.source, /xhigh/);
});

test("the effort env var survives as a var, and is restored after the run", async () => {
  const before = process.env.TRANSCRIPT_OPENCODE_VARIANT;
  await runResponder({
    agentId: "responder_kimi",
    incident: INCIDENT,
    runId: RUN_ID,
    mock: true,
    transport: "file",
  });
  assert.equal(process.env.TRANSCRIPT_OPENCODE_VARIANT, before);
});

// "Absent" now means absent EVERYWHERE, not just unexported. preflight() consults
// mesh/lib/env.js's envPresent(), which reads the real environment AND a dotenv
// file — precisely so that a key sitting in .env can never again be misreported as
// missing. Blanking process.env alone therefore no longer simulates a missing key,
// and these tests point at an empty dotenv file instead of mutating the real one.
const NO_ENV_FILE = path.join(os.tmpdir(), `mesh-run-test-empty-env-${process.pid}`);
fs.writeFileSync(NO_ENV_FILE, "# deliberately empty: no credential of any kind\n");

test("preflight blocks an openrouter-only agent when the key is absent everywhere", () => {
  const saved = process.env.OPENROUTER_API_KEY;
  process.env.OPENROUTER_API_KEY = "";
  try {
    const glm = TABLE.responder_glm;
    const p = preflight(glm, adapterForRuntime(glm.tap_runtime), { envFile: NO_ENV_FILE });
    assert.equal(p.ok, false);
    assert.ok(p.reasons.some((r) => r.includes("OPENROUTER_API_KEY")));

    // responder_codex authenticates against a ChatGPT subscription, so the same
    // empty key must NOT block it.
    const codex = TABLE.responder_codex;
    const pc = preflight(codex, adapterForRuntime(codex.tap_runtime), { envFile: NO_ENV_FILE });
    assert.ok(!pc.reasons.some((r) => r.includes("OPENROUTER_API_KEY")));
  } finally {
    if (saved === undefined) delete process.env.OPENROUTER_API_KEY;
    else process.env.OPENROUTER_API_KEY = saved;
  }
});

test("a blocked agent keeps its exact pin and emits no assessment", async () => {
  const saved = process.env.OPENROUTER_API_KEY;
  process.env.OPENROUTER_API_KEY = "";
  try {
    const r = await runResponder({
      agentId: "responder_glm",
      incident: INCIDENT,
      runId: RUN_ID,
      transport: "file",
      envFile: NO_ENV_FILE,
    });
    assert.equal(r.ok, false);
    assert.equal(r.blocked, true);
    assert.equal(r.mocked, false);
    assert.equal(r.assessment, null);
    assert.equal(r.receiptInput.blocked, true);
    assert.equal(r.receiptInput.model_effective, "z-ai/glm-5.2");
    assert.ok(r.errors.some((e) => e.includes("NOT substituted")));
  } finally {
    if (saved === undefined) delete process.env.OPENROUTER_API_KEY;
    else process.env.OPENROUTER_API_KEY = saved;
  }
});

test("an incident without an incident_id is refused", async () => {
  await assert.rejects(
    () => runResponder({ agentId: "responder_glm", incident: {}, runId: RUN_ID, mock: true }),
    /missing incident_id/,
  );
});

test("resolveBin finds a real executable and returns null for a fake one", () => {
  assert.ok(resolveBin("node"));
  assert.equal(resolveBin("definitely-not-a-real-binary-xyz"), null);
});
