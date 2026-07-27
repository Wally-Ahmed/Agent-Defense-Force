// Tests for pricing, totals, rendering and graceful degradation.
//
// Every fixture run lives in an os.tmpdir() directory created here and removed in
// after(), so the suite depends on no real run and leaves nothing in runs/.

import test, { after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

import { AGENT_IDS } from "../../lib/agents.js";
import { estimateUsd } from "../../lib/prices.js";
import {
  buildReport,
  computeTotals,
  readEffortLedger,
  renderMarkdown,
  safeEstimateUsd,
  effortLedgerPath,
  summariseTarget,
  MISSING_CELL,
  UNPRICED_CELL,
} from "../src/report.js";

const FIXTURES = [];
after(() => {
  for (const dir of FIXTURES) fs.rmSync(dir, { recursive: true, force: true });
});

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

function assessment(agent, model, usage, over = {}) {
  return {
    incident_id: "inc_test0000000000",
    responder: agent,
    model,
    effort_requested: "max",
    effort_effective: "max",
    verdict: "malicious",
    confidence: 0.9134,
    campaign_stages: [2, 3, 4],
    recommended_actions: [
      { action: "quarantine_token", target: "tok_synthetic", ttl_s: 900, blast_radius: "single-identity" },
    ],
    skills_used: [{ path: "skills/triage.md", sha: "deadbeef" }],
    rationale: "fixture",
    usage,
    ...over,
  };
}

/**
 * Build a fixture run dir. `rawLedger` lets a test write bytes the JSON writer
 * would never produce, which is exactly what the malformed-line test needs.
 */
function makeRun({ receipts = [], assessments = {}, rawLedger = null, extra = {} } = {}) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "mesh-report-"));
  FIXTURES.push(root);

  const ledger = rawLedger ?? `${receipts.map((r) => JSON.stringify(r)).join("\n")}\n`;
  fs.writeFileSync(path.join(root, "effort.jsonl"), ledger, "utf8");

  const entries = Object.entries(assessments);
  if (entries.length) {
    fs.mkdirSync(path.join(root, "assessments"), { recursive: true });
    for (const [agent, body] of entries) {
      fs.writeFileSync(
        path.join(root, "assessments", `${agent}.json`),
        `${JSON.stringify(body, null, 2)}\n`,
        "utf8",
      );
    }
  }
  for (const [rel, body] of Object.entries(extra)) {
    const abs = path.join(root, rel);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, typeof body === "string" ? body : `${JSON.stringify(body, null, 2)}\n`, "utf8");
  }
  return root;
}

function rowLine(md, agentId) {
  const line = md.split("\n").find((l) => l.startsWith(`| ${agentId} |`));
  assert.ok(line, `no markdown table row for ${agentId}`);
  return line;
}

test("6. USD math matches the frozen price table exactly", () => {
  // usd = in/1e6*in_per_m + out/1e6*out_per_m; reasoning is already inside out.
  // anthropic/claude-opus-5 @ 5.00 in / 25.00 out: 5.00 + 2.50
  assert.equal(estimateUsd("anthropic/claude-opus-5", { in: 1_000_000, out: 100_000, reasoning: 40_000 }).usd, 7.5);
  assert.equal(safeEstimateUsd("anthropic/claude-opus-5", { in: 1_000_000, out: 100_000, reasoning: 40_000 }).usd, 7.5);

  // z-ai/glm-5.2 @ 0.669 in / 2.10 out: 1.338 + 2.100
  assert.equal(estimateUsd("z-ai/glm-5.2", { in: 2_000_000, out: 1_000_000, reasoning: 0 }).usd, 3.438);
  assert.equal(safeEstimateUsd("z-ai/glm-5.2", { in: 2_000_000, out: 1_000_000, reasoning: 0 }).usd, 3.438);

  // and the same numbers survive the whole report path, not just the estimator.
  const root = makeRun({
    receipts: AGENT_IDS.map((id) => receipt(id)),
    assessments: {
      responder_claude: assessment("responder_claude", "anthropic/claude-opus-5", {
        in: 1_000_000,
        out: 100_000,
        reasoning: 40_000,
        usd: 7.5,
      }),
      responder_glm: assessment("responder_glm", "z-ai/glm-5.2", {
        in: 2_000_000,
        out: 1_000_000,
        reasoning: 0,
        usd: 3.438,
      }),
    },
  });
  const model = buildReport({ runRoot: root });
  const claude = model.agents.find((a) => a.agent_id === "responder_claude");
  const glm = model.agents.find((a) => a.agent_id === "responder_glm");
  assert.equal(claude.usd, 7.5);
  assert.equal(glm.usd, 3.438);
  assert.equal(claude.cells.usd, "$7.500000");
  assert.equal(glm.cells.usd, "$3.438000");
});

test("7. google/gemini-3.6-flash-high is unpriced and never renders as $0.00", () => {
  const est = safeEstimateUsd("google/gemini-3.6-flash-high", { in: 500_000, out: 250_000, reasoning: 80_000 });
  assert.equal(est.priced, false);

  const root = makeRun({
    receipts: AGENT_IDS.map((id) =>
      id === "responder_antigravity"
        ? receipt(id, {
            runtime: "agy",
            model_requested: "gemini-3.6-flash-high",
            model_effective: "gemini-3.6-flash-high",
          })
        : receipt(id),
    ),
    assessments: {
      responder_antigravity: assessment("responder_antigravity", "google/gemini-3.6-flash-high", {
        in: 500_000,
        out: 250_000,
        reasoning: 80_000,
        usd: 0,
      }),
      responder_claude: assessment("responder_claude", "anthropic/claude-opus-5", {
        in: 1_000_000,
        out: 100_000,
        reasoning: 0,
        usd: 7.5,
      }),
    },
  });
  const model = buildReport({ runRoot: root });
  const agy = model.agents.find((a) => a.agent_id === "responder_antigravity");
  assert.equal(agy.priced, false);
  assert.equal(agy.cells.usd, UNPRICED_CELL);

  const md = renderMarkdown(model);
  const line = rowLine(md, "responder_antigravity");
  assert.ok(line.includes(UNPRICED_CELL), `row should say "unpriced": ${line}`);
  assert.ok(!line.includes("$0.00"), `row must never claim $0.00: ${line}`);
  assert.ok(!line.includes("$"), `unpriced row must carry no dollar figure at all: ${line}`);
});

test("8. a run with effort.jsonl and zero assessments still renders and says missing", () => {
  const root = makeRun({ receipts: AGENT_IDS.map((id) => receipt(id)) });
  assert.ok(!fs.existsSync(path.join(root, "assessments")));

  let model;
  let md;
  assert.doesNotThrow(() => {
    model = buildReport({ runRoot: root });
    md = renderMarkdown(model);
  });

  assert.equal(model.agents.length, AGENT_IDS.length);
  assert.ok(md.includes(MISSING_CELL));

  for (const row of model.agents) {
    if (row.agent_id === "monitor") {
      // Expected absence, not a gap: the monitor escalates, it does not vote.
      assert.equal(row.verdict, "n/a");
      assert.equal(row.confidence, "n/a");
      assert.equal(row.cells.usd, "n/a");
    } else {
      assert.equal(row.verdict, MISSING_CELL);
      assert.equal(row.confidence, MISSING_CELL);
      assert.equal(row.cells.in, MISSING_CELL);
      assert.equal(row.cells.out, MISSING_CELL);
      assert.equal(row.cells.reasoning, MISSING_CELL);
      assert.equal(row.cells.usd, MISSING_CELL);
    }
    // never a zero, never a blank
    assert.notEqual(row.cells.in, "");
    assert.notEqual(row.cells.in, "0");
  }

  // absent coordinator / containment artifacts are stated, not skipped
  assert.equal(model.decision.present, false);
  assert.equal(model.containment.present, false);
  assert.ok(md.includes(`decision: ${MISSING_CELL}`));
  assert.ok(md.includes(`containment: ${MISSING_CELL}`));
});

test("9. totals sum only priced rows and report unpriced tokens separately", () => {
  const root = makeRun({
    receipts: AGENT_IDS.map((id) => receipt(id)),
    assessments: {
      responder_claude: assessment("responder_claude", "anthropic/claude-opus-5", {
        in: 1_000_000,
        out: 100_000,
        reasoning: 40_000,
        usd: 7.5,
      }),
      responder_glm: assessment("responder_glm", "z-ai/glm-5.2", {
        in: 2_000_000,
        out: 1_000_000,
        reasoning: 0,
        usd: 3.438,
      }),
      responder_antigravity: assessment("responder_antigravity", "google/gemini-3.6-flash-high", {
        in: 500_000,
        out: 250_000,
        reasoning: 80_000,
        usd: 0,
      }),
    },
  });
  const model = buildReport({ runRoot: root });
  const t = model.totals;

  // 7.5 + 3.438, with the unpriced flash row contributing nothing
  assert.equal(t.usd_priced, 10.938);
  assert.equal(t.priced_rows, 2);
  assert.equal(t.unpriced_rows, 1);

  // token totals still count every row, priced or not
  assert.equal(t.in, 3_500_000);
  assert.equal(t.out, 1_350_000);
  assert.equal(t.reasoning, 120_000);

  // Regression guard: this fixture's antigravity RECEIPT still carries the
  // default z-ai/glm-5.2 model string while its assessment names the unpriced
  // flash model. The row must be priced against the assessment's identity and
  // stay unpriced — never fall through to a known-but-different model's rate.
  const agy = model.agents.find((a) => a.agent_id === "responder_antigravity");
  assert.equal(agy.price_key, "google/gemini-3.6-flash-high");
  assert.equal(agy.priced, false);

  assert.deepEqual(t.unpriced_tokens, { in: 500_000, out: 250_000, reasoning: 80_000 });
  assert.equal(t.unpriced_models.length, 1);
  assert.equal(t.unpriced_models[0].model, "google/gemini-3.6-flash-high");
  assert.deepEqual(t.unpriced_models[0].agents, ["responder_antigravity"]);

  const md = renderMarkdown(model);
  assert.ok(md.includes("$10.938000"), "totals row must carry the priced total");
  assert.ok(
    md.includes("unpriced models EXCLUDED from the priced total"),
    "the report must name the unpriced models so the total is not silently understated",
  );
  assert.ok(md.includes("`google/gemini-3.6-flash-high`"));

  // computeTotals is pure and agrees with the assembled model
  assert.deepEqual(computeTotals(model.agents), t);
});

test("10. a malformed effort.jsonl line is skipped, surfaced and never throws", () => {
  const good = AGENT_IDS.map((id) => JSON.stringify(receipt(id)));
  const rawLedger = [
    good[0],
    good[1],
    '{"agent": "responder_codex", "blocked": false,,,',
    good[3],
    "not json at all",
    good[4],
    "[1,2,3]",
    good[5],
    "",
  ].join("\n");

  const root = makeRun({ rawLedger });

  let ledger;
  assert.doesNotThrow(() => {
    ledger = readEffortLedger(effortLedgerPath(root));
  });
  assert.equal(ledger.receipts.length, 5);
  assert.equal(ledger.parse_errors.length, 3);
  assert.deepEqual(
    ledger.parse_errors.map((e) => e.line),
    [3, 5, 7],
  );
  assert.match(ledger.parse_errors[2].reason, /not a JSON object/);

  let model;
  let md;
  assert.doesNotThrow(() => {
    model = buildReport({ runRoot: root });
    md = renderMarkdown(model);
  });
  assert.equal(model.parse_errors.length, 3);
  // the skipped receipt makes the run un-LIVE, and the report says why
  assert.equal(model.label.label, "MOCKED");
  assert.deepEqual(model.label.missing, ["responder_codex"]);
  assert.ok(md.includes("effort.jsonl line 3:"));
  assert.ok(md.includes("effort.jsonl line 5:"));
  assert.ok(md.includes("effort.jsonl line 7:"));
});

// 11. Regression: decision.v1 `target` is an OBJECT. Rendering it with a plain
// string conversion produced the literal "[object Object]" for every action
// row, hiding exactly what was contained.
test("11. an action target renders its fields, never [object Object]", () => {
  const cell = summariseTarget({
    principal_hash: "ph_9f2c1d4e8a7b6c5d4e3f2a1b",
    tenant: "acme",
    session_ids: ["sess-1", "sess-2", "sess-3"],
    src_ips: ["203.0.113.7"],
  });
  assert.ok(!cell.includes("[object Object]"), `got: ${cell}`);
  assert.ok(cell.includes("tenant=acme"), `got: ${cell}`);
  // Arrays collapse to a count so one action stays one table row.
  assert.ok(cell.includes("session_ids=[3:"), `got: ${cell}`);
  assert.ok(cell.includes("src_ips=203.0.113.7"), `got: ${cell}`);
  // A long hash is clipped rather than allowed to break the table.
  assert.ok(cell.includes("..."), `got: ${cell}`);

  assert.equal(summariseTarget(null), "missing");
  assert.equal(summariseTarget({}), "none");
});
