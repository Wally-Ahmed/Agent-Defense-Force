import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { RESPONDER_IDS, agentTable } from "../../lib/agents.js";
import { loadMockTranscript, mockRawText, mockUsage, hasMock, MOCK_DIR } from "../src/mock.js";
import { parseAssessment } from "../src/parse.js";
import { INCIDENT } from "./fixtures.js";

const TABLE = agentTable();

test("every responder has a recorded transcript on disk", () => {
  for (const id of RESPONDER_IDS) {
    assert.equal(hasMock(id), true, `no recorded transcript for ${id} in ${MOCK_DIR}`);
  }
});

test("each mock produces a schema-valid assessment through the LIVE parse path", () => {
  for (const id of RESPONDER_IDS) {
    const agent = TABLE[id];
    const ctx = {
      incidentId: INCIDENT.incident_id,
      agentId: id,
      model: agent.model_openrouter,
      effortRequested: agent.effort,
      effortEffective: agent.effort,
      usage: { in: 1, out: 1, reasoning: 0, usd: 0 },
    };
    const r = parseAssessment(mockRawText(id, INCIDENT), ctx);
    assert.equal(r.ok, true, `${id}: ${r.errors.join("; ")}`);
    assert.equal(r.assessment.incident_id, INCIDENT.incident_id, `${id}: incident_id not rewritten`);
    assert.equal(r.assessment.responder, id);
    assert.equal(r.assessment.model, agent.model_openrouter);
    assert.equal(r.assessment.effort_requested, agent.effort);
    assert.ok(["malicious", "suspicious", "benign"].includes(r.assessment.verdict));
  }
});

test("a mock cannot be more permissive than a live reply", () => {
  // Corrupt a recording and confirm the same gate rejects it.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ar-mock-"));
  try {
    const doc = loadMockTranscript("responder_glm");
    doc.assessment.verdict = "extremely_malicious";
    fs.writeFileSync(path.join(dir, "responder_glm.json"), JSON.stringify(doc));
    const r = parseAssessment(mockRawText("responder_glm", INCIDENT, dir), {
      incidentId: INCIDENT.incident_id,
      agentId: "responder_glm",
      model: "z-ai/glm-5.2",
      effortRequested: "max",
      effortEffective: "max",
      usage: { in: 0, out: 0, reasoning: 0, usd: 0 },
    });
    assert.equal(r.ok, false);
    assert.equal(r.assessment, null);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("refuses to speak for another responder", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ar-mock-"));
  try {
    const doc = loadMockTranscript("responder_kimi");
    fs.writeFileSync(path.join(dir, "responder_glm.json"), JSON.stringify(doc));
    assert.throws(() => loadMockTranscript("responder_glm", dir), /not "responder_glm"/);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test("mock usage replays recorded counts and is flagged as not measured", () => {
  const u = mockUsage("responder_claude");
  assert.equal(u.reported, false);
  assert.match(u.source, /recorded transcript/);
  assert.equal(u.in, loadMockTranscript("responder_claude").assessment.usage.in);
});

test("a missing recording is a clear error, not a silent empty assessment", () => {
  assert.equal(hasMock("responder_nope"), false);
  assert.throws(() => loadMockTranscript("responder_nope"), /no usable recorded transcript/);
});
