import test from "node:test";
import assert from "node:assert/strict";
import {
  parseAssessment,
  extractJsonObjects,
  extractAnswerText,
} from "../src/parse.js";
import { CTX, MODEL_REPLY, CLAUDE_RESULT } from "./fixtures.js";

const J = (o) => JSON.stringify(o, null, 2);

test("parses a bare JSON object", () => {
  const r = parseAssessment(J(MODEL_REPLY), CTX);
  assert.equal(r.ok, true, r.errors.join("; "));
  assert.equal(r.assessment.verdict, "malicious");
});

test("parses a fenced ```json block", () => {
  const raw = "Here is my assessment.\n\n```json\n" + J(MODEL_REPLY) + "\n```\n\nHope that helps.";
  const r = parseAssessment(raw, CTX);
  assert.equal(r.ok, true, r.errors.join("; "));
  assert.equal(r.assessment.confidence, 0.91);
});

test("parses an object buried in noisy CLI output with braces in prose", () => {
  const raw =
    "⏺ session abc · model claude-opus-5\n" +
    "✳ thinking: the shape is {enumeration} then {canary}, so escalation\n" +
    "⚒ Read [tool_1] {\"file_path\": \"/tmp/x\"}\n" +
    "◇ assistant:\n" +
    J(MODEL_REPLY) +
    "\n✓ result/success · 1234ms\n";
  const r = parseAssessment(raw, CTX);
  assert.equal(r.ok, true, r.errors.join("; "));
  assert.equal(r.assessment.verdict, "malicious");
});

test("braces inside string literals do not confuse the scanner", () => {
  const spans = extractJsonObjects('{"a":"} { not a brace"} trailing');
  assert.equal(spans.length, 1);
  assert.equal(JSON.parse(spans[0].text).a, "} { not a brace");
});

test("escaped quotes inside strings do not confuse the scanner", () => {
  const spans = extractJsonObjects('{"a":"he said \\"}\\" loudly"}');
  assert.equal(spans.length, 1);
  assert.equal(JSON.parse(spans[0].text).a, 'he said "}" loudly');
});

test("prefers the LAST candidate that looks like an assessment", () => {
  const first = { ...MODEL_REPLY, verdict: "benign", confidence: 0.1 };
  const raw =
    "Draft (ignore this one):\n" +
    J(first) +
    "\n\nOn reflection, here is my real answer:\n" +
    J(MODEL_REPLY);
  const r = parseAssessment(raw, CTX);
  assert.equal(r.ok, true, r.errors.join("; "));
  assert.equal(r.assessment.verdict, "malicious");
  assert.equal(r.assessment.confidence, 0.91);
  assert.equal(r.extraction.candidates, 2);
});

test("ignores non-assessment objects that appear after the answer", () => {
  const raw = J(MODEL_REPLY) + '\n{"tool":"Read","input":{"file_path":"/tmp/x"}}\n';
  const r = parseAssessment(raw, CTX);
  assert.equal(r.ok, true, r.errors.join("; "));
  assert.equal(r.assessment.verdict, "malicious");
});

test("tolerates trailing commas and // comments", () => {
  const raw =
    "```json\n{\n" +
    '  // my verdict\n' +
    '  "verdict": "suspicious",\n' +
    '  "confidence": 0.5,\n' +
    '  "campaign_stages": [2,3],\n' +
    '  "recommended_actions": [],\n' +
    '  "skills_used": [],\n' +
    '  "rationale": "Ambiguous.",\n' +
    "}\n```";
  const r = parseAssessment(raw, CTX);
  assert.equal(r.ok, true, r.errors.join("; "));
  assert.equal(r.assessment.verdict, "suspicious");
  assert.ok(r.extraction.repaired);
});

test("garbage in, honest failure out — never a fabricated assessment", () => {
  for (const raw of ["", "no json here at all", "{ this is not json }", "{{{{", '{"a":1}']) {
    const r = parseAssessment(raw, CTX);
    assert.equal(r.ok, false, `expected failure for ${JSON.stringify(raw)}`);
    assert.equal(r.assessment, null);
    assert.ok(r.errors.length > 0);
  }
});

test("a truncated object is rejected rather than half-parsed", () => {
  const raw = J(MODEL_REPLY).slice(0, 80);
  const r = parseAssessment(raw, CTX);
  assert.equal(r.ok, false);
  assert.equal(r.assessment, null);
});

test("rationale is clamped to the 400-character cap", () => {
  const long = { ...MODEL_REPLY, rationale: "A".repeat(900) };
  const r = parseAssessment(J(long), CTX);
  assert.equal(r.ok, true, r.errors.join("; "));
  assert.equal(Array.from(r.assessment.rationale).length, 400);
  assert.equal(r.extraction.rationale_truncated, true);
});

test("truncated rationale does not spill into any other field", () => {
  const long = { ...MODEL_REPLY, rationale: "A".repeat(900) };
  const r = parseAssessment(J(long), CTX);
  const blob = JSON.stringify({ ...r.assessment, rationale: "" });
  assert.ok(!blob.includes("AAAAAAAAAA"), "overflow leaked into another field");
});

test("ctx fields override anything the model claimed", () => {
  const lying = {
    ...MODEL_REPLY,
    incident_id: "inc-WRONG",
    responder: "responder_glm",
    model: "some/other-model",
    effort_requested: "low",
    effort_effective: "low",
    usage: { in: 999999, out: 999999, reasoning: 999999, usd: 999 },
  };
  const r = parseAssessment(J(lying), CTX);
  assert.equal(r.ok, true, r.errors.join("; "));
  assert.equal(r.assessment.incident_id, CTX.incidentId);
  assert.equal(r.assessment.responder, CTX.agentId);
  assert.equal(r.assessment.model, CTX.model);
  assert.equal(r.assessment.effort_requested, "max");
  assert.equal(r.assessment.effort_effective, "max");
  assert.deepEqual(r.assessment.usage, CTX.usage);
  for (const k of ["incident_id", "responder", "model", "effort_requested", "usage"]) {
    assert.ok(r.extraction.overridden_keys.includes(k), `${k} not recorded as overridden`);
  }
});

test("unknown keys are dropped and recorded, not silently swallowed", () => {
  const noisy = { ...MODEL_REPLY, notes: "extra", schema_version: "assessment.v1" };
  const r = parseAssessment(J(noisy), CTX);
  assert.equal(r.ok, true, r.errors.join("; "));
  assert.ok(!("notes" in r.assessment));
  assert.deepEqual(r.extraction.dropped_keys.sort(), ["notes", "schema_version"]);
});

test("absent list fields are filled with [], judgement fields are never invented", () => {
  const sparse = { verdict: "benign", confidence: 0.2, rationale: "Baseline drift only." };
  const r = parseAssessment(J(sparse), CTX);
  assert.equal(r.ok, true, r.errors.join("; "));
  assert.deepEqual(r.assessment.recommended_actions, []);
  assert.deepEqual(r.assessment.skills_used, []);
  assert.deepEqual(r.assessment.campaign_stages, []);

  const noVerdict = { confidence: 0.2, rationale: "x", campaign_stages: [] };
  const r2 = parseAssessment(J(noVerdict), CTX);
  assert.equal(r2.ok, false);
  assert.ok(r2.errors.some((e) => e.includes("verdict")));
});

test("coerces quoted numbers, a single action object, and duplicate stages", () => {
  const sloppy = {
    verdict: "suspicious",
    confidence: "0.6",
    campaign_stages: [2, 2, "3"],
    recommended_actions: {
      action: "raise_logging",
      target: { tenant: "tenant_test" },
      ttl_s: "600",
      blast_radius: "narrow",
    },
    skills_used: [],
    rationale: "Coercion check.",
  };
  const r = parseAssessment(J(sloppy), CTX);
  assert.equal(r.ok, true, r.errors.join("; "));
  assert.equal(r.assessment.confidence, 0.6);
  assert.deepEqual(r.assessment.campaign_stages, [2, 3]);
  assert.equal(Array.isArray(r.assessment.recommended_actions), true);
  assert.equal(r.assessment.recommended_actions[0].ttl_s, 600);
});

test("a bad enum from the model is a rejection, not a repair", () => {
  const bad = { ...MODEL_REPLY, verdict: "very_malicious" };
  const r = parseAssessment(J(bad), CTX);
  assert.equal(r.ok, false);
  assert.equal(r.assessment, null);
  assert.ok(r.rejected, "the rejected object is kept for the run report");
  assert.ok(r.errors.some((e) => e.includes("verdict")));
});

test("extractAnswerText unwraps a claude stream-json answer", () => {
  const raw = [
    '{"type":"system","subtype":"init","model":"claude-opus-5"}',
    '{"type":"assistant","message":{"content":[{"type":"thinking","thinking":"hm {"}]}}',
    '{"type":"assistant","message":{"content":[{"type":"text","text":' +
      JSON.stringify(J(MODEL_REPLY)) +
      "}]}}",
    CLAUDE_RESULT,
  ].join("\n");
  const answer = extractAnswerText("claude_code", raw);
  const r = parseAssessment(answer, CTX);
  assert.equal(r.ok, true, r.errors.join("; "));
  assert.equal(r.assessment.verdict, "malicious");
});

test("extractAnswerText unwraps a codex agent_message answer", () => {
  const raw = [
    '{"type":"thread.started","thread_id":"t1"}',
    '{"type":"item.completed","item":{"type":"reasoning","text":"considering {a}"}}',
    '{"type":"item.completed","item":{"type":"agent_message","text":' +
      JSON.stringify(J(MODEL_REPLY)) +
      "}}",
    '{"type":"turn.completed","usage":{"input_tokens":1,"output_tokens":1}}',
  ].join("\n");
  const answer = extractAnswerText("codex", raw);
  const r = parseAssessment(answer, CTX);
  assert.equal(r.ok, true, r.errors.join("; "));
  assert.equal(r.assessment.verdict, "malicious");
});

test("extractAnswerText returns empty for pty runtimes so the caller scans raw", () => {
  assert.equal(extractAnswerText("agy", '{"type":"result"}'), "");
  assert.equal(extractAnswerText("hermes", '{"type":"result"}'), "");
});
