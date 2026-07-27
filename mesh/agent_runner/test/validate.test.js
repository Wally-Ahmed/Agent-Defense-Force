import test from "node:test";
import assert from "node:assert/strict";
import { validate, charLength, clampChars } from "../src/validate.js";
import { assessmentSchema } from "../src/prompt.js";
import { CTX, MODEL_REPLY } from "./fixtures.js";

const SCHEMA = assessmentSchema();

/** A complete, contract-conforming assessment. */
function good() {
  return {
    incident_id: CTX.incidentId,
    responder: CTX.agentId,
    model: CTX.model,
    effort_requested: "max",
    effort_effective: "max",
    usage: CTX.usage,
    ...structuredClone(MODEL_REPLY),
  };
}

test("accepts a conforming assessment", () => {
  const r = validate(SCHEMA, good());
  assert.equal(r.ok, true, JSON.stringify(r.errors));
});

test("rejects a bad verdict enum value", () => {
  const a = good();
  a.verdict = "probably_bad";
  const r = validate(SCHEMA, a);
  assert.equal(r.ok, false);
  assert.ok(r.errors.some((e) => e.keyword === "enum" && e.path === "$.verdict"));
});

test("rejects an action outside the closed ten-value enum", () => {
  const a = good();
  a.recommended_actions[0].action = "delete_everything";
  const r = validate(SCHEMA, a);
  assert.equal(r.ok, false);
  assert.ok(r.errors.some((e) => e.keyword === "enum"));
});

test("rejects an unknown top-level property (additionalProperties:false)", () => {
  const a = good();
  a.schema_version = "assessment.v1";
  const r = validate(SCHEMA, a);
  assert.equal(r.ok, false);
  assert.ok(
    r.errors.some((e) => e.keyword === "additionalProperties" && e.path === "$.schema_version"),
  );
});

test("rejects an unknown property nested in recommended_actions[].target", () => {
  const a = good();
  a.recommended_actions[0].target.hostname = "box-1";
  const r = validate(SCHEMA, a);
  assert.equal(r.ok, false);
  assert.ok(r.errors.some((e) => e.keyword === "additionalProperties"));
});

test("rejects a missing required property", () => {
  const a = good();
  delete a.rationale;
  const r = validate(SCHEMA, a);
  assert.equal(r.ok, false);
  assert.ok(r.errors.some((e) => e.keyword === "required" && e.path === "$.rationale"));
});

test("rejects an empty target (minProperties)", () => {
  const a = good();
  a.recommended_actions[0].target = {};
  const r = validate(SCHEMA, a);
  assert.equal(r.ok, false);
  assert.ok(r.errors.some((e) => e.keyword === "minProperties"));
});

test("rejects out-of-range confidence and campaign_stages", () => {
  const a = good();
  a.confidence = 1.4;
  a.campaign_stages = [0, 11];
  const r = validate(SCHEMA, a);
  assert.equal(r.ok, false);
  assert.ok(r.errors.some((e) => e.keyword === "maximum" && e.path === "$.confidence"));
  assert.ok(r.errors.some((e) => e.keyword === "minimum"));
  assert.ok(r.errors.some((e) => e.keyword === "maximum" && e.path.startsWith("$.campaign_stages")));
});

test("rejects duplicate campaign_stages (uniqueItems)", () => {
  const a = good();
  a.campaign_stages = [3, 3];
  const r = validate(SCHEMA, a);
  assert.equal(r.ok, false);
  assert.ok(r.errors.some((e) => e.keyword === "uniqueItems"));
});

test("rejects a non-integer ttl_s and a negative usage count", () => {
  const a = good();
  a.recommended_actions[0].ttl_s = 12.5;
  a.usage = { in: -1, out: 0, reasoning: 0, usd: 0 };
  const r = validate(SCHEMA, a);
  assert.equal(r.ok, false);
  assert.ok(r.errors.some((e) => e.keyword === "type" && e.path.includes("ttl_s")));
  assert.ok(r.errors.some((e) => e.keyword === "minimum" && e.path === "$.usage.in"));
});

test("rejects a rationale over the 400-character cap", () => {
  const a = good();
  a.rationale = "x".repeat(401);
  const r = validate(SCHEMA, a);
  assert.equal(r.ok, false);
  assert.ok(r.errors.some((e) => e.keyword === "maxLength" && e.path === "$.rationale"));
});

test("reports unsupported keywords instead of silently skipping them", () => {
  const r = validate({ type: "string", oneOf: [{ type: "string" }] }, "hi");
  assert.equal(r.ok, false);
  assert.ok(r.errors.some((e) => e.keyword === "oneOf"));
});

test("string length is counted in code points, not UTF-16 units", () => {
  assert.equal(charLength("ab"), 2);
  assert.equal(charLength("\u{1F600}"), 1); // one emoji = one character
  assert.equal(clampChars("\u{1F600}\u{1F600}", 1), "\u{1F600}");
  const r = validate({ type: "string", maxLength: 1 }, "\u{1F600}");
  assert.equal(r.ok, true);
});
