import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import { RUNS_DIR, readJson } from "../../lib/paths.js";
import { sendAssessment, COORDINATOR } from "../src/dm.js";
import { CTX, MODEL_REPLY } from "./fixtures.js";

const RUN_ID = `test-agentrunner-dm-${process.pid}`;

function assessment() {
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

test.after(() => {
  fs.rmSync(path.join(RUNS_DIR, RUN_ID), { recursive: true, force: true });
});

test("writes the durable artifact at runs/<run>/assessments/<agent>.json", async () => {
  const a = assessment();
  const r = await sendAssessment(a, {
    runId: RUN_ID,
    agentId: CTX.agentId,
    transport: "file",
  });
  assert.equal(r.ok, true);
  assert.equal(r.path, path.join(RUNS_DIR, RUN_ID, "assessments", `${CTX.agentId}.json`));
  assert.deepEqual(readJson(r.path), a);
});

test("addresses the coordinator directly and never a channel", async () => {
  const seen = [];
  const r = await sendAssessment(assessment(), {
    runId: RUN_ID,
    agentId: CTX.agentId,
    transport: {
      name: "test",
      sendDm: (payload, to) => {
        seen.push({ payload, to });
      },
    },
  });
  assert.equal(r.ok, true);
  assert.equal(r.transport, "test");
  assert.equal(r.to, COORDINATOR);
  assert.equal(r.broadcast, false);
  assert.equal(seen.length, 1);
  assert.equal(seen[0].to, "coordinator");
  assert.equal(seen[0].payload.verdict, "malicious");
  assert.equal(seen[0].payload.incident_id, CTX.incidentId);
});

test("a transport failure degrades to the file drop and never loses the assessment", async () => {
  const r = await sendAssessment(assessment(), {
    runId: RUN_ID,
    agentId: CTX.agentId,
    transport: {
      name: "boom",
      sendDm: () => {
        throw new Error("mesh down");
      },
    },
  });
  assert.equal(r.ok, true);
  assert.equal(r.transport, "file");
  assert.ok(r.errors.some((e) => e.includes("mesh down")));
  assert.ok(fs.existsSync(r.path));
});

test("auto mode never throws when Cotal is absent", async () => {
  const r = await sendAssessment(assessment(), {
    runId: RUN_ID,
    agentId: CTX.agentId,
    transport: "auto",
  });
  assert.equal(r.ok, true);
  assert.ok(fs.existsSync(r.path));
  assert.equal(r.broadcast, false);
});

test("dm.js contains no channel-publish path at all", () => {
  // Structural assertion: the security property is "there is no code that can
  // broadcast", which a behavioural test cannot prove. Guard the source instead.
  const src = fs.readFileSync(new URL("../src/dm.js", import.meta.url), "utf8");
  const code = src
    .split("\n")
    .filter((l) => !l.trimStart().startsWith("//") && !l.trimStart().startsWith("*"))
    .join("\n");
  assert.ok(!/sec\.incident/.test(code), "dm.js must not reference sec.incident in code");
  assert.ok(!/sec\.deliberate/.test(code), "dm.js must not reference sec.deliberate in code");
  assert.ok(!/\bpublish\s*\(/.test(code), "dm.js must not call a publish() method");
  assert.ok(!/broadcast\s*\(/.test(code), "dm.js must not call a broadcast() method");
});
