// mock.js — the recorded-transcript responder, for agents that are BLOCKED.
//
// As of 2026-07-26 NO agent is blocked: all six reach their pinned model live.
// The earlier note here — that the monitor on hermes and both opencode
// responders were stuck because OPENROUTER_API_KEY was "present as a name but
// empty" and `opencode auth list` showed no credentials — was a misdiagnosis.
// The key was in the repo-root .env, valid, and nothing in mesh/ had ever loaded
// it (see mesh/lib/env.js); opencode reads the provider key straight from its
// inherited environment and never needed a stored credential at all.
//
// This module stays because a harness CAN break at any time — a revoked key, an
// offline laptop, a CLI that stops shipping. A blocked agent still has to produce
// something the coordinator can count, or the mesh cannot be demonstrated at all.
//
// THE INVARIANT THAT MAKES THIS SAFE: a mock is not a shortcut past the gate.
// This module does not build an assessment object — it hands the recorded reply
// back as TEXT and lets run.js push it through the identical parse + validate
// path a live reply takes. So a recorded transcript can never be accepted on
// terms a live model would be rejected on, and a schema change breaks the mocks
// exactly as loudly as it breaks the live agents.
//
// A mock is never silent: run.js stamps `mocked: true` on the effort receipt and
// the CLI prints it. Recorded output is a labeled presentation fallback, and it
// never satisfies a live-run acceptance test.

import fs from "node:fs";
import path from "node:path";
import { REPO_ROOT } from "../../lib/paths.js";

export const MOCK_DIR = path.join(REPO_ROOT, "coordinator", "mocks", "transcripts");

export function mockPath(agentId, dir = MOCK_DIR) {
  return path.join(dir, `${agentId}.json`);
}

export function hasMock(agentId, dir = MOCK_DIR) {
  return fs.existsSync(mockPath(agentId, dir));
}

/**
 * Load one recorded transcript file.
 * @returns {{transcript_version:number, responder:string, recorded_at_ms:number,
 *            scenario:string, assessment:object}}
 */
export function loadMockTranscript(agentId, dir = MOCK_DIR) {
  const file = mockPath(agentId, dir);
  let doc;
  try {
    doc = JSON.parse(fs.readFileSync(file, "utf8"));
  } catch (err) {
    throw new Error(`no usable recorded transcript for "${agentId}" at ${file}: ${err.message}`);
  }
  if (!doc || typeof doc !== "object" || !doc.assessment) {
    throw new Error(`recorded transcript ${file} has no "assessment" object`);
  }
  if (doc.responder && doc.responder !== agentId) {
    throw new Error(
      `recorded transcript ${file} is for "${doc.responder}", not "${agentId}" — refusing to speak for another responder`,
    );
  }
  return doc;
}

/**
 * The recorded reply, rendered as the text a live harness would have printed.
 *
 * incident_id is rewritten to the LIVE incident so the coordinator's join works;
 * every other field is the recording verbatim. run.js overwrites the identity
 * and usage fields anyway on the way through parse.js.
 */
export function mockRawText(agentId, incident, dir = MOCK_DIR) {
  const doc = loadMockTranscript(agentId, dir);
  const assessment = { ...doc.assessment };
  if (incident?.incident_id) assessment.incident_id = incident.incident_id;
  return (
    `[recorded transcript ${agentId} · recorded_at_ms=${doc.recorded_at_ms ?? "?"} · ` +
    `scenario=${JSON.stringify(doc.scenario ?? "")}]\n` +
    "```json\n" +
    JSON.stringify(assessment, null, 2) +
    "\n```\n"
  );
}

/**
 * Token counts from the recording. Flagged `reported: false` because nothing was
 * measured in THIS run — they are a replay of a past measurement, and the run
 * report must be able to say so.
 */
export function mockUsage(agentId, dir = MOCK_DIR) {
  const u = loadMockTranscript(agentId, dir).assessment?.usage ?? {};
  return {
    in: Number(u.in) || 0,
    out: Number(u.out) || 0,
    reasoning: Number(u.reasoning) || 0,
    reported: false,
    source: "recorded transcript — replayed token counts, not measured this run",
  };
}
