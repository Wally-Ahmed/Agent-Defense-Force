import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { extractUsage } from "../src/usage.js";
import { CODEX_TURN_COMPLETED, CLAUDE_RESULT } from "./fixtures.js";

test("codex: reads a REAL turn.completed usage block", () => {
  const raw = [
    '{"type":"thread.started","thread_id":"t1"}',
    '{"type":"item.completed","item":{"type":"agent_message","text":"PONG"}}',
    CODEX_TURN_COMPLETED,
  ].join("\n");
  const u = extractUsage("codex", { rawText: raw });
  assert.deepEqual(
    { in: u.in, out: u.out, reasoning: u.reasoning, reported: u.reported },
    { in: 17832, out: 6, reasoning: 0, reported: true },
  );
});

test("codex: cached_input_tokens is not double-counted into `in`", () => {
  const raw =
    '{"type":"turn.completed","usage":{"input_tokens":1000,"cached_input_tokens":800,' +
    '"output_tokens":50,"reasoning_output_tokens":40}}';
  const u = extractUsage("codex", raw);
  assert.equal(u.in, 1000);
  assert.equal(u.reasoning, 40);
});

test("codex: the LAST turn.completed wins on a multi-turn run", () => {
  const raw = [
    '{"type":"turn.completed","usage":{"input_tokens":10,"output_tokens":1,"reasoning_output_tokens":0}}',
    '{"type":"turn.completed","usage":{"input_tokens":99,"output_tokens":9,"reasoning_output_tokens":3}}',
  ].join("\n");
  const u = extractUsage("codex", raw);
  assert.equal(u.in, 99);
  assert.equal(u.out, 9);
});

test("claude: reads a REAL stream-json result usage block, cache buckets included", () => {
  const u = extractUsage("claude_code", { rawText: CLAUDE_RESULT });
  // 16 fresh + 21513 cache-creation + 43250 cache-read = every token consumed.
  assert.equal(u.in, 64779);
  assert.equal(u.out, 129);
  assert.equal(u.reasoning, 0);
  assert.equal(u.reported, true);
});

test("agy and hermes report nothing, and say so instead of guessing", () => {
  for (const rt of ["agy", "hermes"]) {
    const u = extractUsage(rt, { rawText: "some pty output\nwith no telemetry\n" });
    assert.deepEqual({ in: u.in, out: u.out, reasoning: u.reasoning }, { in: 0, out: 0, reasoning: 0 });
    assert.equal(u.reported, false);
    assert.match(u.source, /reports no token counts/);
  }
});

test("opencode returns zeros with reported:false when no usage event exists", () => {
  const u = extractUsage("opencode", { rawText: "plain opencode log output\n" });
  assert.equal(u.reported, false);
  assert.equal(u.in + u.out + u.reasoning, 0);
});

test("opencode picks up a usage-bearing event when one is present", () => {
  const raw = '{"type":"step.finish","usage":{"input_tokens":120,"output_tokens":34}}';
  const u = extractUsage("opencode", raw);
  assert.equal(u.reported, true);
  assert.equal(u.in, 120);
  assert.equal(u.out, 34);
});

test("a truncated or absent transcript yields zeros, never a crash", () => {
  assert.equal(extractUsage("codex", { rawText: '{"type":"turn.compl' }).reported, false);
  assert.equal(extractUsage("codex", { spool: { raw: "/nonexistent/x.raw" } }).reported, false);
  assert.equal(extractUsage("unknown_runtime", "").reported, false);
});

test("reads the transcript off a tap result's spool path", () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "ar-usage-"));
  const raw = path.join(dir, "responder_codex.raw");
  fs.writeFileSync(raw, CODEX_TURN_COMPLETED + "\n");
  try {
    const u = extractUsage("codex", { spool: { raw } });
    assert.equal(u.in, 17832);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
