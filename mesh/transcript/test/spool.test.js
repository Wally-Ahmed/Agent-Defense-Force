// spool.test.js — spool-on-publish-failure and failure isolation.
//
// The contract under test: losing chat output must never lose an assessment.
// Every frame reaches disk BEFORE the sink is asked to publish it, publish()
// never throws to the caller, and a run whose sink is entirely dead still
// produces a complete, replayable transcript and the child's real exit code.

import { test, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

// --- isolation --------------------------------------------------------------
// runsDir() is resolved lazily per call, so setting this before the first
// runTap/Spool call is sufficient; nothing lands in the repo's real runs/.
const RUNS = fs.mkdtempSync(path.join(os.tmpdir(), "tap-spool-"));
process.env.TRANSCRIPT_RUNS_DIR = RUNS;
process.env.TRANSCRIPT_SINK = "file";
process.env.TRANSCRIPT_REDACT_ENV = "0";
delete process.env.TRANSCRIPT_MAX_CHAT_BYTES;
delete process.env.TRANSCRIPT_CHUNK_BYTES;
// No Cotal identity => createCotalSink() degrades to a broken sink instead of
// dialling a real mesh. Deleting these makes the test independent of the host.
for (const k of Object.keys(process.env)) if (k.startsWith("COTAL_")) delete process.env[k];

import { runTap } from "../src/tap.js";
import { readSpool, runsDir, transcriptPaths } from "../src/spool.js";
import { KIND, Sequencer, makeFrame } from "../src/frame.js";
import { PublishQueue } from "../src/sinks/index.js";
import { createFileSink, brokenSink } from "../src/sinks/file.js";
import { channelFor, loadChannelFn } from "../src/adapters/common.js";

await loadChannelFn();

after(() => fs.rmSync(RUNS, { recursive: true, force: true }));

function shAdapter(script) {
  return {
    runtime: "fake",
    cli: "sh",
    capturePoint: "pipe",
    channel: channelFor,
    async build({ cwd }) {
      return { command: "/bin/sh", args: ["-c", script], env: process.env, cwd, pty: false };
    },
    render: null,
  };
}

const N = 50;
const LINES = Array.from({ length: N }, (_, i) => `SPOOLED-${String(i + 1).padStart(3, "0")}`);
const EXIT_CODE = 5;

/**
 * One shared run whose sink is dead for the whole invocation: TRANSCRIPT_SINK
 * is "cotal" and there is no Cotal identity in the environment, so
 * createCotalSink() returns brokenSink() and not one frame is ever delivered.
 * Memoised so the tests below all inspect the same on-disk artefacts.
 */
let brokenRun = null;
function runWithBrokenSink() {
  if (brokenRun) return brokenRun;
  brokenRun = (async () => {
    const prev = process.env.TRANSCRIPT_SINK;
    process.env.TRANSCRIPT_SINK = "cotal";
    try {
      return await runTap({
        agentId: "responder_claude",
        adapter: shAdapter(
          `i=1; while [ $i -le ${N} ]; do printf 'SPOOLED-%03d\\n' "$i"; i=$((i+1)); done; exit ${EXIT_CODE}`,
        ),
        prompt: "p",
        runId: "run-broken-sink",
        incidentId: "incident-broken",
      });
    } finally {
      if (prev === undefined) delete process.env.TRANSCRIPT_SINK;
      else process.env.TRANSCRIPT_SINK = prev;
    }
  })();
  return brokenRun;
}

// --- 0. isolation guard ------------------------------------------------------
test("tests are pointed at a throwaway runs dir, not the repo's", () => {
  assert.equal(runsDir(), RUNS);
  assert.ok(transcriptPaths("r", "monitor").log.startsWith(RUNS + path.sep));
});

// --- 1. a throwing sink never reaches the caller -----------------------------
test("PublishQueue swallows every publish failure and records it", async () => {
  const ctx = {
    run_id: "run-queue",
    incident_id: "incident-queue",
    agent_id: "monitor",
    runtime: "fake",
    channel: "tr-monitor",
  };

  let attempts = 0;
  const exploding = {
    name: "exploding",
    target: "/dev/null",
    ready: true,
    async publish() {
      attempts += 1;
      throw new Error("sink exploded");
    },
    async close() {},
  };

  const queue = new PublishQueue([exploding], ctx);
  const reported = [];
  queue.onError = (msg) => reported.push(msg);

  const seq = new Sequencer();
  const frames = Array.from({ length: 7 }, (_, i) =>
    makeFrame(ctx, { kind: KIND.CHUNK, seq: seq.next(), stream: "stdout", text: `line ${i}` }),
  );

  for (const f of frames) {
    assert.doesNotThrow(() => queue.publish(f), "publish() must never throw to the caller");
  }
  const { undelivered } = await queue.close();

  assert.equal(attempts, frames.length, "every frame was offered to the sink");
  assert.equal(queue.stats.failed, frames.length);
  assert.equal(queue.stats.published, 0);
  assert.equal(undelivered, 0, "the queue drained despite every publish failing");
  assert.ok(queue.errors.length > 0, "queue.errors is empty");
  assert.ok(queue.errors.length <= 20, "errors list is capped");
  assert.match(queue.errors[0], /exploding publish failed at seq 1: sink exploded/);
  assert.equal(reported.length, frames.length, "onError fired once per failure");

  // An error reporter that itself throws must not take the run down either.
  const queue2 = new PublishQueue([exploding], ctx);
  queue2.onError = () => {
    throw new Error("reporter exploded");
  };
  assert.doesNotThrow(() => queue2.publish(frames[0]));
  await queue2.close();
  assert.equal(queue2.stats.failed, 1);

  // A sink that reports itself unavailable is skipped, not retried.
  const queue3 = new PublishQueue([brokenSink("cotal", "no identity")], ctx);
  queue3.publish(frames[0]);
  await queue3.close();
  assert.equal(queue3.stats.failed, 0);
  assert.equal(queue3.stats.published, 0);
  assert.match(queue3.description, /unavailable/);
});

// --- 2. end to end: a dead sink still yields a complete spool -----------------
test("a run with a dead sink keeps its exit code and its whole transcript", async () => {
  const res = await runWithBrokenSink();

  // Guard: if the sink were somehow live, this test would prove nothing.
  assert.match(
    String(res.sink),
    /unavailable/,
    `expected a broken cotal sink, got: ${res.sink}`,
  );

  assert.equal(res.exitCode, EXIT_CODE, "the child's real exit code must survive");
  assert.equal(res.ok, false);
  assert.equal(res.timedOut, false);

  const frames = readSpool(res.spool.log);
  assert.equal(frames[0].kind, KIND.START, "no START frame");
  assert.equal(frames.at(-1).kind, KIND.EXIT, "no EXIT frame");
  assert.deepEqual(
    frames.map((f) => f.seq),
    Array.from({ length: frames.length }, (_, i) => i + 1),
    "spool has a sequence gap",
  );

  const joined = frames
    .filter((f) => f.kind === KIND.CHUNK)
    .map((f) => f.text)
    .join("\n");
  let cursor = 0;
  for (const line of LINES) {
    const at = joined.indexOf(line, cursor);
    assert.ok(at !== -1, `${line} lost when the sink was dead`);
    cursor = at + line.length;
  }

  // Nothing was delivered, and that failure is visible in the run's stats.
  assert.equal(res.stats.sink.published, 0, "a broken sink must not report deliveries");
  assert.equal(res.stats.frames, frames.length, "spool stats disagree with the spool file");
});

// --- 3. the spool is write-ahead --------------------------------------------
test("both spool files exist and .raw holds the harness's exact stdout lines", async () => {
  const res = await runWithBrokenSink();

  for (const p of [res.spool.log, res.spool.raw]) {
    assert.ok(fs.existsSync(p), `missing ${p}`);
    assert.ok(fs.statSync(p).size > 0, `${p} is empty`);
  }

  const raw = fs.readFileSync(res.spool.raw, "utf8");
  const rawLines = raw.split("\n");
  assert.equal(rawLines.at(-1), "", ".raw should end with a newline");
  assert.deepEqual(rawLines.slice(0, -1), LINES, ".raw is not byte-faithful");

  // The envelope spool is NDJSON: one parseable frame per line, nothing partial.
  const logLines = fs.readFileSync(res.spool.log, "utf8").split("\n").filter(Boolean);
  assert.equal(logLines.length, readSpool(res.spool.log).length);
  for (const line of logLines) assert.doesNotThrow(() => JSON.parse(line));
});

// --- 4. readSpool tolerates a torn final line --------------------------------
test("readSpool skips a torn final line instead of throwing", async () => {
  const res = await runWithBrokenSink();
  const intact = readSpool(res.spool.log);
  assert.ok(intact.length > 2);

  // Copy first: the shared run's artefacts are read by other tests.
  const torn = path.join(RUNS, "torn.log");
  fs.copyFileSync(res.spool.log, torn);
  fs.appendFileSync(torn, `{"v":1,"kind":"transcript.chu`);

  let frames;
  assert.doesNotThrow(() => {
    frames = readSpool(torn);
  }, "readSpool threw on a torn tail");
  assert.deepEqual(frames, intact, "a torn tail cost us an earlier frame");

  // Garbage in the middle is survivable too, and a missing file is empty.
  const dirty = path.join(RUNS, "dirty.log");
  const lines = fs.readFileSync(res.spool.log, "utf8").split("\n").filter(Boolean);
  fs.writeFileSync(dirty, [lines[0], "{not json at all", ...lines.slice(1)].join("\n") + "\n");
  assert.equal(readSpool(dirty).length, intact.length);
  assert.deepEqual(readSpool(path.join(RUNS, "does-not-exist.log")), []);
});

// --- 5. replay ---------------------------------------------------------------
test("a spool from a dead-sink run replays into a working file sink", async () => {
  const res = await runWithBrokenSink();
  const frames = readSpool(res.spool.log);
  assert.ok(frames.length > 2);

  const ctx = {
    run_id: "run-replay",
    incident_id: frames[0].incident_id,
    agent_id: frames[0].agent_id,
    runtime: frames[0].runtime,
    channel: channelFor(frames[0].agent_id),
  };

  const sink = createFileSink(ctx);
  assert.equal(sink.ready, true, `file sink not ready: ${sink.brokenReason}`);
  for (const f of frames) await sink.publish(f);
  await sink.close();

  const text = fs.readFileSync(sink.target, "utf8");
  assert.ok(sink.target.startsWith(path.join(RUNS, "run-replay") + path.sep), sink.target);

  const all = text.split("\n").filter((l) => l !== "");
  const heads = all.filter((l) => l.startsWith("["));
  assert.equal(heads.length, frames.length, "one rendered block per frame");
  for (const l of all) {
    if (!l.startsWith("[")) {
      assert.ok(l.startsWith("    "), `stray unattributed line: ${JSON.stringify(l)}`);
    }
  }

  // Rendered order is spool order, and every seq survived the replay.
  const seqs = heads.map((l) => Number(l.match(/· #(\d{6}) ·/)[1]));
  assert.deepEqual(seqs, frames.map((f) => f.seq), "replay reordered the transcript");
  for (let i = 1; i < seqs.length; i++) assert.ok(seqs[i] > seqs[i - 1]);

  // The payload made it through the round trip.
  for (const line of LINES) assert.ok(text.includes(line), `${line} lost in replay`);
});

// --- 6. non-zero exit and stderr are reported --------------------------------
test("a harness that writes to stderr and exits 42 is reported faithfully", async () => {
  const res = await runTap({
    agentId: "responder_codex",
    adapter: shAdapter("printf 'fatal: the harness gave up\\n' >&2; exit 42"),
    prompt: "p",
    runId: "run-exit42",
    incidentId: "incident-exit42",
  });

  assert.equal(res.exitCode, 42);
  assert.equal(res.ok, false);
  assert.equal(res.signal, null);
  assert.equal(res.timedOut, false);

  const frames = readSpool(res.spool.log);
  const exit = frames.at(-1);
  assert.equal(exit.kind, KIND.EXIT);
  assert.equal(exit.extra.exit_code, 42);
  assert.equal(exit.extra.timed_out, false);
  assert.equal(exit.extra.truncated, false);
  assert.match(exit.text, /exit code=42/);

  const stderr = frames.filter((f) => f.kind === KIND.CHUNK && f.stream === "stderr");
  assert.ok(
    stderr.some((f) => f.text.includes("fatal: the harness gave up")),
    "stderr output missing from the spool",
  );
});
