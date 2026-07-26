// ordering.test.js — ordering and attribution under interleaved writers.
//
// The mesh's readability claim rests on four fields being present on EVERY
// chunk (agent id, incident id, monotonic sequence, timestamp) and on the
// sequence being dense: a gap is proof of loss, not of reordering. These tests
// drive real child processes through the tap and check that claim from the
// spool outwards.
//
// Nothing here runs a real AI CLI — every "harness" is /bin/sh.

import { test, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

// ---------------------------------------------------------------------------
// Isolation. TRANSCRIPT_RUNS_DIR is resolved lazily by spool.js (runsDir() is
// called per transcriptPaths()/createFileSink() call, never at module load), so
// setting it here — before the first runTap/Spool call — keeps every byte these
// tests write inside a throwaway directory. The repo's real runs/ is never
// touched. `assert.equal(runsDir(), RUNS)` below verifies that laziness.
// ---------------------------------------------------------------------------
const RUNS = fs.mkdtempSync(path.join(os.tmpdir(), "tap-ordering-"));
process.env.TRANSCRIPT_RUNS_DIR = RUNS;
process.env.TRANSCRIPT_SINK = "file";
// Host env must not perturb byte-exact assertions: a machine-local secret whose
// literal value happened to appear in generated output would be rewritten.
process.env.TRANSCRIPT_REDACT_ENV = "0";
delete process.env.TRANSCRIPT_MAX_CHAT_BYTES;
delete process.env.TRANSCRIPT_CHUNK_BYTES;
delete process.env.TRANSCRIPT_KEEP_ANSI;

import { runTap } from "../src/tap.js";
import { readSpool, transcriptPaths, runsDir } from "../src/spool.js";
import { KIND, makeFrame, renderChat, shortIncident } from "../src/frame.js";
import { channelFor, loadChannelFn } from "../src/adapters/common.js";

await loadChannelFn();

after(() => fs.rmSync(RUNS, { recursive: true, force: true }));

/** A fake harness: /bin/sh running `script`, never a real AI CLI. */
function shAdapter(script, { pty = false } = {}) {
  return {
    runtime: "fake",
    cli: "sh",
    capturePoint: "pipe",
    channel: channelFor,
    async build({ cwd }) {
      return { command: "/bin/sh", args: ["-c", script], env: process.env, cwd, pty };
    },
    render: null,
  };
}

/** POSIX-sh loop emitting `count` lines of `printf` format `fmt` (gets %03d). */
const emitLines = (fmt, count) =>
  `i=1; while [ $i -le ${count} ]; do printf '${fmt}\\n' "$i"; i=$((i+1)); done`;

const chunkText = (frames) =>
  frames.filter((f) => f.kind === KIND.CHUNK).map((f) => f.text).join("\n");

/** Assert seq is exactly 1..frames.length with no gaps and no duplicates. */
function assertDenseSeq(frames, label) {
  assert.ok(frames.length > 0, `${label}: no frames`);
  const seqs = frames.map((f) => f.seq);
  assert.deepEqual(
    seqs,
    Array.from({ length: frames.length }, (_, i) => i + 1),
    `${label}: seq is not the dense run 1..${frames.length} (got ${seqs.join(",")})`,
  );
  assert.equal(new Set(seqs).size, seqs.length, `${label}: duplicate seq`);
}

// --- 0. the isolation itself -------------------------------------------------
test("tests are pointed at a throwaway runs dir, not the repo's", () => {
  assert.equal(runsDir(), RUNS);
  const p = transcriptPaths("run-x", "monitor");
  assert.ok(p.log.startsWith(RUNS + path.sep), p.log);
  assert.ok(!p.log.includes(`${path.sep}JacHacksSF-2026${path.sep}runs${path.sep}`), p.log);
});

// --- 1. dense monotonic sequence, single tap ---------------------------------
test("200 fast lines produce a dense, monotonic, fully attributed transcript", async () => {
  const N = 200;
  const res = await runTap({
    agentId: "monitor",
    adapter: shAdapter(emitLines("L%03d payload alpha", N)),
    prompt: "ignored by the fake harness",
    runId: "run-dense",
    incidentId: "incident-dense",
  });

  assert.equal(res.exitCode, 0, JSON.stringify(res.stats));
  const frames = readSpool(res.spool.log);

  assertDenseSeq(frames, "dense run");
  assert.equal(frames.length, res.frames, "spooled frame count != tap frame count");
  assert.equal(frames[0].kind, KIND.START);
  assert.equal(frames.at(-1).kind, KIND.EXIT);

  // mono_ms is the ordering tiebreaker — it may never go backwards.
  for (let i = 1; i < frames.length; i++) {
    assert.ok(
      frames[i].mono_ms >= frames[i - 1].mono_ms,
      `mono_ms went backwards at seq ${frames[i].seq}: ` +
        `${frames[i - 1].mono_ms} -> ${frames[i].mono_ms}`,
    );
  }

  for (const f of frames) {
    assert.equal(f.agent_id, "monitor");
    assert.equal(f.incident_id, "incident-dense");
    assert.equal(f.run_id, "run-dense");
    assert.ok(f.agent_id && f.incident_id && f.run_id, `empty attribution at seq ${f.seq}`);
    assert.equal(typeof f.ts, "string");
    assert.equal(new Date(f.ts).toISOString(), f.ts, `ts is not ISO-8601: ${f.ts}`);
    assert.equal(typeof f.seq, "number");
  }
});

// --- 2. payload completeness -------------------------------------------------
test("every emitted line survives coalescing, in order", async () => {
  const N = 200;
  const res = await runTap({
    agentId: "monitor",
    adapter: shAdapter(emitLines("L%03d payload alpha", N)),
    prompt: "p",
    runId: "run-payload",
    incidentId: "incident-payload",
  });

  const frames = readSpool(res.spool.log);
  // Lines are coalesced into multi-line chunks, so completeness is a property
  // of the joined text, not of any one frame.
  const joined = chunkText(frames);

  let cursor = 0;
  for (let i = 1; i <= N; i++) {
    const needle = `L${String(i).padStart(3, "0")} payload alpha`;
    const at = joined.indexOf(needle, cursor);
    assert.ok(at !== -1, `line ${i} ("${needle}") missing or out of order`);
    cursor = at + needle.length;
  }

  // And the raw spool is byte-faithful for the same 200 lines.
  const raw = fs.readFileSync(res.spool.raw, "utf8");
  assert.equal(
    raw.split("\n").filter((l) => l.startsWith("L")).length,
    N,
    "raw spool line count",
  );
});

// --- 3. five interleaved writers stay attributable ---------------------------
test("five concurrent taps never cross-contaminate spool or chat", async () => {
  const AGENTS = [
    "monitor",
    "responder_claude",
    "responder_codex",
    "responder_kimi",
    "responder_glm",
  ];
  const N = 50;
  const runId = "run-interleaved";
  const incidentId = "incident-interleaved";

  const results = await Promise.all(
    AGENTS.map((agentId) =>
      runTap({
        agentId,
        adapter: shAdapter(emitLines(`MARK-${agentId}-%03d`, N)),
        prompt: "p",
        runId,
        incidentId,
      }),
    ),
  );

  const seen = new Set();
  for (const [i, res] of results.entries()) {
    const agentId = AGENTS[i];
    assert.equal(res.exitCode, 0);

    // Each agent gets its own spool file.
    assert.equal(res.spool.log, transcriptPaths(runId, agentId).log);
    assert.ok(!seen.has(res.spool.log), `spool file reused by two agents: ${res.spool.log}`);
    seen.add(res.spool.log);

    const frames = readSpool(res.spool.log);
    assertDenseSeq(frames, agentId);
    for (const f of frames) assert.equal(f.agent_id, agentId);

    const joined = chunkText(frames);
    for (let n = 1; n <= N; n++) {
      assert.ok(
        joined.includes(`MARK-${agentId}-${String(n).padStart(3, "0")}`),
        `${agentId}: marker ${n} missing`,
      );
    }
    // No other agent's marker text appears anywhere in this agent's spool.
    const wholeFile = fs.readFileSync(res.spool.log, "utf8");
    for (const other of AGENTS) {
      if (other === agentId) continue;
      assert.ok(
        !wholeFile.includes(`MARK-${other}-`),
        `${agentId} spool contains ${other}'s marker text`,
      );
    }
  }

  // --- the file sink: five separate chat files, each self-attributing --------
  const chatDir = path.join(RUNS, runId, "chat");
  const chatFiles = fs.readdirSync(chatDir).sort();
  assert.equal(chatFiles.length, AGENTS.length, chatFiles.join(","));

  for (const [i, res] of results.entries()) {
    const agentId = AGENTS[i];
    const file = path.join(chatDir, `${channelFor(agentId)}.txt`);
    assert.ok(fs.existsSync(file), `missing chat file ${file}`);

    const lines = fs.readFileSync(file, "utf8").split("\n").filter((l) => l !== "");
    let heads = 0;
    for (const line of lines) {
      if (line.startsWith("[")) {
        heads += 1;
        // The prefix carries this agent's id and nobody else's.
        assert.ok(
          line.startsWith(`[${agentId} · `),
          `${agentId} chat line lacks its own prefix: ${line.slice(0, 60)}`,
        );
        for (const other of AGENTS) {
          if (other === agentId) continue;
          assert.ok(
            !line.startsWith(`[${other} · `),
            `${agentId} chat file carries a ${other} prefix`,
          );
        }
      } else {
        // The only other legal shape is a 4-space continuation of the block
        // above it (frame.js indents multi-line bodies so an interleaved
        // reader can tell them apart). Anything else is an unattributed line.
        assert.ok(
          line.startsWith("    "),
          `${agentId}: line is neither prefixed nor an indented continuation: ${JSON.stringify(line)}`,
        );
      }
    }
    assert.equal(
      heads,
      readSpool(res.spool.log).length,
      `${agentId}: one rendered block per frame`,
    );

    const text = fs.readFileSync(file, "utf8");
    for (const other of AGENTS) {
      if (other === agentId) continue;
      assert.ok(!text.includes(`MARK-${other}-`), `${agentId} chat file leaked ${other} output`);
    }
  }
});

// --- 4. renderChat carries all four attribution fields -----------------------
test("renderChat prefixes agent, short incident, padded seq and time", () => {
  const ctx = {
    run_id: "run-render",
    incident_id: "incident-abcdefghijklmnopqrstuvwxyz",
    agent_id: "responder_antigravity",
    runtime: "fake",
    channel: "tr-responder_antigravity",
  };
  const frame = makeFrame(ctx, {
    kind: KIND.CHUNK,
    seq: 42,
    stream: "stdout",
    text: "first line\nsecond line\nthird line",
  });

  const rendered = renderChat(frame);
  const lines = rendered.split("\n");

  const m = lines[0].match(/^\[([^\]]*)\] /);
  assert.ok(m, `no bracketed prefix in: ${lines[0]}`);
  const [agent, incident, seq, time] = m[1].split(" · ");

  assert.equal(agent, "responder_antigravity");

  // shortIncident() is a head-and-tail elision, not a left-truncation: real
  // incident ids are date-prefixed, so cutting from the left alone would render
  // every incident raised on the same day identically. That form is 13 chars.
  assert.ok(incident.length <= 13, `incident form is ${incident.length} chars: ${incident}`);
  assert.equal(incident, shortIncident(ctx.incident_id));
  assert.ok(incident.length < ctx.incident_id.length, "incident id was not shortened");
  assert.ok(incident.startsWith("inci"), `elision lost the id's head: ${incident}`);
  assert.ok(incident.endsWith("stuvwxyz"), `elision lost the id's tail: ${incident}`);
  assert.ok(!lines[0].includes(ctx.incident_id), "full incident id leaked into the prefix");
  // The point of keeping the tail: two same-day ids must not collapse together.
  assert.notEqual(
    shortIncident("inc-2026-07-26-0001"),
    shortIncident("inc-2026-07-26-0002"),
    "two incidents from the same day render the same short form",
  );

  assert.equal(seq, "#000042");
  assert.match(seq, /^#\d{6}$/);
  assert.match(time, /^\d{2}:\d{2}:\d{2}\.\d{3}Z$/);

  // A multi-line body indents continuation lines by exactly 4 spaces, so the
  // whole block reads as one unit and cannot be mistaken for another agent's
  // interleaved output.
  assert.equal(lines.length, 3);
  assert.ok(lines[0].endsWith("first line"), lines[0]);
  assert.equal(lines[1], "    second line");
  assert.equal(lines[2], "    third line");
  for (const l of lines.slice(1)) {
    assert.ok(l.startsWith("    ") && !l.startsWith("     "), JSON.stringify(l));
    assert.ok(!l.startsWith("["), "continuation line must not look like a new block");
  }
});

// --- 5. stderr vs stdout are distinguished and never merged ------------------
test("stdout and stderr get distinct frames and never share one chunk", async () => {
  const script = [
    "printf 'OUTMARKER-1\\nOUTMARKER-2\\n'",
    "printf 'ERRMARKER-1\\nERRMARKER-2\\n' >&2",
    "printf 'OUTMARKER-3\\n'",
  ].join("; ");

  const res = await runTap({
    agentId: "responder_glm",
    adapter: shAdapter(script),
    prompt: "p",
    runId: "run-streams",
    incidentId: "incident-streams",
  });

  const chunks = readSpool(res.spool.log).filter((f) => f.kind === KIND.CHUNK);
  assert.ok(chunks.length >= 2, `expected >=2 chunks, got ${chunks.length}`);

  const out = chunks.filter((f) => f.stream === "stdout");
  const err = chunks.filter((f) => f.stream === "stderr");
  assert.ok(out.length >= 1, "no stdout frame");
  assert.ok(err.length >= 1, "no stderr frame");
  assert.ok(out.some((f) => f.text.includes("OUTMARKER-1")), "stdout payload missing");
  assert.ok(err.some((f) => f.text.includes("ERRMARKER-1")), "stderr payload missing");

  for (const f of chunks) {
    // The coalescer flushes on a stream change, so no single frame may ever
    // carry both streams' text. (Only CHUNK frames are captured output; the
    // START banner legitimately echoes the whole argv, markers included.)
    const hasOut = f.text.includes("OUTMARKER");
    const hasErr = f.text.includes("ERRMARKER");
    assert.ok(!(hasOut && hasErr), `seq ${f.seq} merged stdout and stderr: ${f.text}`);
    if (f.stream === "stdout") assert.ok(!hasErr, `stdout frame ${f.seq} carries stderr text`);
    if (f.stream === "stderr") assert.ok(!hasOut, `stderr frame ${f.seq} carries stdout text`);
  }

  // Both marker sets are complete across the transcript.
  const all = chunks.map((f) => f.text).join("\n");
  for (const n of [1, 2, 3]) assert.ok(all.includes(`OUTMARKER-${n}`), `OUTMARKER-${n}`);
  for (const n of [1, 2]) assert.ok(all.includes(`ERRMARKER-${n}`), `ERRMARKER-${n}`);
});

// --- 6. an oversized line is SPLIT, never truncated --------------------------
test("a 5000-char line is split into sequenced parts with no bytes lost", async () => {
  const UNIT = "abcdefghij";
  const REPS = 500;
  const expected = UNIT.repeat(REPS); // 5000 chars, nothing a redactor matches
  assert.equal(expected.length, 5000);

  // Build the line in the shell so the START banner's argv stays small.
  // `${s}` must be braced: unbraced, the shell would read `$sabcdefghij` as one
  // (unset) variable name and print an empty line.
  const script =
    `i=0; s=""; while [ $i -lt ${REPS} ]; do s="\${s}${UNIT}"; i=$((i+1)); done; printf '%s\\n' "$s"`;

  const prev = process.env.TRANSCRIPT_CHUNK_BYTES;
  process.env.TRANSCRIPT_CHUNK_BYTES = "200";
  let res;
  try {
    res = await runTap({
      agentId: "responder_kimi",
      adapter: shAdapter(script),
      prompt: "p",
      runId: "run-split",
      incidentId: "incident-split",
    });
  } finally {
    if (prev === undefined) delete process.env.TRANSCRIPT_CHUNK_BYTES;
    else process.env.TRANSCRIPT_CHUNK_BYTES = prev;
  }

  assert.equal(res.exitCode, 0);
  assert.equal(res.truncated, false, "an oversized line must never set truncated");

  const frames = readSpool(res.spool.log);
  assertDenseSeq(frames, "split run");

  const parts = frames.filter((f) => typeof f.part === "string");
  assert.ok(parts.length > 1, `expected multiple parts, got ${parts.length}`);

  const total = Number(parts[0].part.split("/")[1]);
  assert.equal(parts.length, total, `part denominator ${total} != parts found ${parts.length}`);
  parts.forEach((f, i) => {
    assert.match(f.part, /^\d+\/\d+$/, `bad part field: ${f.part}`);
    assert.equal(f.part, `${i + 1}/${total}`, `parts are out of order at index ${i}`);
    assert.equal(f.kind, KIND.CHUNK);
    assert.equal(f.stream, "stdout");
    assert.ok(Buffer.byteLength(f.text) <= 200, `part ${f.part} exceeds the 200-byte cap`);
  });

  // seq order must already be part order.
  const bySeq = [...parts].sort((a, b) => a.seq - b.seq);
  assert.deepEqual(bySeq.map((f) => f.part), parts.map((f) => f.part));

  const rebuilt = bySeq.map((f) => f.text).join("");
  assert.equal(rebuilt.length, 5000, `reconstructed ${rebuilt.length} chars, expected 5000`);
  assert.equal(rebuilt, expected, "split parts did not reconstruct the original line");

  // The raw spool holds the line whole, unsplit and uncut.
  assert.ok(fs.readFileSync(res.spool.raw, "utf8").includes(expected), "raw spool lost bytes");
});
