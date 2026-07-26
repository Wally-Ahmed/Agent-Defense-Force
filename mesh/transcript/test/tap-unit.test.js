// tap-unit.test.js — the capture-path primitives.
//
// Everything between "bytes arrive from the child" and "a display line is
// enqueued" is a pure function, and each one of them is a place where a
// transcript can silently lose or corrupt data: a line reassembled wrong, a
// spinner expanded into 400 chat lines, an escape sequence left in, a UTF-8
// code point cut in half, or a private key streamed through a line-granularity
// redactor that cannot see it. The last test covers the one impure primitive:
// a timeout must take the whole process group with it.

import { test, after } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSync } from "node:child_process";
import { setTimeout as delay } from "node:timers/promises";
import { StringDecoder } from "node:string_decoder";

// --- isolation --------------------------------------------------------------
const RUNS = fs.mkdtempSync(path.join(os.tmpdir(), "tap-unit-"));
process.env.TRANSCRIPT_RUNS_DIR = RUNS;
process.env.TRANSCRIPT_SINK = "file";
process.env.TRANSCRIPT_REDACT_ENV = "0";
delete process.env.TRANSCRIPT_CHUNK_BYTES;
delete process.env.TRANSCRIPT_MAX_CHAT_BYTES;

import {
  LineSplitter,
  lastOverwrite,
  makePemGuard,
  runTap,
  splitBytes,
  stripAnsi,
} from "../src/tap.js";
import { readSpool, runsDir } from "../src/spool.js";
import { KIND } from "../src/frame.js";
import { channelFor, loadChannelFn } from "../src/adapters/common.js";

await loadChannelFn();

after(() => fs.rmSync(RUNS, { recursive: true, force: true }));

// --- 1. LineSplitter ---------------------------------------------------------
test("LineSplitter reassembles lines split across pushes", () => {
  const s = new LineSplitter();

  assert.deepEqual(s.push("hel"), [], "a partial line must not be emitted");
  assert.deepEqual(s.push("lo\nwor"), ["hello"]);
  assert.deepEqual(s.push("ld\nagain\ntrail"), ["world", "again"]);
  assert.deepEqual(s.flush(), ["trail"], "flush() returns the trailing partial line");
  assert.deepEqual(s.flush(), [], "flush() is idempotent");

  // Several newlines in one push, and an empty line in the middle, are kept.
  const t = new LineSplitter();
  assert.deepEqual(t.push("a\n\nb\n"), ["a", "", "b"]);
  assert.deepEqual(t.flush(), [], "nothing pending after a trailing newline");

  // Byte-level: exactly what onData() does — decode, then split — with the
  // buffer cut at arbitrary, line-unaligned boundaries.
  const payload = Buffer.from("alpha\nbeta\ngamma\ndelta", "utf8");
  const dec = new StringDecoder("utf8");
  const sp = new LineSplitter();
  const got = [];
  for (let i = 0; i < payload.length; i += 3) {
    got.push(...sp.push(dec.write(payload.subarray(i, i + 3))));
  }
  const tail = dec.end();
  if (tail) got.push(...sp.push(tail));
  got.push(...sp.flush());
  assert.deepEqual(got, ["alpha", "beta", "gamma", "delta"]);
});

// --- 2. lastOverwrite --------------------------------------------------------
test("lastOverwrite keeps only what the terminal would still show", () => {
  assert.equal(lastOverwrite("aaa\rbbb\rccc"), "ccc");
  assert.equal(lastOverwrite("a line with no carriage return"), "a line with no carriage return");
  assert.equal(lastOverwrite(""), "");
  assert.equal(lastOverwrite("\rfirst column"), "first column");
  assert.equal(lastOverwrite("overwritten\r"), "", "a trailing \\r blanks the line");
  // A spinner's worth of redraws collapses to one visible frame.
  assert.equal(lastOverwrite("| working\r/ working\r- working\rdone"), "done");
});

// --- 3. stripAnsi ------------------------------------------------------------
test("stripAnsi removes CSI and OSC sequences but keeps the text", () => {
  // Escapes are built from \u escapes, never literal control bytes in source.
  const ESC = "\u001B";
  const RED = `${ESC}[31m`;
  const RESET = `${ESC}[0m`;
  const OSC_BEL = `${ESC}]0;transcript-tap running${"\u0007"}`;
  const OSC_ST = `${ESC}]2;another title${ESC}\\`;

  assert.equal(stripAnsi(`${RED}error: nope${RESET}`), "error: nope");
  assert.equal(stripAnsi(`${OSC_BEL}plain after title`), "plain after title");
  assert.equal(stripAnsi(`${OSC_ST}still plain`), "still plain");
  assert.equal(stripAnsi(`${ESC}[2K${ESC}[1Gredrawn line`), "redrawn line");
  assert.equal(
    stripAnsi(`${ESC}[1m${ESC}[38;5;214mbold orange${RESET} then normal`),
    "bold orange then normal",
  );

  const plain = "plain text 123 with punctuation: -/_=+ and unicode é😀 intact";
  assert.equal(stripAnsi(plain), plain, "plain text was modified");

  // Line structure the splitter depends on survives; \r survives for
  // lastOverwrite() to interpret.
  assert.equal(stripAnsi("a\tb\rc\nd"), "a\tb\rc\nd");
  assert.equal(stripAnsi(""), "");
});

// --- 4. splitBytes never cuts a code point -----------------------------------
test("splitBytes splits on code-point boundaries and loses nothing", () => {
  const original = "😀é😀ü😀🚀日本語données😀ñ🎉";
  assert.ok(Buffer.byteLength(original) > original.length, "test string is not multi-byte");

  // 4, 5, 6, 7 and 9 all land mid-character somewhere in this string.
  for (const n of [4, 5, 6, 7, 9, 11, 16, 32]) {
    const pieces = splitBytes(original, n);
    assert.equal(pieces.join(""), original, `n=${n}: round trip failed`);
    for (const p of pieces) {
      assert.ok(p.length > 0, `n=${n}: empty piece`);
      assert.ok(!p.includes("\uFFFD"), `n=${n}: replacement char in piece ${JSON.stringify(p)}`);
      assert.ok(Buffer.byteLength(p) <= n, `n=${n}: piece exceeds the cap`);
    }
    assert.ok(pieces.length > 1, `n=${n}: expected a split`);
  }

  // A string that already fits is returned whole, not copied through Buffer.
  assert.deepEqual(splitBytes(original, 4096), [original]);
  assert.deepEqual(splitBytes("", 8), [""]);

  // Pure ASCII splits exactly at the cap.
  const ascii = "abcdefghij".repeat(10);
  const chunks = splitBytes(ascii, 10);
  assert.equal(chunks.length, 10);
  assert.equal(chunks.join(""), ascii);
  for (const c of chunks) assert.equal(c, "abcdefghij");
});

// --- 5. makePemGuard ---------------------------------------------------------
test("makePemGuard suppresses a whole multi-line private key block", () => {
  // Synthetic, clearly fake key material.
  const body = [
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz",
    "c2gtZWQyNTUxOQAAACBGQUtFZmFrZUZBS0VmYWtlRkFLRWZha2VGQUtFZmFrZUZB",
    "S0UAAAAJRkFLRUZBS0UAAAALc3NoLWVkMjU1MTkAAAAgRkFLRWZha2VGQUtFZmFr",
  ];
  const guard = makePemGuard();

  assert.equal(
    guard("-----BEGIN OPENSSH PRIVATE KEY-----"),
    "[REDACTED:pem_block]",
    "the BEGIN line must be replaced with the marker",
  );
  for (const line of body) {
    assert.equal(guard(line), null, `interior key line leaked: ${line.slice(0, 16)}…`);
  }
  assert.equal(guard("-----END OPENSSH PRIVATE KEY-----"), null, "the END line must be dropped");

  // The guard reopens for ordinary output straight after the block.
  const trailing = "[12:04:35] key loaded, continuing";
  assert.equal(guard(trailing), trailing, "ordinary output was swallowed after the block");
  assert.equal(guard("exit code 0"), "exit code 0");

  // A second block in the same stream is caught too, and other PEM labels work.
  assert.equal(guard("-----BEGIN RSA PRIVATE KEY-----"), "[REDACTED:pem_block]");
  assert.equal(guard(body[0]), null);
  assert.equal(guard("-----END RSA PRIVATE KEY-----"), null);
  assert.equal(guard("done"), "done");

  // Guards are per-stream and independent: a fresh one is not mid-block.
  assert.equal(makePemGuard()(body[0]), body[0]);

  // A single-line BEGIN...END is marked without swallowing what follows.
  const oneLine = makePemGuard();
  assert.equal(
    oneLine("-----BEGIN CERTIFICATE----- QUJD -----END CERTIFICATE-----"),
    "[REDACTED:pem_block]",
  );
  assert.equal(oneLine("next ordinary line"), "next ordinary line");
});

// --- 6. a timeout kills the whole process group ------------------------------
/** How many processes currently match `pgrep -f <pattern>`. */
function pgrepCount(pattern) {
  try {
    const out = execFileSync("pgrep", ["-f", pattern], { encoding: "utf8" });
    return out.split("\n").filter((l) => l.trim()).length;
  } catch {
    return 0; // pgrep exits non-zero when nothing matches
  }
}

test("a timeout terminates the pty process group and leaves no orphan", { timeout: 30000 }, async () => {
  const PATTERN = "sleep 30";
  const baseline = pgrepCount(PATTERN);

  const adapter = {
    runtime: "fake",
    cli: "sh",
    capturePoint: "pipe",
    channel: channelFor,
    async build({ cwd }) {
      // pty: true puts script(1) between us and the shell, so the sleep is a
      // grandchild — the exact shape that a plain kill(pid) would orphan.
      return {
        command: "/bin/sh",
        args: ["-c", "sleep 30"],
        env: process.env,
        cwd,
        pty: true,
      };
    },
    render: null,
  };

  const started = Date.now();
  const res = await runTap({
    agentId: "monitor",
    adapter,
    prompt: "p",
    runId: "run-timeout",
    incidentId: "incident-timeout",
    timeoutMs: 1500,
  });
  const elapsed = Date.now() - started;

  assert.ok(elapsed < 15000, `runTap took ${elapsed}ms — the timeout did not fire`);
  assert.equal(res.timedOut, true, "res.timedOut");
  assert.equal(res.ok, false);

  const frames = readSpool(res.spool.log);
  assert.ok(
    frames.some((f) => f.kind === KIND.META && /timeout/i.test(f.text)),
    `no META frame mentioning the timeout: ${frames.map((f) => f.kind).join(",")}`,
  );
  const exit = frames.at(-1);
  assert.equal(exit.kind, KIND.EXIT);
  assert.equal(exit.extra.timed_out, true);
  assert.match(exit.text, /TIMED OUT/);

  // No orphan survives. Process teardown is asynchronous, so poll rather than
  // sample once, but never accept a count above the pre-test baseline.
  let count = pgrepCount(PATTERN);
  const deadline = Date.now() + 10000;
  while (count > baseline && Date.now() < deadline) {
    await delay(200);
    count = pgrepCount(PATTERN);
  }
  assert.ok(
    count <= baseline,
    `${count - baseline} orphaned "${PATTERN}" process(es) survived the kill`,
  );
});

// --- 7. splitBytes must terminate on a cap narrower than a code point --------
// Regression: the back-off loop used to land on end === i, push "" and leave i
// unmoved — an infinite loop with the harness child still attached. Reachable
// from config, since TRANSCRIPT_CHUNK_BYTES=0..3 feeds straight into it.
test("splitBytes terminates and loses nothing on pathological caps", () => {
  const cases = [
    ["\u{1F600}", 2],
    ["abc", 0],
    ["abc", -5],
    ["abc", Number.NaN],
    ["\u{1F600}\u{1F601}\u{1F602}", 1],
    ["café naïve 日本語", 3],
  ];
  for (const [s, n] of cases) {
    const parts = splitBytes(s, n);
    const label = `${JSON.stringify(s)} cap=${n}`;
    assert.ok(parts.length >= 1, `${label}: no pieces`);
    assert.equal(parts.join(""), s, `${label}: bytes lost or reordered`);
    assert.ok(!parts.includes(""), `${label}: emitted an empty piece`);
    assert.ok(!parts.some((p) => p.includes("�")), `${label}: split a code point`);
  }
});

const shAdapter = (script) => ({
  runtime: "fake",
  cli: "sh",
  capturePoint: "pipe",
  channel: channelFor,
  async build({ cwd }) {
    return { command: "/bin/sh", args: ["-c", script], env: process.env, cwd, pty: false };
  },
  render: null,
});

test("TRANSCRIPT_CHUNK_BYTES is floored so a 0 cap cannot wedge the tap", async () => {
  const prev = process.env.TRANSCRIPT_CHUNK_BYTES;
  process.env.TRANSCRIPT_CHUNK_BYTES = "0";
  try {
    const res = await runTap({
      agentId: "responder_glm",
      adapter: shAdapter(`printf 'alpha\\nbeta \u{1F600} gamma\\n'`),
      prompt: "p",
      runId: "run-zero-cap",
      incidentId: "incident-zero-cap",
    });
    assert.equal(res.exitCode, 0);
    const body = readSpool(res.spool.log)
      .filter((f) => f.kind === KIND.CHUNK)
      .map((f) => f.text)
      .join("\n");
    assert.match(body, /alpha/);
    assert.match(body, /beta \u{1F600} gamma/u);
  } finally {
    if (prev === undefined) delete process.env.TRANSCRIPT_CHUNK_BYTES;
    else process.env.TRANSCRIPT_CHUNK_BYTES = prev;
  }
});
