// tap.js — the transcript tap.
//
// One tap wraps one harness invocation. It owns the child process, so it sees
// 100% of the bytes the CLI writes — there is no connector, plugin API, or
// session-file digest in between. The pipeline for every byte is:
//
//   child stdout/stderr
//     -> line split             complete lines only, so a secret can never be
//                               halved by a chunk boundary and match nothing
//     -> PEM guard              the one credential form that spans newlines
//     -> REDACT                 <- nothing leaves the process before this
//     -> raw spool (.raw)       redacted byte stream, never truncated
//     -> display render         strip the CRLF terminator, collapse \r
//                               overwrites the way a terminal would, strip ANSI,
//                               then adapter.render() expands structured event
//                               JSON into the lines a human would have seen
//     -> coalesce               flush on idle or byte cap
//     -> frame + monotonic seq
//     -> emitFrame              the single exit: envelope spool (.log,
//                               write-ahead, synchronous), then the sink queue
//                               (chat), best-effort, never blocks the harness
//
// Nothing is truncated by default. A line larger than the chunk cap is SPLIT
// across sequenced parts, not cut. See TRANSCRIPT_MAX_CHAT_BYTES for the only
// cap that can drop data, which is off unless explicitly set.

import { StringDecoder } from "node:string_decoder";
import { KIND, Sequencer, makeFrame, renderChat } from "./frame.js";
import { Spool } from "./spool.js";
import { createSink } from "./sinks/index.js";
import { spawnCaptured, killGroup } from "./pty.js";
import { makeRedactor, secretsFromEnv } from "./redact.js";

// CSI / OSC / charset / single-char escapes emitted by TUI harnesses under a pty.
const ANSI_RE = new RegExp(
  [
    "\\u001B\\][\\s\\S]*?(?:\\u0007|\\u001B\\\\)", // OSC ... BEL | ST
    "\\u001B\\[[0-?]*[ -/]*[@-~]", // CSI
    "\\u001B[()#][0-9A-Za-z]", // charset designators
    "\\u001B[@-Z\\\\-_]", // other Fe escapes
    "[\\u0000-\\u0008\\u000B\\u000C\\u000E-\\u001F\\u007F]", // stray control chars
  ].join("|"),
  "g",
);

export function stripAnsi(s) {
  return String(s).replace(ANSI_RE, "");
}

/**
 * Collapse a terminal line the way a terminal would: a carriage return moves
 * the cursor to column 0, so everything before the final \r has been overwritten
 * and was never simultaneously visible. Keeping only the last segment is what a
 * human actually saw, and it stops a spinner from emitting 400 chat lines.
 */
export function lastOverwrite(line) {
  const i = line.lastIndexOf("\r");
  return i === -1 ? line : line.slice(i + 1);
}

/** Incremental newline splitter over a byte stream. */
export class LineSplitter {
  #buf = "";
  push(text) {
    this.#buf += text;
    const parts = this.#buf.split("\n");
    this.#buf = parts.pop() ?? "";
    return parts;
  }
  flush() {
    const rest = this.#buf;
    this.#buf = "";
    return rest ? [rest] : [];
  }
}

/** Smallest chunk cap that still produces sane frames. */
export const MIN_CHUNK_BYTES = 64;

export const DEFAULTS = {
  flushMs: 250, // streaming cadence: chat updates at least this often
  chunkBytes: 3500, // per-message payload cap (Cotal chunks chat at 6000)
  maxChatBytes: 0, // 0 = UNLIMITED. The only setting that can drop data.
  killGraceMs: 5000,
  timeoutMs: 15 * 60 * 1000,
};

function envInt(name, dflt) {
  const v = process.env[name];
  if (v === undefined || v === "") return dflt;
  const n = Number(v);
  return Number.isFinite(n) && n >= 0 ? n : dflt;
}

/**
 * Run one harness invocation under the tap.
 *
 * @param {object} o
 * @param {string} o.agentId      canonical mesh agent id, e.g. "responder_claude"
 * @param {object} o.adapter      per-runtime adapter (see src/adapters/)
 * @param {string} o.prompt       the prompt to send
 * @param {string} [o.runId]
 * @param {string} [o.incidentId]
 * @param {string} [o.model]
 * @param {string} [o.cwd]
 * @param {string[]} [o.extraArgs]
 * @param {number} [o.timeoutMs]
 */
export async function runTap(o) {
  const cfg = {
    flushMs: envInt("TRANSCRIPT_FLUSH_MS", DEFAULTS.flushMs),
    // Floored: a cap of 0 would make every line "oversized" and a cap in the
    // single digits would emit one frame per character. Both are pathological
    // rather than useful, and neither is what anyone setting this var means.
    chunkBytes: Math.max(
      MIN_CHUNK_BYTES,
      envInt("TRANSCRIPT_CHUNK_BYTES", DEFAULTS.chunkBytes),
    ),
    maxChatBytes: envInt("TRANSCRIPT_MAX_CHAT_BYTES", DEFAULTS.maxChatBytes),
    killGraceMs: envInt("TRANSCRIPT_KILL_GRACE_MS", DEFAULTS.killGraceMs),
    timeoutMs: o.timeoutMs ?? envInt("TRANSCRIPT_TIMEOUT_MS", DEFAULTS.timeoutMs),
    keepAnsi: process.env.TRANSCRIPT_KEEP_ANSI === "1",
  };

  const runId = o.runId || process.env.TRANSCRIPT_RUN_ID || `run-${Date.now()}`;
  const incidentId = o.incidentId || process.env.TRANSCRIPT_INCIDENT_ID || "no-incident";
  const adapter = o.adapter;
  const channel = adapter.channel(o.agentId);

  const ctx = {
    run_id: runId,
    incident_id: incidentId,
    agent_id: o.agentId,
    runtime: adapter.runtime,
    channel,
  };

  // ---- redaction ---------------------------------------------------------
  // Bound to the literal values of every secret-looking env var in this
  // process, so a key that leaks into harness output in a form no regex knows
  // about is still caught by exact match.
  const extraSecrets =
    process.env.TRANSCRIPT_REDACT_ENV === "0" ? [] : secretsFromEnv(process.env);
  const redactor = makeRedactor(extraSecrets);

  const seq = new Sequencer();
  const spool = new Spool(runId, o.agentId);
  const sink = await createSink(ctx);

  let chatBytes = 0;
  let sinkDescription = null;
  let truncationAnnounced = false;
  let rawBytes = 0;
  let redactedTotal = 0;

  /**
   * The single exit from this process. EVERY frame goes through here, so the
   * write-ahead spool and the chat volume cap are applied in exactly one place
   * and cannot be bypassed by a new emit path.
   */
  const emitFrame = (frame) => {
    spool.write(frame); // write-ahead: on disk before chat ever sees it
    if (cfg.maxChatBytes > 0 && chatBytes > cfg.maxChatBytes) {
      if (!truncationAnnounced) {
        truncationAnnounced = true;
        const note = makeFrame(ctx, {
          kind: KIND.TRUNCATED,
          seq: seq.next(),
          text:
            `chat volume cap reached (TRANSCRIPT_MAX_CHAT_BYTES=${cfg.maxChatBytes}). ` +
            `Further output is NOT published to chat. The full, untruncated transcript ` +
            `continues to be written to ${spool.paths.log}`,
        });
        spool.write(note);
        sink.publish(note);
      }
      return frame;
    }
    chatBytes += Buffer.byteLength(renderChat(frame));
    sink.publish(frame);
    return frame;
  };

  const emit = (kind, rawText, stream = "meta", extra) => {
    // Meta frames go through the redactor too. The START banner echoes the
    // harness argv, which can carry a `-c key="..."` override or a token-bearing
    // flag — text the tap itself composed, and therefore text that would
    // otherwise reach chat without ever passing a redaction boundary.
    const { text, hits } = redactor(String(rawText));
    for (const h of hits) redactedTotal += h.count;
    return emitFrame(makeFrame(ctx, { kind, seq: seq.next(), stream, text, extra }));
  };

  sink.onError = (msg) => {
    // Recorded in the spool only — publishing a publish-failure would loop.
    spool.write(makeFrame(ctx, { kind: KIND.SINK_ERROR, seq: seq.next(), text: msg }));
  };

  // ---- build the invocation ---------------------------------------------
  const built = await adapter.build({
    prompt: o.prompt,
    model: o.model,
    cwd: o.cwd || process.cwd(),
    extraArgs: o.extraArgs || [],
    agentId: o.agentId,
    runId,
  });

  emit(
    KIND.START,
    [
      `${o.agentId} (${adapter.runtime}) starting`,
      `capture: ${built.pty ? "pseudo-tty via script(1)" : "piped stdout+stderr"}`,
      `model: ${o.model || built.model || "(connector default)"}`,
      `argv: ${[built.command, ...built.args].join(" ")}`,
      `spool: ${spool.paths.log}`,
      `sink: ${sink.description}`,
    ].join("\n"),
  );

  // ---- coalescer ---------------------------------------------------------
  let pending = [];
  let pendingBytes = 0;
  let pendingStream = "stdout";
  let flushTimer = null;

  const flush = () => {
    if (flushTimer) {
      clearTimeout(flushTimer);
      flushTimer = null;
    }
    if (!pending.length) return;
    const text = pending.join("\n");
    pending = [];
    pendingBytes = 0;
    emit(KIND.CHUNK, text, pendingStream);
  };

  const scheduleFlush = () => {
    if (flushTimer) return;
    flushTimer = setTimeout(flush, cfg.flushMs);
    if (typeof flushTimer.unref === "function") flushTimer.unref();
  };

  /** Enqueue one already-redacted, already-rendered display line. */
  const pushLine = (line, stream) => {
    if (stream !== pendingStream) {
      flush();
      pendingStream = stream;
    }
    const size = Buffer.byteLength(line) + 1;
    // A single line bigger than the whole chunk cap is SPLIT, never truncated.
    if (size > cfg.chunkBytes) {
      flush();
      const parts = splitBytes(line, cfg.chunkBytes);
      parts.forEach((p, i) => {
        emitFrame(
          makeFrame(ctx, {
            kind: KIND.CHUNK,
            seq: seq.next(),
            stream,
            text: p,
            part: `${i + 1}/${parts.length}`,
          }),
        );
      });
      return;
    }
    if (pendingBytes + size > cfg.chunkBytes) flush();
    pending.push(line);
    pendingBytes += size;
    scheduleFlush();
  };

  const splitters = { stdout: new LineSplitter(), stderr: new LineSplitter() };
  // A multi-byte character can straddle two `data` events; StringDecoder holds
  // the partial code point instead of emitting U+FFFD into the transcript.
  const decoders = { stdout: new StringDecoder("utf8"), stderr: new StringDecoder("utf8") };
  const pemGuards = { stdout: makePemGuard(), stderr: makePemGuard() };
  let seenFirstPtyLine = false;

  /**
   * Redact, spool and display ONE COMPLETE LINE.
   *
   * Redacting per line rather than per chunk is a correctness requirement, not a
   * style choice: a secret that straddles two `data` events would be split in
   * half and match no pattern in either half. Line boundaries are safe because a
   * single-line secret cannot contain a newline — and the one credential form
   * that spans lines (a PEM block) is handled by the stateful guard below.
   */
  const handleLine = (rawLine0, stream) => {
    let rawLine = rawLine0;
    // BSD script(1) echoes the EOF character as a literal "^D" on the first
    // line when its stdin is /dev/null. Harness output, not harness content.
    if (built.pty && stream === "stdout" && !seenFirstPtyLine) {
      seenFirstPtyLine = true;
      rawLine = rawLine.replace(/^\^D+/, "");
      if (!rawLine.trim()) return;
    }
    const guarded = pemGuards[stream](rawLine);
    if (guarded === null) {
      redactedTotal += 1; // interior of a suppressed key block
      return;
    }
    const { text: safe, hits } = redactor(guarded);
    for (const h of hits) redactedTotal += h.count;
    spool.writeRaw(safe + "\n"); // full fidelity modulo redaction; never truncated
    for (const out of toDisplayLines(safe, adapter, cfg)) pushLine(out, stream);
  };

  /** Handle one raw chunk of bytes off a stream. */
  const onData = (buf, stream) => {
    rawBytes += buf.length;
    const text = decoders[stream].write(buf);
    for (const line of splitters[stream].push(text)) handleLine(line, stream);
  };

  // ---- spawn -------------------------------------------------------------
  const started = Date.now();
  let spawned;
  try {
    spawned = spawnCaptured({
      command: built.command,
      args: built.args,
      env: built.env,
      cwd: built.cwd,
      pty: built.pty,
      stdin: built.stdin,
    });
  } catch (err) {
    emit(KIND.EXIT, `spawn failed: ${err.message}`);
    await finish();
    return result({ ok: false, exitCode: null, signal: null, error: err.message });
  }

  const { child } = spawned;
  child.stdout?.on("data", (b) => onData(b, "stdout"));
  child.stderr?.on("data", (b) => onData(b, "stderr"));

  if (built.stdin !== undefined && child.stdin) {
    child.stdin.on("error", () => {});
    child.stdin.end(built.stdin);
  } else if (child.stdin) {
    child.stdin.end();
  }

  let timedOut = false;
  const timer = setTimeout(() => {
    timedOut = true;
    emit(
      KIND.META,
      `timeout after ${cfg.timeoutMs}ms — terminating process group ${-child.pid} (SIGTERM, then SIGKILL in ${cfg.killGraceMs}ms)`,
    );
    killGroup(child, cfg.killGraceMs);
  }, cfg.timeoutMs);

  const exit = await new Promise((resolve) => {
    child.once("error", (err) => resolve({ code: null, signal: null, error: err.message }));
    child.once("close", (code, signal) => resolve({ code, signal }));
  });
  clearTimeout(timer);

  // Drain whatever was left in the decoders and line buffers.
  for (const stream of ["stdout", "stderr"]) {
    const tail = decoders[stream].end();
    if (tail) for (const line of splitters[stream].push(tail)) handleLine(line, stream);
    for (const rest of splitters[stream].flush()) handleLine(rest, stream);
  }
  flush();

  const durationMs = Date.now() - started;
  emit(
    KIND.EXIT,
    [
      `${o.agentId} exit code=${exit.code ?? "null"} signal=${exit.signal ?? "none"}` +
        (timedOut ? " (TIMED OUT)" : "") +
        (exit.error ? ` error=${exit.error}` : ""),
      `duration=${durationMs}ms captured=${rawBytes}B frames=${seq.value} redactions=${redactedTotal}`,
    ].join("\n"),
    "meta",
    {
      exit_code: exit.code,
      signal: exit.signal,
      timed_out: timedOut,
      duration_ms: durationMs,
      captured_bytes: rawBytes,
      redactions: redactedTotal,
      truncated: truncationAnnounced,
    },
  );

  const closeInfo = await finish();
  return result({
    ok: !timedOut && exit.code === 0,
    exitCode: exit.code,
    signal: exit.signal,
    timedOut,
    durationMs,
    ...closeInfo,
  });

  async function finish() {
    // Snapshot the description before close() flips every sink to not-ready.
    sinkDescription = sink.description;
    const info = await sink.close();
    const stats = { ...spool.stats, sink: { ...sink.stats }, sinkErrors: sink.errors };
    spool.close();
    if (typeof built.cleanup === "function") {
      try {
        await built.cleanup();
      } catch {
        /* temp-file cleanup is best-effort */
      }
    }
    return { ...info, stats };
  }

  function result(extra) {
    return {
      agent_id: o.agentId,
      runtime: adapter.runtime,
      run_id: runId,
      incident_id: incidentId,
      channel,
      frames: seq.value,
      captured_bytes: rawBytes,
      redactions: redactedTotal,
      truncated: truncationAnnounced,
      spool: spool.paths,
      sink: sinkDescription ?? sink.description,
      ...extra,
    };
  }
}

const PEM_BEGIN = /-----BEGIN[ A-Z0-9]*-----/;
const PEM_END = /-----END[ A-Z0-9]*-----/;

/**
 * Stateful suppressor for the one credential form that legitimately spans
 * newlines. Line-granularity redaction cannot see a whole PEM block, so the
 * BEGIN line is replaced with a marker and every line until END is dropped.
 * Returns null for a dropped line. One guard per stream.
 */
export function makePemGuard() {
  let inBlock = false;
  return (line) => {
    if (!inBlock) {
      if (PEM_BEGIN.test(line)) {
        inBlock = !PEM_END.test(line.slice(line.search(PEM_BEGIN) + 5));
        return "[REDACTED:pem_block]";
      }
      return line;
    }
    if (PEM_END.test(line)) inBlock = false;
    return null;
  };
}

/** Split a string into <=n-byte pieces without splitting a UTF-8 code point. */
export function splitBytes(s, n) {
  const buf = Buffer.from(s, "utf8");
  const cap = Math.max(1, Math.floor(Number(n)) || 1);
  if (buf.length <= cap) return [s];
  const out = [];
  let i = 0;
  while (i < buf.length) {
    let end = Math.min(i + cap, buf.length);
    // Back off to a code-point boundary (continuation bytes are 10xxxxxx).
    while (end > i && end < buf.length && (buf[end] & 0xc0) === 0x80) end -= 1;
    if (end <= i) {
      // The cap is narrower than the code point sitting on this boundary, so
      // backing off consumed the whole window. Emit the entire code point and
      // overshoot the cap by a few bytes: pushing an empty piece here would
      // leave `i` unmoved and spin this loop forever with the child still
      // attached. Overshooting is always preferable to hanging or to slicing a
      // character in half.
      end = i + 1;
      while (end < buf.length && (buf[end] & 0xc0) === 0x80) end += 1;
    }
    out.push(buf.subarray(i, end).toString("utf8"));
    i = end;
  }
  return out;
}

/**
 * Turn one captured line into the display line(s) for chat.
 * The adapter gets first refusal: structured-event runtimes (claude, codex)
 * expand one JSON event into the several lines a human would have seen.
 */
export function toDisplayLines(rawLine, adapter, cfg) {
  // Order is load-bearing. A pty terminates every line with CRLF, so the
  // trailing CR must go FIRST: applied to "TTY=yes\r", lastOverwrite() would
  // otherwise treat that terminator as an overwrite and return the empty string
  // — silently blanking the entire transcript of every pty-captured runtime.
  let line = String(rawLine).replace(/\r$/, "");
  line = lastOverwrite(line);
  if (!cfg.keepAnsi) line = stripAnsi(line);
  let out;
  try {
    out = adapter.render ? adapter.render(line) : [line];
  } catch (err) {
    // A renderer bug must never lose the underlying line.
    out = [line, `[render error: ${err.message}]`];
  }
  return (out ?? []).filter((l) => l !== null && l !== undefined && l !== "");
}
