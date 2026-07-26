// frame.js — the wire envelope for one transcript chunk.
//
// Every record published or spooled by the tap is one of these, serialised as a
// single NDJSON line. The envelope carries the four attribution fields the mesh
// requires on EVERY chunk (agent id, incident id, monotonic sequence, timestamp)
// so that five interleaved transcripts stay readable and replayable.

export const FRAME_VERSION = 1;

export const KIND = {
  START: "transcript.start",
  CHUNK: "transcript.chunk",
  META: "transcript.meta",
  EXIT: "transcript.exit",
  TRUNCATED: "transcript.truncated",
  SINK_ERROR: "transcript.sink_error",
};

/**
 * A monotonic, per-tap sequence counter. Sequence numbers are dense and start
 * at 1, so a gap in a spooled transcript is proof of loss, not of reordering.
 */
export class Sequencer {
  #n = 0;
  next() {
    return ++this.#n;
  }
  get value() {
    return this.#n;
  }
}

/**
 * Build one envelope.
 *
 * @param {object} ctx  stable per-run identity: {run_id, incident_id, agent_id, runtime, model}
 * @param {object} rec  {kind, seq, stream, text, ...extra}
 */
export function makeFrame(ctx, rec) {
  const now = new Date();
  return {
    v: FRAME_VERSION,
    kind: rec.kind,
    run_id: ctx.run_id,
    incident_id: ctx.incident_id,
    agent_id: ctx.agent_id,
    runtime: ctx.runtime,
    seq: rec.seq,
    ts: now.toISOString(),
    // Monotonic clock reading (ms since process start, sub-ms resolution).
    // Wall clock can jump; this cannot, so it is the tiebreaker for ordering.
    mono_ms: Number(process.hrtime.bigint() / 1000n) / 1000,
    stream: rec.stream ?? "meta",
    text: rec.text ?? "",
    ...(rec.redacted ? { redacted: rec.redacted } : {}),
    ...(rec.part ? { part: rec.part } : {}),
    ...(rec.extra ? { extra: rec.extra } : {}),
  };
}

export function serialize(frame) {
  return JSON.stringify(frame) + "\n";
}

const pad = (n, w) => String(n).padStart(w, "0");

/** Short, stable form of an incident id for the chat prefix. */
export function shortIncident(id) {
  if (!id) return "no-incident";
  const s = String(id);
  return s.length <= 12 ? s : s.slice(0, 12);
}

/**
 * Render a frame as the human-readable chat line(s).
 *
 * Format:  [<agent> · <inc> · #000042 · 21:00:00.123Z] text
 *
 * Identical for the `cotal` and `file` sinks — that is the point of putting it
 * here rather than in either sink.
 */
export function renderChat(frame, opts = {}) {
  const prefix = opts.bare
    ? ""
    : `[${frame.agent_id} · ${shortIncident(frame.incident_id)} · #${pad(frame.seq, 6)} · ${frame.ts.slice(11)}] `;

  const MARKER = {
    [KIND.START]: "▶ ",
    [KIND.EXIT]: "■ ",
    [KIND.TRUNCATED]: "✂ ",
    [KIND.SINK_ERROR]: "⚠ ",
    [KIND.META]: "· ",
  };
  const marker =
    MARKER[frame.kind] ??
    (frame.stream === "stderr" ? "!" : " ") + (frame.part ? `(part ${frame.part}) ` : "");

  // The body may be multi-line: the prefix goes on the first line only and
  // continuation lines are indented so the whole block reads as one unit and
  // cannot be mistaken for another agent's interleaved output.
  const lines = String(frame.text).replace(/\n$/, "").split("\n");
  const head = `${prefix}${marker}${lines[0] ?? ""}`;
  if (lines.length === 1) return head;
  return [head, ...lines.slice(1).map((l) => "    " + l)].join("\n");
}
