// sinks/index.js — sink selection and the ordered, failure-isolated publish queue.
//
// TRANSCRIPT_SINK selects the destination:
//   file   (default) — runs/<run_id>/chat/<tr-channel>.txt, works with no mesh
//   cotal            — the Cotal chat channel tr-<agent_id>
//   both             — publish to each; either may fail independently
//   none             — spool only
//
// FAILURE ISOLATION: publish() never throws to the caller and never blocks the
// harness. Frames are appended to a serial queue that preserves sequence order;
// a failing or hung sink costs that frame its chat delivery and nothing else —
// the frame is already on disk before the queue ever sees it.

import { createFileSink } from "./file.js";
import { createCotalSink } from "./cotal.js";

export async function createSink(ctx) {
  const mode = (process.env.TRANSCRIPT_SINK || "file").toLowerCase();
  const sinks = [];

  if (mode === "none") {
    // deliberately empty
  } else if (mode === "file") {
    sinks.push(createFileSink(ctx));
  } else if (mode === "cotal") {
    sinks.push(await createCotalSink(ctx));
  } else if (mode === "both") {
    sinks.push(createFileSink(ctx), await createCotalSink(ctx));
  } else {
    throw new Error(
      `TRANSCRIPT_SINK="${mode}" is not one of: file, cotal, both, none`,
    );
  }

  return new PublishQueue(sinks, ctx);
}

export class PublishQueue {
  #q = [];
  #draining = false;
  #closed = false;

  constructor(sinks, ctx) {
    this.sinks = sinks;
    this.ctx = ctx;
    this.stats = { published: 0, failed: 0, queuedPeak: 0 };
    this.errors = [];
    /** Called with a human-readable string whenever a publish fails. */
    this.onError = null;
  }

  get description() {
    return this.sinks
      .map((s) => `${s.name}${s.ready ? `→${s.target}` : `(unavailable: ${s.brokenReason})`}`)
      .join(", ") || "none";
  }

  /** Non-blocking, order-preserving enqueue. */
  publish(frame) {
    if (this.#closed) return;
    this.#q.push(frame);
    if (this.#q.length > this.stats.queuedPeak) this.stats.queuedPeak = this.#q.length;
    if (!this.#draining) this.#drain();
  }

  async #drain() {
    this.#draining = true;
    while (this.#q.length) {
      const frame = this.#q.shift();
      for (const sink of this.sinks) {
        if (!sink.ready) continue;
        try {
          await sink.publish(frame);
          this.stats.published += 1;
        } catch (err) {
          this.stats.failed += 1;
          const msg = `${sink.name} publish failed at seq ${frame.seq}: ${err.message}`;
          if (this.errors.length < 20) this.errors.push(msg);
          try {
            this.onError?.(msg);
          } catch {
            /* an error reporter must not itself take down the run */
          }
        }
      }
    }
    this.#draining = false;
  }

  /** Wait for the queue to empty (bounded), then close every sink. */
  async close(drainTimeoutMs = 10_000) {
    const deadline = Date.now() + drainTimeoutMs;
    while ((this.#q.length || this.#draining) && Date.now() < deadline) {
      await new Promise((r) => setTimeout(r, 25));
    }
    const undelivered = this.#q.length;
    this.#closed = true;
    this.#q.length = 0;
    for (const sink of this.sinks) {
      try {
        await sink.close();
      } catch {
        /* ignore */
      }
    }
    return { undelivered };
  }
}
