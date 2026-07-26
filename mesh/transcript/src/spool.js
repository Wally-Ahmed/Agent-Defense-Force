// spool.js — the write-ahead disk spool.
//
// FAILURE ISOLATION CONTRACT: every frame is written here BEFORE the sink is
// asked to publish it, and the write is synchronous. If the mesh is down, if
// the sink throws, or if the process is SIGKILLed mid-run, the complete
// transcript still exists on disk and can be replayed later. Losing chat
// output must never lose an assessment.
//
// Two files per agent per run:
//   runs/<run_id>/transcripts/<agent>.log  — NDJSON envelopes (replayable)
//   runs/<run_id>/transcripts/<agent>.raw  — the redacted byte stream exactly
//                                            as the CLI emitted it
// The spool is NEVER truncated, whatever the chat volume cap is set to.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { serialize } from "./frame.js";

const HERE = path.dirname(fileURLToPath(import.meta.url));
/** repo root = mesh/transcript/src -> ../../.. */
export const REPO_ROOT = path.resolve(HERE, "..", "..", "..");

export function runsDir() {
  return process.env.TRANSCRIPT_RUNS_DIR || path.join(REPO_ROOT, "runs");
}

export function transcriptPaths(runId, agentId) {
  const dir = path.join(runsDir(), runId, "transcripts");
  return {
    dir,
    log: path.join(dir, `${agentId}.log`),
    raw: path.join(dir, `${agentId}.raw`),
  };
}

export class Spool {
  #logFd = null;
  #rawFd = null;
  #bytes = 0;
  #frames = 0;
  #errors = [];

  constructor(runId, agentId) {
    this.paths = transcriptPaths(runId, agentId);
    try {
      fs.mkdirSync(this.paths.dir, { recursive: true });
      this.#logFd = fs.openSync(this.paths.log, "a");
      this.#rawFd = fs.openSync(this.paths.raw, "a");
    } catch (err) {
      // A broken spool must not take down the harness run either.
      this.#errors.push(`spool open failed: ${err.message}`);
    }
  }

  /** Append one envelope. Synchronous by design. */
  write(frame) {
    if (this.#logFd === null) return false;
    try {
      const line = serialize(frame);
      fs.writeSync(this.#logFd, line);
      this.#bytes += Buffer.byteLength(line);
      this.#frames += 1;
      return true;
    } catch (err) {
      this.#errors.push(`spool write failed: ${err.message}`);
      return false;
    }
  }

  /** Append raw (already-redacted) harness bytes. */
  writeRaw(text) {
    if (this.#rawFd === null) return false;
    try {
      fs.writeSync(this.#rawFd, text);
      return true;
    } catch (err) {
      this.#errors.push(`spool raw write failed: ${err.message}`);
      return false;
    }
  }

  close() {
    for (const fd of [this.#logFd, this.#rawFd]) {
      if (fd !== null) {
        try {
          fs.closeSync(fd);
        } catch {
          /* already gone */
        }
      }
    }
    this.#logFd = null;
    this.#rawFd = null;
  }

  get stats() {
    return { bytes: this.#bytes, frames: this.#frames, errors: [...this.#errors] };
  }
}

/**
 * Read a spooled transcript back as frames — used by `transcript-tap replay`
 * to push a transcript into chat after the fact when the mesh was down.
 */
export function readSpool(logPath) {
  const out = [];
  let text;
  try {
    text = fs.readFileSync(logPath, "utf8");
  } catch {
    return out;
  }
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      out.push(JSON.parse(line));
    } catch {
      // A torn final line (process killed mid-write) is expected; skip it.
    }
  }
  return out;
}
