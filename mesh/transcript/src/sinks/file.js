// sinks/file.js — the offline sink.
//
// Formats each frame EXACTLY as the cotal sink would (both call renderChat from
// frame.js), then appends it to runs/<run_id>/chat/<tr-channel>.txt instead of
// publishing it to the mesh. This is what makes the tap usable while the Cotal
// mesh is not running: same bytes, different destination.

import fs from "node:fs";
import path from "node:path";
import { renderChat } from "../frame.js";
import { runsDir } from "../spool.js";

export function createFileSink(ctx) {
  const dir = path.join(runsDir(), ctx.run_id, "chat");
  const file = path.join(dir, `${ctx.channel}.txt`);
  let fd = null;
  let ready = false;

  try {
    fs.mkdirSync(dir, { recursive: true });
    fd = fs.openSync(file, "a");
    ready = true;
  } catch (err) {
    return brokenSink("file", `open ${file}: ${err.message}`);
  }

  return {
    name: "file",
    target: file,
    get ready() {
      return ready;
    },
    async publish(frame) {
      const line = renderChat(frame) + "\n";
      fs.writeSync(fd, line);
      if (process.env.TRANSCRIPT_ECHO === "1") process.stderr.write(line);
    },
    async close() {
      if (fd !== null) {
        try {
          fs.closeSync(fd);
        } catch {
          /* ignore */
        }
        fd = null;
      }
      ready = false;
    },
  };
}

export function brokenSink(name, reason) {
  return {
    name,
    target: null,
    ready: false,
    brokenReason: reason,
    async publish() {
      throw new Error(`${name} sink unavailable: ${reason}`);
    },
    async close() {},
  };
}
