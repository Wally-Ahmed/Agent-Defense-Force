// sinks/cotal.js — publish transcript chunks to the Cotal chat channel tr-<agent_id>.
//
// WRAP, DON'T PATCH. This talks to the same two public primitives the upstream
// connectors use — configFromEnv() and MeshAgent.send(text, channel) — from a
// process we own, sitting around the harness. No connector is forked, and the
// upstream `transcriptChannel()` naming rule is reused verbatim when the SDK is
// available so our channel names can never drift from Cotal's.
//
// The SDK is loaded dynamically: it is an ESM-only, exports-gated package that
// lives in the global `cotal-ai` install rather than in this repo's
// node_modules, and we must degrade cleanly to spool-only when it is absent.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { renderChat } from "../frame.js";
import { REPO_ROOT } from "../spool.js";
import { brokenSink } from "./file.js";

const PKG = "@cotal-ai/connector-core";

/** Candidate directories that may contain the connector-core dist entry. */
export function sdkCandidates() {
  const out = [];
  const push = (d) => d && out.push(path.join(d, "dist", "index.js"));

  if (process.env.COTAL_SDK_DIR) push(process.env.COTAL_SDK_DIR);
  push(path.join(REPO_ROOT, "node_modules", PKG));
  push(path.join(os.homedir(), ".config", "cotal", "extensions", "node_modules", PKG));

  // Derive the global npm root from wherever the `cotal` binary lives, without
  // shelling out: /<prefix>/bin/cotal -> /<prefix>/lib/node_modules/cotal-ai/...
  for (const dir of (process.env.PATH || "").split(path.delimiter)) {
    if (!dir) continue;
    const bin = path.join(dir, "cotal");
    let real;
    try {
      if (!fs.existsSync(bin)) continue;
      real = fs.realpathSync(bin);
    } catch {
      continue;
    }
    let cur = path.dirname(real);
    for (let i = 0; i < 8 && cur !== path.dirname(cur); i++) {
      push(path.join(cur, "node_modules", PKG));
      push(path.join(cur, "node_modules", "cotal-ai", "node_modules", PKG));
      cur = path.dirname(cur);
    }
  }
  return out;
}

export async function loadCotalSdk() {
  const tried = [];
  for (const entry of sdkCandidates()) {
    tried.push(entry);
    if (!fs.existsSync(entry)) continue;
    try {
      return await import(pathToFileURL(entry).href);
    } catch (err) {
      tried.push(`  ^ import failed: ${err.message}`);
    }
  }
  // Last resort: normal resolution, in case it is a real dependency here.
  try {
    return await import(PKG);
  } catch {
    /* fall through */
  }
  const err = new Error(`${PKG} not found (tried ${tried.length} paths)`);
  err.tried = tried;
  throw err;
}

/** The upstream naming rule, reproduced only as a fallback when the SDK is absent. */
export function transcriptChannelFallback(name) {
  return `tr-${String(name).toLowerCase().replace(/[^a-z0-9_-]+/g, "-")}`;
}

/**
 * Create the Cotal sink. Never throws: on any failure it returns a broken sink,
 * and the tap keeps running with disk spooling only.
 */
export async function createCotalSink(ctx) {
  let sdk;
  try {
    sdk = await loadCotalSdk();
  } catch (err) {
    return brokenSink("cotal", err.message);
  }

  const { MeshAgent, configFromEnv } = sdk;
  if (typeof MeshAgent !== "function" || typeof configFromEnv !== "function") {
    return brokenSink("cotal", `${PKG} loaded but has no MeshAgent/configFromEnv`);
  }

  let config;
  try {
    config = configFromEnv();
  } catch (err) {
    // Most commonly: no identity (COTAL_NAME / COTAL_AGENT_FILE / COTAL_LINK).
    return brokenSink("cotal", `configFromEnv: ${err.message}`);
  }

  let agent;
  try {
    agent = new MeshAgent(config);
    if (typeof agent.start === "function") await agent.start();
  } catch (err) {
    return brokenSink("cotal", `MeshAgent start: ${err.message}`);
  }

  const timeoutMs = Number(process.env.TRANSCRIPT_PUBLISH_TIMEOUT_MS || 5000);

  return {
    name: "cotal",
    target: ctx.channel,
    ready: true,
    async publish(frame) {
      const text = renderChat(frame);
      await withTimeout(agent.send(text, ctx.channel), timeoutMs, "cotal publish");
    },
    async close() {
      try {
        if (typeof agent.stop === "function") await withTimeout(agent.stop(), 3000, "stop");
        else if (typeof agent.close === "function") await withTimeout(agent.close(), 3000, "close");
      } catch {
        /* teardown is best-effort */
      }
    },
  };
}

export function withTimeout(promise, ms, label) {
  if (!ms || ms <= 0) return Promise.resolve(promise);
  return new Promise((resolve, reject) => {
    const t = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms);
    Promise.resolve(promise).then(
      (v) => {
        clearTimeout(t);
        resolve(v);
      },
      (e) => {
        clearTimeout(t);
        reject(e);
      },
    );
  });
}
