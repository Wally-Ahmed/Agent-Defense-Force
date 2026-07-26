// adapters/common.js — shared adapter helpers.

import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { transcriptChannelFallback } from "../sinks/cotal.js";

/**
 * Channel naming. Uses Cotal's own transcriptChannel() when the SDK is loadable
 * so our names can never drift from the mesh's; otherwise reproduces the rule.
 * Resolved once, lazily, and cached.
 */
let cachedChannelFn = null;
export async function loadChannelFn() {
  if (cachedChannelFn) return cachedChannelFn;
  try {
    const { loadCotalSdk } = await import("../sinks/cotal.js");
    const sdk = await loadCotalSdk();
    if (typeof sdk.transcriptChannel === "function") {
      cachedChannelFn = sdk.transcriptChannel;
      return cachedChannelFn;
    }
  } catch {
    /* SDK absent — offline development */
  }
  cachedChannelFn = transcriptChannelFallback;
  return cachedChannelFn;
}

export function channelFor(agentId) {
  return (cachedChannelFn || transcriptChannelFallback)(agentId);
}

/**
 * Environment for the harness child.
 *
 * COTAL_* is stripped exactly as the upstream connectors do: the child must not
 * believe it is a Cotal-managed agent, and its mesh identity is ours, not its.
 * Our own process keeps those vars for the cotal sink.
 */
export function childEnv(extra = {}) {
  const out = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (k.startsWith("COTAL_")) continue;
    if (k.startsWith("TRANSCRIPT_")) continue;
    out[k] = v;
  }
  if (!out.TERM) out.TERM = "xterm-256color";
  const localBin = path.join(os.homedir(), ".local", "bin");
  if (!String(out.PATH || "").split(path.delimiter).includes(localBin)) {
    out.PATH = `${localBin}${path.delimiter}${out.PATH || ""}`;
  }
  return { ...out, ...extra };
}

/**
 * Approval-bypass flags are OFF by default and must be opted into explicitly.
 * The tap's job is to capture output, not to widen what a harness may do; every
 * runtime here has a "--dangerously-*"/"--yolo" flag and silently enabling them
 * would be a permission escalation hidden inside a logging change.
 */
export function unsafeAllowed() {
  return process.env.TRANSCRIPT_ALLOW_UNSAFE_HARNESS_FLAGS === "1";
}

/** Write a prompt to a temp file; returns {file, cleanup}. */
export function promptFile(runId, agentId, prompt) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `tap-${agentId}-`));
  const file = path.join(dir, "prompt.txt");
  fs.writeFileSync(file, prompt, "utf8");
  return {
    file,
    cleanup: () => fs.rmSync(dir, { recursive: true, force: true }),
  };
}

/** Try to parse a line as JSON; returns undefined when it is not JSON. */
export function tryJson(line) {
  const t = line.trim();
  if (!t.startsWith("{") && !t.startsWith("[")) return undefined;
  try {
    return JSON.parse(t);
  } catch {
    return undefined;
  }
}

/**
 * Render an arbitrary value for display WITHOUT truncating it. Completeness
 * over prettiness: an oversized value is split into sequenced parts downstream,
 * never cut here.
 */
export function show(v) {
  if (v === undefined || v === null) return "";
  if (typeof v === "string") return v;
  try {
    return JSON.stringify(v);
  } catch {
    return String(v);
  }
}

/** Indent a possibly multi-line block under a marker line. */
export function block(marker, text) {
  const body = String(text ?? "");
  if (!body) return [marker];
  return [marker, ...body.split("\n").map((l) => "  " + l)];
}
