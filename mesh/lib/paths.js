// mesh/lib/paths.js — repo-relative path resolution.
//
// Everything resolves from THIS FILE's location, never from cwd. up.sh,
// run_live.sh, the runner and the receipt writer are all invoked from different
// working directories, and a cwd-relative path would silently write a run
// artifact into whatever directory the operator happened to be standing in.

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));

/** Repo root = mesh/lib/.. /.. */
export const REPO_ROOT = path.resolve(HERE, "..", "..");

export const MESH_DIR = path.join(REPO_ROOT, "mesh");
export const CONTRACTS_DIR = path.join(REPO_ROOT, "contracts", "mesh");
export const RUNS_DIR = path.join(REPO_ROOT, "runs");

/** Directory for one run's artifacts. Created on demand. */
export function runDir(runId) {
  const d = path.join(RUNS_DIR, runId);
  fs.mkdirSync(d, { recursive: true });
  return d;
}

/** runs/<run_id>/effort.jsonl — the effort receipt ledger the coordinator gates on. */
export function effortLedger(runId) {
  return path.join(runDir(runId), "effort.jsonl");
}

/** runs/<run_id>/assessments/<agent>.json — one responder's DM'd assessment. */
export function assessmentPath(runId, agentId) {
  const d = path.join(runDir(runId), "assessments");
  fs.mkdirSync(d, { recursive: true });
  return path.join(d, `${agentId}.json`);
}

/** A sortable, collision-resistant run id. */
export function newRunId(prefix = "run") {
  const t = new Date().toISOString().replace(/[-:]/g, "").replace(/\..+/, "");
  return `${prefix}-${t}-${Math.random().toString(36).slice(2, 8)}`;
}

export function readJson(p) {
  return JSON.parse(fs.readFileSync(p, "utf8"));
}
