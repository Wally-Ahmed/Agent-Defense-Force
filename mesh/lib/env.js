// mesh/lib/env.js — the ONE place the mesh runtime reads the repo-root .env.
//
// WHY THIS FILE EXISTS. Before it, nothing in mesh/ loaded .env. The operator had
// to export OPENROUTER_API_KEY by hand, and when they did not, run.js's preflight()
// read `process.env.OPENROUTER_API_KEY`, found it empty, and reported the three
// OpenRouter-backed agents (monitor on hermes, responder_kimi and responder_glm on
// opencode) as BLOCKED. That conclusion was recorded across the repo as fact. It was
// wrong: the key was in .env the whole time, valid, and both CLIs read it straight
// out of their inherited environment. The gap was ours, not the harnesses'.
//
// So there is exactly one loader, it is called from the entry points, and every
// child harness inherits the result through the tap's childEnv().
//
// CREDENTIAL RULE, enforced by construction:
//   * no function here returns, prints, logs or stores a VALUE — only names and
//     booleans leave this module;
//   * values are written into process.env and nowhere else;
//   * writing into process.env is also what keeps the transcript tap's redaction
//     covering them: tap.js calls secretsFromEnv(process.env), whose
//     SENSITIVE_NAME_COMPOUND (/API_?KEY/i) matches OPENROUTER_API_KEY, so the key
//     is registered as a literal to scrub from every captured byte. A key exported
//     only into a child's env would be invisible to that scrubber. Loading it HERE
//     is therefore the safe option, not merely the convenient one.
//
// PRECEDENCE: a variable already present in the real environment always wins. .env
// fills gaps; it never overrides what the operator deliberately exported.

import fs from "node:fs";
import path from "node:path";
import { REPO_ROOT } from "./paths.js";

export const ENV_PATH = path.join(REPO_ROOT, ".env");

/**
 * Parse dotenv text into a plain object.
 *
 * Deliberately small and total — this runs at mesh bring-up, before anything is
 * installed, so it takes no dependency. Handled: comments, blank lines, an
 * optional `export ` prefix, CRLF, single/double quotes, and inline `#` comments
 * on UNQUOTED values only (a `#` inside quotes is data, and an OpenRouter key can
 * legitimately contain one).
 *
 * @param {string} text
 * @returns {Record<string,string>}
 */
export function parseEnv(text) {
  const out = {};
  for (const rawLine of String(text).split("\n")) {
    const line = rawLine.replace(/\r$/, "");
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;

    const m = trimmed.match(/^(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$/);
    if (!m) continue;
    const name = m[1];
    let value = m[2];

    const quote = value[0];
    if (quote === '"' || quote === "'") {
      const end = value.lastIndexOf(quote);
      value = end > 0 ? value.slice(1, end) : value.slice(1);
      // Only double quotes carry escapes in dotenv, matching `set -a; . ./.env`.
      if (quote === '"') value = value.replace(/\\n/g, "\n").replace(/\\"/g, '"');
    } else {
      const hash = value.indexOf(" #");
      if (hash >= 0) value = value.slice(0, hash);
      value = value.trim();
    }
    out[name] = value;
  }
  return out;
}

let LOADED = null;

/**
 * Load the repo-root .env into process.env, once per process.
 *
 * @param {{file?: string, force?: boolean}} [opts]
 * @returns {{path: string, exists: boolean, applied: string[], skipped: string[]}}
 *   `applied`/`skipped` are variable NAMES only — never values.
 */
export function loadRepoEnv(opts = {}) {
  const file = opts.file || ENV_PATH;
  if (LOADED && LOADED.path === file && !opts.force) return LOADED;

  const result = { path: file, exists: false, applied: [], skipped: [] };

  let text;
  try {
    text = fs.readFileSync(file, "utf8");
    result.exists = true;
  } catch {
    // No .env is a legitimate configuration (CI, a box where everything is
    // exported already). It is not an error and must not be fatal at bring-up.
    LOADED = result;
    return result;
  }

  for (const [name, value] of Object.entries(parseEnv(text))) {
    const existing = process.env[name];
    if (typeof existing === "string" && existing.trim() !== "") {
      result.skipped.push(name);
      continue;
    }
    process.env[name] = value;
    result.applied.push(name);
  }

  LOADED = result;
  return result;
}

/**
 * Is `name` set to a non-empty value, in the real environment or in .env?
 *
 * Returns a BOOLEAN. The value is compared against empty and dropped; it is never
 * returned, logged or written anywhere. This is the presence check every preflight
 * and probe in the mesh should use, so "not exported in my shell" can never again
 * be mistaken for "the credential does not exist".
 *
 * An EMPTY value is treated as no value, on both sides. An empty string carries no
 * information — it is what an unset shell variable expands to and what a leftover
 * `export FOO=` leaves behind — so it is never taken as a deliberate "absent"
 * signal that should stop us reading .env. That misreading is the entire bug this
 * module exists to close.
 *
 * @param {string} name
 * @param {string} [envFile] the dotenv file to consult; defaults to the repo root's.
 *   Overridable so a caller can point the mesh at a different environment (and so a
 *   test can assert the genuinely-absent path without touching the real .env). It is
 *   a path, never a value.
 * @returns {boolean}
 */
export function envPresent(name, envFile = ENV_PATH) {
  const live = process.env[name];
  if (typeof live === "string" && live.trim() !== "") return true;
  try {
    const v = parseEnv(fs.readFileSync(envFile, "utf8"))[name];
    return typeof v === "string" && v.trim() !== "";
  } catch {
    return false;
  }
}
