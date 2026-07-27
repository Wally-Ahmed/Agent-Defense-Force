// mesh/effort_receipts/src/receipt.js — build, validate and append effort_receipt.v1 lines.
//
// One receipt per agent per run, appended as a single JSON line to
// runs/<id>/effort.jsonl. The schema at contracts/mesh/effort_receipt.v1.schema.json
// is FROZEN: it is the wire format the Jac coordinator gates on, so this module
// treats it as read-only law and validates against the file on disk rather than
// against a copy of the rules embedded here. If the contract ever moves, this
// module follows automatically instead of drifting.
//
// Zero npm dependencies is a hard constraint for the mesh bring-up path: the
// receipt writer runs at boot, before anything is installed, inside five
// different runtimes. That is why the JSON Schema validator below is hand-rolled
// rather than pulled from ajv.

import fs from "node:fs";
import path from "node:path";

import { CONTRACTS_DIR, RUNS_DIR, effortLedger } from "../../lib/paths.js";
import { AGENT_IDS, agentTable } from "../../lib/agents.js";

// ---------------------------------------------------------------------------
// Effort scale
// ---------------------------------------------------------------------------

/**
 * The unified reasoning-effort scale, weakest to strongest.
 *
 * Ordering is the whole point: "never silently downgraded" is only checkable if
 * two effort strings can be compared, and every runtime in the mesh speaks a
 * different dialect. This array is the single place that ordering lives.
 */
export const EFFORT_SCALE = ["none", "minimal", "low", "medium", "high", "xhigh", "max"];

/** Position on EFFORT_SCALE, or -1 when the string is not on the scale at all. */
export function effortRank(effort) {
  return EFFORT_SCALE.indexOf(typeof effort === "string" ? effort : String(effort));
}

// ---------------------------------------------------------------------------
// Minimal JSON Schema validator
// ---------------------------------------------------------------------------

// Supported keyword subset — deliberately small and honest about its limits:
//   type ("object" | "string" | "boolean" | "number" | "integer" | "array" | "null")
//   required, additionalProperties:false, properties (recursive), minLength, enum
// Anything else in a schema (allOf, $ref, pattern, format, items, ...) is IGNORED
// rather than guessed at. That is safe for the frozen effort receipt contract,
// which uses only the keywords above, but it means this must never be pointed at
// an arbitrary schema and trusted to be complete.

function isPlainObject(value) {
  // typeof null === "object" and arrays are objects too, so both must be excluded
  // before anything may be treated as a JSON object.
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function matchesType(value, type) {
  switch (type) {
    case "object":
      return isPlainObject(value);
    case "array":
      return Array.isArray(value);
    case "null":
      return value === null;
    case "string":
      return typeof value === "string";
    case "boolean":
      return typeof value === "boolean";
    case "number":
      return typeof value === "number" && Number.isFinite(value);
    case "integer":
      return Number.isInteger(value);
    default:
      // Unknown type keyword: report nothing rather than inventing a failure.
      return true;
  }
}

function repr(value) {
  if (value === undefined) return "undefined";
  try {
    return JSON.stringify(value);
  } catch {
    return String(value);
  }
}

function sameJson(a, b) {
  return a === b || repr(a) === repr(b);
}

/**
 * Validate `value` against `schema`. Returns an array of human-readable error
 * strings; an empty array means valid.
 *
 * @param {object} schema
 * @param {unknown} value
 * @param {string} at dotted path of the value being checked ("" at the root)
 * @returns {string[]}
 */
export function validateAgainstSchema(schema, value, at = "") {
  const errors = [];
  if (!isPlainObject(schema)) return errors;
  const where = at ? `${at}: ` : "";

  if (schema.type !== undefined) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type];
    if (!types.some((t) => matchesType(value, t))) {
      const named = types.map((t) => `'${t}'`).join(" or ");
      errors.push(`${where}${repr(value)} is not of type ${named}`);
      // A type mismatch makes every other keyword meaningless noise, so stop here.
      return errors;
    }
  }

  if (Array.isArray(schema.enum) && !schema.enum.some((allowed) => sameJson(allowed, value))) {
    errors.push(`${where}${repr(value)} is not one of ${repr(schema.enum)}`);
  }

  if (typeof value === "string" && Number.isFinite(schema.minLength) && value.length < schema.minLength) {
    errors.push(`${where}${repr(value)} should be non-empty (minLength ${schema.minLength})`);
  }

  if (isPlainObject(value)) {
    const props = isPlainObject(schema.properties) ? schema.properties : {};

    if (Array.isArray(schema.required)) {
      for (const key of schema.required) {
        if (!Object.hasOwn(value, key)) errors.push(`${where}'${key}' is a required property`);
      }
    }

    if (schema.additionalProperties === false) {
      for (const key of Object.keys(value)) {
        if (!Object.hasOwn(props, key)) {
          errors.push(`${where}'${key}' was unexpected (additionalProperties is false)`);
        }
      }
    }

    for (const [key, sub] of Object.entries(props)) {
      if (!Object.hasOwn(value, key)) continue;
      errors.push(...validateAgainstSchema(sub, value[key], at ? `${at}.${key}` : key));
    }
  }

  return errors;
}

let SCHEMA_CACHE = null;

/** The frozen effort_receipt.v1 schema, read once and cached for the process. */
export function loadEffortSchema() {
  if (SCHEMA_CACHE) return SCHEMA_CACHE;
  const p = path.join(CONTRACTS_DIR, "effort_receipt.v1.schema.json");
  SCHEMA_CACHE = JSON.parse(fs.readFileSync(p, "utf8"));
  return SCHEMA_CACHE;
}

/** @returns {string[]} schema errors for one receipt; empty means valid. */
export function validateReceipt(receipt) {
  return validateAgainstSchema(loadEffortSchema(), receipt);
}

// ---------------------------------------------------------------------------
// Downgrade detection
// ---------------------------------------------------------------------------

/**
 * Was this agent silently weakened relative to what we pinned?
 *
 * @param {{modelRequested: string, modelEffective: string,
 *          effortRequested: string, effortEffective: string,
 *          effortCeiling?: string|null}} args
 * @returns {boolean}
 */
export function isDowngraded({
  modelRequested,
  modelEffective,
  effortRequested,
  effortEffective,
  effortCeiling = null,
}) {
  // A substituted model is a downgrade no matter what the effort says and no
  // matter what ceiling the agent declares. An effort ceiling is a statement
  // about how strongly THIS model can be asked to think; it says nothing about
  // being handed a different model, so it must never rescue a substitution.
  // This check is first precisely so the ceiling exception below cannot reach it.
  if (String(modelEffective) !== String(modelRequested)) return true;

  // CEILING EXCEPTION — why this is not a loophole:
  // Some runtimes cannot express the top of EFFORT_SCALE at all. responder_antigravity
  // pins effort "high" with effort_ceiling "high" because `agy --effort` only accepts
  // (low|medium|high): "high" IS agy's maximum. Reading back "high" there is the
  // strongest setting that runtime can physically express, so calling it a downgrade
  // would report a false positive and block a mesh that is in fact running flat out.
  // The ceiling comes from our own committed mesh/config/models.json, is reviewed with
  // the rest of the pins, and is checked by exact string equality against the value
  // READ BACK from the runtime — so this branch only fires when the runtime confirms
  // it is sitting at its documented maximum.
  //
  // Judgement call: this exception is evaluated BEFORE the unknown-effort check
  // below. An off-scale string that exactly equals the declared ceiling is a runtime
  // CONFIRMING its documented maximum, which is positive evidence, not the absence
  // of evidence that the fail-closed rule exists to catch.
  if (effortCeiling && String(effortEffective) === String(effortCeiling)) return false;

  const requested = effortRank(effortRequested);
  const effective = effortRank(effortEffective);

  // Fail closed on an unrecognised EFFECTIVE effort: the runtime reported something
  // we cannot place on the scale, so we cannot prove it is as strong as what we asked
  // for. "Unprovable" and "fine" are not the same thing, and the whole point of this
  // receipt is that a downgrade is provable rather than assumed. An unrecognised
  // REQUESTED effort is not treated the same way — that value comes from our own
  // config, and a rank of -1 there simply cannot be beaten downward.
  if (effective < 0) return true;

  return effective < requested;
}

// ---------------------------------------------------------------------------
// Receipt construction
// ---------------------------------------------------------------------------

let AGENTS_CACHE = null;

function agents() {
  // agentTable() re-reads and cross-checks mesh/config/models.json on every call;
  // the pins cannot change mid-process, so read them once.
  if (!AGENTS_CACHE) AGENTS_CACHE = agentTable();
  return AGENTS_CACHE;
}

function asString(value) {
  if (typeof value === "string") return value;
  if (value === undefined || value === null) return "";
  return String(value);
}

function hasText(value) {
  return asString(value).trim().length > 0;
}

function textOr(value, fallback) {
  // Every string field in the contract carries minLength 1, so a blank value must
  // never reach the ledger — an empty string would be rejected by the gate and the
  // whole run would fail on a formatting detail instead of reporting the real state.
  return hasText(value) ? asString(value) : fallback;
}

/** The exact key order of the frozen contract, so emitted lines are byte-stable. */
const RECEIPT_KEYS = [
  "agent",
  "runtime",
  "runtime_version",
  "model_requested",
  "model_effective",
  "effort_requested",
  "effort_effective",
  "source",
  "downgraded",
  "blocked",
  "mocked",
];

/**
 * Build a complete effort_receipt.v1 object for one agent.
 *
 * @param {{agentId: string,
 *          probe?: {runtime_version?: string, model_effective?: string,
 *                   effort_effective?: string, source?: string, evidence?: unknown,
 *                   ok?: boolean, error?: string},
 *          mocked?: boolean, blocked?: boolean}} args
 * @returns {object} an object with exactly the eleven contract keys
 */
export function buildReceipt({ agentId, probe = {}, mocked = false, blocked = false } = {}) {
  const spec = agents()[agentId];
  if (!spec) {
    throw new Error(
      `buildReceipt: unknown agentId ${JSON.stringify(agentId)} — expected one of ${AGENT_IDS.join(", ")}`,
    );
  }

  const p = isPlainObject(probe) ? probe : {};

  // `runtime` is the TAP runtime name, not models.json's runtime key. The two
  // disagree for exactly one agent: models.json calls Claude's harness "claude"
  // while contracts/mesh/channels.yaml calls it "claude_code". The receipt is read
  // by the coordinator alongside the channel contract, so it must speak the
  // contract's vocabulary or the two artifacts will not join up.
  const runtime = spec.tap_runtime;

  // The contract says model_requested is an OpenRouter id, so the pin's OpenRouter
  // form is authoritative here even when the runtime is driven by its native name.
  const modelRequested = spec.model_openrouter;
  const effortRequested = spec.effort;

  const probeOk = p.ok === true;
  const readBackValues = hasText(p.model_effective) && hasText(p.effort_effective);
  const isBlocked = blocked === true || !probeOk || !readBackValues;

  if (isBlocked) {
    // BLOCKED: the runtime is missing, unauthenticated, or gave us nothing to read
    // back. The pinned model is RETAINED verbatim rather than substituted or
    // blanked — the pin is still what we asked for and still what will run the
    // moment the block clears, and writing anything else here would fabricate a
    // substitution that never happened.
    //
    // A CLI can print --version while still refusing to run unauthenticated, so a
    // version the probe genuinely read is kept even on this path.
    const version = textOr(p.runtime_version, "unknown");
    const source = textOr(p.error, textOr(p.source, `${runtime}: blocked, no probe result`));

    return freezeShape({
      agent: agentId,
      runtime,
      runtime_version: version,
      model_requested: modelRequested,
      model_effective: modelRequested,
      effort_requested: effortRequested,
      effort_effective: effortRequested,
      source,
      // A blocked agent is NOT a downgraded agent. `downgraded` reports what was
      // actually read back and contradicted the pin; a blocked agent read back
      // nothing at all, so nothing contradicts it. The blocked/mocked flags already
      // say this agent has not run, and forcing downgraded:true here would conflate
      // "not authenticated yet" with "silently weakened" — two very different
      // failures that the coordinator reports with two different reason codes.
      downgraded: false,
      blocked: true,
      // Blocked implies mocked: nothing live produced this receipt, so the run is
      // not an acceptance run and every artifact it touches must be labeled MOCKED.
      mocked: true,
    });
  }

  const modelEffective = asString(p.model_effective);
  const effortEffective = asString(p.effort_effective);

  return freezeShape({
    agent: agentId,
    runtime,
    runtime_version: textOr(p.runtime_version, "unknown"),
    model_requested: modelRequested,
    model_effective: modelEffective,
    effort_requested: effortRequested,
    effort_effective: effortEffective,
    // `source` is the provenance of the two values above. A successful probe that
    // failed to record where it read them is a probe bug; say so instead of
    // emitting an empty string the gate would reject.
    source: textOr(p.source, `${runtime}: probe succeeded, source not recorded`),
    downgraded: isDowngraded({
      modelRequested,
      modelEffective,
      effortRequested,
      effortEffective,
      effortCeiling: spec.effort_ceiling,
    }),
    blocked: false,
    mocked: Boolean(mocked),
  });
}

function freezeShape(receipt) {
  // additionalProperties:false means one stray key (probe.evidence being the obvious
  // temptation) invalidates the whole line, so the object is rebuilt key by key from
  // the contract's own list rather than spread from anything.
  const out = {};
  for (const key of RECEIPT_KEYS) out[key] = receipt[key];
  return out;
}

// ---------------------------------------------------------------------------
// Ledger IO
// ---------------------------------------------------------------------------

/**
 * runs/<run_id>/effort.jsonl WITHOUT creating anything.
 *
 * paths.effortLedger() mkdirs the run directory as a side effect, which is right
 * for a writer and wrong for a reader — a gate check on a run id that does not
 * exist must not bring that run into existence.
 */
export function ledgerPathFor(runId) {
  return path.join(RUNS_DIR, String(runId), "effort.jsonl");
}

/**
 * Parse JSONL exactly the way coordinator/effort_gate.jac's parse_receipts does.
 *
 * Line numbers are 1-based and count EVERY line including blanks, so a reported
 * line number can be found with an editor. Blank lines are skipped entirely and
 * are not records. A line that is not parseable, or that parses to something that
 * is not a JSON object, becomes a failed record — never a dropped one, because a
 * dropped line is a silent hole in the audit trail.
 *
 * @returns {{line: number, ok: boolean, error: string, raw: string, receipt: object|null}[]}
 */
export function parseReceiptLines(text) {
  const out = [];
  const lines = String(text).split("\n");
  for (let i = 0; i < lines.length; i += 1) {
    const lineNo = i + 1;
    const raw = lines[i];
    if (raw.trim() === "") continue;

    let body;
    try {
      body = JSON.parse(raw);
    } catch (err) {
      out.push({ line: lineNo, ok: false, error: `not parseable JSON (${err.name})`, raw, receipt: null });
      continue;
    }

    if (!isPlainObject(body)) {
      out.push({ line: lineNo, ok: false, error: "not a JSON object", raw, receipt: null });
      continue;
    }

    out.push({ line: lineNo, ok: true, error: "", raw, receipt: body });
  }
  return out;
}

/** Parse records for one run's ledger. Returns [] when the file does not exist. */
export function readReceipts(runId) {
  return readReceiptsFile(ledgerPathFor(runId));
}

/** Parse records for a ledger at an absolute path. Returns [] when absent. */
export function readReceiptsFile(absPath) {
  let text;
  try {
    if (!fs.statSync(absPath).isFile()) return [];
    text = fs.readFileSync(absPath, "utf8");
  } catch {
    return [];
  }
  return parseReceiptLines(text);
}

/**
 * Append one receipt to runs/<run_id>/effort.jsonl.
 *
 * @returns {{path: string, written: boolean, reason: string}}
 */
export function writeReceipt(runId, receipt) {
  // Validate BEFORE touching the filesystem. The coordinator reports an unparseable
  // or off-contract line as RECEIPT_INVALID and refuses to leave WATCHING, and an
  // append-only ledger has no way to take a bad line back. Failing loudly in the
  // writer is the only place this can still be fixed, so a line the Jac gate would
  // reject must never reach the disk.
  const errors = validateReceipt(receipt);
  if (errors.length) {
    throw new Error(`effort_receipt.v1: ${errors.slice().sort().join("; ")}`);
  }

  const p = effortLedger(runId);

  // Idempotent per agent per run. A second boot of the same agent (a retried
  // supervisor, a re-run of up.sh) must be a no-op: the gate rejects two receipts
  // for one agent with RECEIPT_DUPLICATE, so appending again would turn a harmless
  // restart into a hard gate failure.
  for (const record of readReceiptsFile(p)) {
    if (!record.ok || !record.receipt) continue;
    if (record.receipt.agent !== receipt.agent) continue;
    if (validateReceipt(record.receipt).length === 0) {
      return { path: p, written: false, reason: "already_present" };
    }
  }

  // JSONL: one object per line, no pretty-printing, no wrapping array.
  const buf = Buffer.from(`${JSON.stringify(receipt)}\n`, "utf8");

  // Atomicity: O_APPEND plus a SINGLE write syscall. Six agents boot concurrently
  // and all append to this one file, so the append offset must be chosen by the
  // kernel per write rather than by a seek this process performs. One write of the
  // complete line plus its newline is what keeps two agents from interleaving
  // halves of each other's receipts.
  //
  // The worst case is still bounded and visible: a torn write corrupts exactly one
  // line, and the gate REPORTS that line as invalid rather than dropping it, so the
  // run fails loudly instead of quietly gating on five receipts it thinks are six.
  const fd = fs.openSync(p, "a");
  try {
    const written = fs.writeSync(fd, buf);
    if (written !== buf.length) {
      throw new Error(
        `writeReceipt: short write for agent ${receipt.agent} (${written}/${buf.length} bytes) — ${p} may hold a partial line`,
      );
    }
    // fsync before the process exits: a receipt still sitting in the page cache is
    // not evidence, and the coordinator may read this file within milliseconds.
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }

  return { path: p, written: true, reason: "appended" };
}
