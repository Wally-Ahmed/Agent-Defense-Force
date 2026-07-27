// mesh/effort_receipts/src/gate.js
//
// ==========================================================================
//  coordinator/effort_gate.jac IS THE AUTHORITATIVE GATE.
//
//  This module is a FAST PRE-CHECK for bring-up only. It exists so that a
//  broken mesh fails in milliseconds, with the SAME reason codes, BEFORE the
//  Jac coordinator is even started — so an operator watching up.sh sees
//  RECEIPT_DOWNGRADED immediately instead of after a full coordinator boot.
//
//  It is NOT a replacement for the Jac gate and it NEVER overrides the Jac
//  verdict. If the two ever disagree, the Jac gate is right and this file has
//  a bug. Nothing downstream may treat `open: true` here as permission to
//  leave WATCHING; only the coordinator decides that.
//
//  Every rule below deliberately mirrors effort_gate.jac line for line,
//  including the reason-code precedence chain, so keep them in lockstep.
// ==========================================================================

import fs from "node:fs";

import { AGENT_IDS } from "../../lib/agents.js";
import { ledgerPathFor, readReceiptsFile, validateReceipt } from "./receipt.js";

/** The six agents that must each produce exactly one receipt: monitor + 5 responders. */
export const CANONICAL_AGENTS = Object.freeze([...AGENT_IDS]);
export const REQUIRED_RECEIPTS = 6;

// Reason codes, strictest first — the order below IS the precedence order.
export const RECEIPTS_FILE_MISSING = "RECEIPTS_FILE_MISSING";
export const RECEIPT_INVALID = "RECEIPT_INVALID";
export const RECEIPT_DUPLICATE = "RECEIPT_DUPLICATE";
export const RECEIPTS_MISSING = "RECEIPTS_MISSING";
export const RECEIPT_DOWNGRADED = "RECEIPT_DOWNGRADED";
/** Empty string means the gate is open — same convention as the Jac gate. */
export const REASON_OK = "";

export const REASON_CODES = Object.freeze([
  RECEIPTS_FILE_MISSING,
  RECEIPT_INVALID,
  RECEIPT_DUPLICATE,
  RECEIPTS_MISSING,
  RECEIPT_DOWNGRADED,
]);

export const RUN_LABEL_LIVE = "LIVE";
export const RUN_LABEL_MOCKED = "MOCKED";

function sorted(list) {
  // Sorted, not de-duplicated: the Jac gate pushes one entry per receipt, so a
  // duplicated agent legitimately appears twice in downgraded/blocked/mocked and
  // collapsing it would hide the duplication.
  return [...list].sort();
}

/**
 * Evaluate already-parsed receipt records. Pure with respect to the run
 * directory — it never reads or writes runs/ — so tests can drive precedence
 * directly without laying down files.
 *
 * @param {{line: number, ok: boolean, error: string, receipt: object|null}[]} records
 */
export function evaluateReceipts(records) {
  const invalid = [];
  const receipts = [];
  const unexpected = [];
  const downgradedAgents = [];
  const blockedAgents = [];
  const mockedAgents = [];
  const counts = new Map();

  for (const record of Array.isArray(records) ? records : []) {
    if (!record || record.ok !== true || !record.receipt) {
      // Unparseable / non-object lines are REPORTED, never dropped. A dropped line
      // is a silent hole; a reported one fails the run visibly.
      const detail = record && record.error ? record.error : "not a JSON object";
      invalid.push(`line ${record ? record.line : "?"}: ${detail}`);
      continue;
    }

    const body = record.receipt;
    const errors = validateReceipt(body);
    if (errors.length) {
      const who = typeof body.agent === "string" ? body.agent : "?";
      const joined = errors.slice().sort().join("; ");
      invalid.push(`line ${record.line}: agent=${who}: effort_receipt.v1: ${joined}`);
      continue;
    }

    receipts.push(body);

    // The three flag lists are collected BEFORE the canonical-agent check, exactly
    // as the Jac gate does. A receipt from an agent we did not expect still tells
    // the truth about whether something in this run was blocked or mocked, and a
    // run must not be able to shed its MOCKED label by using an unrecognised id.
    if (body.downgraded === true) downgradedAgents.push(body.agent);
    if (body.blocked === true) blockedAgents.push(body.agent);
    if (body.mocked === true) mockedAgents.push(body.agent);

    if (!CANONICAL_AGENTS.includes(body.agent)) {
      unexpected.push(body.agent);
      continue; // an unexpected agent does not count toward the required six
    }

    counts.set(body.agent, (counts.get(body.agent) || 0) + 1);
  }

  const seen = sorted([...counts.keys()]);
  const duplicates = sorted([...counts.entries()].filter(([, n]) => n > 1).map(([agent]) => agent));
  const missing = sorted(CANONICAL_AGENTS.filter((agent) => !counts.has(agent)));

  // run_label is computed ALWAYS, including on every failure path. A run that
  // refuses to open the gate still has to be labeled honestly in its artifacts.
  // Invalid lines contribute nothing: an unreadable line proves nothing about
  // whether anything was mocked.
  const runLabel =
    blockedAgents.length > 0 || mockedAgents.length > 0 ? RUN_LABEL_MOCKED : RUN_LABEL_LIVE;

  const open =
    invalid.length === 0 &&
    duplicates.length === 0 &&
    missing.length === 0 &&
    seen.length === REQUIRED_RECEIPTS &&
    downgradedAgents.length === 0;

  // Precedence, strictest first — this if/else chain mirrors effort_gate.jac
  // exactly. Order matters: a file that is both invalid AND short reports
  // RECEIPT_INVALID, because we cannot know what the unreadable lines contained.
  let reason = REASON_OK;
  if (invalid.length > 0) {
    reason = RECEIPT_INVALID;
  } else if (duplicates.length > 0) {
    reason = RECEIPT_DUPLICATE;
  } else if (missing.length > 0 || seen.length !== REQUIRED_RECEIPTS) {
    reason = RECEIPTS_MISSING;
  } else if (downgradedAgents.length > 0) {
    reason = RECEIPT_DOWNGRADED;
  }

  return {
    open,
    reason,
    receipts,
    missing,
    // Line-ordered, not alphabetically sorted: these entries are keyed by line
    // number, so line order is both the stable order and the useful one.
    invalid,
    duplicates,
    run_label: runLabel,
    // Extras below are not part of the Jac gate's return, but are what an operator
    // needs to act on the reason code.
    detail: describe(reason, { missing, duplicates, invalid, downgraded: downgradedAgents, seen }),
    agents_seen: seen,
    receipts_seen: seen.length,
    unexpected: sorted(unexpected),
    downgraded: sorted(downgradedAgents),
    blocked: sorted(blockedAgents),
    mocked: sorted(mockedAgents),
  };
}

function describe(reason, { missing, duplicates, invalid, downgraded, seen }) {
  switch (reason) {
    case RECEIPTS_FILE_MISSING:
      return "runs/<id>/effort.jsonl does not exist — no agent has written a receipt yet";
    case RECEIPT_INVALID:
      return `${invalid.length} unusable receipt line(s): ${invalid.join(" | ")}`;
    case RECEIPT_DUPLICATE:
      return `more than one receipt for: ${duplicates.join(", ")}`;
    case RECEIPTS_MISSING:
      return `${seen.length}/${REQUIRED_RECEIPTS} receipts; missing: ${missing.join(", ") || "(none)"}`;
    case RECEIPT_DOWNGRADED:
      return `effort or model was weakened for: ${downgraded.join(", ")}`;
    default:
      return `all ${REQUIRED_RECEIPTS} receipts present, none downgraded`;
  }
}

function fileMissingResult(p) {
  return {
    open: false,
    reason: RECEIPTS_FILE_MISSING,
    receipts: [],
    missing: sorted(CANONICAL_AGENTS),
    invalid: [],
    duplicates: [],
    run_label: RUN_LABEL_LIVE,
    detail: `no receipt ledger at ${p}`,
    agents_seen: [],
    receipts_seen: 0,
    unexpected: [],
    downgraded: [],
    blocked: [],
    mocked: [],
    path: p,
  };
}

/** Pre-check the ledger at an absolute path. */
export function checkGateFile(absPath) {
  let isFile = false;
  try {
    isFile = fs.statSync(absPath).isFile();
  } catch {
    isFile = false;
  }
  if (!isFile) return fileMissingResult(absPath);

  const result = evaluateReceipts(readReceiptsFile(absPath));
  result.path = absPath;
  return result;
}

/**
 * Pre-check runs/<run_id>/effort.jsonl.
 *
 * @returns {{open: boolean, reason: string, receipts: object[], missing: string[],
 *            invalid: string[], duplicates: string[], run_label: string}}
 */
export function checkGate(runId) {
  return checkGateFile(ledgerPathFor(runId));
}
