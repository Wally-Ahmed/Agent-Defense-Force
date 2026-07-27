// mesh/report/src/report.js — the mesh run-report generator.
//
// Reads one run's frozen artifacts under runs/<run_id>/ and renders an audit
// artifact (markdown + JSON) whose single most important claim is the RUN LABEL:
// was this run LIVE, or was any part of it mocked, blocked or downgraded?
//
// Two properties drive every design choice here:
//
//  1. A mocked run must NEVER be able to read as live. The label defaults to
//     MOCKED and is only upgraded to LIVE when all six agents produced a receipt
//     and every one of those receipts explicitly says blocked:false, mocked:false
//     and downgraded:false. A missing or non-boolean flag is not "probably fine",
//     it is not-LIVE — absence of evidence is not evidence of a live call.
//
//  2. The report must never crash and never silently understate. A missing file,
//     an empty file, a malformed JSONL line or an absent field degrades to the
//     literal strings `missing` / `n/a` / `unpriced` and is surfaced in the
//     report itself, because a report that dies on a partial run is useless
//     exactly when it is needed most.
//
// Cost is recomputed from the frozen table (contracts/mesh/prices.json, via
// mesh/lib/prices.js) rather than trusted from the assessment, and a model with
// no entry in that table renders `unpriced` — never $0.00. A confident zero in an
// audit artifact is a lie; an explicit "unpriced" is not.

import fs from "node:fs";
import path from "node:path";

import { RUNS_DIR, readJson } from "../../lib/paths.js";
import { estimateUsd, isPriced } from "../../lib/prices.js";
import { AGENT_IDS, agentTable, openrouterId } from "../../lib/agents.js";

export const REPORT_SCHEMA = "run_report.v1";

/** Cell literals. These are contract-visible strings — tests assert on them. */
export const MISSING_CELL = "missing";
export const UNPRICED_CELL = "unpriced";
export const NA_CELL = "n/a";
export const NONE_CELL = "none";

/** Hard cap on any free-text value echoed into the report. */
export const MAX_TEXT = 200;

/**
 * The coordinator has not pinned its output path yet, so probe in order and take
 * the first that exists. Exported so the list is testable and cheap to extend
 * when the driver does pin it.
 */
export const DECISION_CANDIDATES = [
  "decision.json",
  "coordinator/decision.json",
  "decision.v1.json",
];

/** Same story for the containment service's result artifact. */
export const CONTAINMENT_CANDIDATES = [
  "containment.json",
  "containment/result.json",
  "containment_result.json",
];

// ---------------------------------------------------------------------------
// text hygiene
// ---------------------------------------------------------------------------

/**
 * Best-effort scrub of anything credential-shaped before it reaches the report.
 * Receipts and decisions carry no secrets by contract, but this file echoes
 * provenance strings and parser error text that were produced by other
 * processes, and a run report is an artifact people paste into chat.
 */
export function redact(text) {
  return String(text)
    .replace(/-----BEGIN[^-]*-----[\s\S]*?-----END[^-]*-----/g, "[redacted-pem]")
    .replace(/-----BEGIN[^-]*-----/g, "[redacted-pem]")
    .replace(/\b(?:sk|pk|rk|ghp|gho|ghs|github_pat|xox[abpsr])[-_][A-Za-z0-9_-]{8,}/gi, "[redacted]")
    .replace(/\b(?:Bearer|token|api[_-]?key|secret|password)\s*[:=]?\s*[A-Za-z0-9._~+/-]{12,}=*/gi, "[redacted]")
    .replace(/\b[A-Fa-f0-9]{40,}\b/g, "[redacted-hex]");
}

/** Truncate to MAX_TEXT with an explicit marker, so truncation is never silent. */
export function truncate(value, max = MAX_TEXT) {
  const s = String(value);
  return s.length <= max ? s : `${s.slice(0, max)}…[truncated ${s.length} chars]`;
}

/** Redact + truncate + flatten. Everything free-text goes through this. */
export function safeText(value, max = MAX_TEXT) {
  if (value === null || value === undefined) return "";
  return truncate(redact(String(value).replace(/\s+/g, " ").trim()), max);
}

/** Markdown table cells cannot contain a bare pipe or a newline. */
export function escapeCell(value) {
  const s = value === null || value === undefined ? "" : String(value);
  return s.replace(/\|/g, "\\|").replace(/\r?\n/g, " ");
}

// ---------------------------------------------------------------------------
// I/O that cannot throw
// ---------------------------------------------------------------------------

function describeError(err) {
  const code = err && err.code ? `${err.code}: ` : "";
  return safeText(`${code}${(err && err.message) || String(err)}`);
}

/**
 * readJson() from mesh/lib, wrapped so a missing or corrupt file degrades into
 * data instead of an exception. Never throws.
 */
export function safeReadJson(filePath) {
  try {
    const value = readJson(filePath);
    return { ok: true, value, error: null };
  } catch (err) {
    return { ok: false, value: null, error: describeError(err) };
  }
}

/** mesh/config/models.json is a contract, but a broken one must not kill the report. */
export function safeAgentTable() {
  try {
    return { ok: true, table: agentTable(), error: null };
  } catch (err) {
    return { ok: false, table: {}, error: describeError(err) };
  }
}

// ---------------------------------------------------------------------------
// run layout
// ---------------------------------------------------------------------------
//
// These take an explicit run root rather than a run id so the whole pipeline can
// be pointed at a fixture directory in tmpdir. They intentionally do NOT call
// paths.js's runDir()/effortLedger()/assessmentPath(), because those mkdir on
// demand — a *reporting* tool must not mutate the run it audits, and creating
// runs/<id>/ as a side effect would defeat the "run does not exist" check below.
// test/report.test.js asserts these stay byte-identical to the paths.js layout.

export function resolveRunRoot(runId) {
  return path.join(RUNS_DIR, String(runId));
}

export function effortLedgerPath(runRoot) {
  return path.join(runRoot, "effort.jsonl");
}

export function assessmentFilePath(runRoot, agentId) {
  return path.join(runRoot, "assessments", `${agentId}.json`);
}

export function runExists(runRoot) {
  try {
    return fs.statSync(runRoot).isDirectory();
  } catch {
    return false;
  }
}

/**
 * First existing candidate, relative to the run root. Returns null when none of
 * them exist — which is a legitimate state, not an error.
 */
export function probeCandidates(runRoot, candidates) {
  for (const rel of candidates) {
    const abs = path.join(runRoot, rel);
    try {
      if (fs.statSync(abs).isFile()) return { relative: rel, absolute: abs };
    } catch {
      // candidate absent; keep probing
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// effort.jsonl
// ---------------------------------------------------------------------------

/**
 * Parse the effort ledger line by line. A malformed line is skipped and recorded
 * in parse_errors rather than aborting: one corrupt receipt must not hide the
 * five good ones, and the corruption itself is reportable evidence.
 */
export function readEffortLedger(ledgerPath) {
  const out = {
    ledger_path: ledgerPath,
    present: false,
    lines_read: 0,
    receipts: [],
    parse_errors: [],
  };

  let raw;
  try {
    raw = fs.readFileSync(ledgerPath, "utf8");
  } catch (err) {
    out.parse_errors.push({ line: 0, reason: `effort.jsonl unreadable — ${describeError(err)}` });
    return out;
  }
  out.present = true;

  const lines = raw.split(/\r?\n/);
  for (let i = 0; i < lines.length; i += 1) {
    const text = lines[i].trim();
    if (!text) continue;
    out.lines_read += 1;
    let obj;
    try {
      obj = JSON.parse(text);
    } catch (err) {
      // Deliberately no excerpt of the bad line: the parser message is enough to
      // locate it and echoing raw bytes is how a report leaks something.
      out.parse_errors.push({ line: i + 1, reason: `malformed JSON — ${describeError(err)}` });
      continue;
    }
    if (!obj || typeof obj !== "object" || Array.isArray(obj)) {
      out.parse_errors.push({ line: i + 1, reason: "malformed receipt — line is not a JSON object" });
      continue;
    }
    out.receipts.push(obj);
  }
  return out;
}

// ---------------------------------------------------------------------------
// the run label
// ---------------------------------------------------------------------------

function uniq(list) {
  return [...new Set(list)];
}

function agentOf(receipt) {
  const a = receipt && receipt.agent;
  return typeof a === "string" && a.trim() ? a.trim() : "(unnamed-agent)";
}

/**
 * The single most important output of this tool.
 *
 * MOCKED unless proven LIVE. `downgraded` is called out separately and loudly:
 * a run that quietly dropped to a lower reasoning effort is not the run we
 * claimed to make, so it can never render as live.
 *
 * @param {object[]} receipts parsed effort_receipt.v1 objects
 * @returns {{label:string, reasons:string[], blocked:string[], mocked:string[],
 *            downgraded:string[], missing:string[]}}
 */
export function computeLabel(receipts) {
  const list = Array.isArray(receipts) ? receipts.filter((r) => r && typeof r === "object") : [];

  const blocked = [];
  const mocked = [];
  const downgraded = [];
  const nonBoolean = [];
  const seen = new Set();

  for (const r of list) {
    const agent = agentOf(r);
    seen.add(agent);
    if (r.blocked === true) blocked.push(agent);
    if (r.mocked === true) mocked.push(agent);
    if (r.downgraded === true) downgraded.push(agent);
    for (const field of ["blocked", "mocked", "downgraded"]) {
      if (typeof r[field] !== "boolean") nonBoolean.push(`${agent}.${field}`);
    }
  }

  const blockedU = uniq(blocked);
  const mockedU = uniq(mocked);
  const downgradedU = uniq(downgraded);
  const nonBooleanU = uniq(nonBoolean);
  const missing = AGENT_IDS.filter((id) => !seen.has(id));

  const reasons = [];
  // Downgrade first: it is the reason most likely to be glossed over.
  if (downgradedU.length) reasons.push(`DOWNGRADED: ${downgradedU.join(", ")}`);
  if (blockedU.length) reasons.push(`BLOCKED: ${blockedU.join(", ")}`);
  if (mockedU.length) reasons.push(`MOCKED_FLAG: ${mockedU.join(", ")}`);
  if (list.length < AGENT_IDS.length) {
    reasons.push(`RECEIPT_COUNT: ${list.length} of ${AGENT_IDS.length} expected receipts`);
  }
  if (missing.length) reasons.push(`MISSING_RECEIPT: ${missing.join(", ")}`);
  if (nonBooleanU.length) {
    reasons.push(`FLAG_NOT_BOOLEAN: ${nonBooleanU.join(", ")}`);
  }

  const label = reasons.length ? "MOCKED" : "LIVE";
  if (!reasons.length) {
    reasons.push(
      `LIVE: ${AGENT_IDS.length} of ${AGENT_IDS.length} receipts, none blocked, mocked or downgraded`,
    );
  }

  return { label, reasons, blocked: blockedU, mocked: mockedU, downgraded: downgradedU, missing };
}

// ---------------------------------------------------------------------------
// pricing
// ---------------------------------------------------------------------------

/**
 * A receipt's model_effective can arrive as prose with a trailing parenthetical —
 * the offline monitor backend writes "z-ai/glm-5.2 (offline deterministic
 * backend)" — and harnesses use native short ids. The price table is keyed by
 * OpenRouter id only, so normalise before looking anything up. This is a naming
 * map, never a substitution: an unrecognised model stays unrecognised.
 *
 * The parenthetical form is now the exception rather than the rule: as of
 * 2026-07-26 all six agents run live and write bare OpenRouter ids. The split is
 * kept because the offline backend still exists as a labelled fallback.
 */
export function normalizeModelKey(raw) {
  if (typeof raw !== "string") return null;
  const base = raw.split(" (")[0].trim();
  if (!base) return null;
  return openrouterId(base);
}

function safeIsPriced(key) {
  if (!key) return false;
  try {
    return isPriced(key);
  } catch {
    return false; // price table unreadable — treat everything as unpriced, loudly
  }
}

/**
 * Pick the model id to price against: the FIRST identity we have, in order of
 * authority (what the responder said it used > what the receipt says was
 * effective > what was requested > what the agent table pins).
 *
 * It deliberately does NOT keep scanning for a candidate the price table happens
 * to know. Falling through to a cheaper-but-known neighbour would invent a cost
 * for a model we cannot price — the precise failure mode mesh/lib/prices.js
 * refuses. Once the identity is fixed, it is either in the frozen table or the
 * row is `unpriced`, full stop.
 */
export function resolvePriceKey({ assessment, receipt, tableEntry }) {
  const candidates = [
    assessment && assessment.model,
    receipt && receipt.model_effective,
    receipt && receipt.model_requested,
    tableEntry && tableEntry.model_openrouter,
  ];
  for (const candidate of candidates) {
    const key = normalizeModelKey(candidate);
    if (key) return { key, priced: safeIsPriced(key) };
  }
  return { key: null, priced: false };
}

/** estimateUsd() wrapped so a missing/corrupt price table degrades to unpriced. */
export function safeEstimateUsd(modelKey, usage) {
  if (!modelKey) return { usd: 0, priced: false, error: "no model id available" };
  try {
    const r = estimateUsd(modelKey, usage || {});
    return { usd: r.usd, priced: r.priced, error: null };
  } catch (err) {
    return { usd: 0, priced: false, error: describeError(err) };
  }
}

// ---------------------------------------------------------------------------
// per-agent rows
// ---------------------------------------------------------------------------

function num(value) {
  return typeof value === "number" && Number.isFinite(value) ? value : null;
}

function fmtInt(value) {
  const n = num(value);
  return n === null ? null : String(Math.trunc(n));
}

function fmtConfidence(value) {
  const n = num(value);
  return n === null ? null : n.toFixed(4);
}

/** Six decimals: estimateUsd rounds to 1e-6 and an audit artifact should not lose it. */
export function fmtUsd(value) {
  const n = num(value);
  return n === null ? MISSING_CELL : `$${n.toFixed(6)}`;
}

/**
 * Build one table row per expected agent. Never skips an agent, never emits a
 * zero or a blank for data it does not have.
 */
export function buildAgentRows({ runRoot, receipts, table }) {
  const byAgent = new Map();
  for (const r of receipts) {
    const id = agentOf(r);
    if (!byAgent.has(id)) byAgent.set(id, []);
    byAgent.get(id).push(r);
  }

  const rows = [];
  for (const agentId of AGENT_IDS) {
    const agentReceipts = byAgent.get(agentId) || [];
    // Display the newest receipt, but OR the flags across all of them: a run that
    // was blocked and then retried is still a run that was blocked.
    const receipt = agentReceipts.length ? agentReceipts[agentReceipts.length - 1] : null;
    const flags = [];
    if (agentReceipts.some((r) => r.blocked === true)) flags.push("blocked");
    if (agentReceipts.some((r) => r.mocked === true)) flags.push("mocked");
    if (agentReceipts.some((r) => r.downgraded === true)) flags.push("downgraded");
    if (!receipt) flags.push("no-receipt");

    const tableEntry = table[agentId] || null;
    const assessmentPathAbs = assessmentFilePath(runRoot, agentId);
    const assessmentRead = fs.existsSync(assessmentPathAbs)
      ? safeReadJson(assessmentPathAbs)
      : { ok: false, value: null, error: null };
    const assessment =
      assessmentRead.ok && assessmentRead.value && typeof assessmentRead.value === "object"
        ? assessmentRead.value
        : null;

    // The monitor escalates, it does not vote — it has no assessment.v1 by
    // design, so its assessment-derived cells are `n/a` (expected), not
    // `missing` (a gap). Every other agent's absent assessment IS a gap.
    const expectedNoAssessment = agentId === "monitor" && !assessment;
    const absent = expectedNoAssessment ? NA_CELL : MISSING_CELL;

    const usage = assessment && typeof assessment.usage === "object" ? assessment.usage : null;
    const priceKey = resolvePriceKey({ assessment, receipt, tableEntry });
    const cost = usage ? safeEstimateUsd(priceKey.key, usage) : { usd: null, priced: false, error: null };

    const modelDisplay =
      safeText(receipt && receipt.model_effective) ||
      safeText(tableEntry && tableEntry.model_openrouter) ||
      MISSING_CELL;

    const usdCell = !usage ? absent : cost.priced ? fmtUsd(cost.usd) : UNPRICED_CELL;

    rows.push({
      agent_id: agentId,
      has_receipt: Boolean(receipt),
      has_assessment: Boolean(assessment),
      expected_no_assessment: expectedNoAssessment,
      model: modelDisplay,
      price_key: priceKey.key,
      priced: usage ? cost.priced : null,
      effort_effective: safeText(receipt && receipt.effort_effective) || MISSING_CELL,
      effort_requested: safeText(receipt && receipt.effort_requested) || MISSING_CELL,
      runtime: safeText(receipt && receipt.runtime) || MISSING_CELL,
      verdict: assessment ? safeText(assessment.verdict) || absent : absent,
      confidence: assessment ? fmtConfidence(assessment.confidence) || absent : absent,
      tokens: {
        in: usage ? num(usage.in) : null,
        out: usage ? num(usage.out) : null,
        reasoning: usage ? num(usage.reasoning) : null,
      },
      cells: {
        in: (usage && fmtInt(usage.in)) || absent,
        out: (usage && fmtInt(usage.out)) || absent,
        reasoning: (usage && fmtInt(usage.reasoning)) || absent,
        usd: usdCell,
      },
      usd: usage && cost.priced ? cost.usd : null,
      flags,
      flags_cell: flags.length ? flags.join(",") : NONE_CELL,
      source: safeText(receipt && receipt.source) || MISSING_CELL,
      assessment_error: assessmentRead.error,
    });
  }
  return rows;
}

/**
 * Priced total plus an explicit unpriced callout. The two are kept apart on
 * purpose: folding unpriced rows into the total at $0 would understate the run's
 * real cost without ever saying so.
 */
export function computeTotals(rows) {
  const totals = {
    in: 0,
    out: 0,
    reasoning: 0,
    usd_priced: 0,
    priced_rows: 0,
    unpriced_rows: 0,
    unpriced_tokens: { in: 0, out: 0, reasoning: 0 },
    unpriced_models: [],
  };

  const unpricedByModel = new Map();
  for (const row of rows) {
    totals.in += row.tokens.in || 0;
    totals.out += row.tokens.out || 0;
    totals.reasoning += row.tokens.reasoning || 0;

    if (row.priced === true) {
      totals.priced_rows += 1;
      totals.usd_priced += row.usd || 0;
    } else if (row.priced === false) {
      totals.unpriced_rows += 1;
      totals.unpriced_tokens.in += row.tokens.in || 0;
      totals.unpriced_tokens.out += row.tokens.out || 0;
      totals.unpriced_tokens.reasoning += row.tokens.reasoning || 0;
      const key = row.price_key || "(unknown model)";
      if (!unpricedByModel.has(key)) {
        unpricedByModel.set(key, { model: key, agents: [], in: 0, out: 0, reasoning: 0 });
      }
      const entry = unpricedByModel.get(key);
      entry.agents.push(row.agent_id);
      entry.in += row.tokens.in || 0;
      entry.out += row.tokens.out || 0;
      entry.reasoning += row.tokens.reasoning || 0;
    }
  }

  totals.usd_priced = Math.round(totals.usd_priced * 1e6) / 1e6;
  totals.unpriced_models = [...unpricedByModel.values()];
  return totals;
}

// ---------------------------------------------------------------------------
// coordinator decision / containment
// ---------------------------------------------------------------------------

function readProbed(runRoot, candidates) {
  const hit = probeCandidates(runRoot, candidates);
  if (!hit) {
    return { present: false, path: null, candidates: [...candidates], data: null, error: null };
  }
  const read = safeReadJson(hit.absolute);
  return {
    present: read.ok,
    path: hit.relative,
    candidates: [...candidates],
    data: read.ok ? read.value : null,
    error: read.error,
  };
}

export function readDecision(runRoot) {
  return readProbed(runRoot, DECISION_CANDIDATES);
}

export function readContainment(runRoot) {
  return readProbed(runRoot, CONTAINMENT_CANDIDATES);
}

/** Pull an action set out of whatever shape the artifact happens to use. */
function actionSetOf(data) {
  if (!data || typeof data !== "object") return [];
  const raw = data.action_set || data.actions || data.applied || data.applied_actions;
  return Array.isArray(raw) ? raw.filter((a) => a && typeof a === "object") : [];
}

// ---------------------------------------------------------------------------
// assembly
// ---------------------------------------------------------------------------

/**
 * Collect one run into the report model. Accepts either an explicit runRoot
 * (fixtures, tests) or a runId resolved against the repo's runs/ directory.
 * Never throws for missing or malformed artifacts.
 */
export function buildReport({ runId, runRoot } = {}) {
  const root = runRoot ? path.resolve(runRoot) : resolveRunRoot(runId);
  const id = runId || path.basename(root);

  const ledger = readEffortLedger(effortLedgerPath(root));
  const at = safeAgentTable();
  const rows = buildAgentRows({ runRoot: root, receipts: ledger.receipts, table: at.table });
  const label = computeLabel(ledger.receipts);
  const totals = computeTotals(rows);

  const notes = [];
  if (!at.ok) notes.push(`agent table unavailable — ${at.error}`);
  if (!ledger.present) notes.push(`effort.jsonl absent at ${effortLedgerPath(root)}`);
  for (const row of rows) {
    if (row.assessment_error) {
      notes.push(`assessments/${row.agent_id}.json unreadable — ${row.assessment_error}`);
    }
  }

  return {
    schema: REPORT_SCHEMA,
    run_id: id,
    run_dir: root,
    run_dir_exists: runExists(root),
    generated_at_ms: Date.now(),
    label,
    receipts: { count: ledger.receipts.length, expected: AGENT_IDS.length, present: ledger.present },
    parse_errors: ledger.parse_errors,
    agents: rows,
    totals,
    decision: readDecision(root),
    containment: readContainment(root),
    notes,
  };
}

// ---------------------------------------------------------------------------
// markdown
// ---------------------------------------------------------------------------

function mdTable(header, bodyRows) {
  const lines = [
    `| ${header.join(" | ")} |`,
    `| ${header.map(() => "---").join(" | ")} |`,
    ...bodyRows.map((r) => `| ${r.map((c) => escapeCell(c)).join(" | ")} |`),
  ];
  return lines.join("\n");
}

function listOrNone(list) {
  return list && list.length ? list.join(", ") : NONE_CELL;
}

/**
 * Render a containment target as readable `key=value` pairs.
 *
 * WHY this exists: `target` is an OBJECT per decision.v1
 * ({principal_hash, tenant, session_ids[], src_ips[], feature, queue,
 * credential_id, integration}), so stringifying it produced the literal
 * "[object Object]" for every row -- the reader could not see WHAT was
 * contained, which is the single most important fact about a containment
 * action. Arrays collapse to a count so one row stays one line, and long
 * values are clipped so a wide hash cannot break the table.
 */
export function summariseTarget(target) {
  if (target === undefined || target === null) return MISSING_CELL;
  if (typeof target !== "object") return safeText(target);
  const parts = [];
  for (const [k, v] of Object.entries(target)) {
    if (v === undefined || v === null) continue;
    if (Array.isArray(v)) {
      if (!v.length) continue;
      // One representative value plus a count: enough to identify the scope
      // without letting a 40-session list wrap the table.
      parts.push(v.length === 1 ? `${k}=${clip(safeText(v[0]))}` : `${k}=[${v.length}: ${clip(safeText(v[0]))}, ...]`);
    } else if (typeof v === "object") {
      parts.push(`${k}={...}`);
    } else {
      parts.push(`${k}=${clip(safeText(v))}`);
    }
  }
  return parts.length ? parts.join(", ") : NONE_CELL;
}

function clip(s, max = 24) {
  const t = String(s);
  return t.length > max ? `${t.slice(0, max)}...` : t;
}

function renderActionSet(actions) {
  if (!actions.length) return `- action set: ${NONE_CELL}`;
  return mdTable(
    ["action", "target", "ttl_s", "blast_radius", "proposed_by"],
    actions.map((a) => [
      safeText(a.action) || MISSING_CELL,
      summariseTarget(a.target),
      a.ttl_s === undefined || a.ttl_s === null ? MISSING_CELL : safeText(a.ttl_s),
      safeText(a.blast_radius) || MISSING_CELL,
      Array.isArray(a.proposed_by) ? listOrNone(a.proposed_by.map((p) => safeText(p))) : MISSING_CELL,
    ]),
  );
}

function renderDecision(decision) {
  const out = ["## Coordinator decision", ""];
  if (!decision.present) {
    out.push(`decision: ${MISSING_CELL}`);
    out.push("");
    out.push(`- probed: ${decision.candidates.map((c) => `\`${c}\``).join(", ")}`);
    if (decision.error) out.push(`- read error: ${decision.error}`);
    return out.join("\n");
  }
  const d = decision.data || {};
  const vc = d.verdict_counts && typeof d.verdict_counts === "object" ? d.verdict_counts : {};
  out.push(`- source: \`${decision.path}\``);
  out.push(`- incident_id: ${safeText(d.incident_id) || MISSING_CELL}`);
  out.push(
    `- verdict_counts: malicious=${vc.malicious ?? MISSING_CELL} suspicious=${vc.suspicious ?? MISSING_CELL} benign=${vc.benign ?? MISSING_CELL}`,
  );
  out.push(`- score: ${num(d.score) === null ? MISSING_CELL : d.score}`);
  out.push(`- contain: ${typeof d.contain === "boolean" ? d.contain : MISSING_CELL}`);
  out.push(`- quorum_met: ${typeof d.quorum_met === "boolean" ? d.quorum_met : MISSING_CELL}`);
  out.push(`- degraded: ${typeof d.degraded === "boolean" ? d.degraded : MISSING_CELL}`);
  out.push(`- rule: ${safeText(d.rule) || MISSING_CELL}`);
  out.push(`- responders_voted: ${num(d.responders_voted) === null ? MISSING_CELL : d.responders_voted}`);
  out.push(
    `- responders_no_vote: ${Array.isArray(d.responders_no_vote) ? listOrNone(d.responders_no_vote.map((r) => safeText(r))) : MISSING_CELL}`,
  );
  out.push(
    `- decided_at_ms: ${num(d.decided_at_ms) === null ? MISSING_CELL : d.decided_at_ms}`,
  );
  out.push("");
  out.push(renderActionSet(actionSetOf(d)));
  return out.join("\n");
}

function renderContainment(containment) {
  const out = ["## Containment", ""];
  if (!containment.present) {
    out.push(`containment: ${MISSING_CELL}`);
    out.push("");
    out.push(`- probed: ${containment.candidates.map((c) => `\`${c}\``).join(", ")}`);
    if (containment.error) out.push(`- read error: ${containment.error}`);
    return out.join("\n");
  }
  const c = containment.data || {};
  out.push(`- source: \`${containment.path}\``);
  const outcome = c.outcome ?? c.status ?? c.result ?? c.applied_ok;
  out.push(`- outcome: ${outcome === undefined ? MISSING_CELL : safeText(outcome)}`);
  if (c.incident_id !== undefined) out.push(`- incident_id: ${safeText(c.incident_id)}`);
  if (c.error !== undefined && c.error !== null) out.push(`- error: ${safeText(c.error)}`);
  out.push("");
  out.push("Actions applied:");
  out.push("");
  out.push(renderActionSet(actionSetOf(c)));
  return out.join("\n");
}

/**
 * Render the report model as markdown. The label banner is the first thing after
 * the title, on purpose: whoever skims this artifact must not be able to miss it.
 */
export function renderMarkdown(model) {
  const L = model.label;
  const out = [];

  out.push(`# Mesh run report — ${model.run_id}`);
  out.push("");
  out.push(`**RUN LABEL: ${L.label} — ${L.reasons.join("; ")}**`);
  out.push("");
  out.push(`- blocked agents: ${listOrNone(L.blocked)}`);
  out.push(`- mocked agents: ${listOrNone(L.mocked)}`);
  out.push(`- downgraded agents: ${listOrNone(L.downgraded)}`);
  out.push(`- missing receipts: ${listOrNone(L.missing)}`);
  out.push(
    `- receipts read: ${model.receipts.count} of ${model.receipts.expected} expected | parse errors: ${model.parse_errors.length}`,
  );
  out.push(`- run dir: \`${model.run_dir}\``);
  out.push("");

  out.push("## Agents");
  out.push("");
  const header = [
    "agent",
    "model (effective)",
    "effort (effective)",
    "verdict",
    "confidence",
    "in",
    "out",
    "reasoning",
    "usd",
    "flags",
    "source",
  ];
  const body = model.agents.map((r) => [
    r.agent_id,
    r.model,
    r.effort_effective,
    r.verdict,
    r.confidence,
    r.cells.in,
    r.cells.out,
    r.cells.reasoning,
    r.cells.usd,
    r.flags_cell,
    r.source,
  ]);
  const t = model.totals;
  body.push([
    "**totals**",
    "",
    "",
    "",
    "",
    String(t.in),
    String(t.out),
    String(t.reasoning),
    `${fmtUsd(t.usd_priced)} (priced only)`,
    "",
    "",
  ]);
  out.push(mdTable(header, body));
  out.push("");

  if (t.unpriced_models.length) {
    const parts = t.unpriced_models.map(
      (m) =>
        `\`${m.model}\` (${m.agents.join(", ")}): in=${m.in} out=${m.out} reasoning=${m.reasoning}`,
    );
    out.push(
      `- unpriced models EXCLUDED from the priced total: ${parts.join("; ")} — total unpriced tokens in=${t.unpriced_tokens.in} out=${t.unpriced_tokens.out} reasoning=${t.unpriced_tokens.reasoning}. The priced total above therefore UNDERSTATES real spend.`,
    );
  } else {
    out.push(`- unpriced models: ${NONE_CELL} — the priced total covers every row with usage.`);
  }
  out.push(
    `- \`${NA_CELL}\` = expected absence (monitor escalates, it does not vote). \`${MISSING_CELL}\` = artifact or field genuinely absent. \`${UNPRICED_CELL}\` = no entry in the frozen price table; cost unknown, never zero.`,
  );
  out.push("");

  out.push(renderDecision(model.decision));
  out.push("");
  out.push(renderContainment(model.containment));
  out.push("");

  out.push("## Parse errors");
  out.push("");
  if (!model.parse_errors.length) {
    out.push(`parse_errors: ${NONE_CELL}`);
  } else {
    out.push(`parse_errors: ${model.parse_errors.length}`);
    out.push("");
    for (const e of model.parse_errors) {
      out.push(`- effort.jsonl line ${e.line}: ${e.reason}`);
    }
  }
  out.push("");

  out.push("## Notes");
  out.push("");
  if (!model.notes.length) {
    out.push(`notes: ${NONE_CELL}`);
  } else {
    for (const n of model.notes) out.push(`- ${n}`);
  }
  out.push("");

  return out.join("\n");
}

// ---------------------------------------------------------------------------
// write
// ---------------------------------------------------------------------------

export const FORMATS = ["md", "json", "both"];

/**
 * Build, render and write. Returns the markdown plus the list of files written
 * so the CLI stays a thin wrapper.
 */
export function generateReport({ runId, runRoot, format = "md" }) {
  if (!FORMATS.includes(format)) {
    throw new Error(`unsupported --format "${format}"; expected one of ${FORMATS.join(", ")}`);
  }
  const model = buildReport({ runId, runRoot });
  const markdown = renderMarkdown(model);
  const written = [];

  if (format === "md" || format === "both") {
    const p = path.join(model.run_dir, "report.md");
    fs.writeFileSync(p, markdown, "utf8");
    written.push(p);
  }
  if (format === "json" || format === "both") {
    const p = path.join(model.run_dir, "report.json");
    fs.writeFileSync(p, `${JSON.stringify(model, null, 2)}\n`, "utf8");
    written.push(p);
  }
  return { model, markdown, written };
}
