// parse.js — noisy CLI output -> one schema-valid assessment.v1, or an error.
//
// This is the piece most likely to fail in a live demo, so it is written to be
// stubborn rather than elegant. A harness's stdout is not a JSON API: it carries
// banners, spinners, tool previews, reasoning traces, code fences, and prose the
// model wrote around its answer. Any of those can contain braces.
//
// The scan is a brace-balancer that respects string literals and escapes, so a
// `{` inside "..." never opens a level and a `\"` never closes a string. That
// beats a regex, which cannot count.
//
// AUTHORITY: fields that identify WHO produced this and at WHAT cost are taken
// from the run's own record, never from the model. A model that misreports its
// own id, model name or token count would corrupt the audit trail, and it has no
// way to know its OpenRouter id or real telemetry anyway. Everything it says in
// those fields is overwritten without comment.

import path from "node:path";
import { CONTRACTS_DIR, readJson } from "../../lib/paths.js";
import { validate, formatErrors, clampChars } from "./validate.js";

export const ASSESSMENT_SCHEMA_PATH = path.join(CONTRACTS_DIR, "assessment.v1.schema.json");

let schemaCache = null;
export function assessmentSchema(file = ASSESSMENT_SCHEMA_PATH) {
  if (!schemaCache) schemaCache = readJson(file);
  return schemaCache;
}

/** Keys that mark a candidate object as "probably the assessment". */
const IDENTIFYING = ["incident_id", "verdict"];
const SUPPORTING = ["confidence", "recommended_actions", "campaign_stages", "rationale"];

/**
 * Every balanced top-level {...} in `text`, in document order, with the brace
 * counter blind to braces inside string literals.
 */
export function extractJsonObjects(text) {
  const s = String(text ?? "");
  const out = [];
  let depth = 0;
  let start = -1;
  let inString = false;
  let escaped = false;

  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (inString) {
      if (escaped) escaped = false;
      else if (c === "\\") escaped = true;
      else if (c === '"') inString = false;
      continue;
    }
    if (c === '"') {
      inString = true;
      continue;
    }
    if (c === "{") {
      if (depth === 0) start = i;
      depth++;
      continue;
    }
    if (c === "}") {
      if (depth === 0) continue; // stray closer in prose
      depth--;
      if (depth === 0 && start >= 0) {
        out.push({ text: s.slice(start, i + 1), start, end: i + 1 });
        start = -1;
      }
    }
  }
  return out;
}

/**
 * Parse one candidate, with two forgiving retries. Both repairs target things
 * models emit that JSON forbids; neither one changes any value.
 */
export function parseLenient(src) {
  try {
    return { ok: true, value: JSON.parse(src), repaired: null };
  } catch {
    /* try repairs */
  }
  const noComments = stripLineComments(src);
  try {
    return { ok: true, value: JSON.parse(noComments), repaired: "comments" };
  } catch {
    /* try trailing commas too */
  }
  const noTrailing = noComments.replace(/,(\s*[}\]])/g, "$1");
  try {
    return { ok: true, value: JSON.parse(noTrailing), repaired: "comments+trailing-commas" };
  } catch (err) {
    return { ok: false, value: null, repaired: null, error: err.message };
  }
}

/** Strip `//` comments that are outside string literals. */
function stripLineComments(src) {
  let out = "";
  let inString = false;
  let escaped = false;
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (inString) {
      out += c;
      if (escaped) escaped = false;
      else if (c === "\\") escaped = true;
      else if (c === '"') inString = false;
      continue;
    }
    if (c === '"') {
      inString = true;
      out += c;
      continue;
    }
    if (c === "/" && src[i + 1] === "/") {
      while (i < src.length && src[i] !== "\n") i++;
      out += "\n";
      continue;
    }
    out += c;
  }
  return out;
}

function isPlainObject(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v);
}

function score(obj) {
  if (!isPlainObject(obj)) return -1;
  const keys = Object.keys(obj);
  if (IDENTIFYING.some((k) => keys.includes(k))) return 2;
  if (SUPPORTING.some((k) => keys.includes(k))) return 1;
  return 0;
}

/**
 * Choose the assessment among the candidates.
 *
 * LAST, not first: a model that corrects itself, or a harness that echoes the
 * prompt (which contains an example shape) before the answer, both put the real
 * answer at the END. Preferring the last identifying object is what makes an
 * echoed prompt harmless.
 */
export function chooseCandidate(objects) {
  let best = null;
  objects.forEach((cand, index) => {
    const s = score(cand.value);
    if (s < 0) return;
    if (best === null || s >= best.score) best = { ...cand, score: s, index };
  });
  return best;
}

const CTX_OVERRIDES = [
  ["incident_id", "incidentId"],
  ["responder", "agentId"],
  ["model", "model"],
  ["effort_requested", "effortRequested"],
  ["effort_effective", "effortEffective"],
];

/**
 * @param {string} rawText harness output (or a bare JSON string)
 * @param {object} ctx {incidentId, agentId, model, effortRequested, effortEffective, usage}
 * @returns {{ok:boolean, assessment:object|null, errors:string[], extraction:object}}
 */
export function parseAssessment(rawText, ctx = {}) {
  const schema = ctx.schema ?? assessmentSchema();
  const extraction = {
    raw_chars: String(rawText ?? "").length,
    candidates: 0,
    parsed: 0,
    chosen_index: null,
    chosen_score: null,
    repaired: null,
    dropped_keys: [],
    filled_keys: [],
    overridden_keys: [],
    rationale_truncated: false,
    coercions: [],
  };

  const found = extractJsonObjects(rawText);
  extraction.candidates = found.length;
  if (found.length === 0) {
    return {
      ok: false,
      assessment: null,
      errors: ["no JSON object found in harness output"],
      extraction,
    };
  }

  const parsed = [];
  for (const cand of found) {
    const r = parseLenient(cand.text);
    if (r.ok) parsed.push({ ...cand, value: r.value, repaired: r.repaired });
  }
  extraction.parsed = parsed.length;
  if (parsed.length === 0) {
    return {
      ok: false,
      assessment: null,
      errors: [`found ${found.length} brace-balanced span(s), none parsed as JSON`],
      extraction,
    };
  }

  const chosen = chooseCandidate(parsed);
  if (!chosen) {
    return {
      ok: false,
      assessment: null,
      errors: ["no JSON object in the output looked like an assessment"],
      extraction,
    };
  }
  extraction.chosen_index = chosen.index;
  extraction.chosen_score = chosen.score;
  extraction.repaired = chosen.repaired;

  const assessment = normalize(chosen.value, ctx, schema, extraction);
  const { ok, errors } = validate(schema, assessment);
  return {
    ok,
    assessment: ok ? assessment : null,
    // Kept even on failure: the run report shows what the model actually said.
    rejected: ok ? null : assessment,
    errors: ok ? [] : formatErrors(errors),
    extraction,
  };
}

/** Coerce the model's object toward the contract without inventing judgement. */
function normalize(input, ctx, schema, extraction) {
  const allowed = new Set(Object.keys(schema.properties));
  const out = {};

  for (const [k, v] of Object.entries(input)) {
    if (allowed.has(k)) out[k] = v;
    else extraction.dropped_keys.push(k); // recorded, never silently discarded
  }

  // Authoritative fields: the run knows these, the model does not.
  for (const [field, ctxKey] of CTX_OVERRIDES) {
    if (ctx[ctxKey] === undefined) continue;
    if (out[field] !== undefined && out[field] !== ctx[ctxKey]) {
      extraction.overridden_keys.push(field);
    }
    out[field] = ctx[ctxKey];
  }
  if (ctx.usage !== undefined) {
    if (out.usage !== undefined) extraction.overridden_keys.push("usage");
    out.usage = ctx.usage; // real harness telemetry, never the model's guess
  }

  // Numeric fields a model sometimes quotes.
  if (typeof out.confidence === "string" && out.confidence.trim() !== "") {
    const n = Number(out.confidence);
    if (Number.isFinite(n)) {
      out.confidence = n;
      extraction.coercions.push("confidence:string->number");
    }
  }

  // A single action object instead of a one-element array.
  if (isPlainObject(out.recommended_actions)) {
    out.recommended_actions = [out.recommended_actions];
    extraction.coercions.push("recommended_actions:object->array");
  }

  if (Array.isArray(out.campaign_stages)) {
    const ints = out.campaign_stages.map((s) => {
      const n = typeof s === "string" ? Number(s) : s;
      return Number.isInteger(n) ? n : s;
    });
    // uniqueItems is a contract constraint; a model repeating a stage is a
    // formatting slip, not a different judgement.
    const deduped = [...new Set(ints.map((v) => JSON.stringify(v)))].map((v) => JSON.parse(v));
    if (deduped.length !== out.campaign_stages.length) {
      extraction.coercions.push("campaign_stages:deduped");
    }
    out.campaign_stages = deduped;
  }

  if (Array.isArray(out.recommended_actions)) {
    const actionSchema = schema.properties.recommended_actions.items;
    const actionKeys = new Set(Object.keys(actionSchema.properties));
    const targetKeys = new Set(Object.keys(actionSchema.properties.target.properties));
    out.recommended_actions = out.recommended_actions.map((a) => {
      if (!isPlainObject(a)) return a;
      const kept = {};
      for (const [k, v] of Object.entries(a)) {
        if (actionKeys.has(k)) kept[k] = v;
        else extraction.dropped_keys.push(`recommended_actions[].${k}`);
      }
      if (typeof kept.ttl_s === "string" && Number.isInteger(Number(kept.ttl_s))) {
        kept.ttl_s = Number(kept.ttl_s);
        extraction.coercions.push("ttl_s:string->int");
      }
      if (isPlainObject(kept.target)) {
        const t = {};
        for (const [k, v] of Object.entries(kept.target)) {
          if (targetKeys.has(k)) t[k] = v;
          else extraction.dropped_keys.push(`recommended_actions[].target.${k}`);
        }
        kept.target = t;
      }
      return kept;
    });
  }

  // Absent LIST fields mean "I propose nothing / I loaded nothing". Filling []
  // records that honestly. A verdict, confidence or rationale is a JUDGEMENT and
  // is never filled — an assessment without one is invalid and must say so.
  for (const field of ["recommended_actions", "skills_used", "campaign_stages"]) {
    if (out[field] === undefined) {
      out[field] = [];
      extraction.filled_keys.push(field);
    }
  }

  // The 400-char cap. Truncate; the contract explicitly forbids spilling the
  // remainder into any other field, so the remainder is simply dropped.
  const cap = schema.properties.rationale.maxLength;
  if (typeof out.rationale === "string") {
    const clamped = clampChars(out.rationale, cap);
    if (clamped !== out.rationale) {
      out.rationale = clamped;
      extraction.rationale_truncated = true;
    }
  }

  return out;
}

/**
 * Pull the model's ANSWER out of a structured harness stream.
 *
 * Necessary because the tap's .raw spool is the harness's event stream, not the
 * answer: a brace-scan over it finds the OUTER event envelope first, and for
 * claude/codex the assessment lives JSON-escaped inside a string field of that
 * envelope. Returns "" when the stream carries no recognisable answer, so the
 * caller can fall back to scanning the whole raw text.
 */
export function extractAnswerText(runtime, rawText) {
  const lines = String(rawText ?? "").split("\n");
  const events = [];
  for (const line of lines) {
    const t = line.trim();
    if (!t.startsWith("{")) continue;
    try {
      events.push(JSON.parse(t));
    } catch {
      /* not an event line — the tap interleaves plain harness text too */
    }
  }
  if (events.length === 0) return "";

  const parts = [];
  switch (runtime) {
    case "claude":
    case "claude_code": {
      for (const ev of events) {
        if (ev.type === "assistant") {
          for (const c of ev.message?.content ?? []) {
            if (c?.type === "text" && c.text) parts.push(c.text);
          }
        } else if (ev.type === "result" && typeof ev.result === "string") {
          // The closing `result` event is the final answer verbatim; prefer it.
          parts.push(ev.result);
        }
      }
      break;
    }
    case "codex": {
      for (const ev of events) {
        const item = ev.item ?? {};
        if (ev.type === "item.completed" && item.type === "agent_message" && item.text) {
          parts.push(item.text);
        }
      }
      break;
    }
    case "opencode": {
      for (const ev of events) {
        const type = ev.type ?? ev.event ?? ev.part?.type;
        if (type === "text" || type === "message.part.updated") {
          const t = ev.text ?? ev.part?.text;
          if (t) parts.push(t);
        }
      }
      break;
    }
    default:
      // agy and hermes have no JSON event mode at all — the pty stream IS the
      // answer, so there is nothing to unwrap.
      return "";
  }
  return parts.join("\n");
}
