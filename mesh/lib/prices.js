// mesh/lib/prices.js — USD estimation from the frozen price table.
//
// contracts/mesh/prices.json is a FROZEN CONTRACT and is never edited from here.
// Formula, verbatim from that file:
//   usd = in_tokens/1e6 * in_per_m + out_tokens/1e6 * out_per_m
// with reasoning tokens ALREADY INCLUDED in out_tokens for every model listed.
//
// Unpriced models: the table is keyed by OpenRouter id and does not carry an
// entry for every pin. Today `google/gemini-3.6-flash-high` is absent — the
// table predates the documented 3.1-pro -> 3.6-flash deviation recorded in
// mesh/config/models.json. We do NOT guess a price and we do NOT silently
// substitute a neighbouring model's rate: an invented cost in an audit artifact
// is worse than an absent one. Cost is reported as 0 (assessment.v1 requires
// usd >= 0) and `priced: false` is surfaced so the run report can say
// "unpriced" out loud instead of showing a confident $0.00.

import path from "node:path";
import { CONTRACTS_DIR, readJson } from "./paths.js";

export const PRICES_PATH = path.join(CONTRACTS_DIR, "prices.json");

let cache = null;
export function priceTable(file = PRICES_PATH) {
  if (!cache) cache = readJson(file);
  return cache;
}

/**
 * Estimate USD for one call.
 * @param {string} modelOpenrouterId e.g. "anthropic/claude-opus-5"
 * @param {{in:number,out:number,reasoning:number}} usage
 * @returns {{usd:number, priced:boolean, in_per_m:number|null, out_per_m:number|null}}
 */
export function estimateUsd(modelOpenrouterId, usage) {
  const entry = priceTable().models?.[modelOpenrouterId];
  const inTok = Math.max(0, Number(usage?.in) || 0);
  const outTok = Math.max(0, Number(usage?.out) || 0);
  if (!entry) {
    return { usd: 0, priced: false, in_per_m: null, out_per_m: null };
  }
  // reasoning tokens are already inside out_tokens per the contract's own note,
  // so they are NOT added again here.
  const usd = (inTok / 1e6) * entry.in_per_m + (outTok / 1e6) * entry.out_per_m;
  return {
    usd: Math.round(usd * 1e6) / 1e6,
    priced: true,
    in_per_m: entry.in_per_m,
    out_per_m: entry.out_per_m,
  };
}

/** True when the price table carries a rate for this model. */
export function isPriced(modelOpenrouterId) {
  return Boolean(priceTable().models?.[modelOpenrouterId]);
}
