// usage.js — real token counts out of a captured transcript.
//
// GROUND RULE: zeros are honest, invented numbers are not. Only two of the five
// runtimes report token usage at all. For the other three this returns zeros and
// says `reported: false` out loud, so the run report can print "not reported"
// instead of a confident 0 that looks like a measurement. An audit artifact
// carrying a plausible-looking number nobody measured is worse than one carrying
// an admitted gap.
//
// Key names below were read off REAL captured transcripts, not from memory:
//   codex  runs/.../responder_codex.raw  -> {"type":"turn.completed","usage":{
//            "input_tokens":17832,"cached_input_tokens":0,
//            "cache_write_input_tokens":0,"output_tokens":6,
//            "reasoning_output_tokens":0}}
//   claude runs/e2e-verify/transcripts/responder_claude.raw -> {"type":"result",
//            ...,"usage":{"input_tokens":16,"cache_creation_input_tokens":21513,
//            "cache_read_input_tokens":43250,"output_tokens":129,...}}

import fs from "node:fs";

export const ZERO = Object.freeze({ in: 0, out: 0, reasoning: 0 });

function num(v) {
  const n = Number(v);
  return Number.isFinite(n) && n > 0 ? Math.round(n) : 0;
}

/** Read the transcript text a tap result points at. */
export function transcriptText(tapResult) {
  if (typeof tapResult === "string") return tapResult;
  if (tapResult?.rawText !== undefined) return String(tapResult.rawText);
  const p = tapResult?.spool?.raw;
  if (!p) return "";
  try {
    return fs.readFileSync(p, "utf8");
  } catch {
    // A missing spool is a capture failure, not a usage failure; the caller
    // still gets an honest `reported: false`.
    return "";
  }
}

/** Every JSON event line in a transcript, in order. */
function events(text) {
  const out = [];
  for (const line of String(text).split("\n")) {
    const t = line.trim();
    if (!t.startsWith("{")) continue;
    try {
      out.push(JSON.parse(t));
    } catch {
      /* interleaved plain harness text */
    }
  }
  return out;
}

/**
 * @param {string} runtime tap runtime key: claude_code | codex | agy | opencode | hermes
 * @param {object|string} tapResult runTap() result, or transcript text directly
 * @returns {{in:number,out:number,reasoning:number,reported:boolean,source:string}}
 */
export function extractUsage(runtime, tapResult) {
  const text = transcriptText(tapResult);
  const evs = text ? events(text) : [];

  switch (runtime) {
    case "codex":
      return fromCodex(evs);
    case "claude":
    case "claude_code":
      return fromClaude(evs);
    case "opencode":
      return fromOpencode(evs);
    case "agy":
      return unreported("agy exposes no JSON event mode and reports no token counts");
    case "hermes":
      return unreported("hermes exposes no JSON event mode and reports no token counts");
    default:
      return unreported(`unknown runtime "${runtime}"`);
  }
}

function unreported(why) {
  return { ...ZERO, reported: false, source: why };
}

function fromCodex(evs) {
  // LAST turn.completed: a multi-turn run reports per turn, and the final one is
  // the cumulative figure for the invocation.
  let usage = null;
  for (const ev of evs) if (ev.type === "turn.completed" && ev.usage) usage = ev.usage;
  if (!usage) return unreported("no turn.completed event in the codex transcript");
  return {
    // cached_input_tokens is a SUBSET of input_tokens in codex's accounting, so
    // adding it would double-count the cached prefix.
    in: num(usage.input_tokens),
    out: num(usage.output_tokens),
    reasoning: num(usage.reasoning_output_tokens),
    reported: true,
    source: "codex turn.completed.usage",
  };
}

function fromClaude(evs) {
  let usage = null;
  for (const ev of evs) if (ev.type === "result" && ev.usage) usage = ev.usage;
  if (!usage) return unreported("no result event in the claude transcript");
  return {
    // All three input buckets are tokens the call actually consumed. Cache reads
    // are cheaper per token than fresh input, but the frozen price table has a
    // single in_per_m rate and no cache tier — so the honest thing is to report
    // the true token count and let the cost be a documented over-estimate,
    // rather than hide real tokens to make the estimate prettier.
    in:
      num(usage.input_tokens) +
      num(usage.cache_creation_input_tokens) +
      num(usage.cache_read_input_tokens),
    out: num(usage.output_tokens),
    // Claude Code does not break thinking tokens out of output_tokens in the
    // stream-json result event, so there is nothing to report separately. They
    // are already counted inside `out`.
    reasoning: 0,
    reported: true,
    source: "claude stream-json result.usage",
  };
}

function fromOpencode(evs) {
  // VERIFIED against a real transcript on opencode 1.18.5. `opencode run
  // --format json` closes with:
  //   {"type":"step_finish","part":{"type":"step-finish","tokens":{
  //      "total":9835,"input":8678,"output":5,"reasoning":0,
  //      "cache":{"write":0,"read":64}}}}
  // so the counts sit at part.tokens, one level deeper than the other shapes.
  // The looser keys below are kept ahead of it because opencode's JSON stream is
  // not a frozen contract and older/newer builds have used `usage`; whichever
  // shape a transcript actually carries, the numbers come out.
  //
  // cache.read/cache.write are deliberately NOT added to `in`: opencode's
  // `total` already exceeds input+output by exactly the cache figures, so adding
  // them would double-count a prefix that `input` has counted once.
  for (let i = evs.length - 1; i >= 0; i--) {
    const ev = evs[i];
    const u = ev.usage ?? ev.tokens ?? ev.part?.usage ?? ev.part?.tokens ?? ev.step?.usage;
    if (!u || typeof u !== "object") continue;
    const inTok = num(u.input_tokens ?? u.input ?? u.prompt_tokens);
    const outTok = num(u.output_tokens ?? u.output ?? u.completion_tokens);
    if (inTok === 0 && outTok === 0) continue;
    return {
      in: inTok,
      out: outTok,
      reasoning: num(u.reasoning_tokens ?? u.reasoning ?? u.reasoning_output_tokens),
      reported: true,
      source: `opencode ${ev.type ?? ev.event ?? "event"} tokens{input,output,reasoning}`,
    };
  }
  return unreported("no usage-bearing event found in the opencode transcript");
}
