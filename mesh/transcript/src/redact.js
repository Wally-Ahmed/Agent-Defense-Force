/**
 * redact.js — the last line of defense.
 *
 * Every chunk of AI-harness CLI output passes through here BEFORE it leaves the
 * process: before it hits stdout, a spool file, a NATS subject, or the Cotal
 * chat channel. Nothing downstream is trusted to scrub credentials, so this
 * module deliberately favours OVER-redaction — a mangled transcript line is
 * recoverable, a leaked key is not.
 *
 * Pure, synchronous, zero dependencies (node: builtins only), never throws.
 */

const MARK = "[REDACTED:";
const ERROR_TEXT = "[REDACTED:redactor-error — chunk withheld]";

/** Values that look like a secret assignment but carry no secret. */
const PLACEHOLDER_VALUE = /^(?:null|undefined|true|false|none|nil|-?\d+(?:\.\d+)?)$/i;

/** Common words we refuse to treat as literal env secrets (too much collateral). */
const LITERAL_DENYLIST = new Set([
  "password",
  "passwords",
  "changeme",
  "localhost",
  "undefined",
  "development",
  "production",
  "username",
  "default",
  "example",
  "secret",
  "unknown",
  "disabled",
  "enabled",
  "0.0.0.0",
  "127.0.0.1",
]);

/**
 * Ordered detection table. Longest / most-specific first so that a broad
 * pattern can never eat the prefix of a narrow one (e.g. `openai_key` would
 * otherwise swallow `sk-or-v1-…`).
 *
 * Each entry: { kind, re, replace? }. `replace` receives the standard
 * String.prototype.replace callback arguments and returns the replacement;
 * when absent the whole match becomes `[REDACTED:<kind>]`.
 *
 * All regexes are global and backtracking-safe (no nested quantifiers).
 */
export const PATTERNS = [
  // 1. PEM / armoured key blocks — whole block goes.
  {
    kind: "pem_block",
    re: /-----BEGIN [A-Z ]*(?:PRIVATE KEY|NATS USER JWT|NATS USER SEED|CERTIFICATE)-----[\s\S]*?-----END [A-Z ]*-----/g,
  },
  // 1b. Unterminated block (truncated chunk): burn everything after the header.
  {
    kind: "pem_block",
    re: /-----BEGIN [A-Z ]*(?:PRIVATE KEY|NATS USER JWT|NATS USER SEED|CERTIFICATE)-----[\s\S]*/g,
  },

  // 2. JSON Web Tokens.
  { kind: "jwt", re: /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/g },

  // 3. OpenRouter.
  { kind: "openrouter_key", re: /\bsk-or-v1-[A-Za-z0-9]{16,}\b/g },
  { kind: "openrouter_key", re: /\bsk-or-[A-Za-z0-9-]{16,}\b/g },

  // 4. Anthropic.
  { kind: "anthropic_key", re: /\bsk-ant-[A-Za-z0-9_-]{16,}\b/g },

  // 5. OpenAI (generic `sk-` catch-all — must run after the vendor-specific ones).
  { kind: "openai_key", re: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{16,}\b/g },

  // 6. GitHub.
  { kind: "github_token", re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{16,}\b/g },
  { kind: "github_token", re: /\bgithub_pat_[A-Za-z0-9_]{20,}\b/g },

  // 7. AWS access key id.
  { kind: "aws_key_id", re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },

  // 8. Google API key.
  { kind: "google_api_key", re: /\bAIza[0-9A-Za-z_-]{35}\b/g },

  // 9. Slack.
  { kind: "slack_token", re: /\bxox[baprse]-[A-Za-z0-9-]{10,}\b/g },

  // 10. NATS seed (58 chars, base32 A-Z2-7). Private material — highest value here.
  { kind: "nats_seed", re: /\b[SP][ABCNOU][A-Z2-7]{54,56}\b/g },
  { kind: "nats_seed", re: /\bS[ABCNOU][A-Z2-7]{54}\b/g },

  // 11. NATS public nkey (56 chars).
  { kind: "nats_nkey", re: /\b[UAONCX][A-Z2-7]{55}\b/g },

  // 11b. Vendor keys using an underscore prefix (Stripe-style live/test keys,
  // webhook signing secrets). The `sk-` family above only covers hyphens.
  {
    kind: "vendor_key",
    re: /\b(?:sk|pk|rk|ak)_(?:live|test|prod)_[A-Za-z0-9]{12,}\b/g,
  },
  { kind: "vendor_key", re: /\bwhsec_[A-Za-z0-9_-]{16,}\b/g },
  { kind: "vendor_key", re: /\bhf_[A-Za-z0-9]{30,}\b/g },
  { kind: "vendor_key", re: /\bnpm_[A-Za-z0-9]{30,}\b/g },

  // 12. Authorization: Bearer <token> — keep the scheme word, drop the token.
  {
    kind: "bearer",
    re: /\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/g,
    replace: () => `Bearer ${MARK}bearer]`,
  },

  // 12b. Any other Authorization header value (Basic, Token, DPoP, custom).
  // `Basic <base64(user:pass)>` is a credential the Bearer rule above misses.
  {
    kind: "auth_header",
    re: /\b(Authorization|Proxy-Authorization|X-Api-Key|X-Auth-Token)(\s*[:=]\s*)(?!\[REDACTED:)(?:(Basic|Token|Digest|DPoP|ApiKey)\s+)?[A-Za-z0-9._~+/=-]{8,}/gi,
    replace: (_m, header, op, scheme) =>
      `${header}${op}${scheme ? scheme + " " : ""}${MARK}auth_header]`,
  },

  // 13. Inline URL credentials — keep the scheme so the line stays readable.
  {
    kind: "basic_auth_url",
    re: /\b([a-z][a-z0-9+.-]*):\/\/(?!\[REDACTED:)[^\s/:@]+:[^\s/@]+@/gi,
    replace: (_m, scheme) => `${scheme}://${MARK}basic_auth_url]@`,
  },

  // 14. Secret-bearing query / fragment params — keep `name=`, drop the value.
  {
    kind: "url_secret_param",
    re: /([?&#](?:access_token|api_key|apikey|auth|code|credential|id_token|key|password|refresh_token|secret|session|sig|signature|token)=)(?!\[REDACTED:)([^&\s#"']{6,})/gi,
    replace: (_m, name) => `${name}${MARK}url_secret_param]`,
  },

  // 15. Generic `SOMETHING_SECRET = value` assignments.
  {
    kind: "assignment",
    re: /\b([A-Za-z_][A-Za-z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|SEED|PASSPHRASE|AUTH))(\s*(?:=>|[:=])\s*)(['"]?)(?!\[REDACTED:)([^\s'"]{6,})\3/gi,
    replace: (m, name, op, quote, value) =>
      PLACEHOLDER_VALUE.test(value) ? m : `${name}${op}${quote}${MARK}assignment]${quote}`,
  },

  // 16. OpenSSH public/authorized_keys lines.
  {
    kind: "private_key_line",
    re: /\b(?:ssh-rsa|ssh-ed25519|ecdsa-sha2-nistp256)\s+[A-Za-z0-9+/=]{40,}/g,
  },
];

/** Env var NAMEs that make their value a secret. */
const SENSITIVE_NAME =
  /(^|_)(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL|CREDS|SEED|PASSPHRASE|APIKEY|AUTH)($|_)/i;
const SENSITIVE_NAME_COMPOUND = /API_?KEY|ACCESS_?TOKEN|PRIVATE_?KEY/i;

const PATH_LIKE = /^(?:\/|~|\.\/)/;
const NUMERIC = /^-?\d+(?:\.\d+)?$/;
const DIGITS_ONLY = /^\d+$/;

function escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function toText(value) {
  if (typeof value === "string") return value;
  if (value === null || value === undefined) return "";
  return String(value);
}

/**
 * Turn caller-supplied literal secrets into a de-duplicated, longest-first list
 * of global regexes. Longest-first matters: if two secrets share a prefix, the
 * longer one must be consumed before the shorter one fragments it.
 */
function literalRegexes(secrets, minLen) {
  if (!Array.isArray(secrets) || secrets.length === 0) return [];
  const keep = [];
  const seen = new Set();
  for (const raw of secrets) {
    if (typeof raw !== "string") continue;
    if (raw.length < minLen) continue;
    if (DIGITS_ONLY.test(raw)) continue;
    if (LITERAL_DENYLIST.has(raw.toLowerCase())) continue;
    if (seen.has(raw)) continue;
    seen.add(raw);
    keep.push(raw);
  }
  keep.sort((a, b) => b.length - a.length);
  return keep.map((s) => new RegExp(escapeRegExp(s), "g"));
}

function core(input, opts) {
  const minLen = Number.isFinite(opts.minLen) ? opts.minLen : 8;
  const counts = new Map();
  let text = toText(input);

  if (text.length === 0) return { text, hits: [] };

  const bump = (kind, n) => {
    if (n > 0) counts.set(kind, (counts.get(kind) || 0) + n);
  };

  // Known literal values first: an exact match is the strongest signal we have.
  for (const re of literalRegexes(opts.secrets, minLen)) {
    let n = 0;
    text = text.replace(re, () => {
      n++;
      return `${MARK}env]`;
    });
    bump("env", n);
  }

  for (const p of PATTERNS) {
    let n = 0;
    const fallback = `${MARK}${p.kind}]`;
    text = text.replace(p.re, (...args) => {
      const matched = args[0];
      const out = p.replace ? p.replace(...args) : fallback;
      if (out !== matched) n++;
      return out;
    });
    bump(p.kind, n);
  }

  const hits = [...counts.entries()]
    .map(([kind, count]) => ({ kind, count }))
    .sort((a, b) => (a.kind < b.kind ? -1 : a.kind > b.kind ? 1 : 0));

  return { text, hits };
}

/**
 * Redact every credential we can recognise in `text`.
 *
 * @param {string} text
 * @param {{secrets?: string[], minLen?: number}} [opts]
 * @returns {{text: string, hits: Array<{kind: string, count: number}>}}
 *   `hits` is sorted by kind; kinds with zero matches are omitted.
 *   Never throws — on any internal error the chunk is withheld entirely.
 */
export function redact(text, opts = {}) {
  try {
    return core(text, opts && typeof opts === "object" ? opts : {});
  } catch {
    return { text: ERROR_TEXT, hits: [{ kind: "redactor-error", count: 1 }] };
  }
}

/**
 * Build a redactor bound to extra literal secrets (typically env var values).
 * Each occurrence of a bound secret is replaced with `[REDACTED:env]`.
 *
 * @param {string[]} [secrets]
 * @param {{minLen?: number}} [opts]
 * @returns {(text: string, callOpts?: object) => {text: string, hits: Array<{kind: string, count: number}>}}
 */
export function makeRedactor(secrets = [], opts = {}) {
  const bound = Array.isArray(secrets) ? secrets.slice() : [];
  const baseOpts = opts && typeof opts === "object" ? opts : {};
  return function boundRedact(text, callOpts = {}) {
    try {
      const merged = { ...baseOpts, ...(callOpts && typeof callOpts === "object" ? callOpts : {}) };
      const extra = Array.isArray(merged.secrets) ? merged.secrets : [];
      return redact(text, { ...merged, secrets: bound.concat(extra) });
    } catch {
      return { text: ERROR_TEXT, hits: [{ kind: "redactor-error", count: 1 }] };
    }
  };
}

/**
 * Harvest literal secret values out of a process env, keyed on the NAME looking
 * sensitive. Non-secret-shaped values (short, boolean, numeric, path-like) are
 * dropped so we do not turn `/usr/bin` into a redaction rule.
 *
 * @param {Record<string, string|undefined>} [env]
 * @returns {string[]}
 */
export function secretsFromEnv(env = process.env) {
  const out = [];
  try {
    if (!env || typeof env !== "object") return out;
    const seen = new Set();
    for (const name of Object.keys(env)) {
      if (!SENSITIVE_NAME.test(name) && !SENSITIVE_NAME_COMPOUND.test(name)) continue;
      const value = env[name];
      if (typeof value !== "string") continue;
      if (value.length < 8) continue;
      const lower = value.toLowerCase();
      if (lower === "true" || lower === "false") continue;
      if (NUMERIC.test(value)) continue;
      if (PATH_LIKE.test(value)) continue;
      if (seen.has(value)) continue;
      seen.add(value);
      out.push(value);
    }
  } catch {
    return out;
  }
  return out;
}
