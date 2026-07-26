import { test } from "node:test";
import assert from "node:assert/strict";

import { redact, makeRedactor, secretsFromEnv, PATTERNS } from "../src/redact.js";

const MARKER = "[REDACTED:";

// --- synthetic (clearly fake) credentials, one per detector kind ------------
// Base32 helpers for the NATS shapes (alphabet A-Z2-7).
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const NATS_SEED = `SUAJ${B32}${B32.slice(0, 22)}`; // 4 + 54 = 58 chars
const NATS_NKEY = `U${B32}${B32.slice(0, 23)}`; // 1 + 55 = 56 chars

const PEM_BODY = "MIIEowIBAAKCAQEA0FAKEfakeFAKEfakeFAKEfakeFAKEfakeFAKEfakeFAKE0z";
const PEM_BLOCK = [
  "-----BEGIN RSA PRIVATE KEY-----",
  PEM_BODY,
  "wIDAQABAoIBAQCfakefakefakefakefakefakefakefakefakefakefakefake0",
  "-----END RSA PRIVATE KEY-----",
].join("\n");

const SSH_LINE =
  "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleFakeKeyDataAAAABBBBCCCCDDDD dev@laptop";

/**
 * kind    — the detector we expect to fire
 * secret  — the literal that must not survive
 * needles — extra substrings that must also be gone (defaults to [secret])
 */
const CASES = [
  { kind: "pem_block", secret: PEM_BLOCK, needles: [PEM_BODY] },
  {
    kind: "jwt",
    secret:
      "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk",
  },
  { kind: "openrouter_key", secret: "sk-or-v1-0123456789abcdef0123456789abcdef" },
  {
    kind: "openrouter_key",
    secret: "OPENROUTER_API_KEY=sk-or-v1-fedcba9876543210fedcba9876543210",
    needles: ["sk-or-v1-fedcba9876543210fedcba9876543210"],
  },
  { kind: "anthropic_key", secret: "sk-ant-api03-0123456789abcdefABCDEF-0123456789" },
  { kind: "openai_key", secret: "sk-proj-0123456789abcdefghijklmnop0123" },
  { kind: "github_token", secret: "ghp_0123456789abcdefghij0123456789abcd" },
  {
    kind: "github_token",
    secret: "github_pat_11ABCDEFG0abcdefghijklmnop_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
  },
  { kind: "aws_key_id", secret: "AKIAIOSFODNN7EXAMPLE" },
  { kind: "google_api_key", secret: "AIzaSyD-1234567890abcdefghijklmnopqrstu" },
  { kind: "slack_token", secret: "xoxb-1111111111-2222222222222-abcdefghijklmnopqrstuvwx" },
  { kind: "nats_seed", secret: NATS_SEED },
  { kind: "nats_nkey", secret: NATS_NKEY },
  {
    kind: "bearer",
    secret: "Authorization: Bearer aB3dEf9hIjKlMnOpQrStUv",
    needles: ["aB3dEf9hIjKlMnOpQrStUv"],
  },
  {
    kind: "basic_auth_url",
    secret: "https://deploy:hunter2hunter2@registry.internal/x",
    needles: ["deploy:hunter2hunter2@", "hunter2hunter2"],
  },
  {
    kind: "url_secret_param",
    secret: "https://api.example.com/v1/run?token=abcdef123456&mode=fast",
    needles: ["abcdef123456"],
  },
  {
    kind: "assignment",
    secret: "SESSION_SECRET=w9f3kd02ls91xz",
    needles: ["w9f3kd02ls91xz"],
  },
  { kind: "private_key_line", secret: SSH_LINE, needles: [SSH_LINE.split(" ")[1]] },
];

/** Wrap a secret in a realistic multi-line harness transcript. */
function transcript(secret) {
  return [
    "$ mesh run --agent claude --task build",
    "[12:04:31] transcript-tap attached (pid 4821)",
    "[12:04:31] loading config from /Users/dev/.config/mesh/config.json",
    `[12:04:32] ${secret}`,
    "[12:04:33] streaming 128 frames to tr-agent-7",
    "[12:04:34] exit code 0",
  ].join("\n");
}

const CORPUS = CASES.map((c) => transcript(c.secret)).join("\n---\n");

// --- 1. synthetic secrets never survive -------------------------------------
test("synthetic secrets never survive redaction", () => {
  assert.ok(CASES.length >= 16, `expected >=16 cases, got ${CASES.length}`);

  for (const { kind, secret, needles } of CASES) {
    const input = transcript(secret);
    const { text, hits } = redact(input);

    assert.ok(
      !text.includes(secret),
      `[${kind}] raw secret survived redaction:\n${text}`,
    );
    for (const needle of needles ?? [secret]) {
      assert.ok(!text.includes(needle), `[${kind}] needle "${needle}" survived:\n${text}`);
    }
    assert.ok(
      hits.some((h) => h.kind === kind),
      `[${kind}] missing from hits: ${JSON.stringify(hits)}`,
    );
    // Surrounding transcript context is preserved.
    assert.ok(text.includes("exit code 0"), `[${kind}] context lost`);
    assert.ok(text.includes(`${MARKER}${kind}]`) || kind === "bearer", `[${kind}] no marker`);
  }
});

// --- hits invariants ---------------------------------------------------------
test("hits are sorted by kind, non-zero, and omit misses", () => {
  const { hits } = redact(CORPUS);
  const kinds = hits.map((h) => h.kind);
  assert.deepEqual(kinds, [...kinds].sort(), "hits not sorted by kind");
  assert.equal(new Set(kinds).size, kinds.length, "duplicate kind in hits");
  for (const h of hits) assert.ok(h.count > 0, `zero-count hit: ${h.kind}`);
  assert.ok(!kinds.includes("env"), "env should not fire without bound secrets");
});

test("PATTERNS is exported in application order with {kind, re}", () => {
  assert.ok(Array.isArray(PATTERNS) && PATTERNS.length >= 16);
  for (const p of PATTERNS) {
    assert.equal(typeof p.kind, "string");
    assert.ok(p.re instanceof RegExp, `${p.kind} re is not a RegExp`);
    assert.ok(p.re.global, `${p.kind} re is not global`);
  }
  assert.equal(PATTERNS[0].kind, "pem_block");
  assert.equal(PATTERNS[PATTERNS.length - 1].kind, "private_key_line");
});

test("no pattern matches the literal redaction marker", () => {
  const marked = [...new Set(PATTERNS.map((p) => p.kind)), "env"]
    .map((k) => `value=${MARKER}${k}] and bare ${MARKER}${k}]`)
    .join("\n");
  const { text } = redact(marked);
  assert.equal(text, marked, "a pattern re-matched already-redacted text");
});

// --- 2. non-secrets survive --------------------------------------------------
test("ordinary transcript text is untouched", () => {
  const benign = [
    "$ node /Users/wally/Documents/GitHub/JacHacksSF-2026/mesh/transcript/src/index.js",
    "reading /etc/hosts and ./relative/path.json",
    "exit code 0",
    "commit a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0",
    "model=anthropic/claude-opus-5",
    'KEY=""',
    "TOKEN=null",
    "COUNT=42",
    "nothing secret happened during this run, the secret sauce is just caching",
    "warning: 3 files changed, 12 insertions(+), 4 deletions(-)",
  ].join("\n");

  const { text, hits } = redact(benign);
  assert.equal(text, benign, "benign text was modified");
  assert.deepEqual(hits, [], `unexpected hits: ${JSON.stringify(hits)}`);
});

// --- 3. idempotence ----------------------------------------------------------
test("redaction is idempotent over the whole synthetic corpus", () => {
  const once = redact(CORPUS).text;
  const twice = redact(once).text;
  assert.equal(twice, once);

  for (const { kind, secret } of CASES) {
    const a = redact(transcript(secret)).text;
    const b = redact(a).text;
    assert.equal(b, a, `[${kind}] not idempotent`);
  }
});

// --- 4. makeRedactor with literal env secrets --------------------------------
test("makeRedactor replaces bound literal secrets with [REDACTED:env]", () => {
  const r = makeRedactor(["hunter2hunter2", "abc"]);
  const input = [
    "[12:04:32] connecting to broker with hunter2hunter2 ok",
    "[12:04:33] label abc retained verbatim",
  ].join("\n");

  const { text, hits } = r(input);
  assert.ok(!text.includes("hunter2hunter2"), text);
  assert.ok(text.includes(`${MARKER}env]`), text);
  assert.ok(text.includes("label abc retained"), "short secret should be ignored");
  assert.ok(hits.some((h) => h.kind === "env" && h.count === 1), JSON.stringify(hits));

  // No pattern matches the bare value, so only the literal binding catches it.
  assert.ok(redact(input).text.includes("hunter2hunter2"));

  // Pure-digit and denylisted entries are ignored too.
  const r2 = makeRedactor(["123456789", "password", "correcthorse"]);
  const out2 = r2("pin 123456789 word password phrase correcthorse").text;
  assert.ok(out2.includes("123456789"));
  assert.ok(out2.includes("word password"));
  assert.ok(!out2.includes("correcthorse"));

  // minLen is configurable.
  assert.ok(!makeRedactor(["abcd"], { minLen: 4 })("x abcd y").text.includes("abcd"));

  // Bound redactor keeps full redact() semantics.
  const { text: t3 } = r(transcript("AKIAIOSFODNN7EXAMPLE"));
  assert.ok(!t3.includes("AKIAIOSFODNN7EXAMPLE"));
});

// --- 5. secretsFromEnv -------------------------------------------------------
test("secretsFromEnv picks sensitive names and skips the rest", () => {
  const env = {
    OPENROUTER_API_KEY: "sk-or-v1-0123456789abcdef0123456789abcdef",
    MY_TOKEN: "tok_abcdefghijklmnop",
    DB_PASSWORD: "sup3rsecretpw",
    HOME: "/Users/wally",
    PATH: "/usr/local/bin:/usr/bin:/bin",
    COST_WARN_USD: "50",
    SOME_KEY: "/a/path",
    DEBUG_AUTH: "true",
    NODE_ENV: "production",
  };

  const found = secretsFromEnv(env);
  assert.ok(found.includes(env.OPENROUTER_API_KEY));
  assert.ok(found.includes(env.MY_TOKEN));
  assert.ok(found.includes(env.DB_PASSWORD));
  assert.ok(!found.includes(env.HOME));
  assert.ok(!found.includes(env.PATH));
  assert.ok(!found.includes("50"));
  assert.ok(!found.includes("/a/path"));
  assert.ok(!found.includes("true"));
  assert.ok(!found.includes("production"));
  assert.equal(found.length, 3, JSON.stringify(found));

  // End to end: env values feed makeRedactor.
  const r = makeRedactor(secretsFromEnv(env));
  const out = r(`[12:00:00] db connect with ${env.DB_PASSWORD}`).text;
  assert.ok(!out.includes("sup3rsecretpw"), out);

  assert.deepEqual(secretsFromEnv({}), []);
  assert.ok(Array.isArray(secretsFromEnv()));
});

// --- 6. never throws ---------------------------------------------------------
test("redact never throws on non-string / empty input", () => {
  for (const input of [undefined, null, 12345, "", NaN, true, [], {}, Symbol.iterator]) {
    let out;
    assert.doesNotThrow(() => {
      out = redact(input);
    }, `threw on ${String(input)}`);
    assert.equal(typeof out, "object");
    assert.equal(typeof out.text, "string");
    assert.ok(Array.isArray(out.hits));
  }

  assert.equal(redact(undefined).text, "");
  assert.equal(redact(null).text, "");
  assert.equal(redact("").text, "");
  assert.equal(redact(12345).text, "12345");
  assert.deepEqual(redact("").hits, []);

  // Bad opts must not throw either.
  assert.equal(typeof redact("hello", null).text, "string");
  assert.equal(typeof redact("hello", { secrets: "not-an-array" }).text, "string");
  assert.equal(typeof makeRedactor(null)("hello").text, "string");

  // A poisoned input still yields the withheld sentinel rather than throwing.
  const poisoned = {
    toString() {
      throw new Error("boom");
    },
  };
  const out = redact(poisoned);
  assert.equal(out.text, "[REDACTED:redactor-error — chunk withheld]");
  assert.deepEqual(out.hits, [{ kind: "redactor-error", count: 1 }]);
});

// --- 7. multi-secret line ----------------------------------------------------
test("a single line containing three secrets loses all three", () => {
  const gh = "ghp_0123456789abcdefghij0123456789abcd";
  const aws = "AKIAIOSFODNN7EXAMPLE";
  const slack = "xoxb-1111111111-2222222222222-abcdefghijklmnopqrstuvwx";
  const line = `[12:04:34] curl -H "X-Api-Key: ${gh}" -d "aws=${aws}" -d "slack=${slack}"`;

  const { text, hits } = redact(line);
  for (const s of [gh, aws, slack]) {
    assert.ok(!text.includes(s), `${s} survived:\n${text}`);
  }
  const kinds = hits.map((h) => h.kind);
  for (const k of ["github_token", "aws_key_id", "slack_token"]) {
    assert.ok(kinds.includes(k), `${k} missing from ${JSON.stringify(hits)}`);
  }
  assert.ok(text.startsWith("[12:04:34] curl -H"), text);
});

// --- 8. large input ----------------------------------------------------------
test("~1MB input completes and redacts the secret in the middle", () => {
  const filler = "the harness printed an ordinary line of output here\n";
  const half = filler.repeat(10000);
  const secret = "sk-or-v1-deadbeefdeadbeefdeadbeefdeadbeef";
  const big = `${half}[12:09:00] key ${secret}\n${half}`;
  assert.ok(big.length > 1_000_000, `input too small: ${big.length}`);

  const { text, hits } = redact(big);
  assert.ok(!text.includes(secret));
  assert.ok(text.includes(`${MARKER}openrouter_key]`));
  assert.ok(hits.some((h) => h.kind === "openrouter_key" && h.count === 1));
  assert.ok(text.startsWith(filler));
  assert.ok(text.endsWith(filler));
});
