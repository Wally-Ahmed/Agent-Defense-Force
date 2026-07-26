# Cotal Integration Branch

Reproducible integration of three unmerged upstream PRs onto the latest Cotal release,
built for the JacHacksSF-2026 coordinator.

**Checkout location:** `/Users/wally/Documents/GitHub/Cotal` (sibling of this repo, not nested).
Nothing here is pushed. `integ/mesh` is a local branch only; no upstream PR was opened or modified.

---

## 1. Branch identity

| | |
|---|---|
| Repo | `Cotal-AI/Cotal` (org casing canonicalizes to `Cotal-AI`) |
| Base | tag `v0.14.6` = `d012370a1a4242cf927220a14d07a6b2551614b2` (also `main` tip at clone time) |
| Branch | `integ/mesh` |
| **Final SHA** | **`5da35eb3250133f7fd9d8a8d482c2a2b3fcfce89`** |

### Reproduce

```sh
cd /Users/wally/Documents/GitHub
git clone https://github.com/Cotal-AI/Cotal.git Cotal
cd Cotal
git checkout v0.14.6 -b integ/mesh
git fetch origin pull/254/head:pr254 pull/255/head:pr255 pull/294/head:pr294
git merge --no-ff -m "merge: PR #294 ..." bf012046f8440d95442e7d1f055c7095bdb8ea25
git merge --no-ff -m "merge: PR #254 ..." 1169415b08417e08bc9407940553a5c04af83a8b
git merge --no-ff -m "merge: PR #255 ..." 59e35fba014ae139172f6144af2c9ae6bdb2687f   # 1 conflict, see §2
```

Merge order is deliberate: #294's merge-base is exactly `v0.14.6`, so it lands clean first.
#254 and #255 were both authored against `8aa223e8` (`v0.13.1-21-g8aa223e8`), an older base.

### Merged heads (all verified ancestors of `HEAD`)

| PR | Branch | Head SHA | Merge commit | Adds |
|---|---|---|---|---|
| #294 | `fix/286-dead-agents-go-dark` | `bf012046f8440d95442e7d1f055c7095bdb8ea25` | `73e815a4` | opencode: idle clears activity, shim lifeline, honest offline rows |
| #254 | `add-connector-codex` | `1169415b08417e08bc9407940553a5c04af83a8b` | `7c73afbb` | `extensions/connector-codex` |
| #255 | `add-connector-agy` | `59e35fba014ae139172f6144af2c9ae6bdb2687f` | `5da35eb3` | `extensions/connector-agy` |

---

## 2. Conflicts and how they were resolved

Exactly **one** conflict across all three merges.

### `.changeset/config.json` — `fixed[]` array (PR #255 merge)

Both #254 and #255 appended a package name to the same position in the `fixed[]` version-lock
array. Git could not tell that these were independent additions.

Resolved as a **union** — both entries kept, in merge order:

```json
      "@cotal-ai/connector-opencode",
      "@cotal-ai/connector-codex",
      "@cotal-ai/connector-agy",
      "@cotal-ai/pi",
```

Rationale: this is a release-tooling manifest, not runtime code. Both connectors genuinely
belong in the fixed-version group alongside every other `@cotal-ai/*` package, so the union is
the semantically correct resolution and preserves upstream v0.14.6 intent. Validated with
`JSON.parse`.

### Auto-merged without conflict

- `pnpm-lock.yaml` — all three PRs touched it; git resolved it, and a subsequent `pnpm i`
  produced **zero** lockfile drift (clean `git status`), so the merged lockfile is correct.

### Not a conflict, but noted (no change made)

`extensions/connector-codex` and `extensions/connector-agy` carry `"version": "0.13.1"` in
their `package.json` while every other workspace package is at `0.14.6`. This was left alone
deliberately (conservative resolution — do not hand-edit versions that changesets owns):

- Both declare internal deps as `workspace:*`, so pnpm links them to the **local 0.14.6**
  `@cotal-ai/core` / `@cotal-ai/connector-core`, not to a registry 0.13.1.
- Their only `peerDependencies` entry is `"@cotal-ai/core": ">=0.1.0"` — permissive, no gate.
- There is no runtime version-compatibility check on connectors anywhere in the tree.

So the skew is inert **today**; changesets would normalize it at release. Verified by
`pnpm ls -r` and by a clean typecheck/build of both packages.

**It is not inert unconditionally** — see §5.3, finding 2: `verifyInstalled`
(`implementations/cli/src/seed/reconcile.ts:420-431`) throws on
`installedExtensionVersion(pkg) !== seedGeneration()`. codex/agy escape it only because they are
absent from `OFFICIAL_CONNECTORS`. Adding them there without bumping to `0.14.6` breaks every
boot reconcile.

---

## 3. Build and test results (actual, unedited outcomes)

Toolchain present: Node v25.6.1, pnpm 11.1.2 (repo pins `packageManager: pnpm@11.1.2`),
`nats-server` v2.14.3 at `/opt/homebrew/bin/nats-server`. pnpm was available — no npm fallback needed.

| Step | Command | Result |
|---|---|---|
| Install | `pnpm i` | **exit 0**, 6.9s, no lockfile drift |
| Build | `pnpm build` | **exit 0**, 20/20 packages `Done`, 0 errors |
| Typecheck | `pnpm -r typecheck` | **exit 0**, 20/20 packages `Done`, 0 `error TS` |
| Test | `pnpm test` | **exit 0**, 8 packages with a `test` script all `Done`, 106 `ok -` assertions, **0 failures** |

Honest caveats on `pnpm test`:

- Root `test` is `pnpm -r --if-present test`, so it only runs packages that *define* a test
  script. 8 do: `core`, `workspace`, `connector-hermes`, `pi`, `auth`, `cli`, `manager`, `web`.
- `connector-codex`, `connector-agy`, `connector-opencode`, `connector-core`, `cmux`, `orca`,
  `tmux`, `connector-claude-code`, `delivery` define **no** test script and were skipped.
  In particular **the two new connectors ship no tests of their own.**
- A grep for `not ok|FAILED|✗` in the log returns 14 lines; all 14 are false positives —
  passing assertions whose *names* contain "failed"/"✗" (e.g. `ok - a failed static authority
  commit cannot be finalized`). There are no real failures.

### PR #294 smoke tests (run explicitly — `pnpm test` does not cover them)

PR #294 added three smoke scripts and wired them into `smoke:ci`. Since #294 is load-bearing
for fail-fast dead-agent detection, they were run directly:

| Smoke | Result |
|---|---|
| `pnpm smoke:opencode-idle-activity` | **exit 0** — PASSED (10 checks) |
| `pnpm smoke:opencode-shim-orphan` | **exit 0** — PASSED (7 passed, 0 failed) — spawns a live NATS-backed mesh, SIGKILLs the shim, confirms `offline` is published and the base name respawns healthy (the #286 wedge) |
| `pnpm smoke:offline-display` | **exit 0** — PASSED |

The full `pnpm check` / `pnpm smoke:ci` suite (several hundred smokes, many requiring a live
broker) was **not** run — out of scope and long-running. Everything reported above was executed.

---

## 4. The four connectors we need

All four are pnpm workspace members, all four build to `dist/`, all four typecheck clean.

| Connector | Version | Source | `dist/` output |
|---|---|---|---|
| `connector-codex` | 0.13.1 | PR #254 | `index.js` (691 KB), `serve.js` (2.8 MB) + `.d.ts` |
| `connector-agy` | 0.13.1 | PR #255 | `index.js` (692 KB), `serve.js` (2.8 MB) + `.d.ts` |
| `connector-opencode` | 0.14.6 | upstream + PR #294 | `index.js`, `serve.js`, `plugin.bundle.js` + `.d.ts` |
| `connector-hermes` | 0.14.6 | upstream (untouched) | `index.js`, `launch.js` + `.d.ts` |

`connector-hermes`, `connector-opencode`, `connector-claude-code` were not rewritten.

---

## 5. Operational answers (read from source, with citations)

All paths below are absolute in the integration checkout at
`/Users/wally/Documents/GitHub/Cotal`.

### 5.1 How does `cotal up` start or discover NATS?

**Verdict: external process, auto-spawned. No embedded server.** `cotal up` always spawns a
separate `nats-server` OS process — it is never linked in-process. You do **not** need to start
`nats-server` yourself, but the binary must be resolvable.

Resolution order (`implementations/cli/src/lib/nats-bin.ts:7-33`):

1. **PATH first** — `spawnSync("nats-server", ["--version"])`; if it exits 0, use it
   (`nats-bin.ts:10-11`). On this machine that is `/opt/homebrew/bin/nats-server` v2.14.3 —
   **verified empirically**, so our Homebrew server is what will actually run.
2. **Bundled fallback** — dynamic `import("@eplightning/nats-server-${platform}-${arch}")`,
   then `getBinaryPath()` (`nats-bin.ts:5,15-16`). Declared as optional deps of the CLI
   (`implementations/cli/package.json:40-45`). Verified resolvable from the CLI package to
   `node_modules/.pnpm/@eplightning+nats-server-darwin-arm64@2.14.0/.../bin/nats-server`.
3. **Neither** — throws `nats-server not found on PATH, and the bundled binary for
   ${platform}/${arch} (${pkg}) is not installed.` plus install recourse
   (`nats-bin.ts:25-31`).

Spawn and artifacts:

- Foreground: `const { bin, source } = await resolveNatsServer();` then
  `spawn(bin, natsArgs, { stdio: "inherit" })` — `implementations/cli/src/commands/up.ts:669,678`.
- Detached (`--detach`): `spawn(bin, args, { detached: true, stdio: ["ignore", fd, fd] })`
  with `fd` on `.cotal/nats.log` — `up.ts:1608-1614`.
- Pidfile: `<root>/.cotal/nats.pid` — `up.ts:680` (`writeFileSync(cotalPath("nats.pid"), …)`),
  removed on shutdown at `up.ts:723`.
- JetStream store dir: default `<root>/.cotal/nats` (`up.ts:647`, `cotalPath` at
  `implementations/cli/src/lib/paths.ts:12-14`); override `--store-dir`.
- Server config: `<root>/.cotal/auth/server.conf` — written at `up.ts:1913-1914`, rendered by
  `serverConfig()` in `packages/core/src/provision.ts:1748-1789`. It sets
  `jetstream { store_dir: … }`, `max_control_line: 65536`, and decentralized JWT auth
  (`operator:`, `system_account:`, `resolver: MEMORY`, `resolver_preload`).
- `--open` mode skips the conf file and passes raw flags instead:
  `["-js", "-sd", storeDir, "-p", String(port), "-a", host]` — `up.ts:664`.

Defaults / overrides: `DEFAULT_SERVER = "nats://127.0.0.1:4222"`
(`packages/core/src/endpoint.ts:129`); host defaults to `127.0.0.1` (`up.ts:465`); port comes
from the `--server` URL or 4222 (`up.ts:661`). **Overrides are CLI flags only** — `upFlags` at
`up.ts:137-153` (`--server`, `--host`, `--store-dir`, `--open`, `--user-auth`, `--detach`).
No env var controls broker URL/port/store-dir. (`COTAL_HOME` only relocates the machine-wide
mesh registry — `packages/workspace/src/mesh-registry.ts:71-81`.)

**No prior init step is needed.** There is no `cotal init`; `cotal setup` is explicitly
configure-only and "NEVER launches anything"
(`implementations/cli/src/commands/setup.ts:36-51`). `cotal up` self-provisions space trust via
`authSetup()` → `createSpaceAuth()`/`putSpaceAuth()` (`up.ts:1874-1919`).

Note: `bin/cotal.ts:1-30` enforces **Node ≥ 22** before anything imports the broker chain,
because npm silently skips the optional binary package on older Node.

### 5.2 The exact `cotal mint` invocation, and what it writes where

Command registration: `implementations/cli/src/index.ts:205-218`.
Implementation: `implementations/cli/src/commands/mint.ts:23-115`.

Literal usage string (`mint.ts:50`):

```
cotal mint <name> --profile <agent|observer|admin> [--allow-subscribe a,b] [--allow-publish a,b] [--out <path>]
```

`--profile` defaults to `agent`. A second mode exists:
`cotal mint --signer [--out <path>] [--force]`.

Files written (**paths only — no credential material is reproduced anywhere in this repo**):

| Path | What it is | Constructed at |
|---|---|---|
| `<root>/.cotal/auth/creds/<name>.creds` | Default output. A NATS creds file (JWT block + user nkey seed). Written twice byte-identically: once to secret-store key `auth/creds/<name>.creds`, then materialized to the same on-disk path | `mint.ts:106-110` via `agentSecretFilePaths()`; path built in `packages/workspace/src/auth-paths.ts:237-242,258` |
| `<--out path>` | Caller-chosen path, resolved from cwd. Written as a plain file, bypassing the secret store | `mint.ts:97-102` |
| `./signer.json` (default for `--signer`) | Stripped `space` + `account.pub` + `account.signingSeed` only, no operator root-of-trust. Intended to be mounted read-only at `/workspace/.cotal/auth/auth.json` in a containerized manager | `mint.ts:36,44` |

Permissions: all secret writes go through `packages/core/src/secret-fs.ts` — files at `0o600`
(`secret-fs.ts:87-88`), parent dirs at `0o700` (`secret-fs.ts:128-129`), plus `icacls` ACL
hardening on win32 (`secret-fs.ts:52-79`). Modes are passed directly to
`mkdirSync`/`writeFileSync`; there is no umask call.

Credentials minted as a side-effect elsewhere:

- `cotal spawn` (auth mode, foreground) mints an `agent`-profile cred to the **identical**
  canonical path/key (`implementations/cli/src/commands/spawn.ts:436-474`) and deletes it —
  store entry plus `rmSync(credsPath)` — on exit via a `deprovisioner` mint
  (`spawn.ts:494-508`).
- `cotal join` with no `--creds`/`--token`/link self-mints a `provisioner` then an `agent` cred
  **in memory only**; nothing is written to disk
  (`implementations/cli/src/commands/join.ts:139-171`).
- `cotal ext` has **no** credential side-effects (grepped `mint`/`creds`/`nkey`/`jwt` in
  `implementations/cli/src/commands/ext.ts` — no matches).

### 5.3 How is a connector registered and launched?

**Registration — `cotal ext add`.** Literal usage string
(`implementations/cli/src/commands/ext.ts:91`):

```
cotal ext <add <npm-package> | remove <name> | list | root | seed [--repair|--reset|--force]>
```

Accepted specs: an npm name (`name`, `@scope/name`, either with an optional `@range`) or a local
path (`./relative` or `/absolute`). **Git and tarball URLs are explicitly refused**, not guessed
at — `ext.ts:365`, rejection in `packageNameFromSpec` at `ext.ts:367-381`; path-vs-registry
classification at `ext.ts:45-47`. Dispatch at `ext.ts:65-91`, core logic `addExtension` at
`ext.ts:164-360`, which npm-installs into a Cotal-owned prefix (never the user's project),
imports the package once, verifies the import actually registered something in the `registry`,
and rejects a name collision or a non-peer'd `@cotal-ai/*` dependency.

What it writes:

- npm tree under `extensionsDir()` = `<globalConfigDir()>/extensions`
  (`packages/workspace/src/extensions.ts:61-63`)
- manifest `extensions.json` at `extensionsManifestPath()` =
  `<globalConfigDir()>/extensions/extensions.json` (`extensions.ts:65-67`), saved at
  `ext.ts:349` (and rewritten on remove at `ext.ts:425`)

`globalConfigDir()` = `$XDG_CONFIG_HOME/cotal`, else `%APPDATA%\Cotal` on win32, else
`~/.config/cotal` (`packages/core/src/connector-config.ts:60-66`). **On this machine that
resolves to `~/.config/cotal/extensions/extensions.json`.**

**Launch chain.** Each connector package registers a `Connector` object on import
(`registry.register(...)` at the bottom of its entry module); the launcher resolves it with
`registry.resolve<Connector>("connector", agentType)`. Two paths:

1. **Foreground `cotal spawn <persona>`** — `connector.buildLaunch(opts)` returns a
   `LaunchSpec`, spawned directly by Node:
   `spawnProcess(spec.command, spec.args, { stdio: "inherit", env: spec.env, cwd })` at
   `implementations/cli/src/commands/spawn.ts:549`. Note the env is *only* the
   connector-declared env — never `...process.env` — so operator secrets do not bleed in.
2. **`cotal spawn --detach`, a manifest, or a peer's `cotal_spawn` MCP tool** — the CLI sends a
   `"start"` control op to the running manager (`spawn.ts:242`). The manager preflights
   `connector.requires` / `supportsResume` / `supportsModelVariant`
   (`implementations/manager/src/manager.ts:2153-2231`), calls `connector.buildLaunch(...)` at
   `manager.ts:2334`, then `this.runtime.spawn(name, spec, cwd)` at `manager.ts:2372`. The
   default runtime is `PtyRuntime`, which does the OS spawn through `@lydell/node-pty`:
   `pty.spawn(command, args, { cols, rows, cwd, env: spec.env ?? {} })` —
   `implementations/manager/src/runtime/pty.ts:33-49`. Pluggable alternatives live in
   `extensions/orca`, `extensions/cmux`, `extensions/tmux`.

`LaunchSpec.command` is always `process.execPath` (Node), with args pointing at the connector's
own bundled shim resolved via `fileURLToPath(new URL("./serve.js", import.meta.url))` — e.g.
`extensions/connector-codex/src/index.ts:22,80`. It is **never** an npm `bin` entry. (Only
`connector-hermes` declares a `bin` at all, and it is an unrelated one-off `bin/install.mjs`.)

**Drift found in the two new connectors — invisible to `tsc`, matters at runtime:**

The connector code itself is conformant: both `package.json`s correctly peer `@cotal-ai/core`
without vendoring `@cotal-ai/*`, and both `src/index.ts` register a spec-shaped `Connector`
(`requires`, `supportsModelVariant`, `buildLaunch`) identical in shape to opencode/hermes.
The drift is in the surrounding registry:

1. **Neither is in the first-party connector registry.** `OFFICIAL_CONNECTORS` in
   `packages/workspace/src/official-connectors.ts:11-16` still lists only
   `claude, opencode, hermes, pi` — a grep for `codex|agy` in that file returns **0** matches.
   `SEEDED_EXTENSIONS` (`official-connectors.ts:30-35`) is derived from it, as is
   `SEED_BUILTINS` (`implementations/cli/src/seed/paths.ts:20`). Consequence: the boot-time
   auto-reconcile (`implementations/cli/src/seed/reconcile.ts`) will **never** install codex or
   agy on a fresh `cotal-ai` install — **we must `cotal ext add` them by hand.** The
   `connectorInstallHint` text (`official-connectors.ts:44-51`) and the `cotal_spawn` MCP
   tool's `agent` field description (`extensions/connector-core/src/tool-specs.ts:530`) also
   still name only claude/opencode/hermes.
2. **Version-skew landmine.** `verifyInstalled` in
   `implementations/cli/src/seed/reconcile.ts:420-431` hard-throws
   `"... installed at version X but the seed generation is Y (a version-skewed payload)"` unless
   `installedExtensionVersion(pkg) === seedGeneration()` (the CLI's own version, `0.14.6`).
   codex/agy at `0.13.1` are shielded today *only* by finding #1 keeping them out of the seed
   list. **If anyone adds them to `OFFICIAL_CONNECTORS` without bumping their `package.json` to
   `0.14.6`, every boot reconcile and `cotal ext seed` breaks loudly.**

### 5.4 How are a model and a reasoning effort passed per connector?

**One generic pair — `model` and `variant`** — carried on `LaunchOpts`
(`packages/core/src/connector.ts:47-55`), with `Connector.supportsModelVariant` as the opt-in
gate (`connector.ts:186-188`). Each connector renders `variant` into its own host CLI's form;
only codex's rendering is literally a reasoning effort.

Precedence (highest wins): **CLI flag → agent-file frontmatter → default**.

| Layer | Names | Source |
|---|---|---|
| CLI flags | `--model <m>`, `--variant <v>`, plus repeatable `--opt k=v` | `packages/workspace/src/flags.ts:31-33` |
| Agent file | `model:`, `variant:` frontmatter | same flag descriptions ("wins over the agent file's model:") |
| Child env | `COTAL_MODEL`, `COTAL_VARIANT` | read into `AgentConfig` at `extensions/connector-core/src/config.ts:201-202`:<br>`model: env.COTAL_MODEL?.trim() \|\| def?.model \|\| undefined`<br>`variant: env.COTAL_VARIANT?.trim() \|\| def?.variant \|\| undefined` |

Unsupported variants **fail loud before any credential is minted** — gated at
`implementations/manager/src/manager.ts:2231` and `implementations/cli/src/commands/spawn.ts:398`
(`if (variant && !connector.supportsModelVariant) …`).

| Connector | Model | Reasoning effort (`variant`) |
|---|---|---|
| **codex** | `--model <m>` appended to `codex exec` — `extensions/connector-codex/src/serve.ts:151` | **Yes — this is a true reasoning effort.** `supportsModelVariant: true` (`index.ts:28`), rendered verbatim as `-c model_reasoning_effort="<variant>"` — `serve.ts:152` |
| **agy** | `--model "<name>"` under `script -qec …` — `extensions/connector-agy/src/serve.ts:250-251` | **No.** `supportsModelVariant: false`; `buildLaunch` throws if `variant` is set — `extensions/connector-agy/src/index.ts:71-74`. Effort must be baked into the model *string*, e.g. `"Gemini 3.1 Pro (High)"` |
| **opencode** | `config.model` / `agent.cotal.model` injected via `OPENCODE_CONFIG_CONTENT` — `extensions/connector-opencode/src/extension.ts:194-198` | **Yes**, but it is opencode's *own* model-variant concept (e.g. high/max/low from `opencode models --pure --verbose`). Cotal only threads the string into `agent.cotal.variant` — `extension.ts:199-201,219` |
| **hermes** | `HERMES_MODEL` / `COTAL_MODEL` written into Hermes' own `config.yaml` — `extensions/connector-hermes/src/launch.ts:70-71` | **No.** Declares no `supportsModelVariant` (absent = default-deny); `buildLaunch` throws unconditionally: `"the Hermes connector does not support model variants (variant)"` — `extensions/connector-hermes/src/extension.ts:40` |

Practical upshot for the coordinator: **codex is the only one of our four connectors with a
first-class per-launch reasoning-effort dial.** For agy, select effort by choosing the model
display name. For hermes, do not pass `--variant` at all — it throws.


### 5.5 Can an agent's full CLI output be surfaced into Cotal chat?

**Short answer: partially, and NOT for the connectors we are adding. This is a blocker for the
hard requirement.**

**Mechanism name: the transcript mirror.** It is a per-agent chat channel named `tr-<name>`,
produced by `transcriptChannel(name)`:

```ts
// extensions/connector-core/src/launch.ts:201-203
export function transcriptChannel(name: string): string {
  return `tr-${name.toLowerCase().replace(/[^a-z0-9_-]+/g, "-")}`;
}
```

It is **not** a separate stream or KV bucket — it is an ordinary multicast chat subject
`cotal.<space>.chat.<owner>.<actor>.tr-<name>` built by `chatSubject()`
(`packages/core/src/subjects.ts:78-83`), riding the same JetStream stream as all chat,
`CHAT_<space>` (`subjects.ts:845-847`). Presence, by contrast, *does* live in a JetStream KV
bucket (`subjects.ts:11`); transcript does not.

**It is a condensed digest, not raw CLI output.** `condensePart()` in
`extensions/connector-opencode/src/transcript.ts:46-63`:

- assistant text — passed through in full
- tool calls — collapsed to a one-liner `⚒ tool: input`
- tool results — truncated to 700 chars (`MAX_PREVIEW`)
- reasoning / thinking parts — **dropped entirely**
- file / step / snapshot / patch parts — **skipped** (so diffs never appear)

`connector-claude-code` mirrors the same shape by reading the session JSONL rather than stdout
(`extensions/connector-claude-code/src/transcript.ts:9-11,49-84`). **No connector taps a
pty or stdout stream anywhere in the tree** — no such producer exists. So "everything a user
would see in the terminal" is *not* what lands in chat even in the best case.

**Visibility / grants.** Same subject space as any named channel, but grant-scoped like a
non-default channel. A spawned agent's `allowSubscribe` defaults to `["general"]` only
(`implementations/manager/src/manager.ts:2209`, `packages/core/src/provision.ts:905`), so a peer
cannot read another agent's `tr-<name>` without an explicit subscribe grant. `--transcript` /
`transcript: true` grants the mirroring agent **publish** on its own channel only
(`manager.ts:2245-2249`); that is exactly what `smoke:transcript-grant` verifies
(`implementations/manager/smoke/transcript-grant-acl.smoke.ts:93-116`). Elevated
`observer`/`admin` connection profiles — dashboards, `cotal console` — get a wildcard `chat.>`
subscribe and therefore see transcripts for free (`packages/core/src/provision.ts:833-850`).

**What a connector must implement:**

- `MeshAgent.send(text, channel?, mentions?)` — `extensions/connector-core/src/agent.ts:649`
- `MeshAgent.setStatus(status, activity?)` — `extensions/connector-core/src/agent.ts:773`
- the optional `Connector.transcriptChannel(name)` contract field
  (`packages/core/src/connector.ts:166`), backed by the `transcriptChannel()` helper above;
  the manager calls it to grant the publish ACL.

There is **no shared mirror/condense helper** in `connector-core` — opencode and claude-code
each hand-roll their own buffering and condensing against those two primitives.

**Per-connector status:**

| Connector | Mirrors to chat? | Evidence |
|---|---|---|
| `connector-opencode` | **Yes** (condensed) | `createTranscriptMirror` wired in `extensions/connector-opencode/src/plugin.ts:107-114,458-476` |
| `connector-hermes` | **No** — presence only | `extensions/connector-hermes/src/hermes-hooks.ts:34-54`; its `Connector` registration has no `transcriptChannel` field (`extension.ts:24-30`) |
| `connector-codex` | **No** — fails loud | `throw new Error("codex connector: transcript mirroring is not implemented (v1).")` — `extensions/connector-codex/src/index.ts:40` |
| `connector-agy` | **No** — fails loud | `throw new Error("agy connector: transcript mirroring is not implemented (v1).")` — `extensions/connector-agy/src/index.ts:44` |

**Implication for us:** requesting `--transcript` on a codex or agy agent will *throw*, not
degrade silently. To meet the "all action logs appear in Cotal chat" requirement we must either
(a) implement `transcriptChannel` + a mirror in codex/agy against `MeshAgent.send`, modeled on
`extensions/connector-opencode/src/transcript.ts`, or (b) restrict the requirement to
opencode/claude-code agents and accept a condensed digest rather than literal terminal output.

### 5.6 What PR #294 actually changed (the fail-fast property we depend on)

- **Idle clears retained activity** — session end, `/new` adoption, and error paths now call
  `safeStatus("idle", "")` instead of a bare `"idle"`, so a stale activity string cannot linger:
  `extensions/connector-opencode/src/plugin.ts:268,471,488,507`.
- **Shim lifeline** — the launcher passes its own pid as `COTAL_OPENCODE_SHIM_PID`
  (`extensions/connector-opencode/src/serve.ts:145`); the plugin polls it every 2s and
  self-shuts-down if the shim disappears (e.g. SIGKILL) —
  `extensions/connector-opencode/src/plugin.ts:175-205`.
- **Honest offline rows** — new `relativeTime()` / `offlineDetail()` render
  `last seen <relative> · was: <activity>`: `implementations/cli/src/ui.ts:21-46`, consumed in
  `implementations/cli/src/commands/status.ts:328-337` and
  `implementations/cli/src/commands/endpoints.ts:41-48`.
- **Single-flight bounded shutdown** — a `stopping` guard plus an unref'd 10s hard-exit so the
  control-plane and lifeline paths cannot double-teardown —
  `extensions/connector-opencode/src/plugin.ts:54,134-154`.

This is what stops a dead agent from reading `working` forever, which is why our coordinator can
fail fast instead of burning its full 180s assessment window.

---

## 6. Known gaps / blockers

1. **Transcript mirroring is unimplemented in `connector-codex` and `connector-agy`** — both
   throw explicitly (§5.5). Blocks the "all action logs in Cotal chat" requirement for those
   two agents until we implement it.
2. **Even where mirroring exists it is a digest, not raw terminal output** — reasoning traces
   dropped, tool args one-lined, tool results truncated at 700 chars, diffs skipped (§5.5).
   Nothing in Cotal currently tapes a pty/stdout.
3. **The two new connectors ship no tests** — they compile and typecheck, but their runtime
   behavior is unverified by CI (§3).
4. **codex and agy are not first-party-registered** — absent from `OFFICIAL_CONNECTORS`
   (`packages/workspace/src/official-connectors.ts:11-16`), so the boot-time seed reconcile
   never installs them. **We must `cotal ext add` both explicitly** on every fresh environment
   (§5.3). They also do not appear in `connectorInstallHint` or the `cotal_spawn` MCP tool's
   `agent` enum description, so a peer agent asked to spawn `codex`/`agy` gets no hint they exist.
5. **`connector-codex` / `connector-agy` stamped `0.13.1` vs the CLI's `0.14.6`** — harmless
   while they stay out of `OFFICIAL_CONNECTORS`, but `verifyInstalled`
   (`implementations/cli/src/seed/reconcile.ts:420-431`) will hard-throw a "version-skewed
   payload" the moment they are promoted into the seed set without a version bump (§2, §5.3).
6. **No per-launch reasoning-effort dial on agy or hermes** — only codex renders `variant` to a
   real reasoning effort; agy requires baking the level into the model display name and hermes
   throws on any `variant` (§5.4). Plan coordinator configs accordingly.
7. **Full `pnpm check` / `smoke:ci` was not run** — hundreds of live-broker smokes, out of scope.
   The three #294 smokes that matter for fail-fast were run and pass (§3).
