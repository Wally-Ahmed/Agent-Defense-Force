# Shot list — scene visuals

One entry per scene. Every frame is **1800 × 600** (3:1), which is the canvas the media strip's
`object-fit: cover` crop expects at typical widths — **keep critical content vertically centred**
and leave safe margins.

**File naming — the engine picks these up with zero code changes:**

```
walkthrough/img/scene<n>.mp4    animated clip — WINS when present
walkthrough/img/scene<n>.png    still fallback — gets an automatic Ken Burns pan/zoom
```

`<n>` is the scene's **stable ID** from the `TOUR` array, not its play position. Until either file
exists the strip shows a labelled placeholder card carrying the scene's `shot` string (the one-liner
in `TOUR`, which mirrors the **Shot** line below). Missing files degrade gracefully — `onerror`
no-ops — so you can ship stills first and upgrade scenes to video later, one at a time.

## Rules that apply to every frame

- **`<meta charset="utf-8">` in every HTML frame source.** Without it arrows and dashes render as
  mojibake in the screenshot. This has bitten before.
- **Serve frames over `localhost` to screenshot them.** Playwright will not screenshot `file://`.
  Path-bind the server: `python3 -m http.server 8901 --directory <framedir>`.
- **Animated, not a slideshow.** A still-per-beat video reads as "static images in a slide show" and
  gets rejected. Author one self-contained 1800×600 stage HTML per scene with all motion on an
  absolute WAAPI timeline exposed as `window.seek(t)`, capture at 15 fps by seeking, then encode.
  Motion gate: unique frames (via `mpdecimate`) ≥ 0.8 × source frames.
- **Video duration must equal the scene's mp3 duration** (±0.1 s). Until narration exists, build to
  the `dur` declared in `TOUR` / the duration table in `script.md`, and re-time when audio lands.
- **Match the page palette** so the strip does not look bolted on:
  bg `#07090e` · panel `#161b28` · line `#2a3245` · text `#e4eaf5` · dim `#8b93a7` ·
  accent `#5eead4` · indigo `#818cf8` · hermes `#c792ea` · win `#34d399` · warn `#fbbf24` ·
  fail `#f87171` · Claude `#e0975c` · GPT `#74b9ff` · Gemini `#7bd88f` · Kimi `#f0abfc` ·
  GLM `#fbbf24`.
- **Label anything not yet measured.** Any frame showing a number that did not come out of a real
  run carries a visible `ILLUSTRATIVE` chip, exactly as the page does.
- **Never re-bake from a baked frame.** Crops/upscales lose a generation each time — always rebuild
  from the original source asset.

---

## Scene 1 — `img/scene1.*` · 49.5 s

**Shot:** the two-phase chain — vulnerability in, then credentials harvested and lateral movement
over a weekend.
**Capture from:** not the running system. This is an authored diagram frame.
**Content:** a left-to-right timeline in two clearly separated halves.
Half A (`fail` red, labelled *PHASE ONE · JULY 2026 · THE WAY IN*): "malicious dataset →
remote-code dataset loader + template-injection → code runs on a processing worker".
Half B (`warn` amber, labelled *PHASE TWO · THE PART WE BUILT FOR*): "node-level access →
**valid cloud and cluster credentials harvested** → lateral movement across internal clusters →
over a weekend". A footer strip carries the attribution: *Hugging Face disclosure, 16 Jul 2026 ·
OpenAI: its own models, internal cyber benchmark, escaped test scope (TechCrunch, 21 Jul 2026)*.
**Do not draw:** a hooded-figure/hacker motif, or anything implying a criminal third party. It was
an eval that escaped scope.
**Motion:** the chain draws left to right; the phase-two half brightens as phase one dims.

## Scene 2 — `img/scene2.*` · 49.8 s

**Shot:** split panel — five refusable request classes against five that look identical and are
legitimate.
**Capture from:** authored frame; the request text can be lifted from the frozen Northwind API
contract once the gateway exists.
**Content:** two columns of five rows. Left, red: `401 expired session` · `403 wrong tenant` ·
`403 role lacks permission` · `403 CSRF missing` · `422 / 429 malformed or over limit`. Right,
teal: five rows that are visually *identical in structure* and all `200 OK`. A hairline between
them, and one line under the whole thing: **"the difference is not in a request — it is across
requests."**
**Motion:** left column stamps down one row at a time, then right column, then the footer line
resolves last.

## Scene 3 — `img/scene3.*` · 45.5 s

**Shot:** the skills-library card with the community-maintained disclaimer set large, plus the
pinned commit.
**Capture from:** `vendor/cybersecurity-skills/index.json` (real — 817 entries) and the pinned
commit SHA recorded in the repo. A `git log -1 --format=%H vendor/cybersecurity-skills` screenshot
is an acceptable inset.
**Content:** big count **817**, `Apache-2.0`, `github.com/mukul975/Anthropic-Cybersecurity-Skills`,
the short pinned SHA. Beside it, at equal or greater weight: **"Community-maintained. Not an
official Anthropic release."** Small inset showing an `assessment.v1` fragment with a populated
`skills_used[]` (path + sha).
**Motion:** skill tiles cascade in behind the count; the disclaimer arrives last and stays.

## Scene 4 — `img/scene4.*` · 47.5 s

**Shot:** one channel out to five isolated responders, five direct messages back, no path between
them.
**Capture from:** authored frame; subject names from `contracts/mesh/channels.yaml`.
**Content:** Hermes at left publishing onto a channel rail; five responder boxes stacked at right,
**with visible gaps and no connecting lines between them**; five separate return arrows labelled
`DM` running back to the coordinator. Legend chips: `channel — multicast` · `toService — anycast` ·
`to — unicast DM`. Footer: **"independence is enforced by the transport."**
**Motion:** the outbound packet travels the channel and forks five ways; return DMs travel back at
staggered times. Ambient traveling dots keep the rails alive throughout.

## Scene 5 — `img/scene5.*` · 40.0 s

**Shot:** the thesis sentence with its four commitments pulled out beneath it.
**Capture from:** authored typographic frame.
**Content:** the thesis verbatim, set large, with `recognizes the coordinated behavior`,
`five independent model assessments` and `narrowly scoped containment` accented. Four numbered
commitment chips beneath. **The sentence is verbatim — proofread against `script.md` before
capture.**
**Motion:** the sentence types/reveals by clause; each commitment chip pops as its clause completes.

## Scene 6 — `img/scene6.*` · 45.5 s

**Shot:** the eight shipped controls ringing the app, all green, with the domain model beneath.
**Capture from:** `contracts/app_api.openapi.yaml` (frozen) for the control names; a capture of the
running gateway's `/healthz` + a real 200 response once the app exists.
**Content:** centre — `Northwind Projects · Jac`. Ring of eight green control chips:
`__Host-sid` · `__Host-csrf double-submit` · `nwp_ argon2id` · `15-step deny order` ·
`per-(user,tenant) membership: owner > admin > member > viewer` · `per-route rate limits` ·
`CORS / HSTS / CSP` · `Tenant → Project → Task → Comment, sensitivity normal|confidential|canary`.
A banner across the bottom, unmissable: **"NOT DELIBERATELY VULNERABLE — nothing was weakened."**
**Motion:** chips light around the ring in sequence; the banner is present from t=0 and never dims.

## Scene 7 — `img/scene7.*` · 46.0 s

**Shot:** the full architecture animating stage by stage, top to bottom.
**Capture from:** authored frame mirroring `#arch` on the page — keep the two consistent, a mismatch
reads as a bug.
**Content:** app → Hermes (`z-ai/glm-5.2`) → incident record → Cotal mesh → five responder boxes in
their model colours → coordinator (badged **NOT A MODEL**) → policy + audit. Three bands drawn
behind it, labelled **DETECTION · JUDGMENT · ENFORCEMENT**.
**Motion:** a single packet travels the whole path once, each stage lighting as it arrives; the
three bands label themselves as the packet crosses each boundary.

## Scene 8 — `img/scene8.*` · 47.0 s

**Shot:** a rolling ninety-second window with the feature vector redrawing, none of it a violation.
**Capture from:** `contracts/mesh/window.v1.schema.json` for the exact feature names; once the
aggregator exists, capture a real `window.v1` payload.
**Content:** six 15-second window tiles marching left across a 90-second rail. Underneath, the
feature vector as labelled bars against a p95 baseline line: `req` · `distinct_paths` ·
`path_entropy` · `auth_fail` · `authz_deny` · `deny_ratio` · `new_endpoints_first_seen` ·
`src_ips_distinct` · `ua_distinct` · `cross_tenant_attempts` · `canary_touch` ·
`post_deny_pivot_ms_p50` · `integration_calls` · `export_bytes`. Every bar tagged
**"not a violation"**.
**Motion:** windows march continuously (this is the scene's ambient motion — keep it constant
velocity, no easing dwell); bars redraw per window; a few cross the baseline late in the clip.

## Scene 9 — `img/scene9.*` · 43.2 s

**Shot:** five responder cards, each a different lineage, receiving the identical incident record.
**Capture from:** `contracts/mesh/channels.yaml` (runtime + model ids) and
`contracts/mesh/assessment.v1.schema.json` (output shape).
**Content:** five cards in model colours: `responder_claude · claude_code · anthropic/claude-opus-5`
· `responder_codex · codex · openai/gpt-5.6-sol` ·
`responder_antigravity · agy · google/gemini-3.1-pro-preview` ·
`responder_kimi · opencode · moonshotai/kimi-k3` · `responder_glm · opencode · z-ai/glm-5.2`.
One incident record above, five identical copies dropping into the five cards. Beneath, the answer
schema: `verdict` · `confidence` · `campaign_stages[]` · `recommended_actions[]` · `skills_used[]` ·
`rationale ≤ 400 chars`.
**Motion:** the incident splits into five identical copies that fall into the cards at a stagger;
each card's schema slots fill.

## Scene 10 — `img/scene10.*` · 49.8 s

**Shot:** five confidences resolving into one arithmetic score against the frozen contain rule.
**Capture from:** `contracts/mesh/decision.v1.schema.json` — the rule string is frozen and must be
reproduced exactly: `contain iff >= 3/5 malicious AND score >= 1.5`.
**Content:** five confidence bars collapsing into a single score dial with the `1.5` threshold drawn
as a hard line. Chips for `verdict_counts` · `quorum_met` · `degraded`. A prominent, deliberate
callout: **"per-responder weights: NOT YET DEFINED"** — this frame must not display invented
weights. Corner badge: **NOT AN LLM JUDGE · plain Jac · model: null**.
**Motion:** bars converge into the dial; the needle settles above the threshold; the
weights-undefined callout arrives and holds.

## Scene 11 — `img/scene11.*` · 46.0 s

**Shot:** the ten containment kinds with their TTLs, the two chosen lit, whole-tenant struck out.
**Capture from:** `contracts/containment.contract.jac` — this file is real and compiles, so the
kinds, TTLs, blast radii and approval flags can be read straight out of `CONTAINMENT_KINDS`.
**Content:** ten rows: `revoke_session` · `revoke_token` · `suspend_principal 1800s` ·
`force_reauth 3600s` · `throttle_source 900s` · `block_source 900s` · `feature_readonly 900s` ·
`pause_queue 600s` · `raise_logging 3600s` · `rotate_service_credential — HUMAN REQUIRED`. The first
two lit as chosen. A struck-out row beneath the set reading **"whole tenant / stop service — NOT
AVAILABLE"**. Side panel: `prior_state` snapshot → `rolled_back` as an ordinary state.
**Motion:** rows arrive in order; the two chosen brighten; the struck-out row draws its strike last.

## Scene 12 — `img/scene12.*` · 43.2 s

**Shot:** six refused requests, each annotated with the decision-order step that caught it.
**Capture from:** the running gateway once it exists — a real terminal/log capture is much stronger
than an authored frame here. Until then, authored, chip-labelled `ILLUSTRATIVE`.
**Content:** six log rows with red status codes and, to the right of each, the numbered step of the
15-step deny decision order that produced it. Footer: **"every one of these is decidable from a
single request."**
**Motion:** rows land one at a time with the matching decision-order step lighting on the right.

## Scene 13 — `img/scene13.*` · 42.0 s

**Shot:** the campaign log, every line 200 OK, with the fan-out count climbing in the corner.
**Capture from:** the attack driver against the running gateway once both exist. Real capture
strongly preferred — the whole point is that it looks legitimate.
**Content:** the same visual grammar as scene 12 so the pair reads as a matched set, but every
status is a green `200`. A counter in the corner climbing to `31 projects / 94 s`. Footer:
**"nothing here is refusable."**
**Motion:** rows stream continuously (constant rate, no easing) while the counter climbs.

## Scene 14 — `img/scene14.*` · 44.3 s

**Shot:** the live incident record — narrow normal cluster beside the wide campaign fan, with join
keys and families.
**Capture from:** a real `incident.v1` payload once Hermes emits one; the graph rendering is a
**view** of that record. Node/edge types are not implemented yet, so until then this is a hand-drawn
approximation and must carry the `ILLUSTRATIVE` chip.
**Content:** left, a narrow deep cluster (one principal → one project → its tasks → their comments).
Right, a wide flat fan (one principal → 31 unrelated projects). Both drawn with the note **"every
edge individually authorized."** Below, the record's own fields: `join_keys` (principal, tenant,
session ids, source ips, user agents) · `evidence[]` event ids · the family chips
`denial_shape · breadth · novelty · cadence · pivot · escalation · canary` · `stage_signature`.
**Motion:** the two clusters grow edge by edge — the normal one deepening, the campaign one
fanning — then the family chips light in sequence.

## Scene 15 — `img/scene15.*` · 40.8 s

**Shot:** Hermes publishing once, then five isolated responder lanes returning by direct message.
**Capture from:** a real mesh transcript once the responders are wired. Until then, authored.
**Content:** one publish event at left; five horizontal lanes, visually sealed from each other,
each with its own return arrow and arrival time. Verdicts land at the right: four `malicious`,
one `suspicious`. Footer: **"they will not agree perfectly. that is the design working."**
**Motion:** the publish fires, five lanes animate independently at different speeds, verdict chips
pop as each lands.
**Note:** if the real run's split is not 4/1, the frame *and* scene 15's narration both change —
they must be updated together.

## Scene 16 — `img/scene16.*` · 40.8 s

**Shot:** two lanes side by side — the contained session stopped, real users still at 200 OK.
**Capture from:** the running system: a split screen of the contained principal's requests failing
closed beside a live legitimate-traffic tail. This is the single most persuasive real capture in the
deck — prioritise it.
**Content:** left lane, red: `revoke_session s-9f3a` · `revoke_token nwp_…7c1` and the contained
session's next request refused. Right lane, green: four or five real users in the same tenant, same
second, all `200`. Big centre label: **"blast radius: one session, one token."** Struck-out chips:
`tenant lock` · `service shutdown` · `mass sign-out`.
**Motion:** the left lane stops dead; the right lane keeps streaming for the whole clip — the
continuing motion on the right *is* the argument.

## Scene 17 — `img/scene17.*` · 44.3 s

**Shot:** the audit ledger filling row by row, ending on the rollback record.
**Capture from:** the real audit trail once the executor exists — `AuditEvent` nodes plus the
`ContainmentAction` state transition to `rolled_back`.
**Content:** six ledger rows: `window` · `incident` · `assessments` · `decision` · `action` ·
`rollback`, each with a hash/id and a `replayable ✓`. The final row shows the state transition
`applied → rolled_back` and the session restored. Footer: **"reversal is a recorded operation, not
an emergency."**
**Motion:** rows land in order; the rollback row lands last and holds, brighter than the rest.

---

## Production order (highest value first)

1. **Scene 16** — the two-lane containment capture. It carries the claim judges are most likely to
   doubt, and it is the hardest to fake convincingly.
2. **Scenes 12 + 13** — the matched refused/allowed pair. They must share a visual grammar exactly;
   build them together or the contrast is lost.
3. **Scene 14** — the incident record. Needs a real `incident.v1` payload to be worth anything.
4. **Scene 1** — the sourced two-phase chain. Authored, no system dependency, so it can be built any
   time; re-check the sourcing before capture.
5. **Scenes 6, 7, 10, 11** — contract-derived frames. All buildable today from files that already
   exist in the repo.
6. Everything else.

## Blocked on the system

Scenes **12, 13, 14, 15, 16, 17** want captures from a running system that does not exist yet
(gateway, Hermes detector, coordinator, containment executor, responder wiring, attack driver).
Ship them as authored `ILLUSTRATIVE` frames first — the engine takes the upgrade to a real capture
as a pure file swap, no code change — and replace them as each component lands.
