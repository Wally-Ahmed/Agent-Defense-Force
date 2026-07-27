# Narrated walkthrough — build, run, and the audio swap

Phase 5 work, pulled early to de-risk it. This directory is the **frame**: a working scene engine,
a full narration script, and a shot list. **Narration audio is in** — all seventeen scenes are
voiced. The demo system it presents is still being built, so the page ships with no captured
visuals, and says so on its face.

```
walkthrough/
  index.html      the page + the tour engine (TOUR array, playScene, sceneVis, transport)
  script.md       the per-scene narration script + sourcing + the dur table (source of truth)
  visuals.md      the shot list: what 1800×600 frame each scene needs
  README.md       this file
  img/            scene visuals go here (empty today)
  scene<n>.mp3    narration — all 17 present, 706 s total (≈11 m 46 s)
  scene<n>.txt    the exact text each clip was voiced from, cut from script.md
  stt/scene<n>.json  the STT round-trip, word-level timestamps — the beat source
```

## Run it

`file://` is blocked by the engine's own media loading — **serve it over HTTP**, path-bound:

```bash
python3 -m http.server 8912 --directory /Users/wally/Documents/GitHub/JacHacksSF-2026/walkthrough
# → http://localhost:8912/index.html
```

Always pass `--directory`. A cwd-inherited server wedges when the served directory changes under it,
and has previously served a 404 that looked like a JavaScript bug. One port per agent.

Click **▶ Narrated walkthrough**. The tour requests fullscreen, walks 17 scenes, and returns the
page when you stop or pause.

| Control | Effect |
|---|---|
| ▶ / ■ button | start / stop the tour |
| Right-hand rail | one segment per scene — click to jump; ❚❚ pauses |
| Hardware ⏯ / ⏭ / ⏮ | pause, resume, next scene, previous scene (Media Session API) |
| `ESC` | leaves fullscreen **without** stopping playback |

Pausing hands the page back: the media strip hides, the choreography dim lifts, the caption goes,
fullscreen exits, and **every clock freezes** — the scene timer, the caption fade, the pending
choreography beats and the scene-advance countdown all resume with the time they had left.

---

## The audio swap — what "no re-authoring" means

All seventeen `scene<n>.mp3` now exist, so `ended` drives every scene and `dur` is a fallback only.
The swap needed **no engine change** — `playScene()` already handled both cases, and a clip that
goes missing still degrades to the silent path:

```js
function playScene(n, durationMs){
  ...
  tourAudio = new Audio("scene"+n+".mp3");
  tourAudio.addEventListener("ended", done);                                  // AUDIO PATH
  tourAudio.addEventListener("error", ()=>{ if(!settled) armFallback(done, ms); });  // SILENT PATH
  tourAudio.play().catch(()=>{ if(!settled) armFallback(done, ms); });               // SILENT PATH
}
```

- **With no mp3:** the `error` event fires, and the scene's declared `dur` (from the `TOUR` array)
  drives the silent timing.
- **With an mp3 present:** `ended` fires first and **audio drives timing**, exactly as the skill
  requires. `dur` is simply never consulted for that scene.

So dropping the files in is enough. `dur` is declared per scene, **keyed by scene id**, so re-timing
is a data edit in one place — no engine changes, no re-authoring, and scenes can be converted one at
a time (a half-recorded tour runs fine: voiced scenes use audio, silent scenes use `dur`).

### Procedure

**1 · Record.** The repo's `.env.example` already declares the two keys this needs —
`ELEVENLABS_API_KEY` and `ELEVENLABS_VOICE_ID`. Copy it to a **gitignored `.env`** at the repo root
and fill them in. Never commit it; no credential belongs in this directory.

```bash
set -a; source .env; set +a
VOICE="$ELEVENLABS_VOICE_ID"     # pick ONE voice up front — changing it later
N=1                              # means re-recording EVERY scene
curl -s -X POST "https://api.elevenlabs.io/v1/text-to-speech/${VOICE}?output_format=mp3_44100_128" \
  -H "xi-api-key: $ELEVENLABS_API_KEY" -H "Content-Type: application/json" \
  -d "$(jq -n --arg t "$(cat scene${N}.txt)" '{text:$t, model_id:"eleven_multilingual_v2"}')" \
  -o walkthrough/scene${N}.mp3
```

Keep the per-scene text in durable `scene<n>.txt` files cut from `script.md` so re-records and
truth-passes diff cleanly. **Numbers stay written as spoken words** ("eight hundred and seventeen",
not "817") — TTS butchers digits.

**2 · Verify with STT and actually read the transcript.** Mispronunciations and dropped clauses are
inaudible to you until a human hears them.

```bash
curl -s -X POST "https://api.elevenlabs.io/v1/speech-to-text" \
  -H "xi-api-key: $ELEVENLABS_API_KEY" \
  -F model_id=scribe_v1 -F file=@walkthrough/scene${N}.mp3 | jq -r .text
```

Compare line by line against `script.md`. Re-record anything that drifted.

**Done for all 17** (transcripts in `stt/`). No clip truncated or dropped a clause. Scene 11 was
re-recorded once ("each **shifts** with" → "each ships with"). The residual diffs are all STT
*spelling*, not TTS error, and are expected — do not chase them into a re-record:
spoken numbers written back as digits ("sixteenth twenty twenty-six" → "16th 2026" — the
numbers-as-words rule working), homophones (`Jac`→"jack", `principal`→"principle"), and
out-of-vocabulary proper nouns (`Cotal`→"Katal"/"CODEL", sentence-final `Jac.`→"Jackal").
That last one was checked acoustically, not assumed: the token is 380 ms, inside the 221–400 ms
range of the `Jac`→"jack" tokens that transcribed correctly, so it is one syllable, not two.

**3 · Update `dur` to the measured duration.**

```bash
ffprobe -v error -show_entries format=duration -of csv=p=0 walkthrough/scene${N}.mp3
```

Round up ~300 ms and set that scene's `dur` in `TOUR`. Strictly this is optional — with audio
present, `ended` wins — but keeping `dur` honest means the tour still runs correctly at the right
pace if an mp3 ever fails to load, and it keeps the runtime estimate in `script.md` true. Update the
duration table in `script.md` in the same edit.

**Done:** every `dur` in `TOUR` is now measured, not estimated. The recorded tour is 706.3 s
(≈11 m 46 s) against the 765.2 s estimate — the real voice runs a little faster than 2.55 words/s.

**4 · Re-derive the choreography beats. This is not optional.** Every `choreo()` beat in `index.html`
is currently a fraction of `dur`, guessed with no audio to time against. **Beats are wrong until
proven against the audio.**

```bash
curl -s -X POST "https://api.elevenlabs.io/v1/speech-to-text" \
  -H "xi-api-key: $ELEVENLABS_API_KEY" \
  -F model_id=scribe_v1 -F timestamps_granularity=word \
  -F file=@walkthrough/scene${N}.mp3 > stt/scene${N}.json
```

A beat's `t` is the **start time of the word that names the unit being lit**. Then verify by
lit-state sampling: start the scene headlessly, wait to each spoken timestamp, read which units
carry `.steplit`, and check it matches what the voice is saying at that moment. Also confirm the
**actual DOM order** of each choreo root before trusting an index-addressed beat — DOM order is not
narrative order, and assuming it lights the wrong box.

**5 · Re-time any scene video.** A scene's mp4 must match its mp3 duration within ±0.1 s. Re-time
from the **original** source, never from an already re-timed copy (generational quality loss).

**When a narrated fact changes, re-record the clip.** A page whose text contradicts its own
voiceover reads as a bug. Tense matters: `script.md` flags the two lines most likely to go stale
(scene 10's undefined weights, scene 15's four-to-one split).

---

## The visuals swap

Identical shape. Drop files in and the engine picks them up:

```
walkthrough/img/scene<n>.mp4    animated clip — wins when present
walkthrough/img/scene<n>.png    still fallback — gets automatic Ken Burns
```

Until either exists the strip shows a labelled placeholder card carrying that scene's `shot` string,
so the frame is never a blank black box and every viewer can see exactly which shot is outstanding.
Full specs, capture sources and production order: `visuals.md`.

---

## Editing the tour

- **Scene IDs (`n`) are stable.** They tie `TOUR[i].n` → `scene<n>.mp3` → `img/scene<n>.{mp4,png}`.
  Play order is array order. **Never renumber on insert** — add a new ID at the play position the
  story needs, or audio and visuals silently mismatch.
- **Every `run()` sets its own tab**, so `jumpTo(i)` lands correctly from anywhere.
- **Captions are orientation titles, not subtitles.** They auto-fade a few seconds in, on purpose —
  a caption that lingers occludes the content being narrated.
- `vis:null` on a scene hides the strip when the page itself is the visual. Drop the strip rather
  than repeat an earlier scene's visual.
- **New page content ships with a new voiced scene.** If a section gains a claim, the scene
  narrating it says it too.
- After changing any section's height, re-check the scroll landings of scenes focusing content
  **below** the edit — they all shift.
- Verify layout at **1920×1080, 1600×900 and 1366×768**. A 16:10 dev machine hides ~180 px of
  missing height.

## Accuracy constraints — do not regress these

1. **Scene 1 is sourced, and it corrects the brief.** Initial access at Hugging Face was
   code-execution vulnerabilities, **not** stolen credentials; credentials were harvested afterwards
   for lateral movement. And it was OpenAI's own models under internal benchmark testing, **not** a
   third-party attacker. The `TODO(verify)` block in `index.html` at `#origin-claim` lists the open
   items — including that OpenAI's own post 403s to automated fetch and the story is days old.
   **Re-fetch both primary URLs before presenting.**
2. **The skills library is community-maintained**, not an official Anthropic release, despite the
   repository name.
3. **Cotal is third-party open source. We did not author it.** Our own contributions upstream are
   deliberately out of scope for this story — do not add them.
4. **Northwind Projects is not deliberately vulnerable.** Never imply otherwise.
5. **Do not invent the quorum weights.** They are genuinely undefined; scene 10 says so on purpose.
6. **No credentials, tokens or `.env` values anywhere** in this directory.

## Optional: record the tour as an MP4

A deliberate, explicitly requested step — never auto-re-record because content changed. It only
makes sense once narration exists. The full working pipeline (Playwright supersampled capture with
`--force-device-scale-factor=3` on the **browser args**, instant-scroll patching, an instrumented
`playScene` timing log, and a per-scene `adelay` + `amix` mux) is in the walkthrough-builder skill's
`references/recording.md`. Two traps worth repeating: run a ~20 s probe and check a frame fills the
canvas before a long take, and stub `requestFullscreen` in the recorder or headless Chromium
resizes the render surface to 800×600 and pads the capture.
