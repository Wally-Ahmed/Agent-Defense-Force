# PINNED.md — cybersecurity-skills vendor pin

## What this is

`vendor/cybersecurity-skills/` vendors a **community-maintained** skills
library. Despite the upstream repository's name, **this is not an official
Anthropic release** — it is maintained by an independent author and
licensed Apache-2.0.

| | |
|---|---|
| Upstream | https://github.com/mukul975/Anthropic-Cybersecurity-Skills |
| Author | mahipal (GitHub: mukul975) |
| License | Apache-2.0 — full text at `vendor/cybersecurity-skills/LICENSE` |
| Pinned commit SHA | `673da1f3b0b7be34ffc9624ef3858fe45f1c3bed` |
| Skill count | 817 |
| Framework coverage | MITRE ATT&CK, NIST CSF 2.0, MITRE ATLAS, D3FEND, NIST AI RMF, MITRE F3 |

`vendor/` is gitignored — the payload (49MB, 817 skills) is never committed.
This file is the committed record of the pin, so the exact tree can be
reconstructed from nothing but the SHA above.

## Reconstructing the vendor tree

```bash
mkdir -p vendor
git init vendor/cybersecurity-skills
cd vendor/cybersecurity-skills
git remote add origin https://github.com/mukul975/Anthropic-Cybersecurity-Skills.git
git fetch --depth 1 origin 673da1f3b0b7be34ffc9624ef3858fe45f1c3bed
git checkout FETCH_HEAD
cd -
```

Shallow clone (depth 1, no branch history), fetch of the exact pinned SHA,
then checkout — this is the sequence actually used to produce the current
`vendor/cybersecurity-skills/`. Verified: `git -C vendor/cybersecurity-skills
rev-parse HEAD` returns `673da1f3b0b7be34ffc9624ef3858fe45f1c3bed`.

## After re-vendoring

`skills/index.json` is derived from the vendor tree and must be rebuilt any
time `vendor/` is reconstructed or updated:

```bash
python3 skills/build_index.py
```

## Citing this

Community-built, third-party, pinned for reproducibility — not published,
reviewed, or endorsed by Anthropic. Any writeup, README, or slide that
references this library must say so.
