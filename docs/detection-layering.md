# Why source rotation is detected in two places

The monitor track flagged that `window.v1` carries `src_ips_distinct` and
`ua_distinct` as **counts**, not values, so stage-7 source rotation looks
undetectable across windows. Checked — the observation is right, the concern is
not. This is a deliberate layering decision, recorded so nobody "fixes" it.

## What each layer sees

| Layer | Input | Rotation visibility |
|---|---|---|
| **Monitor** (Hermes/GLM-5.2) | `window.v1` frames | `session_ids` is an array of **values**, `src_ips_distinct` is a **count**. One session id with a distinct-source count > 1 is rotation — detectable, intra-window. |
| **Incident graph** (Jac) | raw audit events | Full value-level correlation. Reported stage signatures **1–10** including the `pivot` family, joining the anon recon session to the compromised principal via `client_fp` — not by IP. |

## Why the frame does not carry raw values

`window.v1` is the **prompt-injection boundary**. Free-text and
attacker-controlled values are reduced to `sha256[:12]` + length + a
character-class histogram before anything reaches the model. Putting raw source
IPs and user-agent strings into the frame would hand an attacker a channel
straight into model input — the exact failure the injection acceptance test
exists to prevent.

The monitor's differential test proves the boundary holds: stripping all
payloads and saturating all 250 events with them produce identical frames.
Widening the frame to carry values would break that property for a capability
the graph layer already provides.

## Conclusion

No contract change. Stage 7 is covered — by the layer that can see raw events
safely, using `client_fp` rather than IP, which is the more robust join anyway
since an attacker controls their source address and not their client
fingerprint.
