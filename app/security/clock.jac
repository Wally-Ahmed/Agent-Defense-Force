# app/security/clock.jac — one clock, so expiry is never format-dependent.
#
# App-owned nodes store time as INT epoch milliseconds; the frozen contracts
# store ISO-8601 strings. Every conversion between the two happens here, so a
# timezone-naive parse cannot creep into an expiry comparison and quietly turn
# an expired credential into a live one.
#
# FRAMEWORK NOTE: Jac's type checker resolves `datetime.now(...)` /
# `datetime.fromtimestamp(...)` to `Self` and then rejects every instance method
# on the result (error[E1030]/[E1031]). Both directions are therefore built on
# `time` + `calendar`, which type-check cleanly and are UTC-explicit anyway.

import time;
import calendar;

"""Current UTC time in epoch milliseconds."""
def:pub now_ms() -> int {
    return int(time.time() * 1000);
}

"""Epoch milliseconds as ISO-8601 UTC with microseconds and a trailing Z.

Matches the format the AuditEvent contract specifies for `ts`."""
def:pub iso_ts(ms: int) -> str {
    secs = ms // 1000;
    micros = (ms % 1000) * 1000;
    base = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(secs));
    return base + "." + str(micros).zfill(6) + "Z";
}

"""Parse an ISO-8601 UTC timestamp to epoch milliseconds.

Returns `on_error` for an empty or unparseable value. Callers must decide
explicitly what that means: control expiry passes -1 so a malformed timestamp
reads as long-expired, because a corrupt control must never become a permanent
lockout that nobody can find or roll back."""
def:pub iso_to_ms(value: str, on_error: int = 0) -> int {
    if value == "" {
        return on_error;
    }
    try {
        text: str = value.strip();
        if text.endswith("Z") {
            text = text[:-1];
        } elif text.endswith("+00:00") {
            text = text[:-6];
        }
        frac_ms = 0;
        if "." in text {
            parts = text.split(".");
            text = parts[0];
            digits: str = "".join([ch for ch in parts[1] if ch.isdigit()]);
            if digits != "" {
                frac_ms = int(round(float("0." + digits) * 1000));
            }
        }
        parsed = time.strptime(text, "%Y-%m-%dT%H:%M:%S");
        return calendar.timegm(parsed) * 1000 + frac_ms;
    } except Exception as e {
        return on_error;
    }
}

# --------------------------------------------------------------------------
# Credential lifetimes. Short, and not configurable by request.
# --------------------------------------------------------------------------

glob:pub SESSION_TTL_MS: int = 3600000;        # 1 hour
glob:pub API_TOKEN_TTL_MS: int = 900000;       # 15 minutes -- short-lived and revocable
glob:pub REFRESH_TOKEN_TTL_MS: int = 86400000; # 24 hours
glob:pub INVITE_TTL_MS: int = 172800000;       # 48 hours
glob:pub REAUTH_MAX_AGE_MS: int = 900000;      # a step-up is satisfied for 15 minutes
