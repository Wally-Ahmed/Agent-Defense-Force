"""Rate limiting, login throttling, and the containment Control surface.

Two things live here because they are the same decision: how much traffic this
source is allowed right now. The baseline comes from the frozen budgets in
contracts/app_api.openapi.yaml; containment narrows it at runtime by writing
`Control` nodes (contracts/containment_contract.jac), which this module reads so
that a throttle imposed by the responder actually takes effect at the front door
rather than only inside guard().

SCOPE NOTE — which controls the gateway enforces:
  * `throttle_source`  -> tightens the (src_ip, route_class) bucket. Tripping it
                          denies RATE_LIMITED, which contracts/vocab.md assigns to
                          the gateway. Enforced here.
  * every other kind   -> left to guard(). The emission map gives the gateway
                          exactly three events; denying SOURCE_BLOCKED or
                          SUSPENDED here would reject before any guard() call and
                          leave that denial unrecorded by anyone. Those controls
                          are enforced one layer in, where the event is emitted.
"""

import os;
import json;
import math;
import time;
import from threading { Lock }
import from typing { Any }
import from datetime { datetime, timezone }
import from config {
    RATE_BUDGETS, LOGIN_FAIL_THRESHOLD, LOGIN_BACKOFF_BASE_S,
    LOGIN_BACKOFF_MAX_S, LOGIN_FAIL_WINDOW_S
}

glob POLICY_LOCK: Lock = Lock();

"""Parse an ISO-8601 timestamp to epoch millis. Returns 0 when unparseable."""
def iso_to_ms(value: str) -> int {
    if not value {
        return 0;
    }
    txt = str(value).strip();
    if txt.endswith("Z") {
        txt = txt[:-1] + "+00:00";
    }
    try {
        dt = datetime.fromisoformat(txt);
    } except Exception {
        return 0;
    }
    if dt.tzinfo is None {
        dt = dt.replace(tzinfo=timezone.utc);
    }
    return int(dt.timestamp() * 1000);
}

# ---------------------------------------------------------------------------
# Containment controls
# ---------------------------------------------------------------------------

"""The active `Control` set, as the gateway sees it.

BACKEND / SWAP POINT. `Control` is a Jac graph node written by track T5. The
gateway is a separate process and cannot walk that graph directly, so it reads a
JSON projection of the same node set:

    {"controls": [{"control_id": "...", "kind": "throttle_source",
                   "scope_key": "203.0.113.9", "params": {"rate_per_min": 6},
                   "expires_at": "2026-03-17T14:30:00Z", "active": true}]}

To swap in the live graph once T5 lands, replace `_load()` with a call to the
containment engine's list-controls walker and keep the returned shape identical —
one dict per Control node with exactly the node's six fields. Nothing else in this
module changes."""
obj ControlSource {
    has path: str = "var/controls/controls.json";
    has ttl_ms: int = 2000;
    has _cache: list = [];
    has _loaded_ms: int = 0;
    has _mtime: float = -1.0;

    """Read the projection from disk, tolerating absence and malformed content.

    A missing or unreadable control file means "no containment is active", never
    "fail open on rate limiting" — the baseline budgets always still apply."""
    def _load -> list {
        if not os.path.isfile(self.path) {
            return [];
        }
        try {
            with open(self.path, "r", encoding="utf-8") as fh {
                blob = json.load(fh);
            }
        } except Exception {
            return [];
        }
        rows = blob;
        if isinstance(blob, dict) {
            rows = blob.get("controls", []);
        }
        if not isinstance(rows, list) {
            return [];
        }
        return rows;
    }

    """Active, unexpired controls. Cached for `ttl_ms` and invalidated on mtime."""
    def active(now_ms: int) -> list {
        mtime = -1.0;
        try {
            mtime = os.path.getmtime(self.path);
        } except Exception {
            mtime = -1.0;
        }
        stale = (now_ms - self._loaded_ms) > self.ttl_ms;
        if stale or mtime != self._mtime {
            self._cache = self._load();
            self._loaded_ms = now_ms;
            self._mtime = mtime;
        }
        out: list = [];
        for c in self._cache {
            if not isinstance(c, dict) {
                continue;
            }
            if not c.get("active", False) {
                continue;
            }
            exp = iso_to_ms(str(c.get("expires_at", "")));
            if exp and exp <= now_ms {
                continue;
            }
            out.append(c);
        }
        return out;
    }

    """Tightest containment-imposed requests-per-minute for a source IP.

    Returns 0 when no `throttle_source` control covers this source. `scope_key`
    matches either the exact IP or a `prefix:` form such as `prefix:203.0.113.`."""
    def throttle_rpm(src_ip: str, now_ms: int) -> int {
        best = 0;
        for c in self.active(now_ms) {
            if c.get("kind") != "throttle_source" {
                continue;
            }
            scope = str(c.get("scope_key", ""));
            hit = False;
            if scope == src_ip {
                hit = True;
            } elif scope == ("ip:" + src_ip) {
                # app/security/controls.jac key_ip() writes the `ip:<addr>` form.
                # Matching it here means a throttle_source control is never
                # silently inert just because two modules spell the key
                # differently. Both dialects are accepted deliberately.
                hit = True;
            } elif scope.startswith("prefix:") and src_ip.startswith(scope[7:]) {
                hit = True;
            } elif scope in ["*", "all"] {
                hit = True;
            }
            if not hit {
                continue;
            }
            params = c.get("params", {});
            rpm = 0;
            if isinstance(params, dict) {
                try {
                    rpm = int(params.get("rate_per_min", 0));
                } except Exception {
                    rpm = 0;
                }
            }
            if rpm <= 0 {
                rpm = 1;
            }
            if best == 0 or rpm < best {
                best = rpm;
            }
        }
        return best;
    }
}

# ---------------------------------------------------------------------------
# Token buckets
# ---------------------------------------------------------------------------

"""One token bucket. `capacity` tokens, refilling at `rate` tokens per second."""
obj Bucket {
    has tokens: float = 0.0;
    has capacity: float = 0.0;
    has rate: float = 0.0;
    has updated_ms: int = 0;
}

"""The outcome of a limit check."""
obj LimitResult {
    has allowed: bool = True;
    has limit: int = 0;
    has remaining: int = 0;
    has retry_after_s: int = 0;
    has reset_epoch_s: int = 0;
    has scope: str = "";
}

"""Token-bucket limiter keyed (src_ip, route_class) and (identity, route_class),
plus the (email, src_ip) login throttle.

Containment narrows the source bucket: a `throttle_source` control replaces the
route-class budget with the control's own rate whenever the control's rate is
tighter. That is the mechanism by which a responder-imposed throttle takes effect
at the front door."""
obj RateLimiter {
    has controls: ControlSource = ControlSource();
    has _buckets: dict = {};
    has _login_fails: dict = {};

    """Consume one token from `key`'s bucket, creating it at full capacity."""
    def _consume(key: str, limit: int, window_s: int, now_ms: int, scope: str) -> LimitResult {
        if limit <= 0 or window_s <= 0 {
            return LimitResult(allowed=True, limit=0, remaining=0, scope=scope);
        }
        rate = float(limit) / float(window_s);
        b = self._buckets.get(key);
        if b is None {
            b = Bucket(tokens=float(limit), capacity=float(limit), rate=rate, updated_ms=now_ms);
            self._buckets[key] = b;
        }
        # A tightened budget shrinks an existing bucket immediately rather than
        # waiting for it to drain at the old rate.
        if b.capacity != float(limit) or b.rate != rate {
            b.capacity = float(limit);
            b.rate = rate;
            if b.tokens > b.capacity {
                b.tokens = b.capacity;
            }
        }
        elapsed = float(now_ms - b.updated_ms) / 1000.0;
        if elapsed > 0.0 {
            b.tokens = min(b.capacity, b.tokens + (elapsed * b.rate));
            b.updated_ms = now_ms;
        }
        reset_s = int((now_ms / 1000) + math.ceil((b.capacity - b.tokens) / b.rate));
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            return LimitResult(
                allowed=True, limit=limit, remaining=int(b.tokens),
                retry_after_s=0, reset_epoch_s=reset_s, scope=scope
            );
        }
        wait_s = int(math.ceil((1.0 - b.tokens) / b.rate));
        if wait_s < 1 {
            wait_s = 1;
        }
        return LimitResult(
            allowed=False, limit=limit, remaining=0,
            retry_after_s=wait_s, reset_epoch_s=int((now_ms / 1000) + wait_s), scope=scope
        );
    }

    """Check both the source bucket and the identity bucket for one request.

    The tighter of the two decides. `identity` is "" for anonymous callers, in
    which case only the source bucket applies."""
    def check(src_ip: str, route_class: str, identity: str, now_ms: int) -> LimitResult {
        budget = RATE_BUDGETS.get(route_class);
        if budget is None {
            budget = RATE_BUDGETS.get("write");
        }
        with POLICY_LOCK {
            ip_limit = int(budget["ip_limit"]);
            ip_window = int(budget["ip_window_s"]);

            # Containment override: a throttle_source control tightens the source
            # bucket for every route class.
            rpm = self.controls.throttle_rpm(src_ip, now_ms);
            scope = "ip";
            if rpm > 0 {
                candidate = rpm;
                candidate_window = 60;
                if (float(candidate) / float(candidate_window)) < (float(ip_limit) / float(ip_window)) {
                    ip_limit = candidate;
                    ip_window = candidate_window;
                    scope = "ip:contained";
                }
            }

            ip_res = self._consume(f"ip|{src_ip}|{route_class}", ip_limit, ip_window, now_ms, scope);
            if not ip_res.allowed {
                return ip_res;
            }

            id_limit = int(budget["id_limit"]);
            id_window = int(budget["id_window_s"]);
            if identity and id_limit > 0 {
                id_res = self._consume(f"id|{identity}|{route_class}", id_limit, id_window, now_ms, "identity");
                if not id_res.allowed {
                    return id_res;
                }
                if id_res.remaining < ip_res.remaining {
                    return id_res;
                }
            }
            return ip_res;
        }
    }

    # -----------------------------------------------------------------------
    # Login throttle keyed (email, src_ip), exponential backoff after 5 failures.
    # -----------------------------------------------------------------------

    """Seconds the caller must wait before another login attempt, or 0.

    delay = base * 2^(failures - threshold), capped at LOGIN_BACKOFF_MAX_S. The
    key is (email_hash, src_ip) so throttling one account from one source cannot
    lock that account out from everywhere — and never reveals whether the account
    exists, because the counter advances identically for unknown addresses."""
    def login_backoff(email_hash: str, src_ip: str, now_ms: int) -> int {
        key = f"login|{email_hash}|{src_ip}";
        with POLICY_LOCK {
            st = self._login_fails.get(key);
            if st is None {
                return 0;
            }
            if (now_ms - st["last_ms"]) > (LOGIN_FAIL_WINDOW_S * 1000) {
                del self._login_fails[key];
                return 0;
            }
            fails = int(st["fails"]);
            if fails < LOGIN_FAIL_THRESHOLD {
                return 0;
            }
            power = fails - LOGIN_FAIL_THRESHOLD;
            if power > 20 {
                power = 20;
            }
            delay = LOGIN_BACKOFF_BASE_S * (2 ** power);
            if delay > LOGIN_BACKOFF_MAX_S {
                delay = LOGIN_BACKOFF_MAX_S;
            }
            ready_ms = st["last_ms"] + (delay * 1000);
            if now_ms >= ready_ms {
                return 0;
            }
            return int(math.ceil((ready_ms - now_ms) / 1000.0));
        }
    }

    """Record a failed login. Returns the resulting consecutive-failure count."""
    def login_failed(email_hash: str, src_ip: str, now_ms: int) -> int {
        key = f"login|{email_hash}|{src_ip}";
        with POLICY_LOCK {
            st = self._login_fails.get(key);
            if st is None or (now_ms - st["last_ms"]) > (LOGIN_FAIL_WINDOW_S * 1000) {
                st = {"fails": 0, "last_ms": now_ms};
            }
            st["fails"] = int(st["fails"]) + 1;
            st["last_ms"] = now_ms;
            self._login_fails[key] = st;
            return int(st["fails"]);
        }
    }

    """Clear the throttle for a key after a successful login."""
    def login_ok(email_hash: str, src_ip: str) -> None {
        key = f"login|{email_hash}|{src_ip}";
        with POLICY_LOCK {
            if key in self._login_fails {
                del self._login_fails[key];
            }
        }
    }
}
