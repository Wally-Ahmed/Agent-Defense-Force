"""Gateway-side audit emission into the shared sink.

Same file, same schema, same encoding as the application's guard() emissions:
one JSON object per line, exactly the 38 AuditEvent fields in contract order,
`json.dumps(row, ensure_ascii=True, separators=(",",":"), sort_keys=False)` — the
encoding used by contracts/fixtures/generate_golden.py:892-894.

WHAT THE GATEWAY EMITS (contracts/vocab.md emission map) — and nothing else:
  * auth.login_failed
  * any RATE_LIMITED denial
  * any CSRF_INVALID denial
These three are rejected before walker dispatch, so no guard() call ever happens
for them and the gateway is the only component positioned to record them.
Emitting anything guard() also emits would double-count and corrupt the very
rate and result_count signals T4 reads.
"""

import os;
import json;
import time;
import uuid;
import threading;
import from typing { Any }

# The 38 AuditEvent fields, in the frozen order from
# contracts/audit_event_contract.jac. Order is part of the contract.
glob:pub SCHEMA_KEYS: list = [
    "event_id", "schema_version", "ts", "ts_ms", "kind", "action", "outcome",
    "reason", "severity",
    "actor_principal_id", "actor_email", "actor_role", "auth_method",
    "session_id", "token_id",
    "tenant_id", "actor_tenant_id",
    "target_kind", "target_id", "parent_id", "target_sensitivity",
    "src_ip", "src_asn", "user_agent_hash", "client_fp", "request_id",
    "http_method", "route", "status_code", "latency_ms", "req_bytes",
    "resp_bytes", "result_count",
    "service", "integration_id",
    "trace_id", "prev_event_id", "seq"
];

glob:pub SCHEMA_VERSION: str = "1.0.0";

# The only three events the gateway is permitted to write.
glob:pub GATEWAY_ACTIONS: list = ["auth.login_failed"];
glob:pub GATEWAY_REASONS: list = ["RATE_LIMITED", "CSRF_INVALID"];

glob AUDIT_LOCK: Any = threading.Lock();

"""ISO-8601 UTC with microseconds and a trailing Z, matching the golden fixture."""
def iso_utc(ts_ms: int) -> str {
    secs = ts_ms / 1000.0;
    base = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(secs));
    micros = int(round((secs - int(secs)) * 1000000.0));
    if micros > 999999 {
        micros = 999999;
    }
    return f"{base}.{micros:06d}Z";
}

"""A blank event with every one of the 38 fields present at its contract default."""
def blank_event -> dict {
    row: dict = {};
    for k in SCHEMA_KEYS {
        if k in ["ts_ms", "status_code", "latency_ms", "req_bytes", "resp_bytes", "result_count", "seq"] {
            row[k] = 0;
        } else {
            row[k] = "";
        }
    }
    row["schema_version"] = SCHEMA_VERSION;
    return row;
}

"""Severity per contracts/vocab.md section 4, evaluated top-down, first match wins.

The gateway only ever reaches the `warn` and `notice` tiers: it emits no
containment action, touches no canary, and returns no result_count."""
def severity_for(action: str, outcome: str, reason: str, repeated: bool) -> str {
    if outcome == "deny" {
        if reason in ["CTX_UNVERIFIED", "TENANT_MISMATCH", "SOURCE_BLOCKED", "SUSPENDED"] {
            return "high";
        }
        return "warn";
    }
    if outcome == "error" {
        return "warn";
    }
    if action == "auth.login_failed" {
        if repeated {
            return "warn";
        }
        return "warn";
    }
    if action.startswith("auth.") {
        return "notice";
    }
    return "info";
}

"""Append-only audit sink with a per-session seq / prev_event_id chain.

The chain rule (contracts/vocab.md): `seq` is monotonic per session starting at 1,
`prev_event_id` chains to the previous event in that same session, and both are
maintained across gateway and guard() emissions alike so the chain has no holes.

guard() runs in a different process against the same file, so chain state is
recovered by scanning the tail of the sink the first time a session is seen and
cached thereafter. Writes are single `O_APPEND` line writes, which the kernel
keeps atomic below PIPE_BUF, so interleaved gateway and application writes cannot
tear a line."""
obj AuditSink {
    has path: str = "var/audit/audit.jsonl";
    has tail_scan_lines: int = 4000;
    has _chain: dict = {};

    """Create the sink directory if it does not exist yet."""
    def ensure -> None {
        parent = os.path.dirname(os.path.abspath(self.path));
        if parent and not os.path.isdir(parent) {
            os.makedirs(parent, exist_ok=True);
        }
    }

    """Recover (seq, event_id) for `session_id` from the tail of the sink.

    Returns [0, ""] when the session has no prior event."""
    def _recover(session_id: str) -> list {
        if not os.path.isfile(self.path) {
            return [0, ""];
        }
        lines: list = [];
        try {
            with open(self.path, "r", encoding="utf-8") as fh {
                lines = fh.readlines()[-self.tail_scan_lines:];
            }
        } except Exception {
            return [0, ""];
        }
        best_seq = 0;
        best_id = "";
        for raw in lines {
            s = raw.strip();
            if not s {
                continue;
            }
            try {
                row = json.loads(s);
            } except Exception {
                continue;
            }
            if row.get("session_id") != session_id {
                continue;
            }
            seq = row.get("seq", 0);
            if isinstance(seq, int) and seq >= best_seq {
                best_seq = seq;
                best_id = row.get("event_id", "");
            }
        }
        return [best_seq, best_id];
    }

    """Next (seq, prev_event_id) for a session, advancing the cached chain."""
    def _advance(session_id: str, event_id: str) -> list {
        state = self._chain.get(session_id);
        if state is None {
            state = self._recover(session_id);
        }
        nxt = state[0] + 1;
        prev = state[1];
        self._chain[session_id] = [nxt, event_id];
        return [nxt, prev];
    }

    """Write one fully-populated event. Returns the row that was written.

    `fields` supplies overrides; every one of the 38 keys is always present."""
    def emit(fields: dict) -> dict {
        row = blank_event();
        ts_ms = int(fields.get("ts_ms", 0));
        if ts_ms <= 0 {
            ts_ms = int(time.time() * 1000);
        }
        event_id = str(fields.get("event_id", "")) or str(uuid.uuid4());

        for k in fields.keys() {
            if k in SCHEMA_KEYS {
                row[k] = fields[k];
            }
        }

        row["event_id"] = event_id;
        row["schema_version"] = SCHEMA_VERSION;
        row["ts_ms"] = ts_ms;
        row["ts"] = iso_utc(ts_ms);
        if not row["kind"] {
            row["kind"] = "security";
        }

        sid = str(row["session_id"]);
        if not sid {
            # The fixture keeps session_id non-empty for pre-auth traffic so that
            # seq and prev_event_id stay well defined.
            sid = f"sess_anon_{event_id[:12]}";
            row["session_id"] = sid;
        }

        with AUDIT_LOCK {
            chain = self._advance(sid, event_id);
            row["seq"] = chain[0];
            row["prev_event_id"] = chain[1];

            ordered: dict = {};
            for k in SCHEMA_KEYS {
                ordered[k] = row[k];
            }
            line = json.dumps(ordered, ensure_ascii=True, separators=(",", ":"), sort_keys=False);
            self.ensure();
            with open(self.path, "a", encoding="utf-8", newline="\n") as fh {
                fh.write(line + "\n");
            }
        }
        return row;
    }
}

"""Populate the transport-fact half of an event from the observed request facts.

`obs` is the gateway's observed-facts dict — never a claimed value from a body."""
def with_transport(fields: dict, obs: dict) -> dict {
    out: dict = {};
    for k in fields.keys() {
        out[k] = fields[k];
    }
    out["src_ip"] = obs.get("src_ip", "");
    out["src_asn"] = obs.get("src_asn", "");
    out["user_agent_hash"] = obs.get("user_agent_hash", "");
    out["client_fp"] = obs.get("client_fp", "");
    out["request_id"] = obs.get("request_id", "");
    out["http_method"] = obs.get("http_method", "");
    out["route"] = obs.get("route", "");
    out["service"] = obs.get("service", "web");
    out["trace_id"] = obs.get("trace_id", "");
    out["req_bytes"] = obs.get("req_bytes", 0);
    return out;
}
