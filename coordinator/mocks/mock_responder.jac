# coordinator/mocks/mock_responder.jac
#
# The mock side of the responder seam.
#
# A MockResponder replays a RECORDED assessment (mocks/transcripts/*.json) on an
# injectable virtual clock. It exists so the coordinator's failure modes —
# latency, a dead responder, a responder that dies and reconnects, a split that
# forces one bounded deliberation round — are exercised deterministically and in
# zero wall-clock time.
#
# Determinism is the contract: no `random`, no wall clock, no I/O beyond reading
# the transcript file once. Identical config + identical virtual clock produces
# byte-identical assessment JSON, every run.
#
# It is a MockResponder only from the outside of this file. The coordinator sees
# a `ResponderHandle` and cannot tell.

import json;
import os;
import from typing { Any }
import from ids { RESPONDER_IDS, DELIBERATION_ROUNDS_MAX }
import from responder { ResponderHandle, register_responder_kind }

glob:pub HERE: str = os.path.dirname(os.path.abspath(__file__));
glob:pub TRANSCRIPT_DIR: str = os.path.join(HERE, "transcripts");

"""Deep copy via the JSON round trip.

Used everywhere a payload leaves this object so a caller mutating an assessment
can never reach back into the transcript and change the next run's output."""
def _clone(value: Any) -> Any {
    return json.loads(json.dumps(value));
}

# --------------------------------------------------------------------------
# Transcript loading
# --------------------------------------------------------------------------

"""Absolute path of `responder_id`'s recorded transcript."""
def transcript_path(responder_id: str) -> str {
    return os.path.join(TRANSCRIPT_DIR, f"{responder_id}.json");
}

"""Load and sanity-check `responder_id`'s recorded transcript.

Checks only the envelope invariants this module depends on. Schema validity of
the assessment blocks themselves is asserted by the test suite against the
frozen contracts/mesh/assessment.v1.schema.json — this loader does not carry a
second copy of the schema."""
def load_transcript(responder_id: str) -> dict {
    path = transcript_path(responder_id);
    if not os.path.exists(path) {
        raise FileNotFoundError(f"no transcript for {responder_id}: {path}");
    }
    with open(path, "r") as fh {
        data = json.load(fh);
    }
    if "assessment" not in data {
        raise ValueError(f"transcript for {responder_id} has no assessment block");
    }
    recorded = data["assessment"].get("responder", "");
    if recorded != responder_id {
        raise ValueError(
            f"transcript responder mismatch: file says {recorded}, expected {responder_id}"
        );
    }
    return data;
}

"""Every canonical responder's transcript, keyed by responder id."""
def load_all_transcripts -> dict {
    out: dict = {};
    for rid in RESPONDER_IDS {
        out[rid] = load_transcript(rid);
    }
    return out;
}

# --------------------------------------------------------------------------
# The mock
# --------------------------------------------------------------------------

"""A recorded responder on a virtual clock.

Failure knobs, all deterministic:
  latency_ms            how long after escalate() the assessment becomes ready
  dead                  never answers; presence goes offline
  verdict_override      force a verdict ("" = use the transcript's)
  confidence_override   force a confidence (<0 = use the transcript's)
  actions_override      replace recommended_actions (non-empty = replace)
  heartbeat_stops_at_ms after this instant the card freezes and goes stale,
                        while still claiming `working` — this reproduces the
                        upstream "dead agents go dark" bug that presence
                        liveness exists to defeat (-1 = never stops)"""
obj MockResponder(ResponderHandle) {
    has transcript: dict = {};        # loaded recorded transcript
    has latency_ms: int = 0;          # how long after escalate() its assessment becomes ready
    has dead: bool = False;           # never answers, presence goes stale/offline
    has verdict_override: str = "";   # force a verdict, "" = use transcript
    has confidence_override: float = -1.0;   # <0 = use transcript
    has actions_override: list = [];  # non-empty = replace transcript actions
    has heartbeat_stops_at_ms: int = -1;  # after this, presence stops updating (goes stale)

    # ---- internal bookkeeping (not configuration) -------------------------
    has inbox: list = [];             # [{"ready_at_ms": int, "payload": dict}], FIFO
    has escalated_at_ms: int = -1;    # when the incident was accepted
    has incident_id: str = "";        # id of the accepted incident, copied verbatim
    has died_at_ms: int = -1;         # when kill() was called
    has deliberation_round: int = 0;  # rounds opened so far
    has seq: int = 0;                 # presence sequence
    has last_heartbeat_ms: int = -1;  # last instant a heartbeat was actually emitted

    # ---- assessment construction -----------------------------------------

    """Build this responder's assessment for `incident_id`, applying overrides.

    `incident_id` is copied VERBATIM from the escalated incident; the recorded
    id in the transcript is only a placeholder. Every other field comes from the
    recording, so the emitted object stays a schema-valid assessment.v1."""
    def render(block: str, incident_id: str) -> dict {
        source = self.transcript.get("assessment", {});
        if block == "revised" {
            delib = self.transcript.get("deliberation", {});
            source = delib.get("revised", source);
        }
        payload = _clone(source);
        payload["incident_id"] = incident_id;
        payload["responder"] = self.responder_id;
        if self.verdict_override != "" {
            payload["verdict"] = self.verdict_override;
        }
        if self.confidence_override >= 0.0 {
            payload["confidence"] = self.confidence_override;
        }
        if len(self.actions_override) > 0 {
            payload["recommended_actions"] = _clone(self.actions_override);
        }
        return payload;
    }

    """Does this transcript carry a revised assessment for the split round?"""
    def has_deliberation -> bool {
        delib = self.transcript.get("deliberation", {});
        return "revised" in delib;
    }

    # ---- transport surface ------------------------------------------------

    """Presence card as of `now_ms`.

    Fresh (heartbeat == now_ms, status `working`) while alive. Once dead the
    card is `offline` and frozen at the instant of death. Past
    `heartbeat_stops_at_ms` the card freezes but keeps claiming `working` — the
    dark-agent case. Either way PresenceStore.is_live goes False."""
    def presence(now_ms: int) -> dict {
        status = "working";
        heartbeat_ms = now_ms;
        if self.dead {
            status = "offline";
            heartbeat_ms = self.died_at_ms if self.died_at_ms >= 0 else now_ms;
        } elif self.heartbeat_stops_at_ms >= 0 and now_ms > self.heartbeat_stops_at_ms {
            # Still reports `working`. It just stopped saying it.
            heartbeat_ms = self.heartbeat_stops_at_ms;
        }
        if heartbeat_ms != self.last_heartbeat_ms {
            self.seq += 1;
            self.last_heartbeat_ms = heartbeat_ms;
        }
        return {
            "agent": self.responder_id,
            "status": status,
            "heartbeat_ms": heartbeat_ms,
            "seq": self.seq
        };
    }

    """Accept `incident`.

    A DEAD responder still accepts — that is the durable-channel backstop. It
    simply never becomes ready while dead; revive() re-arms the delivery."""
    def escalate(incident: dict, now_ms: int) -> None {
        iid = incident.get("incident_id", "");
        if iid == "" {
            raise ValueError("incident has no incident_id");
        }
        self.incident_id = iid;
        self.escalated_at_ms = now_ms;
        self._enqueue(self.render("assessment", iid), now_ms);
    }

    """Assessments ready at or before `now_ms`, each returned AT MOST ONCE.

    A dead responder yields nothing, however long it has been holding the
    incident."""
    def poll(now_ms: int) -> list {
        if self.dead {
            return [];
        }
        out: list = [];
        keep: list = [];
        for item in self.inbox {
            ready = item["ready_at_ms"];
            if ready >= 0 and now_ms >= ready {
                out.append(item["payload"]);
            } else {
                keep.append(item);
            }
        }
        self.inbox = keep;
        return out;
    }

    """Open the one bounded deliberation round and queue the revised assessment.

    No-op when the transcript records no revision, when the round budget is
    exhausted, or when this responder never received the incident."""
    def open_deliberation(incident_id: str, round_no: int, now_ms: int) -> None {
        if round_no > DELIBERATION_ROUNDS_MAX {
            raise ValueError(
                f"deliberation round {round_no} exceeds max {DELIBERATION_ROUNDS_MAX}"
            );
        }
        if self.deliberation_round >= DELIBERATION_ROUNDS_MAX {
            return;
        }
        if not self.has_deliberation() {
            return;
        }
        if self.escalated_at_ms < 0 {
            return;
        }
        self.deliberation_round += 1;
        self._enqueue(self.render("revised", incident_id), now_ms);
    }

    """Force death at `now_ms`. Anything armed but undelivered is held, not
    dropped — a dead responder loses time, not messages."""
    def kill(now_ms: int) -> None {
        self.dead = True;
        self.died_at_ms = now_ms;
        for item in self.inbox {
            item["ready_at_ms"] = -1;
        }
    }

    """Reconnect at `now_ms`.

    Everything the responder was holding when it died is re-armed, so an
    incident escalated to a dead responder is still answered after it comes
    back. This is the durable-channel backstop."""
    def revive(now_ms: int) -> None {
        self.dead = False;
        self.died_at_ms = -1;
        self.heartbeat_stops_at_ms = -1;
        for item in self.inbox {
            if item["ready_at_ms"] < 0 {
                item["ready_at_ms"] = now_ms + self.latency_ms;
            }
        }
    }

    def is_alive -> bool {
        return not self.dead;
    }

    """Queue `payload`, ready `latency_ms` after `now_ms`. Held (never ready)
    while this responder is dead."""
    def _enqueue(payload: dict, now_ms: int) -> None {
        ready = -1;
        if not self.dead {
            ready = now_ms + self.latency_ms;
        }
        self.inbox.append({"ready_at_ms": ready, "payload": payload});
    }
}

# --------------------------------------------------------------------------
# Construction
# --------------------------------------------------------------------------

"""Build a mock for `responder_id` from its recorded transcript.

`opts` carries only failure knobs — never a credential, never an endpoint:
  latency_ms, dead, verdict_override, confidence_override, actions_override,
  heartbeat_stops_at_ms."""
def mock_from_transcript(responder_id: str, opts: dict) -> MockResponder {
    mock = MockResponder(
        responder_id=responder_id,
        kind="mock",
        transcript=load_transcript(responder_id),
        latency_ms=int(opts.get("latency_ms", 0)),
        dead=bool(opts.get("dead", False)),
        verdict_override=str(opts.get("verdict_override", "")),
        confidence_override=float(opts.get("confidence_override", -1.0)),
        actions_override=list(opts.get("actions_override", [])),
        heartbeat_stops_at_ms=int(opts.get("heartbeat_stops_at_ms", -1))
    );
    if mock.dead {
        mock.died_at_ms = int(opts.get("died_at_ms", opts.get("now_ms", 0)));
    }
    return mock;
}

"""Registry factory. Returns the handle typed as the abstract ResponderHandle —
config cannot hand the coordinator anything narrower."""
def mock_factory(responder_id: str, opts: dict) -> ResponderHandle {
    return mock_from_transcript(responder_id, opts);
}

with entry {
    register_responder_kind("mock", mock_factory);
}
