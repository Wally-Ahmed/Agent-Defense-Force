# coordinator/fsm.jac
#
# THE DETERMINISTIC STATE MACHINE. Cotal has no task lifecycle — this table is
# ours. It drives ONE incident through
#
#   WATCHING -> ESCALATED -> ASSESSING -> (DELIBERATING) -> DECIDING
#            -> CONTAINING -> VERIFYING -> CONTAINED     (contain path)
#   ... or -> DECIDING -> WATCHING                       (no-contain path)
#   ... or -> DEGRADED                                   (sub-quorum path)
#   ... or -> VERIFYING -> ROLLED_BACK                   (verify-fail path)
#
# and rests at the terminal decision state so a caller can observe it.
#
# Every timeout is evaluated against the injected virtual Clock — never a wall
# clock, never sleep, never random. Identical inputs produce a byte-identical
# decision.v1 and a byte-stable run summary, which is the whole security
# argument: a containment decision you cannot reproduce is one you cannot audit.
#
# THREE HARD RULES this file honours and never bypasses:
#   1. The ONLY way to contain is quorum.decide() returning contain==true. There
#      is no flag, env var or "test mode" that forces contain, skips the effort
#      gate, or skips the quorum.
#   2. The quorum rule and the action-set derivation are NOT reimplemented here —
#      quorum.jac is called.
#   3. A run that touches a mock is MOCKED end to end and can never be reported
#      as live.

import from typing { Any }
import from ids {
    S_WATCHING, S_ESCALATED, S_ASSESSING, S_DELIBERATING, S_DECIDING,
    S_CONTAINING, S_VERIFYING, S_CONTAINED, S_ROLLED_BACK, S_DEGRADED,
    TIMEOUTS_MS, RESPONDER_IDS, QUORUM_FLOOR, CONTAIN_MAX_REDELIVER,
    DEFAULT_TTL_S, DELIBERATION_ROUNDS_MAX, RUN_MOCKED
}
import from events { EventLog }
import from presence { PresenceStore, PresenceCard, seeded_store }
import from config { MeshConfig, build_mesh }
import from quorum { QuorumInput, decide, tally, is_split, monitor_only_posture }
import from schema_check { validate_payload }
import from effort_gate { enforce_gate }

# How far past the ASSESSING window the coordinator sweeps once more for a
# durably-held / very-late assessment. Anything that surfaces here is recorded
# with late:true and NEVER reopens the decided incident.
glob:pub LATE_SWEEP_MS: int = 180000;
# Virtual time budget spent collecting the one bounded deliberation round.
glob:pub DELIB_COLLECT_MS: int = 1000;


"""One incident as the coordinator sees it. `payload` is an incident.v1-ish dict;
the only field the mesh actually reads is incident_id."""
obj Incident {
    has incident_id: str = "";
    has payload: dict = {};
}


obj CoordinatorFSM {
    # ---- injected collaborators / config ---------------------------------
    has receipts_path: str = "";
    has mesh: dict = {};              # responder_id -> ResponderHandle
    has presence: Any = None;         # PresenceStore, seeded at ESCALATED
    has executor: Any = None;         # MockContainment (or a live executor)
    has clock: Any = None;            # Clock (virtual)
    has log: Any = None;              # EventLog
    has fallback_target: dict = {};   # default entry for the degraded posture

    # ---- run state -------------------------------------------------------
    has state: str = "WATCHING";
    has run_label: str = "LIVE";
    has incident_id: str = "";
    has decision: dict = {};          # the emitted decision.v1
    has posture: list = [];           # DEGRADED monitor-only posture
    has late_arrivals: list = [];     # assessments that arrived after the vote closed

    # ---- bookkeeping -----------------------------------------------------
    has assessments: list = [];       # counted assessments (<=1 per responder)
    has voted_ids: list = [];         # responder ids whose assessment was counted
    has no_vote: list = [];           # responder ids that did not vote
    has decided_at_ms: int = 0;
    has gate_ok: bool = False;
    has gate_reason: str = "";
    has applied_actions: list = [];   # actions the executor ACKed
    has aborted_actions: list = [];   # actions aborted after redeliver
    has min_ttl_s: int = 0;

    # ---------------------------------------------------------------------
    # Presence (layer 1 of the dead-responder defence)
    # ---------------------------------------------------------------------

    """Overwrite the presence store with each responder's ACTUAL card as of
    `now_ms`. A dead or dark responder reports offline/stale here, which is what
    lets ASSESSING resolve it to NO_VOTE immediately instead of at the 180s
    timeout."""
    def _refresh_presence(now_ms: int) -> None {
        for rid in RESPONDER_IDS {
            card = self.mesh[rid].presence(now_ms);
            self.presence.put(PresenceCard(
                agent=rid,
                status=card["status"],
                heartbeat_ms=card["heartbeat_ms"],
                seq=card["seq"]
            ));
        }
    }

    """Escalate the incident to ALL responders on the durable channel — a dead
    responder still accepts (durable backstop). 'respawn missing, proceed.'"""
    def _escalate(incident: Incident, now_ms: int) -> None {
        for rid in RESPONDER_IDS {
            self.mesh[rid].escalate(incident.payload, now_ms);
        }
        self.log.emit(
            action="state.transition",
            incident_id=incident.incident_id,
            ts_ms=now_ms,
            detail={"phase": "escalated", "escalated_to": sorted(RESPONDER_IDS)},
            state_from="",
            state_to=""
        );
    }

    """Poll every not-yet-counted responder at `now_ms`, recording any ready
    assessment. A dead responder yields nothing; at-most-once is the mock's job."""
    def _poll_into(collected: dict, now_ms: int) -> None {
        for rid in RESPONDER_IDS {
            if rid in collected {
                continue;
            }
            got = self.mesh[rid].poll(now_ms);
            if len(got) > 0 {
                collected[rid] = got[len(got) - 1];
            }
        }
    }

    """True when every LIVE responder has already voted — i.e. nothing worth
    waiting for. Dead responders never force a wait; that is the short-circuit."""
    def _all_live_voted(collected: dict, now_ms: int) -> bool {
        for rid in RESPONDER_IDS {
            if self.presence.is_live(rid, now_ms) and (rid not in collected) {
                return False;
            }
        }
        return True;
    }

    # ---------------------------------------------------------------------
    # ASSESSING
    # ---------------------------------------------------------------------

    """Collect assessments across the ASSESSING window.

    Dead responders resolve to NO_VOTE at t0 via presence. If every live
    responder has already answered at t0 the vote closes AT t0 (this is what
    makes a 2-dead incident decide near the live responders' ready time, not
    180s later). Otherwise the clock advances once to the 180s deadline and
    polls a final time; any live responder still silent then is a NO_VOTE."""
    def _assess(incident: Incident) -> None {
        t0 = self.clock.now_ms();
        deadline = t0 + TIMEOUTS_MS[S_ASSESSING];

        self.log.transition(incident.incident_id, t0, S_ESCALATED, S_ASSESSING);
        self.state = S_ASSESSING;

        self._refresh_presence(t0);
        collected: dict = {};
        self._poll_into(collected, t0);
        now = t0;

        if not self._all_live_voted(collected, t0) {
            now = deadline;
            self.clock.set_ms(now);
            self._refresh_presence(now);
            self._poll_into(collected, now);
        }

        self.decided_at_ms = now;
        self.voted_ids = sorted(collected.keys());
        self.assessments = [collected[r] for r in self.voted_ids];
        self.no_vote = sorted([r for r in RESPONDER_IDS if r not in collected]);
    }

    # ---------------------------------------------------------------------
    # DELIBERATING (one bounded round on a split)
    # ---------------------------------------------------------------------

    """Open the single deliberation round on the responders that voted, collect
    their revised assessments, and replace each responder's assessment with its
    revision. Exactly one round — no re-splitting."""
    def _deliberate(incident: Incident) -> None {
        now = self.clock.now_ms();
        self.log.transition(
            incident.incident_id, now, S_ASSESSING, S_DELIBERATING,
            detail={"round": DELIBERATION_ROUNDS_MAX}
        );
        self.state = S_DELIBERATING;

        for rid in self.voted_ids {
            self.mesh[rid].open_deliberation(
                incident.incident_id, DELIBERATION_ROUNDS_MAX, now
            );
        }

        self.clock.advance(DELIB_COLLECT_MS);
        now2 = self.clock.now_ms();

        revised: dict = {};
        for rid in self.voted_ids {
            got = self.mesh[rid].poll(now2);
            if len(got) > 0 {
                revised[rid] = got[len(got) - 1];
            }
        }

        new_assessments: list = [];
        for a in self.assessments {
            rid = a.get("responder", "");
            if rid in revised {
                new_assessments.append(revised[rid]);
            } else {
                new_assessments.append(a);
            }
        }
        self.assessments = new_assessments;
        self.decided_at_ms = now2;
    }

    # ---------------------------------------------------------------------
    # DECIDING
    # ---------------------------------------------------------------------

    """Call quorum.decide, validate + publish the decision.v1 on sec.verdict,
    then branch: contain==true -> CONTAINING, contain==false -> WATCHING."""
    def _decide(incident: Incident, from_state: str) -> None {
        now = self.decided_at_ms;
        inp = QuorumInput(
            incident_id=incident.incident_id,
            assessments=self.assessments,
            no_vote=self.no_vote,
            decided_at_ms=now,
            force_degraded=self.log.is_mocked()
        );
        decision = decide(inp);
        validate_payload("decision.v1", decision);
        self.decision = decision;

        self.log.transition(
            incident.incident_id, now, from_state, S_DECIDING,
            detail={"channel": "sec.verdict", "decision": decision}
        );
        self.state = S_DECIDING;

        # Any assessment that surfaces now arrived AFTER the vote closed.
        self._collect_late(incident);

        if decision["contain"] {
            self._contain(incident, decision["action_set"]);
        } else {
            self.log.transition(
                incident.incident_id, self.clock.now_ms(), S_DECIDING, S_WATCHING,
                detail={"resolved": "no_contain"}
            );
            self.state = S_WATCHING;
        }
    }

    # ---------------------------------------------------------------------
    # CONTAINING -> VERIFYING -> CONTAINED / ROLLED_BACK
    # ---------------------------------------------------------------------

    """Dispatch the action_set to the executor, verify it, and hold or roll back.

    NAK -> ONE redeliver -> still NAK -> abort THAT action, keep the others.
    Any health-probe failure rolls back the failed actions and lands in
    ROLLED_BACK; all-pass lands in CONTAINED holding at the minimum applied ttl."""
    def _contain(incident: Incident, action_set: list) -> None {
        now = self.clock.now_ms();
        self.log.transition(
            incident.incident_id, now, S_DECIDING, S_CONTAINING,
            action="containment.propose",
            detail={"count": len(action_set), "action_set": action_set}
        );
        self.state = S_CONTAINING;

        applied: list = [];
        aborted: list = [];
        for action in action_set {
            res = self.executor.apply(action, now);
            redeliver = 0;
            while (res["status"] == "nak") and (redeliver < CONTAIN_MAX_REDELIVER) {
                redeliver = redeliver + 1;
                res = self.executor.apply(action, now);
            }
            if res["status"] == "ack" {
                applied.append(action);
                self.log.emit(
                    action="containment.apply",
                    incident_id=incident.incident_id, ts_ms=now,
                    detail={"action": action, "redelivered": redeliver},
                    state_from="", state_to=""
                );
            } else {
                aborted.append(action);
                self.log.emit(
                    action="containment.apply",
                    incident_id=incident.incident_id, ts_ms=now,
                    detail={"action": action, "status": "aborted", "redelivered": redeliver},
                    state_from="", state_to=""
                );
            }
        }
        self.applied_actions = applied;
        self.aborted_actions = aborted;

        now = self.clock.now_ms();
        self.log.transition(
            incident.incident_id, now, S_CONTAINING, S_VERIFYING,
            detail={"probes": len(applied)}
        );
        self.state = S_VERIFYING;

        failed: list = [];
        for action in applied {
            probe = self.executor.health_probe(action, now);
            self.log.emit(
                action="containment.verify",
                incident_id=incident.incident_id, ts_ms=now,
                detail={"action": action, "health": probe["health"]},
                state_from="", state_to=""
            );
            if probe["health"] == "fail" {
                failed.append(action);
            }
        }

        if len(failed) > 0 {
            for action in failed {
                self.executor.rollback(action, now);
            }
            self.log.transition(
                incident.incident_id, now, S_VERIFYING, S_ROLLED_BACK,
                action="containment.rollback",
                detail={"count": len(failed), "rolled_back": failed}
            );
            self.state = S_ROLLED_BACK;
        } else {
            min_ttl = DEFAULT_TTL_S;
            if len(applied) > 0 {
                ttls = [int(a.get("ttl_s", DEFAULT_TTL_S)) for a in applied];
                min_ttl = min(ttls);
            }
            self.min_ttl_s = min_ttl;
            self.log.transition(
                incident.incident_id, now, S_VERIFYING, S_CONTAINED,
                detail={"holding": len(applied), "min_ttl_s": min_ttl}
            );
            self.state = S_CONTAINED;
        }
    }

    """Auto-expire the containment at the minimum applied ttl. Emits the frozen
    containment.expire audit action and lands in ROLLED_BACK. NOT auto-driven by
    run_incident — CONTAINED is a holding state, exactly like DEGRADED — but
    provided so the next lifecycle tick has the transition it needs."""
    def tick_expire(incident: Incident) -> None {
        if self.state != S_CONTAINED {
            return;
        }
        self.clock.advance(self.min_ttl_s * 1000);
        now = self.clock.now_ms();
        for action in self.applied_actions {
            self.executor.rollback(action, now);
        }
        self.log.transition(
            incident.incident_id, now, S_CONTAINED, S_ROLLED_BACK,
            action="containment.expire",
            detail={"expired_after_s": self.min_ttl_s}
        );
        self.state = S_ROLLED_BACK;
    }

    # ---------------------------------------------------------------------
    # DEGRADED (sub-quorum) — monitor-only, ZERO revocation
    # ---------------------------------------------------------------------

    """Quorum was missed. Emit a valid (contain==false) decision.v1 for the
    audit trail, then apply the MONITOR_ONLY posture from quorum.jac —
    raise_logging only, zero revocation. Nothing is ever dispatched to the
    executor on this path."""
    def _degrade(incident: Incident, from_state: str) -> None {
        now = self.decided_at_ms;
        inp = QuorumInput(
            incident_id=incident.incident_id,
            assessments=self.assessments,
            no_vote=self.no_vote,
            decided_at_ms=now,
            force_degraded=True
        );
        decision = decide(inp);
        validate_payload("decision.v1", decision);
        self.decision = decision;

        self.posture = monitor_only_posture(self.assessments, self.fallback_target);

        self.log.transition(
            incident.incident_id, now, from_state, S_DEGRADED,
            detail={"reason": "sub_quorum", "posture": self.posture, "decision": decision}
        );
        self.state = S_DEGRADED;

        self._collect_late(incident);
    }

    # ---------------------------------------------------------------------
    # Late arrivals (layer 2/3 of the dead-responder defence)
    # ---------------------------------------------------------------------

    """Advance past the window and sweep once for durably-held / very-late
    assessments. Each is recorded with late:true and NEVER reopens the decision."""
    def _collect_late(incident: Incident) -> None {
        self.clock.advance(LATE_SWEEP_MS);
        now = self.clock.now_ms();
        for rid in RESPONDER_IDS {
            got = self.mesh[rid].poll(now);
            for a in got {
                entry = dict(a);
                entry["late"] = True;
                self.late_arrivals.append(entry);
            }
        }
    }

    # ---------------------------------------------------------------------
    # Run summary — JSON-stable
    # ---------------------------------------------------------------------

    """A byte-stable summary of the run. Lists are sorted so
    json.dumps(summary, sort_keys=True) is deterministic."""
    def summary -> dict {
        ex_applied: list = [];
        if self.executor is not None {
            ex_applied = sorted([a.get("action", "") for a in self.executor.applied]);
        }
        return {
            "incident_id": self.incident_id,
            "final_state": self.state,
            "run_label": self.run_label,
            "mocked": self.log.is_mocked(),
            "gate_ok": self.gate_ok,
            "gate_reason": self.gate_reason,
            "contain": self.decision.get("contain", False),
            "quorum_met": self.decision.get("quorum_met", False),
            "degraded": self.decision.get("degraded", False),
            "responders_voted": self.decision.get("responders_voted", 0),
            "responders_no_vote": sorted(self.no_vote),
            "decided_at_ms": self.decided_at_ms,
            "action_set_kinds": sorted([a["action"] for a in self.decision.get("action_set", [])]),
            "posture_kinds": sorted([a["action"] for a in self.posture]),
            "late_arrivals": len(self.late_arrivals),
            "applied_kinds": ex_applied,
            "state_trace": self.log.state_trace(),
            "events": len(self.log.events)
        };
    }
}


"""Assemble a coordinator around a mesh config, an executor and a virtual clock.

A mock mesh forces the whole run to MOCKED at construction — a mocked run can
never be reported as live, no matter what the effort receipts say."""
def build_fsm(receipts_path: str, cfg: MeshConfig, executor: Any, clock: Any,
              fallback_target: dict) -> CoordinatorFSM {
    now = clock.now_ms();
    mesh = build_mesh(cfg, now);
    log = EventLog(run_label=cfg.effective_run_label());
    fsm = CoordinatorFSM(
        receipts_path=receipts_path,
        mesh=mesh,
        presence=PresenceStore(),
        executor=executor,
        clock=clock,
        log=log,
        state=S_WATCHING,
        run_label=cfg.effective_run_label(),
        fallback_target=dict(fallback_target)
    );
    if cfg.is_mocked() {
        log.mark_mocked();
        fsm.run_label = RUN_MOCKED;
    }
    return fsm;
}


"""Drive one incident through the full lifecycle. Returns the run summary.

WATCHING is left ONLY when the effort gate passes; a gate failure aborts the run
in WATCHING with the reason recorded and NOTHING escalated. Past the gate the
machine seeds presence, escalates durably, collects assessments (dead responders
resolve immediately via presence), and then — strictly by quorum.decide's
verdict — either degrades (sub-quorum), deliberates once (split), contains
(contain==true), or resolves back to WATCHING (contain==false)."""
def run_incident(fsm: CoordinatorFSM, incident: Incident) -> dict {
    fsm.incident_id = incident.incident_id;

    # ---- WATCHING: the boot gate. No bypass. ----
    now = fsm.clock.now_ms();
    gate = enforce_gate(fsm.receipts_path, fsm.log, incident.incident_id, now);
    fsm.run_label = fsm.log.run_label;
    fsm.gate_ok = gate.ok;
    fsm.gate_reason = gate.reason;
    if not gate.ok {
        fsm.state = S_WATCHING;
        return fsm.summary();
    }

    # ---- ESCALATED: seed presence, escalate to ALL (durable) ----
    fsm.state = S_ESCALATED;
    now = fsm.clock.now_ms();
    fsm.presence = seeded_store(RESPONDER_IDS, now);
    fsm._escalate(incident, now);

    # ---- ASSESSING (+ DELIBERATING / DECIDING / DEGRADED) ----
    fsm._assess(incident);
    counts = tally(fsm.assessments);
    voted = len(fsm.assessments);

    if voted < QUORUM_FLOOR {
        fsm._degrade(incident, S_ASSESSING);
    } elif is_split(counts, voted) {
        fsm._deliberate(incident);
        voted2 = len(fsm.assessments);
        if voted2 < QUORUM_FLOOR {
            fsm._degrade(incident, S_DELIBERATING);
        } else {
            fsm._decide(incident, S_DELIBERATING);
        }
    } else {
        fsm._decide(incident, S_ASSESSING);
    }

    return fsm.summary();
}
