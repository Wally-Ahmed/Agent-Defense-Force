# mesh/bridge/mesh_responder.jac
#
# The LIVE side of the responder seam — the Jac layer that lets the existing
# deterministic coordinator consume REAL assessments produced by real models.
#
# WHY THIS FILE EXISTS AND WHY IT IS NOT IN coordinator/
#
#   coordinator/responder.jac ships a `LiveResponder` that is an HONEST STUB:
#   every transport method raises NotImplementedError. That was correct while no
#   transport existed. It is not a place to bolt a file-and-subprocess runner
#   onto, because the coordinator is FORBIDDEN from naming a concrete
#   implementation.
#
#   The sanctioned extension seam is already public:
#
#       register_responder_kind(kind, factory)     # responder.jac:151-155
#
#   So this module registers a NEW kind, "cotal", from OUTSIDE the coordinator
#   tree. Zero coordinator edits. `is_known_kind("cotal")` becomes true the
#   moment this module is imported, and `config.MeshConfig.validate()` then
#   accepts `kind="cotal"` on any ResponderConfig. Going live is a config edit.
#
# WHAT THE TRANSPORT ACTUALLY IS
#
#   contracts/mesh/channels.yaml says an assessment comes back to the
#   coordinator as a UNICAST DM, at-least-once, never on a channel. On disk that
#   DM is one file:
#
#       runs/<run_id>/assessments/<agent_id>.json     (assessment.v1, FROZEN)
#
#   written by mesh/agent_runner once its harness has produced an answer. This
#   object is the coordinator's end of that wire: it watches for the file,
#   validates it against the frozen schema, and hands it up EXACTLY ONCE.
#
# CREDENTIALS: this module NEVER holds, reads, echoes, stores or forwards a
# credential. It launches a harness process that authenticates itself out of the
# operator's own already-established session; the secret never enters this
# process's memory and never enters an artifact. A credential literal in this
# file would be a bug, and so would reading one out of the environment here.

import os;
import sys;
import json;
import hashlib;
import subprocess;
import from typing { Any }

# --------------------------------------------------------------------------
# Path bootstrap
#
# Jac resolves `import from <name>` against sys.path, which starts at the
# INVOCATION directory — not this file's directory (docs/running-tests.md).
# coordinator/effort_gate.jac has the same problem and solves it the same way:
# derive every path from __file__ so nothing depends on where jac was invoked.
#
# The `with entry` below runs at module load, in source order, BEFORE the
# coordinator imports underneath it — verified, not assumed.
# --------------------------------------------------------------------------

glob:pub HERE: str = os.path.dirname(os.path.abspath(__file__));
glob:pub REPO_ROOT: str = os.path.dirname(os.path.dirname(HERE));
glob:pub COORD_DIR: str = os.path.join(REPO_ROOT, "coordinator");
glob:pub RUNS_DIR: str = os.path.join(REPO_ROOT, "runs");
glob:pub SCHEMA_PATH: str = os.path.join(
    REPO_ROOT, "contracts", "mesh", "assessment.v1.schema.json"
);
glob:pub RUNNER_JS: str = os.path.join(
    REPO_ROOT, "mesh", "agent_runner", "bin", "agent-runner.js"
);

with entry {
    if COORD_DIR not in sys.path {
        sys.path.insert(0, COORD_DIR);
    }
}

import from jsonschema { Draft202012Validator }
import from ids { RESPONDER_IDS, DELIBERATION_ROUNDS_MAX, PRESENCE_STATUSES }
import from responder { ResponderHandle, register_responder_kind }

# --------------------------------------------------------------------------
# The frozen contract, READ not copied
# --------------------------------------------------------------------------
# Same discipline as coordinator/effort_gate.jac: the schema is loaded from
# contracts/ at runtime. If the contract moves or changes, this breaks loudly
# rather than validating against a stale private duplicate.

glob VALIDATOR_CACHE: dict = {};

"""The frozen assessment.v1 validator, built once per process."""
def assessment_validator -> Any {
    if "v" not in VALIDATOR_CACHE {
        with open(SCHEMA_PATH, "r") as fh {
            schema = json.load(fh);
        }
        Draft202012Validator.check_schema(schema);
        VALIDATOR_CACHE["v"] = Draft202012Validator(schema);
    }
    return VALIDATOR_CACHE["v"];
}

"""Sorted schema-violation messages for `payload`. Empty list means valid."""
def assessment_errors(payload: Any) -> list {
    out: list = [];
    for e in assessment_validator().iter_errors(payload) {
        out.append(str(e.message));
    }
    return sorted(out);
}

# --------------------------------------------------------------------------
# Rejection reason codes — machine-readable, stable, and the ONLY values a
# rejection ever takes. A rejected assessment is a LOST VOTE, so every one of
# them is recorded on the handle and surfaced by describe(). Nothing here is
# ever silently discarded.
# --------------------------------------------------------------------------

glob:pub R_UNREADABLE: str = "unreadable_file";
glob:pub R_INVALID_JSON: str = "invalid_json";
glob:pub R_SCHEMA_INVALID: str = "schema_invalid";
glob:pub R_RESPONDER_MISMATCH: str = "responder_mismatch";
glob:pub R_INCIDENT_MISMATCH: str = "incident_mismatch";
glob:pub R_NOT_ESCALATED: str = "not_escalated";
glob:pub R_UNSOLICITED_DUPLICATE: str = "unsolicited_duplicate";
glob:pub R_RUNNER_MISSING: str = "agent_runner_missing";

glob:pub REJECTION_REASONS: list = [
    "unreadable_file",
    "invalid_json",
    "schema_invalid",
    "responder_mismatch",
    "incident_mismatch",
    "not_escalated",
    "unsolicited_duplicate",
    "agent_runner_missing"
];

"""Content digest of the bytes on the wire.

At-most-once delivery is keyed on the CONTENT, not on a flag: an assessment the
runner rewrites byte-identically is the same DM redelivered (at-least-once on
the wire) and must never be counted twice. A genuinely different payload — the
revised assessment from the one bounded deliberation round — is a different DM
and is delivered once on its own account."""
def _digest(raw: str) -> str {
    return hashlib.sha256(raw.encode("utf-8")).hexdigest();
}

# --------------------------------------------------------------------------
# The live responder
# --------------------------------------------------------------------------

"""One real responder, backed by real artifacts on disk.

Its inbox is runs/<run_id>/assessments/<responder_id>.json — the assessment.v1
file mesh/agent_runner writes when that agent's harness has answered. Everything
this object reports is DERIVED from observable state (does the file exist, is
the process still alive, did it validate); nothing is asserted on faith.

`opts`, from ResponderConfig.opts, and never a secret:
    run_id            str   the run whose artifacts to read
    assessments_dir   str   optional absolute override of the inbox directory
    poll_timeout_ms   int   after this long with no answer a NON-SPAWNED
                            responder is honestly reported offline (0 = never)
    spawn             bool  launch the harness process on escalate()
    mocked            bool  pass --mock to the runner (a mocked live run)
    incident_path     str   incident.v1 file to hand the runner; written from
                            the escalated incident when not supplied
    runner_path       str   optional absolute override of the runner entry
                            point, so the missing-runner guard is testable
                            without depending on whether it happens to be built"""
obj MeshResponder(ResponderHandle) {
    # ---- configuration ----------------------------------------------------
    has run_id: str = "";
    has assessments_dir: str = "";
    has incident_path: str = "";
    has runner_path: str = "";
    has spawn: bool = False;
    has mocked: bool = False;
    has poll_timeout_ms: int = 0;

    # ---- bookkeeping (not configuration) ----------------------------------
    has incident_id: str = "";         # id of the accepted incident, verbatim
    has escalated_at_ms: int = -1;     # when the incident was accepted
    has answered: bool = False;        # a VALID assessment was handed up
    has seen_digests: list = [];       # content digests already dispositioned
    has rejected: list = [];           # every assessment refused, with a reason
    has deliberation_round: int = 0;   # bounded rounds opened so far
    has dead: bool = False;            # kill() was called
    has died_at_ms: int = -1;
    has offline_at_ms: int = -1;       # instant death was OBSERVED (card freezes here)
    has proc: Any = None;              # subprocess.Popen for the harness, or None
    has launch_error: str = "";        # why the harness was not launched, if it wasn't
    has seq: int = 0;                  # presence sequence
    has last_heartbeat_ms: int = -1;

    # ---- where the artifacts live -----------------------------------------

    """Absolute path of this run's assessment inbox directory."""
    def inbox_dir -> str {
        if self.assessments_dir != "" {
            return self.assessments_dir;
        }
        return os.path.join(RUNS_DIR, self.run_id, "assessments");
    }

    """Absolute path of THIS responder's unicast DM file."""
    def assessment_path -> str {
        return os.path.join(self.inbox_dir(), f"{self.responder_id}.json");
    }

    """Where this bridge writes ITS OWN artifacts: the incident file handed to
    the runner, and the runner's log.

    Always a sibling of the inbox, so a caller that redirected the inbox (a test
    pointing at a temp directory) cannot end up scattering artifacts into the
    real runs/ tree."""
    def bridge_dir -> str {
        if self.assessments_dir != "" {
            return os.path.join(
                os.path.dirname(os.path.abspath(self.assessments_dir)), "bridge"
            );
        }
        return os.path.join(RUNS_DIR, self.run_id, "bridge");
    }

    """Absolute path of this responder's harness log.

    The runner's stdout/stderr goes here rather than to /dev/null: a harness
    that dies on startup must leave evidence, not a silent absence."""
    def log_path -> str {
        return os.path.join(self.bridge_dir(), f"{self.responder_id}.log");
    }

    """The runner entry point this responder would launch."""
    def runner -> str {
        return self.runner_path if self.runner_path != "" else RUNNER_JS;
    }

    # ---- transport surface ------------------------------------------------

    """Presence card as of `now_ms`, shaped exactly like PresenceCard.as_dict().

    Status is DERIVED, never assumed:
      offline  kill() was called, OR the harness process exited without writing
               an assessment, OR spawn was asked for and the launch failed, OR a
               non-spawned responder blew its poll_timeout_ms budget;
      idle     an assessment has landed — this responder is done, and honestly
               says so instead of claiming `working` forever;
      working  the harness is genuinely still running and has not answered yet.

    The `working`-forever case is exactly the upstream "dead agents go dark" bug
    that presence liveness exists to defeat, so it is the one thing this method
    must never do. A process that has exited without answering reports offline
    and the coordinator resolves that slot to NO_VOTE immediately."""
    def presence(now_ms: int) -> dict {
        status = self.status_at(now_ms);
        if status not in PRESENCE_STATUSES {
            # A status outside the frozen set is a programming error here, not a
            # liveness signal — raise rather than write an unreadable card.
            raise ValueError(f"unknown presence status: {status}");
        }
        heartbeat_ms = now_ms;
        if status == "offline" {
            # Freeze the card at the instant death was OBSERVED. A frozen card
            # also ages out on its own, so PresenceStore.is_live agrees whether
            # it reads the status or the staleness.
            heartbeat_ms = self.offline_at_ms if self.offline_at_ms >= 0 else now_ms;
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

    """The honest status, and the side effect of remembering when death began.

    Split out of presence() so a caller can ask without minting a heartbeat."""
    def status_at(now_ms: int) -> str {
        if self.dead {
            if self.offline_at_ms < 0 {
                self.offline_at_ms = self.died_at_ms if self.died_at_ms >= 0 else now_ms;
            }
            return "offline";
        }
        # An answer on disk beats every other signal: the work is done whether
        # or not the process that produced it is still winding down.
        if self.answered or os.path.exists(self.assessment_path()) {
            return "idle";
        }
        if self.escalated_at_ms < 0 {
            # Nothing has been asked of this responder yet. Alive, not working.
            return "idle";
        }
        if self.spawn {
            if self.proc is None {
                # spawn was configured and the launch did not happen. Reporting
                # `working` here would be the dark-agent bug by another route.
                if self.offline_at_ms < 0 {
                    self.offline_at_ms = self.escalated_at_ms;
                }
                return "offline";
            }
            if self.proc.poll() is not None {
                # The harness EXITED and there is no assessment on disk. Dead.
                if self.offline_at_ms < 0 {
                    self.offline_at_ms = now_ms;
                }
                return "offline";
            }
            return "working";
        }
        # Not spawned by us: the runner is driven externally, so the only
        # honest liveness evidence we have is the answer budget.
        if self.poll_timeout_ms > 0
                and (now_ms - self.escalated_at_ms) > self.poll_timeout_ms {
            if self.offline_at_ms < 0 {
                self.offline_at_ms = self.escalated_at_ms + self.poll_timeout_ms;
            }
            return "offline";
        }
        return "working";
    }

    """Deliver `incident` to this responder.

    DURABLE channel semantics: ACCEPTANCE IS NOT AN ANSWER. A responder that is
    dead at delivery time still accepts — the incident is recorded, and revive()
    launches the harness that answers it. That is the backstop that keeps a
    restart from silently losing an incident.

    Returns PROMPTLY. The harness is launched non-blocking and never waited on;
    the coordinator learns the answer by polling, exactly as it does for a
    recorded mock."""
    def escalate(incident: dict, now_ms: int) -> None {
        iid = incident.get("incident_id", "");
        if iid == "" {
            raise ValueError("incident has no incident_id");
        }
        # Record acceptance FIRST and unconditionally, so a launch problem below
        # cannot lose the fact that this responder owns this incident.
        self.incident_id = iid;
        self.escalated_at_ms = now_ms;
        if self.dead {
            return;
        }
        if self.spawn {
            self.launch(incident, now_ms);
        }
    }

    """Assessments that have APPEARED since the last poll, each returned AT MOST
    ONCE and never again.

    At-least-once on the wire, at-most-once here: the caller cannot double-count
    a verdict. Delivery is keyed on the payload's content digest, so a
    redelivered byte-identical file is silently recognised as the same DM, while
    a genuinely different payload (the revised assessment from the one bounded
    deliberation round) is delivered once on its own account.

    Every refusal is RECORDED in `self.rejected`, never dropped: a dropped
    assessment is a lost vote, and a lost vote that nobody can see is worse than
    a visible failure."""
    def poll(now_ms: int) -> list {
        if self.dead {
            return [];
        }
        path = self.assessment_path();
        if not os.path.exists(path) {
            return [];
        }
        raw: str = "";
        try {
            with open(path, "r", encoding="utf-8") as fh {
                raw = fh.read();
            }
        } except Exception as e {
            # Reported, not dropped. No digest is recorded, so a transient read
            # error is retried on the next poll instead of written off forever.
            self.reject(R_UNREADABLE, type(e).__name__, path, now_ms);
            return [];
        }
        digest = _digest(raw);
        if digest in self.seen_digests {
            # Already dispositioned once — accepted or rejected. Either way this
            # exact payload never leaves this object a second time.
            return [];
        }
        self.seen_digests.append(digest);

        try {
            payload: Any = json.loads(raw);
        } except Exception as e {
            self.reject(R_INVALID_JSON, type(e).__name__, path, now_ms);
            return [];
        }
        errs = assessment_errors(payload);
        if len(errs) > 0 {
            self.reject(R_SCHEMA_INVALID, "; ".join(errs), path, now_ms);
            return [];
        }
        if payload.get("responder", "") != self.responder_id {
            self.reject(
                R_RESPONDER_MISMATCH,
                f"file says {payload.get('responder', '')}",
                path,
                now_ms
            );
            return [];
        }
        if self.escalated_at_ms < 0 {
            # An answer to a question this responder was never asked. Not a
            # vote — nothing has established which incident it belongs to.
            self.reject(R_NOT_ESCALATED, payload.get("incident_id", ""), path, now_ms);
            return [];
        }
        if payload.get("incident_id", "") != self.incident_id {
            # A stale assessment from an earlier incident, left in the run
            # directory. Counting it would attach one incident's verdict to
            # another's decision.
            self.reject(
                R_INCIDENT_MISMATCH,
                f"file says {payload.get('incident_id', '')}, escalated {self.incident_id}",
                path,
                now_ms
            );
            return [];
        }
        if self.answered and self.deliberation_round == 0 {
            # A second, different assessment with no deliberation round open.
            # assessment.v1: exactly one assessment per responder per incident.
            self.reject(R_UNSOLICITED_DUPLICATE, digest, path, now_ms);
            return [];
        }
        self.answered = True;
        return [payload];
    }

    """Open the one bounded deliberation round for `incident_id`.

    No-op when the budget is already spent, when this responder never received
    the incident, or when it is dead. The revised assessment arrives the way the
    first one did — the runner rewrites the same inbox file, and poll() picks it
    up because its content digest is new. This bridge does not itself re-invoke
    a harness for the second round; the mesh runner owns process lifecycle."""
    def open_deliberation(incident_id: str, round_no: int, now_ms: int) -> None {
        if round_no > DELIBERATION_ROUNDS_MAX {
            raise ValueError(
                f"deliberation round {round_no} exceeds max {DELIBERATION_ROUNDS_MAX}"
            );
        }
        if self.deliberation_round >= DELIBERATION_ROUNDS_MAX {
            return;
        }
        if self.escalated_at_ms < 0 {
            return;
        }
        if self.dead {
            return;
        }
        self.deliberation_round += 1;
    }

    """Force this responder dead as of `now_ms`.

    Also terminates the harness process if one is still running — kill() means
    the responder is gone, and leaving an orphan model call burning tokens
    behind a dead handle would be a lie in both directions. Anything already on
    disk is retained, not deleted: a dead responder loses time, not messages."""
    def kill(now_ms: int) -> None {
        self.dead = True;
        self.died_at_ms = now_ms;
        self.offline_at_ms = now_ms;
        if self.proc is not None {
            try {
                if self.proc.poll() is None {
                    self.proc.terminate();
                }
            } except Exception as e {
                # Reaping is best-effort; a process that has already gone is not
                # an error, and neither is one we may not signal.
                self.launch_error = f"terminate failed: {type(e).__name__}";
            }
        }
    }

    """Reconnect at `now_ms`.

    The durable-channel backstop: an incident escalated to a dead responder is
    still answered after it comes back, because acceptance was recorded at
    escalate() time and the harness is launched here."""
    def revive(now_ms: int) -> None {
        self.dead = False;
        self.died_at_ms = -1;
        self.offline_at_ms = -1;
        if self.spawn and self.proc is None and self.escalated_at_ms >= 0 {
            self.launch(self.load_incident(), now_ms);
        }
    }

    def is_alive -> bool {
        return not self.dead;
    }

    """Identity plus honest health, for logs and the audit trail.

    Carries no transport detail and no credential — `rejections` is counts and
    reason codes, so a bad payload cannot leak its contents into an artifact."""
    def describe -> dict {
        reasons: dict = {};
        for r in self.rejected {
            code = r["reason"];
            reasons[code] = reasons.get(code, 0) + 1;
        }
        return {
            "responder_id": self.responder_id,
            "kind": self.kind,
            "run_id": self.run_id,
            "answered": self.answered,
            "rejections": len(self.rejected),
            "rejection_reasons": dict(sorted(reasons.items())),
            "launched": self.proc is not None,
            "launch_error": self.launch_error
        };
    }

    # ---- internals --------------------------------------------------------

    """Record a refusal. Never called for a payload that was handed up."""
    def reject(reason: str, detail: str, path: str, now_ms: int) -> None {
        self.rejected.append({
            "reason": reason,
            "detail": detail,
            "path": path,
            "at_ms": now_ms
        });
    }

    """The incident file this responder was escalated, as a dict.

    Used by revive() to relaunch. Returns just the id when the file is gone —
    enough for escalate()'s contract, and honest about what is actually known."""
    def load_incident -> dict {
        if self.incident_path != "" and os.path.exists(self.incident_path) {
            try {
                with open(self.incident_path, "r") as fh {
                    return json.load(fh);
                }
            } except Exception as e {
                # An unreadable incident file must not lose the incident: fall
                # through to the id recorded at acceptance time, and say so.
                self.launch_error = f"incident file unreadable: {type(e).__name__}";
            }
        }
        return {"incident_id": self.incident_id};
    }

    """Materialise the incident the runner reads, and return its path.

    Written under runs/<run_id>/bridge/ — a directory this bridge owns — so it
    can never collide with an artifact the mesh runner writes."""
    def ensure_incident_file(incident: dict) -> str {
        if self.incident_path != "" {
            return self.incident_path;
        }
        d = self.bridge_dir();
        os.makedirs(d, exist_ok=True);
        p = os.path.join(d, f"incident-{self.responder_id}.json");
        with open(p, "w") as fh {
            json.dump(incident, fh, sort_keys=True, separators=(",", ":"));
        }
        self.incident_path = p;
        return p;
    }

    """Launch this agent's harness, NON-BLOCKING.

    Never waited on, never communicated with: escalate() must return promptly
    and the coordinator learns the answer by polling. The child authenticates
    itself from the operator's own session — no credential crosses this
    boundary, in either direction.

    mesh/agent_runner/ is built separately. If its entry point is not on disk
    this raises a CLEAR RuntimeError naming the missing path, rather than
    letting Popen surface a bare ENOENT. Acceptance of the incident has already
    been recorded by the time this runs, so the durable-channel guarantee
    survives the failure."""
    def launch(incident: dict, now_ms: int) -> None {
        runner = self.runner();
        if not os.path.exists(runner) {
            self.launch_error = f"agent_runner not built yet: {runner}";
            self.reject(R_RUNNER_MISSING, self.launch_error, runner, now_ms);
            if self.offline_at_ms < 0 {
                self.offline_at_ms = now_ms;
            }
            raise RuntimeError(self.launch_error);
        }
        inc_path = self.ensure_incident_file(incident);
        cmd: list = [
            "node",
            runner,
            "--agent", self.responder_id,
            "--incident", inc_path,
            "--run-id", self.run_id
        ];
        if self.mocked {
            cmd.append("--mock");
        }
        log = self.log_path();
        os.makedirs(os.path.dirname(log), exist_ok=True);
        try {
            fh = open(log, "ab");
            self.proc = subprocess.Popen(
                cmd,
                cwd=REPO_ROOT,
                stdin=subprocess.DEVNULL,
                stdout=fh,
                stderr=subprocess.STDOUT,
                start_new_session=True
            );
        } except Exception as e {
            self.launch_error = f"{type(e).__name__} launching {self.responder_id}";
            self.reject(R_RUNNER_MISSING, self.launch_error, runner, now_ms);
            if self.offline_at_ms < 0 {
                self.offline_at_ms = now_ms;
            }
            raise RuntimeError(self.launch_error);
        }
    }
}

# --------------------------------------------------------------------------
# Construction + registration
# --------------------------------------------------------------------------

"""Build a MeshResponder for `responder_id` from `opts`.

`opts` carries run wiring only — never a credential, never a token, never an
endpoint. `now_ms` is threaded in by config.build_mesh and ignored here: this
responder reads a real clock's worth of state off the filesystem and is handed
`now_ms` on every call that needs it."""
def mesh_responder_from_opts(responder_id: str, opts: dict) -> MeshResponder {
    run_id = str(opts.get("run_id", ""));
    if run_id == "" and str(opts.get("assessments_dir", "")) == "" {
        raise ValueError(
            f"cotal responder {responder_id} needs run_id (or assessments_dir) in opts"
        );
    }
    return MeshResponder(
        responder_id=responder_id,
        kind="cotal",
        run_id=run_id,
        assessments_dir=str(opts.get("assessments_dir", "")),
        incident_path=str(opts.get("incident_path", "")),
        runner_path=str(opts.get("runner_path", "")),
        spawn=bool(opts.get("spawn", False)),
        mocked=bool(opts.get("mocked", False)),
        poll_timeout_ms=int(opts.get("poll_timeout_ms", 0))
    );
}

"""Registry factory. Returns the handle typed as the abstract ResponderHandle —
config cannot hand the coordinator anything narrower, so the coordinator still
cannot tell a real model from a recording."""
def cotal_factory(responder_id: str, opts: dict) -> ResponderHandle {
    return mesh_responder_from_opts(responder_id, opts);
}

glob:pub COTAL_KIND: str = "cotal";

with entry {
    # THE SEAM. Importing this module is the entire wiring step: from here on
    # `is_known_kind("cotal")` is true and MeshConfig.validate() accepts
    # kind="cotal". coordinator/ is not touched.
    register_responder_kind(COTAL_KIND, cotal_factory);
}
