# coordinator/config.jac
#
# Mesh configuration. This file is the ONLY place that knows whether a run is
# mocked or live.
#
# Swapping a mock responder for a real Cotal-backed one is a CONFIG CHANGE:
# flip `kind` from "mock" to "live" on a ResponderConfig. Nothing in the
# coordinator, the quorum logic, the presence layer or the audit trail changes,
# because `build_mesh` hands back handles typed only as `ResponderHandle` and
# the coordinator has no way to ask which implementation it got.
#
# The one thing config CANNOT hide: `is_mocked()`. If any responder in the mesh
# is a mock, the run is not an acceptance run, and the run label is forced to
# MOCKED so no mocked artifact can ever be presented as a live result.
#
# No credentials, tokens, endpoints or host names live here. A live responder's
# transport is constructed by whoever owns the credentials and passed in via
# `opts["transport"]` as an already-authenticated object.

import from ids { RESPONDER_IDS, RUN_LIVE, RUN_MOCKED }
import from responder {
    ResponderHandle,
    build_responder,
    is_known_kind,
    known_responder_kinds
}
import from mocks.mock_responder { mock_from_transcript }   # registers kind "mock"

# --------------------------------------------------------------------------
# Per-responder configuration
# --------------------------------------------------------------------------

"""How to build ONE responder.

`kind` is the single field a human edits to go live. `opts` carries
implementation-specific settings — failure knobs for a mock, an injected
transport for a live responder — and never a secret."""
obj ResponderConfig {
    has responder_id: str = "";
    has kind: str = "mock";       # "mock" | "live"  <-- the ONE thing that changes for a live run
    has opts: dict = {};

    """Audit view of this entry. `opts` is summarised by key only, so nothing
    an integrator wrongly put in opts can leak into an artifact."""
    def describe -> dict {
        return {
            "responder_id": self.responder_id,
            "kind": self.kind,
            "opt_keys": sorted(self.opts.keys())
        };
    }
}

# --------------------------------------------------------------------------
# The mesh
# --------------------------------------------------------------------------

"""The full five-responder mesh configuration."""
obj MeshConfig {
    has responders: list[ResponderConfig] = [];   # one per RESPONDER_IDS
    has run_label: str = "LIVE";

    """Reject a mesh the coordinator could not run deterministically.

    Every canonical responder present exactly once, no strangers, and every
    `kind` registered in the responder factory registry."""
    def validate -> None {
        seen: dict = {};
        for rc in self.responders {
            if rc.responder_id not in RESPONDER_IDS {
                raise ValueError(f"unknown responder id in config: {rc.responder_id}");
            }
            if rc.responder_id in seen {
                raise ValueError(f"duplicate responder in config: {rc.responder_id}");
            }
            seen[rc.responder_id] = True;
            if not is_known_kind(rc.kind) {
                raise ValueError(
                    f"unknown responder kind {rc.kind} for {rc.responder_id} "
                    f"(known: {known_responder_kinds()})"
                );
            }
        }
        missing = sorted([r for r in RESPONDER_IDS if r not in seen]);
        if len(missing) > 0 {
            raise ValueError(f"config missing responders: {missing}");
        }
    }

    """True when ANY responder is a mock. One mock makes the whole run mocked."""
    def is_mocked -> bool {
        for rc in self.responders {
            if rc.kind == "mock" {
                return True;
            }
        }
        return False;
    }

    """The run label this configuration forces: MOCKED if any mock is present."""
    def effective_run_label -> str {
        if self.is_mocked() {
            return RUN_MOCKED;
        }
        return RUN_LIVE;
    }

    """The ResponderConfig for `responder_id`, or None."""
    def entry(responder_id: str) -> ResponderConfig | None {
        for rc in self.responders {
            if rc.responder_id == responder_id {
                return rc;
            }
        }
        return None;
    }

    """Audit view: what this run was configured to be, in canonical order."""
    def describe -> dict {
        rows: list = [];
        for rid in RESPONDER_IDS {
            rc = self.entry(rid);
            if rc is not None {
                rows.append(rc.describe());
            }
        }
        return {
            "run_label": self.effective_run_label(),
            "mocked": self.is_mocked(),
            "responders": rows
        };
    }
}

# --------------------------------------------------------------------------
# Standard configurations
# --------------------------------------------------------------------------

"""The all-mock mesh: five recorded responders, no latency, none dead.

This is the demo/CI default. Its run_label is MOCKED and cannot be talked out
of it."""
def default_mock_config -> MeshConfig {
    rows: list = [];
    for rid in RESPONDER_IDS {
        rows.append(ResponderConfig(responder_id=rid, kind="mock", opts={}));
    }
    return MeshConfig(responders=rows, run_label=RUN_MOCKED);
}

"""The all-live mesh. THIS is the swap: same five ids, `kind` = "live".

`transports` maps responder_id -> an already-authenticated transport object,
built by the caller. Omit it and every LiveResponder is constructed with no
transport and raises on first use — honest, and exactly what an unwired live run
should do."""
def default_live_config(transports: dict = {}) -> MeshConfig {
    rows: list = [];
    for rid in RESPONDER_IDS {
        opts: dict = {};
        if rid in transports {
            opts["transport"] = transports[rid];
        }
        rows.append(ResponderConfig(responder_id=rid, kind="live", opts=opts));
    }
    return MeshConfig(responders=rows, run_label=RUN_LIVE);
}

"""A mock mesh with per-responder failure knobs.

`overrides` maps responder_id -> opts dict (latency_ms, dead,
verdict_override, confidence_override, actions_override,
heartbeat_stops_at_ms)."""
def mock_config_with(overrides: dict) -> MeshConfig {
    cfg = default_mock_config();
    for rc in cfg.responders {
        if rc.responder_id in overrides {
            rc.opts = dict(overrides[rc.responder_id]);
        }
    }
    return cfg;
}

# --------------------------------------------------------------------------
# Construction
# --------------------------------------------------------------------------

"""Build the mesh: responder_id -> ResponderHandle, in canonical order.

Validates first, then forces `run_label` to MOCKED if any mock is present.
`clock_now_ms` is the injected virtual clock's current instant; it is threaded
into every responder's opts as `now_ms` so an implementation that needs a
construction-time baseline (a mock born dead, for instance) never has to reach
for a wall clock.

The returned values are typed `ResponderHandle` and nothing narrower. That is
the seam: the coordinator cannot tell mock from live."""
def build_mesh(cfg: MeshConfig, clock_now_ms: int) -> dict {
    cfg.validate();
    cfg.run_label = cfg.effective_run_label();

    mesh: dict = {};
    for rid in RESPONDER_IDS {
        rc = cfg.entry(rid);
        if rc is None {
            # validate() already guarantees this; belt and braces against a
            # future validate/build skew, which would otherwise silently drop
            # a responder and hand the coordinator a four-agent mesh.
            raise ValueError(f"config lost responder between validate and build: {rid}");
        }
        opts: dict = dict(rc.opts);
        opts["now_ms"] = clock_now_ms;
        mesh[rid] = build_responder(rc.kind, rid, opts);
    }
    return mesh;
}
