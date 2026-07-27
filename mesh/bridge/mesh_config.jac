# mesh/bridge/mesh_config.jac
#
# The proof that going live is a CONFIG CHANGE.
#
# coordinator/config.jac states the claim: swapping a recorded responder for a
# real one is one `kind` string on one ResponderConfig, and nothing in the
# coordinator, the quorum logic, the presence layer or the audit trail moves.
# This module is that claim executed. It builds a real coordinator.MeshConfig
# in which some responders carry kind="cotal" (real model, real artifacts, via
# mesh/bridge/mesh_responder.jac) and the rest carry kind="mock" (recorded), and
# hands it to the SAME build_mesh the all-mock demo uses.
#
# Unblocking an agent is therefore:
#
#     move its id from `mocked_agents` to `live_agents`
#
# which flips exactly one field — ResponderConfig.kind, "mock" -> "cotal". No
# coordinator code, no test, no contract and no artifact schema changes.
#
# THE ONE THING CONFIG CANNOT TALK ITS WAY OUT OF: MeshConfig.is_mocked() is
# true if ANY responder is a mock, and effective_run_label() then forces MOCKED.
# A mixed run — three real models, two recordings — is a MOCKED run and every
# artifact it touches says so. That is deliberate: a partially-real run must
# never be presentable as the live acceptance run.
#
# No credentials, tokens, endpoints or host names live here. `opts` carries run
# wiring only, and coordinator/config.jac's ResponderConfig.describe() summarises
# opts BY KEY so nothing an integrator wrongly put there can reach an artifact.

import os;
import sys;

glob:pub HERE: str = os.path.dirname(os.path.abspath(__file__));
glob:pub REPO_ROOT: str = os.path.dirname(os.path.dirname(HERE));
glob:pub COORD_DIR: str = os.path.join(REPO_ROOT, "coordinator");

with entry {
    # Same bootstrap as mesh_responder.jac, for the same reason: Jac resolves
    # imports against the invocation directory, and this module must import
    # cleanly whether jac was invoked from mesh/bridge, from the repo root, or
    # from anywhere else. Runs before the imports below, in source order.
    if COORD_DIR not in sys.path {
        sys.path.insert(0, COORD_DIR);
    }
}

import from ids { RESPONDER_IDS, RUN_LIVE, RUN_MOCKED }
import from config { ResponderConfig, MeshConfig }
import from mesh_responder { COTAL_KIND }   # importing this registers kind "cotal"

glob:pub MOCK_KIND: str = "mock";

# --------------------------------------------------------------------------
# Today's reality
#
# Recorded here as DATA, not as a promise. These lists are what the harnesses
# on this machine could actually be driven to do at the time of writing; they
# are the default argument to todays_config() and nothing else depends on them.
# A model is NEVER substituted — a blocked agent keeps its exact pin from
# mesh/config/models.json and runs from its recording instead.
# --------------------------------------------------------------------------

# 2026-07-26 CORRECTION. responder_kimi, responder_glm and monitor were listed
# here as blocked on two findings that were BOTH wrong:
#   * "opencode has no credential (`opencode auth list` reports 0)" — that count
#     is of STORED credentials. opencode reads its provider key from the
#     ENVIRONMENT and needs nothing stored. Verified live.
#   * "hermes/OpenRouter credential is empty; /auth/key returns 401" — the key
#     was in the gitignored .env all along and /auth/key returns HTTP 200.
#     Nothing in mesh/ had ever loaded .env; that is now mesh/lib/env.js.
# All six harnesses answer live. Kept as a note, not deleted, so the misdiagnosis
# is not silently rewritten out of the record.

glob:pub TODAY_LIVE: list = [
    "responder_claude",        # claude v2.1.220, claude-opus-5 @ max
    "responder_antigravity",   # agy v1.1.7, gemini-3.6-flash-high @ high (ceiling)
    "responder_codex",         # codex-cli 0.145.0, gpt-5.6-sol @ max
    "responder_kimi",          # opencode 1.18.5, moonshotai/kimi-k3 @ max via OpenRouter
    "responder_glm"            # opencode 1.18.5, z-ai/glm-5.2 @ max via OpenRouter
];

glob:pub TODAY_BLOCKED: list = [];

# `monitor` is not a responder — it never appears in a MeshConfig — but the
# effort gate counts it, so its state is recorded here rather than lost. It runs
# live on hermes v0.16.0, z-ai/glm-5.2 @ xhigh (hermes' own ceiling) via
# OpenRouter, driven by monitor/replay.py --backend live.
glob:pub TODAY_BLOCKED_NON_RESPONDER: list = [];

# Reason codes only. No credential, no key name's VALUE, no endpoint.
# Empty because nothing is blocked. The dict stays so the shape does not change
# the moment a harness does break.
glob:pub BLOCK_REASONS: dict = {};

# --------------------------------------------------------------------------
# The builder
# --------------------------------------------------------------------------

"""Merge `overrides` over `base` without mutating either."""
def _merged(base: dict, overrides: dict) -> dict {
    out: dict = dict(base);
    for k in overrides.keys() {
        out[k] = overrides[k];
    }
    return out;
}

"""The opts a cotal responder needs, from the shared `opts` block.

Only run wiring is copied through, key by key. An unrecognised key in `opts` —
including anything credential-shaped an integrator wrongly added — is NOT
forwarded to the responder."""
def _cotal_opts(run_id: str, opts: dict) -> dict {
    out: dict = {"run_id": run_id};
    for k in [
        "assessments_dir", "poll_timeout_ms", "spawn", "mocked",
        "incident_path", "runner_path"
    ] {
        if k in opts {
            out[k] = opts[k];
        }
    }
    return out;
}

"""Build the five-responder mesh for `run_id`.

  live_agents     ids that run a REAL model through mesh/agent_runner
  mocked_agents   ids that replay a recording — a blocked harness, or an agent
                  deliberately held back
  opts            shared run wiring for the live responders (assessments_dir,
                  poll_timeout_ms, spawn, mocked, incident_path), plus an
                  optional `per_agent` map of id -> opts merged over the shared
                  block for that one responder (mocks included, so a mock can
                  still carry its latency/dead knobs)

Together the two lists must cover the five canonical RESPONDER_IDS exactly once.
That is checked here AND again by MeshConfig.validate(), which this function
calls before returning — an invalid mesh never escapes this module."""
def cotal_config(
    run_id: str,
    live_agents: list,
    mocked_agents: list,
    opts: dict = {}
) -> MeshConfig {
    if run_id == "" {
        raise ValueError("cotal_config needs a run_id");
    }
    live = list(live_agents);
    mocked = list(mocked_agents);
    seen: dict = {};
    for rid in live + mocked {
        if rid not in RESPONDER_IDS {
            raise ValueError(f"unknown responder id: {rid}");
        }
        if rid in seen {
            raise ValueError(f"responder listed twice: {rid}");
        }
        seen[rid] = True;
    }
    missing = sorted([r for r in RESPONDER_IDS if r not in seen]);
    if len(missing) > 0 {
        raise ValueError(f"config missing responders: {missing}");
    }

    per_agent: dict = dict(opts.get("per_agent", {}));
    shared = _cotal_opts(run_id, opts);

    rows: list = [];
    for rid in RESPONDER_IDS {
        # Canonical order, so the built config is byte-stable regardless of the
        # order the caller listed its agents in.
        if rid in live {
            rows.append(ResponderConfig(
                responder_id=rid,
                kind=COTAL_KIND,
                opts=_merged(shared, dict(per_agent.get(rid, {})))
            ));
        } else {
            rows.append(ResponderConfig(
                responder_id=rid,
                kind=MOCK_KIND,
                opts=dict(per_agent.get(rid, {}))
            ));
        }
    }

    cfg = MeshConfig(responders=rows, run_label=RUN_LIVE);
    cfg.validate();
    # One mock makes the whole run mocked. Computed, never asserted.
    cfg.run_label = cfg.effective_run_label();
    return cfg;
}

"""The mesh as this machine can actually run it right now.

All five responders real, no recordings — so run_label computes to LIVE. If a
harness breaks, move its id from TODAY_LIVE to TODAY_BLOCKED with a reason in
BLOCK_REASONS (or pass explicit lists to cotal_config); one mock makes the whole
run MOCKED, which is computed from the rows and never asserted."""
def todays_config(run_id: str, opts: dict = {}) -> MeshConfig {
    return cotal_config(run_id, TODAY_LIVE, TODAY_BLOCKED, opts);
}

"""The all-real mesh: five live responders, run_label LIVE.

This is the acceptance configuration. It becomes runnable the moment all five
harnesses hold a credential — no code changes, only the list membership."""
def all_live_config(run_id: str, opts: dict = {}) -> MeshConfig {
    return cotal_config(run_id, list(RESPONDER_IDS), [], opts);
}

"""Per-responder audit row: id, kind, and (for a mock) why it is not live.

Reason codes only — this is the artifact-facing view and it carries no
transport detail and no secret."""
def block_report(cfg: MeshConfig) -> dict {
    rows: list = [];
    for rid in RESPONDER_IDS {
        rc = cfg.entry(rid);
        if rc is None {
            continue;
        }
        row: dict = {"responder_id": rid, "kind": rc.kind, "live": rc.kind == COTAL_KIND};
        if rc.kind == MOCK_KIND {
            row["blocked_reason"] = BLOCK_REASONS.get(rid, "held back by configuration");
        }
        rows.append(row);
    }
    return {
        "run_label": cfg.effective_run_label(),
        "mocked": cfg.is_mocked(),
        "live_count": len([r for r in rows if r["live"]]),
        "responders": rows
    };
}
