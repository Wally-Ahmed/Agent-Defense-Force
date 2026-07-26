# incident/graph.jac — the incident correlation graph archetypes.
#
# The whole graph hangs off a locally constructed CorrelationGraph hub, NOT off `root`.
# That is deliberate: `jac run` persists the `root` graph into .jac/data between runs, which
# would make "same events in -> same incident out" false. A per-run hub makes determinism
# structural rather than a matter of remembering to clear a cache.

node CorrelationGraph {
    has label: str = "incident";
    has seen_events: dict = {};      # event_id -> 1 . IngestAudit idempotence.
    has rows: list = [];             # Observation projections in ingest order (window buffer).
    has idx_identity: dict = {};
    has idx_session: dict = {};
    has idx_source: dict = {};
    has idx_asset: dict = {};
    has idx_service: dict = {};
    has idx_baseline: dict = {};
    has quarantine: dict = {};       # event_id -> free text. Write-only until Promote.
    has asset_history: dict = {};    # principal_hash -> {asset_hash: first_ts_ms}. Novelty prior.
    has baseline_store: dict = {};   # "<scope>|<metric>" -> EWMA state
    has idx_signal: dict = {};       # "<subject>|<family>" -> Signal node
    has idx_src_prins: dict = {};    # source key -> {principal_hash: 1}
    has promotions: list = [];       # gate verdicts awaiting Promote
    has window_trace: list = [];     # per-window gate verdict summaries (audit trail)
}

# --- entity nodes -------------------------------------------------------------------------
node Observation {
    has event_id: str = "";
    has ts_ms: int = 0;
    has action: str = "";
    has outcome: str = "";
    has reason: str = "";
    has severity: str = "";
    has target_sensitivity: str = "";
    has target_kind: str = "";
    has role_rank: int = 0;
    has sens_rank: int = 0;
    has result_count: int = 0;
    has tenant_cross: int = 0;
    has endpoint_class: str = "";
}

node Identity {
    has principal_hash: str = "";
    has tenant_id: str = "";
    has authenticated: int = 0;
}

node Session {
    has session_id: str = "";
    has first_ts_ms: int = 0;
}

node Source {
    has src_ip: str = "";
    has src_asn: str = "";
    has client_fp: str = "";
}

node Asset {
    has asset_hash: str = "";
    has kind: str = "";
    has sensitivity: str = "";
}

node Service {
    has name: str = "";
}

node Baseline {
    has scope_key: str = "";
    has metric: str = "";
    has ewma_mean: float = 0.0;
    has ewma_std: float = 0.0;
    has n: int = 0;
}

node Signal {
    has family: str = "";
    has axis: str = "";
    has score: float = 0.0;
    has window_start_ms: int = 0;
    has window_end_ms: int = 0;
    has join_keys: list = [];
    has evidence: list = [];
    has detail: dict = {};
    has subject: str = "";
}

node Incident {
    has incident_id: str = "";
    has state: str = "open";
    has confidence: float = 0.0;
    has first_ts: int = 0;
    has last_ts: int = 0;
    has axes: list = [];
    has families: list = [];
    has subject: str = "";
    has join_keys: dict = {};
    has evidence: list = [];
    has stage_signatures: list = [];
    has aggregate: float = 0.0;
    has window_start_ms: int = 0;
    has window_end_ms: int = 0;
    has detected_at_ms: int = 0;     # window end at which the gate FIRST opened; never moves
}

# --- edges --------------------------------------------------------------------------------
edge PerformedBy {}
edge InSession {}
edge FromSource {}
edge Targeted {}
edge Via {}
edge Supports {}
edge MitigatedBy {}                       # reserved for the containment track
edge SharesFingerprint { has client_fp: str = ""; }
edge PivotedTo { has via: str = ""; }
edge HasBaseline {}
edge Holds {}                             # hub -> entity containment
