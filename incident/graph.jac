# incident/graph.jac — the incident graph's archetypes.
#
# RUN EVERYTHING FROM THE REPOSITORY ROOT. Jac resolves imports against the
# invocation cwd, so `import from incident.graph { ... }` and
# `import from contracts.audit_event_contract { ... }` only both resolve there.
#
# THE SHAPE (arrows exactly as specified; Jac traverses either direction):
#
#   Identity -PerformedBy-> Observation -InSession-> Session
#                           Observation -FromSource-> Source
#                           Observation -Targeted->  Asset
#                           Observation -Via->       Service
#   Source   -SharesFingerprint-> Source
#   Identity -PivotedTo->         Identity
#   Incident -Supports->          Signal -MitigatedBy-> ContainmentAction
#
# WHY THE GRAPH IS DETACHED FROM root().
# Jac persists every anchor reachable from root() into .jac/data/anchor_store.db
# and reloads it in the next process. A detector whose answer depends on how many
# times it has been run before is not a detector. Every analysis therefore hangs
# off a freshly constructed `IncidentGraph()` that is never linked to root(), so
# two runs over the same input agree exactly and no state survives the process.
# Verified: repeated `jac run` leaves no anchor_store.db at all.
#
# THE PROMPT-INJECTION BOUNDARY IS STRUCTURAL, NOT STYLISTIC.
# `Observation` carries closed enums, opaque identifiers and numbers. It has no
# free-text field, so no scorer can read one. Attacker-influenced text
# (`actor_email`, raw `route` query strings) is projected into `Quarantine`
# nodes hanging off the IncidentGraph, reachable only by the emitter, which
# fences them into incident.v1's `untrusted_data`. There is no edge from
# Observation to Quarantine: the isolation is a missing edge, not a convention
# somebody has to remember.

# --------------------------------------------------------------------------
# Edges
# --------------------------------------------------------------------------

edge PerformedBy {}        # Identity    -> Observation
edge InSession {}          # Observation -> Session
edge FromSource {}         # Observation -> Source
edge Targeted {}           # Observation -> Asset
edge Via {}                # Observation -> Service
edge SharesFingerprint {}  # Source      -> Source    (same client_fp, other ip)
edge PivotedTo {}          # Identity    -> Identity  (same client_fp, other principal)
edge Supports {}           # Incident    -> Signal
edge MitigatedBy {}        # Signal      -> ContainmentAction

# Index edges: the IncidentGraph anchor owns every top-level entity so a walker
# can enumerate them without a global registry.
edge Observes {}           # IncidentGraph -> Observation
edge Knows {}              # IncidentGraph -> Identity | Session | Source | Asset | Service
edge Measures {}           # IncidentGraph -> Baseline
edge Emitted {}            # IncidentGraph -> Signal
edge Raised {}             # IncidentGraph -> Incident
edge Quarantined {}        # IncidentGraph -> Quarantine   (emitter-only subgraph)

# --------------------------------------------------------------------------
# The anchor
# --------------------------------------------------------------------------

# Detached root of one analysis. `idx` maps a natural key ("src|198.51.100.11")
# to the node that owns it, which is what makes IngestAudit idempotent and O(1)
# per event instead of a linear scan of the graph.
node IncidentGraph {
    has run_id: str = "";
    has idx: dict = {};             # natural key -> node
    has seen_events: dict = {};     # event_id -> 1  (idempotency ledger)
    has cluster_parent: dict = {};  # union-find parent map over join keys
    has n_ingested: int = 0;
    has n_duplicates: int = 0;
    has n_rejected: int = 0;        # events failing the closed-vocabulary check
}

# --------------------------------------------------------------------------
# Observation — the projection of an AuditEvent. Enums, opaque ids, numbers.
# --------------------------------------------------------------------------

node Observation {
    has event_id: str = "";
    has ts_ms: int = 0;
    has seq: int = 0;

    # closed vocabularies (validated against ACTIONS / DENY_REASONS on ingest)
    has kind: str = "";
    has action: str = "";
    has outcome: str = "";
    has reason: str = "";
    has severity: str = "";
    has actor_role: str = "";
    has auth_method: str = "";
    has target_kind: str = "";
    has target_sensitivity: str = "";
    has service: str = "";
    has http_method: str = "";

    # opaque identifiers — compared, never parsed, never rendered into a prompt
    has principal_id: str = "";
    has session_id: str = "";
    has tenant_id: str = "";
    has actor_tenant_id: str = "";
    has target_id: str = "";
    has parent_id: str = "";
    has src_ip: str = "";
    has src_asn: str = "";
    has client_fp: str = "";
    has ua_hash: str = "";
    has integration_id: str = "";
    has trace_id: str = "";

    # derived, closed. route_class is a hex digest of the normalized route
    # TEMPLATE — the one place raw route text is touched, and the text does not
    # survive the call. See incident/projection.jac.
    has route_class: str = "";
    has cross_tenant: bool = False;
    has authenticated: bool = False;
    has asset_rank: int = 0;

    # numeric
    has status_code: int = 0;
    has latency_ms: int = 0;
    has req_bytes: int = 0;
    has resp_bytes: int = 0;
    has result_count: int = 0;
}

# --------------------------------------------------------------------------
# Entities
# --------------------------------------------------------------------------

node Identity {
    has principal_id: str = "";      # "" for the anonymous pre-auth actor
    has tenant_id: str = "";
    has role: str = "";
    has first_ts_ms: int = 0;
    has last_ts_ms: int = 0;
}

node Session {
    has session_id: str = "";
    has client_fp: str = "";
    has first_ts_ms: int = 0;
    has last_ts_ms: int = 0;
}

node Source {
    has src_ip: str = "";
    has src_asn: str = "";
    has client_fp: str = "";
    has first_ts_ms: int = 0;
    has last_ts_ms: int = 0;
}

node Asset {
    has kind: str = "";
    has asset_id: str = "";
    has sensitivity: str = "normal";   # normal | confidential | canary
}

node Service {
    has name: str = "";                # web | api | export | integration | scheduler
}

# --------------------------------------------------------------------------
# Baseline — per-principal AND per-tenant EWMA, one node per (scope, metric).
#
# scope_key is "P|<principal>" | "S|<subject>" | "T|<tenant>" | "G|*". A metric
# is scored against the narrowest scope that is warm (n >= MIN_SAMPLES) and
# falls back outward, so a brand-new principal is judged against its tenant
# rather than against nothing.
# --------------------------------------------------------------------------

node Baseline {
    has scope_key: str = "";
    has metric: str = "";
    has ewma_mean: float = 0.0;
    has ewma_var: float = 0.0;     # EWMA of squared deviation; std = sqrt(var)
    has n: int = 0;
}

# --------------------------------------------------------------------------
# Signal — one firing family, in one window, for one subject.
# --------------------------------------------------------------------------

node Signal {
    has family: str = "";          # one of the seven, closed
    has axis: str = "";            # identity | asset | time | source
    has score: float = 0.0;
    has window_start_ms: int = 0;
    has window_end_ms: int = 0;
    has subject_key: str = "";
    has join_keys: list = [];      # ["principal|u_x", "session|s_y", ...]
    has evidence: list = [];       # event_ids
    has detail: dict = {};         # the numeric features behind the score
}

# --------------------------------------------------------------------------
# Incident — the promoted campaign. One per subject cluster; later qualifying
# windows merge into it rather than raising a duplicate, which is why it has
# state, first/last timestamps and accumulating family/axis sets.
# --------------------------------------------------------------------------

node Incident {
    has incident_id: str = "";
    has state: str = "open";       # open | merged | contained
    has subject_key: str = "";
    has confidence: float = 0.0;
    has first_ts_ms: int = 0;
    has last_ts_ms: int = 0;
    has axes: list = [];
    has families: list = [];
    has join_keys: dict = {};
    has evidence: list = [];
    has stage_signatures: list = [];
    has window_count: int = 0;
    has peak_score: float = 0.0;
}

node ContainmentAction {
    has kind: str = "";
    has target: str = "";
    has state: str = "proposed";
}

# --------------------------------------------------------------------------
# Quarantine — attacker-influenced text. Reachable from the IncidentGraph only.
# Nothing in features.jac, scorers.jac, gate.jac or stages.jac imports this.
# --------------------------------------------------------------------------

node Quarantine {
    has event_id: str = "";
    has label: str = "";           # monitor-authored provenance label
    has text: str = "";            # raw; fenced at emit time, never scored
}
