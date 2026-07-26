"""
audit_window.py -- Tails an audit JSONL stream and emits window.v1 frames.

This is the ONLY component that sees raw audit logs (raw actor_email, raw
route query strings, raw user-agent strings, ...). Everything downstream
(the monitor) sees only the pre-aggregated numeric/identity features defined
by contracts/mesh/window.v1.schema.json -- never raw free text.

Free text that must be retained for forensics (actor_email, the raw route
with its query string, user_agent_hash) never reaches a frame. It is either
discarded after being reduced to a route TEMPLATE (normalize_path drops the
query string, which is where injection payloads in this fixture live), or,
when --quarantine is given, written to a separate sidecar file as a
sanitize.digest() (numeric fingerprint) plus a sanitize.fence()'d copy for
human/forensic use. See sanitize.py for why that boundary is safe.

CLI:
    python3 monitor/audit_window.py --input <audit.jsonl> --out-frames <frames.jsonl>
        [--quarantine <quarantine.jsonl>] [--follow] [--window-ms 15000] [--ring 6]
"""

import argparse
import hashlib
import json
import math
import os
import re
import statistics
import sys
import time
from collections import deque

try:
    from . import sanitize
except ImportError:
    import sanitize


_ID_SEGMENT_RE = re.compile(r'/(p_|t_|tk_|u_|ex_|c_|sess_)[A-Za-z0-9_]+')

# The 13 numeric actor metrics that have a p95_* counterpart in `baseline`.
# session_ids (list) and canary_touch (bool) are deliberately excluded.
NUMERIC_METRICS = (
    "req",
    "distinct_paths",
    "path_entropy",
    "auth_fail",
    "authz_deny",
    "deny_ratio",
    "new_endpoints_first_seen",
    "src_ips_distinct",
    "ua_distinct",
    "cross_tenant_attempts",
    "post_deny_pivot_ms_p50",
    "integration_calls",
    "export_bytes",
)


def normalize_path(route):
    """
    Reduce a raw route (which may carry a query string -- where injection
    payloads in this fixture live) to a route TEMPLATE: strip the query
    string, then collapse opaque id segments to '/{id}'. Only counts and
    entropies derived from templates ever reach a frame.
    """
    path = route.split("?", 1)[0]
    return _ID_SEGMENT_RE.sub("/{id}", path)


def _shannon_entropy_bits(items):
    """Shannon entropy (bits) of the distribution of `items`. 0.0 for empty input."""
    n = len(items)
    if n == 0:
        return 0.0
    counts = {}
    for item in items:
        counts[item] = counts.get(item, 0) + 1
    entropy = 0.0
    for c in counts.values():
        p = c / n
        entropy -= p * math.log2(p)
    return 0.0 if entropy == 0 else entropy  # clamp -0.0 -> 0.0


def _p95(values):
    """p95 via linear interpolation over `values`; 0.0 for empty input."""
    if not values:
        return 0.0
    s = sorted(values)
    n = len(s)
    k = 0.95 * (n - 1)
    lo = math.floor(k)
    hi = math.ceil(k)
    if lo == hi:
        return float(s[int(lo)])
    return float(s[lo] + (s[hi] - s[lo]) * (k - lo))


class _ClusterIndex:
    """
    Union-find over identity keys: ("fp", client_fp), ("ss", session_id),
    ("pr", actor_principal_id). Each cluster also carries a live record
    (all member keys ever merged in; the cluster ANCHOR; all route
    templates ever touched) that survives future re-parenting.

    Union-find roots can change identity as more merges happen (the node
    that used to be the root can become a child of a new root). find()
    always returns the CURRENT root, and the record for whichever key is
    currently a root is always the fully-merged one (merged in place at
    union time), so callers never need to reason about stale root labels
    -- they just call find()/record_by_root() fresh each time.

    "anchor" is the lexicographically smallest member key ever admitted to
    the cluster. Unlike the member SET (which grows with every merge), the
    anchor only changes when a genuinely smaller key joins, which is what
    makes it usable as a streaming identity (see _streaming_principal_hash).
    """

    def __init__(self):
        self._parent = {}
        # root-key -> {"members": set(keys), "anchor": key, "ever_seen": set(templates),
        #              "home_tenants": {tenant: count}, "target_tenants": {tenant: count}}
        self._record = {}

    def find(self, key):
        parent = self._parent
        if key not in parent:
            parent[key] = key
            self._record[key] = {
                "members": {key},
                "anchor": key,
                "ever_seen": set(),
                "home_tenants": {},
                "target_tenants": {},
            }
            return key
        root = key
        while parent[root] != root:
            root = parent[root]
        while parent[key] != root:
            parent[key], key = root, parent[key]
        return root

    def union(self, a, b):
        ra, rb = self.find(a), self.find(b)
        if ra == rb:
            return ra
        rec_a, rec_b = self._record[ra], self._record[rb]
        # Deterministic tie-break (bigger cluster wins; ties broken by the
        # key itself) so re-parenting never depends on incidental hashing.
        # This affects internal tree shape only -- both emitted identities
        # (full sorted member set / anchor) are symmetric in a and b, so
        # they are identical either way.
        if (len(rec_a["members"]), ra) < (len(rec_b["members"]), rb):
            ra, rb = rb, ra
            rec_a, rec_b = rec_b, rec_a
        rec_a["members"] |= rec_b["members"]
        rec_a["anchor"] = min(rec_a["anchor"], rec_b["anchor"])
        rec_a["ever_seen"] |= rec_b["ever_seen"]
        for field in ("home_tenants", "target_tenants"):
            merged = rec_a[field]
            for tenant, count in rec_b[field].items():
                merged[tenant] = merged.get(tenant, 0) + count
        self._parent[rb] = ra
        return ra

    def record_by_root(self, root):
        return self._record[root]


#: Emitted when a cluster has no tenant evidence at all. A stable placeholder is
#: required because the monitor keys its per-actor ring on (principal_hash, tenant);
#: an empty string there would silently split one cluster into two actors.
UNATTRIBUTED_TENANT = "t_unattributed"


def resolve_cluster_tenant(record):
    """One tenant per cluster, for the whole run.

    The monitor's ring buffer is keyed on (principal_hash, tenant), so tenant is
    half of the correlation identity -- resolving it per WINDOW would split a
    cluster the same way an unstable principal_hash does. Unauthenticated
    reconnaissance carries neither `actor_tenant_id` nor `tenant_id`, so a
    per-window reading yields "" for the recon phase and the real tenant for the
    authenticated phase, and the two never correlate.

    Preference order, most to least authoritative:
      1. the tenant the actor BELONGS to (`actor_tenant_id`), most frequent wins
      2. the tenant the actor TARGETED (`tenant_id`), most frequent wins
      3. UNATTRIBUTED_TENANT
    Ties break on the lexicographically smallest tenant id so the result is
    deterministic regardless of event order.
    """
    for field in ("home_tenants", "target_tenants"):
        counts = record.get(field) or {}
        if counts:
            return min(counts.items(), key=lambda kv: (-kv[1], kv[0]))[0]
    return UNATTRIBUTED_TENANT


def _apply_unions(cluster_index, event):
    """
    Union the three identity keys for one event: fp<->session always,
    fp<->principal only when actor_principal_id is non-empty.
    """
    fp_key = ("fp", event.get("client_fp", ""))
    ss_key = ("ss", event.get("session_id", ""))
    cluster_index.union(fp_key, ss_key)
    principal = event.get("actor_principal_id", "")
    if principal:
        cluster_index.union(fp_key, ("pr", principal))

    # Tally tenant evidence onto the CURRENT root. Later merges fold these
    # dicts together (see union()), so after pass 1 every cluster carries the
    # tenant evidence of all its members.
    record = cluster_index.record_by_root(cluster_index.find(fp_key))
    home = event.get("actor_tenant_id", "")
    if home:
        record["home_tenants"][home] = record["home_tenants"].get(home, 0) + 1
    target = event.get("tenant_id", "")
    if target:
        record["target_tenants"][target] = record["target_tenants"].get(target, 0) + 1


def _principal_hash(keys):
    """
    'c_' + sha256(<canonical cluster root string>)[:16].
    Canonical root string = repr of the sorted tuple of `keys` --
    deterministic and order-independent. Always a hash: never an email,
    a username, a session id or a token in the clear.
    """
    canonical = repr(tuple(sorted(keys)))
    return "c_" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]


def _batch_principal_hash(record):
    """
    BATCH identity (authoritative). Hash of the FINAL, fully-merged member-key
    set of the cluster. iter_frames() resolves every union BEFORE emitting any
    frame, so this set is already final in window 0 and the identity of a
    cluster is constant for the whole run: one cluster <=> one principal_hash,
    no matter when the merge evidence arrived.
    """
    return _principal_hash(record["members"])


def _streaming_principal_hash(record):
    """
    STREAMING identity (--follow only). A live tail cannot see the future, so
    the member set is not knowable when early frames are emitted; deriving the
    identity from it would rename a cluster on every merge and split one
    correlated actor into several. Derive it from the cluster ANCHOR (the
    lexicographically smallest member key ever admitted) instead: the anchor
    is monotone under merges (min of the two anchors), so the identity changes
    at most when a genuinely older key joins, and it settles on the final
    cluster's anchor. It is still not byte-equal to the batch id -- batch is
    the authoritative identity for replay and acceptance.
    """
    return _principal_hash({record["anchor"]})


def _quarantine_records(window_start_ms, window_end_ms, principal_hash, cluster_events, nonce):
    """
    Build (capped, deterministically ordered) quarantine records for one
    (window, cluster): one record per distinct non-empty free-text value
    observed in actor_email, raw route (WITH query string), and
    user_agent_hash. Capped at 24 records per (window, cluster).
    """
    values_by_label = {"actor_email": set(), "route": set(), "user_agent": set()}
    for e in cluster_events:
        email = e.get("actor_email", "")
        if email:
            values_by_label["actor_email"].add(email)
        route = e.get("route", "")
        if route:
            values_by_label["route"].add(route)
        ua = e.get("user_agent_hash", "")
        if ua:
            values_by_label["user_agent"].add(ua)

    records = []
    for label in ("actor_email", "route", "user_agent"):
        for value in sorted(values_by_label[label]):
            records.append(
                {
                    "nonce": nonce,
                    "cluster_id": principal_hash,
                    "window_start_ms": window_start_ms,
                    "window_end_ms": window_end_ms,
                    "label": label,
                    "digest": sanitize.digest(value),
                    "fenced": sanitize.fence(value, nonce),
                }
            )
    return records[:24]


def _build_actor_row(
    root,
    cluster_events,
    prev_cluster_events,
    cluster_index,
    window_start_ms,
    window_end_ms,
    quarantine_sink,
    nonce,
    principal_hash_fn,
):
    req = len(cluster_events)
    templates = [normalize_path(e.get("route", "")) for e in cluster_events]
    template_set = set(templates)
    distinct_paths = len(template_set)
    path_entropy = _shannon_entropy_bits(templates)

    auth_fail = sum(
        1
        for e in cluster_events
        if e.get("status_code") == 401 or e.get("action") == "auth.login_failed"
    )
    authz_deny = sum(1 for e in cluster_events if e.get("status_code") == 403)
    deny_ratio = (auth_fail + authz_deny) / req if req else 0.0

    record = cluster_index.record_by_root(root)
    ever_seen = record["ever_seen"]
    new_endpoints_first_seen = len(template_set - ever_seen)
    ever_seen |= template_set  # update the ever-seen set AFTER computing novelty

    src_ips_distinct = len(set(e.get("src_ip", "") for e in cluster_events))
    ua_distinct = len(set(e.get("user_agent_hash", "") for e in cluster_events))
    session_ids = sorted(set(e.get("session_id", "") for e in cluster_events))

    cross_tenant_attempts = sum(
        1
        for e in cluster_events
        if e.get("tenant_id")
        and e.get("actor_tenant_id")
        and e["tenant_id"] != e["actor_tenant_id"]
    )
    canary_touch = any(e.get("target_sensitivity") == "canary" for e in cluster_events)

    # post_deny_pivot_ms_p50: over (previous window + current window) events
    # for this SAME cluster, sorted by ts_ms.
    combined = list(prev_cluster_events) + list(cluster_events)
    combined.sort(key=lambda e: e["ts_ms"])
    pivots = []
    for i, e in enumerate(combined):
        if e.get("outcome") == "deny" and i + 1 < len(combined):
            nxt = combined[i + 1]
            if normalize_path(nxt.get("route", "")) != normalize_path(e.get("route", "")):
                pivots.append(nxt["ts_ms"] - e["ts_ms"])
    post_deny_pivot_ms_p50 = float(statistics.median(pivots)) if pivots else 0.0

    integration_calls = sum(1 for e in cluster_events if e.get("service") == "integration")
    export_bytes = sum(e.get("resp_bytes", 0) for e in cluster_events)

    # Cluster-level, NOT per-window: tenant is half of the (principal_hash, tenant)
    # ring key, so resolving it per window would split the recon phase (which has no
    # tenant fields at all) away from the authenticated phase of the same cluster.
    tenant = resolve_cluster_tenant(record)

    principal_hash = principal_hash_fn(record)

    row = {
        "principal_hash": principal_hash,
        "tenant": tenant,
        "req": req,
        "distinct_paths": distinct_paths,
        "path_entropy": path_entropy,
        "auth_fail": auth_fail,
        "authz_deny": authz_deny,
        "deny_ratio": deny_ratio,
        "new_endpoints_first_seen": new_endpoints_first_seen,
        "src_ips_distinct": src_ips_distinct,
        "ua_distinct": ua_distinct,
        "session_ids": session_ids,
        "cross_tenant_attempts": cross_tenant_attempts,
        "canary_touch": canary_touch,
        "post_deny_pivot_ms_p50": post_deny_pivot_ms_p50,
        "integration_calls": integration_calls,
        "export_bytes": export_bytes,
    }

    if quarantine_sink is not None:
        for rec in _quarantine_records(
            window_start_ms, window_end_ms, principal_hash, cluster_events, nonce
        ):
            quarantine_sink(rec)

    return row


def _compute_baseline(ring_history):
    """Global rolling p95 of each numeric metric across ALL actor rows in ring_history."""
    baseline = {}
    for metric in NUMERIC_METRICS:
        values = [row[metric] for past_actors in ring_history for row in past_actors]
        baseline["p95_" + metric] = _p95(values)
    return baseline


def _build_frame(
    idx,
    window_ms,
    epoch0,
    idx_events,
    prev_events,
    cluster_index,
    ring_history,
    quarantine_sink,
    nonce,
    principal_hash_fn,
):
    window_start_ms = epoch0 + idx * window_ms
    window_end_ms = window_start_ms + window_ms

    by_cluster = {}
    order = []
    for e in idx_events:
        root = cluster_index.find(("fp", e.get("client_fp", "")))
        if root not in by_cluster:
            by_cluster[root] = []
            order.append(root)
        by_cluster[root].append(e)

    actors = []
    for root in order:
        cluster_events = by_cluster[root]
        prev_cluster_events = [
            e for e in prev_events if cluster_index.find(("fp", e.get("client_fp", ""))) == root
        ]
        actors.append(
            _build_actor_row(
                root,
                cluster_events,
                prev_cluster_events,
                cluster_index,
                window_start_ms,
                window_end_ms,
                quarantine_sink,
                nonce,
                principal_hash_fn,
            )
        )

    actors.sort(key=lambda r: r["principal_hash"])

    frame = {
        "window_start_ms": window_start_ms,
        "window_end_ms": window_end_ms,
        "actors": actors,
        "baseline": _compute_baseline(ring_history),
    }

    # H. Self-check before every frame is written -- fail loud.
    sanitize.assert_clean(frame, ["@", "%"])
    for actor in frame["actors"]:
        if not actor["principal_hash"].startswith("c_"):
            raise ValueError(
                "self-check failed: principal_hash missing 'c_' prefix: {!r}".format(
                    actor["principal_hash"]
                )
            )

    return frame


def _emit_frames(events, cluster_index, window_ms, ring, quarantine_sink, principal_hash_fn):
    """
    Shared windowing/emit loop behind both entry points. Yields one frame per
    15s tumbling window index from 0 to the last observed index inclusive
    (idle windows get an empty actors list), strictly ordered by
    window_start_ms.

    `cluster_index` may arrive already fully merged (batch: iter_frames has
    resolved every union in a first pass) or empty (streaming: merges are
    discovered here as events arrive). _apply_unions is idempotent, so the
    same loop serves both: in the batch case the calls below simply find the
    unions already in place.
    """
    ring_history = deque(maxlen=ring)

    nonce = None
    if quarantine_sink is not None:
        nonce = sanitize.new_nonce()
        print("quarantine nonce: {}".format(nonce), file=sys.stderr)

    epoch0 = None
    current_idx = 0
    bucket = []
    prev_bucket = []

    def flush(idx, idx_events):
        frame = _build_frame(
            idx,
            window_ms,
            epoch0,
            idx_events,
            prev_bucket,
            cluster_index,
            ring_history,
            quarantine_sink,
            nonce,
            principal_hash_fn,
        )
        ring_history.append(frame["actors"])
        return frame

    for event in events:
        ts_ms = event["ts_ms"]
        if epoch0 is None:
            epoch0 = ts_ms
        idx = (ts_ms - epoch0) // window_ms

        while idx > current_idx:
            frame = flush(current_idx, bucket)
            yield frame
            prev_bucket = bucket
            bucket = []
            current_idx += 1

        _apply_unions(cluster_index, event)
        bucket.append(event)

    if epoch0 is not None:
        frame = flush(current_idx, bucket)
        yield frame


def iter_frames(events, window_ms=15000, ring=6, quarantine_sink=None):
    """
    BATCH entry point (authoritative). Consume an iterable of parsed audit
    events (dicts) and yield window.v1 frames, one per 15s tumbling window
    index from 0 to the last observed index inclusive (idle windows get an
    empty actors list), strictly ordered by window_start_ms.

    Two passes, deliberately:
      1. materialise the input and resolve EVERY union-find merge first;
      2. emit frames against that fully-merged index.
    A cluster therefore has exactly one principal_hash for the whole run --
    the identity of a correlated actor never changes mid-stream just because
    the evidence that links two of its keys (same client fingerprint, say)
    arrives late. Only --follow, which cannot see the future, uses the
    weaker streaming identity (see iter_frames_streaming); batch is what
    replay and acceptance run on, so batch is the authoritative answer.

    Materialising is intentional: callers pass finite, already-bounded audit
    slices (a fixture, a replay window), and correctness of the identity
    beats streaming the input.

    This is the only place raw events are read; the CLI is a thin wrapper
    over it (see main()) so replay.py or anything else can call it
    in-process instead of shelling out.
    """
    materialized = list(events)

    cluster_index = _ClusterIndex()
    for event in materialized:  # pass 1: resolve all merges before emitting
        _apply_unions(cluster_index, event)

    # pass 2: emit against the final clusters
    for frame in _emit_frames(
        materialized, cluster_index, window_ms, ring, quarantine_sink, _batch_principal_hash
    ):
        yield frame


def iter_frames_streaming(events, window_ms=15000, ring=6, quarantine_sink=None):
    """
    STREAMING entry point (--follow). Same frames as iter_frames, but a live
    tail must emit window N before window N+1 exists, so it cannot pre-resolve
    merges. Identity comes from the cluster anchor instead of the member set
    (see _streaming_principal_hash), which is the most stable identity
    available without lookahead: it changes at most when a genuinely older key
    joins the cluster, rather than on every merge. Re-run in batch mode for the
    authoritative, merge-order-independent identities.
    """
    for frame in _emit_frames(
        events, _ClusterIndex(), window_ms, ring, quarantine_sink, _streaming_principal_hash
    ):
        yield frame


def _tail_jsonl(path, follow, poll_interval=0.25):
    """
    Yield parsed JSON objects from `path`, one per non-blank line. If
    `follow` is true, keep polling for new lines every `poll_interval`
    seconds after EOF, re-stat'ing to detect truncation/rotation (inode
    change, or size shrinking below our current read position) and
    reopening from the top when detected. Runs forever when follow=True.
    """
    fh = open(path, "r")
    try:
        last_ino = os.fstat(fh.fileno()).st_ino
    except (OSError, AttributeError):
        last_ino = None
    try:
        while True:
            line = fh.readline()
            if line:
                stripped = line.strip()
                if stripped:
                    yield json.loads(stripped)
                continue
            if not follow:
                return
            time.sleep(poll_interval)
            try:
                st = os.stat(path)
            except OSError:
                continue
            try:
                cur_ino = st.st_ino
            except AttributeError:
                cur_ino = None
            rotated = last_ino is not None and cur_ino is not None and cur_ino != last_ino
            truncated = st.st_size < fh.tell()
            if rotated or truncated:
                fh.close()
                fh = open(path, "r")
                try:
                    last_ino = os.fstat(fh.fileno()).st_ino
                except (OSError, AttributeError):
                    last_ino = None
            else:
                fh.seek(fh.tell())
    finally:
        fh.close()


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Tail an audit JSONL stream and emit window.v1 frames."
    )
    parser.add_argument("--input", required=True, help="Path to the audit JSONL input.")
    parser.add_argument(
        "--out-frames", required=True, dest="out_frames", help="Path to write window.v1 JSONL frames."
    )
    parser.add_argument(
        "--quarantine",
        default=None,
        help="Optional path for the free-text quarantine sidecar JSONL (never model input).",
    )
    parser.add_argument(
        "--follow", action="store_true", help="Tail --input for new lines instead of stopping at EOF."
    )
    parser.add_argument(
        "--window-ms", type=int, default=15000, dest="window_ms", help="Tumbling window size in ms."
    )
    parser.add_argument(
        "--ring", type=int, default=6, help="Preceding windows kept for the rolling p95 baseline."
    )
    args = parser.parse_args(argv)

    quarantine_file = open(args.quarantine, "w") if args.quarantine else None

    def sink(record):
        quarantine_file.write(json.dumps(record) + "\n")
        quarantine_file.flush()

    events = _tail_jsonl(args.input, args.follow)

    # --follow never reaches EOF, so it cannot be two-passed; it gets the
    # anchor-derived streaming identity instead. The default (batch) path
    # pre-resolves every merge and is the authoritative one.
    frame_source = iter_frames_streaming if args.follow else iter_frames

    try:
        with open(args.out_frames, "w") as out_f:
            for frame in frame_source(
                events,
                window_ms=args.window_ms,
                ring=args.ring,
                quarantine_sink=(sink if quarantine_file else None),
            ):
                out_f.write(json.dumps(frame) + "\n")
                out_f.flush()
    finally:
        if quarantine_file:
            quarantine_file.close()


if __name__ == "__main__":
    main()
