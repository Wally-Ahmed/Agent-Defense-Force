# incident/stages.jac — behavioural stage signatures.
#
# incident.v1 carries `stage_signatures`: which of the ten authorized-scenario
# attack steps the monitor saw evidence of. These are derived HERE, from event
# ordering and closed enums, and never read from any label. The golden fixture
# ships ground truth in a sidecar file precisely so detection cannot consult it;
# tests/test_no_label_leak.jac asserts no module on this path opens it.
#
# Each predicate below is a statement about SHAPE, not identity. None of them
# names a principal, a tenant, an address or a route. Rewriting the fixture with
# different identifiers would not change a single answer.
#
#   1 reconnaissance          unauthenticated non-auth traffic
#   2 password spraying       >= 3 auth.login_failed
#   3 compromised identity    successful login/token issue after unauth traffic
#   4 enumeration             repeated list calls, many targets, sub-2s spacing
#   5 boundary probing        INSUFFICIENT_ROLE / NOT_A_MEMBER denials
#   6 rapid adaptation        a denial answered <1s later on another endpoint class
#   7 source rotation         one session/fingerprint across >= 2 addresses
#   8 higher-value discovery  reached confidential-class targets
#   9 lateral movement        acted on a tenant the actor does not belong to
#  10 canary                  touched a canary-sensitivity target

# Actions that constitute a listing/enumeration call. Closed subset of ACTIONS.
glob:pub LIST_ACTIONS: list = [
    "project.list", "task.list", "comment.list", "search.query", "project.read"
];

# Deny reason codes that mean "you are inside the system but not allowed here" —
# the signature of probing a permission boundary rather than failing to log in.
glob:pub BOUNDARY_REASONS: list = ["INSUFFICIENT_ROLE", "NOT_A_MEMBER"];

# How quickly a follow-up must arrive after a denial to count as adaptation
# rather than a person reading an error message.
glob:pub ADAPT_MS: int = 1000;

# Upper bound on the spacing of an enumeration sweep, and how many calls in a
# row it takes before tempo counts as a sweep rather than a coincidence.
glob:pub ENUM_GAP_MS: int = 2000;
glob:pub ENUM_MIN_CALLS: int = 3;
glob:pub SPRAY_MIN: int = 3;

glob:pub STAGE_NAMES: dict = {
    1: "reconnaissance",
    2: "credential spraying",
    3: "compromised identity in use",
    4: "high-speed enumeration",
    5: "permission-boundary probing",
    6: "rapid post-denial adaptation",
    7: "source rotation",
    8: "higher-value resource discovery",
    9: "lateral movement across tenants",
    10: "canary / protected-export touch"
};


"""Stage numbers evidenced by `rows`, ascending. `rows` are Observation
projections for one subject in timestamp order."""
def signatures(rows: list) -> list {
    found = set();
    n_failed_login = 0;
    saw_unauth = False;
    enum_run = 0;
    enum_targets = set();
    prev_ts = -1;
    prev_authenticated_ts = -1;

    i = 0;
    while i < len(rows) {
        r = rows[i];
        action = str(r.get("action", ""));
        outcome = str(r.get("outcome", ""));
        reason = str(r.get("reason", ""));
        authed = bool(r.get("authenticated", False));
        ts = int(r.get("ts_ms", 0));

        # 1 — unauthenticated traffic that is not an auth attempt.
        if not authed {
            saw_unauth = True;
            if not action.startswith("auth.") {
                found.add(1);
            }
        }

        # 2 — repeated failed logins.
        if action == "auth.login_failed" {
            n_failed_login += 1;
            if n_failed_login >= SPRAY_MIN {
                found.add(2);
            }
        }

        # 3 — a credential that works, used by something that was scouting first.
        if outcome == "allow" and (action == "auth.login" or action == "auth.token_issued") {
            if saw_unauth {
                found.add(3);
            }
        }

        # 4 — a listing sweep: a contiguous run of list-class calls at
        # sub-two-second spacing spanning more than one kind of resource.
        # Deliberately NOT keyed on distinct target_id: a collection listing
        # names no single target, so target_id is empty on exactly the calls
        # that do the enumerating. The observable is the tempo and the spread
        # across resource kinds.
        if action in LIST_ACTIONS {
            gap_ok = prev_ts < 0 or (ts - prev_ts) <= ENUM_GAP_MS;
            if gap_ok {
                enum_run += 1;
            } else {
                enum_run = 1;
                enum_targets = set();
            }
            k = str(r.get("target_kind", ""));
            if k != "" {
                enum_targets.add(k);
            }
            if enum_run >= ENUM_MIN_CALLS and len(enum_targets) >= 2 {
                found.add(4);
            }
        } else {
            enum_run = 0;
            enum_targets = set();
        }

        # 5 — refused for authority reasons, not for identity reasons.
        if outcome == "deny" and reason in BOUNDARY_REASONS {
            found.add(5);
        }

        # 6 — a denial answered on a different endpoint class within a second.
        # A benign client retries the call it just lost; this abandons it.
        if outcome == "deny" and i + 1 < len(rows) {
            nxt = rows[i + 1];
            dt = int(nxt.get("ts_ms", 0)) - ts;
            if dt >= 0 and dt <= ADAPT_MS {
                if nxt.get("route_class", "") != r.get("route_class", "") {
                    found.add(6);
                }
            }
        }

        # 8 — reached a confidential-class target.
        if r.get("target_sensitivity", "") == "confidential" {
            found.add(8);
        }

        # 9 — acted on a tenant the actor does not belong to.
        if r.get("cross_tenant", False) or reason == "TENANT_MISMATCH" {
            found.add(9);
        }

        # 10 — canary.
        if r.get("target_sensitivity", "") == "canary" {
            found.add(10);
        }

        if authed {
            prev_authenticated_ts = ts;
        }
        prev_ts = ts;
        i += 1;
    }

    # 7 — one session or fingerprint seen from more than one address.
    by_session = {};
    by_fp = {};
    for r in rows {
        s = r.get("session_id", "");
        fp = r.get("client_fp", "");
        ip = r.get("src_ip", "");
        if ip == "" {
            continue;
        }
        if s != "" {
            if s not in by_session {
                by_session[s] = set();
            }
            by_session[s].add(ip);
        }
        if fp != "" {
            if fp not in by_fp {
                by_fp[fp] = set();
            }
            by_fp[fp].add(ip);
        }
    }
    for k in by_session.keys() {
        if len(by_session[k]) >= 2 {
            found.add(7);
        }
    }
    for k in by_fp.keys() {
        if len(by_fp[k]) >= 2 {
            found.add(7);
        }
    }

    _ = prev_authenticated_ts;
    return sorted(list(found));
}


"""Human-readable stage name. Monitor-authored strings only."""
def stage_name(n: int) -> str {
    return str(STAGE_NAMES.get(n, "unknown"));
}
