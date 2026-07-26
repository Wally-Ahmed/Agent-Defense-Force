# coordinator/mocks/mock_containment.jac
#
# The mock containment executor the state machine dispatches to in
# CONTAINING / VERIFYING / CONTAINED / ROLLED_BACK.
#
# It SIMULATES the enforcement surface — it is NOT a real revoker. No
# credentials, no endpoints, no real side effects. Everything is deterministic
# and driven by the injected virtual clock: identical inputs => identical
# results, every run.
#
# Anycast / exactly-one semantics are modelled two ways:
#   * idempotent by action_key — applying the same action twice records it once;
#   * a per-action delivery counter so a transient NAK on the FIRST delivery can
#     be recovered by the ONE redeliver the coordinator is allowed.

import from typing { Any }
import from ids { action_key, is_revocation }


"""A deterministic, in-memory containment executor.

Failure knobs, all matched by action KIND or by exact action_key:
  nak_actions   NAK on the FIRST delivery only, ACK on redeliver (transient,
                recovered by the coordinator's single redeliver)
  nak_forever   NAK on every delivery — the action is aborted after redeliver
  health_fail   the post-apply health probe FAILS, which drives a rollback

Audit surfaces:
  applied       action dicts that actually took effect (deduped by key)
  rolled_back   action dicts that were rolled back"""
obj MockContainment {
    has nak_actions: list = [];
    has nak_forever: list = [];
    has health_fail: list = [];
    has applied: list = [];
    has rolled_back: list = [];

    # ---- internal bookkeeping (not configuration) ------------------------
    has _deliveries: dict = {};    # action_key -> delivery count
    has _applied_keys: dict = {};  # action_key -> True (idempotency ledger)

    """Canonical identity of an action: (kind, canonical target)."""
    def _key(action: dict) -> str {
        return action_key(action.get("action", ""), action.get("target", {}));
    }

    """True when `action` is named in `names` either by its kind or by its
    exact action_key. Lets a test target one action precisely, or a whole kind
    at once."""
    def _matches(action: dict, names: list) -> bool {
        if action.get("action", "") in names {
            return True;
        }
        if self._key(action) in names {
            return True;
        }
        return False;
    }

    """Apply one action. Returns {"status":"ack"|"nak","action","target"}.

    NAK semantics:
      * nak_forever  -> always NAK (never recorded as applied)
      * nak_actions  -> NAK on delivery #1 only, ACK from delivery #2 on
    ACK is idempotent: the same action_key is recorded in `applied` exactly
    once no matter how many times it is delivered."""
    def apply(action: dict, now_ms: int) -> dict {
        key = self._key(action);
        n = self._deliveries.get(key, 0) + 1;
        self._deliveries[key] = n;

        kind = action.get("action", "");
        target = action.get("target", {});

        if self._matches(action, self.nak_forever) {
            return {"status": "nak", "action": kind, "target": target};
        }
        if self._matches(action, self.nak_actions) and (n == 1) {
            return {"status": "nak", "action": kind, "target": target};
        }

        if key not in self._applied_keys {
            self._applied_keys[key] = True;
            self.applied.append(dict(action));
        }
        return {"status": "ack", "action": kind, "target": target};
    }

    """Post-apply health probe. Returns {"action","target","health":"pass"|"fail"}.
    An action in `health_fail` (by kind or key) reports fail — the coordinator
    treats that as the trigger to roll the action back."""
    def health_probe(action: dict, now_ms: int) -> dict {
        health = "pass";
        if self._matches(action, self.health_fail) {
            health = "fail";
        }
        return {
            "action": action.get("action", ""),
            "target": action.get("target", {}),
            "health": health
        };
    }

    """Roll one action back. Idempotently removes it from `applied` and records
    it in `rolled_back`. Returns {"action","target","status":"rolled_back"}."""
    def rollback(action: dict, now_ms: int) -> dict {
        key = self._key(action);

        keep: list = [];
        for a in self.applied {
            if self._key(a) != key {
                keep.append(a);
            }
        }
        self.applied = keep;

        already: list = [self._key(x) for x in self.rolled_back];
        if key not in already {
            self.rolled_back.append(dict(action));
        }
        return {
            "action": action.get("action", ""),
            "target": action.get("target", {}),
            "status": "rolled_back"
        };
    }

    """The audit list of applied action KINDS, sorted — convenience for tests."""
    def applied_kinds -> list {
        return sorted([a.get("action", "") for a in self.applied]);
    }

    """True iff no revocation-class action was ever applied. A degraded/monitor
    -only run must be able to assert this."""
    def zero_revocation_applied -> bool {
        for a in self.applied {
            if is_revocation(a.get("action", "")) {
                return False;
            }
        }
        return True;
    }
}
