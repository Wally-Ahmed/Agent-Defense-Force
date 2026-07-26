# containment/expiry.jac — containment that ends on its own.
#
# Every action this system applies carries a TTL, and the sweeper below is what
# makes that TTL mean something. It walks the platform roughly every fifteen
# seconds; any `active` ContainmentAction whose `expires_at` has passed is rolled
# back by restoring its `prior_state`, and the pair of events
# `containment.expire` + `containment.rollback` goes into the audit trail.
#
# WHY A SWEEPER AND NOT JUST AN EXPIRY CHECK. guard() already ignores an expired
# control (app/security/controls.is_live), so an expired action is harmless on
# the read path. That is not enough. An expired-but-present Control is a piece of
# state nobody is tracking: it survives in the gateway's JSON projection, it
# shows up in the dashboard, and — most importantly — as long as it exists the
# system has not actually returned to the state it was in before. "Reversible"
# has to mean the reversal HAPPENED, not that it would happen if anyone asked.
#
# ORDER OF THE TWO EVENTS. `expire` first, then `rollback`. They are different
# facts: the TTL elapsed (expire), and the prior state was restored (rollback).
# Emitting only one would leave a reader unable to distinguish "the clock ran
# out" from "a human intervened", and those want different follow-up.
#
# THE SWEEP IS IDEMPOTENT AND CRASH-SAFE. It reads state, acts, and re-reads;
# an action already `rolled_back` is skipped, so a sweeper restarted mid-pass
# does not double-roll-back or re-emit. Two sweepers running at once would each
# find the action in a terminal state after the first one moved it.
#
# WHAT IT WILL NOT DO. It never applies anything, never approves anything, never
# extends a TTL. Expiry is a one-way door in the safe direction: the only change
# this module can make to the world is to remove containment.

import time;

import from contracts.containment_contract { ContainmentAction, Control }
import from app.model.graph { get_platform, all_controls }
import from app.security.clock { now_ms, iso_ts, iso_to_ms }
import from containment.executor {
    Proposes, all_actions, find_action, rollback, emit_containment,
    control_surface, project_controls, _target_kind_of
}

# How often the scheduler wakes. ~15s per the containment design: short enough
# that a 600s pause_queue is not meaningfully extended, long enough that the
# sweep is free.
glob:pub SWEEP_INTERVAL_S: int = 15;

# States a sweep will act on. Deliberately just one: an action that is not
# `active` is either not applied or already finished.
glob:pub SWEEPABLE_STATES: list = ["active"];

"""True when this action's TTL has elapsed.

An action with `expires_at == ""` has no TTL — CONTAINMENT_KINDS gives
`ttl_s == 0` to revoke_session, revoke_token and rotate_service_credential,
which are permanent until someone rolls them back explicitly.

An UNPARSEABLE expires_at counts as expired. Same reasoning as
app/security/controls.is_live: a corrupt timestamp must fail towards releasing
containment, never towards a permanent lockout that nobody can find."""
def:pub is_expired(action: ContainmentAction, at_ms: int) -> bool {
    if action.expires_at == "" {
        return False;
    }
    deadline: int = iso_to_ms(action.expires_at, -1);
    return deadline <= at_ms;
}

"""Actions that are active and past their deadline, right now."""
def:pub due(at_ms: int) -> list {
    out: list = [];
    for a in all_actions() {
        act: ContainmentAction = a;
        if act.state in SWEEPABLE_STATES and is_expired(act, at_ms) {
            out.append(act);
        }
    }
    return out;
}

"""Expire one action: emit `containment.expire`, then roll it back completely.

Returns the per-action record the sweep reports. `surface_before` and
`surface_after` are the full Control set on either side of the restoration, so a
caller can assert equality against the pre-apply snapshot rather than trust
this function's own opinion of its work."""
def:pub expire_one(action: ContainmentAction, at_ms: int) -> dict {
    act: ContainmentAction = action;

    # Re-read state at the moment of acting. Between `due()` and here, another
    # sweeper or a human could have rolled this back already.
    if act.state not in SWEEPABLE_STATES {
        return {
            "action_id": act.action_id, "ok": True, "skipped": True,
            "state": act.state, "detail": "no longer active; nothing to expire"
        };
    }

    surface_before: list = control_surface();

    # 1. The TTL elapsed. That is a fact on its own and it is recorded first.
    act.state = "expired";
    emit_containment(act, "expire", "allow", "", _target_kind_of(act),
                     len(act.prior_state.get("controls", [])));

    # 2. The restoration. `rollback()` sets state to rolled_back, rewrites the
    #    gateway projection and emits containment.rollback.
    result: dict = rollback(act, "ttl expired at " + iso_ts(at_ms));

    return {
        "action_id": act.action_id,
        "ok": True,
        "skipped": False,
        "state": act.state,
        "kind": act.kind,
        "expires_at": act.expires_at,
        "restored": result["restored"],
        "surface_before": surface_before,
        "surface_after": control_surface(),
        "detail": "ttl elapsed; prior_state restored"
    };
}

"""One pass. Returns {swept, expired, at_ms, actions}."""
def:pub sweep_once(at_ms: int = 0) -> dict {
    now: int = at_ms if at_ms > 0 else now_ms();
    ready: list = due(now);
    handled: list = [];
    for a in ready {
        act: ContainmentAction = a;
        try {
            handled.append(expire_one(act, now));
        } except Exception as e {
            # One bad action must not stop the sweep — the others are still
            # holding containment that has already outlived its mandate.
            handled.append({
                "action_id": act.action_id, "ok": False, "skipped": False,
                "state": act.state, "detail": "expiry failed: " + str(e)
            });
        }
    }
    if len(handled) > 0 {
        project_controls();
    }
    return {
        "at_ms": now,
        "at": iso_ts(now),
        "swept": len(ready),
        "expired": len([h for h in handled if h["ok"] and (not h["skipped"])]),
        "actions": handled
    };
}

# --------------------------------------------------------------------------
# The scheduler.
# --------------------------------------------------------------------------

"""Sweep forever, every `interval_s` seconds.

`iterations > 0` bounds the loop, which is what tests and demo scripts use;
0 means run until the process is stopped. There is no way to make this function
apply a containment action — the only verb it reaches for is rollback."""
walker:pub ExpiryScheduler {
    has interval_s: int = SWEEP_INTERVAL_S;
    has iterations: int = 0;
    has verbose: bool = True;
    has passes: int = 0;
    has expired_total: int = 0;
    has log: list = [];

    can sweep with `root entry {
        n: int = 0;
        while self.iterations <= 0 or n < self.iterations {
            result: dict = sweep_once(now_ms());
            self.passes = self.passes + 1;
            self.expired_total = self.expired_total + int(result["expired"]);
            if int(result["expired"]) > 0 {
                self.log.append(result);
                if self.verbose {
                    print("[containment.expiry] " + str(result["at"]) + " expired "
                          + str(result["expired"]) + " action(s)");
                    rows: list = result["actions"];
                    for h in rows {
                        row: dict = h;
                        print("    " + str(row["action_id"]) + " -> "
                              + str(row["state"]) + ": " + str(row["detail"]));
                    }
                }
            }
            n = n + 1;
            if self.iterations <= 0 or n < self.iterations {
                time.sleep(float(self.interval_s));
            }
        }
    }
}

"""Run the scheduler without constructing a walker by hand."""
def:pub run_scheduler(interval_s: int = 0, iterations: int = 0, verbose: bool = True) -> dict {
    every: int = interval_s if interval_s > 0 else SWEEP_INTERVAL_S;
    w = ExpiryScheduler(interval_s=every, iterations=iterations, verbose=verbose);
    root spawn w;
    return {"passes": w.passes, "expired_total": w.expired_total, "log": w.log};
}

with entry:__main__ {
    # `jac run containment/expiry.jac` starts the real 15s scheduler.
    print("[containment.expiry] scheduler starting, interval="
          + str(SWEEP_INTERVAL_S) + "s");
    run_scheduler(SWEEP_INTERVAL_S, 0, True);
}
