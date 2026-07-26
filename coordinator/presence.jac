# coordinator/presence.jac
#
# Layer 1 of the dead-responder defence: KV presence cards.
#
# Upstream has a known "dead agents go dark" bug — a dead agent keeps reporting
# `working` forever. If the coordinator trusted that, one dead responder would
# burn the entire 180s ASSESSING window before the slot resolved. Presence
# liveness fixes that: a slot whose card is missing, explicitly `offline`, or
# staler than PRESENCE_STALE_MS resolves to NO_VOTE IMMEDIATELY, and the run
# degrades on schedule instead of on a timeout.
#
# This module is pure data + comparisons. No I/O, no wall clock: every liveness
# question is answered against a `now_ms` handed in by the injected Clock.

import from ids { PRESENCE_HEARTBEAT_MS, PRESENCE_STALE_MS, PRESENCE_STATUSES }

# --------------------------------------------------------------------------
# The card
# --------------------------------------------------------------------------

"""One agent's liveness card as last written to the presence KV.

`heartbeat_ms` is the virtual-clock instant the agent last announced itself;
`seq` is a monotonic counter so a replayed/stuck card is distinguishable from a
fresh one carrying the same timestamp."""
obj PresenceCard {
    has agent: str = "";
    has status: str = "working";   # one of PRESENCE_STATUSES
    has heartbeat_ms: int = 0;
    has seq: int = 0;

    """Audit-stable dict form. Key order is fixed so snapshots are byte-stable."""
    def as_dict -> dict {
        return {
            "agent": self.agent,
            "status": self.status,
            "heartbeat_ms": self.heartbeat_ms,
            "seq": self.seq
        };
    }
}

"""True when `status` is one of the three frozen presence statuses."""
def is_valid_status(status: str) -> bool {
    return status in PRESENCE_STATUSES;
}

# --------------------------------------------------------------------------
# The store
# --------------------------------------------------------------------------

"""The presence KV surface the coordinator reads to decide who is answering.

Deliberately dumb: it never calls a responder and never waits. The coordinator
writes what responders report and then asks `is_live` / `dead_agents`."""
obj PresenceStore {
    has cards: dict[str, PresenceCard] = {};   # agent id -> PresenceCard

    """Upsert a card. Last write wins — the store keeps no history."""
    def put(card: PresenceCard) -> None {
        self.cards[card.agent] = card;
    }

    """The card for `agent`, or None when that agent has never reported."""
    def get(agent: str) -> PresenceCard | None {
        return self.cards.get(agent, None);
    }

    """Record a heartbeat at `now_ms`, bumping the card's seq.

    Creates the card on first heartbeat. `status` must be one of
    PRESENCE_STATUSES; anything else is a programming error, not a liveness
    signal, so it raises rather than silently registering as dead."""
    def heartbeat(agent: str, now_ms: int, status: str = "working") -> None {
        if not is_valid_status(status) {
            raise ValueError(f"unknown presence status: {status}");
        }
        prior = self.cards.get(agent, None);
        next_seq = 1;
        if prior is not None {
            next_seq = prior.seq + 1;
        }
        self.cards[agent] = PresenceCard(
            agent=agent,
            status=status,
            heartbeat_ms=now_ms,
            seq=next_seq
        );
    }

    """Explicitly mark `agent` offline. An offline card is never live, however
    fresh its heartbeat is — a clean shutdown must not have to wait out the
    staleness window."""
    def mark_offline(agent: str, now_ms: int) -> None {
        self.heartbeat(agent, now_ms, "offline");
    }

    """Is `agent` answering as of `now_ms`?

    False when: no card, OR status == "offline", OR the card is older than
    PRESENCE_STALE_MS. A heartbeat stamped in the future (clock skew between
    the responder and the coordinator's virtual clock) counts as live — skew is
    not evidence of death."""
    def is_live(agent: str, now_ms: int) -> bool {
        card = self.cards.get(agent, None);
        if card is None {
            return False;
        }
        if card.status == "offline" {
            return False;
        }
        age_ms = now_ms - card.heartbeat_ms;
        if age_ms <= 0 {
            return True;
        }
        return age_ms <= PRESENCE_STALE_MS;
    }

    """Age of `agent`'s card in ms, or -1 when there is no card."""
    def age_ms(agent: str, now_ms: int) -> int {
        card = self.cards.get(agent, None);
        if card is None {
            return -1;
        }
        return now_ms - card.heartbeat_ms;
    }

    """Sorted ids from `agents` that are NOT live as of `now_ms`.

    These are the slots the coordinator resolves to NO_VOTE immediately instead
    of waiting for the ASSESSING timeout."""
    def dead_agents(agents: list, now_ms: int) -> list {
        out: list = [];
        for a in agents {
            if not self.is_live(a, now_ms) {
                out.append(a);
            }
        }
        return sorted(out);
    }

    """Sorted ids from `agents` that ARE live as of `now_ms`."""
    def live_agents(agents: list, now_ms: int) -> list {
        out: list = [];
        for a in agents {
            if self.is_live(a, now_ms) {
                out.append(a);
            }
        }
        return sorted(out);
    }

    """agent -> card dict, key-sorted, for the audit trail."""
    def snapshot -> dict {
        out: dict = {};
        for a in sorted(self.cards.keys()) {
            card: PresenceCard = self.cards[a];
            out[a] = card.as_dict();
        }
        return out;
    }
}

"""A store pre-seeded with a fresh `working` card for every id in `agents`.

Convenience for tests and for the coordinator's ESCALATED entry, where every
responder is assumed live until its card goes stale."""
def seeded_store(agents: list, now_ms: int) -> PresenceStore {
    store = PresenceStore();
    for a in agents {
        store.heartbeat(a, now_ms, "working");
    }
    return store;
}
