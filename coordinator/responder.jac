# coordinator/responder.jac
#
# The interchangeability seam.
#
# The whole point of this file: swapping a mock responder for a real
# Cotal-backed one must be a CONFIG CHANGE, not a rewrite. The coordinator is
# therefore forbidden from ever naming a concrete implementation — it only ever
# holds a `ResponderHandle`, and it cannot tell mock from live.
#
# Transport reality this abstraction is modelling (contracts/mesh/channels.yaml):
#   - the incident reaches a responder on the durable `sec.incident` channel;
#   - the assessment comes BACK as a unicast DM (`to: coordinator`),
#     at-least-once, never on a channel — so no responder can observe another
#     responder's verdict. Independence is an ACL property, not a convention;
#   - `sec.deliberate` is opened ONLY on a split, for exactly one bounded round.
#
# NOTHING in this file holds a credential, a token, an endpoint or a host name.
# A live responder receives its transport object from config at construction.

import from typing { Any }
import from ids { RESPONDER_IDS }

# --------------------------------------------------------------------------
# The abstract handle — the ONLY responder type the coordinator may reference
# --------------------------------------------------------------------------

"""One responder, as seen by the coordinator.

Every method that touches the transport is abstract here. Trivial accessors
(`is_alive`, identity) are concrete because they are bookkeeping, not I/O."""
obj ResponderHandle {
    has responder_id: str = "";
    has kind: str = "abstract";        # "mock" | "live"

    """This responder's presence card as a dict, as of `now_ms`.

    Shape matches presence.PresenceCard.as_dict()."""
    def presence(now_ms: int) -> dict {
        raise NotImplementedError("abstract");
    }

    """Deliver `incident` to this responder.

    DURABLE channel semantics: acceptance is not an answer. A responder that is
    dead at delivery time must still accept the escalation and answer it after
    it reconnects — that is the backstop that keeps a restart from silently
    losing an incident."""
    def escalate(incident: dict, now_ms: int) -> None {
        raise NotImplementedError("abstract");
    }

    """Assessments READY at or before `now_ms`.

    Models the unicast DM inbox. At-least-once on the wire, at-MOST-once here:
    each assessment is returned exactly once and never again, so the caller
    cannot double-count a verdict."""
    def poll(now_ms: int) -> list {
        raise NotImplementedError("abstract");
    }

    """Open the one bounded deliberation round for `incident_id`.

    Only ever called on a split verdict, and only for round_no <=
    DELIBERATION_ROUNDS_MAX."""
    def open_deliberation(incident_id: str, round_no: int, now_ms: int) -> None {
        raise NotImplementedError("abstract");
    }

    """Force this responder dead as of `now_ms`."""
    def kill(now_ms: int) -> None {
        raise NotImplementedError("abstract");
    }

    """Bookkeeping only — the authoritative liveness answer is the presence
    card evaluated by PresenceStore.is_live."""
    def is_alive -> bool {
        return True;
    }

    """True when this handle is one of the five canonical responders."""
    def is_canonical -> bool {
        return self.responder_id in RESPONDER_IDS;
    }

    """Identity, for logs and the audit trail. Never includes transport detail."""
    def describe -> dict {
        return {"responder_id": self.responder_id, "kind": self.kind};
    }
}

# --------------------------------------------------------------------------
# The live implementation — an HONEST stub
# --------------------------------------------------------------------------

"""A real Cotal-backed responder.

Deliberately NOT implemented. Every transport method raises. This object exists
to prove the seam is real: the coordinator can hold one of these and type-checks
identically, and the day the Cotal transport is wired the change is confined to
this file plus one `kind` string in config.

`transport` is injected by config at construction and is opaque here. There are
no credentials, tokens, endpoints or host names in this module — by
construction, a literal in this file would be a bug."""
obj LiveResponder(ResponderHandle) {
    has transport: Any = None;     # injected by config; opaque to the coordinator

    def presence(now_ms: int) -> dict {
        raise NotImplementedError("live Cotal transport not wired: presence");
    }

    def escalate(incident: dict, now_ms: int) -> None {
        raise NotImplementedError("live Cotal transport not wired: escalate");
    }

    def poll(now_ms: int) -> list {
        raise NotImplementedError("live Cotal transport not wired: poll");
    }

    def open_deliberation(incident_id: str, round_no: int, now_ms: int) -> None {
        raise NotImplementedError("live Cotal transport not wired: open_deliberation");
    }

    def kill(now_ms: int) -> None {
        raise NotImplementedError("live Cotal transport not wired: kill");
    }

    def is_alive -> bool {
        raise NotImplementedError("live Cotal transport not wired: is_alive");
    }
}

"""Build a live responder. `opts` may carry a pre-built `transport` object,
never a secret: transports are constructed by the process that owns the
credentials and handed in already-authenticated."""
def live_factory(responder_id: str, opts: dict) -> ResponderHandle {
    return LiveResponder(
        responder_id=responder_id,
        kind="live",
        transport=opts.get("transport", None)
    );
}

# --------------------------------------------------------------------------
# The registry — how config picks an implementation by name
# --------------------------------------------------------------------------
# kind -> factory(responder_id: str, opts: dict) -> ResponderHandle

glob:pub RESPONDER_FACTORIES: dict[str, Any] = {};

"""Register `factory` under `kind`. Re-registering a kind replaces it, which is
how a test swaps an implementation without touching config."""
def register_responder_kind(kind: str, factory: Any) -> None {
    RESPONDER_FACTORIES[kind] = factory;
}

"""The kinds config may legally name, sorted."""
def known_responder_kinds -> list {
    return sorted(RESPONDER_FACTORIES.keys());
}

"""True when `kind` has a registered factory."""
def is_known_kind(kind: str) -> bool {
    return kind in RESPONDER_FACTORIES;
}

"""Construct a responder of `kind`.

The return type is `ResponderHandle` and nothing narrower — this is the line the
coordinator is not allowed to see past."""
def build_responder(kind: str, responder_id: str, opts: dict) -> ResponderHandle {
    if kind not in RESPONDER_FACTORIES {
        raise ValueError(
            f"unknown responder kind: {kind} (known: {known_responder_kinds()})"
        );
    }
    factory = RESPONDER_FACTORIES[kind];
    handle = factory(responder_id, opts);
    if not isinstance(handle, ResponderHandle) {
        raise TypeError(f"factory for kind {kind} did not return a ResponderHandle");
    }
    return handle;
}

with entry {
    register_responder_kind("live", live_factory);
}
