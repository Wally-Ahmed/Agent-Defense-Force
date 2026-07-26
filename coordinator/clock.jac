# coordinator/clock.jac
#
# Injectable clock. The state machine NEVER calls time.time() directly: every
# timeout in TIMEOUTS_MS is evaluated against a Clock, so a test can advance
# 180 seconds of ASSESSING in zero wall-clock time and get a byte-identical
# artifact. Determinism is a property we test, so the clock has to be data.

import time;

obj Clock {
    # When frozen, now_ms() returns `t_ms` and only advance()/set() move it.
    has frozen: bool = True;
    has t_ms: int = 0;

    """Current epoch milliseconds (virtual when frozen, wall-clock otherwise)."""
    def now_ms -> int {
        if self.frozen {
            return self.t_ms;
        }
        return int(time.time() * 1000);
    }

    """Advance virtual time by `ms`. No-op on a wall-clock clock."""
    def advance(ms: int) -> int {
        if self.frozen {
            self.t_ms = (self.t_ms + ms);
        }
        return self.now_ms();
    }

    """Jump virtual time to an absolute epoch-ms value."""
    def set_ms(ms: int) -> int {
        if self.frozen {
            self.t_ms = ms;
        }
        return self.now_ms();
    }
}

"""A deterministic clock starting at a fixed, arbitrary-but-stable epoch."""
def frozen_clock(start_ms: int = 1769472000000) -> Clock {
    return Clock(frozen=True, t_ms=start_ms);
}

"""A real wall-clock clock, for production runs."""
def wall_clock -> Clock {
    return Clock(frozen=False, t_ms=0);
}
