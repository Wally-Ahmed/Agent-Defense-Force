# tests/test_keys.test.jac — the startup key-strength proof.
#
# THE THREAT. app/security/keys.jac is the one place that decides whether the
# process is allowed to run at all, and every ctx HMAC in the system is keyed by
# what it hands back. Its original check measured only LENGTH, so `" " * 32`,
# `"a" * 32`, `"0" * 64` and `"ab" * 32` all cleared the bar. Each of those is
# guessable in about one attempt, which makes the ctx signature forgeable by
# anyone who guesses it -- the exact failure the signature exists to prevent.
# A key that weak is not a weaker key, it is no key.
#
# These arrive by accident, not by malice: an operator holding down a character
# to "just get it started", a shell script that quoted an empty variable into
# existence, a fixture nobody revisited. The startup check is the only thing
# standing between that accident and a signed-looking production run.
#
# THE MITIGATION UNDER TEST. require_env() now rejects whitespace-only input,
# measures length against the whitespace-FREE core so padding cannot reach the
# bar, and requires MIN_DISTINCT_CHARS distinct characters. This file asserts
# each degenerate shape is refused and that real key material still passes.
#
# WHAT MUST NOT REGRESS. The refusal to start without the variable at all. A
# test suite that only checked "weak keys are rejected" would happily pass
# against a build that had quietly grown a default key, so the no-default
# property is asserted here too, right next to the new checks.
#
# NO CREDENTIAL IS EMBEDDED HERE. The accepted-key cases use a freshly generated
# throwaway and an obviously-inert readable literal. Neither authenticates
# anything and neither is ever a default.

import os;
import secrets;
import from app.security.keys {
    require_env, ctx_signing_key, MIN_KEY_BYTES, MIN_DISTINCT_CHARS
}

# --------------------------------------------------------------------------
# Probe harness.
#
# The checks live in require_env(), which is generic, so the degenerate values
# are pushed through a SCRATCH variable rather than APP_CTX_SIGNING_KEY. Two
# reasons: the rest of the suite shares this process and must keep a working
# signing key, and testing the generic function is what proves the bar applies
# to every secret rather than to one hard-coded name.
# --------------------------------------------------------------------------

glob PROBE: str = "APP_TEST_KEY_PROBE";

"""Set the probe variable to `value`, call require_env, and report what happened.

Returns the RuntimeError message on refusal or "" on acceptance. The variable is
removed again before returning either way, so one case can never leak into the
next."""
def refusal_for(value: str) -> str {
    os.environ[PROBE] = value;
    message = "";
    try {
        require_env(PROBE, MIN_KEY_BYTES);
    } except RuntimeError as e {
        message = str(e);
    }
    del os.environ[PROBE];
    return message;
}

"""True when `value` is refused. Reads as the assertion it supports."""
def is_refused(value: str) -> bool {
    return refusal_for(value) != "";
}

# --------------------------------------------------------------------------
# The bar itself. Pinned, so silently lowering it fails a test rather than
# quietly widening what counts as a key.
# --------------------------------------------------------------------------

test "the strength bar is 32 bytes and 8 distinct characters" {
    assert MIN_KEY_BYTES == 32;
    assert MIN_DISTINCT_CHARS == 8;
}

# --------------------------------------------------------------------------
# Degenerate keys are refused.
# --------------------------------------------------------------------------

test "a whitespace-only key of 32+ characters is refused" {
    # THE ORIGINAL BUG. 40 bytes of spaces passed a byte-length check with room
    # to spare. It is an unset variable wearing a disguise.
    assert is_refused(" " * 40);

    # Not just the space character -- tabs and newlines pad just as well, and a
    # mixed run of them is what a broken heredoc or a stray quote actually
    # produces.
    assert is_refused("\t" * 40);
    assert is_refused(" \t\n\r" * 10);
}

test "a short key padded with whitespace to 32+ characters is refused" {
    # THE BYPASS THE LENGTH CHECK INVITED. If padding counted toward the
    # minimum, then "pad it until it starts" would be a working answer to the
    # error message -- and the error message would be teaching the operator to
    # defeat the control it just enforced.
    padded = ("  " * 13) + "abcdef";
    assert len(padded) >= MIN_KEY_BYTES;
    assert is_refused(padded);

    # Interior whitespace is padding too, so trimming the ends is not enough.
    interior = "ab" + (" " * 30) + "cd";
    assert len(interior) >= MIN_KEY_BYTES;
    assert is_refused(interior);

    # And leading/trailing padding around real-looking material still fails,
    # because only the core is measured.
    assert is_refused("   " + "abc" + (" " * 26));
}

test "a single-repeated-character key of 32+ characters is refused" {
    # Long, whitespace-free, and clears the length bar -- refused purely on
    # having one byte of variety. This is the check that length alone cannot
    # express.
    assert is_refused("a" * 40);
    assert is_refused("0" * 64);
    assert is_refused("k" * 40);
}

test "a short repeating cycle of characters is refused" {
    # "ab" * 32 is 64 characters and 2 distinct ones. Length is not entropy.
    assert is_refused("ab" * 32);
    assert is_refused("abab" * 16);

    # Seven distinct characters sits one below the bar and must still fail --
    # proving the boundary is where it is claimed to be, not merely somewhere
    # near it.
    assert is_refused("abcdefg" * 8);
}

test "the variable being unset is still refused -- there is no default key" {
    # THE PROPERTY THAT MUST SURVIVE THE FIX. Every test above adds a NEW way to
    # fail; none of them may have added a way to succeed. If a default or
    # generated-on-first-run key ever appears, this is the test that catches it.
    if PROBE in os.environ {
        del os.environ[PROBE];
    }
    raised = False;
    try {
        require_env(PROBE, MIN_KEY_BYTES);
    } except RuntimeError as e {
        raised = True;
    }
    assert raised;

    # An empty string is an unset variable by another name.
    assert is_refused("");
}

# --------------------------------------------------------------------------
# Real key material is accepted. Without these, "reject everything" would pass.
# --------------------------------------------------------------------------

test "a real 64-hex-character key is accepted and returned unchanged" {
    # Exactly what the error messages tell an operator to generate, and what
    # `openssl rand -hex 32` produces. If this ever fails, the bar has been set
    # somewhere that breaks real deployments.
    real = secrets.token_hex(32);
    assert len(real) == 64;

    os.environ[PROBE] = real;
    got = require_env(PROBE, MIN_KEY_BYTES);
    del os.environ[PROBE];

    # Byte-identical. A validator that trimmed or normalised the key would
    # silently desynchronise the two ends of the HMAC.
    assert got == real;
}

test "a readable non-random test key is accepted" {
    # Human-readable fixtures are legitimate and must not be collateral damage:
    # 32 characters, 14 distinct, no whitespace. The bar rejects degenerate
    # input, not merely un-random input.
    readable = "test-signing-key-for-unit-tests!";
    assert len(readable) == 32;
    assert is_refused(readable) == False;

    # The boundary from the accepting side: exactly 8 distinct characters is
    # allowed, confirming the comparison is >= and not >.
    at_bar = "abcdefgh" * 4;
    assert len(set(at_bar)) == MIN_DISTINCT_CHARS;
    assert is_refused(at_bar) == False;
}

# --------------------------------------------------------------------------
# The messages. An error that leaks the value it rejected turns a startup
# failure into a credential disclosure -- into logs, terminals and screen shares.
# --------------------------------------------------------------------------

test "refusal messages are distinct, actionable, and never echo the key" {
    whitespace = refusal_for(" " * 40);
    padded = refusal_for(("  " * 13) + "abcdef");
    repeated = refusal_for("a" * 40);

    # Each failure mode says something different, so an operator can tell WHICH
    # rule they tripped without having to read the source.
    assert whitespace != padded;
    assert padded != repeated;
    assert whitespace != repeated;

    for message in [whitespace, padded, repeated] {
        assert message.startswith("FATAL: ");
        assert PROBE in message;

        # THE POINT. The rejected value never appears in the text -- not whole,
        # and not as the recognisable run it was built from.
        assert "aaaa" not in message;
        assert "abcdef" not in message;
        assert "                " not in message;
    }

    # Each message names its own cause.
    assert "whitespace" in whitespace;
    assert "non-whitespace bytes" in padded;
    assert "distinct characters" in repeated;
}

# --------------------------------------------------------------------------
# The live accessor. Everything above exercises the generic helper; this proves
# the real APP_CTX_SIGNING_KEY path inherits the same refusal.
# --------------------------------------------------------------------------

test "ctx_signing_key() itself refuses a degenerate APP_CTX_SIGNING_KEY" {
    # The suite shares this process and needs a working key afterwards, so the
    # original is restored BEFORE the assertion runs -- a failure here must not
    # take the remaining tests down with it.
    original = os.environ.get("APP_CTX_SIGNING_KEY", "");

    os.environ["APP_CTX_SIGNING_KEY"] = " " * 40;
    whitespace_raised = False;
    try {
        ctx_signing_key();
    } except RuntimeError as e {
        whitespace_raised = True;
    }

    os.environ["APP_CTX_SIGNING_KEY"] = "a" * 40;
    repeated_raised = False;
    try {
        ctx_signing_key();
    } except RuntimeError as e {
        repeated_raised = True;
    }

    os.environ["APP_CTX_SIGNING_KEY"] = original;

    assert whitespace_raised;
    assert repeated_raised;

    # The environment really was put back: the live key still works, so nothing
    # after this test is running against a corrupted signing key.
    assert len(ctx_signing_key()) >= MIN_KEY_BYTES;
}
