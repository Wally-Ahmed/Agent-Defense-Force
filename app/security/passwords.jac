# app/security/passwords.jac — password storage and the generic-failure rule.
#
# bcrypt, cost 12. Not sha256, not pbkdf2-with-a-shrug, not "hashed" with a
# static salt. Cost 12 is the point at which a verify still fits comfortably
# inside a request and an offline cracker does not.
#
# THE GENERIC-FAILURE RULE. `verify_password` is written so that a login attempt
# against a NON-EXISTENT account costs the same as one against a real account
# with the wrong password. If a miss returned early, the response-time
# difference would be a free account-enumeration oracle: an attacker learns
# which of ten thousand leaked emails are customers here, without ever
# authenticating. So a miss verifies the supplied password against a fixed dummy
# hash and then returns False. Same work, same latency, same answer.

import bcrypt;
import hmac;
import hashlib;
import secrets;

# bcrypt work factor. Raising this is safe (old hashes carry their own cost in
# the string and still verify); lowering it is not.
glob:pub BCRYPT_ROUNDS: int = 12;

# bcrypt silently truncates at 72 bytes, so anything past that contributes
# nothing to the hash. Rejecting long inputs is honest; accepting and truncating
# them is a password that is shorter than the user believes it to be.
glob:pub MAX_PASSWORD_BYTES: int = 72;
glob:pub MIN_PASSWORD_CHARS: int = 12;

# A real bcrypt hash of a value nobody can present, used only to burn the same
# CPU on a miss as on a hit. It is not a credential: no principal carries it, so
# there is no password that authenticates against it. It is generated fresh at
# import from random bytes, which is why there is no literal digest in this file
# for anyone to mistake for a backdoor.
glob DUMMY_HASH: str = "";

"""Build the constant-time decoy hash. Called once, at import."""
def _init_dummy() -> str {
    filler = secrets.token_bytes(32);
    digest = bytes(bcrypt.hashpw(filler, bcrypt.gensalt(rounds=BCRYPT_ROUNDS)));
    return digest.decode("utf-8");
}

with entry {
    DUMMY_HASH = _init_dummy();
}

"""Validate a candidate password. Returns "" when acceptable, else a reason.

The reason is shown only on REGISTRATION, where the account does not exist yet
and there is nothing to enumerate. Login never surfaces it."""
def:pub password_complaint(password: str) -> str {
    if len(password) < MIN_PASSWORD_CHARS {
        return "password must be at least " + str(MIN_PASSWORD_CHARS) + " characters";
    }
    if len(password.encode("utf-8")) > MAX_PASSWORD_BYTES {
        return "password must be at most " + str(MAX_PASSWORD_BYTES) + " bytes";
    }
    return "";
}

"""bcrypt-hash a password at cost 12. Raises if the password is unacceptable."""
def:pub hash_password(password: str) -> str {
    complaint = password_complaint(password);
    if complaint != "" {
        raise ValueError(complaint);
    }
    digest = bytes(bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=BCRYPT_ROUNDS)));
    return digest.decode("utf-8");
}

"""Check a password against a stored hash in constant-ish time.

`stored` of "" means the account was not found. That case deliberately performs
a full bcrypt verify against DUMMY_HASH before returning False, so the caller
cannot leak account existence through timing."""
def:pub verify_password(password: str, stored: str) -> bool {
    candidate = stored;
    is_real = stored != "";
    if not is_real {
        candidate = DUMMY_HASH;
    }
    try {
        matched = bool(bcrypt.checkpw(password.encode("utf-8"), candidate.encode("utf-8")));
    } except Exception as e {
        # A corrupt or non-bcrypt stored value must fail closed, never pass.
        return False;
    }
    if not is_real {
        return False;
    }
    return matched;
}

# --------------------------------------------------------------------------
# Bearer secrets: session ids, token jtis, invite tokens.
# --------------------------------------------------------------------------

"""A cryptographically random, URL-safe bearer secret.

`secrets`, never `random` -- Mersenne Twister output is reconstructable from a
few hundred observed values, which for session ids means predicting the next
one."""
def:pub new_secret(nbytes: int = 32) -> str {
    return secrets.token_urlsafe(nbytes);
}

"""SHA-256 hex of a bearer token. Invites are stored as this, never in the
clear, so a read of the graph does not hand over a working invite."""
def:pub token_digest(token: str) -> str {
    return hashlib.sha256(token.encode("utf-8")).hexdigest();
}

"""Constant-time comparison of two bearer secrets."""
def:pub secret_equals(a: str, b: str) -> bool {
    return hmac.compare_digest(a, b);
}
