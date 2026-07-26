# app/services/validate.jac -- input validation for every domain walker.
#
# Walkers receive `has` fields deserialized straight from a JSON body. Jac
# guarantees the TYPE (str/int/bool/list/dict) and nothing else: length, charset,
# enum membership and range are all still attacker-controlled. Every walker runs
# its inputs through this module before the input reaches the graph.
#
# The style is accumulate-then-report: a validator appends to an `errs` list and
# returns a bool, so a walker collects every problem in one pass and returns one
# VALIDATION_FAILED with a `details` array. Short-circuiting on the first error
# would turn the endpoint into a field-probing oracle by response timing.
#
# NOTE: there is no SQL, no query string, and no interpolation of user input into
# any executable form anywhere in this application -- the graph is the database
# and every write goes through a typed node constructor. Validation here is about
# shape and size, not about escaping.

import re;

# Ids we mint and ids we accept back. Deliberately narrow: an id is an opaque
# handle, so anything outside this charset is a probe, not a typo.
glob:pub ID_PATTERN: str = r"^[A-Za-z0-9_\-]{1,64}$";

# RFC-5322 in full is a trap; this is the pragmatic subset every real signup uses.
glob:pub EMAIL_PATTERN: str = r"^[^@\s]{1,64}@[A-Za-z0-9.\-]{1,190}\.[A-Za-z]{2,24}$";

# Field size ceilings. These bound memory and the audit record alike.
glob:pub MAX_TITLE: int = 200;
glob:pub MAX_NAME: int = 120;
glob:pub MAX_KEY: int = 32;
glob:pub MAX_BODY: int = 4000;
glob:pub MAX_QUERY: int = 200;
glob:pub MAX_CURSOR: int = 512;

"""Record one field-level failure."""
def:pub add_err(errs: list, field: str, message: str) -> bool {
    errs.append({"field": field, "message": message});
    return False;
}

"""A required string of bounded length. Rejects non-str, empty, and oversize."""
def:pub v_str(
    errs: list, field: str, value: object, min_len: int = 1, max_len: int = 200
) -> bool {
    if not isinstance(value, str) {
        return add_err(errs, field, "must be a string");
    }
    n = len(value);
    if n < min_len {
        return add_err(errs, field, f"must be at least {min_len} characters");
    }
    if n > max_len {
        return add_err(errs, field, f"must be at most {max_len} characters");
    }
    return True;
}

"""An optional string: absent ("") passes, present must satisfy v_str."""
def:pub v_opt_str(errs: list, field: str, value: object, max_len: int = 200) -> bool {
    if isinstance(value, str) and value == "" {
        return True;
    }
    return v_str(errs, field, value, 1, max_len);
}

"""An opaque identifier: bounded length, restricted charset."""
def:pub v_id(errs: list, field: str, value: object) -> bool {
    if not v_str(errs, field, value, 1, 64) {
        return False;
    }
    if re.match(ID_PATTERN, str(value)) is None {
        return add_err(errs, field, "is not a valid identifier");
    }
    return True;
}

"""An optional identifier: "" passes, anything else must be a valid id."""
def:pub v_opt_id(errs: list, field: str, value: object) -> bool {
    if isinstance(value, str) and value == "" {
        return True;
    }
    return v_id(errs, field, value);
}

"""Membership of a closed enum. The allowed list always comes from a contract
constant or a module-level table -- never from a literal at the call site."""
def:pub v_enum(errs: list, field: str, value: object, allowed: list) -> bool {
    if not isinstance(value, str) {
        return add_err(errs, field, "must be a string");
    }
    if value not in allowed {
        return add_err(errs, field, "is not an accepted value");
    }
    return True;
}

"""An optional enum: "" passes (meaning "leave unchanged")."""
def:pub v_opt_enum(errs: list, field: str, value: object, allowed: list) -> bool {
    if isinstance(value, str) and value == "" {
        return True;
    }
    return v_enum(errs, field, value, allowed);
}

"""An email address, bounded and shaped."""
def:pub v_email(errs: list, field: str, value: object) -> bool {
    if not v_str(errs, field, value, 3, 254) {
        return False;
    }
    if re.match(EMAIL_PATTERN, str(value)) is None {
        return add_err(errs, field, "is not a valid email address");
    }
    return True;
}

"""An integer within an inclusive range. bool is rejected: in Python `True` is
an int, and a client sending `true` for a limit is not sending 1."""
def:pub v_int(errs: list, field: str, value: object, lo: int, hi: int) -> bool {
    if isinstance(value, bool) or not isinstance(value, int) {
        return add_err(errs, field, "must be an integer");
    }
    if value < lo or value > hi {
        return add_err(errs, field, f"must be between {lo} and {hi}");
    }
    return True;
}

"""A string that must match a whole-string regular expression.

The pattern always comes from a module-level constant, never from input."""
def:pub v_pattern(errs: list, field: str, value: object, pattern: str, max_len: int = 200) -> bool {
    if not v_str(errs, field, value, 1, max_len) {
        return False;
    }
    if re.match(pattern, str(value)) is None {
        return add_err(errs, field, "does not match the required format");
    }
    return True;
}

"""A list of bounded length whose entries are all short strings."""
def:pub v_str_list(errs: list, field: str, value: object, max_items: int = 20, max_len: int = 64) -> bool {
    if not isinstance(value, list) {
        return add_err(errs, field, "must be an array");
    }
    if len(value) > max_items {
        return add_err(errs, field, f"must have at most {max_items} entries");
    }
    for item in value {
        if not isinstance(item, str) or len(item) < 1 or len(item) > max_len {
            return add_err(errs, field, "entries must be strings of 1-" + str(max_len) + " characters");
        }
    }
    return True;
}

"""True when nothing was recorded."""
def:pub clean(errs: list) -> bool {
    return len(errs) == 0;
}
