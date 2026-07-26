# app/services/ids.jac -- identifier minting for domain records.
#
# Ids are opaque, random, and server-generated. A client never supplies the id
# of a record it is creating (the one exception is `tenant_id` on CreateTenant,
# which the contract makes a caller-chosen slug and which is validated and
# uniqueness-checked before use). Sequential or guessable ids would turn every
# list endpoint into an enumeration oracle for records the caller cannot see.
#
# 128 bits of urandom via uuid4, hex-encoded and prefixed so a stray id in a log
# is self-describing.

import uuid;

"""A fresh opaque id with a short type prefix, e.g. "p_9f2c...". """
def:pub mint(prefix: str) -> str {
    return prefix + "_" + uuid.uuid4().hex;
}

"""Project id."""
def:pub project_id() -> str { return mint("p"); }

"""Task id."""
def:pub task_id() -> str { return mint("t"); }

"""Comment id."""
def:pub comment_id() -> str { return mint("c"); }

"""Membership id."""
def:pub membership_id() -> str { return mint("m"); }

"""Invite id."""
def:pub invite_id() -> str { return mint("i"); }

"""Export job id."""
def:pub export_id() -> str { return mint("x"); }

"""Integration call id."""
def:pub call_id() -> str { return mint("ic"); }

"""A high-entropy bearer secret (an invite token). Returned to the caller once
and never stored -- only its SHA-256 hash is persisted."""
def:pub secret() -> str {
    return uuid.uuid4().hex + uuid.uuid4().hex;
}
