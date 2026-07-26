# Attack sandbox fixtures

Controlled, synthetic seed data for the **authorized** attack demo. Nothing here
is a real credential and nothing here is a backdoor.

| File | Role |
| --- | --- |
| `seed.json` | Authoritative fixture: tenants, resources + sensitivity, spray targets, both service accounts, source IPs, injection payloads. Read by `driver.py`, `benign.py`, `mock_app.py`, `reset.py`. |
| `compromised.json` | Focused view of the **pre-compromised** identity and how its Bearer token is minted. |
| `state.json` | Runtime baseline written by `reset.py` (accounts active, sessions cleared, services active, containment cleared). Deterministic — regenerated, never hand-edited. |

## The compromised identity — obtained OUTSIDE the app, not a backdoor

`svc_ingest@northwind.test` is an **ordinary low-privilege service account**:
Membership `role = member` in tenant `t_acme`. It carries exactly the access any
member has and nothing more.

Its credential is a service-account API token (`Authorization: Bearer nwp_…`).
In the scenario the attacker obtained this token **outside the application** —
e.g. leaked from a compromised CI runner. The application itself is never
breached to get it. Per the frozen contract there is **no admin bypass, no debug
endpoint, no hidden route, and no header/param that relaxes authorization**; there
is no `/auth/*` path that hands an attacker a token.

**How the token is minted (documented, not a vulnerability):** `reset.py` installs
the token from this fixture and (in the live app) it is bcrypt-hashed into the
service-account table during seeding, exactly as an operator provisions any service
token. The literal `nwp_fixture_…` string only authenticates against a loopback
sandbox that `reset.py` has seeded with its hash. It is not real secret material and
authenticates to nothing else.

The maliciousness is entirely in the **pattern** of use (enumeration, boundary
probing, rapid adaptation, source rotation, sensitivity climbing, cross-tenant
attempts) correlated across time — never in any single request, and never in a
privileged capability the token does not have.

## What it can and cannot reach

Reaches: normal-sensitivity projects/tasks/comments/search **within t_acme**.

Denied by ordinary authorization:
- admin-only operations → `403 INSUFFICIENT_ROLE`
- other tenants → `403 TENANT_MISMATCH`
- confidential / canary records → `404 NOT_FOUND` (unreachable by tenant-subtree
  traversal within its sensitivity ceiling — indistinguishable from a nonexistent id)
- the admin-gated export download → `403 INSUFFICIENT_ROLE`

## The canary is an ordinary record

`p_ac_999` (project), `tk_ac_9999` (task) and `ex_ac_canary_01` (export) are
**ordinary records this member legitimately cannot read**. The application has no
branch on `sensitivity == "canary"`, emits no special event for it, and alters no
response for it. The member is denied them by the **same authorization code path**
(and the same 404/403 outcomes) as any confidential record. The `canary` label
exists only so the external monitor knows which record was touched.

## The benign service account (negative control)

`svc_reporting@globex.test`, role `admin` in `t_globex`, drives `benign.py`. It is
**admin** (not member) because `RequestExport` is admin-only in the frozen contract
with no service-account scope exception — a legitimate reporting integration must be
able to export within its own tenant with zero denials. It still exhibits none of the
campaign's behavioural signals.

## Everything is synthetic

`.test` domains only; RFC-5737 documentation IPs (`192.0.2.0/24`, `198.51.100.0/24`,
`203.0.113.0/24`); RFC-5737 is also the only space allowed in `X-Forwarded-For`.
`token_id` values are opaque synthetic identifiers. No real credentials, secrets, or
tokens of any kind.
