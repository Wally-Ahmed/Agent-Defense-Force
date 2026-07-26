# FROZEN CONTRACT — do not edit without conductor approval. Consumed by: T1 gateway, T2 guard/authz, T3 domain walkers, T4 monitor/detection, T5 responder/containment, T6 dashboard

Human-readable reference for the audit vocabulary. The machine-readable source of
truth is `contracts/audit_event_contract.jac` (`ACTIONS`, `DENY_REASONS`) and
`contracts/containment_contract.jac` (`CONTAINMENT_KINDS`). **Import those
constants — never retype the strings.**

---

## 1. Action vocabulary

Closed set. `AuditEvent.action` is always exactly one of these 38 values. Anything
not on this list is a bug, not a new action.

### auth (8)

| Action | Meaning |
| --- | --- |
| `auth.register` | New principal created an account |
| `auth.login` | Successful authentication |
| `auth.login_failed` | Failed authentication — **emitted by the gateway** |
| `auth.logout` | Explicit session termination |
| `auth.session_expired` | Session rejected because it aged out |
| `auth.token_issued` | API token minted |
| `auth.token_revoked` | API token invalidated |
| `auth.reauth_required` | Step-up authentication demanded before proceeding |

### tenant (2)

| Action | Meaning |
| --- | --- |
| `tenant.create` | New tenant provisioned |
| `tenant.read` | Tenant record read |

### member (4)

| Action | Meaning |
| --- | --- |
| `member.invite` | Invitation issued |
| `member.accept` | Invitation accepted, membership created |
| `member.role_change` | Role changed on an existing membership |
| `member.remove` | Membership revoked |

### project (5)

`project.create` · `project.read` · `project.list` · `project.update` · `project.delete`

### task (6)

`task.create` · `task.read` · `task.list` · `task.update` · `task.delete` · `task.assign`

### comment (4)

`comment.create` · `comment.read` · `comment.list` · `comment.delete`

### export / search / integration (4)

| Action | Meaning |
| --- | --- |
| `export.request` | Export job requested |
| `export.download` | Export artifact actually fetched — watch `result_count` / `resp_bytes` |
| `search.query` | Cross-record search — watch `result_count` |
| `integration.call` | Outbound or inbound integration invocation |

### containment (5)

| Action | Meaning |
| --- | --- |
| `containment.propose` | A `ContainmentAction` was proposed |
| `containment.apply` | A `Control` was written and made active |
| `containment.verify` | Health check run against an applied control |
| `containment.expire` | Control lapsed at TTL |
| `containment.rollback` | Control reverted to `prior_state` |

---

## 2. Deny reason codes

Closed set of 15. `AuditEvent.reason` holds exactly one of these when
`outcome == "deny"`, and is `""` when `outcome == "allow"`. These are **codes, not
prose** — never write a human sentence into `reason`.

| Code | Emitted when |
| --- | --- |
| `NO_SESSION` | No session or credential presented |
| `SESSION_EXPIRED` | Session present but past expiry |
| `TOKEN_REVOKED` | API token presented but revoked (or killed by containment) |
| `NOT_A_MEMBER` | Principal has no membership in the target tenant |
| `INSUFFICIENT_ROLE` | Membership exists but role is too low for the action |
| `TENANT_MISMATCH` | `actor_tenant_id != tenant_id` — a crossing attempt |
| `NOT_FOUND` | Target does not exist, or is masked as non-existent |
| `VALIDATION_FAILED` | Request body/params failed validation |
| `RATE_LIMITED` | Rate limit or throttle control tripped — **emitted by the gateway** |
| `CSRF_INVALID` | CSRF token missing or wrong — **emitted by the gateway** |
| `SUSPENDED` | Principal suspended by a containment control |
| `SOURCE_BLOCKED` | Source IP/ASN blocked by a containment control |
| `REAUTH_REQUIRED` | Step-up auth required before this action |
| `READONLY_MODE` | Feature placed in read-only mode by a containment control |
| `CTX_UNVERIFIED` | `ctx.sig` missing, failed HMAC verification, or `issued_at_ms` older than 30s — the request is treated as **fully unauthenticated** |

### `CTX_UNVERIFIED` and the trust boundary

The Jac backend on `:8000` binds `0.0.0.0` and cannot be restricted to loopback, so
the gateway on `:8080` is bypassable. Every `ctx` is therefore HMAC-signed by the
gateway and verified by `guard()` before any field of it is trusted. See the trust
model block in `contracts/req_ctx_contract.jac` for the canonicalization rule and
the constant-time-compare requirement.

When `guard()` denies with `CTX_UNVERIFIED` it MUST emit the audit event with
`actor_principal_id: ""` and only the **observed** transport facts — never the
claimed `src_ip`, `session_id`, or `csrf_ok` from the unverified payload. Treating
a forged ctx's claims as fact would poison the very audit trail used to detect the
bypass.

---

## 3. Emission map

**The governing rule: every `guard()` call emits exactly one `AuditEvent`.**
Not zero, not two.

### Who emits what

| Emitter | Emits | Notes |
| --- | --- | --- |
| **Gateway** | `auth.login_failed` | Never reaches a walker |
| **Gateway** | any `RATE_LIMITED` denial | Never reaches a walker |
| **Gateway** | any `CSRF_INVALID` denial | Never reaches a walker |
| **`guard()`** | exactly one event per call | Both allow and deny outcomes |
| **Domain walkers** | *nothing* | They emit **no second event** |

### Why it is shaped this way

The three gateway-emitted cases are rejected *before* walker dispatch, so no
`guard()` call ever happens for them — the gateway is the only component in a
position to record them. Everything past the gateway funnels through `guard()`,
which is therefore the single choke point where the audit record is written.

Because `guard()` already emitted, a domain walker that also emitted would
double-count every request — corrupting the very `result_count` and rate signals
that T4 monitor/detection reads. **If you are writing a domain walker: call
`guard()`, then do your work, and emit nothing.**

### Consequences to build against

- Event count per request is `1` (guard path) or `1` (gateway-reject path) —
  never `0`, never `2`.
- A request denied at the gateway has **no** walker-level context: `target_id`,
  `result_count`, and similar walker-populated fields stay at their defaults.
- `seq` is monotonic **per session**, and `prev_event_id` chains to the previous
  event in that same session — both are maintained across gateway and `guard()`
  emissions alike, so the chain has no holes.

---

## 4. Severity assignment rules

> **Conductor note:** the frozen spec fixed the severity *enum*
> (`info | notice | warn | high`) but not the enum-to-condition mapping. The table
> below is the working default so parallel tracks have something concrete to build
> against. Flag to the conductor before treating it as immutable.

Evaluate **top-down and stop at the first match** — the highest matching rule wins.

### `high`

Escalate immediately. Any one of:

- `outcome == "deny"` with `reason == "CTX_UNVERIFIED"` — a forged or replayed context, i.e. a direct attempt to bypass the gateway. Always `high`.
- `outcome == "deny"` with `reason` in `TENANT_MISMATCH`, `SOURCE_BLOCKED`, or `SUSPENDED` — an active boundary being tested.
- `target_sensitivity == "canary"`, on **any** outcome. Canaries have no legitimate traffic; a touch is a signal.
- Any `containment.*` action, i.e. the system is actively defending itself.
- An allowed action with an anomalous `result_count` / `resp_bytes` — the bulk-exfiltration signal, most importantly on `export.download` and `search.query`.

### `warn`

- `outcome == "error"` (any action).
- `outcome == "deny"` for any reason not already escalated to `high`.
- Repeated `auth.login_failed` from one `client_fp` or `src_ip`.

### `notice`

Allowed, but security-relevant — the events you want in the timeline when
reconstructing an incident:

- Any `auth.*` success: `auth.login`, `auth.logout`, `auth.token_issued`, `auth.token_revoked`.
- Any privilege or membership change: `member.invite`, `member.accept`, `member.role_change`, `member.remove`.
- Any data egress: `export.request`, `export.download`.
- `tenant.create`, and any `integration.call`.
- Any allowed action where `target_sensitivity == "confidential"`.

### `info`

Everything else: ordinary allowed reads, lists, and writes against
`normal`-sensitivity targets — the `project.*`, `task.*`, and `comment.*` bulk.

### Quick reference

| Severity | One-line trigger |
| --- | --- |
| `high` | Boundary probe, canary touch, containment activity, or bulk egress |
| `warn` | Any deny or error |
| `notice` | Allowed but security-relevant: auth, membership, egress, confidential |
| `info` | Routine allowed activity on normal-sensitivity targets |
