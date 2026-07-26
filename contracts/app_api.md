# Northwind Projects — API contract (human summary)

**FROZEN 2026-07-26.** Machine-readable source of truth: [`app_api.openapi.yaml`](./app_api.openapi.yaml)
(OpenAPI 3.1.1, 23 paths / **33 operations** / 33 walkers, 1:1). Where this page and the YAML
disagree, the YAML wins.

Northwind Projects is an ordinary, competently secured multi-tenant project-management SaaS.
Fixture tenants: `t_acme`, `t_globex`, `t_initech`. Roles `owner > admin > member > viewer`
are held on a **Membership** (per user, per tenant) — never globally on a user.

---

## Two layers

| | Public | Internal |
|---|---|---|
| Base | `http://127.0.0.1:8080/api/v1` | `http://127.0.0.1:8000` (loopback only) |
| Shape | REST-ish, tenant-scoped paths | `POST /walker/<WalkerName>` |
| Body | per-operation JSON | walker `has` fields (same names, incl. path params) + injected `ctx` |
| Response | the payload | `{"status": <int>, "reports": [<payload>]}` — gateway unwraps `reports[0]` |
| Auth | `__Host-sid` cookie **or** `Authorization: Bearer nwp_…` | 90 s ES256 JWT minted by the gateway |

The gateway terminates cookies, CSRF, CORS, rate limits and containment flags, then injects a
trusted `ctx`. Any client-supplied `ctx` is stripped unconditionally. `ctx` integrity is bound
by a `ctx_hash` claim in the JWT which every walker verifies before reading a field —
so a forged `ctx` posted straight at the upstream fails, and the upstream is not routable from
outside loopback anyway. `ctx.tenant.role` is **transport only**: every walker re-reads the
Membership node from the graph and re-evaluates the role itself.

## Auth mechanics

- **`__Host-sid`** — opaque, HttpOnly, Secure, SameSite=Lax, Path=/, no Domain. Idle 30 min,
  absolute 12 h (never extended). Rotated on login / refresh / reauth.
- **CSRF** — double-submit: `__Host-csrf` cookie (not HttpOnly) + `X-CSRF-Token` header,
  constant-time compare, required on **every** cookie-authenticated non-GET including login and
  register. Not required for Bearer requests (no ambient authority).
- **`Authorization: Bearer nwp_…`** — service-account tokens, bcrypt-hashed (cost 12), bound to exactly
  one tenant + one Membership, carrying explicit scopes. Header only, never a query string,
  never on `/auth/*`. This is the credential class the compromised synthetic identity belongs to.
- **Step-up** — `auth_age_s <= 900` required on member role change, member remove, export request,
  export download, integration call; plus any identity flagged `require_reauth` by containment.
  Not applicable to Bearer principals (containment revokes those instead).
- **Pagination** — `limit` (default 25, **max 100**, rejected not clamped) + opaque HMAC-signed
  `cursor` bound to (tenant, endpoint, filter set), TTL 900 s. Enumeration works *within* these
  rules by design.

## Failure modes → status

`error.code` is always one of these fourteen, paired with exactly this status:

| 401 | 403 | 404 | 422 | 423 | 429 |
|---|---|---|---|---|---|
| `NO_SESSION` `SESSION_EXPIRED` `TOKEN_REVOKED` `REAUTH_REQUIRED` | `NOT_A_MEMBER` `INSUFFICIENT_ROLE` `TENANT_MISMATCH` `CSRF_INVALID` `SUSPENDED` `SOURCE_BLOCKED` | `NOT_FOUND` | `VALIDATION_FAILED` | `READONLY_MODE` | `RATE_LIMITED` |

**Decision order** (first failure wins — see `x-northwind-decision-order`):
`SOURCE_BLOCKED → RATE_LIMITED → NO_SESSION → SESSION_EXPIRED → TOKEN_REVOKED → REAUTH_REQUIRED
→ CSRF_INVALID → SUSPENDED → READONLY_MODE → TENANT_MISMATCH → NOT_FOUND (tenant) → NOT_A_MEMBER
→ INSUFFICIENT_ROLE → NOT_FOUND (target) → VALIDATION_FAILED`.

Two consequences the attack driver depends on:

1. **Role check precedes resource resolution.** An under-privileged caller gets
   `403 INSUFFICIENT_ROLE` for *every* id — real, foreign or invented — so probing leaks nothing.
2. **Sensitivity gating happens during resolution**, yielding an ordinary `404 NOT_FOUND`.

Error body: `{"error":{"code","message","request_id","retry_after_s"?,"feature"?,"details"?}}`.
`details` appears only for `VALIDATION_FAILED`.

## Tenant-scoped addressing

Every resource path is rooted at `/tenants/{tenant_id}/…` and resolution walks the subtree
`Tenant → Project → Task → Comment`. A foreign id is **unreachable by traversal**, not merely
rejected — the walk never reaches it, so the answer is `404`, identical to an id that never
existed. There is no `/projects/{id}` or `/tasks/{id}` surface anywhere in the API.

`TENANT_MISMATCH` means something narrower and is the lateral-movement signal: *the presented
credential is bound to tenant A and the path addresses tenant B* (API tokens, invite tokens).
A user session simply lacking a Membership gets `NOT_A_MEMBER` instead.

## Sensitivity, and why the canary is not a trap

Projects / tasks / attachments carry `sensitivity: normal | confidential | canary`.
Reachability floor: `normal → viewer`, `confidential → admin`, `canary → admin`.
Task effective sensitivity is `max(project, task)`; attachment is `max(task_effective, own)`.
Lists, reads and **search** apply the identical predicate, so a `member` never sees a
confidential or canary record, its id, or a snippet of it.

`canary` and `confidential` traverse the **identical authorization code path with the identical
floor**. The application contains no branch on `sensitivity == "canary"`, emits no special event
for it, and alters no response for it. The distinct enum value exists only so the fixture
generator and the *external* monitor know which record was seeded. Deleting `canary` from the
enum would not change a single authorization outcome. A low-privilege member is denied it by
ordinary authorization, exactly as they are denied any other confidential record.

## No bypass

No admin bypass, no debug endpoint, no maintenance route, no hard-coded credential (not even
commented out), and no header, query parameter or body field that relaxes authorization. Every
one of the 33 operations goes through the same decision order. **Every mutating endpoint requires
both authentication and a server-side authorization check** — stated per operation in the YAML
under `x-authz.server_side_check`. The single mutating endpoint without an authenticated
principal is `POST /auth/register`, which by construction grants the caller access to nothing.

The compromised synthetic identity is an ordinary API token on an ordinary low-privilege
service-account Membership, supplied by the fixture. It reaches exactly what its Membership
permits and nothing more.

---

## Mapping: public → walker → role → audit action

Role column is the **minimum Membership rank** in the path tenant. `authenticated` = any logged-in
principal, no Membership needed. `public` = no credential.

| # | Method | Public path | Walker | Role | Audit action | OK |
|---|---|---|---|---|---|---|
| 1 | POST | `/auth/register` | `RegisterUser` | public | `auth.register` | 201 |
| 2 | POST | `/auth/login` | `LoginUser` | public | `auth.login` / `auth.login_failed` | 200 |
| 3 | POST | `/auth/logout` | `LogoutSession` | authenticated | `auth.logout` + `auth.token_revoked` | 200 |
| 4 | POST | `/auth/refresh` | `RefreshSession` | authenticated | `auth.token_issued` + `auth.token_revoked` | 200 |
| 5 | POST | `/auth/reauth` | `ReauthSession` | authenticated | `auth.reauth_required` + `auth.token_issued` | 200 |
| 6 | GET | `/auth/session` | `GetSession` | authenticated | *(none — see note A)* | 200 |
| 7 | GET | `/tenants` | `ListMyTenants` | authenticated | `tenant.read` | 200 |
| 8 | POST | `/tenants` | `CreateTenant` | authenticated | `tenant.create` | 201 |
| 9 | GET | `/tenants/{tenant_id}` | `ReadTenant` | viewer | `tenant.read` | 200 |
| 10 | GET | `/tenants/{tenant_id}/members` | `ListMembers` | viewer | `tenant.read` | 200 |
| 11 | POST | `/tenants/{tenant_id}/members/invites` | `InviteMember` | admin | `member.invite` | 201 |
| 12 | POST | `/tenants/{tenant_id}/invites/accept` | `AcceptInvite` | authenticated | `member.accept` | 200 |
| 13 | PATCH | `/tenants/{tenant_id}/members/{membership_id}` | `ChangeMemberRole` | admin † | `member.role_change` | 200 |
| 14 | DELETE | `/tenants/{tenant_id}/members/{membership_id}` | `RemoveMember` | admin † | `member.remove` | 200 |
| 15 | POST | `/tenants/{tenant_id}/projects` | `CreateProject` | member ‡ | `project.create` | 201 |
| 16 | GET | `/tenants/{tenant_id}/projects` | `ListProjects` | viewer | `project.list` | 200 |
| 17 | GET | `/tenants/{tenant_id}/projects/{project_id}` | `ReadProject` | viewer | `project.read` | 200 |
| 18 | PATCH | `/tenants/{tenant_id}/projects/{project_id}` | `UpdateProject` | member ‡ | `project.update` | 200 |
| 19 | DELETE | `/tenants/{tenant_id}/projects/{project_id}` | `DeleteProject` | admin | `project.delete` | 200 |
| 20 | POST | `…/tasks` | `CreateTask` | member ‡ | `task.create` | 201 |
| 21 | GET | `…/tasks` | `ListTasks` | viewer | `task.list` | 200 |
| 22 | GET | `…/tasks/{task_id}` | `ReadTask` | viewer | `task.read` | 200 |
| 23 | PATCH | `…/tasks/{task_id}` | `UpdateTask` | member ‡ | `task.update` | 200 |
| 24 | DELETE | `…/tasks/{task_id}` | `DeleteTask` | admin | `task.delete` | 200 |
| 25 | POST | `…/tasks/{task_id}/assign` | `AssignTask` | member | `task.assign` | 200 |
| 26 | POST | `…/tasks/{task_id}/comments` | `CreateComment` | member | `comment.create` | 201 |
| 27 | GET | `…/tasks/{task_id}/comments` | `ListComments` | viewer | `comment.list` | 200 |
| 28 | GET | `…/tasks/{task_id}/comments/{comment_id}` | `ReadComment` | viewer | `comment.read` | 200 |
| 29 | DELETE | `…/tasks/{task_id}/comments/{comment_id}` | `DeleteComment` | member § | `comment.delete` | 200 |
| 30 | GET | `/tenants/{tenant_id}/search` | `SearchTenant` | viewer | `search.query` | 200 |
| 31 | POST | `/tenants/{tenant_id}/exports` | `RequestExport` | admin † | `export.request` | 202 |
| 32 | GET | `/tenants/{tenant_id}/exports/{export_id}` | `DownloadExport` | admin † | `export.download` | 200 / 202 |
| 33 | POST | `/tenants/{tenant_id}/integrations/call` | `IntegrationCall` | ¶ | `integration.call` | 200 |

`…` = `/tenants/{tenant_id}/projects/{project_id}`.
**†** step-up gated (`auth_age_s <= 900`, else `401 REAUTH_REQUIRED`).
**‡** effective role is `max(member, floor(sensitivity))` — `admin` whenever the current or
requested sensitivity is not `normal`.
**§** author, or `admin` for someone else's comment.
**¶** Bearer token: service-account Membership `>= member` **and** scope `integration:call`.
User session: `admin` **and** step-up.

### Audit emission

One **primary** event per request, action per the table, with `outcome: allowed | denied` and
`deny_reason` when denied. Denied requests still emit their primary action. Additional rules:

- Login emits `auth.login_failed` **instead of** `auth.login` on failure.
- Rows 3–5 emit the listed secondary event on success (`secondary: true`).
- Refresh on an expired session emits `auth.session_expired` instead of its primary.
- Any response with `SESSION_EXPIRED` / `REAUTH_REQUIRED` / `TOKEN_REVOKED` also emits
  `auth.session_expired` / `auth.reauth_required` / `auth.token_revoked` as a secondary.

Audit records never contain passwords, hashes, session values, API token values, invite tokens,
CSRF tokens or the gateway JWT. Schema: `components.schemas.AuditEvent`.

---

## Notes on judgement calls

**A. `GET /auth/session` emits no audit action.** The closed vocabulary has no
read-your-own-session action, and mapping it to `auth.token_issued` would be a lie. It emits
nothing on 200; on `401 SESSION_EXPIRED` the secondary rule emits `auth.session_expired`.

**B. Login failure reuses `NO_SESSION` (401).** The closed deny-reason set has no
`INVALID_CREDENTIALS`. `NO_SESSION` is defined as "no valid credential was presented **or
established**". The body is byte-identical for unknown account, wrong password and suspended
account, with a dummy bcrypt verification for unknown emails to equalise timing.

**C. `tenant.read` covers three reads** — my tenants, one tenant, member roster. The vocabulary
has no `tenant.list` or `member.list`.

**D. `DELETE …/comments/{comment_id}` inverts the usual order.** Authorship cannot be known
before resolution, so it is: rank ≥ member (403) → resolve within ceiling (404) → author-or-admin
(403). A member can therefore tell "someone else's comment" from "no such comment" — but only
among comments already visible to them, so nothing new is disclosed.

**E. Duplicate-email registration returns `422`.** A deliberate, documented tradeoff: it is what
essentially every real SaaS signup does, and it is bounded at 3 per hour per source. The endpoint
the attack track sprays (`/auth/login`) discloses nothing.

**F. Sensitivity is enforced as a role floor, not an ACL.** There are no per-record grant lists in
v1, so `confidential`/`canary` are reachable by `admin` and `owner` only. This keeps the "canary
is not special-cased" property provable by inspection.

## Validation

```
python3 -c "import yaml,sys; yaml.safe_load(open('contracts/app_api.openapi.yaml'))"   # parses
openapi_spec_validator.OpenAPIV31SpecValidator                                          # 0 errors
```

Also checked programmatically: mapping rows ↔ operations are 1:1 and agree field-for-field with
each operation's `x-jac-walker` / `x-required-role` / `x-audit-action`; all 33 audit actions have
a home; all 14 deny reasons are used and appear in the decision order; every operation declaring a
deny reason also declares its status code; every list endpoint has `limit` + `cursor`; every
non-auth path is tenant-scoped; every mutating operation declares `authentication: required` plus
a server-side check; every non-GET requires CSRF or Bearer; all `$ref`s resolve.
