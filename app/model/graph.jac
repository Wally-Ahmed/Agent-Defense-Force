# app/model/graph.jac — the shared-platform object graph.
#
# ONE shared platform root. Jac's per-user-root isolation is deliberately NOT
# used: it hands each identity a private subgraph, which is structurally wrong
# for a tenant that has many members, and it buries the isolation boundary in
# framework magic. Here the boundary is a visible edge in this file.
#
#   root -> Platform
#           -> Tenant(tenant_id, name, plan, status)
#                -> Membership(principal_id, role, state) -> Principal
#                -> Project(project_id, key, visibility, sensitivity)
#                     -> Task(task_id, title, status, assignee_id, sensitivity)
#                          -> Comment(comment_id, body, author_id)
#                -> Invite(token_hash, email, role, expires_at, state)
#                -> ExportJob(job_id, state, row_count)
#           -> Principal(principal_id, email, pw_hash, status, mfa)
#                -> Session(session_id, ip_first, fp, issued_at, expires_at, revoked)
#                -> Token(jti, kind, scope, expires_at, revoked)
#           -> Control(control_id, kind, scope_key, params, expires_at, active)
#
# THE ISOLATION RULE: nothing in this application resolves a tenant-owned
# resource by global id. Every lookup walks Tenant --> Project --> Task -->
# Comment through the typed edges below. A foreign id is therefore UNREACHABLE
# rather than merely rejected -- see app/model/resolve.jac. Enforced by
# tests/test_tenant_isolation.test.jac.
#
# TIME: every *_at / expires_at field on an app-owned node is an INT of epoch
# MILLISECONDS (UTC). The frozen contracts use ISO strings in their own nodes;
# app/security/clock.jac converts between the two. Ints are used here so that
# expiry is a comparison and can never be a locale- or format-dependent parse.

import from contracts.containment_contract { Control }

# --------------------------------------------------------------------------
# Typed edges. Every one of these is a containment relation: the source node
# OWNS the target. Traversal across a typed edge is the only sanctioned way to
# reach a tenant-owned resource.
# --------------------------------------------------------------------------

edge Hosts {}          # Platform  -> Tenant
edge Registers {}      # Platform  -> Principal
edge Enforces {}       # Platform  -> Control
edge Records {}        # Platform  -> AuditEvent / AuditChain
edge HasMember {}      # Tenant    -> Membership
edge Identifies {}     # Membership-> Principal
edge Owns {}           # Tenant    -> Project
edge Invited {}        # Tenant    -> Invite
edge Exports {}        # Tenant    -> ExportJob
edge Contains {}       # Project   -> Task
edge Discusses {}      # Task      -> Comment
edge Authenticates {}  # Principal -> Session
edge Bears {}          # Principal -> Token

# --------------------------------------------------------------------------
# Platform: the single shared root of the object graph.
# --------------------------------------------------------------------------

node Platform {
    has platform_id: str = "platform";
    has created_at: int = 0;
}

# --------------------------------------------------------------------------
# Tenancy
# --------------------------------------------------------------------------

node Tenant {
    has tenant_id: str = "";
    has name: str = "";
    has plan: str = "free";        # free | pro | enterprise
    has status: str = "active";    # active | suspended
    has created_at: int = 0;
}

# Roles live HERE, never on Principal. A principal is not "an admin"; a
# principal is an admin OF A TENANT. Rank order: owner > admin > member > viewer.
node Membership {
    has membership_id: str = "";
    has principal_id: str = "";
    has tenant_id: str = "";
    has role: str = "viewer";      # owner | admin | member | viewer
    has state: str = "active";     # active | suspended | removed
    has created_at: int = 0;
}

node Invite {
    has invite_id: str = "";
    has token_hash: str = "";      # sha256 of the invite token; the token itself is never stored
    has email: str = "";
    has role: str = "viewer";
    has tenant_id: str = "";
    has expires_at: int = 0;
    has state: str = "pending";    # pending | accepted | revoked | expired
    has created_at: int = 0;
}

node ExportJob {
    has job_id: str = "";
    has tenant_id: str = "";
    has state: str = "queued";     # queued | running | ready | downloaded | failed
    has row_count: int = 0;
    has requested_by: str = "";
    has created_at: int = 0;
    # --- descriptive fields, added for the domain layer (T3). All defaulted.
    has format: str = "json";      # json | csv
    has include: list = [];        # projects | tasks | comments | members | audit
    has project_ids: list = [];    # "" means every project the requester can reach
    has ready_at: int = 0;
    has expires_at: int = 0;
    # The requester's sensitivity ceiling AT REQUEST TIME, recorded so a later
    # download can be re-filtered and the two can be compared.
    has sensitivity_ceiling: str = "normal";
}

# --------------------------------------------------------------------------
# Identity
# --------------------------------------------------------------------------

node Principal {
    has principal_id: str = "";
    has email: str = "";
    has pw_hash: str = "";         # bcrypt, cost 12. Never a plaintext, never a reversible digest.
    has status: str = "active";    # active | suspended | disabled
    has mfa: bool = False;
    has created_at: int = 0;
}

# A session is TENANT-SCOPED: it is issued for one principal acting inside one
# tenant. Crossing to another tenant_id with this session is a TENANT_MISMATCH,
# which is exactly the boundary-probe signal the monitor watches for.
node Session {
    has session_id: str = "";
    has principal_id: str = "";
    has tenant_id: str = "";
    has ip_first: str = "";        # source ip at issue time
    has fp: str = "";              # client fingerprint at issue time
    has issued_at: int = 0;
    has expires_at: int = 0;
    has last_auth_at: int = 0;     # last time a password was actually presented (step-up clock)
    has revoked: bool = False;
}

node Token {
    has jti: str = "";
    has principal_id: str = "";
    has tenant_id: str = "";
    has kind: str = "api";         # api | refresh
    has scope: str = "";           # space-separated action prefixes, "" == none
    has issued_at: int = 0;
    has expires_at: int = 0;
    has revoked: bool = False;
}

# --------------------------------------------------------------------------
# Work objects
# --------------------------------------------------------------------------

node Project {
    has project_id: str = "";
    has tenant_id: str = "";
    has key: str = "";
    has visibility: str = "tenant";     # tenant | private
    has sensitivity: str = "normal";    # normal | confidential | canary
    has created_at: int = 0;
    # --- descriptive fields, added for the domain layer (T3). Every one is
    # defaulted, so nothing that existed before this block changed behaviour.
    has name: str = "";
    has description: str = "";
    has status: str = "active";         # active | archived
    has owner_user_id: str = "";
    has updated_at: int = 0;
}

node Task {
    has task_id: str = "";
    has project_id: str = "";
    has title: str = "";
    has status: str = "open";           # open | in_progress | done
    has assignee_id: str = "";
    has sensitivity: str = "normal";    # normal | confidential | canary
    has created_at: int = 0;
    # --- descriptive fields, added for the domain layer (T3).
    has description: str = "";
    has priority: str = "normal";       # low | normal | high | urgent
    has due_date: str = "";             # ISO-8601 date, "" when unset
    has labels: list = [];
    has created_by: str = "";
    has updated_at: int = 0;
}

node Comment {
    has comment_id: str = "";
    has task_id: str = "";
    has body: str = "";
    has author_id: str = "";
    has created_at: int = 0;
    # --- descriptive fields, added for the domain layer (T3).
    has project_id: str = "";
    has edited_at: int = 0;
}

# --------------------------------------------------------------------------
# Audit chain state. `seq` is monotonic per session and `prev_event_id` chains
# to the previous event in that same session, so a gap in the chain is
# detectable. Anonymous / unverified traffic chains under a synthetic key so
# that a gateway-bypass attempt still produces an ordered, gap-free record.
# --------------------------------------------------------------------------

node AuditChain {
    has chain_key: str = "";       # "session:<id>" or "anon:<client_fp-or-ip>"
    has last_event_id: str = "";
    has seq: int = 0;
}

# --------------------------------------------------------------------------
# Platform singleton. Created on first use; never duplicated.
# --------------------------------------------------------------------------

"""Return the one Platform node, creating it on first call."""
def get_platform() -> Platform {
    found = [root()-->][?:Platform];
    if len(found) > 0 {
        return found[0];
    }
    return (root() ++> Platform(platform_id="platform"))[0];
}

"""Every tenant on the platform. Used only by admin/bootstrap paths."""
def all_tenants() -> list[Tenant] {
    p = get_platform();
    return [p->:Hosts:->][?:Tenant];
}

"""Every principal on the platform. Used only by the login path, which must
resolve an identity before any tenant context exists."""
def all_principals() -> list[Principal] {
    p = get_platform();
    return [p->:Registers:->][?:Principal];
}

"""Every control on the platform. Read by guard() on every single call."""
def all_controls() -> list[Control] {
    p = get_platform();
    return [p->:Enforces:->][?:Control];
}
