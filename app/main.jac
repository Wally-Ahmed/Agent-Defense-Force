# app/main.jac — the server entrypoint. Run with `jac start app/main.jac`.
#
# WHAT THIS FILE GUARANTEES, and why it is nothing but imports:
#
# 1. THE APP REFUSES TO START WITHOUT `APP_CTX_SIGNING_KEY`. Importing
#    app.security.keys runs its import-time check, which raises RuntimeError
#    unless a key of at least 32 bytes is present in the environment. That key is
#    what the gateway signs each ReqCtx with and what guard() verifies before
#    trusting a single field of it. Generate one and export it before starting:
#      export APP_CTX_SIGNING_KEY=$(python3 -c "import secrets;print(secrets.token_hex(32))")
#
# 2. THERE IS NO DEV-MODE BYPASS. No default key, no generated-on-first-run key,
#    no DEBUG flag, no `if not sig and DEV_MODE` escape hatch — not here, not in
#    the walkers, not commented out anywhere. `jac start` binds 0.0.0.0 with no
#    --host option, so the walker endpoints are directly reachable and the
#    gateway can be skipped entirely; the ctx signature, not the network, is the
#    trust boundary. A bypass would BE the backdoor this design exists to rule
#    out.
#
# 3. THE POLICY TABLE IS COMPLETE OR THE APP DOES NOT START. Importing
#    app.security.roles runs assert_policy_complete(), which raises unless every
#    action in the frozen vocabulary has exactly one entry in ACTION_MIN_ROLE. An
#    action nobody assigned a role to stops the process instead of defaulting to
#    something permissive.
#
# 4. EVERY PROTECTED WALKER CALLS guard() FIRST. Each `walker:priv` in
#    app/walkers/ opens its ability with `g = guard(...)` — before any
#    validation, any lookup, any logging. Resolve, authorize and audit happen
#    inside that single call, so no walker can touch a record it has not yet been
#    authorized to touch.
#
# 5. DOMAIN WALKERS EMIT NO AUDIT EVENTS. guard() emits exactly one AuditEvent
#    per request, and the `outcome` / `result_count` in that row are the
#    monitor's signals. A second emission from application code would
#    double-count them, so `grep -rn "emit_audit" app/walkers/` returns nothing.
#    Register and Login are the only pre-auth cases; they call emit_preauth()
#    once each.
#
# THERE IS NOTHING ELSE IN THIS FILE ON PURPOSE. No seed data, no demo tenant,
# no bootstrap account, no reset or debug endpoint, and no walkers of its own. A
# seeded credential is a hard-coded credential with a nicer name, and a reset
# endpoint is an unauthenticated write to production.

import app.security.keys;
import app.security.roles;

import app.walkers.auth;
import app.walkers.tenancy;
import app.walkers.work;

# Bind the walker archetypes into this module's namespace so `jac start`
# registers an HTTP endpoint for every one of them.
import from app.walkers.auth {
    Register, Login, Logout, SessionInfo, Reauth, IssueToken, RevokeToken
}
import from app.walkers.tenancy {
    CreateTenant, ReadTenant, InviteMember, AcceptInvite, ChangeRole, RemoveMember
}
import from app.walkers.work {
    ListProjects, ReadProject, ListTasks, ReadTask, ListComments
}

# The remaining contract endpoints live in app/services/. These imports are
# SELECTIVE BY NAME, never `import app.services.X`, and that is load-bearing: the
# service modules also define archetypes named ListProjects, ReadProject,
# ListTasks, ReadTask, ListComments, CreateTenant, ReadTenant, InviteMember,
# AcceptInvite and RemoveMember. A whole-module import would bind those into this
# namespace and let them shadow the app/walkers/ implementations above, silently
# swapping the audited, test-covered path for a different one. Naming each walker
# explicitly means only the walkers listed here are added, and the ones already
# bound above stay bound.
import from app.services.tenants { ListMyTenants }
import from app.services.members { ListMembers }
import from app.services.projects { CreateProject, UpdateProject, DeleteProject }
import from app.services.tasks { CreateTask, UpdateTask, DeleteTask, AssignTask }
import from app.services.comments { CreateComment, ReadComment, DeleteComment }
import from app.services.discovery {
    SearchTenant, RequestExport, DownloadExport, IntegrationCall
}
