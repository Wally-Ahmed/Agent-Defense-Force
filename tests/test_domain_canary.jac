# tests/test_domain_canary.jac -- the canary is an ordinary record.
#
#     APP_CTX_SIGNING_KEY=<64 hex> jac test tests/test_domain_canary.jac
#
# THE CLAIM UNDER TEST, in three parts:
#
#   1. BEHAVIOUR -- a low-privilege member is denied the canary record, and is
#      denied it by the same role/sensitivity logic that denies them any other
#      above-rank record.
#   2. INDISTINGUISHABILITY -- the response for the canary is byte-identical to
#      the response for an ordinary `confidential` record. If a monitor could
#      tell them apart from the outside, so could an attacker.
#   3. STRUCTURE -- no code path anywhere under app/ branches on the value
#      "canary". Asserted by reading the source, so it stays true.
#
# Part 3 is what makes parts 1 and 2 mean something. Behaviour can be made to
# look right by a special case; the source scan is what proves there isn't one.
# The strongest form of the claim is the equivalence test below: for EVERY role,
# `can_reach(role, "canary")` and `can_reach(role, "confidential")` agree. If the
# `canary` row were deleted from the floor table entirely, not one authorization
# outcome in this application would change.

import os;
import re;
import glob;

import from tests.fixtures { world, ctx_for }
import from tests.helpers { audit_count, only_event }
import from app.services.projects { ReadProject, ListProjects, UpdateProject }
import from app.services.sensitivity { floor_for, can_reach, SENSITIVITY_FLOOR }
import from app.security.roles { ROLES }

glob:pub W: dict = world();

# --------------------------------------------------------------------------
# 1. Behaviour
# --------------------------------------------------------------------------

test "a member is denied the canary project by ordinary authorization" {
    mark = audit_count();
    w = ReadProject(
        ctx=ctx_for("s_member", "/api/v1/tenants/t_acme/projects/pr_canary", "GET"),
        tenant_id="t_acme", project_id="pr_canary"
    ) spawn root;
    r = w.reports[0];
    print("MEMBER -> CANARY:", r);
    assert r["ok"] == False;
    assert r["status"] == 404;
    assert r["error"]["code"] == "NOT_FOUND";

    ev = only_event(mark);
    print("  audit:", ev);
    # The action is the ordinary one. There is no `canary.*` action, no special
    # event, and no extra emission -- the record's sensitivity rides along on
    # the SAME event every other read produces, and vocab.md's severity rule
    # escalates it to `high` from there.
    assert ev["action"] == "project.read";
    assert ev["target_sensitivity"] == "canary";
    assert ev["severity"] == "high";

    # ------------------------------------------------------------------ SEAM
    # guard() ALLOWS this request and the domain layer denies it, so the audit
    # row reads `allow` for a request that returned 404. guard() resolves the
    # target by traversal and records its sensitivity, but does not gate on it
    # (app/security/authz.jac step 6); the floor lives in
    # app/services/sensitivity.jac. Detection is unaffected -- the event still
    # carries `target_sensitivity: canary` and still escalates to `high` -- but
    # `outcome` misreports what the caller received.
    #
    # The fix belongs in guard(), one condition at step 6: deny NOT_FOUND when
    # `can_reach(membership.role, sensitivity_of(resolved))` is False. It is not
    # applied here because app/security/ is another track's file.
    #
    # This assertion records the CURRENT seam so that closing it turns this test
    # red and forces the line below to be updated rather than forgotten.
    assert ev["outcome"] == "allow",
        "guard() now gates on sensitivity -- flip this to `deny` and drop the SEAM note";
}

test "an admin reaches the canary project -- the floor is a floor, not a wall" {
    w = ReadProject(
        ctx=ctx_for("s_admin", "/api/v1/tenants/t_acme/projects/pr_canary", "GET"),
        tenant_id="t_acme", project_id="pr_canary"
    ) spawn root;
    r = w.reports[0];
    print("ADMIN -> CANARY:", r["ok"], r["status"]);
    assert r["ok"] == True;
    assert r["data"]["sensitivity"] == "canary";
}

test "a member's project list contains neither the canary nor the confidential" {
    w = ListProjects(
        ctx=ctx_for("s_member", "/api/v1/tenants/t_acme/projects", "GET"),
        tenant_id="t_acme", limit=100
    ) spawn root;
    r = w.reports[0];
    items: list = r["data"]["items"];
    ids = [i["project_id"] for i in items];
    print("MEMBER PROJECT LIST:", ids, "total_visible:", r["data"]["total_visible"]);
    assert "pr_canary" not in ids;
    assert "pr_conf" not in ids;
    assert "pr_normal" in ids;
    # It is not merely hidden from the page -- it never entered the collection,
    # so it cannot leak through the count either.
    assert r["data"]["total_visible"] == len(ids);
}

# --------------------------------------------------------------------------
# 2. Indistinguishability
# --------------------------------------------------------------------------

test "the canary denial is byte-identical to an ordinary confidential denial" {
    canary = ReadProject(
        ctx=ctx_for("s_member", "/api/v1/tenants/t_acme/projects/pr_canary", "GET"),
        tenant_id="t_acme", project_id="pr_canary"
    ) spawn root;
    conf = ReadProject(
        ctx=ctx_for("s_member", "/api/v1/tenants/t_acme/projects/pr_conf", "GET"),
        tenant_id="t_acme", project_id="pr_conf"
    ) spawn root;
    a = canary.reports[0];
    b = conf.reports[0];
    print("CANARY      :", a);
    print("CONFIDENTIAL:", b);
    assert a == b;
}

test "a member cannot write a canary project either, by the same floor" {
    up = UpdateProject(
        ctx=ctx_for("s_member", "/api/v1/tenants/t_acme/projects/pr_canary", "PATCH"),
        tenant_id="t_acme", project_id="pr_canary", name="touched"
    ) spawn root;
    r = up.reports[0];
    print("MEMBER UPDATE -> CANARY:", r);
    assert r["ok"] == False;
    assert r["error"]["code"] == "NOT_FOUND";
}

# --------------------------------------------------------------------------
# 3. Structure -- the property that makes the rest meaningful
# --------------------------------------------------------------------------

test "canary and confidential are the SAME authorization outcome for every role" {
    assert floor_for("canary") == floor_for("confidential");
    for role in ROLES {
        same = can_reach(role, "canary") == can_reach(role, "confidential");
        print(f"  role={role}: canary={can_reach(role, 'canary')} confidential={can_reach(role, 'confidential')}");
        assert same,
            f"role {role} is treated differently for canary vs confidential";
    }
    # An unknown sensitivity floors at the strictest rank, so deleting the
    # `canary` row from the table would leave it unreachable rather than open.
    assert floor_for("something_new_and_unlisted") == "owner";
}

"""Every readable .jac source under app/, excluding bytecode directories."""
def app_sources() -> list {
    here = os.path.abspath(os.getcwd());
    base = here;
    if not os.path.isdir(os.path.join(here, "app")) {
        base = os.path.dirname(here);
    }
    out: list = [];
    for path in sorted(glob.glob(os.path.join(base, "app", "**", "*.jac"), recursive=True)) {
        if os.path.isfile(path) {
            out.append(path);
        }
    }
    return out;
}

# A comparison against the literal "canary" in any of the shapes it could take.
glob:pub CANARY_BRANCH_RE: str = r"""(==|!=|\bis\b|\bin\b)\s*\[?\s*["']canary["']|["']canary["']\s*(==|!=)""";

# The ONE place in the codebase permitted to name the value, with the reason.
# vocab.md: "target_sensitivity == canary, on ANY outcome -> high. Canaries have
# no legitimate traffic; a touch is a signal." That is a SEVERITY rule in the
# audit writer -- it labels an event after the decision is made. It cannot allow
# or deny anything, and removing it would change no authorization outcome. Every
# other match is a failure.
glob:pub SEVERITY_RULE_FILE: str = "security/audit.jac";

test "no AUTHORIZATION path under app/ branches on the value \"canary\"" {
    sources = app_sources();
    assert len(sources) > 0, "found no app sources -- this test would be vacuous";
    offenders: list = [];
    mentions: list = [];
    exempt: list = [];
    for path in sources {
        handle = open(path, "r", encoding="utf-8", errors="replace");
        text = handle.read();
        handle.close();
        lineno = 0;
        for line in text.split("\n") {
            lineno += 1;
            stripped = line.strip();
            if stripped.startswith("#") {
                continue;
            }
            if "canary" not in line {
                continue;
            }
            mentions.append(path.split("/app/")[-1] + ":" + str(lineno) + "  " + stripped);
            if re.search(CANARY_BRANCH_RE, line) is not None {
                where = path.split("/app/")[-1] + ":" + str(lineno) + "  " + stripped;
                if path.split("/app/")[-1] == SEVERITY_RULE_FILE {
                    exempt.append(where);
                } else {
                    offenders.append(where);
                }
            }
        }
    }
    print("EVERY non-comment mention of \"canary\" under app/:");
    for m in mentions {
        print("   ", m);
    }
    print("Comparisons, all of which must be the audit severity rule:");
    for e in exempt {
        print("    EXEMPT (severity labelling, not authorization):", e);
    }
    assert len(offenders) == 0,
        "these lines branch on the canary value inside an authorization path: "
        + " | ".join(offenders);
    # And the exemption itself is bounded: exactly one line, in one file.
    assert len(exempt) <= 1,
        "the severity-rule exemption has grown: " + " | ".join(exempt);
}
