# SPEC — JacHacksSF 2026

**Authoritative requirements of record.** Recorded verbatim 2026-07-26.

This document is the *final clarifications and overrides* layer of the project brief. It
states plainly that it overrides any conflicting wording "above" — that is, in the earlier
brief it amends. **That earlier brief is not currently in this repository.** If it lands
later, add it below this section; this layer still wins on any conflict.

The only editorial change made to the text below is that the section titles are rendered as
markdown headings. No wording was added, removed, reordered, or reinterpreted.

---

# FINAL CLARIFICATIONS AND OVERRIDES

These requirements override any conflicting wording above.

## GITHUB AND COTAL PR DISCOVERY

GitHub credentials are available through the user’s local environment.

1. Run `gh auth status`.
2. If authentication is required, give me the exact interactive login command and pause while I complete it. Never ask me to paste a token into chat or write credentials into the repository.
3. Once authenticated, query pull requests authored by my authenticated GitHub identity against `Cotal-Ai/Cotal`.
4. Identify the three relevant PRs from their content and relationship to the required connectors.
5. If more than three plausible PRs make the selection genuinely ambiguous, show only the candidate URLs and ask me which three.
6. Inspect their merge state, head SHAs, CI results, dependencies, and whether their functionality is already present upstream.
7. Use a pinned upstream version containing the changes when merged. Otherwise create a reproducible integration branch containing the exact PR changes and verify it with Cotal’s tests.

## MODEL TARGET AND AUTHENTICATION

The monitoring model is GLM-5.2, not GLM-5.5.

The complete mesh contains six model processes:

- Hermes + GLM-5.2 as the continuous monitor
- Claude Code + Claude Opus 5
- Codex + GPT-5.6 Sol
- Google Antigravity (`agy`) + Gemini 3.1 Pro
- OpenCode + Kimi K3
- OpenCode + GLM-5.2

Use the highest supported effort requested for each combination and record the effective setting. Never silently downgrade or substitute.

Credentials exist but some harnesses are not logged in yet. Audit each CLI independently. When interactive browser, OAuth, or device authentication is required:

- Show the exact login command
- Pause for me to complete authentication
- Recheck authentication afterward
- Never expose, store, echo, or commit credentials
- Perform a minimal smoke test before invoking the full mesh

A successful full live end-to-end run involving the real monitor, real Cotal mesh, and all five real responders is mandatory before calling the system complete. Recorded replay may be retained as a clearly labeled presentation backup, but it does not satisfy acceptance testing.

Diagnose, repair, and retest until the live path succeeds. Do not repeat an unchanged failing call indefinitely: inspect the failure, change something justified, and then retry. Track provider usage and estimated cost throughout testing.

## CYBERSECURITY SKILLS

Pin the community cybersecurity-skills repository and make the complete library discoverable to every harness.

Do not inject the full library directly into every context. Agents must be able to search the index and load only the skills relevant to the current incident. Log which skills were selected, their paths, and the pinned repository SHA.

Verify through smoke tests that all six model runtimes can discover and selectively load a relevant skill.

## REALISTIC FAKE COMPANY

Do not create a deliberately insecure toy, a cybersecurity company, or a website whose only purpose is to be hacked.

Build an ordinary, believable multi-user web company in Jac—for example, a collaborative file-processing, project-management, or data-sharing SaaS. Choose a product that can be demonstrated clearly within the available time.

The application should behave like a competently built modern website and include, where applicable:

- Normal registration, authentication, logout, and session expiration
- Secure password hashing
- Secure cookie and session settings
- Server-side authorization on every protected operation
- Role-based access and tenant isolation
- Schema and input validation
- Parameterized data access
- CSRF protection for browser state changes
- Restrictive CORS
- Common security headers
- Rate limiting and sensible login throttling
- Environment-based secrets
- Short-lived tokens and revocation
- Structured security and application audit events
- Dependency pinning
- No production debug endpoints
- No hidden admin bypass
- No hard-coded credentials
- No deliberate SQL injection, command injection, path traversal, or equivalent backdoor

Use normal security testing to verify these controls. Where tooling is available, test authorization boundaries, tenant isolation, injection handling, session behavior, security headers, secret leakage, and dependency configuration.

The demonstration must not depend on the company having an embarrassingly obvious vulnerability.

## AUTHORIZED ATTACK SCENARIO

Model a realistic incident in which an attacker has obtained a synthetic low-privilege account credential or API token outside the application. The compromised credential is part of the controlled fixture; it is not created through a hidden application backdoor.

The attacker should operate through legitimate public interfaces while exhibiting agentic behavior:

1. Reconnaissance using ordinary HTTP requests
2. Failed login attempts or password spraying against synthetic accounts
3. Successful use of the pre-compromised synthetic identity
4. High-speed enumeration of accessible resources
5. Permission-boundary probing
6. Rapid adaptation after denied operations
7. Token or session use across rotating synthetic source identities
8. Attempts to discover higher-value resources
9. Attempts at lateral movement through legitimate integrations or service APIs
10. Attempted access to a synthetic canary record or protected export

Most individual requests should look plausible in isolation. The monitor’s value comes from correlating behavior across identities, sessions, services, time, and failed actions.

The application’s ordinary controls should continue working:

- Invalid operations remain denied
- Tenant boundaries remain enforced
- Injection attempts fail
- Unauthenticated access remains blocked
- The attacker cannot leave the sandbox

The agentic defense should detect the broader campaign before meaningful synthetic exfiltration occurs, revoke the compromised access, block or rate-limit associated sources, and preserve service for legitimate users.

If the attacker needs limited access to demonstrate containment, grant that access through the explicitly documented compromised test identity—not through a secret vulnerability.

Use a deterministic attack driver for the reliable judged path. An optional live adversary model may drive the same authorized sandbox scenario only after the deterministic path works and only if it cannot reach external systems.

## REALISTIC CONTAINMENT

Prefer targeted responses over shutting down the entire company:

- Revoke the compromised sessions and tokens
- Temporarily suspend the affected synthetic account
- Rate-limit or block correlated synthetic sources
- Require reauthentication for affected identities
- Switch a targeted high-risk feature into read-only mode
- Pause a specific export or file-processing queue
- Rotate synthetic service credentials
- Increase logging or challenge requirements
- Restore actions automatically after their TTL when safe

Service degradation or shutdown should use ordinary feature flags, circuit breakers, or administrative controls. It must have a visible blast-radius estimate, approval policy, TTL, health verification, and rollback.

Demonstrate that legitimate users retain as much availability as possible during containment.

## HARDENING ACCEPTANCE TESTS

In addition to the existing end-to-end criteria, prove:

- No deliberately exploitable backdoor exists in the application
- A normal unauthorized user cannot cross tenant or role boundaries
- The compromised test identity can access only what its legitimate permissions allow
- The attack is detected through behavioral correlation rather than a hard-coded “attack” flag
- Benign high-volume activity does not automatically become an incident
- Prompt injection embedded in request fields or uploaded content cannot change monitor instructions
- The attacker cannot reach the host, external network, real credentials, or other projects
- Targeted containment stops the malicious workflow while ordinary users continue functioning
- Reset restores all synthetic accounts, sessions, services, and fixtures
- At least one complete live six-model run succeeds from traffic generation through rollback

## PRESENTATION UPDATE

Frame the fake company as a normally secured application, not an intentionally vulnerable victim.

The central message is:

“Traditional controls can reject invalid requests, but a stolen valid credential operated by an autonomous agent may look normal one request at a time. Our system recognizes the coordinated behavior, assembles five independent model assessments, and applies narrowly scoped containment through enforceable Jac policy.”

During the demo, visibly show:

- Ordinary security controls blocking invalid requests
- A compromised synthetic identity making individually legitimate requests
- The Jac incident graph correlating those actions into a campaign
- Hermes escalating the incident
- Five live responders coordinating through Cotal
- Targeted containment instead of indiscriminate shutdown
- Legitimate traffic continuing
- Complete auditability and successful rollback

The confirmed presentation capability is the installed `walkthrough-builder` skill. Read and follow its complete `SKILL.md` when creating the narrated walkthrough.
